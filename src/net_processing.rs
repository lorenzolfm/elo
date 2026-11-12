//! The handshake: the `version` and `verack` messages before a peer is ready. Then the
//! messages after it: our `ping`, and the header sync.

use crate::serialize::{Decode, Encode};

/// The lowest protocol version elo accepts from a peer.
const PROTOCOL_VERSION_MIN: i32 = 70016;

// elo accepts its own `version`.
const _: () = assert!(crate::protocol::PROTOCOL_VERSION >= PROTOCOL_VERSION_MIN);

/// The most messages a peer may send in a handshake, its `verack` included. A peer needs five
/// at most: `version`, `wtxidrelay`, `sendaddrv2`, `sendtxrcncl` and `verack`. The rest is room
/// for messages that later BIPs add.
const MESSAGE_COUNT_MAX: u32 = 16;

/// How long after our last `ping` the next one goes, when its `pong` came.
const PING_INTERVAL: std::time::Duration = std::time::Duration::from_mins(2);

/// How long our `ping` may wait for its `pong`.
const PING_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(20);

// `PingState::send` wakes `PING_TIMEOUT` after `now`. So the `wake > now` assert in `tick`
// holds for it.
const _: () = assert!(!PING_TIMEOUT.is_zero());

/// How long our `getheaders` may wait for its `headers`.
const HEADERS_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

// `SyncState::tick` sends a `getheaders` and wakes `HEADERS_TIMEOUT` after `now`. So the
// `wake > now` assert in `tick` holds for it.
const _: () = assert!(!HEADERS_TIMEOUT.is_zero());

/// Why elo refuses the peer in the handshake. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// Their `version` payload did not decode.
    Version(crate::serialize::Error),
    /// Their protocol version is below `PROTOCOL_VERSION_MIN`.
    Obsolete(i32),
    /// Their `version` has our nonce, so the socket is connected to itself.
    SelfConnection,
    /// The peer sent `MESSAGE_COUNT_MAX` messages without its `verack`.
    TooManyMessages,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Version(error) => write!(f, "version payload: {error}"),
            HandshakeError::Obsolete(version) => {
                write!(
                    f,
                    "protocol version {version} is below {PROTOCOL_VERSION_MIN}"
                )
            }
            HandshakeError::SelfConnection => {
                write!(f, "connected to self: their version has our nonce")
            }
            HandshakeError::TooManyMessages => {
                write!(
                    f,
                    "the peer sent {MESSAGE_COUNT_MAX} messages without its verack"
                )
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Why elo refuses the peer after the handshake. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerError {
    /// Their `ping` payload did not decode.
    Ping(crate::serialize::Error),
    /// Their `pong` payload did not decode.
    Pong(crate::serialize::Error),
    /// Their `pong` came when no `ping` of ours was outstanding.
    UnsolicitedPong,
    /// Their `pong` has a nonce that is not the nonce of our outstanding `ping`.
    PongNonce,
    /// Our `ping` had no `pong` within `PING_TIMEOUT`.
    PingTimeout,
    /// Their `headers` payload did not decode, or it has too many headers or a transaction.
    Headers(crate::protocol::HeadersError),
    /// Our chain refused their batch, or a header that the second download of a low-work sync
    /// released. The error says why.
    Extend(crate::chain::ExtendError),
    /// A low-work sync refused their batch. The error says why.
    HeadersSync(crate::headerssync::HeadersSyncError),
    /// Their `headers` came when no `getheaders` of ours was outstanding.
    UnsolicitedHeaders,
    /// Our `getheaders` had no `headers` within `HEADERS_TIMEOUT`.
    HeadersTimeout,
    /// Their sync ended, and our chain has less work than the minimum.
    ChainWorkTooLow,
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Ping(error) => write!(f, "ping payload: {error}"),
            PeerError::Pong(error) => write!(f, "pong payload: {error}"),
            PeerError::UnsolicitedPong => write!(f, "pong without our ping"),
            PeerError::PongNonce => write!(f, "pong nonce is not our ping's"),
            PeerError::PingTimeout => {
                write!(f, "no pong within {} s", PING_TIMEOUT.as_secs())
            }
            PeerError::Headers(error) => write!(f, "{error}"),
            PeerError::Extend(error) => write!(f, "{error}"),
            PeerError::HeadersSync(error) => write!(f, "low-work sync: {error}"),
            PeerError::UnsolicitedHeaders => write!(f, "headers without our getheaders"),
            PeerError::HeadersTimeout => {
                write!(f, "no headers within {} s", HEADERS_TIMEOUT.as_secs())
            }
            PeerError::ChainWorkTooLow => {
                write!(f, "the sync ended on a chain below the minimum work")
            }
        }
    }
}

impl std::error::Error for PeerError {}

/// The `version` that elo sends to `peer`. elo serves no blocks and relays nothing, so it
/// claims no services and asks for no transactions.
fn our_version(peer: std::net::SocketAddr, timestamp: i64, nonce: u64) -> crate::protocol::Version {
    let unspecified = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0));
    crate::protocol::Version {
        version: crate::protocol::PROTOCOL_VERSION,
        services: crate::protocol::ServiceFlags::NONE,
        timestamp,
        addr_recv: crate::protocol::Address::new(crate::protocol::ServiceFlags::NONE, peer),
        addr_from: crate::protocol::Address::new(crate::protocol::ServiceFlags::NONE, unspecified),
        nonce,
        user_agent: crate::protocol::UserAgent::elo(),
        start_height: 0,
        relay: false,
    }
}

/// Where the handshake is. Our `version` is sent in both states.
#[derive(Debug)]
enum State {
    /// Their `version` has not come.
    AwaitingVersion,
    /// Their `version` came and our `verack` is sent. Their `verack` has not come.
    AwaitingVerack(crate::protocol::Version),
}

/// The handshake with one peer. It does no I/O: the driver gives it each message and sends
/// what it returns.
#[derive(Debug)]
pub(crate) struct Handshake {
    state: State,
    /// The network of the peer. Its genesis header starts our chain.
    network: crate::chainparams::Network,
    /// The work that our chain must reach in the sync.
    work_min: crate::pow::Work,
    /// The salt of a low-work sync. It must be secret.
    salt: crate::headerssync::Salt,
    /// The nonce in our `version`.
    nonce: u64,
    /// The messages that came, fewer than `MESSAGE_COUNT_MAX`.
    message_count: u32,
}

/// A message that the handshake sends.
#[derive(Debug)]
pub(crate) enum HandshakeOutbound {
    /// Our `version`, encoded.
    Version(Vec<u8>),
    /// A `verack`, which has no payload.
    Verack,
}

/// A message that elo sends after the handshake.
#[derive(Debug)]
pub(crate) enum PeerOutbound {
    /// Our `ping` with a new nonce.
    Ping(u64),
    /// A `pong` with the nonce of their `ping`.
    Pong(u64),
    /// Our `getheaders` from the last header that the sync has.
    GetHeaders(crate::protocol::GetHeaders),
}

/// What a tick sends. It has no `pong`, because only their `ping` gets one.
#[derive(Debug)]
pub(crate) struct TickOutbound {
    /// The nonce of our `ping`, if one is due.
    ping: Option<u64>,
    /// Our `getheaders`, if one is due.
    get_headers: Option<crate::protocol::GetHeaders>,
}

impl TickOutbound {
    /// The messages to send, in order: our `ping` first, then our `getheaders`.
    pub(crate) fn into_outbounds(self) -> impl Iterator<Item = PeerOutbound> {
        let ping = self.ping.map(PeerOutbound::Ping);
        let get_headers = self.get_headers.map(PeerOutbound::GetHeaders);
        ping.into_iter().chain(get_headers)
    }
}

/// What the peer does after a message. It has no `ping` and no `getheaders`, because only a
/// tick sends them.
#[derive(Debug)]
pub(crate) enum Received {
    /// Send nothing. The message was skipped, or it was a `pong` or a full batch that the peer
    /// took.
    NoReply,
    /// Send a `pong` with the nonce of their `ping`.
    Pong(u64),
    /// Their batch was not full, so the sync ended, and our chain has at least the minimum work.
    /// It holds the tip of our chain.
    Synced(crate::chain::Tip),
}

/// What the handshake does after a message.
#[derive(Debug)]
pub(crate) enum Step {
    /// Read the next message.
    Wait(Handshake),
    /// Send the message, then read the next one.
    Reply(Handshake, HandshakeOutbound),
    /// The handshake is complete. It holds the peer for the messages after it, and their
    /// `version`.
    Done(Peer, crate::protocol::Version),
}

impl Handshake {
    /// Returns our `version` to `peer` on `network`, to send first. The sync after the handshake
    /// must end on a chain with at least `work_min`. A low-work sync in it reads `salt`, which
    /// must be new and secret. Only the first batch on a genesis below `work_min` can start one,
    /// so a connection has at most one, and the sync moves the salt into it.
    pub(crate) fn start(
        network: crate::chainparams::Network,
        peer: std::net::SocketAddr,
        timestamp: i64,
        nonce: u64,
        work_min: crate::pow::Work,
        salt: crate::headerssync::Salt,
    ) -> (Handshake, HandshakeOutbound) {
        let ours = our_version(peer, timestamp, nonce);
        let mut payload = Vec::new();
        ours.encode(&mut payload);
        // The payload decodes to the same `version`, with no bytes left.
        let mut input = payload.as_slice();
        assert_eq!(crate::protocol::Version::decode(&mut input), Ok(ours));
        assert!(input.is_empty());

        (
            Handshake {
                state: State::AwaitingVersion,
                network,
                work_min,
                salt,
                nonce,
                message_count: 0,
            },
            HandshakeOutbound::Version(payload),
        )
    }

    /// Before their `version`, each other message is skipped. After it, each message is
    /// skipped until their `verack`, a second `version` too. Message `MESSAGE_COUNT_MAX` must
    /// be their `verack`.
    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
    ) -> Result<Step, HandshakeError> {
        assert!(self.message_count < MESSAGE_COUNT_MAX);
        let message_count = self.message_count + 1;

        match self.state {
            State::AwaitingVersion => {
                if message.msg_type() == crate::protocol::VERSION {
                    let theirs = receive_version(message, self.nonce)?;
                    let state = State::AwaitingVerack(theirs);
                    let handshake = next(
                        state,
                        self.network,
                        self.work_min,
                        self.salt,
                        self.nonce,
                        message_count,
                    )?;
                    Ok(Step::Reply(handshake, HandshakeOutbound::Verack))
                } else {
                    let state = State::AwaitingVersion;
                    let handshake = next(
                        state,
                        self.network,
                        self.work_min,
                        self.salt,
                        self.nonce,
                        message_count,
                    )?;
                    Ok(Step::Wait(handshake))
                }
            }
            State::AwaitingVerack(theirs) => {
                assert!(theirs.version >= PROTOCOL_VERSION_MIN);
                assert_ne!(theirs.nonce, self.nonce);

                if message.msg_type() == crate::protocol::VERACK {
                    let chain = crate::chain::Chain::new(self.network);
                    let download = if chain.tip().work() < self.work_min {
                        Download::Genesis(self.salt)
                    } else {
                        Download::Chain
                    };
                    let peer = Peer {
                        ping: PingState::Unsent,
                        sync: SyncState::Due(download),
                        chain,
                        work_min: self.work_min,
                    };
                    Ok(Step::Done(peer, theirs))
                } else {
                    let state = State::AwaitingVerack(theirs);
                    let handshake = next(
                        state,
                        self.network,
                        self.work_min,
                        self.salt,
                        self.nonce,
                        message_count,
                    )?;
                    Ok(Step::Wait(handshake))
                }
            }
        }
    }
}

/// The handshake after `message_count` messages, if the peer may send one more.
fn next(
    state: State,
    network: crate::chainparams::Network,
    work_min: crate::pow::Work,
    salt: crate::headerssync::Salt,
    nonce: u64,
    message_count: u32,
) -> Result<Handshake, HandshakeError> {
    if message_count < MESSAGE_COUNT_MAX {
        Ok(Handshake {
            state,
            network,
            work_min,
            salt,
            nonce,
            message_count,
        })
    } else {
        Err(HandshakeError::TooManyMessages)
    }
}

/// Every field up to `start_height` is required. The bytes after `relay` are ignored. A
/// `version` with our `nonce` is our own.
fn receive_version(
    message: &crate::transport::Message,
    nonce: u64,
) -> Result<crate::protocol::Version, HandshakeError> {
    assert_eq!(message.msg_type(), crate::protocol::VERSION);

    let mut input = message.payload();
    let theirs = crate::protocol::Version::decode(&mut input).map_err(HandshakeError::Version)?;
    if theirs.version < PROTOCOL_VERSION_MIN {
        Err(HandshakeError::Obsolete(theirs.version))
    } else if theirs.nonce == nonce {
        Err(HandshakeError::SelfConnection)
    } else {
        Ok(theirs)
    }
}

/// The peer after the handshake. Only `Handshake` makes one, so no message reaches it before
/// the handshake is complete. It does no I/O, reads no clock and draws no random number: the
/// driver gives the handshake a salt, each message with the local clock, and the instant of each
/// tick with a nonce, and sends what it returns.
#[derive(Debug)]
pub(crate) struct Peer {
    ping: PingState,
    sync: SyncState,
    /// The headers that the peer sent, on the genesis header of its network.
    chain: crate::chain::Chain,
    /// The work that `chain` must reach in the sync.
    work_min: crate::pow::Work,
}

/// Where our `ping` is. At most one is outstanding.
#[derive(Debug)]
enum PingState {
    /// No `ping` went yet. The next tick sends one.
    Unsent,
    /// Our `ping` with `nonce` went at `sent`. Its `pong` has not come.
    Outstanding {
        nonce: u64,
        sent: std::time::Instant,
    },
    /// Our last `ping` went at `sent`. Its `pong` came.
    Answered { sent: std::time::Instant },
}

/// Where the header sync is. At most one `getheaders` is outstanding.
#[derive(Debug)]
enum SyncState {
    /// Our next `getheaders` for this download is due: none went yet, or the last batch did not
    /// end the sync. The next tick sends it.
    Due(Download),
    /// Our `getheaders` for `download` went at `sent`. Its `headers` has not come.
    Outstanding {
        download: Download,
        sent: std::time::Instant,
    },
    /// A batch that was not full came, so our tip is the tip of the peer. Our chain has at least
    /// the minimum work. No `getheaders` goes again, so the chain stays the same.
    Synced,
}

/// Where the next batch of the sync goes. Only `Genesis` and `Chain` put a batch on the tip of our
/// chain as it comes. In a low-work sync our chain takes only the headers that the second download
/// releases, and they go on the tip that the first download read. So no other path may extend the
/// chain before the sync ends. The boxes keep `Genesis` and `Chain` small, because each download
/// holds its commitments and links. A sync above the minimum moves only `Chain`.
#[derive(Debug)]
enum Download {
    /// On genesis, the only header of our chain, which is below the minimum work. A full batch
    /// starts a low-work sync with the salt. Only the handshake makes this, so only the first
    /// batch of a connection can start a low-work sync.
    Genesis(crate::headerssync::Salt),
    /// On the tip of our chain, which has at least the minimum work.
    Chain,
    /// The first download of a low-work sync, on its last header.
    Presync(Box<crate::headerssync::Presync>),
    /// The second download of a low-work sync, on its last header.
    Redownload(Box<crate::headerssync::Redownload>),
}

impl Peer {
    /// A `ping` gets a `pong` with its nonce. A `pong` must answer our outstanding `ping`, and a
    /// `headers` our outstanding `getheaders`. Each other message is skipped. Each result but an
    /// error returns the peer, because an error ends the connection. `clock` is the local
    /// clock, in seconds since the Unix epoch, and only a `headers` reads it.
    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<(Peer, Received), PeerError> {
        let msg_type = message.msg_type();
        if msg_type == crate::protocol::PING {
            // The bytes after the nonce are ignored.
            let mut input = message.payload();
            let nonce = u64::decode(&mut input).map_err(PeerError::Ping)?;
            Ok((self, Received::Pong(nonce)))
        } else if msg_type == crate::protocol::PONG {
            let peer = self.receive_pong(message)?;
            Ok((peer, Received::NoReply))
        } else if msg_type == crate::protocol::HEADERS {
            self.receive_headers(message, clock)
        } else {
            Ok((self, Received::NoReply))
        }
    }

    /// The `pong` must have the nonce of our outstanding `ping`. Then no `ping` is outstanding.
    /// The bytes after the nonce are ignored.
    fn receive_pong(self, message: &crate::transport::Message) -> Result<Peer, PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::PONG);

        let mut input = message.payload();
        let theirs = u64::decode(&mut input).map_err(PeerError::Pong)?;
        match self.ping {
            PingState::Outstanding { nonce: ours, sent } => {
                if theirs == ours {
                    Ok(Peer {
                        ping: PingState::Answered { sent },
                        ..self
                    })
                } else {
                    Err(PeerError::PongNonce)
                }
            }
            PingState::Unsent | PingState::Answered { .. } => Err(PeerError::UnsolicitedPong),
        }
    }

    /// The `headers` must answer our outstanding `getheaders`, and the download of that
    /// `getheaders` must take the batch at `clock`. Then no `getheaders` is outstanding. The
    /// payload is checked first, also when no `getheaders` is outstanding. The bytes after the
    /// last transaction count are ignored.
    ///
    /// A full batch on a genesis below the minimum work starts a low-work sync with the salt, and
    /// the batch goes to its first download. Else our chain takes a batch on its tip, and then a
    /// full batch makes the next one due. A batch that is not full ends the sync, an empty one
    /// too, and the sync must end on a chain with at least the minimum work.
    ///
    /// In a low-work sync, each download makes the next batch due, until the second download
    /// reaches the minimum. Our chain takes each header that it releases, with the checks of each
    /// batch. Then the sync goes on from the tip of our chain if the batch was full, or ends.
    fn receive_headers(
        mut self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<(Peer, Received), PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::HEADERS);

        let mut input = message.payload();
        let headers = crate::protocol::Headers::decode(&mut input).map_err(PeerError::Headers)?;
        let SyncState::Outstanding { download, .. } = self.sync else {
            return Err(PeerError::UnsolicitedHeaders);
        };
        let full = headers.is_full();
        let next = match download {
            Download::Genesis(salt) => {
                receive_on_genesis(&mut self.chain, self.work_min, headers, clock, salt)?
            }
            Download::Chain => receive_on_tip(&mut self.chain, self.work_min, headers, clock)?,
            Download::Presync(presync) => {
                let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
                Some(presync_next(step))
            }
            Download::Redownload(redownload) => {
                match redownload
                    .receive(headers)
                    .map_err(PeerError::HeadersSync)?
                {
                    crate::headerssync::RedownloadStep::More(redownload, released) => {
                        extend_released(&mut self.chain, released, clock)?;
                        Some(Download::Redownload(redownload))
                    }
                    crate::headerssync::RedownloadStep::Done(released) => {
                        extend_released(&mut self.chain, released, clock)?;
                        // The second download gave each header that it checked, and it reached
                        // the minimum with them.
                        assert!(self.chain.tip().work() >= self.work_min);
                        full.then_some(Download::Chain)
                    }
                }
            }
        };
        match next {
            Some(download) => {
                self.sync = SyncState::Due(download);
                Ok((self, Received::NoReply))
            }
            None => {
                self.sync = SyncState::Synced;
                let tip = self.chain.tip();
                Ok((self, Received::Synced(tip)))
            }
        }
    }

    /// Returns the peer, what to send, and when to tick next. A `ping` with `nonce` is due at
    /// once after the handshake. Then it is due `PING_INTERVAL` after the last `ping` went, if
    /// its `pong` came. A `getheaders` is due at once after the handshake, and at once after each
    /// batch that does not end the sync. The tick fails when our outstanding `ping` is
    /// `PING_TIMEOUT` old, or our outstanding `getheaders` is `HEADERS_TIMEOUT` old. The `ping` is
    /// checked first. Each deadline is due at its instant, not after it. The wake is the earliest
    /// deadline. The `now` of a tick is not before the `now` of an earlier tick, because each
    /// deadline counts from an earlier `now`.
    pub(crate) fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(Peer, TickOutbound, std::time::Instant), PeerError> {
        let Peer {
            ping,
            sync,
            chain,
            work_min,
        } = self;
        let (ping, ping_nonce, ping_wake) = ping.tick(now, nonce)?;
        let (sync, get_headers, headers_wake) = sync.tick(now, &chain, work_min)?;
        let wake = headers_wake.map_or(ping_wake, |headers_wake| headers_wake.min(ping_wake));

        // Each `getheaders` that is due goes in this tick.
        assert!(!matches!(sync, SyncState::Due(_)));
        // A wake at or before `now` would make the driver tick again with no wait.
        assert!(wake > now);
        let outbound = TickOutbound {
            ping: ping_nonce,
            get_headers,
        };
        let peer = Peer {
            ping,
            sync,
            chain,
            work_min,
        };
        Ok((peer, outbound, wake))
    }
}

impl PingState {
    /// Returns the next state, the nonce of our `ping` if one is due, and its deadline: the
    /// ping timeout, or the next `ping` if none is outstanding.
    fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(PingState, Option<u64>, std::time::Instant), PeerError> {
        match self {
            PingState::Unsent => Ok(PingState::send(now, nonce)),
            PingState::Outstanding { sent, .. } => {
                // `sent` is the `now` of an earlier tick.
                assert!(sent <= now);
                let timeout = sent + PING_TIMEOUT;
                if now < timeout {
                    Ok((self, None, timeout))
                } else {
                    Err(PeerError::PingTimeout)
                }
            }
            PingState::Answered { sent } => {
                // `sent` is the `now` of an earlier tick.
                assert!(sent <= now);
                let due = sent + PING_INTERVAL;
                if now < due {
                    Ok((self, None, due))
                } else {
                    Ok(PingState::send(now, nonce))
                }
            }
        }
    }

    /// Our `ping` with `nonce` goes at `now`. Its deadline is its timeout.
    fn send(now: std::time::Instant, nonce: u64) -> (PingState, Option<u64>, std::time::Instant) {
        let ping = PingState::Outstanding { nonce, sent: now };
        (ping, Some(nonce), now + PING_TIMEOUT)
    }
}

impl SyncState {
    /// Returns the next state, our `getheaders` if one is due, and the headers timeout if a
    /// `getheaders` is outstanding. The `getheaders` goes from the last header of its download: the
    /// tip of `chain`, or the last header of a download of a low-work sync.
    fn tick(
        self,
        now: std::time::Instant,
        chain: &crate::chain::Chain,
        work_min: crate::pow::Work,
    ) -> Result<
        (
            SyncState,
            Option<crate::protocol::GetHeaders>,
            Option<std::time::Instant>,
        ),
        PeerError,
    > {
        match self {
            SyncState::Due(download) => {
                let after = match &download {
                    Download::Genesis(_) | Download::Chain => chain.tip().hash(),
                    Download::Presync(presync) => presync.last_hash(),
                    Download::Redownload(redownload) => redownload.last_hash(),
                };
                let get_headers = crate::protocol::GetHeaders::new(after);
                let sync = SyncState::Outstanding {
                    download,
                    sent: now,
                };
                Ok((sync, Some(get_headers), Some(now + HEADERS_TIMEOUT)))
            }
            SyncState::Outstanding { sent, .. } => {
                // `sent` is the `now` of an earlier tick.
                assert!(sent <= now);
                let timeout = sent + HEADERS_TIMEOUT;
                if now < timeout {
                    Ok((self, None, Some(timeout)))
                } else {
                    Err(PeerError::HeadersTimeout)
                }
            }
            SyncState::Synced => {
                // Only a sync that reaches the minimum work ends at `Synced`, and the work of a
                // chain does not go down.
                assert!(chain.tip().work() >= work_min);
                Ok((self, None, None))
            }
        }
    }
}

/// The first batch, on genesis, which is below `work_min`. A full batch starts a low-work sync
/// with `salt`. Our chain takes a batch that is not full, and it ends the sync, which must reach
/// `work_min`. Returns where the next batch goes, or `None` if the sync ended. A saturated work
/// means "at least the highest number", so it reaches the minimum.
fn receive_on_genesis(
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    headers: crate::protocol::Headers,
    clock: u64,
    salt: crate::headerssync::Salt,
) -> Result<Option<Download>, PeerError> {
    // Only the handshake makes `Download::Genesis`, and only on a chain below the minimum.
    assert_eq!(chain.tip().height(), 0);
    assert!(chain.tip().work() < work_min);
    if headers.is_full() {
        // The peer can make cheap headers for as long as it wants, so the chain keeps none of
        // them until the chain of the peer shows the minimum.
        let presync = crate::headerssync::Presync::new(chain, work_min, clock, salt);
        let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
        return Ok(Some(presync_next(step)));
    }
    chain.extend(headers, clock).map_err(PeerError::Extend)?;
    if chain.tip().work() >= work_min {
        Ok(None)
    } else {
        Err(PeerError::ChainWorkTooLow)
    }
}

/// A batch on the tip of `chain`, which has at least `work_min`. Returns where the next batch
/// goes, or `None` if the batch was not full and so ended the sync.
fn receive_on_tip(
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    headers: crate::protocol::Headers,
    clock: u64,
) -> Result<Option<Download>, PeerError> {
    let full = headers.is_full();
    chain.extend(headers, clock).map_err(PeerError::Extend)?;
    // Only the handshake on a chain at the minimum and a sync that reached it give
    // `Download::Chain`, and the work of a chain does not go down.
    assert!(chain.tip().work() >= work_min);
    Ok(full.then_some(Download::Chain))
}

/// Puts each header that the second download of a low-work sync released on `chain`, in order,
/// through the checks of `Chain::extend`.
fn extend_released(
    chain: &mut crate::chain::Chain,
    released: Vec<crate::block::BlockHeader>,
    clock: u64,
) -> Result<(), PeerError> {
    // The second download keeps at most `redownload_buffer_size` headers between two batches, and
    // a batch adds at most `HEADERS_COUNT_MAX`. So this bounds the loop below.
    assert!(
        released.len()
            <= chain.network().redownload_buffer_size() + crate::protocol::HEADERS_COUNT_MAX
    );
    // The second download starts on the tip of the chain, and only it extends the chain in the
    // sync. So a refusal of the first header with `NotOnTip` would be our error.
    if let Some(first) = released.first() {
        assert_eq!(first.prev, chain.tip().hash());
    }
    for batch in crate::protocol::Headers::batches(released) {
        chain.extend(batch, clock).map_err(PeerError::Extend)?;
    }
    Ok(())
}

/// Where the next batch goes after a batch of the first download of a low-work sync.
fn presync_next(step: crate::headerssync::PresyncStep) -> Download {
    match step {
        crate::headerssync::PresyncStep::More(presync) => Download::Presync(Box::new(presync)),
        crate::headerssync::PresyncStep::Redownload(redownload) => {
            Download::Redownload(Box::new(redownload))
        }
    }
}

/// The entry point of the `machines` fuzz target.
#[cfg(fuzzing)]
// Only cargo-mutants reads this attribute. Its test runs do not build this module.
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    use crate::serialize::{Decode, Encode};

    /// The network of each frame. The machines do not read the magic, so one is enough. The network
    /// of the machines comes from the script.
    const FRAME_NETWORK: crate::chainparams::Network = crate::chainparams::Network::Regtest;

    /// The address of the peer in each `version` of a script.
    const PEER_ADDRESS: std::net::SocketAddr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 18444);

    // The models take each limit from the constant that the machines use, and the seeds hold each
    // limit as a count of bytes and turns. So a new limit moves the models and not the seeds, and
    // each row can still pass: `SEED_ENDS` does not see a `PING_INTERVAL` of 119 or 121 seconds.
    // A new limit must rewrite the seeds at the limit.
    const _: () = assert!(super::PROTOCOL_VERSION_MIN == 70016);
    const _: () = assert!(super::MESSAGE_COUNT_MAX == 16);
    const _: () = assert!(super::PING_INTERVAL.as_secs() == 120);
    const _: () = assert!(super::PING_TIMEOUT.as_secs() == 1200);
    const _: () = assert!(super::HEADERS_TIMEOUT.as_secs() == 120);

    /// The count of a full batch. It is a second copy of the limit in `protocol`, so a wrong value
    /// of that limit makes the model and the machine disagree.
    const HEADERS_FULL_COUNT: usize = 2000;

    /// The most headers that one script writes. A full batch costs about 7 ms and 160 KB of chain,
    /// and a few bytes of a script ask for one. So this bounds the cost of a run.
    const SCRIPT_HEADERS_COUNT_MAX: usize = 3 * HEADERS_FULL_COUNT;

    // The seeds need two full batches and then a batch that is not empty. Below this, those batches
    // get shorter. A row fails, but a new end in that row hides the lost case.
    const _: () = assert!(SCRIPT_HEADERS_COUNT_MAX >= 2 * HEADERS_FULL_COUNT + 2);

    /// The `bits` of each header that a script writes. They are above the limit of each other
    /// network, so a script goes past its first header only on regtest. Regtest requires them at
    /// each height, so no script ends at `WrongBits`.
    const SCRIPT_HEADER_BITS: u32 = crate::chainparams::Network::Regtest.genesis().bits;

    /// The `version` of each header that a script writes. It is the lowest version that regtest
    /// takes at each height above genesis, so no script ends at `VersionTooLow`. A person wrote
    /// the 4, so another lowest version stops the build at the asserts below.
    const SCRIPT_HEADER_VERSION: i32 = 4;
    // The lowest version only rises with the height. So with the same bound at the first height
    // above genesis and at the top height, the bound is the same at each height between them.
    const _: () =
        assert!(SCRIPT_HEADER_VERSION == crate::chainparams::Network::Regtest.version_min(1));
    const _: () = assert!(
        SCRIPT_HEADER_VERSION == crate::chainparams::Network::Regtest.version_min(usize::MAX)
    );

    /// The time of the header that a script writes as its `written_count`th, from 1. Each time is
    /// one second above the last, so it is above the times of all the headers below it, and each
    /// median of those times. This reads no byte of the script, so the layout of the corpus stays.
    /// Regtest is the only network where a script goes past its first header, so this starts from
    /// the regtest genesis, and no script ends at `TimeTooOld`. The local clock of a script is the
    /// last of these times, so no script ends at `TimeTooNew`.
    fn script_header_time(written_count: usize) -> u32 {
        assert!((1..=SCRIPT_HEADERS_COUNT_MAX).contains(&written_count));
        let seconds = u32::try_from(written_count).unwrap_or(u32::MAX);
        crate::chainparams::Network::Regtest.genesis().time + seconds
    }

    /// The salt of each low-work sync. The layout has no byte for it, so the layout of the corpus
    /// stays. Each value is legal.
    const SCRIPT_SALT: crate::headerssync::Salt = crate::headerssync::Salt {
        keys: [0, 0],
        offset: 0,
    };

    /// Spreads a byte over the places of a nonce. It is odd, so each byte gives another nonce.
    const NONCE_SPREAD: u64 = 0x0123_4567_89ab_cdef;
    const _: () = assert!(NONCE_SPREAD % 2 == 1);
    const _: () = assert!(NONCE_SPREAD != NONCE_SPREAD.swap_bytes());

    /// The bit of a nonce that a `pong` byte other than 0 flips.
    const fn pong_flip_bit(byte: u8) -> u8 {
        byte % 64
    }

    // Only `pong-high-bit` flips bit 63 and only `pong-low-bit` flips bit 0, and their rows do not
    // hold the bit. A new layout that moves a bit keeps the end of the seed, so it must fail here
    // until it rewrites the seed.
    const _: () = assert!(pong_flip_bit(63) == 63);
    const _: () = assert!(pong_flip_bit(64) == 0);

    /// How a script ended. Only the tests read it, through its `Debug`.
    #[derive(Debug)]
    #[expect(dead_code)]
    enum ScriptEnd {
        /// The bytes ended in the handshake.
        HandshakeOpen,
        HandshakeRefused(super::HandshakeError),
        /// The bytes ended after the handshake.
        PeerOpen {
            height: usize,
            synced: bool,
        },
        PeerRefused(super::PeerError),
    }

    /// A seed, its bytes, and the `Debug` of its `ScriptEnd`.
    #[cfg(test)]
    macro_rules! seed {
        ($name:literal, $end:literal) => {
            (
                $name,
                include_bytes!(concat!("../fuzz/corpus/machines/", $name)).as_slice(),
                $end,
            )
        };
    }

    /// Each committed seed. Each byte string is a legal script, so a seed in an old layout runs,
    /// and the model and the machine agree. A new layout that moves the end of a seed fails here
    /// until it also rewrites that seed and its row.
    /// A new layout that keeps the end of each seed does not fail here. For example, with another
    /// network order, each seed only runs another network and keeps its end.
    // Without this, rustfmt stacks each row and the table is 223 lines.
    #[rustfmt::skip]
    #[cfg(test)]
    const SEED_ENDS: &[(&str, &[u8], &str)] = &[
        seed!("handshake-15th-is-version", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-16th-is-other", "HandshakeRefused(TooManyMessages)"),
        seed!("handshake-16th-is-other-no-version", "HandshakeRefused(TooManyMessages)"),
        seed!("handshake-16th-is-verack", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-16th-is-version", "HandshakeRefused(TooManyMessages)"),
        seed!("handshake-bytes-after-relay", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-empty-version", "HandshakeRefused(Version(UnexpectedEnd))"),
        seed!("handshake-no-message-kinds", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-no-messages", "HandshakeOpen"),
        seed!("handshake-no-relay", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-no-start-height", "HandshakeRefused(Version(UnexpectedEnd))"),
        seed!("handshake-obsolete-and-self-connection", "HandshakeRefused(Obsolete(70015))"),
        seed!("handshake-peer-messages-skipped", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-protocol-above-min", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-protocol-below-min", "HandshakeRefused(Obsolete(70015))"),
        seed!("handshake-second-version-is-skipped", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-self-connection", "HandshakeRefused(SelfConnection)"),
        seed!("handshake-skips-before-and-after-version", "PeerOpen { height: 0, synced: false }"),
        seed!("handshake-version-verack", "PeerOpen { height: 0, synced: false }"),
        seed!("headers-above-full", "PeerRefused(Headers(TooMany(2001)))"),
        seed!("headers-after-sync", "PeerRefused(UnsolicitedHeaders)"),
        seed!("headers-break-last", "PeerRefused(Extend(NotContinuous))"),
        seed!("headers-break-last-of-full", "PeerRefused(Extend(NotContinuous))"),
        seed!("headers-break-second", "PeerRefused(Extend(NotContinuous))"),
        seed!("headers-budget-ends", "PeerOpen { height: 6000, synced: true }"),
        seed!("headers-bytes-after", "PeerOpen { height: 2, synced: true }"),
        seed!("headers-cut", "PeerRefused(Headers(Payload(UnexpectedEnd)))"),
        seed!("headers-cut-after-sync", "PeerRefused(Headers(Payload(UnexpectedEnd)))"),
        seed!("headers-empty-payload", "PeerRefused(Headers(Payload(UnexpectedEnd)))"),
        seed!("headers-off-tip", "PeerRefused(Extend(NotOnTip))"),
        seed!("headers-off-tip-after-full", "PeerRefused(Extend(NotOnTip))"),
        seed!("headers-off-tip-after-sync", "PeerRefused(UnsolicitedHeaders)"),
        seed!("headers-wrong-index-past-end", "PeerOpen { height: 2, synced: true }"),
        seed!("mix-long", "PeerRefused(PingTimeout)"),
        seed!("network-mainnet", "PeerRefused(Extend(ProofOfWork))"),
        seed!("network-signet", "PeerRefused(Extend(ProofOfWork))"),
        seed!("network-testnet4", "PeerRefused(Extend(ProofOfWork))"),
        seed!("peer-skips-version-and-verack", "PeerOpen { height: 0, synced: false }"),
        seed!("ping-bytes-after", "PeerOpen { height: 0, synced: false }"),
        seed!("ping-cut", "PeerRefused(Ping(UnexpectedEnd))"),
        seed!("ping-empty", "PeerRefused(Ping(UnexpectedEnd))"),
        seed!("ping-gets-pong", "PeerOpen { height: 0, synced: false }"),
        seed!("pong-answers", "PeerOpen { height: 0, synced: false }"),
        seed!("pong-bytes-after", "PeerOpen { height: 0, synced: false }"),
        seed!("pong-cut", "PeerRefused(Pong(UnexpectedEnd))"),
        seed!("pong-cut-after-answer", "PeerRefused(Pong(UnexpectedEnd))"),
        seed!("pong-high-bit", "PeerRefused(PongNonce)"),
        seed!("pong-low-bit", "PeerRefused(PongNonce)"),
        seed!("pong-other-nonce-after-answer", "PeerRefused(UnsolicitedPong)"),
        seed!("pong-twice", "PeerRefused(UnsolicitedPong)"),
        seed!("sync-below-full", "PeerOpen { height: 1999, synced: true }"),
        seed!("sync-empty-batch", "PeerOpen { height: 0, synced: true }"),
        seed!("sync-full-full-empty", "PeerOpen { height: 4000, synced: true }"),
        seed!("sync-full-late-tick-then-empty", "PeerOpen { height: 2000, synced: true }"),
        seed!("sync-full-then-short", "PeerOpen { height: 2002, synced: true }"),
        seed!("sync-longest-short-byte", "PeerOpen { height: 252, synced: true }"),
        seed!("sync-low-work-full-mainnet", "PeerRefused(HeadersSync(ProofOfWork))"),
        seed!("sync-low-work-full-off-tip-signet", "PeerRefused(HeadersSync(NotContinuous))"),
        seed!("sync-low-work-mainnet", "PeerRefused(ChainWorkTooLow)"),
        seed!("sync-low-work-signet", "PeerRefused(ChainWorkTooLow)"),
        seed!("sync-low-work-testnet4", "PeerRefused(ChainWorkTooLow)"),
        seed!("sync-one-header", "PeerOpen { height: 1, synced: true }"),
        seed!("sync-short-batch", "PeerOpen { height: 2, synced: true }"),
        seed!("sync-then-idle-turns", "PeerOpen { height: 2, synced: true }"),
        seed!("time-after-sync-only-ping-sets-wake", "PeerOpen { height: 2, synced: true }"),
        seed!("time-answered-ping-and-headers-timeout", "PeerRefused(HeadersTimeout)"),
        seed!("time-both-timeouts-ping-first", "PeerRefused(PingTimeout)"),
        seed!("time-headers-timeout-at-wake", "PeerRefused(HeadersTimeout)"),
        seed!("time-headers-timeout-late", "PeerRefused(HeadersTimeout)"),
        seed!("time-headers-timeout-ping-not-due", "PeerRefused(HeadersTimeout)"),
        seed!("time-late-pong-next-ping-at-once", "PeerOpen { height: 0, synced: true }"),
        seed!("time-next-getheaders-before-timeout", "PeerOpen { height: 2000, synced: false }"),
        seed!("time-next-getheaders-restarts-timeout", "PeerRefused(HeadersTimeout)"),
        seed!("time-next-ping-at-interval", "PeerOpen { height: 0, synced: true }"),
        seed!("time-next-ping-before-interval", "PeerOpen { height: 0, synced: true }"),
        seed!("time-no-message-before-headers-timeout", "PeerOpen { height: 0, synced: false }"),
        seed!("time-no-second-ping-while-outstanding", "PeerOpen { height: 0, synced: true }"),
        seed!("time-ping-timeout-at-wake", "PeerRefused(PingTimeout)"),
        seed!("time-ping-timeout-late", "PeerRefused(PingTimeout)"),
        seed!("time-ping-wake-before-headers-wake", "PeerOpen { height: 2000, synced: false }"),
        seed!("time-skipped-message-moves-nothing", "PeerRefused(HeadersTimeout)"),
        seed!("time-their-ping-does-not-move-ours", "PeerRefused(PingTimeout)"),
    ];

    /// Runs `Handshake` and `Peer` on the script in `data`, in the order of the driver: a tick
    /// before each receive, and `now` never goes back. `HandshakeModel` and `PeerModel` write the
    /// doc of each function a second time, and each result must be what they expect. Each error
    /// ends the run, as it ends the connection.
    ///
    /// A script holds a network byte (`script_network`), a nonce byte for our `version`, messages
    /// until the handshake ends, and then turns. A turn holds a nonce byte for the tick, a message,
    /// and a byte for `now_next`. A read after the end of `data` gives 0. A message is a kind byte,
    /// modulo 7, then:
    ///
    /// - 0: no message.
    /// - 1: `version`. A byte to add to our nonce in the handshake, so 0 is our nonce, and an `i8`
    ///   to add to `PROTOCOL_VERSION_MIN`.
    /// - 2: `verack`.
    /// - 3: `ping`. A nonce byte.
    /// - 4: `pong` with the nonce of our last `ping`. A byte: 0 keeps the nonce, and each other
    ///   byte `b` flips bit `b % 64`.
    /// - 5: `headers`, each on the header below it, from our tip. A count byte: 253 is one above a
    ///   full batch, 254 is one below it, 255 is a full batch, and each other byte is the count.
    ///   The script stops at `SCRIPT_HEADERS_COUNT_MAX` headers, so a later batch can be shorter.
    ///   Then a byte `b`: header `b - 1` has a wrong `prev`, 255 is the last header, and 0 changes
    ///   none. The script mines each header after it picks the `prev`, so proof of work never
    ///   decides between two ends on regtest. `script_header_time` gives each time.
    /// - 6: another message type, which each machine skips.
    ///
    /// Then an `i8` to add to the length of the payload, so bytes come off its end or go after it.
    /// The committed corpus uses this layout, so a change to the layout must rewrite the corpus.
    pub fn machines(data: &[u8]) {
        machines_run(data);
    }

    /// Runs the script in `data`, and returns how it ended.
    fn machines_run(data: &[u8]) -> ScriptEnd {
        let mut script = Script {
            unread: data,
            headers_written_count: 0,
        };
        let network = script_network(script.byte());
        let nonce = script.nonce();
        // The layout has no byte for it. A value from the script still shows a fixed timestamp.
        let timestamp = nonce.cast_signed();
        let work_min = crate::pow::chain_work_min(network);
        let (handshake, outbound) = super::Handshake::start(
            network,
            PEER_ADDRESS,
            timestamp,
            nonce,
            work_min,
            SCRIPT_SALT,
        );
        machines_start_check(&outbound, timestamp, nonce);
        match handshake_run(&mut script, handshake, nonce) {
            Ok(peer) => peer_run(&mut script, peer, network),
            Err(end) => end,
        }
    }

    /// The network of a script. Its genesis header starts the chain of the peer.
    fn script_network(byte: u8) -> crate::chainparams::Network {
        match byte % 4 {
            0 => crate::chainparams::Network::Regtest,
            1 => crate::chainparams::Network::Mainnet,
            2 => crate::chainparams::Network::Testnet4,
            _ => crate::chainparams::Network::Signet,
        }
    }

    /// Checks each field of `outbound`, our `version`. It claims no services and asks for no
    /// transactions. The handshake compares their nonce with the nonce that it keeps, so `nonce`
    /// must also be on the wire.
    fn machines_start_check(outbound: &super::HandshakeOutbound, timestamp: i64, nonce: u64) {
        let super::HandshakeOutbound::Version(payload) = outbound else {
            panic!("the handshake starts with {outbound:?}");
        };
        let ours = match crate::protocol::Version::decode(&mut payload.as_slice()) {
            Ok(ours) => ours,
            Err(error) => panic!("the decode refuses our `version`: {error}"),
        };
        let no_services = crate::protocol::ServiceFlags::NONE;
        let unspecified = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0));
        let user_agent = format!("/elo:{}/", env!("CARGO_PKG_VERSION"));
        assert_eq!(ours.version, crate::protocol::PROTOCOL_VERSION);
        assert_eq!(ours.services, no_services);
        assert_eq!(ours.timestamp, timestamp);
        assert_eq!(
            ours.addr_recv,
            crate::protocol::Address::new(no_services, PEER_ADDRESS)
        );
        assert_eq!(
            ours.addr_from,
            crate::protocol::Address::new(no_services, unspecified)
        );
        assert_eq!(ours.nonce, nonce);
        assert_eq!(ours.user_agent.as_bytes(), user_agent.as_bytes());
        assert_eq!(ours.start_height, 0);
        assert!(!ours.relay);
    }

    /// Gives each message of `script` to `handshake`. Returns the peer if the handshake ended
    /// with one, or how the script ended. A message takes at least its kind byte, so the length
    /// of the script bounds the loop.
    fn handshake_run(
        script: &mut Script,
        mut handshake: super::Handshake,
        nonce: u64,
    ) -> Result<super::Peer, ScriptEnd> {
        // The handshake skips each `pong` and `headers`, so their base does not matter.
        let base = MessageBase {
            our_nonce: nonce,
            ping_nonce: 0,
            tip: bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]),
        };
        let mut model = HandshakeModel {
            nonce,
            theirs: None,
            message_count: 0,
        };
        while !script.unread.is_empty() {
            let unread_count = script.unread.len();
            let message_next = script.message(&base);
            assert!(script.unread.len() < unread_count);
            let Some(message) = message_next else {
                continue;
            };
            match (handshake.receive(&message), model.receive(&message)) {
                (Ok(super::Step::Wait(next)), Ok(HandshakeExpected::Wait)) => handshake = next,
                (
                    Ok(super::Step::Reply(next, super::HandshakeOutbound::Verack)),
                    Ok(HandshakeExpected::Reply),
                ) => handshake = next,
                (Ok(super::Step::Done(peer, theirs)), Ok(HandshakeExpected::Done(expected))) => {
                    assert_eq!(theirs, expected);
                    return Ok(peer);
                }
                (Err(error), Err(expected)) => {
                    assert_eq!(error, expected);
                    return Err(ScriptEnd::HandshakeRefused(error));
                }
                (step, expected) => panic!("the handshake gave {step:?}, not {expected:?}"),
            }
        }
        Err(ScriptEnd::HandshakeOpen)
    }

    /// Runs one turn after the other, as the driver does. Each turn takes at least one byte of
    /// the script, so the length of the script bounds the loop.
    fn peer_run(
        script: &mut Script,
        mut peer: super::Peer,
        network: crate::chainparams::Network,
    ) -> ScriptEnd {
        let mut now = std::time::Instant::now();
        // The layout has no byte for it, so the layout of the corpus stays.
        let clock = u64::from(script_header_time(SCRIPT_HEADERS_COUNT_MAX));
        let mut model = PeerModel::new(now, network);
        while !script.unread.is_empty() {
            let unread_count = script.unread.len();
            let nonce = script.nonce();
            assert!(script.unread.len() < unread_count);
            let (ticked, wake) = match peer_tick(peer, &mut model, now, nonce) {
                Ok(ticked) => ticked,
                Err(error) => return ScriptEnd::PeerRefused(error),
            };
            peer = ticked;
            // The peer skips each `version`, so its base does not matter.
            let base = MessageBase {
                our_nonce: 0,
                ping_nonce: model.ping_nonce,
                tip: model.tip,
            };
            // The wait of the driver can end with no message.
            if let Some(message) = script.message(&base) {
                peer = match peer_receive(peer, &mut model, &message, clock) {
                    Ok(received) => received,
                    Err(error) => return ScriptEnd::PeerRefused(error),
                };
            }
            now = now_next(script.byte(), now, wake);
            // The chain holds only headers that the script wrote.
            assert!(model.height <= script.headers_written_count);
        }
        ScriptEnd::PeerOpen {
            height: model.height,
            synced: model.is_synced(),
        }
    }

    /// Ticks `peer`, and checks the result against `model`. Returns the peer and its wake, or the
    /// error if the tick failed.
    fn peer_tick(
        peer: super::Peer,
        model: &mut PeerModel,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(super::Peer, std::time::Instant), super::PeerError> {
        match (peer.tick(now, nonce), model.tick(now, nonce)) {
            (Ok((peer, outbound, wake)), Ok(expected)) => {
                assert_eq!(wake, expected.wake);
                // The driver sends these, in this order.
                let mut outbounds = outbound.into_outbounds();
                if expected.ping {
                    match outbounds.next() {
                        Some(super::PeerOutbound::Ping(ping_nonce)) => {
                            assert_eq!(ping_nonce, nonce)
                        }
                        other => panic!("{other:?}, not a ping"),
                    }
                }
                if expected.get_headers {
                    match outbounds.next() {
                        Some(super::PeerOutbound::GetHeaders(get_headers)) => {
                            peer_get_headers_check(get_headers, model.tip);
                        }
                        other => panic!("{other:?}, not a getheaders"),
                    }
                }
                let extra = outbounds.next();
                assert!(extra.is_none(), "{extra:?}");
                Ok((peer, wake))
            }
            (Err(error), Err(expected)) => {
                assert_eq!(error, expected);
                Err(error)
            }
            (ticked, expected) => panic!("the tick gave {ticked:?}, not {expected:?}"),
        }
    }

    /// Checks that `get_headers` asks for the headers after `tip`, and for as many as a `headers`
    /// can carry.
    fn peer_get_headers_check(
        get_headers: crate::protocol::GetHeaders,
        tip: bitcoin_hashes::sha256d::Hash,
    ) {
        let mut encoded = Vec::new();
        get_headers.encode(&mut encoded);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::protocol::PROTOCOL_VERSION.to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(tip.as_byte_array());
        expected.extend_from_slice(&[0; 32]);
        assert_eq!(encoded, expected);
    }

    /// Gives `message` to `peer` at `clock`, and checks the result against `model`. Returns the
    /// peer, or the error if it refused the message.
    fn peer_receive(
        peer: super::Peer,
        model: &mut PeerModel,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<super::Peer, super::PeerError> {
        match (peer.receive(message, clock), model.receive(message)) {
            (Ok((peer, super::Received::NoReply)), Ok(ReceivedExpected::NoReply)) => Ok(peer),
            (Ok((peer, super::Received::Pong(nonce))), Ok(ReceivedExpected::Pong(expected))) => {
                assert_eq!(nonce, expected);
                Ok(peer)
            }
            (Ok((peer, super::Received::Synced(tip))), Ok(ReceivedExpected::Synced)) => {
                assert_eq!(tip.hash(), model.tip);
                let height = format!("{} ", model.height);
                assert!(tip.to_string().starts_with(&height), "{tip}, not {height}");
                let work_text = format!(" {:064x}", model.work());
                assert!(
                    tip.to_string().ends_with(&work_text),
                    "{tip}, not {work_text}"
                );
                Ok(peer)
            }
            (Err(error), Err(expected)) => {
                assert_eq!(error, expected);
                Err(error)
            }
            (received, expected) => panic!("the peer gave {received:?}, not {expected:?}"),
        }
    }

    /// The `now` of the next tick. A deadline is due at its instant, so a random time would almost
    /// never test it. So each kind but the first steps relative to `wake`, the earliest deadline
    /// from the last tick. `byte % 4` picks the kind, and `byte / 4` is a count of units:
    ///
    /// - 0: that many seconds after `now`, so a message that came before `wake`, or no time.
    /// - 1: just before `wake`.
    /// - 2: at `wake`.
    /// - 3: that many minutes after `wake`, so a tick that came late.
    fn now_next(byte: u8, now: std::time::Instant, wake: std::time::Instant) -> std::time::Instant {
        // `tick` asserts this. The next assert needs it for the second kind.
        assert!(now < wake);
        let unit_count = u64::from(byte / 4);
        let next = match byte % 4 {
            0 => now + std::time::Duration::from_secs(unit_count),
            1 => wake - std::time::Duration::from_nanos(1),
            2 => wake,
            _ => wake + std::time::Duration::from_mins(unit_count),
        };
        // `tick` needs this for its deadlines.
        assert!(now <= next);
        next
    }

    /// The bytes of a script that no read took yet.
    struct Script<'a> {
        unread: &'a [u8],
        /// The headers that the script wrote, at most `SCRIPT_HEADERS_COUNT_MAX`.
        headers_written_count: usize,
    }

    impl Script<'_> {
        /// The next byte, or 0 after the end of the script.
        fn byte(&mut self) -> u8 {
            let (byte, rest) = self.unread.split_first().unwrap_or((&0, &[]));
            self.unread = rest;
            *byte
        }

        fn signed_byte(&mut self) -> i8 {
            i8::from_le_bytes([self.byte()])
        }

        /// One byte, spread over the places of the nonce. The same byte in each place reads the
        /// same in both byte orders, and that hides a byte-order bug.
        fn nonce(&mut self) -> u64 {
            u64::from(self.byte()).wrapping_mul(NONCE_SPREAD)
        }

        /// The next message, as the driver reads it.
        fn message(&mut self, base: &MessageBase) -> Option<crate::transport::Message> {
            /// A type that no machine reads.
            const OTHER: crate::protocol::MessageType =
                crate::protocol::MessageType::new(*b"wtxidrelay\0\0").expect("a printable name");

            let (msg_type, mut payload) = match self.byte() % 7 {
                0 => return None,
                1 => (
                    crate::protocol::VERSION,
                    self.version_payload(base.our_nonce),
                ),
                2 => (crate::protocol::VERACK, Vec::new()),
                3 => (crate::protocol::PING, self.nonce().to_le_bytes().to_vec()),
                4 => (crate::protocol::PONG, self.pong_payload(base.ping_nonce)),
                5 => (crate::protocol::HEADERS, self.headers_payload(base.tip)),
                _ => (OTHER, Vec::new()),
            };
            let length = payload
                .len()
                .saturating_add_signed(isize::from(self.signed_byte()));
            // Not zero, so a read of these bytes as a field gives a value that shows.
            payload.resize(length, 0xaa);
            Some(message_read(msg_type, &payload))
        }

        fn version_payload(&mut self, our_nonce: u64) -> Vec<u8> {
            let their_nonce = our_nonce.wrapping_add(u64::from(self.byte()));
            let mut theirs = super::our_version(PEER_ADDRESS, 0, their_nonce);
            theirs.version = super::PROTOCOL_VERSION_MIN + i32::from(self.signed_byte());
            let mut payload = Vec::new();
            theirs.encode(&mut payload);
            payload
        }

        fn pong_payload(&mut self, ping_nonce: u64) -> Vec<u8> {
            let byte = self.byte();
            let theirs = match byte {
                0 => ping_nonce,
                _ => ping_nonce ^ (1 << pong_flip_bit(byte)),
            };
            assert_eq!(theirs == ping_nonce, byte == 0);
            theirs.to_le_bytes().to_vec()
        }

        /// A batch from `tip`. Random bytes never match the hash of the tip, so this builds each
        /// `prev`. Without this, each batch stops at `NotOnTip`.
        fn headers_payload(&mut self, tip: bitcoin_hashes::sha256d::Hash) -> Vec<u8> {
            let count_asked = match self.byte() {
                253 => HEADERS_FULL_COUNT + 1,
                254 => HEADERS_FULL_COUNT - 1,
                255 => HEADERS_FULL_COUNT,
                byte => usize::from(byte),
            };
            let count = count_asked.min(SCRIPT_HEADERS_COUNT_MAX - self.headers_written_count);
            assert!(self.headers_written_count + count <= SCRIPT_HEADERS_COUNT_MAX);
            // The loop below takes its bound from this.
            assert!(count <= HEADERS_FULL_COUNT + 1);
            let wrong_prev_index = match self.byte() {
                0 => None,
                255 => count.checked_sub(1),
                byte => Some(usize::from(byte) - 1),
            };

            let mut payload = Vec::new();
            crate::serialize::write_compact_size(&mut payload, count);
            let mut prev = tip;
            for index in 0..count {
                self.headers_written_count += 1;
                let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
                    version: SCRIPT_HEADER_VERSION,
                    prev: if Some(index) == wrong_prev_index {
                        hash_wrong(prev)
                    } else {
                        prev
                    },
                    merkle_root: [0; 32],
                    time: script_header_time(self.headers_written_count),
                    bits: SCRIPT_HEADER_BITS,
                    nonce: 0,
                });
                header.encode(&mut payload);
                crate::serialize::write_compact_size(&mut payload, 0);
                prev = header.hash();
            }
            payload
        }
    }

    /// What the messages of a script build on.
    struct MessageBase {
        /// The nonce in our `version`. A `version` starts from it.
        our_nonce: u64,
        /// The nonce of our last `ping`. A `pong` starts from it, so a `pong` can repeat.
        ping_nonce: u64,
        /// The hash of the tip of our chain. A batch starts from it.
        tip: bitcoin_hashes::sha256d::Hash,
    }

    /// `hash` with one bit of its last byte flipped, so a compare of only its start does not see
    /// it.
    fn hash_wrong(hash: bitcoin_hashes::sha256d::Hash) -> bitcoin_hashes::sha256d::Hash {
        let mut bytes = hash.to_byte_array();
        bytes[31] ^= 1;
        let wrong = bitcoin_hashes::sha256d::Hash::from_byte_array(bytes);
        assert_ne!(wrong, hash);
        wrong
    }

    /// `check_payload` is the only constructor of a `Message`, so this reads a frame as the driver
    /// does.
    fn message_read(
        msg_type: crate::protocol::MessageType,
        payload: &[u8],
    ) -> crate::transport::Message {
        let frame = crate::transport::encode(FRAME_NETWORK, msg_type, payload);
        let Some((header, read_payload)) = frame.split_first_chunk() else {
            panic!("a frame of {} bytes has no header", frame.len());
        };
        let message = crate::transport::decode_header(FRAME_NETWORK, header)
            .and_then(|header| crate::transport::check_payload(header, read_payload.to_vec()));
        match message {
            Ok(message) => {
                assert_eq!(message.msg_type(), msg_type);
                assert_eq!(message.payload(), payload);
                message
            }
            Err(error) => panic!("elo refuses a frame that it wrote: {error}"),
        }
    }

    /// What `Handshake::receive` returns, by its doc.
    struct HandshakeModel {
        nonce: u64,
        /// Their first `version`, once it came.
        theirs: Option<crate::protocol::Version>,
        message_count: u32,
    }

    /// What `Handshake::receive` returns, without the machine.
    #[derive(Debug)]
    enum HandshakeExpected {
        Wait,
        Reply,
        Done(crate::protocol::Version),
    }

    impl HandshakeModel {
        fn receive(
            &mut self,
            message: &crate::transport::Message,
        ) -> Result<HandshakeExpected, super::HandshakeError> {
            assert!(self.message_count < super::MESSAGE_COUNT_MAX);
            self.message_count += 1;
            // The handshake keeps only a `version` that it accepts.
            if let Some(theirs) = &self.theirs {
                assert!(theirs.version >= super::PROTOCOL_VERSION_MIN);
                assert_ne!(theirs.nonce, self.nonce);
            }

            let msg_type = message.msg_type();
            let expected = match &self.theirs {
                None if msg_type == crate::protocol::VERSION => {
                    let theirs = crate::protocol::Version::decode(&mut message.payload())
                        .map_err(super::HandshakeError::Version)?;
                    if theirs.version < super::PROTOCOL_VERSION_MIN {
                        return Err(super::HandshakeError::Obsolete(theirs.version));
                    }
                    if theirs.nonce == self.nonce {
                        return Err(super::HandshakeError::SelfConnection);
                    }
                    self.theirs = Some(theirs);
                    HandshakeExpected::Reply
                }
                Some(theirs) if msg_type == crate::protocol::VERACK => {
                    return Ok(HandshakeExpected::Done(theirs.clone()));
                }
                _ => HandshakeExpected::Wait,
            };
            if self.message_count < super::MESSAGE_COUNT_MAX {
                Ok(expected)
            } else {
                Err(super::HandshakeError::TooManyMessages)
            }
        }
    }

    /// What `Peer::tick` and `Peer::receive` return, by their docs. It holds deadlines, not the
    /// states of the peer, so a change to those states needs no change here.
    struct PeerModel {
        /// When our next `ping` is due, or when our outstanding one times out.
        ping_deadline: std::time::Instant,
        /// The nonce of our last `ping`. No message comes before the first tick, which sends one.
        ping_nonce: u64,
        /// The `pong` to our last `ping` has not come.
        ping_outstanding: bool,
        get_headers: GetHeadersModel,
        /// The hash and the height of the last header of the chain.
        tip: bitcoin_hashes::sha256d::Hash,
        height: usize,
        network: crate::chainparams::Network,
    }

    /// Where our `getheaders` is.
    enum GetHeadersModel {
        /// The next tick sends one.
        Due,
        /// One is outstanding, and it times out at this instant.
        Outstanding(std::time::Instant),
        /// A batch that was not full came, so none goes again.
        Ended,
    }

    /// What `Peer::tick` returns, without the peer. The tick nonce and `PeerModel::tip` give the
    /// contents of what it sends.
    #[derive(Debug)]
    struct TickExpected {
        ping: bool,
        get_headers: bool,
        wake: std::time::Instant,
    }

    /// What `Peer::receive` returns, without the peer. `PeerModel` holds the tip for `Synced`.
    #[derive(Debug)]
    enum ReceivedExpected {
        NoReply,
        Pong(u64),
        Synced,
    }

    impl PeerModel {
        /// The model of a new peer on the genesis header of `network`. Its first tick is at `now`.
        fn new(now: std::time::Instant, network: crate::chainparams::Network) -> PeerModel {
            PeerModel {
                ping_deadline: now,
                ping_nonce: 0,
                ping_outstanding: false,
                get_headers: GetHeadersModel::Due,
                tip: network.genesis().hash(),
                height: 0,
                network,
            }
        }

        fn is_synced(&self) -> bool {
            matches!(self.get_headers, GetHeadersModel::Ended)
        }

        fn tick(
            &mut self,
            now: std::time::Instant,
            nonce: u64,
        ) -> Result<TickExpected, super::PeerError> {
            // The `ping` is checked first, as the doc of `Peer::tick` says.
            let ping = if now < self.ping_deadline {
                false
            } else if self.ping_outstanding {
                return Err(super::PeerError::PingTimeout);
            } else {
                true
            };
            let (get_headers, headers_deadline) = match self.get_headers {
                GetHeadersModel::Due => (true, Some(now + super::HEADERS_TIMEOUT)),
                GetHeadersModel::Outstanding(deadline) if now < deadline => (false, Some(deadline)),
                GetHeadersModel::Outstanding(_) => return Err(super::PeerError::HeadersTimeout),
                GetHeadersModel::Ended => (false, None),
            };

            if ping {
                self.ping_nonce = nonce;
                self.ping_outstanding = true;
                self.ping_deadline = now + super::PING_TIMEOUT;
            }
            self.get_headers =
                headers_deadline.map_or(GetHeadersModel::Ended, GetHeadersModel::Outstanding);
            let wake = headers_deadline.map_or(self.ping_deadline, |deadline| {
                deadline.min(self.ping_deadline)
            });
            assert!(now < wake);
            Ok(TickExpected {
                ping,
                get_headers,
                wake,
            })
        }

        fn receive(
            &mut self,
            message: &crate::transport::Message,
        ) -> Result<ReceivedExpected, super::PeerError> {
            let msg_type = message.msg_type();
            if msg_type == crate::protocol::PING {
                let nonce = message_nonce(message).map_err(super::PeerError::Ping)?;
                Ok(ReceivedExpected::Pong(nonce))
            } else if msg_type == crate::protocol::PONG {
                let theirs = message_nonce(message).map_err(super::PeerError::Pong)?;
                if !self.ping_outstanding {
                    Err(super::PeerError::UnsolicitedPong)
                } else if theirs != self.ping_nonce {
                    Err(super::PeerError::PongNonce)
                } else {
                    self.ping_outstanding = false;
                    // The deadline was `sent + PING_TIMEOUT`. It is now `sent + PING_INTERVAL`.
                    self.ping_deadline -= super::PING_TIMEOUT - super::PING_INTERVAL;
                    Ok(ReceivedExpected::NoReply)
                }
            } else if msg_type == crate::protocol::HEADERS {
                self.receive_headers(message)
            } else {
                Ok(ReceivedExpected::NoReply)
            }
        }

        fn receive_headers(
            &mut self,
            message: &crate::transport::Message,
        ) -> Result<ReceivedExpected, super::PeerError> {
            let headers = crate::protocol::Headers::decode(&mut message.payload())
                .map_err(super::PeerError::Headers)?
                .into_vec();
            assert!(headers.len() <= HEADERS_FULL_COUNT);
            let GetHeadersModel::Outstanding(_) = self.get_headers else {
                return Err(super::PeerError::UnsolicitedHeaders);
            };
            if headers.len() == HEADERS_FULL_COUNT && self.work() < chain_work_min(self.network) {
                // A low-work sync starts, and its first download checks the batch. Only off
                // regtest is a chain below the minimum, and there no script header passes. So the
                // first header gives the error: its `prev` first, then its proof of work.
                assert_ne!(self.network, crate::chainparams::Network::Regtest);
                let error = match headers.first() {
                    Some(first) if first.prev == self.tip => {
                        crate::headerssync::HeadersSyncError::ProofOfWork
                    }
                    _ => crate::headerssync::HeadersSyncError::NotContinuous,
                };
                return Err(super::PeerError::HeadersSync(error));
            }

            let mut tip = self.tip;
            for (index, header) in headers.iter().enumerate() {
                if header.prev == tip {
                    // A script mines each header for regtest, and `SCRIPT_HEADER_BITS` are above
                    // each other limit. So only regtest takes what a script writes. A new script
                    // byte that writes other headers fails here, and must change this model.
                    assert_eq!(header.bits, SCRIPT_HEADER_BITS);
                    assert_eq!(header.version, SCRIPT_HEADER_VERSION);
                    assert!(header.hash().as_byte_array()[31] < 0x7f);
                    if self.network != crate::chainparams::Network::Regtest {
                        return Err(super::PeerError::Extend(
                            crate::chain::ExtendError::ProofOfWork,
                        ));
                    }
                    tip = header.hash();
                } else if index == 0 {
                    return Err(super::PeerError::Extend(
                        crate::chain::ExtendError::NotOnTip,
                    ));
                } else {
                    return Err(super::PeerError::Extend(
                        crate::chain::ExtendError::NotContinuous,
                    ));
                }
            }
            // Only an empty batch keeps the tip.
            assert_eq!(tip == self.tip, headers.is_empty());
            self.tip = tip;
            self.height += headers.len();
            if headers.len() == HEADERS_FULL_COUNT {
                self.get_headers = GetHeadersModel::Due;
                Ok(ReceivedExpected::NoReply)
            } else if self.work() >= chain_work_min(self.network) {
                self.get_headers = GetHeadersModel::Ended;
                Ok(ReceivedExpected::Synced)
            } else {
                Err(super::PeerError::ChainWorkTooLow)
            }
        }

        /// The work of the chain. A person wrote the work of each genesis. Each script header has
        /// the regtest limit, whose work is 2, and off regtest no script header passes. A height
        /// has at most 64 bits, so the work fits a `u128` with no overflow.
        fn work(&self) -> u128 {
            let genesis_work: u128 = match self.network {
                crate::chainparams::Network::Mainnet | crate::chainparams::Network::Testnet4 => {
                    0x1_0001_0001
                }
                crate::chainparams::Network::Signet => 0x49_d414,
                crate::chainparams::Network::Regtest => 2,
            };
            const { assert!(usize::BITS <= 64) };
            genesis_work + self.height as u128 * 2
        }
    }

    /// The lowest work of a chain at the end of a sync. A person wrote each minimum. Each one but
    /// regtest is above the work of its genesis, and off regtest no script header passes. So off
    /// regtest each sync that a script ends fails.
    fn chain_work_min(network: crate::chainparams::Network) -> u128 {
        match network {
            crate::chainparams::Network::Mainnet => 0x1_1287_50f8_2f4c_3661_53a3_a030,
            crate::chainparams::Network::Testnet4 => 0x9a0_fe15_d017_7d08_6304,
            crate::chainparams::Network::Signet => 0xb46_3ea0_a4b8,
            crate::chainparams::Network::Regtest => 0,
        }
    }

    /// The first 8 bytes of the payload, little-endian. Each byte after them is ignored.
    fn message_nonce(message: &crate::transport::Message) -> Result<u64, crate::serialize::Error> {
        match message.payload().first_chunk() {
            Some(nonce) => Ok(u64::from_le_bytes(*nonce)),
            None => Err(crate::serialize::Error::UnexpectedEnd),
        }
    }

    #[cfg(test)]
    mod tests {
        /// A row with no seed stops the build, so only this sees a new seed. It reads the
        /// directory, so it also fails on the new inputs of a random run. Only tracked files
        /// reach the `elo-fuzz` gate.
        #[test]
        fn each_seed_has_a_row() {
            let directory = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus/machines");
            let no_row: Vec<_> = std::fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .filter(|seed| !super::SEED_ENDS.iter().any(|row| row.0 == seed))
                .collect();
            assert!(no_row.is_empty(), "seeds with no row: {no_row:?}");
        }

        /// This prints each wrong row, because a new layout moves the ends of many seeds.
        #[test]
        fn each_seed_ends_as_its_row_says() {
            let wrong: Vec<_> = super::SEED_ENDS
                .iter()
                .filter_map(|(name, bytes, expected)| {
                    let end = format!("{:?}", super::machines_run(bytes));
                    (end != *expected).then(|| format!("{name}: {end}, not {expected}"))
                })
                .collect();
            assert!(wrong.is_empty(), "{}", wrong.join("\n"));
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::Decode;

    /// The message in a regtest frame, as the driver reads it.
    fn message(frame: &[u8]) -> crate::transport::Message {
        let (header, payload) = frame.split_first_chunk().unwrap();
        let header =
            crate::transport::decode_header(crate::chainparams::Network::Regtest, header).unwrap();
        crate::transport::check_payload(header, payload.to_vec()).unwrap()
    }

    fn core_message(frame: &str) -> crate::transport::Message {
        message(&crate::fixtures::hex(frame))
    }

    /// A `version` with Core's payload after `change`.
    fn version_message(change: impl FnOnce(&mut Vec<u8>)) -> crate::transport::Message {
        let mut payload = crate::fixtures::version_payload();
        change(&mut payload);
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::VERSION,
            &payload,
        ))
    }

    /// A `ping` with Core's payload after `change`.
    fn ping_message(change: impl FnOnce(&mut Vec<u8>)) -> crate::transport::Message {
        let mut payload = crate::fixtures::hex(crate::fixtures::PING_FRAME)
            .split_off(crate::transport::MESSAGE_HEADER_SIZE);
        change(&mut payload);
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::PING,
            &payload,
        ))
    }

    /// A `pong` with `payload`.
    fn pong_message(payload: &[u8]) -> crate::transport::Message {
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::PONG,
            payload,
        ))
    }

    /// A `pong` with `nonce`.
    fn pong(nonce: u64) -> crate::transport::Message {
        pong_message(&nonce.to_le_bytes())
    }

    /// A `headers` with `payload`.
    fn headers_payload_message(payload: &[u8]) -> crate::transport::Message {
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::HEADERS,
            payload,
        ))
    }

    /// A `headers` with `headers`, each with a transaction count of 0.
    fn headers_message(headers: &[crate::block::BlockHeader]) -> crate::transport::Message {
        headers_payload_message(&crate::fixtures::headers_payload_with(headers))
    }

    /// The tip of a second regtest chain, after `headers`, in batches of 2,000.
    fn tip_after(headers: &[crate::block::BlockHeader]) -> crate::chain::Tip {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        for batch in headers.chunks(2_000) {
            chain
                .extend(
                    crate::fixtures::headers_batch(batch),
                    crate::fixtures::CLOCK,
                )
                .unwrap();
        }
        chain.tip()
    }

    /// The peer after the first tick at `now` of a regtest peer whose sync must reach `work_min`.
    fn asked_with(work_min: crate::pow::Work, now: std::time::Instant) -> super::Peer {
        let handshake = start_with(crate::chainparams::Network::Regtest, work_min);
        asked_from(peer_with(handshake), now, 7)
    }

    /// `peer` takes `headers` with no reply, and then a tick at `now` sends our next
    /// `getheaders`. Returns the peer, and the hash that the `getheaders` asks after.
    fn batch_then_tick(
        peer: super::Peer,
        headers: &[crate::block::BlockHeader],
        now: std::time::Instant,
    ) -> (super::Peer, crate::protocol::GetHeaders) {
        let peer = accept(peer, &headers_message(headers));
        match peer.tick(now, 8) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: None,
                    get_headers: Some(get_headers),
                },
                _,
            )) => (peer, get_headers),
            other => panic!("{other:?}"),
        }
    }

    /// The `getheaders` that asks for the headers after `header`.
    fn get_headers_after(header: &crate::block::BlockHeader) -> crate::protocol::GetHeaders {
        crate::protocol::GetHeaders::new(header.hash())
    }

    fn start() -> super::Handshake {
        start_on(crate::chainparams::Network::Regtest)
    }

    /// The handshake with a peer on `network`, with the minimum work of the network. The machines
    /// do not read the magic, so the frames of the tests can stay on regtest.
    fn start_on(network: crate::chainparams::Network) -> super::Handshake {
        start_with(network, crate::pow::chain_work_min(network))
    }

    /// `start_on`, with a sync that must reach `work_min`.
    fn start_with(
        network: crate::chainparams::Network,
        work_min: crate::pow::Work,
    ) -> super::Handshake {
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        super::Handshake::start(network, peer, 0, 0, work_min, SALT).0
    }

    fn wait(step: Result<super::Step, super::HandshakeError>) -> super::Handshake {
        match step {
            Ok(super::Step::Wait(handshake)) => handshake,
            other => panic!("{other:?}"),
        }
    }

    fn reply(
        step: Result<super::Step, super::HandshakeError>,
    ) -> (super::Handshake, super::HandshakeOutbound) {
        match step {
            Ok(super::Step::Reply(handshake, outbound)) => (handshake, outbound),
            other => panic!("{other:?}"),
        }
    }

    /// The peer as the handshake makes it, after Core's `version` and `verack`.
    fn peer() -> super::Peer {
        peer_on(crate::chainparams::Network::Regtest)
    }

    /// `peer`, on `network`.
    fn peer_on(network: crate::chainparams::Network) -> super::Peer {
        peer_with(start_on(network))
    }

    /// The peer that `handshake` makes after Core's `version` and `verack`.
    fn peer_with(handshake: super::Handshake) -> super::Peer {
        let (handshake, _) =
            reply(handshake.receive(&core_message(crate::fixtures::VERSION_FRAME)));
        match handshake.receive(&core_message(crate::fixtures::VERACK_FRAME)) {
            Ok(super::Step::Done(peer, _)) => peer,
            other => panic!("{other:?}"),
        }
    }

    /// The peer after its first tick at `now`, which sent our `ping` with `nonce` and our
    /// `getheaders`.
    fn asked(now: std::time::Instant, nonce: u64) -> super::Peer {
        asked_on(crate::chainparams::Network::Regtest, now, nonce)
    }

    /// `asked`, on `network`.
    fn asked_on(
        network: crate::chainparams::Network,
        now: std::time::Instant,
        nonce: u64,
    ) -> super::Peer {
        asked_from(peer_on(network), now, nonce)
    }

    /// `peer` after its first tick at `now`, as in `asked`.
    fn asked_from(peer: super::Peer, now: std::time::Instant, nonce: u64) -> super::Peer {
        match peer.tick(now, nonce) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: Some(sent),
                    get_headers: Some(_),
                },
                _,
            )) if sent == nonce => peer,
            other => panic!("{other:?}"),
        }
    }

    /// The peer after `asked`, and after an empty `headers` that ended the sync. So only our
    /// `ping` with `nonce` is outstanding.
    fn pinged(now: std::time::Instant, nonce: u64) -> super::Peer {
        match asked(now, nonce).receive(&headers_message(&[]), crate::fixtures::CLOCK) {
            Ok((peer, super::Received::Synced(_))) => peer,
            other => panic!("{other:?}"),
        }
    }

    /// A tick at `now` that sends nothing. Returns the peer and when to tick next.
    fn idle(peer: super::Peer, now: std::time::Instant) -> (super::Peer, std::time::Instant) {
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: None,
                    get_headers: None,
                },
                wake,
            )) => (peer, wake),
            other => panic!("{other:?}"),
        }
    }

    /// A message that the peer accepts with no reply.
    fn accept(peer: super::Peer, message: &crate::transport::Message) -> super::Peer {
        match peer.receive(message, crate::fixtures::CLOCK) {
            Ok((peer, super::Received::NoReply)) => peer,
            other => panic!("{other:?}"),
        }
    }

    const NANOSECOND: std::time::Duration = std::time::Duration::from_nanos(1);

    /// The salt of each test. A low-work sync passes or fails the same with each salt, when the
    /// peer sends the same chain twice.
    const SALT: crate::headerssync::Salt = crate::headerssync::Salt {
        keys: [1, 2],
        offset: 3,
    };

    #[test]
    fn handshake_skips_until_their_version_and_then_until_their_verack() {
        let handshake = wait(start().receive(&core_message(crate::fixtures::VERACK_FRAME)));
        let (mut handshake, outbound) =
            reply(handshake.receive(&core_message(crate::fixtures::VERSION_FRAME)));
        assert!(
            matches!(outbound, super::HandshakeOutbound::Verack),
            "{outbound:?}"
        );

        // A peer may send `wtxidrelay` and `sendaddrv2` before its `verack`. A second `version` is
        // skipped without a decode, so an empty payload passes.
        for message in [
            core_message(crate::fixtures::WTXIDRELAY_FRAME),
            core_message(crate::fixtures::SENDADDRV2_FRAME),
            version_message(Vec::clear),
        ] {
            handshake = wait(handshake.receive(&message));
        }

        let theirs =
            crate::protocol::Version::decode(&mut crate::fixtures::version_payload().as_slice());
        match handshake.receive(&core_message(crate::fixtures::VERACK_FRAME)) {
            Ok(super::Step::Done(_, version)) => assert_eq!(Ok(version), theirs),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn peer_without_its_verack_in_message_count_max_is_too_many_messages() {
        // The peer sends `MESSAGE_COUNT_MAX` messages: their `version`, `wtxidrelay` frames
        // and a last one. A `verack` as the last completes the handshake. One more
        // `wtxidrelay` in its place is refused.
        let wtxidrelay = core_message(crate::fixtures::WTXIDRELAY_FRAME);
        let before_the_last = || {
            let (mut handshake, _) =
                reply(start().receive(&core_message(crate::fixtures::VERSION_FRAME)));
            for _ in 2..super::MESSAGE_COUNT_MAX {
                handshake = wait(handshake.receive(&wtxidrelay));
            }
            handshake
        };

        let verack = core_message(crate::fixtures::VERACK_FRAME);
        let done = before_the_last().receive(&verack);
        assert!(matches!(done, Ok(super::Step::Done(..))), "{done:?}");
        let refused = before_the_last().receive(&wtxidrelay).err();
        assert_eq!(refused, Some(super::HandshakeError::TooManyMessages));
    }

    #[test]
    fn their_version_is_at_least_protocol_version_min() {
        for (version, expected) in [
            (super::PROTOCOL_VERSION_MIN, Ok(())),
            (
                super::PROTOCOL_VERSION_MIN - 1,
                Err(super::HandshakeError::Obsolete(
                    super::PROTOCOL_VERSION_MIN - 1,
                )),
            ),
        ] {
            let message = version_message(|payload| {
                payload[..size_of::<i32>()].copy_from_slice(&version.to_le_bytes());
            });
            let outcome = start().receive(&message).map(|step| {
                reply(Ok(step));
            });
            assert_eq!(outcome, expected, "version {version}");
        }
    }

    #[test]
    fn their_version_with_our_nonce_is_self_connection() {
        // A socket that is connected to itself reads our `version` back.
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        let (handshake, outbound) = super::Handshake::start(
            crate::chainparams::Network::Regtest,
            peer,
            0,
            0x0123_4567_89ab_cdef,
            crate::pow::chain_work_min(crate::chainparams::Network::Regtest),
            SALT,
        );
        let super::HandshakeOutbound::Version(payload) = outbound else {
            panic!("{outbound:?}");
        };
        let ours = message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::VERSION,
            &payload,
        ));
        assert_eq!(
            handshake.receive(&ours).err(),
            Some(super::HandshakeError::SelfConnection)
        );
    }

    #[test]
    fn their_version_needs_start_height_and_may_have_bytes_after_relay() {
        let truncated = version_message(|payload| {
            payload.truncate(payload.len() - size_of::<i32>() - size_of::<bool>());
        });
        assert_eq!(
            start().receive(&truncated).err(),
            Some(super::HandshakeError::Version(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = version_message(|payload| payload.push(0xaa));
        reply(start().receive(&longer));
    }

    #[test]
    fn their_ping_gets_a_pong_with_its_nonce() {
        let outbound = peer().receive(
            &core_message(crate::fixtures::PING_FRAME),
            crate::fixtures::CLOCK,
        );
        assert!(
            matches!(
                outbound,
                Ok((_, super::Received::Pong(0x34e9_3229_8920_45d8)))
            ),
            "{outbound:?}"
        );
    }

    #[test]
    fn their_ping_needs_a_nonce_and_may_have_bytes_after_it() {
        let short = ping_message(|payload| payload.truncate(size_of::<u64>() - 1));
        assert_eq!(
            peer().receive(&short, crate::fixtures::CLOCK).err(),
            Some(super::PeerError::Ping(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = ping_message(|payload| payload.push(0xaa));
        let outbound = peer().receive(&longer, crate::fixtures::CLOCK);
        assert!(
            matches!(
                outbound,
                Ok((_, super::Received::Pong(0x34e9_3229_8920_45d8)))
            ),
            "{outbound:?}"
        );
    }

    #[test]
    fn their_ping_gets_a_pong_while_our_ping_is_outstanding() {
        // Their `ping` does not touch ours: it still times out at `PING_TIMEOUT`.
        let start = std::time::Instant::now();
        let outbound = pinged(start, 7).receive(
            &core_message(crate::fixtures::PING_FRAME),
            crate::fixtures::CLOCK,
        );
        let Ok((peer, super::Received::Pong(0x34e9_3229_8920_45d8))) = outbound else {
            panic!("{outbound:?}");
        };
        let ticked = peer.tick(start + super::PING_TIMEOUT, 8).err();
        assert_eq!(ticked, Some(super::PeerError::PingTimeout));
    }

    #[test]
    fn first_tick_sends_a_ping_then_getheaders_from_genesis() {
        let start = std::time::Instant::now();
        let ticked = peer().tick(start, 7);
        let Ok((_, outbound, wake)) = ticked else {
            panic!("{ticked:?}");
        };
        let outbounds: Vec<_> = outbound.into_outbounds().collect();
        let genesis = crate::protocol::GetHeaders::new(tip_after(&[]).hash());
        assert!(
            matches!(
                outbounds[..],
                [
                    super::PeerOutbound::Ping(7),
                    super::PeerOutbound::GetHeaders(get_headers),
                ] if get_headers == genesis
            ),
            "{outbounds:?}"
        );
        // The headers timeout comes before the ping timeout.
        assert_eq!(wake, start + super::HEADERS_TIMEOUT);
    }

    #[test]
    fn no_second_ping_while_one_is_outstanding() {
        // `PING_INTERVAL` after the send, a `ping` is due only if its `pong` came.
        let start = std::time::Instant::now();
        let (_, wake) = idle(pinged(start, 7), start + super::PING_INTERVAL);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn next_ping_is_due_ping_interval_after_the_last_ping_went() {
        // The `pong` came at once: the next `ping` waits until `PING_INTERVAL` after ours went.
        let start = std::time::Instant::now();
        let due = start + super::PING_INTERVAL;
        let peer = accept(pinged(start, 7), &pong(7));
        let (peer, wake) = idle(peer, due - NANOSECOND);
        assert_eq!(wake, due);
        let ticked = peer.tick(due, 8);
        let Ok((
            _,
            super::TickOutbound {
                ping: Some(8),
                get_headers: None,
            },
            wake,
        )) = ticked
        else {
            panic!("{ticked:?}");
        };
        assert_eq!(wake, due + super::PING_TIMEOUT);

        // The `pong` came after `PING_INTERVAL`: the next `ping` is due at once.
        let late = due + std::time::Duration::from_mins(1);
        let (peer, _) = idle(pinged(start, 7), late);
        let ticked = accept(peer, &pong(7)).tick(late, 8);
        assert!(
            matches!(
                ticked,
                Ok((
                    _,
                    super::TickOutbound {
                        ping: Some(8),
                        get_headers: None
                    },
                    _
                ))
            ),
            "{ticked:?}"
        );
    }

    #[test]
    fn ping_without_its_pong_for_ping_timeout_is_ping_timeout() {
        let start = std::time::Instant::now();
        let timeout = start + super::PING_TIMEOUT;
        let (peer, wake) = idle(pinged(start, 7), timeout - NANOSECOND);
        assert_eq!(wake, timeout);
        assert_eq!(
            peer.tick(timeout, 8).err(),
            Some(super::PeerError::PingTimeout)
        );
    }

    #[test]
    fn their_pong_needs_a_nonce_and_may_have_bytes_after_it() {
        let start = std::time::Instant::now();
        // The payload is checked first, also when no `ping` is outstanding.
        let short = pong_message(&7_u64.to_le_bytes()[..size_of::<u64>() - 1]);
        for peer in [peer(), pinged(start, 7)] {
            assert_eq!(
                peer.receive(&short, crate::fixtures::CLOCK).err(),
                Some(super::PeerError::Pong(
                    crate::serialize::Error::UnexpectedEnd
                ))
            );
        }

        let mut longer = 7_u64.to_le_bytes().to_vec();
        longer.push(0xaa);
        accept(pinged(start, 7), &pong_message(&longer));
    }

    #[test]
    fn pong_without_our_ping_is_unsolicited_pong() {
        // Before our first `ping`, and after the `pong` to our last one.
        let start = std::time::Instant::now();
        let answered = accept(pinged(start, 7), &pong(7));
        for peer in [peer(), answered] {
            assert_eq!(
                peer.receive(&pong(7), crate::fixtures::CLOCK).err(),
                Some(super::PeerError::UnsolicitedPong)
            );
        }
    }

    #[test]
    fn pong_with_another_nonce_is_pong_nonce() {
        let start = std::time::Instant::now();
        assert_eq!(
            pinged(start, 7)
                .receive(&pong(8), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::PongNonce)
        );
    }

    #[test]
    fn peer_skips_every_message_but_ping_pong_and_headers() {
        // Core sends `sendcmpct` and `feefilter` after the handshake, and a block `inv` for each
        // new tip. elo answers no `getheaders`. The messages of the handshake are skipped too. A
        // `version` is skipped without a decode, so an empty payload passes.
        for message in [
            core_message(crate::fixtures::SENDCMPCT_FRAME),
            core_message(crate::fixtures::FEEFILTER_FRAME),
            core_message(crate::fixtures::BLOCK_INV_FRAME),
            core_message(crate::fixtures::GETHEADERS_FRAME),
            version_message(Vec::clear),
            core_message(crate::fixtures::VERACK_FRAME),
            core_message(crate::fixtures::WTXIDRELAY_FRAME),
            core_message(crate::fixtures::SENDADDRV2_FRAME),
        ] {
            let outbound = peer().receive(&message, crate::fixtures::CLOCK);
            assert!(
                matches!(outbound, Ok((_, super::Received::NoReply))),
                "{:?}: {outbound:?}",
                message.msg_type()
            );
        }
    }

    #[test]
    fn full_batch_makes_the_next_tick_send_getheaders_from_the_new_tip() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2000);
        let peer = accept(asked(start, 7), &headers_message(&headers));

        // The headers timeout starts again with the new `getheaders`.
        let later = start + std::time::Duration::from_mins(1);
        let ticked = peer.tick(later, 8);
        let Ok((
            _,
            super::TickOutbound {
                ping: None,
                get_headers: Some(get_headers),
            },
            wake,
        )) = ticked
        else {
            panic!("{ticked:?}");
        };
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(tip_after(&headers).hash())
        );
        assert_eq!(wake, later + super::HEADERS_TIMEOUT);
    }

    #[test]
    fn short_batch_ends_the_sync_at_its_last_header() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let received = asked(start, 7).receive(&headers_message(&headers), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn empty_batch_ends_the_sync_at_our_tip() {
        // The empty batch comes after a full batch, so our tip is not genesis.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2000);
        let peer = accept(asked(start, 7), &headers_message(&headers));
        let ticked = peer.tick(start, 8);
        let Ok((peer, _, _)) = ticked else {
            panic!("{ticked:?}");
        };

        let received = peer.receive(&headers_message(&[]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn sync_that_ends_below_the_minimum_work_ends_the_connection() {
        // Genesis has less work than the minimum of each network but regtest, and the empty batch
        // ends the sync on it. Regtest has a minimum of zero, so the same batch ends its sync.
        let start = std::time::Instant::now();
        for (network, expected) in [
            (crate::chainparams::Network::Mainnet, false),
            (crate::chainparams::Network::Testnet4, false),
            (crate::chainparams::Network::Signet, false),
            (crate::chainparams::Network::Regtest, true),
        ] {
            let received =
                asked_on(network, start, 7).receive(&headers_message(&[]), crate::fixtures::CLOCK);
            match received {
                Ok((_, super::Received::Synced(_))) => assert!(expected, "{network:?}"),
                Err(super::PeerError::ChainWorkTooLow) => assert!(!expected, "{network:?}"),
                other => panic!("{network:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn sync_that_ends_at_the_minimum_work_ends_there() {
        // A short batch on our tip, so no low-work sync starts.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let work_min = tip_after(&headers).work();
        let received =
            asked_with(work_min, start).receive(&headers_message(&headers), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn full_batch_on_a_chain_at_the_minimum_work_goes_on_the_chain() {
        // The work of genesis is the minimum, so no low-work sync starts. Our chain takes the full
        // batch, and the next one goes on it.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_002);
        let work_min = tip_after(&[]).work();
        let (peer, get_headers) =
            batch_then_tick(asked_with(work_min, start), &headers[..2_000], start);
        assert_eq!(get_headers, get_headers_after(&headers[1_999]));
        let received = peer.receive(&headers_message(&headers[2_000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn full_batch_below_the_minimum_work_starts_a_sync_that_gets_the_chain_twice() {
        // The chain reaches the minimum at height 11,000, in the 6th batch. The second download
        // holds 7,017 headers on regtest, so our chain gets the first 2,983 after its 5th batch,
        // and the rest after its 6th. That batch is full, so the sync goes on from our tip.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(12_002);
        let work_min = tip_after(&headers[..11_000]).work();
        let batches: Vec<_> = headers[..12_000].chunks(2_000).collect();
        let mut peer = asked_with(work_min, start);
        // The first download keeps no header, so each `getheaders` goes from its last header. The
        // last batch reaches the minimum, so the second download starts on our tip.
        for (index, batch) in batches.iter().enumerate() {
            let get_headers;
            (peer, get_headers) = batch_then_tick(peer, batch, start);
            let expected = match batches.get(index + 1) {
                Some(_) => get_headers_after(&batch[1_999]),
                None => crate::protocol::GetHeaders::new(tip_after(&[]).hash()),
            };
            assert_eq!(get_headers, expected, "first download, batch {index}");
        }
        for (index, batch) in batches.iter().enumerate() {
            let get_headers;
            (peer, get_headers) = batch_then_tick(peer, batch, start);
            assert_eq!(
                get_headers,
                get_headers_after(&batch[1_999]),
                "second download, batch {index}"
            );
        }
        let received = peer.receive(&headers_message(&headers[12_000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn low_work_sync_that_reaches_the_minimum_in_a_short_batch_ends_there() {
        // The work of the chain is the minimum. Both downloads take the short batch.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3_500);
        let work_min = tip_after(&headers).work();
        let (peer, _) = batch_then_tick(asked_with(work_min, start), &headers[..2_000], start);
        let (peer, _) = batch_then_tick(peer, &headers[2_000..], start);
        let (peer, _) = batch_then_tick(peer, &headers[..2_000], start);
        let received = peer.receive(&headers_message(&headers[2_000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn low_work_sync_that_refuses_a_batch_ends_the_connection() {
        // The second batch of the first download is the first batch again, so it is not on the
        // last header.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_000);
        let work_min = tip_after(&headers)
            .work()
            .saturating_add(tip_after(&[]).work());
        let (peer, _) = batch_then_tick(asked_with(work_min, start), &headers, start);
        assert_eq!(
            peer.receive(&headers_message(&headers), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::HeadersSync(
                crate::headerssync::HeadersSyncError::NotContinuous
            ))
        );
    }

    #[test]
    fn each_header_that_a_low_work_sync_releases_goes_through_the_checks_of_the_chain() {
        // Header 2,001 has version 1, below the lowest version of regtest. Only the chain checks
        // the version, so both downloads take it, and the chain refuses the second batch that the
        // second download released.
        let start = std::time::Instant::now();
        let first = crate::fixtures::headers_on_genesis(2_000);
        let below = &first[1_999];
        let old = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            version: 1,
            prev: below.hash(),
            time: below.time + 1,
            ..*below
        });
        let rest = crate::fixtures::headers_on(&old, 1_999);
        let second = [&[old][..], &rest].concat();
        // Each regtest header has the same work, so the work of 3,000 other headers is the work
        // of this chain at that height.
        let work_min = tip_after(&crate::fixtures::headers_on_genesis(3_000)).work();
        let (peer, _) = batch_then_tick(asked_with(work_min, start), &first, start);
        let (peer, _) = batch_then_tick(peer, &second, start);
        let (peer, _) = batch_then_tick(peer, &first, start);
        assert_eq!(
            peer.receive(&headers_message(&second), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Extend(
                crate::chain::ExtendError::VersionTooLow
            ))
        );
    }

    #[test]
    fn no_getheaders_after_the_sync() {
        // After the sync, only our `ping` sets the wake, and no headers timeout is left.
        let start = std::time::Instant::now();
        let later = start + std::time::Duration::from_mins(10);
        let (_, wake) = idle(pinged(start, 7), later);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn headers_without_our_getheaders_is_unsolicited_headers() {
        // Before our first `getheaders`, and after the sync.
        let start = std::time::Instant::now();
        for peer in [peer(), pinged(start, 7)] {
            assert_eq!(
                peer.receive(&headers_message(&[]), crate::fixtures::CLOCK)
                    .err(),
                Some(super::PeerError::UnsolicitedHeaders)
            );
        }
    }

    #[test]
    fn their_headers_payload_is_checked_first() {
        // The payload has no count. It fails also when no `getheaders` is outstanding.
        let start = std::time::Instant::now();
        for peer in [peer(), asked(start, 7)] {
            assert_eq!(
                peer.receive(&headers_payload_message(&[]), crate::fixtures::CLOCK)
                    .err(),
                Some(super::PeerError::Headers(
                    crate::protocol::HeadersError::Payload(crate::serialize::Error::UnexpectedEnd)
                ))
            );
        }
    }

    #[test]
    fn headers_off_our_tip_end_the_connection() {
        // The first header is on block 1, which our chain does not have.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        assert_eq!(
            asked(start, 7)
                .receive(&headers_message(&headers[1..]), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Extend(
                crate::chain::ExtendError::NotOnTip
            ))
        );
    }

    #[test]
    fn headers_too_far_after_our_clock_end_the_connection() {
        // The other tests pass a clock that takes each time. So only this one shows that the chain
        // gets the clock of `receive`.
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let clock = u64::from(headers[1].time) - 2 * 60 * 60 - 1;
        assert_eq!(
            asked(start, 7)
                .receive(&headers_message(&headers), clock)
                .err(),
            Some(super::PeerError::Extend(
                crate::chain::ExtendError::TimeTooNew
            ))
        );
    }

    #[test]
    fn getheaders_without_headers_for_headers_timeout_is_headers_timeout() {
        let start = std::time::Instant::now();
        let timeout = start + super::HEADERS_TIMEOUT;
        let (peer, wake) = idle(asked(start, 7), timeout - NANOSECOND);
        assert_eq!(wake, timeout);
        assert_eq!(
            peer.tick(timeout, 8).err(),
            Some(super::PeerError::HeadersTimeout)
        );
    }
}
