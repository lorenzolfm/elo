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
    /// Our chain refused their batch: it is not on our tip, or it is not a chain.
    Extend(crate::chain::ExtendError),
    /// Their `headers` came when no `getheaders` of ours was outstanding.
    UnsolicitedHeaders,
    /// Our `getheaders` had no `headers` within `HEADERS_TIMEOUT`.
    HeadersTimeout,
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
            PeerError::UnsolicitedHeaders => write!(f, "headers without our getheaders"),
            PeerError::HeadersTimeout => {
                write!(f, "no headers within {} s", HEADERS_TIMEOUT.as_secs())
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
    /// Our `getheaders` from the tip of our chain.
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
    /// Their batch was not full, so the sync ended. It holds the tip of our chain.
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
    /// Returns our `version` to `peer` on `network`, to send first.
    pub(crate) fn start(
        network: crate::chainparams::Network,
        peer: std::net::SocketAddr,
        timestamp: i64,
        nonce: u64,
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
                    let handshake = next(state, self.network, self.nonce, message_count)?;
                    Ok(Step::Reply(handshake, HandshakeOutbound::Verack))
                } else {
                    let state = State::AwaitingVersion;
                    let handshake = next(state, self.network, self.nonce, message_count)?;
                    Ok(Step::Wait(handshake))
                }
            }
            State::AwaitingVerack(theirs) => {
                assert!(theirs.version >= PROTOCOL_VERSION_MIN);
                assert_ne!(theirs.nonce, self.nonce);

                if message.msg_type() == crate::protocol::VERACK {
                    let peer = Peer {
                        ping: PingState::Unsent,
                        sync: SyncState::Due,
                        chain: crate::chain::Chain::new(self.network),
                    };
                    Ok(Step::Done(peer, theirs))
                } else {
                    let state = State::AwaitingVerack(theirs);
                    let handshake = next(state, self.network, self.nonce, message_count)?;
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
    nonce: u64,
    message_count: u32,
) -> Result<Handshake, HandshakeError> {
    if message_count < MESSAGE_COUNT_MAX {
        Ok(Handshake {
            state,
            network,
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
/// the handshake is complete. It does no I/O and reads no clock: the driver gives it each
/// message and the time, and sends what it returns.
#[derive(Debug)]
pub(crate) struct Peer {
    ping: PingState,
    sync: SyncState,
    /// The headers that the peer sent, on the genesis header of its network.
    chain: crate::chain::Chain,
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
    /// Our next `getheaders` is due: none went yet, or the last batch was full. The next tick
    /// sends it.
    Due,
    /// Our `getheaders` went at `sent`. Its `headers` has not come.
    Outstanding { sent: std::time::Instant },
    /// A batch that was not full came, so our tip is the tip of the peer. No `getheaders` goes
    /// again.
    Synced,
}

impl Peer {
    /// A `ping` gets a `pong` with its nonce. A `pong` must answer our outstanding `ping`, and a
    /// `headers` our outstanding `getheaders`. Each other message is skipped. Each result but an
    /// error returns the peer, because an error ends the connection.
    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
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
            self.receive_headers(message)
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

    /// The `headers` must answer our outstanding `getheaders`, and the chain must take the
    /// batch. Then no `getheaders` is outstanding. A full batch makes the next one due. A batch
    /// that is not full ends the sync, an empty one too. The payload is checked first, also
    /// when no `getheaders` is outstanding. The bytes after the last transaction count are
    /// ignored.
    fn receive_headers(
        mut self,
        message: &crate::transport::Message,
    ) -> Result<(Peer, Received), PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::HEADERS);

        let mut input = message.payload();
        let headers = crate::protocol::Headers::decode(&mut input).map_err(PeerError::Headers)?;
        let SyncState::Outstanding { .. } = self.sync else {
            return Err(PeerError::UnsolicitedHeaders);
        };
        let full = headers.is_full();
        self.chain
            .extend(headers.into_vec())
            .map_err(PeerError::Extend)?;
        if full {
            self.sync = SyncState::Due;
            Ok((self, Received::NoReply))
        } else {
            self.sync = SyncState::Synced;
            let tip = self.chain.tip();
            Ok((self, Received::Synced(tip)))
        }
    }

    /// Returns the peer, what to send, and when to tick next. A `ping` with `nonce` is due at
    /// once after the handshake. Then it is due `PING_INTERVAL` after the last `ping` went, if
    /// its `pong` came. A `getheaders` is due at once after the handshake, and at once after a
    /// full batch. The tick fails when our outstanding `ping` is `PING_TIMEOUT` old, or our
    /// outstanding `getheaders` is `HEADERS_TIMEOUT` old. The `ping` is checked first. Each
    /// deadline is due at its instant, not after it. The wake is the earliest deadline. The
    /// `now` of a tick is not before the `now` of an earlier tick, because each deadline counts
    /// from an earlier `now`.
    pub(crate) fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(Peer, TickOutbound, std::time::Instant), PeerError> {
        let Peer { ping, sync, chain } = self;
        let (ping, ping_nonce, ping_wake) = ping.tick(now, nonce)?;
        let (sync, get_headers, headers_wake) = sync.tick(now, &chain)?;
        let wake = headers_wake.map_or(ping_wake, |headers_wake| headers_wake.min(ping_wake));

        // Each `getheaders` that is due goes in this tick.
        assert!(!matches!(sync, SyncState::Due));
        // A wake at or before `now` would make the driver tick again with no wait.
        assert!(wake > now);
        let outbound = TickOutbound {
            ping: ping_nonce,
            get_headers,
        };
        Ok((Peer { ping, sync, chain }, outbound, wake))
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
    /// Returns the next state, our `getheaders` from the tip of `chain` if one is due, and the
    /// headers timeout if a `getheaders` is outstanding.
    fn tick(
        self,
        now: std::time::Instant,
        chain: &crate::chain::Chain,
    ) -> Result<
        (
            SyncState,
            Option<crate::protocol::GetHeaders>,
            Option<std::time::Instant>,
        ),
        PeerError,
    > {
        match self {
            SyncState::Due => {
                let get_headers = crate::protocol::GetHeaders::new(chain.tip());
                let sync = SyncState::Outstanding { sent: now };
                Ok((sync, Some(get_headers), Some(now + HEADERS_TIMEOUT)))
            }
            SyncState::Outstanding { sent } => {
                // `sent` is the `now` of an earlier tick.
                assert!(sent <= now);
                let timeout = sent + HEADERS_TIMEOUT;
                if now < timeout {
                    Ok((self, None, Some(timeout)))
                } else {
                    Err(PeerError::HeadersTimeout)
                }
            }
            SyncState::Synced => Ok((self, None, None)),
        }
    }
}

/// The entry point of the `machines` fuzz target.
#[cfg(fuzzing)]
pub(crate) mod fuzz {
    use crate::serialize::{Decode, Encode};

    /// The network of each frame. The machines do not read the magic, so one is enough. The network
    /// of the machines comes from the script.
    const FRAME_NETWORK: crate::chainparams::Network = crate::chainparams::Network::Regtest;

    /// The address of the peer in each `version` of a script.
    const PEER: std::net::SocketAddr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 18444);

    // The models take each limit from the constant that the machines use, and the seeds hold each
    // limit as a count of bytes and turns. So a new limit moves the models and not the seeds, and
    // the replay still passes. A new limit must rewrite the seeds at the limit.
    const _: () = assert!(super::PROTOCOL_VERSION_MIN == 70016);
    const _: () = assert!(super::MESSAGE_COUNT_MAX == 16);
    const _: () = assert!(super::PING_INTERVAL.as_secs() == 120);
    const _: () = assert!(super::PING_TIMEOUT.as_secs() == 1200);
    const _: () = assert!(super::HEADERS_TIMEOUT.as_secs() == 120);

    /// The count of a full batch. It is a second copy of the limit in `protocol`, so a wrong value
    /// of that limit makes the model and the machine disagree.
    const HEADERS_FULL_COUNT: usize = 2000;

    /// The most headers that one script writes. A full batch costs about 3 ms and 160 KB of chain,
    /// and a few bytes of a script ask for one. So this bounds the cost of a run.
    const HEADERS_WRITTEN_COUNT_MAX: usize = 3 * HEADERS_FULL_COUNT;

    /// Spreads a byte over the places of a nonce. It is odd, so each byte gives another nonce.
    const NONCE_SPREAD: u64 = 0x0123_4567_89ab_cdef;
    const _: () = assert!(NONCE_SPREAD % 2 == 1);
    const _: () = assert!(NONCE_SPREAD != NONCE_SPREAD.swap_bytes());

    /// A good peer, with a full batch. A machine that refuses each message fails on each seed. But
    /// a new layout can leave the seeds with nothing to check, and the replay still passes. This
    /// script must end the sync, so a new layout fails here until it also rewrites this script.
    #[rustfmt::skip]
    const GOOD_SCRIPT: &[u8] = &[
        0,                // Regtest.
        1,                // Our nonce.
        1, 1, 0, 0,       // Their `version`.
        2, 0,             // Their `verack`.
        7, 5, 255, 0, 0,  // A tick with our `ping` and `getheaders`, and a full batch.
        0,                // No time passes.
        8, 4, 0, 0,       // A tick with our next `getheaders`, and the `pong` to our `ping`.
        0,                // No time passes.
        9, 5, 2, 0, 0,    // A tick with nothing to send, and a batch that ends the sync.
        0,                // No time passes.
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
    /// - 4: `pong` with the nonce of our outstanding `ping`. A byte: 0 keeps the nonce, and each
    ///   other byte `b` flips bit `b % 64`.
    /// - 5: `headers`, each on the header below it, from our tip. A count byte: 253 is one above a
    ///   full batch, 254 is one below it, 255 is a full batch, and each other byte is the count.
    ///   Then a byte `b`: header `b - 1` has a wrong `prev`, and 0 changes none.
    /// - 6: another message type, which each machine skips.
    ///
    /// Then an `i8` to add to the length of the payload, so bytes come off its end or go after it.
    /// The committed corpus uses this layout, so a change to the layout must rewrite the corpus.
    pub fn machines(data: &[u8]) {
        // One run is enough, because a script does the same in each run.
        static GOOD_SCRIPT_RUN: std::sync::Once = std::sync::Once::new();
        GOOD_SCRIPT_RUN.call_once(|| assert!(machines_run(GOOD_SCRIPT)));

        machines_run(data);
    }

    /// Returns true if the script ended the sync, and no message or tick ended the run.
    fn machines_run(data: &[u8]) -> bool {
        let mut script = Script {
            unread: data,
            headers_written_count: 0,
        };
        let network = script_network(script.byte());
        let nonce = script.nonce();
        let timestamp = nonce.cast_signed();
        let (handshake, outbound) = super::Handshake::start(network, PEER, timestamp, nonce);
        machines_start_check(&outbound, timestamp, nonce);
        let tip = network.genesis().hash();
        match handshake_run(&mut script, handshake, nonce, tip) {
            Some(peer) => peer_run(&mut script, peer, tip),
            None => false,
        }
    }

    /// The network of a script. Its genesis header starts the chain of the peer.
    fn script_network(byte: u8) -> crate::chainparams::Network {
        match byte % 3 {
            0 => crate::chainparams::Network::Regtest,
            1 => crate::chainparams::Network::Mainnet,
            _ => crate::chainparams::Network::Testnet4,
        }
    }

    /// Checks each field of `outbound`, our `version`. It claims no services and asks for no
    /// transactions. The handshake compares their nonce with the nonce that it keeps, so `nonce` must
    /// also be on the wire.
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
            crate::protocol::Address::new(no_services, PEER)
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
    /// with one. A message takes at least its kind byte, so the length of the script bounds the
    /// loop. `tip` is only for the `headers` in the script, which the handshake skips.
    fn handshake_run(
        script: &mut Script,
        mut handshake: super::Handshake,
        nonce: u64,
        tip: bitcoin_hashes::sha256d::Hash,
    ) -> Option<super::Peer> {
        let mut model = HandshakeModel {
            nonce,
            theirs: None,
            message_count: 0,
        };
        while !script.unread.is_empty() {
            let unread_count = script.unread.len();
            let message = script.message(nonce, tip);
            assert!(script.unread.len() < unread_count);
            let Some(message) = message else {
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
                    return Some(peer);
                }
                (Err(error), Err(expected)) => {
                    assert_eq!(error, expected);
                    return None;
                }
                (step, expected) => panic!("the handshake gave {step:?}, not {expected:?}"),
            }
        }
        None
    }

    /// Runs one turn after the other, as the driver does. Returns true if the sync ended and no
    /// error ended the run. Each turn takes at least one byte of the script, so the length of the
    /// script bounds the loop.
    fn peer_run(
        script: &mut Script,
        mut peer: super::Peer,
        tip: bitcoin_hashes::sha256d::Hash,
    ) -> bool {
        let mut now = std::time::Instant::now();
        let mut model = PeerModel::new(now, tip);
        while !script.unread.is_empty() {
            let unread_count = script.unread.len();
            let nonce = script.nonce();
            assert!(script.unread.len() < unread_count);
            let Some((ticked, wake)) = peer_tick(peer, &mut model, now, nonce) else {
                return false;
            };
            peer = ticked;
            // The wait of the driver can end with no message.
            if let Some(message) = script.message(model.ping_nonce(), model.tip) {
                let Some(received) = peer_receive(peer, &mut model, &message) else {
                    return false;
                };
                peer = received;
            }
            now = now_next(script.byte(), now, wake);
        }
        model.is_synced()
    }

    /// Ticks `peer`, and checks the result against `model`. Returns the peer and its wake, or
    /// nothing if the tick failed.
    fn peer_tick(
        peer: super::Peer,
        model: &mut PeerModel,
        now: std::time::Instant,
        nonce: u64,
    ) -> Option<(super::Peer, std::time::Instant)> {
        match (peer.tick(now, nonce), model.tick(now, nonce)) {
            (Ok((peer, outbound, wake)), Ok(expected)) => {
                assert_eq!(wake, expected.wake);
                // The driver sends these, in this order.
                let mut outbounds = outbound.into_outbounds();
                if let Some(nonce) = expected.ping {
                    let ping = outbounds.next();
                    assert!(
                        matches!(ping, Some(super::PeerOutbound::Ping(sent)) if sent == nonce),
                        "{ping:?}, not a ping with {nonce}"
                    );
                }
                if expected.get_headers {
                    let Some(super::PeerOutbound::GetHeaders(get_headers)) = outbounds.next()
                    else {
                        panic!("the tick has no getheaders");
                    };
                    peer_get_headers_check(get_headers, model.tip);
                }
                let extra = outbounds.next();
                assert!(extra.is_none(), "{extra:?}");
                Some((peer, wake))
            }
            (Err(error), Err(expected)) => {
                assert_eq!(error, expected);
                None
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

    /// Gives `message` to `peer`, and checks the result against `model`. Returns the peer, or
    /// nothing if it refused the message.
    fn peer_receive(
        peer: super::Peer,
        model: &mut PeerModel,
        message: &crate::transport::Message,
    ) -> Option<super::Peer> {
        match (peer.receive(message), model.receive(message)) {
            (Ok((peer, super::Received::NoReply)), Ok(ReceivedExpected::NoReply)) => Some(peer),
            (Ok((peer, super::Received::Pong(nonce))), Ok(ReceivedExpected::Pong(expected))) => {
                assert_eq!(nonce, expected);
                Some(peer)
            }
            (Ok((peer, super::Received::Synced(tip))), Ok(ReceivedExpected::Synced)) => {
                assert_eq!(tip.hash(), model.tip);
                let height = format!("{} ", model.height);
                assert!(tip.to_string().starts_with(&height), "{tip}, not {height}");
                Some(peer)
            }
            (Err(error), Err(expected)) => {
                assert_eq!(error, expected);
                None
            }
            (received, expected) => panic!("the peer gave {received:?}, not {expected:?}"),
        }
    }

    /// The `now` of the next tick. A deadline is due at its instant, so a random time would almost
    /// never test it. So each kind but the first steps relative to `wake`, the earliest deadline
    /// from the last tick. `byte % 4` picks the kind, and `byte / 4` is the amount:
    ///
    /// - 0: the amount in seconds after `now`, so a message that came before `wake`, or no time.
    /// - 1: just before `wake`.
    /// - 2: at `wake`.
    /// - 3: the amount in minutes after `wake`, so a tick that came late.
    fn now_next(byte: u8, now: std::time::Instant, wake: std::time::Instant) -> std::time::Instant {
        // `tick` asserts this. The next assert needs it for the second kind.
        assert!(now < wake);
        let amount = u64::from(byte / 4);
        let next = match byte % 4 {
            0 => now + std::time::Duration::from_secs(amount),
            1 => wake - std::time::Duration::from_nanos(1),
            2 => wake,
            _ => wake + std::time::Duration::from_mins(amount),
        };
        // `tick` needs this for its deadlines.
        assert!(now <= next);
        next
    }

    /// The bytes of a script that no read took yet.
    struct Script<'a> {
        unread: &'a [u8],
        /// The headers that the script wrote, at most `HEADERS_WRITTEN_COUNT_MAX`.
        headers_written_count: usize,
    }

    impl Script<'_> {
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

        /// The next message, as the driver reads it. `nonce` is the one that our `version` and
        /// `pong` start from, and `tip` the one that a batch starts from.
        fn message(
            &mut self,
            nonce: u64,
            tip: bitcoin_hashes::sha256d::Hash,
        ) -> Option<crate::transport::Message> {
            /// A type that no machine reads.
            const OTHER: crate::protocol::MessageType =
                crate::protocol::MessageType::new(*b"wtxidrelay\0\0").expect("a printable name");

            let (msg_type, mut payload) = match self.byte() % 7 {
                0 => return None,
                1 => (crate::protocol::VERSION, self.version_payload(nonce)),
                2 => (crate::protocol::VERACK, Vec::new()),
                3 => (crate::protocol::PING, self.nonce().to_le_bytes().to_vec()),
                4 => (crate::protocol::PONG, self.pong_payload(nonce)),
                5 => (crate::protocol::HEADERS, self.headers_payload(tip)),
                _ => (OTHER, Vec::new()),
            };
            let length = payload
                .len()
                .saturating_add_signed(isize::from(self.signed_byte()));
            payload.resize(length, 0xaa);
            Some(message_read(msg_type, &payload))
        }

        fn version_payload(&mut self, nonce: u64) -> Vec<u8> {
            let nonce = nonce.wrapping_add(u64::from(self.byte()));
            let mut theirs = super::our_version(PEER, 0, nonce);
            theirs.version = super::PROTOCOL_VERSION_MIN + i32::from(self.signed_byte());
            let mut payload = Vec::new();
            theirs.encode(&mut payload);
            payload
        }

        fn pong_payload(&mut self, nonce: u64) -> Vec<u8> {
            let byte = self.byte();
            let theirs = match byte {
                0 => nonce,
                _ => nonce ^ (1 << (byte % 64)),
            };
            assert_eq!(theirs == nonce, byte == 0);
            theirs.to_le_bytes().to_vec()
        }

        /// A batch from `tip`. Random bytes never match the hash of the tip, so this builds each
        /// `prev`. Without this, each batch stops at `NotOnTip`.
        fn headers_payload(&mut self, tip: bitcoin_hashes::sha256d::Hash) -> Vec<u8> {
            let count = match self.byte() {
                253 => HEADERS_FULL_COUNT + 1,
                254 => HEADERS_FULL_COUNT - 1,
                255 => HEADERS_FULL_COUNT,
                count => usize::from(count),
            };
            let count = count.min(HEADERS_WRITTEN_COUNT_MAX - self.headers_written_count);
            self.headers_written_count += count;
            assert!(self.headers_written_count <= HEADERS_WRITTEN_COUNT_MAX);
            let wrong_prev_byte = usize::from(self.byte());

            let mut payload = Vec::new();
            crate::serialize::write_compact_size(&mut payload, count);
            let mut prev = tip;
            for index in 0..count {
                let header = crate::block::BlockHeader {
                    version: 0,
                    prev: if index + 1 == wrong_prev_byte {
                        hash_wrong(prev)
                    } else {
                        prev
                    },
                    merkle_root: [0; 32],
                    time: 0,
                    bits: 0,
                    nonce: 0,
                };
                header.encode(&mut payload);
                crate::serialize::write_compact_size(&mut payload, 0);
                prev = header.hash();
            }
            payload
        }
    }

    /// `hash` with one bit flipped, so a compare of part of a hash does not see it.
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
        /// The nonce of our outstanding `ping`, and when it went.
        ping_outstanding: Option<(u64, std::time::Instant)>,
        /// True when the next tick must send a `getheaders`.
        get_headers_due: bool,
        /// When our outstanding `getheaders` times out.
        get_headers_deadline: Option<std::time::Instant>,
        /// The hash and the height of the last header of the chain.
        tip: bitcoin_hashes::sha256d::Hash,
        height: usize,
    }

    #[derive(Debug)]
    struct TickExpected {
        ping: Option<u64>,
        get_headers: bool,
        wake: std::time::Instant,
    }

    #[derive(Debug)]
    enum ReceivedExpected {
        NoReply,
        Pong(u64),
        Synced,
    }

    impl PeerModel {
        /// The model of a new peer on the genesis hash `tip`. Its first tick is at `now`.
        fn new(now: std::time::Instant, tip: bitcoin_hashes::sha256d::Hash) -> PeerModel {
            PeerModel {
                ping_deadline: now,
                ping_outstanding: None,
                get_headers_due: true,
                get_headers_deadline: None,
                tip,
                height: 0,
            }
        }

        /// A batch that was not full came, so no `getheaders` goes again.
        fn is_synced(&self) -> bool {
            !self.get_headers_due && self.get_headers_deadline.is_none()
        }

        /// The nonce of a `pong` that answers our `ping`, or any nonce if none is outstanding.
        fn ping_nonce(&self) -> u64 {
            self.ping_outstanding.map_or(0, |(nonce, _)| nonce)
        }

        fn tick(
            &mut self,
            now: std::time::Instant,
            nonce: u64,
        ) -> Result<TickExpected, super::PeerError> {
            let ping_is_due = self.ping_deadline <= now;
            if ping_is_due && self.ping_outstanding.is_some() {
                return Err(super::PeerError::PingTimeout);
            }
            if self
                .get_headers_deadline
                .is_some_and(|deadline| deadline <= now)
            {
                return Err(super::PeerError::HeadersTimeout);
            }

            let ping = ping_is_due.then_some(nonce);
            if ping_is_due {
                self.ping_outstanding = Some((nonce, now));
                self.ping_deadline = now + super::PING_TIMEOUT;
            }
            let get_headers = self.get_headers_due;
            if get_headers {
                self.get_headers_due = false;
                self.get_headers_deadline = Some(now + super::HEADERS_TIMEOUT);
            }
            let wake = self
                .get_headers_deadline
                .map_or(self.ping_deadline, |deadline| {
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
                let Some((ours, sent)) = self.ping_outstanding else {
                    return Err(super::PeerError::UnsolicitedPong);
                };
                if theirs != ours {
                    return Err(super::PeerError::PongNonce);
                }
                self.ping_outstanding = None;
                self.ping_deadline = sent + super::PING_INTERVAL;
                Ok(ReceivedExpected::NoReply)
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
            if self.get_headers_deadline.is_none() {
                return Err(super::PeerError::UnsolicitedHeaders);
            }

            let mut tip = self.tip;
            for (index, header) in headers.iter().enumerate() {
                if header.prev != tip {
                    return Err(super::PeerError::Extend(if index == 0 {
                        crate::chain::ExtendError::NotOnTip
                    } else {
                        crate::chain::ExtendError::NotContinuous
                    }));
                }
                tip = header.hash();
            }
            self.tip = tip;
            self.height += headers.len();
            self.get_headers_deadline = None;
            if headers.len() == HEADERS_FULL_COUNT {
                self.get_headers_due = true;
                Ok(ReceivedExpected::NoReply)
            } else {
                Ok(ReceivedExpected::Synced)
            }
        }
    }

    /// The first 8 bytes of the payload, little-endian. Each byte after them is ignored.
    fn message_nonce(message: &crate::transport::Message) -> Result<u64, crate::serialize::Error> {
        match message.payload().first_chunk() {
            Some(nonce) => Ok(u64::from_le_bytes(*nonce)),
            None => Err(crate::serialize::Error::UnexpectedEnd),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::{Decode, Encode};

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
        let mut payload = Vec::new();
        crate::serialize::write_compact_size(&mut payload, headers.len());
        for header in headers {
            header.encode(&mut payload);
            payload.push(0);
        }
        headers_payload_message(&payload)
    }

    /// The tip of a second regtest chain, after `headers`.
    fn tip_after(headers: &[crate::block::BlockHeader]) -> crate::chain::Tip {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        chain.extend(headers.to_vec()).unwrap();
        chain.tip()
    }

    fn start() -> super::Handshake {
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        super::Handshake::start(crate::chainparams::Network::Regtest, peer, 0, 0).0
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
        let (handshake, _) = reply(start().receive(&core_message(crate::fixtures::VERSION_FRAME)));
        match handshake.receive(&core_message(crate::fixtures::VERACK_FRAME)) {
            Ok(super::Step::Done(peer, _)) => peer,
            other => panic!("{other:?}"),
        }
    }

    /// The peer after its first tick at `now`, which sent our `ping` with `nonce` and our
    /// `getheaders`.
    fn asked(now: std::time::Instant, nonce: u64) -> super::Peer {
        match peer().tick(now, nonce) {
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
        match asked(now, nonce).receive(&headers_message(&[])) {
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
        match peer.receive(message) {
            Ok((peer, super::Received::NoReply)) => peer,
            other => panic!("{other:?}"),
        }
    }

    const NANOSECOND: std::time::Duration = std::time::Duration::from_nanos(1);

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
        let outbound = peer().receive(&core_message(crate::fixtures::PING_FRAME));
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
            peer().receive(&short).err(),
            Some(super::PeerError::Ping(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = ping_message(|payload| payload.push(0xaa));
        let outbound = peer().receive(&longer);
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
        let outbound = pinged(start, 7).receive(&core_message(crate::fixtures::PING_FRAME));
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
        let genesis = crate::protocol::GetHeaders::new(tip_after(&[]));
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
                peer.receive(&short).err(),
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
                peer.receive(&pong(7)).err(),
                Some(super::PeerError::UnsolicitedPong)
            );
        }
    }

    #[test]
    fn pong_with_another_nonce_is_pong_nonce() {
        let start = std::time::Instant::now();
        assert_eq!(
            pinged(start, 7).receive(&pong(8)).err(),
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
            let outbound = peer().receive(&message);
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
            crate::protocol::GetHeaders::new(tip_after(&headers))
        );
        assert_eq!(wake, later + super::HEADERS_TIMEOUT);
    }

    #[test]
    fn short_batch_ends_the_sync_at_its_last_header() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let received = asked(start, 7).receive(&headers_message(&headers));
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

        let received = peer.receive(&headers_message(&[]));
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
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
                peer.receive(&headers_message(&[])).err(),
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
                peer.receive(&headers_payload_message(&[])).err(),
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
                .receive(&headers_message(&headers[1..]))
                .err(),
            Some(super::PeerError::Extend(
                crate::chain::ExtendError::NotOnTip
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
