use crate::serialize::{Decode, Encode};

const PROTOCOL_VERSION_MIN: i32 = 70016;

const _: () = assert!(crate::protocol::PROTOCOL_VERSION >= PROTOCOL_VERSION_MIN);

const MESSAGE_COUNT_MAX: u32 = 16;

const PING_INTERVAL: std::time::Duration = std::time::Duration::from_mins(2);

const PING_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(20);

const _: () = assert!(!PING_TIMEOUT.is_zero());

const HEADERS_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

const _: () = assert!(!HEADERS_TIMEOUT.is_zero());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    Version(crate::serialize::Error),
    Obsolete(i32),
    SelfConnection,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerError {
    Ping(crate::serialize::Error),
    Pong(crate::serialize::Error),
    UnsolicitedPong,
    PongNonce,
    PingTimeout,
    Inv(crate::protocol::InvError),
    Headers(crate::protocol::HeadersError),
    Extend(crate::chain::ExtendError),
    HeadersSync(crate::headerssync::HeadersSyncError),
    UnsolicitedHeaders,
    HeadersTimeout,
    ChainWorkTooLow,
    SecondLowWorkSync,
    LateWtxidRelay,
    LateSendAddrV2,
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
            PeerError::Inv(error) => write!(f, "{error}"),
            PeerError::Headers(error) => write!(f, "{error}"),
            PeerError::Extend(error) => write!(f, "{error}"),
            PeerError::HeadersSync(error) => write!(f, "low-work sync: {error}"),
            PeerError::UnsolicitedHeaders => write!(f, "headers before our due getheaders"),
            PeerError::HeadersTimeout => {
                write!(f, "no headers within {} s", HEADERS_TIMEOUT.as_secs())
            }
            PeerError::ChainWorkTooLow => {
                write!(f, "the sync ended on a chain below the minimum work")
            }
            PeerError::SecondLowWorkSync => {
                write!(f, "a second low-work sync in one connection")
            }
            PeerError::LateWtxidRelay => write!(f, "wtxidrelay after verack"),
            PeerError::LateSendAddrV2 => write!(f, "sendaddrv2 after verack"),
        }
    }
}

impl std::error::Error for PeerError {}

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

#[derive(Debug)]
enum State {
    AwaitingVersion,
    AwaitingVerack(crate::protocol::Version),
}

#[derive(Debug)]
pub(crate) struct Handshake<'a> {
    state: State,
    chain: &'a mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt: crate::headerssync::Salt,
    nonce: u64,
    message_count: u32,
}

#[derive(Debug)]
pub(crate) enum HandshakeOutbound {
    Version(Vec<u8>),
    Verack,
}

#[derive(Debug)]
pub(crate) enum PeerOutbound {
    Ping(u64),
    Pong(u64),
    SendHeaders,
    GetHeaders(crate::protocol::GetHeaders),
}

#[derive(Debug)]
pub(crate) struct TickOutbound {
    ping: Option<u64>,
    send_headers: bool,
    get_headers: Option<crate::protocol::GetHeaders>,
}

impl TickOutbound {
    pub(crate) fn into_outbounds(self) -> impl Iterator<Item = PeerOutbound> {
        let ping = self.ping.map(PeerOutbound::Ping);
        let send_headers = self.send_headers.then_some(PeerOutbound::SendHeaders);
        let get_headers = self.get_headers.map(PeerOutbound::GetHeaders);
        ping.into_iter().chain(send_headers).chain(get_headers)
    }
}

#[derive(Debug)]
pub(crate) enum Received {
    NoReply,
    Pong(u64),
    Synced(crate::chain::Tip),
}

#[derive(Debug)]
pub(crate) enum Step<'a> {
    Wait(Handshake<'a>),
    Reply(Handshake<'a>, HandshakeOutbound),
    Done(Peer<'a>, crate::protocol::Version),
}

impl<'a> Handshake<'a> {
    pub(crate) fn start(
        peer: std::net::SocketAddr,
        timestamp: i64,
        nonce: u64,
        chain: &'a mut crate::chain::Chain,
        work_min: crate::pow::Work,
        salt: crate::headerssync::Salt,
    ) -> (Handshake<'a>, HandshakeOutbound) {
        let ours = our_version(peer, timestamp, nonce);
        let mut payload = Vec::new();
        ours.encode(&mut payload);
        let mut input = payload.as_slice();
        assert_eq!(crate::protocol::Version::decode(&mut input), Ok(ours));
        assert!(input.is_empty());

        if chain.tip().work() < work_min {
            chain.restart();
        }
        if chain.tip().work() < work_min {
            assert_eq!(chain.tip().height(), 0);
        }

        (
            Handshake {
                state: State::AwaitingVersion,
                chain,
                work_min,
                salt,
                nonce,
                message_count: 0,
            },
            HandshakeOutbound::Version(payload),
        )
    }

    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
    ) -> Result<Step<'a>, HandshakeError> {
        assert!(self.message_count < MESSAGE_COUNT_MAX);
        let message_count = self.message_count + 1;

        match self.state {
            State::AwaitingVersion => {
                if message.msg_type() == crate::protocol::VERSION {
                    let theirs = receive_version(message, self.nonce)?;
                    let state = State::AwaitingVerack(theirs);
                    let handshake = next(
                        state,
                        self.chain,
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
                        self.chain,
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
                    let (download, salt) = if self.chain.tip().work() < self.work_min {
                        (Download::Genesis(self.salt), None)
                    } else {
                        (Download::on_tip(self.chain, self.work_min), Some(self.salt))
                    };
                    let peer = Peer {
                        ping: PingState::Unsent,
                        sync: SyncState::Due(download),
                        send_headers: SendHeadersState::Unsent,
                        chain: self.chain,
                        work_min: self.work_min,
                        salt,
                        branch_tip: None,
                    };
                    Ok(Step::Done(peer, theirs))
                } else {
                    let state = State::AwaitingVerack(theirs);
                    let handshake = next(
                        state,
                        self.chain,
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

fn next(
    state: State,
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt: crate::headerssync::Salt,
    nonce: u64,
    message_count: u32,
) -> Result<Handshake<'_>, HandshakeError> {
    if message_count < MESSAGE_COUNT_MAX {
        Ok(Handshake {
            state,
            chain,
            work_min,
            salt,
            nonce,
            message_count,
        })
    } else {
        Err(HandshakeError::TooManyMessages)
    }
}

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

#[derive(Debug)]
pub(crate) struct Peer<'a> {
    ping: PingState,
    sync: SyncState,
    send_headers: SendHeadersState,
    chain: &'a mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt: Option<crate::headerssync::Salt>,
    branch_tip: Option<crate::chain::BranchTip>,
}

#[derive(Debug)]
enum PingState {
    Unsent,
    Outstanding {
        nonce: u64,
        sent: std::time::Instant,
    },
    Answered {
        sent: std::time::Instant,
    },
}

#[derive(Debug)]
enum SyncState {
    Due(Download),
    Outstanding {
        download: Download,
        sent: std::time::Instant,
    },
    Synced,
}

#[derive(Debug)]
enum SendHeadersState {
    Unsent,
    Sent,
}

#[derive(Debug)]
enum Download {
    Genesis(crate::headerssync::Salt),
    Chain,
    Presync(Box<crate::headerssync::Presync>),
    Redownload(Box<crate::headerssync::Redownload>),
    Branch(Box<crate::chain::Branch>),
    BranchPresync(Box<BranchPresync>),
    BranchRedownload(Box<BranchRedownload>),
}

#[derive(Debug)]
struct BranchPresync {
    start: crate::chain::SyncStart,
    presync: crate::headerssync::Presync,
}

#[derive(Debug)]
struct BranchRedownload {
    start: crate::chain::SyncStart,
    redownload: crate::headerssync::Redownload,
    released: Vec<crate::block::BlockHeader>,
}

impl Download {
    fn on_tip(chain: &crate::chain::Chain, work_min: crate::pow::Work) -> Download {
        assert!(chain.tip().work() >= work_min);
        Download::Chain
    }

    fn locator(&self, chain: &crate::chain::Chain) -> Vec<bitcoin_hashes::sha256d::Hash> {
        match self {
            Download::Genesis(_) | Download::Chain => chain.locator(),
            Download::Presync(presync) => vec![presync.last_hash()],
            Download::Redownload(redownload) => vec![redownload.last_hash()],
            Download::Branch(branch) => vec![branch.last_hash()],
            Download::BranchPresync(sync) => vec![sync.presync.last_hash()],
            Download::BranchRedownload(sync) => vec![sync.redownload.last_hash()],
        }
    }

    fn is_answered_by(
        &self,
        chain: &crate::chain::Chain,
        headers: &crate::protocol::Headers,
    ) -> bool {
        headers
            .first()
            .is_none_or(|first| self.locator(chain).contains(&first.prev))
    }
}

impl<'a> Peer<'a> {
    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<(Peer<'a>, Received), PeerError> {
        let msg_type = message.msg_type();
        if msg_type == crate::protocol::PING {
            let mut input = message.payload();
            let nonce = u64::decode(&mut input).map_err(PeerError::Ping)?;
            Ok((self, Received::Pong(nonce)))
        } else if msg_type == crate::protocol::PONG {
            let peer = self.receive_pong(message)?;
            Ok((peer, Received::NoReply))
        } else if msg_type == crate::protocol::HEADERS {
            self.receive_headers(message, clock)
        } else if msg_type == crate::protocol::INV {
            let peer = self.receive_inv(message)?;
            Ok((peer, Received::NoReply))
        } else if msg_type == crate::protocol::WTXIDRELAY {
            Err(PeerError::LateWtxidRelay)
        } else if msg_type == crate::protocol::SENDADDRV2 {
            Err(PeerError::LateSendAddrV2)
        } else {
            Ok((self, Received::NoReply))
        }
    }

    fn receive_inv(self, message: &crate::transport::Message) -> Result<Peer<'a>, PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::INV);

        let mut input = message.payload();
        let inv = crate::protocol::Inv::decode(&mut input).map_err(PeerError::Inv)?;
        if inv.has_block() && matches!(self.sync, SyncState::Synced) {
            Ok(Peer {
                sync: SyncState::Due(Download::on_tip(self.chain, self.work_min)),
                ..self
            })
        } else {
            Ok(self)
        }
    }

    fn receive_pong(self, message: &crate::transport::Message) -> Result<Peer<'a>, PeerError> {
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

    fn receive_headers(
        mut self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<(Peer<'a>, Received), PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::HEADERS);

        let mut input = message.payload();
        let headers = crate::protocol::Headers::decode(&mut input).map_err(PeerError::Headers)?;
        let next = match self.sync {
            SyncState::Outstanding { download, sent } => {
                if !download.is_answered_by(self.chain, &headers) {
                    self.sync = SyncState::Outstanding { download, sent };
                    return Ok((self, Received::NoReply));
                }
                receive_answer(
                    self.chain,
                    self.work_min,
                    &mut self.salt,
                    &mut self.branch_tip,
                    download,
                    headers,
                    clock,
                )?
            }
            SyncState::Synced => receive_announcement(
                self.chain,
                self.work_min,
                &mut self.branch_tip,
                headers,
                clock,
            )?,
            SyncState::Due(_) => return Err(PeerError::UnsolicitedHeaders),
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

    pub(crate) fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(Peer<'a>, TickOutbound, std::time::Instant), PeerError> {
        let Peer {
            ping,
            sync,
            send_headers,
            chain,
            work_min,
            salt,
            branch_tip,
        } = self;
        let (ping, ping_nonce, ping_wake) = ping.tick(now, nonce)?;
        let (sync, get_headers, headers_wake) = sync.tick(now, chain, work_min)?;
        let wake = headers_wake.map_or(ping_wake, |headers_wake| headers_wake.min(ping_wake));
        let (send_headers, send_headers_due) = match (send_headers, &sync) {
            (SendHeadersState::Unsent, SyncState::Synced) => (SendHeadersState::Sent, true),
            (send_headers, _) => (send_headers, false),
        };

        assert!(!matches!(sync, SyncState::Due(_)));
        assert!(wake > now);
        let outbound = TickOutbound {
            ping: ping_nonce,
            send_headers: send_headers_due,
            get_headers,
        };
        let peer = Peer {
            ping,
            sync,
            send_headers,
            chain,
            work_min,
            salt,
            branch_tip,
        };
        Ok((peer, outbound, wake))
    }
}

impl PingState {
    fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(PingState, Option<u64>, std::time::Instant), PeerError> {
        match self {
            PingState::Unsent => Ok(PingState::send(now, nonce)),
            PingState::Outstanding { sent, .. } => {
                assert!(sent <= now);
                let timeout = sent + PING_TIMEOUT;
                if now < timeout {
                    Ok((self, None, timeout))
                } else {
                    Err(PeerError::PingTimeout)
                }
            }
            PingState::Answered { sent } => {
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

    fn send(now: std::time::Instant, nonce: u64) -> (PingState, Option<u64>, std::time::Instant) {
        let ping = PingState::Outstanding { nonce, sent: now };
        (ping, Some(nonce), now + PING_TIMEOUT)
    }
}

impl SyncState {
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
                let get_headers = crate::protocol::GetHeaders::new(download.locator(chain));
                let sync = SyncState::Outstanding {
                    download,
                    sent: now,
                };
                Ok((sync, Some(get_headers), Some(now + HEADERS_TIMEOUT)))
            }
            SyncState::Outstanding { sent, .. } => {
                assert!(sent <= now);
                let timeout = sent + HEADERS_TIMEOUT;
                if now < timeout {
                    Ok((self, None, Some(timeout)))
                } else {
                    Err(PeerError::HeadersTimeout)
                }
            }
            SyncState::Synced => {
                assert!(chain.tip().work() >= work_min);
                Ok((self, None, None))
            }
        }
    }
}

fn receive_answer(
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt: &mut Option<crate::headerssync::Salt>,
    branch_tip: &mut Option<crate::chain::BranchTip>,
    download: Download,
    headers: crate::protocol::Headers,
    clock: u64,
) -> Result<Option<Download>, PeerError> {
    let full = headers.is_full();
    match download {
        Download::Genesis(genesis_salt) => {
            receive_on_genesis(chain, work_min, salt, genesis_salt, headers, clock)
        }
        Download::Chain => {
            let extended = chain
                .extend_on_locator(headers, clock, work_min)
                .map_err(PeerError::Extend)?;
            chain_next(chain, work_min, salt, branch_tip, extended, clock)
        }
        Download::Branch(branch) => {
            let extended = chain
                .extend_branch(*branch, headers, clock, work_min)
                .map_err(PeerError::Extend)?;
            chain_next(chain, work_min, salt, branch_tip, extended, clock)
        }
        Download::BranchPresync(sync) => {
            let BranchPresync { start, presync } = *sync;
            let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
            Ok(Some(branch_presync_next(start, step)))
        }
        Download::BranchRedownload(sync) => {
            let BranchRedownload {
                start,
                redownload,
                mut released,
            } = *sync;
            match redownload
                .receive(headers)
                .map_err(PeerError::HeadersSync)?
            {
                crate::headerssync::RedownloadStep::More(redownload, more) => {
                    keep_released(chain.network(), &mut released, more);
                    Ok(Some(Download::BranchRedownload(Box::new(
                        BranchRedownload {
                            start,
                            redownload: *redownload,
                            released,
                        },
                    ))))
                }
                crate::headerssync::RedownloadStep::Done(rest) => {
                    keep_released(chain.network(), &mut released, rest);
                    let extended = chain
                        .extend_low_work_branch(start, released, full, clock, work_min)
                        .map_err(PeerError::Extend)?;
                    chain_next(chain, work_min, salt, branch_tip, extended, clock)
                }
            }
        }
        Download::Presync(presync) => {
            let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
            Ok(Some(presync_next(step)))
        }
        Download::Redownload(redownload) => {
            match redownload
                .receive(headers)
                .map_err(PeerError::HeadersSync)?
            {
                crate::headerssync::RedownloadStep::More(redownload, released) => {
                    extend_released(chain, released, clock)?;
                    Ok(Some(Download::Redownload(redownload)))
                }
                crate::headerssync::RedownloadStep::Done(released) => {
                    extend_released(chain, released, clock)?;
                    let next = Download::on_tip(chain, work_min);
                    Ok(full.then_some(next))
                }
            }
        }
    }
}

fn receive_on_genesis(
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt_left: &mut Option<crate::headerssync::Salt>,
    salt: crate::headerssync::Salt,
    headers: crate::protocol::Headers,
    clock: u64,
) -> Result<Option<Download>, PeerError> {
    assert_eq!(chain.tip().height(), 0);
    assert!(chain.tip().work() < work_min);
    if headers.is_full() {
        let presync =
            crate::headerssync::Presync::new(chain.sync_start_on_tip(), work_min, clock, salt);
        let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
        return Ok(Some(presync_next(step)));
    }
    let empty = headers.first().is_none();
    match chain
        .extend_on_locator(headers, clock, work_min)
        .map_err(PeerError::Extend)?
    {
        crate::chain::Extended::Taken { full } => {
            assert!(!full);
            assert!(!empty);
        }
        crate::chain::Extended::Kept => assert!(empty),
        crate::chain::Extended::KeptOver(_)
        | crate::chain::Extended::Branch(_)
        | crate::chain::Extended::BelowMargin { .. } => {
            panic!("genesis has no header below it")
        }
    }
    assert!(salt_left.replace(salt).is_none());
    if chain.tip().work() >= work_min {
        Ok(None)
    } else {
        Err(PeerError::ChainWorkTooLow)
    }
}

fn chain_next(
    chain: &crate::chain::Chain,
    work_min: crate::pow::Work,
    salt: &mut Option<crate::headerssync::Salt>,
    branch_tip: &mut Option<crate::chain::BranchTip>,
    extended: crate::chain::Extended,
    clock: u64,
) -> Result<Option<Download>, PeerError> {
    match extended {
        crate::chain::Extended::Taken { full } => {
            let next = Download::on_tip(chain, work_min);
            Ok(full.then_some(next))
        }
        crate::chain::Extended::Branch(branch) => {
            assert!(chain.tip().work() >= work_min);
            Ok(Some(Download::Branch(Box::new(branch))))
        }
        crate::chain::Extended::Kept => {
            assert!(chain.tip().work() >= work_min);
            Ok(None)
        }
        crate::chain::Extended::KeptOver(tip) => {
            *branch_tip = Some(tip);
            Ok(None)
        }
        crate::chain::Extended::BelowMargin {
            start,
            branch_work_min,
            headers,
        } => {
            assert!(chain.tip().work() >= work_min);
            let salt = salt.take().ok_or(PeerError::SecondLowWorkSync)?;
            let presync = crate::headerssync::Presync::new(start, branch_work_min, clock, salt);
            let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
            Ok(Some(branch_presync_next(start, step)))
        }
    }
}

fn receive_announcement(
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    branch_tip: &mut Option<crate::chain::BranchTip>,
    headers: crate::protocol::Headers,
    clock: u64,
) -> Result<Option<Download>, PeerError> {
    let full = headers.is_full();
    let first_prev = headers.first().map(|first| first.prev);
    *branch_tip = branch_tip.and_then(|tip| chain.branch_tip_current(tip));
    if let Some(tip) = *branch_tip
        && first_prev == Some(tip.hash())
    {
        return match chain
            .extend_branch_tip(tip, &headers)
            .map_err(PeerError::Extend)?
        {
            crate::chain::Announced::Kept(tip) => {
                *branch_tip = Some(tip);
                Ok(None)
            }
            crate::chain::Announced::Ask => {
                *branch_tip = None;
                Ok(Some(Download::on_tip(chain, work_min)))
            }
        };
    }
    match chain.extend(headers, clock) {
        Ok(()) => {
            let next = Download::on_tip(chain, work_min);
            Ok(full.then_some(next))
        }
        Err(crate::chain::ExtendError::NotOnTip) => Ok(Some(Download::on_tip(chain, work_min))),
        Err(error) => Err(PeerError::Extend(error)),
    }
}

fn extend_released(
    chain: &mut crate::chain::Chain,
    released: Vec<crate::block::BlockHeader>,
    clock: u64,
) -> Result<(), PeerError> {
    assert!(
        released.len()
            <= chain.network().redownload_buffer_size() + crate::protocol::HEADERS_COUNT_MAX
    );
    if let Some(first) = released.first() {
        assert_eq!(first.prev, chain.tip().hash());
    }
    for batch in crate::protocol::Headers::batches(released) {
        chain.extend(batch, clock).map_err(PeerError::Extend)?;
    }
    Ok(())
}

fn keep_released(
    network: crate::chainparams::Network,
    released: &mut Vec<crate::block::BlockHeader>,
    more: Vec<crate::block::BlockHeader>,
) {
    assert!(more.len() <= network.redownload_buffer_size() + crate::protocol::HEADERS_COUNT_MAX);
    if let (Some(last), Some(first)) = (released.last(), more.first()) {
        assert_eq!(first.prev, last.hash());
    }
    released.extend(more);
}

fn branch_presync_next(
    start: crate::chain::SyncStart,
    step: crate::headerssync::PresyncStep,
) -> Download {
    match step {
        crate::headerssync::PresyncStep::More(presync) => {
            Download::BranchPresync(Box::new(BranchPresync { start, presync }))
        }
        crate::headerssync::PresyncStep::Redownload(redownload) => {
            Download::BranchRedownload(Box::new(BranchRedownload {
                start,
                redownload,
                released: Vec::new(),
            }))
        }
    }
}

fn presync_next(step: crate::headerssync::PresyncStep) -> Download {
    match step {
        crate::headerssync::PresyncStep::More(presync) => Download::Presync(Box::new(presync)),
        crate::headerssync::PresyncStep::Redownload(redownload) => {
            Download::Redownload(Box::new(redownload))
        }
    }
}

#[cfg(fuzzing)]
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    use crate::serialize::{Decode, Encode};

    const FRAME_NETWORK: crate::chainparams::Network = crate::chainparams::Network::Regtest;

    const PEER_ADDRESS: std::net::SocketAddr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 18444);

    const _: () = assert!(super::PROTOCOL_VERSION_MIN == 70016);
    const _: () = assert!(super::MESSAGE_COUNT_MAX == 16);
    const _: () = assert!(super::PING_INTERVAL.as_secs() == 120);
    const _: () = assert!(super::PING_TIMEOUT.as_secs() == 1200);
    const _: () = assert!(super::HEADERS_TIMEOUT.as_secs() == 120);

    const HEADERS_FULL_COUNT: usize = 2000;

    const SCRIPT_HEADERS_COUNT_MAX: usize = 6 * HEADERS_FULL_COUNT;

    const _: () = assert!(SCRIPT_HEADERS_COUNT_MAX >= 4 * HEADERS_FULL_COUNT + 2);

    const _: () = assert!(
        SCRIPT_HEADERS_COUNT_MAX
            >= 2 * 2 * HEADERS_FULL_COUNT
                + (2 * HEADERS_FULL_COUNT - crate::chain::BRANCH_TIP_HEADERS_BEHIND_MAX)
    );

    const _: () = assert!(
        SCRIPT_HEADERS_COUNT_MAX / 2
            <= crate::chainparams::Network::Regtest.redownload_buffer_size()
    );

    const _: () = assert!(crate::chain::BRANCH_TIP_HEADERS_BEHIND_MAX == 144);
    const _: () = assert!(crate::chain::LOCATOR_DENSE_COUNT == 12);
    const _: () = assert!(crate::chainparams::Network::Regtest.commitment_period() == 275);

    const SCRIPT_WORK_MIN_STEP: usize = HEADERS_FULL_COUNT / 16;
    const _: () = assert!(SCRIPT_WORK_MIN_STEP * 16 == HEADERS_FULL_COUNT);

    const SCRIPT_HEADER_BITS: u32 = crate::chainparams::Network::Regtest.genesis().bits;

    const SCRIPT_HEADER_WORK: u128 = 2;

    const SCRIPT_HEADER_VERSION: i32 = 4;
    const _: () =
        assert!(SCRIPT_HEADER_VERSION == crate::chainparams::Network::Regtest.version_min(1));
    const _: () = assert!(
        SCRIPT_HEADER_VERSION == crate::chainparams::Network::Regtest.version_min(usize::MAX)
    );

    fn script_header_time(height: usize) -> u32 {
        assert!((1..=SCRIPT_HEADERS_COUNT_MAX).contains(&height));
        let seconds = u32::try_from(height).unwrap_or(u32::MAX);
        crate::chainparams::Network::Regtest.genesis().time + seconds
    }

    fn script_merkle_root(tag: u32) -> [u8; 32] {
        let mut root = [0; 32];
        root[..4].copy_from_slice(&tag.to_le_bytes());
        root
    }

    const SCRIPT_KEYS: [u64; 2] = [0, 0];

    const SCRIPT_OFFSET: usize = 0;

    const SCRIPT_SALT: crate::headerssync::Salt =
        crate::headerssync::Salt::new(SCRIPT_KEYS, SCRIPT_OFFSET);

    const NONCE_SPREAD: u64 = 0x0123_4567_89ab_cdef;
    const _: () = assert!(NONCE_SPREAD % 2 == 1);
    const _: () = assert!(NONCE_SPREAD != NONCE_SPREAD.swap_bytes());

    const fn pong_flip_bit(byte: u8) -> u8 {
        byte % 64
    }

    const _: () = assert!(pong_flip_bit(63) == 63);
    const _: () = assert!(pong_flip_bit(64) == 0);

    #[derive(Debug)]
    #[expect(dead_code)]
    enum ScriptEnd {
        HandshakeOpen,
        HandshakeRefused(super::HandshakeError),
        PeerOpen { height: usize, synced: bool },
        PeerRefused(super::PeerError),
    }

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

    #[rustfmt::skip]
    #[cfg(test)]
    const SEED_ENDS: &[(&str, &[u8], &str)] = &[
        seed!("announce-after-sync", "PeerOpen { height: 5, synced: true }"),
        seed!("announce-full-after-sync", "PeerOpen { height: 2005, synced: true }"),
        seed!("announce-full-after-sync-headers-timeout", "PeerRefused(HeadersTimeout)"),
        seed!("announce-on-locator-then-branch", "PeerOpen { height: 7, synced: true }"),
        seed!("fork-below-margin-after-our-headers", "PeerOpen { height: 2200, synced: false }"),
        seed!("fork-below-margin-of-the-minimum", "PeerRefused(SecondLowWorkSync)"),
        seed!("fork-below-margin-short-kept", "PeerOpen { height: 2200, synced: true }"),
        seed!("fork-below-margin-short-kept-then-announce-on-tip", "PeerOpen { height: 2147, synced: true }"),
        seed!("fork-full-at-margin-then-more-work", "PeerOpen { height: 2145, synced: true }"),
        seed!("fork-full-in-margin-then-empty", "PeerOpen { height: 2005, synced: true }"),
        seed!("fork-full-in-margin-then-more-work", "PeerOpen { height: 2006, synced: true }"),
        seed!("fork-less-work-kept", "PeerOpen { height: 3, synced: true }"),
        seed!("fork-low-work-sync-after-one-on-genesis", "PeerRefused(SecondLowWorkSync)"),
        seed!("fork-low-work-sync-after-short-batch", "PeerOpen { height: 2252, synced: false }"),
        seed!("fork-low-work-sync-full-then-empty", "PeerOpen { height: 4000, synced: true }"),
        seed!("fork-low-work-sync-less-work-kept", "PeerOpen { height: 2145, synced: true }"),
        seed!("fork-low-work-sync-more-work", "PeerOpen { height: 2146, synced: true }"),
        seed!("fork-low-work-sync-then-branch", "PeerOpen { height: 4001, synced: true }"),
        seed!("fork-low-work-sync-twice", "PeerRefused(SecondLowWorkSync)"),
        seed!("fork-more-work-reorg", "PeerOpen { height: 6, synced: true }"),
        seed!("fork-our-headers-full-then-tip", "PeerOpen { height: 2010, synced: true }"),
        seed!("fork-our-headers-then-branch", "PeerOpen { height: 2006, synced: true }"),
        seed!("fork-same-work-kept", "PeerOpen { height: 3, synced: true }"),
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
        seed!("headers-after-sync", "PeerOpen { height: 0, synced: true }"),
        seed!("headers-break-last", "PeerRefused(Extend(NotContinuous))"),
        seed!("headers-break-last-of-full", "PeerRefused(Extend(NotContinuous))"),
        seed!("headers-break-second", "PeerRefused(Extend(NotContinuous))"),
        seed!("headers-budget-ends", "PeerOpen { height: 12000, synced: true }"),
        seed!("headers-bytes-after", "PeerOpen { height: 2, synced: true }"),
        seed!("headers-cut", "PeerRefused(Headers(Payload(UnexpectedEnd)))"),
        seed!("headers-cut-after-sync", "PeerRefused(Headers(Payload(UnexpectedEnd)))"),
        seed!("headers-empty-payload", "PeerRefused(Headers(Payload(UnexpectedEnd)))"),
        seed!("headers-off-tip", "PeerOpen { height: 0, synced: false }"),
        seed!("headers-off-tip-after-full", "PeerOpen { height: 2000, synced: false }"),
        seed!("headers-off-tip-after-sync", "PeerOpen { height: 0, synced: false }"),
        seed!("headers-off-tip-after-sync-then-headers", "PeerOpen { height: 1, synced: true }"),
        seed!("headers-off-tip-after-sync-twice", "PeerOpen { height: 0, synced: false }"),
        seed!("headers-off-tip-after-sync-twice-then-answer", "PeerOpen { height: 1, synced: true }"),
        seed!("headers-wrong-index-past-end", "PeerOpen { height: 2, synced: true }"),
        seed!("inv-block-after-sync", "PeerOpen { height: 2, synced: false }"),
        seed!("inv-block-after-sync-then-headers", "PeerOpen { height: 3, synced: true }"),
        seed!("inv-block-in-sync", "PeerOpen { height: 2, synced: true }"),
        seed!("inv-other-after-sync", "PeerOpen { height: 2, synced: true }"),
        seed!("inv-short-payload", "PeerRefused(Inv(Payload(UnexpectedEnd)))"),
        seed!("mix-long", "PeerRefused(PingTimeout)"),
        seed!("network-mainnet", "PeerRefused(Extend(ProofOfWork))"),
        seed!("network-signet", "PeerRefused(Extend(ProofOfWork))"),
        seed!("network-testnet4", "PeerRefused(Extend(ProofOfWork))"),
        seed!("peer-refuses-wtxidrelay", "PeerRefused(LateWtxidRelay)"),
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
        seed!("sync-low-work-full-off-tip-signet", "PeerOpen { height: 0, synced: false }"),
        seed!("sync-low-work-mainnet", "PeerRefused(ChainWorkTooLow)"),
        seed!("sync-low-work-regtest", "PeerOpen { height: 4002, synced: true }"),
        seed!("sync-low-work-regtest-at-batch-end", "PeerOpen { height: 2000, synced: true }"),
        seed!("sync-low-work-regtest-first-short", "PeerRefused(HeadersSync(WorkTooLow))"),
        seed!("sync-low-work-regtest-second-above-first", "PeerOpen { height: 4002, synced: true }"),
        seed!("sync-low-work-regtest-second-break-second", "PeerRefused(HeadersSync(NotContinuous))"),
        seed!("sync-low-work-regtest-second-off-last", "PeerOpen { height: 0, synced: false }"),
        seed!("sync-low-work-regtest-second-other", "PeerRefused(HeadersSync(CommitmentMismatch))"),
        seed!("sync-low-work-regtest-second-short", "PeerRefused(HeadersSync(WorkTooLow))"),
        seed!("sync-low-work-regtest-short-at-min", "PeerOpen { height: 250, synced: true }"),
        seed!("sync-low-work-regtest-short-below-min", "PeerRefused(ChainWorkTooLow)"),
        seed!("sync-low-work-regtest-short-ends", "PeerOpen { height: 2125, synced: true }"),
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

    pub fn machines(data: &[u8]) {
        machines_run(data);
    }

    fn machines_run(data: &[u8]) -> ScriptEnd {
        let mut script = Script {
            unread: data,
            headers_written_count: 0,
            written_on: std::collections::HashMap::new(),
            branch_last: 0,
        };
        let (network, work_min, work_min_model) = script_network_work_min(script.byte());
        let nonce = script.nonce();
        let timestamp = nonce.cast_signed();
        let mut chain = crate::chain::Chain::new(network);
        let (handshake, outbound) = super::Handshake::start(
            PEER_ADDRESS,
            timestamp,
            nonce,
            &mut chain,
            work_min,
            SCRIPT_SALT,
        );
        machines_start_check(&outbound, timestamp, nonce);
        match handshake_run(&mut script, handshake, nonce) {
            Ok(peer) => peer_run(&mut script, peer, network, work_min_model),
            Err(end) => end,
        }
    }

    fn script_network(byte: u8) -> crate::chainparams::Network {
        match byte % 4 {
            0 => crate::chainparams::Network::Regtest,
            1 => crate::chainparams::Network::Mainnet,
            2 => crate::chainparams::Network::Testnet4,
            _ => crate::chainparams::Network::Signet,
        }
    }

    fn script_network_work_min(byte: u8) -> (crate::chainparams::Network, crate::pow::Work, u128) {
        let network = script_network(byte);
        let (work_min, work_min_model) = match network {
            crate::chainparams::Network::Mainnet => (
                crate::pow::chain_work_min(network),
                0x1_1287_50f8_2f4c_3661_53a3_a030,
            ),
            crate::chainparams::Network::Testnet4 => (
                crate::pow::chain_work_min(network),
                0x9a0_fe15_d017_7d08_6304,
            ),
            crate::chainparams::Network::Signet => {
                (crate::pow::chain_work_min(network), 0xb46_3ea0_a4b8)
            }
            crate::chainparams::Network::Regtest => {
                let step_count = byte / 4;
                let Some(header_work) = crate::pow::work(SCRIPT_HEADER_BITS, network) else {
                    panic!("the script bits {SCRIPT_HEADER_BITS:#x} are not a regtest target");
                };
                let headers_count = usize::from(step_count) * SCRIPT_WORK_MIN_STEP;
                let work_min = (0..headers_count)
                    .fold(header_work, |work, _| work.saturating_add(header_work));
                const { assert!(usize::BITS <= 64) };
                let work_min_model = 2 + u128::from(step_count) * SCRIPT_WORK_MIN_STEP as u128 * 2;
                (work_min, work_min_model)
            }
        };
        (network, work_min, work_min_model)
    }

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

    fn handshake_run<'a>(
        script: &mut Script,
        mut handshake: super::Handshake<'a>,
        nonce: u64,
    ) -> Result<super::Peer<'a>, ScriptEnd> {
        let base = MessageBase {
            our_nonce: nonce,
            ping_nonce: 0,
            last: (bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]), 0),
            locator_below: Vec::new(),
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

    fn peer_run(
        script: &mut Script,
        mut peer: super::Peer<'_>,
        network: crate::chainparams::Network,
        work_min: u128,
    ) -> ScriptEnd {
        let mut now = std::time::Instant::now();
        let clock = u64::from(script_header_time(SCRIPT_HEADERS_COUNT_MAX));
        let mut model = PeerModel::new(now, network, work_min);
        while !script.unread.is_empty() {
            let unread_count = script.unread.len();
            let nonce = script.nonce();
            assert!(script.unread.len() < unread_count);
            let (ticked, wake) = match peer_tick(peer, &mut model, now, nonce) {
                Ok(ticked) => ticked,
                Err(error) => return ScriptEnd::PeerRefused(error),
            };
            peer = ticked;
            let base = MessageBase {
                our_nonce: 0,
                ping_nonce: model.ping_nonce,
                last: model.download_last(),
                locator_below: model.locator_below(),
            };
            if let Some(message) = script.message(&base) {
                peer = match peer_receive(peer, &mut model, &message, clock) {
                    Ok(received) => received,
                    Err(error) => return ScriptEnd::PeerRefused(error),
                };
                branch_tip_check(&peer, &model);
            }
            now = now_next(script.byte(), now, wake);
            assert!(model.height() <= script.headers_written_count);
        }
        ScriptEnd::PeerOpen {
            height: model.height(),
            synced: model.is_synced(),
        }
    }

    fn peer_tick<'a>(
        peer: super::Peer<'a>,
        model: &mut PeerModel,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(super::Peer<'a>, std::time::Instant), super::PeerError> {
        match (peer.tick(now, nonce), model.tick(now, nonce)) {
            (Ok((peer, outbound, wake)), Ok(expected)) => {
                assert_eq!(wake, expected.wake);
                let mut outbounds = outbound.into_outbounds();
                if expected.ping {
                    match outbounds.next() {
                        Some(super::PeerOutbound::Ping(ping_nonce)) => {
                            assert_eq!(ping_nonce, nonce)
                        }
                        other => panic!("{other:?}, not a ping"),
                    }
                }
                if expected.send_headers {
                    match outbounds.next() {
                        Some(super::PeerOutbound::SendHeaders) => {}
                        other => panic!("{other:?}, not a sendheaders"),
                    }
                }
                if expected.get_headers {
                    match outbounds.next() {
                        Some(super::PeerOutbound::GetHeaders(get_headers)) => {
                            peer_get_headers_check(get_headers, &model.locator());
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

    fn peer_get_headers_check(
        get_headers: crate::protocol::GetHeaders,
        locator: &[bitcoin_hashes::sha256d::Hash],
    ) {
        let mut encoded = Vec::new();
        get_headers.encode(&mut encoded);

        let mut expected = Vec::new();
        expected.extend_from_slice(&crate::protocol::PROTOCOL_VERSION.to_le_bytes());
        crate::serialize::write_compact_size(&mut expected, locator.len());
        for hash in locator {
            expected.extend_from_slice(hash.as_byte_array());
        }
        expected.extend_from_slice(&[0; 32]);
        assert_eq!(encoded, expected);
    }

    fn peer_receive<'a>(
        peer: super::Peer<'a>,
        model: &mut PeerModel,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<super::Peer<'a>, super::PeerError> {
        match (peer.receive(message, clock), model.receive(message)) {
            (Ok((peer, super::Received::NoReply)), Ok(ReceivedExpected::NoReply)) => Ok(peer),
            (Ok((peer, super::Received::Pong(nonce))), Ok(ReceivedExpected::Pong(expected))) => {
                assert_eq!(nonce, expected);
                Ok(peer)
            }
            (Ok((peer, super::Received::Synced(tip))), Ok(ReceivedExpected::Synced)) => {
                assert_eq!(tip.hash(), model.tip());
                assert_eq!(tip.height(), model.height());
                assert_eq!(tip.work().to_string(), format!("{:064x}", model.work()));
                Ok(peer)
            }
            (Err(error), Err(expected)) => {
                assert_eq!(error, expected);
                Err(error)
            }
            (received, expected) => panic!("the peer gave {received:?}, not {expected:?}"),
        }
    }

    fn branch_tip_check(peer: &super::Peer<'_>, model: &PeerModel) {
        let tip = peer
            .branch_tip
            .and_then(|tip| peer.chain.branch_tip_current(tip))
            .map(|tip| (tip.hash(), tip.work_max().to_string()));
        let expected = model
            .branch_tip
            .map(|(hash, work, _)| (hash, format!("{work:064x}")));
        assert_eq!(tip, expected);
    }

    fn now_next(byte: u8, now: std::time::Instant, wake: std::time::Instant) -> std::time::Instant {
        assert!(now < wake);
        let unit_count = u64::from(byte / 4);
        let next = match byte % 4 {
            0 => now + std::time::Duration::from_secs(unit_count),
            1 => wake - std::time::Duration::from_nanos(1),
            2 => wake,
            _ => wake + std::time::Duration::from_mins(unit_count),
        };
        assert!(now <= next);
        next
    }

    struct Script<'a> {
        unread: &'a [u8],
        headers_written_count: usize,
        written_on:
            std::collections::HashMap<bitcoin_hashes::sha256d::Hash, crate::block::BlockHeader>,
        branch_last: u32,
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

        fn nonce(&mut self) -> u64 {
            u64::from(self.byte()).wrapping_mul(NONCE_SPREAD)
        }

        fn message(&mut self, base: &MessageBase) -> Option<crate::transport::Message> {
            let kind = self.byte();
            let (msg_type, mut payload) = match kind % 8 {
                0 => return None,
                1 => (
                    crate::protocol::VERSION,
                    self.version_payload(base.our_nonce),
                ),
                2 => (crate::protocol::VERACK, Vec::new()),
                3 => (crate::protocol::PING, self.nonce().to_le_bytes().to_vec()),
                4 => (crate::protocol::PONG, self.pong_payload(base.ping_nonce)),
                5 => {
                    let payload = match usize::from(kind / 8).checked_sub(1) {
                        None => self.headers_payload(base.last, false),
                        Some(index) => self.headers_payload(base.on_locator(index), true),
                    };
                    (crate::protocol::HEADERS, payload)
                }
                6 => (crate::protocol::WTXIDRELAY, Vec::new()),
                _ => (crate::protocol::INV, self.inv_payload()),
            };
            let length = payload
                .len()
                .saturating_add_signed(isize::from(self.signed_byte()));
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

        fn inv_payload(&mut self) -> Vec<u8> {
            let mut payload = vec![1];
            payload.extend_from_slice(&u32::from(self.byte()).to_le_bytes());
            payload.extend_from_slice(&[0xbb; 32]);
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

        fn headers_payload(
            &mut self,
            (last_hash, last_height): (bitcoin_hashes::sha256d::Hash, usize),
            branches: bool,
        ) -> Vec<u8> {
            assert!(last_height <= self.headers_written_count);
            let count_asked = count_read(self.byte());
            let count = count_asked.min(SCRIPT_HEADERS_COUNT_MAX - self.headers_written_count);
            assert!(self.headers_written_count + count <= SCRIPT_HEADERS_COUNT_MAX);
            assert!(count <= HEADERS_FULL_COUNT + 1);
            let wrong_prev_index = match self.byte() {
                0 => None,
                255 => count.checked_sub(1),
                byte => Some(usize::from(byte) - 1),
            }
            .filter(|index| *index < count);
            let branch_index = branches
                .then(|| branch_index_read(self.byte()))
                .filter(|index| *index < count);

            let mut payload = Vec::new();
            crate::serialize::write_compact_size(&mut payload, count);
            let mut prev = last_hash;
            for index in 0..count {
                self.headers_written_count += 1;
                let height = last_height + index + 1;
                if Some(index) == branch_index {
                    self.branch_last += 1;
                }
                let header = if Some(index) == wrong_prev_index {
                    script_header_mined(hash_wrong(prev), height, self.branch_last)
                } else {
                    match self.written_on.get(&prev) {
                        Some(written) if Some(index) != branch_index => *written,
                        _ => {
                            let header = script_header_mined(prev, height, self.branch_last);
                            self.written_on.insert(prev, header);
                            assert!(self.written_on.len() <= self.headers_written_count);
                            header
                        }
                    }
                };
                header.encode(&mut payload);
                crate::serialize::write_compact_size(&mut payload, 0);
                prev = header.hash();
            }
            payload
        }
    }

    fn count_read(byte: u8) -> usize {
        match byte {
            253 => HEADERS_FULL_COUNT + 1,
            254 => HEADERS_FULL_COUNT - 1,
            255 => HEADERS_FULL_COUNT,
            byte => usize::from(byte),
        }
    }

    fn branch_index_read(byte: u8) -> usize {
        count_read(byte)
    }

    fn script_header_mined(
        prev: bitcoin_hashes::sha256d::Hash,
        height: usize,
        tag: u32,
    ) -> crate::block::BlockHeader {
        crate::pow::mined_for_regtest(crate::block::BlockHeader {
            version: SCRIPT_HEADER_VERSION,
            prev,
            merkle_root: script_merkle_root(tag),
            time: script_header_time(height),
            bits: SCRIPT_HEADER_BITS,
            nonce: 0,
        })
    }

    struct MessageBase {
        our_nonce: u64,
        ping_nonce: u64,
        last: (bitcoin_hashes::sha256d::Hash, usize),
        locator_below: Vec<(bitcoin_hashes::sha256d::Hash, usize)>,
    }

    impl MessageBase {
        fn on_locator(&self, index: usize) -> (bitcoin_hashes::sha256d::Hash, usize) {
            let Some(below) = index.checked_sub(1) else {
                return self.last;
            };
            self.locator_below
                .get(below)
                .or(self.locator_below.last())
                .copied()
                .unwrap_or(self.last)
        }
    }

    fn hash_wrong(hash: bitcoin_hashes::sha256d::Hash) -> bitcoin_hashes::sha256d::Hash {
        let mut bytes = hash.to_byte_array();
        bytes[31] ^= 1;
        let wrong = bitcoin_hashes::sha256d::Hash::from_byte_array(bytes);
        assert_ne!(wrong, hash);
        wrong
    }

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

    struct HandshakeModel {
        nonce: u64,
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

    struct PeerModel {
        ping_deadline: std::time::Instant,
        ping_nonce: u64,
        ping_outstanding: bool,
        get_headers: GetHeadersModel,
        send_headers: SendHeadersModel,
        chain: Vec<bitcoin_hashes::sha256d::Hash>,
        network: crate::chainparams::Network,
        work_min: u128,
        salt_left: bool,
        branch_tip: Option<(bitcoin_hashes::sha256d::Hash, u128, usize)>,
        download: DownloadModel,
    }

    enum DownloadModel {
        Chain,
        Branch {
            fork: usize,
            hashes: Vec<bitcoin_hashes::sha256d::Hash>,
        },
        Presync {
            start: usize,
            hashes: Vec<bitcoin_hashes::sha256d::Hash>,
        },
        Redownload {
            start: usize,
            presync: Vec<bitcoin_hashes::sha256d::Hash>,
            buffer: Vec<bitcoin_hashes::sha256d::Hash>,
        },
    }

    enum ExtendedModel {
        Taken,
        Kept,
        Branch {
            fork: usize,
            hashes: Vec<bitcoin_hashes::sha256d::Hash>,
        },
        BelowMargin {
            fork: usize,
            hashes: Vec<bitcoin_hashes::sha256d::Hash>,
        },
        KeptOver {
            hash: bitcoin_hashes::sha256d::Hash,
            work_max: u128,
        },
    }

    #[derive(Debug)]
    enum HeaderFault {
        Prev,
        ProofOfWork,
    }

    enum GetHeadersModel {
        Due,
        Outstanding(std::time::Instant),
        Ended,
    }

    #[derive(PartialEq)]
    enum SendHeadersModel {
        Unsent,
        Sent,
    }

    #[derive(Debug)]
    struct TickExpected {
        ping: bool,
        send_headers: bool,
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
        fn new(
            now: std::time::Instant,
            network: crate::chainparams::Network,
            work_min: u128,
        ) -> PeerModel {
            PeerModel {
                ping_deadline: now,
                ping_nonce: 0,
                ping_outstanding: false,
                get_headers: GetHeadersModel::Due,
                send_headers: SendHeadersModel::Unsent,
                chain: vec![network.genesis().hash()],
                network,
                work_min,
                salt_left: true,
                branch_tip: None,
                download: DownloadModel::Chain,
            }
        }

        fn tip(&self) -> bitcoin_hashes::sha256d::Hash {
            self.chain[self.height()]
        }

        fn download_last(&self) -> (bitcoin_hashes::sha256d::Hash, usize) {
            let (start, hashes) = match &self.download {
                DownloadModel::Chain => return (self.tip(), self.height()),
                DownloadModel::Branch { fork, hashes } => (*fork, hashes),
                DownloadModel::Presync { start, hashes, .. } => (*start, hashes),
                DownloadModel::Redownload { start, buffer, .. } => (*start, buffer),
            };
            assert!(start <= self.height());
            let last = hashes.last().copied().unwrap_or(self.chain[start]);
            (last, start + hashes.len())
        }

        fn locator_heights(&self) -> Vec<usize> {
            let mut heights = Vec::new();
            let mut height = self.height();
            let mut step = 1;
            loop {
                heights.push(height);
                if height == 0 {
                    break;
                }
                height = height.saturating_sub(step);
                if heights.len() >= crate::chain::LOCATOR_DENSE_COUNT - 1 {
                    step *= 2;
                }
            }
            heights
        }

        fn locator_below(&self) -> Vec<(bitcoin_hashes::sha256d::Hash, usize)> {
            if !matches!(self.download, DownloadModel::Chain) {
                return Vec::new();
            }
            self.locator_heights()
                .into_iter()
                .skip(1)
                .map(|height| (self.chain[height], height))
                .collect()
        }

        fn locator(&self) -> Vec<bitcoin_hashes::sha256d::Hash> {
            std::iter::once(self.download_last())
                .chain(self.locator_below())
                .map(|(hash, _)| hash)
                .collect()
        }

        fn is_synced(&self) -> bool {
            matches!(self.get_headers, GetHeadersModel::Ended)
        }

        fn tick(
            &mut self,
            now: std::time::Instant,
            nonce: u64,
        ) -> Result<TickExpected, super::PeerError> {
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

            let send_headers = self.send_headers == SendHeadersModel::Unsent
                && matches!(self.get_headers, GetHeadersModel::Ended);

            if ping {
                self.ping_nonce = nonce;
                self.ping_outstanding = true;
                self.ping_deadline = now + super::PING_TIMEOUT;
            }
            if send_headers {
                self.send_headers = SendHeadersModel::Sent;
            }
            self.get_headers =
                headers_deadline.map_or(GetHeadersModel::Ended, GetHeadersModel::Outstanding);
            let wake = headers_deadline.map_or(self.ping_deadline, |deadline| {
                deadline.min(self.ping_deadline)
            });
            assert!(now < wake);
            Ok(TickExpected {
                ping,
                send_headers,
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
                    self.ping_deadline -= super::PING_TIMEOUT - super::PING_INTERVAL;
                    Ok(ReceivedExpected::NoReply)
                }
            } else if msg_type == crate::protocol::HEADERS {
                self.receive_headers(message)
            } else if msg_type == crate::protocol::INV {
                let has_block = message_inv_has_block(message).map_err(super::PeerError::Inv)?;
                if has_block && matches!(self.get_headers, GetHeadersModel::Ended) {
                    assert!(matches!(self.download, DownloadModel::Chain));
                    self.get_headers = GetHeadersModel::Due;
                }
                Ok(ReceivedExpected::NoReply)
            } else if msg_type == crate::protocol::WTXIDRELAY {
                Err(super::PeerError::LateWtxidRelay)
            } else if msg_type == crate::protocol::SENDADDRV2 {
                Err(super::PeerError::LateSendAddrV2)
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
            let announced = matches!(self.get_headers, GetHeadersModel::Ended);
            match self.get_headers {
                GetHeadersModel::Outstanding(_) => {
                    if let Some(first) = headers.first()
                        && !self.locator().contains(&first.prev)
                    {
                        return Ok(ReceivedExpected::NoReply);
                    }
                }
                GetHeadersModel::Ended => {
                    assert!(matches!(self.download, DownloadModel::Chain));
                    if let Some(first) = headers.first()
                        && first.prev != self.tip()
                    {
                        self.receive_off_tip(first.prev, &headers)?;
                        return Ok(ReceivedExpected::NoReply);
                    }
                }
                GetHeadersModel::Due => return Err(super::PeerError::UnsolicitedHeaders),
            }
            let full = headers.len() == HEADERS_FULL_COUNT;
            let download = std::mem::replace(&mut self.download, DownloadModel::Chain);
            let next = match download {
                DownloadModel::Chain if announced => {
                    let batch =
                        script_hashes(self.network, self.tip(), &headers).map_err(extend_error)?;
                    self.chain.extend(batch);
                    full.then_some(DownloadModel::Chain)
                }
                DownloadModel::Chain if full && self.work() < self.work_min => {
                    assert_eq!(self.height(), 0);
                    let hashes =
                        script_hashes(self.network, self.tip(), &headers).map_err(sync_error)?;
                    self.presync_start(0, hashes, full)?
                }
                DownloadModel::Chain => {
                    let extended = self.extend_on_locator(&headers)?;
                    self.chain_next(extended, full)?
                }
                DownloadModel::Branch { fork, hashes } => {
                    let extended = match (headers.first(), hashes.last()) {
                        (None, None) => ExtendedModel::Kept,
                        (None, Some(last)) => ExtendedModel::KeptOver {
                            hash: *last,
                            work_max: self.work_at(fork + hashes.len()),
                        },
                        (Some(_), _) => {
                            let last = hashes.last().copied().unwrap_or(self.chain[fork]);
                            let batch = script_hashes(self.network, last, &headers)
                                .map_err(extend_error)?;
                            self.extend_above(fork, hashes, batch, full)
                        }
                    };
                    self.chain_next(extended, full)?
                }
                DownloadModel::Presync { start, hashes } => {
                    let last = hashes.last().copied().unwrap_or(self.chain[start]);
                    let batch = script_hashes(self.network, last, &headers).map_err(sync_error)?;
                    self.receive_presync(start, hashes, batch, full)?
                }
                DownloadModel::Redownload {
                    start,
                    presync,
                    buffer,
                } => self.receive_redownload(start, presync, buffer, &headers)?,
            };
            match next {
                Some(download) => {
                    self.download = download;
                    self.get_headers = GetHeadersModel::Due;
                    Ok(ReceivedExpected::NoReply)
                }
                None if self.work() < self.work_min => Err(super::PeerError::ChainWorkTooLow),
                None => {
                    self.get_headers = GetHeadersModel::Ended;
                    Ok(ReceivedExpected::Synced)
                }
            }
        }

        fn receive_off_tip(
            &mut self,
            prev: bitcoin_hashes::sha256d::Hash,
            headers: &[crate::block::BlockHeader],
        ) -> Result<(), super::PeerError> {
            if let Some((hash, work, _)) = self.branch_tip
                && hash == prev
            {
                let hashes = script_hashes(self.network, hash, headers).map_err(extend_error)?;
                const { assert!(usize::BITS <= 64) };
                let work = work + hashes.len() as u128 * SCRIPT_HEADER_WORK;
                let full = headers.len() == HEADERS_FULL_COUNT;
                if full || work > self.work() {
                    self.branch_tip = None;
                    self.get_headers = GetHeadersModel::Due;
                    return Ok(());
                }
                let Some(last) = hashes.last() else {
                    panic!("an announcement off our tip has no header");
                };
                self.branch_tip = Some((*last, work, self.height()));
                return Ok(());
            }
            self.get_headers = GetHeadersModel::Due;
            Ok(())
        }

        fn extend_on_locator(
            &mut self,
            headers: &[crate::block::BlockHeader],
        ) -> Result<ExtendedModel, super::PeerError> {
            let Some(first) = headers.first() else {
                return Ok(ExtendedModel::Kept);
            };
            let fork = match self
                .locator_heights()
                .into_iter()
                .find(|height| self.chain[*height] == first.prev)
            {
                Some(height) => height,
                None => {
                    return Err(super::PeerError::Extend(
                        crate::chain::ExtendError::NotOnLocator,
                    ));
                }
            };
            let batch = script_hashes(self.network, first.prev, headers).map_err(extend_error)?;
            if fork == self.height() {
                self.chain.extend(batch);
                return Ok(ExtendedModel::Taken);
            }
            let full = headers.len() == HEADERS_FULL_COUNT;
            Ok(self.extend_above(fork, Vec::new(), batch, full))
        }

        fn extend_above(
            &mut self,
            base: usize,
            branch: Vec<bitcoin_hashes::sha256d::Hash>,
            batch: Vec<bitcoin_hashes::sha256d::Hash>,
            full: bool,
        ) -> ExtendedModel {
            assert!(!batch.is_empty());
            assert!(base < self.height());
            let shared = if branch.is_empty() {
                batch
                    .iter()
                    .zip(&self.chain[base + 1..])
                    .take_while(|(theirs, ours)| theirs == ours)
                    .count()
            } else {
                0
            };
            let fork = base + shared;
            let rest = &batch[shared..];
            if fork == self.height() {
                self.chain.extend_from_slice(rest);
                return ExtendedModel::Taken;
            }
            if rest.is_empty() {
                return ExtendedModel::Branch {
                    fork,
                    hashes: Vec::new(),
                };
            }
            let branch_count = branch.len();
            let mut hashes = branch;
            hashes.extend_from_slice(rest);
            let branch_work = self.work_at(fork + hashes.len());
            if branch_work < self.branch_work_min() {
                assert_eq!(branch_count, 0);
                if !full {
                    let Some(last) = hashes.last() else {
                        panic!("a branch below the margin has no header above the fork");
                    };
                    return ExtendedModel::KeptOver {
                        hash: *last,
                        work_max: self.below_margin_work_max(hashes.len()),
                    };
                }
                return if shared == 0 {
                    ExtendedModel::BelowMargin { fork, hashes }
                } else {
                    ExtendedModel::Branch {
                        fork,
                        hashes: Vec::new(),
                    }
                };
            }
            if branch_work <= self.work() {
                if !full {
                    let Some(last) = hashes.last() else {
                        panic!("a branch with no more work has no header above the fork");
                    };
                    return ExtendedModel::KeptOver {
                        hash: *last,
                        work_max: branch_work,
                    };
                }
                return ExtendedModel::Branch { fork, hashes };
            }
            if let Some((_, _, height)) = self.branch_tip
                && fork < height
            {
                self.branch_tip = None;
            }
            self.chain.truncate(fork + 1);
            self.chain.extend(hashes);
            ExtendedModel::Taken
        }

        fn below_margin_work_max(&self, count: usize) -> u128 {
            const { assert!(usize::BITS <= 64) };
            let work_branch = count as u128 * SCRIPT_HEADER_WORK;
            let work_stop = work_branch + (self.work() - self.branch_work_min());
            let work_above_fork = (work_stop / SCRIPT_HEADER_WORK + 1) * SCRIPT_HEADER_WORK;
            assert!(work_above_fork > work_stop);
            let work = self.work() - work_above_fork + work_branch;
            assert!(work < self.branch_work_min());
            work
        }

        fn branch_work_min(&self) -> u128 {
            const { assert!(usize::BITS <= 64) };
            let behind = SCRIPT_HEADER_WORK * crate::chain::BRANCH_TIP_HEADERS_BEHIND_MAX as u128;
            self.work().saturating_sub(behind).max(self.work_min)
        }

        fn chain_next(
            &mut self,
            extended: ExtendedModel,
            full: bool,
        ) -> Result<Option<DownloadModel>, super::PeerError> {
            match extended {
                ExtendedModel::Taken => Ok(full.then_some(DownloadModel::Chain)),
                ExtendedModel::Kept => Ok(None),
                ExtendedModel::KeptOver { hash, work_max } => {
                    assert!(!full);
                    assert!(work_max <= self.work());
                    self.branch_tip = Some((hash, work_max, self.height()));
                    Ok(None)
                }
                _ if !full => Ok(None),
                ExtendedModel::Branch { fork, hashes } => {
                    Ok(Some(DownloadModel::Branch { fork, hashes }))
                }
                ExtendedModel::BelowMargin { fork, hashes } => {
                    self.presync_start(fork, hashes, full)
                }
            }
        }

        fn presync_start(
            &mut self,
            start: usize,
            batch: Vec<bitcoin_hashes::sha256d::Hash>,
            full: bool,
        ) -> Result<Option<DownloadModel>, super::PeerError> {
            if !self.salt_left {
                return Err(super::PeerError::SecondLowWorkSync);
            }
            self.salt_left = false;
            assert!(self.work_at(start) < self.branch_work_min());
            self.receive_presync(start, Vec::new(), batch, full)
        }

        fn receive_presync(
            &self,
            start: usize,
            mut hashes: Vec<bitcoin_hashes::sha256d::Hash>,
            batch: Vec<bitcoin_hashes::sha256d::Hash>,
            full: bool,
        ) -> Result<Option<DownloadModel>, super::PeerError> {
            hashes.extend(batch);
            if self.work_at(start + hashes.len()) >= self.branch_work_min() {
                Ok(Some(DownloadModel::Redownload {
                    start,
                    presync: hashes,
                    buffer: Vec::new(),
                }))
            } else if full {
                Ok(Some(DownloadModel::Presync { start, hashes }))
            } else {
                Err(super::PeerError::HeadersSync(
                    crate::headerssync::HeadersSyncError::WorkTooLow,
                ))
            }
        }

        fn receive_redownload(
            &mut self,
            start: usize,
            presync: Vec<bitcoin_hashes::sha256d::Hash>,
            mut buffer: Vec<bitcoin_hashes::sha256d::Hash>,
            headers: &[crate::block::BlockHeader],
        ) -> Result<Option<DownloadModel>, super::PeerError> {
            let work_min = self.branch_work_min();
            let period = self.network.commitment_period();
            let mut last = buffer.last().copied().unwrap_or(self.chain[start]);
            for header in headers {
                let hash = script_hash(self.network, last, header).map_err(sync_error)?;
                buffer.push(hash);
                let height = start + buffer.len();
                let below_minimum = self.work_at(height) < work_min;
                let at_commitment = height % period == SCRIPT_OFFSET % period;
                if below_minimum && at_commitment {
                    let Some(first) = presync.get(buffer.len() - 1) else {
                        panic!("the first download has no header at {height}");
                    };
                    if script_commitment(*first) != script_commitment(hash) {
                        return Err(super::PeerError::HeadersSync(
                            crate::headerssync::HeadersSyncError::CommitmentMismatch,
                        ));
                    }
                }
                last = hash;
            }
            let full = headers.len() == HEADERS_FULL_COUNT;
            let on_tip = start == self.height();
            if self.work_at(start + buffer.len()) >= work_min {
                if on_tip {
                    self.chain.extend(buffer);
                    return Ok(full.then_some(DownloadModel::Chain));
                }
                let extended = self.extend_above(start, Vec::new(), buffer, full);
                assert!(!matches!(extended, ExtendedModel::BelowMargin { .. }));
                self.chain_next(extended, full)
            } else if full {
                assert!(buffer.len() <= self.network.redownload_buffer_size());
                Ok(Some(DownloadModel::Redownload {
                    start,
                    presync,
                    buffer,
                }))
            } else {
                Err(super::PeerError::HeadersSync(
                    crate::headerssync::HeadersSyncError::WorkTooLow,
                ))
            }
        }

        fn height(&self) -> usize {
            self.chain.len() - 1
        }

        fn work(&self) -> u128 {
            self.work_at(self.height())
        }

        fn work_at(&self, height: usize) -> u128 {
            let genesis_work: u128 = match self.network {
                crate::chainparams::Network::Mainnet | crate::chainparams::Network::Testnet4 => {
                    0x1_0001_0001
                }
                crate::chainparams::Network::Signet => 0x49_d414,
                crate::chainparams::Network::Regtest => 2,
            };
            const { assert!(usize::BITS <= 64) };
            genesis_work + height as u128 * SCRIPT_HEADER_WORK
        }
    }

    fn script_hash(
        network: crate::chainparams::Network,
        below: bitcoin_hashes::sha256d::Hash,
        header: &crate::block::BlockHeader,
    ) -> Result<bitcoin_hashes::sha256d::Hash, HeaderFault> {
        if header.prev != below {
            return Err(HeaderFault::Prev);
        }
        assert_eq!(header.bits, SCRIPT_HEADER_BITS);
        assert_eq!(header.version, SCRIPT_HEADER_VERSION);
        assert!(header.hash().as_byte_array()[31] < 0x7f);
        if network != crate::chainparams::Network::Regtest {
            return Err(HeaderFault::ProofOfWork);
        }
        Ok(header.hash())
    }

    fn script_hashes(
        network: crate::chainparams::Network,
        below_first: bitcoin_hashes::sha256d::Hash,
        headers: &[crate::block::BlockHeader],
    ) -> Result<Vec<bitcoin_hashes::sha256d::Hash>, HeaderFault> {
        let mut hashes: Vec<bitcoin_hashes::sha256d::Hash> = Vec::with_capacity(headers.len());
        for header in headers {
            let below = hashes.last().copied().unwrap_or(below_first);
            hashes.push(script_hash(network, below, header)?);
        }
        Ok(hashes)
    }

    fn script_commitment(hash: bitcoin_hashes::sha256d::Hash) -> bool {
        let [key_0, key_1] = SCRIPT_KEYS;
        bitcoin_hashes::siphash24::Hash::hash_to_u64_with_keys(key_0, key_1, hash.as_byte_array())
            .is_multiple_of(2)
    }

    fn extend_error(fault: HeaderFault) -> super::PeerError {
        super::PeerError::Extend(match fault {
            HeaderFault::Prev => crate::chain::ExtendError::NotContinuous,
            HeaderFault::ProofOfWork => crate::chain::ExtendError::ProofOfWork,
        })
    }

    fn sync_error(fault: HeaderFault) -> super::PeerError {
        super::PeerError::HeadersSync(match fault {
            HeaderFault::Prev => crate::headerssync::HeadersSyncError::NotContinuous,
            HeaderFault::ProofOfWork => crate::headerssync::HeadersSyncError::ProofOfWork,
        })
    }

    fn message_nonce(message: &crate::transport::Message) -> Result<u64, crate::serialize::Error> {
        match message.payload().first_chunk() {
            Some(nonce) => Ok(u64::from_le_bytes(*nonce)),
            None => Err(crate::serialize::Error::UnexpectedEnd),
        }
    }

    fn message_inv_has_block(
        message: &crate::transport::Message,
    ) -> Result<bool, crate::protocol::InvError> {
        let mut input = message.payload();
        let count = crate::serialize::read_compact_size(&mut input)
            .map_err(crate::protocol::InvError::Payload)?;
        if count > crate::protocol::INV_COUNT_MAX {
            return Err(crate::protocol::InvError::TooMany(count));
        }
        let Some(entries) = input.get(..count * 36) else {
            return Err(crate::protocol::InvError::Payload(
                crate::serialize::Error::UnexpectedEnd,
            ));
        };
        Ok(entries
            .chunks(36)
            .any(|entry| entry.starts_with(&[2, 0, 0, 0])))
    }

    #[cfg(test)]
    mod tests {
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

    fn message(frame: &[u8]) -> crate::transport::Message {
        let (header, payload) = frame.split_first_chunk().unwrap();
        let header =
            crate::transport::decode_header(crate::chainparams::Network::Regtest, header).unwrap();
        crate::transport::check_payload(header, payload.to_vec()).unwrap()
    }

    fn core_message(frame: &str) -> crate::transport::Message {
        message(&crate::fixtures::hex(frame))
    }

    fn version_message(change: impl FnOnce(&mut Vec<u8>)) -> crate::transport::Message {
        let mut payload = crate::fixtures::version_payload();
        change(&mut payload);
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::VERSION,
            &payload,
        ))
    }

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

    fn pong_message(payload: &[u8]) -> crate::transport::Message {
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::PONG,
            payload,
        ))
    }

    fn pong(nonce: u64) -> crate::transport::Message {
        pong_message(&nonce.to_le_bytes())
    }

    fn headers_payload_message(payload: &[u8]) -> crate::transport::Message {
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::HEADERS,
            payload,
        ))
    }

    fn inv_message(types: &[u32]) -> crate::transport::Message {
        inv_payload_message(&crate::fixtures::inv_payload(types))
    }

    fn inv_payload_message(payload: &[u8]) -> crate::transport::Message {
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::INV,
            payload,
        ))
    }

    fn headers_message(headers: &[crate::block::BlockHeader]) -> crate::transport::Message {
        headers_payload_message(&crate::fixtures::headers_payload_with(headers))
    }

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

    fn asked_with(
        chain: &mut crate::chain::Chain,
        work_min: crate::pow::Work,
        now: std::time::Instant,
    ) -> super::Peer<'_> {
        let handshake = start_with(chain, work_min);
        asked_from(peer_with(handshake), now, 7)
    }

    fn batch_then_tick<'a>(
        peer: super::Peer<'a>,
        headers: &[crate::block::BlockHeader],
        now: std::time::Instant,
    ) -> (super::Peer<'a>, crate::protocol::GetHeaders) {
        let peer = accept(peer, &headers_message(headers));
        match peer.tick(now, 8) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: None,
                    send_headers: false,
                    get_headers: Some(get_headers),
                },
                _,
            )) => (peer, get_headers),
            other => panic!("{other:?}"),
        }
    }

    fn get_headers_after(header: &crate::block::BlockHeader) -> crate::protocol::GetHeaders {
        crate::protocol::GetHeaders::new(vec![header.hash()])
    }

    fn get_headers_on(headers: &[crate::block::BlockHeader]) -> crate::protocol::GetHeaders {
        let mut chain = regtest();
        for batch in headers.chunks(crate::protocol::HEADERS_COUNT_MAX) {
            chain
                .extend(
                    crate::fixtures::headers_batch(batch),
                    crate::fixtures::CLOCK,
                )
                .unwrap();
        }
        crate::protocol::GetHeaders::new(chain.locator())
    }

    fn regtest() -> crate::chain::Chain {
        crate::chain::Chain::new(crate::chainparams::Network::Regtest)
    }

    fn start(chain: &mut crate::chain::Chain) -> super::Handshake<'_> {
        let work_min = crate::pow::chain_work_min(chain.network());
        start_with(chain, work_min)
    }

    fn start_with(
        chain: &mut crate::chain::Chain,
        work_min: crate::pow::Work,
    ) -> super::Handshake<'_> {
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        super::Handshake::start(peer, 0, 0, chain, work_min, SALT).0
    }

    fn wait(step: Result<super::Step<'_>, super::HandshakeError>) -> super::Handshake<'_> {
        match step {
            Ok(super::Step::Wait(handshake)) => handshake,
            other => panic!("{other:?}"),
        }
    }

    fn reply(
        step: Result<super::Step<'_>, super::HandshakeError>,
    ) -> (super::Handshake<'_>, super::HandshakeOutbound) {
        match step {
            Ok(super::Step::Reply(handshake, outbound)) => (handshake, outbound),
            other => panic!("{other:?}"),
        }
    }

    fn peer(chain: &mut crate::chain::Chain) -> super::Peer<'_> {
        peer_with(start(chain))
    }

    fn peer_with(handshake: super::Handshake<'_>) -> super::Peer<'_> {
        let (handshake, _) =
            reply(handshake.receive(&core_message(crate::fixtures::VERSION_FRAME)));
        match handshake.receive(&core_message(crate::fixtures::VERACK_FRAME)) {
            Ok(super::Step::Done(peer, _)) => peer,
            other => panic!("{other:?}"),
        }
    }

    fn asked(
        chain: &mut crate::chain::Chain,
        now: std::time::Instant,
        nonce: u64,
    ) -> super::Peer<'_> {
        asked_from(peer(chain), now, nonce)
    }

    fn asked_from(peer: super::Peer<'_>, now: std::time::Instant, nonce: u64) -> super::Peer<'_> {
        match peer.tick(now, nonce) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: Some(sent),
                    send_headers: false,
                    get_headers: Some(_),
                },
                _,
            )) if sent == nonce => peer,
            other => panic!("{other:?}"),
        }
    }

    fn first_get_headers(
        peer: super::Peer<'_>,
        now: std::time::Instant,
    ) -> (super::Peer<'_>, crate::protocol::GetHeaders) {
        match peer.tick(now, 7) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: Some(_),
                    send_headers: false,
                    get_headers: Some(get_headers),
                },
                _,
            )) => (peer, get_headers),
            other => panic!("{other:?}"),
        }
    }

    fn pinged(
        chain: &mut crate::chain::Chain,
        now: std::time::Instant,
        nonce: u64,
    ) -> super::Peer<'_> {
        let peer = synced(asked(chain, now, nonce), &[]);
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: None,
                    send_headers: true,
                    get_headers: None,
                },
                _,
            )) => peer,
            other => panic!("{other:?}"),
        }
    }

    fn synced<'a>(peer: super::Peer<'a>, headers: &[crate::block::BlockHeader]) -> super::Peer<'a> {
        match peer.receive(&headers_message(headers), crate::fixtures::CLOCK) {
            Ok((peer, super::Received::Synced(_))) => peer,
            other => panic!("{other:?}"),
        }
    }

    fn idle(
        peer: super::Peer<'_>,
        now: std::time::Instant,
    ) -> (super::Peer<'_>, std::time::Instant) {
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: None,
                    send_headers: false,
                    get_headers: None,
                },
                wake,
            )) => (peer, wake),
            other => panic!("{other:?}"),
        }
    }

    fn accept<'a>(peer: super::Peer<'a>, message: &crate::transport::Message) -> super::Peer<'a> {
        match peer.receive(message, crate::fixtures::CLOCK) {
            Ok((peer, super::Received::NoReply)) => peer,
            other => panic!("{other:?}"),
        }
    }

    const NANOSECOND: std::time::Duration = std::time::Duration::from_nanos(1);

    const SALT: crate::headerssync::Salt = crate::headerssync::Salt::new([1, 2], 3);

    #[test]
    fn handshake_skips_until_their_version_and_then_until_their_verack() {
        let mut chain = regtest();
        let handshake =
            wait(start(&mut chain).receive(&core_message(crate::fixtures::VERACK_FRAME)));
        let (mut handshake, outbound) =
            reply(handshake.receive(&core_message(crate::fixtures::VERSION_FRAME)));
        assert!(
            matches!(outbound, super::HandshakeOutbound::Verack),
            "{outbound:?}"
        );

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
        let wtxidrelay = core_message(crate::fixtures::WTXIDRELAY_FRAME);
        fn before_the_last<'a>(
            chain: &'a mut crate::chain::Chain,
            wtxidrelay: &crate::transport::Message,
        ) -> super::Handshake<'a> {
            let (mut handshake, _) =
                reply(start(chain).receive(&core_message(crate::fixtures::VERSION_FRAME)));
            for _ in 2..super::MESSAGE_COUNT_MAX {
                handshake = wait(handshake.receive(wtxidrelay));
            }
            handshake
        }

        let verack = core_message(crate::fixtures::VERACK_FRAME);
        let mut chain = regtest();
        let done = before_the_last(&mut chain, &wtxidrelay).receive(&verack);
        assert!(matches!(done, Ok(super::Step::Done(..))), "{done:?}");
        let mut chain = regtest();
        let refused = before_the_last(&mut chain, &wtxidrelay)
            .receive(&wtxidrelay)
            .err();
        assert_eq!(refused, Some(super::HandshakeError::TooManyMessages));
    }

    #[test]
    fn their_version_is_at_least_protocol_version_min() {
        let mut chain = regtest();
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
            let outcome = start(&mut chain).receive(&message).map(|step| {
                reply(Ok(step));
            });
            assert_eq!(outcome, expected, "version {version}");
        }
    }

    #[test]
    fn their_version_with_our_nonce_is_self_connection() {
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        let mut chain = regtest();
        let (handshake, outbound) = super::Handshake::start(
            peer,
            0,
            0x0123_4567_89ab_cdef,
            &mut chain,
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
        let mut chain = regtest();
        let truncated = version_message(|payload| {
            payload.truncate(payload.len() - size_of::<i32>() - size_of::<bool>());
        });
        assert_eq!(
            start(&mut chain).receive(&truncated).err(),
            Some(super::HandshakeError::Version(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = version_message(|payload| payload.push(0xaa));
        reply(start(&mut chain).receive(&longer));
    }

    #[test]
    fn their_ping_gets_a_pong_with_its_nonce() {
        let mut chain = regtest();
        let outbound = peer(&mut chain).receive(
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
        let mut chain = regtest();
        let short = ping_message(|payload| payload.truncate(size_of::<u64>() - 1));
        assert_eq!(
            peer(&mut chain)
                .receive(&short, crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Ping(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = ping_message(|payload| payload.push(0xaa));
        let outbound = peer(&mut chain).receive(&longer, crate::fixtures::CLOCK);
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
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let outbound = pinged(&mut chain, start, 7).receive(
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
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let ticked = peer(&mut chain).tick(start, 7);
        let Ok((_, outbound, wake)) = ticked else {
            panic!("{ticked:?}");
        };
        let outbounds: Vec<_> = outbound.into_outbounds().collect();
        let genesis = get_headers_on(&[]);
        assert!(
            matches!(
                &outbounds[..],
                [
                    super::PeerOutbound::Ping(7),
                    super::PeerOutbound::GetHeaders(get_headers),
                ] if *get_headers == genesis
            ),
            "{outbounds:?}"
        );
        assert_eq!(wake, start + super::HEADERS_TIMEOUT);
    }

    #[test]
    fn no_second_ping_while_one_is_outstanding() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let (_, wake) = idle(pinged(&mut chain, start, 7), start + super::PING_INTERVAL);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn next_ping_is_due_ping_interval_after_the_last_ping_went() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let due = start + super::PING_INTERVAL;
        let peer = accept(pinged(&mut chain, start, 7), &pong(7));
        let (peer, wake) = idle(peer, due - NANOSECOND);
        assert_eq!(wake, due);
        let ticked = peer.tick(due, 8);
        let Ok((
            _,
            super::TickOutbound {
                ping: Some(8),
                send_headers: false,
                get_headers: None,
            },
            wake,
        )) = ticked
        else {
            panic!("{ticked:?}");
        };
        assert_eq!(wake, due + super::PING_TIMEOUT);

        let late = due + std::time::Duration::from_mins(1);
        let (peer, _) = idle(pinged(&mut chain, start, 7), late);
        let ticked = accept(peer, &pong(7)).tick(late, 8);
        assert!(
            matches!(
                ticked,
                Ok((
                    _,
                    super::TickOutbound {
                        ping: Some(8),
                        send_headers: false,
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
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let timeout = start + super::PING_TIMEOUT;
        let (peer, wake) = idle(pinged(&mut chain, start, 7), timeout - NANOSECOND);
        assert_eq!(wake, timeout);
        assert_eq!(
            peer.tick(timeout, 8).err(),
            Some(super::PeerError::PingTimeout)
        );
    }

    #[test]
    fn their_pong_needs_a_nonce_and_may_have_bytes_after_it() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let short = pong_message(&7_u64.to_le_bytes()[..size_of::<u64>() - 1]);
        for peer in [peer(&mut regtest()), pinged(&mut chain, start, 7)] {
            assert_eq!(
                peer.receive(&short, crate::fixtures::CLOCK).err(),
                Some(super::PeerError::Pong(
                    crate::serialize::Error::UnexpectedEnd
                ))
            );
        }

        let mut longer = 7_u64.to_le_bytes().to_vec();
        longer.push(0xaa);
        accept(pinged(&mut chain, start, 7), &pong_message(&longer));
    }

    #[test]
    fn pong_without_our_ping_is_unsolicited_pong() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let answered = accept(pinged(&mut chain, start, 7), &pong(7));
        for peer in [peer(&mut regtest()), answered] {
            assert_eq!(
                peer.receive(&pong(7), crate::fixtures::CLOCK).err(),
                Some(super::PeerError::UnsolicitedPong)
            );
        }
    }

    #[test]
    fn pong_with_another_nonce_is_pong_nonce() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        assert_eq!(
            pinged(&mut chain, start, 7)
                .receive(&pong(8), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::PongNonce)
        );
    }

    #[test]
    fn peer_skips_every_message_but_ping_pong_and_headers() {
        let mut chain = regtest();
        for message in [
            core_message(crate::fixtures::SENDCMPCT_FRAME),
            core_message(crate::fixtures::FEEFILTER_FRAME),
            core_message(crate::fixtures::BLOCK_INV_FRAME),
            core_message(crate::fixtures::GETHEADERS_FRAME),
            version_message(Vec::clear),
            core_message(crate::fixtures::VERACK_FRAME),
        ] {
            let outbound = peer(&mut chain).receive(&message, crate::fixtures::CLOCK);
            assert!(
                matches!(outbound, Ok((_, super::Received::NoReply))),
                "{:?}: {outbound:?}",
                message.msg_type()
            );
        }
    }

    #[test]
    fn peer_refuses_wtxidrelay_and_sendaddrv2() {
        let mut chain = regtest();
        for (frame, error) in [
            (
                crate::fixtures::WTXIDRELAY_FRAME,
                super::PeerError::LateWtxidRelay,
            ),
            (
                crate::fixtures::SENDADDRV2_FRAME,
                super::PeerError::LateSendAddrV2,
            ),
        ] {
            let refused = peer(&mut chain)
                .receive(&core_message(frame), crate::fixtures::CLOCK)
                .err();
            assert_eq!(refused, Some(error));
        }
    }

    #[test]
    fn full_batch_makes_the_next_tick_send_getheaders_from_the_new_tip() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2000);
        let peer = accept(asked(&mut chain, start, 7), &headers_message(&headers));

        let later = start + std::time::Duration::from_mins(1);
        let ticked = peer.tick(later, 8);
        let Ok((
            _,
            super::TickOutbound {
                ping: None,
                send_headers: false,
                get_headers: Some(get_headers),
            },
            wake,
        )) = ticked
        else {
            panic!("{ticked:?}");
        };
        assert_eq!(get_headers, get_headers_on(&headers));
        assert_eq!(wake, later + super::HEADERS_TIMEOUT);
    }

    #[test]
    fn short_batch_ends_the_sync_at_its_last_header() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let received =
            asked(&mut chain, start, 7).receive(&headers_message(&headers), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn empty_batch_ends_the_sync_at_our_tip() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2000);
        let peer = accept(asked(&mut chain, start, 7), &headers_message(&headers));
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
    fn next_handshake_on_the_same_chain_syncs_from_its_tip() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = regtest();
        {
            let received = asked(&mut chain, start, 7)
                .receive(&headers_message(&headers), crate::fixtures::CLOCK);
            assert!(
                matches!(received, Ok((_, super::Received::Synced(_)))),
                "{received:?}"
            );
        }

        let work_min = chain.tip().work();
        let peer = peer_with(start_with(&mut chain, work_min));
        let (peer, get_headers) = first_get_headers(peer, start);
        assert_eq!(get_headers, get_headers_on(&headers));
        let received = peer.receive(&headers_message(&[]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn handshake_on_a_chain_below_the_minimum_starts_it_again_from_genesis() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = regtest();
        chain
            .extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK,
            )
            .unwrap();
        let work_min = tip_after(&crate::fixtures::headers_on_genesis(4)).work();
        let peer = peer_with(start_with(&mut chain, work_min));
        let (_, get_headers) = first_get_headers(peer, std::time::Instant::now());
        assert_eq!(get_headers, get_headers_on(&[]));
        assert_eq!(chain.tip(), tip_after(&[]));
    }

    #[test]
    fn answer_on_a_header_below_our_tip_with_no_more_work_ends_the_sync_on_our_tip() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let branch = crate::fixtures::branch_on(&headers[0], 2);
        for batch in [&headers[..1], &headers[1..], &branch[..]] {
            let mut chain = regtest();
            chain
                .extend(
                    crate::fixtures::headers_batch(&headers),
                    crate::fixtures::CLOCK,
                )
                .unwrap();
            let received = asked(&mut chain, std::time::Instant::now(), 7)
                .receive(&headers_message(batch), crate::fixtures::CLOCK);
            let Ok((_, super::Received::Synced(tip))) = received else {
                panic!("{received:?}");
            };
            assert_eq!(tip, tip_after(&headers));
        }
    }

    #[test]
    fn answer_with_a_branch_of_more_work_takes_the_place_of_our_branch() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let branch = crate::fixtures::branch_on(&headers[0], 3);
        let mut chain = regtest();
        chain
            .extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK,
            )
            .unwrap();
        let received = asked(&mut chain, std::time::Instant::now(), 7)
            .receive(&headers_message(&branch), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        let ours = [headers[0], branch[0], branch[1], branch[2]];
        assert_eq!(tip, tip_after(&ours));
    }

    #[test]
    fn full_answer_with_a_branch_of_more_work_makes_the_next_getheaders_from_its_tip() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3);
        let branch =
            crate::fixtures::branch_on(&crate::chainparams::Network::Regtest.genesis(), 2_000);
        let mut chain = regtest();
        chain
            .extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK,
            )
            .unwrap();
        let (_, get_headers) = batch_then_tick(asked(&mut chain, start, 7), &branch, start);
        assert_eq!(get_headers, get_headers_on(&branch));
    }

    #[test]
    fn full_answer_of_our_headers_below_our_tip_makes_the_next_getheaders_from_its_last_header() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_001);
        let mut chain = regtest();
        for batch in crate::protocol::Headers::batches(headers.clone()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        let (_, get_headers) =
            batch_then_tick(asked(&mut chain, start, 7), &headers[..2_000], start);
        assert_eq!(get_headers, get_headers_after(&headers[1_999]));
        assert_eq!(chain.tip(), tip_after(&headers));
    }

    fn low_work_sync_on_block_50(
        chain: &mut crate::chain::Chain,
        count: usize,
        start: std::time::Instant,
    ) -> (super::Peer<'_>, Vec<crate::block::BlockHeader>) {
        let headers = crate::fixtures::headers_on_genesis(2_200);
        let branch = crate::fixtures::branch_on(&headers[49], count);
        for batch in crate::protocol::Headers::batches(headers.clone()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        let ours = chain.tip();
        let mut peer = asked(chain, start, 7);
        let batches = [
            (
                &[&headers[..50], &branch[..1_950]].concat()[..],
                &headers[49],
            ),
            (&branch[..2_000], &branch[1_999]),
            (&branch[2_000..], &headers[49]),
            (&branch[..2_000], &branch[1_999]),
        ];
        for (batch, after) in batches {
            let (next, get_headers) = batch_then_tick(peer, batch, start);
            assert_eq!(get_headers, get_headers_after(after));
            assert_eq!(next.chain.tip(), ours);
            peer = next;
        }
        (peer, [&headers[..50], &branch[..]].concat())
    }

    #[test]
    fn low_work_sync_of_a_branch_below_the_margin_takes_it_only_with_more_work() {
        for (count, taken) in [(2_300, true), (2_100, false)] {
            let mut chain = regtest();
            let (peer, theirs) =
                low_work_sync_on_block_50(&mut chain, count, std::time::Instant::now());
            let ours = peer.chain.tip();
            let received = peer.receive(&headers_message(&theirs[2_050..]), crate::fixtures::CLOCK);
            let Ok((_, super::Received::Synced(tip))) = received else {
                panic!("{received:?}");
            };
            let expected = if taken { tip_after(&theirs) } else { ours };
            assert_eq!(tip, expected, "{count}");
        }
    }

    #[test]
    fn low_work_sync_of_a_branch_keeps_the_headers_that_its_second_download_releases() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(9_500);
        let branch =
            crate::fixtures::branch_on(&crate::chainparams::Network::Regtest.genesis(), 9_600);
        let mut chain = regtest();
        for batch in crate::protocol::Headers::batches(headers.clone()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        let ours = chain.tip();
        let mut peer = asked(&mut chain, start, 7);
        let genesis = crate::chainparams::Network::Regtest.genesis();
        for download in 0..2 {
            for first in (0..8_000).step_by(2_000) {
                let batch = &branch[first..first + 2_000];
                let (next, get_headers) = batch_then_tick(peer, batch, start);
                assert_eq!(get_headers, get_headers_after(&branch[first + 1_999]));
                peer = next;
            }
            if download == 0 {
                let (next, get_headers) = batch_then_tick(peer, &branch[8_000..], start);
                assert_eq!(get_headers, get_headers_after(&genesis));
                peer = next;
            }
            assert_eq!(peer.chain.tip(), ours);
        }
        let received = peer.receive(&headers_message(&branch[8_000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&branch));
    }

    fn sent_send_headers(peer: super::Peer<'_>, now: std::time::Instant) -> super::Peer<'_> {
        match peer.tick(now, 0) {
            Ok((peer, outbound, _)) => {
                assert!(outbound.send_headers, "{outbound:?}");
                peer
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn second_low_work_sync_in_one_connection_ends_it() {
        let start = std::time::Instant::now();
        let mut chain = regtest();
        let (peer, theirs) = low_work_sync_on_block_50(&mut chain, 2_100, start);
        let peer = sent_send_headers(synced(peer, &theirs[2_050..]), start);
        let (peer, get_headers) = batch_then_tick(peer, &theirs[2_149..], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.locator())
        );
        let (peer, get_headers) = batch_then_tick(peer, &theirs[..2_000], start);
        assert_eq!(get_headers, get_headers_after(&theirs[49]));
        let refused = peer
            .receive(&headers_message(&theirs[50..2_050]), crate::fixtures::CLOCK)
            .err();
        assert_eq!(refused, Some(super::PeerError::SecondLowWorkSync));
    }

    #[test]
    fn announcement_on_a_branch_that_lost_to_ours_asks_for_it_only_with_more_work_than_ours() {
        let start = std::time::Instant::now();
        let mut chain = regtest();
        let (peer, theirs) = low_work_sync_on_block_50(&mut chain, 2_100, start);
        let peer = sent_send_headers(synced(peer, &theirs[2_050..]), start);
        let more = crate::fixtures::headers_on(&theirs[2_149], 52);
        let peer = synced(peer, &more[..25]);
        let (peer, _) = idle(peer, start);
        let ours = crate::fixtures::headers_on_genesis(2_200);
        let peer = synced(peer, &crate::fixtures::headers_on(&ours[2_199], 1));
        let (peer, _) = idle(peer, start);
        let peer = synced(peer, &more[25..51]);
        let (peer, _) = idle(peer, start);
        let (peer, get_headers) = batch_then_tick(peer, &more[51..], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.locator())
        );
    }

    #[test]
    fn branch_that_lost_to_ours_and_then_took_our_chain_is_no_longer_a_branch_tip() {
        let start = std::time::Instant::now();
        let mut chain = regtest();
        let ours = crate::fixtures::headers_on_genesis(100);
        let work_min = tip_after(&ours[..2]).work();
        let peer = synced(asked_with(&mut chain, work_min, start), &ours);
        let peer = sent_send_headers(peer, start);
        let branch = crate::fixtures::branch_on(&ours[97], 2);
        let (peer, _) = batch_then_tick(peer, &branch, start);
        let peer = synced(peer, &branch);
        let more = crate::fixtures::headers_on(&branch[1], 2);
        let (peer, _) = batch_then_tick(peer, &[branch[1], more[0]], start);
        let peer = synced(peer, &[branch[0], branch[1], more[0]]);
        let theirs = [&ours[..98], &branch[..], &more[..]].concat();
        assert_eq!(peer.chain.tip(), tip_after(&theirs[..101]));
        let (peer, get_headers) = batch_then_tick(peer, &more[..1], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.locator())
        );
        let peer = synced(peer, &[]);
        let (peer, _) = idle(peer, start);
        let peer = synced(peer, &more[1..]);
        let (peer, _) = idle(peer, start);
        assert_eq!(peer.chain.tip(), tip_after(&theirs));
    }

    #[test]
    fn branch_that_lost_to_ours_stays_a_branch_tip_after_an_answer_that_extends_our_tip() {
        let start = std::time::Instant::now();
        let mut chain = regtest();
        let ours = crate::fixtures::headers_on_genesis(101);
        let work_min = tip_after(&ours[..2]).work();
        let peer = synced(asked_with(&mut chain, work_min, start), &ours[..100]);
        let peer = sent_send_headers(peer, start);
        let branch = crate::fixtures::branch_on(&ours[97], 2);
        let (peer, _) = batch_then_tick(peer, &branch, start);
        let peer = synced(peer, &branch);
        let (peer, _) = batch_then_tick(peer, &ours[99..], start);
        let peer = synced(peer, &ours[100..]);
        assert_eq!(peer.chain.tip(), tip_after(&ours));
        let more = crate::fixtures::headers_on(&branch[1], 2);
        let peer = synced(peer, &more[..1]);
        let (peer, _) = idle(peer, start);
        let (peer, get_headers) = batch_then_tick(peer, &more[1..], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.locator())
        );
    }

    #[test]
    fn first_batch_on_genesis_that_starts_no_low_work_sync_keeps_the_salt_for_a_branch() {
        let start = std::time::Instant::now();
        let mut chain = regtest();
        let headers = crate::fixtures::headers_on_genesis(3_000);
        let branch =
            crate::fixtures::branch_on(&crate::chainparams::Network::Regtest.genesis(), 2_000);
        let work_min = tip_after(&headers[..2]).work();
        let peer = synced(asked_with(&mut chain, work_min, start), &headers[..1_000]);
        let peer = sent_send_headers(peer, start);
        let (peer, get_headers) = batch_then_tick(peer, &headers[1_000..], start);
        assert_eq!(get_headers, get_headers_on(&headers));
        let (peer, get_headers) = batch_then_tick(peer, &branch, start);
        assert_eq!(get_headers, get_headers_after(&branch[1_999]));
        assert_eq!(peer.chain.tip(), tip_after(&headers));
    }

    #[test]
    fn branch_over_two_batches_with_more_work_takes_the_place_of_our_chain() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_100);
        let branch =
            crate::fixtures::branch_on(&crate::chainparams::Network::Regtest.genesis(), 2_200);
        let mut chain = regtest();
        for batch in crate::protocol::Headers::batches(headers.clone()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        let (peer, get_headers) =
            batch_then_tick(asked(&mut chain, start, 7), &branch[..2_000], start);
        assert_eq!(get_headers, get_headers_after(&branch[1_999]));
        let received = peer.receive(&headers_message(&branch[2_000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&branch));
    }

    #[test]
    fn refused_answer_keeps_the_chain() {
        let headers = crate::fixtures::headers_on_genesis(14);
        let on_tip = crate::fixtures::headers_on(&headers[13], 1);
        let mut unproven = headers[0];
        unproven.nonce = (0..=u32::MAX)
            .find(|nonce| {
                let header = crate::block::BlockHeader {
                    nonce: *nonce,
                    ..unproven
                };
                header.hash().as_byte_array()[31] >= 0x80
            })
            .unwrap();
        for (batch, error) in [
            (vec![unproven], crate::chain::ExtendError::ProofOfWork),
            (
                vec![on_tip[0], on_tip[0]],
                crate::chain::ExtendError::NotContinuous,
            ),
        ] {
            let mut chain = regtest();
            chain
                .extend(
                    crate::fixtures::headers_batch(&headers),
                    crate::fixtures::CLOCK,
                )
                .unwrap();
            let refused = asked(&mut chain, std::time::Instant::now(), 7)
                .receive(&headers_message(&batch), crate::fixtures::CLOCK)
                .err();
            assert_eq!(refused, Some(super::PeerError::Extend(error)));
            assert_eq!(chain.tip(), tip_after(&headers), "{error:?}");
        }
    }

    #[test]
    fn announcement_off_our_tip_after_the_sync_makes_the_next_tick_send_getheaders_from_our_tip() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3);
        let other = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            time: headers[0].time + 1,
            ..headers[0]
        });
        assert_ne!(other.hash(), headers[0].hash());
        for announced in [&headers[..1], &[other][..], &headers[2..]] {
            let mut chain = regtest();
            let peer = synced(pinged(&mut chain, start, 7), &headers[..1]);
            let later = start + std::time::Duration::from_mins(1);
            let (peer, get_headers) = batch_then_tick(peer, announced, later);
            assert_eq!(get_headers, get_headers_on(&headers[..1]));
            let received = peer.receive(&headers_message(&headers[1..]), crate::fixtures::CLOCK);
            let Ok((_, super::Received::Synced(tip))) = received else {
                panic!("{received:?}");
            };
            assert_eq!(tip, tip_after(&headers));
        }
    }

    #[test]
    fn sync_that_ends_below_the_minimum_work_ends_the_connection() {
        let start = std::time::Instant::now();
        for (network, expected) in [
            (crate::chainparams::Network::Mainnet, false),
            (crate::chainparams::Network::Testnet4, false),
            (crate::chainparams::Network::Signet, false),
            (crate::chainparams::Network::Regtest, true),
        ] {
            let mut chain = crate::chain::Chain::new(network);
            let received =
                asked(&mut chain, start, 7).receive(&headers_message(&[]), crate::fixtures::CLOCK);
            match received {
                Ok((_, super::Received::Synced(_))) => assert!(expected, "{network:?}"),
                Err(super::PeerError::ChainWorkTooLow) => assert!(!expected, "{network:?}"),
                other => panic!("{network:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn sync_that_ends_at_the_minimum_work_ends_there() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let work_min = tip_after(&headers).work();
        let received = asked_with(&mut chain, work_min, start)
            .receive(&headers_message(&headers), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn full_batch_on_a_chain_at_the_minimum_work_goes_on_the_chain() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_002);
        let work_min = tip_after(&[]).work();
        let (peer, get_headers) = batch_then_tick(
            asked_with(&mut chain, work_min, start),
            &headers[..2_000],
            start,
        );
        assert_eq!(get_headers, get_headers_on(&headers[..2_000]));
        let received = peer.receive(&headers_message(&headers[2_000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn full_batch_below_the_minimum_work_starts_a_sync_that_gets_the_chain_twice() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(12_002);
        let work_min = tip_after(&headers[..11_000]).work();
        let batches: Vec<_> = headers[..12_000].chunks(2_000).collect();
        let mut peer = asked_with(&mut chain, work_min, start);
        for (index, batch) in batches.iter().enumerate() {
            let get_headers;
            (peer, get_headers) = batch_then_tick(peer, batch, start);
            let expected = match batches.get(index + 1) {
                Some(_) => get_headers_after(&batch[1_999]),
                None => get_headers_after(&crate::chainparams::Network::Regtest.genesis()),
            };
            assert_eq!(get_headers, expected, "first download, batch {index}");
        }
        for (index, batch) in batches.iter().enumerate() {
            let get_headers;
            (peer, get_headers) = batch_then_tick(peer, batch, start);
            let expected = match batches.get(index + 1) {
                Some(_) => get_headers_after(&batch[1_999]),
                None => get_headers_on(&headers[..12_000]),
            };
            assert_eq!(get_headers, expected, "second download, batch {index}");
        }
        let received = peer.receive(&headers_message(&headers[12_000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn low_work_sync_that_reaches_the_minimum_in_a_short_batch_ends_there() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3_500);
        let work_min = tip_after(&headers).work();
        let (peer, _) = batch_then_tick(
            asked_with(&mut chain, work_min, start),
            &headers[..2_000],
            start,
        );
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
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_000);
        let work_min = tip_after(&headers)
            .work()
            .saturating_add(tip_after(&[]).work());
        let (peer, _) = batch_then_tick(asked_with(&mut chain, work_min, start), &headers, start);
        let next = crate::fixtures::headers_on(&headers[1_999], 1);
        assert_eq!(
            peer.receive(
                &headers_message(&[next[0], next[0]]),
                crate::fixtures::CLOCK
            )
            .err(),
            Some(super::PeerError::HeadersSync(
                crate::headerssync::HeadersSyncError::NotContinuous
            ))
        );
    }

    #[test]
    fn each_header_that_a_low_work_sync_releases_goes_through_the_checks_of_the_chain() {
        let mut chain = regtest();
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
        let work_min = tip_after(&crate::fixtures::headers_on_genesis(3_000)).work();
        let (peer, _) = batch_then_tick(asked_with(&mut chain, work_min, start), &first, start);
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
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let later = start + std::time::Duration::from_mins(10);
        let (_, wake) = idle(pinged(&mut chain, start, 7), later);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn headers_before_our_first_getheaders_is_unsolicited_headers() {
        let mut chain = regtest();
        assert_eq!(
            peer(&mut chain)
                .receive(&headers_message(&[]), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::UnsolicitedHeaders)
        );
    }

    #[test]
    fn each_announcement_after_the_sync_goes_on_our_tip_and_ends_a_sync_again() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut peer = pinged(&mut chain, start, 7);
        for (announced, height) in [(&headers[..1], 1), (&headers[1..], 3), (&[][..], 3)] {
            let received = peer.receive(&headers_message(announced), crate::fixtures::CLOCK);
            let Ok((next, super::Received::Synced(tip))) = received else {
                panic!("{received:?}");
            };
            assert_eq!(tip, tip_after(&headers[..height]));
            peer = next;
        }
        let later = start + std::time::Duration::from_mins(10);
        let (_, wake) = idle(peer, later);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn block_inv_after_the_sync_makes_the_next_tick_send_getheaders_from_our_tip() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3);
        let peer = synced(asked(&mut chain, start, 7), &headers[..2]);
        let peer = match peer.tick(start, 0) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: None,
                    send_headers: true,
                    get_headers: None,
                },
                _,
            )) => peer,
            other => panic!("{other:?}"),
        };
        let peer = accept(peer, &inv_message(&[1, 2]));
        let later = start + std::time::Duration::from_mins(1);
        let peer = match peer.tick(later, 0) {
            Ok((
                peer,
                super::TickOutbound {
                    ping: None,
                    send_headers: false,
                    get_headers: Some(get_headers),
                },
                wake,
            )) => {
                assert_eq!(get_headers, get_headers_on(&headers[..2]));
                assert_eq!(wake, later + super::HEADERS_TIMEOUT);
                peer
            }
            other => panic!("{other:?}"),
        };
        let received = peer.receive(&headers_message(&headers[2..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn inv_in_the_sync_or_with_no_block_is_skipped() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(1);
        let mut chain = regtest();
        let peer = accept(asked(&mut chain, start, 7), &inv_message(&[2]));
        synced(peer, &headers);
        assert_eq!(chain.tip(), tip_after(&headers));

        let mut chain = regtest();
        let peer = accept(pinged(&mut chain, start, 7), &inv_message(&[1, 5]));
        let later = start + std::time::Duration::from_mins(1);
        let (_, wake) = idle(peer, later);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn inv_that_does_not_decode_ends_the_connection() {
        let mut payload = crate::fixtures::inv_payload(&[2]);
        payload.pop();
        let mut chain = regtest();
        let start = std::time::Instant::now();
        assert_eq!(
            asked(&mut chain, start, 7)
                .receive(&inv_payload_message(&payload), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Inv(crate::protocol::InvError::Payload(
                crate::serialize::Error::UnexpectedEnd
            )))
        );
    }

    #[test]
    fn full_announcement_after_the_sync_makes_the_next_tick_send_getheaders_from_the_new_tip() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2001);
        let peer = pinged(&mut chain, start, 7);
        let later = start + std::time::Duration::from_mins(1);
        let (peer, get_headers) = batch_then_tick(peer, &headers[..2000], later);
        assert_eq!(get_headers, get_headers_on(&headers[..2000]));
        let received = peer.receive(&headers_message(&headers[2000..]), crate::fixtures::CLOCK);
        let Ok((_, super::Received::Synced(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn their_headers_payload_is_checked_first() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        for peer in [peer(&mut regtest()), asked(&mut chain, start, 7)] {
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
    fn headers_off_our_locator_while_our_getheaders_is_outstanding_are_skipped() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let (mut asked_chain, mut announced_chain) = (regtest(), regtest());
        let later = start + std::time::Duration::from_mins(1);
        let (announced, _) =
            batch_then_tick(pinged(&mut announced_chain, start, 7), &headers[1..], later);
        for peer in [asked(&mut asked_chain, start, 7), announced] {
            let peer = accept(peer, &headers_message(&headers[1..]));
            assert_eq!(peer.chain.tip(), tip_after(&[]));
            synced(peer, &headers);
        }
        assert_eq!(asked_chain.tip(), tip_after(&headers));
        assert_eq!(announced_chain.tip(), tip_after(&headers));
    }

    #[test]
    fn headers_off_our_locator_do_not_restart_the_headers_timeout() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let timeout = start + super::HEADERS_TIMEOUT;
        let (peer, _) = idle(asked(&mut chain, start, 7), timeout - NANOSECOND);
        let peer = accept(peer, &headers_message(&headers[1..]));
        assert_eq!(
            peer.tick(timeout, 8).err(),
            Some(super::PeerError::HeadersTimeout)
        );
    }

    #[test]
    fn headers_too_far_after_our_clock_end_the_connection() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let clock = u64::from(headers[1].time) - 2 * 60 * 60 - 1;
        assert_eq!(
            asked(&mut chain, start, 7)
                .receive(&headers_message(&headers), clock)
                .err(),
            Some(super::PeerError::Extend(
                crate::chain::ExtendError::TimeTooNew
            ))
        );
    }

    #[test]
    fn getheaders_without_headers_for_headers_timeout_is_headers_timeout() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let timeout = start + super::HEADERS_TIMEOUT;
        let (peer, wake) = idle(asked(&mut chain, start, 7), timeout - NANOSECOND);
        assert_eq!(wake, timeout);
        assert_eq!(
            peer.tick(timeout, 8).err(),
            Some(super::PeerError::HeadersTimeout)
        );
    }
}
