use crate::serialize::{Decode, Encode};

const PROTOCOL_VERSION_MIN: i32 = 70016;

const _: () = assert!(crate::protocol::PROTOCOL_VERSION >= PROTOCOL_VERSION_MIN);

const MESSAGE_COUNT_MAX: u32 = 16;

const PING_INTERVAL: std::time::Duration = std::time::Duration::from_mins(2);

const PING_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(20);

const _: () = assert!(!PING_TIMEOUT.is_zero());

const HEADERS_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(2);

const _: () = assert!(!HEADERS_TIMEOUT.is_zero());

const BLOCKS_IN_FLIGHT_MAX: usize = 16;

const _: () = assert!(BLOCKS_IN_FLIGHT_MAX >= 1);
const _: () = assert!(BLOCKS_IN_FLIGHT_MAX <= crate::protocol::INV_COUNT_MAX);
const _: () = assert!(size_of::<crate::chain::BlockPosition>() * BLOCKS_IN_FLIGHT_MAX <= 1024);

const BLOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(10);

const _: () = assert!(!BLOCK_TIMEOUT.is_zero());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    Version(crate::serialize::Error),
    Obsolete(i32),
    SelfConnection,
    MissingServices(crate::protocol::ServiceFlags),
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
            HandshakeError::MissingServices(services) => {
                write!(
                    f,
                    "services {services:016x} do not include network and witness"
                )
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
    Block(crate::serialize::Error),
    BlockMutation(crate::block::MutationError),
    BlockTimeout,
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
            PeerError::Block(error) => write!(f, "block payload: {error}"),
            PeerError::BlockMutation(error) => write!(f, "mutated block: {error}"),
            PeerError::BlockTimeout => {
                write!(f, "no block within {} s", BLOCK_TIMEOUT.as_secs())
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
    GetData(crate::protocol::GetData),
}

#[derive(Debug)]
pub(crate) struct SyncingOutbound {
    ping: Option<u64>,
    get_headers: Option<crate::protocol::GetHeaders>,
}

impl SyncingOutbound {
    pub(crate) fn into_outbounds(self) -> impl Iterator<Item = PeerOutbound> {
        let ping = self.ping.map(PeerOutbound::Ping);
        let get_headers = self.get_headers.map(PeerOutbound::GetHeaders);
        ping.into_iter().chain(get_headers)
    }
}

#[derive(Debug)]
pub(crate) struct SyncedOutbound {
    ping: Option<u64>,
    action: SyncedAction,
}

#[derive(Debug)]
enum SyncedAction {
    None,
    GetHeaders(crate::protocol::GetHeaders),
    SendHeaders(Option<crate::protocol::GetData>),
    GetData(crate::protocol::GetData),
}

impl SyncedOutbound {
    pub(crate) fn into_outbounds(self) -> impl Iterator<Item = PeerOutbound> {
        let ping = self.ping.map(PeerOutbound::Ping);
        let (send_headers, get_headers, get_data) = match self.action {
            SyncedAction::None => (None, None, None),
            SyncedAction::GetHeaders(get_headers) => {
                (None, Some(PeerOutbound::GetHeaders(get_headers)), None)
            }
            SyncedAction::SendHeaders(get_data) => (
                Some(PeerOutbound::SendHeaders),
                None,
                get_data.map(PeerOutbound::GetData),
            ),
            SyncedAction::GetData(get_data) => (None, None, Some(PeerOutbound::GetData(get_data))),
        };
        ping.into_iter()
            .chain(send_headers)
            .chain(get_headers)
            .chain(get_data)
    }
}

#[derive(Debug)]
pub(crate) enum SyncingReceived<'a> {
    NoReply(SyncingPeer<'a>),
    Pong(SyncingPeer<'a>, u64),
    Synced(Box<SyncedPeer<'a>>, crate::chain::Tip),
}

#[derive(Debug)]
pub(crate) enum SyncedReceived {
    NoReply,
    Pong(u64),
    Tip(crate::chain::Tip),
    Block(crate::block::CheckedBlock),
}

#[derive(Debug)]
pub(crate) enum Step<'a> {
    Wait(Handshake<'a>),
    Reply(Handshake<'a>, HandshakeOutbound),
    Done(Box<SyncingPeer<'a>>, crate::protocol::Version),
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

    pub(crate) fn progress(&self) -> Progress {
        Progress {
            tip: self.chain.tip(),
            low_work_download: None,
        }
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
                assert!(
                    theirs
                        .services
                        .has(crate::protocol::ServiceFlags::NETWORK_WITNESS)
                );

                if message.msg_type() == crate::protocol::VERACK {
                    let (download, salt) = if self.chain.tip().work() < self.work_min {
                        (InitialDownload::Genesis(self.salt), None)
                    } else {
                        (
                            InitialDownload::PostSync(PostSyncDownload::on_tip(
                                self.chain,
                                self.work_min,
                            )),
                            Some(self.salt),
                        )
                    };
                    let peer = SyncingPeer {
                        ping: PingState::Unsent,
                        sync: InitialSync::Due(download),
                        chain: self.chain,
                        work_min: self.work_min,
                        salt,
                        branch_tip: None,
                    };
                    Ok(Step::Done(Box::new(peer), theirs))
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
    } else if !theirs
        .services
        .has(crate::protocol::ServiceFlags::NETWORK_WITNESS)
    {
        Err(HandshakeError::MissingServices(theirs.services))
    } else {
        Ok(theirs)
    }
}

#[derive(Debug)]
pub(crate) struct SyncingPeer<'a> {
    ping: PingState,
    sync: InitialSync,
    chain: &'a mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt: Option<crate::headerssync::Salt>,
    branch_tip: Option<crate::chain::BranchTip>,
}

#[derive(Debug)]
pub(crate) struct SyncedPeer<'a> {
    ping: PingState,
    sync: PostSyncState,
    send_headers: SendHeadersState,
    chain: SyncedChain<'a>,
    work_min: crate::pow::Work,
    salt: Option<crate::headerssync::Salt>,
    branch_tip: Option<crate::chain::BranchTip>,
}

#[derive(Debug)]
struct SyncedChain<'a> {
    chain: &'a mut crate::chain::Chain,
    blocks: Blocks,
}

#[derive(Debug)]
struct Blocks {
    next_height: std::num::NonZeroUsize,
    in_flight: Option<InFlightQueue>,
}

#[derive(Debug)]
struct InFlightQueue {
    oldest: crate::chain::BlockPosition,
    rest: Vec<crate::chain::BlockPosition>,
    timer: BlockTimer,
}

#[derive(Clone, Copy, Debug)]
enum BlockTimer {
    Reset,
    Waiting(std::time::Instant),
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
enum InitialSync {
    Due(InitialDownload),
    Outstanding {
        download: InitialDownload,
        sent: std::time::Instant,
        tip: bitcoin_hashes::sha256d::Hash,
    },
}

#[derive(Debug)]
enum PostSyncState {
    Due(PostSyncDownload),
    Outstanding {
        download: PostSyncDownload,
        sent: std::time::Instant,
        tip: bitcoin_hashes::sha256d::Hash,
    },
    Synced,
}

#[derive(Debug)]
enum Answer<D> {
    Next(Option<D>),
    Skipped(D),
}

#[derive(Debug)]
enum SendHeadersState {
    Unsent,
    Sent,
}

#[derive(Debug)]
enum InitialDownload {
    Genesis(crate::headerssync::Salt),
    Presync(Box<crate::headerssync::Presync>),
    Redownload(Box<crate::headerssync::Redownload>),
    PostSync(PostSyncDownload),
}

#[derive(Debug)]
enum PostSyncDownload {
    Chain,
    Branch(Box<crate::chain::Branch>),
    BranchPresync(Box<BranchPresync>),
    BranchRedownload(Box<BranchRedownload>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Progress {
    pub(crate) tip: crate::chain::Tip,
    pub(crate) low_work_download: Option<LowWorkDownload>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LowWorkDownload {
    Presync(std::num::NonZeroUsize),
    Redownload(usize),
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

fn hash_locator(
    chain: &crate::chain::Chain,
    last: bitcoin_hashes::sha256d::Hash,
) -> Vec<bitcoin_hashes::sha256d::Hash> {
    let genesis = chain.network().genesis().hash();
    let mut locator = vec![last];
    if last != genesis {
        locator.push(genesis);
    }
    assert_eq!(locator.first(), Some(&last));
    assert_eq!(locator.last(), Some(&genesis));
    locator
}

impl PostSyncDownload {
    fn on_tip(chain: &crate::chain::Chain, work_min: crate::pow::Work) -> PostSyncDownload {
        assert!(chain.tip().work() >= work_min);
        PostSyncDownload::Chain
    }

    fn locator(&self, chain: &crate::chain::Chain) -> Vec<bitcoin_hashes::sha256d::Hash> {
        let last = match self {
            PostSyncDownload::Chain => return chain.locator(),
            PostSyncDownload::Branch(branch) => branch.last_hash(),
            PostSyncDownload::BranchPresync(sync) => sync.presync.last_hash(),
            PostSyncDownload::BranchRedownload(sync) => sync.redownload.last_hash(),
        };
        hash_locator(chain, last)
    }

    fn low_work_download(&self, chain: &crate::chain::Chain) -> Option<LowWorkDownload> {
        match self {
            PostSyncDownload::BranchPresync(sync) => {
                assert!(sync.start.height() < chain.tip().height());
                Some(LowWorkDownload::Presync(sync.presync.height()))
            }
            PostSyncDownload::BranchRedownload(sync) => {
                assert!(sync.start.height() < chain.tip().height());
                assert_eq!(sync.redownload.released_count(), sync.released.len());
                Some(LowWorkDownload::Redownload(sync.redownload.height()))
            }
            PostSyncDownload::Chain | PostSyncDownload::Branch(_) => None,
        }
    }

    fn is_answered_by(
        &self,
        chain: &crate::chain::Chain,
        headers: &crate::protocol::Headers,
    ) -> bool {
        match self {
            PostSyncDownload::Chain => true,
            PostSyncDownload::Branch(_)
            | PostSyncDownload::BranchPresync(_)
            | PostSyncDownload::BranchRedownload(_) => headers
                .first()
                .is_none_or(|first| self.locator(chain).contains(&first.prev)),
        }
    }
}

impl InitialDownload {
    fn locator(&self, chain: &crate::chain::Chain) -> Vec<bitcoin_hashes::sha256d::Hash> {
        match self {
            InitialDownload::Genesis(_) => chain.locator(),
            InitialDownload::Presync(presync) => hash_locator(chain, presync.last_hash()),
            InitialDownload::Redownload(redownload) => hash_locator(chain, redownload.last_hash()),
            InitialDownload::PostSync(download) => download.locator(chain),
        }
    }

    fn low_work_download(&self, chain: &crate::chain::Chain) -> Option<LowWorkDownload> {
        match self {
            InitialDownload::Presync(presync) => {
                assert_eq!(chain.tip().height(), 0);
                Some(LowWorkDownload::Presync(presync.height()))
            }
            InitialDownload::Redownload(redownload) => {
                assert_eq!(chain.tip().height(), redownload.released_height());
                Some(LowWorkDownload::Redownload(redownload.height()))
            }
            InitialDownload::Genesis(_) => None,
            InitialDownload::PostSync(download) => download.low_work_download(chain),
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

impl<'a> SyncedChain<'a> {
    fn new(chain: &'a mut crate::chain::Chain) -> SyncedChain<'a> {
        SyncedChain {
            chain,
            blocks: Blocks::new(),
        }
    }

    fn chain(&self) -> &crate::chain::Chain {
        self.chain
    }

    fn take_block(
        &mut self,
        header: crate::block::BlockHeader,
    ) -> Option<crate::block::MatchedHeader> {
        let matched = self.blocks.take(header)?;
        assert_eq!(
            self.chain.block_position(matched.position().height()),
            Some(matched.position())
        );
        Some(matched)
    }

    fn tick_waiting(
        &mut self,
        now: std::time::Instant,
    ) -> Result<Option<std::time::Instant>, PeerError> {
        self.blocks.tick_waiting(now, self.chain)
    }

    fn tick_request(
        &mut self,
        now: std::time::Instant,
    ) -> Result<(Option<crate::protocol::GetData>, Option<std::time::Instant>), PeerError> {
        self.blocks.tick_request(now, self.chain)
    }

    fn extend(
        &mut self,
        headers: crate::protocol::Headers,
        clock: u64,
    ) -> Result<(), crate::chain::ExtendError> {
        self.chain.extend(headers, clock)
    }
}

trait ChainStore {
    fn chain(&self) -> &crate::chain::Chain;

    fn extend_on_locator(
        &mut self,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Option<crate::chain::Extended>, crate::chain::ExtendError>;

    fn extend_branch(
        &mut self,
        branch: crate::chain::Branch,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<crate::chain::Extended, crate::chain::ExtendError>;

    fn extend_low_work_branch(
        &mut self,
        start: crate::chain::SyncStart,
        headers: Vec<crate::block::BlockHeader>,
        full: bool,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<crate::chain::Extended, crate::chain::ExtendError>;
}

impl ChainStore for crate::chain::Chain {
    fn chain(&self) -> &crate::chain::Chain {
        self
    }

    fn extend_on_locator(
        &mut self,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Option<crate::chain::Extended>, crate::chain::ExtendError> {
        crate::chain::Chain::extend_on_locator(self, headers, clock, work_min)
    }

    fn extend_branch(
        &mut self,
        branch: crate::chain::Branch,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<crate::chain::Extended, crate::chain::ExtendError> {
        crate::chain::Chain::extend_branch(self, branch, headers, clock, work_min)
    }

    fn extend_low_work_branch(
        &mut self,
        start: crate::chain::SyncStart,
        headers: Vec<crate::block::BlockHeader>,
        full: bool,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<crate::chain::Extended, crate::chain::ExtendError> {
        crate::chain::Chain::extend_low_work_branch(self, start, headers, full, clock, work_min)
    }
}

impl ChainStore for SyncedChain<'_> {
    fn chain(&self) -> &crate::chain::Chain {
        self.chain
    }

    fn extend_on_locator(
        &mut self,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Option<crate::chain::Extended>, crate::chain::ExtendError> {
        let extended = self.chain.extend_on_locator(headers, clock, work_min)?;
        if let Some(crate::chain::Extended::Reorged { fork_height, .. }) = extended {
            self.blocks.reorg(fork_height);
        }
        Ok(extended)
    }

    fn extend_branch(
        &mut self,
        branch: crate::chain::Branch,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<crate::chain::Extended, crate::chain::ExtendError> {
        let extended = self.chain.extend_branch(branch, headers, clock, work_min)?;
        if let crate::chain::Extended::Reorged { fork_height, .. } = extended {
            self.blocks.reorg(fork_height);
        }
        Ok(extended)
    }

    fn extend_low_work_branch(
        &mut self,
        start: crate::chain::SyncStart,
        headers: Vec<crate::block::BlockHeader>,
        full: bool,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<crate::chain::Extended, crate::chain::ExtendError> {
        let extended = self
            .chain
            .extend_low_work_branch(start, headers, full, clock, work_min)?;
        if let crate::chain::Extended::Reorged { fork_height, .. } = extended {
            self.blocks.reorg(fork_height);
        }
        Ok(extended)
    }
}

impl<'a> SyncingPeer<'a> {
    pub(crate) fn progress(&self) -> Progress {
        let low_work_download = match &self.sync {
            InitialSync::Due(download) | InitialSync::Outstanding { download, .. } => {
                download.low_work_download(self.chain)
            }
        };
        Progress {
            tip: self.chain.tip(),
            low_work_download,
        }
    }

    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<SyncingReceived<'a>, PeerError> {
        let msg_type = message.msg_type();
        if msg_type == crate::protocol::PING {
            let mut input = message.payload();
            let nonce = u64::decode(&mut input).map_err(PeerError::Ping)?;
            Ok(SyncingReceived::Pong(self, nonce))
        } else if msg_type == crate::protocol::PONG {
            let ping = self.ping.receive_pong(message)?;
            Ok(SyncingReceived::NoReply(SyncingPeer { ping, ..self }))
        } else if msg_type == crate::protocol::HEADERS {
            self.receive_headers(message, clock)
        } else if msg_type == crate::protocol::BLOCK {
            let mut input = message.payload();
            crate::block::BlockHeader::decode(&mut input).map_err(PeerError::Block)?;
            Ok(SyncingReceived::NoReply(self))
        } else if msg_type == crate::protocol::INV {
            let mut input = message.payload();
            crate::protocol::Inv::decode(&mut input).map_err(PeerError::Inv)?;
            Ok(SyncingReceived::NoReply(self))
        } else if msg_type == crate::protocol::WTXIDRELAY {
            Err(PeerError::LateWtxidRelay)
        } else if msg_type == crate::protocol::SENDADDRV2 {
            Err(PeerError::LateSendAddrV2)
        } else {
            Ok(SyncingReceived::NoReply(self))
        }
    }

    fn receive_headers(
        self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<SyncingReceived<'a>, PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::HEADERS);

        let mut input = message.payload();
        let headers = crate::protocol::Headers::decode(&mut input).map_err(PeerError::Headers)?;
        let SyncingPeer {
            ping,
            sync,
            chain,
            work_min,
            mut salt,
            mut branch_tip,
        } = self;
        let next = match sync {
            InitialSync::Outstanding {
                download,
                sent,
                tip,
            } => {
                assert_eq!(chain.tip().hash(), tip);
                match receive_initial_answer(
                    chain,
                    work_min,
                    &mut salt,
                    &mut branch_tip,
                    download,
                    headers,
                    clock,
                )? {
                    Answer::Next(next) => next,
                    Answer::Skipped(download) => {
                        let peer = SyncingPeer {
                            ping,
                            sync: InitialSync::Outstanding {
                                download,
                                sent,
                                tip,
                            },
                            chain,
                            work_min,
                            salt,
                            branch_tip,
                        };
                        return Ok(SyncingReceived::NoReply(peer));
                    }
                }
            }
            InitialSync::Due(_) => return Err(PeerError::UnsolicitedHeaders),
        };
        match next {
            Some(download) => {
                let peer = SyncingPeer {
                    ping,
                    sync: InitialSync::Due(download),
                    chain,
                    work_min,
                    salt,
                    branch_tip,
                };
                Ok(SyncingReceived::NoReply(peer))
            }
            None => {
                let tip = chain.tip();
                assert!(tip.work() >= work_min);
                let peer = SyncedPeer {
                    ping,
                    sync: PostSyncState::Synced,
                    send_headers: SendHeadersState::Unsent,
                    chain: SyncedChain::new(chain),
                    work_min,
                    salt,
                    branch_tip,
                };
                Ok(SyncingReceived::Synced(Box::new(peer), tip))
            }
        }
    }

    pub(crate) fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(SyncingPeer<'a>, SyncingOutbound, std::time::Instant), PeerError> {
        let SyncingPeer {
            ping,
            sync,
            chain,
            work_min,
            salt,
            branch_tip,
        } = self;
        let (ping, ping_nonce, ping_wake) = ping.tick(now, nonce)?;
        let (sync, get_headers, headers_wake) = match sync {
            InitialSync::Due(download) => {
                let get_headers = crate::protocol::GetHeaders::new(download.locator(chain));
                let sync = InitialSync::Outstanding {
                    download,
                    sent: now,
                    tip: chain.tip().hash(),
                };
                (sync, Some(get_headers), now + HEADERS_TIMEOUT)
            }
            InitialSync::Outstanding { sent, .. } => {
                assert!(sent <= now);
                let timeout = sent + HEADERS_TIMEOUT;
                if now < timeout {
                    (sync, None, timeout)
                } else {
                    return Err(PeerError::HeadersTimeout);
                }
            }
        };
        let wake = headers_wake.min(ping_wake);
        assert!(!matches!(sync, InitialSync::Due(_)));
        assert!(wake > now);
        let outbound = SyncingOutbound {
            ping: ping_nonce,
            get_headers,
        };
        let peer = SyncingPeer {
            ping,
            sync,
            chain,
            work_min,
            salt,
            branch_tip,
        };
        Ok((peer, outbound, wake))
    }
}

impl<'a> SyncedPeer<'a> {
    pub(crate) fn progress(&self) -> Progress {
        let low_work_download = match &self.sync {
            PostSyncState::Due(download) | PostSyncState::Outstanding { download, .. } => {
                download.low_work_download(self.chain.chain())
            }
            PostSyncState::Synced => None,
        };
        Progress {
            tip: self.chain.chain().tip(),
            low_work_download,
        }
    }

    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<(SyncedPeer<'a>, SyncedReceived), PeerError> {
        let msg_type = message.msg_type();
        if msg_type == crate::protocol::PING {
            let mut input = message.payload();
            let nonce = u64::decode(&mut input).map_err(PeerError::Ping)?;
            Ok((self, SyncedReceived::Pong(nonce)))
        } else if msg_type == crate::protocol::PONG {
            let ping = self.ping.receive_pong(message)?;
            Ok((SyncedPeer { ping, ..self }, SyncedReceived::NoReply))
        } else if msg_type == crate::protocol::HEADERS {
            self.receive_headers(message, clock)
        } else if msg_type == crate::protocol::BLOCK {
            self.receive_block(message)
        } else if msg_type == crate::protocol::INV {
            let peer = self.receive_inv(message)?;
            Ok((peer, SyncedReceived::NoReply))
        } else if msg_type == crate::protocol::WTXIDRELAY {
            Err(PeerError::LateWtxidRelay)
        } else if msg_type == crate::protocol::SENDADDRV2 {
            Err(PeerError::LateSendAddrV2)
        } else {
            Ok((self, SyncedReceived::NoReply))
        }
    }

    fn receive_inv(self, message: &crate::transport::Message) -> Result<SyncedPeer<'a>, PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::INV);

        let mut input = message.payload();
        let inv = crate::protocol::Inv::decode(&mut input).map_err(PeerError::Inv)?;
        if inv.has_block() && matches!(self.sync, PostSyncState::Synced) {
            Ok(SyncedPeer {
                sync: PostSyncState::Due(PostSyncDownload::on_tip(
                    self.chain.chain(),
                    self.work_min,
                )),
                ..self
            })
        } else {
            Ok(self)
        }
    }

    fn receive_block(
        mut self,
        message: &crate::transport::Message,
    ) -> Result<(SyncedPeer<'a>, SyncedReceived), PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::BLOCK);

        let mut input = message.payload();
        let header = crate::block::BlockHeader::decode(&mut input).map_err(PeerError::Block)?;
        let Some(matched) = self.chain.take_block(header) else {
            return Ok((self, SyncedReceived::NoReply));
        };
        let block = matched.decode_body(&mut input).map_err(PeerError::Block)?;
        let checked = block.check_mutation().map_err(PeerError::BlockMutation)?;
        Ok((self, SyncedReceived::Block(checked)))
    }

    fn receive_headers(
        self,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<(SyncedPeer<'a>, SyncedReceived), PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::HEADERS);

        let mut input = message.payload();
        let headers = crate::protocol::Headers::decode(&mut input).map_err(PeerError::Headers)?;
        let SyncedPeer {
            ping,
            sync,
            send_headers,
            mut chain,
            work_min,
            mut salt,
            mut branch_tip,
        } = self;
        let next = match sync {
            PostSyncState::Outstanding {
                download,
                sent,
                tip,
            } => {
                assert_eq!(chain.chain().tip().hash(), tip);
                let mut context = PostSyncContext {
                    chain: &mut chain,
                    work_min,
                    salt: &mut salt,
                    branch_tip: &mut branch_tip,
                };
                match context.receive_answer(download, headers, clock)? {
                    Answer::Next(next) => next,
                    Answer::Skipped(download) => {
                        let peer = SyncedPeer {
                            ping,
                            sync: PostSyncState::Outstanding {
                                download,
                                sent,
                                tip,
                            },
                            send_headers,
                            chain,
                            work_min,
                            salt,
                            branch_tip,
                        };
                        return Ok((peer, SyncedReceived::NoReply));
                    }
                }
            }
            PostSyncState::Synced => {
                receive_announcement(&mut chain, work_min, &mut branch_tip, headers, clock)?
            }
            PostSyncState::Due(_) => return Err(PeerError::UnsolicitedHeaders),
        };
        match next {
            Some(download) => {
                let peer = SyncedPeer {
                    ping,
                    sync: PostSyncState::Due(download),
                    send_headers,
                    chain,
                    work_min,
                    salt,
                    branch_tip,
                };
                Ok((peer, SyncedReceived::NoReply))
            }
            None => {
                let tip = chain.chain().tip();
                let peer = SyncedPeer {
                    ping,
                    sync: PostSyncState::Synced,
                    send_headers,
                    chain,
                    work_min,
                    salt,
                    branch_tip,
                };
                Ok((peer, SyncedReceived::Tip(tip)))
            }
        }
    }

    pub(crate) fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(SyncedPeer<'a>, SyncedOutbound, std::time::Instant), PeerError> {
        let SyncedPeer {
            ping,
            sync,
            send_headers,
            mut chain,
            work_min,
            salt,
            branch_tip,
        } = self;
        let (ping, ping_nonce, ping_wake) = ping.tick(now, nonce)?;
        let (sync, send_headers, action, sync_wake) = match sync {
            PostSyncState::Due(download) => {
                let get_headers = crate::protocol::GetHeaders::new(download.locator(chain.chain()));
                let blocks_wake = chain.tick_waiting(now)?;
                let headers_wake = now + HEADERS_TIMEOUT;
                let wake =
                    blocks_wake.map_or(headers_wake, |blocks_wake| blocks_wake.min(headers_wake));
                (
                    PostSyncState::Outstanding {
                        download,
                        sent: now,
                        tip: chain.chain().tip().hash(),
                    },
                    send_headers,
                    SyncedAction::GetHeaders(get_headers),
                    Some(wake),
                )
            }
            PostSyncState::Outstanding { sent, .. } => {
                assert!(sent <= now);
                let headers_wake = sent + HEADERS_TIMEOUT;
                if now >= headers_wake {
                    return Err(PeerError::HeadersTimeout);
                }
                let blocks_wake = chain.tick_waiting(now)?;
                let wake =
                    blocks_wake.map_or(headers_wake, |blocks_wake| blocks_wake.min(headers_wake));
                (sync, send_headers, SyncedAction::None, Some(wake))
            }
            PostSyncState::Synced => {
                assert!(chain.chain().tip().work() >= work_min);
                let (get_data, blocks_wake) = chain.tick_request(now)?;
                let (send_headers, action) = match send_headers {
                    SendHeadersState::Unsent => {
                        (SendHeadersState::Sent, SyncedAction::SendHeaders(get_data))
                    }
                    SendHeadersState::Sent => (
                        SendHeadersState::Sent,
                        get_data.map_or(SyncedAction::None, SyncedAction::GetData),
                    ),
                };
                (PostSyncState::Synced, send_headers, action, blocks_wake)
            }
        };
        let wake = sync_wake.map_or(ping_wake, |sync_wake| sync_wake.min(ping_wake));
        assert!(!matches!(sync, PostSyncState::Due(_)));
        assert!(
            chain
                .blocks
                .in_flight
                .as_ref()
                .is_none_or(|queue| matches!(queue.timer, BlockTimer::Waiting(_)))
        );
        assert!(wake > now);
        let outbound = SyncedOutbound {
            ping: ping_nonce,
            action,
        };
        let peer = SyncedPeer {
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

impl Blocks {
    fn new() -> Blocks {
        Blocks {
            next_height: std::num::NonZeroUsize::MIN,
            in_flight: None,
        }
    }

    fn len(&self) -> usize {
        self.in_flight.as_ref().map_or(0, InFlightQueue::len)
    }

    fn take(&mut self, header: crate::block::BlockHeader) -> Option<crate::block::MatchedHeader> {
        let queue = self.in_flight.take()?;
        let (next, found) = queue.take(header);
        self.in_flight = next;
        if let Some(matched) = found {
            assert!(matched.position().height() < self.next_height);
        }
        found
    }

    fn reorg(&mut self, fork_height: usize) {
        assert!(fork_height < usize::MAX);
        let above_fork = std::num::NonZeroUsize::MIN.saturating_add(fork_height);
        self.next_height = self.next_height.min(above_fork);
        self.in_flight = self
            .in_flight
            .take()
            .and_then(|queue| queue.reorg(fork_height));
        assert!(self.next_height.get() <= fork_height + 1);
    }

    fn tick_waiting(
        &mut self,
        now: std::time::Instant,
        chain: &crate::chain::Chain,
    ) -> Result<Option<std::time::Instant>, PeerError> {
        assert!(self.next_height.get() <= chain.tip().height() + 1);
        assert!(self.len() <= BLOCKS_IN_FLIGHT_MAX);
        match &mut self.in_flight {
            None => Ok(None),
            Some(queue) => queue.tick(now).map(Some),
        }
    }

    fn tick_request(
        &mut self,
        now: std::time::Instant,
        chain: &crate::chain::Chain,
    ) -> Result<(Option<crate::protocol::GetData>, Option<std::time::Instant>), PeerError> {
        let mut wake = self.tick_waiting(now, chain)?;
        let free = BLOCKS_IN_FLIGHT_MAX - self.len();
        let mut asked = Vec::with_capacity(free);
        while asked.len() < free
            && let Some(position) = chain.block_position(self.next_height)
        {
            asked.push(position);
            self.next_height = self.next_height.saturating_add(1);
        }
        assert!(self.next_height.get() <= chain.tip().height() + 1);
        let mut positions = asked.into_iter();
        let Some(first) = positions.next() else {
            return Ok((None, wake));
        };
        let rest_positions: Vec<_> = positions.collect();
        let get_data = crate::protocol::GetData::witness_blocks(
            first.hash(),
            rest_positions
                .iter()
                .map(crate::chain::BlockPosition::hash)
                .collect(),
        );
        match &mut self.in_flight {
            None => {
                self.in_flight = Some(InFlightQueue::new(first, rest_positions, now));
                wake = Some(now + BLOCK_TIMEOUT);
            }
            Some(queue) => queue.push(first, rest_positions),
        }
        assert!(self.len() <= BLOCKS_IN_FLIGHT_MAX);
        Ok((Some(get_data), wake))
    }
}

impl InFlightQueue {
    fn new(
        oldest: crate::chain::BlockPosition,
        rest: Vec<crate::chain::BlockPosition>,
        now: std::time::Instant,
    ) -> InFlightQueue {
        assert!(rest.len() < BLOCKS_IN_FLIGHT_MAX);
        let mut prev_height = oldest.height();
        for position in &rest {
            assert!(position.height() > prev_height);
            prev_height = position.height();
        }
        InFlightQueue {
            oldest,
            rest,
            timer: BlockTimer::Waiting(now),
        }
    }

    fn len(&self) -> usize {
        1 + self.rest.len()
    }

    fn tick(&mut self, now: std::time::Instant) -> Result<std::time::Instant, PeerError> {
        match self.timer {
            BlockTimer::Waiting(since) => {
                assert!(since <= now);
                let timeout = since + BLOCK_TIMEOUT;
                if now < timeout {
                    Ok(timeout)
                } else {
                    Err(PeerError::BlockTimeout)
                }
            }
            BlockTimer::Reset => {
                self.timer = BlockTimer::Waiting(now);
                Ok(now + BLOCK_TIMEOUT)
            }
        }
    }

    fn push(&mut self, first: crate::chain::BlockPosition, more: Vec<crate::chain::BlockPosition>) {
        assert!(matches!(self.timer, BlockTimer::Waiting(_)));
        let len_before = self.len();
        assert!(len_before < BLOCKS_IN_FLIGHT_MAX);
        let mut prev_height = self.rest.last().unwrap_or(&self.oldest).height();
        for position in std::iter::once(first).chain(more) {
            assert!(position.height() > prev_height);
            assert!(self.rest.len() < BLOCKS_IN_FLIGHT_MAX - 1);
            prev_height = position.height();
            self.rest.push(position);
        }
        assert!(self.len() > len_before);
        assert!(self.len() <= BLOCKS_IN_FLIGHT_MAX);
    }

    fn take(
        mut self,
        header: crate::block::BlockHeader,
    ) -> (Option<InFlightQueue>, Option<crate::block::MatchedHeader>) {
        assert!(self.len() <= BLOCKS_IN_FLIGHT_MAX);
        assert!(
            self.rest
                .iter()
                .all(|position| position.height() > self.oldest.height())
        );
        let len_before = self.len();
        let hash = header.hash();
        if let Some(matched) = crate::block::MatchedHeader::new(self.oldest, header) {
            assert!(self.rest.iter().all(|position| position.hash() != hash));
            let next = if self.rest.is_empty() {
                None
            } else {
                let oldest = self.rest.remove(0);
                Some(InFlightQueue {
                    oldest,
                    rest: self.rest,
                    timer: BlockTimer::Reset,
                })
            };
            assert_eq!(next.as_ref().map_or(0, InFlightQueue::len), len_before - 1);
            return (next, Some(matched));
        }
        let found = self
            .rest
            .iter()
            .position(|position| position.hash() == hash)
            .map(|index| {
                let position = self.rest.remove(index);
                crate::block::MatchedHeader::new(position, header).expect("matched hash in rest")
            });
        if found.is_some() {
            assert!(self.rest.iter().all(|position| position.hash() != hash));
        }
        assert_eq!(self.len(), len_before - usize::from(found.is_some()));
        (Some(self), found)
    }

    fn reorg(mut self, fork_height: usize) -> Option<InFlightQueue> {
        assert!(self.len() <= BLOCKS_IN_FLIGHT_MAX);
        assert!(
            self.rest
                .iter()
                .all(|position| position.height() > self.oldest.height())
        );
        if self.oldest.height().get() <= fork_height {
            self.rest
                .retain(|position| position.height().get() <= fork_height);
            assert!(
                self.rest
                    .iter()
                    .all(|position| position.height().get() <= fork_height)
            );
            Some(self)
        } else {
            None
        }
    }
}

impl PingState {
    fn receive_pong(self, message: &crate::transport::Message) -> Result<PingState, PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::PONG);

        let mut input = message.payload();
        let theirs = u64::decode(&mut input).map_err(PeerError::Pong)?;
        match self {
            PingState::Outstanding { nonce: ours, sent } => {
                if theirs == ours {
                    Ok(PingState::Answered { sent })
                } else {
                    Err(PeerError::PongNonce)
                }
            }
            PingState::Unsent | PingState::Answered { .. } => Err(PeerError::UnsolicitedPong),
        }
    }

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

struct PostSyncContext<'a, C> {
    chain: &'a mut C,
    work_min: crate::pow::Work,
    salt: &'a mut Option<crate::headerssync::Salt>,
    branch_tip: &'a mut Option<crate::chain::BranchTip>,
}

impl<C: ChainStore> PostSyncContext<'_, C> {
    fn receive_answer(
        &mut self,
        download: PostSyncDownload,
        headers: crate::protocol::Headers,
        clock: u64,
    ) -> Result<Answer<PostSyncDownload>, PeerError> {
        if !download.is_answered_by(self.chain.chain(), &headers) {
            return Ok(Answer::Skipped(download));
        }
        let full = headers.is_full();
        let next = match download {
            PostSyncDownload::Chain => {
                let Some(extended) = self
                    .chain
                    .extend_on_locator(headers, clock, self.work_min)
                    .map_err(PeerError::Extend)?
                else {
                    return Ok(Answer::Skipped(PostSyncDownload::Chain));
                };
                self.chain_next(extended, clock)?
            }
            PostSyncDownload::Branch(branch) => {
                let extended = self
                    .chain
                    .extend_branch(*branch, headers, clock, self.work_min)
                    .map_err(PeerError::Extend)?;
                self.chain_next(extended, clock)?
            }
            PostSyncDownload::BranchPresync(sync) => {
                let BranchPresync { start, presync } = *sync;
                let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
                Some(branch_presync_next(start, step))
            }
            PostSyncDownload::BranchRedownload(sync) => {
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
                        keep_released(self.chain.chain().network(), &mut released, more);
                        Some(PostSyncDownload::BranchRedownload(Box::new(
                            BranchRedownload {
                                start,
                                redownload: *redownload,
                                released,
                            },
                        )))
                    }
                    crate::headerssync::RedownloadStep::Done(rest) => {
                        keep_released(self.chain.chain().network(), &mut released, rest);
                        let extended = self
                            .chain
                            .extend_low_work_branch(start, released, full, clock, self.work_min)
                            .map_err(PeerError::Extend)?;
                        self.chain_next(extended, clock)?
                    }
                }
            }
        };
        Ok(Answer::Next(next))
    }

    fn chain_next(
        &mut self,
        extended: crate::chain::Extended,
        clock: u64,
    ) -> Result<Option<PostSyncDownload>, PeerError> {
        match extended {
            crate::chain::Extended::Tip { full } | crate::chain::Extended::Reorged { full, .. } => {
                let next = PostSyncDownload::on_tip(self.chain.chain(), self.work_min);
                Ok(full.then_some(next))
            }
            crate::chain::Extended::Branch(branch) => {
                assert!(self.chain.chain().tip().work() >= self.work_min);
                Ok(Some(PostSyncDownload::Branch(Box::new(branch))))
            }
            crate::chain::Extended::Kept => {
                assert!(self.chain.chain().tip().work() >= self.work_min);
                Ok(None)
            }
            crate::chain::Extended::KeptOver(tip) => {
                *self.branch_tip = Some(tip);
                Ok(None)
            }
            crate::chain::Extended::BelowMargin {
                start,
                branch_work_min,
                headers,
            } => {
                assert!(self.chain.chain().tip().work() >= self.work_min);
                let salt = self.salt.take().ok_or(PeerError::SecondLowWorkSync)?;
                let presync = crate::headerssync::Presync::new(start, branch_work_min, clock, salt);
                let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
                Ok(Some(branch_presync_next(start, step)))
            }
        }
    }
}

fn receive_initial_answer(
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt: &mut Option<crate::headerssync::Salt>,
    branch_tip: &mut Option<crate::chain::BranchTip>,
    download: InitialDownload,
    headers: crate::protocol::Headers,
    clock: u64,
) -> Result<Answer<InitialDownload>, PeerError> {
    let full = headers.is_full();
    let next = match download {
        InitialDownload::PostSync(download) => {
            let mut context = PostSyncContext {
                chain,
                work_min,
                salt,
                branch_tip,
            };
            return match context.receive_answer(download, headers, clock)? {
                Answer::Next(next) => Ok(Answer::Next(next.map(InitialDownload::PostSync))),
                Answer::Skipped(download) => {
                    Ok(Answer::Skipped(InitialDownload::PostSync(download)))
                }
            };
        }
        download if !download.is_answered_by(chain, &headers) => {
            return Ok(Answer::Skipped(download));
        }
        InitialDownload::Genesis(genesis_salt) => {
            receive_on_genesis(chain, work_min, salt, genesis_salt, headers, clock)?
        }
        InitialDownload::Presync(presync) => {
            let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
            Some(presync_next(step))
        }
        InitialDownload::Redownload(redownload) => {
            match redownload
                .receive(headers)
                .map_err(PeerError::HeadersSync)?
            {
                crate::headerssync::RedownloadStep::More(redownload, released) => {
                    extend_released(chain, released, clock)?;
                    Some(InitialDownload::Redownload(redownload))
                }
                crate::headerssync::RedownloadStep::Done(released) => {
                    extend_released(chain, released, clock)?;
                    let next = InitialDownload::PostSync(PostSyncDownload::on_tip(chain, work_min));
                    full.then_some(next)
                }
            }
        }
    };
    Ok(Answer::Next(next))
}

fn receive_on_genesis(
    chain: &mut crate::chain::Chain,
    work_min: crate::pow::Work,
    salt_left: &mut Option<crate::headerssync::Salt>,
    salt: crate::headerssync::Salt,
    headers: crate::protocol::Headers,
    clock: u64,
) -> Result<Option<InitialDownload>, PeerError> {
    assert_eq!(chain.tip().height(), 0);
    assert!(chain.tip().work() < work_min);
    if headers.is_full() {
        let presync =
            crate::headerssync::Presync::new(chain.sync_start_on_tip(), work_min, clock, salt);
        let step = presync.receive(headers).map_err(PeerError::HeadersSync)?;
        return Ok(Some(presync_next(step)));
    }
    chain.extend(headers, clock).map_err(PeerError::Extend)?;
    assert!(salt_left.replace(salt).is_none());
    if chain.tip().work() >= work_min {
        Ok(None)
    } else {
        Err(PeerError::ChainWorkTooLow)
    }
}

fn receive_announcement(
    chain: &mut SyncedChain<'_>,
    work_min: crate::pow::Work,
    branch_tip: &mut Option<crate::chain::BranchTip>,
    headers: crate::protocol::Headers,
    clock: u64,
) -> Result<Option<PostSyncDownload>, PeerError> {
    let full = headers.is_full();
    let first_prev = headers.first().map(|first| first.prev);
    *branch_tip = branch_tip.and_then(|tip| chain.chain().branch_tip_current(tip));
    if let Some(tip) = *branch_tip
        && first_prev == Some(tip.hash())
    {
        return match chain
            .chain()
            .extend_branch_tip(tip, &headers)
            .map_err(PeerError::Extend)?
        {
            crate::chain::Announced::Kept(tip) => {
                *branch_tip = Some(tip);
                Ok(None)
            }
            crate::chain::Announced::Ask => {
                *branch_tip = None;
                Ok(Some(PostSyncDownload::on_tip(chain.chain(), work_min)))
            }
        };
    }
    match chain.extend(headers, clock) {
        Ok(()) => {
            let next = PostSyncDownload::on_tip(chain.chain(), work_min);
            Ok(full.then_some(next))
        }
        Err(crate::chain::ExtendError::NotOnTip) => {
            Ok(Some(PostSyncDownload::on_tip(chain.chain(), work_min)))
        }
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
) -> PostSyncDownload {
    match step {
        crate::headerssync::PresyncStep::More(presync) => {
            PostSyncDownload::BranchPresync(Box::new(BranchPresync { start, presync }))
        }
        crate::headerssync::PresyncStep::Redownload(redownload) => {
            assert_eq!(redownload.height(), start.height());
            assert_eq!(redownload.last_hash(), start.hash());
            PostSyncDownload::BranchRedownload(Box::new(BranchRedownload {
                start,
                redownload,
                released: Vec::new(),
            }))
        }
    }
}

fn presync_next(step: crate::headerssync::PresyncStep) -> InitialDownload {
    match step {
        crate::headerssync::PresyncStep::More(presync) => {
            InitialDownload::Presync(Box::new(presync))
        }
        crate::headerssync::PresyncStep::Redownload(redownload) => {
            InitialDownload::Redownload(Box::new(redownload))
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
    const _: () = assert!(super::BLOCKS_IN_FLIGHT_MAX == 16);
    const _: () = assert!(super::BLOCK_TIMEOUT.as_secs() == 600);

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

    fn script_coinbase_bytes(tag: u32) -> [u8; 55] {
        let mut bytes = [0; 55];
        bytes[0..4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[4] = 1;
        bytes[37..41].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[41] = 4;
        bytes[42..46].copy_from_slice(&tag.to_le_bytes());
        bytes
    }

    fn script_merkle_root(tag: u32) -> [u8; 32] {
        bitcoin_hashes::sha256d::Hash::hash(&script_coinbase_bytes(tag)).to_byte_array()
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
        seed!("block-download-all", "PeerOpen { height: 2, synced: true }"),
        seed!("block-download-cap-and-top-up", "PeerOpen { height: 18, synced: true }"),
        seed!("block-download-oldest-resets-timeout", "PeerOpen { height: 2, synced: true }"),
        seed!("block-download-out-of-order", "PeerOpen { height: 2, synced: true }"),
        seed!("block-download-out-of-order-timeout", "PeerRefused(BlockTimeout)"),
        seed!("block-mutated-merkle-root", "PeerRefused(BlockMutation(MerkleRoot))"),
        seed!("block-mutated-unexpected-witness", "PeerRefused(BlockMutation(UnexpectedWitness))"),
        seed!("block-reorg-in-flight", "PeerOpen { height: 4, synced: true }"),
        seed!("block-truncated-payload", "PeerRefused(Block(UnexpectedEnd))"),
        seed!("block-unsolicited-skipped", "PeerOpen { height: 2, synced: true }"),
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
        seed!("handshake-missing-services", "HandshakeRefused(MissingServices(ServiceFlags(0)))"),
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
        seed!("mix-long", "PeerRefused(BlockTimeout)"),
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
        seed!("sync-low-work-regtest-first-on-genesis", "PeerRefused(HeadersSync(NotContinuous))"),
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
            header_by_hash: std::collections::HashMap::new(),
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

    #[derive(Debug)]
    enum FuzzPeer<'a> {
        Syncing(super::SyncingPeer<'a>),
        Synced(super::SyncedPeer<'a>),
    }

    impl FuzzPeer<'_> {
        fn progress(&self) -> super::Progress {
            match self {
                FuzzPeer::Syncing(peer) => peer.progress(),
                FuzzPeer::Synced(peer) => peer.progress(),
            }
        }
    }

    fn handshake_run<'a>(
        script: &mut Script,
        mut handshake: super::Handshake<'a>,
        nonce: u64,
    ) -> Result<super::SyncingPeer<'a>, ScriptEnd> {
        let base = MessageBase {
            our_nonce: nonce,
            ping_nonce: 0,
            last: (bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]), 0),
            locator_below: Vec::new(),
            in_flight: Vec::new(),
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
                    return Ok(*peer);
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
        peer: super::SyncingPeer<'_>,
        network: crate::chainparams::Network,
        work_min: u128,
    ) -> ScriptEnd {
        let mut peer = FuzzPeer::Syncing(peer);
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
                in_flight: model.in_flight_hashes(),
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
        peer: FuzzPeer<'a>,
        model: &mut PeerModel,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(FuzzPeer<'a>, std::time::Instant), super::PeerError> {
        let actual: Result<(FuzzPeer<'a>, Vec<super::PeerOutbound>, std::time::Instant), _> =
            match peer {
                FuzzPeer::Syncing(peer) => peer.tick(now, nonce).map(|(peer, outbound, wake)| {
                    (
                        FuzzPeer::Syncing(peer),
                        outbound.into_outbounds().collect(),
                        wake,
                    )
                }),
                FuzzPeer::Synced(peer) => peer.tick(now, nonce).map(|(peer, outbound, wake)| {
                    (
                        FuzzPeer::Synced(peer),
                        outbound.into_outbounds().collect(),
                        wake,
                    )
                }),
            };
        match (actual, model.tick(now, nonce)) {
            (Ok((peer, outbounds, wake)), Ok(expected)) => {
                assert_eq!(wake, expected.wake);
                let mut outbounds = outbounds.into_iter();
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
                if let Some(hashes) = expected.get_data {
                    match outbounds.next() {
                        Some(super::PeerOutbound::GetData(get_data)) => {
                            peer_get_data_check(get_data, &hashes);
                        }
                        other => panic!("{other:?}, not a getdata"),
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

    fn peer_get_data_check(
        get_data: crate::protocol::GetData,
        hashes: &[bitcoin_hashes::sha256d::Hash],
    ) {
        let mut encoded = Vec::new();
        get_data.encode(&mut encoded);

        let mut expected = Vec::new();
        crate::serialize::write_compact_size(&mut expected, hashes.len());
        for hash in hashes {
            expected.extend_from_slice(&0x4000_0002_u32.to_le_bytes());
            expected.extend_from_slice(hash.as_byte_array());
        }
        assert_eq!(encoded, expected);
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
        peer: FuzzPeer<'a>,
        model: &mut PeerModel,
        message: &crate::transport::Message,
        clock: u64,
    ) -> Result<FuzzPeer<'a>, super::PeerError> {
        let actual: Result<(FuzzPeer<'a>, super::SyncedReceived), _> = match peer {
            FuzzPeer::Syncing(peer) => {
                peer.receive(message, clock).map(|received| match received {
                    super::SyncingReceived::NoReply(peer) => {
                        (FuzzPeer::Syncing(peer), super::SyncedReceived::NoReply)
                    }
                    super::SyncingReceived::Pong(peer, nonce) => {
                        (FuzzPeer::Syncing(peer), super::SyncedReceived::Pong(nonce))
                    }
                    super::SyncingReceived::Synced(peer, tip) => {
                        (FuzzPeer::Synced(*peer), super::SyncedReceived::Tip(tip))
                    }
                })
            }
            FuzzPeer::Synced(peer) => peer
                .receive(message, clock)
                .map(|(peer, received)| (FuzzPeer::Synced(peer), received)),
        };
        let received = match (actual, model.receive(message)) {
            (Ok((peer, super::SyncedReceived::NoReply)), Ok(ReceivedExpected::NoReply)) => Ok(peer),
            (
                Ok((peer, super::SyncedReceived::Pong(nonce))),
                Ok(ReceivedExpected::Pong(expected)),
            ) => {
                assert_eq!(nonce, expected);
                Ok(peer)
            }
            (Ok((peer, super::SyncedReceived::Tip(tip))), Ok(ReceivedExpected::Synced)) => {
                assert_eq!(tip.hash(), model.tip());
                assert_eq!(tip.height(), model.height());
                assert_eq!(tip.work().to_string(), format!("{:064x}", model.work()));
                Ok(peer)
            }
            (
                Ok((peer, super::SyncedReceived::Block(block))),
                Ok(ReceivedExpected::Block {
                    height,
                    hash,
                    transactions_count: expected_transactions_count,
                }),
            ) => {
                assert_eq!(block.height().get(), height);
                assert_eq!(block.hash(), hash);
                assert_eq!(block.transactions_count(), expected_transactions_count);
                Ok(peer)
            }
            (Err(error), Err(expected)) => {
                assert_eq!(error, expected);
                Err(error)
            }
            (received, expected) => panic!("the peer gave {received:?}, not {expected:?}"),
        };
        received.inspect(|peer| {
            peer.progress();
        })
    }

    fn branch_tip_check(peer: &FuzzPeer<'_>, model: &PeerModel) {
        let tip = match peer {
            FuzzPeer::Syncing(peer) => peer
                .branch_tip
                .and_then(|tip| peer.chain.branch_tip_current(tip)),
            FuzzPeer::Synced(peer) => peer
                .branch_tip
                .and_then(|tip| peer.chain.chain().branch_tip_current(tip)),
        }
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
        header_by_hash: std::collections::HashMap<
            bitcoin_hashes::sha256d::Hash,
            (crate::block::BlockHeader, u32),
        >,
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
                    self.version_payload(base.our_nonce, kind / 8),
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
                6 => match usize::from(kind / 8).checked_sub(1) {
                    None => (crate::protocol::WTXIDRELAY, Vec::new()),
                    Some(slot) => (crate::protocol::BLOCK, self.block_payload(base, slot)),
                },
                _ => (crate::protocol::INV, self.inv_payload()),
            };
            let length = payload
                .len()
                .saturating_add_signed(isize::from(self.signed_byte()));
            payload.resize(length, 0xaa);
            Some(message_read(msg_type, &payload))
        }

        fn version_payload(&mut self, our_nonce: u64, services_selector: u8) -> Vec<u8> {
            let their_nonce = our_nonce.wrapping_add(u64::from(self.byte()));
            let mut theirs = super::our_version(PEER_ADDRESS, 0, their_nonce);
            theirs.version = super::PROTOCOL_VERSION_MIN + i32::from(self.signed_byte());
            theirs.services = match services_selector.checked_sub(1) {
                None => crate::protocol::ServiceFlags::NETWORK_WITNESS,
                Some(bits) => crate::protocol::ServiceFlags::from_bits(u64::from(bits)),
            };
            let mut payload = Vec::new();
            theirs.encode(&mut payload);
            payload
        }

        fn block_payload(&mut self, base: &MessageBase, slot: usize) -> Vec<u8> {
            let mode = self.byte();
            let (header, tag) = if mode & 1 == 0
                && !base.in_flight.is_empty()
                && let Some(entry) = self
                    .header_by_hash
                    .get(&base.in_flight[slot % base.in_flight.len()])
            {
                *entry
            } else {
                (FRAME_NETWORK.genesis(), 0)
            };
            let mut payload = Vec::new();
            header.encode(&mut payload);
            payload.push(1);
            let mut tx = script_coinbase_bytes(tag);
            match (mode >> 1) % 3 {
                0 => payload.extend_from_slice(&tx),
                1 => {
                    tx[42] ^= 1;
                    payload.extend_from_slice(&tx);
                }
                _ => {
                    payload.extend_from_slice(&tx[..4]);
                    payload.extend_from_slice(&[0x00, 0x01]);
                    payload.extend_from_slice(&tx[4..51]);
                    payload.extend_from_slice(&[0x01, 0x01, 0xaa]);
                    payload.extend_from_slice(&tx[51..]);
                }
            }
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
                            self.header_by_hash
                                .insert(header.hash(), (header, self.branch_last));
                            assert!(self.written_on.len() <= self.headers_written_count);
                            assert!(self.header_by_hash.len() <= self.headers_written_count);
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
        in_flight: Vec<bitcoin_hashes::sha256d::Hash>,
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
                    if !theirs
                        .services
                        .has(crate::protocol::ServiceFlags::NETWORK_WITNESS)
                    {
                        return Err(super::HandshakeError::MissingServices(theirs.services));
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
        next_block_height: usize,
        blocks_in_flight: Vec<(usize, bitcoin_hashes::sha256d::Hash)>,
        block_deadline: Option<std::time::Instant>,
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
        get_data: Option<Vec<bitcoin_hashes::sha256d::Hash>>,
        wake: std::time::Instant,
    }

    #[derive(Debug)]
    enum ReceivedExpected {
        NoReply,
        Pong(u64),
        Synced,
        Block {
            height: usize,
            hash: bitcoin_hashes::sha256d::Hash,
            transactions_count: usize,
        },
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
                next_block_height: 1,
                blocks_in_flight: Vec::new(),
                block_deadline: None,
            }
        }

        fn in_flight_hashes(&self) -> Vec<bitcoin_hashes::sha256d::Hash> {
            self.blocks_in_flight
                .iter()
                .map(|(_, hash)| *hash)
                .collect()
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
                let (_, height) = self.download_last();
                return if height == 0 {
                    Vec::new()
                } else {
                    vec![(self.chain[0], 0)]
                };
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

        fn locator_height(&self, prev: bitcoin_hashes::sha256d::Hash) -> Option<usize> {
            std::iter::once(self.download_last())
                .chain(self.locator_below())
                .find(|(hash, _)| *hash == prev)
                .map(|(_, height)| height)
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
            if let Some(deadline) = self.block_deadline
                && now >= deadline
            {
                return Err(super::PeerError::BlockTimeout);
            }

            let synced = matches!(self.get_headers, GetHeadersModel::Ended);
            let send_headers = self.send_headers == SendHeadersModel::Unsent && synced;

            let mut asked = Vec::new();
            if synced {
                while self.blocks_in_flight.len() < super::BLOCKS_IN_FLIGHT_MAX
                    && self.next_block_height <= self.height()
                {
                    let hash = self.chain[self.next_block_height];
                    self.blocks_in_flight.push((self.next_block_height, hash));
                    asked.push(hash);
                    self.next_block_height += 1;
                }
            }
            if !self.blocks_in_flight.is_empty() && self.block_deadline.is_none() {
                self.block_deadline = Some(now + super::BLOCK_TIMEOUT);
            }
            let get_data = (!asked.is_empty()).then_some(asked);

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
            let wake = self
                .block_deadline
                .map_or(wake, |deadline| deadline.min(wake));
            assert!(now < wake);
            Ok(TickExpected {
                ping,
                send_headers,
                get_headers,
                get_data,
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
            } else if msg_type == crate::protocol::BLOCK {
                let mut input = message.payload();
                let header = crate::block::BlockHeader::decode(&mut input)
                    .map_err(super::PeerError::Block)?;
                let hash = header.hash();
                let Some(index) = self
                    .blocks_in_flight
                    .iter()
                    .position(|(_, pending)| *pending == hash)
                else {
                    return Ok(ReceivedExpected::NoReply);
                };
                let (height, _) = self.blocks_in_flight.remove(index);
                if index == 0 {
                    self.block_deadline = None;
                }
                let block = crate::block::Block::decode(&mut message.payload())
                    .map_err(super::PeerError::Block)?;
                let position = crate::chain::Position::new(self.network, height, hash);
                let checked = crate::block::PositionedBlock::new(block, position)
                    .expect("matching header hash")
                    .check_mutation()
                    .map_err(super::PeerError::BlockMutation)?;
                Ok(ReceivedExpected::Block {
                    height,
                    hash,
                    transactions_count: checked.transactions_count(),
                })
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
            let mut fork = None;
            match self.get_headers {
                GetHeadersModel::Outstanding(_) => {
                    if let Some(first) = headers.first() {
                        let Some(height) = self.locator_height(first.prev) else {
                            return Ok(ReceivedExpected::NoReply);
                        };
                        fork = Some(height);
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
                    let extended = match fork {
                        None => ExtendedModel::Kept,
                        Some(fork) => self.extend_on_locator(fork, &headers)?,
                    };
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
            fork: usize,
            headers: &[crate::block::BlockHeader],
        ) -> Result<ExtendedModel, super::PeerError> {
            assert!(!headers.is_empty());
            assert!(fork <= self.height());
            let batch =
                script_hashes(self.network, self.chain[fork], headers).map_err(extend_error)?;
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
            self.next_block_height = self.next_block_height.min(fork + 1);
            self.blocks_in_flight.retain(|(height, _)| *height <= fork);
            if self.blocks_in_flight.is_empty() {
                self.block_deadline = None;
            }
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
    ) -> super::SyncingPeer<'_> {
        let handshake = start_with(chain, work_min);
        asked_from(peer_with(handshake), now, 7)
    }

    fn batch_then_tick<'a>(
        peer: super::SyncingPeer<'a>,
        headers: &[crate::block::BlockHeader],
        now: std::time::Instant,
    ) -> (super::SyncingPeer<'a>, crate::protocol::GetHeaders) {
        let peer = accept_syncing(peer, &headers_message(headers));
        match peer.tick(now, 8) {
            Ok((
                peer,
                super::SyncingOutbound {
                    ping: None,
                    get_headers: Some(get_headers),
                },
                _,
            )) => (peer, get_headers),
            other => panic!("{other:?}"),
        }
    }

    fn synced_batch_then_tick<'a>(
        peer: super::SyncedPeer<'a>,
        headers: &[crate::block::BlockHeader],
        now: std::time::Instant,
    ) -> (super::SyncedPeer<'a>, crate::protocol::GetHeaders) {
        let peer = accept(peer, &headers_message(headers));
        match peer.tick(now, 8) {
            Ok((
                peer,
                super::SyncedOutbound {
                    ping: None,
                    action: super::SyncedAction::GetHeaders(get_headers),
                },
                _,
            )) => (peer, get_headers),
            other => panic!("{other:?}"),
        }
    }

    fn get_headers_after(header: &crate::block::BlockHeader) -> crate::protocol::GetHeaders {
        let genesis = crate::chainparams::Network::Regtest.genesis().hash();
        let mut locator = vec![header.hash()];
        if header.hash() != genesis {
            locator.push(genesis);
        }
        crate::protocol::GetHeaders::new(locator)
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

    fn peer(chain: &mut crate::chain::Chain) -> super::SyncingPeer<'_> {
        peer_with(start(chain))
    }

    fn peer_with(handshake: super::Handshake<'_>) -> super::SyncingPeer<'_> {
        let (handshake, _) =
            reply(handshake.receive(&core_message(crate::fixtures::VERSION_FRAME)));
        match handshake.receive(&core_message(crate::fixtures::VERACK_FRAME)) {
            Ok(super::Step::Done(peer, _)) => *peer,
            other => panic!("{other:?}"),
        }
    }

    fn asked(
        chain: &mut crate::chain::Chain,
        now: std::time::Instant,
        nonce: u64,
    ) -> super::SyncingPeer<'_> {
        asked_from(peer(chain), now, nonce)
    }

    fn asked_from(
        peer: super::SyncingPeer<'_>,
        now: std::time::Instant,
        nonce: u64,
    ) -> super::SyncingPeer<'_> {
        match peer.tick(now, nonce) {
            Ok((
                peer,
                super::SyncingOutbound {
                    ping: Some(sent),
                    get_headers: Some(_),
                },
                _,
            )) if sent == nonce => peer,
            other => panic!("{other:?}"),
        }
    }

    fn first_get_headers(
        peer: super::SyncingPeer<'_>,
        now: std::time::Instant,
    ) -> (super::SyncingPeer<'_>, crate::protocol::GetHeaders) {
        match peer.tick(now, 7) {
            Ok((
                peer,
                super::SyncingOutbound {
                    ping: Some(_),
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
    ) -> super::SyncedPeer<'_> {
        let peer = synced(asked(chain, now, nonce), &[]);
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::SyncedOutbound {
                    ping: None,
                    action: super::SyncedAction::SendHeaders(None),
                },
                _,
            )) => peer,
            other => panic!("{other:?}"),
        }
    }

    fn synced<'a>(
        peer: super::SyncingPeer<'a>,
        headers: &[crate::block::BlockHeader],
    ) -> super::SyncedPeer<'a> {
        match peer.receive(&headers_message(headers), crate::fixtures::CLOCK) {
            Ok(super::SyncingReceived::Synced(peer, _)) => *peer,
            other => panic!("{other:?}"),
        }
    }

    fn announced<'a>(
        peer: super::SyncedPeer<'a>,
        headers: &[crate::block::BlockHeader],
    ) -> super::SyncedPeer<'a> {
        match peer.receive(&headers_message(headers), crate::fixtures::CLOCK) {
            Ok((peer, super::SyncedReceived::Tip(_))) => peer,
            other => panic!("{other:?}"),
        }
    }

    fn idle_syncing(
        peer: super::SyncingPeer<'_>,
        now: std::time::Instant,
    ) -> (super::SyncingPeer<'_>, std::time::Instant) {
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::SyncingOutbound {
                    ping: None,
                    get_headers: None,
                },
                wake,
            )) => (peer, wake),
            other => panic!("{other:?}"),
        }
    }

    fn idle(
        peer: super::SyncedPeer<'_>,
        now: std::time::Instant,
    ) -> (super::SyncedPeer<'_>, std::time::Instant) {
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::SyncedOutbound {
                    ping: None,
                    action: super::SyncedAction::None,
                },
                wake,
            )) => (peer, wake),
            other => panic!("{other:?}"),
        }
    }

    fn accept_syncing<'a>(
        peer: super::SyncingPeer<'a>,
        message: &crate::transport::Message,
    ) -> super::SyncingPeer<'a> {
        match peer.receive(message, crate::fixtures::CLOCK) {
            Ok(super::SyncingReceived::NoReply(peer)) => peer,
            other => panic!("{other:?}"),
        }
    }

    fn accept<'a>(
        peer: super::SyncedPeer<'a>,
        message: &crate::transport::Message,
    ) -> super::SyncedPeer<'a> {
        match peer.receive(message, crate::fixtures::CLOCK) {
            Ok((peer, super::SyncedReceived::NoReply)) => peer,
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
                Ok(super::SyncingReceived::Pong(_, 0x34e9_3229_8920_45d8))
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
                Ok(super::SyncingReceived::Pong(_, 0x34e9_3229_8920_45d8))
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
        let Ok((peer, super::SyncedReceived::Pong(0x34e9_3229_8920_45d8))) = outbound else {
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
            super::SyncedOutbound {
                ping: Some(8),
                action: super::SyncedAction::None,
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
                    super::SyncedOutbound {
                        ping: Some(8),
                        action: super::SyncedAction::None,
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
        assert_eq!(
            peer(&mut regtest())
                .receive(&short, crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Pong(
                crate::serialize::Error::UnexpectedEnd
            ))
        );
        assert_eq!(
            pinged(&mut chain, start, 7)
                .receive(&short, crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Pong(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let mut longer = 7_u64.to_le_bytes().to_vec();
        longer.push(0xaa);
        accept(pinged(&mut chain, start, 7), &pong_message(&longer));
    }

    #[test]
    fn pong_without_our_ping_is_unsolicited_pong() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let answered = accept(pinged(&mut chain, start, 7), &pong(7));
        assert_eq!(
            peer(&mut regtest())
                .receive(&pong(7), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::UnsolicitedPong)
        );
        assert_eq!(
            answered.receive(&pong(7), crate::fixtures::CLOCK).err(),
            Some(super::PeerError::UnsolicitedPong)
        );
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
                matches!(outbound, Ok(super::SyncingReceived::NoReply(_))),
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
        let peer = accept_syncing(asked(&mut chain, start, 7), &headers_message(&headers));

        let later = start + std::time::Duration::from_mins(1);
        let ticked = peer.tick(later, 8);
        let Ok((
            _,
            super::SyncingOutbound {
                ping: None,
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
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn empty_batch_ends_the_sync_at_our_tip() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2000);
        let peer = accept_syncing(asked(&mut chain, start, 7), &headers_message(&headers));
        let ticked = peer.tick(start, 8);
        let Ok((peer, _, _)) = ticked else {
            panic!("{ticked:?}");
        };

        let received = peer.receive(&headers_message(&[]), crate::fixtures::CLOCK);
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
                matches!(received, Ok(super::SyncingReceived::Synced(..))),
                "{received:?}"
            );
        }

        let work_min = chain.tip().work();
        let peer = peer_with(start_with(&mut chain, work_min));
        let (peer, get_headers) = first_get_headers(peer, start);
        assert_eq!(get_headers, get_headers_on(&headers));
        let received = peer.receive(&headers_message(&[]), crate::fixtures::CLOCK);
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
    fn progress_of_a_handshake_is_the_tip_of_the_chain_after_a_start_again_below_the_minimum() {
        let headers = crate::fixtures::headers_on_genesis(3);
        for (work_min_count, expected) in [(4, tip_after(&[])), (3, tip_after(&headers))] {
            let mut chain = regtest();
            chain
                .extend(
                    crate::fixtures::headers_batch(&headers),
                    crate::fixtures::CLOCK,
                )
                .unwrap();
            let work_min = tip_after(&crate::fixtures::headers_on_genesis(work_min_count)).work();
            let progress = start_with(&mut chain, work_min).progress();
            assert_eq!(progress.tip, expected, "{work_min_count}");
            assert_eq!(progress.low_work_download, None, "{work_min_count}");
        }
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
            let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
    ) -> (super::SyncingPeer<'_>, Vec<crate::block::BlockHeader>) {
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
            let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
                let expected = if download == 0 {
                    presync(first + 2_000)
                } else {
                    redownload(first + 2_000)
                };
                assert_eq!(heights(&peer), (9_500, expected), "{download}, {first}");
            }
            if download == 0 {
                let (next, get_headers) = batch_then_tick(peer, &branch[8_000..], start);
                assert_eq!(get_headers, get_headers_after(&genesis));
                peer = next;
            }
            assert_eq!(peer.chain.tip(), ours);
        }
        let received = peer.receive(&headers_message(&branch[8_000..]), crate::fixtures::CLOCK);
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&branch));
    }

    fn sent_send_headers(
        peer: super::SyncedPeer<'_>,
        now: std::time::Instant,
    ) -> super::SyncedPeer<'_> {
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::SyncedOutbound {
                    action: super::SyncedAction::SendHeaders(_),
                    ..
                },
                _,
            )) => peer,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn second_low_work_sync_in_one_connection_ends_it() {
        let start = std::time::Instant::now();
        let mut chain = regtest();
        let (peer, theirs) = low_work_sync_on_block_50(&mut chain, 2_100, start);
        let peer = sent_send_headers(synced(peer, &theirs[2_050..]), start);
        let (peer, get_headers) = synced_batch_then_tick(peer, &theirs[2_149..], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.chain().locator())
        );
        let (peer, get_headers) = synced_batch_then_tick(peer, &theirs[..2_000], start);
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
        let peer = announced(peer, &more[..25]);
        let (peer, _) = idle(peer, start);
        let ours = crate::fixtures::headers_on_genesis(2_200);
        let peer = announced(peer, &crate::fixtures::headers_on(&ours[2_199], 1));
        let (peer, _) = idle(peer, start);
        let peer = announced(peer, &more[25..51]);
        let (peer, _) = idle(peer, start);
        let (peer, get_headers) = synced_batch_then_tick(peer, &more[51..], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.chain().locator())
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
        let (peer, _) = synced_batch_then_tick(peer, &branch, start);
        let peer = announced(peer, &branch);
        let more = crate::fixtures::headers_on(&branch[1], 2);
        let (peer, _) = synced_batch_then_tick(peer, &[branch[1], more[0]], start);
        let peer = announced(peer, &[branch[0], branch[1], more[0]]);
        let theirs = [&ours[..98], &branch[..], &more[..]].concat();
        assert_eq!(peer.chain.chain().tip(), tip_after(&theirs[..101]));
        let (peer, get_headers) = synced_batch_then_tick(peer, &more[..1], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.chain().locator())
        );
        let peer = announced(peer, &[]);
        let (peer, _) = idle(peer, start);
        let peer = announced(peer, &more[1..]);
        let (peer, _) = idle(peer, start);
        assert_eq!(peer.chain.chain().tip(), tip_after(&theirs));
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
        let (peer, _) = synced_batch_then_tick(peer, &branch, start);
        let peer = announced(peer, &branch);
        let (peer, _) = synced_batch_then_tick(peer, &ours[99..], start);
        let peer = announced(peer, &ours[100..]);
        assert_eq!(peer.chain.chain().tip(), tip_after(&ours));
        let more = crate::fixtures::headers_on(&branch[1], 2);
        let peer = announced(peer, &more[..1]);
        let (peer, _) = idle(peer, start);
        let (peer, get_headers) = synced_batch_then_tick(peer, &more[1..], start);
        assert_eq!(
            get_headers,
            crate::protocol::GetHeaders::new(peer.chain.chain().locator())
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
        let (peer, get_headers) = synced_batch_then_tick(peer, &headers[1_000..], start);
        assert_eq!(get_headers, get_headers_on(&headers));
        let (peer, get_headers) = synced_batch_then_tick(peer, &branch, start);
        assert_eq!(get_headers, get_headers_after(&branch[1_999]));
        assert_eq!(peer.chain.chain().tip(), tip_after(&headers));
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
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
        for announced_headers in [&headers[..1], &[other][..], &headers[2..]] {
            let mut chain = regtest();
            let peer = announced(pinged(&mut chain, start, 7), &headers[..1]);
            let later = start + std::time::Duration::from_mins(1);
            let (peer, get_headers) = synced_batch_then_tick(peer, announced_headers, later);
            assert_eq!(get_headers, get_headers_on(&headers[..1]));
            let received = peer.receive(&headers_message(&headers[1..]), crate::fixtures::CLOCK);
            let Ok((_, super::SyncedReceived::Tip(tip))) = received else {
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
                Ok(super::SyncingReceived::Synced(..)) => assert!(expected, "{network:?}"),
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
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
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
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    fn heights(peer: &super::SyncingPeer<'_>) -> (usize, Option<super::LowWorkDownload>) {
        let progress = peer.progress();
        (progress.tip.height(), progress.low_work_download)
    }

    fn synced_heights(peer: &super::SyncedPeer<'_>) -> (usize, Option<super::LowWorkDownload>) {
        let progress = peer.progress();
        (progress.tip.height(), progress.low_work_download)
    }

    fn presync(height: usize) -> Option<super::LowWorkDownload> {
        let height = std::num::NonZeroUsize::new(height).unwrap();
        Some(super::LowWorkDownload::Presync(height))
    }

    fn redownload(height: usize) -> Option<super::LowWorkDownload> {
        Some(super::LowWorkDownload::Redownload(height))
    }

    #[test]
    fn progress_of_a_low_work_sync_is_the_height_of_each_download_then_of_the_chain() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(12_002);
        let work_min = tip_after(&headers[..11_000]).work();
        let mut peer = asked_with(&mut chain, work_min, start);
        assert_eq!(heights(&peer), (0, None));
        let expected = [
            (0, presync(2_000)),
            (0, presync(4_000)),
            (0, presync(6_000)),
            (0, presync(8_000)),
            (0, presync(10_000)),
            (0, redownload(0)),
            (0, redownload(2_000)),
            (0, redownload(4_000)),
            (0, redownload(6_000)),
            (983, redownload(8_000)),
            (2_983, redownload(10_000)),
            (12_000, None),
        ];
        let batches = headers[..12_000].chunks(2_000).cycle();
        for (index, (batch, expected)) in batches.zip(expected).enumerate() {
            (peer, _) = batch_then_tick(peer, batch, start);
            assert_eq!(heights(&peer), expected, "batch {index}");
        }
        let received = peer.receive(&headers_message(&headers[12_000..]), crate::fixtures::CLOCK);
        let Ok(super::SyncingReceived::Synced(peer, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(synced_heights(&peer), (12_002, None));
        assert_eq!(peer.progress().tip, tip);
    }

    #[test]
    fn progress_of_a_low_work_sync_of_a_branch_has_the_height_of_each_download_and_of_our_chain() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_200);
        let branch = crate::fixtures::branch_on(&headers[49], 2_300);
        let mut chain = regtest();
        for batch in crate::protocol::Headers::batches(headers.clone()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        let mut peer = asked(&mut chain, start, 7);
        for (batch, expected) in [
            (
                &[&headers[..50], &branch[..1_950]].concat()[..],
                (2_200, None),
            ),
            (&branch[..2_000], (2_200, presync(2_050))),
            (&branch[2_000..], (2_200, redownload(50))),
            (&branch[..2_000], (2_200, redownload(2_050))),
        ] {
            (peer, _) = batch_then_tick(peer, batch, start);
            assert_eq!(heights(&peer), expected, "{}", batch.len());
        }
        let received = peer.receive(&headers_message(&branch[2_000..]), crate::fixtures::CLOCK);
        let Ok(super::SyncingReceived::Synced(peer, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(synced_heights(&peer), (2_350, None));
        assert_eq!(peer.progress().tip, tip);
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
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn headers_off_the_locator_of_a_low_work_sync_are_skipped() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(3_500);
        let work_min = tip_after(&headers).work();
        let (peer, _) = batch_then_tick(
            asked_with(&mut chain, work_min, start),
            &headers[..2_000],
            start,
        );
        let off_locator = crate::fixtures::branch_on(&headers[1_000], 20);
        let peer = accept_syncing(peer, &headers_message(&off_locator));
        let (peer, _) = batch_then_tick(peer, &headers[2_000..], start);
        let (peer, _) = batch_then_tick(peer, &headers[..2_000], start);
        let received = peer.receive(&headers_message(&headers[2_000..]), crate::fixtures::CLOCK);
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn headers_off_the_locator_of_a_branch_download_are_skipped() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_100);
        let branch =
            crate::fixtures::branch_on(&crate::chainparams::Network::Regtest.genesis(), 2_200);
        let mut chain = regtest();
        for batch in crate::protocol::Headers::batches(headers.clone()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        let (peer, _) = batch_then_tick(asked(&mut chain, start, 7), &branch[..2_000], start);
        let off_locator = crate::fixtures::headers_on(&headers[2_099], 1);
        let peer = accept_syncing(peer, &headers_message(&off_locator));
        let received = peer.receive(&headers_message(&branch[2_000..]), crate::fixtures::CLOCK);
        let Ok(super::SyncingReceived::Synced(_, tip)) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&branch));
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
    fn low_work_sync_ends_the_connection_at_once_on_an_answer_from_genesis() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_000);
        let work_min = tip_after(&headers)
            .work()
            .saturating_add(tip_after(&[]).work());
        let (peer, get_headers) =
            batch_then_tick(asked_with(&mut chain, work_min, start), &headers, start);
        assert_eq!(get_headers, get_headers_after(&headers[1_999]));
        let other = crate::fixtures::branch_on(&crate::chainparams::Network::Regtest.genesis(), 1);
        assert_eq!(
            peer.receive(&headers_message(&other), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::HeadersSync(
                crate::headerssync::HeadersSyncError::NotContinuous
            ))
        );
    }

    #[test]
    fn branch_download_ends_the_connection_at_once_on_an_answer_from_genesis() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2_001);
        let mut chain = regtest();
        for batch in crate::protocol::Headers::batches(headers.clone()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        let (peer, get_headers) =
            batch_then_tick(asked(&mut chain, start, 7), &headers[..2_000], start);
        assert_eq!(get_headers, get_headers_after(&headers[1_999]));
        let other = crate::fixtures::branch_on(&crate::chainparams::Network::Regtest.genesis(), 1);
        assert_eq!(
            peer.receive(&headers_message(&other), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Extend(
                crate::chain::ExtendError::NotContinuous
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
        for (announced_headers, height) in [(&headers[..1], 1), (&headers[1..], 3), (&[][..], 3)] {
            let received =
                peer.receive(&headers_message(announced_headers), crate::fixtures::CLOCK);
            let Ok((next, super::SyncedReceived::Tip(tip))) = received else {
                panic!("{received:?}");
            };
            assert_eq!(tip, tip_after(&headers[..height]));
            peer = next;
        }
        let later = start + std::time::Duration::from_mins(10);
        let ticked = peer.tick(later, 0);
        let Ok((
            _,
            super::SyncedOutbound {
                ping: None,
                action: super::SyncedAction::GetData(get_data),
            },
            wake,
        )) = ticked
        else {
            panic!("{ticked:?}");
        };
        assert_eq!(
            get_data,
            crate::protocol::GetData::witness_blocks(
                headers[0].hash(),
                headers[1..]
                    .iter()
                    .map(crate::block::BlockHeader::hash)
                    .collect()
            )
        );
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
                super::SyncedOutbound {
                    ping: None,
                    action: super::SyncedAction::SendHeaders(Some(_)),
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
                super::SyncedOutbound {
                    ping: None,
                    action: super::SyncedAction::GetHeaders(get_headers),
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
        let Ok((_, super::SyncedReceived::Tip(tip))) = received else {
            panic!("{received:?}");
        };
        assert_eq!(tip, tip_after(&headers));
    }

    #[test]
    fn inv_in_the_sync_or_with_no_block_is_skipped() {
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(1);
        let mut chain = regtest();
        let peer = accept_syncing(asked(&mut chain, start, 7), &inv_message(&[2]));
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
        let (peer, get_headers) = synced_batch_then_tick(peer, &headers[..2000], later);
        assert_eq!(get_headers, get_headers_on(&headers[..2000]));
        let received = peer.receive(&headers_message(&headers[2000..]), crate::fixtures::CLOCK);
        let Ok((_, super::SyncedReceived::Tip(tip))) = received else {
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
        let peer = accept_syncing(
            asked(&mut asked_chain, start, 7),
            &headers_message(&headers[1..]),
        );
        assert_eq!(peer.chain.tip(), tip_after(&[]));
        synced(peer, &headers);
        let (announced_peer, _) =
            synced_batch_then_tick(pinged(&mut announced_chain, start, 7), &headers[1..], later);
        let announced_peer = accept(announced_peer, &headers_message(&headers[1..]));
        assert_eq!(announced_peer.chain.chain().tip(), tip_after(&[]));
        announced(announced_peer, &headers);
        assert_eq!(asked_chain.tip(), tip_after(&headers));
        assert_eq!(announced_chain.tip(), tip_after(&headers));
    }

    #[test]
    fn headers_on_a_header_in_a_gap_of_our_locator_are_skipped() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(14);
        chain
            .extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK,
            )
            .unwrap();
        let branch = crate::fixtures::branch_on(&headers[1], 20);
        let peer = accept_syncing(asked(&mut chain, start, 7), &headers_message(&branch));
        assert_eq!(peer.chain.tip(), tip_after(&headers));
    }

    #[test]
    fn headers_off_our_locator_do_not_restart_the_headers_timeout() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let headers = crate::fixtures::headers_on_genesis(2);
        let timeout = start + super::HEADERS_TIMEOUT;
        let (peer, _) = idle_syncing(asked(&mut chain, start, 7), timeout - NANOSECOND);
        let peer = accept_syncing(peer, &headers_message(&headers[1..]));
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
        let (peer, wake) = idle_syncing(asked(&mut chain, start, 7), timeout - NANOSECOND);
        assert_eq!(wake, timeout);
        assert_eq!(
            peer.tick(timeout, 8).err(),
            Some(super::PeerError::HeadersTimeout)
        );
    }

    fn coinbase_block(header: crate::block::BlockHeader, tag: u32) -> crate::block::Block {
        let tx = crate::transaction::Transaction::new(
            1,
            vec![crate::transaction::TxIn {
                previous_output: crate::transaction::OutPoint {
                    txid: bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]),
                    vout: u32::MAX,
                },
                script_sig: tag.to_le_bytes().to_vec(),
                sequence: 0,
                witness: crate::transaction::Witness::default(),
            }],
            Vec::new(),
            0,
        )
        .unwrap();
        let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            merkle_root: tx.txid().to_byte_array(),
            ..header
        });
        crate::block::Block {
            header,
            transactions: vec![tx],
        }
    }

    fn blocks_on(
        below: &crate::block::BlockHeader,
        count: usize,
        tag: u32,
    ) -> Vec<crate::block::Block> {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let mut prev = *below;
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let block = coinbase_block(
                crate::block::BlockHeader {
                    version: crate::fixtures::HEADER_VERSION,
                    prev: prev.hash(),
                    time: prev.time + 1,
                    ..genesis
                },
                tag,
            );
            prev = block.header;
            blocks.push(block);
        }
        blocks
    }

    fn block_message(block: &crate::block::Block) -> crate::transport::Message {
        let mut payload = Vec::new();
        crate::serialize::Encode::encode(block, &mut payload);
        block_payload_message(&payload)
    }

    fn block_payload_message(payload: &[u8]) -> crate::transport::Message {
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::BLOCK,
            payload,
        ))
    }

    fn get_data_for(blocks: &[crate::block::Block]) -> crate::protocol::GetData {
        let (first, rest) = blocks.split_first().unwrap();
        crate::protocol::GetData::witness_blocks(
            first.header.hash(),
            rest.iter().map(|block| block.header.hash()).collect(),
        )
    }

    fn tick_get_data(
        peer: super::SyncedPeer<'_>,
        now: std::time::Instant,
    ) -> (
        super::SyncedPeer<'_>,
        crate::protocol::GetData,
        std::time::Instant,
    ) {
        match peer.tick(now, 0) {
            Ok((
                peer,
                super::SyncedOutbound {
                    ping: None,
                    action:
                        super::SyncedAction::GetData(get_data)
                        | super::SyncedAction::SendHeaders(Some(get_data)),
                },
                wake,
            )) => (peer, get_data, wake),
            other => panic!("{other:?}"),
        }
    }

    fn receive_block<'a>(
        peer: super::SyncedPeer<'a>,
        block: &crate::block::Block,
    ) -> (super::SyncedPeer<'a>, crate::block::CheckedBlock) {
        match peer.receive(&block_message(block), crate::fixtures::CLOCK) {
            Ok((peer, super::SyncedReceived::Block(checked))) => (peer, checked),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn their_version_must_include_network_and_witness_services() {
        for (bits, ok) in [
            (0_u64, false),
            (1, false),
            (8, false),
            (0x0408, false),
            (0x0009, true),
            (0x0c09, true),
        ] {
            let mut chain = regtest();
            let message = version_message(|payload| {
                payload[size_of::<i32>()..size_of::<i32>() + size_of::<u64>()]
                    .copy_from_slice(&bits.to_le_bytes());
            });
            let result = start(&mut chain).receive(&message);
            if ok {
                reply(result);
            } else {
                assert_eq!(
                    result.err(),
                    Some(super::HandshakeError::MissingServices(
                        crate::protocol::ServiceFlags::from_bits(bits)
                    )),
                    "{bits:#x}"
                );
            }
        }
    }

    #[test]
    fn after_sync_getdata_asks_from_height_1_up_to_blocks_in_flight_max_and_tops_up() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let blocks = blocks_on(&genesis, super::BLOCKS_IN_FLIGHT_MAX + 2, 0);
        let headers: Vec<_> = blocks.iter().map(|block| block.header).collect();
        let peer = synced(asked(&mut chain, start, 7), &headers);

        let (peer, get_data, wake) = tick_get_data(peer, start);
        assert_eq!(
            get_data,
            get_data_for(&blocks[..super::BLOCKS_IN_FLIGHT_MAX])
        );
        assert_eq!(wake, start + super::BLOCK_TIMEOUT);
        let (peer, wake) = idle(peer, start);
        assert_eq!(wake, start + super::BLOCK_TIMEOUT);

        let (peer, checked) = receive_block(peer, &blocks[0]);
        assert_eq!(checked.height().get(), 1);
        assert_eq!(checked.hash(), blocks[0].header.hash());
        assert_eq!(checked.transactions_count(), 1);

        let later = start + std::time::Duration::from_mins(1);
        let (peer, get_data, wake) = tick_get_data(peer, later);
        assert_eq!(
            get_data,
            get_data_for(&blocks[super::BLOCKS_IN_FLIGHT_MAX..super::BLOCKS_IN_FLIGHT_MAX + 1])
        );
        assert_eq!(wake, later + super::BLOCK_TIMEOUT);

        let (peer, checked) = receive_block(peer, &blocks[1]);
        assert_eq!(checked.height().get(), 2);
        let (peer, get_data, _) = tick_get_data(peer, later);
        assert_eq!(
            get_data,
            get_data_for(&blocks[super::BLOCKS_IN_FLIGHT_MAX + 1..])
        );

        let mut peer = peer;
        for (index, block) in blocks[2..].iter().enumerate() {
            let (next, checked) = receive_block(peer, block);
            assert_eq!(checked.height().get(), index + 3);
            peer = next;
        }
        let (_, wake) = idle(peer, later);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn out_of_order_block_keeps_the_oldest_timeout_and_oldest_resets_it() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let blocks = blocks_on(&genesis, 2, 0);
        let headers: Vec<_> = blocks.iter().map(|block| block.header).collect();
        let peer = synced(asked(&mut chain, start, 7), &headers);
        let (peer, _, _) = tick_get_data(peer, start);

        let (peer, checked) = receive_block(peer, &blocks[1]);
        assert_eq!(checked.height().get(), 2);
        let before = start + super::BLOCK_TIMEOUT - NANOSECOND;
        let (peer, wake) = idle(peer, before);
        assert_eq!(wake, start + super::BLOCK_TIMEOUT);
        assert_eq!(
            peer.tick(start + super::BLOCK_TIMEOUT, 0).err(),
            Some(super::PeerError::BlockTimeout)
        );

        let mut chain = regtest();
        let peer = synced(asked(&mut chain, start, 7), &headers);
        let (peer, _, _) = tick_get_data(peer, start);
        let (peer, checked) = receive_block(peer, &blocks[0]);
        assert_eq!(checked.height().get(), 1);
        let mid = start + std::time::Duration::from_mins(5);
        let (peer, wake) = idle(peer, mid);
        assert_eq!(wake, mid + super::BLOCK_TIMEOUT);
        let (peer, wake) = idle(peer, start + super::BLOCK_TIMEOUT);
        assert_eq!(wake, mid + super::BLOCK_TIMEOUT);
        assert_eq!(
            peer.tick(mid + super::BLOCK_TIMEOUT, 0).err(),
            Some(super::PeerError::BlockTimeout)
        );
    }

    #[test]
    fn unsolicited_block_is_skipped_and_malformed_or_mutated_block_ends_the_connection() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let blocks = blocks_on(&genesis, 2, 0);
        let headers: Vec<_> = blocks.iter().map(|block| block.header).collect();
        let peer = asked(&mut chain, start, 7);
        let peer = accept_syncing(peer, &block_message(&blocks[0]));
        let peer = synced(peer, &headers[..1]);
        let (peer, _, _) = tick_get_data(peer, start);

        let peer = accept(peer, &block_message(&blocks[1]));
        let mut unsolicited_header_only = Vec::new();
        crate::serialize::Encode::encode(&blocks[1].header, &mut unsolicited_header_only);
        let peer = accept(peer, &block_payload_message(&unsolicited_header_only));
        let genesis_block = crate::fixtures::block(crate::fixtures::REGTEST_GENESIS_BLOCK);
        let peer = accept(peer, &block_message(&genesis_block));

        let mut mutated = blocks[0].clone();
        mutated.transactions.clear();
        assert_eq!(
            peer.receive(&block_message(&mutated), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::BlockMutation(
                crate::block::MutationError::MerkleRoot
            ))
        );

        let mut chain = regtest();
        let peer = synced(asked(&mut chain, start, 7), &headers[..1]);
        let (peer, _, _) = tick_get_data(peer, start);
        let mut requested_header_only = Vec::new();
        crate::serialize::Encode::encode(&blocks[0].header, &mut requested_header_only);
        assert_eq!(
            peer.receive(
                &block_payload_message(&requested_header_only),
                crate::fixtures::CLOCK
            )
            .err(),
            Some(super::PeerError::Block(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let mut chain = regtest();
        let peer = synced(asked(&mut chain, start, 7), &headers[..1]);
        assert_eq!(
            peer.receive(&block_payload_message(&[0; 10]), crate::fixtures::CLOCK)
                .err(),
            Some(super::PeerError::Block(
                crate::serialize::Error::UnexpectedEnd
            ))
        );
    }

    #[test]
    fn reorg_drops_stale_in_flight_blocks_and_requests_the_new_branch() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let first = blocks_on(&genesis, 3, 0);
        let first_headers: Vec<_> = first.iter().map(|block| block.header).collect();
        let peer = synced(asked(&mut chain, start, 7), &first_headers);
        let (peer, get_data, _) = tick_get_data(peer, start);
        assert_eq!(get_data, get_data_for(&first));

        let branch = blocks_on(&first[0].header, 3, 1);
        let branch_headers: Vec<_> = branch.iter().map(|block| block.header).collect();
        let (peer, _) = synced_batch_then_tick(peer, &branch_headers, start);
        let peer = announced(peer, &branch_headers);

        let peer = accept(peer, &block_message(&first[1]));
        let (peer, get_data, wake) = tick_get_data(peer, start + std::time::Duration::from_mins(2));
        assert_eq!(get_data, get_data_for(&branch));
        assert_eq!(wake, start + super::BLOCK_TIMEOUT);

        let (peer, checked) = receive_block(peer, &first[0]);
        assert_eq!(checked.height().get(), 1);
        assert_eq!(checked.hash(), first[0].header.hash());
        let mut peer = peer;
        for (index, block) in branch.iter().enumerate() {
            let (next, checked) = receive_block(peer, block);
            assert_eq!(checked.height().get(), index + 2);
            assert_eq!(checked.hash(), block.header.hash());
            peer = next;
        }
        let (_, wake) = idle(peer, start + std::time::Duration::from_mins(2));
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn reorg_below_oldest_in_flight_clears_the_block_timeout() {
        let mut chain = regtest();
        let start = std::time::Instant::now();
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let first = blocks_on(&genesis, 2, 0);
        let first_headers: Vec<_> = first.iter().map(|block| block.header).collect();
        let peer = synced(asked(&mut chain, start, 7), &first_headers);
        let (peer, _, _) = tick_get_data(peer, start);

        let branch = blocks_on(&genesis, 3, 1);
        let branch_headers: Vec<_> = branch.iter().map(|block| block.header).collect();
        let (peer, _) = synced_batch_then_tick(peer, &branch_headers, start);
        let peer = announced(peer, &branch_headers);

        let later = start + std::time::Duration::from_mins(5);
        let (peer, get_data, wake) = tick_get_data(peer, later);
        assert_eq!(get_data, get_data_for(&branch));
        assert_eq!(wake, later + super::BLOCK_TIMEOUT);
        let _ = accept(peer, &block_message(&first[0]));
    }
}
