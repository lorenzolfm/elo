use crate::serialize::Encode;
use std::hash::{BuildHasher, Hasher};
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(20);

const LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const ADDRESSES_COUNT_MAX: usize = 256;

const SEED_ADDRESSES_COUNT_MAX: usize = 32;

const NAME_LENGTH_MAX: usize = 253;

const LABEL_LENGTH_MAX: usize = 63;

pub(crate) const DESTINATION_LENGTH_MAX: usize = NAME_LENGTH_MAX + ".".len() + ":65535".len();

#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    Destination(Destination),
    Seeds(Seeds),
}

impl Source {
    pub fn destination(&self) -> std::borrow::Cow<'_, Destination> {
        match self {
            Source::Destination(destination) => std::borrow::Cow::Borrowed(destination),
            Source::Seeds(seeds) => std::borrow::Cow::Owned(seeds.choose()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Seeds {
    first: &'static str,
    rest: &'static [&'static str],
    port: std::num::NonZeroU16,
}

impl Seeds {
    pub fn new(network: crate::chainparams::Network) -> Option<Seeds> {
        let (&first, rest) = network.seeds().split_first()?;
        Some(Seeds {
            first,
            rest,
            port: network.default_port(),
        })
    }

    fn choose(&self) -> Destination {
        let random = std::hash::RandomState::new();
        let first = (random.hash_one(self.first), self.first);
        let (_, seed) = self
            .rest
            .iter()
            .map(|&seed| (random.hash_one(seed), seed))
            .fold(first, std::cmp::min);
        Destination::Seed {
            seed: Seed(seed),
            port: self.port,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed(&'static str);

impl Seed {
    fn services_name(&self) -> String {
        let services = crate::protocol::ServiceFlags::NETWORK_WITNESS;
        format!("x{services:x}.{}", self.0)
    }
}

impl std::fmt::Display for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Destination {
    Address(PeerAddress),
    Name {
        name: Name,
        port: std::num::NonZeroU16,
    },
    Seed {
        seed: Seed,
        port: std::num::NonZeroU16,
    },
}

impl std::fmt::Display for Destination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Destination::Address(address) => write!(f, "{}", address.0),
            Destination::Name { name, port } => write!(f, "{name}:{port}"),
            Destination::Seed { seed, port } => write!(f, "{seed}:{port}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerAddress(std::net::SocketAddr);

impl PeerAddress {
    pub fn new(address: std::net::SocketAddr) -> Option<PeerAddress> {
        if address.port() == 0 || address.ip().to_canonical().is_unspecified() {
            return None;
        }
        Some(PeerAddress(address))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Name(String);

impl Name {
    pub fn new(host: &str) -> Option<Name> {
        let labels = host.strip_suffix('.').unwrap_or(host);
        if labels.len() > NAME_LENGTH_MAX {
            return None;
        }
        if !labels.split('.').all(is_label) {
            return None;
        }
        let last = labels.rsplit_once('.').map_or(labels, |(_, last)| last);
        if is_number(last) {
            return None;
        }
        Some(Name(host.to_owned()))
    }
}

impl std::fmt::Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn is_reserved(ip: std::net::IpAddr) -> bool {
    match ip.to_canonical() {
        std::net::IpAddr::V4(ip) => {
            let [first, second, _, _] = ip.octets();
            let is_this_network = first == 0;
            let is_shared = first == 100 && (64..=127).contains(&second);
            let is_benchmarking = first == 198 && (18..=19).contains(&second);
            is_this_network
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || is_shared
                || is_benchmarking
                || ip.is_documentation()
                || ip.is_broadcast()
        }
        std::net::IpAddr::V6(ip) => {
            let [first, second, ..] = ip.segments();
            let is_documentation = first == 0x2001 && second == 0x0db8;
            let is_orchid =
                first == 0x2001 && (second & 0xfff0 == 0x0010 || second & 0xfff0 == 0x0020);
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || is_documentation
                || is_orchid
        }
    }
}

fn is_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    if label.len() > LABEL_LENGTH_MAX {
        return false;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn is_number(label: &str) -> bool {
    let (digits, radix) = match label
        .strip_prefix("0x")
        .or_else(|| label.strip_prefix("0X"))
    {
        Some(hex) => (hex, 16),
        None => (label, 10),
    };
    digits.chars().all(|digit| digit.is_digit(radix))
}

#[derive(Debug)]
pub enum LookupError {
    Failed(std::io::Error),
    Timeout { host: String },
    Empty,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LookupError::Failed(error) => write!(f, "lookup: {error}"),
            LookupError::Timeout { host } => write!(
                f,
                "the lookup of {host} took longer than {} s",
                LOOKUP_TIMEOUT.as_secs()
            ),
            LookupError::Empty => write!(f, "the lookup gave no address"),
        }
    }
}

#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    Timeout,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Io(error) => write!(f, "{error}"),
            ConnectError::Timeout => write!(f, "took longer than {} s", CONNECT_TIMEOUT.as_secs()),
        }
    }
}

#[derive(Debug)]
pub enum HandshakeError {
    Lookup(LookupError),
    Connect {
        address: std::net::SocketAddr,
        addresses_count: usize,
        error: ConnectError,
    },
    HandshakeTimeout,
    Io(std::io::Error),
    Closed,
    Transport(crate::transport::Error),
    NetProcessing(crate::net_processing::HandshakeError),
    Salt(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Lookup(error) => write!(f, "{error}"),
            HandshakeError::Connect {
                address,
                addresses_count: 1,
                error,
            } => write!(f, "connect to {address}: {error}"),
            HandshakeError::Connect {
                address,
                addresses_count,
                error,
            } => write!(
                f,
                "connect to {address}, the last of {addresses_count} addresses: {error}"
            ),
            HandshakeError::HandshakeTimeout => {
                write!(
                    f,
                    "handshake took longer than {} s",
                    HANDSHAKE_TIMEOUT.as_secs()
                )
            }
            HandshakeError::Io(error) => write!(f, "socket: {error}"),
            HandshakeError::Closed => write!(f, "the peer closed the connection"),
            HandshakeError::Transport(error) => write!(f, "frame: {error}"),
            HandshakeError::NetProcessing(error) => write!(f, "peer: {error}"),
            HandshakeError::Salt(error) => write!(f, "salt: {RANDOM_SOURCE}: {error}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<ReceiveError> for HandshakeError {
    fn from(error: ReceiveError) -> HandshakeError {
        match error {
            ReceiveError::Io(error) => HandshakeError::Io(error),
            ReceiveError::Closed => HandshakeError::Closed,
            ReceiveError::Transport(error) => HandshakeError::Transport(error),
        }
    }
}

#[derive(Debug)]
pub enum RunError {
    SendTimeout,
    Io(std::io::Error),
    Closed,
    Transport(crate::transport::Error),
    NetProcessing(crate::net_processing::PeerError),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::SendTimeout => {
                write!(f, "a send took longer than {} s", SEND_TIMEOUT.as_secs())
            }
            RunError::Io(error) => write!(f, "socket: {error}"),
            RunError::Closed => write!(f, "the peer closed the connection"),
            RunError::Transport(error) => write!(f, "frame: {error}"),
            RunError::NetProcessing(error) => write!(f, "peer: {error}"),
        }
    }
}

impl std::error::Error for RunError {}

impl From<ReceiveError> for RunError {
    fn from(error: ReceiveError) -> RunError {
        match error {
            ReceiveError::Io(error) => RunError::Io(error),
            ReceiveError::Closed => RunError::Closed,
            ReceiveError::Transport(error) => RunError::Transport(error),
        }
    }
}

#[derive(Debug)]
enum ReceiveError {
    Io(std::io::Error),
    Closed,
    Transport(crate::transport::Error),
}

#[derive(Debug)]
pub struct Connection<'a> {
    socket: Socket,
    peer: crate::net_processing::Peer<'a>,
    address: std::net::SocketAddr,
}

#[derive(Debug)]
pub struct Synced<'a> {
    socket: Socket,
    peer: crate::net_processing::Peer<'a>,
    tip: crate::chain::Tip,
}

#[derive(Debug)]
struct Socket {
    stream: tokio::net::TcpStream,
    network: crate::chainparams::Network,
    frame: PartialFrame,
}

#[derive(Debug)]
enum PartialFrame {
    Header {
        bytes: [u8; crate::transport::MESSAGE_HEADER_SIZE],
        filled: usize,
    },
    Payload {
        header: crate::transport::MessageHeader,
        payload: Vec<u8>,
        filled: usize,
    },
}

pub async fn handshake<'a>(
    destination: &Destination,
    chain: &'a mut crate::chain::Chain,
) -> Result<(Connection<'a>, crate::protocol::Version), HandshakeError> {
    let addresses = addresses(destination)
        .await
        .map_err(HandshakeError::Lookup)?;
    let (address, stream) = connect_first(&addresses).await?;
    handshake_stream(address, stream, chain).await
}

async fn addresses(destination: &Destination) -> Result<Addresses, LookupError> {
    match destination {
        Destination::Address(address) => Ok(Addresses {
            before: Vec::new(),
            last: *address,
        }),
        Destination::Name { name, port } => name_order(lookup(&name.0, *port).await?),
        Destination::Seed { seed, port } => {
            let services_name = seed.services_name();
            let services = lookup(&services_name, *port).await;
            match services.and_then(seed_order) {
                Ok(addresses) => Ok(addresses),
                Err(error @ LookupError::Timeout { .. }) => Err(error),
                Err(LookupError::Failed(_) | LookupError::Empty) => {
                    seed_order(lookup(seed.0, *port).await?)
                }
            }
        }
    }
}

#[derive(Debug)]
struct Addresses {
    before: Vec<PeerAddress>,
    last: PeerAddress,
}

async fn lookup(
    host: &str,
    port: std::num::NonZeroU16,
) -> Result<impl Iterator<Item = std::net::SocketAddr>, LookupError> {
    let answers = tokio::net::lookup_host((host, port.get()));
    match tokio::time::timeout(LOOKUP_TIMEOUT, answers).await {
        Ok(Ok(answers)) => Ok(answers),
        Ok(Err(error)) => Err(LookupError::Failed(error)),
        Err(_elapsed) => Err(LookupError::Timeout {
            host: host.to_owned(),
        }),
    }
}

fn name_order(
    answers: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Result<Addresses, LookupError> {
    let answers = answers.into_iter().filter_map(PeerAddress::new);
    dial_order::<ADDRESSES_COUNT_MAX>(answers)
}

fn seed_order(
    answers: impl IntoIterator<Item = std::net::SocketAddr>,
) -> Result<Addresses, LookupError> {
    let routable = answers
        .into_iter()
        .filter_map(PeerAddress::new)
        .filter(|address| !is_reserved(address.0.ip()));
    dial_order::<SEED_ADDRESSES_COUNT_MAX>(routable)
}

fn dial_order<const COUNT_MAX: usize>(
    answers: impl Iterator<Item = PeerAddress>,
) -> Result<Addresses, LookupError> {
    const { assert!(COUNT_MAX <= ADDRESSES_COUNT_MAX) };
    let mut before: Vec<PeerAddress> = answers.take(COUNT_MAX).collect();
    before.sort_unstable_by_key(|address| address.0);
    before.dedup();
    let random = std::hash::RandomState::new();
    before.sort_by_cached_key(|address| random.hash_one(address));
    let Some(last) = before.pop() else {
        return Err(LookupError::Empty);
    };
    assert!(before.len() < COUNT_MAX, "{} {COUNT_MAX}", before.len());
    Ok(Addresses { before, last })
}

async fn connect_first(
    addresses: &Addresses,
) -> Result<(std::net::SocketAddr, tokio::net::TcpStream), HandshakeError> {
    let Addresses { before, last } = addresses;
    assert!(before.len() < ADDRESSES_COUNT_MAX, "{}", before.len());
    for &address in before {
        if let Ok(stream) = connect(address).await {
            return Ok((address.0, stream));
        }
    }
    match connect(*last).await {
        Ok(stream) => Ok((last.0, stream)),
        Err(error) => Err(HandshakeError::Connect {
            address: last.0,
            addresses_count: before.len() + 1,
            error,
        }),
    }
}

async fn connect(address: PeerAddress) -> Result<tokio::net::TcpStream, ConnectError> {
    let connect = tokio::net::TcpStream::connect(address.0);
    match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(ConnectError::Io(error)),
        Err(_elapsed) => Err(ConnectError::Timeout),
    }
}

async fn handshake_stream(
    address: std::net::SocketAddr,
    stream: tokio::net::TcpStream,
    chain: &mut crate::chain::Chain,
) -> Result<(Connection<'_>, crate::protocol::Version), HandshakeError> {
    let exchange = handshake_stream_exchange(address, stream, chain);
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(HandshakeError::HandshakeTimeout),
    }
}

async fn handshake_stream_exchange(
    address: std::net::SocketAddr,
    stream: tokio::net::TcpStream,
    chain: &mut crate::chain::Chain,
) -> Result<(Connection<'_>, crate::protocol::Version), HandshakeError> {
    let network = chain.network();
    let mut socket = Socket::new(stream, network);
    let work_min = crate::pow::chain_work_min(network);
    let salt = salt().map_err(HandshakeError::Salt)?;
    let (mut handshake, outbound) = crate::net_processing::Handshake::start(
        address,
        timestamp(),
        nonce(),
        chain,
        work_min,
        salt,
    );
    socket
        .send_handshake_outbound(&outbound)
        .await
        .map_err(HandshakeError::Io)?;
    loop {
        let message = socket.receive().await?;
        match handshake
            .receive(&message)
            .map_err(HandshakeError::NetProcessing)?
        {
            crate::net_processing::Step::Wait(next) => handshake = next,
            crate::net_processing::Step::Reply(next, outbound) => {
                socket
                    .send_handshake_outbound(&outbound)
                    .await
                    .map_err(HandshakeError::Io)?;
                handshake = next;
            }
            crate::net_processing::Step::Done(peer, theirs) => {
                let connection = Connection {
                    socket,
                    peer,
                    address,
                };
                return Ok((connection, theirs));
            }
        }
    }
}

impl<'a> Connection<'a> {
    pub fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    pub async fn sync(self) -> Result<(Synced<'a>, crate::chain::Tip), RunError> {
        let Connection {
            mut socket,
            mut peer,
            address: _,
        } = self;
        loop {
            match run_turn(&mut socket, peer).await? {
                (next, None) => peer = next,
                (peer, Some(tip)) => return Ok((Synced { socket, peer, tip }, tip)),
            }
        }
    }
}

impl<'a> Synced<'a> {
    pub async fn next_tip(self) -> Result<(Synced<'a>, crate::chain::Tip), RunError> {
        let Synced {
            mut socket,
            mut peer,
            tip: previous,
        } = self;
        loop {
            match run_turn(&mut socket, peer).await? {
                (next, None) => peer = next,
                (next, Some(tip)) if tip == previous => peer = next,
                (peer, Some(tip)) => {
                    assert!(tip.work() >= previous.work());
                    return Ok((Synced { socket, peer, tip }, tip));
                }
            }
        }
    }
}

async fn run_turn<'a>(
    socket: &mut Socket,
    peer: crate::net_processing::Peer<'a>,
) -> Result<(crate::net_processing::Peer<'a>, Option<crate::chain::Tip>), RunError> {
    let now = tokio::time::Instant::now().into_std();
    let (peer, tick_outbound, wake) = peer.tick(now, nonce()).map_err(RunError::NetProcessing)?;
    for outbound in tick_outbound.into_outbounds() {
        run_send(socket, &outbound).await?;
    }
    let receive = socket.receive();
    match tokio::time::timeout_at(tokio::time::Instant::from_std(wake), receive).await {
        Ok(message) => run_exchange(socket, peer, &message?).await,
        Err(_elapsed) => Ok((peer, None)),
    }
}

async fn run_exchange<'a>(
    socket: &mut Socket,
    peer: crate::net_processing::Peer<'a>,
    message: &crate::transport::Message,
) -> Result<(crate::net_processing::Peer<'a>, Option<crate::chain::Tip>), RunError> {
    let (peer, received) = peer
        .receive(message, clock())
        .map_err(RunError::NetProcessing)?;
    match received {
        crate::net_processing::Received::NoReply => {
            assert_ne!(message.msg_type(), crate::protocol::PING);
            Ok((peer, None))
        }
        crate::net_processing::Received::Pong(nonce) => {
            assert_eq!(message.msg_type(), crate::protocol::PING);
            let pong = crate::net_processing::PeerOutbound::Pong(nonce);
            run_send(socket, &pong).await?;
            Ok((peer, None))
        }
        crate::net_processing::Received::Synced(tip) => {
            assert_eq!(message.msg_type(), crate::protocol::HEADERS);
            Ok((peer, Some(tip)))
        }
    }
}

async fn run_send(
    socket: &mut Socket,
    outbound: &crate::net_processing::PeerOutbound,
) -> Result<(), RunError> {
    let send = socket.send_peer_outbound(outbound);
    match tokio::time::timeout(SEND_TIMEOUT, send).await {
        Ok(result) => result.map_err(RunError::Io),
        Err(_elapsed) => Err(RunError::SendTimeout),
    }
}

impl Socket {
    fn new(stream: tokio::net::TcpStream, network: crate::chainparams::Network) -> Socket {
        Socket {
            stream,
            network,
            frame: PartialFrame::new(),
        }
    }

    async fn send_handshake_outbound(
        &mut self,
        outbound: &crate::net_processing::HandshakeOutbound,
    ) -> Result<(), std::io::Error> {
        match outbound {
            crate::net_processing::HandshakeOutbound::Version(payload) => {
                self.send(crate::protocol::VERSION, payload).await
            }
            crate::net_processing::HandshakeOutbound::Verack => {
                self.send(crate::protocol::VERACK, &[]).await
            }
        }
    }

    async fn send_peer_outbound(
        &mut self,
        outbound: &crate::net_processing::PeerOutbound,
    ) -> Result<(), std::io::Error> {
        let (msg_type, payload) = match outbound {
            crate::net_processing::PeerOutbound::Ping(nonce) => {
                (crate::protocol::PING, nonce_payload(*nonce))
            }
            crate::net_processing::PeerOutbound::Pong(nonce) => {
                (crate::protocol::PONG, nonce_payload(*nonce))
            }
            crate::net_processing::PeerOutbound::SendHeaders => {
                (crate::protocol::SENDHEADERS, Vec::new())
            }
            crate::net_processing::PeerOutbound::GetHeaders(get_headers) => {
                let mut payload = Vec::new();
                get_headers.encode(&mut payload);
                (crate::protocol::GETHEADERS, payload)
            }
        };
        self.send(msg_type, &payload).await
    }

    async fn send(
        &mut self,
        msg_type: crate::protocol::MessageType,
        payload: &[u8],
    ) -> Result<(), std::io::Error> {
        let frame = crate::transport::encode(self.network, msg_type, payload);
        self.stream.write_all(&frame).await
    }

    async fn receive(&mut self) -> Result<crate::transport::Message, ReceiveError> {
        loop {
            if let Some(message) = self
                .frame
                .cut(self.network)
                .map_err(ReceiveError::Transport)?
            {
                assert!(matches!(self.frame, PartialFrame::Header { filled: 0, .. }));
                return Ok(message);
            }
            self.read().await?;
        }
    }

    async fn read(&mut self) -> Result<(), ReceiveError> {
        let (missing, filled) = self.frame.missing();
        assert!(!missing.is_empty());
        let count = self.stream.read(missing).await.map_err(ReceiveError::Io)?;
        if count == 0 {
            return Err(ReceiveError::Closed);
        }
        *filled += count;
        Ok(())
    }
}

impl PartialFrame {
    fn new() -> PartialFrame {
        PartialFrame::Header {
            bytes: [0; crate::transport::MESSAGE_HEADER_SIZE],
            filled: 0,
        }
    }

    fn missing(&mut self) -> (&mut [u8], &mut usize) {
        match self {
            PartialFrame::Header { bytes, filled } => (&mut bytes[*filled..], filled),
            PartialFrame::Payload {
                payload, filled, ..
            } => (&mut payload[*filled..], filled),
        }
    }

    fn cut(
        &mut self,
        network: crate::chainparams::Network,
    ) -> Result<Option<crate::transport::Message>, crate::transport::Error> {
        if let PartialFrame::Header {
            bytes,
            filled: crate::transport::MESSAGE_HEADER_SIZE,
        } = self
        {
            let header = crate::transport::decode_header(network, bytes)?;
            let payload = vec![0; header.payload_length()];
            *self = PartialFrame::Payload {
                header,
                payload,
                filled: 0,
            };
        }
        if let PartialFrame::Payload {
            header,
            payload,
            filled,
        } = self
            && *filled == payload.len()
        {
            let header = *header;
            let payload = std::mem::take(payload);
            *self = PartialFrame::new();
            return crate::transport::check_payload(header, payload).map(Some);
        }
        Ok(None)
    }
}

fn nonce_payload(nonce: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size_of::<u64>());
    nonce.encode(&mut payload);
    assert_eq!(payload.len(), size_of::<u64>());
    payload
}

fn clock() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_before_epoch) => 0,
    }
}

fn timestamp() -> i64 {
    i64::try_from(clock()).unwrap_or(i64::MAX)
}

fn nonce() -> u64 {
    std::hash::RandomState::new().build_hasher().finish()
}

const RANDOM_SOURCE: &str = "/dev/urandom";

fn salt() -> std::io::Result<crate::headerssync::Salt> {
    let mut source = std::fs::File::open(RANDOM_SOURCE)?;
    let mut key_0 = [0; size_of::<u64>()];
    let mut key_1 = [0; size_of::<u64>()];
    let mut offset = [0; size_of::<usize>()];
    source.read_exact(&mut key_0)?;
    source.read_exact(&mut key_1)?;
    source.read_exact(&mut offset)?;
    Ok(crate::headerssync::Salt {
        keys: [u64::from_le_bytes(key_0), u64::from_le_bytes(key_1)],
        offset: usize::from_le_bytes(offset),
    })
}

#[cfg(fuzzing)]
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    const NETWORK: crate::chainparams::Network = crate::chainparams::Network::Regtest;

    const WRITTEN_PAYLOAD_LENGTH_MAX: usize = 4096;

    #[derive(Debug, PartialEq, Eq)]
    struct FrameRead {
        messages: Vec<crate::transport::Message>,
        end: FrameEnd,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum FrameEnd {
        BytesEnded,
        Refused {
            error: crate::transport::Error,
            unread_count: usize,
        },
    }

    pub fn frame(data: &[u8]) {
        let Some((sizes_count, rest)) = data.split_first() else {
            return;
        };
        let (sizes, stream) = rest.split_at(rest.len().min(usize::from(*sizes_count)));

        let whole = frame_read(stream, std::iter::empty());
        assert_eq!(
            frame_read(stream, std::iter::repeat(std::num::NonZeroUsize::MIN)),
            whole
        );
        let read_sizes = sizes
            .iter()
            .map(|size_byte| std::num::NonZeroUsize::MIN.saturating_add(usize::from(*size_byte)));
        assert_eq!(frame_read(stream, read_sizes.clone()), whole);

        let encoded: Vec<u8> = whole
            .messages
            .iter()
            .flat_map(|message| {
                crate::transport::encode(NETWORK, message.msg_type(), message.payload())
            })
            .collect();
        assert!(stream.starts_with(&encoded));

        let payload = &stream[..stream.len().min(WRITTEN_PAYLOAD_LENGTH_MAX)];
        let written = crate::transport::encode(NETWORK, crate::protocol::VERACK, payload);
        let read = frame_read(&written, read_sizes);
        assert_eq!(read.end, FrameEnd::BytesEnded);
        let [message] = read.messages.as_slice() else {
            panic!("one frame gives {} messages", read.messages.len());
        };
        assert_eq!(message.msg_type(), crate::protocol::VERACK);
        assert_eq!(message.payload(), payload);
    }

    fn frame_read(
        stream: &[u8],
        mut read_sizes: impl Iterator<Item = std::num::NonZeroUsize>,
    ) -> FrameRead {
        let mut frame = super::PartialFrame::new();
        let mut messages = Vec::new();
        let mut unread = stream;
        let end = loop {
            match frame.cut(NETWORK) {
                Ok(Some(message)) => {
                    assert!(matches!(
                        frame,
                        super::PartialFrame::Header { filled: 0, .. }
                    ));
                    messages.push(message);
                }
                Ok(None) if unread.is_empty() => break FrameEnd::BytesEnded,
                Ok(None) => {
                    let (missing, filled) = frame.missing();
                    assert!(!missing.is_empty());
                    let size = read_sizes.next().unwrap_or(std::num::NonZeroUsize::MAX);
                    let count = size.get().min(missing.len()).min(unread.len());
                    let (read, rest) = unread.split_at(count);
                    missing[..count].copy_from_slice(read);
                    *filled += count;
                    unread = rest;
                }
                Err(error) => {
                    break FrameEnd::Refused {
                        error,
                        unread_count: unread.len(),
                    };
                }
            }
        };
        FrameRead { messages, end }
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::Decode;
    use std::io::{Read, Write};

    fn block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn destination(peer: std::net::SocketAddr) -> super::Destination {
        super::Destination::Address(super::PeerAddress::new(peer).unwrap())
    }

    fn peer_addresses(addresses: &[std::net::SocketAddr]) -> Vec<super::PeerAddress> {
        let peer_address = |address| super::PeerAddress::new(address).unwrap();
        addresses.iter().copied().map(peer_address).collect()
    }

    fn dial(addresses: &[std::net::SocketAddr]) -> super::Addresses {
        let mut before = peer_addresses(addresses);
        let last = before.pop().unwrap();
        super::Addresses { before, last }
    }

    fn dialed(addresses: super::Addresses) -> Vec<super::PeerAddress> {
        let super::Addresses { mut before, last } = addresses;
        before.push(last);
        before
    }

    fn read_frame(stream: &mut std::net::TcpStream) -> Vec<u8> {
        read_frame_on(stream, crate::chainparams::Network::Regtest)
    }

    fn read_frame_on(
        stream: &mut std::net::TcpStream,
        network: crate::chainparams::Network,
    ) -> Vec<u8> {
        let mut frame = vec![0; crate::transport::MESSAGE_HEADER_SIZE];
        stream.read_exact(&mut frame).unwrap();
        let header = frame.first_chunk().unwrap();
        let header = crate::transport::decode_header(network, header).unwrap();
        let mut payload = vec![0; header.payload_length()];
        stream.read_exact(&mut payload).unwrap();
        frame.extend(payload);
        frame
    }

    fn read_message(stream: &mut std::net::TcpStream) -> crate::transport::Message {
        let frame = read_frame(stream);
        let (header, payload) = frame.split_first_chunk().unwrap();
        let header =
            crate::transport::decode_header(crate::chainparams::Network::Regtest, header).unwrap();
        crate::transport::check_payload(header, payload.to_vec()).unwrap()
    }

    fn accept_handshake(listener: &std::net::TcpListener) -> std::net::TcpStream {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        read_frame(&mut stream);
        stream
            .write_all(&crate::fixtures::hex(crate::fixtures::VERSION_FRAME))
            .unwrap();
        read_frame(&mut stream);
        stream
            .write_all(&crate::fixtures::hex(crate::fixtures::VERACK_FRAME))
            .unwrap();
        stream
    }

    fn assert_ping(message: &crate::transport::Message) {
        assert_eq!(message.msg_type(), crate::protocol::PING);
        assert_eq!(message.payload().len(), size_of::<u64>());
    }

    fn read_first_get_headers(stream: &mut std::net::TcpStream) {
        assert_eq!(
            read_frame(stream),
            crate::fixtures::hex(crate::fixtures::GETHEADERS_FRAME)
        );
    }

    fn read_send_headers(stream: &mut std::net::TcpStream) {
        let send_headers = read_message(stream);
        assert_eq!(send_headers.msg_type(), crate::protocol::SENDHEADERS);
        assert!(send_headers.payload().is_empty());
    }

    fn empty_headers_frame() -> Vec<u8> {
        crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::HEADERS,
            &[0],
        )
    }

    #[test]
    fn their_version_gets_our_verack() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            read_frame(&mut stream);
            stream
                .write_all(&crate::fixtures::hex(crate::fixtures::VERSION_FRAME))
                .unwrap();
            let verack = read_frame(&mut stream);
            stream
                .write_all(&crate::fixtures::hex(crate::fixtures::VERACK_FRAME))
                .unwrap();
            verack
        });

        let result = block_on(super::handshake(&destination(peer), &mut chain));
        let verack = peer_thread.join().unwrap();
        assert_eq!(verack, crate::fixtures::hex(crate::fixtures::VERACK_FRAME));
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn our_version_has_the_local_clock_in_seconds() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            read_message(&mut stream)
        });

        let seconds = || {
            let elapsed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            i64::try_from(elapsed.as_secs()).unwrap()
        };
        let before = seconds();
        let _closed = block_on(super::handshake(&destination(peer), &mut chain));
        let after = seconds();
        let message = peer_thread.join().unwrap();
        assert_eq!(message.msg_type(), crate::protocol::VERSION);
        let ours = crate::protocol::Version::decode(&mut message.payload()).unwrap();
        assert!(
            (before..=after).contains(&ours.timestamp),
            "{before} {} {after}",
            ours.timestamp
        );
    }

    #[test]
    fn silent_peer_is_handshake_timeout() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (result, elapsed) = block_on(async {
            let stream = tokio::net::TcpStream::connect(peer).await.unwrap();
            tokio::time::pause();
            let start = tokio::time::Instant::now();
            let result = super::handshake_stream(peer, stream, &mut chain).await;
            (result, start.elapsed())
        });
        assert!(
            matches!(result, Err(super::HandshakeError::HandshakeTimeout)),
            "{result:?}"
        );
        assert_eq!(elapsed.as_secs(), super::HANDSHAKE_TIMEOUT.as_secs());
    }

    #[test]
    fn silent_peer_after_our_getheaders_is_headers_timeout() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let mut stream = accept_handshake(&listener);
            assert_ping(&read_message(&mut stream));
            read_first_get_headers(&mut stream);
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            rest
        });

        let (result, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            tokio::time::pause();
            let start = tokio::time::Instant::now();
            let result = connection.sync().await;
            (result, start.elapsed())
        });
        let rest = peer_thread.join().unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        assert!(
            matches!(
                result,
                Err(super::RunError::NetProcessing(
                    crate::net_processing::PeerError::HeadersTimeout
                ))
            ),
            "{result:?}"
        );
        assert_eq!(
            elapsed.as_secs(),
            std::time::Duration::from_mins(2).as_secs()
        );
    }

    #[test]
    fn header_far_after_the_local_clock_ends_the_connection() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let mut stream = accept_handshake(&listener);
            assert_ping(&read_message(&mut stream));
            read_first_get_headers(&mut stream);
            let genesis = crate::chainparams::Network::Regtest.genesis();
            let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
                version: crate::fixtures::HEADER_VERSION,
                prev: genesis.hash(),
                time: u32::MAX,
                ..genesis
            });
            let frame = crate::transport::encode(
                crate::chainparams::Network::Regtest,
                crate::protocol::HEADERS,
                &crate::fixtures::headers_payload_with(&[header]),
            );
            stream.write_all(&frame).unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
        });

        let result = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            connection.sync().await
        });
        peer_thread.join().unwrap();
        assert!(
            matches!(
                result,
                Err(super::RunError::NetProcessing(
                    crate::net_processing::PeerError::Extend(crate::chain::ExtendError::TimeTooNew)
                ))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn sync_that_ends_below_the_minimum_of_the_network_ends_the_connection() {
        let network = crate::chainparams::Network::Signet;
        let mut chain = crate::chain::Chain::new(network);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let frame =
                |msg_type, payload: &[u8]| crate::transport::encode(network, msg_type, payload);
            let replies = [
                Some(frame(
                    crate::protocol::VERSION,
                    &crate::fixtures::version_payload(),
                )),
                Some(frame(crate::protocol::VERACK, &[])),
                None,
                Some(frame(crate::protocol::HEADERS, &[0])),
            ];
            let mut msg_types = Vec::new();
            for reply in replies {
                let ours = read_frame_on(&mut stream, network);
                let msg_type: [u8; crate::protocol::MESSAGE_TYPE_SIZE] =
                    ours[4..16].try_into().unwrap();
                msg_types.push(msg_type);
                if let Some(reply) = reply {
                    stream.write_all(&reply).unwrap();
                }
            }
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            msg_types
        });

        let result = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            connection.sync().await
        });
        let expected = [
            crate::protocol::VERSION,
            crate::protocol::VERACK,
            crate::protocol::PING,
            crate::protocol::GETHEADERS,
        ]
        .map(|msg_type| *msg_type.as_bytes());
        assert_eq!(peer_thread.join().unwrap(), expected);
        assert!(
            matches!(
                result,
                Err(super::RunError::NetProcessing(
                    crate::net_processing::PeerError::ChainWorkTooLow
                ))
            ),
            "{result:?}"
        );
    }

    #[test]
    fn silent_peer_after_the_sync_is_ping_timeout() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let mut stream = accept_handshake(&listener);
            let ping = read_message(&mut stream);
            read_first_get_headers(&mut stream);
            stream.write_all(&empty_headers_frame()).unwrap();
            read_send_headers(&mut stream);
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            (ping, rest)
        });

        let (error, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            let start = tokio::time::Instant::now();
            let (synced, _tip) = connection.sync().await.unwrap();
            tokio::time::pause();
            let error = synced.next_tip().await.unwrap_err();
            (error, start.elapsed())
        });
        let (ping, rest) = peer_thread.join().unwrap();
        assert_ping(&ping);
        assert!(rest.is_empty(), "{rest:?}");
        assert!(
            matches!(
                error,
                super::RunError::NetProcessing(crate::net_processing::PeerError::PingTimeout)
            ),
            "{error:?}"
        );
        assert_eq!(
            elapsed.as_secs(),
            std::time::Duration::from_mins(20).as_secs()
        );
    }

    #[test]
    fn empty_announcement_after_the_sync_does_not_give_the_tip_again() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let headers = crate::fixtures::headers_on_genesis(1);
        let announcement = crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::HEADERS,
            &crate::fixtures::headers_payload_with(&headers),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let mut stream = accept_handshake(&listener);
            assert_ping(&read_message(&mut stream));
            read_first_get_headers(&mut stream);
            stream.write_all(&empty_headers_frame()).unwrap();
            read_send_headers(&mut stream);
            let mut frames = empty_headers_frame();
            frames.extend(announcement);
            stream.write_all(&frames).unwrap();
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            rest
        });

        let (synced_tip, next_tip) = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            let (synced, synced_tip) = connection.sync().await.unwrap();
            let (_synced, next_tip) = synced.next_tip().await.unwrap();
            (synced_tip, next_tip)
        });
        let rest = peer_thread.join().unwrap();
        assert!(rest.is_empty(), "{rest:?}");
        assert_eq!(synced_tip.height(), 0);
        assert_eq!(next_tip.height(), 1);
        assert_eq!(next_tip.hash(), headers[0].hash());
    }

    #[test]
    fn pong_moves_the_next_ping_to_ping_interval_after_the_last() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let mut stream = accept_handshake(&listener);
            let first = read_message(&mut stream);
            read_first_get_headers(&mut stream);
            let mut frames = crate::transport::encode(
                crate::chainparams::Network::Regtest,
                crate::protocol::PONG,
                first.payload(),
            );
            frames.extend(empty_headers_frame());
            stream.write_all(&frames).unwrap();
            read_send_headers(&mut stream);
            let second = read_message(&mut stream);
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            (first, second, rest)
        });

        let (error, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            let start = tokio::time::Instant::now();
            let (synced, _tip) = connection.sync().await.unwrap();
            tokio::time::pause();
            let error = synced.next_tip().await.unwrap_err();
            (error, start.elapsed())
        });
        let (first, second, rest) = peer_thread.join().unwrap();
        assert_ping(&first);
        assert_ping(&second);
        assert_ne!(second.payload(), first.payload());
        assert!(rest.is_empty(), "{rest:?}");
        assert!(
            matches!(
                error,
                super::RunError::NetProcessing(crate::net_processing::PeerError::PingTimeout)
            ),
            "{error:?}"
        );
        assert_eq!(
            elapsed.as_secs(),
            std::time::Duration::from_mins(2 + 20).as_secs()
        );
    }

    #[test]
    fn peer_that_stops_reading_is_send_timeout() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || accept_handshake(&listener));

        let (result, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            let _stream = peer_thread.join().unwrap();
            let stream = &connection.socket.stream;
            stream.writable().await.unwrap();
            let filler = [0; 1 << 16];
            let full = loop {
                if let Err(error) = stream.try_write(&filler) {
                    break error;
                }
            };
            assert_eq!(full.kind(), std::io::ErrorKind::WouldBlock);
            tokio::time::pause();
            let start = tokio::time::Instant::now();
            let sync = connection.sync();
            let result = tokio::time::timeout(std::time::Duration::from_mins(30), sync).await;
            (result, start.elapsed())
        });
        assert!(
            matches!(result, Ok(Err(super::RunError::SendTimeout))),
            "{result:?}"
        );
        assert_eq!(elapsed.as_secs(), super::SEND_TIMEOUT.as_secs());
    }

    #[test]
    fn peer_that_closes_inside_a_frame_is_closed() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_frame(&mut stream);
            let frame = crate::fixtures::hex(crate::fixtures::VERSION_FRAME);
            stream.write_all(&frame[..frame.len() - 1]).unwrap();
        });

        let result = block_on(super::handshake(&destination(peer), &mut chain));
        peer_thread.join().unwrap();
        assert!(
            matches!(result, Err(super::HandshakeError::Closed)),
            "{result:?}"
        );
    }

    #[test]
    fn frame_split_by_a_timeout_is_received_whole() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (first_sent, first_sent_receiver) = std::sync::mpsc::channel();
        let (timed_out, timed_out_receiver) = std::sync::mpsc::channel();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut first = crate::fixtures::hex(crate::fixtures::VERSION_FRAME);
            let rest = first.split_off(first.len() / 2);
            stream.write_all(&first).unwrap();
            first_sent.send(()).unwrap();
            timed_out_receiver.recv().unwrap();
            stream.write_all(&rest).unwrap();
        });

        let (timeout, message) = block_on(async {
            let stream = tokio::net::TcpStream::connect(peer).await.unwrap();
            let mut socket = super::Socket::new(stream, crate::chainparams::Network::Regtest);
            first_sent_receiver.recv().unwrap();
            tokio::time::pause();
            let receive = socket.receive();
            let timeout = tokio::time::timeout(std::time::Duration::from_secs(1), receive).await;
            timed_out.send(()).unwrap();
            let message = socket.receive().await;
            (timeout, message)
        });
        peer_thread.join().unwrap();
        assert!(timeout.is_err(), "{timeout:?}");
        let message = message.unwrap();
        assert_eq!(message.msg_type(), crate::protocol::VERSION);
        assert_eq!(message.payload(), crate::fixtures::version_payload());
    }

    #[test]
    fn ping_in_one_write_with_their_verack_gets_a_pong() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            read_frame(&mut stream);
            stream
                .write_all(&crate::fixtures::hex(crate::fixtures::VERSION_FRAME))
                .unwrap();
            read_frame(&mut stream);
            let mut frames = crate::fixtures::hex(crate::fixtures::VERACK_FRAME);
            frames.extend(crate::fixtures::hex(crate::fixtures::PING_FRAME));
            stream.write_all(&frames).unwrap();
            assert_ping(&read_message(&mut stream));
            read_first_get_headers(&mut stream);
            read_frame(&mut stream)
        });

        let result = block_on(async {
            let (connection, _theirs) = super::handshake(&destination(peer), &mut chain)
                .await
                .unwrap();
            connection.sync().await
        });
        let pong = peer_thread.join().unwrap();
        let mut expected = crate::fixtures::hex(crate::fixtures::PING_FRAME);
        let msg_type =
            crate::chainparams::MAGIC_SIZE..crate::chainparams::MAGIC_SIZE + "ping".len();
        assert_eq!(&expected[msg_type.clone()], b"ping");
        expected[msg_type].copy_from_slice(b"pong");
        assert_eq!(pong, expected);
        assert!(matches!(result, Err(super::RunError::Closed)), "{result:?}");
    }

    #[test]
    fn refused_connect_is_connect_error() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let peer = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let result = block_on(super::handshake(&destination(peer), &mut chain));
        let Err(error) = result else {
            panic!("{result:?}");
        };
        let super::HandshakeError::Connect {
            address,
            addresses_count,
            error: super::ConnectError::Io(io),
        } = &error
        else {
            panic!("{error:?}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::ConnectionRefused);
        assert_eq!(*address, peer);
        assert_eq!(*addresses_count, 1);
        let text = error.to_string();
        assert!(text.starts_with(&format!("connect to {peer}: ")), "{text}");
    }

    #[test]
    fn connect_takes_the_first_address_that_takes_it() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listening = listener.local_addr().unwrap();
        let refused = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        for addresses in [[refused, listening], [listening, refused]] {
            let (address, _stream) = block_on(super::connect_first(&dial(&addresses))).unwrap();
            assert_eq!(address, listening, "{addresses:?}");
        }
    }

    #[test]
    fn connect_to_no_address_gives_the_last_one_and_the_count() {
        let first = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let last = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addresses = [first.local_addr().unwrap(), last.local_addr().unwrap()];
        drop((first, last));

        let result = block_on(super::connect_first(&dial(&addresses)));
        let Err(error) = result else {
            panic!("{result:?}");
        };
        let super::HandshakeError::Connect {
            address,
            addresses_count,
            error: super::ConnectError::Io(_),
        } = &error
        else {
            panic!("{error:?}");
        };
        assert_eq!(*address, addresses[1]);
        assert_eq!(*addresses_count, 2);
        let text = error.to_string();
        let expected = format!("connect to {}, the last of 2 addresses: ", addresses[1]);
        assert!(text.starts_with(&expected), "{text}");
    }

    #[test]
    fn name_order_drops_the_answers_that_name_no_peer_and_keeps_at_most_the_count_max() {
        let unspecified = [
            std::net::SocketAddr::from(([0, 0, 0, 0], 1)),
            std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 1)),
            std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED.to_ipv6_mapped(), 1)),
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        ];
        let result = super::name_order(unspecified);
        assert!(
            matches!(result, Err(super::LookupError::Empty)),
            "{result:?}"
        );

        let answers: Vec<std::net::SocketAddr> = (1..=super::ADDRESSES_COUNT_MAX + 1)
            .map(|port| std::net::SocketAddr::from(([127, 0, 0, 1], u16::try_from(port).unwrap())))
            .collect();
        let kept = super::name_order(unspecified.into_iter().chain(answers.iter().copied()));
        let mut kept = dialed(kept.unwrap());
        kept.sort_unstable_by_key(|address| address.0);
        assert_eq!(kept, peer_addresses(&answers[..super::ADDRESSES_COUNT_MAX]));
    }

    #[test]
    fn name_order_keeps_each_address_one_time() {
        let first = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let second = std::net::SocketAddr::from(([127, 0, 0, 1], 2));
        let addresses = super::name_order([first, second, first, first]).unwrap();
        let mut kept = dialed(addresses);
        kept.sort_unstable_by_key(|address| address.0);
        assert_eq!(kept, peer_addresses(&[first, second]));
    }

    #[test]
    fn lookup_gives_the_addresses_of_a_name_with_the_port() {
        let name = super::Name::new("localhost").unwrap();
        let answers = block_on(super::lookup(&name.0, std::num::NonZeroU16::MIN)).unwrap();
        let addresses = super::name_order(answers).unwrap();
        for super::PeerAddress(address) in dialed(addresses) {
            assert!(address.ip().is_loopback(), "{address}");
            assert_eq!(address.port(), 1, "{address}");
        }
    }

    #[test]
    fn seed_order_keeps_at_most_the_seed_count_max_of_the_routable_answers() {
        let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
        let result = super::seed_order([loopback]);
        assert!(
            matches!(result, Err(super::LookupError::Empty)),
            "{result:?}"
        );

        let answers: Vec<std::net::SocketAddr> = (1..=super::SEED_ADDRESSES_COUNT_MAX + 1)
            .map(|port| std::net::SocketAddr::from(([1, 1, 1, 1], u16::try_from(port).unwrap())))
            .collect();
        let kept = super::seed_order([loopback].into_iter().chain(answers.iter().copied()));
        let mut kept = dialed(kept.unwrap());
        kept.sort_unstable_by_key(|address| address.0);
        assert_eq!(
            kept,
            peer_addresses(&answers[..super::SEED_ADDRESSES_COUNT_MAX])
        );
    }

    #[test]
    fn routable_is_each_address_but_this_host_private_networks_links_and_test_ranges() {
        let v4 = |a, b, c, d| std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
        let v6 = |text: &str| std::net::IpAddr::V6(text.parse().unwrap());
        for (ip, routable) in [
            (v4(0, 0, 0, 1), false),
            (v4(0, 255, 255, 255), false),
            (v4(1, 0, 0, 0), true),
            (v4(9, 255, 255, 255), true),
            (v4(10, 0, 0, 0), false),
            (v4(10, 255, 255, 255), false),
            (v4(11, 0, 0, 0), true),
            (v4(100, 63, 255, 255), true),
            (v4(100, 64, 0, 0), false),
            (v4(100, 127, 255, 255), false),
            (v4(100, 128, 0, 0), true),
            (v4(126, 255, 255, 255), true),
            (v4(127, 0, 0, 0), false),
            (v4(127, 255, 255, 255), false),
            (v4(128, 0, 0, 0), true),
            (v4(169, 253, 255, 255), true),
            (v4(169, 254, 0, 0), false),
            (v4(169, 254, 255, 255), false),
            (v4(169, 255, 0, 0), true),
            (v4(172, 15, 255, 255), true),
            (v4(172, 16, 0, 0), false),
            (v4(172, 31, 255, 255), false),
            (v4(172, 32, 0, 0), true),
            (v4(192, 0, 1, 255), true),
            (v4(192, 0, 2, 0), false),
            (v4(192, 0, 2, 255), false),
            (v4(192, 0, 3, 0), true),
            (v4(192, 167, 255, 255), true),
            (v4(192, 168, 0, 0), false),
            (v4(192, 168, 255, 255), false),
            (v4(192, 169, 0, 0), true),
            (v4(198, 17, 255, 255), true),
            (v4(198, 18, 0, 0), false),
            (v4(198, 19, 255, 255), false),
            (v4(198, 20, 0, 0), true),
            (v4(198, 51, 99, 255), true),
            (v4(198, 51, 100, 0), false),
            (v4(198, 51, 100, 255), false),
            (v4(198, 51, 101, 0), true),
            (v4(203, 0, 112, 255), true),
            (v4(203, 0, 113, 0), false),
            (v4(203, 0, 113, 255), false),
            (v4(203, 0, 114, 0), true),
            (v4(255, 255, 255, 254), true),
            (v4(255, 255, 255, 255), false),
            (v6("::"), false),
            (v6("::1"), false),
            (v6("::2"), true),
            (v6("::ffff:127.0.0.1"), false),
            (v6("::ffff:10.0.0.1"), false),
            (v6("::ffff:1.1.1.1"), true),
            (v6("2001:f::"), true),
            (v6("2001:10::"), false),
            (v6("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff"), false),
            (v6("2001:30::"), true),
            (v6("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff"), true),
            (v6("2001:db8::"), false),
            (v6("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"), false),
            (v6("2001:db9::"), true),
            (v6("2a01::1"), true),
            (v6("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true),
            (v6("fc00::"), false),
            (v6("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), false),
            (v6("fe00::"), true),
            (v6("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true),
            (v6("fe80::"), false),
            (v6("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), false),
            (v6("fec0::"), true),
        ] {
            assert_eq!(super::is_reserved(ip), !routable, "{ip}");
        }
    }

    #[test]
    fn each_network_but_regtest_has_seeds_that_are_names_at_its_default_port() {
        assert_eq!(
            super::Seeds::new(crate::chainparams::Network::Regtest),
            None
        );
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
        ] {
            let seeds = super::Seeds::new(network).unwrap();
            assert_eq!(seeds.port, network.default_port(), "{network:?}");
            for seed in std::iter::once(seeds.first).chain(seeds.rest.iter().copied()) {
                let seed = super::Seed(seed);
                assert_eq!(seed.services_name(), format!("x9.{seed}"));
                for name in [seed.services_name(), seed.to_string()] {
                    assert!(super::Name::new(&name).is_some(), "{name}");
                }
            }
        }
    }

    #[test]
    fn a_seeds_source_chooses_each_seed_of_the_network() {
        let network = crate::chainparams::Network::Mainnet;
        let source = super::Source::Seeds(super::Seeds::new(network).unwrap());
        let mut chosen = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            let super::Destination::Seed { seed, port } = source.destination().into_owned() else {
                panic!();
            };
            assert_eq!(port, network.default_port());
            chosen.insert(seed.0);
        }
        let seeds: std::collections::BTreeSet<&str> = network.seeds().iter().copied().collect();
        assert_eq!(chosen, seeds);
    }

    #[test]
    fn longest_destination_has_the_length_max() {
        let label = "a".repeat(super::LABEL_LENGTH_MAX);
        let labels = [label.as_str(); 4].join(".");
        let longest = format!("{}.", &labels[..super::NAME_LENGTH_MAX]);
        let destination = super::Destination::Name {
            name: super::Name::new(&longest).unwrap(),
            port: std::num::NonZeroU16::MAX,
        };
        assert_eq!(destination.to_string().len(), super::DESTINATION_LENGTH_MAX);
    }

    #[test]
    fn each_salt_word_is_new() {
        let mut words = Vec::new();
        for salt in [super::salt().unwrap(), super::salt().unwrap()] {
            words.extend(salt.keys);
            words.push(u64::try_from(salt.offset).unwrap());
        }
        let mut distinct = words.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), words.len(), "{words:x?}");
    }
}
