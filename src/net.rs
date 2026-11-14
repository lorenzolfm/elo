//! The driver: it dials one peer and runs the handshake on the socket. Then it syncs our header
//! chain from the peer, pings the peer, and answers the messages after the handshake. The chain
//! is not part of the connection, so it outlives each connection.

use crate::serialize::Encode;
use std::hash::{BuildHasher, Hasher};
use std::io::Read;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long the TCP connect may take.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long the handshake may take, from the connect to their `verack`.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long each write after the handshake may take, because a write to a peer that does not
/// read can block forever. The ping timeout covers each read.
const SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(20);

/// Why the connect or the handshake failed.
#[derive(Debug)]
pub enum HandshakeError {
    /// The TCP connect failed.
    Connect(std::io::Error),
    /// The TCP connect took longer than `CONNECT_TIMEOUT`.
    ConnectTimeout,
    /// The handshake took longer than `HANDSHAKE_TIMEOUT`.
    HandshakeTimeout,
    /// A read or a write on the socket failed.
    Io(std::io::Error),
    /// The peer closed the connection.
    Closed,
    /// The peer sent a frame that elo refuses.
    Transport(crate::transport::Error),
    /// elo refused the peer: a bad `version`, our own `version`, or too many messages.
    NetProcessing(crate::net_processing::HandshakeError),
    /// The read of `RANDOM_SOURCE` for the salt of the peer failed.
    Salt(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Connect(error) => write!(f, "connect: {error}"),
            HandshakeError::ConnectTimeout => {
                write!(
                    f,
                    "connect took longer than {} s",
                    CONNECT_TIMEOUT.as_secs()
                )
            }
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

/// Why the connection ended after the handshake.
#[derive(Debug)]
pub enum RunError {
    /// A write after the handshake took longer than `SEND_TIMEOUT`.
    SendTimeout,
    /// A read or a write on the socket failed.
    Io(std::io::Error),
    /// The peer closed the connection.
    Closed,
    /// The peer sent a frame that elo refuses.
    Transport(crate::transport::Error),
    /// elo refused the peer: a bad `ping`, `pong` or `headers`, or no `pong` or `headers` in
    /// time.
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

/// Why `Socket::receive` returned no message. Each one ends the connection, in the handshake
/// or after it.
#[derive(Debug)]
enum ReceiveError {
    /// A read on the socket failed.
    Io(std::io::Error),
    /// The peer closed the connection, inside a frame or between two frames.
    Closed,
    /// The peer sent a frame that elo refuses.
    Transport(crate::transport::Error),
}

/// One peer after the handshake: the socket and the machine for its messages, which borrows our
/// chain. Only `handshake` makes one, so `sync` cannot start before the handshake is complete.
#[derive(Debug)]
pub struct Connection<'a> {
    socket: Socket,
    peer: crate::net_processing::Peer<'a>,
    /// The address of the peer that took the connect.
    address: std::net::SocketAddr,
}

/// One peer after the header sync. Only `Connection::sync` makes one, so `next_tip` cannot start
/// before the sync ends.
#[derive(Debug)]
pub struct Synced<'a> {
    socket: Socket,
    peer: crate::net_processing::Peer<'a>,
    /// The tip that the last call returned, or the sync if no call did.
    tip: crate::chain::Tip,
}

/// The stream to one peer, its network, and the bytes of the frame that is not complete yet.
/// Only `receive` reads the stream, so each byte that comes goes into a frame.
#[derive(Debug)]
struct Socket {
    stream: tokio::net::TcpStream,
    network: crate::chainparams::Network,
    frame: PartialFrame,
}

/// The bytes of one frame, kept across waits. Each part has room for its exact size, and each
/// read goes into the bytes that the part still needs. So a read cannot take a byte of the
/// next frame.
#[derive(Debug)]
enum PartialFrame {
    /// The header has not passed its checks. The bytes so far are `bytes[..filled]`.
    Header {
        bytes: [u8; crate::transport::MESSAGE_HEADER_SIZE],
        filled: usize,
    },
    /// The header passed its checks. The payload so far is `payload[..filled]`.
    Payload {
        header: crate::transport::MessageHeader,
        payload: Vec<u8>,
        filled: usize,
    },
}

/// Dials the first of `peers` that takes the TCP connect, in their order, on the network of
/// `chain`, and runs the handshake. Returns the connection for the messages after it, and their
/// `version`. The sync of the connection extends `chain` from its
/// tip, so the next connection with the same chain does not get those headers again. A chain
/// below the minimum work starts again from genesis. A peer whose chain does not have our tip
/// answers from the highest header of our locator on its chain, and a branch with more work takes
/// the place of ours.
pub async fn handshake<'a>(
    peers: &[std::net::SocketAddr],
    chain: &'a mut crate::chain::Chain,
) -> Result<(Connection<'a>, crate::protocol::Version), HandshakeError> {
    let (peer, stream) = connect_first(peers).await?;
    handshake_stream(peer, stream, chain).await
}

/// The TCP connect to the first of `peers` that takes it. Each try takes at most
/// `CONNECT_TIMEOUT`, so the length of `peers` bounds the time. When each try fails, the error is
/// the one of the last peer.
async fn connect_first(
    peers: &[std::net::SocketAddr],
) -> Result<(std::net::SocketAddr, tokio::net::TcpStream), HandshakeError> {
    let Some((&last, before)) = peers.split_last() else {
        panic!("no peer to dial");
    };
    for &peer in before {
        if let Ok(stream) = connect(peer).await {
            return Ok((peer, stream));
        }
    }
    connect(last).await.map(|stream| (last, stream))
}

/// The TCP connect to `peer`, within `CONNECT_TIMEOUT`.
async fn connect(peer: std::net::SocketAddr) -> Result<tokio::net::TcpStream, HandshakeError> {
    match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(peer)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(HandshakeError::Connect(error)),
        Err(_elapsed) => Err(HandshakeError::ConnectTimeout),
    }
}

/// The handshake on a connected `stream`, within `HANDSHAKE_TIMEOUT`.
async fn handshake_stream(
    peer: std::net::SocketAddr,
    stream: tokio::net::TcpStream,
    chain: &mut crate::chain::Chain,
) -> Result<(Connection<'_>, crate::protocol::Version), HandshakeError> {
    let exchange = handshake_stream_exchange(peer, stream, chain);
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(HandshakeError::HandshakeTimeout),
    }
}

/// Sends our `version`, then reads messages until the handshake is done. The handshake
/// bounds the loop: it refuses a peer that sends too many messages without its `verack`.
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
                // The peer can send more frames in the same segment as its `verack`. Each read
                // stops at the end of a frame, so they are still in the stream, and `sync` reads
                // them next.
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
    /// The address of the peer: of the peers that `handshake` got, the one that took the connect.
    pub fn address(&self) -> std::net::SocketAddr {
        self.address
    }

    /// Runs one turn after the other until a batch that is not full ends the sync. Returns the
    /// peer for `Synced::next_tip`, and the tip of our chain. The loop has no count bound, because
    /// only the chain of the peer bounds the sync. A low-work sync gets the chain twice, and the
    /// clock bounds the height of its first download. But above the minimum work the peer can send
    /// headers for as long as it has them. It ends on an error: the peer closes, a read or a write
    /// fails, a write takes longer than `SEND_TIMEOUT`, our `ping` gets no `pong` in time, or elo
    /// refuses a frame or a message. It also ends when elo refuses a `headers`, none comes within
    /// the headers timeout, or the sync ends on a chain below the minimum work. Each wait for a
    /// message ends at the wake from `tick`, but the read takes a message that is already there,
    /// also after the wake. `tick` checks the headers timeout only at the start of a turn. One turn
    /// can write our `ping` and our `getheaders`, and then a `pong`, and each write can take up to
    /// `SEND_TIMEOUT`. So the connection can end up to three times `SEND_TIMEOUT` after the tick
    /// that sent our `getheaders`, with `SendTimeout`, `PingTimeout` or `HeadersTimeout`.
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
    /// Runs one turn after the other until a batch that is not full ends a sync again on a new
    /// tip: an announcement of the peer, or the last batch of the sync that a full announcement
    /// starts. Returns the peer for the next call, and the new tip of our chain. An empty
    /// announcement ends a sync on the same tip, and the loop goes on. So a peer cannot make the
    /// caller print the tip again for each `headers`. The loop has no count bound, because a peer
    /// sends messages for as long as it is connected. It ends on the errors of
    /// `Connection::sync`. Each wait for a message ends at the wake from `tick`, each write ends
    /// within `SEND_TIMEOUT`, and the frame length limit bounds each message. `tick` checks the
    /// ping timeout only at the start of a turn. So a `pong` write that blocks while our `ping` is
    /// outstanding can end the connection up to `SEND_TIMEOUT` after the ping timeout, with
    /// `SendTimeout`.
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
                    // On one connection, our chain takes a batch on its tip, or a branch with more
                    // work, which can be lower. So only the work goes up. It saturates at its
                    // maximum, so it can stay the same.
                    assert!(tip.work() >= previous.work());
                    return Ok((Synced { socket, peer, tip }, tip));
                }
            }
        }
    }
}

/// Ticks `peer` and sends what the tick returns. Then waits for one message until the wake
/// from the tick, and gives the message to `peer`. Returns the peer for the next turn, which
/// ticks again, and the tip if the message ended the sync. So each wait has a wake from a tick
/// after the last message: a `pong` moves the wake to the next `ping`, and after a full batch
/// the next `getheaders` goes at once.
async fn run_turn<'a>(
    socket: &mut Socket,
    peer: crate::net_processing::Peer<'a>,
) -> Result<(crate::net_processing::Peer<'a>, Option<crate::chain::Tip>), RunError> {
    // The wake goes to a tokio timer, so `now` comes from the same clock. Then a paused clock
    // in a test also moves the time of the peer.
    let now = tokio::time::Instant::now().into_std();
    let (peer, tick_outbound, wake) = peer.tick(now, nonce()).map_err(RunError::NetProcessing)?;
    for outbound in tick_outbound.into_outbounds() {
        run_send(socket, &outbound).await?;
    }
    // The wait covers only the read, which is cancel safe, so the turn keeps the peer when the
    // wait ends. A wait that ends at the wake loses no bytes: the next turn continues the frame.
    let receive = socket.receive();
    match tokio::time::timeout_at(tokio::time::Instant::from_std(wake), receive).await {
        Ok(message) => run_exchange(socket, peer, &message?).await,
        Err(_elapsed) => Ok((peer, None)),
    }
}

/// Gives `message` to `peer`, and sends the `pong` if there is one. Returns the peer for the
/// next turn, and the tip if the message ended the sync.
async fn run_exchange<'a>(
    socket: &mut Socket,
    peer: crate::net_processing::Peer<'a>,
    message: &crate::transport::Message,
) -> Result<(crate::net_processing::Peer<'a>, Option<crate::chain::Tip>), RunError> {
    // The clock is read when the message is there, so a long wait for it does not age the clock.
    let (peer, received) = peer
        .receive(message, clock())
        .map_err(RunError::NetProcessing)?;
    match received {
        crate::net_processing::Received::NoReply => {
            // Each `ping` that the peer accepts gets a `pong`.
            assert_ne!(message.msg_type(), crate::protocol::PING);
            Ok((peer, None))
        }
        crate::net_processing::Received::Pong(nonce) => {
            // The peer replies only to a `ping`.
            assert_eq!(message.msg_type(), crate::protocol::PING);
            let pong = crate::net_processing::PeerOutbound::Pong(nonce);
            run_send(socket, &pong).await?;
            Ok((peer, None))
        }
        crate::net_processing::Received::Synced(tip) => {
            // Only a `headers` ends the sync.
            assert_eq!(message.msg_type(), crate::protocol::HEADERS);
            Ok((peer, Some(tip)))
        }
    }
}

/// Writes `outbound` within `SEND_TIMEOUT`. A write that ends early can leave part of a frame
/// in the stream, so each error ends the connection.
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

    /// Writes a message of the handshake.
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

    /// Writes a message after the handshake.
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

    /// Writes one frame with `msg_type` and `payload`.
    async fn send(
        &mut self,
        msg_type: crate::protocol::MessageType,
        payload: &[u8],
    ) -> Result<(), std::io::Error> {
        let frame = crate::transport::encode(self.network, msg_type, payload);
        self.stream.write_all(&frame).await
    }

    /// Reads until one frame is complete, and returns its message. A wait that ends early,
    /// for example at a timeout, loses no bytes: the next call continues the same frame.
    async fn receive(&mut self) -> Result<crate::transport::Message, ReceiveError> {
        // Each turn returns or reads at least one byte, and a frame has at most
        // `MESSAGE_HEADER_SIZE` + `PAYLOAD_LENGTH_MAX` bytes. So the loop ends.
        loop {
            if let Some(message) = self
                .frame
                .cut(self.network)
                .map_err(ReceiveError::Transport)?
            {
                // The next frame starts empty, so no byte of this frame goes into it.
                assert!(matches!(self.frame, PartialFrame::Header { filled: 0, .. }));
                return Ok(message);
            }
            self.read().await?;
        }
    }

    /// Reads at least one byte, and at most the bytes that the part still needs. A wait that
    /// ends early reads nothing, because `read` is cancel safe.
    async fn read(&mut self) -> Result<(), ReceiveError> {
        let (missing, filled) = self.frame.missing();
        // `cut` takes each complete part, so this part still needs a byte. An empty slice
        // would read nothing, and the zero would look like the end of the stream.
        assert!(!missing.is_empty());
        // A read returns at most the length of its slice, so it stops at the end of the part.
        let count = self.stream.read(missing).await.map_err(ReceiveError::Io)?;
        if count == 0 {
            // The end of the stream, inside a frame or between two frames.
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

    /// The bytes that the part still needs, and the count of the bytes that it has.
    fn missing(&mut self) -> (&mut [u8], &mut usize) {
        match self {
            PartialFrame::Header { bytes, filled } => (&mut bytes[*filled..], filled),
            PartialFrame::Payload {
                payload, filled, ..
            } => (&mut payload[*filled..], filled),
        }
    }

    /// Takes each complete part. A complete header gets its checks and then room for its
    /// payload. A complete payload gets its checksum and becomes the message, and the next
    /// frame starts empty.
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
            // The room is made only after the header passes its checks, so it is at most the
            // length limit.
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

/// The payload of a `ping` or a `pong`.
fn nonce_payload(nonce: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size_of::<u64>());
    nonce.encode(&mut payload);
    // The payload is only the nonce, the `u64` that the peer decodes.
    assert_eq!(payload.len(), size_of::<u64>());
    payload
}

/// Seconds since the Unix epoch, or zero if the clock is before it.
fn clock() -> u64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_before_epoch) => 0,
    }
}

/// `clock` as the `timestamp` of our `version`, which is an `i64` on the wire.
fn timestamp() -> i64 {
    i64::try_from(clock()).unwrap_or(i64::MAX)
}

/// A SipHash with keys from the OS. The nonce in our `version` only detects a connection to
/// self, and the nonce in our `ping` only matches its `pong`. So neither needs to be secret.
fn nonce() -> u64 {
    std::hash::RandomState::new().build_hasher().finish()
}

/// The random source of the OS.
const RANDOM_SOURCE: &str = "/dev/urandom";

/// A salt for a low-work sync, each byte from `RANDOM_SOURCE`. The peer must not know it, and a
/// peer sees each nonce. `nonce` does not give that: the keys of `RandomState` come from the OS
/// once, and each later one is the last plus one. So the salt reads the OS for each value.
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

/// The entry point of the `frame` fuzz target.
#[cfg(fuzzing)]
// Only cargo-mutants reads this attribute. Its test runs do not build this module.
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    /// The network of the seeds.
    const NETWORK: crate::chainparams::Network = crate::chainparams::Network::Regtest;

    /// The longest payload of the frame that `frame` writes. A run can set a larger `-max_len`,
    /// and `encode` panics above the length limit.
    const WRITTEN_PAYLOAD_LENGTH_MAX: usize = 4096;

    /// What `PartialFrame` takes from one stream.
    #[derive(Debug, PartialEq, Eq)]
    struct FrameRead {
        messages: Vec<crate::transport::Message>,
        end: FrameEnd,
    }

    /// Why the reads of one stream stopped.
    #[derive(Debug, PartialEq, Eq)]
    enum FrameEnd {
        /// The reads took each byte, and `PartialFrame` needs more.
        BytesEnded,
        /// `PartialFrame` refused a frame, and no read took the last `unread_count` bytes.
        Refused {
            error: crate::transport::Error,
            unread_count: usize,
        },
    }

    /// Checks that each split of the same bytes gives the same `FrameRead`, that the messages
    /// are the same bytes as the start of the stream, and that a frame from `encode` reads back
    /// as its message.
    ///
    /// The first byte of `data` is the count of the size bytes after it. A size byte `s` is a
    /// read of `s + 1` bytes. The rest of `data` is the stream. The committed corpus uses this
    /// layout, so a change to the layout must rewrite the corpus.
    pub fn frame(data: &[u8]) {
        let Some((sizes_count, rest)) = data.split_first() else {
            return;
        };
        let (sizes, stream) = rest.split_at(rest.len().min(usize::from(*sizes_count)));

        // The largest reads and the smallest reads, so an input with no size bytes still compares
        // two splits.
        let whole = frame_read(stream, std::iter::empty());
        assert_eq!(
            frame_read(stream, std::iter::repeat(std::num::NonZeroUsize::MIN)),
            whole
        );
        let read_sizes = sizes
            .iter()
            .map(|size_byte| std::num::NonZeroUsize::MIN.saturating_add(usize::from(*size_byte)));
        assert_eq!(frame_read(stream, read_sizes.clone()), whole);

        // All the splits can be wrong in the same way, so compare with the stream too.
        let encoded: Vec<u8> = whole
            .messages
            .iter()
            .flat_map(|message| {
                crate::transport::encode(NETWORK, message.msg_type(), message.payload())
            })
            .collect();
        assert!(stream.starts_with(&encoded));

        // A reader that refuses each frame passes all the checks above, so read a frame that elo
        // wrote.
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

    /// Gives `stream` to a new `PartialFrame` as `Socket::receive` does, one read for each size
    /// in `read_sizes`. A read takes all that it can when the sizes end.
    fn frame_read(
        stream: &[u8],
        mut read_sizes: impl Iterator<Item = std::num::NonZeroUsize>,
    ) -> FrameRead {
        let mut frame = super::PartialFrame::new();
        let mut messages = Vec::new();
        let mut unread = stream;
        // Each turn ends the loop, takes a message, or reads at least one byte. So the length of
        // the stream bounds the loop.
        let end = loop {
            match frame.cut(NETWORK) {
                Ok(Some(message)) => {
                    assert!(matches!(
                        frame,
                        super::PartialFrame::Header { filled: 0, .. }
                    ));
                    messages.push(message);
                }
                // On the socket, a read of zero bytes means the same.
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

    /// Reads one frame on the peer's side of the socket.
    fn read_frame(stream: &mut std::net::TcpStream) -> Vec<u8> {
        read_frame_on(stream, crate::chainparams::Network::Regtest)
    }

    /// `read_frame`, with the magic of `network`.
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

    /// Reads one frame on the peer's side of the socket, and returns its message.
    fn read_message(stream: &mut std::net::TcpStream) -> crate::transport::Message {
        let frame = read_frame(stream);
        let (header, payload) = frame.split_first_chunk().unwrap();
        let header =
            crate::transport::decode_header(crate::chainparams::Network::Regtest, header).unwrap();
        crate::transport::check_payload(header, payload.to_vec()).unwrap()
    }

    /// Accepts the driver on `listener` and completes the handshake with Core's frames. A
    /// driver that sends nothing more fails the test fast.
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

    /// Our `ping`: its payload is only the nonce.
    fn assert_ping(message: &crate::transport::Message) {
        assert_eq!(message.msg_type(), crate::protocol::PING);
        assert_eq!(message.payload().len(), size_of::<u64>());
    }

    /// Reads our first `getheaders`. It asks for the headers after genesis, so it is
    /// `GETHEADERS_FRAME`.
    fn read_first_get_headers(stream: &mut std::net::TcpStream) {
        assert_eq!(
            read_frame(stream),
            crate::fixtures::hex(crate::fixtures::GETHEADERS_FRAME)
        );
    }

    /// Reads our `sendheaders`, which the first tick after the sync sends.
    fn read_send_headers(stream: &mut std::net::TcpStream) {
        let send_headers = read_message(stream);
        assert_eq!(send_headers.msg_type(), crate::protocol::SENDHEADERS);
        assert!(send_headers.payload().is_empty());
    }

    /// A `headers` with no header, which ends the sync at our tip.
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
        // The peer sends Core's frames and keeps what the driver sends after their `version`.
        // A peer may send its `verack` before ours comes, so the bitcoind test cannot see this.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // A driver that sends no `verack` fails the test fast.
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

        let result = block_on(super::handshake(&[peer], &mut chain));
        let verack = peer_thread.join().unwrap();
        assert_eq!(verack, crate::fixtures::hex(crate::fixtures::VERACK_FRAME));
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn our_version_has_the_local_clock_in_seconds() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        // A peer reads this time only for its offset from its own clock, so the bitcoind test
        // passes with each value. Only this test reads it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            // The stream closes when this returns, so the handshake of the driver ends.
            read_message(&mut stream)
        });

        let seconds = || {
            let elapsed = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            i64::try_from(elapsed.as_secs()).unwrap()
        };
        let before = seconds();
        let _closed = block_on(super::handshake(&[peer], &mut chain));
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
        // The listener never accepts, so no `version` comes. The clock is paused after the
        // connect. When no task can run, tokio moves the clock to the next timer.
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
        // tokio rounds a deadline up to the next millisecond.
        assert_eq!(elapsed.as_secs(), super::HANDSHAKE_TIMEOUT.as_secs());
    }

    #[test]
    fn silent_peer_after_our_getheaders_is_headers_timeout() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        // The peer completes the handshake, reads our `ping` and our `getheaders`, and then
        // sends nothing. The clock is paused only after the handshake: while the peer thread
        // answers, the runtime has no task to run, so a paused clock would jump to
        // `HANDSHAKE_TIMEOUT`.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let mut stream = accept_handshake(&listener);
            assert_ping(&read_message(&mut stream));
            read_first_get_headers(&mut stream);
            // The socket stays open until the driver closes it. A close here would be `Closed`.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            rest
        });

        let (result, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
            tokio::time::pause();
            let start = tokio::time::Instant::now();
            let result = connection.sync().await;
            (result, start.elapsed())
        });
        let rest = peer_thread.join().unwrap();
        // The driver sends only what `tick` returns, so no second `getheaders` while the first
        // is outstanding.
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
        // 2 min, the headers timeout. tokio rounds a deadline up to the next millisecond.
        assert_eq!(
            elapsed.as_secs(),
            std::time::Duration::from_mins(2).as_secs()
        );
    }

    #[test]
    fn header_far_after_the_local_clock_ends_the_connection() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        // The header has the last time of a `u32`. Until the year 2106, that is more than 2 h
        // after the local clock in seconds, so only the driver decides here. A clock in
        // milliseconds would take this header.
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
            // The driver closes the socket when it refuses the batch.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
        });

        let result = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
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
        // Regtest has a minimum of zero, so only a test on another network shows that the driver
        // gives the peer the minimum of its network. The empty batch ends the sync on genesis,
        // which has less work than the signet minimum.
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
            // The reply to each frame of the driver. Our `ping` gets no `pong`, because the ping
            // timeout is far after the end of the test.
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
            // The driver closes the socket when the sync fails.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            msg_types
        });

        let result = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
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
        // The peer completes the handshake, ends the sync with an empty `headers`, and then
        // sends nothing. The clock is paused only after the sync: while the peer thread
        // answers, the runtime has no task to run, so a paused clock would jump to the headers
        // timeout. The time starts before the sync, so it includes the send of our `ping`.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let mut stream = accept_handshake(&listener);
            let ping = read_message(&mut stream);
            read_first_get_headers(&mut stream);
            stream.write_all(&empty_headers_frame()).unwrap();
            read_send_headers(&mut stream);
            // The socket stays open until the driver closes it. A close here would be `Closed`.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            (ping, rest)
        });

        let (error, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
            let start = tokio::time::Instant::now();
            let (synced, _tip) = connection.sync().await.unwrap();
            tokio::time::pause();
            let error = synced.next_tip().await.unwrap_err();
            (error, start.elapsed())
        });
        let (ping, rest) = peer_thread.join().unwrap();
        assert_ping(&ping);
        // The driver sends only what `tick` returns, so no second `ping` while the first is
        // outstanding.
        assert!(rest.is_empty(), "{rest:?}");
        assert!(
            matches!(
                error,
                super::RunError::NetProcessing(crate::net_processing::PeerError::PingTimeout)
            ),
            "{error:?}"
        );
        // 20 min, the ping timeout. tokio rounds a deadline up to the next millisecond.
        assert_eq!(
            elapsed.as_secs(),
            std::time::Duration::from_mins(20).as_secs()
        );
    }

    #[test]
    fn empty_announcement_after_the_sync_does_not_give_the_tip_again() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        // The peer ends the sync on genesis, and then announces no header and then one. So the
        // first call of `next_tip` gives the tip of the second announcement, not genesis again.
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
            // The driver closes the socket after `next_tip`. Nothing more goes before that.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            rest
        });

        let (synced_tip, next_tip) = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
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
        // The peer answers our first `ping` and not the second. So the connection ends at the
        // ping timeout of the second `ping`, which goes at the ping interval after the first.
        // A wake that stays at the timeout of the first `ping` sends the second one late. The
        // `pong` comes before the empty `headers`, so the driver has it when the sync ends. The
        // clock is paused only then, as in `silent_peer_after_the_sync_is_ping_timeout`.
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
            // The socket stays open until the driver closes it. A close here would be `Closed`.
            let mut rest = Vec::new();
            stream.read_to_end(&mut rest).unwrap();
            (first, second, rest)
        });

        let (error, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
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
        // 2 min to the second `ping`, then 20 min to its timeout. tokio rounds a deadline up to
        // the next millisecond.
        assert_eq!(
            elapsed.as_secs(),
            std::time::Duration::from_mins(2 + 20).as_secs()
        );
    }

    #[test]
    fn peer_that_stops_reading_is_send_timeout() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        // The peer completes the handshake and then reads nothing. The test fills the kernel
        // buffers before `run`, so the write of our first `ping` blocks.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || accept_handshake(&listener));

        let (result, elapsed) = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
            // The peer thread ends when it has sent its `verack`, so this wait blocks nothing.
            // The stream stays open, and nothing reads it.
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
            // A send with no timeout blocks forever. This timeout fails the test instead.
            let sync = connection.sync();
            let result = tokio::time::timeout(std::time::Duration::from_mins(30), sync).await;
            (result, start.elapsed())
        });
        assert!(
            matches!(result, Ok(Err(super::RunError::SendTimeout))),
            "{result:?}"
        );
        // tokio rounds a deadline up to the next millisecond.
        assert_eq!(elapsed.as_secs(), super::SEND_TIMEOUT.as_secs());
    }

    #[test]
    fn peer_that_closes_inside_a_frame_is_closed() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        // The peer reads our `version`, sends all of Core's `version` but its last byte, and
        // closes. A short read must not reach `check_payload`, which panics on it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_frame(&mut stream);
            let frame = crate::fixtures::hex(crate::fixtures::VERSION_FRAME);
            stream.write_all(&frame[..frame.len() - 1]).unwrap();
        });

        let result = block_on(super::handshake(&[peer], &mut chain));
        peer_thread.join().unwrap();
        assert!(
            matches!(result, Err(super::HandshakeError::Closed)),
            "{result:?}"
        );
    }

    #[test]
    fn frame_split_by_a_timeout_is_received_whole() {
        // The peer sends the first half of Core's `version` and blocks. A `receive` under a
        // timeout reads that half and times out. The peer then sends the rest, and the next
        // `receive` must return the whole message, so the wait that ended kept the first half.
        // The peer sends the rest only after the timeout: bytes on their way do not stop a
        // paused clock, so the clock could jump before they come.
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
            // The runtime has no other task, so this wait blocks nothing. The clock is paused
            // only when the first half is in the stream.
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
        // The peer sends Core's `verack` and `ping` in one write, so both can be in the stream
        // when the handshake ends. `sync` must still read the `ping` and answer it, after our
        // own `ping` and `getheaders`. Then the peer closes.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // A driver that sends no `pong` fails the test fast.
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
            // Our `ping` and `getheaders` go at the start of the first turn, before the driver
            // reads.
            assert_ping(&read_message(&mut stream));
            read_first_get_headers(&mut stream);
            read_frame(&mut stream)
        });

        let result = block_on(async {
            let (connection, _theirs) = super::handshake(&[peer], &mut chain).await.unwrap();
            connection.sync().await
        });
        let pong = peer_thread.join().unwrap();
        // A `pong` has the payload of the `ping`, so only the message type differs.
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
        // Nothing listens on a port that was bound and then freed.
        let peer = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let result = block_on(super::handshake(&[peer], &mut chain));
        assert!(
            matches!(
                result,
                Err(super::HandshakeError::Connect(ref error))
                    if error.kind() == std::io::ErrorKind::ConnectionRefused
            ),
            "{result:?}"
        );
    }

    #[test]
    fn connect_takes_the_first_peer_that_takes_it() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listening = listener.local_addr().unwrap();
        // Nothing listens on a port that was bound and then freed. The listener is open while
        // the bind picks the port, so the two ports differ.
        let refused = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        for peers in [[refused, listening], [listening, refused]] {
            let (peer, _stream) = block_on(super::connect_first(&peers)).unwrap();
            assert_eq!(peer, listening, "{peers:?}");
        }
    }

    #[test]
    fn each_salt_word_is_new() {
        // A fixed salt, or one that reads a word twice, passes each other test, and a peer that
        // knows the salt can make a chain that matches each bit. 6 random words are all different,
        // but once in about 2^60 runs.
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
