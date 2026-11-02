//! The driver: it dials one peer, runs the handshake on the socket, and then answers the
//! messages after it.

use crate::serialize::Encode;
use std::hash::{BuildHasher, Hasher};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long the TCP connect may take.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long the handshake may take, from the connect to their `verack`.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long each message after the handshake may take, with our reply to it. A live peer pings
/// far more often, so a longer silence means that it is gone. The deadline also covers the
/// reply, because a write to a peer that does not read can block forever.
const RECEIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(20);

/// Why the connection failed.
#[derive(Debug)]
pub enum Error {
    /// The TCP connect failed.
    Connect(std::io::Error),
    /// The TCP connect took longer than `CONNECT_TIMEOUT`.
    ConnectTimeout,
    /// The handshake took longer than `HANDSHAKE_TIMEOUT`.
    HandshakeTimeout,
    /// A message after the handshake, with our reply to it, took longer than
    /// `RECEIVE_TIMEOUT`.
    ReceiveTimeout,
    /// A read or a write on the socket failed.
    Io(std::io::Error),
    /// The peer closed the connection, before or after the handshake.
    Closed,
    /// The peer sent a frame that elo refuses.
    Transport(crate::transport::Error),
    /// elo refused the peer: a bad `version`, our own `version`, too many messages in the
    /// handshake, or a bad `ping`.
    NetProcessing(crate::net_processing::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Connect(error) => write!(f, "connect: {error}"),
            Error::ConnectTimeout => {
                write!(
                    f,
                    "connect took longer than {} s",
                    CONNECT_TIMEOUT.as_secs()
                )
            }
            Error::HandshakeTimeout => {
                write!(
                    f,
                    "handshake took longer than {} s",
                    HANDSHAKE_TIMEOUT.as_secs()
                )
            }
            Error::ReceiveTimeout => {
                write!(
                    f,
                    "a message and our reply took longer than {} s",
                    RECEIVE_TIMEOUT.as_secs()
                )
            }
            Error::Io(error) => write!(f, "socket: {error}"),
            Error::Closed => write!(f, "the peer closed the connection"),
            Error::Transport(error) => write!(f, "frame: {error}"),
            Error::NetProcessing(error) => write!(f, "peer: {error}"),
        }
    }
}

impl std::error::Error for Error {}

/// One peer after the handshake: the socket and the machine for its messages. Only
/// `handshake` makes one, so `run` cannot start before the handshake is complete.
#[derive(Debug)]
pub struct Connection {
    network: crate::chainparams::Network,
    socket: Socket,
    peer: crate::net_processing::Peer,
}

/// The stream to one peer, and the bytes of the frame that is not complete yet. Only
/// `receive` reads the stream, so each byte that comes goes into a frame.
#[derive(Debug)]
struct Socket {
    stream: tokio::net::TcpStream,
    frame: PartialFrame,
}

/// The bytes of one frame, kept across waits. Each read asks only for the bytes that this
/// frame still needs, so the bytes of the next frame stay in the stream.
#[derive(Debug)]
enum PartialFrame {
    /// The header is not complete: at most `HEADER_SIZE` bytes.
    Header(Vec<u8>),
    /// The header passed its checks: the payload so far, at most its length.
    Payload(crate::transport::MessageHeader, Vec<u8>),
}

/// Dials `peer` and runs the handshake. Returns the connection for the messages after it, and
/// their `version`.
pub async fn handshake(
    network: crate::chainparams::Network,
    peer: std::net::SocketAddr,
) -> Result<(Connection, crate::protocol::Version), Error> {
    let connect = tokio::net::TcpStream::connect(peer);
    let stream = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => return Err(Error::Connect(error)),
        Err(_elapsed) => return Err(Error::ConnectTimeout),
    };
    handshake_stream(network, peer, stream).await
}

/// The handshake on a connected `stream`, within `HANDSHAKE_TIMEOUT`.
async fn handshake_stream(
    network: crate::chainparams::Network,
    peer: std::net::SocketAddr,
    stream: tokio::net::TcpStream,
) -> Result<(Connection, crate::protocol::Version), Error> {
    let exchange = handshake_stream_exchange(network, peer, stream);
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_elapsed) => Err(Error::HandshakeTimeout),
    }
}

/// Sends our `version`, then reads messages until the handshake is done. The handshake
/// bounds the loop: it refuses a peer that sends too many messages without its `verack`.
async fn handshake_stream_exchange(
    network: crate::chainparams::Network,
    peer: std::net::SocketAddr,
    stream: tokio::net::TcpStream,
) -> Result<(Connection, crate::protocol::Version), Error> {
    let mut socket = Socket::new(stream);
    let (mut handshake, outbound) =
        crate::net_processing::Handshake::start(peer, timestamp(), nonce());
    send(&mut socket.stream, network, &outbound).await?;
    loop {
        let message = socket.receive(network).await?;
        match handshake.receive(&message).map_err(Error::NetProcessing)? {
            crate::net_processing::Step::Wait(next) => handshake = next,
            crate::net_processing::Step::Reply(next, outbound) => {
                send(&mut socket.stream, network, &outbound).await?;
                handshake = next;
            }
            crate::net_processing::Step::Done(peer, theirs) => {
                // The peer can send more frames in the same segment as its `verack`. The socket
                // goes into the connection, so `run` reads them next.
                let connection = Connection {
                    network,
                    socket,
                    peer,
                };
                return Ok((connection, theirs));
            }
        }
    }
}

impl Connection {
    /// Reads each message, gives it to the peer, and sends its reply. The loop has no count
    /// bound, because a peer sends messages for as long as it is connected. It ends only on an
    /// error: the peer closes, a read or a write fails, `RECEIVE_TIMEOUT` passes, or elo refuses
    /// a frame or a message. The frame length limit bounds each message.
    pub async fn run(self) -> Error {
        let Connection {
            network,
            mut socket,
            mut peer,
        } = self;
        // The loop has no `break`, so the only way out is a `return` with an error.
        loop {
            let exchange = run_exchange(&mut socket, network, peer);
            peer = match tokio::time::timeout(RECEIVE_TIMEOUT, exchange).await {
                Ok(Ok(next)) => next,
                Ok(Err(error)) => {
                    // After the handshake, only the socket, a frame or a message can fail. The
                    // connect and handshake errors come only from `handshake`.
                    assert!(
                        matches!(
                            error,
                            Error::Io(_)
                                | Error::Closed
                                | Error::Transport(_)
                                | Error::NetProcessing(_)
                        ),
                        "{error:?}"
                    );
                    return error;
                }
                Err(_elapsed) => return Error::ReceiveTimeout,
            };
        }
    }
}

/// Reads one message, gives it to `peer`, and sends the reply if there is one. Returns the
/// peer for the next message.
async fn run_exchange(
    socket: &mut Socket,
    network: crate::chainparams::Network,
    peer: crate::net_processing::Peer,
) -> Result<crate::net_processing::Peer, Error> {
    let message = socket.receive(network).await?;
    let (peer, outbound) = peer.receive(&message).map_err(Error::NetProcessing)?;
    match outbound {
        Some(outbound) => {
            // After the handshake, the peer replies only with a `pong`, and only to a `ping`.
            assert!(matches!(outbound, crate::net_processing::Outbound::Pong(_)));
            assert_eq!(message.msg_type(), crate::protocol::PING);
            send(&mut socket.stream, network, &outbound).await?;
        }
        // Each `ping` that the peer accepts gets a `pong`.
        None => assert_ne!(message.msg_type(), crate::protocol::PING),
    }
    Ok(peer)
}

async fn send(
    stream: &mut tokio::net::TcpStream,
    network: crate::chainparams::Network,
    outbound: &crate::net_processing::Outbound,
) -> Result<(), Error> {
    let frame = match outbound {
        crate::net_processing::Outbound::Version(payload) => {
            crate::transport::encode(network, crate::protocol::VERSION, payload)
        }
        crate::net_processing::Outbound::Verack => {
            crate::transport::encode(network, crate::protocol::VERACK, &[])
        }
        crate::net_processing::Outbound::Pong(nonce) => {
            let mut payload = Vec::new();
            nonce.encode(&mut payload);
            crate::transport::encode(network, crate::protocol::PONG, &payload)
        }
    };
    stream.write_all(&frame).await.map_err(Error::Io)
}

impl Socket {
    fn new(stream: tokio::net::TcpStream) -> Socket {
        Socket {
            stream,
            frame: PartialFrame::new(),
        }
    }

    /// Reads until one frame is complete, and returns its message. A wait that ends early,
    /// for example at a timeout, loses no bytes: the next call continues the same frame.
    async fn receive(
        &mut self,
        network: crate::chainparams::Network,
    ) -> Result<crate::transport::Message, Error> {
        // Each turn returns or reads at least one byte, and a frame has at most
        // `HEADER_SIZE` + `PAYLOAD_LENGTH_MAX` bytes. So the loop ends.
        loop {
            if let Some(message) = self.frame.cut(network).map_err(Error::Transport)? {
                return Ok(message);
            }
            self.read().await?;
        }
    }

    /// Reads at least one byte, and at most the bytes that the frame still needs. A wait that
    /// ends early reads nothing, because `read_buf` is cancel safe.
    async fn read(&mut self) -> Result<(), Error> {
        let (bytes, size) = self.frame.part();
        // `cut` takes each complete part, so this part still needs a byte. A limit of zero
        // would read nothing, and the zero would look like the end of the stream.
        assert!(bytes.len() < size);
        let needed = size - bytes.len();
        const _: () = assert!(usize::BITS <= u64::BITS);
        let count = (&mut self.stream)
            .take(needed as u64)
            .read_buf(bytes)
            .await
            .map_err(Error::Io)?;
        if count == 0 {
            // The end of the stream, inside a frame or between two frames.
            return Err(Error::Closed);
        }
        assert!(count <= needed);
        assert!(bytes.len() <= size);
        Ok(())
    }
}

impl PartialFrame {
    fn new() -> PartialFrame {
        PartialFrame::Header(Vec::with_capacity(crate::transport::HEADER_SIZE))
    }

    /// The bytes of the part that is not complete yet, and the size that completes it.
    fn part(&mut self) -> (&mut Vec<u8>, usize) {
        match self {
            PartialFrame::Header(bytes) => (bytes, crate::transport::HEADER_SIZE),
            PartialFrame::Payload(header, payload) => (payload, header.payload_length()),
        }
    }

    /// Takes each complete part. A complete header gets its checks and then room for its
    /// payload. A complete payload gets its checksum and becomes the message, and the next
    /// frame starts empty.
    fn cut(
        &mut self,
        network: crate::chainparams::Network,
    ) -> Result<Option<crate::transport::Message>, crate::transport::Error> {
        if let PartialFrame::Header(bytes) = self {
            assert!(bytes.len() <= crate::transport::HEADER_SIZE);
            if let Ok(header) = <&[u8; crate::transport::HEADER_SIZE]>::try_from(bytes.as_slice()) {
                let header = crate::transport::decode_header(network, header)?;
                // The room is made only after the header passes its checks, so it is at most
                // the length limit.
                let payload = Vec::with_capacity(header.payload_length());
                *self = PartialFrame::Payload(header, payload);
            }
        }
        if let PartialFrame::Payload(header, payload) = self {
            assert!(payload.len() <= header.payload_length());
            if payload.len() == header.payload_length() {
                let header = *header;
                let payload = std::mem::take(payload);
                *self = PartialFrame::new();
                return crate::transport::check_payload(header, payload).map(Some);
            }
        }
        Ok(None)
    }
}

/// Seconds since the Unix epoch, or zero if the clock is before it.
fn timestamp() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        Err(_before_epoch) => 0,
    }
}

/// A SipHash with keys from the OS. The nonce only detects a connection to self, so it
/// need not be secret.
fn nonce() -> u64 {
    std::hash::RandomState::new().build_hasher().finish()
}

#[cfg(test)]
mod tests {
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
        let mut frame = vec![0; crate::transport::HEADER_SIZE];
        stream.read_exact(&mut frame).unwrap();
        let header = frame.first_chunk().unwrap();
        let header =
            crate::transport::decode_header(crate::chainparams::Network::Regtest, header).unwrap();
        let mut payload = vec![0; header.payload_length()];
        stream.read_exact(&mut payload).unwrap();
        frame.extend(payload);
        frame
    }

    #[test]
    fn their_version_gets_our_verack() {
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

        let result = block_on(super::handshake(crate::chainparams::Network::Regtest, peer));
        let verack = peer_thread.join().unwrap();
        assert_eq!(verack, crate::fixtures::hex(crate::fixtures::VERACK_FRAME));
        assert!(result.is_ok(), "{result:?}");
    }

    #[test]
    fn silent_peer_is_handshake_timeout() {
        // The listener never accepts, so no `version` comes. The clock is paused after the
        // connect. When no task can run, tokio moves the clock to the next timer.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let (result, elapsed) = block_on(async {
            let stream = tokio::net::TcpStream::connect(peer).await.unwrap();
            tokio::time::pause();
            let start = tokio::time::Instant::now();
            let result =
                super::handshake_stream(crate::chainparams::Network::Regtest, peer, stream).await;
            (result, start.elapsed())
        });
        assert!(
            matches!(result, Err(super::Error::HandshakeTimeout)),
            "{result:?}"
        );
        // tokio rounds a deadline up to the next millisecond.
        assert_eq!(elapsed.as_secs(), super::HANDSHAKE_TIMEOUT.as_secs());
    }

    #[test]
    fn silent_peer_after_the_handshake_is_receive_timeout() {
        // The peer completes the handshake with Core's frames and then sends nothing. The
        // clock is paused only after the handshake: while the peer thread answers, the runtime
        // has no task to run, so a paused clock would jump to `HANDSHAKE_TIMEOUT`.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = listener.local_addr().unwrap();
        let peer_thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_frame(&mut stream);
            stream
                .write_all(&crate::fixtures::hex(crate::fixtures::VERSION_FRAME))
                .unwrap();
            read_frame(&mut stream);
            stream
                .write_all(&crate::fixtures::hex(crate::fixtures::VERACK_FRAME))
                .unwrap();
            // The socket stays open until the driver closes it. A close here would be `Closed`.
            stream.read_to_end(&mut Vec::new()).unwrap();
        });

        let (error, elapsed) = block_on(async {
            let (connection, _theirs) =
                super::handshake(crate::chainparams::Network::Regtest, peer)
                    .await
                    .unwrap();
            tokio::time::pause();
            let start = tokio::time::Instant::now();
            let error = connection.run().await;
            (error, start.elapsed())
        });
        peer_thread.join().unwrap();
        assert!(matches!(error, super::Error::ReceiveTimeout), "{error:?}");
        // tokio rounds a deadline up to the next millisecond.
        assert_eq!(elapsed.as_secs(), super::RECEIVE_TIMEOUT.as_secs());
    }

    #[test]
    fn peer_that_closes_inside_a_frame_is_closed() {
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

        let result = block_on(super::handshake(crate::chainparams::Network::Regtest, peer));
        peer_thread.join().unwrap();
        assert!(matches!(result, Err(super::Error::Closed)), "{result:?}");
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
            let mut socket = super::Socket::new(stream);
            // The runtime has no other task, so this wait blocks nothing. The clock is paused
            // only when the first half is in the socket.
            first_sent_receiver.recv().unwrap();
            tokio::time::pause();
            let receive = socket.receive(crate::chainparams::Network::Regtest);
            let timeout = tokio::time::timeout(std::time::Duration::from_secs(1), receive).await;
            timed_out.send(()).unwrap();
            let message = socket.receive(crate::chainparams::Network::Regtest).await;
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
        // The peer sends Core's `verack` and `ping` in one write, so both can be in the socket
        // when the handshake ends. `run` must still read the `ping` and answer it. Then the
        // peer closes.
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
            read_frame(&mut stream)
        });

        let error = block_on(async {
            let (connection, _theirs) =
                super::handshake(crate::chainparams::Network::Regtest, peer)
                    .await
                    .unwrap();
            connection.run().await
        });
        let pong = peer_thread.join().unwrap();
        let ping = crate::fixtures::hex(crate::fixtures::PING_FRAME);
        let nonce = &ping[crate::transport::HEADER_SIZE..];
        assert_eq!(
            pong,
            crate::transport::encode(
                crate::chainparams::Network::Regtest,
                crate::protocol::PONG,
                nonce
            )
        );
        assert!(matches!(error, super::Error::Closed), "{error:?}");
    }

    #[test]
    fn refused_connect_is_connect_error() {
        // Nothing listens on a port that was bound and then freed.
        let peer = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let result = block_on(super::handshake(crate::chainparams::Network::Regtest, peer));
        assert!(
            matches!(
                result,
                Err(super::Error::Connect(ref error))
                    if error.kind() == std::io::ErrorKind::ConnectionRefused
            ),
            "{result:?}"
        );
    }
}
