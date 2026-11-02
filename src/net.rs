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
const RECEIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20 * 60);

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
    stream: tokio::net::TcpStream,
    peer: crate::net_processing::Peer,
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
    mut stream: tokio::net::TcpStream,
) -> Result<(Connection, crate::protocol::Version), Error> {
    let (mut handshake, outbound) =
        crate::net_processing::Handshake::start(peer, timestamp(), nonce());
    send(&mut stream, network, &outbound).await?;
    loop {
        let message = receive(&mut stream, network).await?;
        match handshake.receive(&message).map_err(Error::NetProcessing)? {
            crate::net_processing::Step::Wait(next) => handshake = next,
            crate::net_processing::Step::Reply(next, outbound) => {
                send(&mut stream, network, &outbound).await?;
                handshake = next;
            }
            crate::net_processing::Step::Done(peer, theirs) => {
                let connection = Connection {
                    network,
                    stream,
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
            mut stream,
            mut peer,
        } = self;
        // The loop has no `break`, so the only way out is a `return` with an error.
        loop {
            let exchange = run_exchange(&mut stream, network, peer);
            peer = match tokio::time::timeout(RECEIVE_TIMEOUT, exchange).await {
                Ok(Ok(next)) => next,
                Ok(Err(error)) => return error,
                Err(_elapsed) => return Error::ReceiveTimeout,
            };
        }
    }
}

/// Reads one message, gives it to `peer`, and sends the reply if there is one. Returns the
/// peer for the next message.
async fn run_exchange(
    stream: &mut tokio::net::TcpStream,
    network: crate::chainparams::Network,
    peer: crate::net_processing::Peer,
) -> Result<crate::net_processing::Peer, Error> {
    let message = receive(stream, network).await?;
    let (peer, outbound) = peer.receive(&message).map_err(Error::NetProcessing)?;
    if let Some(outbound) = outbound {
        send(stream, network, &outbound).await?;
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

/// Reads one frame. The payload buffer is made only after the header passes its checks, so
/// it is at most the length limit.
async fn receive(
    stream: &mut tokio::net::TcpStream,
    network: crate::chainparams::Network,
) -> Result<crate::transport::Message, Error> {
    let mut header = [0; crate::transport::HEADER_SIZE];
    stream
        .read_exact(&mut header)
        .await
        .map_err(receive_error)?;
    let header = crate::transport::decode_header(network, &header).map_err(Error::Transport)?;

    // `check_payload` needs exactly the length in the header, and `read_exact` reads that
    // many bytes or fails.
    let mut payload = vec![0; header.payload_length()];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(receive_error)?;
    crate::transport::check_payload(header, payload).map_err(Error::Transport)
}

/// The end of the stream inside a frame means that the peer closed the connection.
fn receive_error(error: std::io::Error) -> Error {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        Error::Closed
    } else {
        Error::Io(error)
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
