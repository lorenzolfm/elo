//! elo — a Bitcoin node.

mod handshake;
mod message;
mod version;

use std::hash::BuildHasher;
use std::io::Write;

const NETWORK: message::Network = message::Network::Regtest;
/// A local `bitcoind -regtest`. The first argument overrides it.
const PEER: &str = "127.0.0.1:18444";
/// For the connect, and for each read during the handshake. Core gives a
/// peer 60 s to finish the handshake (`DEFAULT_PEER_CONNECT_TIMEOUT`,
/// `../bitcoin/src/net.h:87` at v31.1); on loopback, and with one peer, a
/// sixth of that is generous.
///
/// Known gap: a read timeout bounds one syscall, not one message. Neither
/// this nor `LINGER` bounds how long a dripping peer can hold us; see
/// `handshake::MESSAGES_BEFORE_VERACK_MAX` and issue #4.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// After the handshake: how long we stay connected before we hang up, from
/// the moment `verack` arrives, whatever the peer sends, unless the peer hangs
/// up first. Long enough for Core's post-`verack` burst and for
/// `tests/handshake.rs` to ask Core about us; short enough that `cargo test`
/// stays quick.
const LINGER: std::time::Duration = std::time::Duration::from_secs(2);

/// Why `run` stopped.
#[derive(Debug)]
enum Error {
    /// A write to stdout failed. `BrokenPipe` is `elo | head -1`: the reader
    /// went away, nobody is listening, and `main` exits 0 without a word.
    /// Any other stdout failure is reported like the rest.
    Stdout(std::io::Error),
    /// The address, the socket, the clock, or the peer. `main` says the same
    /// thing about each of them, `elo: {e}`, so a variant per source would
    /// only re-wrap. The box is std, not `anyhow`.
    Node(Box<dyn std::error::Error>),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Stdout(e) => write!(f, "stdout: {e}"),
            Error::Node(e) => write!(f, "{e}"),
        }
    }
}

// `?` boxes every error but stdout's: those are mapped by hand where they are
// written, so they can never be mistaken for a socket that broke.
impl<E: std::error::Error + 'static> From<E> for Error {
    fn from(e: E) -> Self {
        Error::Node(Box::new(e))
    }
}

fn main() -> std::process::ExitCode {
    let peer = std::env::args().nth(1).unwrap_or_else(|| PEER.to_string());
    let stdout = std::io::stdout();
    match run(&peer, &mut stdout.lock()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(Error::Stdout(e)) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            // `eprintln!` panics on a closed stderr for the same reason
            // `println!` did on stdout. If nobody is listening there either,
            // there is nobody to tell.
            let _ = writeln!(std::io::stderr(), "elo: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Connects to `peer`, shakes hands, lingers, and narrates it all to `out`,
/// the one place in elo that writes anything a person reads.
fn run(peer: &str, out: &mut impl std::io::Write) -> Result<(), Error> {
    let peer: std::net::SocketAddr = peer.parse()?;
    writeln!(out, "connecting to {peer} as {}", version::USER_AGENT).map_err(Error::Stdout)?;
    let mut stream = std::net::TcpStream::connect_timeout(&peer, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;

    let since_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let timestamp = i64::try_from(since_epoch.as_secs())?;
    // The nonce lets the peer notice a connection to itself
    // (`../bitcoin/src/net.cpp:353`). std's per-process random seed is enough.
    let nonce = std::hash::RandomState::new().hash_one(0u8);
    let our_version = version::build(peer, timestamp, nonce);

    let started = std::time::Instant::now();
    writeln!(out, "-> version ({} bytes)", our_version.len()).map_err(Error::Stdout)?;
    let seen = handshake::run(&mut stream, NETWORK, &our_version)?;
    let elapsed = started.elapsed();
    for frame in &seen {
        writeln!(out, "<- {} ({} bytes)", frame.command, frame.payload.len())
            .map_err(Error::Stdout)?;
    }
    writeln!(out, "handshake complete in {elapsed:?}").map_err(Error::Stdout)?;

    // Each read gets only what is left of `LINGER`, so a peer that keeps
    // talking cannot keep us here; the loop ends when the clock does. A zero
    // timeout is an error to std, hence the guard.
    let hangup = std::time::Instant::now() + LINGER;
    let mut remaining = LINGER;
    while remaining > std::time::Duration::ZERO {
        stream.set_read_timeout(Some(remaining))?;
        match message::read(&mut stream, NETWORK) {
            Ok(frame) => writeln!(
                out,
                "<- {} ({} bytes) ignored",
                frame.command,
                frame.payload.len()
            )
            .map_err(Error::Stdout)?,
            Err(message::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            // The peer closing first is its right, not our fault.
            Err(message::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                writeln!(out, "peer hung up").map_err(Error::Stdout)?;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        remaining = hangup.saturating_duration_since(std::time::Instant::now());
    }
    writeln!(out, "{LINGER:?} after the handshake, hanging up").map_err(Error::Stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A stdout whose reader has gone: `elo | head -1` after the first line.
    struct Gone;

    impl std::io::Write for Gone {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_stdout_is_its_own_error() {
        // Nothing listens on port 1; had the write succeeded, the connect
        // would have failed instead, and as `Node`.
        let err = super::run("127.0.0.1:1", &mut Gone).unwrap_err();
        let super::Error::Stdout(io) = err else {
            panic!("expected Stdout, got {err}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::BrokenPipe);
        println!("stdout closed before the first line: {io}");
    }
}
