//! elo — a Bitcoin node.

mod handshake;
mod message;
mod version;
mod wire;

use std::hash::BuildHasher;

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
/// `tests/regtest.rs` to ask Core about us; short enough that `cargo test`
/// stays quick.
const LINGER: std::time::Duration = std::time::Duration::from_secs(2);

struct Log<W: std::io::Write>(W);

impl<W: std::io::Write> Log<W> {
    fn line(&mut self, args: std::fmt::Arguments<'_>) {
        let _ = self
            .0
            .write_fmt(args)
            .and_then(|()| self.0.write_all(b"\n"));
    }
}

fn main() -> std::process::ExitCode {
    let peer = std::env::args().nth(1).unwrap_or_else(|| PEER.to_string());
    let stdout = std::io::stdout();
    match run(&peer, &mut Log(stdout.lock())) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            Log(std::io::stderr()).line(format_args!("elo: {e}"));
            std::process::ExitCode::FAILURE
        }
    }
}

/// Connects to `peer`, shakes hands, lingers, and narrates it all to `out`,
/// the one place in elo that writes anything a person reads.
fn run(peer: &str, out: &mut Log<impl std::io::Write>) -> Result<(), Box<dyn std::error::Error>> {
    let peer: std::net::SocketAddr = peer.parse()?;
    out.line(format_args!(
        "connecting to {peer} as {}",
        version::USER_AGENT
    ));
    let mut stream = std::net::TcpStream::connect_timeout(&peer, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;

    let since_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let timestamp = i64::try_from(since_epoch.as_secs())?;
    // The nonce lets the peer notice a connection to itself
    // (`../bitcoin/src/net.cpp:353`). std's per-process random seed is enough.
    let nonce = std::hash::RandomState::new().hash_one(0u8);
    let our_version = version::build(peer, timestamp, nonce);

    let started = std::time::Instant::now();
    out.line(format_args!("-> version ({} bytes)", our_version.len()));
    let seen = handshake::run(&mut stream, NETWORK, &our_version)?;
    let elapsed = started.elapsed();
    for frame in &seen {
        out.line(format_args!(
            "<- {} ({} bytes)",
            frame.command,
            frame.payload.len()
        ));
    }
    out.line(format_args!("handshake complete in {elapsed:?}"));

    // Each read gets only what is left of `LINGER`, so a peer that keeps
    // talking cannot keep us here; the loop ends when the clock does. A zero
    // timeout is an error to std, hence the guard.
    let hangup = std::time::Instant::now() + LINGER;
    let mut remaining = LINGER;
    while remaining > std::time::Duration::ZERO {
        stream.set_read_timeout(Some(remaining))?;
        match message::read(&mut stream, NETWORK) {
            Ok(frame) => match wire::Message::decode(frame)? {
                // Core pings right after the handshake and every two minutes
                // (`net_processing.cpp:5507`), and drops a peer whose pong is
                // twenty minutes late (`:5495`, `TIMEOUT_INTERVAL` in
                // `net.h:59`).
                wire::Message::Ping(nonce) => {
                    let pong = wire::Message::Pong(nonce).encode();
                    match message::write(&mut stream, NETWORK, pong.command, &pong.payload) {
                        Ok(()) => out.line(format_args!("<- ping {nonce:#018x}\n-> pong")),
                        // The peer closed between its ping and our pong. Its
                        // right, as below; a write sees it as a broken pipe.
                        Err(message::Error::Io(e))
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::BrokenPipe
                                    | std::io::ErrorKind::ConnectionReset
                            ) =>
                        {
                            out.line(format_args!("peer hung up"));
                            return Ok(());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                other => out.line(format_args!("<- {other} ignored")),
            },
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
                out.line(format_args!("peer hung up"));
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        remaining = hangup.saturating_duration_since(std::time::Instant::now());
    }
    out.line(format_args!("{LINGER:?} after the handshake, hanging up"));
    Ok(())
}

#[cfg(test)]
mod tests {
    /// A stdout whose reader has gone: `elo | head -1` after the first line.
    /// Counts the attempts, so a test can tell "kept writing" from "gave up".
    struct Gone {
        attempts: usize,
    }

    impl std::io::Write for Gone {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            self.attempts += 1;
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_line_ends_with_a_newline() {
        let mut log = super::Log(Vec::new());
        log.line(format_args!("one {}", 1));
        log.line(format_args!("two"));
        assert_eq!(log.0, b"one 1\ntwo\n");
        println!("{:?}", String::from_utf8(log.0).unwrap());
    }

    #[test]
    fn a_closed_stdout_is_not_our_problem() {
        let mut log = super::Log(Gone { attempts: 0 });
        log.line(format_args!("into the void"));
        log.line(format_args!("and again"));
        assert_eq!(log.0.attempts, 2, "every line is still attempted");
        println!("two lines to a closed pipe, no panic");
    }

    #[test]
    fn the_run_goes_on_without_a_reader() {
        // A port nobody listens on: bind, note it, release it.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut log = super::Log(Gone { attempts: 0 });
        let err = super::run(&format!("127.0.0.1:{port}"), &mut log).unwrap_err();
        let io = err.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(io.kind(), std::io::ErrorKind::ConnectionRefused, "{err}");
        assert_eq!(log.0.attempts, 1, "said 'connecting', then connected");
        println!("stdout closed before the first line; the run still reached the socket: {err}");
    }
}
