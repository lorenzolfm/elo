//! elo — a Bitcoin node.

mod handshake;
mod message;
mod version;

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
/// `tests/handshake.rs` to ask Core about us; short enough that `cargo test`
/// stays quick.
const LINGER: std::time::Duration = std::time::Duration::from_secs(2);

fn main() -> std::process::ExitCode {
    let peer = std::env::args().nth(1).unwrap_or_else(|| PEER.to_string());
    match run(&peer) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("elo: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(peer: &str) -> Result<(), Box<dyn std::error::Error>> {
    let peer: std::net::SocketAddr = peer.parse()?;
    println!("connecting to {peer} as {}", version::USER_AGENT);
    let mut stream = std::net::TcpStream::connect_timeout(&peer, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;

    let since_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let timestamp = i64::try_from(since_epoch.as_secs())?;
    // The nonce lets the peer notice a connection to itself
    // (`../bitcoin/src/net.cpp:353`). std's per-process random seed is enough.
    let nonce = std::hash::RandomState::new().hash_one(0u8);
    let our_version = version::build(peer, timestamp, nonce);

    let started = std::time::Instant::now();
    handshake::run(&mut stream, NETWORK, &our_version)?;
    println!("handshake complete in {:?}", started.elapsed());

    // Each read gets only what is left of `LINGER`, so a peer that keeps
    // talking cannot keep us here; the loop ends when the clock does. A zero
    // timeout is an error to std, hence the guard.
    let hangup = std::time::Instant::now() + LINGER;
    let mut remaining = LINGER;
    while remaining > std::time::Duration::ZERO {
        stream.set_read_timeout(Some(remaining))?;
        match message::read(&mut stream, NETWORK) {
            Ok(frame) => println!(
                "<- {} ({} bytes) ignored",
                frame.command,
                frame.payload.len()
            ),
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
                println!("peer hung up");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        remaining = hangup.saturating_duration_since(std::time::Instant::now());
    }
    println!("{LINGER:?} after the handshake, hanging up");
    Ok(())
}
