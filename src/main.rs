//! elo — a Bitcoin node.

use std::hash::BuildHasher;

const NETWORK: elo::chain::network::Network = elo::chain::network::Network::Regtest;
/// A local `bitcoind -regtest`. The first argument overrides it.
const PEER: &str = "127.0.0.1:18444";
/// For the connect, and then for the whole handshake, as one deadline from
/// the moment the socket opens. Core gives a peer 60 s to finish the
/// handshake (`DEFAULT_PEER_CONNECT_TIMEOUT`, `../bitcoin/src/net.h:87` at
/// v31.1); on loopback, and with one peer, a sixth of that is generous.
const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// After the sync: how long we stay connected before we hang up, from the
/// moment the last `headers` arrives, whatever the peer sends, unless the
/// peer hangs up first. Long enough for Core's post-`verack` burst and for
/// `tests/regtest.rs` to ask Core about us; short enough that `cargo test`
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

/// Connects to `peer`, shakes hands, syncs headers, lingers, and narrates it
/// all to stdout, the one place in elo that writes anything a person reads.
fn run(peer: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = connect(peer)?;

    let mut chain = elo::chain::Chain::new(NETWORK);
    let outcome = elo::sync::run(&mut connection, &mut chain, |event| {
        println!("{event}");
    })?;
    match outcome {
        elo::sync::Outcome::Synced => {
            println!("synced: height {}, tip {}", chain.height(), chain.tip());
        }
        elo::sync::Outcome::Capped => println!(
            "stopped at {} batches (ROADMAP step 8): height {}, tip {}; the peer may have more",
            elo::sync::BATCHES_MAX,
            chain.height(),
            chain.tip()
        ),
    }

    // One deadline for every read, so a peer that keeps talking cannot keep
    // us here; the loop ends when the clock does.
    connection.set_read_deadline(Some(connection.now() + LINGER))?;
    loop {
        match connection.read_frame() {
            // Stricter than Core, which ignores the tail of a long `ping` and
            // only logs a short one (`net_processing.cpp:5283`), staying
            // connected either way. A known command with a length it cannot
            // have is a peer we do not want, so the `?` ends the session.
            Ok(frame) => match elo::p2p::message::Message::decode(frame)? {
                // Core pings right after the handshake and every two minutes
                // (`net_processing.cpp:5507`), and drops a peer whose pong is
                // twenty minutes late (`:5495`, `TIMEOUT_INTERVAL` in
                // `net.h:59`).
                elo::p2p::message::Message::Ping(nonce) => {
                    let pong = elo::p2p::message::Message::Pong(nonce).encode();
                    match connection.write_frame(pong.command, &pong.payload) {
                        Ok(()) => println!("<- ping {nonce:#018x}\n-> pong"),
                        // The peer closed between its ping and our pong.
                        Err(elo::p2p::frame::Error::Io(e)) if peer_hung_up(&e) => {
                            println!("peer hung up");
                            return Ok(());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                other => println!("<- {other} ignored"),
            },
            Err(elo::p2p::frame::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(elo::p2p::frame::Error::Io(e)) if peer_hung_up(&e) => {
                println!("peer hung up");
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
    }
    println!("{LINGER:?} after the sync, hanging up");
    Ok(())
}

/// The peer closing first is its right, not our fault. A read sees it as an
/// early end of stream; a write, as a broken pipe; either, as a reset. One
/// predicate for both paths, so they cannot disagree about what a hang-up is.
fn peer_hung_up(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
    )
}

/// Connects, runs the handshake and prints its transcript. Everything before
/// the first message we answer; `run` keeps the decisions.
fn connect(
    peer: &str,
) -> Result<elo::p2p::connection::Connection<elo::p2p::link::Tcp>, Box<dyn std::error::Error>> {
    let peer: std::net::SocketAddr = peer.parse()?;
    println!("connecting to {peer} as {}", elo::p2p::version::USER_AGENT);
    let stream = std::net::TcpStream::connect_timeout(&peer, TIMEOUT)?;
    let mut connection =
        elo::p2p::connection::Connection::new(elo::p2p::link::Tcp::new(stream), NETWORK);
    connection.set_read_deadline(Some(connection.now() + TIMEOUT))?;

    let since_epoch = connection.wall().duration_since(std::time::UNIX_EPOCH)?;
    let timestamp = i64::try_from(since_epoch.as_secs())?;
    // Not the `ping` nonce: this one lets the peer notice a connection to
    // itself (`../bitcoin/src/net.cpp:353`). std's per-process random seed is
    // enough.
    let version_nonce = std::hash::RandomState::new().hash_one(0u8);
    let our_version = elo::p2p::version::build(peer, timestamp, version_nonce);

    let started = std::time::Instant::now();
    println!("-> version ({} bytes)", our_version.len());
    let elo::handshake::Complete { peer, seen } =
        elo::handshake::run(&mut connection, &our_version)?;
    let elapsed = started.elapsed();
    for frame in &seen {
        println!("<- {} ({} bytes)", frame.command, frame.payload.len());
    }
    println!("handshake complete in {elapsed:?}");
    println!("peer is {peer}");
    Ok(connection)
}
