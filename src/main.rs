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

/// Connects to `peer`, runs the session, and narrates it all to stdout, the
/// one place in elo that writes anything a person reads.
fn run(peer: &str) -> Result<(), Box<dyn std::error::Error>> {
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

    let mut chain = elo::chain::Chain::new(NETWORK);
    elo::peer::run(&mut connection, &mut chain, &our_version, LINGER, |event| {
        println!("{event}");
    })?;
    Ok(())
}
