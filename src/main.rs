//! `elo <network> <ip>[:port]`: dials one peer, does the handshake, and prints the peer's
//! `version`.

use std::io::Write;

const USAGE: &str = "usage: elo <mainnet|testnet4|signet|regtest> <ip>[:port]";

/// The exit code for bad usage. A failed connection, handshake or print exits with 1.
const EXIT_USAGE: u8 = 2;

fn main() -> std::process::ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let Some((network, peer)) = parse(&args) else {
        eprintln!("{USAGE}");
        return std::process::ExitCode::from(EXIT_USAGE);
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("elo: runtime: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let version = match runtime.block_on(elo::net::handshake(network, peer)) {
        Ok(version) => version,
        Err(error) => {
            eprintln!("elo: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // `println!` panics when stdout fails, for example on a full disk or a closed pipe.
    let mut stdout = std::io::stdout().lock();
    let printed = writeln!(
        stdout,
        "version {}\nservices {:016x}\nuser_agent {}\nstart_height {}\nrelay {}",
        version.version(),
        version.services(),
        version.user_agent(),
        version.start_height(),
        version.relay(),
    )
    // stdout is not always line buffered, and the exit ignores a failed flush.
    .and_then(|()| stdout.flush());
    if let Err(error) = printed {
        eprintln!("elo: stdout: {error}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

/// The args after the program name. `None` is bad usage.
///
/// An IPv6 address needs brackets even without a port, because `::1:8333` is an IPv6 address
/// and not `::1` with a port.
fn parse(args: &[std::ffi::OsString]) -> Option<(elo::chainparams::Network, std::net::SocketAddr)> {
    let [network, peer] = args else {
        return None;
    };
    let network = match network.to_str()? {
        "mainnet" => elo::chainparams::Network::Mainnet,
        "testnet4" => elo::chainparams::Network::Testnet4,
        "signet" => elo::chainparams::Network::Signet,
        "regtest" => elo::chainparams::Network::Regtest,
        _ => return None,
    };

    let peer = peer.to_str()?;
    let peer = if let Ok(peer) = peer.parse() {
        peer
    } else if let Some(ip) = peer.strip_prefix('[').and_then(|ip| ip.strip_suffix(']')) {
        let ip = ip.parse::<std::net::Ipv6Addr>().ok()?;
        std::net::SocketAddr::from((ip, network.default_port()))
    } else {
        let ip = peer.parse::<std::net::Ipv4Addr>().ok()?;
        std::net::SocketAddr::from((ip, network.default_port()))
    };
    // Port 0, `0.0.0.0`, `[::]` and `[::ffff:0.0.0.0]` name no peer.
    if peer.port() == 0 || peer.ip().to_canonical().is_unspecified() {
        return None;
    }
    Some((network, peer))
}

#[cfg(test)]
mod tests {
    fn parse(args: &[&str]) -> Option<(elo::chainparams::Network, std::net::SocketAddr)> {
        let args: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
        super::parse(&args)
    }

    #[test]
    fn each_network_has_a_name_and_a_default_port() {
        for (name, network, port) in [
            ("mainnet", elo::chainparams::Network::Mainnet, 8333),
            ("testnet4", elo::chainparams::Network::Testnet4, 48333),
            ("signet", elo::chainparams::Network::Signet, 38333),
            ("regtest", elo::chainparams::Network::Regtest, 18444),
        ] {
            let peer = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            assert_eq!(parse(&[name, "127.0.0.1"]), Some((network, peer)), "{name}");
        }
    }

    #[test]
    fn peer_is_an_ip_literal_with_an_optional_port() {
        let localhost_v6 = std::net::Ipv6Addr::LOCALHOST;
        for (peer, expected) in [
            (
                "127.0.0.1:1",
                Some(std::net::SocketAddr::from(([127, 0, 0, 1], 1))),
            ),
            (
                "[::1]",
                Some(std::net::SocketAddr::from((localhost_v6, 18444))),
            ),
            (
                "[::1]:1",
                Some(std::net::SocketAddr::from((localhost_v6, 1))),
            ),
            ("::1:8333", None),
            ("127.0.0.1:0", None),
            ("0.0.0.0", None),
            ("[::]", None),
            ("[::ffff:0.0.0.0]", None),
            ("localhost", None),
            ("localhost:18444", None),
        ] {
            let parsed = parse(&["regtest", peer]).map(|(_, peer)| peer);
            assert_eq!(parsed, expected, "{peer}");
        }
    }

    #[test]
    fn usage_is_a_network_name_and_a_peer() {
        for args in [
            &[][..],
            &["regtest"],
            &["testnet3", "127.0.0.1"],
            &["regtest", "127.0.0.1", "127.0.0.1"],
        ] {
            assert_eq!(parse(args), None, "{args:?}");
        }
    }
}
