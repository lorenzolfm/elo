//! `elo <network> <ip>[:port]`: dials one peer, does the handshake, and prints the peer's
//! `version`. Then it syncs the header chain from the peer and prints the tip. It pings the
//! peer and answers its `ping` messages until the connection ends. Then it waits and dials the
//! peer again. The chain stays in memory, so the next connection syncs from its tip.

use std::io::Write;

const USAGE: &str = "usage: elo <mainnet|testnet4|signet|regtest> <ip>[:port]";

/// The exit code for bad usage. Every other exit is 1, because only a fault of this host ends
/// elo. elo has no signal handler, so Ctrl-C ends it with the shell's signal code.
const EXIT_USAGE: u8 = 2;

/// How long elo waits after a connection ends before it dials the peer again. So a peer that is
/// down, or that ends each connection at once, gets at most one try in each wait.
const RECONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

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
    // One chain for each connection, so a connection ends with the headers of the last one, and
    // a sync gets only the headers after its tip.
    let mut chain = elo::chain::Chain::new(network);
    // The loop has no count bound, because elo keeps its one peer for as long as it runs. Only
    // an end that a new connection cannot fix gets out.
    loop {
        let end = runtime.block_on(dial(peer, &mut chain));
        // The line says if elo dials again, so a reader of stderr does not need the list of
        // ends that exit.
        if !end.retries() {
            eprintln!("elo: {end}");
            return std::process::ExitCode::FAILURE;
        }
        eprintln!("elo: {end}; dial again in {} s", RECONNECT_WAIT.as_secs());
        // No task runs between two connections, so the wait needs no timer of the runtime.
        std::thread::sleep(RECONNECT_WAIT);
    }
}

/// How one connection ended.
#[derive(Debug)]
enum End {
    /// The connect or the handshake failed.
    Handshake(elo::net::HandshakeError),
    /// The connection ended in the sync or after it.
    Run(elo::net::RunError),
    /// A write to stdout failed.
    Stdout(std::io::Error),
}

impl End {
    /// Whether elo dials the peer again. Each end that the peer or the network causes retries,
    /// also a peer that sent bytes that elo refuses: the user named that peer. A fault of this
    /// host that a new connection cannot fix does not. The match names each variant, so
    /// a new error does not compile until it has a side.
    fn retries(&self) -> bool {
        match self {
            End::Handshake(elo::net::HandshakeError::Salt(_)) | End::Stdout(_) => false,
            End::Handshake(
                elo::net::HandshakeError::Connect(_)
                | elo::net::HandshakeError::ConnectTimeout
                | elo::net::HandshakeError::HandshakeTimeout
                | elo::net::HandshakeError::Io(_)
                | elo::net::HandshakeError::Closed
                | elo::net::HandshakeError::Transport(_)
                | elo::net::HandshakeError::NetProcessing(_),
            ) => true,
            End::Run(
                elo::net::RunError::SendTimeout
                | elo::net::RunError::Io(_)
                | elo::net::RunError::Closed
                | elo::net::RunError::Transport(_)
                | elo::net::RunError::NetProcessing(_),
            ) => true,
        }
    }
}

impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            End::Handshake(error) => write!(f, "{error}"),
            End::Run(error) => write!(f, "{error}"),
            End::Stdout(error) => write!(f, "stdout: {error}"),
        }
    }
}

/// Dials `peer`, does the handshake and prints the `version` of the peer. Then syncs `chain`,
/// prints its tip, and runs until the connection ends.
async fn dial(peer: std::net::SocketAddr, chain: &mut elo::chain::Chain) -> End {
    let (connection, version) = match elo::net::handshake(peer, chain).await {
        Ok(handshake) => handshake,
        Err(error) => return End::Handshake(error),
    };

    let printed = print(format_args!(
        "version {}\nservices {:016x}\nuser_agent {}\nstart_height {}\nrelay {}",
        version.version(),
        version.services(),
        version.user_agent(),
        version.start_height(),
        version.relay(),
    ));
    if let Err(error) = printed {
        return End::Stdout(error);
    }

    let (synced, tip) = match connection.sync().await {
        Ok(sync) => sync,
        Err(error) => return End::Run(error),
    };
    if let Err(error) = print(format_args!("tip {tip}")) {
        return End::Stdout(error);
    }

    End::Run(synced.run().await)
}

/// Writes `text` and a newline to stdout. `println!` panics when stdout fails, for example on
/// a full disk or a closed pipe.
fn print(text: std::fmt::Arguments<'_>) -> Result<(), std::io::Error> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{text}")?;
    // stdout is not always line buffered, and the exit ignores a failed flush.
    stdout.flush()
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

    // The L3 tests also hold a closed connection, which retries, and a stdout fault, which
    // exits. The stdout row is here too: a retry on that fault fails the L3 test on its
    // `dial again` line, but slower, and through a process. This row gives the reason at L0.
    #[test]
    fn a_fault_of_this_host_ends_elo_and_a_failed_connect_retries() {
        for (end, retries) in [
            (
                super::End::Handshake(elo::net::HandshakeError::Salt(std::io::Error::other(
                    "salt",
                ))),
                false,
            ),
            (super::End::Stdout(std::io::Error::other("stdout")), false),
            (
                super::End::Handshake(elo::net::HandshakeError::Connect(std::io::Error::other(
                    "connect",
                ))),
                true,
            ),
            (
                super::End::Handshake(elo::net::HandshakeError::ConnectTimeout),
                true,
            ),
        ] {
            assert_eq!(end.retries(), retries, "{end}");
        }
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
