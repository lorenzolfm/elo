const USAGE: &str = "usage: elo <mainnet|testnet4|signet|regtest> [<ip|name>[:port]]
regtest has no seeds, so it needs a peer";

const EXIT_USAGE: u8 = 2;

const RECONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|info| {
        let event = elo::logging::Event::Panic { reason: info };
        if log(&event).is_err() {
            let _ = event.write(&mut std::io::stderr().lock());
        }
    }));

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let Some((network, source)) = parse(&args) else {
        eprintln!("{USAGE}");
        return std::process::ExitCode::from(EXIT_USAGE);
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return exit(&format_args!("runtime: {error}")),
    };
    let code = runtime.block_on(run(network, source));
    runtime.shutdown_background();
    code
}

async fn run(
    network: elo::chainparams::Network,
    source: elo::net::Source,
) -> std::process::ExitCode {
    let mut signals = match Signals::new() {
        Ok(signals) => signals,
        Err(error) => return exit(&format_args!("signals: {error}")),
    };
    let mut chain = elo::chain::Chain::new(network);
    loop {
        let destination = source.destination();
        let end = match signals.unless(dial(&destination, &mut chain)).await {
            Ok(Ok(end)) => end,
            Ok(Err(error)) => return exit_stdout(error),
            Err(signal) => return stop(signal),
        };
        if !end.retries() {
            return exit(&end);
        }
        let logged = log(&elo::logging::Event::End {
            destination: &destination,
            reason: &end,
            wait: RECONNECT_WAIT,
        });
        if let Err(error) = logged {
            return exit_stdout(error);
        }
        if let Err(signal) = signals.unless(tokio::time::sleep(RECONNECT_WAIT)).await {
            return stop(signal);
        }
    }
}

fn stop(signal: Signal) -> std::process::ExitCode {
    let _ = log(&elo::logging::Event::Stop { signal: &signal });
    std::process::ExitCode::SUCCESS
}

fn exit(reason: &dyn std::fmt::Display) -> std::process::ExitCode {
    let event = elo::logging::Event::Exit { reason };
    if log(&event).is_err() {
        let _ = event.write(&mut std::io::stderr().lock());
    }
    std::process::ExitCode::FAILURE
}

fn exit_stdout(error: std::io::Error) -> std::process::ExitCode {
    let reason = format_args!("stdout: {error}");
    let event = elo::logging::Event::Exit { reason: &reason };
    let _ = event.write(&mut std::io::stderr().lock());
    std::process::ExitCode::FAILURE
}

fn log(event: &elo::logging::Event<'_>) -> Result<(), std::io::Error> {
    event.write(&mut std::io::stdout().lock())
}

#[derive(Clone, Copy, Debug)]
enum Signal {
    Terminate,
    Interrupt,
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signal::Terminate => write!(f, "SIGTERM"),
            Signal::Interrupt => write!(f, "SIGINT"),
        }
    }
}

struct Signals {
    terminate: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

impl Signals {
    fn new() -> Result<Self, std::io::Error> {
        Ok(Self {
            terminate: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?,
            interrupt: tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?,
        })
    }

    async fn unless<T>(&mut self, work: impl Future<Output = T>) -> Result<T, Signal> {
        let mut work = std::pin::pin!(work);
        std::future::poll_fn(|context| {
            if let std::task::Poll::Ready(signal) = self.poll_next(context) {
                return std::task::Poll::Ready(Err(signal));
            }
            work.as_mut().poll(context).map(Ok)
        })
        .await
    }

    fn poll_next(&mut self, context: &mut std::task::Context<'_>) -> std::task::Poll<Signal> {
        for (handler, signal) in [
            (&mut self.terminate, Signal::Terminate),
            (&mut self.interrupt, Signal::Interrupt),
        ] {
            if let std::task::Poll::Ready(received) = handler.poll_recv(context) {
                assert!(received.is_some(), "{signal}: the signal driver ended");
                return std::task::Poll::Ready(signal);
            }
        }
        std::task::Poll::Pending
    }
}

#[derive(Debug)]
enum End {
    Handshake(elo::net::HandshakeError),
    Run(elo::net::RunError),
}

impl End {
    fn retries(&self) -> bool {
        match self {
            End::Handshake(elo::net::HandshakeError::Salt(_)) => false,
            End::Handshake(
                elo::net::HandshakeError::Lookup(
                    elo::net::LookupError::Failed(_)
                    | elo::net::LookupError::Timeout { .. }
                    | elo::net::LookupError::Empty,
                )
                | elo::net::HandshakeError::Connect {
                    error: elo::net::ConnectError::Io(_) | elo::net::ConnectError::Timeout,
                    ..
                }
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
        }
    }
}

async fn dial(
    destination: &elo::net::Destination,
    chain: &mut elo::chain::Chain,
) -> Result<End, std::io::Error> {
    let (connection, version) = match elo::net::handshake(destination, chain).await {
        Ok(handshake) => handshake,
        Err(error) => return Ok(End::Handshake(error)),
    };
    let address = connection.address();
    log(&elo::logging::Event::Version {
        peer: address,
        version: &version,
    })?;

    let (mut synced, mut tip) = match connection.sync().await {
        Ok(sync) => sync,
        Err(error) => return Ok(End::Run(error)),
    };
    loop {
        log(&elo::logging::Event::Tip {
            peer: address,
            tip: &tip,
        })?;
        (synced, tip) = match synced.next_tip().await {
            Ok(next) => next,
            Err(error) => return Ok(End::Run(error)),
        };
    }
}

fn parse(args: &[std::ffi::OsString]) -> Option<(elo::chainparams::Network, elo::net::Source)> {
    let (network, peer) = match args {
        [network] => (network, None),
        [network, peer] => (network, Some(peer)),
        _ => return None,
    };
    let network = match network.to_str()? {
        "mainnet" => elo::chainparams::Network::Mainnet,
        "testnet4" => elo::chainparams::Network::Testnet4,
        "signet" => elo::chainparams::Network::Signet,
        "regtest" => elo::chainparams::Network::Regtest,
        _ => return None,
    };
    let source = match peer {
        Some(peer) => elo::net::Source::Destination(destination(peer.to_str()?, network)?),
        None => elo::net::Source::Seeds(elo::net::Seeds::new(network)?),
    };
    Some((network, source))
}

fn destination(peer: &str, network: elo::chainparams::Network) -> Option<elo::net::Destination> {
    let destination = if let Some(address) = address(peer, network.default_port()) {
        elo::net::Destination::Address(elo::net::PeerAddress::new(address)?)
    } else {
        let (host, port) = match peer.split_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (peer, network.default_port()),
        };
        elo::net::Destination::Name {
            name: elo::net::Name::new(host)?,
            port,
        }
    };
    Some(destination)
}

fn address(peer: &str, default_port: std::num::NonZeroU16) -> Option<std::net::SocketAddr> {
    if let Ok(address) = peer.parse() {
        return Some(address);
    }
    let ip = match peer.strip_prefix('[').and_then(|ip| ip.strip_suffix(']')) {
        Some(ip) => std::net::IpAddr::V6(ip.parse().ok()?),
        None => std::net::IpAddr::V4(peer.parse().ok()?),
    };
    Some(std::net::SocketAddr::from((ip, default_port.get())))
}

#[cfg(test)]
mod tests {
    fn parse(args: &[&str]) -> Option<(elo::chainparams::Network, elo::net::Source)> {
        let args: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
        super::parse(&args)
    }

    #[test]
    fn a_fault_of_this_host_ends_elo_and_a_failed_connect_or_lookup_retries() {
        for (end, retries) in [
            (
                super::End::Handshake(elo::net::HandshakeError::Salt(std::io::Error::other(
                    "salt",
                ))),
                false,
            ),
            (
                super::End::Handshake(elo::net::HandshakeError::Connect {
                    address: std::net::SocketAddr::from(([127, 0, 0, 1], 1)),
                    addresses_count: 1,
                    error: elo::net::ConnectError::Timeout,
                }),
                true,
            ),
            (
                super::End::Handshake(elo::net::HandshakeError::Lookup(
                    elo::net::LookupError::Timeout {
                        host: String::from("localhost"),
                    },
                )),
                true,
            ),
        ] {
            assert_eq!(end.retries(), retries, "{end}");
        }
    }

    #[test]
    fn a_fault_of_this_host_exits_with_1() {
        let code = super::exit(&"a test of the exit code");
        assert_eq!(
            format!("{code:?}"),
            format!("{:?}", std::process::ExitCode::FAILURE)
        );
    }

    #[test]
    fn each_network_has_a_name_and_a_default_port() {
        for (name, network, port) in [
            ("mainnet", elo::chainparams::Network::Mainnet, 8333),
            ("testnet4", elo::chainparams::Network::Testnet4, 48333),
            ("signet", elo::chainparams::Network::Signet, 38333),
            ("regtest", elo::chainparams::Network::Regtest, 18444),
        ] {
            let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let destination =
                elo::net::Destination::Address(elo::net::PeerAddress::new(address).unwrap());
            assert_eq!(
                parse(&[name, "127.0.0.1"]),
                Some((network, elo::net::Source::Destination(destination))),
                "{name}"
            );
            let destination = elo::net::Destination::Name {
                name: elo::net::Name::new("localhost").unwrap(),
                port: std::num::NonZeroU16::new(port).unwrap(),
            };
            assert_eq!(
                parse(&[name, "localhost"]),
                Some((network, elo::net::Source::Destination(destination))),
                "{name}"
            );
        }
    }

    #[test]
    fn peer_is_an_ip_literal_or_a_name_with_an_optional_port() {
        let localhost_v6 = std::net::Ipv6Addr::LOCALHOST;
        let address = |address| {
            let address = elo::net::PeerAddress::new(address).unwrap();
            Some(elo::net::Destination::Address(address))
        };
        let name = |host: &str, port| {
            Some(elo::net::Destination::Name {
                name: elo::net::Name::new(host).unwrap(),
                port: std::num::NonZeroU16::new(port).unwrap(),
            })
        };
        let label = "a".repeat(63);
        let long = [label.as_str(); 4].join(".");
        let longest = &long[..253];
        for (peer, expected) in [
            (
                "127.0.0.1:1",
                address(std::net::SocketAddr::from(([127, 0, 0, 1], 1))),
            ),
            (
                "[::1]",
                address(std::net::SocketAddr::from((localhost_v6, 18444))),
            ),
            (
                "[::1]:1",
                address(std::net::SocketAddr::from((localhost_v6, 1))),
            ),
            ("::1:8333", None),
            ("127.0.0.1:0", None),
            ("0.0.0.0", None),
            ("[::]", None),
            ("[::ffff:0.0.0.0]", None),
            ("[localhost]", None),
            ("localhost", name("localhost", 18444)),
            ("localhost:1", name("localhost", 1)),
            ("seed-1.example.org", name("seed-1.example.org", 18444)),
            ("x9.Seed.example", name("x9.Seed.example", 18444)),
            ("1a", name("1a", 18444)),
            (longest, name(longest, 18444)),
            (&long[..254], None),
            (&format!("{label}a"), None),
            ("localhost:0", None),
            ("localhost:65536", None),
            ("localhost:", None),
            ("localhost.", name("localhost.", 18444)),
            ("localhost..", None),
            (".", None),
            (&format!("{longest}."), name(&format!("{longest}."), 18444)),
            (".localhost", None),
            ("local..host", None),
            ("-localhost", None),
            ("localhost-", None),
            ("local_host", None),
            ("local host", None),
            ("127.1", None),
            ("999.0.0.1", None),
            ("0x7f000001", None),
            ("0X7F000001", None),
            ("127.0x1", None),
            ("0x0", None),
            ("0x7f000001.", None),
            ("0x7g", name("0x7g", 18444)),
            ("0x7f.example", name("0x7f.example", 18444)),
            ("", None),
        ] {
            let parsed = parse(&["regtest", peer]).map(|(_, source)| source);
            assert_eq!(
                parsed,
                expected.map(elo::net::Source::Destination),
                "{peer}"
            );
        }
    }

    #[test]
    fn no_peer_is_the_seeds_of_the_network() {
        for (name, network) in [
            ("mainnet", elo::chainparams::Network::Mainnet),
            ("testnet4", elo::chainparams::Network::Testnet4),
            ("signet", elo::chainparams::Network::Signet),
        ] {
            let seeds = elo::net::Seeds::new(network).unwrap();
            assert_eq!(
                parse(&[name]),
                Some((network, elo::net::Source::Seeds(seeds))),
                "{name}"
            );
        }
    }

    #[test]
    fn usage_is_a_network_name_and_a_peer_and_regtest_needs_the_peer() {
        for args in [
            &[][..],
            &["regtest"],
            &["testnet3"],
            &["testnet3", "127.0.0.1"],
            &["regtest", "127.0.0.1", "127.0.0.1"],
        ] {
            assert_eq!(parse(args), None, "{args:?}");
        }
    }
}
