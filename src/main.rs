//! `elo <network> <host>[:port]`: dials one peer, does the handshake, and logs the peer's
//! `version`. The host is an IP address or a name. Before each dial, elo looks up the name, and
//! dials its addresses in a random order until one takes the connect. Then it syncs the header
//! chain from the peer and logs the tip. It asks the peer to announce each new header, takes it on
//! the tip, and logs the tip when it moves. It pings the peer and answers its `ping` messages
//! until the connection ends. Then it waits and dials the peer again. The chain stays in memory,
//! so the next connection syncs from its tip. SIGTERM and SIGINT stop it at any of these steps.
//! Each step writes a line of `elo::logging` to stdout.

const USAGE: &str = "usage: elo <mainnet|testnet4|signet|regtest> <ip|name>[:port]";

/// The exit code for bad usage. A stop by a signal exits with 0, and a panic with 101. Every
/// other exit is 1, because only a fault of this host ends elo.
const EXIT_USAGE: u8 = 2;

/// How long elo waits after a connection ends before it dials the peer again. So a peer that is
/// down, or that ends each connection at once, gets at most one try in each wait.
const RECONNECT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn main() -> std::process::ExitCode {
    // First of all, so each panic writes a `panic` line, and not the text of the default hook,
    // which is not a line of the log. A panic in this hook aborts elo.
    std::panic::set_hook(Box::new(|info| {
        let event = elo::logging::Event::Panic { reason: info };
        if log(&event).is_err() {
            let _ = event.write(&mut std::io::stderr().lock());
        }
    }));

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let Some((network, destination)) = parse(&args) else {
        eprintln!("{USAGE}");
        return std::process::ExitCode::from(EXIT_USAGE);
    };

    // The I/O driver also gives the signals.
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => return exit(&format_args!("runtime: {error}")),
    };
    let code = runtime.block_on(run(network, destination));
    // A lookup runs on a blocking thread of the runtime, and a stop or a lookup timeout does not
    // end it. The drop of the runtime would wait for that thread, so the runtime does not wait.
    runtime.shutdown_background();
    code
}

/// Dials `destination` again after each end that retries, until a signal or an end that exits.
async fn run(
    network: elo::chainparams::Network,
    destination: elo::net::Destination,
) -> std::process::ExitCode {
    // Before the first dial, so a signal from here on stops elo. As PID 1 in a container, a
    // process with no handler never sees a SIGTERM: the kernel drops it, and the stop ends in
    // SIGKILL after its timeout.
    let mut signals = match Signals::new() {
        Ok(signals) => signals,
        Err(error) => return exit(&format_args!("signals: {error}")),
    };
    // One chain for each connection, so a connection ends with the headers of the last one, and
    // a sync gets only the headers after its tip.
    let mut chain = elo::chain::Chain::new(network);
    // The loop has no count bound, because elo keeps its one peer for as long as it runs. Only
    // a signal or an end that a new connection cannot fix gets out.
    loop {
        // The drop of the connection closes its socket. elo keeps nothing on disk, so the stop
        // has nothing else to finish.
        let end = match signals.unless(dial(&destination, &mut chain)).await {
            Ok(Ok(end)) => end,
            Ok(Err(error)) => return exit_stdout(error),
            Err(signal) => return stop(signal),
        };
        // The event says if elo dials again, so a reader of the log does not need the list of
        // ends that exit.
        if !end.retries() {
            return exit(&end);
        }
        // The destination of the command line, and not the address of the connection: the next
        // dial looks up a name again.
        let logged = log(&elo::logging::Event::End {
            peer: &destination,
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

/// Logs the `signal` that stops elo, and gives the exit code of a stop: 0. A failed write does
/// not change the exit code, because the signal asked for the stop.
fn stop(signal: Signal) -> std::process::ExitCode {
    let _ = log(&elo::logging::Event::Stop { signal: &signal });
    std::process::ExitCode::SUCCESS
}

/// Logs the fault of this host that ends elo, and gives the exit code of a fault: 1. When stdout
/// fails, the line goes to stderr, so a fault of stdout has a line too. Nothing is left to tell of
/// a fault of stderr.
fn exit(reason: &dyn std::fmt::Display) -> std::process::ExitCode {
    let event = elo::logging::Event::Exit { reason };
    if log(&event).is_err() {
        let _ = event.write(&mut std::io::stderr().lock());
    }
    std::process::ExitCode::FAILURE
}

/// Logs a failed write to stdout, which ends elo, to stderr only, and gives the exit code of a
/// fault: 1. The write that failed can leave part of its line on stdout, and a second write there
/// would join the `exit` line to that part.
fn exit_stdout(error: std::io::Error) -> std::process::ExitCode {
    let reason = format_args!("stdout: {error}");
    let event = elo::logging::Event::Exit { reason: &reason };
    let _ = event.write(&mut std::io::stderr().lock());
    std::process::ExitCode::FAILURE
}

/// Writes the line of `event` to stdout. `println!` panics when stdout fails, for example on a
/// full disk or a closed pipe.
fn log(event: &elo::logging::Event<'_>) -> Result<(), std::io::Error> {
    event.write(&mut std::io::stdout().lock())
}

/// A signal that stops elo.
#[derive(Clone, Copy, Debug)]
enum Signal {
    /// SIGTERM, from a container stop or a service manager.
    Terminate,
    /// SIGINT, from Ctrl-C.
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

/// The handlers of the signals that stop elo. From their creation, these signals no longer end
/// the process by their default action, and each one waits here until `unless` takes it.
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

    /// The output of `work`, or the first signal if it comes before. A signal wins over an
    /// output that is ready at the same time. A signal that came before this call is taken
    /// first.
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

    /// The next signal. When none came, each handler holds the waker of `context`.
    fn poll_next(&mut self, context: &mut std::task::Context<'_>) -> std::task::Poll<Signal> {
        for (handler, signal) in [
            (&mut self.terminate, Signal::Terminate),
            (&mut self.interrupt, Signal::Interrupt),
        ] {
            if let std::task::Poll::Ready(received) = handler.poll_recv(context) {
                // `None` is a runtime with no signal driver, which cannot be while this runs in
                // it. As a signal, it would come again at each poll: a stop that no one sent.
                assert!(received.is_some(), "{signal}: the signal driver ended");
                return std::task::Poll::Ready(signal);
            }
        }
        std::task::Poll::Pending
    }
}

/// How one connection ended. A failed write to stdout is no end of a connection: it ends elo.
#[derive(Debug)]
enum End {
    /// The lookup, the connect or the handshake failed.
    Handshake(elo::net::HandshakeError),
    /// The connection ended in the sync or after it.
    Run(elo::net::RunError),
}

impl End {
    /// Whether elo dials the peer again. Each end that the peer or the network causes retries,
    /// also a peer that sent bytes that elo refuses: the user named that peer. A fault of this
    /// host that a new connection cannot fix does not. The match names each variant, so
    /// a new error does not compile until it has a side.
    fn retries(&self) -> bool {
        match self {
            End::Handshake(elo::net::HandshakeError::Salt(_)) => false,
            End::Handshake(
                elo::net::HandshakeError::Lookup(
                    elo::net::LookupError::Failed(_)
                    | elo::net::LookupError::Timeout
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

/// Dials `destination`, does the handshake and logs the `version` of the peer. Then syncs
/// `chain` and logs its tip, and logs it again each time an announcement of the peer moves it,
/// until the connection ends. `Err` is a failed write to stdout.
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
    // The loop has no count bound, because the peer announces headers for as long as it is
    // connected. Only the end of the connection or a fault of stdout gets out.
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

/// The args after the program name. `None` is bad usage.
///
/// An IPv6 address needs brackets even without a port, because `::1:8333` is an IPv6 address
/// and not `::1` with a port.
fn parse(
    args: &[std::ffi::OsString],
) -> Option<(elo::chainparams::Network, elo::net::Destination)> {
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
    let destination = if let Some(address) = address(peer, network.default_port()) {
        // Port 0, `0.0.0.0`, `[::]` and `[::ffff:0.0.0.0]` name no peer.
        if address.port() == 0 || address.ip().to_canonical().is_unspecified() {
            return None;
        }
        elo::net::Destination::Address(address)
    } else {
        let (host, port) = match peer.split_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (peer, network.default_port()),
        };
        if port == 0 {
            return None;
        }
        elo::net::Destination::Name {
            name: elo::net::Name::new(host)?,
            port,
        }
    };
    Some((network, destination))
}

/// `peer` as an IP address with an optional port, or `None` if it is no IP address.
fn address(peer: &str, default_port: u16) -> Option<std::net::SocketAddr> {
    if let Ok(address) = peer.parse() {
        return Some(address);
    }
    let ip = match peer.strip_prefix('[').and_then(|ip| ip.strip_suffix(']')) {
        Some(ip) => std::net::IpAddr::V6(ip.parse().ok()?),
        None => std::net::IpAddr::V4(peer.parse().ok()?),
    };
    Some(std::net::SocketAddr::from((ip, default_port)))
}

#[cfg(test)]
mod tests {
    fn parse(args: &[&str]) -> Option<(elo::chainparams::Network, elo::net::Destination)> {
        let args: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
        super::parse(&args)
    }

    // The L3 tests also hold a closed connection, which retries, and a stdout fault, which
    // exits. A stdout fault is no `End`, so it has no row here.
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
                    elo::net::LookupError::Timeout,
                )),
                true,
            ),
        ] {
            assert_eq!(end.retries(), retries, "{end}");
        }
    }

    // An L3 test cannot make the runtime, the signal handlers or `/dev/urandom` fail, so this
    // test holds the exit code of a fault of this host. It writes an `exit` line to stdout.
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
            let destination = elo::net::Destination::Address(address);
            assert_eq!(
                parse(&[name, "127.0.0.1"]),
                Some((network, destination)),
                "{name}"
            );
            let destination = elo::net::Destination::Name {
                name: elo::net::Name::new("localhost").unwrap(),
                port,
            };
            assert_eq!(
                parse(&[name, "localhost"]),
                Some((network, destination)),
                "{name}"
            );
        }
    }

    #[test]
    fn peer_is_an_ip_literal_or_a_name_with_an_optional_port() {
        let localhost_v6 = std::net::Ipv6Addr::LOCALHOST;
        let address = |address| Some(elo::net::Destination::Address(address));
        let name = |host: &str, port| {
            Some(elo::net::Destination::Name {
                name: elo::net::Name::new(host).unwrap(),
                port,
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
            let parsed = parse(&["regtest", peer]).map(|(_, destination)| destination);
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
