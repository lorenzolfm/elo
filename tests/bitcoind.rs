//! elo against a real `bitcoind -regtest`. `BITCOIND` and `BITCOIN_CLI` hold the paths of the
//! binaries.

/// How long `bitcoind` may take to listen, and its RPC server to start.
const LISTEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `bitcoind` may take to show a `pingtime` for elo.
const PINGTIME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A directory that the drop removes.
struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        // A panic in a drop during a panic aborts the tests, so a failure is only printed.
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("remove {}: {error}", self.0.display());
        }
    }
}

/// A child process that the drop kills.
struct Process(std::process::Child);

impl Drop for Process {
    fn drop(&mut self) {
        // A panic in a drop during a panic aborts the tests, so a failure is only printed.
        if let Err(error) = self.0.kill() {
            eprintln!("kill process {}: {error}", self.0.id());
        }
        if let Err(error) = self.0.wait() {
            eprintln!("wait for process {}: {error}", self.0.id());
        }
    }
}

/// A `bitcoind -regtest` in its own datadir, with RPC on. The fields drop in order, so the
/// datadir goes after the kill.
struct Bitcoind {
    process: Process,
    peer: std::net::SocketAddr,
    rpc_port: u16,
    datadir: TempDir,
}

impl Bitcoind {
    fn start() -> Self {
        let path = std::env::var_os("BITCOIND").expect("BITCOIND holds the path of bitcoind");
        // Two ports that were free a moment ago. Both listeners are open at the same time, so
        // the ports differ.
        let peer_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = peer_listener.local_addr().unwrap();
        let rpc_port = rpc_listener.local_addr().unwrap().port();
        drop(peer_listener);
        drop(rpc_listener);

        let datadir = TempDir(std::env::temp_dir().join(format!(
            "elo-bitcoind-{}-{}",
            std::process::id(),
            peer.port()
        )));
        std::fs::create_dir(&datadir.0).unwrap();

        let child = std::process::Command::new(path)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.0.display()))
            .arg(format!("-bind={peer}"))
            .arg("-listenonion=0")
            // bitcoind asks the router to map its port by default. A test must not.
            .arg("-natpmp=0")
            // RPC uses cookie auth. The cookie is in the datadir, where `bitcoin-cli` reads it.
            .arg("-server=1")
            .arg(format!("-rpcport={rpc_port}"))
            .arg("-printtoconsole=0")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut bitcoind = Self {
            process: Process(child),
            peer,
            rpc_port,
            datadir,
        };
        bitcoind.wait_until_listening();
        bitcoind
    }

    /// `bitcoind` is ready when a TCP connect succeeds.
    fn wait_until_listening(&mut self) {
        let start = std::time::Instant::now();
        while std::net::TcpStream::connect(self.peer).is_err() {
            assert_eq!(self.process.0.try_wait().unwrap(), None, "bitcoind exited");
            assert!(start.elapsed() < LISTEN_TIMEOUT, "bitcoind does not listen");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Runs the RPC `command` with `bitcoin-cli` and returns its output. `-rpcwait` waits until
    /// the RPC server is up and out of its warmup.
    fn cli(&self, command: &str) -> String {
        let path =
            std::env::var_os("BITCOIN_CLI").expect("BITCOIN_CLI holds the path of bitcoin-cli");
        let output = std::process::Command::new(path)
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.0.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg("-rpcwait")
            .arg(format!("-rpcwaittimeout={}", LISTEN_TIMEOUT.as_secs()))
            .arg(command)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "bitcoin-cli {command}: {stderr}");
        String::from_utf8(output.stdout).unwrap()
    }
}

#[test]
fn handshake_with_bitcoind_returns_its_version() {
    let bitcoind = Bitcoind::start();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let (_connection, version) = runtime
        .block_on(elo::net::handshake(
            elo::chainparams::Network::Regtest,
            bitcoind.peer,
        ))
        .unwrap();

    assert_eq!(version.version(), 70016);
    let user_agent = version.user_agent();
    assert!(
        user_agent.as_bytes().starts_with(b"/Satoshi:31.1.0/"),
        "{user_agent}"
    );
    assert_eq!(version.start_height(), 0);
}

#[test]
fn stdout_error_after_the_handshake_exits_with_1() {
    let bitcoind = Bitcoind::start();
    // The pipe has no reader, so the first write to stdout fails.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
        .arg("regtest")
        .arg(bitcoind.peer.to_string())
        .stdout(writer)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    // A failed handshake also exits with 1.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("elo: stdout: "), "{stderr}");
}

#[test]
fn ping_from_bitcoind_gets_a_pong() {
    let bitcoind = Bitcoind::start();
    // elo does not exit while the connection is up, so the drop kills it.
    let mut elo = Process(
        std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("regtest")
            .arg(bitcoind.peer.to_string())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );

    // bitcoind pings right after the handshake. It shows a `pingtime` only after a `pong` with
    // the nonce of its `ping`. elo is its only peer, so a match on the text is enough.
    let start = std::time::Instant::now();
    while !bitcoind.cli("getpeerinfo").contains("\"pingtime\"") {
        assert_eq!(elo.0.try_wait().unwrap(), None, "elo exited");
        assert!(
            start.elapsed() < PINGTIME_TIMEOUT,
            "bitcoind shows no pingtime"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
