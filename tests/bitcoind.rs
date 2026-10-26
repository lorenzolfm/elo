//! The handshake against a real `bitcoind -regtest`. `BITCOIND` holds the path of the binary.

/// How long `bitcoind` may take to listen.
const LISTEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

/// A `bitcoind -regtest` in its own datadir. The drop kills it. Then the fields drop, so the
/// datadir goes after the kill.
struct Bitcoind {
    child: std::process::Child,
    peer: std::net::SocketAddr,
    /// Only its drop reads it.
    _datadir: TempDir,
}

impl Bitcoind {
    fn start() -> Self {
        let path = std::env::var_os("BITCOIND").expect("BITCOIND holds the path of bitcoind");
        // A port that was free a moment ago.
        let peer = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
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
            .arg("-server=0")
            .arg("-printtoconsole=0")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut bitcoind = Self {
            child,
            peer,
            _datadir: datadir,
        };
        bitcoind.wait_until_listening();
        bitcoind
    }

    /// `bitcoind` is ready when a TCP connect succeeds.
    fn wait_until_listening(&mut self) {
        let start = std::time::Instant::now();
        while std::net::TcpStream::connect(self.peer).is_err() {
            assert_eq!(self.child.try_wait().unwrap(), None, "bitcoind exited");
            assert!(start.elapsed() < LISTEN_TIMEOUT, "bitcoind does not listen");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        // A panic in a drop during a panic aborts the tests, so a failure is only printed.
        if let Err(error) = self.child.kill() {
            eprintln!("kill bitcoind: {error}");
        }
        if let Err(error) = self.child.wait() {
            eprintln!("wait for bitcoind: {error}");
        }
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
    let version = runtime
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
