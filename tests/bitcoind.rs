//! The handshake against a real `bitcoind -regtest`. `BITCOIND` holds the path of the binary.

/// How long `bitcoind` may take to listen.
const LISTEN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// A `bitcoind -regtest` in its own datadir. The drop kills it and removes the datadir.
struct Bitcoind {
    child: std::process::Child,
    datadir: std::path::PathBuf,
    peer: std::net::SocketAddr,
}

impl Bitcoind {
    fn start() -> Self {
        let path = std::env::var_os("BITCOIND").expect("BITCOIND holds the path of bitcoind");
        // A port that was free a moment ago.
        let peer = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let datadir = std::env::temp_dir().join(format!(
            "elo-bitcoind-{}-{}",
            std::process::id(),
            peer.port()
        ));
        std::fs::create_dir(&datadir).unwrap();

        let child = std::process::Command::new(path)
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-bind={peer}"))
            .arg("-listenonion=0")
            .arg("-server=0")
            .arg("-printtoconsole=0")
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut bitcoind = Self {
            child,
            datadir,
            peer,
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
        if let Err(error) = std::fs::remove_dir_all(&self.datadir) {
            eprintln!("remove {}: {error}", self.datadir.display());
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
