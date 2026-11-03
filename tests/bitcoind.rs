//! elo against a real `bitcoind -regtest`. `BITCOIND` and `BITCOIN_CLI` hold the paths of the
//! binaries.

/// How long `bitcoind` may take to answer RPC after its warmup.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `bitcoin-cli` may wait for the reply to one request.
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `getpeerinfo` may take to show what a test waits for.
const PEER_INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to exit after `bitcoind` closes the connection.
const EXIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to sync the headers of `bitcoind` and print its tip.
const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
        // The tests run in parallel, and the OS can give the same free port to two of them. So
        // each test holds this lock from the pick of its ports until its `bitcoind` listens on
        // them. The OS does not give a port with a listener again.
        let lock = std::fs::File::create(std::env::temp_dir().join("elo-bitcoind.lock")).unwrap();
        lock.lock().unwrap();

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
            // `-rpcbind` needs `-rpcallowip`, which adds nothing: loopback is always allowed.
            // With one RPC address, a port that another process took makes `bitcoind` exit, as
            // a taken P2P port does.
            .arg("-rpcallowip=127.0.0.1")
            .arg("-rpcbind=127.0.0.1")
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
        bitcoind.wait_until_ready();
        drop(lock);
        bitcoind
    }

    /// Waits until an RPC call with the cookie in our datadir succeeds. Each call fails until
    /// the warmup ends, and the warmup ends only after the P2P bind. So a success proves that
    /// both ports belong to this `bitcoind`, and not to another process that took a port first.
    fn wait_until_ready(&mut self) {
        let start = std::time::Instant::now();
        while !self.rpc(&["uptime"]).status.success() {
            assert_eq!(self.process.0.try_wait().unwrap(), None, "bitcoind exited");
            assert!(start.elapsed() < READY_TIMEOUT, "bitcoind is not ready");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Runs the RPC `command` with `bitcoin-cli` and returns its output.
    fn cli(&self, command: &[&str]) -> String {
        let output = self.rpc(command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "bitcoin-cli {command:?}: {stderr}");
        String::from_utf8(output.stdout).unwrap()
    }

    /// One `bitcoin-cli` request, with no retry. It waits at most `RPC_TIMEOUT` for the reply.
    fn rpc(&self, command: &[&str]) -> std::process::Output {
        let path =
            std::env::var_os("BITCOIN_CLI").expect("BITCOIN_CLI holds the path of bitcoin-cli");
        std::process::Command::new(path)
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.0.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-rpcclienttimeout={}", RPC_TIMEOUT.as_secs()))
            .args(command)
            .output()
            .unwrap()
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
    while !bitcoind.cli(&["getpeerinfo"]).contains("\"pingtime\"") {
        assert_eq!(elo.0.try_wait().unwrap(), None, "elo exited");
        assert!(
            start.elapsed() < PEER_INFO_TIMEOUT,
            "bitcoind shows no pingtime"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[test]
fn our_ping_gets_a_pong_from_bitcoind() {
    let bitcoind = Bitcoind::start();
    let mut elo = Process(
        std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("regtest")
            .arg(bitcoind.peer.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );

    // elo pings right after the handshake, and bitcoind sends a `pong` only to a `ping`. The
    // wait also needs our `pong` to the `ping` of bitcoind, the last message that elo sends. A
    // close with bytes that bitcoind has not read is a reset, and not the end of the stream.
    let start = std::time::Instant::now();
    loop {
        let peer_info = bitcoind.cli(&["getpeerinfo"]);
        let received = object_text(&peer_info, "bytesrecv_per_msg");
        let sent = object_text(&peer_info, "bytessent_per_msg");
        if received.contains("\"ping\"")
            && received.contains("\"pong\"")
            && sent.contains("\"pong\"")
        {
            break;
        }
        if let Some(status) = elo.0.try_wait().unwrap() {
            panic!("elo exited with {status}: {}", stderr(&mut elo.0));
        }
        assert!(
            start.elapsed() < PEER_INFO_TIMEOUT,
            "bitcoind shows no pong for our ping: {peer_info}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // elo is the only peer of bitcoind, so it is node 0. TCP delivers the `pong` before the
    // close, so elo checks the `pong` first. A `pong` that elo refuses ends with its reason,
    // and so does a second `pong` for a stray `ping`.
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = elo.0.try_wait().unwrap() {
            break status;
        }
        assert!(start.elapsed() < EXIT_TIMEOUT, "elo did not exit");
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    assert_eq!(status.code(), Some(1));
    assert_eq!(stderr(&mut elo.0), "elo: the peer closed the connection\n");
}

#[test]
fn sync_from_bitcoind_prints_its_tip() {
    let bitcoind = Bitcoind::start();
    // 2001 blocks: a full batch of 2000 headers, our next `getheaders`, and a batch of 1.
    bitcoind.cli(&["generatetodescriptor", "2001", "raw(51)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let mut elo = Process(
        std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("regtest")
            .arg(bitcoind.peer.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );

    // elo stays connected after the sync, so its stdout does not end. A thread reads each line,
    // and the test waits for the `tip` line with a timeout.
    let stdout = elo.0.stdout.take().unwrap();
    let (lines, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(stdout)) {
            if lines.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    let deadline = std::time::Instant::now() + SYNC_TIMEOUT;
    let tip = loop {
        let timeout = deadline.saturating_duration_since(std::time::Instant::now());
        match receiver.recv_timeout(timeout) {
            Ok(line) => {
                if let Some(tip) = line.strip_prefix("tip ") {
                    break tip.to_owned();
                }
            }
            // The thread ends only when stdout ends, so elo exited.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("elo exited: {}", stderr(&mut elo.0))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("elo printed no tip within {} s", SYNC_TIMEOUT.as_secs())
            }
        }
    };
    assert_eq!(tip, format!("2001 {}", best.trim_end()));
}

/// What `child` wrote to its stderr pipe. Call it only after the exit, or it blocks.
fn stderr(child: &mut std::process::Child) -> String {
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.stderr.take().unwrap(), &mut stderr).unwrap();
    stderr
}

/// The text of the `field` object in `getpeerinfo`, or nothing before elo connects. elo is the
/// only peer, and the object holds no other object, so it ends at its first `}`.
fn object_text<'a>(peer_info: &'a str, field: &str) -> &'a str {
    let key = format!("\"{field}\": {{");
    let Some((_, rest)) = peer_info.split_once(&key) else {
        return "";
    };
    rest.split_once('}').unwrap().0
}
