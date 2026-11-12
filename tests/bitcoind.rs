//! elo against a real `bitcoind -regtest`. `BITCOIND` and `BITCOIN_CLI` hold the paths of the
//! binaries.

/// How long `bitcoind` may take to answer RPC after its warmup.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `bitcoin-cli` may wait for the reply to one request.
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `getpeerinfo` may take to show what a test waits for.
const PEER_INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to print the end of a connection: after `bitcoind` closes it, or after
/// the start when the first write to stdout fails.
const END_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to do the handshake again after the end of a connection. It waits 5 s
/// before it dials again.
const RECONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

        // In the target directory, because nextest stops a test with a signal, and then no drop
        // runs. A mutant run removes each target directory, and nothing removes the temp directory
        // of `nix develop`. The lock stays in that temp directory: the two jobs of a mutant run
        // have different target directories, and their tests also take ports.
        let datadir = TempDir(
            std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
                "elo-bitcoind-{}-{}",
                std::process::id(),
                peer.port()
            )),
        );
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
    let mut chain = elo::chain::Chain::new(elo::chainparams::Network::Regtest);
    let (_connection, version) = runtime
        .block_on(elo::net::handshake(bitcoind.peer, &mut chain))
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
    let mut elo = Process(
        std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("regtest")
            .arg(bitcoind.peer.to_string())
            .stdout(writer)
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stderr = lines(elo.0.stderr.take().unwrap());

    // The test waits for the line with a deadline, and not for the exit: an elo that dials
    // again does not exit, and the drop kills it.
    let end = stderr
        .recv_timeout(END_TIMEOUT)
        .expect("elo printed no end line");
    // An end that the peer causes dials again, so the exit comes from stdout.
    assert!(end.starts_with("elo: stdout: "), "{end}");
    // The line of an end that exits does not say that elo dials again.
    assert!(!end.contains("dial again"), "{end}");
    assert_eq!(elo.0.wait().unwrap().code(), Some(1));
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
    let elo = Elo::start(&bitcoind);

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
        // An early end does not exit elo: it dials again, and then node 0 is gone. So the test
        // fails here, with the reason of elo, and not on `disconnectnode`.
        let ended = elo.stderr_so_far();
        assert!(ended.is_empty(), "elo ended the connection: {ended}");
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
    let end = elo.line(&elo.stderr, "elo: ", END_TIMEOUT);
    assert_eq!(end, "the peer closed the connection; dial again in 5 s");
}

#[test]
fn closed_connection_gets_a_new_handshake_and_sync() {
    let bitcoind = Bitcoind::start();
    let elo = Elo::start(&bitcoind);
    let tip = elo.line(&elo.stdout, "tip ", SYNC_TIMEOUT);

    // elo is the only peer of bitcoind, so it is node 0. The test does not check the reason of
    // the end: bitcoind can close with bytes from elo that it has not read, and then elo sees a
    // reset.
    let close = std::time::Instant::now();
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.line(&elo.stderr, "elo: ", END_TIMEOUT);
    let version = elo.line(&elo.stdout, "version ", RECONNECT_TIMEOUT);
    assert_eq!(version, "70016");
    // The close comes after `close`, and the wait of 5 s comes after the close.
    let wait = close.elapsed();
    assert!(wait >= std::time::Duration::from_secs(5), "{wait:?}");
    assert_eq!(elo.line(&elo.stdout, "tip ", SYNC_TIMEOUT), tip);
}

#[test]
fn next_connection_syncs_from_our_tip_and_a_tip_off_the_chain_of_bitcoind_starts_again() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let elo = Elo::start(&bitcoind);
    let first = bitcoind.cli(&["getbestblockhash"]);
    let tip = elo.line(&elo.stdout, "tip ", SYNC_TIMEOUT);
    assert!(
        tip.starts_with(&format!("1 {} ", first.trim_end())),
        "{tip}"
    );

    // bitcoind leaves our tip for a branch of 2 blocks. The branch pays another script, because
    // the same script in the same second makes the block that bitcoind marked invalid. elo is the
    // only peer of bitcoind, so it is node 0.
    bitcoind.cli(&["invalidateblock", first.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "2", "raw(52)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);

    // The next connection asks for the headers after our tip. bitcoind does not have it on its
    // chain, so it sends its headers after genesis, and elo refuses them. The connection after it
    // syncs from genesis, and gets the branch. A connection that synced from genesis at once would
    // take the branch with no refusal.
    let tip = elo.line(&elo.stdout, "tip ", RECONNECT_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(tip, format!("2 {} {chain_work}", best.trim_end()));
    // The refusal came 5 s before the tip, so its line is there. The test does not check the
    // reason of the first end: bitcoind can close with bytes from elo that it has not read, and
    // then elo sees a reset.
    let ends = elo.stderr_so_far();
    let ends: Vec<&str> = ends.lines().collect();
    assert_eq!(ends.len(), 2, "{ends:?}");
    assert_eq!(
        ends[1],
        "elo: peer: our tip is not on their chain, so our chain starts again from genesis; dial again in 5 s"
    );
}

#[test]
fn sync_from_bitcoind_prints_its_tip() {
    let bitcoind = Bitcoind::start();
    // 2001 blocks: a full batch of 2000 headers, our next `getheaders`, and a batch of 1.
    bitcoind.cli(&["generatetodescriptor", "2001", "raw(51)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let elo = Elo::start(&bitcoind);
    let tip = elo.line(&elo.stdout, "tip ", SYNC_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(tip, format!("2001 {} {chain_work}", best.trim_end()));
}

/// elo connected to a `bitcoind`, with the lines of its stdout and its stderr. elo does not
/// exit while it can dial the peer, so the drop kills it.
struct Elo {
    // No test reads it: it is here for its drop.
    _process: Process,
    stdout: std::sync::mpsc::Receiver<String>,
    stderr: std::sync::mpsc::Receiver<String>,
}

impl Elo {
    fn start(bitcoind: &Bitcoind) -> Self {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("regtest")
            .arg(bitcoind.peer.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = lines(child.stdout.take().unwrap());
        let stderr = lines(child.stderr.take().unwrap());
        Self {
            _process: Process(child),
            stdout,
            stderr,
        }
    }

    /// The rest of the next line from `lines` that starts with `prefix`. It skips the lines
    /// before it, and panics if none comes within `timeout`.
    fn line(
        &self,
        lines: &std::sync::mpsc::Receiver<String>,
        prefix: &str,
        timeout: std::time::Duration,
    ) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match lines.recv_timeout(left) {
                Ok(line) => {
                    if let Some(rest) = line.strip_prefix(prefix) {
                        return rest.to_owned();
                    }
                }
                // The thread ends only when the pipe ends, so elo exited, and its stderr ends.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let stderr = self.stderr.iter().collect::<Vec<_>>().join("\n");
                    panic!("elo exited: {stderr}")
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                    "elo printed no {prefix:?} line within {} s: {}",
                    timeout.as_secs(),
                    self.stderr_so_far()
                ),
            }
        }
    }

    /// The lines of stderr that no `line` call took yet.
    fn stderr_so_far(&self) -> String {
        self.stderr.try_iter().collect::<Vec<_>>().join("\n")
    }
}

/// Each line of `pipe`, from a thread. Each test waits for a line with a timeout, and elo does
/// not exit, so a read on the test thread can block forever. The channel ends when the pipe ends.
fn lines(pipe: impl std::io::Read + Send + 'static) -> std::sync::mpsc::Receiver<String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufRead::lines(std::io::BufReader::new(pipe)) {
            if sender.send(line.unwrap()).is_err() {
                break;
            }
        }
    });
    receiver
}

/// The value of the string `field` in `object`, as `bitcoin-cli` writes it.
fn string_field<'a>(object: &'a str, field: &str) -> &'a str {
    let key = format!("\"{field}\": \"");
    let (_, rest) = object.split_once(&key).unwrap();
    rest.split_once('"').unwrap().0
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
