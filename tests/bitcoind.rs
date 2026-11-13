//! elo against a real `bitcoind -regtest`. `BITCOIND` and `BITCOIN_CLI` hold the paths of the
//! binaries.

/// How long `bitcoind` may take to answer RPC after its warmup.
const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `bitcoin-cli` may wait for the reply to one request.
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long `getpeerinfo` may take to show what a test waits for.
const PEER_INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to log the end of a connection: after `bitcoind` closes it, or after
/// the start when the first write to stdout fails.
const END_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to do the handshake again after the end of a connection. It waits 5 s
/// before it dials again.
const RECONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to sync the headers of `bitcoind` and log its tip.
const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long elo may take to exit after a signal. Below the wait of 5 s before a dial, so a
/// signal in that wait must end it, and not the next dial.
const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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
        .expect("elo wrote no exit line");
    // An end that the peer causes dials again, so the exit comes from stdout. stdout failed, so
    // the line is on stderr.
    assert!(
        end.starts_with("level=error event=exit reason=\"stdout: "),
        "{end}"
    );
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
        let ends = elo.events("end");
        assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
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
    let end = elo.event("end", END_TIMEOUT);
    assert_eq!(
        end,
        format!(
            "level=warn event=end peer={} reason=\"the peer closed the connection\" wait_ms=5000",
            bitcoind.peer
        )
    );
}

#[test]
fn closed_connection_gets_a_new_handshake_and_sync() {
    let bitcoind = Bitcoind::start();
    let elo = Elo::start(&bitcoind);
    let tip = elo.event("tip", SYNC_TIMEOUT);

    // elo is the only peer of bitcoind, so it is node 0. The test does not check the reason of
    // the end: bitcoind can close with bytes from elo that it has not read, and then elo sees a
    // reset.
    let close = std::time::Instant::now();
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.event("end", END_TIMEOUT);
    let version = elo.event("version", RECONNECT_TIMEOUT);
    let expected = format!(
        "level=info event=version peer={} version=70016 ",
        bitcoind.peer
    );
    assert!(version.starts_with(&expected), "{version}");
    // The close comes after `close`, and the wait of 5 s comes after the close.
    let wait = close.elapsed();
    assert!(wait >= std::time::Duration::from_secs(5), "{wait:?}");
    assert_eq!(elo.event("tip", SYNC_TIMEOUT), tip);
}

#[test]
fn signal_in_a_connection_exits_with_0() {
    let bitcoind = Bitcoind::start();
    // elo exits each time, so the next elo is again the only peer of bitcoind.
    for signal in ["TERM", "INT"] {
        let mut elo = Elo::start(&bitcoind);
        elo.event("tip", SYNC_TIMEOUT);
        elo.signal(signal);
        assert_eq!(elo.exit_code(), Some(0), "SIG{signal}");
        assert_eq!(
            elo.event("stop", END_TIMEOUT),
            format!("level=info event=stop signal=SIG{signal}")
        );
    }
}

#[test]
fn signal_in_the_wait_before_a_dial_exits_with_0() {
    let bitcoind = Bitcoind::start();
    let mut elo = Elo::start(&bitcoind);
    elo.event("tip", SYNC_TIMEOUT);

    // elo is the only peer of bitcoind, so it is node 0. elo logs the end, and then it waits 5 s.
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    let end = elo.event("end", END_TIMEOUT);
    assert!(end.ends_with(" wait_ms=5000"), "{end}");
    elo.signal("TERM");
    assert_eq!(elo.exit_code(), Some(0));
    assert_eq!(
        elo.event("stop", END_TIMEOUT),
        "level=info event=stop signal=SIGTERM"
    );
}

#[test]
fn next_connection_syncs_from_our_tip_and_a_tip_off_the_chain_of_bitcoind_starts_again() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let elo = Elo::start(&bitcoind);
    let first = bitcoind.cli(&["getbestblockhash"]);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let expected = format!(
        "level=info event=tip peer={} height=1 hash={} ",
        bitcoind.peer,
        first.trim_end()
    );
    assert!(tip.starts_with(&expected), "{tip}");

    // elo is the only peer of bitcoind, so it is node 0. elo ends no connection of its own here,
    // so the close does not race elo. The test does not check the reason of this end: bitcoind
    // can close with bytes from elo that it has not read, and then elo sees a reset.
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.event("end", END_TIMEOUT);

    // In the wait before the next dial, bitcoind leaves our tip for a block on genesis. The block
    // pays another script, because the same script in the same second makes the block that
    // bitcoind marked invalid.
    bitcoind.cli(&["invalidateblock", first.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "1", "raw(52)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);

    // The next connection asks for the headers after our tip. bitcoind does not have it on its
    // chain, so it sends its headers after genesis, and our chain starts again. The connection
    // after it syncs from genesis, and gets the block. A connection that synced from genesis at
    // once would take the block with no refusal.
    let expected = format!(
        "level=info event=tip peer={} height=1 hash={} ",
        bitcoind.peer,
        best.trim_end()
    );
    // The connections log other tips before it. One deadline holds all the waits. Both reconnects
    // fit in one `RECONNECT_TIMEOUT`, because each waits 5 s, and a longer bound goes past the
    // limit of a test in nextest, so `event` could not give its message.
    let deadline = std::time::Instant::now() + RECONNECT_TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if elo.event("tip", left).starts_with(&expected) {
            break;
        }
    }
    // The refusal came at least 5 s before the tip, so its line is there.
    let ends = elo.events("end");
    assert_eq!(ends.len(), 2, "{ends:?}");
    assert_eq!(
        ends[1],
        format!(
            "level=warn event=end peer={} reason=\"peer: our tip is not on their chain, so our \
             chain starts again from genesis\" wait_ms=5000",
            bitcoind.peer
        )
    );
}

#[test]
fn branch_that_bitcoind_announces_off_our_tip_makes_elo_ask_for_the_headers() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let elo = Elo::start(&bitcoind);
    let first = bitcoind.cli(&["getbestblockhash"]);
    elo.event("tip", SYNC_TIMEOUT);

    // bitcoind announces the branch with a `headers` only after our `sendheaders`.
    wait_for_send_headers(&bitcoind, &elo);

    // bitcoind leaves our tip for one block on genesis, with another script as above. One block,
    // so bitcoind sends one announcement: a second one could come before the answer to our
    // `getheaders`, and look like it.
    bitcoind.cli(&["invalidateblock", first.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "1", "raw(52)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);

    // The announcement is on genesis, not on our tip, so elo asks for the headers after our tip.
    // bitcoind does not have our tip on its chain, so it sends its headers after genesis, and
    // our chain starts again on this connection. The next connection syncs from genesis, and
    // gets the block.
    let tip = elo.event("tip", RECONNECT_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(
        tip,
        format!(
            "level=info event=tip peer={} height=1 hash={} work={chain_work}",
            bitcoind.peer,
            best.trim_end()
        )
    );
    // elo ended the connection, so no reset from bitcoind changes the reason.
    let ends = elo.events("end");
    assert_eq!(
        ends,
        [format!(
            "level=warn event=end peer={} reason=\"peer: our tip is not on their chain, so our \
             chain starts again from genesis\" wait_ms=5000",
            bitcoind.peer
        )]
    );
}

#[test]
fn sync_from_bitcoind_logs_its_tip() {
    let bitcoind = Bitcoind::start();
    // 2001 blocks: a full batch of 2000 headers, our next `getheaders`, and a batch of 1.
    bitcoind.cli(&["generatetodescriptor", "2001", "raw(51)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let elo = Elo::start(&bitcoind);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(
        tip,
        format!(
            "level=info event=tip peer={} height=2001 hash={} work={chain_work}",
            bitcoind.peer,
            best.trim_end()
        )
    );
}

#[test]
fn block_that_bitcoind_mines_after_the_sync_logs_the_next_tip() {
    let bitcoind = Bitcoind::start();
    // bitcoind announces no block in its initial block download. On regtest, a block with a recent
    // time ends it.
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let elo = Elo::start(&bitcoind);
    elo.event("tip", SYNC_TIMEOUT);

    // Without our `sendheaders`, bitcoind announces the block with an `inv`. So the test waits
    // until bitcoind has it, and then mines.
    wait_for_send_headers(&bitcoind, &elo);
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);

    // The `headers` of the announcement goes on our tip, as a batch of a sync.
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(
        tip,
        format!(
            "level=info event=tip peer={} height=2 hash={} work={chain_work}",
            bitcoind.peer,
            best.trim_end()
        )
    );
    // The same connection took it.
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

#[test]
fn reorg_that_bitcoind_announces_with_an_inv_makes_elo_ask_for_the_headers() {
    let bitcoind = Bitcoind::start();
    // Block 1, then a branch of 30 blocks on it, which bitcoind leaves. So elo syncs to block 1.
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    bitcoind.cli(&["generatetodescriptor", "30", "raw(51)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let second = bitcoind.cli(&["getblockhash", "2"]);
    bitcoind.cli(&["invalidateblock", second.trim_end()]);
    let elo = Elo::start(&bitcoind);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let expected = format!("level=info event=tip peer={} height=1 ", bitcoind.peer);
    assert!(tip.starts_with(&expected), "{tip}");
    wait_for_send_headers(&bitcoind, &elo);

    // A second branch of 29 blocks on block 1, with another script. elo follows it to height 30.
    bitcoind.cli(&["generatetodescriptor", "29", "raw(52)"]);
    let ours = bitcoind.cli(&["getbestblockhash"]);
    let expected = format!(
        "level=info event=tip peer={} height=30 hash={} ",
        bitcoind.peer,
        ours.trim_end()
    );
    let deadline = std::time::Instant::now() + SYNC_TIMEOUT;
    while !elo.event("tip", SYNC_TIMEOUT).starts_with(&expected) {
        assert!(
            std::time::Instant::now() < deadline,
            "elo did not reach height 30"
        );
    }

    // bitcoind goes back to the first branch, which has more work, in one step. It announces
    // only the last 8 blocks of the step, and elo does not have the block below them. So the
    // announcement is an `inv`, and so is each later one. Only our `getheaders` gets the chain.
    // Its answer is on genesis, because our tip is not on the chain of bitcoind, so our chain
    // starts again, and the next connection syncs the first branch from genesis.
    bitcoind.cli(&["reconsiderblock", second.trim_end()]);
    let tip = elo.event("tip", 2 * RECONNECT_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(
        tip,
        format!(
            "level=info event=tip peer={} height=31 hash={} work={chain_work}",
            bitcoind.peer,
            best.trim_end()
        )
    );
    let ends = elo.events("end");
    assert_eq!(
        ends,
        [format!(
            "level=warn event=end peer={} reason=\"peer: our tip is not on their chain, so our \
             chain starts again from genesis\" wait_ms=5000",
            bitcoind.peer
        )]
    );
}

/// Waits until `bitcoind` got our `sendheaders`, which elo sends after the sync. Then bitcoind
/// announces each new block on our tip with a `headers`. Panics if `elo` ends the connection.
fn wait_for_send_headers(bitcoind: &Bitcoind, elo: &Elo) {
    let start = std::time::Instant::now();
    loop {
        let peer_info = bitcoind.cli(&["getpeerinfo"]);
        if object_text(&peer_info, "bytesrecv_per_msg").contains("\"sendheaders\"") {
            return;
        }
        let ends = elo.events("end");
        assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
        assert!(
            start.elapsed() < PEER_INFO_TIMEOUT,
            "bitcoind shows no sendheaders: {peer_info}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// elo connected to a `bitcoind`, with the log lines of its stdout and the lines of its stderr.
/// elo does not exit while it can dial the peer, so the drop kills it.
struct Elo {
    process: Process,
    stdout: std::sync::mpsc::Receiver<String>,
    stderr: std::sync::mpsc::Receiver<String>,
    /// Each line of stdout that `event` or `events` read, in order.
    read: std::cell::RefCell<Vec<String>>,
    /// How many lines of `read` the calls of `event` went past. `events` can read lines after
    /// them, and the next `event` starts at the first of those.
    passed: std::cell::Cell<usize>,
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
            process: Process(child),
            stdout,
            stderr,
            read: std::cell::RefCell::default(),
            passed: std::cell::Cell::default(),
        }
    }

    /// The next log line of the event `name`, after the line that the last `event` gave. It skips
    /// the lines before it, also lines that `events` read, and panics if none comes within
    /// `timeout`.
    fn event(&self, name: &str, timeout: std::time::Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let passed = self.passed.get();
            if let Some(line) = self.read.borrow().get(passed) {
                self.passed.set(passed + 1);
                if event_name(line) == Some(name) {
                    return line.clone();
                }
                continue;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            match self.stdout.recv_timeout(left) {
                Ok(line) => self.read.borrow_mut().push(line),
                // The thread ends only when the pipe ends, so elo exited, and its stderr ends.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    let stderr = self.stderr.iter().collect::<Vec<_>>().join("\n");
                    panic!("elo exited: {:?} {stderr}", self.read.borrow())
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
                    "elo logged no {name:?} event within {} s: {:?}",
                    timeout.as_secs(),
                    self.read.borrow()
                ),
            }
        }
    }

    /// Each log line of the event `name` from the start of elo up to now.
    fn events(&self, name: &str) -> Vec<String> {
        let mut read = self.read.borrow_mut();
        read.extend(self.stdout.try_iter());
        read.iter()
            .filter(|line| event_name(line) == Some(name))
            .cloned()
            .collect()
    }

    /// Sends the signal `name`, for example `TERM`, to elo. The `kill` of coreutils, because
    /// `std` sends only SIGKILL.
    fn signal(&self, name: &str) {
        let status = std::process::Command::new("kill")
            .arg("-s")
            .arg(name)
            .arg(self.process.0.id().to_string())
            .status()
            .unwrap();
        assert!(status.success(), "kill -s {name}: {status}");
    }

    /// The exit code of elo, which must exit within `STOP_TIMEOUT`. `None` is an end by a
    /// signal.
    fn exit_code(&mut self) -> Option<i32> {
        let deadline = std::time::Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = self.process.0.try_wait().unwrap() {
                return status.code();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "elo did not exit within {} s",
                STOP_TIMEOUT.as_secs()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// The name of the event of a log `line`: its second field.
fn event_name(line: &str) -> Option<&str> {
    line.split(' ').nth(1)?.strip_prefix("event=")
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
