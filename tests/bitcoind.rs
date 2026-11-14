const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const PEER_INFO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const END_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const RECONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("remove {}: {error}", self.0.display());
        }
    }
}

struct Process(std::process::Child);

impl Drop for Process {
    fn drop(&mut self) {
        if let Err(error) = self.0.kill() {
            eprintln!("kill process {}: {error}", self.0.id());
        }
        if let Err(error) = self.0.wait() {
            eprintln!("wait for process {}: {error}", self.0.id());
        }
    }
}

struct Bitcoind {
    process: Process,
    peer: std::net::SocketAddr,
    rpc_port: u16,
    datadir: TempDir,
}

impl Bitcoind {
    fn start() -> Self {
        let path = std::env::var_os("BITCOIND").expect("BITCOIND holds the path of bitcoind");
        let lock = std::fs::File::create(std::env::temp_dir().join("elo-bitcoind.lock")).unwrap();
        lock.lock().unwrap();

        let peer_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let rpc_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = peer_listener.local_addr().unwrap();
        let rpc_port = rpc_listener.local_addr().unwrap().port();
        drop(peer_listener);
        drop(rpc_listener);

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
            .arg("-natpmp=0")
            .arg("-server=1")
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

    fn wait_until_ready(&mut self) {
        let start = std::time::Instant::now();
        while !self.rpc(&["uptime"]).status.success() {
            assert_eq!(self.process.0.try_wait().unwrap(), None, "bitcoind exited");
            assert!(start.elapsed() < READY_TIMEOUT, "bitcoind is not ready");
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    fn cli(&self, command: &[&str]) -> String {
        let output = self.rpc(command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "bitcoin-cli {command:?}: {stderr}");
        String::from_utf8(output.stdout).unwrap()
    }

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
        .block_on(elo::net::handshake(
            &elo::net::Destination::Address(elo::net::PeerAddress::new(bitcoind.peer).unwrap()),
            &mut chain,
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

    let end = stderr
        .recv_timeout(END_TIMEOUT)
        .expect("elo wrote no exit line");
    assert!(
        end.starts_with("level=error event=exit reason=\"stdout: "),
        "{end}"
    );
    assert_eq!(elo.0.wait().unwrap().code(), Some(1));
}

#[test]
fn ping_from_bitcoind_gets_a_pong() {
    let bitcoind = Bitcoind::start();
    let mut elo = Process(
        std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("regtest")
            .arg(bitcoind.peer.to_string())
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );

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
        let ends = elo.events("end");
        assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
        assert!(
            start.elapsed() < PEER_INFO_TIMEOUT,
            "bitcoind shows no pong for our ping: {peer_info}"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    let end = elo.event("end", END_TIMEOUT);
    assert_eq!(
        end,
        format!(
            "level=warn event=end destination={} reason=\"the peer closed the connection\" wait_ms=5000",
            bitcoind.peer
        )
    );
}

#[test]
fn closed_connection_gets_a_new_handshake_and_sync() {
    let bitcoind = Bitcoind::start();
    let elo = Elo::start(&bitcoind);
    let tip = elo.event("tip", SYNC_TIMEOUT);

    let close = std::time::Instant::now();
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.event("end", END_TIMEOUT);
    let version = elo.event("version", RECONNECT_TIMEOUT);
    let expected = format!(
        "level=info event=version peer={} version=70016 ",
        bitcoind.peer
    );
    assert!(version.starts_with(&expected), "{version}");
    let wait = close.elapsed();
    assert!(wait >= std::time::Duration::from_secs(5), "{wait:?}");
    assert_eq!(elo.event("tip", SYNC_TIMEOUT), tip);
}

#[test]
fn peer_with_a_name_gets_a_lookup_and_a_dial_to_its_address() {
    let bitcoind = Bitcoind::start();
    let named = format!("localhost:{}", bitcoind.peer.port());
    let elo = Elo::start_on(&named);

    let version = elo.event("version", SYNC_TIMEOUT);
    let expected = format!(
        "level=info event=version peer={} version=70016 ",
        bitcoind.peer
    );
    assert!(version.starts_with(&expected), "{version}");
    let ends = elo.events("end");
    assert!(ends.is_empty(), "{ends:?}");

    elo.event("tip", SYNC_TIMEOUT);
    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    let end = elo.event("end", END_TIMEOUT);
    assert!(
        end.starts_with(&format!("level=warn event=end destination={named} ")),
        "{end}"
    );
}

#[test]
fn signal_in_a_connection_exits_with_0() {
    let bitcoind = Bitcoind::start();
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
fn next_connection_syncs_from_our_tip_and_keeps_it_against_a_branch_with_the_same_work() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let elo = Elo::start(&bitcoind);
    let first = bitcoind.cli(&["getbestblockhash"]);
    let ours = format!(
        "level=info event=tip peer={} height=1 hash={} ",
        bitcoind.peer,
        first.trim_end()
    );
    let tip = elo.event("tip", SYNC_TIMEOUT);
    assert!(tip.starts_with(&ours), "{tip}");

    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.event("end", END_TIMEOUT);

    bitcoind.cli(&["invalidateblock", first.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "1", "raw(52)"]);

    let tip = elo.event("tip", RECONNECT_TIMEOUT);
    assert!(tip.starts_with(&ours), "{tip}");
    let ends = elo.events("end");
    assert_eq!(ends.len(), 1, "{ends:?}");
}

#[test]
fn branch_with_more_work_that_bitcoind_announces_takes_the_place_of_ours() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let first = bitcoind.cli(&["getbestblockhash"]);
    bitcoind.cli(&["invalidateblock", first.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "2", "raw(52)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let branch = bitcoind.cli(&["getblockhash", "1"]);
    bitcoind.cli(&["invalidateblock", branch.trim_end()]);
    bitcoind.cli(&["reconsiderblock", first.trim_end()]);
    let elo = Elo::start(&bitcoind);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let expected = format!(
        "level=info event=tip peer={} height=1 hash={} ",
        bitcoind.peer,
        first.trim_end()
    );
    assert!(tip.starts_with(&expected), "{tip}");

    wait_for_send_headers(&bitcoind, &elo);

    bitcoind.cli(&["reconsiderblock", branch.trim_end()]);
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
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

#[test]
fn sync_from_bitcoind_logs_its_tip() {
    let bitcoind = Bitcoind::start();
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
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let elo = Elo::start(&bitcoind);
    elo.event("tip", SYNC_TIMEOUT);

    wait_for_send_headers(&bitcoind, &elo);
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);

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
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

#[test]
fn reorg_that_bitcoind_announces_with_an_inv_makes_elo_ask_for_the_headers() {
    let bitcoind = Bitcoind::start();
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

    bitcoind.cli(&["reconsiderblock", second.trim_end()]);
    let tip = elo.event("tip", SYNC_TIMEOUT);
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
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

#[test]
fn branch_that_bitcoind_sends_in_two_batches_takes_the_place_of_ours() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "2101", "raw(51)"]);
    let second = bitcoind.cli(&["getblockhash", "2"]);
    bitcoind.cli(&["invalidateblock", second.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "2200", "raw(52)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let branch = bitcoind.cli(&["getblockhash", "2"]);
    bitcoind.cli(&["invalidateblock", branch.trim_end()]);
    bitcoind.cli(&["reconsiderblock", second.trim_end()]);
    let elo = Elo::start(&bitcoind);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let expected = format!("level=info event=tip peer={} height=2101 ", bitcoind.peer);
    assert!(tip.starts_with(&expected), "{tip}");
    wait_for_send_headers(&bitcoind, &elo);

    bitcoind.cli(&["reconsiderblock", branch.trim_end()]);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(
        tip,
        format!(
            "level=info event=tip peer={} height=2201 hash={} work={chain_work}",
            bitcoind.peer,
            best.trim_end()
        )
    );
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

#[test]
fn branch_below_the_margin_takes_the_place_of_ours_after_a_low_work_sync() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "3001", "raw(51)"]);
    let second = bitcoind.cli(&["getblockhash", "2"]);
    bitcoind.cli(&["invalidateblock", second.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "3100", "raw(52)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let branch = bitcoind.cli(&["getblockhash", "2"]);
    bitcoind.cli(&["invalidateblock", branch.trim_end()]);
    bitcoind.cli(&["reconsiderblock", second.trim_end()]);
    let elo = Elo::start(&bitcoind);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let expected = format!("level=info event=tip peer={} height=3001 ", bitcoind.peer);
    assert!(tip.starts_with(&expected), "{tip}");
    wait_for_send_headers(&bitcoind, &elo);

    bitcoind.cli(&["reconsiderblock", branch.trim_end()]);
    let tip = elo.event("tip", SYNC_TIMEOUT);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = string_field(&chain_work, "chainwork");
    assert_eq!(
        tip,
        format!(
            "level=info event=tip peer={} height=3101 hash={} work={chain_work}",
            bitcoind.peer,
            best.trim_end()
        )
    );
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

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

struct Elo {
    process: Process,
    stdout: std::sync::mpsc::Receiver<String>,
    stderr: std::sync::mpsc::Receiver<String>,
    read: std::cell::RefCell<Vec<String>>,
    passed: std::cell::Cell<usize>,
}

impl Elo {
    fn start(bitcoind: &Bitcoind) -> Self {
        Self::start_on(&bitcoind.peer.to_string())
    }

    fn start_on(peer: &str) -> Self {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .arg("regtest")
            .arg(peer)
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

    fn events(&self, name: &str) -> Vec<String> {
        let mut read = self.read.borrow_mut();
        read.extend(self.stdout.try_iter());
        read.iter()
            .filter(|line| event_name(line) == Some(name))
            .cloned()
            .collect()
    }

    fn signal(&self, name: &str) {
        let status = std::process::Command::new("kill")
            .arg("-s")
            .arg(name)
            .arg(self.process.0.id().to_string())
            .status()
            .unwrap();
        assert!(status.success(), "kill -s {name}: {status}");
    }

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

fn event_name(line: &str) -> Option<&str> {
    line.split(' ').nth(1)?.strip_prefix("event=")
}

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

fn string_field<'a>(object: &'a str, field: &str) -> &'a str {
    let key = format!("\"{field}\": \"");
    let (_, rest) = object.split_once(&key).unwrap();
    rest.split_once('"').unwrap().0
}

fn object_text<'a>(peer_info: &'a str, field: &str) -> &'a str {
    let key = format!("\"{field}\": {{");
    let Some((_, rest)) = peer_info.split_once(&key) else {
        return "";
    };
    rest.split_once('}').unwrap().0
}
