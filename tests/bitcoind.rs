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

impl Process {
    fn signal(&self, name: &str) {
        let status = std::process::Command::new("kill")
            .arg("-s")
            .arg(name)
            .arg(self.0.id().to_string())
            .status()
            .unwrap();
        assert!(status.success(), "kill -s {name}: {status}");
    }

    fn exit_code(&mut self) -> Option<i32> {
        let deadline = std::time::Instant::now() + STOP_TIMEOUT;
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
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
    let metrics = elo::metrics::Metrics::new(&chain);
    let (_connection, version) = runtime
        .block_on(elo::net::handshake(
            &elo::net::Destination::Address(elo::net::PeerAddress::new(bitcoind.peer).unwrap()),
            &mut chain,
            &metrics,
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
    assert_eq!(elo.exit_code(), Some(1));
}

#[test]
fn stdout_error_at_a_signal_writes_the_stop_line_to_stderr_and_exits_with_0() {
    let bitcoind = Bitcoind::start();
    let (reader, writer) = std::io::pipe().unwrap();
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
    let (tip_sender, tip_receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut stdout = std::io::BufRead::lines(std::io::BufReader::new(reader));
        let tip = stdout.any(|line| event_name(&line.unwrap()) == Some("tip"));
        drop(stdout);
        tip_sender.send(tip).unwrap();
    });
    let tip = tip_receiver
        .recv_timeout(SYNC_TIMEOUT)
        .expect("elo logged no tip");
    assert!(tip, "elo closed stdout before a tip");
    assert_eq!(
        stderr.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty),
        "elo wrote to stderr or exited before the signal"
    );

    elo.signal("TERM");

    assert_eq!(
        stderr.recv_timeout(END_TIMEOUT).as_deref(),
        Ok("level=info event=stop signal=SIGTERM")
    );
    assert_eq!(elo.exit_code(), Some(0));
    assert_eq!(
        stderr.recv_timeout(END_TIMEOUT),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected),
        "elo wrote more to stderr after the stop line"
    );
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
        elo.process.signal(signal);
        assert_eq!(elo.process.exit_code(), Some(0), "SIG{signal}");
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
    elo.process.signal("TERM");
    assert_eq!(elo.process.exit_code(), Some(0));
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
    elo.tip_at(bitcoind.peer, 30, ours.trim_end());

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
    let tip = elo.tip_at(bitcoind.peer, 2201, best.trim_end());
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

    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.event("end", END_TIMEOUT);
    bitcoind.cli(&["reconsiderblock", branch.trim_end()]);

    let tip = elo.event("tip", RECONNECT_TIMEOUT);
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
    assert_eq!(ends.len(), 1, "elo ended the connection again: {ends:?}");
}

#[test]
fn announcement_on_a_branch_that_lost_to_ours_after_a_low_work_sync_gets_no_getheaders() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "3001", "raw(51)"]);
    let second = bitcoind.cli(&["getblockhash", "2"]);
    bitcoind.cli(&["invalidateblock", second.trim_end()]);
    bitcoind.cli(&["generatetodescriptor", "2950", "raw(52)"]);
    bitcoind.cli(&["reconsiderblock", second.trim_end()]);
    let elo = Elo::start(&bitcoind);
    let ours = elo.event("tip", SYNC_TIMEOUT);
    let expected = format!("level=info event=tip peer={} height=3001 ", bitcoind.peer);
    assert!(ours.starts_with(&expected), "{ours}");

    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.event("end", END_TIMEOUT);
    bitcoind.cli(&["invalidateblock", second.trim_end()]);

    assert_eq!(elo.event("tip", RECONNECT_TIMEOUT), ours);
    settle(&bitcoind, &elo, 1);
    assert_eq!(elo.events("tip"), [ours.clone(), ours]);

    let get_headers = message_bytes(&bitcoind, "bytesrecv_per_msg", "getheaders");
    let headers_sent = message_bytes(&bitcoind, "bytessent_per_msg", "headers");
    bitcoind.cli(&["generatetodescriptor", "1", "raw(52)"]);
    let start = std::time::Instant::now();
    while message_bytes(&bitcoind, "bytessent_per_msg", "headers") == headers_sent {
        assert!(
            start.elapsed() < PEER_INFO_TIMEOUT,
            "bitcoind sent no headers"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    pong_from(&bitcoind, &elo, 1);
    pong_from(&bitcoind, &elo, 1);
    assert_eq!(
        message_bytes(&bitcoind, "bytesrecv_per_msg", "getheaders"),
        get_headers
    );
}

#[test]
fn announcement_before_the_answer_to_our_getheaders_keeps_the_connection() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let elo = Elo::start(&bitcoind);
    elo.event("tip", SYNC_TIMEOUT);
    wait_for_send_headers(&bitcoind, &elo);

    for round in 0..10 {
        let tip = bitcoind.cli(&["getbestblockhash"]);
        bitcoind.cli(&["invalidateblock", tip.trim_end()]);
        let script = format!("raw({:x})", 0x53 + round % 2);
        bitcoind.cli(&["generatetodescriptor", "2", &script]);
    }
    settle(&bitcoind, &elo, 0);

    let best = bitcoind.cli(&["getbestblockhash"]);
    let tips = elo.events("tip");
    let expected = format!(
        "level=info event=tip peer={} height=11 hash={} ",
        bitcoind.peer,
        best.trim_end()
    );
    assert!(
        tips.last().is_some_and(|tip| tip.starts_with(&expected)),
        "{tips:?}"
    );
}

#[test]
fn metrics_of_elo_have_its_tip_its_chain_its_step_each_reconnect_and_the_bytes_of_each_command() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "2001", "raw(51)"]);
    let best = bitcoind.cli(&["getbestblockhash"]);
    let chain_work = bitcoind.cli(&["getblockheader", best.trim_end()]);
    let chain_work = u128::from_str_radix(string_field(&chain_work, "chainwork"), 16).unwrap();
    let peer = bitcoind.peer.to_string();
    let elo = Elo::start_with(&["--metrics", "127.0.0.1:0", "regtest", &peer]);
    let listen = elo.event("metrics", SYNC_TIMEOUT);
    let address = listen
        .strip_prefix("level=info event=metrics address=")
        .unwrap();
    let address: std::net::SocketAddr = address.parse().unwrap();
    assert!(address.ip().is_loopback(), "{address}");
    assert_ne!(address.port(), 0);
    elo.event("tip", SYNC_TIMEOUT);

    let metrics = scrape(address);
    for line in [
        String::from("elo_header_tip_height 2001\n"),
        format!("elo_header_tip_work {chain_work}\n"),
        String::from("elo_header_chain_height 2001\n"),
        String::from("elo_header_presync_height 0\n"),
        String::from("elo_header_redownload_height 0\n"),
        String::from("elo_header_low_work_download{download=\"presync\"} 0\n"),
        String::from("elo_header_low_work_download{download=\"redownload\"} 0\n"),
        String::from("elo_peer_state{state=\"synced\"} 1\n"),
    ] {
        assert!(metrics.contains(&line), "{line}: {metrics}");
    }
    assert!(metrics.contains("elo_reconnects_total 0\n"), "{metrics}");

    settle(&bitcoind, &elo, 0);
    let metrics = scrape(address);
    for (direction, field) in [
        ("received", "bytessent_per_msg"),
        ("sent", "bytesrecv_per_msg"),
    ] {
        let mut expected = [0; COMMANDS.len() + 1];
        for (command, bytes) in per_message_bytes(&bitcoind, field) {
            let index = COMMANDS
                .iter()
                .position(|known| *known == command)
                .unwrap_or(COMMANDS.len());
            expected[index] += bytes;
        }
        for (command, bytes) in COMMANDS.iter().chain(&["other"]).zip(expected) {
            let line =
                format!("elo_peer_{direction}_bytes_total{{command=\"{command}\"}} {bytes}\n");
            assert!(metrics.contains(&line), "{line}: {metrics}");
        }
    }
    for line in [
        "elo_peer_received_messages_total{command=\"version\"} 1\n",
        "elo_peer_received_messages_total{command=\"verack\"} 1\n",
        "elo_peer_sent_messages_total{command=\"version\"} 1\n",
        "elo_peer_sent_messages_total{command=\"verack\"} 1\n",
        "elo_peer_sent_messages_total{command=\"sendheaders\"} 1\n",
    ] {
        assert!(metrics.contains(line), "{line}: {metrics}");
    }

    bitcoind.cli(&["-named", "disconnectnode", "nodeid=0"]);
    elo.event("end", END_TIMEOUT);
    let metrics = scrape(address);
    assert!(
        metrics.contains("elo_peer_state{state=\"wait\"} 1\n"),
        "{metrics}"
    );
    assert!(metrics.contains("elo_reconnects_total 1\n"), "{metrics}");
}

#[test]
fn metrics_address_in_use_exits_with_1() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = taken.local_addr().unwrap().to_string();
    let mut elo = Elo::start_with(&["--metrics", &address, "regtest", "127.0.0.1"]);
    let exit = elo.event("exit", END_TIMEOUT);
    assert!(
        exit.starts_with("level=error event=exit reason=\"metrics: "),
        "{exit}"
    );
    assert_eq!(elo.process.exit_code(), Some(1));
}

#[test]
fn blocks_from_bitcoind_are_downloaded_checked_and_logged() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "3", "raw(51)"]);
    let hashes: Vec<String> = (1..=3)
        .map(|height| {
            bitcoind
                .cli(&["getblockhash", &height.to_string()])
                .trim_end()
                .to_owned()
        })
        .collect();
    let elo = Elo::start(&bitcoind);
    elo.event("tip", SYNC_TIMEOUT);

    for (index, hash) in hashes.iter().enumerate() {
        let block = elo.event("block", SYNC_TIMEOUT);
        assert_eq!(
            block,
            format!(
                "level=info event=block peer={} height={} hash={hash} transactions=1",
                bitcoind.peer,
                index + 1
            )
        );
    }

    wait_for_send_headers(&bitcoind, &elo);
    bitcoind.cli(&["generatetodescriptor", "1", "raw(51)"]);
    let fourth = bitcoind.cli(&["getbestblockhash"]);
    let block = elo.event("block", SYNC_TIMEOUT);
    assert_eq!(
        block,
        format!(
            "level=info event=block peer={} height=4 hash={} transactions=1",
            bitcoind.peer,
            fourth.trim_end()
        )
    );
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

#[test]
fn blocks_across_bip34_heights_and_witness_spends_pass_all_checks() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "126", "raw(51)"]);
    let block_1_hash = bitcoind.cli(&["getblockhash", "1"]);
    let block_1 = bitcoind.cli(&["getblock", block_1_hash.trim_end(), "1"]);
    let coinbase_txid = array_string(&block_1, "tx", 0);
    let coinbase_txid_le = reverse_hex(coinbase_txid);

    let p2wsh_op_true = "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    let legacy_spend = format!(
        "0200000001{coinbase_txid_le}0000000000ffffffff0100e1f5050000000022{p2wsh_op_true}00000000"
    );
    let block_127_json =
        bitcoind.cli(&["generateblock", "raw(51)", &format!("[\"{legacy_spend}\"]")]);
    let block_127_hash = string_field(&block_127_json, "hash");
    let block_127 = bitcoind.cli(&["getblock", block_127_hash, "1"]);
    let legacy_txid = array_string(&block_127, "tx", 1);
    let legacy_txid_le = reverse_hex(legacy_txid);

    let witness_spend = format!(
        "02000000000101{legacy_txid_le}0000000000ffffffff01c09ee60500000000015101015100000000"
    );
    let block_128_json = bitcoind.cli(&[
        "generateblock",
        "raw(51)",
        &format!("[\"{witness_spend}\"]"),
    ]);
    let block_128_hash = string_field(&block_128_json, "hash");

    let elo = Elo::start(&bitcoind);
    elo.event("tip", SYNC_TIMEOUT);

    for height in 1..=126 {
        let block = elo.event("block", SYNC_TIMEOUT);
        assert!(
            block.contains(&format!(" height={height} ")) && block.ends_with(" transactions=1"),
            "{block}"
        );
    }
    assert_eq!(
        elo.event("block", SYNC_TIMEOUT),
        format!(
            "level=info event=block peer={} height=127 hash={block_127_hash} transactions=2",
            bitcoind.peer
        )
    );
    assert_eq!(
        elo.event("block", SYNC_TIMEOUT),
        format!(
            "level=info event=block peer={} height=128 hash={block_128_hash} transactions=2",
            bitcoind.peer
        )
    );
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

#[test]
fn halving_fees_bip68_and_live_reorg_connect_and_disconnect_blocks() {
    let bitcoind = Bitcoind::start();
    bitcoind.cli(&["generatetodescriptor", "150", "raw(51)"]);
    let block_1_hash = bitcoind.cli(&["getblockhash", "1"]);
    let block_1 = bitcoind.cli(&["getblock", block_1_hash.trim_end(), "1"]);
    let cb_1_txid_le = reverse_hex(array_string(&block_1, "tx", 0));

    let block_2_hash = bitcoind.cli(&["getblockhash", "2"]);
    let block_2 = bitcoind.cli(&["getblock", block_2_hash.trim_end(), "1"]);
    let cb_2_txid_le = reverse_hex(array_string(&block_2, "tx", 0));

    let p2sh_op_true = "a914da1745e9b549bd0bfa1a569971c77eba30cd5a4b87";
    let p2wsh_op_true = "00204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc33260";
    let tx_1 = format!(
        "0200000001{cb_1_txid_le}0000000000ffffffff\
         03\
         009435770000000017{p2sh_op_true}\
         009435770000000022{p2wsh_op_true}\
         0000000000000000066a04656c6f21\
         00000000"
    );
    let tx_1_decoded = bitcoind.cli(&["decoderawtransaction", &tx_1]);
    let tx_1_txid_le = reverse_hex(string_field(&tx_1_decoded, "txid"));

    let tx_2 = format!(
        "0200000001{tx_1_txid_le}0000000002015100000000\
         01\
         00b33f71000000000151\
         00000000"
    );
    let block_151_json = bitcoind.cli(&[
        "generateblock",
        "raw(51)",
        &format!("[\"{tx_1}\",\"{tx_2}\"]"),
    ]);
    let block_151_hash = string_field(&block_151_json, "hash");

    let tx_3 = format!(
        "02000000000101{tx_1_txid_le}010000000001000000\
         01\
         80a33a74000000000151\
         010151\
         00000000"
    );
    let block_152_json = bitcoind.cli(&["generateblock", "raw(51)", &format!("[\"{tx_3}\"]")]);
    let block_152_hash = string_field(&block_152_json, "hash");

    let elo = Elo::start(&bitcoind);
    elo.event("tip", SYNC_TIMEOUT);
    for height in 1..=150 {
        let block = elo.event("block", SYNC_TIMEOUT);
        assert!(
            block.contains(&format!(" height={height} ")) && block.ends_with(" transactions=1"),
            "{block}"
        );
    }
    assert_eq!(
        elo.event("block", SYNC_TIMEOUT),
        format!(
            "level=info event=block peer={} height=151 hash={block_151_hash} transactions=3",
            bitcoind.peer
        )
    );
    assert_eq!(
        elo.event("block", SYNC_TIMEOUT),
        format!(
            "level=info event=block peer={} height=152 hash={block_152_hash} transactions=2",
            bitcoind.peer
        )
    );

    wait_for_send_headers(&bitcoind, &elo);
    bitcoind.cli(&["invalidateblock", block_151_hash]);
    let reorg_tx = format!(
        "0200000001{cb_2_txid_le}0000000000ffffffff\
         01\
         00286bee000000000151\
         00000000"
    );
    let reorg_151_json = bitcoind.cli(&["generateblock", "raw(51)", &format!("[\"{reorg_tx}\"]")]);
    let reorg_151_hash = string_field(&reorg_151_json, "hash");
    bitcoind.cli(&["generatetodescriptor", "2", "raw(51)"]);
    let reorg_152_hash = bitcoind.cli(&["getblockhash", "152"]);
    let reorg_153_hash = bitcoind.cli(&["getblockhash", "153"]);

    assert_eq!(
        elo.event("block", SYNC_TIMEOUT),
        format!(
            "level=info event=block peer={} height=151 hash={reorg_151_hash} transactions=2",
            bitcoind.peer
        )
    );
    assert_eq!(
        elo.event("block", SYNC_TIMEOUT),
        format!(
            "level=info event=block peer={} height=152 hash={} transactions=1",
            bitcoind.peer,
            reorg_152_hash.trim_end()
        )
    );
    assert_eq!(
        elo.event("block", SYNC_TIMEOUT),
        format!(
            "level=info event=block peer={} height=153 hash={} transactions=1",
            bitcoind.peer,
            reorg_153_hash.trim_end()
        )
    );
    let ends = elo.events("end");
    assert!(ends.is_empty(), "elo ended the connection: {ends:?}");
}

fn array_string<'a>(object: &'a str, field: &str, index: usize) -> &'a str {
    let key = format!("\"{field}\": [");
    let (_, mut rest) = object.split_once(&key).unwrap();
    for _ in 0..index {
        let (_, next) = rest.split_once('"').unwrap();
        let (_, next) = next.split_once('"').unwrap();
        rest = next;
    }
    let (_, rest) = rest.split_once('"').unwrap();
    rest.split_once('"').unwrap().0
}

fn reverse_hex(hex: &str) -> String {
    assert_eq!(hex.len() % 2, 0);
    let mut out = String::with_capacity(hex.len());
    for index in (0..hex.len()).step_by(2).rev() {
        out.push_str(&hex[index..index + 2]);
    }
    out
}

fn scrape(address: std::net::SocketAddr) -> String {
    let mut stream = std::net::TcpStream::connect(address).unwrap();
    std::io::Write::write_all(
        &mut stream,
        b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )
    .unwrap();
    let mut response = String::new();
    std::io::Read::read_to_string(&mut stream, &mut response).unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert_eq!(
        head,
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
             Content-Length: {}\r\nConnection: close",
            body.len()
        )
    );
    body.to_owned()
}

fn settle(bitcoind: &Bitcoind, elo: &Elo, ends: usize) {
    let start = std::time::Instant::now();
    loop {
        let before = relay_bytes(bitcoind);
        pong_from(bitcoind, elo, ends);
        pong_from(bitcoind, elo, ends);
        if relay_bytes(bitcoind) == before {
            return;
        }
        assert!(
            start.elapsed() < SYNC_TIMEOUT,
            "bitcoind and elo still relay headers"
        );
    }
}

fn relay_bytes(bitcoind: &Bitcoind) -> [u64; 5] {
    [
        message_bytes(bitcoind, "bytesrecv_per_msg", "getheaders"),
        message_bytes(bitcoind, "bytessent_per_msg", "headers"),
        message_bytes(bitcoind, "bytessent_per_msg", "inv"),
        message_bytes(bitcoind, "bytesrecv_per_msg", "getdata"),
        message_bytes(bitcoind, "bytessent_per_msg", "block"),
    ]
}

fn pong_from(bitcoind: &Bitcoind, elo: &Elo, ends: usize) {
    let start = std::time::Instant::now();
    let before = message_bytes(bitcoind, "bytesrecv_per_msg", "pong");
    bitcoind.cli(&["ping"]);
    while message_bytes(bitcoind, "bytesrecv_per_msg", "pong") == before {
        let all = elo.events("end");
        assert_eq!(all.len(), ends, "elo ended the connection: {all:?}");
        assert!(
            start.elapsed() < PEER_INFO_TIMEOUT,
            "bitcoind got no pong from elo"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let all = elo.events("end");
    assert_eq!(all.len(), ends, "elo ended the connection: {all:?}");
}

const COMMANDS: [&str; 12] = [
    "version",
    "verack",
    "ping",
    "pong",
    "getheaders",
    "headers",
    "wtxidrelay",
    "sendaddrv2",
    "sendheaders",
    "inv",
    "getdata",
    "block",
];

fn per_message_bytes(bitcoind: &Bitcoind, field: &str) -> Vec<(String, u64)> {
    let peer_info = bitcoind.cli(&["getpeerinfo"]);
    object_text(&peer_info, field)
        .split(',')
        .map(|pair| {
            let (message, bytes) = pair.split_once(':').unwrap();
            let message = message.trim().trim_matches('"');
            (message.to_owned(), bytes.trim().parse().unwrap())
        })
        .collect()
}

fn message_bytes(bitcoind: &Bitcoind, field: &str, message: &str) -> u64 {
    let peer_info = bitcoind.cli(&["getpeerinfo"]);
    let key = format!("\"{message}\": ");
    let Some((_, rest)) = object_text(&peer_info, field).split_once(&key) else {
        return 0;
    };
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().unwrap()
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
        Self::start_with(&["regtest", peer])
    }

    fn start_with(args: &[&str]) -> Self {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
            .args(args)
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
        match self.event_by(name, std::time::Instant::now() + timeout) {
            Some(line) => line,
            None => panic!(
                "elo logged no {name:?} event within {} s: {:?}",
                timeout.as_secs(),
                self.read.borrow()
            ),
        }
    }

    fn event_by(&self, name: &str, deadline: std::time::Instant) -> Option<String> {
        loop {
            let passed = self.passed.get();
            if let Some(line) = self.read.borrow().get(passed) {
                self.passed.set(passed + 1);
                if event_name(line) == Some(name) {
                    return Some(line.clone());
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
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => return None,
            }
        }
    }

    fn tip_at(&self, peer: std::net::SocketAddr, height: u32, hash: &str) -> String {
        let prefix = format!("level=info event=tip peer={peer} height={height} hash={hash} ");
        let deadline = std::time::Instant::now() + SYNC_TIMEOUT;
        loop {
            let Some(tip) = self.event_by("tip", deadline) else {
                panic!(
                    "elo logged no tip at {prefix} within {} s: {:?}",
                    SYNC_TIMEOUT.as_secs(),
                    self.read.borrow()
                )
            };
            if tip.starts_with(&prefix) {
                return tip;
            }
            assert!(
                tip_height(&tip) < height,
                "elo logged a tip at or past {prefix}: {tip}"
            );
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
}

fn event_name(line: &str) -> Option<&str> {
    line.split(' ').nth(1)?.strip_prefix("event=")
}

fn tip_height(tip: &str) -> u32 {
    let height = tip
        .split(' ')
        .nth(3)
        .and_then(|field| field.strip_prefix("height="));
    match height.map(str::parse) {
        Some(Ok(height)) => height,
        _ => panic!("no height in {tip}"),
    }
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
