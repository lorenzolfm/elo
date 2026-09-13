//! Spawns a `bitcoind -regtest`, points elo at it, and asks Core whether the
//! handshake happened: `getpeerinfo` must list a peer with our `subver`.
//! Then again, with the reader of elo's stdout gone after one line: elo must
//! finish the handshake and its linger as if nobody had left, and exit 0.
//!
//! Fails when `bitcoind` or `bitcoin-cli` is not on `PATH`, unless
//! `ELO_NO_BITCOIND` is set; then it skips, and says so past the harness's
//! output capture. CI sets the variable; a developer should not have to.

// This whole file is a test. Clippy's `allow-unwrap-in-tests` only sees
// `#[test]` functions and `#[cfg(test)]` items, not the helpers here.
#![allow(clippy::unwrap_used)]

struct Node {
    child: std::process::Child,
    datadir: std::path::PathBuf,
    rpc_port: u16,
    p2p_port: u16,
}

impl Node {
    fn spawn() -> Option<Node> {
        for binary in ["bitcoind", "bitcoin-cli"] {
            std::process::Command::new(binary)
                .arg("--version")
                .output()
                .ok()?;
        }
        let (p2p_port, rpc_port) = free_ports();
        let datadir = std::env::temp_dir().join(format!("elo-handshake-{p2p_port}"));
        std::fs::create_dir_all(&datadir).unwrap();
        let child = std::process::Command::new("bitcoind")
            .arg("-regtest")
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-port={p2p_port}"))
            .arg(format!("-bind=127.0.0.1:{p2p_port}"))
            .arg(format!("-rpcport={rpc_port}"))
            .args([
                "-listenonion=0",
                "-dnsseed=0",
                "-discover=0",
                "-printtoconsole=0",
            ])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let node = Node {
            child,
            datadir,
            rpc_port,
            p2p_port,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while node.cli(&["getblockcount"]).is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "bitcoind did not come up"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        Some(node)
    }

    fn cli(&self, args: &[&str]) -> Option<String> {
        let out = std::process::Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .args(args)
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8(out.stdout).unwrap())
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

/// Two distinct ports: both listeners are alive when the second one binds.
fn free_ports() -> (u16, u16) {
    let bind = || std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (a, b) = (bind(), bind());
    let port = |l: &std::net::TcpListener| l.local_addr().unwrap().port();
    (port(&a), port(&b))
}

/// The node, or `None` with the skip announced, or a panic saying what to
/// install.
fn node_or_skip(test: &str) -> Option<Node> {
    let node = Node::spawn();
    if node.is_none() {
        assert!(
            std::env::var_os("ELO_NO_BITCOIND").is_some(),
            "bitcoind or bitcoin-cli is not on PATH; set ELO_NO_BITCOIND=1 to skip this test"
        );
        // The harness captures `eprintln!`, not the raw handle.
        std::io::Write::write_all(
            &mut std::io::stderr(),
            format!("SKIPPED {test}: ELO_NO_BITCOIND is set\n").as_bytes(),
        )
        .unwrap();
    }
    node
}

#[test]
fn core_lists_us_in_getpeerinfo() {
    let Some(node) = node_or_skip("core_lists_us_in_getpeerinfo") else {
        return;
    };
    let mut elo = std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
        .arg(format!("127.0.0.1:{}", node.p2p_port))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // elo lingers two seconds after the handshake; ask Core meanwhile.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let peers = loop {
        let peers = node.cli(&["getpeerinfo"]).unwrap();
        if peers.contains("/elo:") || std::time::Instant::now() > deadline {
            break peers;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    // Drain the pipe before waiting: a child that fills it blocks on `println!`
    // and a parent that waits first never reads. Reading to EOF is the wait.
    let transcript = std::io::read_to_string(elo.stdout.take().unwrap()).unwrap();
    let status = elo.wait().unwrap();
    println!("--- elo ---\n{transcript}");
    let interesting = |line: &&str| {
        ["subver", "\"version\"", "inbound", "addrlocal", "relaytxes"]
            .iter()
            .any(|key| line.contains(key))
    };
    println!("--- bitcoin-cli getpeerinfo ---");
    peers
        .lines()
        .filter(interesting)
        .for_each(|line| println!("{line}"));

    assert!(status.success(), "elo exited with {status}");
    assert!(transcript.contains("handshake complete"), "{transcript}");
    let subver = format!("\"subver\": \"/elo:{}/\"", env!("CARGO_PKG_VERSION"));
    assert!(peers.contains(&subver), "Core does not list us:\n{peers}");
    assert!(peers.contains("\"inbound\": true"));
    assert!(
        peers.contains("\"relaytxes\": false"),
        "relay=false must turn transaction relay off"
    );
}

/// `elo <peer> | head -1`. Rust ignores `SIGPIPE`, so the next line elo
/// writes after `head` exits fails with `EPIPE` instead of killing the
/// process; `println!` turned that into a panic and exit code 101 (#5).
/// Now, like bitcoind, elo drops the line and keeps working.
#[test]
fn keeps_working_after_its_reader_leaves() {
    let Some(node) = node_or_skip("keeps_working_after_its_reader_leaves") else {
        return;
    };
    let mut elo = std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
        .arg(format!("127.0.0.1:{}", node.p2p_port))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // `head -1`: read one line, then close our end of the pipe.
    let mut first_line = String::new();
    std::io::BufRead::read_line(
        &mut std::io::BufReader::new(elo.stdout.take().unwrap()),
        &mut first_line,
    )
    .unwrap();
    println!("--- elo, first line ---\n{first_line}--- pipe closed ---");
    assert!(first_line.starts_with("connecting to "), "{first_line}");

    // Nobody is reading; the handshake must complete anyway.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let peers = loop {
        let peers = node.cli(&["getpeerinfo"]).unwrap();
        if peers.contains("/elo:") || std::time::Instant::now() > deadline {
            break peers;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let subver = format!("\"subver\": \"/elo:{}/\"", env!("CARGO_PKG_VERSION"));
    assert!(peers.contains(&subver), "Core does not list us:\n{peers}");
    println!("Core lists {subver} with the pipe closed");

    // Reading stderr to EOF is the wait; a panic message would land here.
    let stderr = std::io::read_to_string(elo.stderr.take().unwrap()).unwrap();
    let status = elo.wait().unwrap();
    println!("elo exited with {status}, stderr: {stderr:?}");
    assert!(status.success(), "elo exited with {status}: {stderr}");
    assert!(stderr.is_empty(), "nothing went wrong, so nothing to say");
}
