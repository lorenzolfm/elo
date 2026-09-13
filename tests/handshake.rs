//! Spawns a `bitcoind -regtest`, points elo at it, and asks Core whether the
//! handshake happened: `getpeerinfo` must list a peer with our `subver`.
//!
//! Skips, loudly, when `bitcoind` or `bitcoin-cli` is not on `PATH`.

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
        let (p2p_port, rpc_port) = (free_port(), free_port());
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
fn core_lists_us_in_getpeerinfo() {
    let Some(node) = Node::spawn() else {
        eprintln!("SKIPPED: bitcoind or bitcoin-cli not found on PATH");
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
    assert!(
        peers.contains("\"subver\": \"/elo:0.1.0/\""),
        "Core does not list us:\n{peers}"
    );
    assert!(peers.contains("\"inbound\": true"));
    assert!(
        peers.contains("\"relaytxes\": false"),
        "relay=false must turn transaction relay off"
    );
}
