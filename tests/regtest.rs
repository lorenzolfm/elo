#![allow(clippy::unwrap_used)]

static SPAWN: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
        let _spawning = SPAWN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (p2p_port, rpc_port) = free_ports();
        let datadir = std::env::temp_dir().join(format!("elo-handshake-{p2p_port}"));
        if let Err(e) = std::fs::remove_dir_all(&datadir) {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::NotFound,
                "{}: {e}",
                datadir.display()
            );
        }
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

fn free_ports() -> (u16, u16) {
    let bind = || std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (a, b) = (bind(), bind());
    let port = |l: &std::net::TcpListener| l.local_addr().unwrap().port();
    (port(&a), port(&b))
}

fn node_or_skip(test: &str) -> Option<Node> {
    let node = Node::spawn();
    if node.is_none() {
        assert!(
            std::env::var_os("ELO_NO_BITCOIND").is_some(),
            "bitcoind or bitcoin-cli is not on PATH; set ELO_NO_BITCOIND=1 to skip this test"
        );
        std::io::Write::write_all(
            &mut std::io::stderr(),
            format!("SKIPPED {test}: ELO_NO_BITCOIND is set\n").as_bytes(),
        )
        .unwrap();
    }
    node
}

struct Run {
    peers: String,
    transcript: String,
    status: std::process::ExitStatus,
}

fn run_elo_until(test: &str, done: fn(&str) -> bool) -> Option<Run> {
    Some(run_elo(&node_or_skip(test)?, done))
}

fn run_elo(node: &Node, done: fn(&str) -> bool) -> Run {
    let mut elo = std::process::Command::new(env!("CARGO_BIN_EXE_elo"))
        .arg("regtest")
        .arg(format!("127.0.0.1:{}", node.p2p_port))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let peers = loop {
        let peers = node.cli(&["getpeerinfo"]).unwrap();
        if done(&peers) || std::time::Instant::now() > deadline {
            break peers;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let transcript = std::io::read_to_string(elo.stdout.take().unwrap()).unwrap();
    let status = elo.wait().unwrap();
    println!("--- elo ---\n{transcript}");
    let interesting = |line: &&str| {
        [
            "subver",
            "\"version\"",
            "inbound",
            "addrlocal",
            "relaytxes",
            "pingtime",
            "minping",
            "pingwait",
        ]
        .iter()
        .any(|key| line.contains(key))
    };
    println!("--- bitcoin-cli getpeerinfo ---");
    peers
        .lines()
        .filter(interesting)
        .for_each(|line| println!("{line}"));
    Run {
        peers,
        transcript,
        status,
    }
}

const UNSPENDABLE: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj";

#[test]
fn core_tells_us_its_height() {
    let Some(node) = node_or_skip("core_tells_us_its_height") else {
        return;
    };
    node.cli(&["generatetoaddress", "7", UNSPENDABLE]).unwrap();
    node.cli(&["syncwithvalidationinterfacequeue"]).unwrap();
    let height = node.cli(&["getblockcount"]).unwrap();
    let height = height.trim();
    assert_eq!(height, "7");

    let run = run_elo(&node, |peers| peers.contains("/elo:"));
    assert!(run.status.success(), "elo exited with {}", run.status);
    let peer_line = run
        .transcript
        .lines()
        .find(|line| line.starts_with("peer is "))
        .unwrap_or_else(|| panic!("no peer line:\n{}", run.transcript));
    assert!(peer_line.contains("/Satoshi:"), "{peer_line}");
    assert!(
        peer_line.contains(&format!(" height {height} ")),
        "getblockcount says {height}: {peer_line}"
    );
    println!("getblockcount {height}; {peer_line}");
}

#[test]
fn our_chainwork_is_the_chainwork_core_reports() {
    // Red if the work of a header is wrong, or if the chain drops the work
    // of genesis or of the header at a join: Core is the oracle, and it
    // prints the same number for the same chain.
    let Some(node) = node_or_skip("our_chainwork_is_the_chainwork_core_reports") else {
        return;
    };
    node.cli(&["generatetoaddress", "7", UNSPENDABLE]).unwrap();
    node.cli(&["syncwithvalidationinterfacequeue"]).unwrap();
    let info = node.cli(&["getblockchaininfo"]).unwrap();
    let chainwork = info
        .lines()
        .find(|line| line.contains("\"chainwork\""))
        .and_then(|line| line.split('"').nth(3))
        .unwrap_or_else(|| panic!("no chainwork:\n{info}"))
        .to_string();

    let run = run_elo(&node, |peers| peers.contains("/elo:"));
    assert!(run.status.success(), "elo exited with {}", run.status);
    assert!(
        run.transcript.contains(&format!("chainwork {chainwork}")),
        "getblockchaininfo says {chainwork}:\n{}",
        run.transcript
    );
    println!("getblockchaininfo chainwork {chainwork}: ours agrees");
}

#[test]
fn core_lists_us_in_getpeerinfo() {
    let Some(run) = run_elo_until("core_lists_us_in_getpeerinfo", |peers| {
        peers.contains("/elo:")
    }) else {
        return;
    };
    assert!(run.status.success(), "elo exited with {}", run.status);
    assert!(
        run.transcript.contains("handshake complete"),
        "{}",
        run.transcript
    );
    let subver = format!("\"subver\": \"/elo:{}/\"", env!("CARGO_PKG_VERSION"));
    assert!(
        run.peers.contains(&subver),
        "Core does not list us:\n{}",
        run.peers
    );
    assert!(run.peers.contains("\"inbound\": true"));
    assert!(
        run.peers.contains("\"relaytxes\": false"),
        "relay=false must turn transaction relay off"
    );
}

#[test]
fn core_measures_our_pong() {
    let Some(run) = run_elo_until("core_measures_our_pong", |peers| {
        peers.contains("\"pingtime\"")
    }) else {
        return;
    };
    assert!(run.status.success(), "elo exited with {}", run.status);
    assert!(run.transcript.contains("-> pong"), "{}", run.transcript);
    assert!(
        run.peers.contains("\"pingtime\""),
        "Core never got our pong:\n{}",
        run.peers
    );
}

fn header_bytes(hex: &str) -> [u8; elo::chain::block_header::BYTES] {
    let mut out = [0u8; elo::chain::block_header::BYTES];
    assert_eq!(hex.len(), 2 * out.len(), "one header: {hex}");
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn core_serves_the_headers_after_genesis() {
    // Red if the transaction-count byte is not skipped between headers, or
    // the hash covers anything but the 80 bytes.
    let Some(node) = node_or_skip("core_serves_the_headers_after_genesis") else {
        return;
    };
    node.cli(&["generatetoaddress", "7", UNSPENDABLE]).unwrap();
    let genesis_hash = node.cli(&["getblockhash", "0"]).unwrap();
    let genesis_hash = genesis_hash.trim();
    let genesis = node
        .cli(&["getblockheader", genesis_hash, "false"])
        .unwrap();
    let genesis = elo::chain::block_header::Header::parse(&header_bytes(genesis.trim()));
    assert_eq!(genesis.hash().to_string(), genesis_hash);
    let best = node.cli(&["getbestblockhash"]).unwrap();
    let best = best.trim();

    let peer: std::net::SocketAddr = format!("127.0.0.1:{}", node.p2p_port).parse().unwrap();
    let stream = std::net::TcpStream::connect(peer).unwrap();
    let mut connection = elo::p2p::connection::Connection::new(
        elo::p2p::link::Tcp::new(stream),
        elo::chain::network::Network::Regtest,
    );
    connection
        .set_read_deadline(Some(connection.now() + std::time::Duration::from_secs(10)))
        .unwrap();
    let now = connection
        .wall()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let our_version = elo::p2p::version::build(peer, i64::try_from(now.as_secs()).unwrap(), 0);
    let mut chain = elo::chain::Chain::new(elo::chain::network::Network::Regtest);
    let mut events = Vec::new();
    elo::peer::run(
        &mut connection,
        &mut chain,
        &our_version,
        std::time::Duration::ZERO,
        |event| {
            println!("{event}");
            events.push(event.to_string());
        },
    )
    .unwrap();
    assert_eq!(chain.height(), 7, "getblockcount is 7");
    assert_eq!(chain.at(1).previous_block.to_string(), genesis_hash);
    assert_eq!(chain.at(0).hash().to_string(), genesis.hash().to_string());
    assert_eq!(chain.tip().to_string(), best, "getbestblockhash");
    assert!(
        events.contains(&format!("synced: height 7, tip {best}")),
        "{events:?}"
    );
    println!("height 7, tip {best} = getbestblockhash");
}

#[test]
fn our_tip_is_core_best_block_after_a_full_batch_and_a_short_one() {
    // Red if the second request is built from the old tip (Core answers
    // with the same 2000 again and the chain refuses them), or a batch of
    // exactly 2000 ends the sync at height 2000.
    let Some(node) = node_or_skip("our_tip_is_core_best_block_after_a_full_batch_and_a_short_one")
    else {
        return;
    };
    node.cli(&["generatetoaddress", "2001", UNSPENDABLE])
        .unwrap();
    let best = node.cli(&["getbestblockhash"]).unwrap();
    let best = best.trim();
    let count = node.cli(&["getblockcount"]).unwrap();
    assert_eq!(count.trim(), "2001");

    let run = run_elo(&node, |peers| peers.contains("/elo:"));
    assert!(run.status.success(), "elo exited with {}", run.status);
    for line in [
        "-> getheaders (from height 0)",
        "<- headers (2000), height 2000",
        "-> getheaders (from height 2000)",
        "<- headers (1), height 2001",
        &format!("synced: height 2001, tip {best}"),
    ] {
        assert!(
            run.transcript.contains(line),
            "no {line:?}:\n{}",
            run.transcript
        );
    }
    println!("getbestblockhash {best}, getblockcount 2001: synced");
}
