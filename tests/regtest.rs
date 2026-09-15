//! Spawns a `bitcoind -regtest`, points elo at it, and asks Core what it saw.
//! `getpeerinfo` is the oracle for every claim about the binary; for the
//! library over its own socket, the chain RPCs are.
//!
//! Fails when `bitcoind` or `bitcoin-cli` is not on `PATH`, unless
//! `ELO_NO_BITCOIND` is set; then it skips, and says so past the harness's
//! output capture. CI sets the variable; a developer should not have to.

// This whole file is a test. Clippy's `allow-unwrap-in-tests` only sees
// `#[test]` functions and `#[cfg(test)]` items, not the helpers here.
#![allow(clippy::unwrap_used)]

/// Ports are picked by binding and releasing, because `bitcoind` cannot bind
/// port 0. Between the release and Core's own bind, another test picking the
/// same way can be handed the same ports, and the datadir is named after one
/// of them. Picking and starting under this lock closes the window: the next
/// spawn picks only once this node holds its ports.
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
        // A test that panicked while starting poisons the lock; the ports it
        // was after are free again, so the next spawn goes ahead regardless.
        let _spawning = SPAWN
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (p2p_port, rpc_port) = free_ports();
        let datadir = std::env::temp_dir().join(format!("elo-handshake-{p2p_port}"));
        // A run that was killed leaves its datadir behind, and a later run
        // that draws the same port would inherit its chain. No datadir is
        // the normal case; any other failure is this run's problem.
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

/// What Core saw and what elo printed, once `done` holds for `getpeerinfo`
/// or ten seconds have passed. `None` when there is no `bitcoind` and
/// `ELO_NO_BITCOIND` says that is fine.
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
        .arg(format!("127.0.0.1:{}", node.p2p_port))
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // elo lingers two seconds after the handshake; ask Core meanwhile.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let peers = loop {
        let peers = node.cli(&["getpeerinfo"]).unwrap();
        if done(&peers) || std::time::Instant::now() > deadline {
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

/// `ADDRESS_BCRT1_UNSPENDABLE`, `../bitcoin/test/functional/test_framework/address.py:35`:
/// a witness program of all zeros, so `generatetoaddress` needs no wallet.
const UNSPENDABLE: &str = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3xueyj";

/// Core puts its chain height in `version`: `my_height = m_best_height`,
/// `../bitcoin/src/net_processing.cpp:1572` at v31.1. Mine a few blocks first so the number is not zero, then check the
/// one elo prints against `getblockcount`.
#[test]
fn core_tells_us_its_height() {
    let Some(node) = node_or_skip("core_tells_us_its_height") else {
        return;
    };
    node.cli(&["generatetoaddress", "7", UNSPENDABLE]).unwrap();
    // `m_best_height` is set by `UpdatedBlockTip` (`net_processing.cpp:2162`)
    // on the scheduler thread, after `generatetoaddress` has returned. Wait
    // for it, or the `version` can still say 6.
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

/// Core pings a new peer as soon as the handshake is done, and reports
/// `pingtime` only once a `pong` with the matching nonce came back
/// (`../bitcoin/src/rpc/net.cpp:254` at v31.1).
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

/// `getblockheader <hash> false`, as bytes.
fn header_bytes(hex: &str) -> [u8; elo::block_header::BYTES] {
    let mut out = [0u8; elo::block_header::BYTES];
    assert_eq!(hex.len(), 2 * out.len(), "one header: {hex}");
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Core answers `getheaders` with the headers after the first locator hash
/// it knows, up to 2000 (`../bitcoin/src/net_processing.cpp:4441` and
/// `:4453` at v31.1). A locator of genesis alone on a chain of seven must
/// bring back seven, and the last must hash to `getbestblockhash`.
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
    let genesis = elo::block_header::Header::parse(&header_bytes(genesis.trim()));
    assert_eq!(genesis.hash().to_string(), genesis_hash);
    let best = node.cli(&["getbestblockhash"]).unwrap();
    let best = best.trim();

    let peer: std::net::SocketAddr = format!("127.0.0.1:{}", node.p2p_port).parse().unwrap();
    let stream = std::net::TcpStream::connect(peer).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let our_version = elo::version::build(peer, i64::try_from(now.as_secs()).unwrap(), 0);
    let network = elo::message::Network::Regtest;
    let elo::handshake::Complete { mut stream, .. } =
        elo::handshake::run(stream, network, &our_version).unwrap();

    let request = elo::wire::Message::GetHeaders(elo::headers::GetHeaders {
        locator: vec![genesis.hash()],
        stop: None,
    });
    println!("-> {request}");
    let request = request.encode();
    elo::message::write(&mut stream, network, request.command, &request.payload).unwrap();

    // Core's post-verack burst comes first: `sendcmpct`, `ping`, `feefilter`.
    let headers = (0..8)
        .find_map(|_| {
            let frame = elo::message::read(&mut stream, network).unwrap();
            match elo::wire::Message::decode(frame).unwrap() {
                elo::wire::Message::Headers(headers) => Some(headers),
                other => {
                    println!("<- {other} skipped");
                    None
                }
            }
        })
        .unwrap_or_else(|| panic!("no headers in eight frames"));

    assert_eq!(headers.len(), 7, "getblockcount is 7");
    assert_eq!(headers[0].previous_block.to_string(), genesis_hash);
    for pair in headers.windows(2) {
        assert_eq!(
            pair[1].previous_block.to_string(),
            pair[0].hash().to_string(),
            "each header names the one before"
        );
    }
    let tip = headers.last().unwrap().hash();
    assert_eq!(tip.to_string(), best, "getbestblockhash");
    println!(
        "<- headers ({}), tip {tip} = getbestblockhash",
        headers.len()
    );
}
