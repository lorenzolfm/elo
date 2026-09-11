//! Capture real Bitcoin Core P2P bytes into `tests/fixtures/`.
//!
//! Throwaway tooling, deleted once the corpus is complete. It exists so that
//! elo's codec tests are anchored to bytes Core produced rather than bytes elo
//! produced: a test that round-trips our own encoder through our own decoder
//! passes happily with both halves wrong. Get the checksum as a single SHA-256
//! instead of a double and the round trip never notices.
//!
//! # Why a proxy
//!
//! The obvious design — dial a node and talk to it — needs an encoder for
//! `version`, which is PR 3, plus the envelope and `CompactSize`, which are PRs
//! 1 and 2. Writing those here would mean reviewing them later having already
//! written and validated them, which defeats the point.
//!
//! So this tool encodes nothing. It stands between two real Core nodes and
//! copies bytes: a miner with a short chain, a syncer that knows nothing, and a
//! proxy in the middle recording both directions of their conversation. Every
//! captured byte was written by Bitcoin Core. The only protocol knowledge here
//! is how to find a message boundary — the four magic bytes and the length at
//! offset 16 — and that is used to *slice* the stream, never to rewrite it.
//!
//! Running two nodes rather than one also means the syncer performs a real
//! initial sync against the miner, so the capture includes `getheaders`,
//! `headers`, `inv`, `getdata` and `block` with actual content in them.
//!
//! # Running it
//!
//! ```text
//! cargo run --example capture
//! ```
//!
//! Requires `bitcoind` and `bitcoin-cli` on `PATH`. Both nodes run on regtest
//! in temporary datadirs and are stopped and deleted on the way out.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Regtest message start bytes, `src/kernel/chainparams.cpp` in Core v31.1.
/// Mainnet is `f9beb4d9`; see the note in the pull request about why that
/// difference must not be hardcoded away.
const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda];

/// A bound on the payload length a peer claims, so a desync cannot make this
/// tool sit waiting for gigabytes. Core's own limit is 32 MiB.
const MAX_PAYLOAD: usize = 32 * 1024 * 1024;

/// An anyone-can-spend output script, as a descriptor. Mining to a descriptor
/// avoids needing a wallet at all. The checksum is Core's, from
/// `getdescriptorinfo 'raw(51)'`.
const COINBASE_DESCRIPTOR: &str = "raw(51)#8lvh9jxk";

const MINE_BLOCKS: u32 = 20;
const CAPTURE_FOR: Duration = Duration::from_secs(8);
const POLL: Duration = Duration::from_millis(250);

/// Core binds `port + 1` on localhost alongside the P2P port, so node ports are
/// spaced by two and the RPC ports live well clear of both.
struct Node {
    name: &'static str,
    p2p: u16,
    rpc: u16,
}

const MINER: Node = Node {
    name: "miner",
    p2p: 18545,
    rpc: 18600,
};
const SYNCER: Node = Node {
    name: "syncer",
    p2p: 18547,
    rpc: 18602,
};
const PROXY_PORT: u16 = 18604;

fn main() {
    let root = std::env::temp_dir().join(format!("elo-capture-{}", std::process::id()));
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    let mut miner = start(&MINER, &root);
    let mut syncer = start(&SYNCER, &root);

    let captured = run(&root);

    stop(&MINER, &root, &mut miner);
    stop(&SYNCER, &root, &mut syncer);
    fs::remove_dir_all(&root).ok();

    let core = version_line();
    let mut total = 0;
    for (direction, stream) in captured {
        for (command, raw) in slice(&stream) {
            let dir = fixtures.join(direction.dir());
            fs::create_dir_all(&dir).expect("create fixture directory");
            let hex = dir.join(format!("{command}.hex"));
            if hex.exists() {
                continue; // first occurrence only
            }
            fs::write(&hex, format!("{}\n", to_hex(&raw))).expect("write fixture");
            fs::write(
                dir.join(format!("{command}.md")),
                provenance(&command, &raw, direction, &core),
            )
            .expect("write provenance");
            println!(
                "  {:>9} {:<12} {:>7} bytes",
                direction.dir(),
                command,
                raw.len()
            );
            total += 1;
        }
    }
    println!("{total} fixtures written");
    assert!(total > 0, "captured nothing: is bitcoind on PATH?");
}

/// Which node wrote the bytes. Both are Core, so both sides are equally good
/// fixtures, and some messages only ever appear on one of them.
#[derive(Clone, Copy)]
enum Direction {
    /// Sent by the node that opened the connection.
    Initiator,
    /// Sent by the node that accepted it.
    Responder,
}

impl Direction {
    fn dir(self) -> &'static str {
        match self {
            Direction::Initiator => "initiator",
            Direction::Responder => "responder",
        }
    }
}

/// Mine a chain on the miner, put the syncer onto the proxy, and record both
/// halves of the conversation until the capture window closes.
fn run(root: &Path) -> Vec<(Direction, Vec<u8>)> {
    rpc(
        &MINER,
        root,
        &[
            "generatetodescriptor",
            &MINE_BLOCKS.to_string(),
            COINBASE_DESCRIPTOR,
        ],
    );
    let height = rpc(&MINER, root, &["getblockcount"]);
    println!("miner at height {}", height.trim());

    let listener = TcpListener::bind(("127.0.0.1", PROXY_PORT)).expect("bind proxy");
    rpc(
        &SYNCER,
        root,
        &["addnode", &format!("127.0.0.1:{PROXY_PORT}"), "onetry"],
    );

    let (from_syncer, _) = listener.accept().expect("syncer never connected");
    let to_miner = TcpStream::connect(("127.0.0.1", MINER.p2p)).expect("connect to miner");
    println!("proxying, capturing for {}s", CAPTURE_FOR.as_secs());

    let deadline = Instant::now() + CAPTURE_FOR;
    let a = pump(
        from_syncer.try_clone().expect("clone"),
        to_miner.try_clone().expect("clone"),
        deadline,
    );
    let b = pump(to_miner, from_syncer, deadline);
    vec![
        (Direction::Initiator, a.join().expect("pump panicked")),
        (Direction::Responder, b.join().expect("pump panicked")),
    ]
}

/// Copy `from` into `to` until the deadline, keeping everything that passed
/// through. Bytes are forwarded untouched; this is a wire, not a participant.
fn pump(mut from: TcpStream, mut to: TcpStream, deadline: Instant) -> thread::JoinHandle<Vec<u8>> {
    from.set_read_timeout(Some(POLL)).expect("set read timeout");
    thread::spawn(move || {
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 65536];
        while Instant::now() < deadline {
            match from.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    seen.extend_from_slice(&buf[..n]);
                    if to.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        to.shutdown(Shutdown::Both).ok();
        seen
    })
}

/// Cut a byte stream into whole messages. Reads the magic and the length at
/// offset 16 and nothing else — no checksum is computed, no field is
/// interpreted, no byte is altered.
fn slice(stream: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = stream;
    while rest.len() >= 24 {
        assert_eq!(rest[..4], MAGIC, "desync: not a message boundary");
        let length = u32::from_le_bytes([rest[16], rest[17], rest[18], rest[19]]) as usize;
        assert!(
            length <= MAX_PAYLOAD,
            "payload length {length} over the bound"
        );
        if rest.len() < 24 + length {
            break; // truncated by the capture window closing
        }
        let command = String::from_utf8_lossy(&rest[4..16])
            .trim_end_matches('\0')
            .to_string();
        out.push((command, rest[..24 + length].to_vec()));
        rest = &rest[24 + length..];
    }
    out
}

fn start(node: &Node, root: &Path) -> Child {
    let datadir = root.join(node.name);
    fs::create_dir_all(&datadir).expect("create datadir");
    let child = Command::new("bitcoind")
        .args([
            "-regtest",
            &format!("-datadir={}", datadir.display()),
            &format!("-port={}", node.p2p),
            &format!("-rpcport={}", node.rpc),
            // elo speaks v1. Core has defaulted to the BIP324 encrypted
            // transport for several releases, and as initiator it opens with an
            // ElligatorSwift key and random garbage — no magic, nothing to slice.
            "-v2transport=0",
            "-dnsseed=0",
            "-printtoconsole=0",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("bitcoind not on PATH");

    let mut child = child;
    for _ in 0..100 {
        if try_rpc(node, root, &["getblockcount"]).is_some() {
            return child;
        }
        thread::sleep(POLL);
    }
    child.kill().ok();
    child.wait().ok();
    panic!("{} never answered RPC", node.name);
}

fn stop(node: &Node, root: &Path, child: &mut Child) {
    try_rpc(node, root, &["stop"]);
    for _ in 0..100 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(POLL);
    }
    child.kill().ok();
    child.wait().ok();
}

fn rpc(node: &Node, root: &Path, args: &[&str]) -> String {
    try_rpc(node, root, args).unwrap_or_else(|| panic!("{} rpc failed: {args:?}", node.name))
}

fn try_rpc(node: &Node, root: &Path, args: &[&str]) -> Option<String> {
    let datadir: PathBuf = root.join(node.name);
    let out = Command::new("bitcoin-cli")
        .args([
            "-regtest",
            &format!("-datadir={}", datadir.display()),
            &format!("-rpcport={}", node.rpc),
        ])
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn version_line() -> String {
    Command::new("bitcoind")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            write!(s, "{b:02x}").expect("write to string");
            s
        })
}

fn provenance(command: &str, raw: &[u8], direction: Direction, core: &str) -> String {
    let side = match direction {
        Direction::Initiator => "the node that opened the connection",
        Direction::Responder => "the node that accepted the connection",
    };
    format!(
        "# `{command}` ({})\n\n\
         {} bytes: a 24-byte envelope and a {}-byte payload.\n\n\
         - Written by: {core}, as {side}\n\
         - Network: regtest, magic `{}`\n\
         - Captured by `cargo run --example capture`, proxying between two Core nodes\n\n\
         Core wrote these bytes; elo did not. See `tests/fixtures/README.md`.\n",
        direction.dir(),
        raw.len(),
        raw.len() - 24,
        to_hex(&MAGIC),
    )
}
