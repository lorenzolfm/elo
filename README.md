# elo

A Bitcoin node daemon. Work in progress: the binary dials one peer, does the
v1 `version`/`verack` handshake and logs the peer's `version`. Then it syncs
the header chain from genesis to the peer's tip and logs the tip: its height,
its hash and its work. The work is the sum of the work of each header, in 64
hex digits. The chain is in memory, and elo checks only that each header
is on the one before it, has proof of work, has the `bits` that the network
requires and has a time above the median of the 11 headers before it. On
testnet4, the first header of a period also has a time at most 10 min below the
header before it. Each time is also at most 2 h after the local clock. On
testnet4, signet and regtest, each header above genesis has a version of at
least 4. On mainnet, a header needs a version of at least 2 from height 227931,
3 from 363725 and 4 from 388381. When the sync ends, the work of the chain must
be at least the minimum of the network, or elo drops the peer. On regtest the
minimum is zero. Below the minimum, a peer can make cheap headers for as long
as it wants, so elo gets the chain twice. The first time, it keeps no header,
only a salted bit of one header in each run of about 600. The second time, each
of those headers must match its bit, and a header goes on the chain when about
15,000 headers are above it, or when the chain reaches the minimum. After the
sync, elo stays connected and answers each `ping` with a `pong`. It also sends
`sendheaders`, so the peer announces each new header with a `headers`. elo puts
those headers on its tip, as a batch of a sync, and logs the `tip` when it
moves. After a reorg, the headers of an announcement are not on the tip of elo.
Then elo asks for the headers again, with the hashes of its tip and of the 11
headers below it, then of headers further down in steps that double, then of
genesis. The peer sends the headers after the highest of them on its chain.
When they are on a header below the tip of elo, elo skips the headers that it
has, and the rest is a branch. elo takes it only when it has more work than the
headers above the header that it is on. On the same work, the branch that elo
had first stays. After a full batch of a branch with no more work, elo asks for
the headers after the last header of the branch, and keeps the branch in memory
until it has more work or ends. elo keeps a branch only while its chain from
genesis has at least the minimum work, and at least the work of elo less the
work of 144 headers at the difficulty of the tip. For a full batch of a branch
below that, elo gets the branch twice in a low-work sync from the header that it
is on, as from genesis, and the minimum of that sync is the work of elo less the
144 headers. Then the branch goes on as one that elo kept. A connection has at
most one low-work sync, so a second one ends it, and the next connection gets a
new salt. Each `getheaders` of a low-work sync or of a branch has only the hash
of the last header that elo got. When a branch ends with no more work, elo keeps
the hash and the work of its last header until the connection ends. Headers that
the peer announces on that header do not make elo ask. elo adds the work of each
one that has its proof of work, and asks only when the branch has more work.
A peer announces a block with an `inv` when its headers do not connect to the
last header it sent, so an `inv` of a block makes elo ask too. From the
handshake on, it pings the peer every 2 min.
It drops a peer that does not answer a `ping` within 20 min, or a `getheaders`
within 2 min. It also drops a peer that sends `wtxidrelay` or `sendaddrv2` after
the handshake. When a connection ends, elo logs the reason, waits 5 s and dials
again. Each connection logs the `version` and the `tip` again. The
chain stays in memory, so the next connection syncs from its tip. A chain below
the minimum work starts again from genesis.

```sh
elo <mainnet|testnet4|signet|regtest> [<ip|name>[:port]]    # IPv6 as [::1]:8333
```

The peer is an IP address or a name. Before each dial, elo looks up the name
with the resolver of the OS, within 30 s. It takes at most 256 of its
addresses, in a random order, and dials them in that order until one takes the
connect. So a name with many addresses, such as a DNS seed, gives a new peer
on each dial. A failed lookup is an `end`, and elo looks up the name again
after 5 s.

With no peer, each dial looks up one DNS seed of the network, at random, as
`x9.<seed>`: a seed answers that name with nodes that serve each block and its
witness data. Some seeds have no such names, so when that lookup fails or gives
no address to dial, elo looks up the seed itself. elo takes at most 32 of its
addresses that the internet routes to, so not this host, a private network, a
link or a test range. A seed chose those peers, and elo trusts them as much as
a peer that you name. A lookup that times out ends the dial at once, because
the resolver does not answer. Regtest has no seeds, so `elo regtest` needs a
peer.

SIGTERM and SIGINT (Ctrl-C) stop elo at any step, also in the wait before a
dial. It logs the signal and exits with 0. elo exits with 1 only on a fault of
this host: its async runtime or its signal handlers do not start, a write to
stdout fails, or a read of `/dev/urandom` fails. A bug panics: elo logs the
panic and exits with 101. Bad usage exits with 2.

## Log

elo writes one line to stdout for each event, in logfmt. A collector of the log, such as the
container runtime, reads stdout and adds the time. elo sends nothing to a log server.

```text
level=info event=version peer=127.0.0.1:18444 version=70016 services=0000000000000c09 user_agent=/Satoshi:31.1.0/ start_height=0 relay=true
level=info event=tip peer=127.0.0.1:18444 height=0 hash=0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206 work=0000000000000000000000000000000000000000000000000000000000000002
level=warn event=end destination=127.0.0.1:18444 reason="the peer closed the connection" wait_ms=5000
level=info event=stop signal=SIGTERM
```

| `event` | `level` | Fields after `event` |
| --- | --- | --- |
| `version` | `info` | `peer` `version` `services` `user_agent` `start_height` `relay` |
| `tip` | `info` | `peer` `height` `hash` `work` |
| `end` | `warn` | `destination` `reason` `wait_ms`: elo dials again after `wait_ms`. `destination` is what the dial looked up or dialed: the peer of the command line, also a name, or the seed, such as `seed.bitcoin.sipa.be.:8333`. `peer` is always the address of a connection |
| `exit` | `error` | `reason`: a fault of this host, and elo exits with 1 |
| `stop` | `info` | `signal`: elo exits with 0 |
| `panic` | `error` | `reason`: a bug, and elo exits with 101 |

The names of the events and of the fields are an interface, so a rename breaks the dashboards and
alerts that match on them. `src/logging.rs` holds the one list of them. A value with a space, a `=`,
a `"` or a control character is in quotes, with escapes. A value is at most 260 bytes, so a line is
at most 16 KiB, whatever the peer sends. When a write to stdout fails, elo writes the `exit` line to
stderr only, because the write that failed can leave part of its line on stdout.

## Build

Nix builds everything. `flake.lock` pins nixpkgs and the other inputs, and
`rust-toolchain.toml` pins the compiler.

```sh
nix build          # the binary, at ./result/bin/elo
nix flake check    # every CI gate: build, clippy, tests, rustfmt, no comments, fuzz corpus
nix develop        # a shell with the pinned toolchain (direnv: `direnv allow`)
```

## Image

Each push to `main` also pushes an image of elo to GHCR, as `ghcr.io/lorenzolfm/elo:main` and
`:sha-<commit>`. CI runs one push at a time and drops a push that waits when a newer one comes, so
a burst of merges gets an image for its last commit only. Before the push, CI runs the image against
a regtest `bitcoind` until it prints the `tip`. The arguments of the image are the arguments of
elo. It runs as user 65534 and needs no volume, no port and no writable path:

```sh
nix build .#elo-image && docker load --input result
docker run --rm --read-only --cap-drop ALL --network host elo:local regtest 127.0.0.1
```

elo is PID 1. The kernel gives PID 1 no default action for a signal, but elo has a handler for
SIGTERM. So a stop ends elo at once, and the container exits with 0.

## Fuzz

Each target in `fuzz/fuzz_targets/` calls a function that only a build with
`--cfg fuzzing` has. The compiler is stable, so the targets run with no sanitizer.

```sh
nix develop -c cargo fuzz run --sanitizer none frame    # Ctrl-C stops it
```

A run writes new inputs to `fuzz/corpus/<target>/` and crashes to
`fuzz/artifacts/<target>/`, and git ignores both. CI replays each committed input
once and does no random run. To keep a crash fixed, copy it to the corpus and run
`git add -f`. The committed corpus is at most 1 MiB. A seed of `machines` also needs
a row in `SEED_ENDS`, which holds how the seed ends. To check the rows, run
`RUSTFLAGS="--cfg fuzzing" cargo test --lib`. It also fails on the new inputs of a
random run, because they have no row. `nix build .#elo-fuzz` sees only tracked files.

Each commit on `main` also pushes the targets of the gate to GHCR, as
`ghcr.io/lorenzolfm/elo-fuzz:main` and `:sha-<commit>`. The image runs one session of
`fuzz/session.sh`, on at most two cores, for the seconds that you give it, up to one day. It
needs no network and writes only to `/data`:

```sh
nix build .#elo-fuzz-image && docker load --input result
mkdir --parents /tmp/elo-fuzz
docker run --rm --read-only --network none --user "$(id -u):$(id -g)" \
  --volume /tmp/elo-fuzz:/data elo-fuzz:local 3600
```

A session fails if a target crashes, and each later session fails until you remove the file. The
crash is at `/tmp/elo-fuzz/crashes/<target>-<commit>-*`. To read it, check out that commit and run
the target with the limits of the session:

```sh
cargo fuzz build --sanitizer none <target>
(ulimit -v 1048576; fuzz/target/*/release/<target> -timeout=30 -runs=10000 <file>)
```

The input runs many times, so a leak reaches the limit.

A session does not start when its files take more than 1 GiB. Then remove files from
`/tmp/elo-fuzz/corpus` by hand.

## Mutants

CI runs `cargo mutants` on the lines that each pull request changes. A missed mutant fails the job.
Then add a test, or add a class to `exclude_re` in `.cargo/mutants.toml`, with its reason. A test
fails after 35 s, so a mutant that hangs a test reads as caught. To run the same check here:

```sh
git -c core.quotePath=false diff origin/main... > /tmp/elo.diff
nix develop -c cargo mutants --in-diff /tmp/elo.diff
```

`nix develop -c cargo mutants` runs each mutant in the crate. `mutants.out/missed.txt` lists what the
tests missed.

cargo-mutants does not mutate inside a macro call, such as `assert!` or `matches!`, or inside an
`impl` function named `new`. A change there passes the job with no mutant, so check those by hand.

## Reproducibility

```sh
nix build .#elo .#elo.cargoArtifacts              # the package and its dependencies
nix build --rebuild .#elo .#elo.cargoArtifacts    # builds both again, and fails if the bytes differ
```

`--rebuild` compares with an earlier build, so run the first command once.

CI runs this check on every pull request.
