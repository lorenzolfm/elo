# elo

A Bitcoin node daemon. Work in progress: the binary dials one peer, does the
v1 `version`/`verack` handshake and prints the peer's `version`. Then it syncs
the header chain from genesis to the peer's tip and prints
`tip <height> <hash> <work>`. The work is the sum of the work of each header,
in 64 hex digits. The chain is in memory, and elo checks only that each header
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
sync, elo stays connected and answers each `ping` with a `pong`. From the
handshake on, it pings the peer every 2 min. It drops a peer that does not
answer a `ping` within 20 min, or a `getheaders` within 2 min. It also drops a
peer that sends `wtxidrelay` or `sendaddrv2` after the handshake. When a
connection ends, elo prints `elo: <reason>; dial again in 5 s` to stderr, waits
5 s and dials the peer again. Each connection prints the `version` and the `tip`
again. The chain stays in memory, so the next connection syncs from its tip. A
chain below the minimum work starts again from genesis, and so does a chain
whose tip the peer does not have, because elo cannot choose between two
branches yet.

```sh
elo <mainnet|testnet4|signet|regtest> <ip>[:port]    # IPv6 as [::1]:8333
```

SIGTERM and SIGINT (Ctrl-C) stop elo at any step, also in the wait before a
dial. It prints the signal to stderr, for example `elo: SIGTERM; stop`, and
exits with 0. elo exits with 1 only on a fault of this host: its async runtime
or its signal handlers do not start, a write to stdout fails, or a read of
`/dev/urandom` fails. Bad usage exits with 2.

## Build

Nix builds everything. `flake.lock` pins nixpkgs and the other inputs, and
`rust-toolchain.toml` pins the compiler.

```sh
nix build          # the binary, at ./result/bin/elo
nix flake check    # every CI gate: build, clippy, tests, doctests, rustfmt, fuzz corpus
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
