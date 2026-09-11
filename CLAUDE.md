# elo

A Bitcoin node written in Rust, built to be learned rather than shipped.

The previous attempt (`../bitmigo`) reached 40k lines in a day with commits of
1,200–4,900 insertions each. Nothing that large gets reviewed, so nothing was
learned. This repository exists to fix that, and every rule below serves it.

## The working agreement

Claude writes the code and the tests. Lorenzo reviews every pull request and
intervenes where he wants — there is no mandatory ritual, only a reviewable
diff.

**A pull request may add at most ~200 lines of non-test Rust.** Tests are on top
of that budget and uncapped. If a step does not fit, it is two steps. This is
the load-bearing rule; treat it as hard.

One concept per pull request, one branch per pull request, squash on merge.

## Pull request descriptions

A decision log. No primer, no tutorial.

- what the step does
- which decisions were made, and which alternatives were rejected and why
- which of those decisions Claude was *not* confident about, named as such

If a protocol fact is load-bearing, cite where it came from (BIP number and
section, or a file and line in `../bitcoin` at v31.1). Guesses are labelled as
guesses.

`docs/decisions/NNNN-*.md` gets a record only when a decision reaches past its
own pull request — a new dependency, a wire invariant, an on-disk format.

## Scope

The first main goal is **headers to tip**: connect to one peer, sync every
block header from genesis, verify proof of work and difficulty retargeting,
hold the chain in memory.

Blocks, storage, validation, mempool, RPC, multi-peer, DNS seeding: later
milestones. Do not design for them now. `ROADMAP.md` holds the ladder.

## Dependencies

`bitcoin_hashes` for `sha256d`, and nothing else. `secp256k1` joins when
signature checking does.

Everything Bitcoin-shaped is ours: the message envelope, `CompactSize`, the
`version` payload, the 80-byte header, the compact target, the block locator.
The `bitcoin` crate is not a dependency and must not become one — its decoders
already enforce the invariants this project exists to discover.

Adding a dependency is a decision record and a conversation, not a line in
`Cargo.toml`.

## The clean room

`../bitmigo` contains a finished, differential-tested consensus crate that
answers many of the questions ahead. **Claude does not read it while
implementing.** Derive from the BIPs, from Core v31.1 at `../bitcoin`, and from
bytes captured off the wire.

Lorenzo may open bitmigo after a pull request merges. Anything better in there
becomes a new pull request with its own rationale.

## Shape

Single-threaded, blocking sockets, one peer. One binary crate, plain modules.

Multi-peer is the trigger to revisit the I/O model — after the constraint has
actually been felt, not before.

## Conventions

- Idiomatic Rust. No TigerStyle ceremony.
- **Every value read from the wire is explicitly bounded** before it is used to
  allocate, index, or loop. A length field is attacker-controlled input.
- Invariants get an assertion, not a comment.
- Hand-rolled error enums with `Display`. No `thiserror`, no `anyhow`.
- `#![forbid(unsafe_code)]`.
- `clippy::pedantic` in CI, `cargo fmt` clean.

## Testing

Three oracles, each doing what it is good at.

1. **Committed fixtures**, in `tests/fixtures/`, every one captured from Bitcoin
   Core and carrying a note saying where it came from. Codec tests assert
   against these bytes. A test that round-trips our encoder through our decoder
   proves nothing — both halves can be wrong together.
2. **A spawned `bitcoind -regtest`** when a test needs a conversation or a chain
   shape we control (reorgs, a chain of known height).
3. **The homelab node** as the milestone gate. Not a test; a demonstration.

`cargo test` is the demo. A pull request whose tests print nothing meaningful is
a pull request that cannot be reviewed.
