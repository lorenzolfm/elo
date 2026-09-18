# elo

A Bitcoin node written in Rust

## The working agreement

* Hard requirement: **A pull request may add at most ~500 lines of non-test Rust.** Tests are on top
of that budget and uncapped. If a step does not fit, it is two steps.
* One concept per pull request, one branch per pull request, squash on merge.

## Pull request descriptions

* Title: conventional commits: feat,fix,refactor,docs,test,ci,chore + stated change:
    * Examples:
        * feat: add block header struct and sha256d
        * fix: correct off-by-one in difficulty retargeting
        * refactor: move message envelope to its own module
* What and Why sections.
* use ASD-STE100 Simplified Technical English
* Reference BIPs and Core for protocol facts.

## Commit

* Hard requirement: **linear commit history, shaped for the reviewer**.
* Conventional commits on title. Small descriptive commits.
* use ASD-STE100 Simplified Technical English.

## Dependencies

Always ask before adding.

## Layout

- `src/p2p/` speaks the protocol. One file per message, with its command,
  its payload type, its codec and, where the message does something, its
  `handle`. `frame.rs` is the envelope, `message.rs` the union and the one
  `match` on the command.
- `src/chain/` is what we know: headers, work, the network, the chain. It
  holds the types and the rules.
- `p2p` calls `chain`. `chain` names nothing in `p2p`, in tests too.
- `src/peer.rs` is the one loop: it reads a frame, decodes it, routes the
  message to its handler, and writes what the handler hands back. A handler
  returns messages; it never writes to the connection. The phase of the
  session and every bound on it live in the loop, not in a handler.

## Conventions

- Idiomatic Rust.
- Fully qualified paths at the point of use (`std::net::TcpStream::connect`),
  not `use` imports. Traits are the exception: `use std::io::Read;` is fine.
- **Every value read from the wire is explicitly bounded** before it is used to
  allocate, index, or loop. A length field is attacker-controlled input.
- Invariants get an assertion. An invariant is a fact about
  *our* state. Anything a peer can influence gets an error, never an
  assertion.
- No `unwrap` or `expect` outside tests, no `as` casts anywhere; clippy
  enforces both.
- Hand-rolled error enums with `Display`. No `thiserror`, no `anyhow`.
- Derive only what non-test code uses. No `PartialEq`, `Eq`, `Clone` or
  `Copy` for the sake of a test; a test uses `matches!` or compares fields.
- `#![forbid(unsafe_code)]`.
- `clippy::pedantic` in CI, `cargo fmt` clean.

## Testing

TBD (See https://github.com/lorenzolfm/elo/issues/14)
