# `wtxidrelay` (responder)

24 bytes: a 24-byte envelope and a 0-byte payload.

- Written by: Bitcoin Core daemon version v31.1.0 bitcoind, as the node that accepted the connection
- Network: regtest, magic `fabfb5da`
- Captured by `cargo run --example capture`, proxying between two Core nodes

Core wrote these bytes; elo did not. See `tests/fixtures/README.md`.
