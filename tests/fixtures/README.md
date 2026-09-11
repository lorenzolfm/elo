# Fixtures

Every file here is bytes Bitcoin Core wrote. None of them is bytes elo wrote.

A codec test that round-trips our own encoder through our own decoder proves
nothing: both halves can be wrong in the same direction and the test still
passes. Encode the checksum as a single SHA-256 instead of a double and the
round trip never notices. These captures are the anchor that makes the tests
mean something.

## Layout

- `initiator/` — written by the node that opened the connection
- `responder/` — written by the node that accepted it

Both are Bitcoin Core, so both are equally good fixtures; the split matters
because some messages only ever appear on one side, and because the same
command carries different contents depending on who is asking.

Each `.hex` has a `.md` beside it recording the Core version, the network, the
side that wrote it and how it was captured.

## Where they came from

`cargo run --example capture` stands a proxy between two regtest Core nodes —
one with a short mined chain, one that knows nothing — and records both
directions while the second syncs from the first. The tool encodes nothing and
alters nothing; it slices the stream on the magic bytes and the length field and
copies the rest through untouched.

## Caveats

These are **regtest** captures, so they carry magic `fabfb5da`. Mainnet is
`f9beb4d9`. Code that treats the magic as a constant will pass every test here
and fail against the real network.
