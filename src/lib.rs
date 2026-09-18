//! The protocol: bytes in, values out, and back. This is what tests and fuzz
//! targets link. `main.rs` is the binary: which peer, how long, what a person
//! reads.

mod ancestors;
pub mod block_header;
pub mod chain;
mod compact_size;
pub mod connection;
pub mod handshake;
pub mod headers;
pub mod link;
pub mod locator;
pub mod message;
pub mod pow;
// Test code only: no `main.rs`, `tests/` or fuzz target drives a loop
// against a fake.
#[cfg(test)]
mod scripted;
pub mod sync;
pub mod version;
pub mod wire;
