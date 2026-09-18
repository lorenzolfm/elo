//! The protocol: bytes in, values out, and back. This is what tests and fuzz
//! targets link. `main.rs` is the binary: which peer, how long, what a person
//! reads.

pub mod ancestors;
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
pub mod sync;
pub mod version;
pub mod wire;
