//! The protocol: bytes in, values out, and back. This is what tests and fuzz
//! targets link. `main.rs` is the binary: which peer, how long, what a person
//! reads.

// Nothing reads a header until step 6, `getheaders`.
#[expect(dead_code)]
mod block_header;
mod compact_size;
pub mod handshake;
pub mod message;
pub mod version;
pub mod wire;
