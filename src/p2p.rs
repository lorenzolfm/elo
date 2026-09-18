//! The peer protocol: bytes in, messages out, and back. Nothing here
//! decides what a header means; that is `chain`, which this layer calls and
//! which never calls back.

pub(crate) mod compact_size;
pub mod connection;
pub mod frame;
pub mod getheaders;
pub mod headers;
pub mod link;
pub mod message;
pub mod ping;
pub mod pong;
// Test code only: no `main.rs`, `tests/` or fuzz target drives a loop
// against a fake.
#[cfg(test)]
pub(crate) mod scripted;
pub mod verack;
pub mod version;
