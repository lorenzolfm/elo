//! The protocol: bytes in, values out, and back. This is what tests and fuzz
//! targets link. `main.rs` is the binary: which peer, how long, what a person
//! reads.
//!
//! Two layers. `p2p` speaks to the peer: frames, messages, and one file per
//! message. `chain` is what we know: headers, work, the network. `p2p` calls
//! `chain`; `chain` names nothing in `p2p`.

pub mod chain;
pub mod handshake;
pub mod p2p;
pub mod sync;
