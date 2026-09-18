//! The protocol: bytes in, values out, and back. This is what tests and fuzz
//! targets link. `main.rs` is the binary: which peer, how long, what a person
//! reads.
//!
//! Two layers and a loop. `p2p` speaks to the peer: frames, messages, one
//! file per message with its handler. `chain` is what we know: headers,
//! work, the network. `peer` is the session: it reads frames, routes each
//! message to its handler, and writes what the handler hands back. `p2p`
//! calls `chain`; `chain` names nothing in `p2p`; only `peer` names both.

pub mod chain;
pub mod p2p;
pub mod peer;
