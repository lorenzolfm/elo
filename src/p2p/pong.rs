//! `pong`: a `ping` nonce echoed (BIP31). Core answers ours at
//! `../bitcoin/src/net_processing.cpp:4985` at v31.1. We never send a
//! `ping`, so a `pong` that arrives answers nothing and is dropped; it is
//! decoded so that it is a value and not an unknown frame.

pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("pong");

/// The nonce, or `None` when the payload is not the one nonce. The same
/// shape as a `ping`, read the same way.
pub(super) fn parse(payload: &[u8]) -> Option<u64> {
    crate::p2p::ping::parse(payload)
}

/// The nonce, little-endian, as Core writes it.
pub(super) fn encode(nonce: u64) -> Vec<u8> {
    crate::p2p::ping::encode(nonce)
}
