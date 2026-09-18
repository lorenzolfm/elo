//! `ping`: a nonce the peer wants echoed, so that it knows we are still
//! here. Core sends one right after the handshake and every two minutes
//! (`../bitcoin/src/net_processing.cpp:5507` at v31.1), and drops a peer
//! whose `pong` is twenty minutes late (`:5495`, `TIMEOUT_INTERVAL` in
//! `net.h:59`). We never send one.

pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("ping");

/// `ping` and `pong` carry one `u64` nonce since BIP31. Core reads exactly
/// that from a `ping` (`net_processing.cpp:4973`) and echoes it in the `pong`
/// (`:4985`).
pub(super) const NONCE_BYTES: usize = 8;

/// The nonce, or `None` when the payload is not exactly `NONCE_BYTES`. Core
/// ignores the tail of a long `ping` and only logs a short one (`:5283`); a
/// known command with a length it cannot have is a peer we do not want.
pub(super) fn parse(payload: &[u8]) -> Option<u64> {
    // `try_from` fails on exactly one condition: the slice is not 8 bytes.
    <[u8; NONCE_BYTES]>::try_from(payload)
        .map(u64::from_le_bytes)
        .ok()
}

/// The nonce, little-endian, as Core writes it.
pub(super) fn encode(nonce: u64) -> Vec<u8> {
    nonce.to_le_bytes().to_vec()
}

/// The one reply a `ping` has: its nonce back in a `pong`. The handler
/// touches nothing else, so a `ping` at any point in the session is safe to
/// answer.
#[must_use]
pub fn handle(nonce: u64) -> crate::p2p::message::Message {
    crate::p2p::message::Message::Pong(nonce)
}
