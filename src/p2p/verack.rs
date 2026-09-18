//! `verack`: the peer took our `version`. No payload. Core sends it after
//! its own `version` and its feature negotiation
//! (`../bitcoin/src/net_processing.cpp:3744` at v31.1); ours goes out as
//! soon as the peer's `version` parses.
//!
//! What a `verack` means is a question of where the session is: before the
//! peer's `version` it is an error, after it the handshake is complete. That
//! is the loop's to decide, so there is no handler here.

pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("verack");

/// `Some` for the empty payload a `verack` has, `None` for any other. Core
/// does not look at a `verack`'s payload; we refuse one that has any.
pub(super) fn parse(payload: &[u8]) -> Option<()> {
    payload.is_empty().then_some(())
}
