pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("ping");

pub(super) const NONCE_BYTES: usize = 8;

pub(super) fn parse(payload: &[u8]) -> Option<u64> {
    <[u8; NONCE_BYTES]>::try_from(payload)
        .map(u64::from_le_bytes)
        .ok()
}

pub(super) fn encode(nonce: u64) -> Vec<u8> {
    nonce.to_le_bytes().to_vec()
}

#[must_use]
pub fn handle(nonce: u64) -> crate::p2p::message::Message {
    crate::p2p::message::Message::Pong(nonce)
}
