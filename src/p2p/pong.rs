pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("pong");

pub(super) fn parse(payload: &[u8]) -> Option<u64> {
    crate::p2p::ping::parse(payload)
}

pub(super) fn encode(nonce: u64) -> Vec<u8> {
    crate::p2p::ping::encode(nonce)
}
