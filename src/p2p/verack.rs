pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("verack");

pub(super) fn parse(payload: &[u8]) -> Option<()> {
    payload.is_empty().then_some(())
}
