//! Frames that Bitcoin Core sent, for the tests.
//!
//! Captured on 2026-10-25 from `bitcoind -regtest` v31.1.0 (nixpkgs). A Python
//! script opened a v1 connection, sent a `version`, and read each frame Core
//! sent back until `verack`.

/// The `version`. On loopback, the IPs and ports of both addresses are zero.
pub(crate) const VERSION_FRAME: &str = concat!(
    "fabfb5da76657273696f6e000000000066000000b34372e3",
    "80110100090c0000000000002358de6a00000000",
    "0000000000000000000000000000000000000000000000000000",
    "090c000000000000000000000000000000000000000000000000",
    "c9f081ae97771971102f5361746f7368693a33312e312e302f0000000001",
);

/// The `wtxidrelay`, which Core sends after its `version`. No payload.
pub(crate) const WTXIDRELAY_FRAME: &str = "fabfb5da777478696472656c61790000000000005df6e0e2";

/// The `sendaddrv2`, which Core sends after its `wtxidrelay`. No payload.
pub(crate) const SENDADDRV2_FRAME: &str = "fabfb5da73656e646164647276320000000000005df6e0e2";

/// The `verack`: a header and no payload.
pub(crate) const VERACK_FRAME: &str = "fabfb5da76657261636b000000000000000000005df6e0e2";

/// The payload of `VERSION_FRAME`.
pub(crate) fn version_payload() -> Vec<u8> {
    hex(VERSION_FRAME).split_off(crate::transport::HEADER_SIZE)
}

pub(crate) fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
