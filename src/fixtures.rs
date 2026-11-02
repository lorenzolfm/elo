//! Frames that Bitcoin Core sent, for the tests.
//!
//! Captured on 2026-10-25 from `bitcoind -regtest` v31.1.0 (nixpkgs). A Python
//! script opened a v1 connection, sent a `version`, and read each frame Core
//! sent back until `verack`.
//!
//! The frames after the handshake were captured on 2026-10-26 the same way. The script also
//! sent its `verack` and answered the `ping`. Then `generatetodescriptor 1` mined block 1.

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

/// The `sendcmpct`, which Core sends after our `verack`: high bandwidth off, version 2.
pub(crate) const SENDCMPCT_FRAME: &str =
    "fabfb5da73656e64636d70637400000009000000e92f5ef8000200000000000000";

/// The `ping`, which Core sends after its `sendcmpct`. The nonce is random.
pub(crate) const PING_FRAME: &str =
    "fabfb5da70696e670000000000000000080000006c3569e3d84520892932e934";

/// The `feefilter`, which Core sends after its `ping`. Core was in IBD, so the fee rate is
/// its highest: 9,936,506 sat/kvB.
pub(crate) const FEEFILTER_FRAME: &str =
    "fabfb5da66656566696c746572000000080000000a19f7997a9e970000000000";

/// The `inv` for block 1, which Core sends when its tip changes.
pub(crate) const BLOCK_INV_FRAME: &str = concat!(
    "fabfb5da696e7600000000000000000025000000dcc9e6bf",
    "0102000000faf4d233a8d1e92d0b03cd5dcc530307fdca5133639c54520be1a98d48ff6939",
);

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
