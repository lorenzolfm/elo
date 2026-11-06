//! Frames that Bitcoin Core sent, for the tests.
//!
//! Captured on 2026-10-25 from `bitcoind -regtest` v31.1.0 (nixpkgs). A Python
//! script opened a v1 connection, sent a `version`, and read each frame Core
//! sent back until `verack`.
//!
//! The frames after the handshake were captured on 2026-10-26 the same way. The script also
//! sent its `verack` and answered the `ping`. Then `generatetodescriptor 1` mined block 1.
//!
//! The `headers` frame was captured on 2026-11-03 the same way, on a new chain. First
//! `generatetodescriptor 2` mined blocks 1 and 2. After the handshake, the script sent its
//! `verack` and a `getheaders` with genesis as the only locator hash.
//!
//! The `getheaders` frame was captured on 2026-11-03 from a new node with only genesis. The
//! script listened, and `addnode 127.0.0.1:<port> onetry false` made Core connect to it with
//! v1. The script claimed `NODE_NETWORK` in its `version`, then sent its `verack`. Core sent
//! the `getheaders` after its `ping`.

use crate::serialize::Encode;

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

/// The `headers` reply to a `getheaders` from genesis: blocks 1 and 2, each with a
/// transaction count of 0.
pub(crate) const HEADERS_FRAME: &str = concat!(
    "fabfb5da686561646572730000000000a30000006ba96776",
    "02",
    "0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
    "f90344ddd9a16af4f07ed7af45a2e9aec7b443ae92f7bf6560bbaea78cb122b9",
    "ede8e96affff7f2000000000",
    "00",
    "000000206fd9534f8c89df2b57a96335562c10ee824530e786527a906ad55f589b0b6541",
    "22ea6542f9b592e9cc0b8d6e02eeac9212efd6eda177ed157d9321680975d678",
    "eee8e96affff7f2000000000",
    "00",
);

/// The hash of block 1 in `HEADERS_FRAME`, as `getblockhash 1` wrote it.
pub(crate) const BLOCK_1_HASH: &str =
    "41650b9b585fd56a907a5286e7304582ee102c563563a9572bdf898c4f53d96f";

/// The hash of block 2 in `HEADERS_FRAME`, as `getblockhash 2` wrote it.
pub(crate) const BLOCK_2_HASH: &str =
    "29d4ecbe35de0c35851f0ae8bb5070fbc2273c65b1538591f3deb3179883456a";

/// The `getheaders` that Core sends to a new peer: version 70016, the genesis hash as the only
/// locator hash, and a `hash_stop` of all zeros.
pub(crate) const GETHEADERS_FRAME: &str = concat!(
    "fabfb5da6765746865616465727300004500000070e012a4",
    "80110100",
    "01",
    "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
    "0000000000000000000000000000000000000000000000000000000000000000",
);

/// The payload of `VERSION_FRAME`.
pub(crate) fn version_payload() -> Vec<u8> {
    hex(VERSION_FRAME).split_off(crate::transport::MESSAGE_HEADER_SIZE)
}

/// The payload of `HEADERS_FRAME`.
pub(crate) fn headers_payload() -> Vec<u8> {
    hex(HEADERS_FRAME).split_off(crate::transport::MESSAGE_HEADER_SIZE)
}

/// `count` headers, each on the header before it, the first on the regtest genesis header. Each
/// is the genesis header with its `prev` and its `nonce` changed.
pub(crate) fn headers_on_genesis(count: usize) -> Vec<crate::block::BlockHeader> {
    let genesis = crate::chainparams::Network::Regtest.genesis();
    let on = |below: &crate::block::BlockHeader| {
        crate::pow::mined_for_regtest(crate::block::BlockHeader {
            prev: below.hash(),
            ..genesis
        })
    };
    std::iter::successors(Some(on(&genesis)), |below| Some(on(below)))
        .take(count)
        .collect()
}

/// A `headers` payload with `headers`, each with a transaction count of 0.
pub(crate) fn headers_payload_with(headers: &[crate::block::BlockHeader]) -> Vec<u8> {
    let mut payload = Vec::new();
    crate::serialize::write_compact_size(&mut payload, headers.len());
    for header in headers {
        header.encode(&mut payload);
        payload.push(0);
    }
    payload
}

/// `headers` as a batch for the chain. It goes through `decode`, so `Headers` has no constructor
/// for the tests.
pub(crate) fn headers_batch(headers: &[crate::block::BlockHeader]) -> crate::protocol::Headers {
    crate::protocol::Headers::decode(&mut headers_payload_with(headers).as_slice()).unwrap()
}

/// A hash in hex, in the order a display shows it: the reverse of the wire order.
pub(crate) fn hash_from_display_hex(s: &str) -> bitcoin_hashes::sha256d::Hash {
    let mut bytes: [u8; 32] = hex(s).try_into().unwrap();
    bytes.reverse();
    bitcoin_hashes::sha256d::Hash::from_byte_array(bytes)
}

pub(crate) fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
