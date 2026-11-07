//! Frames that Bitcoin Core sent and real headers, for the tests.
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
//!
//! The real headers of the other networks were captured on 2026-11-06 from the API of
//! mempool.space. A script checked that each hash is the hash of the explorer and is at most its
//! target, and that each `prev` of a next height is the hash below it.

use crate::serialize::{Decode, Encode};

/// Real headers of mainnet at the first change of its target: the first header of the period, the
/// last header of the period, and the next header.
pub(crate) const MAINNET_RETARGET: [&str; 3] = [
    // Height 30240.
    concat!(
        "01000000e6bf7fd7f7790a63786faa878d0dc7fd8f2ff365732e45862c66075100000000",
        "700d342f65c7b6834dffb615358a1897016f0448913372190cbe3d27a4b53355",
        "b1512b4bffff001dbfb02519",
    ),
    // Height 32255.
    concat!(
        "0100000049c1daab3b6536ff1b2633c3a316a6e06ec287676cdeec4ca7baae6b00000000",
        "ac10b36b8f354b3353207de15940a5edbc05bb8364af75b4b5409e7823f2b489",
        "23ec3a4bffff001dbd5fa412",
    ),
    // Height 32256.
    concat!(
        "010000004b0360d834a330ec7833e30e1f523ee05a0793361e29a73421964f9800000000",
        "27b64a020af294e903feed93768705336a20090612a043f47af462a2f5e5b564",
        "f8ee3a4b6ad8001dd3a43707",
    ),
];

/// Real headers of signet at a change of its target, in the same order.
pub(crate) const SIGNET_RETARGET: [&str; 3] = [
    // Height 199584.
    concat!(
        "000000200b61bb8b36ad40ceea78544687903a9524f92bcc323cf6810f64dc7a35000000",
        "cce50bd7b2b2b377dc68951f0949e1b07aa6815da7ad2e323e8fc62af42d880e",
        "c2976866354e011e0fef3f00",
    ),
    // Height 201599.
    concat!(
        "00000020e0b6148086d41986b33ed15c9207ded875683697d11d0ced283a15bf33000000",
        "2dd8f34d9c5ae2edff24ffe6fdfd4e55fcc3024c6167ccbb069d7e6c38457eed",
        "b94e7b66354e011ea0d60000",
    ),
    // Height 201600.
    concat!(
        "00000020c0bd6f869a30e6d558b41ee8f54844e59714e340b6684574ca5935d974000000",
        "1bf0ef8a32407a2f59509bb8e159e4f163f40f94a9c519b424178e2a86ec0f4b",
        "94507b66df52011e6555a900",
    ),
];

/// Real headers of testnet4 at a change of its target, in the same order. The last header of the
/// period has the limit.
pub(crate) const TESTNET4_RETARGET: [&str; 3] = [
    // Height 38304.
    concat!(
        "00600020a4d64c4535d2a737f425706bfb4a0c9f52d7a76ec5ec79b41e7a241c00000000",
        "b99b6fafb6db698ef72c8ae17342aebff5f0ddc0f286fe2423501d4cfa3f96db",
        "786fb26604fa5419aa34e108",
    ),
    // Height 40319.
    concat!(
        "00000020e83bfb271fc94cb48f2c36a9210a221fe9129f463527e853ef748b2800000000",
        "6853ee76759f221c3d39b55a002002af5a133a0e9c81fd6bb1140e20d78f7fa4",
        "6749c366ffff001d6a2a2005",
    ),
    // Height 40320.
    concat!(
        "0000c0201e5267e7ec4667f281a835b7e505ad93496475d661f301480a40d1ac00000000",
        "6a6f0580e2cf0fbc656a008c77dd0d49c362023400c471f96e7005203efd16c6",
        "c84fc36674954d193d2fa6a2",
    ),
];

/// Five real headers of testnet4, from one period. The first has the real `bits`. The next three
/// are late, so they have the limit. The last is not late, because its time goes back, so it has
/// the real `bits` again.
pub(crate) const TESTNET4_RUN: [&str; 5] = [
    // Height 40025.
    concat!(
        "0000dc216d0958dac42bbcadd080874bcadbf82a2bf5d471e4b959bd3400000000000000",
        "7396863d29deaf6fb0ac5f5af5d8e98b9fa2810716fbff15c2dbccbc9e425768",
        "8bf0c06604fa54194c40645f",
    ),
    // Height 40026.
    concat!(
        "0000002031d230c6c901c3469f269ccf25ad8ce08c34e96c8cd295145100000000000000",
        "6649dc40961450e280de1923d61e0a21c41fbf38c8b592888b6bb3c5ac984654",
        "3ff5c066ffff001d4a3c0049",
    ),
    // Height 40027.
    concat!(
        "00000020ac7be0202186a0ea4f47beefe9af0f01013df1e7965bd7103c6d130000000000",
        "4822df05bb5d3870089469c58b924c9bd994193a8b1556ddd9e0824204709e98",
        "f0f9c066ffff001d7a7d6401",
    ),
    // Height 40028.
    concat!(
        "00000020788681150d8e65f1e65c4b7b9657af7366d21c597613a930ff53b94900000000",
        "c7d27773128946d83d4d41443d284df3a13b7a0212887cb1f625768eb832df5e",
        "a1fec066ffff001d2da93aba",
    ),
    // Height 40029.
    concat!(
        "00c01122c4a8d8f4dff4af9bb9a64a5cb63e52cd8a978ef1283fb4518f9261a100000000",
        "76db80a56014e1f355a5feb695234cddc8987bfeaaeca35dac88af61c74cfa34",
        "65f8c06604fa54191169bd16",
    ),
];

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
/// is the genesis header with its `prev`, its `time` and its `nonce` changed. Each time is one
/// second above the header below it, so it is legal.
pub(crate) fn headers_on_genesis(count: usize) -> Vec<crate::block::BlockHeader> {
    let genesis = crate::chainparams::Network::Regtest.genesis();
    let on = |below: &crate::block::BlockHeader| {
        crate::pow::mined_for_regtest(crate::block::BlockHeader {
            prev: below.hash(),
            time: below.time + 1,
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

/// A header from its 80 bytes in hex.
pub(crate) fn header(s: &str) -> crate::block::BlockHeader {
    crate::block::BlockHeader::decode(&mut hex(s).as_slice()).unwrap()
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
