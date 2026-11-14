use crate::serialize::{Decode, Encode};

pub(crate) const MAINNET_BLOCK_1: &str = concat!(
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
    "982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e",
    "61bc6649ffff001d01e36299",
);

pub(crate) const MAINNET_RETARGET: [&str; 3] = [
    concat!(
        "01000000e6bf7fd7f7790a63786faa878d0dc7fd8f2ff365732e45862c66075100000000",
        "700d342f65c7b6834dffb615358a1897016f0448913372190cbe3d27a4b53355",
        "b1512b4bffff001dbfb02519",
    ),
    concat!(
        "0100000049c1daab3b6536ff1b2633c3a316a6e06ec287676cdeec4ca7baae6b00000000",
        "ac10b36b8f354b3353207de15940a5edbc05bb8364af75b4b5409e7823f2b489",
        "23ec3a4bffff001dbd5fa412",
    ),
    concat!(
        "010000004b0360d834a330ec7833e30e1f523ee05a0793361e29a73421964f9800000000",
        "27b64a020af294e903feed93768705336a20090612a043f47af462a2f5e5b564",
        "f8ee3a4b6ad8001dd3a43707",
    ),
];

pub(crate) const SIGNET_RETARGET: [&str; 3] = [
    concat!(
        "000000200b61bb8b36ad40ceea78544687903a9524f92bcc323cf6810f64dc7a35000000",
        "cce50bd7b2b2b377dc68951f0949e1b07aa6815da7ad2e323e8fc62af42d880e",
        "c2976866354e011e0fef3f00",
    ),
    concat!(
        "00000020e0b6148086d41986b33ed15c9207ded875683697d11d0ced283a15bf33000000",
        "2dd8f34d9c5ae2edff24ffe6fdfd4e55fcc3024c6167ccbb069d7e6c38457eed",
        "b94e7b66354e011ea0d60000",
    ),
    concat!(
        "00000020c0bd6f869a30e6d558b41ee8f54844e59714e340b6684574ca5935d974000000",
        "1bf0ef8a32407a2f59509bb8e159e4f163f40f94a9c519b424178e2a86ec0f4b",
        "94507b66df52011e6555a900",
    ),
];

pub(crate) const TESTNET4_RETARGET: [&str; 3] = [
    concat!(
        "00600020a4d64c4535d2a737f425706bfb4a0c9f52d7a76ec5ec79b41e7a241c00000000",
        "b99b6fafb6db698ef72c8ae17342aebff5f0ddc0f286fe2423501d4cfa3f96db",
        "786fb26604fa5419aa34e108",
    ),
    concat!(
        "00000020e83bfb271fc94cb48f2c36a9210a221fe9129f463527e853ef748b2800000000",
        "6853ee76759f221c3d39b55a002002af5a133a0e9c81fd6bb1140e20d78f7fa4",
        "6749c366ffff001d6a2a2005",
    ),
    concat!(
        "0000c0201e5267e7ec4667f281a835b7e505ad93496475d661f301480a40d1ac00000000",
        "6a6f0580e2cf0fbc656a008c77dd0d49c362023400c471f96e7005203efd16c6",
        "c84fc36674954d193d2fa6a2",
    ),
];

pub(crate) const TESTNET4_RUN: [&str; 5] = [
    concat!(
        "0000dc216d0958dac42bbcadd080874bcadbf82a2bf5d471e4b959bd3400000000000000",
        "7396863d29deaf6fb0ac5f5af5d8e98b9fa2810716fbff15c2dbccbc9e425768",
        "8bf0c06604fa54194c40645f",
    ),
    concat!(
        "0000002031d230c6c901c3469f269ccf25ad8ce08c34e96c8cd295145100000000000000",
        "6649dc40961450e280de1923d61e0a21c41fbf38c8b592888b6bb3c5ac984654",
        "3ff5c066ffff001d4a3c0049",
    ),
    concat!(
        "00000020ac7be0202186a0ea4f47beefe9af0f01013df1e7965bd7103c6d130000000000",
        "4822df05bb5d3870089469c58b924c9bd994193a8b1556ddd9e0824204709e98",
        "f0f9c066ffff001d7a7d6401",
    ),
    concat!(
        "00000020788681150d8e65f1e65c4b7b9657af7366d21c597613a930ff53b94900000000",
        "c7d27773128946d83d4d41443d284df3a13b7a0212887cb1f625768eb832df5e",
        "a1fec066ffff001d2da93aba",
    ),
    concat!(
        "00c01122c4a8d8f4dff4af9bb9a64a5cb63e52cd8a978ef1283fb4518f9261a100000000",
        "76db80a56014e1f355a5feb695234cddc8987bfeaaeca35dac88af61c74cfa34",
        "65f8c06604fa54191169bd16",
    ),
];

pub(crate) const TESTNET4_TIMEWARP: [&str; 6] = [
    concat!(
        "000000200000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "056f3566ffff001d00000000",
    ),
    concat!(
        "00000020d63865c0c977eb51da864c86dd3ddf2b907a23e55cc8fd6246d1e118a0603a7b",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "04e44766ffff001d59bec392",
    ),
    concat!(
        "0000002002ef6c700351a00f5afa2a1cf4c333bed29d117217d764cbb5b13bc700000000",
        "0200000000000000000000000000000000000000000000000000000000000000",
        "ace14766ffff001d540ba5d9",
    ),
    concat!(
        "0000002002ef6c700351a00f5afa2a1cf4c333bed29d117217d764cbb5b13bc700000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "abe14766ffff001d7ccbb794",
    ),
    concat!(
        "0000002002ef6c700351a00f5afa2a1cf4c333bed29d117217d764cbb5b13bc700000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "056f3566ffff001dd9769580",
    ),
    concat!(
        "00000020efab162c3e3a395a6dd031370d87d1b31ba9120c8d99bc5078d5d87500000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "04e44766ffff001d0af8cc47",
    ),
];

pub(crate) const MAINNET_VERSION_TIP: &str = concat!(
    "040000000000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "2aab5f49ffff001d00000000",
);

pub(crate) const MAINNET_VERSION_RISE: [[&str; 2]; 3] = [
    [
        concat!(
            "01000000311c94dcd9b9616ed0f17d035b4087bebd67463b9bfdd9f1a301759093b52ea7",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "2bab5f49ffff001d1d0c43d1",
        ),
        concat!(
            "01000000cfd1b41513dc62aa325fbf3089f90528fd65c037e28ea87a1b15a2f100000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "2cab5f49ffff001d6c54114a",
        ),
    ],
    [
        concat!(
            "02000000311c94dcd9b9616ed0f17d035b4087bebd67463b9bfdd9f1a301759093b52ea7",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "2bab5f49ffff001db6a6079a",
        ),
        concat!(
            "020000002666940377a7a458eb0a8affcb6927e7f9b8f93f7f1fb1ae07f698e900000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "2cab5f49ffff001de53ba714",
        ),
    ],
    [
        concat!(
            "03000000311c94dcd9b9616ed0f17d035b4087bebd67463b9bfdd9f1a301759093b52ea7",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "2bab5f49ffff001dfea525cc",
        ),
        concat!(
            "030000007f534b5ac5a6f5c787751a970dc067f080a748e628f8aaddf0e3293c00000000",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "2cab5f49ffff001d9d73947d",
        ),
    ],
];

pub(crate) const VERSION_FRAME: &str = concat!(
    "fabfb5da76657273696f6e000000000066000000b34372e3",
    "80110100090c0000000000002358de6a00000000",
    "0000000000000000000000000000000000000000000000000000",
    "090c000000000000000000000000000000000000000000000000",
    "c9f081ae97771971102f5361746f7368693a33312e312e302f0000000001",
);

pub(crate) const WTXIDRELAY_FRAME: &str = "fabfb5da777478696472656c61790000000000005df6e0e2";

pub(crate) const SENDADDRV2_FRAME: &str = "fabfb5da73656e646164647276320000000000005df6e0e2";

pub(crate) const VERACK_FRAME: &str = "fabfb5da76657261636b000000000000000000005df6e0e2";

pub(crate) const SENDCMPCT_FRAME: &str =
    "fabfb5da73656e64636d70637400000009000000e92f5ef8000200000000000000";

pub(crate) const PING_FRAME: &str =
    "fabfb5da70696e670000000000000000080000006c3569e3d84520892932e934";

pub(crate) const FEEFILTER_FRAME: &str =
    "fabfb5da66656566696c746572000000080000000a19f7997a9e970000000000";

pub(crate) const BLOCK_INV_FRAME: &str = concat!(
    "fabfb5da696e7600000000000000000025000000dcc9e6bf",
    "0102000000faf4d233a8d1e92d0b03cd5dcc530307fdca5133639c54520be1a98d48ff6939",
);

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

pub(crate) const BLOCK_1_HASH: &str =
    "41650b9b585fd56a907a5286e7304582ee102c563563a9572bdf898c4f53d96f";

pub(crate) const BLOCK_2_HASH: &str =
    "29d4ecbe35de0c35851f0ae8bb5070fbc2273c65b1538591f3deb3179883456a";

pub(crate) const GETHEADERS_FRAME: &str = concat!(
    "fabfb5da6765746865616465727300004500000070e012a4",
    "80110100",
    "01",
    "06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
    "0000000000000000000000000000000000000000000000000000000000000000",
);

pub(crate) fn version_payload() -> Vec<u8> {
    hex(VERSION_FRAME).split_off(crate::transport::MESSAGE_HEADER_SIZE)
}

pub(crate) fn headers_payload() -> Vec<u8> {
    hex(HEADERS_FRAME).split_off(crate::transport::MESSAGE_HEADER_SIZE)
}

pub(crate) const HEADER_VERSION: i32 = 0x2000_0000;

const _: () =
    assert!(HEADER_VERSION >= crate::chainparams::Network::Mainnet.version_min(usize::MAX));
const _: () =
    assert!(HEADER_VERSION >= crate::chainparams::Network::Testnet4.version_min(usize::MAX));
const _: () =
    assert!(HEADER_VERSION >= crate::chainparams::Network::Signet.version_min(usize::MAX));
const _: () =
    assert!(HEADER_VERSION >= crate::chainparams::Network::Regtest.version_min(usize::MAX));

pub(crate) fn headers_on_genesis(count: usize) -> Vec<crate::block::BlockHeader> {
    headers_on(&crate::chainparams::Network::Regtest.genesis(), count)
}

pub(crate) fn headers_on(
    below: &crate::block::BlockHeader,
    count: usize,
) -> Vec<crate::block::BlockHeader> {
    let genesis = crate::chainparams::Network::Regtest.genesis();
    let on = |below: &crate::block::BlockHeader| {
        crate::pow::mined_for_regtest(crate::block::BlockHeader {
            version: HEADER_VERSION,
            prev: below.hash(),
            time: below.time + 1,
            ..genesis
        })
    };
    std::iter::successors(Some(on(below)), |below| Some(on(below)))
        .take(count)
        .collect()
}

pub(crate) fn branch_on(
    below: &crate::block::BlockHeader,
    count: usize,
) -> Vec<crate::block::BlockHeader> {
    let first = crate::pow::mined_for_regtest(crate::block::BlockHeader {
        merkle_root: [0xbb; 32],
        ..headers_on(below, 1)[0]
    });
    let on = |below: &crate::block::BlockHeader| {
        crate::pow::mined_for_regtest(crate::block::BlockHeader {
            prev: below.hash(),
            time: below.time + 1,
            ..*below
        })
    };
    std::iter::successors(Some(first), |below| Some(on(below)))
        .take(count)
        .collect()
}

pub(crate) fn headers_payload_with(headers: &[crate::block::BlockHeader]) -> Vec<u8> {
    let mut payload = Vec::new();
    crate::serialize::write_compact_size(&mut payload, headers.len());
    for header in headers {
        header.encode(&mut payload);
        payload.push(0);
    }
    payload
}

pub(crate) fn inv_payload(types: &[u32]) -> Vec<u8> {
    let mut payload = Vec::new();
    crate::serialize::write_compact_size(&mut payload, types.len());
    for entry_type in types {
        payload.extend_from_slice(&entry_type.to_le_bytes());
        payload.extend_from_slice(&[0xbb; 32]);
    }
    payload
}

pub(crate) const CLOCK: u64 = u32::MAX as u64;

pub(crate) fn headers_batch(headers: &[crate::block::BlockHeader]) -> crate::protocol::Headers {
    crate::protocol::Headers::decode(&mut headers_payload_with(headers).as_slice()).unwrap()
}

pub(crate) fn header(s: &str) -> crate::block::BlockHeader {
    crate::block::BlockHeader::decode(&mut hex(s).as_slice()).unwrap()
}

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
