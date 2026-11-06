//! The parameters of each network.

/// A network elo can connect to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet4,
    /// The default signet.
    Signet,
    Regtest,
}

/// The size of the magic that starts every message.
pub(crate) const MAGIC_SIZE: usize = 4;

/// The merkle root of the genesis block of mainnet, signet and regtest. The three have the
/// same coinbase transaction.
const GENESIS_MERKLE_ROOT: [u8; 32] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
];

/// The merkle root of the genesis block of testnet4, which has its own coinbase transaction.
const GENESIS_MERKLE_ROOT_TESTNET4: [u8; 32] = [
    0x4e, 0x7b, 0x2b, 0x91, 0x28, 0xfe, 0x02, 0x91, 0xdb, 0x06, 0x93, 0xaf, 0x2a, 0xe4, 0x18, 0xb7,
    0x67, 0xe6, 0x57, 0xcd, 0x40, 0x7e, 0x80, 0xcb, 0x14, 0x34, 0x22, 0x1e, 0xae, 0xa7, 0xa0, 0x7a,
];

/// The highest target of mainnet and testnet4, big-endian.
const POW_LIMIT: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// The highest target of signet, big-endian.
const POW_LIMIT_SIGNET: [u8; 32] = [
    0x00, 0x00, 0x03, 0x77, 0xae, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// The highest target of regtest, big-endian.
const POW_LIMIT_REGTEST: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

impl Network {
    /// The bytes that start every message.
    pub(crate) const fn magic(self) -> [u8; MAGIC_SIZE] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }

    /// The port that a node of the network listens on.
    pub const fn default_port(self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet4 => 48333,
            Network::Signet => 38333,
            Network::Regtest => 18444,
        }
    }

    /// The highest target that a header of the network may have, big-endian.
    pub(crate) const fn pow_limit(self) -> [u8; 32] {
        match self {
            Network::Mainnet | Network::Testnet4 => POW_LIMIT,
            Network::Signet => POW_LIMIT_SIGNET,
            Network::Regtest => POW_LIMIT_REGTEST,
        }
    }

    /// The first header of the chain.
    pub(crate) const fn genesis(self) -> crate::block::BlockHeader {
        // No header comes before genesis.
        let prev = bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]);
        match self {
            Network::Mainnet => crate::block::BlockHeader {
                version: 1,
                prev,
                merkle_root: GENESIS_MERKLE_ROOT,
                time: 1231006505,
                bits: 0x1d00ffff,
                nonce: 2083236893,
            },
            Network::Testnet4 => crate::block::BlockHeader {
                version: 1,
                prev,
                merkle_root: GENESIS_MERKLE_ROOT_TESTNET4,
                time: 1714777860,
                bits: 0x1d00ffff,
                nonce: 393743547,
            },
            Network::Signet => crate::block::BlockHeader {
                version: 1,
                prev,
                merkle_root: GENESIS_MERKLE_ROOT,
                time: 1598918400,
                bits: 0x1e0377ae,
                nonce: 52613770,
            },
            Network::Regtest => crate::block::BlockHeader {
                version: 1,
                prev,
                merkle_root: GENESIS_MERKLE_ROOT,
                time: 1296688602,
                bits: 0x207fffff,
                nonce: 2,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn signet_magic_is_the_hash_of_the_default_challenge() {
        // The default signet challenge.
        let challenge = crate::fixtures::hex(concat!(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be4",
            "30210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
        ));
        let mut serialized = Vec::new();
        crate::serialize::write_string(&mut serialized, &challenge);
        let hash = bitcoin_hashes::sha256d::Hash::hash(&serialized).to_byte_array();

        assert_eq!(super::Network::Signet.magic(), *hash.first_chunk().unwrap());
    }

    #[test]
    fn pow_limit_is_between_the_highest_bits_in_range_and_the_next_bits() {
        // The lowest hash meets each target, so only the range of the network can refuse.
        let hash = bitcoin_hashes::sha256d::Hash::from_byte_array([0; 32]);
        for (network, bits_in_range, bits_above) in [
            (super::Network::Mainnet, 0x1d00_ffff, 0x1d01_0000),
            (super::Network::Testnet4, 0x1d00_ffff, 0x1d01_0000),
            // These `bits` are exactly the limit.
            (super::Network::Signet, 0x1e03_77ae, 0x1e03_77af),
            (super::Network::Regtest, 0x207f_ffff, 0x2100_8000),
        ] {
            assert!(
                crate::pow::has_proof_of_work(hash, bits_in_range, network),
                "{network:?}"
            );
            assert!(
                !crate::pow::has_proof_of_work(hash, bits_above, network),
                "{network:?}"
            );
        }
    }

    #[test]
    fn genesis_hashes_to_the_genesis_block_hash() {
        let cases = [
            (
                super::Network::Mainnet,
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            ),
            (
                super::Network::Testnet4,
                "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043",
            ),
            (
                super::Network::Signet,
                "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6",
            ),
            (
                super::Network::Regtest,
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
            ),
        ];
        for (network, hash) in cases {
            assert_eq!(
                network.genesis().hash(),
                crate::fixtures::hash_from_display_hex(hash),
                "{network:?}"
            );
        }
    }
}
