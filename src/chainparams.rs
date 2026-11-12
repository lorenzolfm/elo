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

/// The lowest work of a mainnet chain at the end of a sync, big-endian. It is the work of the real
/// chain at a height in the past, so a real chain has more.
const CHAIN_WORK_MIN_MAINNET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x12, 0x87, 0x50, 0xf8, 0x2f, 0x4c, 0x36, 0x61, 0x53, 0xa3, 0xa0, 0x30,
];

/// The lowest work of a testnet4 chain at the end of a sync, big-endian.
const CHAIN_WORK_MIN_TESTNET4: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0xa0, 0xfe, 0x15, 0xd0, 0x17, 0x7d, 0x08, 0x63, 0x04,
];

/// The lowest work of a signet chain at the end of a sync, big-endian.
const CHAIN_WORK_MIN_SIGNET: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x46, 0x3e, 0xa0, 0xa4, 0xb8,
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

    /// The lowest work that a chain of the network must have when its sync ends, big-endian. A
    /// peer can make a chain of cheap headers, or send only part of its chain. With less work than
    /// the real chain had at a height in the past, the chain of the peer is not the chain of the
    /// network. Regtest has no real chain, so its minimum is zero and each chain passes.
    pub(crate) const fn chain_work_min(self) -> [u8; 32] {
        match self {
            Network::Mainnet => CHAIN_WORK_MIN_MAINNET,
            Network::Testnet4 => CHAIN_WORK_MIN_TESTNET4,
            Network::Signet => CHAIN_WORK_MIN_SIGNET,
            Network::Regtest => [0; 32],
        }
    }

    /// The headers for each commitment of a low-work sync. Its first download keeps a bit of one
    /// header in each run of this many headers, so its memory is about the height of the chain
    /// over this count, in bits. Regtest has no real chain, so its count only makes its tests
    /// cheap.
    pub(crate) const fn commitment_period(self) -> usize {
        match self {
            Network::Mainnet => 641,
            Network::Testnet4 => 606,
            Network::Signet => 620,
            Network::Regtest => 275,
        }
    }

    /// The headers that the second download of a low-work sync holds before it gives the first of
    /// them to the chain. So each header that the chain gets has about this count over
    /// `commitment_period` commitments above it, about 24. A peer that sends another chain the
    /// second time passes each commitment by chance, with odds of one half.
    // The peer starts a low-work sync in the next pull request.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) const fn redownload_buffer_size(self) -> usize {
        match self {
            Network::Mainnet => 15_218,
            Network::Testnet4 => 16_092,
            Network::Signet => 15_724,
            Network::Regtest => 7_017,
        }
    }

    /// The lowest `version` that a header at `height` may have. Three rules raise it, to 2, 3 and
    /// 4, each from its own height. Below all three heights, each version passes, so the answer is
    /// `i32::MIN`. On each network other than mainnet, the three heights are 1. So each header
    /// above genesis needs 4, and genesis keeps its version of 1.
    pub(crate) const fn version_min(self, height: usize) -> i32 {
        let [version_2_height, version_3_height, version_4_height] = match self {
            Network::Mainnet => [227_931, 363_725, 388_381],
            Network::Testnet4 | Network::Signet | Network::Regtest => [1, 1, 1],
        };
        // The highest version comes first, so a height at or above two of the heights gets the
        // higher version.
        if height >= version_4_height {
            4
        } else if height >= version_3_height {
            3
        } else if height >= version_2_height {
            2
        } else {
            i32::MIN
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

// A chain starts at genesis with no check, and each header of a chain has at least the lowest
// version of its height. So each genesis must have at least the lowest version of height 0.
const _: () = assert!(Network::Mainnet.genesis().version >= Network::Mainnet.version_min(0));
const _: () = assert!(Network::Testnet4.genesis().version >= Network::Testnet4.version_min(0));
const _: () = assert!(Network::Signet.genesis().version >= Network::Signet.version_min(0));
const _: () = assert!(Network::Regtest.genesis().version >= Network::Regtest.version_min(0));

// A low-work sync reads each height modulo the period.
const _: () = assert!(Network::Mainnet.commitment_period() > 0);
const _: () = assert!(Network::Testnet4.commitment_period() > 0);
const _: () = assert!(Network::Signet.commitment_period() > 0);
const _: () = assert!(Network::Regtest.commitment_period() > 0);

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

    /// A person wrote each height and each version. Each height of mainnet has a row one below it.
    #[test]
    fn version_min_rises_at_each_height() {
        let cases = [
            (super::Network::Mainnet, 0, i32::MIN),
            (super::Network::Mainnet, 227_930, i32::MIN),
            (super::Network::Mainnet, 227_931, 2),
            (super::Network::Mainnet, 363_724, 2),
            (super::Network::Mainnet, 363_725, 3),
            (super::Network::Mainnet, 388_380, 3),
            (super::Network::Mainnet, 388_381, 4),
            (super::Network::Mainnet, usize::MAX, 4),
            (super::Network::Testnet4, 0, i32::MIN),
            (super::Network::Testnet4, 1, 4),
            (super::Network::Testnet4, usize::MAX, 4),
            (super::Network::Signet, 0, i32::MIN),
            (super::Network::Signet, 1, 4),
            (super::Network::Signet, usize::MAX, 4),
            (super::Network::Regtest, 0, i32::MIN),
            (super::Network::Regtest, 1, 4),
            (super::Network::Regtest, usize::MAX, 4),
        ];
        for (network, height, expected) in cases {
            assert_eq!(
                network.version_min(height),
                expected,
                "{network:?} {height}"
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
