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
}
