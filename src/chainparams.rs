//! The parameters of each network. Core: `kernel/chainparams.cpp`.

/// A network elo can connect to. Core: `ChainType` (`util/chaintype.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet4,
    /// The default signet, with Core's default challenge.
    Signet,
    Regtest,
}

impl Network {
    /// The four bytes that start every message.
    /// Core: `CChainParams::MessageStart` (`kernel/chainparams.h`).
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Signet => [0x0a, 0x03, 0xcf, 0x40],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_hashes::sha256d;

    use super::*;
    use crate::fixtures::hex;
    use crate::serialize::write_string;

    #[test]
    fn signet_magic_is_the_hash_of_the_default_challenge() {
        // Core: `SigNetParams`, the default `signet_challenge`.
        let challenge = hex(
            "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae",
        );
        let mut serialized = Vec::new();
        write_string(&mut serialized, &challenge);
        let [m0, m1, m2, m3, ..] = sha256d::Hash::hash(&serialized).to_byte_array();

        assert_eq!(Network::Signet.magic(), [m0, m1, m2, m3]);
    }
}
