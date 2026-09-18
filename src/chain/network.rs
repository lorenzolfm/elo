//! Which Bitcoin network a connection and a chain are on. The magic is what
//! the network puts on the wire: the four bytes that open every frame
//! (`pchMessageStart`, `../bitcoin/src/kernel/chainparams.cpp:114`, `:245`,
//! `:352`, `:592` at v31.1). Everything else a network decides, its genesis,
//! its `powLimit`, how its difficulty moves, lives beside the code that reads
//! it: `chain::genesis`, `pow::Params`.

/// `PartialEq` because `peer::run` asserts that the chain and the
/// connection it syncs from are on one network.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Regtest,
}

impl Network {
    pub(crate) fn magic(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn magic_matches_chainparams() {
        // Red if a magic constant has a typo or is byte-swapped.
        for (network, magic) in [
            (super::Network::Mainnet, 0xf9be_b4d9_u32),
            (super::Network::Testnet3, 0x0b11_0907),
            (super::Network::Testnet4, 0x1c16_3f28),
            (super::Network::Regtest, 0xfabf_b5da),
        ] {
            assert_eq!(network.magic(), magic.to_be_bytes(), "{network:?}");
        }
        println!("four networks, four magics, all from chainparams.cpp");
    }
}
