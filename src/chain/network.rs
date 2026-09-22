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

    #[must_use]
    pub fn port(self) -> u16 {
        match self {
            Network::Mainnet => 8333,
            Network::Testnet3 => 18333,
            Network::Testnet4 => 48333,
            Network::Regtest => 18444,
        }
    }
}

#[derive(Debug)]
pub struct UnknownNetwork(String);

impl std::fmt::Display for UnknownNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown network {:?}: expected main, test, testnet4 or regtest",
            self.0
        )
    }
}

impl std::error::Error for UnknownNetwork {}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Network::Mainnet => "main",
            Network::Testnet3 => "test",
            Network::Testnet4 => "testnet4",
            Network::Regtest => "regtest",
        })
    }
}

impl std::str::FromStr for Network {
    type Err = UnknownNetwork;

    fn from_str(name: &str) -> Result<Network, UnknownNetwork> {
        match name {
            "main" => Ok(Network::Mainnet),
            "test" => Ok(Network::Testnet3),
            "testnet4" => Ok(Network::Testnet4),
            "regtest" => Ok(Network::Regtest),
            _ => Err(UnknownNetwork(name.to_string())),
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

    #[test]
    fn ports_match_chainparams() {
        for (network, port) in [
            (super::Network::Mainnet, 8333),
            (super::Network::Testnet3, 18333),
            (super::Network::Testnet4, 48333),
            (super::Network::Regtest, 18444),
        ] {
            assert_eq!(network.port(), port, "{network:?}");
        }
    }

    #[test]
    fn names_are_cores_chain_names() {
        for (name, network) in [
            ("main", super::Network::Mainnet),
            ("test", super::Network::Testnet3),
            ("testnet4", super::Network::Testnet4),
            ("regtest", super::Network::Regtest),
        ] {
            assert_eq!(name.parse::<super::Network>().unwrap(), network, "{name}");
            assert_eq!(network.to_string(), name);
        }
    }

    #[test]
    fn a_name_core_does_not_use_is_refused() {
        for name in ["mainnet", "testnet3", "Main", ""] {
            let error = name.parse::<super::Network>().unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("unknown network {name:?}: expected main, test, testnet4 or regtest")
            );
        }
    }
}
