enum Buried {
    HeightInCoinbase,
    DerSig,
    Cltv,
}

impl Buried {
    const fn height(&self, network: crate::chain::network::Network) -> usize {
        match (self, network) {
            (Buried::HeightInCoinbase, crate::chain::network::Network::Mainnet) => 227_931,
            (Buried::DerSig, crate::chain::network::Network::Mainnet) => 363_725,
            (Buried::Cltv, crate::chain::network::Network::Mainnet) => 388_381,
            (Buried::HeightInCoinbase, crate::chain::network::Network::Testnet3) => 21_111,
            (Buried::DerSig, crate::chain::network::Network::Testnet3) => 330_776,
            (Buried::Cltv, crate::chain::network::Network::Testnet3) => 581_885,
            (
                _,
                crate::chain::network::Network::Testnet4 | crate::chain::network::Network::Regtest,
            ) => 1,
        }
    }

    const fn version(&self) -> i32 {
        match self {
            Buried::HeightInCoinbase => 2,
            Buried::DerSig => 3,
            Buried::Cltv => 4,
        }
    }
}

#[must_use]
pub(crate) fn version_min(height: usize, network: crate::chain::network::Network) -> Option<i32> {
    [Buried::HeightInCoinbase, Buried::DerSig, Buried::Cltv]
        .iter()
        .filter(|deployment| height >= deployment.height(network))
        .map(Buried::version)
        .max()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_version_is_retired_at_the_height_core_buries_its_deployment() {
        // Red if a height has a typo, a deployment counts as active one
        // height early or late, or BIP65 and BIP66 trade places: Core lists
        // `BIP65Height` above `BIP66Height` (`chainparams.cpp:91-92`), but
        // BIP66 retired version 2 first. Each pair of rows is the last
        // height under a deployment's rule and the first height of the next.
        // Regtest is left to `Chain::extend`, where a test can mine it.
        for (network, height, expected) in [
            (crate::chain::network::Network::Mainnet, 227_930, None),
            (crate::chain::network::Network::Mainnet, 227_931, Some(2)),
            (crate::chain::network::Network::Mainnet, 363_724, Some(2)),
            (crate::chain::network::Network::Mainnet, 363_725, Some(3)),
            (crate::chain::network::Network::Mainnet, 388_380, Some(3)),
            (crate::chain::network::Network::Mainnet, 388_381, Some(4)),
            (crate::chain::network::Network::Testnet3, 21_110, None),
            (crate::chain::network::Network::Testnet3, 21_111, Some(2)),
            (crate::chain::network::Network::Testnet3, 330_775, Some(2)),
            (crate::chain::network::Network::Testnet3, 330_776, Some(3)),
            (crate::chain::network::Network::Testnet3, 581_884, Some(3)),
            (crate::chain::network::Network::Testnet3, 581_885, Some(4)),
            (crate::chain::network::Network::Testnet4, 1, Some(4)),
        ] {
            assert_eq!(
                super::version_min(height, network),
                expected,
                "{network:?} at height {height}"
            );
        }
        println!("mainnet, testnet3 and testnet4 agree with chainparams.cpp");
    }
}
