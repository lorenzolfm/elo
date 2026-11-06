//! The header chain.

/// One linear chain of headers, from genesis to the tip. It is never empty, each header has proof
/// of work, and each header above genesis has the `bits` that the headers below it require.
#[derive(Debug)]
pub(crate) struct Chain {
    /// The network of the chain. Its rules bound the target of each header.
    network: crate::chainparams::Network,
    /// The headers below the tip, from genesis. The index of a header is its height.
    ancestors: Vec<crate::block::BlockHeader>,
    tip: crate::block::BlockHeader,
}

/// The height and the hash of the last header of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    height: usize,
    hash: bitcoin_hashes::sha256d::Hash,
}

/// Why `Chain::extend` refused a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtendError {
    /// The `prev` of the first header is not the hash of the tip.
    NotOnTip,
    /// The `prev` of a header is not the hash of the header before it.
    NotContinuous,
    /// The `bits` of a header are not a target in the range of the network, or the hash of the
    /// header is above that target.
    ProofOfWork,
    /// The `bits` of a header are not the `bits` that the headers below it require.
    WrongBits,
}

impl Chain {
    /// A chain with only the genesis header of `network`.
    pub(crate) fn new(network: crate::chainparams::Network) -> Chain {
        Chain {
            network,
            ancestors: Vec::new(),
            tip: network.genesis(),
        }
    }

    /// Puts all of `headers` on the tip, in order, or none of them. An empty batch changes
    /// nothing. The first header that fails gives the error. For one header, its `prev` is checked
    /// first, then its proof of work, then its `bits`.
    pub(crate) fn extend(&mut self, headers: crate::protocol::Headers) -> Result<(), ExtendError> {
        let headers = headers.into_vec();
        let Some(first) = headers.first() else {
            return Ok(());
        };
        if first.prev != self.tip.hash() {
            return Err(ExtendError::NotOnTip);
        }
        // The hash of a header checks its proof of work and the `prev` of the next header, so one
        // pass hashes each header once.
        let mut prev = first.prev;
        for (index, header) in headers.iter().enumerate() {
            if header.prev != prev {
                return Err(ExtendError::NotContinuous);
            }
            prev = crate::pow::proven_hash(header, self.network).ok_or(ExtendError::ProofOfWork)?;
            let ancestors = crate::pow::Ancestors {
                below_tip: &self.ancestors,
                tip: &self.tip,
                batch: &headers[..index],
            };
            if crate::pow::required_bits(self.network, ancestors, header.time) != Some(header.bits)
            {
                return Err(ExtendError::WrongBits);
            }
        }

        for header in headers {
            self.ancestors
                .push(std::mem::replace(&mut self.tip, header));
        }
        // The checks above read the batch. These read the chain: the tip is on the header below it,
        // it has proof of work, and it has the `bits` that the headers below it require.
        assert_eq!(
            Some(self.tip.prev),
            self.ancestors.last().map(crate::block::BlockHeader::hash)
        );
        assert!(crate::pow::proven_hash(&self.tip, self.network).is_some());
        assert_eq!(
            self.ancestors.split_last().and_then(|(tip, below_tip)| {
                let ancestors = crate::pow::Ancestors {
                    below_tip,
                    tip,
                    batch: &[],
                };
                crate::pow::required_bits(self.network, ancestors, self.tip.time)
            }),
            Some(self.tip.bits)
        );
        Ok(())
    }

    /// The height and the hash of the last header.
    pub(crate) fn tip(&self) -> Tip {
        Tip {
            height: self.ancestors.len(),
            hash: self.tip.hash(),
        }
    }
}

impl Tip {
    /// The hash of the last header, in wire order.
    pub(crate) fn hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.hash
    }
}

/// Writes `<height> <hash>`. The hash is in display order: the reverse of the wire order.
impl std::fmt::Display for Tip {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ", self.height)?;
        for byte in self.hash.as_byte_array().iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for ExtendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendError::NotOnTip => write!(f, "headers do not start at our tip"),
            ExtendError::NotContinuous => write!(f, "headers do not form a chain"),
            ExtendError::ProofOfWork => write!(f, "a header fails proof of work"),
            ExtendError::WrongBits => write!(f, "a header has the wrong bits"),
        }
    }
}

impl std::error::Error for ExtendError {}

#[cfg(test)]
mod tests {
    #[test]
    fn extend_puts_each_batch_on_the_tip() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);

        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&headers[..2])),
            Ok(())
        );
        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&headers[2..])),
            Ok(())
        );

        assert_eq!(
            chain.tip(),
            super::Tip {
                height: 3,
                hash: headers[2].hash(),
            }
        );
    }

    #[test]
    fn extend_refuses_a_batch_off_the_tip() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        // The first header is on block 1, which the chain does not have.
        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&headers[1..])),
            Err(super::ExtendError::NotOnTip)
        );
        assert_eq!(chain.tip(), before);
    }

    #[test]
    fn extend_refuses_a_batch_with_a_break() {
        let mut headers = crate::fixtures::headers_on_genesis(4);
        headers.remove(2);
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        // Blocks 1 and 2 connect, but block 4 is not on block 2, so the chain takes none.
        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&headers)),
            Err(super::ExtendError::NotContinuous)
        );
        assert_eq!(chain.tip(), before);
    }

    #[test]
    fn extend_refuses_a_batch_with_a_hash_above_its_target() {
        let mut headers = crate::fixtures::headers_on_genesis(2);
        // A top byte of 0x80 or more is above each regtest target. The top byte of a hash is its
        // last byte in wire order.
        headers[1].nonce = (0..=u32::MAX)
            .find(|nonce| {
                let header = crate::block::BlockHeader {
                    nonce: *nonce,
                    ..headers[1]
                };
                header.hash().as_byte_array()[31] >= 0x80
            })
            .unwrap();
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        // The bad header is the last, and block 1 is good, so the chain takes none.
        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&headers)),
            Err(super::ExtendError::ProofOfWork)
        );
        assert_eq!(chain.tip(), before);
    }

    #[test]
    fn extend_refuses_a_target_above_the_limit_of_the_network() {
        // This header would pass on regtest, because it has the `bits` of regtest and a hash below
        // that target.
        let network = crate::chainparams::Network::Mainnet;
        let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            prev: network.genesis().hash(),
            ..crate::chainparams::Network::Regtest.genesis()
        });
        let mut chain = super::Chain::new(network);

        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&[header])),
            Err(super::ExtendError::ProofOfWork)
        );
    }

    #[test]
    fn extend_checks_the_prev_of_a_header_before_its_proof_of_work() {
        // `bits` of 0 are no target, so this header fails proof of work with any hash.
        let bad = crate::block::BlockHeader {
            prev: bitcoin_hashes::sha256d::Hash::from_byte_array([1; 32]),
            bits: 0,
            ..crate::chainparams::Network::Regtest.genesis()
        };
        let good = crate::fixtures::headers_on_genesis(1)[0];
        for (headers, expected) in [
            (vec![bad], super::ExtendError::NotOnTip),
            (vec![good, bad], super::ExtendError::NotContinuous),
        ] {
            let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
            assert_eq!(
                chain.extend(crate::fixtures::headers_batch(&headers)),
                Err(expected)
            );
        }
    }

    #[test]
    fn extend_refuses_a_batch_with_bits_that_are_not_required() {
        let mut headers = crate::fixtures::headers_on_genesis(2);
        // These `bits` are in the range, and the mined hash is below their target, so only the rule
        // of the network refuses them.
        headers[1] = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            bits: 0x207f_fffe,
            ..headers[1]
        });
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        // The bad header is the last, and block 1 is good, so the chain takes none.
        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&headers)),
            Err(super::ExtendError::WrongBits)
        );
        assert_eq!(chain.tip(), before);
    }

    /// A chain with `real` at their heights and the last of them as the tip. Each other height has
    /// the genesis header, so only what the rules read is real. A test cannot mine a header on
    /// these networks, so the tip must be a real header for the next real header to pass.
    fn chain_with(
        network: crate::chainparams::Network,
        real: &[(usize, crate::block::BlockHeader)],
    ) -> super::Chain {
        let (tip_height, tip) = *real.last().unwrap();
        let mut ancestors = vec![network.genesis(); tip_height];
        for (height, header) in &real[..real.len() - 1] {
            ancestors[*height] = *header;
        }
        super::Chain {
            network,
            ancestors,
            tip,
        }
    }

    #[test]
    fn extend_takes_a_real_change_of_the_target() {
        for (network, first_height, [first, last, next]) in [
            (
                crate::chainparams::Network::Mainnet,
                30240,
                crate::fixtures::MAINNET_RETARGET,
            ),
            (
                crate::chainparams::Network::Signet,
                199584,
                crate::fixtures::SIGNET_RETARGET,
            ),
            // The last header has the limit, so only the `bits` of the first header give the
            // answer.
            (
                crate::chainparams::Network::Testnet4,
                38304,
                crate::fixtures::TESTNET4_RETARGET,
            ),
        ] {
            let first = crate::fixtures::header(first);
            let last = crate::fixtures::header(last);
            let next = crate::fixtures::header(next);
            let last_height = first_height + 2015;
            let mut chain = chain_with(network, &[(first_height, first), (last_height, last)]);
            assert_eq!(
                chain.extend(crate::fixtures::headers_batch(&[next])),
                Ok(()),
                "{network:?}"
            );
            assert_eq!(chain.tip().height, last_height + 1, "{network:?}");

            // The same `next` has real proof of work, so with another first time only the rule
            // refuses it.
            let other_first = crate::block::BlockHeader {
                time: first.time - 600,
                ..first
            };
            let mut chain =
                chain_with(network, &[(first_height, other_first), (last_height, last)]);
            assert_eq!(
                chain.extend(crate::fixtures::headers_batch(&[next])),
                Err(super::ExtendError::WrongBits),
                "{network:?}"
            );
        }
    }

    #[test]
    fn extend_takes_a_real_run_at_the_limit_of_testnet4() {
        let network = crate::chainparams::Network::Testnet4;
        let [real, late_1, late_2, late_3, back] =
            crate::fixtures::TESTNET4_RUN.map(crate::fixtures::header);
        let on_real = || chain_with(network, &[(40025, real)]);

        // The last header goes back to the real `bits` through each part of what the rule reads:
        // the batch, the tip and the headers below the tip.
        let batches: [&[&[crate::block::BlockHeader]]; 3] = [
            &[&[late_1, late_2, late_3, back]],
            &[&[late_1, late_2], &[late_3, back]],
            &[&[late_1], &[late_2], &[late_3], &[back]],
        ];
        for batches in batches {
            let mut chain = on_real();
            for batch in batches {
                assert_eq!(chain.extend(crate::fixtures::headers_batch(batch)), Ok(()));
            }
            assert_eq!(chain.tip().hash, back.hash());
        }
    }

    #[test]
    fn extend_takes_an_empty_batch() {
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        assert_eq!(chain.extend(crate::fixtures::headers_batch(&[])), Ok(()));
        assert_eq!(chain.tip(), before);
    }

    #[test]
    fn tip_writes_the_hash_in_display_order() {
        let chain = super::Chain::new(crate::chainparams::Network::Regtest);
        assert_eq!(
            chain.tip().to_string(),
            "0 0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
        );
    }
}
