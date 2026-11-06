//! The header chain.

/// One linear chain of headers, from genesis to the tip. It is never empty, and each header has
/// proof of work.
#[derive(Debug)]
pub(crate) struct Chain {
    /// The network of the chain. Its limit bounds the target of each header.
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
    /// nothing. The first header that fails gives the error, and the `prev` of a header is checked
    /// before its proof of work.
    pub(crate) fn extend(
        &mut self,
        headers: Vec<crate::block::BlockHeader>,
    ) -> Result<(), ExtendError> {
        // `Headers` holds this bound for a batch from a peer, and the loops below take their bound
        // from it.
        assert!(headers.len() <= crate::protocol::HEADERS_COUNT_MAX);
        let Some(first) = headers.first() else {
            return Ok(());
        };
        if first.prev != self.tip.hash() {
            return Err(ExtendError::NotOnTip);
        }
        // The hash of a header checks its proof of work and the `prev` of the next header, so one
        // pass hashes each header once.
        let mut prev = first.prev;
        for header in &headers {
            if header.prev != prev {
                return Err(ExtendError::NotContinuous);
            }
            prev = crate::pow::proven_hash(header, self.network).ok_or(ExtendError::ProofOfWork)?;
        }

        for header in headers {
            self.ancestors
                .push(std::mem::replace(&mut self.tip, header));
        }
        // The checks above read the batch. These read the chain: the tip is on the header below it,
        // and it has proof of work.
        assert_eq!(
            Some(self.tip.prev),
            self.ancestors.last().map(crate::block::BlockHeader::hash)
        );
        assert!(crate::pow::proven_hash(&self.tip, self.network).is_some());
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

        assert_eq!(chain.extend(headers[..2].to_vec()), Ok(()));
        assert_eq!(chain.extend(headers[2..].to_vec()), Ok(()));

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
            chain.extend(headers[1..].to_vec()),
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
            chain.extend(headers),
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
        assert_eq!(chain.extend(headers), Err(super::ExtendError::ProofOfWork));
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
            chain.extend(vec![header]),
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
            assert_eq!(chain.extend(headers), Err(expected));
        }
    }

    #[test]
    fn extend_takes_an_empty_batch() {
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        assert_eq!(chain.extend(Vec::new()), Ok(()));
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
