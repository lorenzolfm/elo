//! The header chain.

/// One linear chain of headers, from genesis to the tip. It is never empty.
#[derive(Debug)]
pub(crate) struct Chain {
    /// The headers below the tip, from genesis. The index of a header is its height.
    ancestors: Vec<crate::block::BlockHeader>,
    tip: crate::block::BlockHeader,
}

/// The height and the hash of the last header of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tip {
    height: usize,
    hash: bitcoin_hashes::sha256d::Hash,
}

/// Why `Chain::extend` refused a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtendError {
    /// The `prev` of the first header is not the hash of the tip.
    NotOnTip,
    /// The `prev` of a header is not the hash of the header before it.
    NotContinuous,
}

impl Chain {
    /// A chain with only the genesis header of `network`.
    #[cfg_attr(not(test), expect(dead_code, reason = "until net_processing calls it"))]
    pub(crate) fn new(network: crate::chainparams::Network) -> Chain {
        Chain {
            ancestors: Vec::new(),
            tip: network.genesis(),
        }
    }

    /// Puts all of `headers` on the tip, in order, or none of them. An empty batch changes
    /// nothing.
    #[cfg_attr(not(test), expect(dead_code, reason = "until net_processing calls it"))]
    pub(crate) fn extend(
        &mut self,
        headers: Vec<crate::block::BlockHeader>,
    ) -> Result<(), ExtendError> {
        if let Some(first) = headers.first()
            && first.prev != self.tip.hash()
        {
            return Err(ExtendError::NotOnTip);
        }
        if headers
            .array_windows()
            .any(|[below, header]| header.prev != below.hash())
        {
            return Err(ExtendError::NotContinuous);
        }

        for header in headers {
            self.ancestors
                .push(std::mem::replace(&mut self.tip, header));
        }
        Ok(())
    }

    /// The height and the hash of the last header.
    #[cfg_attr(not(test), expect(dead_code, reason = "until net_processing calls it"))]
    pub(crate) fn tip(&self) -> Tip {
        Tip {
            height: self.ancestors.len(),
            hash: self.tip.hash(),
        }
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

#[cfg(test)]
mod tests {
    /// `count` headers, each on the header before it, the first on the regtest genesis header.
    /// elo checks no proof of work yet, so each header is the genesis header with its `prev`
    /// changed.
    fn headers_on_genesis(count: usize) -> Vec<crate::block::BlockHeader> {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let on = |below: &crate::block::BlockHeader| crate::block::BlockHeader {
            prev: below.hash(),
            ..genesis
        };
        std::iter::successors(Some(on(&genesis)), |below| Some(on(below)))
            .take(count)
            .collect()
    }

    #[test]
    fn extend_puts_each_batch_on_the_tip() {
        let headers = headers_on_genesis(3);
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
        let headers = headers_on_genesis(3);
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
        let mut headers = headers_on_genesis(4);
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
