//! The header chain.

/// The most headers that a median time reads: the header below a new header, and the 10 below it.
const MEDIAN_TIME_HEADERS_COUNT: usize = 11;

/// One linear chain of headers, from genesis to the tip. It is never empty, each header has proof
/// of work, and each header above genesis has the `bits` that the headers below it require and a
/// time above their median time.
#[derive(Debug)]
pub(crate) struct Chain {
    /// The network of the chain. Its rules bound the target of each header.
    network: crate::chainparams::Network,
    /// The headers below the tip, from genesis. The index of a header is its height.
    below_tip: Vec<crate::block::BlockHeader>,
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
    /// The `bits` of a header are not the `bits` that the headers below it require. On testnet4 the
    /// answer also reads the time of the header.
    WrongBits,
    /// The time of a header is at or below the median time of the headers below it.
    TimeTooOld,
}

/// The headers below one header of a batch, by height: the chain, then the part of the batch that
/// comes before that header. A batch is not on the chain until each of its headers passes, so the
/// rules read it through this.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ancestors<'a> {
    pub(crate) below_tip: &'a [crate::block::BlockHeader],
    pub(crate) tip: &'a crate::block::BlockHeader,
    pub(crate) batch: &'a [crate::block::BlockHeader],
}

impl Chain {
    /// A chain with only the genesis header of `network`.
    pub(crate) fn new(network: crate::chainparams::Network) -> Chain {
        Chain {
            network,
            below_tip: Vec::new(),
            tip: network.genesis(),
        }
    }

    /// Puts all of `headers` on the tip, in order, or none of them. An empty batch changes
    /// nothing. The first header that fails gives the error. For one header, its `prev` is checked
    /// first, then its proof of work, then its `bits`, then its time.
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
            let ancestors = Ancestors {
                below_tip: &self.below_tip,
                tip: &self.tip,
                batch: &headers[..index],
            };
            if crate::pow::required_bits(self.network, ancestors, header.time) != Some(header.bits)
            {
                return Err(ExtendError::WrongBits);
            }
            if header.time <= ancestors.median_time_past() {
                return Err(ExtendError::TimeTooOld);
            }
        }

        for header in headers {
            self.below_tip
                .push(std::mem::replace(&mut self.tip, header));
        }
        // A batch that is not empty puts the old tip below the new tip.
        assert!(!self.below_tip.is_empty());
        let last_index = self.below_tip.len() - 1;
        let ancestors = Ancestors {
            below_tip: &self.below_tip[..last_index],
            tip: &self.below_tip[last_index],
            batch: &[],
        };
        // The checks above read the batch. These read the chain: the tip is on the header below it,
        // it has proof of work, it has the `bits` that the headers below it require, and its time
        // is above their median time.
        assert_eq!(self.tip.prev, ancestors.tip.hash());
        assert!(crate::pow::proven_hash(&self.tip, self.network).is_some());
        assert_eq!(
            crate::pow::required_bits(self.network, ancestors, self.tip.time),
            Some(self.tip.bits)
        );
        assert!(self.tip.time > ancestors.median_time_past());
        Ok(())
    }

    /// The height and the hash of the last header.
    pub(crate) fn tip(&self) -> Tip {
        Tip {
            height: self.below_tip.len(),
            hash: self.tip.hash(),
        }
    }
}

impl<'a> Ancestors<'a> {
    /// The height of the header above these headers. It is at least 1, because a chain has genesis.
    pub(crate) fn height_above(self) -> usize {
        self.below_tip.len() + 1 + self.batch.len()
    }

    /// The header at `height`, which must be below `height_above`.
    pub(crate) fn at(self, height: usize) -> &'a crate::block::BlockHeader {
        match height.checked_sub(self.below_tip.len()) {
            None => &self.below_tip[height],
            Some(0) => self.tip,
            Some(above_tip) => &self.batch[above_tip - 1],
        }
    }

    /// The median of the times of the last `MEDIAN_TIME_HEADERS_COUNT` headers, or of each header
    /// if there are fewer. Times can go back, so this sorts them. With an even count, which only a
    /// chain below that height has, this is the higher of the two middle times.
    ///
    /// A peer picks each time, so no value may panic. A peer also runs this once for each header
    /// of a batch. So it reads at most `MEDIAN_TIME_HEADERS_COUNT` headers and uses no heap.
    fn median_time_past(self) -> u32 {
        let height_above = self.height_above();
        let count = height_above.min(MEDIAN_TIME_HEADERS_COUNT);
        assert!(count >= 1);
        let mut times_buffer = [0; MEDIAN_TIME_HEADERS_COUNT];
        let times = &mut times_buffer[..count];
        for (time, height) in times.iter_mut().zip(height_above - count..height_above) {
            *time = self.at(height).time;
        }
        times.sort_unstable();
        times[count / 2]
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
            ExtendError::TimeTooOld => write!(f, "a header has a time at or below the median"),
        }
    }
}

impl std::error::Error for ExtendError {}

#[cfg(fuzzing)]
// Only cargo-mutants reads this attribute. Its test runs do not build this module.
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    /// The first headers of a batch that go through the check. A median reads at most
    /// `MEDIAN_TIME_HEADERS_COUNT` times, so a later header reaches no new path. In a batch that is
    /// longer than its input, the later headers have only zeros. A check of each header costs 40%
    /// of the runs of the `headers` target, and this bound costs 9%.
    const MEDIAN_CHECK_HEADERS_COUNT: usize = 4 * super::MEDIAN_TIME_HEADERS_COUNT;

    /// A peer picks each `time` of `headers`, so the first headers go through the median time, as
    /// the header above the ones before it. It must return for any value. This check does not sort:
    /// of `count` times, only the time at index `count / 2` of the sorted times has more than
    /// `count / 2` times at or below it, and at least `count - count / 2` at or above it.
    pub(crate) fn median_time_past_check(headers: &[crate::block::BlockHeader]) {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        for index in 0..headers.len().min(MEDIAN_CHECK_HEADERS_COUNT) {
            let batch = &headers[..index];
            let ancestors = super::Ancestors {
                below_tip: &[],
                tip: &genesis,
                batch,
            };
            let median = ancestors.median_time_past();
            let times = || {
                std::iter::once(&genesis)
                    .chain(batch)
                    .rev()
                    .take(super::MEDIAN_TIME_HEADERS_COUNT)
                    .map(|header| header.time)
            };
            let count = times().count();
            assert!(times().filter(|time| *time <= median).count() > count / 2);
            assert!(times().filter(|time| *time >= median).count() >= count - count / 2);
        }
    }
}

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

    /// A regtest header for each of `times`, each on the header before it, the first on `below`.
    fn mined_on(below: crate::block::BlockHeader, times: &[u32]) -> Vec<crate::block::BlockHeader> {
        let mut prev = below.hash();
        times
            .iter()
            .map(|time| {
                let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
                    prev,
                    time: *time,
                    ..below
                });
                prev = header.hash();
                header
            })
            .collect()
    }

    #[test]
    fn extend_takes_a_time_only_above_the_median_time_of_the_headers_below() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        // The seconds after the genesis time of each header above genesis, and of their median
        // time. A person wrote each median, from the times with genesis at 0.
        let cases: [(&str, &[u32], u32); 6] = [
            ("only genesis", &[], 0),
            // The lower of the two middle times is genesis.
            ("two times", &[100], 100),
            // A time below the tip can pass.
            ("three times", &[100, 200], 100),
            // With no sort, the same index gives 200 or 100.
            ("four times that go back", &[100, 200, 150], 150),
            // With no sort, the same index gives 155.
            (
                "eleven times that go back",
                &[100, 200, 150, 160, 155, 300, 156, 400, 157, 158],
                157,
            ),
            // The 5000 is the twelfth time below, so it is not read. With one more time or one less
            // time, the median is 100.
            (
                "more than eleven times",
                &[
                    10, 20, 30, 5000, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140,
                ],
                90,
            ),
        ];
        for (name, seconds, median_seconds) in cases {
            let times: Vec<_> = seconds.iter().map(|second| genesis.time + second).collect();
            let below = mined_on(genesis, &times);
            let top = *below.last().unwrap_or(&genesis);
            let median_time = genesis.time + median_seconds;
            // The refused header is not the last, and the header on it has a legal time.
            let refused = mined_on(top, &[median_time, genesis.time + 9000]);
            let taken = mined_on(top, &[median_time + 1]);
            // Each split reads the times from other parts of the chain and the batch.
            for chain_count in [0, below.len() / 2, below.len()] {
                let (on_chain, in_batch) = below.split_at(chain_count);
                let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
                assert_eq!(
                    chain.extend(crate::fixtures::headers_batch(on_chain)),
                    Ok(())
                );
                let before = chain.tip();

                assert_eq!(
                    chain.extend(crate::fixtures::headers_batch(
                        &[in_batch, &refused].concat()
                    )),
                    Err(super::ExtendError::TimeTooOld),
                    "{name} {chain_count}"
                );
                assert_eq!(chain.tip(), before, "{name} {chain_count}");

                assert_eq!(
                    chain.extend(crate::fixtures::headers_batch(&[in_batch, &taken].concat())),
                    Ok(()),
                    "{name} {chain_count}"
                );
                assert_eq!(chain.tip().hash, taken[0].hash(), "{name} {chain_count}");
            }
        }
    }

    #[test]
    fn extend_checks_the_bits_of_a_header_before_its_time() {
        // The genesis time is the median time here, so these fail both checks.
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            prev: genesis.hash(),
            bits: 0x207f_fffe,
            ..genesis
        });
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);

        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&[header])),
            Err(super::ExtendError::WrongBits)
        );
    }

    /// A chain with `real` at their heights and the last of them as the tip. Each other height has
    /// the genesis header, so only what the `bits` rule reads is real. A test cannot mine a header
    /// on these networks, so the tip must be a real header for the next real header to pass. The
    /// median time here is the old genesis time, so a test on this chain holds nothing about it.
    fn chain_with(
        network: crate::chainparams::Network,
        real: &[(usize, crate::block::BlockHeader)],
    ) -> super::Chain {
        let (tip_height, tip) = *real.last().unwrap();
        let mut below_tip = vec![network.genesis(); tip_height];
        for (height, header) in &real[..real.len() - 1] {
            below_tip[*height] = *header;
        }
        super::Chain {
            network,
            below_tip,
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
    fn extend_refuses_a_batch_when_no_bits_can_pass() {
        // Testnet4 changes the `bits` of the first header of a period. That header is not the tip,
        // so the real `next` still chains and has proof of work, and the rule reads these `bits`.
        // `0` is no target, and in the smallest time a target of 3 falls to zero. So the rule has
        // no answer, and that must be a refusal, not a pass.
        let [first, last, next] = crate::fixtures::TESTNET4_RETARGET.map(crate::fixtures::header);
        for bits in [0, 0x0103_0000] {
            let first = crate::block::BlockHeader {
                bits,
                time: last.time,
                ..first
            };
            let mut chain = chain_with(
                crate::chainparams::Network::Testnet4,
                &[(38304, first), (40319, last)],
            );
            assert_eq!(
                chain.extend(crate::fixtures::headers_batch(&[next])),
                Err(super::ExtendError::WrongBits),
                "{bits:#x}"
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
