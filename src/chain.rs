//! The header chain.

/// The most headers that a median time reads: the header below a new header, and the 10 below it.
const MEDIAN_TIME_HEADERS_COUNT_MAX: usize = 11;

// This count has one middle, so only a chain below this height has two middle times.
const _: () = assert!(!MEDIAN_TIME_HEADERS_COUNT_MAX.is_multiple_of(2));

/// One linear chain of headers, from genesis to the tip. It is never empty, each header has proof
/// of work, and each header above genesis has the `bits` that the headers below it require and a
/// time above their median time. On testnet4, each first header of a period above genesis also has
/// a time at most 10 minutes below the header below it.
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
    /// On testnet4, the time of the first header of a period is more than 10 minutes below the
    /// header below it.
    TimeTimewarpAttack,
}

/// The headers below one header of a batch, by height: the chain, then the part of the batch that
/// comes before that header. A batch is not on the chain until each of its headers passes, so the
/// rules read it through this.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Ancestors<'a> {
    below_tip: &'a [crate::block::BlockHeader],
    tip: &'a crate::block::BlockHeader,
    batch: &'a [crate::block::BlockHeader],
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
    /// first, then its proof of work, then its `bits`, then its time against the median time, then
    /// its time against the timewarp rule.
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
            if header.time < crate::pow::timewarp_time_min(self.network, ancestors) {
                return Err(ExtendError::TimeTimewarpAttack);
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
        // is above their median time and at or above the bound of the timewarp rule.
        assert_eq!(self.tip.prev, ancestors.tip.hash());
        assert!(crate::pow::proven_hash(&self.tip, self.network).is_some());
        assert_eq!(
            crate::pow::required_bits(self.network, ancestors, self.tip.time),
            Some(self.tip.bits)
        );
        assert!(self.tip.time > ancestors.median_time_past());
        assert!(self.tip.time >= crate::pow::timewarp_time_min(self.network, ancestors));
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
    /// `tip` as the only header of a chain, and `batch` above it. Only the tests and the fuzz
    /// script call this, so the rules of another module read these headers and cannot write them.
    #[cfg(any(test, fuzzing))]
    // Only cargo-mutants reads this attribute.
    #[cfg_attr(false, mutants::skip)]
    pub(crate) fn on_tip(
        tip: &'a crate::block::BlockHeader,
        batch: &'a [crate::block::BlockHeader],
    ) -> Ancestors<'a> {
        Ancestors {
            below_tip: &[],
            tip,
            batch,
        }
    }

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

    /// The median of the times of the last `MEDIAN_TIME_HEADERS_COUNT_MAX` headers, or of each
    /// header if there are fewer. Times can go back, so this sorts them. With an even count, which
    /// only a chain below that height has, this is the higher of the two middle times.
    ///
    /// A peer picks each time, so no value may panic. A peer also runs this once for each header
    /// of a batch. So it reads at most `MEDIAN_TIME_HEADERS_COUNT_MAX` headers and uses no heap.
    fn median_time_past(self) -> u32 {
        let height_above = self.height_above();
        let times_count = height_above.min(MEDIAN_TIME_HEADERS_COUNT_MAX);
        assert!(times_count >= 1);
        let height_first = height_above - times_count;
        let mut times_buffer = [0; MEDIAN_TIME_HEADERS_COUNT_MAX];
        let times = &mut times_buffer[..times_count];
        // Each place of `times` gets a time, so no zero of the buffer can reach the median.
        for (index, time) in times.iter_mut().enumerate() {
            *time = self.at(height_first + index).time;
        }
        // This sort needs no heap, and two equal times are the same.
        times.sort_unstable();
        // Half of an odd count, rounded down, is its middle. An even count has two middles, and
        // half of it is the higher.
        let middle_index = times_count / 2;
        times[middle_index]
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
            ExtendError::TimeTimewarpAttack => {
                write!(f, "the first header of a period has a time too far back")
            }
        }
    }
}

impl std::error::Error for ExtendError {}

#[cfg(fuzzing)]
// Only cargo-mutants reads this attribute. Its test runs do not build this module.
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    /// The first headers of a batch that go through the check. A median reads at most
    /// `MEDIAN_TIME_HEADERS_COUNT_MAX` times, so the first header with a time out of that window
    /// reaches the last new path. The headers above it only give a run more windows of times. In a
    /// batch that is longer than its input, the later headers have only zeros. A check of each
    /// header costs 40% of the runs of the `headers` target. With this bound, the cost is inside the
    /// noise of a run.
    const MEDIAN_CHECK_HEADERS_COUNT_MAX: usize = 4 * super::MEDIAN_TIME_HEADERS_COUNT_MAX;

    /// The headers below the tip in the timewarp check. The rule reads only their count, and a
    /// `static` means that a run copies nothing.
    static BELOW_TIP: [crate::block::BlockHeader; 2016] =
        [crate::chainparams::Network::Testnet4.genesis(); 2016];

    /// A peer picks each `time`, so `header` goes through the timewarp rule as the header below a
    /// first header of a period, on each network. A batch has fewer headers than a period, so it
    /// does not reach this height by itself. Each height next to the first header and each other
    /// network has no bound. A person wrote the heights and the 600, and the answer is in wider
    /// numbers, so a wrong constant or a subtract that wraps fails here.
    pub(crate) fn timewarp_time_min_check(header: &crate::block::BlockHeader) {
        let ancestors = |height_above: usize| super::Ancestors {
            below_tip: &BELOW_TIP[..height_above - 1],
            tip: header,
            batch: &[],
        };
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
            crate::chainparams::Network::Regtest,
        ] {
            assert_eq!(crate::pow::timewarp_time_min(network, ancestors(2015)), 0);
            assert_eq!(crate::pow::timewarp_time_min(network, ancestors(2017)), 0);
            let expected = match network {
                crate::chainparams::Network::Testnet4 => (i64::from(header.time) - 600).max(0),
                crate::chainparams::Network::Mainnet
                | crate::chainparams::Network::Signet
                | crate::chainparams::Network::Regtest => 0,
            };
            assert_eq!(
                i64::from(crate::pow::timewarp_time_min(network, ancestors(2016))),
                expected
            );
        }
    }

    /// A peer picks each `time` of `headers`, so the first headers go through the median time, as
    /// the header above the ones before it. It must return for any value. This check does not sort:
    /// of `times_count` times, only the time at index `times_count / 2` of the sorted times has
    /// more than `times_count / 2` times at or below it, and at least
    /// `times_count - times_count / 2` at or above it.
    pub(crate) fn median_time_past_check(headers: &[crate::block::BlockHeader]) {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        for index in 0..headers.len().min(MEDIAN_CHECK_HEADERS_COUNT_MAX) {
            let batch = &headers[..index];
            let median = super::Ancestors::on_tip(&genesis, batch).median_time_past();
            let times = || {
                std::iter::once(&genesis)
                    .chain(batch)
                    .rev()
                    .take(super::MEDIAN_TIME_HEADERS_COUNT_MAX)
                    .map(|header| header.time)
            };
            let times_count = times().count();
            let at_or_below_count = times().filter(|time| *time <= median).count();
            let at_or_above_count = times().filter(|time| *time >= median).count();
            assert!(at_or_below_count > times_count / 2);
            assert!(at_or_above_count >= times_count - times_count / 2);
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
        let mut headers = Vec::with_capacity(times.len());
        let mut prev = below.hash();
        for time in times {
            let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
                prev,
                time: *time,
                ..below
            });
            prev = header.hash();
            headers.push(header);
        }
        headers
    }

    /// Each row mines the headers below, and splits them between the chain and the batch. On each
    /// split, a batch with a time at the median or one second below it must leave the chain as it
    /// was, and a batch with a time one second above the median must pass.
    #[test]
    fn extend_takes_a_time_only_above_the_median_time_of_the_headers_below() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        // The seconds after the genesis time of each header above genesis, and of their median
        // time. A person wrote each median, from the times with genesis at 0.
        let cases: [(&str, &[u32], u32); 7] = [
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
            // The 5000 and the 6000 are the twelfth and thirteenth times below, so they are not
            // read. With two more times, the median is 100. The row above gives 90 there, because
            // its two times are on each side of the median. This row gives 90 with four more
            // times, and the row above does not.
            (
                "more than thirteen times",
                &[
                    10, 20, 6000, 5000, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140,
                ],
                90,
            ),
        ];
        for (name, seconds, median_seconds) in cases {
            let times: Vec<_> = seconds.iter().map(|second| genesis.time + second).collect();
            let below = mined_on(genesis, &times);
            let top = *below.last().unwrap_or(&genesis);
            let median_time = genesis.time + median_seconds;
            // Each refused header is not the last, and the header on it has a legal time.
            let refused = [median_time, median_time - 1]
                .map(|time| mined_on(top, &[time, genesis.time + 9000]));
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

                for refused in &refused {
                    let time = refused[0].time;
                    assert_eq!(
                        chain.extend(crate::fixtures::headers_batch(
                            &[in_batch, refused.as_slice()].concat()
                        )),
                        Err(super::ExtendError::TimeTooOld),
                        "{name} {chain_count} {time}"
                    );
                    assert_eq!(chain.tip(), before, "{name} {chain_count} {time}");
                }

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

    /// The header at height 0 of the chains of the timewarp tests. It is two weeks below `last`, so
    /// a change of the target keeps the `bits`, on each network that changes them.
    fn timewarp_first(last: crate::block::BlockHeader) -> crate::block::BlockHeader {
        crate::block::BlockHeader {
            time: last.time - 14 * 24 * 60 * 60,
            ..last
        }
    }

    /// The first header of a period may go back to the bound. Each header has real proof of work
    /// and each other rule takes it, so only this rule refuses it. Each batch reads the header
    /// below through the tip and through the batch.
    #[test]
    fn extend_on_testnet4_bounds_the_time_of_the_first_header_of_a_period() {
        let [
            below_last,
            last,
            at_bound,
            one_below,
            far_below,
            on_one_below,
        ] = crate::fixtures::TESTNET4_TIMEWARP.map(crate::fixtures::header);
        let network = crate::chainparams::Network::Testnet4;
        // These are what the names say, so a wrong fixture cannot hold another bound.
        assert_eq!(last.time - at_bound.time, 600);
        assert_eq!(last.time - one_below.time, 601);
        assert!(last.time - far_below.time > 1_000_000);
        // A read of the tip in place of the header below gives a bound below this time in the
        // second split, so that read lets this header pass.
        assert!(below_last.time < one_below.time - 600);

        let first = timewarp_first(last);
        let splits = [
            (vec![(0, first), (2015, last)], vec![]),
            (vec![(0, first), (2014, below_last)], vec![last]),
        ];
        for (real, in_batch) in &splits {
            let height_tip = real.last().unwrap().0;
            // In the first batch the refused header is not the last, and the header on it is legal.
            for refused in [vec![one_below, on_one_below], vec![far_below]] {
                let time = refused[0].time;
                let mut chain = chain_with(network, real);
                let before = chain.tip();
                assert_eq!(
                    chain.extend(crate::fixtures::headers_batch(
                        &[in_batch.as_slice(), refused.as_slice()].concat()
                    )),
                    Err(super::ExtendError::TimeTimewarpAttack),
                    "{height_tip} {time}"
                );
                assert_eq!(chain.tip(), before, "{height_tip} {time}");
            }

            let mut chain = chain_with(network, real);
            assert_eq!(
                chain.extend(crate::fixtures::headers_batch(
                    &[in_batch.as_slice(), &[at_bound]].concat()
                )),
                Ok(()),
                "{height_tip}"
            );
            assert_eq!(chain.tip().hash, at_bound.hash(), "{height_tip}");
        }
    }

    /// One header goes back past the bound in each row. Only the first header of a period on
    /// testnet4 is refused. The rows are the heights on each side of one first header, the next
    /// first header, and each other network at a first header.
    #[test]
    fn extend_refuses_a_time_far_back_only_at_the_start_of_a_period_on_testnet4() {
        let [_, last, _, one_below, ..] =
            crate::fixtures::TESTNET4_TIMEWARP.map(crate::fixtures::header);
        let first = timewarp_first(last);
        // A test can mine on regtest, so this row needs no fixture, and the `bits` of the fixture
        // are not the `bits` of regtest.
        let regtest_genesis = crate::chainparams::Network::Regtest.genesis();
        let regtest_last = crate::block::BlockHeader {
            time: regtest_genesis.time + 9000,
            ..regtest_genesis
        };
        let regtest_one_below = mined_on(regtest_last, &[regtest_last.time - 601])[0];

        for (network, real, header, expected) in [
            (
                crate::chainparams::Network::Testnet4,
                vec![(2014, last)],
                one_below,
                Ok(()),
            ),
            (
                crate::chainparams::Network::Testnet4,
                vec![(2016, last)],
                one_below,
                Ok(()),
            ),
            (
                crate::chainparams::Network::Testnet4,
                vec![(2016, first), (4031, last)],
                one_below,
                Err(super::ExtendError::TimeTimewarpAttack),
            ),
            (
                crate::chainparams::Network::Mainnet,
                vec![(0, first), (2015, last)],
                one_below,
                Ok(()),
            ),
            (
                crate::chainparams::Network::Signet,
                vec![(0, first), (2015, last)],
                one_below,
                Ok(()),
            ),
            (
                crate::chainparams::Network::Regtest,
                vec![(2015, regtest_last)],
                regtest_one_below,
                Ok(()),
            ),
        ] {
            let height_tip = real.last().unwrap().0;
            let mut chain = chain_with(network, &real);
            assert_eq!(
                chain.extend(crate::fixtures::headers_batch(&[header])),
                expected,
                "{network:?} {height_tip}"
            );
        }
    }

    #[test]
    fn extend_checks_the_median_time_before_the_timewarp_rule() {
        // The headers below the tip have the time of the tip, so this header fails both rules.
        let [_, last, _, one_below, ..] =
            crate::fixtures::TESTNET4_TIMEWARP.map(crate::fixtures::header);
        let mut real = vec![(0, timewarp_first(last))];
        real.extend((2005..=2015).map(|height| (height, last)));
        let mut chain = chain_with(crate::chainparams::Network::Testnet4, &real);

        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&[one_below])),
            Err(super::ExtendError::TimeTooOld)
        );
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
