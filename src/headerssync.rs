const HEADERS_PER_SECOND_MAX: u64 = 6;

const WORD_BITS: usize = 64;

pub(crate) struct Salt {
    pub(crate) keys: [u64; 2],
    pub(crate) offset: usize,
}

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Salt").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadersSyncError {
    NotContinuous,
    ProofOfWork,
    BitsChange,
    TooLong,
    WorkTooLow,
    CommitmentMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Link {
    hash: bitcoin_hashes::sha256d::Hash,
    height: usize,
    bits: u32,
}

struct Commitments {
    keys: [u64; 2],
    period: usize,
    offset: usize,
    start_height: usize,
    words: Vec<u64>,
    count: usize,
}

#[derive(Debug)]
pub(crate) struct Presync {
    network: crate::chainparams::Network,
    start: Link,
    start_work: crate::pow::Work,
    work_min: crate::pow::Work,
    height_max: usize,
    commitments: Commitments,
    last: Link,
    work: crate::pow::Work,
}

#[derive(Debug)]
pub(crate) enum PresyncStep {
    More(Presync),
    Redownload(Redownload),
}

#[derive(Debug)]
pub(crate) struct Redownload {
    network: crate::chainparams::Network,
    work_min: crate::pow::Work,
    commitments: Commitments,
    buffer: std::collections::VecDeque<crate::block::BlockHeader>,
    last: Link,
    work: crate::pow::Work,
}

#[derive(Debug)]
pub(crate) enum RedownloadStep {
    More(Box<Redownload>, Vec<crate::block::BlockHeader>),
    Done(Vec<crate::block::BlockHeader>),
}

impl std::fmt::Debug for Commitments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Commitments")
            .field("period", &self.period)
            .field("start_height", &self.start_height)
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl Commitments {
    fn new(network: crate::chainparams::Network, salt: Salt, start_height: usize) -> Commitments {
        let period = network.commitment_period();
        Commitments {
            keys: salt.keys,
            period,
            offset: salt.offset % period,
            start_height,
            words: Vec::new(),
            count: 0,
        }
    }

    fn is_at(&self, height: usize) -> bool {
        height % self.period == self.offset
    }

    fn index(&self, height: usize) -> usize {
        assert!(height > self.start_height);
        assert!(self.is_at(height));
        (height - self.start_height - 1) / self.period
    }

    fn commitment(&self, hash: bitcoin_hashes::sha256d::Hash) -> bool {
        let [key_0, key_1] = self.keys;
        bitcoin_hashes::siphash24::Hash::hash_to_u64_with_keys(key_0, key_1, hash.as_byte_array())
            .is_multiple_of(2)
    }

    fn push(&mut self, height: usize, hash: bitcoin_hashes::sha256d::Hash) {
        assert_eq!(self.index(height), self.count);
        let bit_index = self.count % WORD_BITS;
        if bit_index == 0 {
            self.words.push(0);
        }
        if self.commitment(hash)
            && let [.., word] = self.words.as_mut_slice()
        {
            assert_eq!(*word >> bit_index, 0);
            *word |= 1 << bit_index;
        }
        self.count += 1;
        assert_eq!(self.words.len(), self.count.div_ceil(WORD_BITS));
    }

    fn get(&self, height: usize) -> Option<bool> {
        assert_eq!(self.words.len(), self.count.div_ceil(WORD_BITS));
        let index = self.index(height);
        if index < self.count {
            let word = self.words.get(index / WORD_BITS)?;
            Some((word >> (index % WORD_BITS)) & 1 == 1)
        } else {
            None
        }
    }
}

impl Presync {
    pub(crate) fn new(
        start: crate::chain::SyncStart,
        work_min: crate::pow::Work,
        clock: u64,
        salt: Salt,
    ) -> Presync {
        let network = start.network();
        assert!(start.work() < work_min);
        let link = Link {
            hash: start.hash(),
            height: start.height(),
            bits: start.bits(),
        };
        let seconds = clock
            .saturating_add(crate::chain::TIME_AHEAD_SECONDS_MAX)
            .saturating_sub(u64::from(start.median_time_past()));
        let headers_count_max =
            usize::try_from(seconds.saturating_mul(HEADERS_PER_SECOND_MAX)).unwrap_or(usize::MAX);
        Presync {
            network,
            start: link,
            start_work: start.work(),
            work_min,
            height_max: link.height.saturating_add(headers_count_max),
            commitments: Commitments::new(network, salt, link.height),
            last: link,
            work: start.work(),
        }
    }

    pub(crate) fn last_hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.last.hash
    }

    pub(crate) fn receive(
        mut self,
        headers: crate::protocol::Headers,
    ) -> Result<PresyncStep, HeadersSyncError> {
        let full = headers.is_full();
        for header in headers.into_vec() {
            let (link, work) = checked(self.network, self.last, &header)?;
            if link.height > self.height_max {
                return Err(HeadersSyncError::TooLong);
            }
            if self.commitments.is_at(link.height) {
                self.commitments.push(link.height, link.hash);
            }
            self.work = self.work.saturating_add(work);
            self.last = link;
        }
        if self.work >= self.work_min {
            Ok(PresyncStep::Redownload(Redownload::new(self)))
        } else if full {
            Ok(PresyncStep::More(self))
        } else {
            Err(HeadersSyncError::WorkTooLow)
        }
    }
}

impl Redownload {
    fn new(presync: Presync) -> Redownload {
        assert!(presync.work >= presync.work_min);
        Redownload {
            network: presync.network,
            work_min: presync.work_min,
            commitments: presync.commitments,
            buffer: std::collections::VecDeque::new(),
            last: presync.start,
            work: presync.start_work,
        }
    }

    pub(crate) fn last_hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.last.hash
    }

    pub(crate) fn receive(
        mut self,
        headers: crate::protocol::Headers,
    ) -> Result<RedownloadStep, HeadersSyncError> {
        let full = headers.is_full();
        for header in headers.into_vec() {
            let (link, work) = checked(self.network, self.last, &header)?;
            self.work = self.work.saturating_add(work);
            if self.work < self.work_min && self.commitments.is_at(link.height) {
                let kept = self.commitments.get(link.height);
                if kept != Some(self.commitments.commitment(link.hash)) {
                    return Err(HeadersSyncError::CommitmentMismatch);
                }
            }
            self.buffer.push_back(header);
            self.last = link;
        }
        if let Some(buffer_last) = self.buffer.back() {
            assert_eq!(buffer_last.hash(), self.last.hash);
        }
        if self.work >= self.work_min {
            Ok(RedownloadStep::Done(Vec::from(self.buffer)))
        } else if full {
            let released_count = self
                .buffer
                .len()
                .saturating_sub(self.network.redownload_buffer_size());
            let released = self.buffer.drain(..released_count).collect();
            assert!(self.buffer.len() <= self.network.redownload_buffer_size());
            Ok(RedownloadStep::More(Box::new(self), released))
        } else {
            Err(HeadersSyncError::WorkTooLow)
        }
    }
}

fn checked(
    network: crate::chainparams::Network,
    below: Link,
    header: &crate::block::BlockHeader,
) -> Result<(Link, crate::pow::Work), HeadersSyncError> {
    if header.prev != below.hash {
        return Err(HeadersSyncError::NotContinuous);
    }
    let (hash, work) = crate::pow::proven(header, network).ok_or(HeadersSyncError::ProofOfWork)?;
    let height = below.height + 1;
    if !crate::pow::permits_bits_change(network, height, below.bits, header.bits) {
        return Err(HeadersSyncError::BitsChange);
    }
    let above = Link {
        hash,
        height,
        bits: header.bits,
    };
    Ok((above, work))
}

impl std::fmt::Display for HeadersSyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeadersSyncError::NotContinuous => write!(f, "headers do not form a chain"),
            HeadersSyncError::ProofOfWork => write!(f, "a header fails proof of work"),
            HeadersSyncError::BitsChange => {
                write!(f, "a header changes the bits more than the network permits")
            }
            HeadersSyncError::TooLong => {
                write!(f, "the chain is higher than any chain can be at our clock")
            }
            HeadersSyncError::WorkTooLow => {
                write!(f, "the chain ended below the minimum work")
            }
            HeadersSyncError::CommitmentMismatch => {
                write!(f, "the second download is not the chain of the first")
            }
        }
    }
}

impl std::error::Error for HeadersSyncError {}

#[cfg(test)]
mod tests {
    const LIMIT_BITS: u32 = 0x207f_ffff;

    const SALT: super::Salt = super::Salt {
        keys: [1, 2],
        offset: 275 * 1_000 + 15,
    };

    fn mined_on(
        below: &crate::block::BlockHeader,
        count: usize,
        bits: u32,
        seed: u8,
    ) -> Vec<crate::block::BlockHeader> {
        let mut headers: Vec<crate::block::BlockHeader> = Vec::with_capacity(count);
        for _ in 0..count {
            let below = headers.last().unwrap_or(below);
            let unmined = crate::block::BlockHeader {
                version: crate::fixtures::HEADER_VERSION,
                prev: below.hash(),
                merkle_root: [seed; 32],
                time: below.time + 1,
                bits,
                nonce: 0,
            };
            let header = (0..=u32::MAX)
                .map(|nonce| crate::block::BlockHeader { nonce, ..unmined })
                .find(|header| {
                    crate::pow::proven(header, crate::chainparams::Network::Regtest).is_some()
                })
                .unwrap();
            headers.push(header);
        }
        headers
    }

    fn chain_on_genesis(count: usize, seed: u8) -> Vec<crate::block::BlockHeader> {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        mined_on(&genesis, count, LIMIT_BITS, seed)
    }

    fn work_on_genesis(headers: &[crate::block::BlockHeader]) -> crate::pow::Work {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        std::iter::once(&genesis)
            .chain(headers)
            .map(|header| crate::pow::work(header.bits, crate::chainparams::Network::Regtest))
            .map(Option::unwrap)
            .reduce(crate::pow::Work::saturating_add)
            .unwrap()
    }

    fn presync(work_min: crate::pow::Work) -> super::Presync {
        let chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        super::Presync::new(
            chain.sync_start_on_tip(),
            work_min,
            crate::fixtures::CLOCK,
            SALT,
        )
    }

    fn more(
        mut presync: super::Presync,
        batches: &[&[crate::block::BlockHeader]],
    ) -> super::Presync {
        for batch in batches {
            let step = presync.receive(crate::fixtures::headers_batch(batch));
            let Ok(super::PresyncStep::More(next)) = step else {
                panic!("{step:?}");
            };
            presync = next;
        }
        presync
    }

    fn redownload(
        work_min: crate::pow::Work,
        batches: &[&[crate::block::BlockHeader]],
    ) -> super::Redownload {
        let [before @ .., last] = batches else {
            panic!("no batch");
        };
        let step = more(presync(work_min), before).receive(crate::fixtures::headers_batch(last));
        let Ok(super::PresyncStep::Redownload(redownload)) = step else {
            panic!("{step:?}");
        };
        redownload
    }

    fn batch(headers: &[crate::block::BlockHeader]) -> crate::protocol::Headers {
        crate::fixtures::headers_batch(headers)
    }

    #[test]
    fn the_debug_of_the_salt_and_of_its_commitments_writes_no_secret() {
        assert_eq!(format!("{SALT:?}"), "Salt { .. }");
        let commitments = super::Commitments::new(crate::chainparams::Network::Regtest, SALT, 7);
        assert_eq!(
            format!("{commitments:?}"),
            "Commitments { period: 275, start_height: 7, count: 0, .. }"
        );
    }

    #[test]
    fn presync_asks_for_more_after_a_full_batch_below_the_minimum() {
        let headers = chain_on_genesis(4_001, 0);
        let work_min = work_on_genesis(&headers).saturating_add(work_on_genesis(&[]));

        let after_two_batches = more(
            presync(work_min),
            &[&headers[..2_000], &headers[2_000..4_000]],
        );

        assert_eq!(
            after_two_batches
                .receive(batch(&headers[4_000..]))
                .unwrap_err(),
            super::HeadersSyncError::WorkTooLow
        );
        assert_eq!(
            presync(work_min).receive(batch(&[])).unwrap_err(),
            super::HeadersSyncError::WorkTooLow
        );
    }

    #[test]
    fn presync_starts_the_redownload_when_the_work_reaches_the_minimum() {
        let headers = chain_on_genesis(2_000, 0);
        let work_at = |count| work_on_genesis(&headers[..count]);

        assert!(matches!(
            presync(work_at(2_000)).receive(batch(&headers)),
            Ok(super::PresyncStep::Redownload(_))
        ));
        assert!(matches!(
            presync(work_at(2_000).saturating_add(work_at(0))).receive(batch(&headers)),
            Ok(super::PresyncStep::More(_))
        ));
        assert!(matches!(
            presync(work_at(1_000)).receive(batch(&headers[..1_000])),
            Ok(super::PresyncStep::Redownload(_))
        ));
    }

    #[test]
    fn presync_refuses_a_header_that_is_not_on_the_header_below_it() {
        let headers = chain_on_genesis(2_000, 0);
        let other = chain_on_genesis(1, 1);
        let work_min = work_on_genesis(&headers).saturating_add(work_on_genesis(&[]));

        let cases: [(&str, super::Presync, Vec<crate::block::BlockHeader>); 3] = [
            ("not on genesis", presync(work_min), headers[1..].to_vec()),
            (
                "a break",
                presync(work_min),
                [&headers[..5], &headers[6..]].concat(),
            ),
            (
                "not on the last header",
                more(presync(work_min), &[&headers]),
                other,
            ),
        ];
        for (name, presync, headers) in cases {
            assert_eq!(
                presync.receive(batch(&headers)).unwrap_err(),
                super::HeadersSyncError::NotContinuous,
                "{name}"
            );
        }
    }

    #[test]
    fn presync_refuses_a_header_without_proof_of_work() {
        let mut headers = chain_on_genesis(3, 0);
        let work_min = work_on_genesis(&headers).saturating_add(work_on_genesis(&[]));
        headers[2] = (headers[2].nonce + 1..)
            .map(|nonce| crate::block::BlockHeader {
                nonce,
                ..headers[2]
            })
            .find(|header| {
                crate::pow::proven(header, crate::chainparams::Network::Regtest).is_none()
            })
            .unwrap();

        assert_eq!(
            presync(work_min).receive(batch(&headers)).unwrap_err(),
            super::HeadersSyncError::ProofOfWork
        );
    }

    #[test]
    fn presync_reads_the_bits_of_the_tip_of_our_chain() {
        let block_1 = crate::fixtures::header(crate::fixtures::MAINNET_BLOCK_1);
        assert_eq!(
            block_1.hash(),
            crate::fixtures::hash_from_display_hex(
                "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
            )
        );
        let chain = crate::chain::Chain::new(crate::chainparams::Network::Mainnet);
        let genesis_work = chain.tip().work();
        let work_min = genesis_work
            .saturating_add(genesis_work)
            .saturating_add(genesis_work);
        let presync = super::Presync::new(
            chain.sync_start_on_tip(),
            work_min,
            crate::fixtures::CLOCK,
            SALT,
        );

        assert_eq!(
            presync.receive(batch(&[block_1])).unwrap_err(),
            super::HeadersSyncError::WorkTooLow
        );
    }

    #[test]
    fn presync_refuses_a_chain_higher_than_the_clock_permits() {
        let headers = chain_on_genesis(701, 0);
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        chain
            .extend(batch(&headers[..100]), crate::fixtures::CLOCK)
            .unwrap();
        let work_min = work_on_genesis(&headers).saturating_add(work_on_genesis(&[]));
        let genesis_time = u64::from(crate::chainparams::Network::Regtest.genesis().time);
        let clock = genesis_time + 95 - crate::chain::TIME_AHEAD_SECONDS_MAX + 100;
        let presync_at =
            |clock| super::Presync::new(chain.sync_start_on_tip(), work_min, clock, SALT);

        assert_eq!(
            presync_at(clock)
                .receive(batch(&headers[100..700]))
                .unwrap_err(),
            super::HeadersSyncError::WorkTooLow
        );
        assert_eq!(
            presync_at(clock)
                .receive(batch(&headers[100..]))
                .unwrap_err(),
            super::HeadersSyncError::TooLong
        );
        assert_eq!(
            presync_at(0)
                .receive(batch(&headers[100..101]))
                .unwrap_err(),
            super::HeadersSyncError::TooLong
        );
    }

    #[test]
    fn redownload_gives_each_header_once_enough_headers_are_above_it() {
        let headers = chain_on_genesis(10_000, 0);
        let batches: Vec<&[crate::block::BlockHeader]> = headers.chunks(2_000).collect();
        let mut redownload = redownload(work_on_genesis(&headers[..9_500]), &batches);

        let mut released = Vec::new();
        for (batch_headers, released_count) in batches[..4].iter().zip([0, 0, 0, 983]) {
            let step = redownload.receive(batch(batch_headers));
            let Ok(super::RedownloadStep::More(next, batch_released)) = step else {
                panic!("{step:?}");
            };
            assert_eq!(batch_released.len(), released_count);
            released.extend(batch_released);
            redownload = *next;
        }
        let step = redownload.receive(batch(batches[4]));
        let Ok(super::RedownloadStep::Done(batch_released)) = step else {
            panic!("{step:?}");
        };
        released.extend(batch_released);

        assert_eq!(released, headers);
    }

    fn redownload_after_one_batch(headers: &[crate::block::BlockHeader]) -> super::Redownload {
        let redownload = redownload(
            work_on_genesis(headers),
            &[&headers[..2_000], &headers[2_000..]],
        );
        let step = redownload.receive(batch(&headers[..2_000]));
        let Ok(super::RedownloadStep::More(redownload, _)) = step else {
            panic!("{step:?}");
        };
        *redownload
    }

    #[test]
    fn redownload_refuses_what_the_first_download_refuses() {
        let headers = chain_on_genesis(4_000, 0);
        let mut unproven = headers[2_000..2_010].to_vec();
        unproven[5] = (unproven[5].nonce + 1..)
            .map(|nonce| crate::block::BlockHeader {
                nonce,
                ..unproven[5]
            })
            .find(|header| {
                crate::pow::proven(header, crate::chainparams::Network::Regtest).is_none()
            })
            .unwrap();
        let work_min = work_on_genesis(&headers);
        let at_start = || redownload(work_min, &[&headers[..2_000], &headers[2_000..]]);

        let cases: [(&str, super::Redownload, &[crate::block::BlockHeader], _); 5] = [
            (
                "on the last header of the first download",
                at_start(),
                &mined_on(&headers[3_999], 1, LIMIT_BITS, 0),
                super::HeadersSyncError::NotContinuous,
            ),
            (
                "not on genesis",
                at_start(),
                &headers[1..2_001],
                super::HeadersSyncError::NotContinuous,
            ),
            (
                "not on the last header",
                redownload_after_one_batch(&headers),
                &headers[2_001..],
                super::HeadersSyncError::NotContinuous,
            ),
            (
                "no proof of work",
                redownload_after_one_batch(&headers),
                &unproven,
                super::HeadersSyncError::ProofOfWork,
            ),
            (
                "a batch that is not full below the minimum",
                redownload_after_one_batch(&headers),
                &headers[2_000..3_999],
                super::HeadersSyncError::WorkTooLow,
            ),
        ];
        for (name, redownload, headers, expected) in cases {
            assert_eq!(
                redownload.receive(batch(headers)).unwrap_err(),
                expected,
                "{name}"
            );
        }
        assert!(matches!(
            redownload_after_one_batch(&headers).receive(batch(&headers[2_000..])),
            Ok(super::RedownloadStep::Done(_))
        ));
    }

    #[test]
    fn redownload_refuses_another_chain() {
        let headers = chain_on_genesis(2_000, 0);
        let other = chain_on_genesis(2_000, 1);
        let redownload = redownload(work_on_genesis(&headers), &[&headers]);

        assert_eq!(
            redownload.receive(batch(&other)).unwrap_err(),
            super::HeadersSyncError::CommitmentMismatch
        );
    }

    #[test]
    fn redownload_reads_no_commitment_from_the_header_that_reaches_the_minimum() {
        let headers = chain_on_genesis(2_000, 0);
        let work_min = work_on_genesis(&headers[..1_115]);
        for seed in 1..=8 {
            let above = mined_on(&headers[1_113], 886, LIMIT_BITS, seed);
            let second = [&headers[..1_114], &above].concat();
            let redownload = redownload(work_min, &[&headers]);

            assert!(
                matches!(
                    redownload.receive(batch(&second)),
                    Ok(super::RedownloadStep::Done(_))
                ),
                "{seed}"
            );
        }
    }

    #[test]
    fn redownload_refuses_a_chain_after_the_last_commitment() {
        let bits_hard = 0x2010_0000;
        let first = chain_on_genesis(1_940, 0);
        let first_hard = mined_on(&first[1_939], 60, bits_hard, 0);
        let second_easy = mined_on(&first[1_939], 275, LIMIT_BITS, 1);
        let first = [first.as_slice(), &first_hard].concat();
        let second = [&first[..1_940], &second_easy].concat();
        let work_min = work_on_genesis(&first);
        assert!(work_on_genesis(&second) < work_min);

        let after_one_batch = || {
            let step = redownload(work_min, &[&first]).receive(batch(&second[..2_000]));
            let Ok(super::RedownloadStep::More(redownload, _)) = step else {
                panic!("{step:?}");
            };
            *redownload
        };

        assert_eq!(
            after_one_batch()
                .receive(batch(&second[2_000..2_214]))
                .unwrap_err(),
            super::HeadersSyncError::WorkTooLow
        );
        assert_eq!(
            after_one_batch()
                .receive(batch(&second[2_000..]))
                .unwrap_err(),
            super::HeadersSyncError::CommitmentMismatch
        );
    }

    #[test]
    fn sync_on_a_tip_with_a_commitment_keeps_the_first_commitment_a_period_above() {
        let headers = chain_on_genesis(2_015, 0);
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        chain
            .extend(batch(&headers[..15]), crate::fixtures::CLOCK)
            .unwrap();
        let presync = super::Presync::new(
            chain.sync_start_on_tip(),
            work_on_genesis(&headers),
            crate::fixtures::CLOCK,
            SALT,
        );

        let step = presync.receive(batch(&headers[15..]));
        let Ok(super::PresyncStep::Redownload(redownload)) = step else {
            panic!("{step:?}");
        };
        assert_eq!(redownload.commitments.count, 7);
        let step = redownload.receive(batch(&headers[15..]));
        let Ok(super::RedownloadStep::Done(released)) = step else {
            panic!("{step:?}");
        };

        assert_eq!(released, headers[15..]);
    }
}
