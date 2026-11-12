//! The sync of a chain of headers that starts below the minimum work. A peer can make cheap
//! headers for as long as it wants, so elo does not keep the headers of such a chain until the
//! chain shows the work. The first download, `Presync`, checks each header, keeps one bit for each
//! period of headers, and drops the headers. When the work is enough, the second download,
//! `Redownload`, gets the same chain again and checks each bit. It gives a header to the chain only
//! when enough bits above that header passed, or when the work is enough again.

/// The most headers for each second of the median time. Each header needs a time above the median
/// time of the 11 headers below it, so at most 6 headers can have the same time.
const HEADERS_PER_SECOND_MAX: u64 = 6;

/// The bits of one `u64` word of `Commitments`.
const WORD_BITS: usize = 64;

/// The random numbers of one sync. The peer must not know them. With them, it could make a second
/// chain that matches the bits of the first.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Salt {
    /// The keys of the hash that gives each bit.
    pub(crate) keys: [u64; 2],
    /// Picks the heights that have a bit. Each value is legal.
    pub(crate) offset: usize,
}

/// Why a sync refused a batch. Each one ends the sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeadersSyncError {
    /// The `prev` of a header is not the hash of the header below it: the tip of our chain, or the
    /// last header that the peer sent in this download.
    NotContinuous,
    /// The `bits` of a header are not a target in the range of the network, or the hash of the
    /// header is above that target.
    ProofOfWork,
    /// The `bits` of a header are not a change that the network permits from the `bits` below it.
    BitsChange,
    /// A header is above the highest height that a chain can have at the clock of the sync.
    TooLong,
    /// A batch that is not full ended the chain, and the chain has less work than the minimum.
    WorkTooLow,
    /// A header of the second download does not have the bit that the first download kept for
    /// its height, or the first download kept no more bits.
    CommitmentMismatch,
}

/// The header that the next header of the peer goes on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Below {
    hash: bitcoin_hashes::sha256d::Hash,
    height: usize,
    bits: u32,
}

/// One bit for each header at a height of `offset` modulo `period`, in the order of the heights.
#[derive(Debug)]
struct Commitments {
    keys: [u64; 2],
    period: usize,
    /// Below `period`.
    offset: usize,
    /// Bit `index` is bit `index % WORD_BITS` of word `index / WORD_BITS`.
    words: Vec<u64>,
    count: usize,
}

/// The first download of a sync. It keeps no header, only one bit for each period of headers.
#[derive(Debug)]
pub(crate) struct Presync {
    network: crate::chainparams::Network,
    /// The tip of our chain, which the chain of the peer goes on.
    start: Below,
    /// The work of our chain.
    start_work: crate::pow::Work,
    /// The work that the chain of the peer must reach. It is above `start_work`.
    work_min: crate::pow::Work,
    /// The highest height that a chain can have at the clock of the sync.
    height_max: usize,
    commitments: Commitments,
    /// The last header that the peer sent, or `start`.
    last: Below,
    /// `start_work` plus the work of each header that the peer sent.
    work: crate::pow::Work,
}

/// What a batch of the first download gave.
#[derive(Debug)]
pub(crate) enum PresyncStep {
    /// The batch was full and the work is below the minimum. The peer sends more on the last
    /// header.
    More(Presync),
    /// The work reached the minimum. The peer sends the chain again, on the tip of our chain.
    Redownload(Redownload),
}

/// The second download of a sync. It holds the headers that wait for more bits above them.
#[derive(Debug)]
pub(crate) struct Redownload {
    network: crate::chainparams::Network,
    work_min: crate::pow::Work,
    commitments: Commitments,
    /// The bits that this download read, from the first.
    commitments_read_count: usize,
    /// The headers that the chain did not get yet, in order. The first is on the tip of our
    /// chain, or on the last header that the chain got.
    buffer: std::collections::VecDeque<crate::block::BlockHeader>,
    /// The last header of `buffer`, or the tip of our chain.
    last: Below,
    /// The work of our chain plus the work of each header of this download.
    work: crate::pow::Work,
}

/// What a batch of the second download gave. Each header in it goes on the chain, in order.
#[derive(Debug)]
pub(crate) enum RedownloadStep {
    /// The batch was full and the work is below the minimum. The peer sends more on the last
    /// header. The box keeps the step small, because `Done` has only the headers.
    More(Box<Redownload>, Vec<crate::block::BlockHeader>),
    /// The work reached the minimum, so the chain gets each header that is left. The sync ends.
    Done(Vec<crate::block::BlockHeader>),
}

impl Commitments {
    fn new(network: crate::chainparams::Network, salt: Salt) -> Commitments {
        let period = network.commitment_period();
        Commitments {
            keys: salt.keys,
            period,
            offset: salt.offset % period,
            words: Vec::new(),
            count: 0,
        }
    }

    /// A header at `height` has a bit.
    fn is_at(&self, height: usize) -> bool {
        height % self.period == self.offset
    }

    /// The bit of the header with `hash`: its salted hash is even.
    fn bit(&self, hash: bitcoin_hashes::sha256d::Hash) -> bool {
        let [key_0, key_1] = self.keys;
        bitcoin_hashes::siphash24::Hash::hash_to_u64_with_keys(key_0, key_1, hash.as_byte_array())
            .is_multiple_of(2)
    }

    /// Keeps the bit of the header with `hash`, after the others.
    fn push(&mut self, hash: bitcoin_hashes::sha256d::Hash) {
        let bit_index = self.count % WORD_BITS;
        if bit_index == 0 {
            self.words.push(0);
        }
        if self.bit(hash) {
            // The bit is clear, so the add is an or.
            if let [.., word] = self.words.as_mut_slice() {
                *word += 1 << bit_index;
            }
        }
        self.count += 1;
        assert_eq!(self.words.len(), self.count.div_ceil(WORD_BITS));
    }

    /// The bit at `index`, if the first download kept that many bits.
    fn get(&self, index: usize) -> Option<bool> {
        if index >= self.count {
            return None;
        }
        let word = self.words.get(index / WORD_BITS)?;
        Some((word >> (index % WORD_BITS)) & 1 == 1)
    }
}

impl Presync {
    /// The first download of the chain of the peer, on the tip of `chain`, until the chain has
    /// `work_min`. The work of `chain` must be below `work_min`. `clock` is the local clock, in
    /// seconds since the Unix epoch. A chain gets at most `HEADERS_PER_SECOND_MAX` headers in each
    /// second from the median time of the tip, until a header can be `TIME_AHEAD_SECONDS_MAX`
    /// after the clock. So the clock bounds the height, and the height bounds the bits.
    pub(crate) fn new(
        chain: &crate::chain::Chain,
        work_min: crate::pow::Work,
        clock: u64,
        salt: Salt,
    ) -> Presync {
        let network = chain.network();
        let tip = chain.tip();
        assert!(tip.work() < work_min);
        let start = Below {
            hash: tip.hash(),
            height: tip.height(),
            bits: chain.tip_bits(),
        };
        // A clock far after each real time saturates, and so does the height, so the bound
        // refuses no chain. A clock below the median time gives zero seconds, and then the bound
        // refuses each header.
        let seconds = clock
            .saturating_add(crate::chain::TIME_AHEAD_SECONDS_MAX)
            .saturating_sub(u64::from(chain.median_time_past()));
        let headers_count_max =
            usize::try_from(seconds.saturating_mul(HEADERS_PER_SECOND_MAX)).unwrap_or(usize::MAX);
        Presync {
            network,
            start,
            start_work: tip.work(),
            work_min,
            height_max: start.height.saturating_add(headers_count_max),
            commitments: Commitments::new(network, salt),
            last: start,
            work: tip.work(),
        }
    }

    /// Checks each of `headers`, in order, on the last header. For one header, its `prev` is
    /// checked first, then its proof of work, then its `bits`, then its height. When the work
    /// reaches the minimum, the next download starts after the batch. Else a batch that is not
    /// full fails, an empty one too.
    pub(crate) fn receive(
        mut self,
        headers: crate::protocol::Headers,
    ) -> Result<PresyncStep, HeadersSyncError> {
        let full = headers.is_full();
        for header in headers.into_vec() {
            let (below, work) = checked(self.network, self.last, &header)?;
            if below.height > self.height_max {
                return Err(HeadersSyncError::TooLong);
            }
            if self.commitments.is_at(below.height) {
                self.commitments.push(below.hash);
                // At most one bit in each period above the start. With the height bound above,
                // this is the bound on the memory of the bits.
                assert!(
                    self.commitments.count
                        <= (below.height - self.start.height) / self.commitments.period + 1
                );
            }
            self.work = self.work.saturating_add(work);
            self.last = below;
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
    /// The second download, on the tip of the chain, with the bits of the first.
    fn new(presync: Presync) -> Redownload {
        assert!(presync.work >= presync.work_min);
        Redownload {
            network: presync.network,
            work_min: presync.work_min,
            commitments: presync.commitments,
            commitments_read_count: 0,
            buffer: std::collections::VecDeque::new(),
            last: presync.start,
            work: presync.start_work,
        }
    }

    /// Checks each of `headers`, in order, on the last header, as the first download did. Each
    /// header at the height of a bit must have that bit, until the work reaches the minimum. From
    /// there the chain shows the work, so no header needs a bit, and the peer can also have new
    /// headers above the first chain. Then the chain gets each header and the sync ends. Else the
    /// chain gets only the headers with more than `redownload_buffer_size` headers above them, and
    /// a batch that is not full fails, an empty one too.
    pub(crate) fn receive(
        mut self,
        headers: crate::protocol::Headers,
    ) -> Result<RedownloadStep, HeadersSyncError> {
        let full = headers.is_full();
        for header in headers.into_vec() {
            let (below, work) = checked(self.network, self.last, &header)?;
            self.work = self.work.saturating_add(work);
            if self.work < self.work_min && self.commitments.is_at(below.height) {
                let kept = self.commitments.get(self.commitments_read_count);
                if kept != Some(self.commitments.bit(below.hash)) {
                    return Err(HeadersSyncError::CommitmentMismatch);
                }
                self.commitments_read_count += 1;
            }
            self.buffer.push_back(header);
            self.last = below;
        }
        if self.work >= self.work_min {
            Ok(RedownloadStep::Done(Vec::from(self.buffer)))
        } else if full {
            let released_count = self
                .buffer
                .len()
                .saturating_sub(self.network.redownload_buffer_size());
            let released = self.buffer.drain(..released_count).collect();
            // A batch has at most 2,000 headers, so this bounds the buffer between two batches.
            assert!(self.buffer.len() <= self.network.redownload_buffer_size());
            Ok(RedownloadStep::More(Box::new(self), released))
        } else {
            Err(HeadersSyncError::WorkTooLow)
        }
    }
}

/// Checks `header` on `below`: its `prev`, then its proof of work, then its `bits`. Returns the
/// header as the header below the next one, and its work.
fn checked(
    network: crate::chainparams::Network,
    below: Below,
    header: &crate::block::BlockHeader,
) -> Result<(Below, crate::pow::Work), HeadersSyncError> {
    if header.prev != below.hash {
        return Err(HeadersSyncError::NotContinuous);
    }
    let (hash, work) = crate::pow::proven(header, network).ok_or(HeadersSyncError::ProofOfWork)?;
    let height = below.height + 1;
    if !crate::pow::permits_bits_change(network, height, below.bits, header.bits) {
        return Err(HeadersSyncError::BitsChange);
    }
    let above = Below {
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
    /// The `bits` of the regtest limit, which each header of a test has unless it says another.
    const LIMIT_BITS: u32 = 0x207f_ffff;

    /// `usize::MAX` modulo the regtest period of 275 is 15, so the first download keeps a bit at
    /// the heights 15, 290, 565, 840, 1115, 1390, 1665, 1940, 2215 and on. A person wrote these.
    const SALT: super::Salt = super::Salt {
        keys: [1, 2],
        offset: usize::MAX,
    };

    /// `count` regtest headers with `bits`, each on the header before it, the first on `below`.
    /// `seed` is each byte of the merkle root, so two seeds give two chains.
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

    /// `count` regtest headers at the limit on genesis, with `seed`.
    fn chain_on_genesis(count: usize, seed: u8) -> Vec<crate::block::BlockHeader> {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        mined_on(&genesis, count, LIMIT_BITS, seed)
    }

    /// The work of regtest genesis and `headers` on it.
    fn work_on_genesis(headers: &[crate::block::BlockHeader]) -> crate::pow::Work {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        std::iter::once(&genesis)
            .chain(headers)
            .map(|header| crate::pow::work(header.bits, crate::chainparams::Network::Regtest))
            .map(Option::unwrap)
            .reduce(crate::pow::Work::saturating_add)
            .unwrap()
    }

    /// A first download on regtest genesis that ends at `work_min`.
    fn presync(work_min: crate::pow::Work) -> super::Presync {
        let chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        super::Presync::new(&chain, work_min, crate::fixtures::CLOCK, SALT)
    }

    /// `presync` after it took each batch of `batches` and asked for more.
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

    /// The second download after the first took `batches`, the last of which reaches the minimum.
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
    fn presync_asks_for_more_after_a_full_batch_below_the_minimum() {
        let headers = chain_on_genesis(4_001, 0);
        let work_min = work_on_genesis(&headers).saturating_add(work_on_genesis(&[]));

        // The second batch is on the last header of the first.
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

        // A full batch exactly at the minimum, and one header below it.
        assert!(matches!(
            presync(work_at(2_000)).receive(batch(&headers)),
            Ok(super::PresyncStep::Redownload(_))
        ));
        assert!(matches!(
            presync(work_at(2_000).saturating_add(work_at(0))).receive(batch(&headers)),
            Ok(super::PresyncStep::More(_))
        ));
        // A batch that is not full still reaches the minimum.
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
        // The first nonce after the mined one that gives a hash above the target.
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

    /// On mainnet, a header inside a period keeps the `bits` of the header below it. Block 1 is
    /// on genesis, so it keeps the `bits` of the tip of our chain.
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
        // Block 1 has the work of genesis, so the minimum is one header above the batch.
        let genesis_work = chain.tip().work();
        let work_min = genesis_work
            .saturating_add(genesis_work)
            .saturating_add(genesis_work);
        let presync = super::Presync::new(&chain, work_min, crate::fixtures::CLOCK, SALT);

        // The batch is not full, so a header that passes ends below the minimum.
        assert_eq!(
            presync.receive(batch(&[block_1])).unwrap_err(),
            super::HeadersSyncError::WorkTooLow
        );
    }

    /// Our chain has 100 headers, each one second above the one below it, so its median time is
    /// the genesis time plus 95. A clock 100 s above that, less the 2 h that a time may be ahead
    /// of the clock, permits 600 headers above the tip, up to height 700. A person wrote these.
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
        let presync_at = |clock| super::Presync::new(&chain, work_min, clock, SALT);

        // The batch is not full, so a chain that is not too high ends below the minimum.
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
        // A clock more than 2 h below the median time permits no header.
        assert_eq!(
            presync_at(0)
                .receive(batch(&headers[100..101]))
                .unwrap_err(),
            super::HeadersSyncError::TooLong
        );
    }

    /// The chain reaches the minimum at height 9,500, so the first download takes 5 batches. The
    /// second download holds 7,017 headers, so the fourth batch gives 983 headers to the chain.
    /// The fifth reaches the minimum, so it gives the rest, also the 500 headers above it.
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

    /// The second download, on a chain that reaches the minimum at height 4,000, after it took
    /// the first full batch of `headers`.
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
            // The second download starts again on the tip of our chain, not on the last header
            // of the first download.
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
        // The same chain passes.
        assert!(matches!(
            redownload_after_one_batch(&headers).receive(batch(&headers[2_000..])),
            Ok(super::RedownloadStep::Done(_))
        ));
    }

    /// The other chain has another merkle root from height 1, so it has another bit at some
    /// height with a bit.
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

    /// The chain reaches the minimum at height 1,115, which has a bit. Each second chain is the
    /// first one up to 1,114, then another header at 1,115 and more on it. About half of the
    /// headers at 1,115 have another bit, so 8 chains read a bit there with odds of 255 in 256.
    #[test]
    fn redownload_reads_no_bit_from_the_header_that_reaches_the_minimum() {
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

    /// The first chain has harder headers above height 1,940, its last bit. Each has 15 times the
    /// work of the limit, so the chain reaches the minimum at height 2,000. The second chain is the
    /// first up to 1,940, then headers at the limit. So at height 2,215 it is still below the
    /// minimum, and the first download kept no bit for that height.
    #[test]
    fn redownload_refuses_a_chain_after_the_last_bit() {
        let bits_hard = 0x2010_0000;
        let first = chain_on_genesis(1_940, 0);
        let first_hard = mined_on(&first[1_939], 60, bits_hard, 0);
        let second_easy = mined_on(&first[1_939], 275, LIMIT_BITS, 1);
        let first = [first.as_slice(), &first_hard].concat();
        let second = [&first[..1_940], &second_easy].concat();
        let work_min = work_on_genesis(&first);
        // The second chain at 2,215 has 2 + 2,215 * 2 of work, and the first chain has
        // 2 + 1,940 * 2 + 60 * 15 at 2,000.
        assert!(work_on_genesis(&second) < work_min);

        let after_one_batch = || {
            let step = redownload(work_min, &[&first]).receive(batch(&second[..2_000]));
            let Ok(super::RedownloadStep::More(redownload, _)) = step else {
                panic!("{step:?}");
            };
            *redownload
        };

        // Each header up to 2,214 passes, so the batch ends below the minimum.
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
}
