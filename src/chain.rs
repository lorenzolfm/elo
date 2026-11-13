//! The header chain.

/// The most headers that a median time reads: the header below a new header, and the 10 below it.
const MEDIAN_TIME_HEADERS_COUNT_MAX: usize = 11;

// This count has one middle, so only a chain below this height has two middle times.
const _: () = assert!(!MEDIAN_TIME_HEADERS_COUNT_MAX.is_multiple_of(2));

/// The most seconds that the time of a header may be after the local clock.
pub(crate) const TIME_AHEAD_SECONDS_MAX: u64 = 2 * 60 * 60;

/// One linear chain of headers, from genesis to the tip. It is never empty, each header has proof
/// of work, and each header above genesis has the `bits` that the headers below it require and a
/// time above their median time. On testnet4, each first header of a period above genesis also has
/// a time at most 10 minutes below the header below it. When the chain took a header, its time was
/// at most `TIME_AHEAD_SECONDS_MAX` after the local clock. Each header has at least the lowest
/// `version` of its height on the network.
#[derive(Debug)]
pub struct Chain {
    /// The network of the chain. Its rules bound the target of each header and, on testnet4, the
    /// time of each first header of a period.
    network: crate::chainparams::Network,
    /// The headers below the tip, from genesis. The index of a header is its height.
    below_tip: Vec<crate::block::BlockHeader>,
    tip: crate::block::BlockHeader,
    /// The sum of the work of each header, genesis too.
    work: crate::pow::Work,
}

/// The height and the hash of the last header of a chain, and the work of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    height: usize,
    hash: bitcoin_hashes::sha256d::Hash,
    work: crate::pow::Work,
}

/// The most headers at the top of a locator that are one height apart. Below them, each step down
/// is twice the step before it, and the last hash is genesis.
pub(crate) const LOCATOR_DENSE_COUNT: usize = 12;

/// What `Chain::extend_on_locator` did with a batch that passed each check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Extended {
    /// The chain took the batch. If the batch was on a header below the tip, the headers above
    /// that header are gone.
    Taken,
    /// The batch gives no more work than the chain, so the chain stays: an empty batch, or a branch
    /// with at most the work of the chain. On the same work, the chain that came first stays.
    Kept,
}

/// Why `Chain::extend` or `Chain::extend_on_locator` refused a batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtendError {
    /// The `prev` of the first header is not the hash of the tip. Only `extend` refuses with this.
    NotOnTip,
    /// The `prev` of the first header is not the hash of a header of the locator of the chain. Only
    /// `extend_on_locator` refuses with this. The tip is the first header of the locator.
    NotOnLocator,
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
    /// The time of a header is more than `TIME_AHEAD_SECONDS_MAX` after the local clock. The same
    /// header can pass at a later clock.
    TimeTooNew,
    /// The `version` of a header is below the lowest version of its height on the network.
    VersionTooLow,
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
    pub fn new(network: crate::chainparams::Network) -> Chain {
        let genesis = network.genesis();
        // A test holds that each genesis has proof of work, so peer bytes cannot reach this.
        let Some((_, work)) = crate::pow::proven(&genesis, network) else {
            panic!("the genesis of {network:?} has no proof of work");
        };
        Chain {
            network,
            below_tip: Vec::new(),
            tip: genesis,
            work,
        }
    }

    /// Drops each header above genesis. The network stays, so a chain never changes its network.
    pub(crate) fn restart(&mut self) {
        *self = Chain::new(self.network);
    }

    /// Puts all of `headers` on the tip, in order, or none of them. An empty batch changes
    /// nothing. The first header that fails gives the error. For one header, its `prev` is checked
    /// first, then its proof of work, then its `bits`, then its time against the median time, then
    /// its time against the timewarp rule, then its time against `clock`, then its `version`.
    /// `clock` is the local clock, in seconds since the Unix epoch.
    pub(crate) fn extend(
        &mut self,
        headers: crate::protocol::Headers,
        clock: u64,
    ) -> Result<(), ExtendError> {
        let headers = headers.into_vec();
        let Some(first) = headers.first() else {
            return Ok(());
        };
        if first.prev != self.tip.hash() {
            return Err(ExtendError::NotOnTip);
        }
        let time_max = time_max(clock);
        let tip_height = self.below_tip.len();
        let count = headers.len();
        let (last_hash, work_batch) = self.check(tip_height, &headers, time_max)?;
        self.extend_store(headers, time_max, self.work.saturating_add(work_batch));
        // The checks proved the last header of the batch, so this holds that the store took each
        // one, and the height holds that it took each one once.
        assert_eq!(self.tip.hash(), last_hash);
        assert_eq!(self.below_tip.len(), tip_height + count);
        Ok(())
    }

    /// Puts `headers`, an answer to a `getheaders` with the locator of the chain, on the header of
    /// the locator that the first `prev` names. On the tip, this is `extend`. On a header below the
    /// tip, the headers above it are a branch, and the batch is another one. The batch goes through
    /// the checks of `extend` on the chain up to that header. Then the chain takes it only if it
    /// has more work than the headers above that header, and drops those headers. The chain finds
    /// only a header of the locator by its hash, so a batch on another header below the tip is
    /// refused.
    ///
    /// A peer can send a batch of our own headers, which passes each check. So the sum of the work
    /// above that header stops when it reaches the work of the batch. The sum reads at most the
    /// headers between that header and the tip. It reads about one of our headers for each header
    /// of the batch only when our headers have about the work of the batch each. A run of our
    /// headers with less work each, such as the minimum-difficulty headers of testnet4, makes it
    /// read more. Each header of the batch passed the proof of work at its `bits`, so the peer pays
    /// for the work that each read stands for.
    pub(crate) fn extend_on_locator(
        &mut self,
        headers: crate::protocol::Headers,
        clock: u64,
    ) -> Result<Extended, ExtendError> {
        let Some(first) = headers.first() else {
            return Ok(Extended::Kept);
        };
        if first.prev == self.tip.hash() {
            self.extend(headers, clock)?;
            return Ok(Extended::Taken);
        }
        let tip_height = self.below_tip.len();
        let first_prev = first.prev;
        let fork_height = locator_heights(tip_height)
            .skip(1)
            .find(|height| self.header_at(*height).hash() == first_prev)
            .ok_or(ExtendError::NotOnLocator)?;
        assert!(fork_height < tip_height);

        let headers = headers.into_vec();
        let count = headers.len();
        let time_max = time_max(clock);
        let (last_hash, work_batch) = self.check(fork_height, &headers, time_max)?;
        // The bound of this loop is the count of headers above the fork, and the work of the batch
        // stops it early. See the doc of this function.
        let mut work_above_fork = crate::pow::Work::ZERO;
        for height in fork_height + 1..=tip_height {
            let header_work = self.stored_work(self.header_at(height));
            work_above_fork = work_above_fork.saturating_add(header_work);
            if work_above_fork >= work_batch {
                return Ok(Extended::Kept);
            }
        }
        // The fork is below the tip, so the loop read at least one header, and each has work.
        assert!(work_above_fork > crate::pow::Work::ZERO);
        assert!(work_batch > work_above_fork);

        // The sum of the chain holds the sum above the fork, so this does not go below zero.
        let work_at_fork = self.work.minus(work_above_fork);
        self.tip = self.below_tip[fork_height];
        self.below_tip.truncate(fork_height);
        self.work = work_at_fork;
        self.extend_store(headers, time_max, work_at_fork.saturating_add(work_batch));
        // The checks proved the last header of the batch, so this holds that the store took each
        // one. The height holds that the fork stays once, and that no header above it stays.
        assert_eq!(self.tip.hash(), last_hash);
        assert_eq!(self.below_tip.len(), fork_height + count);
        Ok(Extended::Taken)
    }

    /// The hashes of the locator of the chain, from the tip down: the tip and the 11 headers below
    /// it, then steps down that are twice the step before, then genesis. A peer answers with the
    /// headers after the first of them on its chain, so the answer starts near the fork of its
    /// chain and ours.
    pub(crate) fn locator(&self) -> Vec<bitcoin_hashes::sha256d::Hash> {
        let locator: Vec<_> = locator_heights(self.below_tip.len())
            .map(|height| self.header_at(height).hash())
            .collect();
        assert!(locator.len() <= crate::protocol::LOCATOR_HASHES_COUNT_MAX);
        assert_eq!(locator.last(), Some(&self.network.genesis().hash()));
        locator
    }

    /// Checks `headers` as a batch on the header at `base_height`, with the headers below it: the
    /// tip for `extend`, or a header of the locator for `extend_on_locator`. Returns the hash of
    /// the last header, and the sum of the work of the batch. The first `prev` must be the hash of
    /// the header at `base_height`. For one header, its `prev` is checked first, then its proof of
    /// work, then its `bits`, then its time against the median time, then its time against the
    /// timewarp rule, then its time against `time_max`, then its `version`.
    fn check(
        &self,
        base_height: usize,
        headers: &[crate::block::BlockHeader],
        time_max: u64,
    ) -> Result<(bitcoin_hashes::sha256d::Hash, crate::pow::Work), ExtendError> {
        let base = self.header_at(base_height);
        let below_base = &self.below_tip[..base_height];
        // Each caller compares the first `prev` with the hash of the header at `base_height`.
        let Some(first) = headers.first() else {
            panic!("an empty batch has nothing to check");
        };
        assert_eq!(first.prev, base.hash());
        // The hash of a header checks its proof of work and the `prev` of the next header, so one
        // pass hashes each header once.
        let mut prev = first.prev;
        let mut work = crate::pow::Work::ZERO;
        for (index, header) in headers.iter().enumerate() {
            if header.prev != prev {
                return Err(ExtendError::NotContinuous);
            }
            let (hash, header_work) =
                crate::pow::proven(header, self.network).ok_or(ExtendError::ProofOfWork)?;
            prev = hash;
            work = work.saturating_add(header_work);
            let ancestors = Ancestors {
                below_tip: below_base,
                tip: base,
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
            if u64::from(header.time) > time_max {
                return Err(ExtendError::TimeTooNew);
            }
            if header.version < self.network.version_min(ancestors.height_above()) {
                return Err(ExtendError::VersionTooLow);
            }
        }
        // The batch has a first header, and each header that passes has work.
        assert!(work > crate::pow::Work::ZERO);
        Ok((prev, work))
    }

    /// The header at `height`, which must be at most the height of the tip.
    fn header_at(&self, height: usize) -> &crate::block::BlockHeader {
        match self.below_tip.get(height) {
            Some(header) => header,
            None => {
                assert_eq!(height, self.below_tip.len());
                &self.tip
            }
        }
    }

    /// The work of `header`, a header of the chain. The chain took it with a target, so it has one.
    fn stored_work(&self, header: &crate::block::BlockHeader) -> crate::pow::Work {
        match crate::pow::work(header.bits, self.network) {
            Some(work) => work,
            None => panic!("a header of the chain has bits with no target"),
        }
    }

    /// Puts each of `headers` on the tip, in order, and `work` as the work of the chain. `check`
    /// checked each header against the batch, and each assert here reads the chain. So with a check
    /// that skips a header, this panics. `extend` calls this on the tip. `extend_on_locator` calls
    /// this on a branch after it drops the headers above the fork, so the tip is then the fork.
    fn extend_store(
        &mut self,
        headers: Vec<crate::block::BlockHeader>,
        time_max: u64,
        work: crate::pow::Work,
    ) {
        // `extend` and `extend_on_locator` return before this on an empty batch, so each assert
        // reads a new header.
        assert!(!headers.is_empty());
        // Each header has work, so the work of the chain rises. Only a sum above 256 bits can stay
        // the same, and no hash can meet the targets that give it. On a branch, the work of the
        // chain is the work at the fork before this, so this holds there too.
        assert!(work > self.work);
        // `check` adds up the work of the batch, and this adds it up again from the stored
        // headers. So a sum that reads the wrong header, or one header twice, fails at the end. It
        // needs no hash. A header with no target gives no sum, and the assert fails too.
        let mut stored_work = Some(self.work);
        self.work = work;
        let genesis_time = self.network.genesis().time;
        for header in headers {
            self.below_tip
                .push(std::mem::replace(&mut self.tip, header));
            stored_work = stored_work
                .zip(crate::pow::work(self.tip.bits, self.network))
                .map(|(sum, header_work)| sum.saturating_add(header_work));
            // A median only rises, and the first one reads genesis. So no peer bytes reach this
            // while the check on the median holds.
            assert!(self.tip.time > genesis_time);
            // The bound is the same for each header, so this holds that the check read each one.
            assert!(u64::from(self.tip.time) <= time_max);
            // The lowest version reads only the height, so this check of each header is cheap. It
            // holds that `check` read each header.
            assert!(self.tip.version >= self.network.version_min(self.below_tip.len()));
            // The first header of a period is rarely the last of a batch, so this reads each
            // header. It reads the chain, and `check` reads the batch.
            assert!(
                self.tip.time
                    >= crate::pow::timewarp_time_min(self.network, self.ancestors_of_tip())
            );
        }
        assert_eq!(stored_work, Some(self.work));
        let ancestors = self.ancestors_of_tip();
        // The checks in `check` read the batch. These read the chain: the tip is on the header
        // below it, it has proof of work, it has the `bits` that the headers below it require, and
        // its time is above their median time.
        assert_eq!(self.tip.prev, ancestors.tip.hash());
        assert!(crate::pow::proven(&self.tip, self.network).is_some());
        assert_eq!(
            crate::pow::required_bits(self.network, ancestors, self.tip.time),
            Some(self.tip.bits)
        );
        assert!(self.tip.time > ancestors.median_time_past());
    }

    /// The headers below the tip. A batch that is not empty puts the old tip below the new tip, so
    /// only a chain above genesis calls this.
    fn ancestors_of_tip(&self) -> Ancestors<'_> {
        assert!(!self.below_tip.is_empty());
        let last_index = self.below_tip.len() - 1;
        Ancestors {
            below_tip: &self.below_tip[..last_index],
            tip: &self.below_tip[last_index],
            batch: &[],
        }
    }

    /// The network of the chain.
    pub(crate) fn network(&self) -> crate::chainparams::Network {
        self.network
    }

    /// The `bits` of the tip.
    pub(crate) fn tip_bits(&self) -> u32 {
        self.tip.bits
    }

    /// The median time of the tip and the 10 headers below it, or of each header if there are
    /// fewer. A header on the tip needs a time above it.
    pub(crate) fn median_time_past(&self) -> u32 {
        let ancestors = Ancestors {
            below_tip: &self.below_tip,
            tip: &self.tip,
            batch: &[],
        };
        ancestors.median_time_past()
    }

    /// The height and the hash of the last header, and the work of the chain.
    pub(crate) fn tip(&self) -> Tip {
        Tip {
            height: self.below_tip.len(),
            hash: self.tip.hash(),
            work: self.work,
        }
    }
}

/// The bound on the time of a header at the local clock `clock`, in seconds since the Unix epoch.
/// The clock can be `u64::MAX`, so the add saturates. The compare is in `u64`, so a bound above
/// `u32::MAX` takes each time.
fn time_max(clock: u64) -> u64 {
    clock.saturating_add(TIME_AHEAD_SECONDS_MAX)
}

/// The heights of the locator of a chain with its tip at `tip_height`, from the tip down. The first
/// `LOCATOR_DENSE_COUNT` are one height apart. Then each step is twice the step before it. The
/// last height is 0, genesis. So a locator has about 12 hashes plus the count of bits of the
/// height. The answer of a peer starts at the fork when the fork is at most 11 headers below the
/// tip. Else it starts at most about as far below the fork as the fork is below the tip.
fn locator_heights(tip_height: usize) -> impl Iterator<Item = usize> {
    let mut next = Some(tip_height);
    let mut step: usize = 1;
    let mut count = 0;
    std::iter::from_fn(move || {
        let height = next?;
        count += 1;
        // Each caller puts the locator in a `getheaders`, or reads a header for each hash of it.
        assert!(count <= crate::protocol::LOCATOR_HASHES_COUNT_MAX);
        next = (height > 0).then(|| height.saturating_sub(step));
        // The step is at least 1, so each height is below the height before it, and the iterator
        // ends at genesis.
        if let Some(next) = next {
            assert!(next < height);
        }
        // From the 11th hash on, the step doubles after the step down. So the 12th hash is one
        // height below the 11th, and the 13th is two below the 12th.
        if count >= LOCATOR_DENSE_COUNT - 1 {
            step = step.saturating_mul(2);
        }
        Some(height)
    })
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

    /// The highest of these headers. There is always one, because `tip` is a header.
    pub(crate) fn last(self) -> &'a crate::block::BlockHeader {
        match self.batch {
            [.., last] => last,
            [] => self.tip,
        }
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

    /// The hash of the last header in display order, the reverse of the wire order, as 64 hex
    /// digits.
    pub(crate) fn hash_display(&self) -> impl std::fmt::Display {
        let hash = self.hash;
        std::fmt::from_fn(move |f| {
            hash.as_byte_array()
                .iter()
                .rev()
                .try_for_each(|byte| write!(f, "{byte:02x}"))
        })
    }

    /// The height of the last header.
    pub(crate) fn height(&self) -> usize {
        self.height
    }

    /// The work of the chain.
    pub(crate) fn work(&self) -> crate::pow::Work {
        self.work
    }
}

impl std::fmt::Display for ExtendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtendError::NotOnTip => write!(f, "headers do not start at our tip"),
            ExtendError::NotOnLocator => {
                write!(f, "headers do not start at a header of our locator")
            }
            ExtendError::NotContinuous => write!(f, "headers do not form a chain"),
            ExtendError::ProofOfWork => write!(f, "a header fails proof of work"),
            ExtendError::WrongBits => write!(f, "a header has the wrong bits"),
            ExtendError::TimeTooOld => write!(f, "a header has a time at or below the median"),
            ExtendError::TimeTimewarpAttack => {
                write!(f, "the first header of a period has a time too far back")
            }
            ExtendError::TimeTooNew => write!(
                f,
                "a header has a time more than {TIME_AHEAD_SECONDS_MAX} s after our clock"
            ),
            ExtendError::VersionTooLow => {
                write!(f, "a header has a version below the lowest of its height")
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
            chain.extend(
                crate::fixtures::headers_batch(&headers[..2]),
                crate::fixtures::CLOCK
            ),
            Ok(())
        );
        assert_eq!(
            chain.extend(
                crate::fixtures::headers_batch(&headers[2..]),
                crate::fixtures::CLOCK
            ),
            Ok(())
        );

        assert_eq!(chain.tip().height(), 3);
        assert_eq!(chain.tip().hash, headers[2].hash());
    }

    #[test]
    fn extend_refuses_a_batch_off_the_tip() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        // The first header is on block 1, which the chain does not have.
        assert_eq!(
            chain.extend(
                crate::fixtures::headers_batch(&headers[1..]),
                crate::fixtures::CLOCK
            ),
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
            chain.extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK
            ),
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
            chain.extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK
            ),
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
            chain.extend(
                crate::fixtures::headers_batch(&[header]),
                crate::fixtures::CLOCK
            ),
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
                chain.extend(
                    crate::fixtures::headers_batch(&headers),
                    crate::fixtures::CLOCK
                ),
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
            chain.extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK
            ),
            Err(super::ExtendError::WrongBits)
        );
        assert_eq!(chain.tip(), before);
    }

    /// A regtest header for each of `times`, each on the header before it, the first on `below`.
    /// Each has `fixtures::HEADER_VERSION`, so `below` can be genesis.
    fn mined_on(below: crate::block::BlockHeader, times: &[u32]) -> Vec<crate::block::BlockHeader> {
        let mut headers = Vec::with_capacity(times.len());
        let mut prev = below.hash();
        for time in times {
            let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
                version: crate::fixtures::HEADER_VERSION,
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
                    chain.extend(
                        crate::fixtures::headers_batch(on_chain),
                        crate::fixtures::CLOCK
                    ),
                    Ok(())
                );
                let before = chain.tip();

                for refused in &refused {
                    let time = refused[0].time;
                    assert_eq!(
                        chain.extend(
                            crate::fixtures::headers_batch(
                                &[in_batch, refused.as_slice()].concat()
                            ),
                            crate::fixtures::CLOCK
                        ),
                        Err(super::ExtendError::TimeTooOld),
                        "{name} {chain_count} {time}"
                    );
                    assert_eq!(chain.tip(), before, "{name} {chain_count} {time}");
                }

                assert_eq!(
                    chain.extend(
                        crate::fixtures::headers_batch(&[in_batch, &taken].concat()),
                        crate::fixtures::CLOCK
                    ),
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
            chain.extend(
                crate::fixtures::headers_batch(&[header]),
                crate::fixtures::CLOCK
            ),
            Err(super::ExtendError::WrongBits)
        );
    }

    /// A chain with `real` at their heights and the last of them as the tip. Each other height has
    /// the genesis header, so only what the `bits` rule reads is real. A test cannot mine a header
    /// on these networks, so the tip must be a real header for the next real header to pass. The
    /// median time here is the old genesis time, so a test on this chain holds nothing about it.
    /// The work of the chain is the work of genesis, so a test reads only the work that a batch
    /// adds.
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
            work: super::Chain::new(network).work,
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
                chain.extend(
                    crate::fixtures::headers_batch(&[next]),
                    crate::fixtures::CLOCK
                ),
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
                chain.extend(
                    crate::fixtures::headers_batch(&[next]),
                    crate::fixtures::CLOCK
                ),
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
                chain.extend(
                    crate::fixtures::headers_batch(&[next]),
                    crate::fixtures::CLOCK
                ),
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
                assert_eq!(
                    chain.extend(
                        crate::fixtures::headers_batch(batch),
                        crate::fixtures::CLOCK
                    ),
                    Ok(())
                );
            }
            assert_eq!(chain.tip().hash, back.hash());
            // The work of genesis, of three headers at the limit, and of one at the real `bits`.
            // The sum is from big integers, not from this code.
            assert_eq!(
                chain.tip().work.to_string(),
                "000000000000000000000000000000000000000000000000030339533015bcbf"
            );
        }
    }

    /// The first header of the period of `last`, in the chains of the timewarp tests. It is two
    /// weeks below `last`, so a change of the target keeps the `bits`, on each network that changes
    /// them.
    fn timewarp_first(last: crate::block::BlockHeader) -> crate::block::BlockHeader {
        crate::block::BlockHeader {
            time: last.time - 14 * 24 * 60 * 60,
            ..last
        }
    }

    /// The first header of a period may go back to the bound. Each header of a batch has real proof
    /// of work and each other rule takes it, so only this rule refuses it. Each batch reads the
    /// header below through the tip and through the batch.
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
                    chain.extend(
                        crate::fixtures::headers_batch(
                            &[in_batch.as_slice(), refused.as_slice()].concat()
                        ),
                        crate::fixtures::CLOCK
                    ),
                    Err(super::ExtendError::TimeTimewarpAttack),
                    "{height_tip} {time}"
                );
                assert_eq!(chain.tip(), before, "{height_tip} {time}");
            }

            let mut chain = chain_with(network, real);
            assert_eq!(
                chain.extend(
                    crate::fixtures::headers_batch(&[in_batch.as_slice(), &[at_bound]].concat()),
                    crate::fixtures::CLOCK
                ),
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
                chain.extend(
                    crate::fixtures::headers_batch(&[header]),
                    crate::fixtures::CLOCK
                ),
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
            chain.extend(
                crate::fixtures::headers_batch(&[one_below]),
                crate::fixtures::CLOCK
            ),
            Err(super::ExtendError::TimeTooOld)
        );
    }

    /// Each row has a clock and the time of one header. In one batch that header is the first and
    /// the header on it has a legal time, and in the other it is the last. So only that header
    /// decides. A refused batch must leave the chain as it was.
    #[test]
    fn extend_takes_a_time_only_up_to_two_hours_after_the_clock() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let below = mined_on(
            genesis,
            &[genesis.time + 1, genesis.time + 2, genesis.time + 3],
        );
        let clock_after_genesis = 100;
        let clock = u64::from(genesis.time + clock_after_genesis);
        // A person wrote the two hours.
        let at_bound = genesis.time + clock_after_genesis + 2 * 60 * 60;
        let cases: [(&str, u64, u32, Result<(), super::ExtendError>); 4] = [
            ("at the bound", clock, at_bound, Ok(())),
            (
                "one second above the bound",
                clock,
                at_bound + 1,
                Err(super::ExtendError::TimeTooNew),
            ),
            (
                "far above the bound",
                clock,
                u32::MAX,
                Err(super::ExtendError::TimeTooNew),
            ),
            // A plain add of the two hours to this clock panics.
            ("the last clock", u64::MAX, u32::MAX, Ok(())),
        ];
        for (name, clock, time, expected) in cases {
            let header = mined_on(below[2], &[time])[0];
            let on_header = mined_on(header, &[genesis.time + 4])[0];
            for (on_chain, batch) in [
                (&below[..], vec![header, on_header]),
                (&below[..2], vec![below[2], header]),
            ] {
                let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
                assert_eq!(
                    chain.extend(
                        crate::fixtures::headers_batch(on_chain),
                        crate::fixtures::CLOCK
                    ),
                    Ok(())
                );
                let before = chain.tip();
                let height_tip = on_chain.len();

                assert_eq!(
                    chain.extend(crate::fixtures::headers_batch(&batch), clock),
                    expected,
                    "{name} {height_tip}"
                );
                let tip = match expected {
                    Ok(()) => batch[batch.len() - 1].hash(),
                    Err(_) => before.hash,
                };
                assert_eq!(chain.tip().hash, tip, "{name} {height_tip}");
            }
        }
    }

    #[test]
    fn extend_checks_the_timewarp_rule_before_the_time_against_the_clock() {
        // The clock is far below the time of this header, so it fails both rules.
        let [_, last, _, one_below, ..] =
            crate::fixtures::TESTNET4_TIMEWARP.map(crate::fixtures::header);
        let mut chain = chain_with(
            crate::chainparams::Network::Testnet4,
            &[(0, timewarp_first(last)), (2015, last)],
        );

        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&[one_below]), 0),
            Err(super::ExtendError::TimeTimewarpAttack)
        );
    }

    /// Each row has the `version` of one header. In one batch that header is at height 1, the first
    /// height with a lowest version, and the header on it is legal. In the other batch it is the
    /// last, at height 3. So only that header decides. A refused batch must leave the chain as it
    /// was.
    #[test]
    fn extend_takes_a_version_only_at_or_above_the_lowest_of_its_height() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let block_1 = mined_on(genesis, &[genesis.time + 1])[0];
        let block_2 = mined_on(block_1, &[genesis.time + 2])[0];
        // A person wrote the 4.
        let cases: [(&str, i32, Result<(), super::ExtendError>); 3] = [
            ("at the bound", 4, Ok(())),
            (
                "one below the bound",
                3,
                Err(super::ExtendError::VersionTooLow),
            ),
            // The top bit is set. As a `u32`, this version is above the bound.
            (
                "the lowest",
                i32::MIN,
                Err(super::ExtendError::VersionTooLow),
            ),
        ];
        for (name, version, expected) in cases {
            let with_version = |header: crate::block::BlockHeader| {
                crate::pow::mined_for_regtest(crate::block::BlockHeader { version, ..header })
            };
            let first = with_version(block_1);
            let on_first = mined_on(first, &[genesis.time + 2])[0];
            let last = with_version(mined_on(block_2, &[genesis.time + 3])[0]);
            for (on_chain, batch) in [
                (vec![], vec![first, on_first]),
                (vec![block_1], vec![block_2, last]),
            ] {
                let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
                assert_eq!(
                    chain.extend(
                        crate::fixtures::headers_batch(&on_chain),
                        crate::fixtures::CLOCK
                    ),
                    Ok(())
                );
                let before = chain.tip();
                let height_tip = on_chain.len();

                assert_eq!(
                    chain.extend(
                        crate::fixtures::headers_batch(&batch),
                        crate::fixtures::CLOCK
                    ),
                    expected,
                    "{name} {height_tip}"
                );
                let tip = match expected {
                    Ok(()) => batch[batch.len() - 1].hash(),
                    Err(_) => before.hash,
                };
                assert_eq!(chain.tip().hash, tip, "{name} {height_tip}");
            }
        }
    }

    /// On mainnet, the lowest version rises at three heights. At each, a header one below the
    /// height and a header at the height both have the version one below the new bound. So only
    /// the height decides: the first passes, and a batch with both is refused. The second is in a
    /// batch, so the height must also count the batch.
    #[test]
    fn extend_on_mainnet_raises_the_lowest_version_at_each_height() {
        let network = crate::chainparams::Network::Mainnet;
        let tip = crate::fixtures::header(crate::fixtures::MAINNET_VERSION_TIP);
        // A person wrote each height and each version.
        let heights = [(227_931, 1), (363_725, 2), (388_381, 3)];
        for ((height, version), [below, at]) in heights
            .into_iter()
            .zip(crate::fixtures::MAINNET_VERSION_RISE)
        {
            let below = crate::fixtures::header(below);
            let at = crate::fixtures::header(at);
            // These are what the names say, so a wrong fixture cannot hold another bound.
            assert_eq!(below.prev, tip.hash());
            assert_eq!(at.prev, below.hash());
            assert_eq!(below.version, version);
            assert_eq!(at.version, version);

            let mut chain = chain_with(network, &[(height - 2, tip)]);
            let before = chain.tip();
            assert_eq!(
                chain.extend(
                    crate::fixtures::headers_batch(&[below, at]),
                    crate::fixtures::CLOCK
                ),
                Err(super::ExtendError::VersionTooLow),
                "{height}"
            );
            assert_eq!(chain.tip(), before, "{height}");
            assert_eq!(
                chain.extend(
                    crate::fixtures::headers_batch(&[below]),
                    crate::fixtures::CLOCK
                ),
                Ok(()),
                "{height}"
            );
        }
    }

    #[test]
    fn extend_checks_the_time_against_the_clock_before_the_version() {
        // The clock is far below the time of this header, so it fails both rules.
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let header = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            version: 3,
            ..mined_on(genesis, &[genesis.time + 1])[0]
        });
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);

        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&[header]), 0),
            Err(super::ExtendError::TimeTooNew)
        );
    }

    #[test]
    fn extend_takes_an_empty_batch() {
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        assert_eq!(
            chain.extend(crate::fixtures::headers_batch(&[]), crate::fixtures::CLOCK),
            Ok(())
        );
        assert_eq!(chain.tip(), before);
    }

    /// A regtest chain of `headers` on genesis.
    fn regtest_with(headers: &[crate::block::BlockHeader]) -> super::Chain {
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        for batch in crate::protocol::Headers::batches(headers.to_vec()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        chain
    }

    #[test]
    fn locator_has_12_heights_one_apart_then_steps_that_double_then_genesis() {
        // A person wrote each list.
        for (tip_height, expected) in [
            (0, &[0][..]),
            (1, &[1, 0][..]),
            (12, &[12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0][..]),
            (13, &[13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 0][..]),
            (
                30,
                &[30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 17, 13, 5, 0][..],
            ),
        ] {
            let heights: Vec<_> = super::locator_heights(tip_height).collect();
            assert_eq!(heights, expected, "{tip_height}");
        }
    }

    #[test]
    fn locator_of_the_highest_height_fits_in_a_getheaders() {
        // 12 heights one apart, then one step for each bit of the height, then genesis.
        let count = super::locator_heights(usize::MAX).count();
        assert!(
            count <= crate::protocol::LOCATOR_HASHES_COUNT_MAX,
            "{count}"
        );
        assert_eq!(super::locator_heights(usize::MAX).last(), Some(0));
    }

    #[test]
    fn locator_has_the_hash_of_each_of_its_heights() {
        let headers = crate::fixtures::headers_on_genesis(13);
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let mut expected: Vec<_> = headers[1..]
            .iter()
            .rev()
            .map(|header| header.hash())
            .collect();
        expected.push(genesis.hash());
        assert_eq!(regtest_with(&headers).locator(), expected);
    }

    #[test]
    fn extend_on_locator_takes_a_batch_on_the_tip() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = regtest_with(&headers[..1]);
        assert_eq!(
            chain.extend_on_locator(
                crate::fixtures::headers_batch(&headers[1..]),
                crate::fixtures::CLOCK
            ),
            Ok(super::Extended::Taken)
        );
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }

    #[test]
    fn extend_on_locator_keeps_the_chain_on_an_empty_batch() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = regtest_with(&headers);
        assert_eq!(
            chain.extend_on_locator(crate::fixtures::headers_batch(&[]), crate::fixtures::CLOCK),
            Ok(super::Extended::Kept)
        );
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }

    #[test]
    fn extend_on_locator_takes_a_branch_only_with_more_work() {
        // Our tip is block 3. On block 1, a branch of 1 has less work than blocks 2 and 3, a
        // branch of 2 the same, and a branch of 3 more. Regtest headers have the same work each.
        let headers = crate::fixtures::headers_on_genesis(3);
        for (count, expected) in [
            (1, super::Extended::Kept),
            (2, super::Extended::Kept),
            (3, super::Extended::Taken),
        ] {
            let branch = crate::fixtures::branch_on(&headers[0], count);
            let mut chain = regtest_with(&headers);
            assert_eq!(
                chain.extend_on_locator(
                    crate::fixtures::headers_batch(&branch),
                    crate::fixtures::CLOCK
                ),
                Ok(expected),
                "{count}"
            );
            let ours = match expected {
                super::Extended::Kept => headers.to_vec(),
                super::Extended::Taken => [&headers[..1], &branch[..]].concat(),
            };
            // The tip has the work of its chain from genesis, and the height of its branch.
            assert_eq!(chain.tip(), regtest_with(&ours).tip(), "{count}");
        }
    }

    #[test]
    fn extend_on_locator_checks_a_branch_on_the_headers_below_its_first_header() {
        // Our tip is block 3, and the median time of our chain is the time of block 2. The first
        // header of the branch on block 1 has that time too. It is above the median time of the
        // headers below it, genesis and block 1, so the chain takes the branch.
        let headers = crate::fixtures::headers_on_genesis(3);
        let branch = crate::fixtures::branch_on(&headers[0], 3);
        let mut chain = regtest_with(&headers);
        assert_eq!(branch[0].time, chain.median_time_past());
        assert_eq!(
            chain.extend_on_locator(
                crate::fixtures::headers_batch(&branch),
                crate::fixtures::CLOCK
            ),
            Ok(super::Extended::Taken)
        );
    }

    #[test]
    fn extend_on_locator_refuses_a_batch_on_a_header_that_is_not_in_the_locator() {
        // Our tip is block 14, so the locator has blocks 14 down to 3, then block 1, then genesis.
        let headers = crate::fixtures::headers_on_genesis(14);
        for (below, expected) in [
            (&headers[0], Ok(super::Extended::Taken)),
            (&headers[1], Err(super::ExtendError::NotOnLocator)),
            (&headers[2], Ok(super::Extended::Taken)),
        ] {
            let branch = crate::fixtures::branch_on(below, 20);
            let mut chain = regtest_with(&headers);
            assert_eq!(
                chain.extend_on_locator(
                    crate::fixtures::headers_batch(&branch),
                    crate::fixtures::CLOCK
                ),
                expected
            );
        }
    }

    #[test]
    fn extend_on_locator_refuses_a_branch_that_fails_a_check_and_keeps_the_chain() {
        // The second header of the branch is not on the first.
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut branch = crate::fixtures::branch_on(&headers[0], 3);
        branch.remove(1);
        let mut chain = regtest_with(&headers);
        assert_eq!(
            chain.extend_on_locator(
                crate::fixtures::headers_batch(&branch),
                crate::fixtures::CLOCK
            ),
            Err(super::ExtendError::NotContinuous)
        );
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }
}
