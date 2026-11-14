const MEDIAN_TIME_HEADERS_COUNT_MAX: usize = 11;

const _: () = assert!(!MEDIAN_TIME_HEADERS_COUNT_MAX.is_multiple_of(2));

pub(crate) const TIME_AHEAD_SECONDS_MAX: u64 = 2 * 60 * 60;

#[derive(Debug)]
pub struct Chain {
    network: crate::chainparams::Network,
    below_tip: Vec<crate::block::BlockHeader>,
    tip: crate::block::BlockHeader,
    work: crate::pow::Work,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    height: usize,
    hash: bitcoin_hashes::sha256d::Hash,
    work: crate::pow::Work,
}

pub(crate) const LOCATOR_DENSE_COUNT: usize = 12;

pub(crate) const BRANCH_TIP_HEADERS_BEHIND_MAX: usize = 144;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Extended {
    Taken,
    Kept,
    KeptOver(BranchTip),
    Branch(Branch),
    BelowMargin {
        start: SyncStart,
        branch_work_min: crate::pow::Work,
        headers: crate::protocol::Headers,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BranchTip {
    hash: bitcoin_hashes::sha256d::Hash,
    work_max: crate::pow::Work,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SyncStart {
    network: crate::chainparams::Network,
    height: usize,
    hash: bitcoin_hashes::sha256d::Hash,
    bits: u32,
    work: crate::pow::Work,
    median_time_past: u32,
    chain_work: crate::pow::Work,
}

#[derive(Debug)]
enum Batch {
    Answer(crate::protocol::Headers),
    Released {
        headers: Vec<crate::block::BlockHeader>,
        full: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Branch {
    fork_height: usize,
    above_fork: AboveFork,
    chain_work: crate::pow::Work,
}

#[derive(Debug, PartialEq, Eq)]
enum AboveFork {
    Empty {
        fork_hash: bitcoin_hashes::sha256d::Hash,
    },
    Headers {
        headers: Vec<crate::block::BlockHeader>,
        work: crate::pow::Work,
        last_hash: bitcoin_hashes::sha256d::Hash,
        time_max: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtendError {
    NotOnTip,
    NotOnLocator,
    NotContinuous,
    ProofOfWork,
    WrongBits,
    TimeTooOld,
    TimeTimewarpAttack,
    TimeTooNew,
    VersionTooLow,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Ancestors<'a> {
    below_tip: &'a [crate::block::BlockHeader],
    tip: &'a crate::block::BlockHeader,
    batch: &'a [crate::block::BlockHeader],
}

impl Chain {
    pub fn new(network: crate::chainparams::Network) -> Chain {
        let genesis = network.genesis();
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

    pub(crate) fn restart(&mut self) {
        *self = Chain::new(self.network);
    }

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
        self.extend_tip(headers, time_max(clock))
    }

    pub(crate) fn extend_on_locator(
        &mut self,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Extended, ExtendError> {
        let Some(first) = headers.first() else {
            return Ok(Extended::Kept);
        };
        if first.prev == self.tip.hash() {
            self.extend_tip(headers.into_vec(), time_max(clock))?;
            return Ok(Extended::Taken);
        }
        let tip_height = self.below_tip.len();
        let first_prev = first.prev;
        let fork_height = locator_heights(tip_height)
            .skip(1)
            .find(|height| self.header_at(*height).hash() == first_prev)
            .ok_or(ExtendError::NotOnLocator)?;
        assert!(fork_height < tip_height);
        let branch = self.branch_on_fork(fork_height);
        self.extend_above(branch, Batch::Answer(headers), clock, work_min)
    }

    pub(crate) fn extend_branch(
        &mut self,
        branch: Branch,
        headers: crate::protocol::Headers,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Extended, ExtendError> {
        self.extend_on_branch(branch, Batch::Answer(headers), clock, work_min)
    }

    pub(crate) fn extend_low_work_branch(
        &mut self,
        start: SyncStart,
        headers: Vec<crate::block::BlockHeader>,
        full: bool,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Extended, ExtendError> {
        assert!(!headers.is_empty());
        if let Some(first) = headers.first() {
            assert_eq!(first.prev, start.hash);
        }
        let branch = Branch {
            fork_height: start.height,
            above_fork: AboveFork::Empty {
                fork_hash: start.hash,
            },
            chain_work: start.chain_work,
        };
        self.extend_on_branch(branch, Batch::Released { headers, full }, clock, work_min)
    }

    fn extend_on_branch(
        &mut self,
        branch: Branch,
        batch: Batch,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Extended, ExtendError> {
        assert!(branch.fork_height < self.below_tip.len());
        let fork_hash = self.header_at(branch.fork_height).hash();
        match &branch.above_fork {
            AboveFork::Empty { fork_hash: hash } => assert_eq!(*hash, fork_hash),
            AboveFork::Headers { headers, .. } => {
                assert_eq!(headers.first().map(|first| first.prev), Some(fork_hash));
            }
        }
        assert_eq!(self.work, branch.chain_work);
        if batch.headers().is_empty() {
            return Ok(match branch.above_fork {
                AboveFork::Empty { .. } => Extended::Kept,
                AboveFork::Headers {
                    work, last_hash, ..
                } => Extended::KeptOver(self.branch_tip(
                    self.work_at(branch.fork_height),
                    work,
                    last_hash,
                )),
            });
        }
        self.extend_above(branch, batch, clock, work_min)
    }

    fn extend_above(
        &mut self,
        branch: Branch,
        batch: Batch,
        clock: u64,
        work_min: crate::pow::Work,
    ) -> Result<Extended, ExtendError> {
        let full = batch.is_full();
        let Branch {
            mut fork_height,
            above_fork,
            chain_work: _,
        } = branch;
        let tip_height = self.below_tip.len();
        assert!(!batch.headers().is_empty());
        assert!(fork_height < tip_height);
        let time_max = time_max(clock);

        let (branch_headers, work_branch_before, time_max_before, shared_count) = match above_fork {
            AboveFork::Headers {
                headers,
                work,
                last_hash: _,
                time_max: time_max_before,
            } => (headers, work, time_max_before, 0),
            AboveFork::Empty { fork_hash: _ } => {
                let ours = self.below_tip[fork_height + 1..]
                    .iter()
                    .chain(std::iter::once(&self.tip));
                let shared_count = batch
                    .headers()
                    .iter()
                    .zip(ours)
                    .take_while(|(theirs, ours)| theirs == ours)
                    .count();
                fork_height += shared_count;
                let rest = &batch.headers()[shared_count..];
                if fork_height == tip_height {
                    if !rest.is_empty() {
                        self.extend_tip(rest.to_vec(), time_max)?;
                    }
                    return Ok(Extended::Taken);
                }
                if rest.is_empty() {
                    if full {
                        let branch = self.branch_on_fork(fork_height);
                        return Ok(Extended::Branch(branch));
                    }
                    return Ok(Extended::Kept);
                }
                (Vec::new(), crate::pow::Work::ZERO, time_max, shared_count)
            }
        };

        let branch_count = branch_headers.len();
        let mut headers = branch_headers;
        headers.extend_from_slice(&batch.headers()[shared_count..]);
        let (last_hash, work_batch) = self.check(fork_height, &headers, branch_count, time_max)?;
        let work_branch = work_branch_before.saturating_add(work_batch);
        let work_stop = work_branch.saturating_add(self.branch_margin(work_min));
        let mut work_above_fork = crate::pow::Work::ZERO;
        for height in fork_height + 1..=tip_height {
            let header_work = self.stored_work(self.header_at(height));
            work_above_fork = work_above_fork.saturating_add(header_work);
            if work_above_fork > work_stop {
                assert_eq!(branch_count, 0);
                return Ok(match (full, shared_count) {
                    (false, _) => {
                        let work_at_fork_max = self.work.minus(work_above_fork);
                        Extended::KeptOver(self.branch_tip(
                            work_at_fork_max,
                            work_branch,
                            last_hash,
                        ))
                    }
                    (true, 0) => match batch {
                        Batch::Answer(answer) => Extended::BelowMargin {
                            start: self.sync_start(fork_height),
                            branch_work_min: self.branch_work_min(work_min),
                            headers: answer,
                        },
                        Batch::Released { .. } => {
                            panic!("a low-work sync of a branch ended below the margin")
                        }
                    },
                    (true, _) => Extended::Branch(self.branch_on_fork(fork_height)),
                });
            }
        }
        assert!(work_above_fork > crate::pow::Work::ZERO);
        let time_max = time_max.max(time_max_before);
        let work_at_fork = self.work.minus(work_above_fork);
        if work_branch <= work_above_fork {
            if full {
                return Ok(Extended::Branch(Branch {
                    fork_height,
                    above_fork: AboveFork::Headers {
                        headers,
                        work: work_branch,
                        last_hash,
                        time_max,
                    },
                    chain_work: self.work,
                }));
            }
            return Ok(Extended::KeptOver(self.branch_tip(
                work_at_fork,
                work_branch,
                last_hash,
            )));
        }

        let count = headers.len();
        self.tip = self.below_tip[fork_height];
        self.below_tip.truncate(fork_height);
        self.work = work_at_fork;
        self.extend_store(headers, time_max, work_at_fork.saturating_add(work_branch));
        assert_eq!(self.tip.hash(), last_hash);
        assert_eq!(self.below_tip.len(), fork_height + count);
        Ok(Extended::Taken)
    }

    fn extend_tip(
        &mut self,
        headers: Vec<crate::block::BlockHeader>,
        time_max: u64,
    ) -> Result<(), ExtendError> {
        let tip_height = self.below_tip.len();
        let count = headers.len();
        let (last_hash, work_batch) = self.check(tip_height, &headers, 0, time_max)?;
        self.extend_store(headers, time_max, self.work.saturating_add(work_batch));
        assert_eq!(self.tip.hash(), last_hash);
        assert_eq!(self.below_tip.len(), tip_height + count);
        Ok(())
    }

    fn branch_margin(&self, work_min: crate::pow::Work) -> crate::pow::Work {
        assert!(self.work >= work_min);
        let tip_work = self.stored_work(&self.tip);
        let behind_tip = (0..BRANCH_TIP_HEADERS_BEHIND_MAX)
            .fold(crate::pow::Work::ZERO, |sum, _| {
                sum.saturating_add(tip_work)
            });
        behind_tip.min(self.work.minus(work_min))
    }

    fn branch_work_min(&self, work_min: crate::pow::Work) -> crate::pow::Work {
        let branch_work_min = self.work.minus(self.branch_margin(work_min));
        assert!(branch_work_min >= work_min);
        branch_work_min
    }

    pub(crate) fn sync_start_on_tip(&self) -> SyncStart {
        self.sync_start(self.below_tip.len())
    }

    fn work_at(&self, height: usize) -> crate::pow::Work {
        let work_above = (height + 1..=self.below_tip.len())
            .map(|height| self.stored_work(self.header_at(height)))
            .fold(crate::pow::Work::ZERO, crate::pow::Work::saturating_add);
        self.work.minus(work_above)
    }

    fn sync_start(&self, height: usize) -> SyncStart {
        let header = self.header_at(height);
        let ancestors = Ancestors {
            below_tip: &self.below_tip[..height],
            tip: header,
            batch: &[],
        };
        SyncStart {
            network: self.network,
            height,
            hash: header.hash(),
            bits: header.bits,
            work: self.work_at(height),
            median_time_past: ancestors.median_time_past(),
            chain_work: self.work,
        }
    }

    fn branch_tip(
        &self,
        work_at_fork: crate::pow::Work,
        work_branch: crate::pow::Work,
        hash: bitcoin_hashes::sha256d::Hash,
    ) -> BranchTip {
        assert!(work_at_fork <= self.work);
        let work_max = work_at_fork.saturating_add(work_branch);
        assert!(work_max <= self.work);
        BranchTip { hash, work_max }
    }

    fn branch_on_fork(&self, fork_height: usize) -> Branch {
        assert!(fork_height < self.below_tip.len());
        Branch {
            fork_height,
            above_fork: AboveFork::Empty {
                fork_hash: self.header_at(fork_height).hash(),
            },
            chain_work: self.work,
        }
    }

    pub(crate) fn locator(&self) -> Vec<bitcoin_hashes::sha256d::Hash> {
        let locator: Vec<_> = locator_heights(self.below_tip.len())
            .map(|height| self.header_at(height).hash())
            .collect();
        assert!(locator.len() <= crate::protocol::LOCATOR_HASHES_COUNT_MAX);
        assert_eq!(locator.last(), Some(&self.network.genesis().hash()));
        locator
    }

    fn check(
        &self,
        base_height: usize,
        headers: &[crate::block::BlockHeader],
        from: usize,
        time_max: u64,
    ) -> Result<(bitcoin_hashes::sha256d::Hash, crate::pow::Work), ExtendError> {
        let base = self.header_at(base_height);
        let below_base = &self.below_tip[..base_height];
        assert!(from < headers.len());
        let below_batch = match from.checked_sub(1) {
            Some(index) => &headers[index],
            None => base,
        };
        let mut prev = below_batch.hash();
        let mut work = crate::pow::Work::ZERO;
        for (index, header) in headers.iter().enumerate().skip(from) {
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
        assert!(work > crate::pow::Work::ZERO);
        Ok((prev, work))
    }

    fn header_at(&self, height: usize) -> &crate::block::BlockHeader {
        match self.below_tip.get(height) {
            Some(header) => header,
            None => {
                assert_eq!(height, self.below_tip.len());
                &self.tip
            }
        }
    }

    fn stored_work(&self, header: &crate::block::BlockHeader) -> crate::pow::Work {
        match crate::pow::work(header.bits, self.network) {
            Some(work) => work,
            None => panic!("a header of the chain has bits with no target"),
        }
    }

    fn extend_store(
        &mut self,
        headers: Vec<crate::block::BlockHeader>,
        time_max: u64,
        work: crate::pow::Work,
    ) {
        assert!(!headers.is_empty());
        assert!(work > self.work);
        let mut stored_work = Some(self.work);
        self.work = work;
        let genesis_time = self.network.genesis().time;
        for header in headers {
            self.below_tip
                .push(std::mem::replace(&mut self.tip, header));
            stored_work = stored_work
                .zip(crate::pow::work(self.tip.bits, self.network))
                .map(|(sum, header_work)| sum.saturating_add(header_work));
            assert!(self.tip.time > genesis_time);
            assert!(u64::from(self.tip.time) <= time_max);
            assert!(self.tip.version >= self.network.version_min(self.below_tip.len()));
            assert!(
                self.tip.time
                    >= crate::pow::timewarp_time_min(self.network, self.ancestors_of_tip())
            );
        }
        assert_eq!(stored_work, Some(self.work));
        let ancestors = self.ancestors_of_tip();
        assert_eq!(self.tip.prev, ancestors.tip.hash());
        assert!(crate::pow::proven(&self.tip, self.network).is_some());
        assert_eq!(
            crate::pow::required_bits(self.network, ancestors, self.tip.time),
            Some(self.tip.bits)
        );
        assert!(self.tip.time > ancestors.median_time_past());
    }

    fn ancestors_of_tip(&self) -> Ancestors<'_> {
        assert!(!self.below_tip.is_empty());
        let last_index = self.below_tip.len() - 1;
        Ancestors {
            below_tip: &self.below_tip[..last_index],
            tip: &self.below_tip[last_index],
            batch: &[],
        }
    }

    pub(crate) fn network(&self) -> crate::chainparams::Network {
        self.network
    }

    pub(crate) fn tip(&self) -> Tip {
        Tip {
            height: self.below_tip.len(),
            hash: self.tip.hash(),
            work: self.work,
        }
    }
}

fn time_max(clock: u64) -> u64 {
    clock.saturating_add(TIME_AHEAD_SECONDS_MAX)
}

fn locator_heights(tip_height: usize) -> impl Iterator<Item = usize> {
    let mut next = Some(tip_height);
    let mut step: usize = 1;
    let mut count = 0;
    std::iter::from_fn(move || {
        let height = next?;
        count += 1;
        assert!(count <= crate::protocol::LOCATOR_HASHES_COUNT_MAX);
        next = (height > 0).then(|| height.saturating_sub(step));
        if let Some(next) = next {
            assert!(next < height);
        }
        if count >= LOCATOR_DENSE_COUNT - 1 {
            step = step.saturating_mul(2);
        }
        Some(height)
    })
}

impl<'a> Ancestors<'a> {
    #[cfg(any(test, fuzzing))]
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

    pub(crate) fn height_above(self) -> usize {
        self.below_tip.len() + 1 + self.batch.len()
    }

    pub(crate) fn last(self) -> &'a crate::block::BlockHeader {
        match self.batch {
            [.., last] => last,
            [] => self.tip,
        }
    }

    pub(crate) fn at(self, height: usize) -> &'a crate::block::BlockHeader {
        match height.checked_sub(self.below_tip.len()) {
            None => &self.below_tip[height],
            Some(0) => self.tip,
            Some(above_tip) => &self.batch[above_tip - 1],
        }
    }

    fn median_time_past(self) -> u32 {
        let height_above = self.height_above();
        let times_count = height_above.min(MEDIAN_TIME_HEADERS_COUNT_MAX);
        assert!(times_count >= 1);
        let height_first = height_above - times_count;
        let mut times_buffer = [0; MEDIAN_TIME_HEADERS_COUNT_MAX];
        let times = &mut times_buffer[..times_count];
        for (index, time) in times.iter_mut().enumerate() {
            *time = self.at(height_first + index).time;
        }
        times.sort_unstable();
        let middle_index = times_count / 2;
        times[middle_index]
    }
}

impl Tip {
    pub(crate) fn hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.hash
    }

    pub(crate) fn hash_display(&self) -> impl std::fmt::Display {
        let hash = self.hash;
        std::fmt::from_fn(move |f| {
            hash.as_byte_array()
                .iter()
                .rev()
                .try_for_each(|byte| write!(f, "{byte:02x}"))
        })
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    pub(crate) fn work(&self) -> crate::pow::Work {
        self.work
    }
}

impl SyncStart {
    pub(crate) fn network(&self) -> crate::chainparams::Network {
        self.network
    }

    pub(crate) fn height(&self) -> usize {
        self.height
    }

    pub(crate) fn hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.hash
    }

    pub(crate) fn bits(&self) -> u32 {
        self.bits
    }

    pub(crate) fn work(&self) -> crate::pow::Work {
        self.work
    }

    pub(crate) fn median_time_past(&self) -> u32 {
        self.median_time_past
    }
}

impl Batch {
    fn headers(&self) -> &[crate::block::BlockHeader] {
        match self {
            Batch::Answer(answer) => answer.as_slice(),
            Batch::Released { headers, full: _ } => headers,
        }
    }

    fn is_full(&self) -> bool {
        match self {
            Batch::Answer(answer) => answer.is_full(),
            Batch::Released { headers: _, full } => *full,
        }
    }
}

impl Branch {
    pub(crate) fn last_hash(&self) -> bitcoin_hashes::sha256d::Hash {
        match &self.above_fork {
            AboveFork::Empty { fork_hash } => *fork_hash,
            AboveFork::Headers { last_hash, .. } => *last_hash,
        }
    }
}

impl BranchTip {
    pub(crate) fn hash(&self) -> bitcoin_hashes::sha256d::Hash {
        self.hash
    }

    pub(crate) fn work_max(&self) -> crate::pow::Work {
        self.work_max
    }

    pub(crate) fn extend(
        self,
        network: crate::chainparams::Network,
        headers: &crate::protocol::Headers,
    ) -> Result<BranchTip, ExtendError> {
        headers.as_slice().iter().try_fold(self, |tip, header| {
            if header.prev != tip.hash {
                return Err(ExtendError::NotContinuous);
            }
            let (hash, work) =
                crate::pow::proven(header, network).ok_or(ExtendError::ProofOfWork)?;
            Ok(BranchTip {
                hash,
                work_max: tip.work_max.saturating_add(work),
            })
        })
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
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    const MEDIAN_CHECK_HEADERS_COUNT_MAX: usize = 4 * super::MEDIAN_TIME_HEADERS_COUNT_MAX;

    static BELOW_TIP: [crate::block::BlockHeader; 2016] =
        [crate::chainparams::Network::Testnet4.genesis(); 2016];

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

        assert_eq!(
            chain.extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK
            ),
            Err(super::ExtendError::NotContinuous)
        );
        assert_eq!(chain.tip(), before);
    }

    fn unproven(header: crate::block::BlockHeader) -> crate::block::BlockHeader {
        let nonce = (0..=u32::MAX)
            .find(|nonce| {
                let header = crate::block::BlockHeader {
                    nonce: *nonce,
                    ..header
                };
                header.hash().as_byte_array()[31] >= 0x80
            })
            .unwrap();
        crate::block::BlockHeader { nonce, ..header }
    }

    #[test]
    fn extend_refuses_a_batch_with_a_hash_above_its_target() {
        let mut headers = crate::fixtures::headers_on_genesis(2);
        headers[1] = unproven(headers[1]);
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

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
        headers[1] = crate::pow::mined_for_regtest(crate::block::BlockHeader {
            bits: 0x207f_fffe,
            ..headers[1]
        });
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        let before = chain.tip();

        assert_eq!(
            chain.extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK
            ),
            Err(super::ExtendError::WrongBits)
        );
        assert_eq!(chain.tip(), before);
    }

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

    #[test]
    fn extend_takes_a_time_only_above_the_median_time_of_the_headers_below() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let cases: [(&str, &[u32], u32); 7] = [
            ("only genesis", &[], 0),
            ("two times", &[100], 100),
            ("three times", &[100, 200], 100),
            ("four times that go back", &[100, 200, 150], 150),
            (
                "eleven times that go back",
                &[100, 200, 150, 160, 155, 300, 156, 400, 157, 158],
                157,
            ),
            (
                "more than eleven times",
                &[
                    10, 20, 30, 5000, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140,
                ],
                90,
            ),
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
            let refused = [median_time, median_time - 1]
                .map(|time| mined_on(top, &[time, genesis.time + 9000]));
            let taken = mined_on(top, &[median_time + 1]);
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
            assert_eq!(
                chain.tip().work.to_string(),
                "000000000000000000000000000000000000000000000000030339533015bcbf"
            );
        }
    }

    fn timewarp_first(last: crate::block::BlockHeader) -> crate::block::BlockHeader {
        crate::block::BlockHeader {
            time: last.time - 14 * 24 * 60 * 60,
            ..last
        }
    }

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
        assert_eq!(last.time - at_bound.time, 600);
        assert_eq!(last.time - one_below.time, 601);
        assert!(last.time - far_below.time > 1_000_000);
        assert!(below_last.time < one_below.time - 600);

        let first = timewarp_first(last);
        let splits = [
            (vec![(0, first), (2015, last)], vec![]),
            (vec![(0, first), (2014, below_last)], vec![last]),
        ];
        for (real, in_batch) in &splits {
            let height_tip = real.last().unwrap().0;
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

    #[test]
    fn extend_refuses_a_time_far_back_only_at_the_start_of_a_period_on_testnet4() {
        let [_, last, _, one_below, ..] =
            crate::fixtures::TESTNET4_TIMEWARP.map(crate::fixtures::header);
        let first = timewarp_first(last);
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

    #[test]
    fn extend_takes_a_time_only_up_to_two_hours_after_the_clock() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let below = mined_on(
            genesis,
            &[genesis.time + 1, genesis.time + 2, genesis.time + 3],
        );
        let clock_after_genesis = 100;
        let clock = u64::from(genesis.time + clock_after_genesis);
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

    #[test]
    fn extend_takes_a_version_only_at_or_above_the_lowest_of_its_height() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        let block_1 = mined_on(genesis, &[genesis.time + 1])[0];
        let block_2 = mined_on(block_1, &[genesis.time + 2])[0];
        let cases: [(&str, i32, Result<(), super::ExtendError>); 3] = [
            ("at the bound", 4, Ok(())),
            (
                "one below the bound",
                3,
                Err(super::ExtendError::VersionTooLow),
            ),
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

    #[test]
    fn extend_on_mainnet_raises_the_lowest_version_at_each_height() {
        let network = crate::chainparams::Network::Mainnet;
        let tip = crate::fixtures::header(crate::fixtures::MAINNET_VERSION_TIP);
        let heights = [(227_931, 1), (363_725, 2), (388_381, 3)];
        for ((height, version), [below, at]) in heights
            .into_iter()
            .zip(crate::fixtures::MAINNET_VERSION_RISE)
        {
            let below = crate::fixtures::header(below);
            let at = crate::fixtures::header(at);
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

    fn regtest_with(headers: &[crate::block::BlockHeader]) -> super::Chain {
        let mut chain = super::Chain::new(crate::chainparams::Network::Regtest);
        for batch in crate::protocol::Headers::batches(headers.to_vec()) {
            chain.extend(batch, crate::fixtures::CLOCK).unwrap();
        }
        chain
    }

    fn on_locator(
        chain: &mut super::Chain,
        headers: &[crate::block::BlockHeader],
    ) -> Result<super::Extended, super::ExtendError> {
        chain.extend_on_locator(
            crate::fixtures::headers_batch(headers),
            crate::fixtures::CLOCK,
            crate::pow::Work::ZERO,
        )
    }

    fn on_branch(
        chain: &mut super::Chain,
        branch: super::Branch,
        headers: &[crate::block::BlockHeader],
    ) -> Result<super::Extended, super::ExtendError> {
        chain.extend_branch(
            branch,
            crate::fixtures::headers_batch(headers),
            crate::fixtures::CLOCK,
            crate::pow::Work::ZERO,
        )
    }

    fn tip_of_branch(headers: &[crate::block::BlockHeader]) -> super::BranchTip {
        let tip = regtest_with(headers).tip();
        super::BranchTip {
            hash: tip.hash(),
            work_max: tip.work(),
        }
    }

    fn kept_over(headers: &[crate::block::BlockHeader]) -> super::Extended {
        super::Extended::KeptOver(tip_of_branch(headers))
    }

    fn branch_of(extended: Result<super::Extended, super::ExtendError>) -> super::Branch {
        match extended {
            Ok(super::Extended::Branch(branch)) => branch,
            other => panic!("{other:?}"),
        }
    }

    fn below_margin_on_genesis(
        chain: &super::Chain,
        extended: Result<super::Extended, super::ExtendError>,
        batch: &[crate::block::BlockHeader],
    ) -> (super::SyncStart, crate::pow::Work) {
        let Ok(super::Extended::BelowMargin {
            start,
            branch_work_min,
            headers,
        }) = extended
        else {
            panic!("{extended:?}");
        };
        assert_eq!(start, chain.sync_start(0));
        assert_eq!(headers, crate::fixtures::headers_batch(batch));
        (start, branch_work_min)
    }

    fn read_start(
        start: super::SyncStart,
    ) -> (
        usize,
        bitcoin_hashes::sha256d::Hash,
        u32,
        crate::pow::Work,
        u32,
    ) {
        (
            start.height(),
            start.hash(),
            start.bits(),
            start.work(),
            start.median_time_past(),
        )
    }

    #[test]
    fn locator_has_12_heights_one_apart_then_steps_that_double_then_genesis() {
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
            on_locator(&mut chain, &headers[1..]),
            Ok(super::Extended::Taken)
        );
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }

    #[test]
    fn extend_on_locator_keeps_the_chain_on_an_empty_batch() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut chain = regtest_with(&headers);
        assert_eq!(on_locator(&mut chain, &[]), Ok(super::Extended::Kept));
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }

    #[test]
    fn extend_on_locator_takes_a_branch_only_with_more_work() {
        let headers = crate::fixtures::headers_on_genesis(3);
        for (count, taken) in [(1, false), (2, false), (3, true)] {
            let branch = crate::fixtures::branch_on(&headers[0], count);
            let mut chain = regtest_with(&headers);
            let (expected, ours) = if taken {
                (
                    super::Extended::Taken,
                    [&headers[..1], &branch[..]].concat(),
                )
            } else {
                let theirs = [&headers[..1], &branch[..]].concat();
                (kept_over(&theirs), headers.to_vec())
            };
            assert_eq!(on_locator(&mut chain, &branch), Ok(expected), "{count}");
            assert_eq!(chain.tip(), regtest_with(&ours).tip(), "{count}");
        }
    }

    #[test]
    fn extend_on_locator_checks_a_branch_on_the_headers_below_its_first_header() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let branch = crate::fixtures::branch_on(&headers[0], 3);
        let mut chain = regtest_with(&headers);
        assert_eq!(branch[0].time, chain.sync_start_on_tip().median_time_past());
        assert_eq!(on_locator(&mut chain, &branch), Ok(super::Extended::Taken));
    }

    #[test]
    fn extend_on_locator_refuses_a_batch_on_a_header_that_is_not_in_the_locator() {
        let headers = crate::fixtures::headers_on_genesis(14);
        for (below, expected) in [
            (&headers[0], Ok(super::Extended::Taken)),
            (&headers[1], Err(super::ExtendError::NotOnLocator)),
            (&headers[2], Ok(super::Extended::Taken)),
        ] {
            let branch = crate::fixtures::branch_on(below, 20);
            let mut chain = regtest_with(&headers);
            assert_eq!(on_locator(&mut chain, &branch), expected);
        }
    }

    #[test]
    fn extend_on_locator_refuses_a_branch_that_fails_a_check_and_keeps_the_chain() {
        let headers = crate::fixtures::headers_on_genesis(3);
        let mut branch = crate::fixtures::branch_on(&headers[0], 3);
        branch.remove(1);
        let mut chain = regtest_with(&headers);
        assert_eq!(
            on_locator(&mut chain, &branch),
            Err(super::ExtendError::NotContinuous)
        );
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }

    fn genesis() -> crate::block::BlockHeader {
        crate::chainparams::Network::Regtest.genesis()
    }

    #[test]
    fn extend_on_locator_goes_on_after_a_full_batch_of_our_headers_below_the_tip() {
        let headers = crate::fixtures::headers_on_genesis(2_001);
        let mut chain = regtest_with(&headers);
        let branch = branch_of(on_locator(&mut chain, &headers[..2_000]));
        assert_eq!(branch, chain.branch_on_fork(2_000));
        assert_eq!(
            on_branch(&mut chain, branch, &headers[2_000..]),
            Ok(super::Extended::Taken)
        );
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }

    #[test]
    fn extend_on_locator_keeps_none_of_our_headers_in_a_branch() {
        let headers = crate::fixtures::headers_on_genesis(2_100);
        let branch = crate::fixtures::branch_on(&headers[0], 1_999);
        let mut chain = regtest_with(&headers);
        let pending = branch_of(on_locator(
            &mut chain,
            &[&headers[..1], &branch[..]].concat(),
        ));
        assert_eq!(pending.fork_height, 1);
        let super::AboveFork::Headers { headers: kept, .. } = &pending.above_fork else {
            panic!("{pending:?}");
        };
        assert_eq!(*kept, branch);
        assert_eq!(pending.last_hash(), branch[1_998].hash());
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
    }

    #[test]
    fn extend_branch_takes_a_branch_over_two_batches_whose_first_has_less_work_than_ours() {
        let headers = crate::fixtures::headers_on_genesis(2_100);
        let branch = crate::fixtures::branch_on(&genesis(), 2_200);
        let mut chain = regtest_with(&headers);
        let pending = branch_of(on_locator(&mut chain, &branch[..2_000]));
        assert_eq!(chain.tip(), regtest_with(&headers).tip());
        assert_eq!(
            on_branch(&mut chain, pending, &branch[2_000..]),
            Ok(super::Extended::Taken)
        );
        assert_eq!(chain.tip(), regtest_with(&branch).tip());
    }

    #[test]
    fn extend_branch_keeps_the_chain_when_the_peer_ends_the_branch_with_no_more_work() {
        let headers = crate::fixtures::headers_on_genesis(2_100);
        let branch = crate::fixtures::branch_on(&genesis(), 2_100);
        for (rest, theirs) in [(&branch[2_000..], &branch[..]), (&[], &branch[..2_000])] {
            let mut chain = regtest_with(&headers);
            let pending = branch_of(on_locator(&mut chain, &branch[..2_000]));
            assert_eq!(on_branch(&mut chain, pending, rest), Ok(kept_over(theirs)));
            assert_eq!(chain.tip(), regtest_with(&headers).tip());
        }
    }

    #[test]
    fn extend_branch_checks_a_batch_on_the_headers_of_the_branch_and_keeps_the_chain() {
        let headers = crate::fixtures::headers_on_genesis(2_100);
        let branch = crate::fixtures::branch_on(&genesis(), 2_200);
        let median = mined_on(branch[1_999], &[branch[1_994].time]);
        for (batch, error) in [
            (&branch[2_001..], super::ExtendError::NotContinuous),
            (&median[..], super::ExtendError::TimeTooOld),
        ] {
            let mut chain = regtest_with(&headers);
            let pending = branch_of(on_locator(&mut chain, &branch[..2_000]));
            assert_eq!(on_branch(&mut chain, pending, batch), Err(error));
            assert_eq!(chain.tip(), regtest_with(&headers).tip(), "{error:?}");
        }
    }

    #[test]
    fn extend_branch_takes_a_branch_whose_first_batch_passed_at_a_later_clock() {
        let headers = crate::fixtures::headers_on_genesis(2_001);
        let branch = crate::fixtures::branch_on(&genesis(), 2_000);
        let more = mined_on(branch[1_999], &[branch[1_996].time, branch[1_997].time]);
        let clock = u64::from(branch[1_997].time) - super::TIME_AHEAD_SECONDS_MAX;
        let mut chain = regtest_with(&headers);
        let pending = branch_of(on_locator(&mut chain, &branch));
        assert_eq!(
            chain.extend_branch(
                pending,
                crate::fixtures::headers_batch(&more),
                clock,
                crate::pow::Work::ZERO
            ),
            Ok(super::Extended::Taken)
        );
        assert_eq!(
            chain.tip(),
            regtest_with(&[&branch[..], &more[..]].concat()).tip()
        );
    }

    #[test]
    fn extend_on_locator_goes_on_with_a_full_branch_only_up_to_144_headers_of_the_tip_below() {
        for (branch_count, count) in [(2_000, 2_144), (2_000, 2_145), (1_999, 2_145)] {
            let branch = crate::fixtures::branch_on(&genesis(), branch_count);
            let headers = crate::fixtures::headers_on_genesis(count);
            let mut chain = regtest_with(&headers);
            let extended = on_locator(&mut chain, &branch);
            match (branch_count, count) {
                (2_000, 2_144) => assert!(
                    matches!(extended, Ok(super::Extended::Branch(_))),
                    "{extended:?}"
                ),
                (2_000, _) => {
                    let (start, work_min) = below_margin_on_genesis(&chain, extended, &branch);
                    assert_eq!(
                        read_start(start),
                        read_start(regtest_with(&[]).sync_start_on_tip())
                    );
                    assert_eq!(work_min, regtest_with(&headers[..2_001]).tip().work());
                }
                _ => assert_eq!(
                    extended,
                    Ok(super::Extended::KeptOver(super::BranchTip {
                        hash: branch[1_998].hash(),
                        work_max: regtest_with(&headers[..2_000]).tip().work(),
                    }))
                ),
            }
            assert_eq!(chain.tip(), regtest_with(&headers).tip());
        }
    }

    #[test]
    fn extend_on_locator_goes_on_with_a_full_branch_only_at_the_minimum_work() {
        let headers = crate::fixtures::headers_on_genesis(2_100);
        let branch = crate::fixtures::branch_on(&genesis(), 2_000);
        for (count, goes_on) in [(2_000, true), (2_001, false)] {
            let work_min = regtest_with(&headers[..count]).tip().work();
            let mut chain = regtest_with(&headers);
            let extended = chain.extend_on_locator(
                crate::fixtures::headers_batch(&branch),
                crate::fixtures::CLOCK,
                work_min,
            );
            assert_eq!(
                matches!(extended, Ok(super::Extended::Branch(_))),
                goes_on,
                "{count}"
            );
            if !goes_on {
                let (_, branch_work_min) = below_margin_on_genesis(&chain, extended, &branch);
                assert_eq!(branch_work_min, work_min);
            }
        }
    }

    #[test]
    fn extend_on_locator_asks_again_from_the_fork_for_a_branch_below_the_margin_after_our_headers()
    {
        let headers = crate::fixtures::headers_on_genesis(2_300);
        let branch = crate::fixtures::branch_on(&headers[999], 2_000);
        let mut chain = regtest_with(&headers);
        let batch = [&headers[..1_000], &branch[..1_000]].concat();
        let pending = branch_of(on_locator(&mut chain, &batch));
        assert_eq!(pending, chain.branch_on_fork(1_000));
        assert_eq!(
            on_branch(&mut chain, pending, &branch),
            Ok(super::Extended::Taken)
        );
        let ours = [&headers[..1_000], &branch[..]].concat();
        assert_eq!(chain.tip(), regtest_with(&ours).tip());
    }

    #[test]
    fn low_work_sync_of_a_branch_starts_as_on_the_tip_of_the_chain_up_to_the_fork() {
        let headers = crate::fixtures::headers_on_genesis(2_200);
        let branch = crate::fixtures::branch_on(&headers[49], 2_000);
        let mut chain = regtest_with(&headers);
        let batch = [&headers[..50], &branch[..1_950]].concat();
        let pending = branch_of(on_locator(&mut chain, &batch));
        let extended = on_branch(&mut chain, pending, &branch);
        let Ok(super::Extended::BelowMargin { start, .. }) = extended else {
            panic!("{extended:?}");
        };
        assert_eq!(
            read_start(start),
            read_start(regtest_with(&headers[..50]).sync_start_on_tip())
        );
    }

    #[test]
    fn branch_work_min_is_our_work_less_144_tip_headers_and_at_least_the_minimum() {
        let headers = crate::fixtures::headers_on_genesis(2_145);
        let chain = regtest_with(&headers);
        let work_at = |count: usize| regtest_with(&headers[..count]).tip().work();
        for (work_min, expected) in [
            (crate::pow::Work::ZERO, work_at(2_001)),
            (work_at(2_001), work_at(2_001)),
            (work_at(2_002), work_at(2_002)),
            (chain.tip().work(), chain.tip().work()),
        ] {
            assert_eq!(chain.branch_work_min(work_min), expected);
        }
    }

    #[test]
    fn extend_low_work_branch_takes_the_headers_of_the_sync_only_with_more_work() {
        let headers = crate::fixtures::headers_on_genesis(2_145);
        for (count, full) in [
            (2_300, false),
            (2_145, false),
            (2_100, false),
            (2_100, true),
        ] {
            let branch = crate::fixtures::branch_on(&genesis(), count);
            let mut chain = regtest_with(&headers);
            let Ok(super::Extended::BelowMargin { start, .. }) =
                on_locator(&mut chain, &branch[..2_000])
            else {
                panic!("no branch below the margin");
            };
            let extended = chain.extend_low_work_branch(
                start,
                branch.clone(),
                full,
                crate::fixtures::CLOCK,
                crate::pow::Work::ZERO,
            );
            match (count, full) {
                (2_300, _) => {
                    assert_eq!(extended, Ok(super::Extended::Taken));
                    assert_eq!(chain.tip(), regtest_with(&branch).tip());
                }
                (_, false) => {
                    assert_eq!(extended, Ok(kept_over(&branch)), "{count}");
                    assert_eq!(chain.tip(), regtest_with(&headers).tip());
                }
                (_, true) => {
                    let pending = branch_of(extended);
                    assert_eq!(pending.last_hash(), branch[2_099].hash());
                    assert_eq!(chain.tip(), regtest_with(&headers).tip());
                }
            }
        }
    }

    #[test]
    fn branch_tip_takes_the_work_of_headers_on_it_that_have_their_proof_of_work() {
        let branch = crate::fixtures::branch_on(&genesis(), 3);
        let network = crate::chainparams::Network::Regtest;
        let tip = tip_of_branch(&branch[..1]);
        let extend = |headers: &[crate::block::BlockHeader]| {
            tip.extend(network, &crate::fixtures::headers_batch(headers))
        };
        assert_eq!(extend(&[]), Ok(tip));
        assert_eq!(extend(&branch[1..]), Ok(tip_of_branch(&branch)));
        let unproven = unproven(branch[2]);
        for (headers, error) in [
            (&branch[2..], super::ExtendError::NotContinuous),
            (
                &[branch[1], branch[1]][..],
                super::ExtendError::NotContinuous,
            ),
            (&[branch[1], unproven][..], super::ExtendError::ProofOfWork),
        ] {
            assert_eq!(extend(headers), Err(error), "{headers:?}");
        }
    }
}
