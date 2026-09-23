pub(crate) mod ancestors;
pub mod block_header;
pub mod locator;
pub mod network;
pub mod pow;
pub(crate) mod retarget;
pub mod u256;

const GENESIS_VERSION: i32 = 1;
const MERKLE_ROOT_2009: [u8; crate::chain::block_header::HASH_BYTES] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
];
const MERKLE_ROOT_TESTNET4: [u8; crate::chain::block_header::HASH_BYTES] = [
    0x4e, 0x7b, 0x2b, 0x91, 0x28, 0xfe, 0x02, 0x91, 0xdb, 0x06, 0x93, 0xaf, 0x2a, 0xe4, 0x18, 0xb7,
    0x67, 0xe6, 0x57, 0xcd, 0x40, 0x7e, 0x80, 0xcb, 0x14, 0x34, 0x22, 0x1e, 0xae, 0xa7, 0xa0, 0x7a,
];

#[must_use]
pub fn genesis(network: crate::chain::network::Network) -> crate::chain::block_header::Header {
    let (time, nonce, bits, merkle_root) = match network {
        crate::chain::network::Network::Mainnet => {
            (1_231_006_505, 2_083_236_893, 0x1d00_ffff, MERKLE_ROOT_2009)
        }
        crate::chain::network::Network::Testnet3 => {
            (1_296_688_602, 414_098_458, 0x1d00_ffff, MERKLE_ROOT_2009)
        }
        crate::chain::network::Network::Testnet4 => (
            1_714_777_860,
            393_743_547,
            0x1d00_ffff,
            MERKLE_ROOT_TESTNET4,
        ),
        crate::chain::network::Network::Regtest => {
            (1_296_688_602, 2, 0x207f_ffff, MERKLE_ROOT_2009)
        }
    };
    crate::chain::block_header::Header {
        version: GENESIS_VERSION,
        previous_block: crate::chain::block_header::BlockHash::from_bytes([0; 32]),
        merkle_root: crate::chain::block_header::MerkleRoot::from_bytes(merkle_root),
        time,
        bits,
        nonce,
    }
}

#[derive(Debug)]
pub enum Error {
    Pow {
        height: usize,
        error: crate::chain::pow::Error,
    },
    NotContinuous {
        index: usize,
    },
    NotOnTip {
        previous_block: crate::chain::block_header::BlockHash,
        tip: crate::chain::block_header::BlockHash,
    },
    Bits {
        height: usize,
        claimed: u32,
        required: u32,
    },
    TimeTooOld {
        height: usize,
        time: u32,
        median_time_past: u32,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Pow { height, error } => write!(f, "header at height {height}: {error}"),
            Error::NotContinuous { index } => write!(
                f,
                "header at index {index} does not name the header before it"
            ),
            Error::NotOnTip {
                previous_block,
                tip,
            } => write!(f, "headers follow {previous_block}, our tip is {tip}"),
            Error::Bits {
                height,
                claimed,
                required,
            } => write!(
                f,
                "header at height {height} claims bits {claimed:#010x}, \
                 the rules require {required:#010x}"
            ),
            Error::TimeTooOld {
                height,
                time,
                median_time_past,
            } => write!(
                f,
                "header at height {height} has time {time}, at or before the \
                 median time past {median_time_past} of the headers before it"
            ),
        }
    }
}

impl std::error::Error for Error {}

pub struct Chain {
    network: crate::chain::network::Network,
    headers: Vec<crate::chain::pow::Checked>,
    work: crate::chain::u256::U256,
}

impl Chain {
    #[must_use]
    pub fn new(network: crate::chain::network::Network) -> Chain {
        let genesis = match crate::chain::pow::checked(genesis(network), network) {
            Ok(header) => header,
            Err(error) => panic!("genesis has the work it claims: {error}"),
        };
        let work = genesis.target(network).work();
        let chain = Chain {
            network,
            headers: vec![genesis],
            work,
        };
        assert_eq!(chain.height(), 0, "genesis is at height 0");
        assert_eq!(
            *chain.at(0).previous_block.as_bytes(),
            [0; crate::chain::block_header::HASH_BYTES],
            "genesis names no block before it"
        );
        chain
    }

    #[must_use]
    pub fn network(&self) -> crate::chain::network::Network {
        self.network
    }

    #[must_use]
    pub fn height(&self) -> usize {
        assert!(!self.headers.is_empty(), "a chain starts at genesis");
        self.headers.len() - 1
    }

    #[must_use]
    pub fn at(&self, height: usize) -> &crate::chain::block_header::Header {
        assert!(height <= self.height(), "height {height} is above the tip");
        self.headers[height].header()
    }

    #[must_use]
    pub fn hash_at(&self, height: usize) -> crate::chain::block_header::BlockHash {
        self.at(height).hash()
    }

    #[must_use]
    pub fn work(&self) -> &crate::chain::u256::U256 {
        &self.work
    }

    #[must_use]
    pub fn tip(&self) -> crate::chain::block_header::BlockHash {
        self.hash_at(self.height())
    }

    #[must_use]
    pub fn locator(&self) -> crate::chain::locator::Locator {
        let locator =
            crate::chain::locator::Locator::new(self.height(), |height| self.hash_at(height));
        assert_eq!(
            locator.as_slice()[0].as_bytes(),
            self.tip().as_bytes(),
            "a locator from our tip starts with it"
        );
        locator
    }

    pub fn extend(
        &mut self,
        headers: Vec<crate::chain::block_header::Header>,
    ) -> Result<(), Error> {
        let held = self.headers.len();
        let batch = checked_batch(headers, held, self.network)?;
        let Some(first) = batch.first() else {
            return Ok(());
        };
        let tip = self.tip();
        if first.header().previous_block.as_bytes() != tip.as_bytes() {
            return Err(Error::NotOnTip {
                previous_block: first.header().previous_block.clone(),
                tip,
            });
        }
        let mut added = crate::chain::u256::U256::ZERO;
        for (offset, header) in batch.iter().enumerate() {
            let ancestors =
                crate::chain::ancestors::Ancestors::new(&self.headers, &batch[..offset]);
            let height = ancestors.height_last() + 1;
            let required =
                crate::chain::retarget::next_bits(&ancestors, header.header(), self.network);
            if header.header().bits != required {
                return Err(Error::Bits {
                    height,
                    claimed: header.header().bits,
                    required,
                });
            }
            let median_time_past = ancestors.median_time_past();
            if header.header().time <= median_time_past {
                return Err(Error::TimeTooOld {
                    height,
                    time: header.header().time,
                    median_time_past,
                });
            }
            let Some(sum) = added.checked_add(&header.target(self.network).work()) else {
                unreachable!("the work of a batch is the work its peer paid for")
            };
            added = sum;
        }
        let Some(work) = self.work.checked_add(&added) else {
            unreachable!("the work of a chain is the work its peers paid for")
        };
        let height_before = self.height();
        let count = batch.len();
        self.headers.extend(batch);
        self.work = work;
        assert_eq!(self.height(), height_before + count);
        Ok(())
    }
}

fn checked_batch(
    headers: Vec<crate::chain::block_header::Header>,
    height_first: usize,
    network: crate::chain::network::Network,
) -> Result<Vec<crate::chain::pow::Checked>, Error> {
    let mut batch = Vec::with_capacity(headers.len());
    for (offset, header) in headers.into_iter().enumerate() {
        match crate::chain::pow::checked(header, network) {
            Ok(header) => {
                let names_the_last =
                    batch
                        .last()
                        .is_none_or(|last: &crate::chain::pow::Checked| {
                            header.header().previous_block.as_bytes()
                                == last.header().hash().as_bytes()
                        });
                if !names_the_last {
                    return Err(Error::NotContinuous { index: offset });
                }
                batch.push(header);
            }
            Err(error) => {
                return Err(Error::Pow {
                    height: height_first + offset,
                    error,
                });
            }
        }
    }
    Ok(batch)
}

#[cfg(test)]
mod tests {
    const MAINNET_GENESIS_HASH: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const TESTNET3_GENESIS_HASH: &str =
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
    const TESTNET4_GENESIS_HASH: &str =
        "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
    const REGTEST_GENESIS_HASH: &str =
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

    const FROM_GENESIS: &str = "030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fce25a9ef6a61909eadcc696fb71eb4d3216de17cc3731ecdd321a030e9213a1226cda96affff7f2000000000000000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000000000200e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2869ee5ba689a2d757c652f917d12a43c9b24ba79dcff22abbea56c075d3d2bd7227cda96affff7f200000000000";
    const BLOCK_3: &str = "08e1a659dc25965d0cdf6d093b9247b09e9ce97a22cc77bca0b510ba4b337d61";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn headers_in(payload: &[u8]) -> Vec<crate::chain::block_header::Header> {
        let (&count, rest) = payload.split_first().unwrap();
        let count = usize::from(count);
        let stride = crate::chain::block_header::BYTES + 1;
        assert_eq!(rest.len(), count * stride, "count and payload agree");
        rest.chunks(stride)
            .map(|chunk| {
                assert_eq!(chunk[crate::chain::block_header::BYTES], 0);
                let bytes: [u8; crate::chain::block_header::BYTES] = chunk
                    [..crate::chain::block_header::BYTES]
                    .try_into()
                    .unwrap();
                crate::chain::block_header::Header::parse(&bytes)
            })
            .collect()
    }

    fn after_genesis() -> Vec<crate::chain::block_header::Header> {
        headers_in(&fixture(FROM_GENESIS))
    }

    fn one_after(
        previous: &crate::chain::block_header::BlockHash,
        time: u32,
        bits: u32,
    ) -> Vec<crate::chain::block_header::Header> {
        let network = crate::chain::network::Network::Regtest;
        let mut header = crate::chain::block_header::Header {
            version: 1,
            previous_block: crate::chain::block_header::BlockHash::from_bytes(*previous.as_bytes()),
            merkle_root: crate::chain::block_header::MerkleRoot::from_bytes([0; 32]),
            time,
            bits,
            nonce: 0,
        };
        crate::chain::pow::mine(&mut header, network);
        vec![header]
    }

    fn time_at(height: usize) -> u32 {
        let genesis = super::genesis(crate::chain::network::Network::Regtest);
        genesis.time + u32::try_from(height).expect("a test height fits")
    }

    fn mined_after(
        previous: &crate::chain::block_header::BlockHash,
        height_first: usize,
        count: usize,
        spoil: Option<usize>,
    ) -> Vec<crate::chain::block_header::Header> {
        let network = crate::chain::network::Network::Regtest;
        let mut batch = Vec::with_capacity(count);
        let mut previous_block =
            crate::chain::block_header::BlockHash::from_bytes(*previous.as_bytes());
        for offset in 0..count {
            let mut header = crate::chain::block_header::Header {
                version: 1,
                previous_block,
                merkle_root: crate::chain::block_header::MerkleRoot::from_bytes([0; 32]),
                time: time_at(height_first + offset),
                bits: 0x207f_ffff,
                nonce: 0,
            };
            crate::chain::pow::mine(&mut header, network);
            if spoil == Some(offset) {
                crate::chain::pow::spoil(&mut header, network);
            }
            previous_block = header.hash();
            batch.push(header);
        }
        batch
    }

    #[test]
    fn genesis_is_built_from_chainparams_values() {
        // Red if a time, nonce or bits is off by one, a merkle root is in
        // display order or on the wrong network, or two networks are
        // swapped: the hash covers every byte.
        for (network, hash) in [
            (
                crate::chain::network::Network::Mainnet,
                MAINNET_GENESIS_HASH,
            ),
            (
                crate::chain::network::Network::Testnet3,
                TESTNET3_GENESIS_HASH,
            ),
            (
                crate::chain::network::Network::Testnet4,
                TESTNET4_GENESIS_HASH,
            ),
            (
                crate::chain::network::Network::Regtest,
                REGTEST_GENESIS_HASH,
            ),
        ] {
            let chain = super::Chain::new(network);
            assert_eq!(chain.tip().to_string(), hash, "{network:?}");
            assert_eq!(chain.height(), 0);
            assert_eq!(chain.at(0).previous_block.as_bytes(), &[0; 32]);
            println!("{network:?} {}", chain.tip());
        }
    }

    #[test]
    fn a_batch_on_the_tip_extends_the_chain() {
        // Red if `extend` compares against the wrong header, or counts from
        // the wrong end. Height and tip come from `getblockcount` and
        // `getbestblockhash` on the node that served the fixture.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain.extend(after_genesis()).unwrap();
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.hash_at(0).to_string(), REGTEST_GENESIS_HASH);
        assert_eq!(
            chain.at(1).previous_block.to_string(),
            REGTEST_GENESIS_HASH,
            "the first header of the batch sits at height 1"
        );
        assert_eq!(chain.tip().to_string(), BLOCK_3, "getbestblockhash");
        println!("height {}, tip {}", chain.height(), chain.tip());
    }

    #[test]
    fn a_chain_of_genesis_alone_holds_the_work_of_genesis() {
        // Red if the chain starts its work at zero, or counts genesis twice.
        // Core reports both numbers as the chainwork of the genesis block.
        let regtest = super::Chain::new(crate::chain::network::Network::Regtest);
        assert_eq!(
            regtest.work().to_string(),
            "0000000000000000000000000000000000000000000000000000000000000002"
        );
        let mainnet = super::Chain::new(crate::chain::network::Network::Mainnet);
        assert_eq!(
            mainnet.work().to_string(),
            "0000000000000000000000000000000000000000000000000000000100010001"
        );
        println!("regtest {}\nmainnet {}", regtest.work(), mainnet.work());
    }

    #[test]
    fn a_batch_adds_the_work_of_every_header_it_brings() {
        // Red if the work of the batch is counted once, or if the header at
        // the join is skipped. Core's three headers after the regtest genesis
        // block, where each header is worth two: `getblockheader` at height 3
        // reports a chainwork of eight.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain.extend(after_genesis()).unwrap();
        assert_eq!(chain.height(), 3);
        assert_eq!(
            chain.work().to_string(),
            "0000000000000000000000000000000000000000000000000000000000000008"
        );
        println!("height {}, chainwork {}", chain.height(), chain.work());
    }

    #[test]
    fn a_refused_batch_leaves_the_work_where_it_was() {
        // Red if the work is summed before the batch is checked: a batch off
        // the tip and a batch with the wrong bits both leave the chain as it
        // was, work and all.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain.extend(after_genesis()).unwrap();
        let before = chain.work().to_string();

        chain.extend(after_genesis()).unwrap_err();
        assert_eq!(chain.work().to_string(), before, "a batch off the tip");

        let wrong_bits = one_after(&chain.tip(), time_at(4), 0x207f_fffe);
        chain.extend(wrong_bits).unwrap_err();
        assert_eq!(chain.work().to_string(), before, "a batch with wrong bits");
        assert_eq!(chain.height(), 3);
        println!("{}", chain.work());
    }

    #[test]
    fn a_batch_off_the_tip_is_refused_and_the_chain_stands() {
        // Red if `extend` appends before it checks, or checks the last
        // header instead of the first. The batch has its work, so the join
        // is the check it fails.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        let elsewhere = super::Chain::new(crate::chain::network::Network::Mainnet).tip();
        let err = chain
            .extend(mined_after(&elsewhere, 1, 2, None))
            .unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::NotOnTip { previous_block, tip }
                    if previous_block.to_string() == MAINNET_GENESIS_HASH
                        && tip.to_string() == REGTEST_GENESIS_HASH
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0, "nothing was kept");
        println!("{err}");
    }

    #[test]
    fn a_target_above_the_limit_is_refused_before_the_join() {
        // Red if the join is checked before the work: Core's regtest
        // headers claim `0x207fffff`, above mainnet's limit, and also fail
        // to join a mainnet chain. The work is the error we name, as Core
        // does (`net_processing.cpp:2987` before `:3028`).
        let mut chain = super::Chain::new(crate::chain::network::Network::Mainnet);
        let err = chain.extend(after_genesis()).unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::Pow {
                    height: 1,
                    error: crate::chain::pow::Error::AboveLimit { .. }
                }
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0, "nothing was kept");
        println!("{err}");
    }

    #[test]
    fn a_header_without_its_work_is_refused_and_the_chain_stands() {
        // Red if only the first header is checked, the height reported is
        // the offset in the batch, or the headers before the bad one were
        // kept. The second of three has a nonce that does not work.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        let batch = mined_after(&chain.tip(), 1, 3, Some(1));
        let spoiled = batch.as_slice()[1].hash();
        let err = chain.extend(batch).unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::Pow {
                    height: 2,
                    error: crate::chain::pow::Error::NotMet { hash, .. }
                } if hash.to_string() == spoiled.to_string()
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0, "nothing was kept");
        chain.extend(mined_after(&chain.tip(), 1, 3, None)).unwrap();
        assert_eq!(chain.height(), 3, "and mined headers pass");
        println!("{err}");
    }

    #[test]
    fn a_header_that_ties_the_median_time_past_is_refused_and_the_chain_stands() {
        // Red if the comparison is `<` and not `<=`, or reads the tip's time
        // in place of the median. `time_at` gives a header a second a block,
        // so over eleven headers the median sits five seconds under the tip
        // and a header that ties the one is nowhere near tying the other.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain
            .extend(mined_after(&chain.tip(), 1, 11, None))
            .unwrap();
        let median = time_at(6);
        let err = chain
            .extend(one_after(&chain.tip(), median, 0x207f_ffff))
            .unwrap_err();
        assert!(
            matches!(
                err,
                super::Error::TimeTooOld {
                    height: 12,
                    time,
                    median_time_past,
                } if time == median && median_time_past == median
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 11, "nothing was kept");
        println!("{err}");
    }

    #[test]
    fn a_header_older_than_its_parent_passes_where_it_beats_the_median() {
        // Red if the rule is read as "later than the header before it". A
        // block time is the miner's own clock and the chain does not sort
        // them, so a header four seconds older than our tip is a header Core
        // accepts, as long as it comes after the median.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain
            .extend(mined_after(&chain.tip(), 1, 11, None))
            .unwrap();
        let tip_time = chain.at(chain.height()).time;
        let time = time_at(7);
        assert!(time < tip_time, "the header is older than our tip");
        chain
            .extend(one_after(&chain.tip(), time, 0x207f_ffff))
            .unwrap();
        assert_eq!(chain.height(), 12);
        println!("tip at {tip_time}, header at {time}, kept");
    }

    #[test]
    fn the_same_batch_twice_is_refused() {
        // Red if `extend` accepts a batch that starts below the tip, which is
        // the shape a peer on a fork sends.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain.extend(after_genesis()).unwrap();
        let err = chain.extend(after_genesis()).unwrap_err();
        assert!(matches!(err, super::Error::NotOnTip { .. }), "{err}");
        assert_eq!(chain.height(), 3);
        println!("{err}");
    }

    #[test]
    fn a_header_that_claims_the_wrong_bits_is_refused() {
        // Red if `extend` does not check the difficulty, or asks for it at
        // the wrong height: regtest never retargets, so the header after
        // genesis must claim what genesis claims, `0x207fffff`. One step
        // harder, `0x207ffffe`, is still work a test can do and still a
        // target under the limit, so the work and the join both pass and
        // the claim is the only thing wrong with it.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain
            .extend(one_after(&chain.tip(), time_at(1), 0x207f_ffff))
            .unwrap();
        assert_eq!(chain.height(), 1, "the right claim is kept");
        let err = chain
            .extend(one_after(&chain.tip(), time_at(2), 0x207f_fffe))
            .unwrap_err();
        assert!(
            matches!(
                err,
                super::Error::Bits {
                    height: 2,
                    claimed: 0x207f_fffe,
                    required: 0x207f_ffff,
                }
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 1, "the wrong claim is not kept");
        println!("{err}");
    }

    #[test]
    fn a_header_that_does_not_name_the_one_before_is_refused() {
        // Red if the continuity check is missing, compares the wrong pair, or
        // reports the wrong index. One bit in the `previous_block` of header
        // 2 (index 1): headers 1 and 3 are untouched, and 3 still names 2, so
        // only index 1 is a gap. The bit flips before the work check would
        // fail, so the batch is spoiled after mining and the work re-done.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        let mut batch = mined_after(&chain.tip(), 1, 3, None);
        let mut bytes = *batch[1].previous_block.as_bytes();
        bytes[0] ^= 1;
        batch[1].previous_block = crate::chain::block_header::BlockHash::from_bytes(bytes);
        crate::chain::pow::mine(&mut batch[1], crate::chain::network::Network::Regtest);
        let err = chain.extend(batch).unwrap_err();
        assert!(
            matches!(err, super::Error::NotContinuous { index: 1 }),
            "{err}"
        );
        assert_eq!(chain.height(), 0);
        println!(
            "{err}; Core: Misbehaving, 'non-continuous headers sequence' (net_processing.cpp:2629)"
        );
    }

    #[test]
    fn an_empty_batch_changes_nothing() {
        // Red if `extend` reads a first header that is not there.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain.extend(Vec::new()).unwrap();
        assert_eq!(chain.height(), 0);
        println!("still genesis alone");
    }

    #[test]
    fn the_locator_starts_at_the_tip() {
        // Red if `locator` starts one below the tip as Core does, or the
        // hashes are not the chain's.
        let mut chain = super::Chain::new(crate::chain::network::Network::Regtest);
        chain.extend(after_genesis()).unwrap();
        let locator = chain.locator();
        let hashes = locator.as_slice();
        assert_eq!(hashes.len(), 4, "tip, two below, genesis");
        assert_eq!(hashes[0].to_string(), chain.tip().to_string());
        assert_eq!(hashes[3].to_string(), REGTEST_GENESIS_HASH);
        println!("{hashes:?}");
    }

    #[test]
    #[should_panic(expected = "height 1 is above the tip")]
    fn a_height_above_the_tip_is_our_bug() {
        // Red if `at` indexes without the assertion; the panic message would
        // be the Vec's.
        let chain = super::Chain::new(crate::chain::network::Network::Regtest);
        let _ = chain.at(1);
    }
}
