//! The headers we hold, genesis first, each naming the one before it. Core
//! keeps a tree of every header it has seen and a `CChain` of the best
//! branch (`../bitcoin/src/chain.h:437` at v31.1); elo keeps the one branch
//! its one peer serves. A reorg is out of scope (ROADMAP, "After"), so a
//! header that does not extend the tip is an error, not a fork.

/// The version of every genesis header, and the roots of the two coinbase
/// transactions there are: `CreateGenesisBlock`,
/// `../bitcoin/src/kernel/chainparams.cpp:36`, `:68`. Mainnet, testnet3 and
/// regtest share the 2009 coinbase; testnet4 has one of its own (`:368`).
/// Both roots are in wire order, the reverse of what `chainparams.cpp`
/// asserts.
const GENESIS_VERSION: i32 = 1;
const MERKLE_ROOT_2009: [u8; crate::block_header::HASH_BYTES] = [
    0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61,
    0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a,
];
const MERKLE_ROOT_TESTNET4: [u8; crate::block_header::HASH_BYTES] = [
    0x4e, 0x7b, 0x2b, 0x91, 0x28, 0xfe, 0x02, 0x91, 0xdb, 0x06, 0x93, 0xaf, 0x2a, 0xe4, 0x18, 0xb7,
    0x67, 0xe6, 0x57, 0xcd, 0x40, 0x7e, 0x80, 0xcb, 0x14, 0x34, 0x22, 0x1e, 0xae, 0xa7, 0xa0, 0x7a,
];

/// The genesis header of `network`: what `chainparams.cpp` passes to
/// `CreateGenesisBlock` as time, nonce and bits (`:134` mainnet, `:260`
/// testnet3, `:370` testnet4, `:634` regtest), around the parts they share.
#[must_use]
pub fn genesis(network: crate::message::Network) -> crate::block_header::Header {
    let (time, nonce, bits, merkle_root) = match network {
        crate::message::Network::Mainnet => {
            (1_231_006_505, 2_083_236_893, 0x1d00_ffff, MERKLE_ROOT_2009)
        }
        crate::message::Network::Testnet3 => {
            (1_296_688_602, 414_098_458, 0x1d00_ffff, MERKLE_ROOT_2009)
        }
        crate::message::Network::Testnet4 => (
            1_714_777_860,
            393_743_547,
            0x1d00_ffff,
            MERKLE_ROOT_TESTNET4,
        ),
        crate::message::Network::Regtest => (1_296_688_602, 2, 0x207f_ffff, MERKLE_ROOT_2009),
    };
    crate::block_header::Header {
        version: GENESIS_VERSION,
        previous_block: crate::block_header::BlockHash::from_bytes([0; 32]),
        merkle_root: crate::block_header::MerkleRoot::from_bytes(merkle_root),
        time,
        bits,
        nonce,
    }
}

#[derive(Debug)]
pub enum Error {
    /// A header of the batch claims a target the network does not allow, or
    /// hashes above the one it claims. Core checks the work of the whole
    /// batch before it asks where the batch joins (`CheckHeadersPoW`,
    /// `net_processing.cpp:2619`, called at `:2987` before `:3028`), and so
    /// do we. `height` is the one the header would take.
    Pow {
        height: usize,
        error: crate::pow::Error,
    },
    /// The first header of a batch names a block that is not our tip. Core
    /// asks again from its best header and waits to see if they connect
    /// (`HandleUnconnectingHeaders`, `net_processing.cpp:2654`); with one
    /// branch and no reorg, we have nothing to connect them to.
    NotOnTip {
        previous_block: crate::block_header::BlockHash,
        tip: crate::block_header::BlockHash,
    },
    /// A header claims `nBits` that are not the ones the retargeting rules
    /// require at its height. Core's `bad-diffbits`,
    /// `ContextualCheckBlockHeader`, `validation.cpp:4136`.
    Bits {
        height: usize,
        claimed: u32,
        required: u32,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Pow { height, error } => write!(f, "header at height {height}: {error}"),
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
                "header at height {height} claims bits {claimed:#010x}, the rules require {required:#010x}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// One branch of headers from genesis. Never empty: genesis is there from
/// `new`, so there is always a tip and a locator. Each header names the one
/// before it: `Headers` holds that within a batch, and `extend` checks it at
/// the join. Each header past genesis has the work it claims, at or below
/// the limit of `network`, and claims the `nBits` the retargeting rules
/// require at its height; `extend` checks both.
pub struct Chain {
    network: crate::message::Network,
    headers: Vec<crate::pow::Checked>,
}

impl Chain {
    /// A chain of genesis alone.
    ///
    /// # Panics
    ///
    /// If genesis is not at height 0, names a block before it, or lacks the
    /// work it claims. `genesis` rules all three out; the third is the
    /// `chainparams.cpp` assertion on the genesis hash, in another form.
    #[must_use]
    pub fn new(network: crate::message::Network) -> Chain {
        let genesis = match crate::pow::checked(genesis(network), network) {
            Ok(header) => header,
            Err(error) => panic!("genesis has the work it claims: {error}"),
        };
        let chain = Chain {
            network,
            headers: vec![genesis],
        };
        assert_eq!(chain.height(), 0, "genesis is at height 0");
        assert_eq!(
            *chain.at(0).previous_block.as_bytes(),
            [0; crate::block_header::HASH_BYTES],
            "genesis names no block before it"
        );
        chain
    }

    /// The network whose genesis starts the chain and whose limit bounds
    /// every target in it.
    #[must_use]
    pub fn network(&self) -> crate::message::Network {
        self.network
    }

    /// The height of the tip: genesis is 0, as `getblockcount` counts.
    ///
    /// # Panics
    ///
    /// If the chain is empty, which `new` rules out.
    #[must_use]
    pub fn height(&self) -> usize {
        assert!(!self.headers.is_empty(), "a chain starts at genesis");
        self.headers.len() - 1
    }

    /// The header at `height`.
    ///
    /// # Panics
    ///
    /// If `height` is above the tip. A height is an index into our chain,
    /// never a peer's number; every caller asks at or below `height()`.
    #[must_use]
    pub fn at(&self, height: usize) -> &crate::block_header::Header {
        assert!(height <= self.height(), "height {height} is above the tip");
        self.headers[height].header()
    }

    /// The hash of the header at `height`, computed on each call. A locator
    /// asks for a few dozen at most.
    ///
    /// # Panics
    ///
    /// As [`Self::at`].
    #[must_use]
    pub fn hash_at(&self, height: usize) -> crate::block_header::BlockHash {
        self.at(height).hash()
    }

    #[must_use]
    pub fn tip(&self) -> crate::block_header::BlockHash {
        self.hash_at(self.height())
    }

    /// The locator for a `getheaders` from our tip. Core starts one below
    /// its best header (`net_processing.cpp:5807`) so that a peer at the same
    /// tip still answers with one header, and learns the peer's best block
    /// from it. We keep nothing about the peer, so we start at the tip, and a
    /// peer with nothing after it answers with an empty `headers`.
    ///
    /// # Panics
    ///
    /// If the locator does not start with our tip. `Locator::new` rules it
    /// out: the first height it asks for is the one it is given.
    #[must_use]
    pub fn locator(&self) -> crate::locator::Locator {
        let locator = crate::locator::Locator::new(self.height(), |height| self.hash_at(height));
        assert_eq!(
            locator.as_slice()[0].as_bytes(),
            self.tip().as_bytes(),
            "a locator from our tip starts with it"
        );
        locator
    }

    /// Appends a batch whose every header has the work it claims, whose
    /// first header names our tip, and whose every header claims the `nBits`
    /// the rules require. An empty batch is fine and changes nothing.
    /// `Headers::parse` bounded the batch and checked that each header names
    /// the one before it; the work, the join and the difficulty are the
    /// checks left, in that order, as Core orders them
    /// (`net_processing.cpp:2987`, `:3028`, then `validation.cpp:4136`).
    ///
    /// # Errors
    ///
    /// `Pow` if a header claims a target above the limit of the network or
    /// hashes above the target it claims. `NotOnTip` if the first header
    /// names a block other than our tip. `Bits` if a header claims `nBits`
    /// that the retargeting rules do not allow at its height. On any of the
    /// three the chain is unchanged.
    ///
    /// # Panics
    ///
    /// If the height after the append is not the height before plus the
    /// count of the batch. `Vec::extend` rules it out.
    pub fn extend(&mut self, headers: crate::headers::Headers) -> Result<(), Error> {
        // The work first, for the whole batch: `next_bits` reads a
        // `pow::Checked` and nothing else, so the difficulty check below
        // cannot run before this loop has made one of every header.
        let mut batch = Vec::with_capacity(headers.len());
        for (offset, header) in headers.into_vec().into_iter().enumerate() {
            let height = self.height() + 1 + offset;
            match crate::pow::checked(header, self.network) {
                Ok(header) => batch.push(header),
                Err(error) => return Err(Error::Pow { height, error }),
            }
        }
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
        let held = self.headers.len();
        for (offset, header) in batch.iter().enumerate() {
            // The chain as it would be with the batch up to here on it, so
            // that a header of the batch can be the one a later header
            // retargets from. Nothing has moved yet: the view is of our
            // headers and the batch side by side.
            let chain = crate::pow::View::new(&self.headers, &batch[..offset]);
            let required = crate::pow::next_bits(&chain, header.header(), self.network);
            if header.header().bits != required {
                return Err(Error::Bits {
                    height: held + offset,
                    claimed: header.header().bits,
                    required,
                });
            }
        }
        let height_before = self.height();
        let count = batch.len();
        self.headers.extend(batch);
        assert_eq!(self.height(), height_before + count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // What `chainparams.cpp` asserts each genesis hashes to: `:136`, `:262`,
    // `:378`, `:636`. Mainnet and regtest are also what `getblockhash 0`
    // printed for `block_header.rs`; here the strings pin the values
    // `genesis` builds from.
    const MAINNET_GENESIS_HASH: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const TESTNET3_GENESIS_HASH: &str =
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
    const TESTNET4_GENESIS_HASH: &str =
        "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043";
    const REGTEST_GENESIS_HASH: &str =
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

    // Core's `headers` after regtest genesis, blocks 1 to 3, captured for
    // `headers.rs` on 2026-09-15 (`FROM_GENESIS` there, with the chain as
    // `getblockhash` printed it): the batch that `extend` must accept from
    // a fresh regtest chain and refuse from a mainnet one.
    const FROM_GENESIS: &str = "030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fce25a9ef6a61909eadcc696fb71eb4d3216de17cc3731ecdd321a030e9213a1226cda96affff7f2000000000000000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000000000200e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2869ee5ba689a2d757c652f917d12a43c9b24ba79dcff22abbea56c075d3d2bd7227cda96affff7f200000000000";
    const BLOCK_3: &str = "08e1a659dc25965d0cdf6d093b9247b09e9ce97a22cc77bca0b510ba4b337d61";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn after_genesis() -> crate::headers::Headers {
        crate::headers::Headers::parse(&fixture(FROM_GENESIS)).unwrap()
    }

    /// One mined regtest header after `previous` that claims `bits`, as a
    /// batch of its own. `mined_after` always claims what regtest genesis
    /// claims; this one is for the header that claims something else.
    fn claiming(previous: &crate::block_header::BlockHash, bits: u32) -> crate::headers::Headers {
        let network = crate::message::Network::Regtest;
        let mut header = crate::block_header::Header {
            version: 1,
            previous_block: crate::block_header::BlockHash::from_bytes(*previous.as_bytes()),
            merkle_root: crate::block_header::MerkleRoot::from_bytes([0; 32]),
            time: 0,
            bits,
            nonce: 0,
        };
        crate::pow::mine(&mut header, network);
        let mut payload = Vec::new();
        crate::compact_size::write_len(&mut payload, 1);
        payload.extend_from_slice(&header.encode());
        payload.push(0);
        crate::headers::Headers::parse(&payload).unwrap()
    }

    /// `count` regtest headers after `previous`, each naming the one before
    /// and each mined, as `sync.rs` builds a batch. `spoil` is the offset of
    /// one header left at the nonce that fails, if any.
    fn mined_after(
        previous: &crate::block_header::BlockHash,
        count: usize,
        spoil: Option<usize>,
    ) -> crate::headers::Headers {
        let network = crate::message::Network::Regtest;
        let mut payload = Vec::new();
        crate::compact_size::write_len(&mut payload, count);
        let mut previous_block = crate::block_header::BlockHash::from_bytes(*previous.as_bytes());
        for offset in 0..count {
            let mut header = crate::block_header::Header {
                version: 1,
                previous_block,
                merkle_root: crate::block_header::MerkleRoot::from_bytes([0; 32]),
                time: u32::try_from(offset).unwrap(),
                bits: 0x207f_ffff,
                nonce: 0,
            };
            crate::pow::mine(&mut header, network);
            if spoil == Some(offset) {
                crate::pow::spoil(&mut header, network);
            }
            payload.extend_from_slice(&header.encode());
            payload.push(0);
            previous_block = header.hash();
        }
        crate::headers::Headers::parse(&payload).unwrap()
    }

    #[test]
    fn genesis_is_built_from_chainparams_values() {
        // Red if a time, nonce or bits is off by one, a merkle root is in
        // display order or on the wrong network, or two networks are
        // swapped: the hash covers every byte.
        for (network, hash) in [
            (crate::message::Network::Mainnet, MAINNET_GENESIS_HASH),
            (crate::message::Network::Testnet3, TESTNET3_GENESIS_HASH),
            (crate::message::Network::Testnet4, TESTNET4_GENESIS_HASH),
            (crate::message::Network::Regtest, REGTEST_GENESIS_HASH),
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
        let mut chain = super::Chain::new(crate::message::Network::Regtest);
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
    fn a_batch_off_the_tip_is_refused_and_the_chain_stands() {
        // Red if `extend` appends before it checks, or checks the last
        // header instead of the first. The batch has its work, so the join
        // is the check it fails.
        let mut chain = super::Chain::new(crate::message::Network::Regtest);
        let elsewhere = super::Chain::new(crate::message::Network::Mainnet).tip();
        let err = chain.extend(mined_after(&elsewhere, 2, None)).unwrap_err();
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
        let mut chain = super::Chain::new(crate::message::Network::Mainnet);
        let err = chain.extend(after_genesis()).unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::Pow {
                    height: 1,
                    error: crate::pow::Error::AboveLimit { .. }
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
        let mut chain = super::Chain::new(crate::message::Network::Regtest);
        let batch = mined_after(&chain.tip(), 3, Some(1));
        let spoiled = batch.as_slice()[1].hash();
        let err = chain.extend(batch).unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::Pow {
                    height: 2,
                    error: crate::pow::Error::NotMet { hash, .. }
                } if hash.to_string() == spoiled.to_string()
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0, "nothing was kept");
        chain.extend(mined_after(&chain.tip(), 3, None)).unwrap();
        assert_eq!(chain.height(), 3, "and mined headers pass");
        println!("{err}");
    }

    #[test]
    fn the_same_batch_twice_is_refused() {
        // Red if `extend` accepts a batch that starts below the tip, which is
        // the shape a peer on a fork sends.
        let mut chain = super::Chain::new(crate::message::Network::Regtest);
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
        let mut chain = super::Chain::new(crate::message::Network::Regtest);
        chain.extend(claiming(&chain.tip(), 0x207f_ffff)).unwrap();
        assert_eq!(chain.height(), 1, "the right claim is kept");
        let err = chain
            .extend(claiming(&chain.tip(), 0x207f_fffe))
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
    fn an_empty_batch_changes_nothing() {
        // Red if `extend` reads a first header that is not there.
        let mut chain = super::Chain::new(crate::message::Network::Regtest);
        let empty = crate::headers::Headers::parse(&[0]).unwrap();
        chain.extend(empty).unwrap();
        assert_eq!(chain.height(), 0);
        println!("still genesis alone");
    }

    #[test]
    fn the_locator_starts_at_the_tip() {
        // Red if `locator` starts one below the tip as Core does, or the
        // hashes are not the chain's.
        let mut chain = super::Chain::new(crate::message::Network::Regtest);
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
        let chain = super::Chain::new(crate::message::Network::Regtest);
        let _ = chain.at(1);
    }
}
