const MANTISSA_MASK: u32 = 0x007f_ffff;
const SIGN_BIT: u32 = 0x0080_0000;

const MANTISSA_BYTES: usize = 3;

pub(super) const SPACING: u32 = 10 * 60;

pub(super) const TIMESPAN_TWO_WEEKS: u32 = 14 * 24 * 60 * 60;
const TIMESPAN_ONE_DAY: u32 = 24 * 60 * 60;

const INTERVAL_TWO_WEEKS: usize = 2016;
const INTERVAL_ONE_DAY: usize = 144;

const _: () = assert!(TIMESPAN_TWO_WEEKS / SPACING == 2016);
const _: () = assert!(TIMESPAN_ONE_DAY / SPACING == 144);
const _: () = assert!(INTERVAL_TWO_WEEKS == 2016);
const _: () = assert!(INTERVAL_ONE_DAY == 144);

const LIMIT_224: Target = Target(crate::chain::u256::U256::from_limbs([
    0x0000_0000_ffff_ffff,
    u64::MAX,
    u64::MAX,
    u64::MAX,
]));
const LIMIT_255: Target = Target(crate::chain::u256::U256::from_limbs([
    0x7fff_ffff_ffff_ffff,
    u64::MAX,
    u64::MAX,
    u64::MAX,
]));

pub(super) enum Edge {
    First,
    Last,
}

pub(super) enum Retarget {
    Never,
    Every { timespan_target: u32, edge: Edge },
}

pub(super) struct Params {
    pub(super) interval: usize,
    pub(super) limit: Target,
    pub(super) min_difficulty: bool,
    pub(super) retarget: Retarget,
}

impl Params {
    pub(super) const fn of(network: crate::chain::network::Network) -> Params {
        match network {
            crate::chain::network::Network::Mainnet => Params {
                interval: INTERVAL_TWO_WEEKS,
                limit: LIMIT_224,
                min_difficulty: false,
                retarget: Retarget::Every {
                    timespan_target: TIMESPAN_TWO_WEEKS,
                    edge: Edge::Last,
                },
            },
            crate::chain::network::Network::Testnet3 => Params {
                interval: INTERVAL_TWO_WEEKS,
                limit: LIMIT_224,
                min_difficulty: true,
                retarget: Retarget::Every {
                    timespan_target: TIMESPAN_TWO_WEEKS,
                    edge: Edge::Last,
                },
            },
            crate::chain::network::Network::Testnet4 => Params {
                interval: INTERVAL_TWO_WEEKS,
                limit: LIMIT_224,
                min_difficulty: true,
                retarget: Retarget::Every {
                    timespan_target: TIMESPAN_TWO_WEEKS,
                    edge: Edge::First,
                },
            },
            crate::chain::network::Network::Regtest => Params {
                interval: INTERVAL_ONE_DAY,
                limit: LIMIT_255,
                min_difficulty: true,
                retarget: Retarget::Never,
            },
        }
    }
}

const fn leaves_room_for_a_timespan(target: &Target) -> bool {
    target.0.leading_zeros() >= 32
}

const fn the_product_fits(network: crate::chain::network::Network) -> bool {
    let params = Params::of(network);
    match params.retarget {
        Retarget::Never => true,
        Retarget::Every { .. } => leaves_room_for_a_timespan(&params.limit),
    }
}

const _: () = assert!(the_product_fits(crate::chain::network::Network::Mainnet));
const _: () = assert!(the_product_fits(crate::chain::network::Network::Testnet3));
const _: () = assert!(the_product_fits(crate::chain::network::Network::Testnet4));
const _: () = assert!(the_product_fits(crate::chain::network::Network::Regtest));

pub struct Target(pub(super) crate::chain::u256::U256);

#[derive(Debug)]
pub enum Error {
    Zero {
        bits: u32,
    },
    Negative {
        bits: u32,
    },
    Overflow {
        bits: u32,
    },
    AboveLimit {
        target: crate::chain::u256::U256,
        limit: Target,
    },
    NotMet {
        hash: crate::chain::block_header::BlockHash,
        target: Target,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Zero { bits } => write!(f, "bits {bits:#010x} encode a target of zero"),
            Error::Negative { bits } => write!(f, "bits {bits:#010x} encode a negative target"),
            Error::Overflow { bits } => write!(f, "bits {bits:#010x} overflow 256 bits"),
            Error::AboveLimit { target, limit } => {
                write!(f, "target {target} is above the limit {limit}")
            }
            Error::NotMet { hash, target } => write!(f, "hash {hash} is above target {target}"),
        }
    }
}

impl std::error::Error for Error {}

fn from_compact(bits: u32) -> Result<crate::chain::u256::U256, Error> {
    let [size, ..] = bits.to_be_bytes();
    let size = usize::from(size);
    let mut mantissa = bits & MANTISSA_MASK;
    if size <= MANTISSA_BYTES {
        mantissa >>= 8 * (MANTISSA_BYTES - size);
    }
    if mantissa == 0 {
        return Err(Error::Zero { bits });
    }
    if bits & SIGN_BIT != 0 {
        return Err(Error::Negative { bits });
    }
    let overflow = size > 34 || (mantissa > 0xff && size > 33) || (mantissa > 0xffff && size > 32);
    if overflow {
        return Err(Error::Overflow { bits });
    }
    let number = if size <= MANTISSA_BYTES {
        crate::chain::u256::U256::from_u64(u64::from(mantissa))
    } else {
        crate::chain::u256::U256::from_u64(u64::from(mantissa)).shl(8 * (size - MANTISSA_BYTES))
    };
    assert!(
        number != crate::chain::u256::U256::ZERO,
        "the shift kept the mantissa"
    );
    Ok(number)
}

pub(super) fn to_compact(number: &crate::chain::u256::U256) -> u32 {
    let bytes = number.to_be_bytes();
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut size = crate::chain::block_header::HASH_BYTES - zeros;
    let mut mantissa: u32 = 0;
    for offset in 0..MANTISSA_BYTES {
        let byte = bytes.get(zeros + offset).copied().unwrap_or(0);
        mantissa = (mantissa << 8) | u32::from(byte);
    }
    if mantissa & SIGN_BIT != 0 {
        mantissa >>= 8;
        size += 1;
    }
    assert!(
        mantissa & !MANTISSA_MASK == 0,
        "the sign step freed the top"
    );
    assert!(
        size <= crate::chain::block_header::HASH_BYTES + 1,
        "a size of {size}"
    );
    let Ok(size) = u32::try_from(size) else {
        unreachable!("a size of {size} is one byte")
    };
    mantissa | (size << 24)
}

impl Target {
    pub fn from_compact(
        bits: u32,
        network: crate::chain::network::Network,
    ) -> Result<Target, Error> {
        let target = from_compact(bits)?;
        let limit = Target::limit(network);
        if target > limit.0 {
            return Err(Error::AboveLimit { target, limit });
        }
        Ok(Target(target))
    }

    #[must_use]
    pub fn limit(network: crate::chain::network::Network) -> Target {
        Params::of(network).limit
    }

    #[must_use]
    pub fn work(&self) -> crate::chain::u256::U256 {
        let Some(divisor) = self.0.checked_add(&crate::chain::u256::U256::ONE) else {
            unreachable!("a target is at or below the limit, below the width")
        };
        let Some(work) = self
            .0
            .not()
            .div(&divisor)
            .checked_add(&crate::chain::u256::U256::ONE)
        else {
            unreachable!("a target of one or more has work below the width")
        };
        work
    }
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

pub fn check(
    hash: &crate::chain::block_header::BlockHash,
    bits: u32,
    network: crate::chain::network::Network,
) -> Result<Target, Error> {
    let target = Target::from_compact(bits, network)?;
    assert!(
        target.0 <= Target::limit(network).0,
        "a Target is at or below the limit"
    );
    if crate::chain::u256::U256::from_hash(hash) > target.0 {
        return Err(Error::NotMet {
            hash: hash.clone(),
            target,
        });
    }
    Ok(target)
}

pub struct Checked(crate::chain::block_header::Header);

impl Checked {
    #[must_use]
    pub fn header(&self) -> &crate::chain::block_header::Header {
        &self.0
    }

    pub(super) fn target(&self, network: crate::chain::network::Network) -> Target {
        match Target::from_compact(self.0.bits, network) {
            Ok(target) => target,
            Err(error) => panic!("a header we kept claims bits that do not decode: {error}"),
        }
    }
}

pub fn checked(
    header: crate::chain::block_header::Header,
    network: crate::chain::network::Network,
) -> Result<Checked, Error> {
    check(&header.hash(), header.bits, network)?;
    Ok(Checked(header))
}

#[cfg(test)]
const TRIES_MAX: u32 = 1 << 16;

#[cfg(test)]
pub(crate) fn mine(
    header: &mut crate::chain::block_header::Header,
    network: crate::chain::network::Network,
) {
    for nonce in 0..TRIES_MAX {
        header.nonce = nonce;
        if check(&header.hash(), header.bits, network).is_ok() {
            return;
        }
    }
    panic!(
        "no nonce below {TRIES_MAX} meets bits {:#010x}",
        header.bits
    );
}

#[cfg(test)]
pub(crate) fn spoil(
    header: &mut crate::chain::block_header::Header,
    network: crate::chain::network::Network,
) {
    let mined = header.nonce;
    for nonce in mined + 1..TRIES_MAX {
        header.nonce = nonce;
        if check(&header.hash(), header.bits, network).is_err() {
            return;
        }
    }
    panic!(
        "no nonce below {TRIES_MAX} fails bits {:#010x}",
        header.bits
    );
}

#[cfg(test)]
pub(crate) fn unchecked(header: crate::chain::block_header::Header) -> Checked {
    Checked(header)
}

#[cfg(test)]
mod tests {
    const CORE_VECTORS: [(u32, Result<&str, &str>); 20] = [
        (0x0000_0000, Err("zero")),
        (0x0012_3456, Err("zero")),
        (0x0100_3456, Err("zero")),
        (0x0200_0056, Err("zero")),
        (0x0300_0000, Err("zero")),
        (0x0400_0000, Err("zero")),
        (0x0092_3456, Err("zero")),
        (0x0180_3456, Err("zero")),
        (0x0280_0056, Err("zero")),
        (0x0380_0000, Err("zero")),
        (0x0480_0000, Err("zero")),
        (
            0x0112_3456,
            Ok("0000000000000000000000000000000000000000000000000000000000000012"),
        ),
        (0x01fe_dcba, Err("negative")),
        (
            0x0212_3456,
            Ok("0000000000000000000000000000000000000000000000000000000000001234"),
        ),
        (
            0x0312_3456,
            Ok("0000000000000000000000000000000000000000000000000000000000123456"),
        ),
        (
            0x0412_3456,
            Ok("0000000000000000000000000000000000000000000000000000000012345600"),
        ),
        (0x0492_3456, Err("negative")),
        (
            0x0500_9234,
            Ok("0000000000000000000000000000000000000000000000000000000092340000"),
        ),
        (
            0x2012_3456,
            Ok("1234560000000000000000000000000000000000000000000000000000000000"),
        ),
        (0xff12_3456, Err("overflow")),
    ];

    const MAINNET_LIMIT: &str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const REGTEST_LIMIT: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    const MAINNET_GENESIS_TARGET: &str =
        "00000000ffff0000000000000000000000000000000000000000000000000000";
    const REGTEST_GENESIS_TARGET: &str =
        "7fffff0000000000000000000000000000000000000000000000000000000000";

    const MAINNET_GENESIS_HASH: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    const ALL_NETWORKS: [crate::chain::network::Network; 4] = [
        crate::chain::network::Network::Mainnet,
        crate::chain::network::Network::Testnet3,
        crate::chain::network::Network::Testnet4,
        crate::chain::network::Network::Regtest,
    ];

    fn flag(error: &super::Error) -> &'static str {
        match error {
            super::Error::Zero { .. } => "zero",
            super::Error::Negative { .. } => "negative",
            super::Error::Overflow { .. } => "overflow",
            super::Error::AboveLimit { .. } => "above limit",
            super::Error::NotMet { .. } => "not met",
        }
    }

    const CORE_COMPACT: [(u32, u32); 6] = [
        (0x0112_3456, 0x0112_0000),
        (0x0212_3456, 0x0212_3400),
        (0x0312_3456, 0x0312_3456),
        (0x0412_3456, 0x0412_3456),
        (0x0500_9234, 0x0500_9234),
        (0x2012_3456, 0x2012_3456),
    ];

    #[test]
    fn to_compact_agrees_with_core_on_its_vectors() {
        // Red if the mantissa is taken from the wrong three bytes, the size
        // counts bits instead of bytes, or the sign step is missing: a
        // mantissa that reaches `0x00800000` must give a byte back to the
        // size, or the value it writes reads back as negative.
        for (bits, expected) in CORE_COMPACT {
            let number = super::from_compact(bits).unwrap();
            assert_eq!(
                super::to_compact(&number),
                expected,
                "{bits:#010x} -> {number}"
            );
            println!(
                "{bits:#010x} -> {number} -> {:#010x}",
                super::to_compact(&number)
            );
        }
        assert_eq!(
            super::to_compact(&crate::chain::u256::U256::from_u64(0x80)),
            0x0200_8000
        );
    }

    #[test]
    fn the_limit_of_each_network_encodes_to_the_bits_its_genesis_claims() {
        // Red if `to_compact` gives a byte back when the sign bit is clear,
        // or keeps a mantissa that reaches it: mainnet's limit is `ffffff`
        // at 28 bytes and must come back as `0x1d00ffff`, regtest's is
        // `7fffff` at 32 bytes and must come back as `0x207fffff`. Those are
        // the bits `chainparams.cpp` gives each genesis.
        for network in ALL_NETWORKS {
            let limit = super::Target::limit(network);
            let genesis = crate::chain::genesis(network);
            assert_eq!(super::to_compact(&limit.0), genesis.bits, "{limit}");
            println!("{network:?}: {limit} -> {:#010x}", genesis.bits);
        }
    }

    #[test]
    fn from_compact_agrees_with_core_on_its_vectors() {
        // Red if the mantissa is shifted by the wrong count or in the wrong
        // direction, a flag is read before the bottom bytes are dropped, or
        // the limbs print in the wrong order.
        for (bits, expected) in CORE_VECTORS {
            let got = super::from_compact(bits);
            match (expected, &got) {
                (Ok(hex), Ok(target)) => assert_eq!(target.to_string(), hex, "{bits:#010x}"),
                (Err(name), Err(error)) => assert_eq!(flag(error), name, "{bits:#010x}: {error}"),
                _ => panic!("{bits:#010x}: expected {expected:?}, got {got:?}"),
            }
            println!("{bits:#010x} -> {got:?}");
        }
    }

    #[test]
    fn overflow_is_by_the_width_of_the_mantissa() {
        // Red if the three overflow clauses use the wrong size or the wrong
        // width, one way or the other: each pair straddles one clause.
        // `arith_uint256.cpp:188`.
        for (bits, expected) in [
            (0x2200_00ff, Ok("ff")),
            (0x2300_00ff, Err("overflow")),
            (0x2100_ffff, Ok("ffff")),
            (0x2200_ffff, Err("overflow")),
            (0x207f_ffff, Ok("7fffff")),
            (0x217f_ffff, Err("overflow")),
        ] {
            let got = super::from_compact(bits);
            match (expected, &got) {
                (Ok(top), Ok(target)) => {
                    let hex = target.to_string();
                    assert!(hex.starts_with(top), "{bits:#010x}: {hex}");
                    assert!(hex[top.len()..].bytes().all(|b| b == b'0'), "{hex}");
                }
                (Err(name), Err(error)) => assert_eq!(flag(error), name, "{bits:#010x}"),
                _ => panic!("{bits:#010x}: expected {expected:?}, got {got:?}"),
            }
        }
        println!("the mantissa fits under bit 256 or it does not");
    }

    #[test]
    fn a_size_past_the_width_with_no_mantissa_is_zero_not_a_panic() {
        // Red if the shift runs before the mantissa is checked: a size of
        // 255 asks for a shift of 2016, past what `shl` allows, and Core's
        // overflow flag stays down because the mantissa is zero.
        let err = super::from_compact(0xff00_0000).unwrap_err();
        assert!(
            matches!(err, super::Error::Zero { bits: 0xff00_0000 }),
            "{err}"
        );
        println!("{err}");
    }

    #[test]
    fn a_target_is_the_number_held_at_or_below_the_limit() {
        // Red if `Target::from_compact` asks the limit before the decode,
        // or takes a number above it: `0xff123456` overflows on every
        // network and is named for that, not for the limit; regtest's
        // genesis target is above mainnet's limit and below regtest's.
        let err = super::Target::from_compact(0xff12_3456, crate::chain::network::Network::Regtest)
            .unwrap_err();
        assert!(matches!(err, super::Error::Overflow { .. }), "{err}");
        let err = super::Target::from_compact(0x207f_ffff, crate::chain::network::Network::Mainnet)
            .unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::AboveLimit { target, limit }
                    if target.to_string() == REGTEST_GENESIS_TARGET
                        && limit.to_string() == MAINNET_LIMIT
            ),
            "{err}"
        );
        let target =
            super::Target::from_compact(0x207f_ffff, crate::chain::network::Network::Regtest)
                .unwrap();
        assert_eq!(target.to_string(), REGTEST_GENESIS_TARGET);
        println!("{err}");
    }

    #[test]
    fn genesis_targets_and_limits_print_as_chainparams_writes_them() {
        // Red if a limit has the wrong top limb, or a genesis `bits` does not
        // decode to the number everyone quotes.
        assert_eq!(
            super::Target::limit(crate::chain::network::Network::Mainnet).to_string(),
            MAINNET_LIMIT
        );
        assert_eq!(
            super::Target::limit(crate::chain::network::Network::Testnet3).to_string(),
            MAINNET_LIMIT,
            "chainparams.cpp:227"
        );
        assert_eq!(
            super::Target::limit(crate::chain::network::Network::Testnet4).to_string(),
            MAINNET_LIMIT,
            "chainparams.cpp:334"
        );
        assert_eq!(
            super::Target::limit(crate::chain::network::Network::Regtest).to_string(),
            REGTEST_LIMIT
        );
        assert_eq!(
            super::Target::from_compact(0x1d00_ffff, crate::chain::network::Network::Mainnet)
                .unwrap()
                .to_string(),
            MAINNET_GENESIS_TARGET
        );
        assert_eq!(
            super::Target::from_compact(0x207f_ffff, crate::chain::network::Network::Regtest)
                .unwrap()
                .to_string(),
            REGTEST_GENESIS_TARGET
        );
        println!("{MAINNET_GENESIS_TARGET} < {MAINNET_LIMIT}");
    }

    #[test]
    fn a_hash_reads_as_the_number_it_prints() {
        // Red if `from_hash` fills the limbs from the wrong end or reads a
        // chunk big-endian: `BlockHash` prints last byte first, which is the
        // little-endian number, so the two prints agree only when both are
        // right.
        let hash = crate::chain::genesis(crate::chain::network::Network::Mainnet).hash();
        assert_eq!(hash.to_string(), MAINNET_GENESIS_HASH);
        let number = crate::chain::u256::U256::from_hash(&hash);
        assert_eq!(number.to_string(), MAINNET_GENESIS_HASH);
        assert!(
            number < super::from_compact(0x1d00_ffff).unwrap(),
            "and it is below the target it claims"
        );
        println!("{number}");
    }

    #[test]
    fn only_a_network_with_a_limit_that_fits_retargets() {
        // Red if a network is given a timespan beside a limit wider than 224
        // bits: 255 bits times a clamped span passes 256, and `mul_u32` would
        // fail on its carry at the first boundary. The `const` assertions
        // beside `Params` are the guard; this is the same fact where a
        // person reads it, and it names the one network that does not
        // retarget.
        for network in ALL_NETWORKS {
            let params = super::Params::of(network);
            match params.retarget {
                super::Retarget::Never => assert!(
                    matches!(network, crate::chain::network::Network::Regtest),
                    "{network:?}"
                ),
                super::Retarget::Every { .. } => assert!(
                    super::leaves_room_for_a_timespan(&params.limit),
                    "{network:?}: {}",
                    params.limit
                ),
            }
            println!("{network:?}: {}", params.limit);
        }
    }

    #[test]
    fn genesis_of_every_network_has_its_work() {
        // Red if any of decode, limit or compare is wrong for a real header:
        // the four genesis blocks are the four `CheckProofOfWork` passes
        // every node makes first.
        for network in ALL_NETWORKS {
            let genesis = crate::chain::genesis(network);
            super::check(&genesis.hash(), genesis.bits, network).unwrap();
            println!(
                "{network:?} {} meets {:#010x}",
                genesis.hash(),
                genesis.bits
            );
        }
    }

    #[test]
    fn a_regtest_target_is_above_the_mainnet_limit_and_not_the_other_way() {
        // Red if the limit is compared the wrong way round: regtest's
        // easiest target is far above mainnet's limit, and mainnet's
        // genesis target is far below regtest's.
        let regtest = crate::chain::genesis(crate::chain::network::Network::Regtest);
        let err = super::check(
            &regtest.hash(),
            regtest.bits,
            crate::chain::network::Network::Mainnet,
        )
        .unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::AboveLimit { target, limit }
                    if target.to_string() == REGTEST_GENESIS_TARGET
                        && limit.to_string() == MAINNET_LIMIT
            ),
            "{err}"
        );
        let mainnet = crate::chain::genesis(crate::chain::network::Network::Mainnet);
        super::check(
            &mainnet.hash(),
            mainnet.bits,
            crate::chain::network::Network::Regtest,
        )
        .unwrap();
        println!("{err}");
    }

    #[test]
    fn a_hash_equal_to_the_target_passes_and_one_above_does_not() {
        // Red if the comparison is strict the wrong way: Core rejects on
        // `hash > target` (`pow.cpp:166`), so equal passes. The target of
        // `0x207fffff` is `7fffff` at wire bytes 31 down to 29; one more at
        // byte 28 is above it.
        let mut bytes = [0; crate::chain::block_header::HASH_BYTES];
        bytes[31] = 0x7f;
        bytes[30] = 0xff;
        bytes[29] = 0xff;
        let equal = crate::chain::block_header::BlockHash::from_bytes(bytes);
        super::check(&equal, 0x207f_ffff, crate::chain::network::Network::Regtest).unwrap();
        bytes[28] = 0x01;
        let above = crate::chain::block_header::BlockHash::from_bytes(bytes);
        let err =
            super::check(&above, 0x207f_ffff, crate::chain::network::Network::Regtest).unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::NotMet { hash, target }
                    if hash.to_string() == above.to_string()
                        && target.to_string() == REGTEST_GENESIS_TARGET
            ),
            "{err}"
        );
        println!("{err}");
    }

    #[test]
    fn a_nonce_off_by_one_loses_the_work() {
        // Red if `check` looks at the header and not the hash: the same
        // `bits`, one nonce over, and the zeros are gone.
        let mut genesis = crate::chain::genesis(crate::chain::network::Network::Mainnet);
        genesis.nonce += 1;
        let err = super::check(
            &genesis.hash(),
            genesis.bits,
            crate::chain::network::Network::Mainnet,
        )
        .unwrap_err();
        assert!(matches!(err, super::Error::NotMet { .. }), "{err}");
        println!("{err}");
    }

    #[test]
    fn mine_finds_the_smallest_nonce_that_works() {
        // Red if `mine` stops early or skips a nonce: every nonce below the
        // one it found fails, and the one it found passes.
        let mut header = crate::chain::genesis(crate::chain::network::Network::Regtest);
        header.merkle_root = crate::chain::block_header::MerkleRoot::from_bytes([1; 32]);
        super::mine(&mut header, crate::chain::network::Network::Regtest);
        super::check(
            &header.hash(),
            header.bits,
            crate::chain::network::Network::Regtest,
        )
        .unwrap();
        let found = header.nonce;
        for nonce in 0..found {
            header.nonce = nonce;
            assert!(
                super::check(
                    &header.hash(),
                    header.bits,
                    crate::chain::network::Network::Regtest
                )
                .is_err(),
                "nonce {nonce} works too"
            );
        }
        println!("nonce {found}");
    }

    #[test]
    #[should_panic(expected = "no nonce below 65536 meets bits 0x1d00ffff")]
    fn mine_gives_up_on_a_target_out_of_reach() {
        let mut header = crate::chain::genesis(crate::chain::network::Network::Mainnet);
        header.time += 1;
        super::mine(&mut header, crate::chain::network::Network::Mainnet);
    }

    #[test]
    fn the_work_of_a_target_is_the_chainwork_core_reports() {
        // Red if the work is 2**256/target instead of 2**256/(target+1), or
        // if the "+ 1" that turns the complement identity back into a
        // division is missing. Every number here is Core's: the chainwork of
        // the mainnet and regtest genesis blocks, and, for a target of a real
        // difficulty, the step chainwork takes from height 968 200 to
        // 968 201 (bits 0x17021ec5).
        let mainnet = crate::chain::network::Network::Mainnet;
        let genesis = super::Target::from_compact(0x1d00_ffff, mainnet).unwrap();
        assert_eq!(
            genesis.work(),
            crate::chain::u256::U256::from_limbs([0, 0, 0, 0x0001_0001_0001])
        );
        assert_eq!(
            genesis.work().to_string(),
            "0000000000000000000000000000000000000000000000000000000100010001"
        );

        let real = super::Target::from_compact(0x1702_1ec5, mainnet).unwrap();
        assert_eq!(
            real.work(),
            crate::chain::u256::U256::from_limbs([0, 0, 0x78be, 0x62f2_b502_3949_a486])
        );

        let regtest = crate::chain::network::Network::Regtest;
        let easiest = super::Target::from_compact(0x207f_ffff, regtest).unwrap();
        assert_eq!(easiest.work(), crate::chain::u256::U256::from_u64(2));
        println!("{}\n{}\n{}", genesis.work(), real.work(), easiest.work());
    }
}
