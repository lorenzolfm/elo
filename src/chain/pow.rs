//! Proof of work: `nBits` decoded to a 256-bit target, and the block hash
//! held against it. `CheckProofOfWork`, `../bitcoin/src/pow.cpp:140` at
//! v31.1: `DeriveTarget` (`:146`) decodes `nBits` and refuses a negative,
//! zero, overflowing or too-easy target; `CheckProofOfWorkImpl` (`:161`)
//! then refuses a hash above it. Every refusal is the peer's, so every one
//! is an error.
//!
//! `retarget::next_bits` is the other half: `GetNextWorkRequired` (`:14`)
//! says which `nBits` a header is allowed to claim at its height. `check`
//! asks whether a header did the work it claims; `next_bits` asks whether it
//! claimed the right amount.

/// The 23-bit mantissa of `nBits`, and the sign bit above it
/// (`arith_uint256.cpp:178`, `:186`).
const MANTISSA_MASK: u32 = 0x007f_ffff;
const SIGN_BIT: u32 = 0x0080_0000;

/// Where the mantissa sits when the exponent is 3: `SetCompact` shifts by
/// `8 * (size - 3)` (`arith_uint256.cpp:180`, `:184`).
const MANTISSA_BYTES: usize = 3;

/// `nPowTargetSpacing`: the seconds one block is meant to take, ten minutes
/// on every network (`chainparams.cpp:98`, `:229`, `:336`, `:577`).
pub(super) const SPACING: u32 = 10 * 60;

/// `nPowTargetTimespan`: the seconds one difficulty period is meant to take,
/// two weeks on mainnet and the two testnets (`chainparams.cpp:97`, `:228`,
/// `:335`), one day on regtest (`:576`).
pub(super) const TIMESPAN_TWO_WEEKS: u32 = 14 * 24 * 60 * 60;
const TIMESPAN_ONE_DAY: u32 = 24 * 60 * 60;

/// `DifficultyAdjustmentInterval`, `params.h:126`: the blocks in one period,
/// the timespan over the spacing. A height counts blocks, so an interval is
/// a `usize`; the `const` assertions hold each one to the division it comes
/// from.
const INTERVAL_TWO_WEEKS: usize = 2016;
const INTERVAL_ONE_DAY: usize = 144;

const _: () = assert!(TIMESPAN_TWO_WEEKS / SPACING == 2016);
const _: () = assert!(TIMESPAN_ONE_DAY / SPACING == 144);
const _: () = assert!(INTERVAL_TWO_WEEKS == 2016);
const _: () = assert!(INTERVAL_ONE_DAY == 144);

/// `powLimit`: the easiest target a header may claim. Mainnet, testnet3 and
/// testnet4 share a limit of 224 bits (`chainparams.cpp:96`, `:227`, `:334`);
/// regtest has one of 255 (`:575`). Not compact values: a compact target
/// holds 23 significant bits, and a limit holds 224 or 255 of them.
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

/// Which block of a period gives the target the next period is scaled from:
/// the last one (`pow.cpp:50`), or the first one under BIP94 (`:67`), so
/// that a min-difficulty block at the end of a period cannot drop the
/// difficulty of the next one.
pub(super) enum Edge {
    First,
    Last,
}

/// How a period ends. Core reads two booleans here, `fPowNoRetargeting` and
/// `enforce_BIP94`, and only three of their four combinations are a network.
/// This is the one question they answer: a network that does not retarget
/// has no timespan to scale and no edge to scale from, and cannot be given
/// either one.
pub(super) enum Retarget {
    /// `fPowNoRetargeting`, `pow.cpp:52`: the difficulty never moves.
    /// Regtest only.
    Never,
    /// The period is scaled from the target at `edge`, over
    /// `timespan_target`, the seconds `nPowTargetTimespan` says it was meant
    /// to take.
    Every { timespan_target: u32, edge: Edge },
}

/// How the difficulty moves on one network: the `Consensus::Params` fields
/// that `GetNextWorkRequired` reads (`../bitcoin/src/consensus/params.h:113`),
/// as `chainparams.cpp` sets them. One arm of `of` describes a network
/// whole, the `powLimit` with the rest, so no second `match` on the network
/// can disagree with this one.
pub(super) struct Params {
    pub(super) interval: usize,
    pub(super) limit: Target,
    /// `fPowAllowMinDifficultyBlocks`: a block more than two spacings after
    /// the one before it may claim the limit (`pow.cpp:22`). Every network
    /// but mainnet.
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

/// Whether a target times a timespan stays inside 256 bits. A timespan
/// clamped to four periods is below 2^23, and a limit of 224 bits leaves the
/// 32 above it clear, so a target that reaches no higher fits.
const fn leaves_room_for_a_timespan(target: &Target) -> bool {
    target.0.leading_zeros() >= 32
}

/// Whether the limit of `network` leaves `mul_u32` the room it needs. Only a
/// network that retargets multiplies, so only those limits must fit.
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

/// A target a header may claim on one network: `nBits` decoded to a number
/// that is not zero, not negative, within 256 bits, and at or below the
/// network's `powLimit`. What `DeriveTarget` (`pow.cpp:146`) returns when it
/// returns anything. Only `from_compact` and `limit` build one, so a
/// `Target` in hand has passed every check but the hash.
pub struct Target(pub(super) crate::chain::u256::U256);

#[derive(Debug)]
pub enum Error {
    /// A mantissa of zero, or one shifted out below the lowest byte: no
    /// hash is below zero, `pow.cpp:155`.
    Zero { bits: u32 },
    /// The sign bit of `nBits` is set with a mantissa to sign. Core's
    /// `fNegative`, `arith_uint256.cpp:186`.
    Negative { bits: u32 },
    /// The mantissa lands wholly above bit 255. Core's `fOverflow`,
    /// `arith_uint256.cpp:188`.
    Overflow { bits: u32 },
    /// Easier than the network allows: `bnTarget > powLimit`, `pow.cpp:155`.
    /// The number decoded is no target, so it is carried as the number.
    AboveLimit {
        target: crate::chain::u256::U256,
        limit: Target,
    },
    /// The hash is above the target the header claims: `pow.cpp:166`.
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

/// `SetCompact`, `arith_uint256.cpp:175`: the top byte of `nBits` is a
/// size in bytes, the low 23 bits a mantissa, the bit between a sign.
/// The top byte of the mantissa lands at byte `size - 1` of the number,
/// counted from the least significant byte as 0: for a size of three or
/// less the mantissa loses bytes at the bottom, for more it is shifted
/// up. Core flags a negative and an overflow on the mantissa *after*
/// the bytes at the bottom are gone (`:186`, `:188`), and `DeriveTarget`
/// refuses on either flag or on a target of zero (`pow.cpp:155`). Here
/// each refusal is its own error. Zero is the mantissa gone, and rules
/// the other two out; both may hold at once, and the sign is named
/// first as Core tests it first. The limit is `Target::from_compact`'s
/// question: this is the number, whatever the network.
///
/// # Errors
///
/// `Zero`, `Negative` or `Overflow`, as above.
///
/// # Panics
///
/// If a mantissa that passed the overflow check shifts to zero. A size
/// of 34 at most, with a mantissa of one byte, shifts by 248 at most:
/// no bit is lost, so the number is not zero.
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

/// `GetCompact`, `arith_uint256.cpp:195`: the size is how many bytes the
/// number takes, and the mantissa is its top three, or the whole of it
/// padded on the right when it is shorter. A mantissa that reaches the
/// sign bit gives a byte back to the size, so that no `nBits` this
/// writes reads as negative (`:207`).
///
/// Not the inverse of `from_compact`: it returns the shortest form, and
/// `0x01123456` is not one (`arith_uint256_tests.cpp:482`). It *is* the
/// inverse for a number `from_compact` did not have to shift.
///
/// # Panics
///
/// If the mantissa keeps a bit above the low 23, or the size passes a
/// byte. The sign step rules both out: 32 bytes and one given back is
/// 33, and the width holds no more.
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
    /// `DeriveTarget`, `pow.cpp:146`: `nBits` decoded as `from_compact`
    /// decodes it, then held at or below the limit of `network`. Equal
    /// passes (`:155`).
    ///
    /// # Errors
    ///
    /// As `from_compact`, then `AboveLimit`.
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

    /// `powLimit` of `network`: the easiest target a header may claim, and
    /// so a target itself. `Params` holds it beside the rest of the network.
    #[must_use]
    pub fn limit(network: crate::chain::network::Network) -> Target {
        Params::of(network).limit
    }
}

/// A target prints as the number it is.
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

/// `CheckProofOfWork`, `pow.cpp:140`, for one header: `bits` decodes to a
/// target of `network`, and `hash` is at or below it. Equal passes
/// (`pow.cpp:166`).
///
/// The target it decoded comes back with the `Ok`: the caller asked what
/// the header claims, and that is the answer.
///
/// # Errors
///
/// As `Target::from_compact`, then `NotMet`.
///
/// # Panics
///
/// If the target decoded is above the limit: `Target::from_compact` holds
/// it there, so reaching it is our bug.
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

/// A header that `check` accepted on one network: its `nBits` decode to a
/// target of that network, and its hash is at or below that target. The
/// field is private, and outside tests `checked` is the only way to fill it,
/// so a `Checked` in hand *is* the proof that the work was checked.
/// `next_bits` takes these and nothing else, which is what keeps the two
/// checks in order without a comment that says so. In test builds
/// `unchecked` fills the field too, for the ancestors a test reads and
/// never checks.
pub struct Checked(crate::chain::block_header::Header);

impl Checked {
    /// The header itself, for everything that does not need the proof.
    #[must_use]
    pub fn header(&self) -> &crate::chain::block_header::Header {
        &self.0
    }

    /// The target the header claims. A target is 32 bytes and one header in
    /// a period is asked for its own, so it is decoded here rather than
    /// kept beside every header we hold.
    ///
    /// # Panics
    ///
    /// If the `nBits` do not decode to a target of `network`, which says
    /// the header was checked against another network. A chain holds one
    /// network and checks every header it keeps against that one.
    pub(super) fn target(&self, network: crate::chain::network::Network) -> Target {
        match Target::from_compact(self.0.bits, network) {
            Ok(target) => target,
            Err(error) => panic!("a header we kept claims bits that do not decode: {error}"),
        }
    }
}

/// `check` for a whole header, with the header back inside the proof: this
/// is how a chain takes a header in.
///
/// # Errors
///
/// As `check`.
pub fn checked(
    header: crate::chain::block_header::Header,
    network: crate::chain::network::Network,
) -> Result<Checked, Error> {
    check(&header.hash(), header.bits, network)?;
    Ok(Checked(header))
}

/// How many nonces `mine` and `spoil` try before they give up. On a regtest
/// target a nonce works, or fails, every second try on average.
#[cfg(test)]
const TRIES_MAX: u32 = 1 << 16;

/// The miner's side of `check`, for tests that build headers by hand: the
/// smallest nonce whose hash meets the target the header claims, as
/// `generatetoaddress` grinds one on regtest (`rpc/mining.cpp:142`).
///
/// # Panics
///
/// If no nonce in `TRIES_MAX` works: the header claims a target that is not
/// within reach of a test, or one above the limit, which no nonce fixes.
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

/// The opposite of `mine`, for a header that must lose its work: the
/// smallest nonce above the one held whose hash does not meet the target.
///
/// # Panics
///
/// If no nonce in `TRIES_MAX` fails: the header claims a target every hash
/// is below, which no test target is.
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

/// A `Checked` whose proof is filled in by hand, for tests that read a
/// chain rather than check one. Ancestors are read for the heights, times
/// and bits of the headers before a candidate and never for their work, so
/// a test that builds them has no reason to mine.
#[cfg(test)]
pub(crate) fn unchecked(header: crate::chain::block_header::Header) -> Checked {
    Checked(header)
}

#[cfg(test)]
mod tests {
    // Core's `SetCompact` vectors, `test/arith_uint256_tests.cpp:409`, as
    // `GetHex` prints the result or as the flag Core raises. Every zero is
    // a mantissa that the size shifted away, sign bit or not: `0x00923456`
    // and `0x01803456` have the sign set and Core does not call them
    // negative.
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

    // The limits as `chainparams.cpp` writes them: `:96` and `:575`.
    const MAINNET_LIMIT: &str = "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const REGTEST_LIMIT: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    // What genesis claims on mainnet (`chainparams.cpp:134`) and on regtest
    // (`:634`), decoded: the mantissa `ffff` at bytes 26 to 28 and `7fffff`
    // at bytes 29 to 31.
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

    // `GetCompact` of each vector above that decodes, as
    // `arith_uint256_tests.cpp:482` to `:528` expects it. Only the sizes of
    // three and up come back as they went in: a compact value whose size
    // shifted the mantissa is not the shortest form of its number.
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
        // `arith_uint256_tests.cpp:487`: 128 is one byte, and writing it as
        // one would set the sign bit, so it is written as two.
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
}
