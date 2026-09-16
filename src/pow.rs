//! Proof of work: `nBits` decoded to a 256-bit target, and the block hash
//! held against it. `CheckProofOfWork`, `../bitcoin/src/pow.cpp:140` at
//! v31.1: `DeriveTarget` (`:146`) decodes `nBits` and refuses a negative,
//! zero, overflowing or too-easy target; `CheckProofOfWorkImpl` (`:160`)
//! then refuses a hash above it. Every refusal is the peer's, so every one
//! is an error. Retargeting, which says what `nBits` should be, is step 10.

const BITS: usize = 256;
const LIMB_BITS: usize = 64;
const LIMBS: usize = BITS / LIMB_BITS;

const _: () = assert!(LIMBS * LIMB_BITS == BITS);
const _: () = assert!(LIMBS * (LIMB_BITS / 8) == crate::block_header::HASH_BYTES);

/// The 23-bit mantissa of `nBits`, and the sign bit above it
/// (`arith_uint256.cpp:178`, `:186`).
const MANTISSA_MASK: u32 = 0x007f_ffff;
const SIGN_BIT: u32 = 0x0080_0000;

/// Where the mantissa sits when the exponent is 3: `SetCompact` shifts by
/// `8 * (size - 3)` (`arith_uint256.cpp:180`, `:183`).
const MANTISSA_BYTES: usize = 3;

/// A 256-bit unsigned number: what `nBits` decodes to before the limit is
/// asked, or a block hash read as one. Core's `arith_uint256`
/// (`arith_uint256.h:31`) is eight 32-bit limbs, least significant first.
/// This is four 64-bit limbs, *most* significant first, so that the derived
/// comparison of the array is the comparison of the number: two
/// equal-length arrays compared limb by limb from the top compare as the
/// numbers they spell. No other operation is needed before step 10.
#[derive(PartialEq, PartialOrd)]
pub struct U256([u64; LIMBS]);

/// A target a header may claim on one network: `nBits` decoded to a number
/// that is not zero, not negative, within 256 bits, and at or below the
/// network's `powLimit`. What `DeriveTarget` (`pow.cpp:146`) returns when it
/// returns anything. Only `from_compact` and `limit` build one, so a
/// `Target` in hand has passed every check but the hash.
pub struct Target(U256);

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
    AboveLimit { target: U256, limit: Target },
    /// The hash is above the target the header claims: `pow.cpp:166`.
    NotMet {
        hash: crate::block_header::BlockHash,
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

impl U256 {
    const ZERO: U256 = U256([0; LIMBS]);

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
    fn from_compact(bits: u32) -> Result<U256, Error> {
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
        let overflow =
            size > 34 || (mantissa > 0xff && size > 33) || (mantissa > 0xffff && size > 32);
        if overflow {
            return Err(Error::Overflow { bits });
        }
        let number = if size <= MANTISSA_BYTES {
            U256::from_u64(u64::from(mantissa))
        } else {
            U256::from_u64(u64::from(mantissa)).shl(8 * (size - MANTISSA_BYTES))
        };
        assert!(number != U256::ZERO, "the shift kept the mantissa");
        Ok(number)
    }

    /// `UintToArith256`, `arith_uint256.cpp:225`: the 32 bytes of a hash read
    /// as a little-endian number. That is the number Core prints, so a hash
    /// and the number made from it print the same.
    ///
    /// # Panics
    ///
    /// If the hash does not split into whole limbs. The `const` assertion
    /// beside `LIMBS` says it does.
    #[must_use]
    pub fn from_hash(hash: &crate::block_header::BlockHash) -> U256 {
        let (chunks, rest) = hash.as_bytes().as_chunks::<{ LIMB_BITS / 8 }>();
        assert_eq!(chunks.len(), LIMBS, "a hash is exactly LIMBS limbs");
        assert!(rest.is_empty(), "a hash is whole limbs");
        let mut limbs = [0; LIMBS];
        for (limb, chunk) in limbs.iter_mut().rev().zip(chunks) {
            *limb = u64::from_le_bytes(*chunk);
        }
        U256(limbs)
    }

    const fn from_u64(value: u64) -> U256 {
        let mut limbs = [0; LIMBS];
        limbs[LIMBS - 1] = value;
        U256(limbs)
    }

    /// `operator<<=`, `arith_uint256.cpp:14`, for a shift below the width:
    /// each limb moves up by whole limbs, and the bits it pushes past its
    /// new place land in the limb above.
    ///
    /// # Panics
    ///
    /// If `shift` is the width or more: the overflow check in `from_compact`
    /// rules it out, so reaching it is our bug.
    fn shl(self, shift: usize) -> U256 {
        assert!(shift < BITS, "a shift of {shift} clears every bit");
        let whole = shift / LIMB_BITS;
        let part = shift % LIMB_BITS;
        let mut limbs = [0; LIMBS];
        for (from, limb) in self.0.iter().enumerate() {
            let Some(to) = from.checked_sub(whole) else {
                continue;
            };
            limbs[to] |= limb << part;
            if part != 0
                && let Some(above) = to.checked_sub(1)
            {
                limbs[above] |= limb >> (LIMB_BITS - part);
            }
        }
        U256(limbs)
    }
}

impl Target {
    /// `DeriveTarget`, `pow.cpp:146`: `nBits` decoded as `U256::from_compact`
    /// decodes it, then held at or below the limit of `network`. Equal
    /// passes (`:155`).
    ///
    /// # Errors
    ///
    /// As `U256::from_compact`, then `AboveLimit`.
    pub fn from_compact(bits: u32, network: crate::message::Network) -> Result<Target, Error> {
        let target = U256::from_compact(bits)?;
        let limit = Target::limit(network);
        if target > limit.0 {
            return Err(Error::AboveLimit { target, limit });
        }
        Ok(Target(target))
    }

    /// `powLimit` of `network`: the easiest target a header may claim, and
    /// so a target itself. `chainparams.cpp:96` mainnet, `:227` testnet3,
    /// `:334` testnet4, `:575` regtest. Not a compact value: a compact
    /// target has at most 23 significant bits, and a limit has 224 or 255
    /// of them.
    #[must_use]
    pub fn limit(network: crate::message::Network) -> Target {
        match network {
            crate::message::Network::Mainnet
            | crate::message::Network::Testnet3
            | crate::message::Network::Testnet4 => {
                Target(U256([0x0000_0000_ffff_ffff, u64::MAX, u64::MAX, u64::MAX]))
            }
            crate::message::Network::Regtest => {
                Target(U256([0x7fff_ffff_ffff_ffff, u64::MAX, u64::MAX, u64::MAX]))
            }
        }
    }
}

/// Lowercase hex, most significant first: `GetHex`, `arith_uint256.cpp:140`,
/// the form `chainparams.cpp` writes a `powLimit` in.
impl std::fmt::Display for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for limb in &self.0 {
            write!(f, "{limb:016x}")?;
        }
        Ok(())
    }
}

/// The same as `Display`: a number prints as one.
impl std::fmt::Debug for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
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
/// # Errors
///
/// As `Target::from_compact`, then `NotMet`.
///
/// # Panics
///
/// If the target decoded is above the limit: `Target::from_compact` holds
/// it there, so reaching it is our bug.
pub fn check(
    hash: &crate::block_header::BlockHash,
    bits: u32,
    network: crate::message::Network,
) -> Result<(), Error> {
    let target = Target::from_compact(bits, network)?;
    assert!(
        target.0 <= Target::limit(network).0,
        "a Target is at or below the limit"
    );
    if U256::from_hash(hash) > target.0 {
        return Err(Error::NotMet {
            hash: hash.clone(),
            target,
        });
    }
    Ok(())
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
pub(crate) fn mine(header: &mut crate::block_header::Header, network: crate::message::Network) {
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
pub(crate) fn spoil(header: &mut crate::block_header::Header, network: crate::message::Network) {
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

    const ALL_NETWORKS: [crate::message::Network; 4] = [
        crate::message::Network::Mainnet,
        crate::message::Network::Testnet3,
        crate::message::Network::Testnet4,
        crate::message::Network::Regtest,
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

    #[test]
    fn from_compact_agrees_with_core_on_its_vectors() {
        // Red if the mantissa is shifted by the wrong count or in the wrong
        // direction, a flag is read before the bottom bytes are dropped, or
        // the limbs print in the wrong order.
        for (bits, expected) in CORE_VECTORS {
            let got = super::U256::from_compact(bits);
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
            let got = super::U256::from_compact(bits);
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
        let err = super::U256::from_compact(0xff00_0000).unwrap_err();
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
        let err =
            super::Target::from_compact(0xff12_3456, crate::message::Network::Regtest).unwrap_err();
        assert!(matches!(err, super::Error::Overflow { .. }), "{err}");
        let err =
            super::Target::from_compact(0x207f_ffff, crate::message::Network::Mainnet).unwrap_err();
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
            super::Target::from_compact(0x207f_ffff, crate::message::Network::Regtest).unwrap();
        assert_eq!(target.to_string(), REGTEST_GENESIS_TARGET);
        println!("{err}");
    }

    #[test]
    fn genesis_targets_and_limits_print_as_chainparams_writes_them() {
        // Red if a limit has the wrong top limb, or a genesis `bits` does not
        // decode to the number everyone quotes.
        assert_eq!(
            super::Target::limit(crate::message::Network::Mainnet).to_string(),
            MAINNET_LIMIT
        );
        assert_eq!(
            super::Target::limit(crate::message::Network::Testnet3).to_string(),
            MAINNET_LIMIT,
            "chainparams.cpp:227"
        );
        assert_eq!(
            super::Target::limit(crate::message::Network::Testnet4).to_string(),
            MAINNET_LIMIT,
            "chainparams.cpp:334"
        );
        assert_eq!(
            super::Target::limit(crate::message::Network::Regtest).to_string(),
            REGTEST_LIMIT
        );
        assert_eq!(
            super::Target::from_compact(0x1d00_ffff, crate::message::Network::Mainnet)
                .unwrap()
                .to_string(),
            MAINNET_GENESIS_TARGET
        );
        assert_eq!(
            super::Target::from_compact(0x207f_ffff, crate::message::Network::Regtest)
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
        let hash = crate::chain::genesis(crate::message::Network::Mainnet).hash();
        assert_eq!(hash.to_string(), MAINNET_GENESIS_HASH);
        let number = super::U256::from_hash(&hash);
        assert_eq!(number.to_string(), MAINNET_GENESIS_HASH);
        assert!(
            number < super::U256::from_compact(0x1d00_ffff).unwrap(),
            "and it is below the target it claims"
        );
        println!("{number}");
    }

    #[test]
    fn comparison_runs_from_the_top_limb() {
        // Red if the limbs are least significant first, where the derived
        // order would be wrong: a top limb of one beats every lower limb
        // full.
        let low_full = super::U256([0, 0, 0, u64::MAX]);
        let next_up = super::U256([0, 0, 1, 0]);
        let top_one = super::U256([1, 0, 0, 0]);
        let top_one_again = super::U256([1, 0, 0, 0]);
        let below_top = super::U256([0, u64::MAX, u64::MAX, u64::MAX]);
        assert!(low_full < next_up);
        assert!(below_top < top_one);
        assert!(top_one > low_full);
        assert!(top_one <= top_one_again, "equal is not above");
        println!("{low_full} < {next_up}, {below_top} < {top_one}");
    }

    #[test]
    fn a_shift_carries_the_bits_that_cross_a_limb() {
        // Red if the carry into the limb above is dropped or lands one limb
        // off, or a shift by whole limbs is off by one limb.
        let across = super::U256::from_u64(0xffff).shl(56);
        assert_eq!(across.0, [0, 0, 0xff, 0xff00_0000_0000_0000]);
        let top_bit = super::U256::from_u64(1).shl(255);
        assert_eq!(top_bit.0, [1 << 63, 0, 0, 0]);
        let whole = super::U256::from_u64(0x1234).shl(192);
        assert_eq!(whole.0, [0x1234, 0, 0, 0]);
        let none = super::U256::from_u64(0x1234).shl(0);
        assert_eq!(none.0, [0, 0, 0, 0x1234]);
        println!("{across}\n{top_bit}\n{whole}");
    }

    #[test]
    #[should_panic(expected = "a shift of 256 clears every bit")]
    fn a_shift_of_the_width_is_our_bug() {
        let _ = super::U256::from_u64(1).shl(256);
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
        let regtest = crate::chain::genesis(crate::message::Network::Regtest);
        let err = super::check(
            &regtest.hash(),
            regtest.bits,
            crate::message::Network::Mainnet,
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
        let mainnet = crate::chain::genesis(crate::message::Network::Mainnet);
        super::check(
            &mainnet.hash(),
            mainnet.bits,
            crate::message::Network::Regtest,
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
        let mut bytes = [0; crate::block_header::HASH_BYTES];
        bytes[31] = 0x7f;
        bytes[30] = 0xff;
        bytes[29] = 0xff;
        let equal = crate::block_header::BlockHash::from_bytes(bytes);
        super::check(&equal, 0x207f_ffff, crate::message::Network::Regtest).unwrap();
        bytes[28] = 0x01;
        let above = crate::block_header::BlockHash::from_bytes(bytes);
        let err = super::check(&above, 0x207f_ffff, crate::message::Network::Regtest).unwrap_err();
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
        let mut genesis = crate::chain::genesis(crate::message::Network::Mainnet);
        genesis.nonce += 1;
        let err = super::check(
            &genesis.hash(),
            genesis.bits,
            crate::message::Network::Mainnet,
        )
        .unwrap_err();
        assert!(matches!(err, super::Error::NotMet { .. }), "{err}");
        println!("{err}");
    }

    #[test]
    fn mine_finds_the_smallest_nonce_that_works() {
        // Red if `mine` stops early or skips a nonce: every nonce below the
        // one it found fails, and the one it found passes.
        let mut header = crate::chain::genesis(crate::message::Network::Regtest);
        header.merkle_root = crate::block_header::MerkleRoot::from_bytes([1; 32]);
        super::mine(&mut header, crate::message::Network::Regtest);
        super::check(
            &header.hash(),
            header.bits,
            crate::message::Network::Regtest,
        )
        .unwrap();
        let found = header.nonce;
        for nonce in 0..found {
            header.nonce = nonce;
            assert!(
                super::check(
                    &header.hash(),
                    header.bits,
                    crate::message::Network::Regtest
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
        let mut header = crate::chain::genesis(crate::message::Network::Mainnet);
        header.time += 1;
        super::mine(&mut header, crate::message::Network::Mainnet);
    }
}
