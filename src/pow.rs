//! Proof of work: `nBits` decoded to a 256-bit target, and the block hash
//! held against it. `CheckProofOfWork`, `../bitcoin/src/pow.cpp:140` at
//! v31.1: `DeriveTarget` (`:146`) decodes `nBits` and refuses a negative,
//! zero, overflowing or too-easy target; `CheckProofOfWorkImpl` (`:161`)
//! then refuses a hash above it. Every refusal is the peer's, so every one
//! is an error.
//!
//! `next_bits` is the other half: `GetNextWorkRequired` (`:14`) says which
//! `nBits` a header is allowed to claim at its height, and `retarget`
//! (`:50`) is the arithmetic on a period boundary. `check` asks whether a
//! header did the work it claims; `next_bits` asks whether it claimed the
//! right amount.

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
/// `8 * (size - 3)` (`arith_uint256.cpp:180`, `:184`).
const MANTISSA_BYTES: usize = 3;

/// `nPowTargetSpacing`: the seconds one block is meant to take, ten minutes
/// on every network (`chainparams.cpp:98`, `:229`, `:336`, `:577`).
const SPACING: u32 = 10 * 60;

/// `nPowTargetTimespan`: the seconds one difficulty period is meant to take,
/// two weeks on mainnet and the two testnets (`chainparams.cpp:97`, `:228`,
/// `:335`), one day on regtest (`:576`).
const TIMESPAN_TWO_WEEKS: u32 = 14 * 24 * 60 * 60;
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
const LIMIT_224: Target = Target(U256([0x0000_0000_ffff_ffff, u64::MAX, u64::MAX, u64::MAX]));
const LIMIT_255: Target = Target(U256([0x7fff_ffff_ffff_ffff, u64::MAX, u64::MAX, u64::MAX]));

/// Which block of a period gives the target the next period is scaled from:
/// the last one (`pow.cpp:50`), or the first one under BIP94 (`:67`), so
/// that a min-difficulty block at the end of a period cannot drop the
/// difficulty of the next one.
enum Edge {
    First,
    Last,
}

/// How a period ends. Core reads two booleans here, `fPowNoRetargeting` and
/// `enforce_BIP94`, and only three of their four combinations are a network.
/// This is the one question they answer: a network that does not retarget
/// has no timespan to scale and no edge to scale from, and cannot be given
/// either one.
enum Retarget {
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
struct Params {
    interval: usize,
    limit: Target,
    /// `fPowAllowMinDifficultyBlocks`: a block more than two spacings after
    /// the one before it may claim the limit (`pow.cpp:22`). Every network
    /// but mainnet.
    min_difficulty: bool,
    retarget: Retarget,
}

impl Params {
    const fn of(network: crate::message::Network) -> Params {
        match network {
            crate::message::Network::Mainnet => Params {
                interval: INTERVAL_TWO_WEEKS,
                limit: LIMIT_224,
                min_difficulty: false,
                retarget: Retarget::Every {
                    timespan_target: TIMESPAN_TWO_WEEKS,
                    edge: Edge::Last,
                },
            },
            crate::message::Network::Testnet3 => Params {
                interval: INTERVAL_TWO_WEEKS,
                limit: LIMIT_224,
                min_difficulty: true,
                retarget: Retarget::Every {
                    timespan_target: TIMESPAN_TWO_WEEKS,
                    edge: Edge::Last,
                },
            },
            crate::message::Network::Testnet4 => Params {
                interval: INTERVAL_TWO_WEEKS,
                limit: LIMIT_224,
                min_difficulty: true,
                retarget: Retarget::Every {
                    timespan_target: TIMESPAN_TWO_WEEKS,
                    edge: Edge::First,
                },
            },
            crate::message::Network::Regtest => Params {
                interval: INTERVAL_ONE_DAY,
                limit: LIMIT_255,
                min_difficulty: true,
                retarget: Retarget::Never,
            },
        }
    }
}

/// Whether the limit of `network` leaves `mul_u32` the room it needs. Only a
/// network that retargets multiplies, so only those limits must fit.
const fn the_product_fits(network: crate::message::Network) -> bool {
    let params = Params::of(network);
    match params.retarget {
        Retarget::Never => true,
        Retarget::Every { .. } => params.limit.0.leaves_room_for_a_timespan(),
    }
}

const _: () = assert!(the_product_fits(crate::message::Network::Mainnet));
const _: () = assert!(the_product_fits(crate::message::Network::Testnet3));
const _: () = assert!(the_product_fits(crate::message::Network::Testnet4));
const _: () = assert!(the_product_fits(crate::message::Network::Regtest));

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

    /// Whether this number times a timespan stays inside 256 bits. A
    /// timespan clamped to four periods is below 2^23, and 224 bits leave
    /// the 32 above them free, so a number that reaches no higher fits.
    const fn leaves_room_for_a_timespan(&self) -> bool {
        self.0[0] <= 0x0000_0000_ffff_ffff
    }

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

    /// The number as 32 bytes, most significant first: the order `Display`
    /// prints and the order `to_compact` reads a mantissa in.
    fn to_be_bytes(&self) -> [u8; crate::block_header::HASH_BYTES] {
        let mut bytes = [0; crate::block_header::HASH_BYTES];
        let (chunks, rest) = bytes.as_chunks_mut::<{ LIMB_BITS / 8 }>();
        assert_eq!(chunks.len(), LIMBS, "a number is exactly LIMBS limbs");
        assert!(rest.is_empty(), "a number is whole limbs");
        for (chunk, limb) in chunks.iter_mut().zip(&self.0) {
            *chunk = limb.to_be_bytes();
        }
        bytes
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
    fn to_compact(&self) -> u32 {
        let bytes = self.to_be_bytes();
        let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
        let mut size = crate::block_header::HASH_BYTES - zeros;
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
            size <= crate::block_header::HASH_BYTES + 1,
            "a size of {size}"
        );
        let Ok(size) = u32::try_from(size) else {
            unreachable!("a size of {size} is one byte")
        };
        mantissa | (size << 24)
    }

    /// `operator*=(uint32_t)`, `arith_uint256.cpp:48`: each limb times the
    /// factor, the overflow carried into the limb above.
    ///
    /// # Panics
    ///
    /// If the product passes 256 bits. Core lets it wrap. The one caller is
    /// `retarget`, where the number is a target at or below a `powLimit` of
    /// 224 bits and the factor is a clamped timespan below 2^23, so 247 bits
    /// is the most the product takes. Only regtest has a wider limit, 255
    /// bits, and regtest does not retarget: the `const` assertions beside
    /// `Params` hold every network that does to a limit that fits.
    fn mul_u32(self, factor: u32) -> U256 {
        let mut limbs = [0; LIMBS];
        let mut carry: u128 = 0;
        for (limb, out) in self.0.iter().zip(limbs.iter_mut()).rev() {
            let product = u128::from(*limb) * u128::from(factor) + carry;
            let Ok(low) = u64::try_from(product & u128::from(u64::MAX)) else {
                unreachable!("the mask keeps one limb")
            };
            *out = low;
            carry = product >> LIMB_BITS;
        }
        assert_eq!(carry, 0, "a target times a timespan stays in 256 bits");
        U256(limbs)
    }

    /// `operator/=`, `arith_uint256.cpp:76`, for a divisor of one limb: long
    /// division from the top, each limb joined to the remainder above it. The
    /// remainder is below the divisor, so the pair is never wider than a
    /// `u128` and the digit it yields is never wider than a limb.
    ///
    /// # Panics
    ///
    /// If `divisor` is zero. The one caller divides by a network's
    /// `nPowTargetTimespan`, which is a constant above zero.
    fn div_u32(self, divisor: u32) -> U256 {
        assert!(divisor != 0, "a timespan is not zero");
        let divisor = u128::from(divisor);
        let mut limbs = [0; LIMBS];
        let mut rest: u128 = 0;
        for (limb, out) in self.0.iter().zip(limbs.iter_mut()) {
            let joined = (rest << LIMB_BITS) | u128::from(*limb);
            let Ok(digit) = u64::try_from(joined / divisor) else {
                unreachable!("a remainder below the divisor leaves one limb")
            };
            *out = digit;
            rest = joined % divisor;
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
    /// so a target itself. `Params` holds it beside the rest of the network.
    #[must_use]
    pub fn limit(network: crate::message::Network) -> Target {
        Params::of(network).limit
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
    hash: &crate::block_header::BlockHash,
    bits: u32,
    network: crate::message::Network,
) -> Result<Target, Error> {
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
    Ok(target)
}

/// A header that `check` accepted on one network: its `nBits` decode to a
/// target of that network, and its hash is at or below that target. The
/// field is private and `checked` is the only way to fill it, so a `Checked`
/// in hand *is* the proof that the work was checked. `next_bits` takes these
/// and nothing else, which is what keeps the two checks in order without a
/// comment that says so.
pub struct Checked(crate::block_header::Header);

impl Checked {
    /// The header itself, for everything that does not need the proof.
    #[must_use]
    pub fn header(&self) -> &crate::block_header::Header {
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
    fn target(&self, network: crate::message::Network) -> Target {
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
    header: crate::block_header::Header,
    network: crate::message::Network,
) -> Result<Checked, Error> {
    check(&header.hash(), header.bits, network)?;
    Ok(Checked(header))
}

/// `CalculateNextWorkRequired`, `pow.cpp:50`, without the
/// `fPowNoRetargeting` line that opens it: `target` scaled by
/// `timespan_actual` over `timespan_target`, the seconds the period was
/// meant to take, held at or below `limit`, and written back in compact
/// form.
///
/// `timespan_actual` is the seconds the period really took, and it is
/// signed: block times are not sorted, so the last block of a period can be
/// older than the first. It is clamped to a quarter of the target timespan
/// and to four times it (`pow.cpp:57`), so one period moves the target by
/// four either way at most, and a span below zero is simply the low clamp.
///
/// The scaling drops the low bits, and `to_compact` keeps 23 of them, so the
/// result is not the exact ratio. It is what every node computes, which is
/// what consensus asks.
///
/// The caller brings the target of a header it already checked, so there is
/// no decode here and no error to return. It also brings the
/// `timespan_target` and the `limit`, and a `Retarget::Every` is the only
/// source of a target timespan, so a network that does not retarget cannot
/// reach here and cannot bring the 255-bit limit that would overflow the
/// multiply.
///
/// # Panics
///
/// If the product passes 256 bits, which the `const` assertions beside
/// `Params` rule out.
fn retarget(target: Target, timespan_actual: i64, timespan_target: u32, limit: &Target) -> u32 {
    let low = i64::from(timespan_target / 4);
    let high = i64::from(timespan_target) * 4;
    let clamped = timespan_actual.clamp(low, high);
    let Ok(clamped) = u32::try_from(clamped) else {
        unreachable!("a timespan clamped to {low}..={high} fits a u32")
    };
    let scaled = target.0.mul_u32(clamped).div_u32(timespan_target);
    if scaled > limit.0 {
        limit.0.to_compact()
    } else {
        scaled.to_compact()
    }
}

/// One answer from `next_bits`, held to what a header may claim. The rules
/// must ask for `nBits` that decode to a target of `network`: if they ask
/// for anything else, no header can meet both them and `check`, and the
/// chain stops at that height for good with the refusal blamed on the peer.
/// `check` decodes on the way in, this decodes on the way out, so the
/// property is asserted at both ends of the pair. Every path here already
/// holds it — a checked header's own claim, the limit, or a product held at
/// or below the limit — and a decode is a few shifts beside the two hashes
/// the header has already cost.
///
/// # Panics
///
/// If the bits do not decode to a target of `network`, which is our bug.
fn next_bits_required(bits: u32, network: crate::message::Network) -> u32 {
    if let Err(error) = Target::from_compact(bits, network) {
        panic!("the rules require bits {bits:#010x} that no header may claim: {error}");
    }
    bits
}

/// `GetNextWorkRequired`, `pow.cpp:14`: the `nBits` the header after the
/// last of `ancestors` must claim. `candidate` is the header the peer
/// offers, and only a min-difficulty network reads it, for its time.
///
/// Away from a period boundary the answer is the last header's `nBits`, so
/// the difficulty holds for a whole period. On the boundary the period is
/// measured from the header `interval - 1` back, not `interval` back: the
/// span covers one block interval less than the period it is divided by, so
/// a period of 2016 blocks is timed as if it were 2015. The off-by-one has
/// been consensus since 2009 and is copied here on purpose.
///
/// # Panics
///
/// If a boundary falls with fewer than `interval` headers under it. A chain
/// starts at genesis and grows by one, so it cannot. Or if the answer is
/// not bits a header may claim, as `next_bits_required` says.
#[must_use]
pub fn next_bits(
    ancestors: &crate::ancestors::Ancestors,
    candidate: &crate::block_header::Header,
    network: crate::message::Network,
) -> u32 {
    let params = Params::of(network);
    let height_last = ancestors.height_last();
    if !(height_last + 1).is_multiple_of(params.interval) {
        if !params.min_difficulty {
            return next_bits_required(ancestors.at(height_last).header().bits, network);
        }
        let limit_bits = params.limit.0.to_compact();
        // `pow.cpp:26`: on a test network a block more than two spacings
        // after the one before it may claim the limit, so that a chain with
        // no miner on it is never stuck.
        let gap = i64::from(candidate.time) - i64::from(ancestors.at(height_last).header().time);
        if gap > i64::from(SPACING) * 2 {
            return next_bits_required(limit_bits, network);
        }
        // `pow.cpp:32`: those blocks do not set the difficulty. Walk back
        // over them, and stop at the first block of the period whatever it
        // claims. The height falls by one each step and the walk stops at a
        // multiple of the interval, so it takes `interval - 1` steps at
        // most: 2015 on the networks that retarget, 143 on regtest.
        let mut height = height_last;
        while height > 0
            && !height.is_multiple_of(params.interval)
            && ancestors.at(height).header().bits == limit_bits
        {
            height -= 1;
        }
        return next_bits_required(ancestors.at(height).header().bits, network);
    }
    let Retarget::Every {
        timespan_target,
        edge,
    } = params.retarget
    else {
        return next_bits_required(ancestors.at(height_last).header().bits, network);
    };
    let Some(height_first) = (height_last + 1).checked_sub(params.interval) else {
        unreachable!(
            "a boundary at height {} has no period under it",
            height_last + 1
        )
    };
    let timespan_actual = i64::from(ancestors.at(height_last).header().time)
        - i64::from(ancestors.at(height_first).header().time);
    // BIP94, `pow.cpp:67`: testnet4 scales the period from the target its
    // first block claims. A min-difficulty block cannot be that one, so the
    // real difficulty of the period survives at its start.
    let height_source = match edge {
        Edge::First => height_first,
        Edge::Last => height_last,
    };
    let bits = retarget(
        ancestors.at(height_source).target(network),
        timespan_actual,
        timespan_target,
        &params.limit,
    );
    next_bits_required(bits, network)
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

/// A `Checked` whose proof is filled in by hand, for tests that read a
/// chain rather than check one. Ancestors are read for the heights, times
/// and bits of the headers before a candidate and never for their work, so
/// a test that builds them has no reason to mine.
#[cfg(test)]
pub(crate) fn unchecked(header: crate::block_header::Header) -> Checked {
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

    // Core's four `CalculateNextWorkRequired` cases, `test/pow_tests.cpp:18`,
    // `:36`, `:51` and `:67`, all on mainnet: the time of the last block of
    // the period, the time of the first, the bits in force, and the bits
    // Core computes. The first is a plain retarget (blocks 30240 and 32255),
    // the second is held at `powLimit` (blocks 0 and 2015), the third has a
    // span below a quarter of two weeks (blocks 66528 and 68543), the fourth
    // a span above four times it (block 46367, and a first time Core made
    // up).
    const CORE_RETARGETS: [(u32, u32, u32, u32); 4] = [
        (1_262_152_739, 1_261_130_161, 0x1d00_ffff, 0x1d00_d86a),
        (1_233_061_996, 1_231_006_505, 0x1d00_ffff, 0x1d00_ffff),
        (1_279_297_671, 1_279_008_237, 0x1c05_a3f4, 0x1c01_68fd),
        (1_269_211_443, 1_263_163_443, 0x1c38_7f6f, 0x1d00_e1fd),
    ];

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

    /// The seconds two weeks hold: `nPowTargetTimespan` on mainnet.
    const TWO_WEEKS: i64 = 14 * 24 * 60 * 60;

    /// A header with a time and bits, and nothing else `next_bits` reads.
    fn header(time: u32, bits: u32) -> crate::block_header::Header {
        crate::block_header::Header {
            version: 1,
            previous_block: crate::block_header::BlockHash::from_bytes([0; 32]),
            merkle_root: crate::block_header::MerkleRoot::from_bytes([0; 32]),
            time,
            bits,
            nonce: 0,
        }
    }

    /// Headers for `next_bits` to read, one per time given, all claiming the
    /// same bits. Nothing here is mined: `next_bits` asks what a header may
    /// claim, and `check` is what asks whether it did the work, so the
    /// tests fill the proof themselves.
    fn timeline(times: &[u32], bits: u32) -> Vec<super::Checked> {
        times
            .iter()
            .map(|time| super::Checked(header(*time, bits)))
            .collect()
    }

    /// A header a peer offers, read only for its time.
    fn candidate(time: u32) -> crate::block_header::Header {
        header(time, 0x1d00_ffff)
    }

    /// `retarget` on mainnet, where Core's vectors come from: the target of
    /// `bits` scaled over two weeks and held at the mainnet limit.
    fn mainnet_retarget(bits: u32, actual: i64) -> u32 {
        let network = crate::message::Network::Mainnet;
        let target = super::Target::from_compact(bits, network).unwrap();
        let params = super::Params::of(network);
        super::retarget(target, actual, super::TIMESPAN_TWO_WEEKS, &params.limit)
    }

    #[test]
    fn retarget_agrees_with_core_on_its_vectors() {
        // Red if the span is scaled by the wrong ratio, the multiply and the
        // divide swap places, the clamps use the wrong quarter or multiple,
        // or the result is not held at the limit.
        for (last, first, bits, expected) in CORE_RETARGETS {
            let actual = i64::from(last) - i64::from(first);
            let got = mainnet_retarget(bits, actual);
            assert_eq!(got, expected, "{bits:#010x} over {actual} seconds");
            println!("{bits:#010x} over {actual}s -> {got:#010x}");
        }
    }

    #[test]
    fn to_compact_agrees_with_core_on_its_vectors() {
        // Red if the mantissa is taken from the wrong three bytes, the size
        // counts bits instead of bytes, or the sign step is missing: a
        // mantissa that reaches `0x00800000` must give a byte back to the
        // size, or the value it writes reads back as negative.
        for (bits, expected) in CORE_COMPACT {
            let number = super::U256::from_compact(bits).unwrap();
            assert_eq!(number.to_compact(), expected, "{bits:#010x} -> {number}");
            println!("{bits:#010x} -> {number} -> {:#010x}", number.to_compact());
        }
        // `arith_uint256_tests.cpp:487`: 128 is one byte, and writing it as
        // one would set the sign bit, so it is written as two.
        assert_eq!(super::U256::from_u64(0x80).to_compact(), 0x0200_8000);
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
            assert_eq!(limit.0.to_compact(), genesis.bits, "{limit}");
            println!("{network:?}: {limit} -> {:#010x}", genesis.bits);
        }
    }

    #[test]
    fn a_span_at_or_below_a_quarter_of_the_period_is_read_as_a_quarter() {
        // Red if the low clamp is missing, uses the wrong quarter, or lets a
        // span below zero through: block times are not sorted, so the last
        // block of a period can be older than the first.
        const BITS: u32 = 0x1c05_a3f4;
        let quarter = mainnet_retarget(BITS, TWO_WEEKS / 4);
        for actual in [TWO_WEEKS / 4 - 1, 0, -1, i64::MIN] {
            let got = mainnet_retarget(BITS, actual);
            assert_eq!(got, quarter, "{actual} seconds");
        }
        let above = mainnet_retarget(BITS, TWO_WEEKS / 2);
        assert_ne!(above, quarter);
        println!("a quarter -> {quarter:#010x}, a half -> {above:#010x}");
    }

    #[test]
    fn a_span_at_or_above_four_periods_is_read_as_four() {
        // Red if the high clamp is missing or uses the wrong multiple: four
        // times the period and one second more must give the same bits, and
        // two times it must not.
        const BITS: u32 = 0x1c38_7f6f;
        let four = mainnet_retarget(BITS, TWO_WEEKS * 4);
        for actual in [TWO_WEEKS * 4 + 1, i64::MAX] {
            let got = mainnet_retarget(BITS, actual);
            assert_eq!(got, four, "{actual} seconds");
        }
        let below = mainnet_retarget(BITS, TWO_WEEKS * 2);
        assert_ne!(below, four);
        println!("four periods -> {four:#010x}, two -> {below:#010x}");
    }

    #[test]
    fn mainnet_holds_its_bits_until_the_last_block_of_the_period() {
        // Red if the boundary test is off by one: the header after height
        // 2014 still claims what 2014 claims, and the header after 2015 is
        // the first that retargets. Six hundred seconds is the spacing, so
        // three hundred is a period that came in at half the time and cannot
        // leave the difficulty where it was.
        let times: Vec<u32> = (0..2016u32)
            .map(|height| 1_500_000_000 + height * 300)
            .collect();
        let headers = timeline(&times, 0x1d00_ffff);
        let next = candidate(1_500_700_000);
        let network = crate::message::Network::Mainnet;
        let ancestors = crate::ancestors::Ancestors::new(&headers[..=2014], &[]);
        let held = super::next_bits(&ancestors, &next, network);
        assert_eq!(held, 0x1d00_ffff);
        let ancestors = crate::ancestors::Ancestors::new(&headers[..=2015], &[]);
        let moved = super::next_bits(&ancestors, &next, network);
        assert_ne!(moved, 0x1d00_ffff);
        println!("after 2014 {held:#010x}, after 2015 {moved:#010x}");
    }

    #[test]
    fn a_period_is_timed_from_the_block_one_short_of_its_length() {
        // Red if the first block of the period is `interval` back from the
        // last instead of `interval - 1`: the span would then cover 2016
        // block intervals and start one block earlier. Heights 2016 to 4031
        // are the second period and run at the spacing, so the right span is
        // 2015 spacings and gives `0x1d00ffde`. A jump of a day sits between
        // heights 2015 and 2016: the wrong span picks it up, runs long, and
        // is held at the limit the chain already claims.
        let times: Vec<u32> = (0..4032u32)
            .map(|height| {
                let time = 1_500_000_000 + height * 600;
                if height < 2016 { time - 86_400 } else { time }
            })
            .collect();
        let headers = timeline(&times, 0x1d00_ffff);
        let next = candidate(1_502_419_200);
        let network = crate::message::Network::Mainnet;
        let ancestors = crate::ancestors::Ancestors::new(&headers[..=4031], &[]);
        let bits = super::next_bits(&ancestors, &next, network);
        assert_eq!(bits, 0x1d00_ffde);
        assert_ne!(bits, 0x1d00_ffff);
        println!("2015 spacings -> {bits:#010x}");
    }

    #[test]
    fn the_two_testnets_scale_the_period_from_opposite_ends_of_it() {
        // Red if `Edge` is read backwards, or if both networks are given the
        // same end: BIP94 (`pow.cpp:67`) has testnet4 scale the period from
        // the target its *first* block claims, so that a min-difficulty
        // block at the end of a period cannot drop the difficulty of the
        // next one, while testnet3 scales from the last block as mainnet
        // does. The first block of this period claims the limit and the
        // last claims something harder, and the period ran exactly the two
        // weeks it was meant to, so the scaling is one to one and each
        // network must answer with the bits of the block it reads.
        const FIRST: u32 = 0x1d00_ffff;
        const LAST: u32 = 0x1c05_a3f4;
        let mut times: Vec<u32> = (0..2016u32)
            .map(|height| 1_500_000_000 + height * 600)
            .collect();
        times[2015] = times[0] + 1_209_600;
        let mut headers = timeline(&times, LAST);
        headers[0] = super::Checked(header(times[0], FIRST));
        let next = candidate(times[2015] + 600);
        let ancestors = crate::ancestors::Ancestors::new(&headers, &[]);
        let testnet4 = super::next_bits(&ancestors, &next, crate::message::Network::Testnet4);
        let testnet3 = super::next_bits(&ancestors, &next, crate::message::Network::Testnet3);
        assert_eq!(testnet4, FIRST);
        assert_eq!(testnet3, LAST);
        assert_ne!(testnet4, testnet3);
        println!("testnet4 {testnet4:#010x}, testnet3 {testnet3:#010x}");
    }

    #[test]
    fn regtest_never_moves_its_bits() {
        // Red if `fPowNoRetargeting` is not read: regtest ends a period
        // every 144 blocks, and a period that came in at a tenth of the
        // spacing would raise the difficulty on any network that retargets.
        let times: Vec<u32> = (0..144u32)
            .map(|height| 1_500_000_000 + height * 60)
            .collect();
        let headers = timeline(&times, 0x207f_ffff);
        let next = candidate(1_500_008_640);
        let network = crate::message::Network::Regtest;
        let ancestors = crate::ancestors::Ancestors::new(&headers[..=143], &[]);
        let bits = super::next_bits(&ancestors, &next, network);
        assert_eq!(bits, 0x207f_ffff);
        println!("after a tenth of a day -> {bits:#010x}");
    }

    #[test]
    fn a_test_network_lets_a_block_more_than_two_spacings_late_claim_the_limit() {
        // Red if the gap is compared with `>=` instead of `>`, or against
        // one spacing instead of two: a candidate exactly two spacings after
        // the header before it must still claim what that header claims, and
        // one second later may claim the limit.
        let headers = timeline(&[1_500_000_000, 1_500_000_600], 0x1b00_0100);
        let network = crate::message::Network::Testnet3;
        let on_time = candidate(1_500_000_600 + 1200);
        let ancestors = crate::ancestors::Ancestors::new(&headers[..=1], &[]);
        let bits = super::next_bits(&ancestors, &on_time, network);
        assert_eq!(bits, 0x1b00_0100);
        let late = candidate(1_500_000_600 + 1201);
        let eased = super::next_bits(&ancestors, &late, network);
        assert_eq!(eased, 0x1d00_ffff);
        println!("two spacings -> {bits:#010x}, one second more -> {eased:#010x}");
    }

    #[test]
    fn a_test_network_walks_back_over_the_blocks_that_claimed_the_limit() {
        // Red if the walk stops at the last header instead of the last one
        // that claimed something other than the limit: heights 1 and 2 are
        // min-difficulty blocks, height 0 holds the difficulty of the
        // period, and that is the one the next header must claim.
        let mut headers = timeline(&[1_500_000_000, 1_500_000_600, 1_500_001_200], 0x1d00_ffff);
        headers[0] = super::Checked(header(1_500_000_000, 0x1b00_0100));
        let network = crate::message::Network::Testnet3;
        let next = candidate(1_500_001_800);
        let ancestors = crate::ancestors::Ancestors::new(&headers[..=2], &[]);
        let bits = super::next_bits(&ancestors, &next, network);
        assert_eq!(bits, 0x1b00_0100);
        println!("past two min-difficulty blocks -> {bits:#010x}");
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
                    matches!(network, crate::message::Network::Regtest),
                    "{network:?}"
                ),
                super::Retarget::Every { .. } => assert!(
                    params.limit.0.leaves_room_for_a_timespan(),
                    "{network:?}: {}",
                    params.limit
                ),
            }
            println!("{network:?}: {}", params.limit);
        }
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
