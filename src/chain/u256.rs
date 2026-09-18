//! A 256-bit unsigned number: Core's `arith_uint256`
//! (`../bitcoin/src/arith_uint256.h:31` at v31.1), as far as a target needs
//! one. What `nBits` decodes to before the limit is asked, or a block hash
//! read as one. The arithmetic is here; what the bits mean is `pow`'s.

const BITS: usize = 256;
const LIMB_BITS: usize = 64;
const LIMBS: usize = BITS / LIMB_BITS;

const _: () = assert!(LIMBS * LIMB_BITS == BITS);
const _: () = assert!(LIMBS * (LIMB_BITS / 8) == crate::chain::block_header::HASH_BYTES);

/// Core's `arith_uint256` (`arith_uint256.h:31`) is eight 32-bit limbs,
/// least significant first. This is four 64-bit limbs, *most* significant
/// first, so that the derived comparison of the array is the comparison of
/// the number: two equal-length arrays compared limb by limb from the top
/// compare as the numbers they spell.
#[derive(PartialEq, PartialOrd)]
pub struct U256([u64; LIMBS]);

impl U256 {
    pub(crate) const ZERO: U256 = U256([0; LIMBS]);

    /// How many bits above the top set one are clear: `u64::leading_zeros`
    /// for the whole number, and `BITS` for zero. Core asks the same of a
    /// target through `arith_uint256::bits()` (`arith_uint256.cpp:172`).
    /// `const`, so a `const` assertion can ask it of a limit.
    pub(crate) const fn leading_zeros(&self) -> u32 {
        let mut zeros = 0;
        let mut index = 0;
        while index < LIMBS {
            let limb = self.0[index];
            zeros += limb.leading_zeros();
            if limb != 0 {
                break;
            }
            index += 1;
        }
        zeros
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
    pub fn from_hash(hash: &crate::chain::block_header::BlockHash) -> U256 {
        let (chunks, rest) = hash.as_bytes().as_chunks::<{ LIMB_BITS / 8 }>();
        assert_eq!(chunks.len(), LIMBS, "a hash is exactly LIMBS limbs");
        assert!(rest.is_empty(), "a hash is whole limbs");
        let mut limbs = [0; LIMBS];
        for (limb, chunk) in limbs.iter_mut().rev().zip(chunks) {
            *limb = u64::from_le_bytes(*chunk);
        }
        U256(limbs)
    }

    /// The limbs as they sit, most significant first. For the constants
    /// `chainparams.cpp` writes out in full, the `powLimit` of each network.
    pub(crate) const fn from_limbs(limbs: [u64; LIMBS]) -> U256 {
        U256(limbs)
    }

    pub(crate) const fn from_u64(value: u64) -> U256 {
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
    pub(crate) fn shl(self, shift: usize) -> U256 {
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
    pub(crate) fn to_be_bytes(&self) -> [u8; crate::chain::block_header::HASH_BYTES] {
        let mut bytes = [0; crate::chain::block_header::HASH_BYTES];
        let (chunks, rest) = bytes.as_chunks_mut::<{ LIMB_BITS / 8 }>();
        assert_eq!(chunks.len(), LIMBS, "a number is exactly LIMBS limbs");
        assert!(rest.is_empty(), "a number is whole limbs");
        for (chunk, limb) in chunks.iter_mut().zip(&self.0) {
            *chunk = limb.to_be_bytes();
        }
        bytes
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
    pub(crate) fn mul_u32(self, factor: u32) -> U256 {
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
    pub(crate) fn div_u32(self, divisor: u32) -> U256 {
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

#[cfg(test)]
mod tests {
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
    fn leading_zeros_counts_down_from_the_top_limb() {
        // Red if the count stops at the first limb, zero or not, or runs on
        // past the first set bit: a top bit in the second limb is 64 clear
        // above it, and zero is all 256.
        assert_eq!(super::U256::ZERO.leading_zeros(), 256);
        assert_eq!(super::U256::from_u64(1).leading_zeros(), 255);
        assert_eq!(super::U256::from_u64(1).shl(191).leading_zeros(), 64);
        assert_eq!(super::U256([1, 0, 0, 0]).leading_zeros(), 63);
        assert_eq!(super::U256([u64::MAX, 0, 0, 0]).leading_zeros(), 0);
        println!("a limb at a time, then the bits of the first that is set");
    }
}
