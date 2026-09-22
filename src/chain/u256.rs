const BITS: usize = 256;
const LIMB_BITS: usize = 64;
const LIMBS: usize = BITS / LIMB_BITS;

const _: () = assert!(LIMBS * LIMB_BITS == BITS);
const _: () = assert!(LIMBS * (LIMB_BITS / 8) == crate::chain::block_header::HASH_BYTES);

#[derive(PartialEq, PartialOrd)]
pub struct U256([u64; LIMBS]);

impl U256 {
    pub(crate) const ZERO: U256 = U256([0; LIMBS]);

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

    pub(crate) const fn from_limbs(limbs: [u64; LIMBS]) -> U256 {
        U256(limbs)
    }

    pub(crate) const fn from_u64(value: u64) -> U256 {
        let mut limbs = [0; LIMBS];
        limbs[LIMBS - 1] = value;
        U256(limbs)
    }

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

impl std::fmt::Display for U256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for limb in &self.0 {
            write!(f, "{limb:016x}")?;
        }
        Ok(())
    }
}

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
