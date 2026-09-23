const BITS: usize = 256;
const LIMB_BITS: usize = 64;
const LIMBS: usize = BITS / LIMB_BITS;

const _: () = assert!(LIMBS * LIMB_BITS == BITS);
const _: () = assert!(LIMBS * (LIMB_BITS / 8) == crate::chain::block_header::HASH_BYTES);

#[derive(PartialEq, PartialOrd)]
pub struct U256([u64; LIMBS]);

impl U256 {
    pub(crate) const ZERO: U256 = U256([0; LIMBS]);

    pub(crate) const ONE: U256 = U256::from_u64(1);

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

    pub(crate) fn bits(&self) -> usize {
        let Ok(zeros) = usize::try_from(self.leading_zeros()) else {
            unreachable!("a count of at most 256 fits a usize")
        };
        BITS - zeros
    }

    pub(crate) fn not(&self) -> U256 {
        let mut limbs = [0; LIMBS];
        for (out, limb) in limbs.iter_mut().zip(&self.0) {
            *out = !limb;
        }
        U256(limbs)
    }

    pub(crate) fn checked_add(&self, other: &U256) -> Option<U256> {
        let mut limbs = [0; LIMBS];
        let mut carry = 0;
        for ((out, mine), theirs) in limbs
            .iter_mut()
            .rev()
            .zip(self.0.iter().rev())
            .zip(other.0.iter().rev())
        {
            let (sum, wrapped) = mine.overflowing_add(*theirs);
            let (sum, wrapped_again) = sum.overflowing_add(carry);
            *out = sum;
            carry = u64::from(wrapped || wrapped_again);
        }
        if carry == 0 { Some(U256(limbs)) } else { None }
    }

    fn sub(&self, other: &U256) -> U256 {
        assert!(self >= other, "a subtraction below zero");
        let mut limbs = [0; LIMBS];
        let mut borrow = 0;
        for ((out, mine), theirs) in limbs
            .iter_mut()
            .rev()
            .zip(self.0.iter().rev())
            .zip(other.0.iter().rev())
        {
            let (rest, wrapped) = mine.overflowing_sub(*theirs);
            let (rest, wrapped_again) = rest.overflowing_sub(borrow);
            *out = rest;
            borrow = u64::from(wrapped || wrapped_again);
        }
        assert_eq!(borrow, 0, "the comparison above left no borrow");
        U256(limbs)
    }

    pub(crate) fn shr(&self, shift: usize) -> U256 {
        assert!(shift < BITS, "a shift of {shift} clears every bit");
        let whole = shift / LIMB_BITS;
        let part = shift % LIMB_BITS;
        let mut limbs = [0; LIMBS];
        for (from, limb) in self.0.iter().enumerate() {
            let to = from + whole;
            if let Some(out) = limbs.get_mut(to) {
                *out |= limb >> part;
            }
            if part != 0
                && let Some(out) = limbs.get_mut(to + 1)
            {
                *out |= limb << (LIMB_BITS - part);
            }
        }
        U256(limbs)
    }

    pub(crate) fn div(&self, divisor: &U256) -> U256 {
        assert!(divisor != &U256::ZERO, "a division by zero");
        let divisor_bits = divisor.bits();
        let Some(mut shift) = self.bits().checked_sub(divisor_bits) else {
            return U256::ZERO;
        };
        let mut rest = U256(self.0);
        let mut shifted = U256(divisor.0).shl(shift);
        let mut limbs = [0; LIMBS];
        loop {
            if rest >= shifted {
                rest = rest.sub(&shifted);
                limbs[LIMBS - 1 - shift / LIMB_BITS] |= 1 << (shift % LIMB_BITS);
            }
            if shift == 0 {
                break;
            }
            shifted = shifted.shr(1);
            shift -= 1;
        }
        assert!(&rest < divisor, "a remainder is below the divisor");
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
    fn not_flips_every_bit() {
        // Red if the complement walks the limbs in the wrong order or stops
        // early: the complement of zero is every bit set, and the two are a
        // pair.
        assert_eq!(super::U256::ZERO.not().0, [u64::MAX; 4]);
        assert_eq!(super::U256([u64::MAX; 4]).not().0, [0; 4]);
        let one = super::U256::ONE;
        assert_eq!(one.not().0, [u64::MAX, u64::MAX, u64::MAX, u64::MAX - 1]);
        assert_eq!(one.not().not().0, one.0, "the complement of a complement");
        println!("{}", super::U256::ONE.not());
    }

    #[test]
    fn an_addition_carries_into_the_limb_above() {
        // Red if the carry is dropped or lands one limb off: a full low limb
        // plus one is the limb above, and the carry runs the whole width.
        let low_full = super::U256([0, 0, 0, u64::MAX]);
        let carried = low_full.checked_add(&super::U256::ONE).unwrap();
        assert_eq!(carried.0, [0, 0, 1, 0]);
        let all_but_top = super::U256([0, u64::MAX, u64::MAX, u64::MAX]);
        let over = all_but_top.checked_add(&super::U256::ONE).unwrap();
        assert_eq!(over.0, [1, 0, 0, 0], "the carry crossed three limbs");
        println!("{low_full} + 1 = {carried}");
    }

    #[test]
    fn an_addition_past_the_width_is_none() {
        // Red if a sum past 256 bits wraps in silence instead of saying so.
        let full = super::U256([u64::MAX; 4]);
        assert!(full.checked_add(&super::U256::ONE).is_none());
        assert!(full.checked_add(&full).is_none());
        assert!(
            full.checked_add(&super::U256::ZERO).is_some(),
            "nothing added still fits"
        );
        println!("{full} + 1 does not fit");
    }

    #[test]
    fn a_subtraction_borrows_from_the_limb_above() {
        // Red if the borrow is dropped or taken from the wrong side: one off
        // a limb boundary leaves the limb below full.
        let next_up = super::U256([0, 0, 1, 0]);
        assert_eq!(next_up.sub(&super::U256::ONE).0, [0, 0, 0, u64::MAX]);
        let top = super::U256([1, 0, 0, 0]);
        assert_eq!(
            top.sub(&super::U256::ONE).0,
            [0, u64::MAX, u64::MAX, u64::MAX],
            "the borrow crossed three limbs"
        );
        assert_eq!(top.sub(&top).0, [0; 4], "a number less itself is zero");
        println!("{next_up} - 1 = {}", next_up.sub(&super::U256::ONE));
    }

    #[test]
    #[should_panic(expected = "a subtraction below zero")]
    fn a_subtraction_below_zero_is_our_bug() {
        let _ = super::U256::ZERO.sub(&super::U256::ONE);
    }

    #[test]
    fn a_shift_right_carries_the_bits_that_cross_a_limb() {
        // Red if the bits that leave a limb are dropped or land one limb
        // off: the mirror of the left shift, and the two undo each other.
        let down = super::U256([0, 0, 0xff, 0xff00_0000_0000_0000]).shr(56);
        assert_eq!(down.0, [0, 0, 0, 0xffff]);
        let from_the_top = super::U256([1 << 63, 0, 0, 0]).shr(255);
        assert_eq!(from_the_top.0, [0, 0, 0, 1]);
        let whole = super::U256([0x1234, 0, 0, 0]).shr(192);
        assert_eq!(whole.0, [0, 0, 0, 0x1234]);
        let none = super::U256::from_u64(0x1234).shr(0);
        assert_eq!(none.0, [0, 0, 0, 0x1234]);
        println!("{down}\n{from_the_top}\n{whole}");
    }

    #[test]
    #[should_panic(expected = "a shift of 256 clears every bit")]
    fn a_shift_right_of_the_width_is_our_bug() {
        let _ = super::U256::from_u64(1).shr(256);
    }

    #[test]
    fn division_keeps_the_quotient_and_drops_the_remainder() {
        // Red if the shift that aligns the divisor is off by one, if a
        // divisor above the number gives anything but zero, or if the
        // remainder leaks into the quotient.
        let seven = super::U256::from_u64(7);
        let two = super::U256::from_u64(2);
        assert_eq!(seven.div(&two).0, [0, 0, 0, 3], "the remainder is dropped");
        assert_eq!(seven.div(&super::U256::ONE).0, seven.0);
        assert_eq!(seven.div(&seven).0, super::U256::ONE.0);
        assert_eq!(
            two.div(&seven).0,
            super::U256::ZERO.0,
            "a divisor above the number"
        );
        assert_eq!(super::U256::ZERO.div(&seven).0, super::U256::ZERO.0);
        let across = super::U256([0, 0, 1, 0]);
        assert_eq!(
            across.div(&two).0,
            [0, 0, 0, 1 << 63],
            "a quotient that crosses a limb"
        );
        let full = super::U256([u64::MAX; 4]);
        assert_eq!(
            full.div(&two).0,
            [u64::MAX >> 1, u64::MAX, u64::MAX, u64::MAX]
        );
        println!(
            "7 / 2 = {}, 2^64 / 2 = {}",
            seven.div(&two),
            across.div(&two)
        );
    }

    #[test]
    #[should_panic(expected = "a division by zero")]
    fn a_division_by_zero_is_our_bug() {
        let _ = super::U256::ONE.div(&super::U256::ZERO);
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
