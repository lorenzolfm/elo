//! Proof of work.

/// The seconds that a period of headers should take: two weeks.
const PERIOD_TIMESPAN_SECONDS: u32 = 14 * 24 * 60 * 60;

/// A period that takes less time counts as this, so a target falls by at most a factor of 4.
const TIMESPAN_SECONDS_MIN: u32 = PERIOD_TIMESPAN_SECONDS / 4;

/// A period that takes more time counts as this, so a target rises by at most a factor of 4.
const TIMESPAN_SECONDS_MAX: u32 = PERIOD_TIMESPAN_SECONDS * 4;

// The divide in the smallest time is exact, so the two factors are the same.
const _: () = assert!(PERIOD_TIMESPAN_SECONDS.is_multiple_of(4));

/// The highest hash that a header may have. The bytes are big-endian, so the order of two arrays is
/// the order of their numbers. Only `from_bits` makes one, so it is above zero and at most the
/// limit that `from_bits` got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target([u8; 32]);

impl Target {
    /// Reads the compact form `bits`. Its first byte is the size of the number in bytes. Its other
    /// three bytes are the first bytes of the number, so a number of fewer than three bytes uses
    /// only the first of them. The first bit after the size byte is a sign. Returns nothing for a
    /// number that is negative, is zero, does not fit in 32 bytes, or is above `limit`. A peer
    /// picks `bits`, so no value may panic.
    fn from_bits(bits: u32, limit: [u8; 32]) -> Option<Target> {
        let [size, high, middle, low] = bits.to_be_bytes();
        if high & 0x80 != 0 {
            return None;
        }
        let mut target = [0; 32];
        for (word_index, byte) in [high, middle, low].into_iter().enumerate() {
            match (target.len() + word_index).checked_sub(usize::from(size)) {
                // An index past the end is after the last byte of the number, so the number does
                // not use this byte.
                Some(target_index) => {
                    if let Some(place) = target.get_mut(target_index) {
                        *place = byte;
                    }
                }
                // Before the first byte of the target, only a zero fits.
                None if byte == 0 => {}
                None => return None,
            }
        }
        if target == [0; 32] {
            return None;
        }
        // A size of 0 or above 34 keeps no byte of the word, so it gives a target of zero.
        assert!(size >= 1);
        assert!(usize::from(size) <= target.len() + 2);
        if target > limit {
            return None;
        }
        Some(Target(target))
    }

    /// `hash` is in wire order: the reverse of the order of a target.
    fn is_met_by(self, hash: bitcoin_hashes::sha256d::Hash) -> bool {
        assert_ne!(self.0, [0; 32]);
        let mut hash_big_endian = hash.to_byte_array();
        hash_big_endian.reverse();
        hash_big_endian <= self.0
    }
}

/// The compact form of `number`, as `Target::from_bits` reads it. Only the first three bytes of the
/// number stay. A first byte with its top bit set would read as the sign, so it moves one byte
/// down and the size goes up by one. A number of zero gives zero, so `number` is no `Target`.
fn to_bits(number: [u8; 32]) -> u32 {
    let mut size = 32_u8;
    let mut rest = number.as_slice();
    while let [0, after_zero @ ..] = rest {
        size -= 1;
        rest = after_zero;
    }
    assert_eq!(usize::from(size), rest.len());
    let (high, middle, low) = match *rest {
        [high, middle, low, ..] => (high, middle, low),
        [high, middle] => (high, middle, 0),
        [high] => (high, 0, 0),
        [] => (0, 0, 0),
    };
    if high & 0x80 != 0 {
        u32::from_be_bytes([size + 1, 0, high, middle])
    } else {
        u32::from_be_bytes([size, high, middle, low])
    }
}

/// `number` times `factor`, over `divisor`, rounded down. The multiply is first, so the divide sees
/// all of the product. The product must fit in 32 bytes. The answer can be zero or above a limit,
/// so it is no `Target`.
fn scaled(mut number: [u8; 32], factor: u32, divisor: u32) -> [u8; 32] {
    // A byte times a `u32`, plus a carry of at most that `u32`, fits in a `u64`.
    let mut carry = 0_u64;
    for byte in number.iter_mut().rev() {
        let value = u64::from(*byte) * u64::from(factor) + carry;
        [.., *byte] = value.to_be_bytes();
        carry = value >> 8;
    }
    assert_eq!(carry, 0, "the product must fit in 32 bytes");
    // A remainder is below a `u32`, so with one more byte it fits in a `u64`.
    let divisor = u64::from(divisor);
    let mut remainder = 0_u64;
    for byte in &mut number {
        let value = (remainder << 8) + u64::from(*byte);
        let quotient = value / divisor;
        // A remainder below `divisor` gives a quotient of one byte, so this drops no bit of it.
        assert!(quotient <= u64::from(u8::MAX));
        [.., *byte] = quotient.to_be_bytes();
        remainder = value % divisor;
    }
    number
}

/// The `bits` of the next period. `bits` give the target to change, and `first_time` and
/// `last_time` are the times of the first and the last header of the period that ends. The target
/// changes by the time between them over `PERIOD_TIMESPAN_SECONDS`, by at most a factor of 4 in
/// each direction, and it stays at most `limit`. A target below 4 can become zero, and that gives
/// `bits` of zero. Returns nothing if `bits` are no target up to `limit`.
///
/// At the largest change, `limit` times the time must fit in 32 bytes. Regtest does not fit.
///
/// This takes `bits`, not a `Target`, and reads them with `limit`. So the limit that bounds the
/// target and the limit that caps the answer cannot differ.
#[cfg_attr(
    not(any(test, fuzzing)),
    expect(dead_code, reason = "until the exact `bits` check calls it")
)]
fn retargeted_bits(bits: u32, first_time: u32, last_time: u32, limit: [u8; 32]) -> Option<u32> {
    // A test holds that the largest change of the signet limit fits, and a lower limit has a lower
    // product. Without this, a limit that does not fit passes until a peer picks a high target.
    assert!(
        limit <= crate::chainparams::Network::Signet.pow_limit(),
        "the limit is above the highest limit that fits"
    );
    let target = Target::from_bits(bits, limit)?;
    // A time before `first_time` counts as zero, so it takes the smallest time, as any short time
    // does.
    let timespan_seconds = last_time
        .saturating_sub(first_time)
        .clamp(TIMESPAN_SECONDS_MIN, TIMESPAN_SECONDS_MAX);
    let next = to_bits(scaled(target.0, timespan_seconds, PERIOD_TIMESPAN_SECONDS).min(limit));
    // This reads the answer with `from_bits`, not with the code that wrote it. Zero is the one
    // answer that is no target.
    if next != 0 {
        assert!(Target::from_bits(next, limit).is_some());
    }
    Some(next)
}

/// The hash of `header`, if its `bits` are a target in the range of `network` and the hash is at
/// most that target.
#[must_use = "a dropped answer lets each header pass"]
pub(crate) fn proven_hash(
    header: &crate::block::BlockHeader,
    network: crate::chainparams::Network,
) -> Option<bitcoin_hashes::sha256d::Hash> {
    let target = Target::from_bits(header.bits, network.pow_limit())?;
    let hash = header.hash();
    target.is_met_by(hash).then_some(hash)
}

/// `header` with the first `nonce` that gives a hash below the regtest target, whatever its `bits`
/// are. A top byte below 0x7f is below that target, so about every second nonce passes. The top
/// byte of a hash is its last byte in wire order. This does not call the check above, so a check
/// that reads the wrong byte refuses these headers. Only the tests and the fuzz script call this.
#[cfg(any(test, fuzzing))]
// Only cargo-mutants reads this attribute.
#[cfg_attr(false, mutants::skip)]
pub(crate) fn mined_for_regtest(header: crate::block::BlockHeader) -> crate::block::BlockHeader {
    let mined = (0..=u32::MAX)
        .map(|nonce| crate::block::BlockHeader { nonce, ..header })
        .find(|header| header.hash().as_byte_array()[31] < 0x7f);
    let Some(mined) = mined else {
        panic!("no nonce mines {header:?}");
    };
    mined
}

#[cfg(fuzzing)]
// Only cargo-mutants reads this attribute. Its test runs do not build this module.
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    /// A peer picks each field of `header`, so its `bits` and its times go through the change of a
    /// target, whose asserts must hold for any value. A header has one time, and `nonce` gives a
    /// second `u32` that a peer picks, so it is the first time. Signet has the highest limit of a
    /// network that changes its target, so it is the nearest to an overflow.
    pub(crate) fn retarget_check(header: &crate::block::BlockHeader) {
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Signet,
        ] {
            let limit = network.pow_limit();
            let next = super::retargeted_bits(header.bits, header.nonce, header.time, limit);
            let target = super::Target::from_bits(header.bits, limit);
            assert_eq!(next.is_some(), target.is_some());
        }
    }
}

#[cfg(test)]
mod tests {
    /// A target from its 32 bytes in hex.
    fn target(s: &str) -> super::Target {
        super::Target(crate::fixtures::hex(s).try_into().unwrap())
    }

    #[test]
    fn from_bits_reads_the_compact_form() {
        // The limit is above each target, so only the compact form can refuse.
        let limit = [0xff; 32];
        let cases = [
            // A size of three bytes or fewer. The sign bit is not a bit of the number.
            (
                0x0112_3456,
                "0000000000000000000000000000000000000000000000000000000000000012",
            ),
            (
                0x0200_8000,
                "0000000000000000000000000000000000000000000000000000000000000080",
            ),
            (
                0x0212_3456,
                "0000000000000000000000000000000000000000000000000000000000001234",
            ),
            (
                0x0312_3456,
                "0000000000000000000000000000000000000000000000000000000000123456",
            ),
            // A size above three bytes.
            (
                0x0412_3456,
                "0000000000000000000000000000000000000000000000000000000012345600",
            ),
            (
                0x0500_9234,
                "0000000000000000000000000000000000000000000000000000000092340000",
            ),
            (
                0x2012_3456,
                "1234560000000000000000000000000000000000000000000000000000000000",
            ),
            // At the top of the target: the size may pass 32 only by the zeros at the word's start.
            (
                0x2100_ffff,
                "ffff000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                0x2200_00ff,
                "ff00000000000000000000000000000000000000000000000000000000000000",
            ),
        ];
        for (bits, expected) in cases {
            assert_eq!(
                super::Target::from_bits(bits, limit),
                Some(target(expected)),
                "{bits:#010x}"
            );
        }
    }

    #[test]
    fn from_bits_refuses_zero_and_negative_and_what_does_not_fit() {
        // The limit is above each target, so only the compact form can refuse.
        let limit = [0xff; 32];
        let cases = [
            // Zero: the word is zero, or it has no byte that the size keeps.
            0x0000_0000,
            0x0012_3456,
            0x0100_3456,
            0x0200_0056,
            0x0300_0000,
            0x0400_0000,
            // Zero with the sign bit.
            0x0092_3456,
            0x0180_3456,
            0x0280_0056,
            0x0380_0000,
            0x0480_0000,
            // Negative, with a number that is not zero.
            0x01fe_dcba,
            0x0492_3456,
            // At the top of the target: another byte of the word is not zero, so only the fit
            // refuses it.
            0x2101_0001,
            0x2200_0101,
            // No byte of the word fits.
            0x2300_0001,
            0xff12_3456,
        ];
        for bits in cases {
            assert_eq!(super::Target::from_bits(bits, limit), None, "{bits:#010x}");
        }
    }

    #[test]
    fn hash_meets_a_target_at_or_above_it() {
        let target = target("00000377ae000000000000000000000000000000000000000000000000000000");
        let cases = [
            (
                "00000377adffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                true,
            ),
            (
                "00000377ae000000000000000000000000000000000000000000000000000000",
                true,
            ),
            (
                "00000377ae000000000000000000000000000000000000000000000000000001",
                false,
            ),
        ];
        for (hash, expected) in cases {
            assert_eq!(
                target.is_met_by(crate::fixtures::hash_from_display_hex(hash)),
                expected,
                "{hash}"
            );
        }
    }

    #[test]
    fn pow_limit_is_between_the_highest_bits_in_range_and_the_next_bits() {
        for (network, bits_in_range, bits_above) in [
            (
                crate::chainparams::Network::Mainnet,
                0x1d00_ffff,
                0x1d01_0000,
            ),
            (
                crate::chainparams::Network::Testnet4,
                0x1d00_ffff,
                0x1d01_0000,
            ),
            // These `bits` are exactly the limit.
            (
                crate::chainparams::Network::Signet,
                0x1e03_77ae,
                0x1e03_77af,
            ),
            (
                crate::chainparams::Network::Regtest,
                0x207f_ffff,
                0x2100_8000,
            ),
        ] {
            let limit = network.pow_limit();
            assert!(
                super::Target::from_bits(bits_in_range, limit).is_some(),
                "{network:?}"
            );
            assert_eq!(
                super::Target::from_bits(bits_above, limit),
                None,
                "{network:?}"
            );
        }
    }

    /// 32 bytes from hex.
    fn number(s: &str) -> [u8; 32] {
        crate::fixtures::hex(s).try_into().unwrap()
    }

    #[test]
    fn to_bits_writes_the_compact_form() {
        let cases = [
            (
                "0000000000000000000000000000000000000000000000000000000000000000",
                0x0000_0000,
            ),
            // One or two bytes: the bytes after the number are zero.
            (
                "0000000000000000000000000000000000000000000000000000000000000012",
                0x0112_0000,
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000001234",
                0x0212_3400,
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000123456",
                0x0312_3456,
            ),
            // Only the first three bytes stay.
            (
                "0000000000000000000000000000000000000000000000000000000012345678",
                0x0412_3456,
            ),
            // A first byte with its top bit set moves one byte down.
            (
                "0000000000000000000000000000000000000000000000000000000000000080",
                0x0200_8000,
            ),
            (
                "0000000000000000000000000000000000000000000000000000000000008012",
                0x0300_8012,
            ),
            (
                "0000000000000000000000000000000000000000000000000000000092345678",
                0x0500_9234,
            ),
            // The whole width.
            (
                "1234560000000000000000000000000000000000000000000000000000000000",
                0x2012_3456,
            ),
            (
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                0x2100_ffff,
            ),
        ];
        for (hex, expected) in cases {
            assert_eq!(super::to_bits(number(hex)), expected, "{hex}");
        }
    }

    #[test]
    fn to_bits_of_each_limit_is_the_bits_of_its_genesis() {
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
            crate::chainparams::Network::Regtest,
        ] {
            assert_eq!(
                super::to_bits(network.pow_limit()),
                network.genesis().bits,
                "{network:?}"
            );
        }
    }

    /// Each row has a name, `bits`, the first time, the last time and the answer on the mainnet
    /// limit.
    fn assert_retargets(cases: &[(&str, u32, u32, u32, u32)]) {
        let limit = crate::chainparams::Network::Mainnet.pow_limit();
        for &(name, bits, first_time, last_time, expected) in cases {
            assert_eq!(
                super::retargeted_bits(bits, first_time, last_time, limit),
                Some(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn retargeted_bits_match_real_retargets() {
        // These come from `pow_tests.cpp` of Bitcoin Core: real mainnet retargets, but the first
        // time of the last row is not a real block time.
        assert_retargets(&[
            ("no bound", 0x1d00_ffff, 1261130161, 1262152739, 0x1d00_d86a),
            (
                "the limit",
                0x1d00_ffff,
                1231006505,
                1233061996,
                0x1d00_ffff,
            ),
            (
                "the smallest time",
                0x1c05_a3f4,
                1279008237,
                1279297671,
                0x1c01_68fd,
            ),
            (
                "the largest time",
                0x1c38_7f6f,
                1263163443,
                1269211443,
                0x1d00_e1fd,
            ),
        ]);
    }

    #[test]
    fn retargeted_bits_change_with_the_time_of_the_period() {
        assert_retargets(&[
            // At a bound, a second inside it changes the answer and a second outside it does not.
            (
                "below a quarter",
                0x1c7f_ffff,
                1_000_000,
                1_302_399,
                0x1c1f_ffff,
            ),
            ("a quarter", 0x1c7f_ffff, 1_000_000, 1_302_400, 0x1c1f_ffff),
            (
                "above a quarter",
                0x1c7f_ffff,
                1_000_000,
                1_302_401,
                0x1c20_0006,
            ),
            (
                "below four times",
                0x1b1f_ffff,
                1_000_000,
                5_838_399,
                0x1b7f_fffa,
            ),
            ("four times", 0x1b1f_ffff, 1_000_000, 5_838_400, 0x1b7f_fffc),
            (
                "above four times",
                0x1b1f_ffff,
                1_000_000,
                5_838_401,
                0x1b7f_fffc,
            ),
            ("the same", 0x1c04_0000, 1_000_000, 2_209_600, 0x1c04_0000),
            // A time that goes back counts as a short time.
            ("back", 0x1c7f_ffff, 1_302_401, 1_000_000, 0x1c1f_ffff),
            // The multiply is first: a divide first gives zero.
            ("one", 0x0101_0000, 1_000_000, 2_209_600, 0x0101_0000),
            // The answer can be zero.
            ("zero", 0x0101_0000, 1_000_000, 1_000_000, 0),
        ]);
    }

    #[test]
    fn retargeted_bits_refuse_what_is_no_target_up_to_the_limit() {
        let limit = crate::chainparams::Network::Mainnet.pow_limit();
        for bits in [0, 0x1d01_0000] {
            assert_eq!(
                super::retargeted_bits(bits, 1_000_000, 2_209_600, limit),
                None,
                "{bits:#010x}"
            );
        }
    }

    #[test]
    fn the_largest_change_of_each_limit_that_changes_fits() {
        // These products are from big integers, not from this code.
        let mainnet = "00000003fffffffffffffffffffffffffffffffffffffffffffffffffffffffc";
        for (network, expected) in [
            (crate::chainparams::Network::Mainnet, mainnet),
            (crate::chainparams::Network::Testnet4, mainnet),
            (
                crate::chainparams::Network::Signet,
                "00000ddeb8000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            assert_eq!(
                super::scaled(
                    network.pow_limit(),
                    super::TIMESPAN_SECONDS_MAX,
                    super::PERIOD_TIMESPAN_SECONDS
                ),
                number(expected),
                "{network:?}"
            );
        }
    }

    #[test]
    #[should_panic(expected = "the product must fit in 32 bytes")]
    fn the_largest_change_of_the_regtest_limit_does_not_fit() {
        super::scaled(
            crate::chainparams::Network::Regtest.pow_limit(),
            super::TIMESPAN_SECONDS_MAX,
            super::PERIOD_TIMESPAN_SECONDS,
        );
    }

    #[test]
    #[should_panic(expected = "the limit is above the highest limit that fits")]
    fn a_limit_that_does_not_fit_panics_with_a_low_target() {
        // The product of this target fits, so only the check of the limit can panic.
        super::retargeted_bits(
            0x1d00_ffff,
            1_000_000,
            2_209_600,
            crate::chainparams::Network::Regtest.pow_limit(),
        );
    }

    #[test]
    fn each_genesis_has_proof_of_work() {
        // Real headers, so this also shows the byte order of the hash: in wire order, each hash
        // but the regtest one starts with bytes above its target.
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
            crate::chainparams::Network::Regtest,
        ] {
            let genesis = network.genesis();
            assert_eq!(
                super::proven_hash(&genesis, network),
                Some(genesis.hash()),
                "{network:?}"
            );
        }
    }
}
