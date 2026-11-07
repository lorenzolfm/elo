//! Proof of work.

/// The headers of one period. The first header of a period has a height that is a multiple of this.
const PERIOD_HEADERS_COUNT: usize = 2016;

/// The seconds that a period of headers should take: two weeks.
const PERIOD_TIMESPAN_SECONDS: u32 = 14 * 24 * 60 * 60;

/// A period that takes less time counts as this, so a target falls by at most a factor of 4.
const TIMESPAN_SECONDS_MIN: u32 = PERIOD_TIMESPAN_SECONDS / 4;

/// A period that takes more time counts as this, so a target rises by at most a factor of 4.
const TIMESPAN_SECONDS_MAX: u32 = PERIOD_TIMESPAN_SECONDS * 4;

// The divide in the smallest time is exact, so the two factors are the same.
const _: () = assert!(PERIOD_TIMESPAN_SECONDS.is_multiple_of(4));

/// On testnet4, a header more than this many seconds after the header below it has the limit.
const MIN_DIFFICULTY_GAP_SECONDS: u32 = 20 * 60;

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

/// `number` times `timespan_seconds`, over `PERIOD_TIMESPAN_SECONDS`, rounded down, and at most
/// `limit`. The multiply is first, so the divide sees all of the product. The answer can be zero,
/// so it is no `Target`.
fn scaled_up_to(mut number: [u8; 32], timespan_seconds: u32, limit: [u8; 32]) -> [u8; 32] {
    // `high` holds the bytes of the product above the 32. A byte times a `u32`, plus a `high` of at
    // most that `u32`, fits in a `u64`. So no number and no time can overflow.
    let mut high = 0_u64;
    for byte in number.iter_mut().rev() {
        let value = u64::from(*byte) * u64::from(timespan_seconds) + high;
        [.., *byte] = value.to_be_bytes();
        high = value >> 8;
    }
    let divisor = u64::from(PERIOD_TIMESPAN_SECONDS);
    // The answer passes 32 bytes, so it is above each limit.
    if high >= divisor {
        return limit;
    }
    // A remainder is below a `u32`, so with one more byte it fits in a `u64`.
    let mut remainder = high;
    for byte in &mut number {
        let value = (remainder << 8) + u64::from(*byte);
        let quotient = value / divisor;
        // A remainder below `divisor` gives a quotient of one byte, so this drops no bit of it.
        assert!(quotient <= u64::from(u8::MAX));
        [.., *byte] = quotient.to_be_bytes();
        remainder = value % divisor;
    }
    number.min(limit)
}

/// The `bits` of the next period. `bits` give the target to change, and `first_time` and
/// `last_time` are the times of the first and the last header of the period that ends. The target
/// changes by the time between them over `PERIOD_TIMESPAN_SECONDS`, by at most a factor of 4 in
/// each direction, and it stays at most `limit`. Returns nothing if `bits` are no target up to
/// `limit`, or if the answer is zero, which a target below 4 can reach. No header can pass in
/// either case, and each answer is a target.
///
/// This takes `bits`, not a `Target`, and reads them with `limit`. So the limit that bounds the
/// target and the limit that caps the answer cannot differ.
fn retargeted_bits(bits: u32, first_time: u32, last_time: u32, limit: [u8; 32]) -> Option<u32> {
    let target = Target::from_bits(bits, limit)?;
    // A time before `first_time` counts as zero, so it takes the smallest time, as any short time
    // does.
    let timespan_seconds = last_time
        .saturating_sub(first_time)
        .clamp(TIMESPAN_SECONDS_MIN, TIMESPAN_SECONDS_MAX);
    let next = to_bits(scaled_up_to(target.0, timespan_seconds, limit));
    if next == 0 {
        return None;
    }
    // This reads the answer with `from_bits`, not with the code that wrote it.
    assert!(Target::from_bits(next, limit).is_some());
    Some(next)
}

/// The `bits` of the last header of this period that does not have the limit. If each one has the
/// limit, these are the limit. The header above `ancestors` must not start a period. The first
/// header of a period comes from the change of the target, so this does not read below it. So this
/// reads fewer than `PERIOD_HEADERS_COUNT` headers.
fn last_real_bits(ancestors: crate::chain::Ancestors<'_>, limit_bits: u32) -> u32 {
    let height_above = ancestors.height_above();
    assert!(!height_above.is_multiple_of(PERIOD_HEADERS_COUNT));
    let period_first = height_above - height_above % PERIOD_HEADERS_COUNT;
    (period_first..height_above)
        .rev()
        .map(|height| ancestors.at(height).bits)
        .find(|bits| *bits != limit_bits)
        .unwrap_or(limit_bits)
}

/// The `bits` that a header with `time` must have on `ancestors`. Returns nothing if a change of
/// the target has no answer, so no header can pass: a target below 4 fell to zero, or the `bits`
/// that change are no target up to the limit, and a chain does not hold such `bits`. Inside a
/// period this does not read `bits` as a target, so the answer is `bits` from below the header or
/// the limit.
///
/// Regtest has one target. Each header of its chain has the `bits` of the limit, because its
/// genesis has them and no rule gives other `bits`. So it needs no period and no time.
#[must_use = "a dropped answer lets each `bits` pass"]
pub(crate) fn required_bits(
    network: crate::chainparams::Network,
    ancestors: crate::chain::Ancestors<'_>,
    time: u32,
) -> Option<u32> {
    let limit = network.pow_limit();
    let height_above = ancestors.height_above();
    let last = ancestors.at(height_above - 1);
    let period_ends = height_above.is_multiple_of(PERIOD_HEADERS_COUNT);
    match network {
        // `extend` checks the `bits` of a header before the rule reads that header, so peer bytes
        // cannot reach this assert.
        crate::chainparams::Network::Regtest => {
            assert_eq!(last.bits, to_bits(limit));
            Some(last.bits)
        }
        crate::chainparams::Network::Mainnet | crate::chainparams::Network::Signet => {
            if period_ends {
                let first = ancestors.at(height_above - PERIOD_HEADERS_COUNT);
                retargeted_bits(last.bits, first.time, last.time, limit)
            } else {
                Some(last.bits)
            }
        }
        // The first header of a period cannot have the limit by a late time, so its `bits` are the
        // real ones. The last header of a period can.
        crate::chainparams::Network::Testnet4 => {
            if period_ends {
                let first = ancestors.at(height_above - PERIOD_HEADERS_COUNT);
                retargeted_bits(first.bits, first.time, last.time, limit)
            } else if time.saturating_sub(last.time) > MIN_DIFFICULTY_GAP_SECONDS {
                Some(to_bits(limit))
            } else {
                Some(last_real_bits(ancestors, to_bits(limit)))
            }
        }
    }
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
    /// second `u32` that a peer picks, so it is the first time. Regtest has the highest limit, so
    /// only it reaches a product above 32 bytes.
    pub(crate) fn retarget_check(header: &crate::block::BlockHeader) {
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Signet,
            crate::chainparams::Network::Regtest,
        ] {
            let limit = network.pow_limit();
            let next = super::retargeted_bits(header.bits, header.nonce, header.time, limit);
            match super::Target::from_bits(header.bits, limit) {
                None => assert_eq!(next, None),
                // Only a target below 4 can have no answer.
                Some(super::Target([high @ .., low])) => {
                    assert!(next.is_some() || (high == [0; 31] && low < 4));
                }
            }
        }
    }

    /// A peer picks each `bits` and each `time` of `headers`, so each header goes through the rule
    /// of each network, as the header above the ones before it. The rule must return for any value,
    /// apart from one case: on regtest it asserts that the header below has the limit, because a
    /// chain holds no other `bits`. So on regtest this stops at a header with other `bits`. A batch
    /// has fewer headers than a period, so no period ends here, and a period that ends would fail
    /// the assert on mainnet. These checks do not repeat the walk of testnet4: its answer must only
    /// be the limit or `bits` from below the header.
    pub(crate) fn required_bits_check(headers: &[crate::block::BlockHeader]) {
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
            crate::chainparams::Network::Regtest,
        ] {
            let genesis = network.genesis();
            for (index, header) in headers.iter().enumerate() {
                let batch = &headers[..index];
                let ancestors = crate::chain::Ancestors {
                    below_tip: &[],
                    tip: &genesis,
                    batch,
                };
                let required = super::required_bits(network, ancestors, header.time);
                let last_bits = batch.last().unwrap_or(&genesis).bits;
                match network {
                    crate::chainparams::Network::Regtest => {
                        assert_eq!(required, Some(genesis.bits));
                        if header.bits != genesis.bits {
                            break;
                        }
                    }
                    crate::chainparams::Network::Mainnet | crate::chainparams::Network::Signet => {
                        assert_eq!(required, Some(last_bits));
                    }
                    crate::chainparams::Network::Testnet4 => {
                        assert!(required.is_some_and(|required| {
                            required == genesis.bits
                                || batch.iter().any(|below| below.bits == required)
                        }));
                    }
                }
            }
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
    fn retargeted_bits_refuse_an_answer_of_zero() {
        let limit = crate::chainparams::Network::Mainnet.pow_limit();
        // The time is the smallest, so the answer is a quarter of the target, rounded down.
        for (bits, expected) in [(0x0103_0000, None), (0x0104_0000, Some(0x0101_0000))] {
            assert_eq!(
                super::retargeted_bits(bits, 1_000_000, 1_000_000, limit),
                expected,
                "{bits:#010x}"
            );
        }
    }

    #[test]
    fn the_largest_change_of_a_limit_is_four_times_it() {
        // These answers are from big integers, not from this code. The cap is above each one, so it
        // hides no wrong answer.
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
                super::scaled_up_to(network.pow_limit(), super::TIMESPAN_SECONDS_MAX, [0xff; 32]),
                number(expected),
                "{network:?}"
            );
        }
    }

    #[test]
    fn retargeted_bits_keep_a_product_above_32_bytes() {
        // These answers are from big integers, not from this code.
        let limit = crate::chainparams::Network::Regtest.pow_limit();
        for (bits, last_time, expected) in [
            // The product passes 32 bytes, but the answer does not.
            (0x207f_ffff, 1_302_400, 0x201f_ffff),
            // The answer also passes 32 bytes, so it takes the limit.
            (0x207f_ffff, 5_838_400, 0x207f_ffff),
            // The answer is exactly 2^256: the smallest number above 32 bytes.
            (0x2040_0000, 5_838_400, 0x207f_ffff),
        ] {
            assert_eq!(
                super::retargeted_bits(bits, 1_000_000, last_time, limit),
                Some(expected),
                "{bits:#010x} {last_time}"
            );
        }
    }

    /// `count` headers with `bits`, each 600 seconds after the header before it.
    fn headers(count: u32, bits: u32) -> Vec<crate::block::BlockHeader> {
        (0..count)
            .map(|index| crate::block::BlockHeader {
                time: 600 * index,
                bits,
                ..crate::chainparams::Network::Regtest.genesis()
            })
            .collect()
    }

    /// `chain` as the headers below one header. The rule reads each part the same way.
    fn ancestors(chain: &[crate::block::BlockHeader]) -> crate::chain::Ancestors<'_> {
        let (tip, batch) = chain.split_first().unwrap();
        crate::chain::Ancestors {
            below_tip: &[],
            tip,
            batch,
        }
    }

    const REAL_BITS: u32 = 0x1c7f_ffff;
    const LOW_BITS: u32 = 0x1b1f_ffff;

    #[test]
    fn required_bits_keep_the_last_bits_inside_a_period() {
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Signet,
        ] {
            for count in [1, 2015, 2017] {
                let mut chain = headers(count, REAL_BITS);
                chain.last_mut().unwrap().bits = LOW_BITS;
                // A late time changes nothing on these networks.
                assert_eq!(
                    super::required_bits(network, ancestors(&chain), u32::MAX),
                    Some(LOW_BITS),
                    "{network:?} {count}"
                );
            }
        }
    }

    #[test]
    fn required_bits_read_the_end_of_a_period_in_a_batch() {
        // A sync in full batches ends each batch at an even height, and the last header of a period
        // has an odd height. So that header is always in the batch, and this reads it there. The
        // answer is from big integers, not from this code.
        let chain = headers(2016, REAL_BITS);
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
        ] {
            assert_eq!(
                super::required_bits(network, ancestors(&chain), u32::MAX),
                Some(0x1c7f_efbd),
                "{network:?}"
            );
        }
    }

    #[test]
    fn required_bits_on_testnet4_take_the_limit_after_a_late_time() {
        let network = crate::chainparams::Network::Testnet4;
        let limit_bits = network.genesis().bits;
        let chain = headers(2, REAL_BITS);
        let last_time = chain[1].time;
        for (time, expected) in [
            (last_time + 1201, limit_bits),
            (last_time + 1200, REAL_BITS),
            // A time that goes back is not late.
            (last_time - 1, REAL_BITS),
        ] {
            assert_eq!(
                super::required_bits(network, ancestors(&chain), time),
                Some(expected),
                "{time}"
            );
        }
    }

    #[test]
    fn required_bits_on_testnet4_go_back_to_the_last_real_bits() {
        let network = crate::chainparams::Network::Testnet4;
        let limit_bits = network.genesis().bits;
        // Each case gives the `bits` from height 0. The time is not late, so the rule goes back.
        let last_of_period = {
            let mut bits = vec![limit_bits; 2015];
            bits[2014] = REAL_BITS;
            bits
        };
        let start_of_period_real = {
            let mut bits = vec![limit_bits; 2100];
            bits[2016] = REAL_BITS;
            bits
        };
        let start_of_period_at_limit = {
            let mut bits = vec![REAL_BITS; 2100];
            bits[2016..].fill(limit_bits);
            bits
        };
        for (name, bits, expected) in [
            ("the last", vec![limit_bits, REAL_BITS], REAL_BITS),
            (
                "below two",
                vec![limit_bits, REAL_BITS, limit_bits, limit_bits],
                REAL_BITS,
            ),
            (
                "the nearest",
                vec![limit_bits, LOW_BITS, REAL_BITS, limit_bits],
                REAL_BITS,
            ),
            ("only the limit", vec![limit_bits, limit_bits], limit_bits),
            ("end of the period", last_of_period, REAL_BITS),
            (
                "to the first of the period",
                start_of_period_real,
                REAL_BITS,
            ),
            // The real `bits` below the period do not count.
            ("not below the period", start_of_period_at_limit, limit_bits),
        ] {
            let chain: Vec<_> = bits
                .into_iter()
                .map(|bits| crate::block::BlockHeader {
                    bits,
                    ..network.genesis()
                })
                .collect();
            let last_time = chain.last().unwrap().time;
            assert_eq!(
                super::required_bits(network, ancestors(&chain), last_time),
                Some(expected),
                "{name}"
            );
        }
    }

    #[test]
    fn required_bits_on_regtest_are_the_limit_at_each_height() {
        let network = crate::chainparams::Network::Regtest;
        let limit_bits = network.genesis().bits;
        // A period ends at 2016, and the math that changes a target gives other `bits` there.
        for count in [1, 2015, 2016] {
            assert_eq!(
                super::required_bits(network, ancestors(&headers(count, limit_bits)), u32::MAX),
                Some(limit_bits),
                "{count}"
            );
        }
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
