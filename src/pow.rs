const PERIOD_HEADERS_COUNT: usize = 2016;

const PERIOD_TIMESPAN_SECONDS: u32 = 14 * 24 * 60 * 60;

const TIMESPAN_SECONDS_MIN: u32 = PERIOD_TIMESPAN_SECONDS / 4;

const TIMESPAN_SECONDS_MAX: u32 = PERIOD_TIMESPAN_SECONDS * 4;

const _: () = assert!(PERIOD_TIMESPAN_SECONDS.is_multiple_of(4));

const MIN_DIFFICULTY_GAP_SECONDS: u32 = 20 * 60;

const TIMEWARP_SECONDS_MAX: u32 = 10 * 60;

const _: () = assert!(crate::chainparams::Network::Testnet4.genesis().time > TIMEWARP_SECONDS_MAX);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target([u8; 32]);

impl Target {
    fn from_bits(bits: u32, limit: [u8; 32]) -> Option<Target> {
        let [size, high, middle, low] = bits.to_be_bytes();
        if high & 0x80 != 0 {
            return None;
        }
        let mut target = [0; 32];
        for (word_index, byte) in [high, middle, low].into_iter().enumerate() {
            match (target.len() + word_index).checked_sub(usize::from(size)) {
                Some(target_index) => {
                    if let Some(place) = target.get_mut(target_index) {
                        *place = byte;
                    }
                }
                None if byte == 0 => {}
                None => return None,
            }
        }
        if target == [0; 32] {
            return None;
        }
        assert!(size >= 1);
        assert!(usize::from(size) <= target.len() + 2);
        if target > limit {
            return None;
        }
        Some(Target(target))
    }

    fn is_met_by(self, hash: bitcoin_hashes::sha256d::Hash) -> bool {
        assert_ne!(self.0, [0; 32]);
        let mut hash_big_endian = hash.to_byte_array();
        hash_big_endian.reverse();
        hash_big_endian <= self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Work {
    high: u128,
    low: u128,
}

impl Work {
    pub(crate) const ZERO: Work = Work { high: 0, low: 0 };
    const ONE: Work = Work { high: 0, low: 1 };
    const MAX: Work = Work {
        high: u128::MAX,
        low: u128::MAX,
    };

    fn of(target: Target) -> Work {
        let target = Work::from_be_bytes(target.0);
        assert_ne!(target, Work::ZERO);
        assert_ne!(target, Work::MAX);
        let divisor = target.saturating_add(Work::ONE);
        let inverse = Work {
            high: !target.high,
            low: !target.low,
        };
        let quotient = inverse.divided_by(divisor);
        assert_eq!(quotient.high >> 127, 0);
        quotient.saturating_add(Work::ONE)
    }

    pub(crate) fn saturating_add(self, other: Work) -> Work {
        let (low, carry) = self.low.overflowing_add(other.low);
        let sum = match self
            .high
            .checked_add(other.high)
            .and_then(|high| high.checked_add(u128::from(carry)))
        {
            Some(high) => Work { high, low },
            None => Work::MAX,
        };
        assert!(sum >= self);
        assert!(sum >= other);
        sum
    }

    pub(crate) fn minus(self, other: Work) -> Work {
        assert!(other <= self);
        let (low, borrow) = self.low.overflowing_sub(other.low);
        Work {
            high: self.high - other.high - u128::from(borrow),
            low,
        }
    }

    fn divided_by(self, divisor: Work) -> Work {
        assert_ne!(divisor, Work::ZERO);
        let Some(shift) = divisor.leading_zeros().checked_sub(self.leading_zeros()) else {
            return Work::ZERO;
        };
        let mut step_divisor = divisor.shifted_left(shift);
        let mut remainder = self;
        let mut quotient = Work::ZERO;
        for _ in 0..=shift {
            quotient = quotient.shifted_left(1);
            if remainder >= step_divisor {
                remainder = remainder.minus(step_divisor);
                quotient.low |= 1;
            }
            step_divisor = step_divisor.shifted_right_once();
        }
        assert!(remainder < divisor);
        assert!(quotient <= self);
        quotient
    }

    fn shifted_left(self, bits: u32) -> Work {
        assert!(bits < 256);
        if bits >= 128 {
            Work {
                high: self.low << (bits - 128),
                low: 0,
            }
        } else {
            let low_to_high = self.low.checked_shr(128 - bits).unwrap_or(0);
            Work {
                high: (self.high << bits) + low_to_high,
                low: self.low << bits,
            }
        }
    }

    fn shifted_right_once(self) -> Work {
        Work {
            high: self.high >> 1,
            low: (self.low >> 1) + (self.high << 127),
        }
    }

    fn leading_zeros(self) -> u32 {
        if self.high == 0 {
            128 + self.low.leading_zeros()
        } else {
            self.high.leading_zeros()
        }
    }

    fn from_be_bytes(bytes: [u8; 32]) -> Work {
        bytes.into_iter().fold(Work::ZERO, |number, byte| {
            let shifted = number.shifted_left(8);
            Work {
                low: shifted.low + u128::from(byte),
                ..shifted
            }
        })
    }
}

impl std::fmt::Display for Work {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:032x}{:032x}", self.high, self.low)
    }
}

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

fn scaled_up_to(mut number: [u8; 32], timespan_seconds: u32, limit: [u8; 32]) -> [u8; 32] {
    let mut high = 0_u64;
    for byte in number.iter_mut().rev() {
        let value = u64::from(*byte) * u64::from(timespan_seconds) + high;
        [.., *byte] = value.to_be_bytes();
        high = value >> 8;
    }
    let divisor = u64::from(PERIOD_TIMESPAN_SECONDS);
    if high >= divisor {
        return limit;
    }
    let mut remainder = high;
    for byte in &mut number {
        let value = (remainder << 8) + u64::from(*byte);
        let quotient = value / divisor;
        assert!(quotient <= u64::from(u8::MAX));
        [.., *byte] = quotient.to_be_bytes();
        remainder = value % divisor;
    }
    number.min(limit)
}

fn retargeted_bits(bits: u32, first_time: u32, last_time: u32, limit: [u8; 32]) -> Option<u32> {
    let target = Target::from_bits(bits, limit)?;
    let timespan_seconds = last_time
        .saturating_sub(first_time)
        .clamp(TIMESPAN_SECONDS_MIN, TIMESPAN_SECONDS_MAX);
    let next = to_bits(scaled_up_to(target.0, timespan_seconds, limit));
    if next == 0 {
        return None;
    }
    assert!(Target::from_bits(next, limit).is_some());
    Some(next)
}

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

#[must_use = "a dropped answer lets each `bits` pass"]
pub(crate) fn required_bits(
    network: crate::chainparams::Network,
    ancestors: crate::chain::Ancestors<'_>,
    time: u32,
) -> Option<u32> {
    let limit = network.pow_limit();
    let height_above = ancestors.height_above();
    let last = ancestors.last();
    let period_ends = height_above.is_multiple_of(PERIOD_HEADERS_COUNT);
    match network {
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

#[must_use = "a dropped answer lets each time pass"]
pub(crate) fn timewarp_time_min(
    network: crate::chainparams::Network,
    ancestors: crate::chain::Ancestors<'_>,
) -> u32 {
    match network {
        crate::chainparams::Network::Mainnet
        | crate::chainparams::Network::Signet
        | crate::chainparams::Network::Regtest => 0,
        crate::chainparams::Network::Testnet4 => {
            if ancestors
                .height_above()
                .is_multiple_of(PERIOD_HEADERS_COUNT)
            {
                let last_time = ancestors.last().time;
                let time_min = last_time.saturating_sub(TIMEWARP_SECONDS_MAX);
                assert!(time_min <= last_time);
                time_min
            } else {
                0
            }
        }
    }
}

#[must_use = "a dropped answer lets each `bits` pass"]
pub(crate) fn permits_bits_change(
    network: crate::chainparams::Network,
    height: usize,
    bits_below: u32,
    bits: u32,
) -> bool {
    match network {
        crate::chainparams::Network::Testnet4 | crate::chainparams::Network::Regtest => true,
        crate::chainparams::Network::Mainnet | crate::chainparams::Network::Signet => {
            if !height.is_multiple_of(PERIOD_HEADERS_COUNT) {
                return bits == bits_below;
            }
            let limit = network.pow_limit();
            assert!(Target::from_bits(bits_below, limit).is_some());
            let Some(target) = Target::from_bits(bits, limit) else {
                return false;
            };
            let bound = |last_time| {
                retargeted_bits(bits_below, 0, last_time, limit)
                    .and_then(|bits| Target::from_bits(bits, limit))
            };
            let highest = bound(u32::MAX);
            assert!(highest.is_some());
            if highest.is_some_and(|highest| target.0 <= highest.0) {
                bound(0).is_none_or(|lowest| lowest.0 <= target.0)
            } else {
                false
            }
        }
    }
}

#[must_use = "a dropped answer lets each header pass"]
pub(crate) fn proven(
    header: &crate::block::BlockHeader,
    network: crate::chainparams::Network,
) -> Option<(bitcoin_hashes::sha256d::Hash, Work)> {
    let target = Target::from_bits(header.bits, network.pow_limit())?;
    let hash = header.hash();
    target.is_met_by(hash).then(|| (hash, Work::of(target)))
}

pub(crate) fn work(bits: u32, network: crate::chainparams::Network) -> Option<Work> {
    Target::from_bits(bits, network.pow_limit()).map(Work::of)
}

pub(crate) fn chain_work_min(network: crate::chainparams::Network) -> Work {
    Work::from_be_bytes(network.chain_work_min())
}

#[cfg(any(test, fuzzing))]
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
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
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
                Some(super::Target([high @ .., low])) => {
                    assert!(next.is_some() || (high == [0; 31] && low < 4));
                }
            }
        }
    }

    pub(crate) fn work_check(header: &crate::block::BlockHeader) {
        if let Some(target) = super::Target::from_bits(header.bits, [0xff; 32]) {
            assert!(super::Work::of(target) >= super::Work::ONE);
        }
    }

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
                let ancestors = crate::chain::Ancestors::on_tip(&genesis, batch);
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
    fn target(s: &str) -> super::Target {
        super::Target(crate::fixtures::hex(s).try_into().unwrap())
    }

    #[test]
    fn from_bits_reads_the_compact_form() {
        let limit = [0xff; 32];
        let cases = [
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
        let limit = [0xff; 32];
        let cases = [
            0x0000_0000,
            0x0012_3456,
            0x0100_3456,
            0x0200_0056,
            0x0300_0000,
            0x0400_0000,
            0x0092_3456,
            0x0180_3456,
            0x0280_0056,
            0x0380_0000,
            0x0480_0000,
            0x01fe_dcba,
            0x0492_3456,
            0x2101_0001,
            0x2200_0101,
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
            (
                "0000000000000000000000000000000000000000000000000000000012345678",
                0x0412_3456,
            ),
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
            ("back", 0x1c7f_ffff, 1_302_401, 1_000_000, 0x1c1f_ffff),
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
        let limit = crate::chainparams::Network::Regtest.pow_limit();
        for (bits, last_time, expected) in [
            (0x207f_ffff, 1_302_400, 0x201f_ffff),
            (0x207f_ffff, 5_838_400, 0x207f_ffff),
            (0x2040_0000, 5_838_400, 0x207f_ffff),
        ] {
            assert_eq!(
                super::retargeted_bits(bits, 1_000_000, last_time, limit),
                Some(expected),
                "{bits:#010x} {last_time}"
            );
        }
    }

    fn headers(count: u32, bits: u32) -> Vec<crate::block::BlockHeader> {
        (0..count)
            .map(|index| crate::block::BlockHeader {
                time: 600 * index,
                bits,
                ..crate::chainparams::Network::Regtest.genesis()
            })
            .collect()
    }

    fn ancestors(chain: &[crate::block::BlockHeader]) -> crate::chain::Ancestors<'_> {
        let (tip, batch) = chain.split_first().unwrap();
        crate::chain::Ancestors::on_tip(tip, batch)
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
        for count in [1, 2015, 2016] {
            assert_eq!(
                super::required_bits(network, ancestors(&headers(count, limit_bits)), u32::MAX),
                Some(limit_bits),
                "{count}"
            );
        }
    }

    #[test]
    fn timewarp_bound_stops_at_zero() {
        let mut chain = headers(2016, REAL_BITS);
        for (last_time, expected) in [
            (0, 0),
            (1, 0),
            (599, 0),
            (600, 0),
            (601, 1),
            (u32::MAX, u32::MAX - 600),
        ] {
            chain.last_mut().unwrap().time = last_time;
            assert_eq!(
                super::timewarp_time_min(crate::chainparams::Network::Testnet4, ancestors(&chain)),
                expected,
                "{last_time}"
            );
        }
    }

    #[test]
    fn work_is_two_to_the_256_over_the_target_plus_one() {
        let limit = [0xff; 32];
        for (bits, expected) in [
            (0x1d00_ffff, "100010001"),
            (0x1e03_77ae, "49d414"),
            (0x207f_ffff, "2"),
            (0x1703_4219, "4e9235f043634662e0cb"),
            (
                0x0101_0000,
                "8000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                0x0300_8000,
                "1fffc0007fff0001fffc0007fff0001fffc0007fff0001fffc0007fff0001",
            ),
            (0x107f_ffff, "200000400000800001000002000003ffc"),
            (0x1100_8000, "1fffffffffffffffffffffffffffffffc"),
            (0x1101_0000, "ffffffffffffffffffffffffffffffff"),
            (0x2100_ffff, "1"),
        ] {
            let target = super::Target::from_bits(bits, limit).unwrap();
            assert_eq!(
                super::Work::of(target).to_string(),
                format!("{expected:0>64}"),
                "{bits:#010x}"
            );
        }
    }

    #[test]
    fn work_adds_with_a_carry_and_stops_at_the_highest_number() {
        let work = |high, low| super::Work { high, low };
        for (left, right, expected) in [
            (work(0, u128::MAX), work(0, 1), work(1, 0)),
            (work(u128::MAX, 0), work(0, u128::MAX), super::Work::MAX),
            (super::Work::MAX, work(0, 1), super::Work::MAX),
            (work(u128::MAX, 0), work(1, 0), super::Work::MAX),
        ] {
            assert_eq!(left.saturating_add(right), expected, "{left} {right}");
        }
    }

    #[test]
    fn chain_work_min_is_the_minimum_of_its_network() {
        for (network, minimum) in [
            (
                crate::chainparams::Network::Mainnet,
                "0000000000000000000000000000000000000001128750f82f4c366153a3a030",
            ),
            (
                crate::chainparams::Network::Testnet4,
                "0000000000000000000000000000000000000000000009a0fe15d0177d086304",
            ),
            (
                crate::chainparams::Network::Signet,
                "00000000000000000000000000000000000000000000000000000b463ea0a4b8",
            ),
            (
                crate::chainparams::Network::Regtest,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ] {
            let minimum =
                super::Work::from_be_bytes(crate::fixtures::hex(minimum).try_into().unwrap());
            assert_eq!(super::chain_work_min(network), minimum, "{network:?}");
        }
    }

    #[test]
    fn each_genesis_has_proof_of_work() {
        for network in [
            crate::chainparams::Network::Mainnet,
            crate::chainparams::Network::Testnet4,
            crate::chainparams::Network::Signet,
            crate::chainparams::Network::Regtest,
        ] {
            let genesis = network.genesis();
            assert_eq!(
                super::proven(&genesis, network).map(|(hash, _)| hash),
                Some(genesis.hash()),
                "{network:?}"
            );
        }
    }

    #[test]
    fn permits_bits_change_bounds_each_change_of_the_target() {
        let cases = [
            (
                crate::chainparams::Network::Mainnet,
                32_255,
                0x1d00_ffff,
                0x1d00_ffff,
                true,
            ),
            (
                crate::chainparams::Network::Mainnet,
                32_255,
                0x1d00_ffff,
                0x1d00_d86a,
                false,
            ),
            (
                crate::chainparams::Network::Mainnet,
                32_257,
                0x1d00_ffff,
                0x1d00_d86a,
                false,
            ),
            (
                crate::chainparams::Network::Signet,
                1,
                0x1e03_77ae,
                0x1e00_ddeb,
                false,
            ),
            (
                crate::chainparams::Network::Mainnet,
                32_256,
                0x1d00_ffff,
                0x1d00_d86a,
                true,
            ),
            (
                crate::chainparams::Network::Mainnet,
                32_256,
                0x1d00_ffff,
                0x1d01_0000,
                false,
            ),
            (
                crate::chainparams::Network::Mainnet,
                32_256,
                0x1d00_ffff,
                0x1c3f_ffc0,
                true,
            ),
            (
                crate::chainparams::Network::Mainnet,
                32_256,
                0x1d00_ffff,
                0x1c3f_ffbf,
                false,
            ),
            (
                crate::chainparams::Network::Mainnet,
                4_032,
                0x1b04_04cb,
                0x1b10_132c,
                true,
            ),
            (
                crate::chainparams::Network::Mainnet,
                4_032,
                0x1b04_04cb,
                0x1b10_132d,
                false,
            ),
            (
                crate::chainparams::Network::Mainnet,
                4_032,
                0x1b04_04cb,
                0x1b01_0132,
                true,
            ),
            (
                crate::chainparams::Network::Mainnet,
                4_032,
                0x1b04_04cb,
                0x1b01_0131,
                false,
            ),
            (
                crate::chainparams::Network::Mainnet,
                2_016,
                0x0103_0000,
                0x0101_0000,
                true,
            ),
            (
                crate::chainparams::Network::Mainnet,
                2_016,
                0x0103_0000,
                0x010c_0000,
                true,
            ),
            (
                crate::chainparams::Network::Mainnet,
                2_016,
                0x0103_0000,
                0x010d_0000,
                false,
            ),
            (
                crate::chainparams::Network::Signet,
                2_016,
                0x1e03_77ae,
                0x1e00_ddeb,
                true,
            ),
            (
                crate::chainparams::Network::Signet,
                2_016,
                0x1e03_77ae,
                0x1e00_ddea,
                false,
            ),
            (
                crate::chainparams::Network::Testnet4,
                1,
                0x1d00_ffff,
                0x1c00_ffff,
                true,
            ),
            (
                crate::chainparams::Network::Testnet4,
                2_016,
                0x1d00_ffff,
                0x1b00_ffff,
                true,
            ),
            (
                crate::chainparams::Network::Regtest,
                1,
                0x207f_ffff,
                0x2000_0001,
                true,
            ),
        ];
        for (network, height, bits_below, bits, expected) in cases {
            assert_eq!(
                super::permits_bits_change(network, height, bits_below, bits),
                expected,
                "{network:?} {height} {bits_below:#010x} {bits:#010x}"
            );
        }
    }
}
