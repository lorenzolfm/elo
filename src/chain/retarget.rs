fn retarget(
    target: crate::chain::pow::Target,
    timespan_actual: i64,
    timespan_target: u32,
    limit: &crate::chain::pow::Target,
) -> u32 {
    let low = i64::from(timespan_target / 4);
    let high = i64::from(timespan_target) * 4;
    let clamped = timespan_actual.clamp(low, high);
    let Ok(clamped) = u32::try_from(clamped) else {
        unreachable!("a timespan clamped to {low}..={high} fits a u32")
    };
    let scaled = target.0.mul_u32(clamped).div_u32(timespan_target);
    if scaled > limit.0 {
        crate::chain::pow::to_compact(&limit.0)
    } else {
        crate::chain::pow::to_compact(&scaled)
    }
}

fn next_bits_required(bits: u32, network: crate::chain::network::Network) -> u32 {
    if let Err(error) = crate::chain::pow::Target::from_compact(bits, network) {
        panic!("the rules require bits {bits:#010x} that no header may claim: {error}");
    }
    bits
}

#[must_use]
pub(crate) fn next_bits(
    ancestors: &crate::chain::ancestors::Ancestors,
    candidate: &crate::chain::block_header::Header,
    network: crate::chain::network::Network,
) -> u32 {
    let params = crate::chain::pow::Params::of(network);
    let height_last = ancestors.height_last();
    if !(height_last + 1).is_multiple_of(params.interval) {
        if !params.min_difficulty {
            return next_bits_required(ancestors.at(height_last).header().bits, network);
        }
        let limit_bits = crate::chain::pow::to_compact(&params.limit.0);
        let gap = i64::from(candidate.time) - i64::from(ancestors.at(height_last).header().time);
        if gap > i64::from(crate::chain::pow::SPACING) * 2 {
            return next_bits_required(limit_bits, network);
        }
        let mut height = height_last;
        while height > 0
            && !height.is_multiple_of(params.interval)
            && ancestors.at(height).header().bits == limit_bits
        {
            height -= 1;
        }
        return next_bits_required(ancestors.at(height).header().bits, network);
    }
    let crate::chain::pow::Retarget::Every {
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
    let height_source = match edge {
        crate::chain::pow::Edge::First => height_first,
        crate::chain::pow::Edge::Last => height_last,
    };
    let bits = retarget(
        ancestors.at(height_source).target(network),
        timespan_actual,
        timespan_target,
        &params.limit,
    );
    next_bits_required(bits, network)
}

#[must_use]
pub(crate) fn opens_a_bip94_period(height: usize, network: crate::chain::network::Network) -> bool {
    let params = crate::chain::pow::Params::of(network);
    let crate::chain::pow::Retarget::Every {
        edge: crate::chain::pow::Edge::First,
        ..
    } = params.retarget
    else {
        return false;
    };
    height.is_multiple_of(params.interval)
}

#[cfg(test)]
mod tests {
    const CORE_RETARGETS: [(u32, u32, u32, u32); 4] = [
        (1_262_152_739, 1_261_130_161, 0x1d00_ffff, 0x1d00_d86a),
        (1_233_061_996, 1_231_006_505, 0x1d00_ffff, 0x1d00_ffff),
        (1_279_297_671, 1_279_008_237, 0x1c05_a3f4, 0x1c01_68fd),
        (1_269_211_443, 1_263_163_443, 0x1c38_7f6f, 0x1d00_e1fd),
    ];

    const TWO_WEEKS: i64 = 14 * 24 * 60 * 60;

    fn header(time: u32, bits: u32) -> crate::chain::block_header::Header {
        crate::chain::block_header::Header {
            version: 1,
            previous_block: crate::chain::block_header::BlockHash::from_bytes([0; 32]),
            merkle_root: crate::chain::block_header::MerkleRoot::from_bytes([0; 32]),
            time,
            bits,
            nonce: 0,
        }
    }

    fn timeline(times: &[u32], bits: u32) -> Vec<crate::chain::pow::Checked> {
        times
            .iter()
            .map(|time| crate::chain::pow::unchecked(header(*time, bits)))
            .collect()
    }

    fn candidate(time: u32) -> crate::chain::block_header::Header {
        header(time, 0x1d00_ffff)
    }

    fn mainnet_retarget(bits: u32, actual: i64) -> u32 {
        let network = crate::chain::network::Network::Mainnet;
        let target = crate::chain::pow::Target::from_compact(bits, network).unwrap();
        let params = crate::chain::pow::Params::of(network);
        super::retarget(
            target,
            actual,
            crate::chain::pow::TIMESPAN_TWO_WEEKS,
            &params.limit,
        )
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
        let network = crate::chain::network::Network::Mainnet;
        let ancestors = crate::chain::ancestors::Ancestors::new(&headers[..=2014], &[]);
        let held = super::next_bits(&ancestors, &next, network);
        assert_eq!(held, 0x1d00_ffff);
        let ancestors = crate::chain::ancestors::Ancestors::new(&headers[..=2015], &[]);
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
        let network = crate::chain::network::Network::Mainnet;
        let ancestors = crate::chain::ancestors::Ancestors::new(&headers[..=4031], &[]);
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
        headers[0] = crate::chain::pow::unchecked(header(times[0], FIRST));
        let next = candidate(times[2015] + 600);
        let ancestors = crate::chain::ancestors::Ancestors::new(&headers, &[]);
        let testnet4 =
            super::next_bits(&ancestors, &next, crate::chain::network::Network::Testnet4);
        let testnet3 =
            super::next_bits(&ancestors, &next, crate::chain::network::Network::Testnet3);
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
        let network = crate::chain::network::Network::Regtest;
        let ancestors = crate::chain::ancestors::Ancestors::new(&headers[..=143], &[]);
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
        let network = crate::chain::network::Network::Testnet3;
        let on_time = candidate(1_500_000_600 + 1200);
        let ancestors = crate::chain::ancestors::Ancestors::new(&headers[..=1], &[]);
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
        headers[0] = crate::chain::pow::unchecked(header(1_500_000_000, 0x1b00_0100));
        let network = crate::chain::network::Network::Testnet3;
        let next = candidate(1_500_001_800);
        let ancestors = crate::chain::ancestors::Ancestors::new(&headers[..=2], &[]);
        let bits = super::next_bits(&ancestors, &next, network);
        assert_eq!(bits, 0x1b00_0100);
        println!("past two min-difficulty blocks -> {bits:#010x}");
    }
}
