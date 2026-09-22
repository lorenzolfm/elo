const SPAN_HEADERS_MAX: usize = 11;

const _: () = assert!(SPAN_HEADERS_MAX % 2 == 1);

pub(crate) struct Ancestors<'a> {
    held: &'a [crate::chain::pow::Checked],
    batch: &'a [crate::chain::pow::Checked],
}

impl<'a> Ancestors<'a> {
    #[must_use]
    pub(crate) fn new(
        held: &'a [crate::chain::pow::Checked],
        batch: &'a [crate::chain::pow::Checked],
    ) -> Ancestors<'a> {
        assert!(!held.is_empty(), "ancestors start at genesis");
        Ancestors { held, batch }
    }

    #[must_use]
    pub(crate) fn height_last(&self) -> usize {
        let count = self.held.len() + self.batch.len();
        assert!(count > 0, "ancestors start at genesis");
        count - 1
    }

    #[must_use]
    pub(crate) fn at(&self, height: usize) -> &crate::chain::pow::Checked {
        assert!(
            height <= self.height_last(),
            "height {height} is above the ancestors"
        );
        match height.checked_sub(self.held.len()) {
            None => &self.held[height],
            Some(offset) => &self.batch[offset],
        }
    }

    #[must_use]
    pub(crate) fn median_time_past(&self) -> u32 {
        let height_last = self.height_last();
        let count = std::cmp::min(height_last + 1, SPAN_HEADERS_MAX);
        let mut times = [0; SPAN_HEADERS_MAX];
        for (offset, time) in times[..count].iter_mut().enumerate() {
            *time = self.at(height_last - offset).header().time;
        }
        let window = &mut times[..count];
        window.sort_unstable();
        let median = window[count / 2];
        assert!(
            (0..count).any(|offset| self.at(height_last - offset).header().time == median),
            "a median time past is the time of one of the ancestors"
        );
        median
    }
}

#[cfg(test)]
mod tests {
    const CORE_TIMES: [u32; 17] = [
        0, 100, 200, 5000, 300, 400, 6000, 500, 700, 7000, 600, 800, 8000, 900, 1000, 9000, 1100,
    ];
    const CORE_MEDIANS: [u32; 17] = [
        0, 100, 100, 200, 200, 300, 300, 400, 400, 500, 500, 600, 700, 800, 800, 900, 1000,
    ];

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

    #[test]
    fn ancestors_read_across_the_join_of_what_we_hold_and_the_batch() {
        // Red if the batch is counted from the wrong end, or `height_last`
        // is off by one: with one header held and one in the batch, the
        // batch header sits at height 1 and is the last of the ancestors.
        let held = timeline(&[1_500_000_000], 0x1d00_ffff);
        let batch = timeline(&[1_500_000_600], 0x1b00_0100);
        let ancestors = super::Ancestors::new(&held, &batch);
        assert_eq!(ancestors.height_last(), 1);
        assert_eq!(ancestors.at(0).header().bits, 0x1d00_ffff);
        assert_eq!(ancestors.at(1).header().bits, 0x1b00_0100);
        println!(
            "one held, one in the batch, last {}",
            ancestors.height_last()
        );
    }

    #[test]
    #[should_panic(expected = "height 2 is above the ancestors")]
    fn a_height_above_the_ancestors_is_our_bug() {
        // Red if `at` indexes without the assertion; the panic message would
        // be the slice's.
        let held = timeline(&[1_500_000_000, 1_500_000_600], 0x1d00_ffff);
        let _ = super::Ancestors::new(&held, &[]).at(2);
    }

    #[test]
    #[should_panic(expected = "ancestors start at genesis")]
    fn ancestors_over_nothing_held_is_our_bug() {
        // Red if `new` takes the invariant on trust and leaves it to
        // `height_last`: ancestors are built from a chain, and a chain holds
        // genesis before it holds anything else. The batch alone is not a
        // chain.
        let batch = timeline(&[1_500_000_000], 0x1d00_ffff);
        let _ = super::Ancestors::new(&[], &batch);
    }
    #[test]
    fn a_median_time_past_agrees_with_core_at_every_height_of_its_chain() {
        // Red if the sort is dropped, the walk runs from the wrong end, or
        // the middle is taken one off: Core's chain has no order to its
        // times, so the tip's own time is the answer at no height at all,
        // and a median read without sorting is wrong at almost every one.
        let genesis = crate::chain::genesis(crate::chain::network::Network::Regtest).time;
        let times: Vec<u32> = CORE_TIMES.iter().map(|after| genesis + after).collect();
        let headers = timeline(&times, 0x207f_ffff);
        for (height, after) in CORE_MEDIANS.iter().enumerate() {
            let ancestors = super::Ancestors::new(&headers[..=height], &[]);
            assert_eq!(
                ancestors.median_time_past(),
                genesis + after,
                "at height {height}"
            );
        }
        println!("{} heights agree with core", CORE_MEDIANS.len());
    }

    #[test]
    fn a_median_time_past_reads_eleven_headers_and_no_more() {
        // Red if the span is ten or twelve. Height 1 jumps far ahead and
        // every height after it rises by a hundred, so the answer at height
        // 12 is 600 over eleven headers, and 700 over ten or over twelve:
        // one fewer drops the lowest of the window, one more lets the jump
        // back in and pushes the middle up a place.
        let afters = [
            0, 9000, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100,
        ];
        let genesis = crate::chain::genesis(crate::chain::network::Network::Regtest).time;
        let times: Vec<u32> = afters.iter().map(|after| genesis + after).collect();
        let headers = timeline(&times, 0x207f_ffff);
        let median = super::Ancestors::new(&headers, &[]).median_time_past();
        assert_eq!(super::SPAN_HEADERS_MAX, 11);
        assert_eq!(median, genesis + 600);
        println!(
            "over {} headers -> {}",
            super::SPAN_HEADERS_MAX,
            median - genesis
        );
    }

    #[test]
    fn genesis_alone_is_its_own_median_time_past() {
        // Red if the walk reads a fixed eleven headers and takes the zeros
        // it did not fill: the median of a chain of one is the one time
        // there is, and every chain is that chain first.
        let genesis = crate::chain::genesis(crate::chain::network::Network::Regtest).time;
        let headers = timeline(&[genesis], 0x207f_ffff);
        let ancestors = super::Ancestors::new(&headers, &[]);
        assert_eq!(ancestors.median_time_past(), genesis);
        println!("genesis alone -> {}", ancestors.median_time_past());
    }

    #[test]
    fn a_median_time_past_reads_across_the_join_of_what_we_hold_and_the_batch() {
        // Red if the median reads only what we hold: a header of a batch is
        // checked against the headers of that batch in front of it too, so
        // they must be part of the window. Held times are the low ones, so
        // a median that misses the batch answers 200 and not 400. Six times
        // is an even count, and 400 is the upper of the two middles.
        let held = timeline(&[100, 200, 300], 0x207f_ffff);
        let batch = timeline(&[400, 500, 600], 0x207f_ffff);
        let ancestors = super::Ancestors::new(&held, &batch);
        assert_eq!(ancestors.height_last(), 5);
        assert_eq!(ancestors.median_time_past(), 400);
        println!(
            "held and batch together -> {}",
            ancestors.median_time_past()
        );
    }
}
