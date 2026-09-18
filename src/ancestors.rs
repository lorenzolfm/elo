//! The chain a contextual check reads: the headers we hold, and after them
//! the part of a batch already taken. Core gives such a check `pindexPrev`
//! and lets it walk the `pprev` chain behind it (`ContextualCheckBlockHeader`,
//! `../bitcoin/src/validation.cpp:4128` at v31.1); elo keeps one branch and
//! no tree, so the ancestors of a header are the two slices side by side.

/// How many headers a median time past is taken over: Core's
/// `nMedianTimeSpan`, `../bitcoin/src/chain.h:231`.
const SPAN_HEADERS_MAX: usize = 11;

/// The span is odd, so the middle of a full window is one time and not the
/// mean of two. `median_time_past` takes `window[count / 2]`, which is the
/// median only while this holds; the even case it also handles is a chain
/// shorter than the span, never the span itself.
const _: () = assert!(SPAN_HEADERS_MAX % 2 == 1);

/// The chain a contextual check reads. Every height from 0 to `height_last`
/// is one of the headers in it, so the height a header follows is a fact of
/// the ancestors and not a number the caller brings beside it.
pub(crate) struct Ancestors<'a> {
    held: &'a [crate::pow::Checked],
    batch: &'a [crate::pow::Checked],
}

impl<'a> Ancestors<'a> {
    /// The ancestors `held` with `batch` after them. `Chain::extend` builds
    /// one for each header of a batch, over the headers in front of that one:
    /// a header of the batch can be the one a later header retargets from.
    ///
    /// # Panics
    ///
    /// If `held` is empty. A chain holds genesis before it holds anything
    /// else, so every header has genesis behind it. `height_last` reads
    /// the same invariant at the other end.
    #[must_use]
    pub(crate) fn new(
        held: &'a [crate::pow::Checked],
        batch: &'a [crate::pow::Checked],
    ) -> Ancestors<'a> {
        assert!(!held.is_empty(), "ancestors start at genesis");
        Ancestors { held, batch }
    }

    /// The height of the last of the ancestors: the height the header a
    /// peer offers would follow.
    ///
    /// # Panics
    ///
    /// If there are no ancestors. `new` asserts there is one.
    #[must_use]
    pub(crate) fn height_last(&self) -> usize {
        let count = self.held.len() + self.batch.len();
        assert!(count > 0, "ancestors start at genesis");
        count - 1
    }

    /// The header at `height`.
    ///
    /// # Panics
    ///
    /// If `height` is above `height_last`. As `Chain::at`: a height here
    /// is an index into our own chain, never a number a peer sends.
    #[must_use]
    pub(crate) fn at(&self, height: usize) -> &crate::pow::Checked {
        assert!(
            height <= self.height_last(),
            "height {height} is above the ancestors"
        );
        match height.checked_sub(self.held.len()) {
            None => &self.held[height],
            Some(offset) => &self.batch[offset],
        }
    }

    /// `GetMedianTimePast`, `../bitcoin/src/chain.h:233`: the median of the
    /// times of the last `SPAN_HEADERS_MAX` of the ancestors. Core walks
    /// back over `pprev` and stops where there is no header before
    /// (`:240`), so ancestors shorter than the span give up every header
    /// they hold.
    ///
    /// A miner writes its own clock into the header it mines, so block times
    /// do not rise along the chain and one header alone says little. The
    /// median of eleven is what a rule about time reads instead: to move it
    /// by a second, a miner must move six of the eleven.
    ///
    /// With an even count the answer is the upper of the two middle times,
    /// which is what `pbegin[(pend - pbegin) / 2]` takes (`:242`). Only the
    /// first ten heights of a chain have an even count.
    ///
    /// # Panics
    ///
    /// If there are no ancestors. `new` rules it out.
    #[must_use]
    pub(crate) fn median_time_past(&self) -> u32 {
        let height_last = self.height_last();
        // The walk is the shorter of the span and the ancestors:
        // `height_last + 1` is how many headers there are, and it bounds the
        // loop below where the ancestors are fewer than the span.
        let count = std::cmp::min(height_last + 1, SPAN_HEADERS_MAX);
        let mut times = [0; SPAN_HEADERS_MAX];
        for (offset, time) in times[..count].iter_mut().enumerate() {
            *time = self.at(height_last - offset).header().time;
        }
        let window = &mut times[..count];
        window.sort_unstable();
        let median = window[count / 2];
        // The pair to the loop above, read back from the ancestors rather
        // than from `times`: the answer is the time of a header the walk
        // read, and never a slot of `times` the walk left at zero.
        assert!(
            (0..count).any(|offset| self.at(height_last - offset).header().time == median),
            "a median time past is the time of one of the ancestors"
        );
        median
    }
}

#[cfg(test)]
mod tests {
    /// What Core answered for a regtest chain of sixteen blocks, generated
    /// with `setmocktime` set high and low by turns so that the times do not
    /// rise along the chain: five blocks jump far ahead and every block
    /// after one of them is older than its own parent. `getblockheader`
    /// prints both columns (`../bitcoin/src/rpc/blockchain.cpp:169` at
    /// v31.1); they are seconds after the time regtest genesis claims,
    /// genesis first.
    const CORE_TIMES: [u32; 17] = [
        0, 100, 200, 5000, 300, 400, 6000, 500, 700, 7000, 600, 800, 8000, 900, 1000, 9000, 1100,
    ];
    const CORE_MEDIANS: [u32; 17] = [
        0, 100, 100, 200, 200, 300, 300, 400, 400, 500, 500, 600, 700, 800, 800, 900, 1000,
    ];

    /// A header with a time and bits, and nothing else the ancestors are
    /// read for.
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

    /// Headers to build ancestors over, one per time given, all claiming
    /// the same bits. Nothing here is mined: `pow::unchecked` says why.
    fn timeline(times: &[u32], bits: u32) -> Vec<crate::pow::Checked> {
        times
            .iter()
            .map(|time| crate::pow::unchecked(header(*time, bits)))
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
        let genesis = crate::chain::genesis(crate::message::Network::Regtest).time;
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
        let genesis = crate::chain::genesis(crate::message::Network::Regtest).time;
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
        let genesis = crate::chain::genesis(crate::message::Network::Regtest).time;
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
