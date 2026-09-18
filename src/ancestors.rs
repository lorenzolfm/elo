//! The chain a contextual check reads: the headers we hold, and after them
//! the part of a batch already taken. Core gives such a check `pindexPrev`
//! and lets it walk the `pprev` chain behind it (`ContextualCheckBlockHeader`,
//! `../bitcoin/src/validation.cpp:4128` at v31.1); elo keeps one branch and
//! no tree, so the ancestors of a header are the two slices side by side.

/// The chain a contextual check reads. Every height from 0 to `height_last`
/// is one of the headers in it, so the height a header follows is a fact of
/// the ancestors and not a number the caller brings beside it.
pub struct Ancestors<'a> {
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
    pub fn new(held: &'a [crate::pow::Checked], batch: &'a [crate::pow::Checked]) -> Ancestors<'a> {
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
}

#[cfg(test)]
mod tests {
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
}
