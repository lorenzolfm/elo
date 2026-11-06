//! Proof of work.

/// The highest hash that a header may have. The bytes are big-endian, so the order of two arrays is
/// the order of their numbers. Only `from_bits` makes one, so it is above zero and at most the limit
/// that `from_bits` got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target([u8; 32]);

impl Target {
    /// Reads the compact form `bits`. Its first byte is the size of the number in bytes. Its other
    /// three bytes are the first bytes of the number, so a number of fewer than three bytes uses
    /// only the first of them. The first bit after the size byte is a sign. Returns nothing for a
    /// number that is negative, is zero, does not fit in 32 bytes, or is above `limit`. A peer picks
    /// `bits`, so no value may panic.
    fn from_bits(bits: u32, limit: [u8; 32]) -> Option<Target> {
        let [size, high, middle, low] = bits.to_be_bytes();
        if high & 0x80 != 0 {
            return None;
        }
        let mut target = [0; 32];
        for (offset, byte) in [high, middle, low].into_iter().enumerate() {
            match (target.len() + offset).checked_sub(usize::from(size)) {
                // An index past the end is after the last byte of the number, so the number does
                // not use this byte.
                Some(index) => {
                    if let Some(place) = target.get_mut(index) {
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

/// The target in `bits` is in the range of `network`, and `hash` is at most that target.
#[must_use = "a dropped answer lets each header pass"]
pub(crate) fn has_proof_of_work(
    hash: bitcoin_hashes::sha256d::Hash,
    bits: u32,
    network: crate::chainparams::Network,
) -> bool {
    Target::from_bits(bits, network.pow_limit()).is_some_and(|target| target.is_met_by(hash))
}

/// `header` with the first `nonce` that gives a hash below the regtest target, whatever its `bits`
/// are. A top byte below 0x7f is below that target, so about every second nonce passes. The top byte
/// of a hash is its last byte in wire order. This does not call the check above, so a check that
/// reads the wrong byte refuses these headers. Only the tests and the fuzz script call this.
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
            // Zero: the word is zero, or it has no byte that the size keeps.
            (0x0000_0000, None),
            (0x0012_3456, None),
            (0x0100_3456, None),
            (0x0200_0056, None),
            (0x0300_0000, None),
            (0x0400_0000, None),
            // Zero with the sign bit.
            (0x0092_3456, None),
            (0x0180_3456, None),
            (0x0280_0056, None),
            (0x0380_0000, None),
            (0x0480_0000, None),
            // A size of three bytes or fewer. The sign bit is not a bit of the number.
            (
                0x0112_3456,
                Some("0000000000000000000000000000000000000000000000000000000000000012"),
            ),
            (0x01fe_dcba, None),
            (
                0x0200_8000,
                Some("0000000000000000000000000000000000000000000000000000000000000080"),
            ),
            (
                0x0212_3456,
                Some("0000000000000000000000000000000000000000000000000000000000001234"),
            ),
            (
                0x0312_3456,
                Some("0000000000000000000000000000000000000000000000000000000000123456"),
            ),
            // A size above three bytes.
            (
                0x0412_3456,
                Some("0000000000000000000000000000000000000000000000000000000012345600"),
            ),
            (0x0492_3456, None),
            (
                0x0500_9234,
                Some("0000000000000000000000000000000000000000000000000000000092340000"),
            ),
            (
                0x2012_3456,
                Some("1234560000000000000000000000000000000000000000000000000000000000"),
            ),
            // At the top of the target: the size may pass 32 only by the zeros at the word's start.
            // In each `None`, another byte of the word is not zero, so only the fit refuses it.
            (
                0x2100_ffff,
                Some("ffff000000000000000000000000000000000000000000000000000000000000"),
            ),
            (0x2101_0001, None),
            (
                0x2200_00ff,
                Some("ff00000000000000000000000000000000000000000000000000000000000000"),
            ),
            (0x2200_0101, None),
            // No byte of the word fits.
            (0x2300_0001, None),
            (0xff12_3456, None),
        ];
        for (bits, expected) in cases {
            assert_eq!(
                super::Target::from_bits(bits, limit),
                expected.map(target),
                "{bits:#010x}"
            );
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
            assert!(
                super::has_proof_of_work(genesis.hash(), genesis.bits, network),
                "{network:?}"
            );
        }
    }
}
