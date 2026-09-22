pub const HASHES_MAX: usize = 101;

const _: () = assert!(HASHES_MAX < 0xfd);

const DENSE: usize = 10;

const BUILT_MAX: usize = 1 + DENSE + (64 - 1) + 1;

const _: () = assert!(usize::BITS <= 64);
const _: () = assert!(BUILT_MAX <= HASHES_MAX);

#[must_use]
pub fn heights(tip: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(BUILT_MAX);
    let mut height = tip;
    let mut step: usize = 1;
    loop {
        out.push(height);
        if height == 0 {
            break;
        }
        height = height.saturating_sub(step);
        if out.len() > DENSE {
            step = step.saturating_mul(2);
        }
    }
    assert!(
        out.len() <= BUILT_MAX,
        "{} heights for tip {tip}",
        out.len()
    );
    assert_eq!(out.last(), Some(&0), "a locator ends at genesis");
    out
}

#[derive(Debug)]
pub struct Locator(Vec<crate::chain::block_header::BlockHash>);

impl Locator {
    pub fn new(
        tip: usize,
        hash_at: impl FnMut(usize) -> crate::chain::block_header::BlockHash,
    ) -> Locator {
        let hashes: Vec<crate::chain::block_header::BlockHash> =
            heights(tip).into_iter().map(hash_at).collect();
        assert!(!hashes.is_empty(), "a built locator names genesis at least");
        assert!(hashes.len() <= HASHES_MAX);
        Locator(hashes)
    }

    pub(crate) fn from_wire(hashes: Vec<crate::chain::block_header::BlockHash>) -> Locator {
        assert!(
            hashes.len() <= HASHES_MAX,
            "parse let {} hashes through",
            hashes.len()
        );
        Locator(hashes)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[crate::chain::block_header::BlockHash] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    const CORE_GETHEADERS: &str = "801101001357432727ae1ead6d3f9f2d4d648f0479111eecef28af7d251d17100700c41d3512b7a4295bb9903b2896a0a98f27b0e0c7a4f57187abb5e08a4fe536c79cef1fb6d8fef1eaa3ee9fe0cce5f7ab51d83702a7d720b07d3b69c15a773bbd97076b6b60e28cbe9d410d831e382bddc5139784a5c49e63899f0a1771911b7841ba68cc3a779adaedb4893385c25733557dfb600b5f7e1614dac02ea84840c28a5702cebabe31906bf7849f3c6f56a61df74c8f2a12cdd623396371748faf31576f71a8af5a27dd5d52379a3b2547356a5b9b731ff2d6623c2826cfad866ace0b0e5377cfafe4a8950c536dab4fd6341a28fdaabc7875b39c618af17c6656a6c77365aac6413e0cc05cfbe9746c4527cb2cc8902e4a89cf9bfacfe64d533c3702f80f81b50fcc2a83fcd9c9635485263ec01d4dec99c27823897c3b0f9f3b59b1063b28e5e4943faa04a5451cdbd7241b8edda545a397097b8f6c3191aa7d37c1a5115dc3cded6fae00409a49b68f733e7bd44d9f8f530806eeff1c10340ed7b1f21b54b5cde8bd8a7cafb8bc414d8e52c518c68ae53227dae42b6de750b6ace0b304e3a2815e330018eae36f1ae482a5fc294ff8ac06b03ffbbd398a682b39160f629431557d321881cd431e12287cd813e4d3bfd2a89bf9589519cc908329838e269cf56b8db46cb0b9b2983d65c361478330a91b3b64ae06ac9479d8d040623a05be604ff7c8bef1707f014846eb1d328e39b9ee9373b30c665a2e5d37a6d12a2ec172d92aab7869066116ff92737bb58906bc77f76aa126fb598d5b569c16144a06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000000000000000000000000000000000000000000000000000000000000000";

    const SPARSE: [(usize, &str); 8] = [
        (
            187,
            "1bf2b1d70e34101cffee0608538f9f4dd47b3e738fb6499a4000ae6fedcdc35d",
        ),
        (
            185,
            "04b3e0acb650e76d2be4da2732e58ac618c5528e4d41bcb8af7c8abde8cdb554",
        ),
        (
            181,
            "620f16392b688a39bdfb3fb006acf84f29fca582e41a6fe3ea1800335e81a2e3",
        ),
        (
            173,
            "268e83298390cc199558f99ba8d2bfd3e413d87c28121e43cd8118327d553194",
        ),
        (
            157,
            "053a6240d0d87994ac06ae643b1ba930834761c3653d98b2b9b06cb48d6bf59c",
        ),
        (
            125,
            "2e2ad1a6375d2e5a660cb37393eeb9398e321deb4648017f70f1bec8f74f60be",
        ),
        (
            61,
            "4a14169c565b8d59fb26a16af777bc0689b57b7392ff1661066978ab2ad972c1",
        ),
        (
            0,
            "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
        ),
    ];
    const BLOCK_198: &str = "351dc4000710171d257daf28efec1e1179048f644d2d9f3f6dad1eae27274357";
    const BLOCK_188: &str = "11a5c1377daa91316c8f7b0997a345a5dd8e1b24d7db1c45a504aa3f94e4e528";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn core_locator() -> super::Locator {
        let payload = fixture(CORE_GETHEADERS);
        let count = usize::from(payload[4]);
        let hashes = payload[5..]
            .chunks(crate::chain::block_header::HASH_BYTES)
            .take(count)
            .map(|chunk| {
                crate::chain::block_header::BlockHash::from_bytes(chunk.try_into().unwrap())
            })
            .collect();
        super::Locator::from_wire(hashes)
    }

    #[test]
    fn the_shape_is_core_shape_at_every_height() {
        // Red if the dense run is ten or twelve long, the step doubles before
        // the height is computed, or the doubling starts one entry early or
        // late. Nineteen hashes from Core; nineteen heights from us; each
        // sparse height must hash to what `getblockhash` printed for it.
        let core = core_locator();
        let heights = super::heights(198);
        assert_eq!(heights.len(), core.len(), "{heights:?}");
        let dense: Vec<usize> = (188..=198).rev().collect();
        assert_eq!(&heights[..11], &dense[..]);
        let sparse: Vec<usize> = SPARSE.iter().map(|(height, _)| *height).collect();
        assert_eq!(&heights[11..], &sparse[..]);
        let hashes = core.as_slice();
        assert_eq!(hashes[0].to_string(), BLOCK_198);
        assert_eq!(hashes[10].to_string(), BLOCK_188);
        for (i, (height, hash)) in SPARSE.iter().enumerate() {
            assert_eq!(hashes[11 + i].to_string(), *hash, "height {height}");
        }
        println!("Core's locator at tip 199: {heights:?}");
    }

    #[test]
    fn new_asks_for_each_height_and_rebuilds_core_locator() {
        // Red if `new` maps heights to hashes in another order, or skips one.
        // The lookup here is Core's own locator by position, which is a chain
        // only at the heights `heights(198)` names; a wrong height panics.
        let core_hashes = core_locator();
        let heights = super::heights(198);
        let mut asked = Vec::new();
        let ours = super::Locator::new(198, |height| {
            asked.push(height);
            let position = heights.iter().position(|&h| h == height).unwrap();
            crate::chain::block_header::BlockHash::from_bytes(
                *core_hashes.as_slice()[position].as_bytes(),
            )
        });
        assert_eq!(asked, heights, "asked once per height, newest first");
        let ours: Vec<String> = ours.as_slice().iter().map(ToString::to_string).collect();
        let core: Vec<String> = core_hashes
            .as_slice()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(ours, core);
        println!("{} hashes, the same as Core's", core.len());
    }

    #[test]
    fn a_short_chain_is_all_dense() {
        // Red if genesis is missed on a chain shorter than the dense run, or
        // the step doubles on the way to it.
        assert_eq!(super::heights(0), [0]);
        assert_eq!(super::heights(1), [1, 0]);
        assert_eq!(super::heights(10), (0..=10).rev().collect::<Vec<_>>());
        assert_eq!(super::heights(11), (0..=11).rev().collect::<Vec<_>>());
        assert_eq!(
            super::heights(12),
            [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
        );
        assert_eq!(
            super::heights(13),
            [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 0]
        );
        println!("tip 13: {:?}", super::heights(13));
    }

    #[test]
    fn a_locator_never_reaches_core_limit() {
        // Red if `BUILT_MAX` is wrong in either direction: the arithmetic is
        // tight at the largest height there is, and well under 101.
        let heights = super::heights(usize::MAX);
        let powers = usize::try_from(usize::BITS).unwrap() - 1;
        assert_eq!(heights.len(), 1 + super::DENSE + powers + 1);
        assert_eq!(heights.len(), super::BUILT_MAX);
        assert!(heights.len() < super::HASHES_MAX);
        assert_eq!(heights[0], usize::MAX);
        assert_eq!(heights[super::DENSE], usize::MAX - super::DENSE);
        assert_eq!(*heights.last().unwrap(), 0);
        for pair in heights.windows(2) {
            assert!(pair[0] > pair[1], "strictly descending: {pair:?}");
        }
        println!(
            "tip {}: {} hashes, {} under Core's limit",
            usize::MAX,
            heights.len(),
            super::HASHES_MAX - heights.len()
        );
    }

    #[test]
    fn a_wire_locator_may_be_empty_or_full() {
        // Red if `from_wire` refuses the empty locator a stop-only request
        // carries, or the last count Core accepts.
        let hash = || crate::chain::block_header::BlockHash::from_bytes([0; 32]);
        let none = super::Locator::from_wire(Vec::new());
        assert!(none.is_empty());
        let full = super::Locator::from_wire((0..super::HASHES_MAX).map(|_| hash()).collect());
        assert_eq!(full.len(), 101);
        assert!(!full.is_empty());
        println!("0 and 101 are locators");
    }

    #[test]
    #[should_panic(expected = "parse let 102 hashes through")]
    fn a_wire_locator_over_core_limit_is_our_bug() {
        // Red if `from_wire` trusts its caller: `parse` bounds the count, and
        // this is the assertion that says so.
        let hash = || crate::chain::block_header::BlockHash::from_bytes([0; 32]);
        let _ = super::Locator::from_wire((0..=super::HASHES_MAX).map(|_| hash()).collect());
    }
}
