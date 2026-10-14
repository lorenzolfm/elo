pub const BYTES: usize = 80;

pub const HASH_BYTES: usize = 32;

const _: () = assert!(4 + HASH_BYTES + HASH_BYTES + 4 + 4 + 4 == BYTES);

#[derive(Clone)]
pub struct BlockHash([u8; HASH_BYTES]);

pub struct MerkleRoot([u8; HASH_BYTES]);

impl BlockHash {
    pub(crate) const fn from_bytes(bytes: [u8; HASH_BYTES]) -> BlockHash {
        BlockHash(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_BYTES] {
        &self.0
    }
}

impl MerkleRoot {
    pub(crate) const fn from_bytes(bytes: [u8; HASH_BYTES]) -> MerkleRoot {
        MerkleRoot(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; HASH_BYTES] {
        &self.0
    }
}

fn fmt_reversed(bytes: &[u8; HASH_BYTES], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    for byte in bytes.iter().rev() {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

impl std::fmt::Display for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_reversed(&self.0, f)
    }
}

impl std::fmt::Display for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_reversed(&self.0, f)
    }
}

impl std::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Debug for MerkleRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[derive(Debug)]
pub struct Header {
    pub version: i32,
    pub previous_block: BlockHash,
    pub merkle_root: MerkleRoot,
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl Header {
    #[must_use]
    pub fn parse(bytes: &[u8; BYTES]) -> Header {
        let (version, rest) = parse_field::<4>(bytes);
        let (previous_block, rest) = parse_field::<32>(rest);
        let (merkle_root, rest) = parse_field::<32>(rest);
        let (time, rest) = parse_field::<4>(rest);
        let (bits, rest) = parse_field::<4>(rest);
        let (nonce, rest) = parse_field::<4>(rest);
        assert!(rest.is_empty(), "the fields add up to {BYTES} bytes");
        Header {
            version: i32::from_le_bytes(*version),
            previous_block: BlockHash(*previous_block),
            merkle_root: MerkleRoot(*merkle_root),
            time: u32::from_le_bytes(*time),
            bits: u32::from_le_bytes(*bits),
            nonce: u32::from_le_bytes(*nonce),
        }
    }

    #[must_use]
    pub fn encode(&self) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        let (version, rest) = encode_field::<4>(&mut out);
        let (previous_block, rest) = encode_field::<32>(rest);
        let (merkle_root, rest) = encode_field::<32>(rest);
        let (time, rest) = encode_field::<4>(rest);
        let (bits, rest) = encode_field::<4>(rest);
        let (nonce, rest) = encode_field::<4>(rest);
        assert!(rest.is_empty(), "the fields add up to {BYTES} bytes");
        *version = self.version.to_le_bytes();
        *previous_block = *self.previous_block.as_bytes();
        *merkle_root = *self.merkle_root.as_bytes();
        *time = self.time.to_le_bytes();
        *bits = self.bits.to_le_bytes();
        *nonce = self.nonce.to_le_bytes();
        out
    }

    #[must_use]
    pub fn hash(&self) -> BlockHash {
        BlockHash(bitcoin_hashes::sha256d::Hash::hash(&self.encode()).to_byte_array())
    }
}

fn parse_field<const N: usize>(bytes: &[u8]) -> (&[u8; N], &[u8]) {
    let Some(split) = bytes.split_first_chunk() else {
        unreachable!("a header field runs past {BYTES} bytes")
    };
    split
}

fn encode_field<const N: usize>(bytes: &mut [u8]) -> (&mut [u8; N], &mut [u8]) {
    let Some(split) = bytes.split_first_chunk_mut() else {
        unreachable!("a header field runs past {BYTES} bytes")
    };
    split
}

#[cfg(test)]
mod tests {
    const MAINNET_GENESIS: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
    const REGTEST_GENESIS: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff7f2002000000";

    const MAINNET_GENESIS_HASH: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const REGTEST_GENESIS_HASH: &str =
        "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";

    fn fixture(hex: &str) -> [u8; super::BYTES] {
        let mut out = [0u8; super::BYTES];
        assert_eq!(hex.len(), 2 * out.len(), "a fixture is one header");
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    #[test]
    fn genesis_hashes_to_the_number_everyone_knows() {
        let header = super::Header::parse(&fixture(MAINNET_GENESIS));
        let hash = header.hash();
        assert_eq!(hash.to_string(), MAINNET_GENESIS_HASH);
        assert_eq!(&hash.as_bytes()[28..], &[0, 0, 0, 0]);
        assert_eq!(hash.as_bytes()[0], 0x6f);
        println!(
            "genesis is {hash}; on the wire it ends {:02x?}",
            &hash.as_bytes()[28..]
        );
    }

    #[test]
    fn genesis_fields_match_chainparams() {
        let header = super::Header::parse(&fixture(MAINNET_GENESIS));
        assert_eq!(header.version, 1);
        assert_eq!(
            header.previous_block.as_bytes(),
            &[0; 32],
            "nothing before genesis"
        );
        assert_eq!(
            header.merkle_root.to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
            "chainparams.cpp:137 prints the root reversed like a hash"
        );
        assert_eq!(
            header.merkle_root.as_bytes()[0],
            0x3b,
            "and the wire order starts where the print ends"
        );
        assert_eq!(header.time, 1_231_006_505, "2009-01-03 18:15:05 UTC");
        assert_eq!(header.bits, 0x1d00_ffff);
        assert_eq!(header.nonce, 2_083_236_893);
        println!("{header:?}");
    }

    #[test]
    fn regtest_genesis_matches_getblockhash_zero() {
        let header = super::Header::parse(&fixture(REGTEST_GENESIS));
        assert_eq!(header.time, 1_296_688_602);
        assert_eq!(header.bits, 0x207f_ffff, "the easiest target there is");
        assert_eq!(header.nonce, 2, "found on the second try");
        assert_eq!(header.hash().to_string(), REGTEST_GENESIS_HASH);
        println!("regtest genesis is {}", header.hash());
    }

    #[test]
    fn display_reverses_the_bytes() {
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap();
        }
        let hash = super::BlockHash(bytes);
        let printed = hash.to_string();
        assert_eq!(printed.len(), 64);
        assert!(printed.starts_with("1f1e1d1c"), "{printed}");
        assert!(printed.ends_with("03020100"), "{printed}");
        assert_eq!(format!("{hash:?}"), printed, "Debug shows the same view");
        let root = super::MerkleRoot(bytes);
        assert_eq!(root.to_string(), printed, "a root prints like a hash");
        assert_eq!(format!("{root:?}"), printed);
        println!("{printed}");
    }
}
