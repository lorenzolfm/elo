//! The 80-byte block header, `CBlockHeader` in
//! `../bitcoin/src/primitives/block.h:26` at v31.1, and `sha256d` over it.
//!
//! A block hash is 32 bytes. On the wire, in `previous_block` and in this struct
//! they run in the order `sha256d` produced them. Core prints a hash with the
//! bytes reversed (`uint256.cpp:11`; the comment at `uint256.h:71` says why):
//! read as a little-endian number, the hash then prints as that number would,
//! and the zeros that proof of work demands come first. `BlockHash` keeps the
//! wire order and reverses only in `Display`; nothing else in elo reverses
//! anything.

/// Version 4, previous hash 32, merkle root 32, time 4, bits 4, nonce 4: the
/// serialization order at `block.h:42`.
pub const BYTES: usize = 80;

const _: () = assert!(4 + 32 + 32 + 4 + 4 + 4 == BYTES);

/// `sha256d` of a serialized header (`block.cpp:15`, `hash.h:115`), in the
/// order `sha256d` produced it. From `hash` it is computed; from `previous_block`
/// it is what the peer claims, and the chain checks the claim by lookup.
pub struct BlockHash([u8; 32]);

/// The root of the transaction merkle tree, in wire order like a block hash.
/// Kept opaque: elo does not validate transactions, so nothing computes a
/// root to compare it against. Its own type so that it cannot stand in for a
/// block hash, and so that it prints the way Core prints it.
pub struct MerkleRoot([u8; 32]);

impl BlockHash {
    /// The bytes as they run on the wire.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl MerkleRoot {
    /// The bytes as they run on the wire.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Lowercase hex, last byte first: what Core prints and what
/// `getblockhash` returns.
fn fmt_reversed(bytes: &[u8; 32], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

/// The same as `Display`: a hash in wire order is not one a person can look
/// up, so no view of it shows that order.
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

/// The header as it is on the wire. Every field is fixed-width, so there is
/// no length to bound and no way for 80 bytes to fail to parse; whether the
/// fields make sense is a question for the chain, not the decoder.
#[derive(Debug)]
pub struct Header {
    pub version: i32,
    pub previous_block: BlockHash,
    pub merkle_root: MerkleRoot,
    pub time: u32,
    /// The target in compact form. Decoded in a later step.
    pub bits: u32,
    pub nonce: u32,
}

impl Header {
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

    /// The mirror of `parse`: the same widths in the same order, so the
    /// layout is written down once per direction and asserted in both.
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

    /// The hash is over the serialized header and nothing else: the
    /// transaction count and the transactions are not part of it.
    pub fn hash(&self) -> BlockHash {
        BlockHash(bitcoin_hashes::sha256d::Hash::hash(&self.encode()).to_byte_array())
    }
}

/// The next `N` bytes, and the rest. `parse` starts from a fixed-size array
/// and every width is a constant, so running out of bytes is our bug, not
/// the peer's. That is why this is not `version::take`: `take` reads a slice
/// the peer sized and returns `Truncated` when it runs out.
fn parse_field<const N: usize>(bytes: &[u8]) -> (&[u8; N], &[u8]) {
    let Some(split) = bytes.split_first_chunk() else {
        unreachable!("a header field runs past {BYTES} bytes")
    };
    split
}

/// `parse_field` for `encode`: the next `N` bytes to write, and the rest.
fn encode_field<const N: usize>(bytes: &mut [u8]) -> (&mut [u8; N], &mut [u8]) {
    let Some(split) = bytes.split_first_chunk_mut() else {
        unreachable!("a header field runs past {BYTES} bytes")
    };
    split
}
