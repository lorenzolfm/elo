use crate::serialize::{Decode, Encode};

pub(crate) const BLOCK_HEADER_SIZE: usize = 80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockHeader {
    pub(crate) version: i32,
    pub(crate) prev: bitcoin_hashes::sha256d::Hash,
    pub(crate) merkle_root: [u8; 32],
    pub(crate) time: u32,
    pub(crate) bits: u32,
    pub(crate) nonce: u32,
}

impl BlockHeader {
    pub(crate) fn hash(&self) -> bitcoin_hashes::sha256d::Hash {
        let mut bytes = Vec::with_capacity(BLOCK_HEADER_SIZE);
        self.encode(&mut bytes);
        bitcoin_hashes::sha256d::Hash::hash(&bytes)
    }
}

impl Encode for BlockHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        let length_before = out.len();
        self.version.encode(out);
        self.prev.encode(out);
        self.merkle_root.encode(out);
        self.time.encode(out);
        self.bits.encode(out);
        self.nonce.encode(out);
        assert_eq!(out.len() - length_before, BLOCK_HEADER_SIZE);
    }
}

impl Decode for BlockHeader {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        let length_before = input.len();
        let header = Self {
            version: i32::decode(input)?,
            prev: Decode::decode(input)?,
            merkle_root: Decode::decode(input)?,
            time: u32::decode(input)?,
            bits: u32::decode(input)?,
            nonce: u32::decode(input)?,
        };
        assert_eq!(length_before - input.len(), BLOCK_HEADER_SIZE);
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::Decode;

    #[test]
    fn header_decodes_prev_in_wire_order() {
        let payload = crate::fixtures::headers_payload();
        let (count, mut input) = payload.split_first().unwrap();
        assert_eq!(*count, 2);
        let header = super::BlockHeader::decode(&mut input).unwrap();

        assert_eq!(
            header.prev,
            crate::fixtures::hash_from_display_hex(
                "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
            )
        );
    }

    #[test]
    fn header_requires_nonce() {
        let payload = crate::fixtures::headers_payload();
        let (_, headers) = payload.split_first().unwrap();
        let mut input = &headers[..super::BLOCK_HEADER_SIZE - size_of::<u32>()];
        assert_eq!(
            super::BlockHeader::decode(&mut input),
            Err(crate::serialize::Error::UnexpectedEnd)
        );
    }
}
