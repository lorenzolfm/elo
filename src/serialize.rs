//! The wire encoding.

/// The largest value a CompactSize may hold.
const COMPACT_SIZE_MAX: u32 = 0x0200_0000;

// A CompactSize elo accepts fits in a `usize`.
const _: () = assert!(usize::BITS >= u32::BITS);

/// Why a decode failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ended inside a field.
    UnexpectedEnd,
    /// A CompactSize used more bytes than its value needs.
    NonCanonicalCompactSize,
    /// A CompactSize above `COMPACT_SIZE_MAX`.
    CompactSizeTooLarge(u64),
    /// A string longer than its limit.
    StringTooLong { length: usize, length_max: usize },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::UnexpectedEnd => write!(f, "input ended inside a field"),
            Error::NonCanonicalCompactSize => write!(f, "non-canonical CompactSize"),
            Error::CompactSizeTooLarge(value) => {
                write!(f, "CompactSize {value} is above {COMPACT_SIZE_MAX}")
            }
            Error::StringTooLong { length, length_max } => {
                write!(f, "string of {length} bytes is longer than {length_max}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Writes a value in the wire encoding.
pub(crate) trait Encode {
    fn encode(&self, out: &mut Vec<u8>);
}

/// Reads a value in the wire encoding, and moves `input` past it.
pub(crate) trait Decode: Sized {
    fn decode(input: &mut &[u8]) -> Result<Self, Error>;
}

impl<const N: usize> Encode for [u8; N] {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode(input: &mut &[u8]) -> Result<Self, Error> {
        let (bytes, rest) = input.split_first_chunk().ok_or(Error::UnexpectedEnd)?;
        *input = rest;
        Ok(*bytes)
    }
}

macro_rules! little_endian {
    ($($t:ty),*) => {$(
        impl Encode for $t {
            fn encode(&self, out: &mut Vec<u8>) {
                self.to_le_bytes().encode(out);
            }
        }

        impl Decode for $t {
            fn decode(input: &mut &[u8]) -> Result<Self, Error> {
                Decode::decode(input).map(<$t>::from_le_bytes)
            }
        }
    )*};
}

little_endian!(u8, u16, u32, u64, i32, i64);

/// The bytes in the order that SHA-256 writes them. A hash shows as hex in the reverse order.
impl Encode for bitcoin_hashes::sha256d::Hash {
    fn encode(&self, out: &mut Vec<u8>) {
        self.as_byte_array().encode(out);
    }
}

impl Decode for bitcoin_hashes::sha256d::Hash {
    fn decode(input: &mut &[u8]) -> Result<Self, Error> {
        Decode::decode(input).map(Self::from_byte_array)
    }
}

impl Encode for bool {
    fn encode(&self, out: &mut Vec<u8>) {
        u8::from(*self).encode(out);
    }
}

/// Any byte other than zero is true.
impl Decode for bool {
    fn decode(input: &mut &[u8]) -> Result<Self, Error> {
        Ok(u8::decode(input)? != 0)
    }
}

/// One, three or five bytes: the shortest form that holds `value`.
///
/// Panics if `value` is above `COMPACT_SIZE_MAX`, because a peer refuses it.
pub(crate) fn write_compact_size(out: &mut Vec<u8>, value: usize) {
    assert!(value <= COMPACT_SIZE_MAX as usize);

    match value {
        0..0xfd => {
            let byte = u8::try_from(value).expect("the value is below 0xfd");
            byte.encode(out);
        }
        0xfd..=0xffff => {
            out.push(0xfd);
            u16::try_from(value)
                .expect("the value fits in two bytes")
                .encode(out);
        }
        _ => {
            out.push(0xfe);
            u32::try_from(value)
                .expect("COMPACT_SIZE_MAX fits in four bytes")
                .encode(out);
        }
    }
}

/// Refuses a form longer than the value needs, and a value above `COMPACT_SIZE_MAX`. So the
/// value fits in a `usize`.
pub(crate) fn read_compact_size(input: &mut &[u8]) -> Result<usize, Error> {
    let (value, value_min) = match u8::decode(input)? {
        0xfd => (u64::from(u16::decode(input)?), 0xfd),
        0xfe => (u64::from(u32::decode(input)?), 0x1_0000),
        0xff => (u64::decode(input)?, 0x1_0000_0000),
        byte => (u64::from(byte), 0),
    };
    if value < value_min {
        Err(Error::NonCanonicalCompactSize)
    } else {
        match u32::try_from(value) {
            Ok(narrow) if narrow <= COMPACT_SIZE_MAX => Ok(narrow as usize),
            _ => Err(Error::CompactSizeTooLarge(value)),
        }
    }
}

/// A CompactSize length, then the bytes.
pub(crate) fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// Refuses a string longer than `length_max` bytes.
pub(crate) fn read_limited_string(input: &mut &[u8], length_max: usize) -> Result<Vec<u8>, Error> {
    let length = read_compact_size(input)?;
    if length <= length_max {
        let (bytes, rest) = input.split_at_checked(length).ok_or(Error::UnexpectedEnd)?;
        *input = rest;
        Ok(bytes.to_vec())
    } else {
        Err(Error::StringTooLong { length, length_max })
    }
}

/// The entry point of the `compact_size` fuzz target.
#[cfg(fuzzing)]
pub(crate) mod fuzz {
    // The seeds hold this limit as bytes, and the check takes its limit from the same constant. So
    // a new limit moves the check and not the seeds, and the replay still passes. A new limit must
    // rewrite the seeds at the limit.
    const _: () = assert!(super::COMPACT_SIZE_MAX == 0x0200_0000);

    /// Checks that a value from a read writes back as the bytes that the read took, and that a
    /// value from `data` reads back after a write.
    ///
    /// The value is the first four bytes of `data`, little-endian, with zeros after their end. The
    /// committed corpus uses this layout, so a change to the layout must rewrite the corpus.
    pub fn compact_size(data: &[u8]) {
        let mut input = data;
        if let Ok(value) = super::read_compact_size(&mut input) {
            let mut written = Vec::new();
            // A write panics above `COMPACT_SIZE_MAX`, so a read cannot let such a value through.
            super::write_compact_size(&mut written, value);
            assert_eq!(written, data[..data.len() - input.len()]);
        }

        // A reader that refuses each value passes the check above, so read a value that elo wrote.
        let mut value_bytes = [0; size_of::<u32>()];
        for (value_byte, byte) in value_bytes.iter_mut().zip(data) {
            *value_byte = *byte;
        }
        let value = (u32::from_le_bytes(value_bytes) % (super::COMPACT_SIZE_MAX + 1)) as usize;
        let mut written = Vec::new();
        super::write_compact_size(&mut written, value);
        let mut input = written.as_slice();
        assert_eq!(super::read_compact_size(&mut input), Ok(value));
        assert!(input.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::Decode;

    #[test]
    fn compact_size_uses_the_shortest_form() {
        let cases: [(usize, &[u8]); 6] = [
            (0, &[0x00]),
            (0xfc, &[0xfc]),
            (0xfd, &[0xfd, 0xfd, 0x00]),
            (0xffff, &[0xfd, 0xff, 0xff]),
            (0x1_0000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
            (
                super::COMPACT_SIZE_MAX as usize,
                &[0xfe, 0x00, 0x00, 0x00, 0x02],
            ),
        ];
        for (value, bytes) in cases {
            let mut out = Vec::new();
            super::write_compact_size(&mut out, value);
            assert_eq!(out, bytes, "write {value:#x}");

            let mut input = bytes;
            assert_eq!(
                super::read_compact_size(&mut input),
                Ok(value),
                "read {value:#x}"
            );
            assert!(input.is_empty());
        }
    }

    #[test]
    #[should_panic]
    fn compact_size_write_panics_above_compact_size_max() {
        super::write_compact_size(&mut Vec::new(), super::COMPACT_SIZE_MAX as usize + 1);
    }

    #[test]
    fn compact_size_refuses_a_longer_form() {
        let cases: [&[u8]; 3] = [
            &[0xfd, 0xfc, 0x00],
            &[0xfe, 0xff, 0xff, 0x00, 0x00],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00],
        ];
        for mut input in cases {
            assert_eq!(
                super::read_compact_size(&mut input),
                Err(super::Error::NonCanonicalCompactSize)
            );
        }
    }

    #[test]
    fn compact_size_refuses_above_compact_size_max() {
        let mut input: &[u8] = &[0xfe, 0x01, 0x00, 0x00, 0x02];
        assert_eq!(
            super::read_compact_size(&mut input),
            Err(super::Error::CompactSizeTooLarge(
                u64::from(super::COMPACT_SIZE_MAX) + 1
            ))
        );

        let mut input: &[u8] = &[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            super::read_compact_size(&mut input),
            Err(super::Error::CompactSizeTooLarge(0x1_0000_0000))
        );
    }

    #[test]
    fn truncated_input_is_unexpected_end() {
        let mut input: &[u8] = &[0xfd, 0x00];
        assert_eq!(
            super::read_compact_size(&mut input),
            Err(super::Error::UnexpectedEnd)
        );

        let mut input: &[u8] = &[0x01, 0x00, 0x00];
        assert_eq!(u32::decode(&mut input), Err(super::Error::UnexpectedEnd));

        let mut input: &[u8] = &[0x03, b'a', b'b'];
        assert_eq!(
            super::read_limited_string(&mut input, 3),
            Err(super::Error::UnexpectedEnd)
        );
    }

    #[test]
    fn bool_is_true_for_any_nonzero_byte() {
        for (byte, expected) in [(0x00, false), (0x01, true), (0x02, true)] {
            assert_eq!(bool::decode(&mut &[byte][..]), Ok(expected));
        }
    }
}
