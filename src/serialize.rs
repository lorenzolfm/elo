//! The wire encoding.

use std::fmt;

/// The largest value a CompactSize may hold.
pub const COMPACT_SIZE_MAX: u64 = 0x0200_0000;

// A CompactSize elo accepts fits in four bytes, and so in a `usize`.
const _: () = assert!(COMPACT_SIZE_MAX < 1 << 32);
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
pub trait Encode {
    fn encode(&self, out: &mut Vec<u8>);
}

/// Reads a value in the wire encoding, and moves `input` past it.
pub trait Decode: Sized {
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
pub fn write_compact_size(out: &mut Vec<u8>, value: u64) {
    assert!(value <= COMPACT_SIZE_MAX);

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

/// Refuses a form longer than the value needs, and a value above `COMPACT_SIZE_MAX`.
pub fn read_compact_size(input: &mut &[u8]) -> Result<u64, Error> {
    let (value, value_min) = match u8::decode(input)? {
        0xfd => (u64::from(u16::decode(input)?), 0xfd),
        0xfe => (u64::from(u32::decode(input)?), 0x1_0000),
        0xff => (u64::decode(input)?, 0x1_0000_0000),
        byte => (u64::from(byte), 0),
    };
    if value < value_min {
        Err(Error::NonCanonicalCompactSize)
    } else if value <= COMPACT_SIZE_MAX {
        Ok(value)
    } else {
        Err(Error::CompactSizeTooLarge(value))
    }
}

/// A CompactSize length, then the bytes.
pub fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("a usize fits in a u64");
    write_compact_size(out, length);
    out.extend_from_slice(bytes);
}

/// Refuses a string longer than `length_max` bytes.
pub fn read_limited_string(input: &mut &[u8], length_max: usize) -> Result<Vec<u8>, Error> {
    let length =
        usize::try_from(read_compact_size(input)?).expect("COMPACT_SIZE_MAX fits in a usize");
    if length <= length_max {
        let (bytes, rest) = input.split_at_checked(length).ok_or(Error::UnexpectedEnd)?;
        *input = rest;
        Ok(bytes.to_vec())
    } else {
        Err(Error::StringTooLong { length, length_max })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_uses_the_shortest_form() {
        let cases: [(u64, &[u8]); 6] = [
            (0, &[0x00]),
            (0xfc, &[0xfc]),
            (0xfd, &[0xfd, 0xfd, 0x00]),
            (0xffff, &[0xfd, 0xff, 0xff]),
            (0x1_0000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
            (COMPACT_SIZE_MAX, &[0xfe, 0x00, 0x00, 0x00, 0x02]),
        ];
        for (value, bytes) in cases {
            let mut out = Vec::new();
            write_compact_size(&mut out, value);
            assert_eq!(out, bytes, "write {value:#x}");

            let mut input = bytes;
            assert_eq!(read_compact_size(&mut input), Ok(value), "read {value:#x}");
            assert!(input.is_empty());
        }
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
                read_compact_size(&mut input),
                Err(Error::NonCanonicalCompactSize)
            );
        }
    }

    #[test]
    fn compact_size_refuses_above_compact_size_max() {
        let mut input: &[u8] = &[0xfe, 0x01, 0x00, 0x00, 0x02];
        assert_eq!(
            read_compact_size(&mut input),
            Err(Error::CompactSizeTooLarge(COMPACT_SIZE_MAX + 1))
        );
    }

    #[test]
    fn truncated_input_is_unexpected_end() {
        let mut input: &[u8] = &[0xfd, 0x00];
        assert_eq!(read_compact_size(&mut input), Err(Error::UnexpectedEnd));

        let mut input: &[u8] = &[0x01, 0x00, 0x00];
        assert_eq!(u32::decode(&mut input), Err(Error::UnexpectedEnd));

        let mut input: &[u8] = &[0x03, b'a', b'b'];
        assert_eq!(
            read_limited_string(&mut input, 3),
            Err(Error::UnexpectedEnd)
        );
    }

    #[test]
    fn bool_is_true_for_any_nonzero_byte() {
        for (byte, expected) in [(0x00, false), (0x01, true), (0x02, true)] {
            assert_eq!(bool::decode(&mut &[byte][..]), Ok(expected));
        }
    }
}
