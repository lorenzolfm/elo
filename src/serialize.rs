//! The wire encoding. Core: `serialize.h`.

use std::fmt;

/// The largest value a CompactSize may hold. Core: `MAX_SIZE` (`serialize.h`).
pub const MAX_SIZE: u64 = 0x0200_0000;

/// Why a decode failed. Core throws `std::ios_base::failure` (`serialize.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input ended inside a field.
    UnexpectedEnd,
    /// A CompactSize used more bytes than its value needs.
    /// Core: `ReadCompactSize` (`serialize.h`).
    NonCanonicalCompactSize,
    /// A CompactSize above `MAX_SIZE`. Core: `ReadCompactSize` (`serialize.h`).
    CompactSizeTooLarge(u64),
    /// A string longer than its limit. Core: `LimitedStringFormatter` (`serialize.h`).
    StringTooLong { len: u64, max: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEnd => write!(f, "input ended inside a field"),
            Error::NonCanonicalCompactSize => write!(f, "non-canonical CompactSize"),
            Error::CompactSizeTooLarge(n) => write!(f, "CompactSize {n} is above {MAX_SIZE}"),
            Error::StringTooLong { len, max } => {
                write!(f, "string of {len} bytes is longer than {max}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Writes a value in the wire encoding. Core: `Serialize` (`serialize.h`).
pub trait Encode {
    fn encode(&self, out: &mut Vec<u8>);
}

/// Reads a value in the wire encoding, and moves `input` past it.
/// Core: `Unserialize` (`serialize.h`).
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

/// Little-endian, as in Core's `ser_writedata*` and `ser_readdata*`.
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

/// Any byte other than zero is true, as in Core.
impl Decode for bool {
    fn decode(input: &mut &[u8]) -> Result<Self, Error> {
        Ok(u8::decode(input)? != 0)
    }
}

/// Core: `WriteCompactSize` (`serialize.h`).
pub fn write_compact_size(out: &mut Vec<u8>, n: u64) {
    if let Ok(byte) = u8::try_from(n)
        && byte < 0xfd
    {
        byte.encode(out);
    } else if let Ok(n) = u16::try_from(n) {
        out.push(0xfd);
        n.encode(out);
    } else if let Ok(n) = u32::try_from(n) {
        out.push(0xfe);
        n.encode(out);
    } else {
        out.push(0xff);
        n.encode(out);
    }
}

/// Core: `ReadCompactSize` (`serialize.h`), with its range check.
pub fn read_compact_size(input: &mut &[u8]) -> Result<u64, Error> {
    let (n, min) = match u8::decode(input)? {
        0xfd => (u64::from(u16::decode(input)?), 0xfd),
        0xfe => (u64::from(u32::decode(input)?), 0x1_0000),
        0xff => (u64::decode(input)?, 0x1_0000_0000),
        byte => (u64::from(byte), 0),
    };
    if n < min {
        return Err(Error::NonCanonicalCompactSize);
    }
    if n > MAX_SIZE {
        return Err(Error::CompactSizeTooLarge(n));
    }
    Ok(n)
}

/// A CompactSize length, then the bytes. Core: `Serialize` for `std::string` (`serialize.h`).
pub fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).expect("a usize fits in a u64");
    write_compact_size(out, len);
    out.extend_from_slice(bytes);
}

/// Core: `LIMITED_STRING` (`serialize.h`).
pub fn read_limited_string(input: &mut &[u8], max: usize) -> Result<Vec<u8>, Error> {
    let len = read_compact_size(input)?;
    let Some(n) = usize::try_from(len).ok().filter(|&n| n <= max) else {
        return Err(Error::StringTooLong { len, max });
    };
    let (bytes, rest) = input.split_at_checked(n).ok_or(Error::UnexpectedEnd)?;
    *input = rest;
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_uses_the_shortest_form() {
        let cases: [(u64, &[u8]); 7] = [
            (0, &[0x00]),
            (0xfc, &[0xfc]),
            (0xfd, &[0xfd, 0xfd, 0x00]),
            (0xffff, &[0xfd, 0xff, 0xff]),
            (0x1_0000, &[0xfe, 0x00, 0x00, 0x01, 0x00]),
            (MAX_SIZE, &[0xfe, 0x00, 0x00, 0x00, 0x02]),
            (
                0x1_0000_0000,
                &[0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00],
            ),
        ];
        for (n, bytes) in cases {
            let mut out = Vec::new();
            write_compact_size(&mut out, n);
            assert_eq!(out, bytes, "write {n:#x}");

            if n <= MAX_SIZE {
                let mut input = bytes;
                assert_eq!(read_compact_size(&mut input), Ok(n), "read {n:#x}");
                assert!(input.is_empty());
            }
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
    fn compact_size_refuses_above_max_size() {
        let mut input: &[u8] = &[0xfe, 0x01, 0x00, 0x00, 0x02];
        assert_eq!(
            read_compact_size(&mut input),
            Err(Error::CompactSizeTooLarge(MAX_SIZE + 1))
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
    fn limited_string_refuses_above_its_limit() {
        let mut input: &[u8] = &[0x03, b'a', b'b', b'c'];
        assert_eq!(read_limited_string(&mut input, 3), Ok(b"abc".to_vec()));

        let mut input: &[u8] = &[0x04, b'a', b'b', b'c', b'd'];
        assert_eq!(
            read_limited_string(&mut input, 3),
            Err(Error::StringTooLong { len: 4, max: 3 })
        );
    }

    #[test]
    fn bool_is_true_for_any_nonzero_byte() {
        for (byte, expected) in [(0x00, false), (0x01, true), (0x02, true)] {
            assert_eq!(bool::decode(&mut &[byte][..]), Ok(expected));
        }
    }
}
