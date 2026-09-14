//! `CompactSize`, the length prefix in front of every list and string on the
//! wire: one byte below 0xfd, else a marker byte and 2, 4 or 8 little-endian
//! bytes. Core's `ReadCompactSize`, `../bitcoin/src/serialize.h:330` at v31.1.
//!
//! `read` returns the value unbounded: `u64::MAX` is a valid encoding, and a
//! `CompactSize` is not always a length. `read_len` is for one that is: it
//! takes the limit of the field it prefixes and returns a `usize` that is
//! already under it, so the caller cannot allocate or slice before the bound.

#[derive(Debug)]
pub enum Error {
    /// The marker promised more bytes than the payload holds.
    Truncated,
    /// A value in more bytes than it needs, which Core rejects
    /// (`serialize.h:342`, `:348`, `:353`). One value, one encoding.
    NonCanonical(u64),
    /// A well-formed value above the limit of the field it prefixes.
    TooLarge { value: u64, max: usize },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "compact size truncated"),
            Error::NonCanonical(value) => write!(f, "compact size {value} is not canonical"),
            Error::TooLarge { value, max } => write!(f, "length {value} exceeds {max}"),
        }
    }
}

impl std::error::Error for Error {}

/// Decodes the `CompactSize` at the front of `bytes`. Returns the value and
/// the bytes after it.
pub fn read(bytes: &[u8]) -> Result<(u64, &[u8]), Error> {
    let (&marker, rest) = bytes.split_first().ok_or(Error::Truncated)?;
    // The width of the value that follows, and the smallest value that
    // needs it (`serialize.h:300`).
    let (width, floor) = match marker {
        one_byte @ 0..=0xfc => return Ok((u64::from(one_byte), rest)),
        0xfd => (2, 0xfd),
        0xfe => (4, 0x1_0000),
        0xff => (8, 0x1_0000_0000),
    };
    if rest.len() < width {
        return Err(Error::Truncated);
    }
    let (raw, rest) = rest.split_at(width);
    let mut value_bytes = [0u8; 8];
    value_bytes[..width].copy_from_slice(raw);
    let value = u64::from_le_bytes(value_bytes);
    if value < floor {
        return Err(Error::NonCanonical(value));
    }
    Ok((value, rest))
}

/// Decodes the `CompactSize` at the front of `bytes` as a length of at most
/// `max`. A value that does not fit `usize` is above `max` by definition.
pub fn read_len(bytes: &[u8], max: usize) -> Result<(usize, &[u8]), Error> {
    let (value, rest) = read(bytes)?;
    match usize::try_from(value) {
        Ok(len) if len <= max => Ok((len, rest)),
        _ => Err(Error::TooLarge { value, max }),
    }
}

#[cfg(test)]
mod tests {
    // Both were sent by Bitcoin Core v31.1.0, `bitcoind -regtest`, on
    // 2026-09-13, to a throwaway Python script over a raw TCP socket.
    //
    // The first 17 bytes of Core's `version` payload from byte 80: the
    // user-agent length, then `/Satoshi:31.1.0/`.
    const USER_AGENT: &str = "102f5361746f7368693a33312e312e302f";
    // The first three bytes of a `headers` payload sent after
    // `generatetoaddress 300`: the count of headers that follow.
    const THREE_HUNDRED_HEADERS: &str = "fd2c01";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn one_byte_is_the_value() {
        let bytes = fixture(USER_AGENT);
        let (len, rest) = super::read(&bytes).unwrap();
        assert_eq!(len, 16);
        assert_eq!(rest, b"/Satoshi:31.1.0/");
        println!(
            "{:#04x} -> {len}, then {:?}",
            bytes[0],
            str::from_utf8(rest)
        );
    }

    #[test]
    fn fd_then_two_bytes() {
        let bytes = fixture(THREE_HUNDRED_HEADERS);
        let (count, rest) = super::read(&bytes).unwrap();
        assert_eq!(count, 300);
        assert!(rest.is_empty());
        println!("{THREE_HUNDRED_HEADERS} -> {count} headers");
    }

    /// Derived from `WriteCompactSize`, `serialize.h:300`, not captured: Core
    /// never sends a list long enough to need four or eight bytes.
    #[test]
    fn fe_and_ff_forms() {
        for (bytes, value) in [
            (vec![0xfe, 0, 0, 1, 0], 0x1_0000),
            (vec![0xfe, 0xff, 0xff, 0xff, 0xff], 0xffff_ffff),
            (vec![0xff, 0, 0, 0, 0, 1, 0, 0, 0], 0x1_0000_0000),
            (vec![0xff; 9], u64::MAX),
        ] {
            let (got, rest) = super::read(&bytes).unwrap();
            assert_eq!(got, value, "{bytes:02x?}");
            assert!(rest.is_empty());
            println!("{bytes:02x?} -> {value:#x}");
        }
    }

    #[test]
    fn rejects_the_long_way_to_write_a_small_number() {
        for (bytes, value) in [
            (vec![0xfd, 0xfc, 0], 0xfc),
            (vec![0xfd, 0, 0], 0),
            (vec![0xfe, 0xff, 0xff, 0, 0], 0xffff),
            (vec![0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0], 0xffff_ffff),
        ] {
            let err = super::read(&bytes).unwrap_err();
            assert!(
                matches!(err, super::Error::NonCanonical(got) if got == value),
                "{bytes:02x?}: {err}"
            );
            println!("{bytes:02x?}: {err}");
        }
        println!("Core throws 'non-canonical ReadCompactSize()' for each");
    }

    #[test]
    fn rejects_a_marker_with_nothing_behind_it() {
        for bytes in [
            &[][..],
            &[0xfd],
            &[0xfd, 0x2c],
            &[0xfe, 1, 2, 3],
            &[0xff, 1, 2, 3, 4, 5, 6, 7],
        ] {
            let err = super::read(bytes).unwrap_err();
            assert!(
                matches!(err, super::Error::Truncated),
                "{bytes:02x?}: {err}"
            );
        }
        println!("five prefixes cut short, five errors, nothing read past the end");
    }

    #[test]
    fn a_length_is_bounded_before_it_is_a_usize() {
        let bytes = fixture(THREE_HUNDRED_HEADERS);
        let (count, _) = super::read_len(&bytes, 300).unwrap();
        assert_eq!(count, 300);
        let err = super::read_len(&bytes, 299).unwrap_err();
        assert!(
            matches!(
                err,
                super::Error::TooLarge {
                    value: 300,
                    max: 299
                }
            ),
            "{err}"
        );
        println!("{THREE_HUNDRED_HEADERS} under 300: {count}; under 299: {err}");

        // The biggest value there is, against the smallest bound: no `usize`
        // conversion is asked to hold it.
        let err = super::read_len(&[0xff; 9], 0).unwrap_err();
        assert!(
            matches!(
                err,
                super::Error::TooLarge {
                    value: u64::MAX,
                    max: 0
                }
            ),
            "{err}"
        );
        println!("{err}");

        let (zero, rest) = super::read_len(&[0, 7], 0).unwrap();
        assert_eq!((zero, rest), (0, &[7][..]), "the bound is inclusive");
    }
}
