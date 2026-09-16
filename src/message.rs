/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH`, `src/net.h:65` at v31.1.
const MAX_PAYLOAD_BYTES: usize = 4_000_000;

pub(crate) const HEADER_BYTES: usize = 24;
const COMMAND_BYTES: usize = 12;

// The header is magic, command, length, checksum.
const _: () = assert!(4 + COMMAND_BYTES + 4 + 4 == HEADER_BYTES);

// The length field is a `u32`. `read` converts it to `usize` and treats failure as unreachable; this is why it is.
const _: () = assert!(usize::BITS >= 32);

/// `PartialEq` because `sync::run` asserts that the chain and the
/// connection it syncs from are on one network.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Regtest,
}

impl Network {
    fn magic(self) -> [u8; 4] {
        match self {
            Network::Mainnet => [0xf9, 0xbe, 0xb4, 0xd9],
            Network::Testnet3 => [0x0b, 0x11, 0x09, 0x07],
            Network::Testnet4 => [0x1c, 0x16, 0x3f, 0x28],
            Network::Regtest => [0xfa, 0xbf, 0xb5, 0xda],
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Command([u8; COMMAND_BYTES]);

/// Core's `IsMessageTypeValid`, `src/protocol.cpp:26` at v31.1: the name is printable ASCII, `0x20` to `0x7e`.
const fn is_printable(byte: u8) -> bool {
    byte >= b' ' && byte <= b'~'
}

impl Command {
    pub(crate) const fn from_static(name: &'static str) -> Self {
        let bytes = name.as_bytes();
        assert!(!bytes.is_empty());
        assert!(bytes.len() <= COMMAND_BYTES);
        let mut raw = [0u8; COMMAND_BYTES];
        let mut i = 0;
        while i < bytes.len() {
            assert!(is_printable(bytes[i]));
            raw[i] = bytes[i];
            i += 1;
        }
        Self(raw)
    }

    fn as_bytes(&self) -> &[u8; COMMAND_BYTES] {
        &self.0
    }
}

impl TryFrom<[u8; COMMAND_BYTES]> for Command {
    type Error = Error;

    fn try_from(raw: [u8; COMMAND_BYTES]) -> Result<Self, Error> {
        let name_len = raw.iter().position(|&b| b == 0).unwrap_or(COMMAND_BYTES);
        let (name, padding) = raw.split_at(name_len);
        if name.is_empty() {
            return Err(Error::BadCommand(raw));
        }
        if !name.iter().all(|&byte| is_printable(byte)) {
            return Err(Error::BadCommand(raw));
        }
        if padding.iter().any(|&byte| byte != 0) {
            return Err(Error::BadCommand(raw));
        }
        Ok(Self(raw))
    }
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_bytes()
            .iter()
            .take_while(|&&b| b != 0)
            .try_for_each(|&b| std::fmt::Write::write_char(f, char::from(b)))
    }
}

#[derive(Debug)]
pub struct Frame {
    pub command: Command,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    BadMagic([u8; 4]),
    BadCommand([u8; COMMAND_BYTES]),
    PayloadTooLong(usize),
    BadChecksum { claimed: [u8; 4], computed: [u8; 4] },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(io) => write!(f, "io: {io}"),
            Error::BadMagic(magic) => write!(f, "bad magic {magic:02x?}"),
            Error::BadCommand(command) => write!(f, "bad command {command:02x?}"),
            Error::PayloadTooLong(len) => {
                write!(f, "payload length {len} exceeds {MAX_PAYLOAD_BYTES}")
            }
            Error::BadChecksum { claimed, computed } => {
                write!(
                    f,
                    "checksum claimed {claimed:02x?}, computed {computed:02x?}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(io: std::io::Error) -> Self {
        Error::Io(io)
    }
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = bitcoin_hashes::sha256d::Hash::hash(payload).to_byte_array();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Writes one frame: the header, then `payload`.
///
/// # Errors
///
/// `PayloadTooLong` if `payload` is longer than `MAX_PAYLOAD_BYTES`; nothing
/// reaches `writer`. `Io` if `writer` fails.
pub fn write(
    writer: &mut impl std::io::Write,
    network: Network,
    command: Command,
    payload: &[u8],
) -> Result<(), Error> {
    let len = match u32::try_from(payload.len()) {
        Ok(len) if payload.len() <= MAX_PAYLOAD_BYTES => len,
        _ => return Err(Error::PayloadTooLong(payload.len())),
    };

    let mut header = [0u8; HEADER_BYTES];
    header[..4].copy_from_slice(&network.magic());
    header[4..16].copy_from_slice(command.as_bytes());
    header[16..20].copy_from_slice(&len.to_le_bytes());
    header[20..].copy_from_slice(&checksum(payload));

    writer.write_all(&header)?;
    writer.write_all(payload)?;

    Ok(())
}

/// Reads one frame. The length field is bounded by `MAX_PAYLOAD_BYTES`
/// before the payload is allocated.
///
/// # Errors
///
/// `Io` if `reader` fails or ends early. `BadMagic`, `BadCommand`,
/// `PayloadTooLong` and `BadChecksum` name the header field Core would
/// reject.
///
/// # Panics
///
/// If `usize` is narrower than `u32`. The compile-time assertion beside
/// `HEADER_BYTES` rules that out on every target elo builds for.
pub fn read(reader: &mut impl std::io::Read, network: Network) -> Result<Frame, Error> {
    let mut header = [0u8; HEADER_BYTES];
    reader.read_exact(&mut header)?;

    let [m0, m1, m2, m3, rest @ ..] = header;
    let [raw_command @ .., l0, l1, l2, l3, k0, k1, k2, k3] = rest;
    let received_magic = [m0, m1, m2, m3];
    let raw_len = [l0, l1, l2, l3];
    let received_checksum = [k0, k1, k2, k3];

    if received_magic != network.magic() {
        return Err(Error::BadMagic(received_magic));
    }

    let command = Command::try_from(raw_command)?;

    let Ok(len) = usize::try_from(u32::from_le_bytes(raw_len)) else {
        unreachable!("a u32 fits in usize on every target elo builds for")
    };

    if len > MAX_PAYLOAD_BYTES {
        return Err(Error::PayloadTooLong(len));
    }

    // A fresh allocation per frame, up to 4 MB. With one peer and blocking
    // I/O the cost is not felt. When it is, the caller owns one buffer and
    // `read` fills it; `Frame` changes with it.
    let mut payload = vec![0u8; len];

    reader.read_exact(&mut payload)?;

    let computed_checksum = checksum(&payload);
    if computed_checksum != received_checksum {
        return Err(Error::BadChecksum {
            claimed: received_checksum,
            computed: computed_checksum,
        });
    }

    Ok(Frame { command, payload })
}

#[cfg(test)]
mod tests {
    // Both frames were sent by Bitcoin Core v31.1.0, `bitcoind -regtest`, on
    // 2026-09-13. A throwaway Python script sent `version` and `verack` over a
    // raw TCP socket and hex-dumped everything Core answered.
    const VERACK: &str = "fabfb5da76657261636b000000000000000000005df6e0e2";
    const PING: &str = "fabfb5da70696e670000000000000000080000008626b8926616846538060637";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn read_err(bytes: &[u8], network: super::Network) -> super::Error {
        match super::read(&mut &bytes[..], network) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn reads_core_verack() {
        // Red if `read` demands at least one payload byte.
        let bytes = fixture(VERACK);
        let frame = super::read(&mut &bytes[..], super::Network::Regtest).unwrap();
        assert_eq!(frame.command, super::Command::from_static("verack"));
        assert!(frame.payload.is_empty());
        println!(
            "verack: {} bytes, checksum of nothing is {:02x?}",
            bytes.len(),
            &bytes[20..]
        );
    }

    #[test]
    fn reads_core_ping() {
        // Red if the length field is read big-endian.
        let bytes = fixture(PING);
        let frame = super::read(&mut &bytes[..], super::Network::Regtest).unwrap();
        assert_eq!(frame.command, super::Command::from_static("ping"));
        assert_eq!(frame.payload.len(), 8);
        println!("ping nonce (LE bytes): {:02x?}", frame.payload);
    }

    #[test]
    fn writes_bytes_identical_to_core() {
        // Red if `write` puts the length before the command, or writes it big-endian.
        for (name, hex) in [("verack", VERACK), ("ping", PING)] {
            let core = fixture(hex);
            let mut ours = Vec::new();
            let command = super::Command::from_static(name);
            super::write(
                &mut ours,
                super::Network::Regtest,
                command,
                &core[super::HEADER_BYTES..],
            )
            .unwrap();
            assert_eq!(ours, core, "{name}");
            println!(
                "{name}: our {} bytes match Core's byte for byte",
                ours.len()
            );
        }
    }

    #[test]
    fn rejects_wrong_magic() {
        // Red if the magic check is missing.
        let err = read_err(&fixture(VERACK), super::Network::Mainnet);
        assert!(matches!(err, super::Error::BadMagic(_)), "{err}");
        println!("mainnet reader on regtest bytes: {err}");
    }

    #[test]
    fn rejects_corrupted_payload() {
        // Red if the checksum check is missing.
        let mut bytes = fixture(PING);
        bytes[24] ^= 1;
        let err = read_err(&bytes, super::Network::Regtest);
        assert!(matches!(err, super::Error::BadChecksum { .. }), "{err}");
        println!("one bit flipped in the nonce: {err}");
    }

    #[test]
    fn rejects_oversized_length() {
        // Red if the length check is missing, or allows one byte over.
        let mut bytes = fixture(PING);
        bytes[16..20].copy_from_slice(&4_000_001u32.to_le_bytes());
        let err = read_err(&bytes, super::Network::Regtest);
        assert!(
            matches!(err, super::Error::PayloadTooLong(4_000_001)),
            "{err}"
        );
        println!("length field one over the limit: {err}");
    }

    #[test]
    fn reads_and_writes_a_payload_at_the_limit() {
        // Red if the length check is `>=` instead of `>`, in `read` or `write`.
        //
        // No captured frame carries 4,000,000 bytes, so the header is built by
        // hand: Core's `MAX_PROTOCOL_MESSAGE_LENGTH`, `src/net.h:65` at v31.1,
        // is the last length Core accepts. The checksum comes from
        // `super::checksum`, which `writes_bytes_identical_to_core` already
        // pins to Core's bytes.
        let payload = vec![0u8; super::MAX_PAYLOAD_BYTES];
        let command = super::Command::from_static("block");
        let mut header = [0u8; super::HEADER_BYTES];
        header[..4].copy_from_slice(&super::Network::Regtest.magic());
        header[4..16].copy_from_slice(command.as_bytes());
        header[16..20].copy_from_slice(&4_000_000u32.to_le_bytes());
        header[20..].copy_from_slice(&super::checksum(&payload));

        let mut reader = std::io::Read::chain(&header[..], &payload[..]);
        let frame = super::read(&mut reader, super::Network::Regtest).unwrap();
        assert_eq!(frame.command, command);
        assert_eq!(frame.payload.len(), super::MAX_PAYLOAD_BYTES);

        let mut ours = Vec::new();
        super::write(&mut ours, super::Network::Regtest, command, &payload).unwrap();
        assert_eq!(&ours[..super::HEADER_BYTES], &header);
        assert_eq!(ours.len(), super::HEADER_BYTES + super::MAX_PAYLOAD_BYTES);
        println!(
            "{} payload bytes: read and written, checksum {:02x?}",
            frame.payload.len(),
            &header[20..]
        );
    }

    #[test]
    fn refuses_to_write_oversized_payload() {
        // Red if `write` does not bound the payload, or writes the header before it checks.
        let payload = vec![0u8; super::MAX_PAYLOAD_BYTES + 1];
        let mut sink = Vec::new();
        let command = super::Command::from_static("block");
        let Err(err) = super::write(&mut sink, super::Network::Regtest, command, &payload) else {
            panic!("expected an error");
        };
        assert!(
            matches!(err, super::Error::PayloadTooLong(4_000_001)),
            "{err}"
        );
        assert!(sink.is_empty(), "nothing reaches the wire");
        println!("one byte over the limit: {err}");
    }

    #[test]
    fn writes_a_twelve_byte_command() {
        // Red if `write` truncates the command to leave room for a NUL.
        const GETCFCHECKPT: super::Command = super::Command::from_static("getcfcheckpt");
        let mut bytes = Vec::new();
        super::write(&mut bytes, super::Network::Regtest, GETCFCHECKPT, &[]).unwrap();
        assert_eq!(&bytes[4..16], b"getcfcheckpt");
        println!("command field full, no NUL: {:02x?}", &bytes[4..16]);
    }

    #[test]
    fn reads_a_twelve_byte_command() {
        // Red if `Command::try_from` requires a NUL terminator.
        //
        // No captured frame fills the command field, so the header is built by
        // hand. Core reads the name up to the first NUL or byte 12, whichever
        // comes first (`CMessageHeader::GetMessageType`, `src/protocol.cpp:21`
        // at v31.1). The checksum of the empty payload is taken from the
        // captured `VERACK` frame.
        let verack = fixture(VERACK);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&super::Network::Regtest.magic());
        bytes.extend_from_slice(b"getcfcheckpt");
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&verack[20..]);
        let frame = super::read(&mut &bytes[..], super::Network::Regtest).unwrap();
        assert_eq!(frame.command, super::Command::from_static("getcfcheckpt"));
        println!("command field full, no NUL: {}", frame.command);
    }

    #[test]
    fn rejects_unprintable_command_byte() {
        // Red if `is_printable` drops either bound.
        for (name, byte) in [("US", 0x1f), ("DEL", 0x7f)] {
            let mut bytes = fixture(PING);
            bytes[4] = byte;
            let err = read_err(&bytes, super::Network::Regtest);
            assert!(matches!(err, super::Error::BadCommand(_)), "{err}");
            println!("{name} in the command: {err}");
        }
    }

    #[test]
    fn accepts_command_bytes_at_the_printable_bounds() {
        // Red if `is_printable` is `>` instead of `>=`, or `<` instead of `<=`.
        //
        // Core's `IsMessageTypeValid`, `src/protocol.cpp:26` at v31.1, accepts
        // `0x20` to `0x7e` inclusive.
        for byte in [0x20, 0x7e] {
            let mut bytes = fixture(PING);
            bytes[4] = byte;
            let frame = super::read(&mut &bytes[..], super::Network::Regtest).unwrap();
            assert_eq!(frame.command.as_bytes()[0], byte);
            println!(
                "first command byte {byte:#04x}: read as `{}`",
                frame.command
            );
        }
    }

    #[test]
    fn reports_a_truncated_payload_as_io() {
        // Red if `read` accepts a short payload instead of demanding every byte.
        let bytes = fixture(PING);
        let err = read_err(&bytes[..bytes.len() - 1], super::Network::Regtest);
        let super::Error::Io(io) = err else {
            panic!("expected io, got {err}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
        println!("peer hung up one byte short: {io}");
    }

    #[test]
    fn rejects_padding_that_is_not_nul() {
        // Red if the padding check is missing.
        let mut bytes = fixture(VERACK);
        bytes[15] = b'x';
        let err = read_err(&bytes, super::Network::Regtest);
        assert!(matches!(err, super::Error::BadCommand(_)), "{err}");
        println!("`x` after the NUL padding of verack: {err}");
    }

    #[test]
    fn rejects_an_all_nul_command() {
        // Red if the empty-name check is missing.
        let mut bytes = fixture(VERACK);
        bytes[4..16].fill(0);
        let err = read_err(&bytes, super::Network::Regtest);
        assert!(matches!(err, super::Error::BadCommand(_)), "{err}");
        println!("twelve NUL bytes, which Core would accept: {err}");
    }

    #[test]
    fn magic_matches_chainparams() {
        // Red if a magic constant has a typo or is byte-swapped.
        for (network, hex) in [
            (super::Network::Mainnet, "f9beb4d9"),
            (super::Network::Testnet3, "0b110907"),
            (super::Network::Testnet4, "1c163f28"),
            (super::Network::Regtest, "fabfb5da"),
        ] {
            assert_eq!(network.magic().to_vec(), fixture(hex), "{network:?}");
        }
        println!("four networks, four magics, all from chainparams.cpp");
    }
}
