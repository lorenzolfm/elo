/// Core's `MAX_PROTOCOL_MESSAGE_LENGTH`, `src/net.h:65` at v31.1.
const MAX_PAYLOAD_BYTES: usize = 4_000_000;

const HEADER_BYTES: usize = 24;
const COMMAND_BYTES: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet3,
    Testnet4,
    Regtest,
}

impl Network {
    pub fn magic(self) -> [u8; 4] {
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

impl Command {
    pub const fn from_static(name: &'static str) -> Self {
        let bytes = name.as_bytes();
        assert!(!bytes.is_empty() && bytes.len() <= COMMAND_BYTES);
        let mut raw = [0u8; COMMAND_BYTES];
        let mut i = 0;
        while i < bytes.len() {
            assert!(bytes[i] >= b' ' && bytes[i] <= b'~');
            raw[i] = bytes[i];
            i += 1;
        }
        Self(raw)
    }

    /// The field as it sits on the wire, padding included.
    pub fn as_bytes(&self) -> &[u8; COMMAND_BYTES] {
        &self.0
    }
}

impl TryFrom<[u8; COMMAND_BYTES]> for Command {
    type Error = Error;

    fn try_from(raw: [u8; COMMAND_BYTES]) -> Result<Self, Error> {
        let name_len = raw.iter().position(|&b| b == 0).unwrap_or(COMMAND_BYTES);
        let (name, pad) = raw.split_at(name_len);
        let printable = name.iter().all(|b| (b' '..=b'~').contains(b));
        if !printable || pad.iter().any(|&b| b != 0) {
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

pub struct Frame {
    pub command: Command,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    BadMagic([u8; 4]),
    BadCommand([u8; COMMAND_BYTES]),
    TooLong(usize),
    BadChecksum { expected: [u8; 4], actual: [u8; 4] },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::BadMagic(m) => write!(f, "bad magic {m:02x?}"),
            Error::BadCommand(c) => write!(f, "bad command {c:02x?}"),
            Error::TooLong(n) => write!(f, "payload length {n} exceeds {MAX_PAYLOAD_BYTES}"),
            Error::BadChecksum { expected, actual } => {
                write!(f, "checksum {actual:02x?}, expected {expected:02x?}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = bitcoin_hashes::sha256d::Hash::hash(payload).to_byte_array();
    [hash[0], hash[1], hash[2], hash[3]]
}

pub fn write(
    w: &mut impl std::io::Write,
    network: Network,
    command: Command,
    payload: &[u8],
) -> Result<(), Error> {
    let len = match u32::try_from(payload.len()) {
        Ok(len) if payload.len() <= MAX_PAYLOAD_BYTES => len,
        _ => return Err(Error::TooLong(payload.len())),
    };

    let mut header = [0u8; HEADER_BYTES];
    header[..4].copy_from_slice(&network.magic());
    header[4..16].copy_from_slice(command.as_bytes());
    header[16..20].copy_from_slice(&len.to_le_bytes());
    header[20..].copy_from_slice(&checksum(payload));

    w.write_all(&header)?;
    w.write_all(payload)?;

    Ok(())
}

pub fn read(r: &mut impl std::io::Read, network: Network) -> Result<Frame, Error> {
    let mut header = [0u8; HEADER_BYTES];
    r.read_exact(&mut header)?;

    let [m0, m1, m2, m3, rest @ ..] = header;
    let [raw_command @ .., l0, l1, l2, l3, k0, k1, k2, k3] = rest;
    let recv_magic = [m0, m1, m2, m3];
    let raw_len = [l0, l1, l2, l3];
    let recv_checksum = [k0, k1, k2, k3];

    if recv_magic != network.magic() {
        return Err(Error::BadMagic(recv_magic));
    }

    let command = Command::try_from(raw_command)?;

    let Ok(len) = usize::try_from(u32::from_le_bytes(raw_len)) else {
        unreachable!("a u32 fits in usize on every target elo builds for")
    };

    if len > MAX_PAYLOAD_BYTES {
        return Err(Error::TooLong(len));
    }

    let mut payload = vec![0u8; len];

    r.read_exact(&mut payload)?;

    let actual_checksum = checksum(&payload);
    if actual_checksum != recv_checksum {
        return Err(Error::BadChecksum {
            expected: recv_checksum,
            actual: actual_checksum,
        });
    }

    Ok(Frame { command, payload })
}

#[cfg(test)]
mod tests {
    use super::{Command, Network};

    const VERACK: &str = "fabfb5da76657261636b000000000000000000005df6e0e2";
    const PING: &str = "fabfb5da70696e67000000000000000008000000335f19f0358313d39039497c";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn read_err(bytes: &[u8], network: Network) -> super::Error {
        match super::read(&mut &bytes[..], network) {
            Err(e) => e,
            Ok(_) => panic!("expected an error"),
        }
    }

    #[test]
    fn reads_core_verack() {
        let bytes = fixture(VERACK);
        let frame = super::read(&mut &bytes[..], Network::Regtest).unwrap();
        assert_eq!(frame.command, Command::from_static("verack"));
        assert!(frame.payload.is_empty());
        println!(
            "verack: {} bytes, checksum of nothing is {:02x?}",
            bytes.len(),
            &bytes[20..]
        );
    }

    #[test]
    fn reads_core_ping() {
        let bytes = fixture(PING);
        let frame = super::read(&mut &bytes[..], Network::Regtest).unwrap();
        assert_eq!(frame.command, Command::from_static("ping"));
        assert_eq!(frame.payload.len(), 8);
        println!("ping nonce (LE bytes): {:02x?}", frame.payload);
    }

    #[test]
    fn writes_bytes_identical_to_core() {
        for (name, hex) in [("verack", VERACK), ("ping", PING)] {
            let core = fixture(hex);
            let mut ours = Vec::new();
            let command = Command::from_static(name);
            super::write(
                &mut ours,
                Network::Regtest,
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
        let err = read_err(&fixture(VERACK), Network::Mainnet);
        assert!(matches!(err, super::Error::BadMagic(_)), "{err}");
        println!("mainnet reader on regtest bytes: {err}");
    }

    #[test]
    fn rejects_corrupted_payload() {
        let mut bytes = fixture(PING);
        bytes[24] ^= 1;
        let err = read_err(&bytes, Network::Regtest);
        assert!(matches!(err, super::Error::BadChecksum { .. }), "{err}");
        println!("one bit flipped in the nonce: {err}");
    }

    #[test]
    fn rejects_oversized_length_before_allocating() {
        let mut bytes = fixture(PING);
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = read_err(&bytes, Network::Regtest);
        assert!(matches!(err, super::Error::TooLong(0xffff_ffff)), "{err}");
        println!("length field says 4 GiB: {err}");
    }

    #[test]
    fn refuses_to_write_oversized_payload() {
        let payload = vec![0u8; super::MAX_PAYLOAD_BYTES + 1];
        let mut sink = Vec::new();
        let command = Command::from_static("block");
        let Err(err) = super::write(&mut sink, Network::Regtest, command, &payload) else {
            panic!("expected an error");
        };
        assert!(matches!(err, super::Error::TooLong(4_000_001)), "{err}");
        assert!(sink.is_empty(), "nothing reaches the wire");
        println!("one byte over the limit: {err}");
    }

    #[test]
    fn round_trips_a_twelve_byte_command() {
        const GETCFCHECKPT: Command = Command::from_static("getcfcheckpt");
        let mut bytes = Vec::new();
        super::write(&mut bytes, Network::Regtest, GETCFCHECKPT, &[]).unwrap();
        assert_eq!(&bytes[4..16], b"getcfcheckpt");
        let frame = super::read(&mut &bytes[..], Network::Regtest).unwrap();
        assert_eq!(frame.command, GETCFCHECKPT);
        println!("command field full, no NUL: {}", frame.command);
    }

    #[test]
    fn rejects_unprintable_command_byte() {
        let mut bytes = fixture(PING);
        bytes[4] = 0x7f;
        let err = read_err(&bytes, Network::Regtest);
        assert!(matches!(err, super::Error::BadCommand(_)), "{err}");
        println!("DEL in the command: {err}");
    }

    #[test]
    fn reports_a_truncated_payload_as_io() {
        let bytes = fixture(PING);
        let err = read_err(&bytes[..bytes.len() - 1], Network::Regtest);
        let super::Error::Io(io) = err else {
            panic!("expected io, got {err}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
        println!("peer hung up one byte short: {io}");
    }

    #[test]
    fn rejects_padding_that_is_not_nul() {
        let mut bytes = fixture(VERACK);
        bytes[15] = b'x';
        let err = read_err(&bytes, Network::Regtest);
        assert!(matches!(err, super::Error::BadCommand(_)), "{err}");
    }

    #[test]
    fn accepts_an_all_nul_command_as_core_does() {
        let mut bytes = fixture(VERACK);
        bytes[4..16].fill(0);
        let frame = super::read(&mut &bytes[..], Network::Regtest).unwrap();
        assert_eq!(frame.command.to_string(), "");
        println!(
            "twelve NUL bytes: command {:?}, Core's IsMessageTypeValid says yes too",
            frame.command.to_string()
        );
    }

    #[test]
    fn a_read_command_can_always_be_written_back() {
        let bytes = fixture(PING);
        let frame = super::read(&mut &bytes[..], Network::Regtest).unwrap();
        let mut again = Vec::new();
        super::write(&mut again, Network::Regtest, frame.command, &frame.payload).unwrap();
        assert_eq!(again, bytes);
        println!("read then write: {} bytes, unchanged", again.len());
    }

    #[test]
    fn magic_matches_chainparams() {
        for (network, hex) in [
            (Network::Mainnet, "f9beb4d9"),
            (Network::Testnet3, "0b110907"),
            (Network::Testnet4, "1c163f28"),
            (Network::Regtest, "fabfb5da"),
        ] {
            assert_eq!(network.magic().to_vec(), fixture(hex), "{network:?}");
        }
        println!("four networks, four magics, all from chainparams.cpp");
    }
}
