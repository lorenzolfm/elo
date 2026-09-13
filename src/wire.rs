//! What a frame means. The envelope (`message.rs`) checks magic, length and
//! checksum and hands over a command and a payload; this module turns that
//! pair into a value, and a value back into the pair.
//!
//! `decode` is pure: no socket, no clock. It checks each payload's size once,
//! here, so nothing downstream handles a length.

const VERSION: crate::message::Command = crate::message::Command::from_static("version");
const VERACK: crate::message::Command = crate::message::Command::from_static("verack");
const PING: crate::message::Command = crate::message::Command::from_static("ping");
const PONG: crate::message::Command = crate::message::Command::from_static("pong");

/// `ping` and `pong` carry one `u64` nonce since BIP31. Core reads exactly
/// that from a `ping` (`../bitcoin/src/net_processing.cpp:4973` at v31.1)
/// and echoes it in the `pong` (`:4985`).
const NONCE_BYTES: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// The payload as it came. Reading the fields is step 4; until then the
    /// handshake needs only to recognise the command.
    Version(Vec<u8>),
    Verack,
    Ping(u64),
    Pong(u64),
    /// A command we do not speak. Core logs it and carries on
    /// (`net_processing.cpp:5167`); a newer peer must not cost us the
    /// connection.
    Unknown(crate::message::Frame),
}

#[derive(Debug)]
pub enum Error {
    /// A command we know, with a payload of a size it cannot have.
    BadLength {
        command: crate::message::Command,
        len: usize,
        expected: usize,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadLength {
                command,
                len,
                expected,
            } => write!(f, "{command} payload is {len} bytes, expected {expected}"),
        }
    }
}

impl std::error::Error for Error {}

impl Message {
    /// Takes the frame by value: an unknown payload passes through
    /// untouched, and a known one is moved, not copied.
    pub fn decode(frame: crate::message::Frame) -> Result<Message, Error> {
        match frame.command {
            VERSION => Ok(Message::Version(frame.payload)),
            VERACK if frame.payload.is_empty() => Ok(Message::Verack),
            VERACK => Err(bad_length(&frame, 0)),
            PING => Ok(Message::Ping(nonce(&frame)?)),
            PONG => Ok(Message::Pong(nonce(&frame)?)),
            _ => Ok(Message::Unknown(frame)),
        }
    }

    pub fn encode(self) -> crate::message::Frame {
        let (command, payload) = match self {
            Message::Version(payload) => (VERSION, payload),
            Message::Verack => (VERACK, Vec::new()),
            Message::Ping(nonce) => (PING, nonce.to_le_bytes().to_vec()),
            Message::Pong(nonce) => (PONG, nonce.to_le_bytes().to_vec()),
            Message::Unknown(frame) => return frame,
        };
        crate::message::Frame { command, payload }
    }
}

impl std::fmt::Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Message::Version(payload) => write!(f, "version ({} bytes)", payload.len()),
            Message::Verack => write!(f, "verack"),
            Message::Ping(nonce) => write!(f, "ping {nonce:#018x}"),
            Message::Pong(nonce) => write!(f, "pong {nonce:#018x}"),
            Message::Unknown(frame) => {
                write!(f, "{} ({} bytes)", frame.command, frame.payload.len())
            }
        }
    }
}

fn bad_length(frame: &crate::message::Frame, expected: usize) -> Error {
    Error::BadLength {
        command: frame.command,
        len: frame.payload.len(),
        expected,
    }
}

fn nonce(frame: &crate::message::Frame) -> Result<u64, Error> {
    // `try_from` fails on exactly one condition: the slice is not 8 bytes.
    <[u8; NONCE_BYTES]>::try_from(frame.payload.as_slice())
        .map(u64::from_le_bytes)
        .map_err(|_| bad_length(frame, NONCE_BYTES))
}

#[cfg(test)]
mod tests {
    // Every frame below was sent by Bitcoin Core v31.1.0, `bitcoind -regtest`,
    // on 2026-09-13, in this order, to a throwaway Python script over a raw
    // TCP socket. The script sent `version`, then `verack` after Core's, then
    // `ping` with nonce 0x0123456789abcdef; `pong` is Core's answer to it.
    const VERSION: &str = "fabfb5da76657273696f6e000000000066000000c975755780110100090c00000000000058efa66a000000000000000000000000000000000000000000000000000000000000090c000000000000000000000000000000000000000000000000c732f4e357ca9782102f5361746f7368693a33312e312e302f0000000001";
    const WTXIDRELAY: &str = "fabfb5da777478696472656c61790000000000005df6e0e2";
    const SENDADDRV2: &str = "fabfb5da73656e646164647276320000000000005df6e0e2";
    const VERACK: &str = "fabfb5da76657261636b000000000000000000005df6e0e2";
    const SENDCMPCT: &str = "fabfb5da73656e64636d70637400000009000000e92f5ef8000200000000000000";
    const PING: &str = "fabfb5da70696e670000000000000000080000000518a0f806d2e2149c8064fd";
    const FEEFILTER: &str = "fabfb5da66656566696c746572000000080000000a19f7997a9e970000000000";
    const PONG: &str = "fabfb5da706f6e6700000000000000000800000033bc15e5efcdab8967452301";

    const OUR_NONCE: u64 = 0x0123_4567_89ab_cdef;

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn frame(hex: &str) -> crate::message::Frame {
        let bytes = fixture(hex);
        crate::message::read(&mut &bytes[..], crate::message::Network::Regtest).unwrap()
    }

    fn decode(hex: &str) -> super::Message {
        super::Message::decode(frame(hex)).unwrap()
    }

    fn encode_to_wire(message: super::Message) -> Vec<u8> {
        let frame = message.encode();
        let mut bytes = Vec::new();
        crate::message::write(
            &mut bytes,
            crate::message::Network::Regtest,
            frame.command,
            &frame.payload,
        )
        .unwrap();
        bytes
    }

    #[test]
    fn decodes_every_core_frame_in_order() {
        use super::Message;
        let all = [
            VERSION, WTXIDRELAY, SENDADDRV2, VERACK, SENDCMPCT, PING, FEEFILTER, PONG,
        ];
        let messages: Vec<Message> = all.iter().map(|hex| decode(hex)).collect();

        let Message::Version(payload) = &messages[0] else {
            panic!("{}", messages[0]);
        };
        assert_eq!(payload, &fixture(VERSION)[24..], "payload kept as it came");
        assert_eq!(messages[3], Message::Verack);
        let Message::Ping(nonce) = messages[5] else {
            panic!("{}", messages[5]);
        };
        assert_eq!(
            nonce.to_le_bytes(),
            fixture(PING)[24..],
            "the nonce is little-endian on the wire"
        );
        assert_eq!(
            messages[7],
            Message::Pong(OUR_NONCE),
            "Core echoed our nonce"
        );
        for (i, name) in [
            (1, "wtxidrelay"),
            (2, "sendaddrv2"),
            (4, "sendcmpct"),
            (6, "feefilter"),
        ] {
            let Message::Unknown(frame) = &messages[i] else {
                panic!("{}", messages[i]);
            };
            assert_eq!(frame.command.to_string(), name);
        }

        for message in &messages {
            println!("<- {message}");
        }
    }

    #[test]
    fn our_pong_is_core_pong_byte_for_byte() {
        let ours = encode_to_wire(super::Message::Pong(OUR_NONCE));
        assert_eq!(ours, fixture(PONG));
        println!(
            "pong {OUR_NONCE:#018x}: {} bytes, identical to Core's",
            ours.len()
        );
    }

    #[test]
    fn our_ping_and_verack_are_core_bytes() {
        let super::Message::Ping(nonce) = decode(PING) else {
            panic!("not a ping");
        };
        assert_eq!(encode_to_wire(super::Message::Ping(nonce)), fixture(PING));
        assert_eq!(encode_to_wire(super::Message::Verack), fixture(VERACK));
        println!("ping {nonce:#018x} and verack re-encode to Core's frames");
    }

    #[test]
    fn unknown_passes_through_unchanged() {
        let original = frame(SENDCMPCT);
        let message = super::Message::decode(original.clone()).unwrap();
        assert_eq!(message.encode(), original);
        println!("sendcmpct: decode then encode is the identity");
    }

    fn malformed(command: &'static str, len: usize) -> super::Error {
        let frame = crate::message::Frame {
            command: crate::message::Command::from_static(command),
            payload: vec![0; len],
        };
        super::Message::decode(frame).unwrap_err()
    }

    #[test]
    fn rejects_a_nonce_of_the_wrong_size() {
        for (command, len) in [("ping", 7), ("ping", 9), ("pong", 0)] {
            let err = malformed(command, len);
            assert!(
                matches!(err, super::Error::BadLength { expected: 8, .. }),
                "{err}"
            );
            println!("{err}");
        }
        println!("Core reads eight bytes and ignores the rest; we do not");
    }

    #[test]
    fn rejects_a_verack_with_a_payload() {
        let err = malformed("verack", 1);
        assert!(
            matches!(
                err,
                super::Error::BadLength {
                    len: 1,
                    expected: 0,
                    ..
                }
            ),
            "{err}"
        );
        println!("{err}; Core does not look at a verack's payload");
    }
}
