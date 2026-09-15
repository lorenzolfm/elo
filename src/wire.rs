//! What a frame means. The envelope (`message.rs`) checks magic, length and
//! checksum and hands over a command and a payload; this module turns that
//! pair into a value, and a value back into the pair.

const VERSION: crate::message::Command = crate::message::Command::from_static("version");
const VERACK: crate::message::Command = crate::message::Command::from_static("verack");
const PING: crate::message::Command = crate::message::Command::from_static("ping");
const PONG: crate::message::Command = crate::message::Command::from_static("pong");
const GETHEADERS: crate::message::Command = crate::message::Command::from_static("getheaders");
const HEADERS: crate::message::Command = crate::message::Command::from_static("headers");

/// `ping` and `pong` carry one `u64` nonce since BIP31. Core reads exactly
/// that from a `ping` (`../bitcoin/src/net_processing.cpp:4973` at v31.1)
/// and echoes it in the `pong` (`:4985`).
const NONCE_BYTES: usize = 8;

#[derive(Debug)]
pub enum Message {
    /// The payload as it came. The one `version` that counts is parsed inside
    /// the handshake; any other is a redundant one, which Core drops before it
    /// reads a field (`net_processing.cpp:3586`), and so do we.
    Version(Vec<u8>),
    Verack,
    Ping(u64),
    Pong(u64),
    GetHeaders(crate::headers::GetHeaders),
    Headers(crate::headers::Headers),
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
        len_actual: usize,
        len_expected: usize,
    },
    /// A command we know, with a payload that does not parse.
    BadPayload {
        command: crate::message::Command,
        error: crate::headers::Error,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadLength {
                command,
                len_actual,
                len_expected,
            } => write!(
                f,
                "{command} payload is {len_actual} bytes, expected {len_expected}"
            ),
            Error::BadPayload { command, error } => write!(f, "{command} payload: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl Message {
    /// Turns a frame into the message it carries.
    ///
    /// # Errors
    ///
    /// `BadLength` if a command we know carries a payload of a size it
    /// cannot have. `BadPayload` if a `getheaders` or `headers` payload does
    /// not parse.
    pub fn decode(frame: crate::message::Frame) -> Result<Message, Error> {
        match frame.command {
            VERSION => Ok(Message::Version(frame.payload)),
            VERACK if frame.payload.is_empty() => Ok(Message::Verack),
            VERACK => Err(bad_length(&frame, 0)),
            PING => Ok(Message::Ping(nonce(&frame)?)),
            PONG => Ok(Message::Pong(nonce(&frame)?)),
            GETHEADERS => crate::headers::GetHeaders::parse(&frame.payload)
                .map(Message::GetHeaders)
                .map_err(|error| bad_payload(&frame, error)),
            HEADERS => crate::headers::Headers::parse(&frame.payload)
                .map(Message::Headers)
                .map_err(|error| bad_payload(&frame, error)),
            _ => Ok(Message::Unknown(frame)),
        }
    }

    #[must_use]
    pub fn encode(self) -> crate::message::Frame {
        let (command, payload) = match self {
            Message::Version(payload) => (VERSION, payload),
            Message::Verack => (VERACK, Vec::new()),
            Message::Ping(nonce) => (PING, nonce.to_le_bytes().to_vec()),
            Message::Pong(nonce) => (PONG, nonce.to_le_bytes().to_vec()),
            Message::GetHeaders(request) => (GETHEADERS, request.encode()),
            Message::Headers(headers) => (HEADERS, headers.encode()),
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
            Message::GetHeaders(request) => {
                write!(f, "getheaders ({} locator hashes)", request.locator.len())
            }
            Message::Headers(headers) => write!(f, "headers ({})", headers.len()),
            Message::Unknown(frame) => {
                write!(f, "{} ({} bytes)", frame.command, frame.payload.len())
            }
        }
    }
}

fn bad_length(frame: &crate::message::Frame, len_expected: usize) -> Error {
    Error::BadLength {
        command: frame.command,
        len_actual: frame.payload.len(),
        len_expected,
    }
}

fn bad_payload(frame: &crate::message::Frame, error: crate::headers::Error) -> Error {
    Error::BadPayload {
        command: frame.command,
        error,
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
    // Two more, from `bitcoind -regtest` after `generatetoaddress 3` on
    // 2026-09-15: Core's `getheaders` to a listening script that claimed
    // `NODE_NETWORK`, and Core's `headers` to a script that asked from
    // genesis. `headers.rs` has the chain and the capture.
    const GETHEADERS: &str = "fabfb5da676574686561646572730000850000008c4a998480110100030e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2834cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b23306226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000000000000000000000000000000000000000000000000000000000000000";
    const HEADERS: &str = "fabfb5da686561646572730000000000f40000002f52e50d030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fce25a9ef6a61909eadcc696fb71eb4d3216de17cc3731ecdd321a030e9213a1226cda96affff7f2000000000000000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000000000200e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2869ee5ba689a2d757c652f917d12a43c9b24ba79dcff22abbea56c075d3d2bd7227cda96affff7f200000000000";

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
        assert_eq!(
            payload,
            &fixture(VERSION)[crate::message::HEADER_BYTES..],
            "payload kept as it came"
        );
        assert!(matches!(messages[3], Message::Verack), "{}", messages[3]);
        let Message::Ping(nonce) = messages[5] else {
            panic!("{}", messages[5]);
        };
        assert_eq!(
            nonce.to_le_bytes(),
            fixture(PING)[crate::message::HEADER_BYTES..],
            "the nonce is little-endian on the wire"
        );
        assert!(
            matches!(messages[7], Message::Pong(OUR_NONCE)),
            "Core echoed our nonce: {}",
            messages[7]
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
        let again = super::Message::decode(frame(SENDCMPCT)).unwrap().encode();
        assert_eq!(again.command, original.command);
        assert_eq!(again.payload, original.payload);
        println!("sendcmpct: decode then encode is the identity");
    }

    #[test]
    fn decodes_core_getheaders_and_headers() {
        // Red if either command falls through to `Unknown`, or the two are
        // swapped.
        let request = decode(GETHEADERS);
        let super::Message::GetHeaders(inner) = &request else {
            panic!("{request}");
        };
        assert_eq!(inner.locator.len(), 3);
        assert_eq!(request.to_string(), "getheaders (3 locator hashes)");
        let reply = decode(HEADERS);
        let super::Message::Headers(headers) = &reply else {
            panic!("{reply}");
        };
        assert_eq!(headers.len(), 3);
        assert_eq!(reply.to_string(), "headers (3)");
        println!("<- {request}\n<- {reply}");
    }

    #[test]
    fn getheaders_and_headers_re_encode_to_core_frames() {
        // Red if either message encodes under the wrong command, or the
        // payload comes back changed.
        for hex in [GETHEADERS, HEADERS] {
            let ours = encode_to_wire(decode(hex));
            assert_eq!(ours, fixture(hex));
            println!("{}: {} bytes, identical to Core's", decode(hex), ours.len());
        }
    }

    #[test]
    fn a_payload_that_does_not_parse_names_its_command() {
        // Red if a payload error is dropped and the frame becomes `Unknown`,
        // or the error loses the command it came from.
        let mut bytes = fixture(HEADERS);
        bytes[crate::message::HEADER_BYTES] = 4;
        let frame = crate::message::Frame {
            command: crate::message::Command::from_static("headers"),
            payload: bytes[crate::message::HEADER_BYTES..].to_vec(),
        };
        let err = super::Message::decode(frame).unwrap_err();
        assert!(
            matches!(
                &err,
                super::Error::BadPayload { command, error: crate::headers::Error::Truncated }
                    if command.to_string() == "headers"
            ),
            "{err}"
        );
        assert_eq!(err.to_string(), "headers payload: payload truncated");
        println!("count 4 over three headers: {err}");
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
                matches!(
                    err,
                    super::Error::BadLength {
                        len_expected: 8,
                        ..
                    }
                ),
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
                    len_actual: 1,
                    len_expected: 0,
                    ..
                }
            ),
            "{err}"
        );
        println!("{err}; Core does not look at a verack's payload");
    }
}
