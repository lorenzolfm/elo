//! Message types and payloads.

use std::net::Ipv6Addr;

use crate::serialize::{Decode, Encode, Error, read_limited_string, write_string};

/// The longest user agent a `version` may carry.
pub const MAX_SUBVERSION_LENGTH: usize = 256;

/// The message type in a header: printable ASCII, then NUL padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageType([u8; 12]);

pub const VERSION: MessageType = MessageType(*b"version\0\0\0\0\0");

pub const VERACK: MessageType = MessageType(*b"verack\0\0\0\0\0\0");

impl MessageType {
    /// `None` unless the bytes are printable ASCII followed only by NULs.
    pub fn new(bytes: [u8; 12]) -> Option<Self> {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let (name, padding) = bytes.split_at(end);
        let valid =
            name.iter().all(|b| (b' '..=b'~').contains(b)) && padding.iter().all(|&b| b == 0);
        valid.then_some(Self(bytes))
    }

    /// The 12 bytes, with the padding.
    pub const fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// A message header. `transport` checks the magic, so the header does not keep it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    pub msg_type: MessageType,
    /// The length of the payload in bytes.
    pub length: u32,
    /// The first four bytes of the sha256d of the payload.
    pub checksum: [u8; 4],
}

/// The services a node offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceFlags(pub u64);

impl Encode for ServiceFlags {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for ServiceFlags {
    fn decode(input: &mut &[u8]) -> Result<Self, Error> {
        u64::decode(input).map(Self)
    }
}

/// An address as a `version` carries it. An IPv4 address is IPv4-mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    pub services: ServiceFlags,
    pub ip: Ipv6Addr,
    pub port: u16,
}

/// The port is big-endian.
impl Encode for Address {
    fn encode(&self, out: &mut Vec<u8>) {
        self.services.encode(out);
        self.ip.octets().encode(out);
        self.port.to_be_bytes().encode(out);
    }
}

impl Decode for Address {
    fn decode(input: &mut &[u8]) -> Result<Self, Error> {
        Ok(Self {
            services: ServiceFlags::decode(input)?,
            ip: Ipv6Addr::from(<[u8; 16]>::decode(input)?),
            port: u16::from_be_bytes(Decode::decode(input)?),
        })
    }
}

/// The `version` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub version: i32,
    pub services: ServiceFlags,
    pub timestamp: i64,
    pub addr_recv: Address,
    pub addr_from: Address,
    pub nonce: u64,
    /// Raw bytes, which need not be UTF-8.
    pub user_agent: Vec<u8>,
    pub start_height: i32,
    pub relay: bool,
}

impl Encode for Version {
    fn encode(&self, out: &mut Vec<u8>) {
        self.version.encode(out);
        self.services.encode(out);
        self.timestamp.encode(out);
        self.addr_recv.encode(out);
        self.addr_from.encode(out);
        self.nonce.encode(out);
        write_string(out, &self.user_agent);
        self.start_height.encode(out);
        self.relay.encode(out);
    }
}

/// Every field up to `start_height` is required. A missing `relay` is true
/// (BIP37). Bytes after `relay` stay in `input`.
impl Decode for Version {
    fn decode(input: &mut &[u8]) -> Result<Self, Error> {
        Ok(Self {
            version: i32::decode(input)?,
            services: ServiceFlags::decode(input)?,
            timestamp: i64::decode(input)?,
            addr_recv: Address::decode(input)?,
            addr_from: Address::decode(input)?,
            nonce: u64::decode(input)?,
            user_agent: read_limited_string(input, MAX_SUBVERSION_LENGTH)?,
            start_height: i32::decode(input)?,
            relay: if input.is_empty() {
                true
            } else {
                bool::decode(input)?
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{VERSION_FRAME, hex};
    use crate::transport::HEADER_SIZE;

    fn core_payload() -> Vec<u8> {
        hex(VERSION_FRAME).split_off(HEADER_SIZE)
    }

    /// The fields of `VERSION_FRAME`, read by hand.
    fn core_version() -> Version {
        let zero = Address {
            services: ServiceFlags(0),
            ip: Ipv6Addr::UNSPECIFIED,
            port: 0,
        };
        Version {
            version: 70016,
            services: ServiceFlags(0x0c09),
            timestamp: 0x6ade_5823,
            addr_recv: zero,
            addr_from: Address {
                services: ServiceFlags(0x0c09),
                ..zero
            },
            nonce: 0x7119_7797_ae81_f0c9,
            user_agent: b"/Satoshi:31.1.0/".to_vec(),
            start_height: 0,
            relay: true,
        }
    }

    #[test]
    fn version_decodes_core_bytes() {
        let payload = core_payload();
        let mut input = payload.as_slice();
        assert_eq!(Version::decode(&mut input), Ok(core_version()));
        assert!(input.is_empty());
    }

    #[test]
    fn version_encodes_to_core_bytes() {
        let mut out = Vec::new();
        core_version().encode(&mut out);
        assert_eq!(out, core_payload());
    }

    #[test]
    fn version_without_relay_relays() {
        let mut payload = core_payload();
        payload.pop();
        let version = Version::decode(&mut payload.as_slice()).unwrap();
        assert!(version.relay);
    }

    #[test]
    fn version_leaves_the_bytes_after_relay() {
        let mut payload = core_payload();
        payload.push(0xaa);
        let mut input = payload.as_slice();
        assert_eq!(Version::decode(&mut input), Ok(core_version()));
        assert_eq!(input, [0xaa]);
    }

    #[test]
    fn version_requires_start_height() {
        let mut payload = core_payload();
        payload.truncate(payload.len() - 5);
        assert_eq!(
            Version::decode(&mut payload.as_slice()),
            Err(Error::UnexpectedEnd)
        );
    }

    #[test]
    fn version_user_agent_is_at_most_256_bytes() {
        for (len, expected) in [
            (256, Ok(())),
            (257, Err(Error::StringTooLong { len: 257, max: 256 })),
        ] {
            let version = Version {
                user_agent: vec![b'a'; len],
                ..core_version()
            };
            let mut payload = Vec::new();
            version.encode(&mut payload);
            let decoded = Version::decode(&mut payload.as_slice());
            assert_eq!(decoded.map(|_| ()), expected, "user agent of {len} bytes");
        }
    }

    #[test]
    fn address_is_ipv4_mapped_with_a_big_endian_port() {
        let address = Address {
            services: ServiceFlags(1),
            ip: std::net::Ipv4Addr::LOCALHOST.to_ipv6_mapped(),
            port: 18444,
        };
        let bytes = hex(concat!(
            "0100000000000000",
            "00000000000000000000ffff7f000001",
            "480c"
        ));
        let mut out = Vec::new();
        address.encode(&mut out);
        assert_eq!(out, bytes);
        assert_eq!(Address::decode(&mut bytes.as_slice()), Ok(address));
    }

    #[test]
    fn message_type_is_printable_ascii_then_nul_padding() {
        let cases: [(&[u8; 12], bool); 6] = [
            (b"verack\0\0\0\0\0\0", true),
            (b"\0\0\0\0\0\0\0\0\0\0\0\0", true),
            (b" ~\0\0\0\0\0\0\0\0\0\0", true),
            (b"ver\0ack\0\0\0\0\0", false),
            (b"verack\x1f\0\0\0\0\0", false),
            (b"verack\x7f\0\0\0\0\0", false),
        ];
        for (bytes, valid) in cases {
            assert_eq!(
                MessageType::new(*bytes).is_some(),
                valid,
                "{}",
                bytes.escape_ascii()
            );
        }
    }
}
