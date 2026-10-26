//! Message types and payloads.

use crate::serialize::{Decode, Encode};

/// The longest user agent a `version` may carry.
const USER_AGENT_LENGTH_MAX: usize = 256;

/// The user agent elo sends (BIP14).
const USER_AGENT_ELO: &str = concat!("/elo:", env!("CARGO_PKG_VERSION"), "/");
const _: () = assert!(USER_AGENT_ELO.len() <= USER_AGENT_LENGTH_MAX);

/// The size of a message type, with the padding.
pub(crate) const MESSAGE_TYPE_SIZE: usize = 12;

/// The message type in a header: printable ASCII, then NUL padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MessageType([u8; MESSAGE_TYPE_SIZE]);

// `from_name` runs at compile time here, so an invalid name does not build.
pub(crate) const VERSION: MessageType = MessageType::from_name("version");
pub(crate) const VERACK: MessageType = MessageType::from_name("verack");

impl MessageType {
    /// Pads `name` with NULs to `MESSAGE_TYPE_SIZE` bytes. Panics if the name
    /// is longer or `new` rejects the padded bytes.
    const fn from_name(name: &str) -> Self {
        let name = name.as_bytes();
        assert!(name.len() <= MESSAGE_TYPE_SIZE);
        let mut bytes = [0; MESSAGE_TYPE_SIZE];
        let mut index = 0;
        while index < name.len() {
            bytes[index] = name[index];
            index += 1;
        }
        Self::new(bytes).expect("a printable ASCII name")
    }

    /// `None` unless the bytes are printable ASCII followed only by NULs.
    pub(crate) const fn new(bytes: [u8; MESSAGE_TYPE_SIZE]) -> Option<Self> {
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == 0 {
                break;
            }
            if !matches!(byte, b' '..=b'~') {
                return None;
            }
            index += 1;
        }
        while index < bytes.len() {
            if bytes[index] != 0 {
                return None;
            }
            index += 1;
        }
        Some(Self(bytes))
    }

    /// All the bytes, with the padding.
    pub(crate) const fn as_bytes(&self) -> &[u8; MESSAGE_TYPE_SIZE] {
        &self.0
    }
}

/// The services a node offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// No services.
    pub(crate) const NONE: Self = Self(0);
}

impl std::fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.0, f)
    }
}

impl Encode for ServiceFlags {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for ServiceFlags {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        u64::decode(input).map(Self)
    }
}

/// An address as a `version` carries it. An IPv4 address is IPv4-mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Address {
    services: ServiceFlags,
    ip: std::net::Ipv6Addr,
    port: u16,
}

impl Address {
    pub(crate) fn new(services: ServiceFlags, address: std::net::SocketAddr) -> Self {
        let ip = match address.ip() {
            std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
            std::net::IpAddr::V6(ip) => ip,
        };
        Self {
            services,
            ip,
            port: address.port(),
        }
    }
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
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        Ok(Self {
            services: ServiceFlags::decode(input)?,
            ip: std::net::Ipv6Addr::from_octets(Decode::decode(input)?),
            port: u16::from_be_bytes(Decode::decode(input)?),
        })
    }
}

/// Raw bytes, which need not be UTF-8. At most `USER_AGENT_LENGTH_MAX`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAgent(Vec<u8>);

impl UserAgent {
    /// The user agent that elo sends: `/elo:<version>/`.
    pub(crate) fn elo() -> Self {
        Self(USER_AGENT_ELO.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Escapes each byte that is not printable ASCII, so a peer cannot send control codes to a
/// terminal.
impl std::fmt::Display for UserAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.escape_ascii())
    }
}

impl TryFrom<Vec<u8>> for UserAgent {
    type Error = crate::serialize::Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self, crate::serialize::Error> {
        if bytes.len() <= USER_AGENT_LENGTH_MAX {
            Ok(Self(bytes))
        } else {
            Err(crate::serialize::Error::StringTooLong {
                length: bytes.len(),
                length_max: USER_AGENT_LENGTH_MAX,
            })
        }
    }
}

impl Encode for UserAgent {
    fn encode(&self, out: &mut Vec<u8>) {
        assert!(self.0.len() <= USER_AGENT_LENGTH_MAX);
        crate::serialize::write_string(out, &self.0);
    }
}

impl Decode for UserAgent {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        crate::serialize::read_limited_string(input, USER_AGENT_LENGTH_MAX).map(Self)
    }
}

/// The `version` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub(crate) version: i32,
    pub(crate) services: ServiceFlags,
    pub(crate) timestamp: i64,
    pub(crate) addr_recv: Address,
    pub(crate) addr_from: Address,
    pub(crate) nonce: u64,
    pub(crate) user_agent: UserAgent,
    pub(crate) start_height: i32,
    pub(crate) relay: bool,
}

impl Version {
    /// The protocol version.
    pub fn version(&self) -> i32 {
        self.version
    }

    pub fn services(&self) -> ServiceFlags {
        self.services
    }

    pub fn user_agent(&self) -> &UserAgent {
        &self.user_agent
    }

    /// The height of the sender's best chain.
    pub fn start_height(&self) -> i32 {
        self.start_height
    }

    /// Whether the sender wants to get transactions (BIP37).
    pub fn relay(&self) -> bool {
        self.relay
    }
}

impl Encode for Version {
    fn encode(&self, out: &mut Vec<u8>) {
        self.version.encode(out);
        self.services.encode(out);
        self.timestamp.encode(out);
        self.addr_recv.encode(out);
        self.addr_from.encode(out);
        self.nonce.encode(out);
        self.user_agent.encode(out);
        self.start_height.encode(out);
        self.relay.encode(out);
    }
}

/// Every field up to `start_height` is required. A missing `relay` is true
/// (BIP37). Bytes after `relay` stay in `input`.
impl Decode for Version {
    fn decode(input: &mut &[u8]) -> Result<Self, crate::serialize::Error> {
        Ok(Self {
            version: i32::decode(input)?,
            services: ServiceFlags::decode(input)?,
            timestamp: i64::decode(input)?,
            addr_recv: Address::decode(input)?,
            addr_from: Address::decode(input)?,
            nonce: u64::decode(input)?,
            user_agent: UserAgent::decode(input)?,
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
    use crate::serialize::{Decode, Encode};

    /// The fields of `VERSION_FRAME`, read by hand.
    fn core_version() -> super::Version {
        let zero = super::Address {
            services: super::ServiceFlags(0),
            ip: std::net::Ipv6Addr::UNSPECIFIED,
            port: 0,
        };
        super::Version {
            version: 70016,
            services: super::ServiceFlags(0x0c09),
            timestamp: 0x6ade_5823,
            addr_recv: zero,
            addr_from: super::Address {
                services: super::ServiceFlags(0x0c09),
                ..zero
            },
            nonce: 0x7119_7797_ae81_f0c9,
            user_agent: super::UserAgent::try_from(b"/Satoshi:31.1.0/".to_vec()).unwrap(),
            start_height: 0,
            relay: true,
        }
    }

    /// Core's payload with another user agent. It does not call `Version::encode`,
    /// so the user agent can be longer than the limit.
    fn payload_with_user_agent(user_agent: &[u8]) -> Vec<u8> {
        let mut payload = crate::fixtures::version_payload();
        let start_height_and_relay =
            payload.split_off(payload.len() - size_of::<i32>() - size_of::<bool>());
        let mut core_user_agent = Vec::new();
        crate::serialize::write_string(&mut core_user_agent, b"/Satoshi:31.1.0/");
        let tail = payload.split_off(payload.len() - core_user_agent.len());
        assert_eq!(tail, core_user_agent);

        crate::serialize::write_string(&mut payload, user_agent);
        payload.extend(start_height_and_relay);
        payload
    }

    #[test]
    fn version_decodes_core_bytes() {
        let payload = crate::fixtures::version_payload();
        let mut input = payload.as_slice();
        assert_eq!(super::Version::decode(&mut input), Ok(core_version()));
        assert!(input.is_empty());
    }

    #[test]
    fn version_encodes_to_core_bytes() {
        let mut out = Vec::new();
        core_version().encode(&mut out);
        assert_eq!(out, crate::fixtures::version_payload());
    }

    #[test]
    fn version_without_relay_relays() {
        let mut payload = crate::fixtures::version_payload();
        payload.pop();
        let version = super::Version::decode(&mut payload.as_slice()).unwrap();
        assert!(version.relay);
    }

    #[test]
    fn version_leaves_the_bytes_after_relay() {
        let mut payload = crate::fixtures::version_payload();
        payload.push(0xaa);
        let mut input = payload.as_slice();
        assert_eq!(super::Version::decode(&mut input), Ok(core_version()));
        assert_eq!(input, [0xaa]);
    }

    #[test]
    fn version_requires_start_height() {
        let mut payload = crate::fixtures::version_payload();
        payload.truncate(payload.len() - size_of::<i32>() - size_of::<bool>());
        assert_eq!(
            super::Version::decode(&mut payload.as_slice()),
            Err(crate::serialize::Error::UnexpectedEnd)
        );
    }

    #[test]
    fn user_agent_is_at_most_user_agent_length_max() {
        let user_agent = [b'a'; super::USER_AGENT_LENGTH_MAX + 1];
        let longest = &user_agent[..super::USER_AGENT_LENGTH_MAX];
        let payload = payload_with_user_agent(longest);
        let version = super::Version::decode(&mut payload.as_slice()).unwrap();
        assert_eq!(version.user_agent.as_bytes(), longest);
        assert_eq!(
            super::UserAgent::try_from(longest.to_vec()),
            Ok(version.user_agent)
        );

        let too_long = crate::serialize::Error::StringTooLong {
            length: user_agent.len(),
            length_max: super::USER_AGENT_LENGTH_MAX,
        };
        let payload = payload_with_user_agent(&user_agent);
        assert_eq!(
            super::Version::decode(&mut payload.as_slice()),
            Err(too_long)
        );
        assert_eq!(
            super::UserAgent::try_from(user_agent.to_vec()),
            Err(too_long)
        );
    }

    #[test]
    fn address_is_ipv4_mapped_with_a_big_endian_port() {
        let address = super::Address::new(
            super::ServiceFlags(1),
            std::net::SocketAddr::from(([127, 0, 0, 1], 18444)),
        );
        let bytes = crate::fixtures::hex(concat!(
            "0100000000000000",
            "00000000000000000000ffff7f000001",
            "480c"
        ));
        let mut out = Vec::new();
        address.encode(&mut out);
        assert_eq!(out, bytes);
        assert_eq!(super::Address::decode(&mut bytes.as_slice()), Ok(address));
    }

    #[test]
    fn user_agent_display_escapes_control_bytes() {
        // An ANSI escape that would turn the terminal text red.
        let user_agent = super::UserAgent::try_from(b"/evil:\x1b[31m/".to_vec()).unwrap();
        assert_eq!(user_agent.to_string(), r"/evil:\x1b[31m/");
    }

    #[test]
    fn message_type_is_printable_ascii_then_nul_padding() {
        let cases: [(&[u8; super::MESSAGE_TYPE_SIZE], bool); 6] = [
            (b"verack\0\0\0\0\0\0", true),
            (b"\0\0\0\0\0\0\0\0\0\0\0\0", true),
            (b" ~\0\0\0\0\0\0\0\0\0\0", true),
            (b"ver\0ack\0\0\0\0\0", false),
            (b"verack\x1f\0\0\0\0\0", false),
            (b"verack\x7f\0\0\0\0\0", false),
        ];
        for (bytes, valid) in cases {
            assert_eq!(
                super::MessageType::new(*bytes).is_some(),
                valid,
                "{}",
                bytes.escape_ascii()
            );
        }
    }
}
