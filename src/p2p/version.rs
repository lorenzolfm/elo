pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("version");

const PROTOCOL_VERSION: i32 = 70016;

const PEER_PROTOCOL_VERSION_MIN: i32 = 31800;

const USER_AGENT_BYTES_MAX: usize = 256;

pub const USER_AGENT: &str = concat!("/elo:", env!("CARGO_PKG_VERSION"), "/");

const PAYLOAD_BYTES: usize = 4
    + 8
    + 8
    + NET_ADDR_BYTES
    + NET_ADDR_BYTES
    + 8
    + crate::p2p::compact_size::encoded_len(USER_AGENT.len())
    + USER_AGENT.len()
    + 4
    + 1;

const NET_ADDR_BYTES: usize = 8 + 16 + 2;

#[must_use]
pub fn build(peer: std::net::SocketAddr, timestamp: i64, nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYLOAD_BYTES);
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&timestamp.to_le_bytes());
    push_net_addr(&mut out, Some(peer));
    push_net_addr(&mut out, None);
    out.extend_from_slice(&nonce.to_le_bytes());
    crate::p2p::compact_size::write_len(&mut out, USER_AGENT.len());
    out.extend_from_slice(USER_AGENT.as_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.push(0);
    assert_eq!(out.len(), PAYLOAD_BYTES);
    out
}

pub fn handle(payload: &[u8]) -> Result<(Peer, crate::p2p::message::Message), Error> {
    let peer = parse(payload)?;
    Ok((peer, crate::p2p::message::Message::Verack))
}

#[derive(Debug)]
pub struct Peer {
    pub(crate) protocol: i32,
    pub(crate) services: u64,
    pub(crate) user_agent: Vec<u8>,
    pub(crate) start_height: u32,
    pub(crate) relay: bool,
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} protocol {} height {} services {:#x} relay {}",
            self.user_agent.escape_ascii(),
            self.protocol,
            self.start_height,
            self.services,
            self.relay
        )
    }
}

#[derive(Debug)]
pub enum Error {
    Truncated,
    Obsolete(i32),
    UserAgentTooLong(u64),
    NonCanonicalUserAgentLength(u64),
    NegativeHeight(i32),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "version payload truncated"),
            Error::Obsolete(protocol) => {
                write!(
                    f,
                    "protocol {protocol} is below {PEER_PROTOCOL_VERSION_MIN}"
                )
            }
            Error::UserAgentTooLong(len) => {
                write!(
                    f,
                    "user agent of {len} bytes exceeds {USER_AGENT_BYTES_MAX}"
                )
            }
            Error::NonCanonicalUserAgentLength(len) => {
                write!(f, "user agent length {len} is not canonical")
            }
            Error::NegativeHeight(height) => write!(f, "height {height} is negative"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::p2p::compact_size::Error> for Error {
    fn from(e: crate::p2p::compact_size::Error) -> Self {
        match e {
            crate::p2p::compact_size::Error::Truncated => Error::Truncated,
            crate::p2p::compact_size::Error::NonCanonical(len) => {
                Error::NonCanonicalUserAgentLength(len)
            }
            crate::p2p::compact_size::Error::TooLarge { value, .. } => {
                Error::UserAgentTooLong(value)
            }
        }
    }
}

pub(crate) fn parse(payload: &[u8]) -> Result<Peer, Error> {
    let (protocol, rest) = crate::p2p::compact_size::take::<4>(payload)?;
    let protocol = i32::from_le_bytes(*protocol);
    if protocol < PEER_PROTOCOL_VERSION_MIN {
        return Err(Error::Obsolete(protocol));
    }
    let (services, rest) = crate::p2p::compact_size::take::<8>(rest)?;
    let (_timestamp, rest) = crate::p2p::compact_size::take::<8>(rest)?;
    let (_addr_recv, rest) = crate::p2p::compact_size::take::<NET_ADDR_BYTES>(rest)?;
    let (_addr_from, rest) = crate::p2p::compact_size::take::<NET_ADDR_BYTES>(rest)?;
    let (_nonce, rest) = crate::p2p::compact_size::take::<8>(rest)?;
    let (agent_len, rest) = crate::p2p::compact_size::read_len(rest, USER_AGENT_BYTES_MAX)?;
    if rest.len() < agent_len {
        return Err(Error::Truncated);
    }
    let (user_agent, rest) = rest.split_at(agent_len);
    let (start_height, rest) = crate::p2p::compact_size::take::<4>(rest)?;
    let start_height = i32::from_le_bytes(*start_height);
    let start_height =
        u32::try_from(start_height).map_err(|_| Error::NegativeHeight(start_height))?;
    let relay = rest.first().is_none_or(|&byte| byte != 0);
    assert!(protocol >= PEER_PROTOCOL_VERSION_MIN);
    assert!(user_agent.len() <= USER_AGENT_BYTES_MAX);
    Ok(Peer {
        protocol,
        services: u64::from_le_bytes(*services),
        user_agent: user_agent.to_vec(),
        start_height,
        relay,
    })
}

fn push_net_addr(out: &mut Vec<u8>, addr: Option<std::net::SocketAddr>) {
    out.extend_from_slice(&0u64.to_le_bytes());
    match addr {
        Some(std::net::SocketAddr::V4(a)) => {
            out.extend_from_slice(&a.ip().to_ipv6_mapped().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        Some(std::net::SocketAddr::V6(a)) => {
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        None => out.extend_from_slice(&[0u8; 18]),
    }
}

#[cfg(test)]
mod tests {
    const CORE: &str = "80110100090c00000000000028b0a66a000000000000000000000000000000000000000000000000000000000000090c000000000000000000000000000000000000000000000000d07dc58995aa90bc102f5361746f7368693a33312e312e302f0000000001";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    const CORE_AT_300: &str = "80110100090c0000000000007d08a76a000000000000000000000000000000000000000000000000000000000000090c000000000000000000000000000000000000000000000000169ddf69497b1661102f5361746f7368693a33312e312e302f2c01000001";

    fn ours() -> Vec<u8> {
        let peer = "127.0.0.1:28444".parse().unwrap();
        super::build(peer, 0x6aa6_b028, 0x0123_4567_89ab_cdef)
    }

    #[test]
    fn layout_matches_core_field_by_field() {
        let core = fixture(CORE);
        let ours = ours();

        assert_eq!(&ours[0..4], &core[0..4], "protocol version");
        assert_eq!(&ours[4..12], &[0; 8], "our services");
        assert_eq!(
            &core[4..12],
            &[0x09, 0x0c, 0, 0, 0, 0, 0, 0],
            "Core: NETWORK | WITNESS | NETWORK_LIMITED | P2P_V2"
        );
        assert_eq!(&ours[12..20], &core[12..20], "timestamp, same second");
        assert_eq!(&ours[20..28], &[0; 8], "addr_recv services");
        assert_eq!(
            &ours[28..44],
            b"\0\0\0\0\0\0\0\0\0\0\xff\xff\x7f\0\0\x01",
            "addr_recv: 127.0.0.1 as ::ffff:7f00:1"
        );
        assert_eq!(&ours[44..46], &28444u16.to_be_bytes(), "port, big-endian");
        assert_eq!(&core[20..46], &[0; 26], "Core's addr_recv for loopback");
        assert_eq!(&ours[46..72], &[0; 26], "addr_from: zeros");
        assert_eq!(
            &core[46..54],
            &[0x09, 0x0c, 0, 0, 0, 0, 0, 0],
            "Core repeats its services in addr_from"
        );
        assert_eq!(&ours[72..80], &0x0123_4567_89ab_cdefu64.to_le_bytes());
        let agent = super::USER_AGENT.as_bytes();
        let agent_end = 81 + agent.len();
        assert_eq!(usize::from(ours[80]), agent.len(), "agent length");
        assert_eq!(&ours[81..agent_end], agent);
        assert_eq!(core[80], 16);
        assert_eq!(&core[81..97], b"/Satoshi:31.1.0/");
        assert_eq!(&ours[agent_end..agent_end + 4], &[0; 4], "our height");
        assert_eq!(&core[97..101], &[0; 4], "Core's height: fresh regtest");
        assert_eq!(ours[agent_end + 4], 0, "relay: false");
        assert_eq!(core[101], 1, "Core: relay true");
        assert_eq!(ours.len(), agent_end + 5);
        assert_eq!(core.len(), 102);

        println!("ours ({} bytes): {:02x?}", ours.len(), ours);
        println!("core ({} bytes): {:02x?}", core.len(), core);
    }

    #[test]
    fn ipv6_peer_is_sent_verbatim() {
        let peer = "[2001:db8::1]:8333".parse().unwrap();
        let ours = super::build(peer, 0, 0);
        assert_eq!(&ours[28..44], b"\x20\x01\x0d\xb8\0\0\0\0\0\0\0\0\0\0\0\x01");
        assert_eq!(&ours[44..46], &8333u16.to_be_bytes());
        println!("addr_recv for [2001:db8::1]:8333: {:02x?}", &ours[28..46]);
    }

    #[test]
    fn reads_core_field_by_field() {
        let received = super::parse(&fixture(CORE)).unwrap();
        assert_eq!(received.protocol, 70016);
        assert_eq!(received.services, 0x0c09);
        assert_eq!(received.user_agent, b"/Satoshi:31.1.0/");
        assert_eq!(received.start_height, 0);
        assert!(received.relay);
        let at_300 = super::parse(&fixture(CORE_AT_300)).unwrap();
        assert_eq!(at_300.start_height, 300, "the height it claims");
        println!("{received}");
        println!("{at_300}");
    }

    #[test]
    fn every_field_but_relay_is_required() {
        let core = fixture(CORE);
        let last_required = core.len() - 1;
        for len in 0..last_required {
            let err = super::parse(&core[..len]).unwrap_err();
            assert!(matches!(err, super::Error::Truncated), "{len} bytes: {err}");
        }
        let without_relay = super::parse(&core[..last_required]).unwrap();
        assert!(without_relay.relay, "absent relay is true, as in Core");
        let mut relay_off = core.clone();
        relay_off[last_required] = 0;
        assert!(!super::parse(&relay_off).unwrap().relay);
        let mut trailing = core;
        trailing.extend_from_slice(b"whatever");
        assert!(
            super::parse(&trailing).is_ok(),
            "bytes after relay are ignored"
        );
        println!("{last_required} prefixes truncated; {last_required} bytes parse with relay true");
    }

    #[test]
    fn rejects_an_obsolete_protocol() {
        let mut payload = fixture(CORE);
        payload[..4].copy_from_slice(&31799i32.to_le_bytes());
        let err = super::parse(&payload).unwrap_err();
        assert!(matches!(err, super::Error::Obsolete(31799)), "{err}");
        println!("{err}");
        payload[..4].copy_from_slice(&31800i32.to_le_bytes());
        assert_eq!(super::parse(&payload).unwrap().protocol, 31800);
        println!("31800 is the oldest Core keeps, so the oldest we keep");
    }

    fn with_user_agent(agent: &[u8]) -> Vec<u8> {
        let core = fixture(CORE);
        let mut payload = core[..80].to_vec();
        crate::p2p::compact_size::write_len(&mut payload, agent.len());
        payload.extend_from_slice(agent);
        payload.extend_from_slice(&core[97..]);
        payload
    }

    #[test]
    fn bounds_the_user_agent_before_reading_it() {
        let longest = super::parse(&with_user_agent(&[b'x'; 256])).unwrap();
        assert_eq!(longest.user_agent.len(), 256);
        let err = super::parse(&with_user_agent(&[b'x'; 257])).unwrap_err();
        assert!(matches!(err, super::Error::UserAgentTooLong(257)), "{err}");
        println!("256 bytes: read; 257: {err}");

        let mut promised = with_user_agent(b"/short/");
        promised[80] = 200;
        let err = super::parse(&promised).unwrap_err();
        assert!(matches!(err, super::Error::Truncated), "{err}");

        let empty = super::parse(&with_user_agent(b"")).unwrap();
        assert!(empty.user_agent.is_empty(), "no user agent is a user agent");
    }

    #[test]
    fn a_hostile_user_agent_prints_escaped() {
        let received = super::parse(&with_user_agent(b"/x\x1b[2Jy\n\xff/")).unwrap();
        let shown = received.to_string();
        assert!(shown.starts_with(r"/x\x1b[2Jy\n\xff/ protocol"), "{shown}");
        println!("{shown}");
    }

    #[test]
    fn a_non_canonical_agent_length_is_an_error() {
        let mut payload = with_user_agent(&[b'x'; 253]);
        payload[80..83].copy_from_slice(&[0xfd, 16, 0]);
        let err = super::parse(&payload).unwrap_err();
        assert!(
            matches!(err, super::Error::NonCanonicalUserAgentLength(16)),
            "{err}"
        );
        println!("{err}");
    }

    #[test]
    fn a_height_below_zero_is_not_a_height() {
        let mut payload = fixture(CORE);
        payload[97..101].copy_from_slice(&(-1i32).to_le_bytes());
        let err = super::parse(&payload).unwrap_err();
        assert!(matches!(err, super::Error::NegativeHeight(-1)), "{err}");
        println!("{err}; Core's own 'not sent' sentinel, which we never need");
        payload[97..101].copy_from_slice(&i32::MAX.to_le_bytes());
        let tallest = super::parse(&payload).unwrap();
        assert_eq!(tallest.start_height, 2_147_483_647, "the wire's ceiling");
    }
}

#[cfg(test)]
mod handler_tests {
    const CORE_VERSION: &str = "80110100090c00000000000028b0a66a000000000000000000000000000000000000000000000000000000000000090c000000000000000000000000000000000000000000000000d07dc58995aa90bc102f5361746f7368693a33312e312e302f0000000001";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn a_version_that_parses_earns_a_verack() {
        // Red if the handler answers with anything but `verack`, or drops a
        // field of the peer on the way.
        let (peer, reply) = super::handle(&fixture(CORE_VERSION)).unwrap();
        assert_eq!(peer.user_agent, b"/Satoshi:31.1.0/");
        assert!(
            matches!(reply, crate::p2p::message::Message::Verack),
            "{reply}"
        );
        println!("{peer} -> {reply}");
    }

    #[test]
    fn a_version_that_does_not_parse_earns_nothing() {
        // Red if a truncated `version` still earns a `verack`.
        let err = super::handle(&fixture(CORE_VERSION)[..80]).unwrap_err();
        assert!(matches!(err, super::Error::Truncated), "{err}");
        println!("{err}: no verack");
    }
}
