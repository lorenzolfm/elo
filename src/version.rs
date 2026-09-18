//! The `version` payload we send. The field order is the argument order of
//! `PushNodeVersion`, `../bitcoin/src/net_processing.cpp:1576` at v31.1.
//!
//! `Peer` is the peer as its `version` describes it, read the way Core reads ours
//! (`net_processing.cpp:3585`).

/// `PROTOCOL_VERSION`, `../bitcoin/src/node/protocol_version.h:12` at v31.1.
/// Announcing 70016 is what makes Core send `wtxidrelay` and `sendaddrv2`
/// before its `verack` (`net_processing.cpp:3716` and `:3725`).
const PROTOCOL_VERSION: i32 = 70016;

/// `MIN_PEER_PROTO_VERSION`, `protocol_version.h:18`. Core disconnects a
/// peer below it (`net_processing.cpp:3623`); so do we.
const PEER_PROTOCOL_VERSION_MIN: i32 = 31800;

/// `MAX_SUBVERSION_LENGTH`, `../bitcoin/src/net.h:67`. Core rejects a longer
/// user agent before it reads it (`net_processing.cpp:3640`, `serialize.h:621`).
const USER_AGENT_BYTES_MAX: usize = 256;

pub const USER_AGENT: &str = concat!("/elo:", env!("CARGO_PKG_VERSION"), "/");

// The user agent is length-prefixed with a `CompactSize`. Below 0xfd that is
// the length itself in one byte; `build` relies on it and encodes nothing else.
const _: () = assert!(USER_AGENT.len() < 0xfd);

/// Every field but the user agent: version 4, services 8, timestamp 8, two
/// addresses of 26, nonce 8, agent length 1, height 4, relay 1.
const FIXED_BYTES: usize = 4 + 8 + 8 + NET_ADDR_BYTES + NET_ADDR_BYTES + 8 + 1 + 4 + 1;

/// Services 8, IPv6 address 16, port 2. No timestamp: `version` carries the
/// pre-31402 address form, `net_processing.cpp:1582`.
const NET_ADDR_BYTES: usize = 8 + 16 + 2;

/// Builds the payload that announces us to `peer`.
///
/// # Panics
///
/// If `USER_AGENT` is 0xfd bytes or longer, or the payload does not come to
/// `FIXED_BYTES + USER_AGENT.len()`. Both are facts about elo, fixed at
/// compile time; a peer cannot reach them.
#[must_use]
pub fn build(peer: std::net::SocketAddr, timestamp: i64, nonce: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(FIXED_BYTES + USER_AGENT.len());
    out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // services: none
    out.extend_from_slice(&timestamp.to_le_bytes());
    push_net_addr(&mut out, Some(peer)); // addr_recv: the peer as we see it
    push_net_addr(&mut out, None); // addr_from: Core ignores it, sends zeros
    out.extend_from_slice(&nonce.to_le_bytes());
    let Ok(agent_len) = u8::try_from(USER_AGENT.len()) else {
        unreachable!("the compile-time assertion above bounds the agent below 0xfd")
    };
    out.push(agent_len);
    out.extend_from_slice(USER_AGENT.as_bytes());
    out.extend_from_slice(&0i32.to_le_bytes()); // start_height: we hold no chain
    out.push(0); // relay (BIP37): do not announce transactions to us
    assert_eq!(out.len(), FIXED_BYTES + USER_AGENT.len());
    out
}

/// What the peer said about itself: the fields Core keeps from the message
/// (`net_processing.cpp:3668` to `:3679`), minus three it keeps for features
/// we do not have. The timestamp feeds Core's clock-skew warning (`:3793`);
/// the address is where the peer sees us (`:3674`); the nonce catches a
/// connection to ourself, which only the inbound side checks (`:3649`).
#[derive(Debug)]
pub struct Peer {
    pub(crate) protocol: i32,
    pub(crate) services: u64,
    /// Raw bytes. BIP14 says what a user agent should look like; a peer says
    /// what it likes, so `Display` escapes anything outside printable ASCII.
    pub(crate) user_agent: Vec<u8>,
    /// Core reads a signed height and keeps `-1` for "not sent"
    /// (`net_processing.cpp:3597`). We require the field, so the sentinel has
    /// no meaning here, and a height below zero is not a height.
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
    /// A required field runs past the end of the payload.
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

impl From<crate::compact_size::Error> for Error {
    /// The one `CompactSize` in a `version` is the user agent's length, so
    /// each of its errors is an error about that field. A prefix cut short
    /// is the payload cut short: one error, not two.
    fn from(e: crate::compact_size::Error) -> Self {
        match e {
            crate::compact_size::Error::Truncated => Error::Truncated,
            crate::compact_size::Error::NonCanonical(len) => {
                Error::NonCanonicalUserAgentLength(len)
            }
            crate::compact_size::Error::TooLarge { value, .. } => Error::UserAgentTooLong(value),
        }
    }
}

/// Reads the peer's `version` payload.
///
/// Core reads the fields after the addresses only if bytes remain
/// (`net_processing.cpp:3631` to `:3648`), a tolerance for peers older than
/// the ones it disconnects at `:3623`. We require every field through the
/// height. `relay` alone stays optional: BIP37 added it, and Core takes an
/// absent one as `true`. Bytes after it are ignored, as Core ignores them.
pub(crate) fn parse(payload: &[u8]) -> Result<Peer, Error> {
    let (protocol, rest) = crate::compact_size::take::<4>(payload)?;
    let protocol = i32::from_le_bytes(*protocol);
    if protocol < PEER_PROTOCOL_VERSION_MIN {
        return Err(Error::Obsolete(protocol));
    }
    let (services, rest) = crate::compact_size::take::<8>(rest)?;
    let (_timestamp, rest) = crate::compact_size::take::<8>(rest)?;
    let (_addr_recv, rest) = crate::compact_size::take::<NET_ADDR_BYTES>(rest)?;
    let (_addr_from, rest) = crate::compact_size::take::<NET_ADDR_BYTES>(rest)?;
    let (_nonce, rest) = crate::compact_size::take::<8>(rest)?;
    let (agent_len, rest) = crate::compact_size::read_len(rest, USER_AGENT_BYTES_MAX)?;
    if rest.len() < agent_len {
        return Err(Error::Truncated);
    }
    let (user_agent, rest) = rest.split_at(agent_len);
    let (start_height, rest) = crate::compact_size::take::<4>(rest)?;
    let start_height = i32::from_le_bytes(*start_height);
    let start_height =
        u32::try_from(start_height).map_err(|_| Error::NegativeHeight(start_height))?;
    // A serialized `bool` is one byte, nonzero for true (`serialize.h:277`).
    let relay = rest.first().is_none_or(|&byte| byte != 0);
    // What the guards above promised, restated where the value is kept.
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

/// The 26-byte address inside `version`: services, a 16-byte IPv6 address
/// with IPv4 as `::ffff:a.b.c.d`, and the port, the one big-endian field in
/// the protocol.
fn push_net_addr(out: &mut Vec<u8>, addr: Option<std::net::SocketAddr>) {
    out.extend_from_slice(&0u64.to_le_bytes()); // services: we know none
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
    // Core's `version` to a peer at 127.0.0.1:28444, without the envelope.
    // Bitcoin Core v31.1.0, `bitcoind -regtest`, captured on 2026-09-13 by a
    // throwaway Python script that sent `version` over a raw TCP socket and
    // hex-dumped the answer.
    const CORE: &str = "80110100090c00000000000028b0a66a000000000000000000000000000000000000000000000000000000000000090c000000000000000000000000000000000000000000000000d07dc58995aa90bc102f5361746f7368693a33312e312e302f0000000001";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // The same, from a node after `generatetoaddress 300`, captured the same
    // way on the same day. Bytes 97 to 100 are the height.
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
        // Core zeroes addr_recv unless the peer is routable
        // (net_processing.cpp:1570). 127.0.0.1 is not. We send it anyway.
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

    /// Core's payload with the user agent swapped for `agent`, its length
    /// written as Core would write it.
    fn with_user_agent(agent: &[u8]) -> Vec<u8> {
        let core = fixture(CORE);
        let mut payload = core[..80].to_vec();
        if agent.len() < 0xfd {
            payload.push(u8::try_from(agent.len()).unwrap());
        } else {
            payload.push(0xfd);
            payload.extend_from_slice(&u16::try_from(agent.len()).unwrap().to_le_bytes());
        }
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

        // A length that promises more than the payload holds, well under the
        // limit: truncated, not allocated.
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
