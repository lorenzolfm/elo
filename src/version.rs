//! The `version` payload we send. The field order is the argument order of
//! `PushNodeVersion`, `../bitcoin/src/net_processing.cpp:1576` at v31.1.
//!
//! Only the encoder lives here. Reading the peer's `version` needs
//! `CompactSize` and is its own step.

/// `PROTOCOL_VERSION`, `../bitcoin/src/node/protocol_version.h:12` at v31.1.
/// Announcing 70016 is what makes Core send `wtxidrelay` and `sendaddrv2`
/// before its `verack` (`net_processing.cpp:3716` and `:3725`).
pub const PROTOCOL_VERSION: i32 = 70016;

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
