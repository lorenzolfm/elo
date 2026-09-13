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
        assert_eq!(ours[80], 11, "agent length");
        assert_eq!(&ours[81..92], b"/elo:0.1.0/");
        assert_eq!(core[80], 16);
        assert_eq!(&core[81..97], b"/Satoshi:31.1.0/");
        assert_eq!(&ours[92..96], &[0; 4], "our height");
        assert_eq!(&core[97..101], &[0; 4], "Core's height: fresh regtest");
        assert_eq!(ours[96], 0, "relay: false");
        assert_eq!(core[101], 1, "Core: relay true");
        assert_eq!(ours.len(), 97);
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
}
