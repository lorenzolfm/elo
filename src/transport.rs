//! The v1 message framing.

use std::fmt;

use bitcoin_hashes::sha256d;

use crate::chainparams::Network;
use crate::protocol::{MessageHeader, MessageType};
use crate::serialize::Encode;

/// Magic, message type, length and checksum.
pub const HEADER_SIZE: usize = 24;

/// The longest payload a peer may send.
pub const MAX_PROTOCOL_MESSAGE_LENGTH: u32 = 4_000_000;

/// Why a frame was refused. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongMagic([u8; 4]),
    InvalidMessageType([u8; 12]),
    TooLarge(u32),
    BadChecksum,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongMagic(magic) => write!(f, "wrong magic {:08x}", u32::from_be_bytes(*magic)),
            Error::InvalidMessageType(bytes) => {
                write!(f, "invalid message type \"{}\"", bytes.escape_ascii())
            }
            Error::TooLarge(length) => {
                write!(
                    f,
                    "payload of {length} bytes is longer than {MAX_PROTOCOL_MESSAGE_LENGTH}"
                )
            }
            Error::BadChecksum => write!(f, "bad checksum"),
        }
    }
}

impl std::error::Error for Error {}

/// Checks the magic, the message type and the length.
pub fn decode_header(network: Network, bytes: &[u8; HEADER_SIZE]) -> Result<MessageHeader, Error> {
    let [m0, m1, m2, m3, rest @ ..] = *bytes;
    let [msg_type @ .., l0, l1, l2, l3, c0, c1, c2, c3] = rest;

    let magic = [m0, m1, m2, m3];
    if magic != network.magic() {
        return Err(Error::WrongMagic(magic));
    }
    let msg_type = MessageType::new(msg_type).ok_or(Error::InvalidMessageType(msg_type))?;
    let length = u32::from_le_bytes([l0, l1, l2, l3]);
    if length > MAX_PROTOCOL_MESSAGE_LENGTH {
        return Err(Error::TooLarge(length));
    }
    Ok(MessageHeader {
        msg_type,
        length,
        checksum: [c0, c1, c2, c3],
    })
}

/// Checks the payload against the checksum in its header.
pub fn check_payload(header: &MessageHeader, payload: &[u8]) -> Result<(), Error> {
    if checksum(payload) != header.checksum {
        return Err(Error::BadChecksum);
    }
    Ok(())
}

/// A header, then the payload.
///
/// Panics if the payload is longer than `MAX_PROTOCOL_MESSAGE_LENGTH`.
pub fn encode(network: Network, msg_type: MessageType, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len())
        .ok()
        .filter(|&n| n <= MAX_PROTOCOL_MESSAGE_LENGTH)
        .expect("elo sends no payload longer than MAX_PROTOCOL_MESSAGE_LENGTH");

    let mut out = Vec::with_capacity(HEADER_SIZE + payload.len());
    network.magic().encode(&mut out);
    msg_type.as_bytes().encode(&mut out);
    length.encode(&mut out);
    checksum(payload).encode(&mut out);
    out.extend_from_slice(payload);
    out
}

/// The first four bytes of the sha256d.
fn checksum(payload: &[u8]) -> [u8; 4] {
    let [c0, c1, c2, c3, ..] = sha256d::Hash::hash(payload).to_byte_array();
    [c0, c1, c2, c3]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{VERACK_FRAME, VERSION_FRAME, hex};
    use crate::protocol::{MessageHeader, VERACK, VERSION};

    fn split(frame: &[u8]) -> (&[u8; HEADER_SIZE], &[u8]) {
        frame.split_first_chunk().unwrap()
    }

    /// A regtest frame's header, decoded, and its payload.
    fn decode(frame: &[u8]) -> (MessageHeader, &[u8]) {
        let (header, payload) = split(frame);
        (decode_header(Network::Regtest, header).unwrap(), payload)
    }

    #[test]
    fn core_frames_decode() {
        let frame = hex(VERACK_FRAME);
        let (header, payload) = decode(&frame);
        assert_eq!(header.msg_type, VERACK);
        assert_eq!(header.length, 0);
        assert_eq!(check_payload(&header, payload), Ok(()));

        let frame = hex(VERSION_FRAME);
        let (header, payload) = decode(&frame);
        assert_eq!(header.msg_type, VERSION);
        assert_eq!(usize::try_from(header.length), Ok(payload.len()));
        assert_eq!(check_payload(&header, payload), Ok(()));
    }

    #[test]
    fn encode_writes_core_frames() {
        let frame = hex(VERACK_FRAME);
        assert_eq!(encode(Network::Regtest, VERACK, &[]), frame);

        let frame = hex(VERSION_FRAME);
        let (_, payload) = split(&frame);
        assert_eq!(encode(Network::Regtest, VERSION, payload), frame);
    }

    #[test]
    fn header_of_another_network_is_wrong_magic() {
        let frame = hex(VERACK_FRAME);
        let (header, _) = split(&frame);
        assert_eq!(
            decode_header(Network::Mainnet, header),
            Err(Error::WrongMagic(Network::Regtest.magic()))
        );
    }

    #[test]
    fn header_with_invalid_message_type_is_refused() {
        let mut frame = hex(VERACK_FRAME);
        frame[4 + 3] = 0;
        let (header, _) = split(&frame);
        assert_eq!(
            decode_header(Network::Regtest, header),
            Err(Error::InvalidMessageType(*b"ver\0ck\0\0\0\0\0\0"))
        );
    }

    #[test]
    fn header_length_is_at_most_max_protocol_message_length() {
        let mut frame = hex(VERACK_FRAME);
        for (length, expected) in [
            (MAX_PROTOCOL_MESSAGE_LENGTH, Ok(MAX_PROTOCOL_MESSAGE_LENGTH)),
            (
                MAX_PROTOCOL_MESSAGE_LENGTH + 1,
                Err(Error::TooLarge(MAX_PROTOCOL_MESSAGE_LENGTH + 1)),
            ),
        ] {
            frame[16..20].copy_from_slice(&length.to_le_bytes());
            let (header, _) = split(&frame);
            let decoded = decode_header(Network::Regtest, header).map(|h| h.length);
            assert_eq!(decoded, expected, "length {length}");
        }
    }

    #[test]
    fn payload_with_a_flipped_bit_is_bad_checksum() {
        let mut frame = hex(VERSION_FRAME);
        let last = frame.len() - 1;
        frame[last] ^= 1;
        let (header, payload) = decode(&frame);
        assert_eq!(check_payload(&header, payload), Err(Error::BadChecksum));
    }
}
