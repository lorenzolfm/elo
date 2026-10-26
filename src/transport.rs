//! The v1 message framing.

use crate::serialize::{Decode, Encode};

/// The size of the checksum in a header.
const CHECKSUM_SIZE: usize = 4;

/// Magic, message type, length and checksum.
pub(crate) const HEADER_SIZE: usize = crate::chainparams::MAGIC_SIZE
    + crate::protocol::MESSAGE_TYPE_SIZE
    + size_of::<u32>()
    + CHECKSUM_SIZE;

/// The longest payload a peer may send.
const PAYLOAD_LENGTH_MAX: u32 = 4_000_000;

/// Why a frame was refused. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongMagic([u8; crate::chainparams::MAGIC_SIZE]),
    InvalidMessageType([u8; crate::protocol::MESSAGE_TYPE_SIZE]),
    TooLarge(u32),
    BadChecksum,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WrongMagic(magic) => write!(f, "wrong magic {:08x}", u32::from_be_bytes(*magic)),
            Error::InvalidMessageType(bytes) => {
                write!(f, "invalid message type \"{}\"", bytes.escape_ascii())
            }
            Error::TooLarge(length) => {
                write!(
                    f,
                    "payload of {length} bytes is longer than {PAYLOAD_LENGTH_MAX}"
                )
            }
            Error::BadChecksum => write!(f, "bad checksum"),
        }
    }
}

impl std::error::Error for Error {}

/// A message header that passed the checks of `decode_header`. It does not keep
/// the magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MessageHeader {
    msg_type: crate::protocol::MessageType,
    /// The length of the payload in bytes.
    length: u32,
    /// The start of the sha256d of the payload.
    checksum: [u8; CHECKSUM_SIZE],
}

impl MessageHeader {
    /// The number of payload bytes to read next, at most `PAYLOAD_LENGTH_MAX`.
    pub(crate) fn payload_length(&self) -> usize {
        usize::try_from(self.length).expect("PAYLOAD_LENGTH_MAX fits in a usize")
    }
}

/// A payload whose checksum matched its header. Only `check_payload` makes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Message {
    msg_type: crate::protocol::MessageType,
    payload: Vec<u8>,
}

impl Message {
    pub(crate) fn msg_type(&self) -> crate::protocol::MessageType {
        self.msg_type
    }

    /// The whole payload of the frame, and nothing after it.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Checks the magic, the message type and the length.
pub(crate) fn decode_header(
    network: crate::chainparams::Network,
    bytes: &[u8; HEADER_SIZE],
) -> Result<MessageHeader, Error> {
    let mut input = bytes.as_slice();
    let magic = <[u8; crate::chainparams::MAGIC_SIZE]>::decode(&mut input)
        .expect("a header holds the magic");
    let msg_type = <[u8; crate::protocol::MESSAGE_TYPE_SIZE]>::decode(&mut input)
        .expect("a header holds the message type");
    let length = u32::decode(&mut input).expect("a header holds the length");
    let checksum = <[u8; CHECKSUM_SIZE]>::decode(&mut input).expect("a header holds the checksum");
    assert!(input.is_empty());

    if magic != network.magic() {
        return Err(Error::WrongMagic(magic));
    }
    let Some(msg_type) = crate::protocol::MessageType::new(msg_type) else {
        return Err(Error::InvalidMessageType(msg_type));
    };
    if length <= PAYLOAD_LENGTH_MAX {
        Ok(MessageHeader {
            msg_type,
            length,
            checksum,
        })
    } else {
        Err(Error::TooLarge(length))
    }
}

/// Checks the payload against the checksum in its header.
///
/// Panics if the payload is not `header.length` bytes. The caller reads exactly that many.
pub(crate) fn check_payload(header: MessageHeader, payload: Vec<u8>) -> Result<Message, Error> {
    assert!(header.length <= PAYLOAD_LENGTH_MAX);
    assert_eq!(u32::try_from(payload.len()), Ok(header.length));

    if checksum(&payload) == header.checksum {
        Ok(Message {
            msg_type: header.msg_type,
            payload,
        })
    } else {
        Err(Error::BadChecksum)
    }
}

/// A header, then the payload.
///
/// Panics if the payload is longer than `PAYLOAD_LENGTH_MAX`, because a peer refuses it.
pub(crate) fn encode(
    network: crate::chainparams::Network,
    msg_type: crate::protocol::MessageType,
    payload: &[u8],
) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("the payload is at most PAYLOAD_LENGTH_MAX");
    assert!(length <= PAYLOAD_LENGTH_MAX);
    let header = MessageHeader {
        msg_type,
        length,
        checksum: checksum(payload),
    };

    let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
    network.magic().encode(&mut frame);
    header.msg_type.as_bytes().encode(&mut frame);
    header.length.encode(&mut frame);
    header.checksum.encode(&mut frame);
    // The header passes the same checks as a header elo reads.
    let written = frame.first_chunk().expect("the header is written");
    assert_eq!(decode_header(network, written), Ok(header));

    frame.extend_from_slice(payload);
    frame
}

/// The start of the sha256d.
fn checksum(payload: &[u8]) -> [u8; CHECKSUM_SIZE] {
    let hash = bitcoin_hashes::sha256d::Hash::hash(payload).to_byte_array();
    *hash.first_chunk().expect("a sha256d is 32 bytes")
}

#[cfg(test)]
mod tests {
    fn split(frame: &[u8]) -> (&[u8; super::HEADER_SIZE], &[u8]) {
        frame.split_first_chunk().unwrap()
    }

    /// A regtest frame's header, decoded, and its payload.
    fn decode(frame: &[u8]) -> (super::MessageHeader, &[u8]) {
        let (header, payload) = split(frame);
        (
            super::decode_header(crate::chainparams::Network::Regtest, header).unwrap(),
            payload,
        )
    }

    #[test]
    fn core_frames_decode() {
        let frame = crate::fixtures::hex(crate::fixtures::VERACK_FRAME);
        let (header, payload) = decode(&frame);
        assert_eq!(header.length, 0);
        let message = super::check_payload(header, payload.to_vec()).unwrap();
        assert_eq!(message.msg_type(), crate::protocol::VERACK);
        assert_eq!(message.payload(), payload);

        let frame = crate::fixtures::hex(crate::fixtures::VERSION_FRAME);
        let (header, payload) = decode(&frame);
        assert_eq!(header.payload_length(), payload.len());
        let message = super::check_payload(header, payload.to_vec()).unwrap();
        assert_eq!(message.msg_type(), crate::protocol::VERSION);
        assert_eq!(message.payload(), payload);
    }

    #[test]
    fn encode_writes_core_frames() {
        let frame = crate::fixtures::hex(crate::fixtures::VERACK_FRAME);
        assert_eq!(
            super::encode(
                crate::chainparams::Network::Regtest,
                crate::protocol::VERACK,
                &[]
            ),
            frame
        );

        let frame = crate::fixtures::hex(crate::fixtures::VERSION_FRAME);
        let (_, payload) = split(&frame);
        assert_eq!(
            super::encode(
                crate::chainparams::Network::Regtest,
                crate::protocol::VERSION,
                payload
            ),
            frame
        );
    }

    #[test]
    fn header_of_another_network_is_wrong_magic() {
        let frame = crate::fixtures::hex(crate::fixtures::VERACK_FRAME);
        let (header, _) = split(&frame);
        assert_eq!(
            super::decode_header(crate::chainparams::Network::Mainnet, header),
            Err(super::Error::WrongMagic(
                crate::chainparams::Network::Regtest.magic()
            ))
        );
    }

    #[test]
    fn header_with_invalid_message_type_is_refused() {
        let mut frame = crate::fixtures::hex(crate::fixtures::VERACK_FRAME);
        frame[crate::chainparams::MAGIC_SIZE + "ver".len()] = 0;
        let (header, _) = split(&frame);
        assert_eq!(
            super::decode_header(crate::chainparams::Network::Regtest, header),
            Err(super::Error::InvalidMessageType(*b"ver\0ck\0\0\0\0\0\0"))
        );
    }

    #[test]
    fn header_length_is_at_most_payload_length_max() {
        let mut frame = crate::fixtures::hex(crate::fixtures::VERACK_FRAME);
        let length_start = crate::chainparams::MAGIC_SIZE + crate::protocol::MESSAGE_TYPE_SIZE;
        for (length, expected) in [
            (super::PAYLOAD_LENGTH_MAX, Ok(super::PAYLOAD_LENGTH_MAX)),
            (
                super::PAYLOAD_LENGTH_MAX + 1,
                Err(super::Error::TooLarge(super::PAYLOAD_LENGTH_MAX + 1)),
            ),
        ] {
            frame[length_start..length_start + size_of::<u32>()]
                .copy_from_slice(&length.to_le_bytes());
            let (header, _) = split(&frame);
            let decoded = super::decode_header(crate::chainparams::Network::Regtest, header)
                .map(|h| h.length);
            assert_eq!(decoded, expected, "length {length}");
        }
    }

    #[test]
    fn payload_with_a_flipped_bit_is_bad_checksum() {
        let mut frame = crate::fixtures::hex(crate::fixtures::VERSION_FRAME);
        let last = frame.len() - 1;
        frame[last] ^= 1;
        let (header, payload) = decode(&frame);
        assert_eq!(
            super::check_payload(header, payload.to_vec()),
            Err(super::Error::BadChecksum)
        );
    }
}
