use crate::serialize::{Decode, Encode};

pub(crate) const PROTOCOL_VERSION: i32 = 70016;

pub(crate) const HEADERS_COUNT_MAX: usize = 2000;

pub(crate) const LOCATOR_HASHES_COUNT_MAX: usize = 101;

pub(crate) const INV_COUNT_MAX: usize = 50_000;

const INV_TYPE_BLOCK: u32 = 2;

const USER_AGENT_LENGTH_MAX: usize = 256;

const USER_AGENT_ELO: &str = concat!("/elo:", env!("CARGO_PKG_VERSION"), "/");
const _: () = assert!(USER_AGENT_ELO.len() <= USER_AGENT_LENGTH_MAX);

pub(crate) const MESSAGE_TYPE_SIZE: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MessageType([u8; MESSAGE_TYPE_SIZE]);

pub(crate) const VERSION: MessageType = MessageType::from_name("version");
pub(crate) const VERACK: MessageType = MessageType::from_name("verack");
pub(crate) const PING: MessageType = MessageType::from_name("ping");
pub(crate) const PONG: MessageType = MessageType::from_name("pong");
pub(crate) const GETHEADERS: MessageType = MessageType::from_name("getheaders");
pub(crate) const HEADERS: MessageType = MessageType::from_name("headers");
pub(crate) const WTXIDRELAY: MessageType = MessageType::from_name("wtxidrelay");
pub(crate) const SENDADDRV2: MessageType = MessageType::from_name("sendaddrv2");
pub(crate) const SENDHEADERS: MessageType = MessageType::from_name("sendheaders");
pub(crate) const INV: MessageType = MessageType::from_name("inv");

impl MessageType {
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

    pub(crate) const fn as_bytes(&self) -> &[u8; MESSAGE_TYPE_SIZE] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const NETWORK_WITNESS: Self = Self(0b1001);
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserAgent(Vec<u8>);

impl UserAgent {
    pub(crate) fn elo() -> Self {
        Self(USER_AGENT_ELO.as_bytes().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

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
    pub fn version(&self) -> i32 {
        self.version
    }

    pub(crate) fn services(&self) -> ServiceFlags {
        self.services
    }

    pub fn user_agent(&self) -> &UserAgent {
        &self.user_agent
    }

    pub fn start_height(&self) -> i32 {
        self.start_height
    }

    pub(crate) fn relay(&self) -> bool {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GetHeaders {
    locator: Vec<bitcoin_hashes::sha256d::Hash>,
}

impl GetHeaders {
    pub(crate) fn new(locator: Vec<bitcoin_hashes::sha256d::Hash>) -> GetHeaders {
        assert!(!locator.is_empty());
        assert!(locator.len() <= LOCATOR_HASHES_COUNT_MAX);
        GetHeaders { locator }
    }
}

impl Encode for GetHeaders {
    fn encode(&self, out: &mut Vec<u8>) {
        PROTOCOL_VERSION.encode(out);
        crate::serialize::write_compact_size(out, self.locator.len());
        for hash in &self.locator {
            hash.encode(out);
        }
        let hash_stop = [0_u8; 32];
        hash_stop.encode(out);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Headers(Vec<crate::block::BlockHeader>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadersError {
    Payload(crate::serialize::Error),
    TooMany(usize),
    TxCount(std::num::NonZeroUsize),
}

impl Headers {
    pub(crate) fn decode(input: &mut &[u8]) -> Result<Self, HeadersError> {
        let count = crate::serialize::read_compact_size(input).map_err(HeadersError::Payload)?;
        if count > HEADERS_COUNT_MAX {
            return Err(HeadersError::TooMany(count));
        }

        let mut headers = Vec::with_capacity(count);
        for _ in 0..count {
            let header = crate::block::BlockHeader::decode(input).map_err(HeadersError::Payload)?;
            let tx_count =
                crate::serialize::read_compact_size(input).map_err(HeadersError::Payload)?;
            if let Some(tx_count) = std::num::NonZeroUsize::new(tx_count) {
                return Err(HeadersError::TxCount(tx_count));
            }
            headers.push(header);
        }
        Ok(Self(headers))
    }

    pub(crate) fn batches(headers: Vec<crate::block::BlockHeader>) -> Vec<Self> {
        let batches: Vec<Self> = headers
            .chunks(HEADERS_COUNT_MAX)
            .map(|batch| Self(batch.to_vec()))
            .collect();
        assert_eq!(batches.len(), headers.len().div_ceil(HEADERS_COUNT_MAX));
        batches
    }

    pub(crate) fn is_full(&self) -> bool {
        self.0.len() == HEADERS_COUNT_MAX
    }

    pub(crate) fn first(&self) -> Option<&crate::block::BlockHeader> {
        self.0.first()
    }

    pub(crate) fn as_slice(&self) -> &[crate::block::BlockHeader] {
        assert!(self.0.len() <= HEADERS_COUNT_MAX);
        &self.0
    }

    pub(crate) fn into_vec(self) -> Vec<crate::block::BlockHeader> {
        assert!(self.0.len() <= HEADERS_COUNT_MAX);
        self.0
    }
}

impl std::fmt::Display for HeadersError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HeadersError::Payload(error) => write!(f, "headers payload: {error}"),
            HeadersError::TooMany(count) => {
                write!(f, "{count} headers, more than {HEADERS_COUNT_MAX}")
            }
            HeadersError::TxCount(count) => {
                write!(f, "a header has {count} transactions, not 0")
            }
        }
    }
}

impl std::error::Error for HeadersError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Inv {
    has_block: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvError {
    Payload(crate::serialize::Error),
    TooMany(usize),
}

impl Inv {
    pub(crate) fn decode(input: &mut &[u8]) -> Result<Self, InvError> {
        let count = crate::serialize::read_compact_size(input).map_err(InvError::Payload)?;
        if count > INV_COUNT_MAX {
            return Err(InvError::TooMany(count));
        }

        let mut has_block = false;
        for _ in 0..count {
            let entry_type = u32::decode(input).map_err(InvError::Payload)?;
            <[u8; 32]>::decode(input).map_err(InvError::Payload)?;
            has_block |= entry_type == INV_TYPE_BLOCK;
        }
        Ok(Self { has_block })
    }

    pub(crate) fn has_block(&self) -> bool {
        self.has_block
    }
}

impl std::fmt::Display for InvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvError::Payload(error) => write!(f, "inv payload: {error}"),
            InvError::TooMany(count) => write!(f, "{count} inv entries, more than {INV_COUNT_MAX}"),
        }
    }
}

impl std::error::Error for InvError {}

#[cfg(fuzzing)]
#[cfg_attr(false, mutants::skip)]
pub(crate) mod fuzz {
    use crate::serialize::{Decode, Encode};

    const _: () = assert!(super::HEADERS_COUNT_MAX == 2000);
    const _: () = assert!(super::USER_AGENT_LENGTH_MAX == 256);

    const VERSION_BEFORE_USER_AGENT_SIZE: usize = 80;

    const VERSION_AFTER_USER_AGENT_SIZE: usize = size_of::<i32>() + size_of::<bool>();

    const VERSION_FIXED_SIZE: usize =
        VERSION_BEFORE_USER_AGENT_SIZE + VERSION_AFTER_USER_AGENT_SIZE;

    const HEADERS_WRITTEN_COUNT_MAX: usize = super::HEADERS_COUNT_MAX + 1;

    pub fn version(data: &[u8]) {
        let mut input = data;
        if let Ok(version) = super::Version::decode(&mut input) {
            version_check(&version, &data[..data.len() - input.len()], input);
        }

        let written = version_write(data);
        version_read_all(&written, &[]);
        version_read_all(&written[..written.len() - size_of::<bool>()], &[]);
        version_read_all(&written, data);
    }

    fn version_write(data: &[u8]) -> Vec<u8> {
        let mut fixed = [0; VERSION_FIXED_SIZE];
        for (fixed_byte, byte) in fixed.iter_mut().zip(data) {
            *fixed_byte = *byte;
        }
        let (before, after) = fixed.split_at(VERSION_BEFORE_USER_AGENT_SIZE);
        let user_agent = data.get(VERSION_FIXED_SIZE..).unwrap_or_default();
        let user_agent = &user_agent[..user_agent.len().min(super::USER_AGENT_LENGTH_MAX)];

        let mut written = before.to_vec();
        crate::serialize::write_string(&mut written, user_agent);
        written.extend_from_slice(after);
        written
    }

    fn version_read_all(payload: &[u8], after: &[u8]) {
        let stream = [payload, after].concat();
        let mut input = stream.as_slice();
        match super::Version::decode(&mut input) {
            Ok(version) => version_check(&version, payload, after),
            Err(error) => panic!("the decode refuses a valid `version`: {error}"),
        }
        assert_eq!(input, after);
    }

    fn version_check(version: &super::Version, taken: &[u8], rest: &[u8]) {
        let mut encoded = Vec::new();
        version.encode(&mut encoded);
        let (fields, encoded_relay) = encoded.split_at(encoded.len() - size_of::<bool>());
        assert_eq!(encoded_relay, [u8::from(version.relay)]);
        match taken.strip_prefix(fields) {
            Some([]) => {
                assert!(rest.is_empty());
                assert!(version.relay);
            }
            Some([relay]) => assert_eq!(version.relay, *relay != 0),
            _ => panic!("the decode took {taken:02x?}, and the encode wrote {encoded:02x?}"),
        }
    }

    pub fn headers(data: &[u8]) {
        let mut input = data;
        if let Ok(headers) = super::Headers::decode(&mut input) {
            headers_check(headers, &data[..data.len() - input.len()]);
        }

        let [count_low, count_high, bytes @ ..] = data else {
            return;
        };
        let count = usize::from(u16::from_le_bytes([*count_low, *count_high]))
            % (HEADERS_WRITTEN_COUNT_MAX + 1);
        let header_bytes_size = bytes.len().min(count * crate::block::BLOCK_HEADER_SIZE);
        let (header_bytes, after) = bytes.split_at(header_bytes_size);
        let mut written = headers_write(count, header_bytes);
        let batch_size = written.len();
        written.extend_from_slice(after);
        let mut input = written.as_slice();
        match super::Headers::decode(&mut input) {
            Ok(headers) => {
                assert!(count <= super::HEADERS_COUNT_MAX);
                assert_eq!(input, after);
                assert_eq!(headers.is_full(), count == super::HEADERS_COUNT_MAX);
                headers_check(headers, &written[..batch_size]);
            }
            Err(error) => {
                assert!(count > super::HEADERS_COUNT_MAX);
                assert_eq!(error, super::HeadersError::TooMany(count));
            }
        }
    }

    fn headers_write(count: usize, bytes: &[u8]) -> Vec<u8> {
        assert!(count <= HEADERS_WRITTEN_COUNT_MAX);
        let mut bytes = bytes.iter().copied().chain(std::iter::repeat(0));
        let mut written = Vec::new();
        crate::serialize::write_compact_size(&mut written, count);
        for _ in 0..count {
            written.extend(bytes.by_ref().take(crate::block::BLOCK_HEADER_SIZE));
            crate::serialize::write_compact_size(&mut written, 0);
        }
        written
    }

    fn headers_check(headers: super::Headers, taken: &[u8]) {
        let headers = headers.into_vec();
        let mut encoded = Vec::new();
        crate::serialize::write_compact_size(&mut encoded, headers.len());
        for header in &headers {
            header.encode(&mut encoded);
            crate::serialize::write_compact_size(&mut encoded, 0);
            crate::pow::fuzz::retarget_check(header);
            crate::pow::fuzz::work_check(header);
            crate::chain::fuzz::timewarp_time_min_check(header);
            let network = crate::chainparams::Network::Regtest;
            if let Some((hash, _)) = crate::pow::proven(header, network) {
                assert!(hash.as_byte_array()[31] <= 0x7f);
            }
        }
        crate::pow::fuzz::required_bits_check(&headers);
        crate::chain::fuzz::median_time_past_check(&headers);
        assert_eq!(encoded, taken);
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::{Decode, Encode};

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
    fn get_headers_encodes_to_core_bytes() {
        let get_headers =
            super::GetHeaders::new(vec![crate::chainparams::Network::Regtest.genesis().hash()]);
        let mut payload = Vec::new();
        get_headers.encode(&mut payload);
        assert_eq!(
            crate::transport::encode(
                crate::chainparams::Network::Regtest,
                super::GETHEADERS,
                &payload
            ),
            crate::fixtures::hex(crate::fixtures::GETHEADERS_FRAME)
        );
    }

    #[test]
    fn batches_cut_headers_at_2000_in_order() {
        let genesis = crate::chainparams::Network::Regtest.genesis();
        for (count, expected) in [
            (0, &[][..]),
            (1, &[1][..]),
            (2_000, &[2_000][..]),
            (2_001, &[2_000, 1][..]),
            (4_001, &[2_000, 2_000, 1][..]),
        ] {
            let headers: Vec<_> = (0..count)
                .map(|nonce| crate::block::BlockHeader { nonce, ..genesis })
                .collect();
            let batches = super::Headers::batches(headers.clone());
            let counts: Vec<_> = batches.iter().map(|batch| batch.0.len()).collect();
            assert_eq!(counts, expected, "{count}");
            let joined: Vec<_> = batches
                .into_iter()
                .flat_map(super::Headers::into_vec)
                .collect();
            assert_eq!(joined, headers, "{count}");
        }
    }

    #[test]
    fn headers_decodes_core_bytes() {
        let frame = crate::fixtures::hex(crate::fixtures::HEADERS_FRAME);
        let (message_header, payload) = frame.split_first_chunk().unwrap();
        let message_header =
            crate::transport::decode_header(crate::chainparams::Network::Regtest, message_header)
                .unwrap();
        let message = crate::transport::check_payload(message_header, payload.to_vec()).unwrap();
        assert_eq!(message.msg_type(), super::HEADERS);

        let mut input = message.payload();
        let headers = super::Headers::decode(&mut input).unwrap();
        assert!(!headers.is_full());
        let hashes: Vec<_> = headers
            .into_vec()
            .iter()
            .map(crate::block::BlockHeader::hash)
            .collect();
        assert_eq!(
            hashes,
            [
                crate::fixtures::hash_from_display_hex(crate::fixtures::BLOCK_1_HASH),
                crate::fixtures::hash_from_display_hex(crate::fixtures::BLOCK_2_HASH),
            ]
        );
        assert!(input.is_empty());
    }

    #[test]
    fn headers_count_is_at_most_2000() {
        let core = crate::fixtures::headers_payload();
        let (_, entries) = core.split_first().unwrap();
        let block_1 = &entries[..80 + 1];
        let mut payload = Vec::new();
        crate::serialize::write_compact_size(&mut payload, 2000);
        for _ in 0..2000 {
            payload.extend_from_slice(block_1);
        }
        let headers = super::Headers::decode(&mut payload.as_slice()).unwrap();
        assert!(headers.is_full());
        assert_eq!(headers.into_vec().len(), 2000);

        let mut payload = Vec::new();
        crate::serialize::write_compact_size(&mut payload, 2001);
        assert_eq!(
            super::Headers::decode(&mut payload.as_slice()),
            Err(super::HeadersError::TooMany(2001))
        );
    }

    #[test]
    fn headers_refuses_a_tx_count_that_is_not_0() {
        let mut payload = crate::fixtures::headers_payload();
        let tx_count = &mut payload[1 + 80];
        assert_eq!(*tx_count, 0);
        *tx_count = 1;
        assert_eq!(
            super::Headers::decode(&mut payload.as_slice()),
            Err(super::HeadersError::TxCount(std::num::NonZeroUsize::MIN))
        );
    }

    #[test]
    fn headers_requires_each_tx_count() {
        let mut payload = crate::fixtures::headers_payload();
        payload.pop();
        assert_eq!(
            super::Headers::decode(&mut payload.as_slice()),
            Err(super::HeadersError::Payload(
                crate::serialize::Error::UnexpectedEnd
            ))
        );
    }

    #[test]
    fn headers_leaves_the_bytes_after_the_last_tx_count() {
        let mut payload = crate::fixtures::headers_payload();
        payload.push(0xaa);
        let mut input = payload.as_slice();
        let headers = super::Headers::decode(&mut input).unwrap();
        assert_eq!(headers.into_vec().len(), 2);
        assert_eq!(input, [0xaa]);
    }

    #[test]
    fn inv_has_a_block_only_with_an_entry_of_type_2() {
        for (types, has_block) in [
            (&[][..], false),
            (&[1, 5, 0x4000_0002][..], false),
            (&[2][..], true),
            (&[1, 2, 5][..], true),
            (&[2, 2][..], true),
        ] {
            let payload = crate::fixtures::inv_payload(types);
            let mut input = payload.as_slice();
            let inv = super::Inv::decode(&mut input).unwrap();
            assert_eq!(inv.has_block(), has_block, "{types:?}");
            assert!(input.is_empty());
        }
    }

    #[test]
    fn inv_count_is_at_most_50000() {
        let payload = crate::fixtures::inv_payload(&[1; 50_000]);
        assert!(
            !super::Inv::decode(&mut payload.as_slice())
                .unwrap()
                .has_block()
        );

        let mut payload = Vec::new();
        crate::serialize::write_compact_size(&mut payload, 50_001);
        assert_eq!(
            super::Inv::decode(&mut payload.as_slice()),
            Err(super::InvError::TooMany(50_001))
        );
    }

    #[test]
    fn inv_requires_each_byte_of_each_entry() {
        let mut payload = crate::fixtures::inv_payload(&[1, 2]);
        for cut in [1, 32 + 1] {
            payload.truncate(payload.len() - cut);
            assert_eq!(
                super::Inv::decode(&mut payload.as_slice()),
                Err(super::InvError::Payload(
                    crate::serialize::Error::UnexpectedEnd
                )),
                "{cut}"
            );
        }
    }

    #[test]
    fn inv_leaves_the_bytes_after_the_last_entry() {
        let mut payload = crate::fixtures::inv_payload(&[2]);
        payload.push(0xaa);
        let mut input = payload.as_slice();
        assert!(super::Inv::decode(&mut input).unwrap().has_block());
        assert_eq!(input, [0xaa]);
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
