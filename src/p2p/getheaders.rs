pub const COMMAND: crate::p2p::frame::Command =
    crate::p2p::frame::Command::from_static("getheaders");

const LOCATOR_VERSION: i32 = 70016;

const HASH_BYTES: usize = crate::chain::block_header::HASH_BYTES;

#[derive(Debug)]
pub struct GetHeaders {
    pub locator: crate::chain::locator::Locator,
    pub stop: Option<crate::chain::block_header::BlockHash>,
}

#[derive(Debug)]
pub enum Error {
    Truncated,
    NonCanonicalCount(u64),
    TooMany { count: u64, max: usize },
    TrailingBytes(usize),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "payload truncated"),
            Error::NonCanonicalCount(count) => write!(f, "count {count} is not canonical"),
            Error::TooMany { count, max } => write!(f, "count {count} exceeds {max}"),
            Error::TrailingBytes(len) => write!(f, "{len} bytes after the last field"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::p2p::compact_size::Error> for Error {
    fn from(e: crate::p2p::compact_size::Error) -> Self {
        match e {
            crate::p2p::compact_size::Error::Truncated => Error::Truncated,
            crate::p2p::compact_size::Error::NonCanonical(count) => Error::NonCanonicalCount(count),
            crate::p2p::compact_size::Error::TooLarge { value, max } => {
                Error::TooMany { count: value, max }
            }
        }
    }
}

impl GetHeaders {
    #[must_use]
    pub fn from_tip(chain: &crate::chain::Chain) -> GetHeaders {
        GetHeaders {
            locator: chain.locator(),
            stop: None,
        }
    }

    pub(crate) fn parse(payload: &[u8]) -> Result<GetHeaders, Error> {
        let (_version, rest) = crate::p2p::compact_size::take::<4>(payload)?;
        let (count, mut rest) =
            crate::p2p::compact_size::read_len(rest, crate::chain::locator::HASHES_MAX)?;
        let mut locator = Vec::with_capacity(count);
        for _ in 0..count {
            let (hash, after) = crate::p2p::compact_size::take::<HASH_BYTES>(rest)?;
            locator.push(crate::chain::block_header::BlockHash::from_bytes(*hash));
            rest = after;
        }
        let (stop, rest) = crate::p2p::compact_size::take::<HASH_BYTES>(rest)?;
        if !rest.is_empty() {
            return Err(Error::TrailingBytes(rest.len()));
        }
        assert_eq!(locator.len(), count);
        let locator = crate::chain::locator::Locator::from_wire(locator);
        let stop = (*stop != [0; HASH_BYTES])
            .then(|| crate::chain::block_header::BlockHash::from_bytes(*stop));
        Ok(GetHeaders { locator, stop })
    }

    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let size = 4 + 1 + HASH_BYTES * (self.locator.len() + 1);
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&LOCATOR_VERSION.to_le_bytes());
        crate::p2p::compact_size::write_len(&mut out, self.locator.len());
        for hash in self.locator.as_slice() {
            out.extend_from_slice(hash.as_bytes());
        }
        match &self.stop {
            Some(hash) => out.extend_from_slice(hash.as_bytes()),
            None => out.extend_from_slice(&[0; HASH_BYTES]),
        }
        assert_eq!(out.len(), size);
        out
    }
}

#[cfg(test)]
mod tests {

    const STOP_AT_TWO_REQUEST: &str =
        "80110100000e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c28";
    const STOP_AT_TWO: &str = "010000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000";
    const CORE_GETHEADERS: &str = "80110100030e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2834cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b23306226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000000000000000000000000000000000000000000000000000000000000000";

    const GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
    const BLOCK_1: &str = "33b2b7436b4a452524f261f2b60b1baffb5509d347a0ea0073381b8fda96cf34";
    const BLOCK_2: &str = "284cf210d6324d92446d2e875098764304da557d7f66ff99b8ee1a47ccdc6d0e";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn reads_core_getheaders() {
        // Red if the version field is not skipped, the hashes are read
        // reversed, or a zero stop hash is `Some`.
        let request = super::GetHeaders::parse(&fixture(CORE_GETHEADERS)).unwrap();
        let locator: Vec<String> = request
            .locator
            .as_slice()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(locator, [BLOCK_2, BLOCK_1, GENESIS], "newest first");
        assert!(request.stop.is_none(), "{:?}", request.stop);
        println!("Core asks from {} up: {request:?}", locator[0]);
    }
    #[test]
    fn our_getheaders_is_core_getheaders_byte_for_byte() {
        // Red if the version is not 70016, the count is not a `CompactSize`,
        // or `None` is not 32 zero bytes.
        let core = fixture(CORE_GETHEADERS);
        let super::GetHeaders { locator, stop } = super::GetHeaders::parse(&core).unwrap();
        assert!(stop.is_none());
        let ours = super::GetHeaders {
            locator,
            stop: None,
        }
        .encode();
        assert_eq!(ours, core);
        println!("{} bytes, identical to Core's", ours.len());
    }
    #[test]
    fn a_stop_hash_ends_the_reply_at_that_block() {
        // Red if `stop` is written before the locator, or a `Some` stop is
        // written as zeros. Core answered these exact bytes with block 2
        // alone, so the request is proven by its reply.
        let answer = crate::p2p::headers::Headers::parse(&fixture(STOP_AT_TWO)).unwrap();
        let [answer] = answer.as_slice() else {
            panic!("{} headers", answer.len());
        };
        assert_eq!(answer.hash().to_string(), BLOCK_2);
        let ours = super::GetHeaders {
            locator: crate::chain::locator::Locator::from_wire(Vec::new()),
            stop: Some(answer.hash()),
        }
        .encode();
        assert_eq!(ours, fixture(STOP_AT_TWO_REQUEST));
        println!("stop at {BLOCK_2}: Core sent that header and no other");
    }
    #[test]
    fn a_stop_hash_is_none_only_when_every_byte_is_zero() {
        // Red if `None` is decided on a prefix of the hash, say the first byte.
        let mut payload = fixture(CORE_GETHEADERS);
        let last = payload.len() - 1;
        payload[last] = 1;
        let request = super::GetHeaders::parse(&payload).unwrap();
        let Some(stop) = request.stop else {
            panic!("{:?}", request.locator);
        };
        assert_eq!(stop.as_bytes()[31], 1);
        assert!(stop.to_string().starts_with("01"), "{stop}");
        println!("one bit in the last byte: stop is {stop}");
    }
    #[test]
    fn rejects_a_locator_longer_than_core_takes() {
        // Red if the bound on the locator is missing, or off by one either way.
        let mut payload = fixture(CORE_GETHEADERS);
        payload[4] = 102;
        let err = super::GetHeaders::parse(&payload).unwrap_err();
        assert!(
            matches!(
                err,
                super::Error::TooMany {
                    count: 102,
                    max: 101
                }
            ),
            "{err}"
        );
        println!("102: {err}; Core reads them all, then hangs up (net_processing.cpp:4399)");
        payload[4] = 101;
        let err = super::GetHeaders::parse(&payload).unwrap_err();
        assert!(matches!(err, super::Error::Truncated), "{err}");
        println!("101 on a payload of three: {err}");
    }
    #[test]
    fn every_byte_of_a_getheaders_payload_is_required() {
        // Red if the stop hash is optional, or bytes after it are ignored.
        let core = fixture(CORE_GETHEADERS);
        for len in 0..core.len() {
            let err = super::GetHeaders::parse(&core[..len]).unwrap_err();
            assert!(matches!(err, super::Error::Truncated), "{len} bytes: {err}");
        }
        let mut trailing = core.clone();
        trailing.push(0);
        let err = super::GetHeaders::parse(&trailing).unwrap_err();
        assert!(matches!(err, super::Error::TrailingBytes(1)), "{err}");
        println!("{} prefixes truncated; one byte over: {err}", core.len());
    }
}
