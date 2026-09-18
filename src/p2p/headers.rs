//! `headers`: the answer to a `getheaders`, at most `HEADERS_MAX` block
//! headers, each followed by the transaction count of a block that carries
//! none. Core sends it at `../bitcoin/src/net_processing.cpp:4453` at v31.1
//! and reads it at `:4816`.
//!
//! elo reads the answer. Writing one is here so that the message is a value
//! that `message::Message` can turn back into a frame; nothing in elo serves
//! headers.

pub const COMMAND: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("headers");

/// `MAX_HEADERS_RESULTS`, `net_processing.h:51`. Core sends at most this many
/// in one `headers` (`:4453`) and penalizes a peer that sends more (`:4829`).
pub(crate) const HEADERS_MAX: usize = 2000;

const HEADER_BYTES: usize = crate::chain::block_header::BYTES;

#[derive(Debug)]
pub enum Error {
    /// A field runs past the end of the payload.
    Truncated,
    /// The count in front of the list is not in its shortest form.
    NonCanonicalCount(u64),
    /// More headers than `HEADERS_MAX`.
    TooMany { count: u64, max: usize },
    /// The transaction count after a header is not zero. Core reads and
    /// ignores it (`:4835`); a header on the wire has no transactions, so a
    /// peer that counts some is not sending headers.
    TransactionCount(u8),
    /// Bytes after the last header.
    TrailingBytes(usize),
    /// The header at `index` does not name the one before it. Core penalizes
    /// the peer for this before it looks at its chain
    /// (`CheckHeadersAreContinuous`, `:2673`, from `CheckHeadersPoW`, `:2628`).
    NotContinuous { index: usize },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Truncated => write!(f, "payload truncated"),
            Error::NonCanonicalCount(count) => write!(f, "count {count} is not canonical"),
            Error::TooMany { count, max } => write!(f, "count {count} exceeds {max}"),
            Error::TransactionCount(count) => {
                write!(f, "transaction count {count} after a header, expected 0")
            }
            Error::TrailingBytes(len) => write!(f, "{len} bytes after the last field"),
            Error::NotContinuous { index } => {
                write!(
                    f,
                    "header at index {index} does not name the header before it"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::p2p::compact_size::Error> for Error {
    /// The payload has one `CompactSize`, the count in front of the list, so
    /// each of its errors is an error about that count.
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

/// A `headers` payload as one peer sent it: at most `HEADERS_MAX`, each
/// naming the one before it. Only `parse` builds one, so both facts hold by
/// construction, and the chain checks one join, the first header against
/// what it has, not one per header. `encode` asserts the bound again, so a
/// second constructor cannot break it in silence; continuity costs a
/// `sha256d` per header to re-check and is not asserted twice.
///
/// Whether the first header names a block we know, and whether each header
/// has the work it claims, are questions for the chain.
#[derive(Debug)]
pub struct Headers(Vec<crate::chain::block_header::Header>);

impl Headers {
    /// Reads a `headers` payload: a count, then that many headers, each
    /// followed by the transaction count of a block that carries none
    /// (`:4446`). Core reads it the same way (`:4827` to `:4836`), but
    /// accepts any transaction count; we accept the one byte a count of zero
    /// takes. Then each header must name the one before it, as Core requires
    /// once it has the list (`:2673`); here a gap is refused as it is read.
    pub(crate) fn parse(payload: &[u8]) -> Result<Headers, Error> {
        let (count, mut rest) = crate::p2p::compact_size::read_len(payload, HEADERS_MAX)?;
        let mut headers: Vec<crate::chain::block_header::Header> = Vec::with_capacity(count);
        for index in 0..count {
            let (header, after) = crate::p2p::compact_size::take::<HEADER_BYTES>(rest)?;
            let (&transaction_count, after) = after.split_first().ok_or(Error::Truncated)?;
            if transaction_count != 0 {
                return Err(Error::TransactionCount(transaction_count));
            }
            let header = crate::chain::block_header::Header::parse(header);
            // The first header has nothing before it to name.
            let names_the_last = headers
                .last()
                .is_none_or(|last| header.previous_block.as_bytes() == last.hash().as_bytes());
            if !names_the_last {
                return Err(Error::NotContinuous { index });
            }
            headers.push(header);
            rest = after;
        }
        if !rest.is_empty() {
            return Err(Error::TrailingBytes(rest.len()));
        }
        assert_eq!(headers.len(), count);
        assert!(headers.len() <= HEADERS_MAX);
        Ok(Headers(headers))
    }

    /// The payload Core writes at `:4469`: each header as a `CBlock` with no
    /// transactions, which is the header and one zero byte.
    #[must_use]
    pub(crate) fn encode(&self) -> Vec<u8> {
        assert!(self.0.len() <= HEADERS_MAX);
        // Room for the count in its `fd` form, which a count below 0xfd
        // does not need: two bytes over for a short run, never short.
        let mut out = Vec::with_capacity(3 + self.0.len() * (HEADER_BYTES + 1));
        crate::p2p::compact_size::write_len(&mut out, self.0.len());
        for header in &self.0 {
            out.extend_from_slice(&header.encode());
            out.push(0);
        }
        out
    }

    #[must_use]
    pub fn as_slice(&self) -> &[crate::chain::block_header::Header] {
        &self.0
    }

    /// The headers, for a chain to keep. The bound and the continuity go
    /// with them; the chain checks the join and nothing else.
    pub(crate) fn into_vec(self) -> Vec<crate::chain::block_header::Header> {
        self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    // Every payload below was exchanged with Bitcoin Core v31.1.0, `bitcoind
    // -regtest`, on 2026-09-15, after `generatetoaddress 3`, by a throwaway
    // Python script over a raw TCP socket. The chain, as `getblockhash`
    // printed it:
    //
    //   0  0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
    //   1  33b2b7436b4a452524f261f2b60b1baffb5509d347a0ea0073381b8fda96cf34
    //   2  284cf210d6324d92446d2e875098764304da557d7f66ff99b8ee1a47ccdc6d0e
    //   3  08e1a659dc25965d0cdf6d093b9247b09e9ce97a22cc77bca0b510ba4b337d61
    //
    // The script connected, shook hands, and sent three `getheaders`. Core's
    // `headers` to a locator of genesis alone: blocks 1 to 3.
    const FROM_GENESIS: &str = "030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fce25a9ef6a61909eadcc696fb71eb4d3216de17cc3731ecdd321a030e9213a1226cda96affff7f2000000000000000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000000000200e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2869ee5ba689a2d757c652f917d12a43c9b24ba79dcff22abbea56c075d3d2bd7227cda96affff7f200000000000";
    // Core's answer to a request that stopped at block 2: that header alone.
    const STOP_AT_TWO: &str = "010000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000";
    // Core's answer to a locator of its own tip: nothing after it.
    const FROM_TIP: &str = "00";
    const GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
    const BLOCK_1: &str = "33b2b7436b4a452524f261f2b60b1baffb5509d347a0ea0073381b8fda96cf34";
    const BLOCK_2: &str = "284cf210d6324d92446d2e875098764304da557d7f66ff99b8ee1a47ccdc6d0e";
    const BLOCK_3: &str = "08e1a659dc25965d0cdf6d093b9247b09e9ce97a22cc77bca0b510ba4b337d61";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn hashes(headers: &[crate::chain::block_header::Header]) -> Vec<String> {
        headers.iter().map(|h| h.hash().to_string()).collect()
    }

    #[test]
    fn reads_core_headers_after_genesis() {
        // Red if the transaction-count byte is not skipped: header 2 then
        // starts one byte late and hashes to nothing on the chain.
        let headers = super::Headers::parse(&fixture(FROM_GENESIS)).unwrap();
        let headers = headers.as_slice();
        assert_eq!(hashes(headers), [BLOCK_1, BLOCK_2, BLOCK_3]);
        assert_eq!(headers[0].previous_block.to_string(), GENESIS);
        for pair in headers.windows(2) {
            assert_eq!(
                pair[1].previous_block.to_string(),
                pair[0].hash().to_string(),
                "each header names the one before"
            );
        }
        for header in headers {
            println!("{}", header.hash());
        }
    }
    #[test]
    fn reads_an_empty_headers() {
        // Red if a count of zero is refused, or a header is read before the
        // count is.
        let headers = super::Headers::parse(&fixture(FROM_TIP)).unwrap();
        assert!(headers.is_empty());
        println!("a peer at our tip sends {FROM_TIP}: no headers, no error");
    }
    #[test]
    fn writes_headers_as_core_writes_them() {
        // Red if the zero transaction-count byte is not written after each
        // header, or an empty list is not the one byte `00`.
        let core = fixture(FROM_GENESIS);
        let headers = super::Headers::parse(&core).unwrap();
        assert_eq!(headers.encode(), core);
        let none = super::Headers::parse(&fixture(FROM_TIP)).unwrap();
        assert_eq!(none.encode(), fixture(FROM_TIP));
        println!(
            "{} headers re-encode to Core's {} bytes",
            headers.len(),
            core.len()
        );
    }

    /// Core's three-header payload with its count rewritten as `count`,
    /// in the `fd` form.
    fn with_count(count: u16) -> Vec<u8> {
        let mut payload = vec![0xfd];
        payload.extend_from_slice(&count.to_le_bytes());
        payload.extend_from_slice(&fixture(FROM_GENESIS)[1..]);
        payload
    }

    #[test]
    fn rejects_more_headers_than_core_sends() {
        // Red if the bound on the count is missing, or off by one either way.
        let err = super::Headers::parse(&with_count(2001)).unwrap_err();
        assert!(
            matches!(
                err,
                super::Error::TooMany {
                    count: 2001,
                    max: 2000
                }
            ),
            "{err}"
        );
        println!("2001: {err}");
        // The last count Core accepts passes the bound; the payload behind it
        // is then too short, which is a different error.
        let err = super::Headers::parse(&with_count(2000)).unwrap_err();
        assert!(matches!(err, super::Error::Truncated), "{err}");
        println!("2000 on a payload of three: {err}");
    }
    #[test]
    fn rejects_a_non_canonical_count() {
        // Red if the count's shortest-form check is missing.
        let err = super::Headers::parse(&with_count(3)).unwrap_err();
        assert!(matches!(err, super::Error::NonCanonicalCount(3)), "{err}");
        println!("fd 03 00: {err}");
    }
    #[test]
    fn rejects_a_transaction_count_that_is_not_zero() {
        // Red if the byte after a header is skipped without being read.
        let mut payload = fixture(FROM_GENESIS);
        payload[1 + super::HEADER_BYTES] = 1;
        let err = super::Headers::parse(&payload).unwrap_err();
        assert!(matches!(err, super::Error::TransactionCount(1)), "{err}");
        println!("{err}; Core reads the count and ignores it (net_processing.cpp:4835)");
    }
    #[test]
    fn rejects_a_header_that_does_not_name_the_one_before() {
        // Red if the continuity check is missing, compares the wrong pair, or
        // reports the wrong index. One bit in the `previous_block` of header
        // 2 (index 1): headers 1 and 3 are untouched, and 3 still names 2, so
        // only index 1 is a gap.
        let mut payload = fixture(FROM_GENESIS);
        payload[1 + (super::HEADER_BYTES + 1) + 4] ^= 1;
        let err = super::Headers::parse(&payload).unwrap_err();
        assert!(
            matches!(err, super::Error::NotContinuous { index: 1 }),
            "{err}"
        );
        println!(
            "{err}; Core: Misbehaving, 'non-continuous headers sequence' (net_processing.cpp:2629)"
        );
        // The same bit in the only header of a run: nothing before it to
        // name, so the run is continuous and the chain will be the one to
        // refuse it.
        let mut payload = fixture(STOP_AT_TWO);
        payload[1 + 4] ^= 1;
        let headers = super::Headers::parse(&payload).unwrap();
        assert_ne!(
            headers.as_slice()[0].previous_block.to_string(),
            BLOCK_1,
            "the first header names nothing we know, and that is not the parser's call"
        );
    }
    #[test]
    fn every_byte_of_a_headers_payload_is_required() {
        // Red if a short payload is padded, or the last header is optional.
        let core = fixture(FROM_GENESIS);
        for len in 0..core.len() {
            let err = super::Headers::parse(&core[..len]).unwrap_err();
            assert!(matches!(err, super::Error::Truncated), "{len} bytes: {err}");
        }
        println!("{} prefixes cut short, {} errors", core.len(), core.len());
    }
    #[test]
    fn rejects_bytes_after_the_last_header() {
        // Red if bytes after the count's worth of headers are ignored.
        let mut payload = fixture(FROM_GENESIS);
        payload.push(0);
        let err = super::Headers::parse(&payload).unwrap_err();
        assert!(matches!(err, super::Error::TrailingBytes(1)), "{err}");
        println!("{err}");
    }
}
