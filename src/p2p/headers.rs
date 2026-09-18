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

/// What the handler did with a batch.
pub struct Taken {
    /// How many headers the chain took.
    pub count: usize,
    /// Whether the peer may have more: a batch of `HEADERS_MAX` says so
    /// (`ProcessHeadersMessage`, `net_processing.cpp:3106`); a shorter one
    /// says the peer has nothing after our tip (`:2966`).
    pub more: bool,
}

/// The handler: the chain takes the batch, and the answer says whether to
/// ask again. This is the one place a `headers` reaches the chain, and the
/// chain is the only thing it reaches.
///
/// # Errors
///
/// As `Chain::extend`: a header without the work it claims, a gap, a batch
/// off our tip, the wrong `nBits`, or a time not after the median time past.
/// The chain is unchanged on any of them.
///
/// # Panics
///
/// If the batch is longer than `HEADERS_MAX`, which `parse` rules out.
pub fn handle(
    headers: Headers,
    chain: &mut crate::chain::Chain,
) -> Result<Taken, crate::chain::Error> {
    let count = headers.len();
    // `parse` bounded the batch, so a short one is the only shape left that
    // is not full.
    assert!(count <= HEADERS_MAX);
    chain.extend(headers.into_vec())?;
    Ok(Taken {
        count,
        more: count == HEADERS_MAX,
    })
}

/// A `headers` payload as one peer sent it: at most `HEADERS_MAX`. Only
/// `parse` builds one, so the bound holds by construction; `encode` asserts
/// it again, so a second constructor cannot break it in silence.
///
/// Whether each header names the one before it, whether the first names a
/// block we know, and whether each has the work it claims, are questions for
/// the chain: `Chain::extend` asks them in Core's order.
#[derive(Debug)]
pub struct Headers(Vec<crate::chain::block_header::Header>);

impl Headers {
    /// Reads a `headers` payload: a count, then that many headers, each
    /// followed by the transaction count of a block that carries none
    /// (`:4446`). Core reads it the same way (`:4827` to `:4836`), but
    /// accepts any transaction count; we accept the one byte a count of zero
    /// takes.
    pub(crate) fn parse(payload: &[u8]) -> Result<Headers, Error> {
        let (count, mut rest) = crate::p2p::compact_size::read_len(payload, HEADERS_MAX)?;
        let mut headers: Vec<crate::chain::block_header::Header> = Vec::with_capacity(count);
        for _ in 0..count {
            let (header, after) = crate::p2p::compact_size::take::<HEADER_BYTES>(rest)?;
            let (&transaction_count, after) = after.split_first().ok_or(Error::Truncated)?;
            if transaction_count != 0 {
                return Err(Error::TransactionCount(transaction_count));
            }
            headers.push(crate::chain::block_header::Header::parse(header));
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

    /// The headers, for a chain to keep: what `Chain::extend` takes.
    #[must_use]
    pub fn into_vec(self) -> Vec<crate::chain::block_header::Header> {
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
    fn a_gap_between_headers_is_not_the_parsers_call() {
        // Red if the parser refuses a batch for its shape rather than its
        // bytes: one bit in the `previous_block` of header 2 leaves three
        // well-formed headers that do not chain, and that is `Chain::extend`'s
        // to refuse (Core: `CheckHeadersAreContinuous`, `net_processing.cpp:2673`).
        let mut payload = fixture(FROM_GENESIS);
        payload[1 + (super::HEADER_BYTES + 1) + 4] ^= 1;
        let headers = super::Headers::parse(&payload).unwrap();
        assert_eq!(headers.len(), 3);
        assert_ne!(
            headers.as_slice()[1].previous_block.to_string(),
            BLOCK_1,
            "header 2 no longer names header 1"
        );
        println!("three headers, one gap, parsed: the chain refuses it, not the parser");
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

#[cfg(test)]
mod handler_tests {
    // The handler with no socket and no loop: a `Headers` in, the chain
    // grown, and the answer that says whether to ask again.
    const FROM_GENESIS: &str = "030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fce25a9ef6a61909eadcc696fb71eb4d3216de17cc3731ecdd321a030e9213a1226cda96affff7f2000000000000000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000000000200e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2869ee5ba689a2d757c652f917d12a43c9b24ba79dcff22abbea56c075d3d2bd7227cda96affff7f200000000000";
    const BLOCK_3: &str = "08e1a659dc25965d0cdf6d093b9247b09e9ce97a22cc77bca0b510ba4b337d61";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn a_short_batch_grows_the_chain_and_asks_for_no_more() {
        // Red if the handler does not reach the chain, or reads a short
        // batch as a full one.
        let mut chain = crate::chain::Chain::new(crate::chain::network::Network::Regtest);
        let headers = super::Headers::parse(&fixture(FROM_GENESIS)).unwrap();
        let taken = super::handle(headers, &mut chain).unwrap();
        assert_eq!(taken.count, 3);
        assert!(!taken.more);
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().to_string(), BLOCK_3);
        println!("three headers taken, height 3, the peer has no more");
    }

    #[test]
    fn a_batch_the_chain_refuses_is_the_chains_error_and_changes_nothing() {
        // Red if the handler swallows the chain's refusal or keeps a batch
        // the chain refused: the same three headers twice, the second time
        // off the tip.
        let mut chain = crate::chain::Chain::new(crate::chain::network::Network::Regtest);
        super::handle(
            super::Headers::parse(&fixture(FROM_GENESIS)).unwrap(),
            &mut chain,
        )
        .unwrap();
        let err = super::handle(
            super::Headers::parse(&fixture(FROM_GENESIS)).unwrap(),
            &mut chain,
        )
        .err()
        .unwrap();
        assert!(matches!(err, crate::chain::Error::NotOnTip { .. }), "{err}");
        assert_eq!(chain.height(), 3);
        println!("{err}");
    }
}
