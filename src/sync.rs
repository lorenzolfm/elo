//! The headers sync: `getheaders` from our tip, `headers` back, the chain
//! grows, and again while the batches come full. Core runs the same loop
//! from `ProcessHeadersMessage`: a batch of `MAX_HEADERS_RESULTS` means the
//! peer may have more, so it asks again from the last header
//! (`../bitcoin/src/net_processing.cpp:3106` at v31.1); a shorter batch
//! ends the sync, and an empty one says the peer has nothing after our tip
//! (`:2966`).
//!
//! Everything the loop reads and every moment it waits go through the
//! [`Connection`](crate::connection::Connection): no socket, no clock, so a
//! simulator can drive it.

/// `HEADERS_RESPONSE_TIME`, `net_processing.cpp:100`: how long a `headers`
/// may take to arrive after our `getheaders`. Core keeps one request in
/// flight for this long before it asks again (`:2831`). It is the bound on
/// `await_headers`, which sets it as the read deadline and clears it on the
/// way out, so `run` leaves the connection with no deadline.
pub const RESPONSE_TIME: std::time::Duration = std::time::Duration::from_secs(120);

/// How many batches one run asks for. ROADMAP step 8 caps the sync at a
/// couple; step 12, the full run from genesis, lifts the cap. Until then it
/// is also what bounds the chain: `BATCHES_MAX * HEADERS_MAX` headers at
/// most, each with the work it claims: `Chain::extend` checks every one.
pub const BATCHES_MAX: usize = 2;

/// How the sync ended.
pub enum Outcome {
    /// The last batch was short: the peer has nothing after our tip.
    Synced,
    /// `BATCHES_MAX` full batches came in. The peer may have more.
    Capped,
}

/// What the loop did, as it did it, for the caller to narrate.
pub enum Event {
    /// `getheaders` went out, with a locator from our tip at this height.
    Asked { height: usize },
    /// `headers` came in and the chain took it; `height` is the new tip.
    Took { count: usize, height: usize },
    /// A `ping` came in while we waited, and was answered.
    Ponged(u64),
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::Asked { height } => write!(f, "-> getheaders (from height {height})"),
            Event::Took { count, height } => write!(f, "<- headers ({count}), height {height}"),
            Event::Ponged(nonce) => write!(f, "<- ping {nonce:#018x}\n-> pong"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// A frame could not be read or written, the deadline passed, or the
    /// peer hung up.
    Message(crate::message::Error),
    /// A command we know with a payload we cannot read. Core penalizes a
    /// `headers` with more than it sends (`:4829`) and logs one that does
    /// not deserialize; with one peer we hang up on either.
    Wire(crate::wire::Error),
    /// A header has no work or claims the wrong `nBits`, or the batch
    /// does not extend our tip.
    Chain(crate::chain::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Message(e) => write!(f, "{e}"),
            Error::Wire(e) => write!(f, "{e}"),
            Error::Chain(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::message::Error> for Error {
    fn from(e: crate::message::Error) -> Self {
        Error::Message(e)
    }
}

/// The link refusing a deadline is an I/O error like any other on it.
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Message(crate::message::Error::from(e))
    }
}

impl From<crate::wire::Error> for Error {
    fn from(e: crate::wire::Error) -> Self {
        Error::Wire(e)
    }
}

impl From<crate::chain::Error> for Error {
    fn from(e: crate::chain::Error) -> Self {
        Error::Chain(e)
    }
}

/// Syncs `chain` from the peer on `connection`, which has finished its
/// handshake. Each `getheaders` is answered within `RESPONSE_TIME` or not
/// at all; `ping`s that arrive meanwhile are answered, and every other
/// message is dropped. `report` is called once per event, in order, as it
/// happens. The connection comes back with no read deadline.
///
/// # Errors
///
/// `Message` if a frame cannot be read or written, including `Io` with kind
/// `TimedOut` when no `headers` arrives in `RESPONSE_TIME`. `Wire` if a
/// known command does not parse. `Chain` if a header has no work, claims
/// the wrong `nBits`, or a batch does not extend our tip. On any error the
/// chain holds every batch taken before it.
///
/// # Panics
///
/// If the chain and the connection are on different networks: the magic
/// that frames a `headers` and the limit that checks its work are one
/// choice, made by whoever built the two. Also if the loop asks more than
/// `BATCHES_MAX` times or returns without asking once; the loop condition
/// rules both out.
pub fn run<L: crate::link::Link>(
    connection: &mut crate::connection::Connection<L>,
    chain: &mut crate::chain::Chain,
    mut report: impl FnMut(Event),
) -> Result<Outcome, Error> {
    assert_eq!(
        connection.network(),
        chain.network(),
        "the chain and the connection are on one network"
    );
    let mut batches = 0;
    while batches < BATCHES_MAX {
        let request = crate::wire::Message::GetHeaders(crate::headers::GetHeaders {
            locator: chain.locator(),
            stop: None,
        })
        .encode();
        connection.write_frame(request.command, &request.payload)?;
        report(Event::Asked {
            height: chain.height(),
        });

        let headers = await_headers(connection, &mut report)?;
        let count = headers.len();
        chain.extend(headers)?;
        batches += 1;
        report(Event::Took {
            count,
            height: chain.height(),
        });
        // `Headers::parse` bounded the batch, so a short one is the only
        // shape left that is not full.
        assert!(count <= crate::headers::HEADERS_MAX);
        if count < crate::headers::HEADERS_MAX {
            return Ok(Outcome::Synced);
        }
    }
    assert_eq!(batches, BATCHES_MAX);
    Ok(Outcome::Capped)
}

/// Reads until a `headers` arrives, or `RESPONSE_TIME` passes. The loop has
/// no count: a peer may send any number of frames first, and time is the
/// bound, set here as the read deadline so that the loop and its bound are
/// in one place. The deadline is cleared before either return. A `ping` on
/// the way is answered, so that a long wait does not cost us the peer
/// (`TIMEOUT_INTERVAL`, `net.h:59`). Anything else is dropped, and named,
/// so that a new message must decide here whether it too is dropped.
fn await_headers<L: crate::link::Link>(
    connection: &mut crate::connection::Connection<L>,
    report: &mut impl FnMut(Event),
) -> Result<crate::headers::Headers, Error> {
    connection.set_read_deadline(Some(connection.now() + RESPONSE_TIME))?;
    let result = await_headers_until_deadline(connection, report);
    connection.set_read_deadline(None)?;
    result
}

/// The read loop of `await_headers`, with the deadline already set.
fn await_headers_until_deadline<L: crate::link::Link>(
    connection: &mut crate::connection::Connection<L>,
    report: &mut impl FnMut(Event),
) -> Result<crate::headers::Headers, Error> {
    loop {
        let frame = connection.read_frame()?;
        match crate::wire::Message::decode(frame)? {
            crate::wire::Message::Headers(headers) => return Ok(headers),
            crate::wire::Message::Ping(nonce) => {
                let pong = crate::wire::Message::Pong(nonce).encode();
                connection.write_frame(pong.command, &pong.payload)?;
                report(Event::Ponged(nonce));
            }
            crate::wire::Message::Version(_)
            | crate::wire::Message::Verack
            | crate::wire::Message::Pong(_)
            | crate::wire::Message::GetHeaders(_)
            | crate::wire::Message::Unknown(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    // Core's frames, Bitcoin Core v31.1.0, `bitcoind -regtest`, as `wire.rs`
    // has them: the post-`verack` burst of 2026-09-13, and the `headers`
    // for a locator of genesis alone after `generatetoaddress 3` on
    // 2026-09-15. `headers.rs` prints the chain.
    const SENDCMPCT: &str = "fabfb5da73656e64636d70637400000009000000e92f5ef8000200000000000000";
    const PING: &str = "fabfb5da70696e670000000000000000080000000518a0f806d2e2149c8064fd";
    const FEEFILTER: &str = "fabfb5da66656566696c746572000000080000000a19f7997a9e970000000000";
    const HEADERS: &str = "fabfb5da686561646572730000000000f40000002f52e50d030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fce25a9ef6a61909eadcc696fb71eb4d3216de17cc3731ecdd321a030e9213a1226cda96affff7f2000000000000000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000000000200e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2869ee5ba689a2d757c652f917d12a43c9b24ba79dcff22abbea56c075d3d2bd7227cda96affff7f200000000000";
    /// The nonce in `PING`, little-endian on the wire.
    const PING_NONCE: u64 = 0xfd64_809c_14e2_d206;

    const GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
    const BLOCK_3: &str = "08e1a659dc25965d0cdf6d093b9247b09e9ce97a22cc77bca0b510ba4b337d61";

    const NETWORK: crate::message::Network = crate::message::Network::Regtest;

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// A frame as `message::write` puts it on the wire.
    fn framed(message: crate::wire::Message) -> Vec<u8> {
        let frame = message.encode();
        let mut out = Vec::new();
        crate::message::write(&mut out, NETWORK, frame.command, &frame.payload).unwrap();
        out
    }

    /// `count` headers after `previous`, each naming the one before and
    /// each mined to the regtest target, which takes two tries on average.
    /// Hand-built because no captured `headers` is 2000 long; Core's rule
    /// for a full batch is `net_processing.cpp:3106`.
    fn batch_after(previous: &crate::block_header::BlockHash, count: usize) -> Vec<u8> {
        let mut payload = Vec::new();
        crate::compact_size::write_len(&mut payload, count);
        let mut previous_block = crate::block_header::BlockHash::from_bytes(*previous.as_bytes());
        for i in 0..count {
            let mut header = crate::block_header::Header {
                version: 1,
                previous_block,
                merkle_root: crate::block_header::MerkleRoot::from_bytes([0; 32]),
                time: u32::try_from(i).unwrap(),
                bits: 0x207f_ffff,
                nonce: 0,
            };
            crate::pow::mine(&mut header, NETWORK);
            payload.extend_from_slice(&header.encode());
            payload.push(0);
            previous_block = header.hash();
        }
        let headers = crate::headers::Headers::parse(&payload).unwrap();
        framed(crate::wire::Message::Headers(headers))
    }

    /// Every frame its own step, as in `handshake.rs`: a read never
    /// crosses two.
    fn sends(frames: Vec<Vec<u8>>) -> Vec<crate::scripted::Step> {
        frames
            .into_iter()
            .map(crate::scripted::Step::Send)
            .collect()
    }

    /// What one run left behind.
    struct Ran {
        result: Result<super::Outcome, super::Error>,
        events: Vec<String>,
        sent: Vec<u8>,
        unread: usize,
        /// How far the peer's clock moved. Only a `Silence` moves it, so
        /// this is how long the loop waited.
        waited: std::time::Duration,
    }

    fn run(chain: &mut crate::chain::Chain, script: Vec<crate::scripted::Step>) -> Ran {
        run_with(chain, script, None)
    }

    /// The same, with `chunk` bytes at most per read.
    fn run_with(
        chain: &mut crate::chain::Chain,
        script: Vec<crate::scripted::Step>,
        chunk: Option<usize>,
    ) -> Ran {
        let mut connection = match chunk {
            Some(chunk) => crate::scripted::connect_in_chunks(script, chunk, std::time::UNIX_EPOCH),
            None => crate::scripted::connect(script, std::time::UNIX_EPOCH),
        };
        let started = connection.now();
        let mut events = Vec::new();
        let result = super::run(&mut connection, chain, |event| {
            events.push(event.to_string());
        });
        Ran {
            result,
            events,
            sent: connection.link().sent().to_vec(),
            unread: connection.link().unread(),
            waited: connection.now() - started,
        }
    }

    /// Our `getheaders` for a locator from `chain`'s tip, on the wire.
    fn getheaders(chain: &crate::chain::Chain) -> Vec<u8> {
        framed(crate::wire::Message::GetHeaders(
            crate::headers::GetHeaders {
                locator: chain.locator(),
                stop: None,
            },
        ))
    }

    /// The headers inside a framed `headers`.
    fn headers_in(batch: &[u8]) -> crate::headers::Headers {
        let frame = crate::message::read(&mut &batch[..], NETWORK).unwrap();
        match crate::wire::Message::decode(frame).unwrap() {
            crate::wire::Message::Headers(headers) => headers,
            other => panic!("{other}"),
        }
    }

    #[test]
    #[should_panic(expected = "the chain and the connection are on one network")]
    fn a_chain_on_another_network_than_the_connection_is_our_bug() {
        // Red if the assertion is missing or after the first request: the
        // script is empty, so a run that gets past the check fails on the
        // read, not on the panic. `run` above builds the connection on
        // `NETWORK`; the chain here is not.
        let mut chain = crate::chain::Chain::new(crate::message::Network::Mainnet);
        let _ = run(&mut chain, Vec::new());
    }

    #[test]
    fn syncs_core_headers_in_one_batch_and_answers_the_ping_on_the_way() {
        // Red if the loop takes the first frame as the answer, drops the
        // ping, asks from one below the tip as Core does, or asks again
        // after a short batch.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let expected_request = getheaders(&chain);
        let ran = run(
            &mut chain,
            sends(vec![
                fixture(SENDCMPCT),
                fixture(PING),
                fixture(FEEFILTER),
                fixture(HEADERS),
            ]),
        );
        assert!(matches!(ran.result, Ok(super::Outcome::Synced)));
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().to_string(), BLOCK_3);
        let pong = framed(crate::wire::Message::Pong(PING_NONCE));
        assert_eq!(ran.sent, [expected_request, pong].concat());
        assert_eq!(
            ran.events,
            [
                "-> getheaders (from height 0)",
                &format!("<- ping {PING_NONCE:#018x}\n-> pong"),
                "<- headers (3), height 3",
            ]
        );
        assert_eq!(ran.unread, 0);
        println!("{}", ran.events.join("\n"));
    }

    #[test]
    fn a_full_batch_is_followed_by_a_request_from_the_new_tip() {
        // Red if a batch of exactly 2000 ends the sync, or the second
        // request carries the old locator.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let first_request = getheaders(&chain);
        let full = batch_after(&chain.tip(), crate::headers::HEADERS_MAX);
        // The second request, built from a chain in the state the loop is
        // in when it asks.
        let mut at_2000 = crate::chain::Chain::new(NETWORK);
        at_2000.extend(headers_in(&full)).unwrap();
        let second_request = getheaders(&at_2000);
        let short = batch_after(&at_2000.tip(), 5);
        let last = headers_in(&short).as_slice().last().unwrap().hash();

        let ran = run(&mut chain, sends(vec![full, short]));
        assert!(matches!(ran.result, Ok(super::Outcome::Synced)));
        assert_eq!(chain.height(), 2005);
        assert_eq!(chain.tip().to_string(), last.to_string());
        assert_eq!(ran.sent, [first_request, second_request].concat());
        assert_eq!(
            ran.events,
            [
                "-> getheaders (from height 0)",
                "<- headers (2000), height 2000",
                "-> getheaders (from height 2000)",
                "<- headers (5), height 2005",
            ]
        );
        println!("{}", ran.events.join("\n"));
    }

    #[test]
    fn stops_after_the_capped_number_of_full_batches() {
        // Red if the cap is off by one in either direction: a third request
        // would read the third batch, one fewer would leave two unread.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let mut script = Vec::new();
        let mut previous = chain.tip();
        for _ in 0..=super::BATCHES_MAX {
            let batch = batch_after(&previous, crate::headers::HEADERS_MAX);
            previous = headers_in(&batch).as_slice().last().unwrap().hash();
            script.push(batch);
        }
        let third = script.last().unwrap().len();

        let ran = run(&mut chain, sends(script));
        assert!(matches!(ran.result, Ok(super::Outcome::Capped)));
        assert_eq!(
            chain.height(),
            super::BATCHES_MAX * crate::headers::HEADERS_MAX
        );
        assert_eq!(ran.unread, third, "the third batch was never asked for");
        assert_eq!(
            ran.events.iter().filter(|e| e.starts_with("->")).count(),
            super::BATCHES_MAX
        );
        println!("{}", ran.events.join("\n"));
    }

    #[test]
    fn a_batch_off_the_tip_ends_the_sync_with_the_chain_as_it_was() {
        // Red if the join is not checked, or the chain took the batch before
        // the check. Core's `headers` from genesis, sent to a chain that has
        // those three already: the shape a peer answers from a fork below
        // our tip.
        let mut chain = crate::chain::Chain::new(NETWORK);
        chain.extend(headers_in(&fixture(HEADERS))).unwrap();
        let ran = run(&mut chain, sends(vec![fixture(HEADERS)]));
        let err = ran.result.err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Chain(crate::chain::Error::NotOnTip { previous_block, tip })
                    if previous_block.to_string() == GENESIS && tip.to_string() == BLOCK_3
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 3);
        assert_eq!(ran.events, ["-> getheaders (from height 3)"]);
        println!("{err}");
    }

    #[test]
    fn silence_after_getheaders_is_a_timeout() {
        // Red if the loop waits without a deadline, treats a frame that is
        // not `headers` as the answer, or bounds each read instead of the
        // wait: the clock then stops short of `RESPONSE_TIME`.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let mut script = sends(vec![fixture(SENDCMPCT), fixture(PING)]);
        script.push(crate::scripted::Step::Silence);
        let ran = run(&mut chain, script);
        let err = ran.result.err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Message(crate::message::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::TimedOut
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0);
        let pong = framed(crate::wire::Message::Pong(PING_NONCE));
        assert!(ran.sent.ends_with(&pong), "the ping was answered first");
        assert_eq!(ran.waited, super::RESPONSE_TIME, "waited the whole bound");
        println!("{err} after {:?}", ran.waited);
    }

    #[test]
    fn a_headers_that_does_not_parse_is_an_error() {
        // Red if a bad `headers` is dropped like an unknown command. Core's
        // `headers` with the first transaction count set to one, reframed
        // so that the checksum holds; Core reads any count (`:4834`), we
        // refuse it, and either way the peer hangs up on nothing.
        let frame = crate::message::read(&mut &fixture(HEADERS)[..], NETWORK).unwrap();
        let mut payload = frame.payload;
        assert_eq!(payload[1 + 80], 0, "the count after the first header");
        payload[1 + 80] = 1;
        let mut bad = Vec::new();
        crate::message::write(&mut bad, NETWORK, frame.command, &payload).unwrap();

        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(&mut chain, sends(vec![bad]));
        let err = ran.result.err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Wire(crate::wire::Error::BadPayload { .. })
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0);
        println!("{err}");
    }

    #[test]
    fn a_headers_dripped_one_byte_per_read_is_read_whole() {
        // Red if `message::read` reads once instead of `read_exact`, or the
        // loop takes a short read for a frame: one byte is not a header.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run_with(
            &mut chain,
            sends(vec![fixture(PING), fixture(HEADERS)]),
            Some(1),
        );
        assert!(matches!(ran.result, Ok(super::Outcome::Synced)));
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().to_string(), BLOCK_3);
        assert_eq!(ran.unread, 0);
        println!("{}", ran.events.join("\n"));
    }

    #[test]
    fn a_hang_up_while_we_wait_is_an_end_of_stream_not_a_timeout() {
        // Red if the loop reports the deadline instead of the peer: a
        // deadline is set the whole time we wait, so a hang-up must not
        // come back as `TimedOut`.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let half = fixture(HEADERS)[..crate::message::HEADER_BYTES + 10].to_vec();
        let mut script = sends(vec![half]);
        script.push(crate::scripted::Step::HangUp);
        let ran = run(&mut chain, script);
        let err = ran.result.err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Message(crate::message::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::UnexpectedEof
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0);
        assert_eq!(ran.waited, std::time::Duration::ZERO, "no wait at all");
        println!("peer left ten bytes into a headers: {err}");
    }

    #[test]
    fn a_redundant_verack_is_dropped_like_core_drops_it() {
        // Red if the `Verack` arm ends the wait or fails the sync. The
        // handshake is over, so a second `verack` is a message Core drops
        // (`../bitcoin/src/net_processing.cpp:3823` at v31.1).
        let mut chain = crate::chain::Chain::new(NETWORK);
        let expected_request = getheaders(&chain);
        let ran = run(
            &mut chain,
            sends(vec![framed(crate::wire::Message::Verack), fixture(HEADERS)]),
        );
        assert!(matches!(ran.result, Ok(super::Outcome::Synced)));
        assert_eq!(chain.height(), 3);
        assert_eq!(ran.sent, expected_request, "the verack earned no answer");
        assert_eq!(
            ran.events,
            ["-> getheaders (from height 0)", "<- headers (3), height 3"]
        );
        println!("{}", ran.events.join("\n"));
    }
}
