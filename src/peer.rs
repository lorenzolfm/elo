const MESSAGES_BEFORE_VERACK_MAX: usize = 16;

pub const RESPONSE_TIME: std::time::Duration = std::time::Duration::from_secs(120);

pub const BATCHES_MAX: usize = 2;

pub enum Event {
    SentVersion {
        bytes: usize,
    },
    Seen {
        command: crate::p2p::frame::Command,
        bytes: usize,
    },
    HandshakeComplete {
        peer: crate::p2p::version::Peer,
        elapsed: std::time::Duration,
    },
    Asked {
        height: usize,
    },
    Took {
        count: usize,
        height: usize,
    },
    Ponged(u64),
    Synced {
        height: usize,
        tip: crate::chain::block_header::BlockHash,
    },
    Capped {
        height: usize,
        tip: crate::chain::block_header::BlockHash,
    },
    Ignored(crate::p2p::message::Message),
    PeerHungUp,
    LingerOver(std::time::Duration),
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::SentVersion { bytes } => write!(f, "-> version ({bytes} bytes)"),
            Event::Seen { command, bytes } => write!(f, "<- {command} ({bytes} bytes)"),
            Event::HandshakeComplete { peer, elapsed } => {
                write!(f, "handshake complete in {elapsed:?}\npeer is {peer}")
            }
            Event::Asked { height } => write!(f, "-> getheaders (from height {height})"),
            Event::Took { count, height } => write!(f, "<- headers ({count}), height {height}"),
            Event::Ponged(nonce) => write!(f, "<- ping {nonce:#018x}\n-> pong"),
            Event::Synced { height, tip } => write!(f, "synced: height {height}, tip {tip}"),
            Event::Capped { height, tip } => write!(
                f,
                "stopped at {BATCHES_MAX} batches (ROADMAP step 8): height {height}, tip {tip}; the peer may have more"
            ),
            Event::Ignored(message) => write!(f, "<- {message} ignored"),
            Event::PeerHungUp => write!(f, "peer hung up"),
            Event::LingerOver(linger) => write!(f, "{linger:?} after the sync, hanging up"),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Frame(crate::p2p::frame::Error),
    Message(crate::p2p::message::Error),
    Version(crate::p2p::version::Error),
    VerackBeforeVersion,
    NoVerackAfter,
    Chain(crate::chain::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Frame(e) => write!(f, "{e}"),
            Error::Message(e) => write!(f, "{e}"),
            Error::Version(e) => write!(f, "peer version: {e}"),
            Error::VerackBeforeVersion => write!(f, "verack before version"),
            Error::NoVerackAfter => {
                write!(f, "no verack after {MESSAGES_BEFORE_VERACK_MAX} messages")
            }
            Error::Chain(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::p2p::frame::Error> for Error {
    fn from(e: crate::p2p::frame::Error) -> Self {
        Error::Frame(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Frame(crate::p2p::frame::Error::from(e))
    }
}

impl From<crate::p2p::message::Error> for Error {
    fn from(e: crate::p2p::message::Error) -> Self {
        Error::Message(e)
    }
}

impl From<crate::p2p::version::Error> for Error {
    fn from(e: crate::p2p::version::Error) -> Self {
        Error::Version(e)
    }
}

impl From<crate::chain::Error> for Error {
    fn from(e: crate::chain::Error) -> Self {
        Error::Chain(e)
    }
}

pub fn run<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    chain: &mut crate::chain::Chain,
    our_version: &[u8],
    linger: std::time::Duration,
    mut report: impl FnMut(Event),
) -> Result<(), Error> {
    assert_eq!(
        connection.network(),
        chain.network(),
        "the chain and the connection are on one network"
    );
    handshake(connection, our_version, &mut report)?;
    sync(connection, chain, &mut report)?;
    linger_for(connection, linger, &mut report)
}

fn send<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    message: crate::p2p::message::Message,
) -> Result<(), crate::p2p::frame::Error> {
    let frame = message.encode();
    connection.write_frame(frame.command, &frame.payload)
}

enum Handshake {
    AwaitingVersion,
    AwaitingVerack(crate::p2p::version::Peer),
}

fn handshake<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    our_version: &[u8],
    report: &mut impl FnMut(Event),
) -> Result<(), Error> {
    let started = connection.now();
    send(
        connection,
        crate::p2p::message::Message::Version(our_version.to_vec()),
    )?;
    report(Event::SentVersion {
        bytes: our_version.len(),
    });

    let mut state = Handshake::AwaitingVersion;
    let mut seen = 0;
    while seen < MESSAGES_BEFORE_VERACK_MAX {
        let frame = connection.read_frame()?;
        seen += 1;
        assert!(seen <= MESSAGES_BEFORE_VERACK_MAX);
        report(Event::Seen {
            command: frame.command,
            bytes: frame.payload.len(),
        });
        let message = crate::p2p::message::Message::decode(frame)?;
        state = match (state, message) {
            (Handshake::AwaitingVersion, crate::p2p::message::Message::Version(payload)) => {
                let (peer, verack) = crate::p2p::version::handle(&payload)?;
                send(connection, verack)?;
                Handshake::AwaitingVerack(peer)
            }
            (Handshake::AwaitingVersion, crate::p2p::message::Message::Verack) => {
                return Err(Error::VerackBeforeVersion);
            }
            (Handshake::AwaitingVerack(peer), crate::p2p::message::Message::Verack) => {
                report(Event::HandshakeComplete {
                    peer,
                    elapsed: connection.now() - started,
                });
                return Ok(());
            }
            (state, _) => state,
        };
    }
    assert_eq!(seen, MESSAGES_BEFORE_VERACK_MAX);
    Err(Error::NoVerackAfter)
}

fn sync<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    chain: &mut crate::chain::Chain,
    report: &mut impl FnMut(Event),
) -> Result<(), Error> {
    let mut batches = 0;
    while batches < BATCHES_MAX {
        let request = crate::p2p::getheaders::GetHeaders::from_tip(chain);
        send(
            connection,
            crate::p2p::message::Message::GetHeaders(request),
        )?;
        report(Event::Asked {
            height: chain.height(),
        });

        let headers = await_headers(connection, report)?;
        let taken = crate::p2p::headers::handle(headers, chain)?;
        batches += 1;
        report(Event::Took {
            count: taken.count,
            height: chain.height(),
        });
        if !taken.more {
            report(Event::Synced {
                height: chain.height(),
                tip: chain.tip(),
            });
            return Ok(());
        }
    }
    assert_eq!(batches, BATCHES_MAX);
    report(Event::Capped {
        height: chain.height(),
        tip: chain.tip(),
    });
    Ok(())
}

fn await_headers<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    report: &mut impl FnMut(Event),
) -> Result<crate::p2p::headers::Headers, Error> {
    connection.set_read_deadline(Some(connection.now() + RESPONSE_TIME))?;
    let result = await_headers_until_deadline(connection, report);
    connection.set_read_deadline(None)?;
    result
}

fn await_headers_until_deadline<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    report: &mut impl FnMut(Event),
) -> Result<crate::p2p::headers::Headers, Error> {
    loop {
        let frame = connection.read_frame()?;
        match crate::p2p::message::Message::decode(frame)? {
            crate::p2p::message::Message::Headers(headers) => return Ok(headers),
            crate::p2p::message::Message::Ping(nonce) => {
                send(connection, crate::p2p::ping::handle(nonce))?;
                report(Event::Ponged(nonce));
            }
            crate::p2p::message::Message::Version(_)
            | crate::p2p::message::Message::Verack
            | crate::p2p::message::Message::Pong(_)
            | crate::p2p::message::Message::GetHeaders(_)
            | crate::p2p::message::Message::Unknown(_) => {}
        }
    }
}

fn linger_for<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    linger: std::time::Duration,
    report: &mut impl FnMut(Event),
) -> Result<(), Error> {
    connection.set_read_deadline(Some(connection.now() + linger))?;
    let result = linger_until_deadline(connection, linger, report);
    connection.set_read_deadline(None)?;
    result
}

fn linger_until_deadline<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    linger: std::time::Duration,
    report: &mut impl FnMut(Event),
) -> Result<(), Error> {
    loop {
        match connection.read_frame() {
            Ok(frame) => match crate::p2p::message::Message::decode(frame)? {
                crate::p2p::message::Message::Ping(nonce) => {
                    match send(connection, crate::p2p::ping::handle(nonce)) {
                        Ok(()) => report(Event::Ponged(nonce)),
                        Err(crate::p2p::frame::Error::Io(e)) if peer_hung_up(&e) => {
                            report(Event::PeerHungUp);
                            return Ok(());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                other => report(Event::Ignored(other)),
            },
            Err(crate::p2p::frame::Error::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                report(Event::LingerOver(linger));
                return Ok(());
            }
            Err(crate::p2p::frame::Error::Io(e)) if peer_hung_up(&e) => {
                report(Event::PeerHungUp);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
    }
}

fn peer_hung_up(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
    )
}

#[cfg(test)]
mod tests {
    const VERSION: &str = "fabfb5da76657273696f6e000000000066000000da70f6db80110100090c00000000000028b0a66a000000000000000000000000000000000000000000000000000000000000090c000000000000000000000000000000000000000000000000d07dc58995aa90bc102f5361746f7368693a33312e312e302f0000000001";
    const WTXIDRELAY: &str = "fabfb5da777478696472656c61790000000000005df6e0e2";
    const SENDADDRV2: &str = "fabfb5da73656e646164647276320000000000005df6e0e2";
    const VERACK: &str = "fabfb5da76657261636b000000000000000000005df6e0e2";
    const SENDCMPCT: &str = "fabfb5da73656e64636d70637400000009000000e92f5ef8000200000000000000";
    const PING: &str = "fabfb5da70696e670000000000000000080000000518a0f806d2e2149c8064fd";
    const FEEFILTER: &str = "fabfb5da66656566696c746572000000080000000a19f7997a9e970000000000";
    const HEADERS: &str = "fabfb5da686561646572730000000000f40000002f52e50d030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910fce25a9ef6a61909eadcc696fb71eb4d3216de17cc3731ecdd321a030e9213a1226cda96affff7f2000000000000000002034cf96da8f1b387300eaa047d30955fbaf1b0bb6f261f22425454a6b43b7b233650b72ea7da500a8429598a02571115bf2b6ee26da96be0378ff7cba4c98780e27cda96affff7f200300000000000000200e6ddccc471aeeb899ff667f7d55da0443769850872e6d44924d32d610f24c2869ee5ba689a2d757c652f917d12a43c9b24ba79dcff22abbea56c075d3d2bd7227cda96affff7f200000000000";
    const PING_NONCE: u64 = 0xfd64_809c_14e2_d206;

    const GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
    const BLOCK_3: &str = "08e1a659dc25965d0cdf6d093b9247b09e9ce97a22cc77bca0b510ba4b337d61";

    const NETWORK: crate::chain::network::Network = crate::chain::network::Network::Regtest;
    const OUR_VERSION: &[u8] = b"a version payload the peer does not read";
    const LINGER: std::time::Duration = std::time::Duration::from_secs(60);

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn framed(message: crate::p2p::message::Message) -> Vec<u8> {
        let frame = message.encode();
        let mut out = Vec::new();
        crate::p2p::frame::write(&mut out, NETWORK, frame.command, &frame.payload).unwrap();
        out
    }

    fn sends(frames: Vec<Vec<u8>>) -> Vec<crate::p2p::scripted::Step> {
        frames
            .into_iter()
            .map(crate::p2p::scripted::Step::Send)
            .collect()
    }

    fn handshake() -> Vec<Vec<u8>> {
        vec![fixture(VERSION), fixture(VERACK)]
    }

    fn our_handshake_bytes() -> usize {
        2 * crate::p2p::frame::HEADER_BYTES + OUR_VERSION.len()
    }

    fn batch_after(
        previous: &crate::chain::block_header::BlockHash,
        height_first: usize,
        count: usize,
    ) -> Vec<u8> {
        let genesis = crate::chain::genesis(NETWORK);
        let mut payload = Vec::new();
        crate::p2p::compact_size::write_len(&mut payload, count);
        let mut previous_block =
            crate::chain::block_header::BlockHash::from_bytes(*previous.as_bytes());
        for i in 0..count {
            let mut header = crate::chain::block_header::Header {
                version: 1,
                previous_block,
                merkle_root: crate::chain::block_header::MerkleRoot::from_bytes([0; 32]),
                time: genesis.time + u32::try_from(height_first + i).unwrap(),
                bits: 0x207f_ffff,
                nonce: 0,
            };
            crate::chain::pow::mine(&mut header, NETWORK);
            payload.extend_from_slice(&header.encode());
            payload.push(0);
            previous_block = header.hash();
        }
        let headers = crate::p2p::headers::Headers::parse(&payload).unwrap();
        framed(crate::p2p::message::Message::Headers(headers))
    }

    fn getheaders(chain: &crate::chain::Chain) -> Vec<u8> {
        framed(crate::p2p::message::Message::GetHeaders(
            crate::p2p::getheaders::GetHeaders::from_tip(chain),
        ))
    }

    fn headers_in(batch: &[u8]) -> crate::p2p::headers::Headers {
        let frame = crate::p2p::frame::read(&mut &batch[..], NETWORK).unwrap();
        match crate::p2p::message::Message::decode(frame).unwrap() {
            crate::p2p::message::Message::Headers(headers) => headers,
            other => panic!("{other}"),
        }
    }

    struct Ran {
        result: Result<(), super::Error>,
        events: Vec<String>,
        sent: Vec<u8>,
        unread: usize,
        waited: std::time::Duration,
    }

    impl Ran {
        fn after_handshake(&self) -> &[String] {
            let complete = self
                .events
                .iter()
                .position(|e| e.starts_with("handshake complete"))
                .unwrap_or_else(|| panic!("no handshake in {:?}", self.events));
            &self.events[complete + 1..]
        }

        fn sent_after_handshake(&self) -> &[u8] {
            &self.sent[our_handshake_bytes()..]
        }
    }

    fn run(chain: &mut crate::chain::Chain, script: Vec<crate::p2p::scripted::Step>) -> Ran {
        run_with(chain, script, None, None)
    }

    fn run_with(
        chain: &mut crate::chain::Chain,
        script: Vec<crate::p2p::scripted::Step>,
        chunk: Option<usize>,
        deadline: Option<std::time::Duration>,
    ) -> Ran {
        let mut connection = match chunk {
            Some(chunk) => {
                crate::p2p::scripted::connect_in_chunks(script, chunk, std::time::UNIX_EPOCH)
            }
            None => crate::p2p::scripted::connect(script, std::time::UNIX_EPOCH),
        };
        if let Some(deadline) = deadline {
            connection
                .set_read_deadline(Some(connection.now() + deadline))
                .unwrap();
        }
        let started = connection.now();
        let mut events = Vec::new();
        let result = super::run(&mut connection, chain, OUR_VERSION, LINGER, |event| {
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

    fn session(script: Vec<Vec<u8>>) -> (crate::chain::Chain, Ran) {
        let mut chain = crate::chain::Chain::new(NETWORK);
        let mut frames = handshake();
        frames.extend(script);
        let ran = run(&mut chain, sends(frames));
        (chain, ran)
    }

    #[test]
    fn a_whole_session_against_core_bytes() {
        // Red if any phase drops a frame it should answer, or answers one it
        // should drop: Core's handshake burst, its post-verack burst, and
        // its headers, in the order they came, then the peer hangs up.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(
            &mut chain,
            sends(vec![
                fixture(VERSION),
                fixture(WTXIDRELAY),
                fixture(SENDADDRV2),
                fixture(VERACK),
                fixture(SENDCMPCT),
                fixture(PING),
                fixture(FEEFILTER),
                fixture(HEADERS),
            ]),
        );
        ran.result.as_ref().unwrap();
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().to_string(), BLOCK_3);

        assert_eq!(
            &ran.sent[..16],
            b"\xfa\xbf\xb5\xdaversion\0\0\0\0\0",
            "BIP324 v1 prefix"
        );
        let our_version_frame_len = crate::p2p::frame::HEADER_BYTES + OUR_VERSION.len();
        assert_eq!(
            &ran.sent[our_version_frame_len..our_handshake_bytes()],
            fixture(VERACK),
            "our verack is Core's verack"
        );
        let request = getheaders(&crate::chain::Chain::new(NETWORK));
        let pong = framed(crate::p2p::message::Message::Pong(PING_NONCE));
        assert_eq!(ran.sent_after_handshake(), [request, pong].concat());

        assert_eq!(
            ran.events,
            [
                format!("-> version ({} bytes)", OUR_VERSION.len()),
                "<- version (102 bytes)".to_string(),
                "<- wtxidrelay (0 bytes)".to_string(),
                "<- sendaddrv2 (0 bytes)".to_string(),
                "<- verack (0 bytes)".to_string(),
                "handshake complete in 0ns\npeer is /Satoshi:31.1.0/ protocol 70016 height 0 services 0xc09 relay true".to_string(),
                "-> getheaders (from height 0)".to_string(),
                format!("<- ping {PING_NONCE:#018x}\n-> pong"),
                "<- headers (3), height 3".to_string(),
                format!("synced: height 3, tip {BLOCK_3}"),
                "peer hung up".to_string(),
            ]
        );
        assert_eq!(ran.unread, 0);
        println!("{}", ran.events.join("\n"));
    }

    #[test]
    fn a_frame_dripped_one_byte_per_read_is_read_whole() {
        // Red if a frame is read in one `read` call and a short read is
        // taken for the whole.
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run_with(
            &mut chain,
            sends(vec![
                fixture(VERSION),
                fixture(WTXIDRELAY),
                fixture(SENDADDRV2),
                fixture(VERACK),
                fixture(PING),
                fixture(HEADERS),
            ]),
            Some(1),
            None,
        );
        ran.result.as_ref().unwrap();
        assert_eq!(chain.height(), 3);
        assert_eq!(chain.tip().to_string(), BLOCK_3);
        assert_eq!(ran.unread, 0);
        println!("six frames, one byte per read:\n{}", ran.events.join("\n"));
    }

    #[test]
    fn rejects_verack_before_version() {
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(&mut chain, sends(vec![fixture(VERACK), fixture(VERSION)]));
        let err = ran.result.unwrap_err();
        assert!(matches!(err, super::Error::VerackBeforeVersion), "{err}");
        assert_eq!(
            ran.sent.len(),
            crate::p2p::frame::HEADER_BYTES + OUR_VERSION.len(),
            "no verack from us"
        );
        println!("{err}");
    }

    fn version_cut_to(len: usize) -> Vec<u8> {
        let payload = &fixture(VERSION)[crate::p2p::frame::HEADER_BYTES..][..len];
        let mut bytes = Vec::new();
        crate::p2p::frame::write(&mut bytes, NETWORK, crate::p2p::version::COMMAND, payload)
            .unwrap();
        bytes
    }

    #[test]
    fn a_version_that_does_not_parse_earns_no_verack() {
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(
            &mut chain,
            sends(vec![
                version_cut_to(80),
                fixture(WTXIDRELAY),
                fixture(VERACK),
            ]),
        );
        let err = ran.result.unwrap_err();
        assert!(
            matches!(
                err,
                super::Error::Version(crate::p2p::version::Error::Truncated)
            ),
            "{err}"
        );
        assert_eq!(
            ran.sent.len(),
            crate::p2p::frame::HEADER_BYTES + OUR_VERSION.len(),
            "no verack from us"
        );
        println!("{err}; the stream is dropped with the peer's verack unread");
    }

    #[test]
    fn a_second_version_is_dropped_like_core_drops_it() {
        let (chain, ran) = {
            let mut chain = crate::chain::Chain::new(NETWORK);
            let ran = run(
                &mut chain,
                sends(vec![
                    fixture(VERSION),
                    version_cut_to(3),
                    fixture(VERACK),
                    fixture(HEADERS),
                ]),
            );
            (chain, ran)
        };
        ran.result.as_ref().unwrap();
        assert_eq!(chain.height(), 3);
        assert!(
            ran.events
                .iter()
                .any(|e| e.contains("peer is /Satoshi:31.1.0/")),
            "the first one counts: {:?}",
            ran.events
        );
        assert_eq!(ran.events[2], "<- version (3 bytes)");
        println!("second version, three bytes long, ignored; handshake complete");
    }

    #[test]
    fn gives_up_without_verack() {
        let mut frames = vec![fixture(VERSION)];
        frames.resize(super::MESSAGES_BEFORE_VERACK_MAX, fixture(WTXIDRELAY));
        frames.push(fixture(VERACK));
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(&mut chain, sends(frames));
        let err = ran.result.unwrap_err();
        assert!(matches!(err, super::Error::NoVerackAfter), "{err}");
        assert_eq!(
            ran.unread,
            fixture(VERACK).len(),
            "the verack that followed was never read"
        );
        println!("{err}; the verack that followed was never read");
    }

    #[test]
    fn reports_a_peer_that_hangs_up_mid_handshake() {
        let mut script = sends(vec![fixture(VERSION)]);
        script.push(crate::p2p::scripted::Step::HangUp);
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(&mut chain, script);
        let super::Error::Frame(crate::p2p::frame::Error::Io(io)) = ran.result.unwrap_err() else {
            panic!("expected io");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
        println!("peer sent version then closed: {io}");
    }

    #[test]
    fn a_deadline_before_verack_is_an_error_not_a_wait() {
        // Red if the handshake re-arms the caller's deadline or reads on
        // after a timeout.
        let mut script = sends(vec![fixture(VERSION)]);
        script.push(crate::p2p::scripted::Step::Silence);
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run_with(
            &mut chain,
            script,
            None,
            Some(std::time::Duration::from_secs(10)),
        );
        let super::Error::Frame(crate::p2p::frame::Error::Io(io)) = ran.result.unwrap_err() else {
            panic!("expected io");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            ran.sent.len(),
            our_handshake_bytes(),
            "version answered with verack before the peer went quiet"
        );
        assert_eq!(ran.waited, std::time::Duration::from_secs(10));
        println!("peer sent version then nothing: {io}");
    }

    #[test]
    #[should_panic(expected = "the chain and the connection are on one network")]
    fn a_chain_on_another_network_than_the_connection_is_our_bug() {
        // Red if the assertion is missing or after the first write: the
        // script is empty, so a run that gets past the check fails on the
        // read, not on the panic. `run` above builds the connection on
        // `NETWORK`; the chain here is not.
        let mut chain = crate::chain::Chain::new(crate::chain::network::Network::Mainnet);
        let _ = run(&mut chain, Vec::new());
    }

    #[test]
    fn a_full_batch_is_followed_by_a_request_from_the_new_tip() {
        // Red if a batch of exactly 2000 ends the sync, or the second
        // request carries the old locator.
        let first_request = getheaders(&crate::chain::Chain::new(NETWORK));
        let full = batch_after(
            &crate::chain::Chain::new(NETWORK).tip(),
            1,
            crate::p2p::headers::HEADERS_MAX,
        );
        let mut at_2000 = crate::chain::Chain::new(NETWORK);
        at_2000.extend(headers_in(&full).into_vec()).unwrap();
        let second_request = getheaders(&at_2000);
        let short = batch_after(&at_2000.tip(), crate::p2p::headers::HEADERS_MAX + 1, 5);
        let last = headers_in(&short).as_slice().last().unwrap().hash();

        let (chain, ran) = session(vec![full, short]);
        ran.result.as_ref().unwrap();
        assert_eq!(chain.height(), 2005);
        assert_eq!(chain.tip().to_string(), last.to_string());
        assert_eq!(
            ran.sent_after_handshake(),
            [first_request, second_request].concat()
        );
        assert_eq!(
            ran.after_handshake(),
            [
                "-> getheaders (from height 0)",
                "<- headers (2000), height 2000",
                "-> getheaders (from height 2000)",
                "<- headers (5), height 2005",
                &format!("synced: height 2005, tip {last}"),
                "peer hung up",
            ]
        );
        println!("{}", ran.events.join("\n"));
    }

    #[test]
    fn stops_after_the_capped_number_of_full_batches() {
        // Red if the cap is off by one in either direction: a third request
        // would take the third batch into the chain, one fewer would leave
        // the second unread. The third batch arrives during the linger,
        // where nothing asked for it, and is named and dropped.
        let mut script = Vec::new();
        let mut previous = crate::chain::Chain::new(NETWORK).tip();
        let mut height_first = 1;
        for _ in 0..=super::BATCHES_MAX {
            let batch = batch_after(&previous, height_first, crate::p2p::headers::HEADERS_MAX);
            previous = headers_in(&batch).as_slice().last().unwrap().hash();
            height_first += crate::p2p::headers::HEADERS_MAX;
            script.push(batch);
        }

        let (chain, ran) = session(script);
        ran.result.as_ref().unwrap();
        let height = super::BATCHES_MAX * crate::p2p::headers::HEADERS_MAX;
        assert_eq!(chain.height(), height);
        assert_eq!(
            ran.after_handshake()
                .iter()
                .filter(|e| e.starts_with("->"))
                .count(),
            super::BATCHES_MAX
        );
        let tip = chain.tip();
        assert!(
            ran.events.contains(&format!(
                "stopped at {} batches (ROADMAP step 8): height {height}, tip {tip}; the peer may have more",
                super::BATCHES_MAX
            )),
            "{:?}",
            ran.events
        );
        assert_eq!(
            ran.events[ran.events.len() - 2],
            "<- headers (2000) ignored",
            "the third batch was never asked for"
        );
        assert_eq!(ran.unread, 0);
        println!("{}", ran.after_handshake().join("\n"));
    }

    #[test]
    fn a_batch_off_the_tip_ends_the_sync_with_the_chain_as_it_was() {
        // Red if the join is not checked, or the chain took the batch before
        // the check. Core's `headers` from genesis, sent to a chain that has
        // those three already: the shape a peer answers from a fork below
        // our tip.
        let mut chain = crate::chain::Chain::new(NETWORK);
        chain
            .extend(headers_in(&fixture(HEADERS)).into_vec())
            .unwrap();
        let mut frames = handshake();
        frames.push(fixture(HEADERS));
        let ran = run(&mut chain, sends(frames));
        let err = ran.result.as_ref().err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Chain(crate::chain::Error::NotOnTip { previous_block, tip })
                    if previous_block.to_string() == GENESIS && tip.to_string() == BLOCK_3
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 3);
        assert_eq!(ran.after_handshake(), ["-> getheaders (from height 3)"]);
        println!("{err}");
    }

    #[test]
    fn silence_after_getheaders_is_a_timeout() {
        // Red if the loop waits without a deadline, re-arms it per read, or
        // treats a frame that is not `headers` as the answer: two waits that
        // each fit the bound and together do not.
        let wait = super::RESPONSE_TIME * 2 / 3;
        let mut script = sends(handshake());
        script.extend([
            crate::p2p::scripted::Step::Send(fixture(SENDCMPCT)),
            crate::p2p::scripted::Step::Wait(wait),
            crate::p2p::scripted::Step::Send(fixture(PING)),
            crate::p2p::scripted::Step::Wait(wait),
        ]);
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(&mut chain, script);
        let err = ran.result.as_ref().err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Frame(crate::p2p::frame::Error::Io(e))
                    if e.kind() == std::io::ErrorKind::TimedOut
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0);
        let pong = framed(crate::p2p::message::Message::Pong(PING_NONCE));
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
        let frame = crate::p2p::frame::read(&mut &fixture(HEADERS)[..], NETWORK).unwrap();
        let mut payload = frame.payload;
        assert_eq!(payload[1 + 80], 0, "the count after the first header");
        payload[1 + 80] = 1;
        let mut bad = Vec::new();
        crate::p2p::frame::write(&mut bad, NETWORK, frame.command, &payload).unwrap();

        let (chain, ran) = session(vec![bad]);
        let err = ran.result.as_ref().err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Message(crate::p2p::message::Error::Headers(_))
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 0);
        println!("{err}");
    }

    #[test]
    fn a_hang_up_while_we_wait_is_an_end_of_stream_not_a_timeout() {
        // Red if a peer that leaves mid-frame is reported as a timeout, or
        // the read waits out the deadline first.
        let half = fixture(HEADERS)[..crate::p2p::frame::HEADER_BYTES + 10].to_vec();
        let mut frames = handshake();
        frames.push(half);
        let mut script = sends(frames);
        script.push(crate::p2p::scripted::Step::HangUp);
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(&mut chain, script);
        let err = ran.result.as_ref().err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Frame(crate::p2p::frame::Error::Io(e))
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
        // Red if a `verack` after the handshake is an error or an answer.
        let request = getheaders(&crate::chain::Chain::new(NETWORK));
        let (chain, ran) = session(vec![
            framed(crate::p2p::message::Message::Verack),
            fixture(HEADERS),
        ]);
        ran.result.as_ref().unwrap();
        assert_eq!(chain.height(), 3);
        assert_eq!(
            ran.sent_after_handshake(),
            request,
            "the verack earned no answer"
        );
        assert_eq!(
            ran.after_handshake(),
            [
                "-> getheaders (from height 0)",
                "<- headers (3), height 3",
                &format!("synced: height 3, tip {BLOCK_3}"),
                "peer hung up",
            ]
        );
        println!("{}", ran.after_handshake().join("\n"));
    }

    #[test]
    fn the_linger_answers_pings_names_the_rest_and_ends_on_the_clock() {
        // Red if the linger has no deadline, drops a ping, or reports a
        // silence as the peer's hang-up.
        let mut script = sends(handshake());
        script.push(crate::p2p::scripted::Step::Send(fixture(HEADERS)));
        script.push(crate::p2p::scripted::Step::Send(fixture(FEEFILTER)));
        script.push(crate::p2p::scripted::Step::Send(fixture(PING)));
        script.push(crate::p2p::scripted::Step::Silence);
        let mut chain = crate::chain::Chain::new(NETWORK);
        let ran = run(&mut chain, script);
        ran.result.as_ref().unwrap();
        let pong = framed(crate::p2p::message::Message::Pong(PING_NONCE));
        assert!(ran.sent.ends_with(&pong));
        assert_eq!(
            &ran.after_handshake()[3..],
            [
                "<- feefilter (8 bytes) ignored",
                &format!("<- ping {PING_NONCE:#018x}\n-> pong"),
                &format!("{LINGER:?} after the sync, hanging up"),
            ]
        );
        assert_eq!(ran.waited, LINGER);
        println!("{}", ran.after_handshake().join("\n"));
    }

    #[test]
    fn a_malformed_ping_during_the_linger_ends_the_session() {
        // Red if the linger drops a known command with a bad length the way
        // it drops an unknown command. Core would stay; we do not.
        let mut bad = Vec::new();
        crate::p2p::frame::write(&mut bad, NETWORK, crate::p2p::ping::COMMAND, &[0; 7]).unwrap();
        let (chain, ran) = session(vec![fixture(HEADERS), bad]);
        let err = ran.result.as_ref().err().unwrap();
        assert!(
            matches!(
                &err,
                super::Error::Message(crate::p2p::message::Error::BadLength {
                    len_actual: 7,
                    len_expected: 8,
                    ..
                })
            ),
            "{err}"
        );
        assert_eq!(chain.height(), 3, "the sync was done");
        println!("{err}");
    }
}
