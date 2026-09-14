//! The `version`/`verack` exchange, from the side that opened the connection.
//!
//! We send `version` first, whole, before we read anything. A Core with
//! BIP324 on decides v1 or v2 from the first 16 bytes on the socket: the
//! magic and `"version\0\0\0\0\0"` (`../bitcoin/src/net.cpp:1090` at v31.1).
//! Anything else starts a v2 key exchange.
//!
//! The peer's `version` earns our `verack`. The peer's `verack` completes the
//! handshake. Core, as the responder, sends both in that order, with feature
//! negotiation in between (`net_processing.cpp:3664`, `:3716`, `:3725`,
//! `:3744`).

const VERSION: crate::message::Command = crate::message::Command::from_static("version");
const VERACK: crate::message::Command = crate::message::Command::from_static("verack");

/// How many messages we read before we give up waiting for `verack`. Core
/// sends at most four before it: `version`, `wtxidrelay`, `sendaddrv2` and
/// `sendtxrcncl`. A peer that sends many more is not shaking hands; Core
/// bounds the same wait with a 60 s timer instead.
///
/// Known gap: this bounds messages, not time. The socket's read timeout is
/// per syscall, so a peer that drips one byte at a time holds `read` open
/// for as long as it likes and this counter never advances. Accepted for
/// now with one trusted peer; the wall-clock bound is issue #4.
const MESSAGES_BEFORE_VERACK_MAX: usize = 16;

#[derive(Debug)]
pub enum Error {
    Message(crate::message::Error),
    /// The peer's `version` did not parse, or is too old to keep. Core would
    /// log the first and wait out its 60 s timer; with one peer we hang up.
    Version(crate::version::Error),
    /// The peer acknowledged our `version` before it sent its own. Core drops
    /// every message that arrives before `version`
    /// (`net_processing.cpp:3815`); with one peer we have nothing to keep, so
    /// we hang up instead.
    VerackBeforeVersion,
    /// `MESSAGES_BEFORE_VERACK_MAX` frames came in and none was `verack`.
    NoVerackAfter,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Message(e) => write!(f, "{e}"),
            Error::Version(e) => write!(f, "peer version: {e}"),
            Error::VerackBeforeVersion => write!(f, "verack before version"),
            Error::NoVerackAfter => {
                write!(f, "no verack after {MESSAGES_BEFORE_VERACK_MAX} messages")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<crate::message::Error> for Error {
    fn from(e: crate::message::Error) -> Self {
        Error::Message(e)
    }
}

impl From<crate::version::Error> for Error {
    fn from(e: crate::version::Error) -> Self {
        Error::Version(e)
    }
}

/// A handshake that finished: both sides have sent `version` and `verack`.
#[derive(Debug)]
pub struct Complete<S> {
    /// The stream, positioned after the peer's `verack`.
    pub stream: S,
    pub peer: crate::version::Received,
    /// Every frame the peer sent, up to and including its `verack`, in order,
    /// for the caller to report: at most `MESSAGES_BEFORE_VERACK_MAX`, each
    /// already bounded by `message::read`.
    pub seen: Vec<crate::message::Frame>,
}

/// Where we are between our `version` and the peer's `verack`. The peer's
/// `version` is parsed on the way into `AwaitingVerack`, so a `verack` we
/// send is one that a parsed `version` earned.
enum State {
    AwaitingVersion,
    AwaitingVerack(crate::version::Received),
}

/// Runs the handshake over `stream`, which comes back inside `Complete` on
/// `Ok`. On `Err` it is gone: the peer left it in a state we cannot name, and
/// dropping it is the hang-up.
pub fn run<S: std::io::Read + std::io::Write>(
    mut stream: S,
    network: crate::message::Network,
    our_version: &[u8],
) -> Result<Complete<S>, Error> {
    crate::message::write(&mut stream, network, VERSION, our_version)?;

    let mut seen = Vec::with_capacity(MESSAGES_BEFORE_VERACK_MAX);
    let mut state = State::AwaitingVersion;
    while seen.len() < MESSAGES_BEFORE_VERACK_MAX {
        let frame = crate::message::read(&mut stream, network)?;
        state = match (state, frame.command) {
            (State::AwaitingVersion, VERSION) => {
                let peer = crate::version::parse(&frame.payload)?;
                crate::message::write(&mut stream, network, VERACK, &[])?;
                State::AwaitingVerack(peer)
            }
            (State::AwaitingVersion, VERACK) => return Err(Error::VerackBeforeVersion),
            (State::AwaitingVerack(peer), VERACK) => {
                seen.push(frame);
                assert!(seen.len() <= MESSAGES_BEFORE_VERACK_MAX);
                return Ok(Complete { stream, peer, seen });
            }
            // Feature negotiation we do not speak yet, and a second `version`,
            // which Core also drops (`net_processing.cpp:3586`).
            (state, _) => state,
        };
        seen.push(frame);
    }
    assert_eq!(seen.len(), MESSAGES_BEFORE_VERACK_MAX);
    Err(Error::NoVerackAfter)
}

#[cfg(test)]
mod tests {
    // Every frame below was sent by Bitcoin Core v31.1.0, `bitcoind -regtest`,
    // on 2026-09-13, in this order, in answer to a `version` that a throwaway
    // Python script sent over a raw TCP socket. `sendcmpct` came after the
    // script's `verack`.
    const VERSION: &str = "fabfb5da76657273696f6e000000000066000000da70f6db80110100090c00000000000028b0a66a000000000000000000000000000000000000000000000000000000000000090c000000000000000000000000000000000000000000000000d07dc58995aa90bc102f5361746f7368693a33312e312e302f0000000001";
    const WTXIDRELAY: &str = "fabfb5da777478696472656c61790000000000005df6e0e2";
    const SENDADDRV2: &str = "fabfb5da73656e646164647276320000000000005df6e0e2";
    const VERACK: &str = "fabfb5da76657261636b000000000000000000005df6e0e2";
    const SENDCMPCT: &str = "fabfb5da73656e64636d70637400000009000000e92f5ef8000200000000000000";

    const OUR_VERSION: &[u8] = b"a version payload the peer does not read";

    fn fixture(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// A socket stand-in: the peer's bytes on one side, ours collected on the
    /// other. `run` takes the stream by value and keeps it only on `Ok`, so
    /// the written bytes live outside: a test that expects `Err` still gets
    /// to read them, once the borrow ends with the dropped stream.
    #[derive(Debug)]
    struct Duplex<'a> {
        from_peer: std::io::Cursor<Vec<u8>>,
        to_peer: &'a mut Vec<u8>,
    }

    impl<'a> Duplex<'a> {
        fn peer_sends(frames: &[&str], to_peer: &'a mut Vec<u8>) -> Self {
            let bytes = frames.iter().flat_map(|hex| fixture(hex)).collect();
            Duplex {
                from_peer: std::io::Cursor::new(bytes),
                to_peer,
            }
        }

        fn unread(&self) -> usize {
            self.from_peer.get_ref().len() - usize::try_from(self.from_peer.position()).unwrap()
        }
    }

    impl std::io::Read for Duplex<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.from_peer, buf)
        }
    }

    impl std::io::Write for Duplex<'_> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(self.to_peer, buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run<'a>(
        frames: &[&str],
        sent: &'a mut Vec<u8>,
    ) -> Result<super::Complete<Duplex<'a>>, super::Error> {
        let stream = Duplex::peer_sends(frames, sent);
        super::run(stream, crate::message::Network::Regtest, OUR_VERSION)
    }

    #[test]
    fn completes_against_core_bytes() {
        let mut sent = Vec::new();
        let done = run(
            &[VERSION, WTXIDRELAY, SENDADDRV2, VERACK, SENDCMPCT],
            &mut sent,
        )
        .unwrap();

        let commands: Vec<String> = done.seen.iter().map(|f| f.command.to_string()).collect();
        assert_eq!(
            commands,
            ["version", "wtxidrelay", "sendaddrv2", "verack"],
            "every frame up to verack comes back, in order"
        );
        assert_eq!(done.peer.user_agent, b"/Satoshi:31.1.0/");
        assert_eq!(done.peer.start_height, 0);

        let to_peer = &*done.stream.to_peer;
        assert_eq!(
            &to_peer[..16],
            b"\xfa\xbf\xb5\xdaversion\0\0\0\0\0",
            "BIP324 v1 prefix"
        );
        let our_version_frame_len = crate::message::HEADER_BYTES + OUR_VERSION.len();
        assert_eq!(
            &to_peer[our_version_frame_len..],
            fixture(VERACK),
            "our verack is Core's verack"
        );
        assert_eq!(
            to_peer.len(),
            our_version_frame_len + crate::message::HEADER_BYTES,
            "nothing else"
        );
        assert_eq!(
            done.stream.unread(),
            fixture(SENDCMPCT).len(),
            "stops at verack; sendcmpct is left for the caller"
        );
        println!(
            "sent version and verack; saw {}; peer is {}",
            commands.join(", "),
            done.peer
        );
    }

    #[test]
    fn rejects_verack_before_version() {
        let mut sent = Vec::new();
        let err = run(&[VERACK, VERSION], &mut sent).unwrap_err();
        assert!(matches!(err, super::Error::VerackBeforeVersion), "{err}");
        assert_eq!(
            sent.len(),
            crate::message::HEADER_BYTES + OUR_VERSION.len(),
            "no verack from us"
        );
        println!("{err}");
    }

    /// Core's `version` frame with its payload cut to `len` bytes, framed
    /// again so the envelope passes and only the payload is wrong.
    fn version_cut_to(len: usize) -> String {
        let payload = &fixture(VERSION)[crate::message::HEADER_BYTES..][..len];
        let mut bytes = Vec::new();
        crate::message::write(
            &mut bytes,
            crate::message::Network::Regtest,
            super::VERSION,
            payload,
        )
        .unwrap();
        bytes.iter().fold(String::new(), |mut hex, byte| {
            std::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}")).unwrap();
            hex
        })
    }

    #[test]
    fn a_version_that_does_not_parse_earns_no_verack() {
        let mut sent = Vec::new();
        let err = run(&[&version_cut_to(80), WTXIDRELAY, VERACK], &mut sent).unwrap_err();
        assert!(
            matches!(err, super::Error::Version(crate::version::Error::Truncated)),
            "{err}"
        );
        assert_eq!(
            sent.len(),
            crate::message::HEADER_BYTES + OUR_VERSION.len(),
            "no verack from us"
        );
        println!("{err}; the stream is dropped with the peer's verack unread");
    }

    #[test]
    fn a_second_version_is_dropped_like_core_drops_it() {
        let mut sent = Vec::new();
        let done = run(&[VERSION, &version_cut_to(3), VERACK], &mut sent).unwrap();
        assert_eq!(done.seen.len(), 3);
        assert_eq!(
            done.peer.user_agent, b"/Satoshi:31.1.0/",
            "the first one counts"
        );
        println!("second version, three bytes long, ignored; handshake complete");
    }

    #[test]
    fn gives_up_without_verack() {
        let mut frames = vec![VERSION];
        frames.resize(super::MESSAGES_BEFORE_VERACK_MAX, WTXIDRELAY);
        frames.push(VERACK);
        let mut sent = Vec::new();
        let err = run(&frames, &mut sent).unwrap_err();
        assert!(matches!(err, super::Error::NoVerackAfter), "{err}");
        println!("{err}; the verack that followed was never read");
    }

    #[test]
    fn reports_a_peer_that_hangs_up_mid_handshake() {
        let mut sent = Vec::new();
        let err = run(&[VERSION], &mut sent).unwrap_err();
        let super::Error::Message(crate::message::Error::Io(io)) = err else {
            panic!("expected io, got {err}");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
        println!("peer sent version then closed: {io}");
    }
}
