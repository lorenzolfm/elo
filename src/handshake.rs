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

const VERSION: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("version");
const VERACK: crate::p2p::frame::Command = crate::p2p::frame::Command::from_static("verack");

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
    Message(crate::p2p::frame::Error),
    /// The peer's `version` did not parse, or is too old to keep. Core would
    /// log the first and wait out its 60 s timer; with one peer we hang up.
    Version(crate::p2p::version::Error),
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

impl From<crate::p2p::frame::Error> for Error {
    fn from(e: crate::p2p::frame::Error) -> Self {
        Error::Message(e)
    }
}

impl From<crate::p2p::version::Error> for Error {
    fn from(e: crate::p2p::version::Error) -> Self {
        Error::Version(e)
    }
}

/// A handshake that finished: both sides have sent `version` and `verack`.
#[derive(Debug)]
pub struct Complete {
    pub peer: crate::p2p::version::Peer,
    /// Every frame the peer sent, up to and including its `verack`, in order,
    /// for the caller to report: at most `MESSAGES_BEFORE_VERACK_MAX`, each
    /// already bounded by `frame::read`.
    pub seen: Vec<crate::p2p::frame::Frame>,
}

/// Where we are between our `version` and the peer's `verack`. The peer's
/// `version` is parsed on the way into `AwaitingVerack`, so a `verack` we
/// send is one that a parsed `version` earned.
enum State {
    AwaitingVersion,
    AwaitingVerack(crate::p2p::version::Peer),
}

/// Runs the handshake over `connection`. On `Ok` the connection is
/// positioned after the peer's `verack`. On `Err` the peer left it in a state
/// we cannot name; the caller drops it, and that is the hang-up.
///
/// The read deadline is the caller's: set it on `connection` before the call,
/// and every read in here runs into it (`main::TIMEOUT` today).
///
/// # Errors
///
/// `Message` if a frame cannot be read or written, including `Io` with kind
/// `TimedOut` when the deadline passes first. `Version` if the peer's
/// `version` does not parse or is too old. `VerackBeforeVersion` and
/// `NoVerackAfter` if the peer's messages come in an order or a number no
/// handshake has.
///
/// # Panics
///
/// If `seen` outgrows `MESSAGES_BEFORE_VERACK_MAX`. The loop condition rules
/// that out; the assertions restate it where a frame is kept.
pub fn run<L: crate::p2p::link::Link>(
    connection: &mut crate::p2p::connection::Connection<L>,
    our_version: &[u8],
) -> Result<Complete, Error> {
    connection.write_frame(VERSION, our_version)?;

    let mut seen = Vec::with_capacity(MESSAGES_BEFORE_VERACK_MAX);
    let mut state = State::AwaitingVersion;
    while seen.len() < MESSAGES_BEFORE_VERACK_MAX {
        let frame = connection.read_frame()?;
        state = match (state, frame.command) {
            (State::AwaitingVersion, VERSION) => {
                let peer = crate::p2p::version::parse(&frame.payload)?;
                connection.write_frame(VERACK, &[])?;
                State::AwaitingVerack(peer)
            }
            (State::AwaitingVersion, VERACK) => return Err(Error::VerackBeforeVersion),
            (State::AwaitingVerack(peer), VERACK) => {
                seen.push(frame);
                assert!(seen.len() <= MESSAGES_BEFORE_VERACK_MAX);
                return Ok(Complete { peer, seen });
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

    /// The peer's frames, each one its own step: a read never crosses two,
    /// so a hang-up or a silence can fall on a frame boundary.
    fn sends(frames: &[&str]) -> Vec<crate::p2p::scripted::Step> {
        frames
            .iter()
            .map(|hex| crate::p2p::scripted::Step::Send(fixture(hex)))
            .collect()
    }

    /// What one handshake left behind: what it returned, what we sent, and
    /// how many scripted bytes the peer never got to say.
    struct Ran {
        result: Result<super::Complete, super::Error>,
        sent: Vec<u8>,
        unread: usize,
    }

    /// Runs the handshake against a peer on this script. `chunk` bounds the
    /// bytes one read serves; `wait`, when set, is the read deadline the
    /// caller gives the loop, as `main.rs` does.
    fn run_with(
        script: Vec<crate::p2p::scripted::Step>,
        chunk: Option<usize>,
        wait: Option<std::time::Duration>,
    ) -> Ran {
        let mut connection = match chunk {
            Some(chunk) => {
                crate::p2p::scripted::connect_in_chunks(script, chunk, std::time::UNIX_EPOCH)
            }
            None => crate::p2p::scripted::connect(script, std::time::UNIX_EPOCH),
        };
        if let Some(wait) = wait {
            connection
                .set_read_deadline(Some(connection.now() + wait))
                .unwrap();
        }
        let result = super::run(&mut connection, OUR_VERSION);
        Ran {
            result,
            sent: connection.link().sent().to_vec(),
            unread: connection.link().unread(),
        }
    }

    fn run(frames: &[&str]) -> Ran {
        run_with(sends(frames), None, None)
    }

    #[test]
    fn completes_against_core_bytes() {
        // Mutant: `run` takes the peer's `version` for the end of the
        // handshake, or reads on past its `verack`.
        let ran = run(&[VERSION, WTXIDRELAY, SENDADDRV2, VERACK, SENDCMPCT]);
        let done = ran.result.unwrap();

        let commands: Vec<String> = done.seen.iter().map(|f| f.command.to_string()).collect();
        assert_eq!(
            commands,
            ["version", "wtxidrelay", "sendaddrv2", "verack"],
            "every frame up to verack comes back, in order"
        );
        assert_eq!(done.peer.user_agent, b"/Satoshi:31.1.0/");
        assert_eq!(done.peer.start_height, 0);

        let to_peer = &ran.sent;
        assert_eq!(
            &to_peer[..16],
            b"\xfa\xbf\xb5\xdaversion\0\0\0\0\0",
            "BIP324 v1 prefix"
        );
        let our_version_frame_len = crate::p2p::frame::HEADER_BYTES + OUR_VERSION.len();
        assert_eq!(
            &to_peer[our_version_frame_len..],
            fixture(VERACK),
            "our verack is Core's verack"
        );
        assert_eq!(
            to_peer.len(),
            our_version_frame_len + crate::p2p::frame::HEADER_BYTES,
            "nothing else"
        );
        assert_eq!(
            ran.unread,
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
    fn a_frame_dripped_one_byte_per_read_is_read_whole() {
        // Mutant: `frame::read` calls `read` once for the header and once
        // for the payload instead of `read_exact`; one byte is not a header.
        let ran = run_with(
            sends(&[VERSION, WTXIDRELAY, SENDADDRV2, VERACK]),
            Some(1),
            None,
        );
        let done = ran.result.unwrap();
        assert_eq!(done.seen.len(), 4);
        assert_eq!(done.peer.user_agent, b"/Satoshi:31.1.0/");
        assert_eq!(ran.unread, 0);
        println!("four frames, one byte per read; peer is {}", done.peer);
    }

    #[test]
    fn rejects_verack_before_version() {
        // Mutant: the `(AwaitingVersion, VERACK)` arm drops the frame like
        // the arms below it, so the `version` that follows completes a
        // handshake the peer acknowledged before it saw ours.
        let ran = run(&[VERACK, VERSION]);
        let err = ran.result.unwrap_err();
        assert!(matches!(err, super::Error::VerackBeforeVersion), "{err}");
        assert_eq!(
            ran.sent.len(),
            crate::p2p::frame::HEADER_BYTES + OUR_VERSION.len(),
            "no verack from us"
        );
        println!("{err}");
    }

    /// Core's `version` frame with its payload cut to `len` bytes, framed
    /// again so the envelope passes and only the payload is wrong.
    fn version_cut_to(len: usize) -> String {
        let payload = &fixture(VERSION)[crate::p2p::frame::HEADER_BYTES..][..len];
        let mut bytes = Vec::new();
        crate::p2p::frame::write(
            &mut bytes,
            crate::chain::network::Network::Regtest,
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
        // Mutant: `run` writes the `verack` before it parses the peer's
        // `version`, so a payload we cannot read still earns one.
        let ran = run(&[&version_cut_to(80), WTXIDRELAY, VERACK]);
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
        // Mutant: the catch-all arm parses a second `version` instead of
        // dropping it, so a three-byte one fails a handshake Core completes.
        let ran = run(&[VERSION, &version_cut_to(3), VERACK]);
        let done = ran.result.unwrap();
        assert_eq!(done.seen.len(), 3);
        assert_eq!(
            done.peer.user_agent, b"/Satoshi:31.1.0/",
            "the first one counts"
        );
        println!("second version, three bytes long, ignored; handshake complete");
    }

    #[test]
    fn gives_up_without_verack() {
        // Mutant: the bound counts only the frames before the `version`, or
        // is one too high, so the `verack` after the sixteenth frame still
        // completes the handshake.
        let mut frames = vec![VERSION];
        frames.resize(super::MESSAGES_BEFORE_VERACK_MAX, WTXIDRELAY);
        frames.push(VERACK);
        let ran = run(&frames);
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
        // Mutant: `run` takes the end of the stream for the end of the
        // handshake and returns what it has, or calls it a timeout.
        let mut script = sends(&[VERSION]);
        script.push(crate::p2p::scripted::Step::HangUp);
        let ran = run_with(script, None, None);
        let super::Error::Message(crate::p2p::frame::Error::Io(io)) = ran.result.unwrap_err()
        else {
            panic!("expected io");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
        println!("peer sent version then closed: {io}");
    }

    #[test]
    fn a_deadline_before_verack_is_an_error_not_a_wait() {
        // Mutant: `run` matches `TimedOut` on `read_frame` and reads again.
        let mut script = sends(&[VERSION]);
        script.push(crate::p2p::scripted::Step::Silence);
        let ran = run_with(script, None, Some(std::time::Duration::from_secs(10)));
        let super::Error::Message(crate::p2p::frame::Error::Io(io)) = ran.result.unwrap_err()
        else {
            panic!("expected io");
        };
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(
            ran.sent.len(),
            2 * crate::p2p::frame::HEADER_BYTES + OUR_VERSION.len(),
            "version answered with verack before the peer went quiet"
        );
        println!("peer sent version then nothing: {io}");
    }
}
