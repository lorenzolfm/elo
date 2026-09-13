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

/// Runs the handshake over `stream`. On `Ok`, both sides have sent `version`
/// and `verack`. On `Err`, the stream is in an unknown state and the caller
/// must drop it.
pub fn run(
    stream: &mut (impl std::io::Read + std::io::Write),
    network: crate::message::Network,
    our_version: &[u8],
) -> Result<(), Error> {
    crate::message::write(stream, network, VERSION, our_version)?;
    println!("-> version ({} bytes)", our_version.len());

    let mut version_received = false;
    for _ in 0..MESSAGES_BEFORE_VERACK_MAX {
        let frame = crate::message::read(stream, network)?;
        println!("<- {} ({} bytes)", frame.command, frame.payload.len());
        match frame.command {
            VERSION if !version_received => {
                version_received = true;
                crate::message::write(stream, network, VERACK, &[])?;
                println!("-> verack");
            }
            VERACK if version_received => return Ok(()),
            VERACK => return Err(Error::VerackBeforeVersion),
            // Feature negotiation we do not speak yet, and a second `version`,
            // which Core also drops (`net_processing.cpp:3586`).
            _ => {}
        }
    }
    Err(Error::NoVerackAfter)
}
