//! The handshake: the `version` and `verack` messages before a peer is ready.

use crate::serialize::{Decode, Encode};

/// The protocol version elo sends.
const PROTOCOL_VERSION: i32 = 70016;

/// The lowest protocol version elo accepts from a peer.
const PROTOCOL_VERSION_MIN: i32 = 70016;

// elo accepts its own `version`.
const _: () = assert!(PROTOCOL_VERSION >= PROTOCOL_VERSION_MIN);

/// The most messages a peer may send in a handshake, its `verack` included. A peer needs five
/// at most: `version`, `wtxidrelay`, `sendaddrv2`, `sendtxrcncl` and `verack`. The rest is room
/// for messages that later BIPs add.
const MESSAGE_COUNT_MAX: u32 = 16;

/// Why the handshake failed. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Their `version` payload did not decode.
    Version(crate::serialize::Error),
    /// Their protocol version is below `PROTOCOL_VERSION_MIN`.
    Obsolete(i32),
    /// The peer sent `MESSAGE_COUNT_MAX` messages without its `verack`.
    TooManyMessages,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Version(error) => write!(f, "version payload: {error}"),
            Error::Obsolete(version) => {
                write!(
                    f,
                    "protocol version {version} is below {PROTOCOL_VERSION_MIN}"
                )
            }
            Error::TooManyMessages => {
                write!(
                    f,
                    "the peer sent {MESSAGE_COUNT_MAX} messages without its verack"
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// The `version` that elo sends to `peer`. elo serves no blocks and relays nothing, so it
/// claims no services and asks for no transactions.
fn our_version(peer: std::net::SocketAddr, timestamp: i64, nonce: u64) -> crate::protocol::Version {
    let unspecified = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0));
    crate::protocol::Version {
        version: PROTOCOL_VERSION,
        services: crate::protocol::ServiceFlags::NONE,
        timestamp,
        addr_recv: crate::protocol::Address::new(crate::protocol::ServiceFlags::NONE, peer),
        addr_from: crate::protocol::Address::new(crate::protocol::ServiceFlags::NONE, unspecified),
        nonce,
        user_agent: crate::protocol::UserAgent::elo(),
        start_height: 0,
        relay: false,
    }
}

/// Where the handshake is. Our `version` is sent in both states.
#[derive(Debug)]
enum State {
    /// Their `version` has not come.
    AwaitingVersion,
    /// Their `version` came and our `verack` is sent. Their `verack` has not come.
    AwaitingVerack(crate::protocol::Version),
}

/// The handshake with one peer. It does no I/O: the driver gives it each message and sends
/// what it returns.
#[derive(Debug)]
pub(crate) struct Handshake {
    state: State,
    /// The messages that came, fewer than `MESSAGE_COUNT_MAX`.
    message_count: u32,
}

/// A message to send: one of the two that elo sends.
#[derive(Debug)]
pub(crate) enum Outbound {
    /// Our `version`, encoded.
    Version(Vec<u8>),
    /// A `verack`, which has no payload.
    Verack,
}

/// What the handshake does after a message.
#[derive(Debug)]
pub(crate) enum Step {
    /// Read the next message.
    Wait(Handshake),
    /// Send the message, then read the next one.
    Reply(Handshake, Outbound),
    /// The handshake is complete. It holds their `version`.
    Done(crate::protocol::Version),
}

impl Handshake {
    /// Returns our `version` to `peer`, to send first.
    pub(crate) fn start(
        peer: std::net::SocketAddr,
        timestamp: i64,
        nonce: u64,
    ) -> (Handshake, Outbound) {
        let ours = our_version(peer, timestamp, nonce);
        let mut payload = Vec::new();
        ours.encode(&mut payload);
        // The payload decodes to the same `version`, with no bytes left.
        let mut input = payload.as_slice();
        assert_eq!(crate::protocol::Version::decode(&mut input), Ok(ours));
        assert!(input.is_empty());

        (
            Handshake {
                state: State::AwaitingVersion,
                message_count: 0,
            },
            Outbound::Version(payload),
        )
    }

    /// Before their `version`, each other message is skipped. After it, each message is
    /// skipped until their `verack`, a second `version` too. Message `MESSAGE_COUNT_MAX` must
    /// be their `verack`.
    pub(crate) fn receive(self, message: &crate::transport::Message) -> Result<Step, Error> {
        assert!(self.message_count < MESSAGE_COUNT_MAX);
        let message_count = self.message_count + 1;

        match self.state {
            State::AwaitingVersion => {
                if message.msg_type() == crate::protocol::VERSION {
                    let theirs = receive_version(message)?;
                    let handshake = next(State::AwaitingVerack(theirs), message_count)?;
                    Ok(Step::Reply(handshake, Outbound::Verack))
                } else {
                    Ok(Step::Wait(next(State::AwaitingVersion, message_count)?))
                }
            }
            State::AwaitingVerack(theirs) => {
                assert!(theirs.version >= PROTOCOL_VERSION_MIN);

                if message.msg_type() == crate::protocol::VERACK {
                    Ok(Step::Done(theirs))
                } else {
                    let handshake = next(State::AwaitingVerack(theirs), message_count)?;
                    Ok(Step::Wait(handshake))
                }
            }
        }
    }
}

/// The handshake after `message_count` messages, if the peer may send one more.
fn next(state: State, message_count: u32) -> Result<Handshake, Error> {
    if message_count < MESSAGE_COUNT_MAX {
        Ok(Handshake {
            state,
            message_count,
        })
    } else {
        Err(Error::TooManyMessages)
    }
}

/// Every field up to `start_height` is required. The bytes after `relay` are ignored.
fn receive_version(message: &crate::transport::Message) -> Result<crate::protocol::Version, Error> {
    assert_eq!(message.msg_type(), crate::protocol::VERSION);

    let mut input = message.payload();
    let theirs = crate::protocol::Version::decode(&mut input).map_err(Error::Version)?;
    if theirs.version >= PROTOCOL_VERSION_MIN {
        Ok(theirs)
    } else {
        Err(Error::Obsolete(theirs.version))
    }
}

#[cfg(test)]
mod tests {
    use crate::serialize::Decode;

    /// The message in a regtest frame, as the driver reads it.
    fn message(frame: &[u8]) -> crate::transport::Message {
        let (header, payload) = frame.split_first_chunk().unwrap();
        let header =
            crate::transport::decode_header(crate::chainparams::Network::Regtest, header).unwrap();
        crate::transport::check_payload(header, payload.to_vec()).unwrap()
    }

    fn core_message(frame: &str) -> crate::transport::Message {
        message(&crate::fixtures::hex(frame))
    }

    /// A `version` with Core's payload after `change`.
    fn version_message(change: impl FnOnce(&mut Vec<u8>)) -> crate::transport::Message {
        let mut payload = crate::fixtures::version_payload();
        change(&mut payload);
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::VERSION,
            &payload,
        ))
    }

    fn start() -> super::Handshake {
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        super::Handshake::start(peer, 0, 0).0
    }

    fn wait(step: Result<super::Step, super::Error>) -> super::Handshake {
        match step {
            Ok(super::Step::Wait(handshake)) => handshake,
            other => panic!("{other:?}"),
        }
    }

    fn reply(step: Result<super::Step, super::Error>) -> (super::Handshake, super::Outbound) {
        match step {
            Ok(super::Step::Reply(handshake, outbound)) => (handshake, outbound),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn handshake_skips_until_their_version_and_then_until_their_verack() {
        let handshake = wait(start().receive(&core_message(crate::fixtures::VERACK_FRAME)));
        let (mut handshake, outbound) =
            reply(handshake.receive(&core_message(crate::fixtures::VERSION_FRAME)));
        assert!(matches!(outbound, super::Outbound::Verack), "{outbound:?}");

        // A peer may send `wtxidrelay` and `sendaddrv2` before its `verack`. A second `version` is
        // skipped without a decode, so an empty payload passes.
        for message in [
            core_message(crate::fixtures::WTXIDRELAY_FRAME),
            core_message(crate::fixtures::SENDADDRV2_FRAME),
            version_message(Vec::clear),
        ] {
            handshake = wait(handshake.receive(&message));
        }

        let theirs =
            crate::protocol::Version::decode(&mut crate::fixtures::version_payload().as_slice());
        match handshake.receive(&core_message(crate::fixtures::VERACK_FRAME)) {
            Ok(super::Step::Done(version)) => assert_eq!(Ok(version), theirs),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn peer_without_its_verack_in_message_count_max_is_too_many_messages() {
        // The peer sends `MESSAGE_COUNT_MAX` messages: their `version`, `wtxidrelay` frames
        // and a last one. A `verack` as the last completes the handshake. One more
        // `wtxidrelay` in its place is refused.
        let wtxidrelay = core_message(crate::fixtures::WTXIDRELAY_FRAME);
        let before_the_last = || {
            let (mut handshake, _) =
                reply(start().receive(&core_message(crate::fixtures::VERSION_FRAME)));
            for _ in 2..super::MESSAGE_COUNT_MAX {
                handshake = wait(handshake.receive(&wtxidrelay));
            }
            handshake
        };

        let verack = core_message(crate::fixtures::VERACK_FRAME);
        let done = before_the_last().receive(&verack);
        assert!(matches!(done, Ok(super::Step::Done(_))), "{done:?}");
        let refused = before_the_last().receive(&wtxidrelay).err();
        assert_eq!(refused, Some(super::Error::TooManyMessages));
    }

    #[test]
    fn their_version_is_at_least_protocol_version_min() {
        for (version, expected) in [
            (super::PROTOCOL_VERSION_MIN, Ok(())),
            (
                super::PROTOCOL_VERSION_MIN - 1,
                Err(super::Error::Obsolete(super::PROTOCOL_VERSION_MIN - 1)),
            ),
        ] {
            let message = version_message(|payload| {
                payload[..size_of::<i32>()].copy_from_slice(&version.to_le_bytes());
            });
            let outcome = start().receive(&message).map(|step| {
                reply(Ok(step));
            });
            assert_eq!(outcome, expected, "version {version}");
        }
    }

    #[test]
    fn their_version_needs_start_height_and_may_have_bytes_after_relay() {
        let truncated = version_message(|payload| {
            payload.truncate(payload.len() - size_of::<i32>() - size_of::<bool>());
        });
        assert_eq!(
            start().receive(&truncated).err(),
            Some(super::Error::Version(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = version_message(|payload| payload.push(0xaa));
        reply(start().receive(&longer));
    }
}
