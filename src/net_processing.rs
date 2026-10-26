//! The handshake: the `version` and `verack` messages before a peer is ready.

use crate::serialize::{Decode, Encode};

/// The protocol version elo sends.
const PROTOCOL_VERSION: i32 = 70016;

/// The lowest protocol version elo accepts from a peer.
const PROTOCOL_VERSION_MIN: i32 = 70016;

// elo accepts its own `version`.
const _: () = assert!(PROTOCOL_VERSION >= PROTOCOL_VERSION_MIN);

/// Why the handshake failed. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Their `version` payload did not decode.
    Version(crate::serialize::Error),
    /// Their protocol version is below `PROTOCOL_VERSION_MIN`.
    Obsolete(i32),
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
        }
    }
}

impl std::error::Error for Error {}

/// The `version` that elo sends to `peer`. elo serves no blocks and relays nothing, so it
/// claims no services and asks for no transactions.
pub(crate) fn our_version(
    peer: std::net::SocketAddr,
    timestamp: i64,
    nonce: u64,
) -> crate::protocol::Version {
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
pub(crate) struct Handshake(State);

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
    /// Returns our `version`, to send first.
    pub(crate) fn start(ours: &crate::protocol::Version) -> (Handshake, Outbound) {
        assert!(ours.version >= PROTOCOL_VERSION_MIN);

        let mut payload = Vec::new();
        ours.encode(&mut payload);
        // The payload decodes to the same `version`, with no bytes left.
        let mut input = payload.as_slice();
        assert_eq!(
            crate::protocol::Version::decode(&mut input).as_ref(),
            Ok(ours)
        );
        assert!(input.is_empty());

        (
            Handshake(State::AwaitingVersion),
            Outbound::Version(payload),
        )
    }

    /// Before their `version`, each other message is skipped. After it, each message is
    /// skipped until their `verack`, a second `version` too.
    pub(crate) fn receive(self, message: &crate::transport::Message) -> Result<Step, Error> {
        match self.0 {
            State::AwaitingVersion => {
                if message.msg_type() == crate::protocol::VERSION {
                    let theirs = receive_version(message)?;
                    Ok(Step::Reply(
                        Handshake(State::AwaitingVerack(theirs)),
                        Outbound::Verack,
                    ))
                } else {
                    Ok(Step::Wait(Handshake(State::AwaitingVersion)))
                }
            }
            State::AwaitingVerack(theirs) => {
                assert!(theirs.version >= PROTOCOL_VERSION_MIN);

                if message.msg_type() == crate::protocol::VERACK {
                    Ok(Step::Done(theirs))
                } else {
                    Ok(Step::Wait(Handshake(State::AwaitingVerack(theirs))))
                }
            }
        }
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
        super::Handshake::start(&super::our_version(peer, 0, 0)).0
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
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        let ours = super::our_version(peer, 0, 0);
        let (handshake, outbound) = super::Handshake::start(&ours);
        let super::Outbound::Version(payload) = outbound else {
            panic!("{outbound:?}");
        };
        assert_eq!(
            crate::protocol::Version::decode(&mut payload.as_slice()),
            Ok(ours)
        );

        let handshake = wait(handshake.receive(&core_message(crate::fixtures::VERACK_FRAME)));
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
