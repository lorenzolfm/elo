//! The handshake: the `version` and `verack` messages before a peer is ready. Then the
//! messages after it, and our `ping`.

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

/// How long after our last `ping` the next one goes, when its `pong` came.
const PING_INTERVAL: std::time::Duration = std::time::Duration::from_mins(2);

/// How long our `ping` may wait for its `pong`.
const PING_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(20);

// The tick that returns a `ping` wakes `PING_TIMEOUT` later. So it wakes after itself.
const _: () = assert!(!PING_TIMEOUT.is_zero());

/// Why elo refuses the peer in the handshake. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// Their `version` payload did not decode.
    Version(crate::serialize::Error),
    /// Their protocol version is below `PROTOCOL_VERSION_MIN`.
    Obsolete(i32),
    /// Their `version` has our nonce, so the socket is connected to itself.
    SelfConnection,
    /// The peer sent `MESSAGE_COUNT_MAX` messages without its `verack`.
    TooManyMessages,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Version(error) => write!(f, "version payload: {error}"),
            HandshakeError::Obsolete(version) => {
                write!(
                    f,
                    "protocol version {version} is below {PROTOCOL_VERSION_MIN}"
                )
            }
            HandshakeError::SelfConnection => {
                write!(f, "connected to self: their version has our nonce")
            }
            HandshakeError::TooManyMessages => {
                write!(
                    f,
                    "the peer sent {MESSAGE_COUNT_MAX} messages without its verack"
                )
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Why elo refuses the peer after the handshake. Each one ends the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerError {
    /// Their `ping` payload did not decode.
    Ping(crate::serialize::Error),
    /// Their `pong` payload did not decode.
    Pong(crate::serialize::Error),
    /// Their `pong` came when no `ping` of ours was outstanding.
    UnsolicitedPong,
    /// Their `pong` has a nonce that is not the nonce of our outstanding `ping`.
    PongNonce,
    /// Our `ping` had no `pong` within `PING_TIMEOUT`.
    PingTimeout,
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::Ping(error) => write!(f, "ping payload: {error}"),
            PeerError::Pong(error) => write!(f, "pong payload: {error}"),
            PeerError::UnsolicitedPong => write!(f, "pong without our ping"),
            PeerError::PongNonce => write!(f, "pong nonce is not our ping's"),
            PeerError::PingTimeout => {
                write!(f, "no pong within {} s", PING_TIMEOUT.as_secs())
            }
        }
    }
}

impl std::error::Error for PeerError {}

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
    /// The nonce in our `version`.
    nonce: u64,
    /// The messages that came, fewer than `MESSAGE_COUNT_MAX`.
    message_count: u32,
}

/// A message that the handshake sends.
#[derive(Debug)]
pub(crate) enum HandshakeOutbound {
    /// Our `version`, encoded.
    Version(Vec<u8>),
    /// A `verack`, which has no payload.
    Verack,
}

/// A message that elo sends after the handshake.
#[derive(Debug)]
pub(crate) enum PeerOutbound {
    /// Our `ping` with a new nonce.
    Ping(u64),
    /// A `pong` with the nonce of their `ping`.
    Pong(u64),
}

/// What the handshake does after a message.
#[derive(Debug)]
pub(crate) enum Step {
    /// Read the next message.
    Wait(Handshake),
    /// Send the message, then read the next one.
    Reply(Handshake, HandshakeOutbound),
    /// The handshake is complete. It holds the peer for the messages after it, and their
    /// `version`.
    Done(Peer, crate::protocol::Version),
}

impl Handshake {
    /// Returns our `version` to `peer`, to send first.
    pub(crate) fn start(
        peer: std::net::SocketAddr,
        timestamp: i64,
        nonce: u64,
    ) -> (Handshake, HandshakeOutbound) {
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
                nonce,
                message_count: 0,
            },
            HandshakeOutbound::Version(payload),
        )
    }

    /// Before their `version`, each other message is skipped. After it, each message is
    /// skipped until their `verack`, a second `version` too. Message `MESSAGE_COUNT_MAX` must
    /// be their `verack`.
    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
    ) -> Result<Step, HandshakeError> {
        assert!(self.message_count < MESSAGE_COUNT_MAX);
        let message_count = self.message_count + 1;

        match self.state {
            State::AwaitingVersion => {
                if message.msg_type() == crate::protocol::VERSION {
                    let theirs = receive_version(message, self.nonce)?;
                    let handshake = next(State::AwaitingVerack(theirs), self.nonce, message_count)?;
                    Ok(Step::Reply(handshake, HandshakeOutbound::Verack))
                } else {
                    let handshake = next(State::AwaitingVersion, self.nonce, message_count)?;
                    Ok(Step::Wait(handshake))
                }
            }
            State::AwaitingVerack(theirs) => {
                assert!(theirs.version >= PROTOCOL_VERSION_MIN);
                assert_ne!(theirs.nonce, self.nonce);

                if message.msg_type() == crate::protocol::VERACK {
                    let peer = Peer {
                        ping: PingState::Unsent,
                    };
                    Ok(Step::Done(peer, theirs))
                } else {
                    let handshake = next(State::AwaitingVerack(theirs), self.nonce, message_count)?;
                    Ok(Step::Wait(handshake))
                }
            }
        }
    }
}

/// The handshake after `message_count` messages, if the peer may send one more.
fn next(state: State, nonce: u64, message_count: u32) -> Result<Handshake, HandshakeError> {
    if message_count < MESSAGE_COUNT_MAX {
        Ok(Handshake {
            state,
            nonce,
            message_count,
        })
    } else {
        Err(HandshakeError::TooManyMessages)
    }
}

/// Every field up to `start_height` is required. The bytes after `relay` are ignored. A
/// `version` with our `nonce` is our own.
fn receive_version(
    message: &crate::transport::Message,
    nonce: u64,
) -> Result<crate::protocol::Version, HandshakeError> {
    assert_eq!(message.msg_type(), crate::protocol::VERSION);

    let mut input = message.payload();
    let theirs = crate::protocol::Version::decode(&mut input).map_err(HandshakeError::Version)?;
    if theirs.version < PROTOCOL_VERSION_MIN {
        Err(HandshakeError::Obsolete(theirs.version))
    } else if theirs.nonce == nonce {
        Err(HandshakeError::SelfConnection)
    } else {
        Ok(theirs)
    }
}

/// The peer after the handshake. Only `Handshake` makes one, so no message reaches it before
/// the handshake is complete. It does no I/O and reads no clock: the driver gives it each
/// message and the time, and sends what it returns.
#[derive(Debug)]
pub(crate) struct Peer {
    ping: PingState,
}

/// Where our `ping` is. At most one is outstanding.
#[derive(Debug)]
enum PingState {
    /// No `ping` went yet. The next tick sends one.
    Unsent,
    /// Our `ping` with `nonce` went at `sent`. Its `pong` has not come.
    Outstanding {
        nonce: u64,
        sent: std::time::Instant,
    },
    /// Our last `ping` went at `sent`. Its `pong` came.
    Answered { sent: std::time::Instant },
}

impl Peer {
    /// A `ping` gets a `pong` with its nonce. A `pong` must answer our outstanding `ping`. Each
    /// other message is skipped. Each result but an error returns the peer, because an error
    /// ends the connection.
    pub(crate) fn receive(
        self,
        message: &crate::transport::Message,
    ) -> Result<(Peer, Option<PeerOutbound>), PeerError> {
        let msg_type = message.msg_type();
        if msg_type == crate::protocol::PING {
            // The bytes after the nonce are ignored.
            let mut input = message.payload();
            let nonce = u64::decode(&mut input).map_err(PeerError::Ping)?;
            Ok((self, Some(PeerOutbound::Pong(nonce))))
        } else if msg_type == crate::protocol::PONG {
            let peer = self.receive_pong(message)?;
            Ok((peer, None))
        } else {
            Ok((self, None))
        }
    }

    /// The `pong` must have the nonce of our outstanding `ping`. Then no `ping` is outstanding.
    /// The bytes after the nonce are ignored.
    fn receive_pong(self, message: &crate::transport::Message) -> Result<Peer, PeerError> {
        assert_eq!(message.msg_type(), crate::protocol::PONG);

        let mut input = message.payload();
        let theirs = u64::decode(&mut input).map_err(PeerError::Pong)?;
        match self.ping {
            PingState::Outstanding { nonce: ours, sent } => {
                if theirs == ours {
                    Ok(Peer {
                        ping: PingState::Answered { sent },
                    })
                } else {
                    Err(PeerError::PongNonce)
                }
            }
            PingState::Unsent | PingState::Answered { .. } => Err(PeerError::UnsolicitedPong),
        }
    }

    /// Returns the peer, a `ping` with `nonce` if one is due, and when to tick next. A `ping`
    /// is due at once after the handshake. Then it is due `PING_INTERVAL` after the last `ping`
    /// went, if its `pong` came. When our outstanding `ping` is `PING_TIMEOUT` old, the tick
    /// fails. Each deadline is due at its instant, not after it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "until `Connection::run` calls it")
    )]
    pub(crate) fn tick(
        self,
        now: std::time::Instant,
        nonce: u64,
    ) -> Result<(Peer, Option<PeerOutbound>, std::time::Instant), PeerError> {
        let (peer, outbound, wake) = match self.ping {
            PingState::Unsent => Peer::tick_ping(now, nonce),
            PingState::Outstanding { sent, .. } => {
                let timeout = sent + PING_TIMEOUT;
                if now < timeout {
                    (self, None, timeout)
                } else {
                    return Err(PeerError::PingTimeout);
                }
            }
            PingState::Answered { sent } => {
                let due = sent + PING_INTERVAL;
                if now < due {
                    (self, None, due)
                } else {
                    Peer::tick_ping(now, nonce)
                }
            }
        };
        // A wake at or before `now` would make the driver tick again with no wait.
        assert!(wake > now);
        Ok((peer, outbound, wake))
    }

    /// Our `ping` with `nonce` goes at `now`, and the next tick is at its timeout.
    fn tick_ping(
        now: std::time::Instant,
        nonce: u64,
    ) -> (Peer, Option<PeerOutbound>, std::time::Instant) {
        let peer = Peer {
            ping: PingState::Outstanding { nonce, sent: now },
        };
        (peer, Some(PeerOutbound::Ping(nonce)), now + PING_TIMEOUT)
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

    /// A `ping` with Core's payload after `change`.
    fn ping_message(change: impl FnOnce(&mut Vec<u8>)) -> crate::transport::Message {
        let mut payload = crate::fixtures::hex(crate::fixtures::PING_FRAME)
            .split_off(crate::transport::HEADER_SIZE);
        change(&mut payload);
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::PING,
            &payload,
        ))
    }

    /// A `pong` with `payload`.
    fn pong_message(payload: &[u8]) -> crate::transport::Message {
        message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::PONG,
            payload,
        ))
    }

    /// A `pong` with `nonce`.
    fn pong(nonce: u64) -> crate::transport::Message {
        pong_message(&nonce.to_le_bytes())
    }

    fn start() -> super::Handshake {
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        super::Handshake::start(peer, 0, 0).0
    }

    fn wait(step: Result<super::Step, super::HandshakeError>) -> super::Handshake {
        match step {
            Ok(super::Step::Wait(handshake)) => handshake,
            other => panic!("{other:?}"),
        }
    }

    fn reply(
        step: Result<super::Step, super::HandshakeError>,
    ) -> (super::Handshake, super::HandshakeOutbound) {
        match step {
            Ok(super::Step::Reply(handshake, outbound)) => (handshake, outbound),
            other => panic!("{other:?}"),
        }
    }

    /// The peer as the handshake makes it.
    fn peer() -> super::Peer {
        super::Peer {
            ping: super::PingState::Unsent,
        }
    }

    /// The peer after a tick at `now` sent our `ping` with `nonce`.
    fn pinged(now: std::time::Instant, nonce: u64) -> super::Peer {
        match peer().tick(now, nonce) {
            Ok((peer, Some(super::PeerOutbound::Ping(sent)), _)) if sent == nonce => peer,
            other => panic!("{other:?}"),
        }
    }

    /// A tick at `now` that sends nothing. Returns the peer and when to tick next.
    fn idle(peer: super::Peer, now: std::time::Instant) -> (super::Peer, std::time::Instant) {
        match peer.tick(now, 0) {
            Ok((peer, None, wake)) => (peer, wake),
            other => panic!("{other:?}"),
        }
    }

    /// A message that the peer accepts with no reply.
    fn accept(peer: super::Peer, message: &crate::transport::Message) -> super::Peer {
        match peer.receive(message) {
            Ok((peer, None)) => peer,
            other => panic!("{other:?}"),
        }
    }

    const NANOSECOND: std::time::Duration = std::time::Duration::from_nanos(1);

    #[test]
    fn handshake_skips_until_their_version_and_then_until_their_verack() {
        let handshake = wait(start().receive(&core_message(crate::fixtures::VERACK_FRAME)));
        let (mut handshake, outbound) =
            reply(handshake.receive(&core_message(crate::fixtures::VERSION_FRAME)));
        assert!(
            matches!(outbound, super::HandshakeOutbound::Verack),
            "{outbound:?}"
        );

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
            Ok(super::Step::Done(_, version)) => assert_eq!(Ok(version), theirs),
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
        assert!(matches!(done, Ok(super::Step::Done(..))), "{done:?}");
        let refused = before_the_last().receive(&wtxidrelay).err();
        assert_eq!(refused, Some(super::HandshakeError::TooManyMessages));
    }

    #[test]
    fn their_version_is_at_least_protocol_version_min() {
        for (version, expected) in [
            (super::PROTOCOL_VERSION_MIN, Ok(())),
            (
                super::PROTOCOL_VERSION_MIN - 1,
                Err(super::HandshakeError::Obsolete(
                    super::PROTOCOL_VERSION_MIN - 1,
                )),
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
    fn their_version_with_our_nonce_is_self_connection() {
        // A socket that is connected to itself reads our `version` back.
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], 18444));
        let (handshake, outbound) = super::Handshake::start(peer, 0, 0x0123_4567_89ab_cdef);
        let super::HandshakeOutbound::Version(payload) = outbound else {
            panic!("{outbound:?}");
        };
        let ours = message(&crate::transport::encode(
            crate::chainparams::Network::Regtest,
            crate::protocol::VERSION,
            &payload,
        ));
        assert_eq!(
            handshake.receive(&ours).err(),
            Some(super::HandshakeError::SelfConnection)
        );
    }

    #[test]
    fn their_version_needs_start_height_and_may_have_bytes_after_relay() {
        let truncated = version_message(|payload| {
            payload.truncate(payload.len() - size_of::<i32>() - size_of::<bool>());
        });
        assert_eq!(
            start().receive(&truncated).err(),
            Some(super::HandshakeError::Version(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = version_message(|payload| payload.push(0xaa));
        reply(start().receive(&longer));
    }

    #[test]
    fn their_ping_gets_a_pong_with_its_nonce() {
        let outbound = peer().receive(&core_message(crate::fixtures::PING_FRAME));
        assert!(
            matches!(
                outbound,
                Ok((_, Some(super::PeerOutbound::Pong(0x34e9_3229_8920_45d8))))
            ),
            "{outbound:?}"
        );
    }

    #[test]
    fn their_ping_needs_a_nonce_and_may_have_bytes_after_it() {
        let short = ping_message(|payload| payload.truncate(size_of::<u64>() - 1));
        assert_eq!(
            peer().receive(&short).err(),
            Some(super::PeerError::Ping(
                crate::serialize::Error::UnexpectedEnd
            ))
        );

        let longer = ping_message(|payload| payload.push(0xaa));
        let outbound = peer().receive(&longer);
        assert!(
            matches!(
                outbound,
                Ok((_, Some(super::PeerOutbound::Pong(0x34e9_3229_8920_45d8))))
            ),
            "{outbound:?}"
        );
    }

    #[test]
    fn their_ping_gets_a_pong_while_our_ping_is_outstanding() {
        // Their `ping` does not touch ours: it still times out at `PING_TIMEOUT`.
        let start = std::time::Instant::now();
        let outbound = pinged(start, 7).receive(&core_message(crate::fixtures::PING_FRAME));
        let Ok((peer, Some(super::PeerOutbound::Pong(0x34e9_3229_8920_45d8)))) = outbound else {
            panic!("{outbound:?}");
        };
        let ticked = peer.tick(start + super::PING_TIMEOUT, 8).err();
        assert_eq!(ticked, Some(super::PeerError::PingTimeout));
    }

    #[test]
    fn first_tick_sends_a_ping() {
        let start = std::time::Instant::now();
        let ticked = peer().tick(start, 7);
        let Ok((_, Some(super::PeerOutbound::Ping(7)), wake)) = ticked else {
            panic!("{ticked:?}");
        };
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn no_second_ping_while_one_is_outstanding() {
        // `PING_INTERVAL` after the send, a `ping` is due only if its `pong` came.
        let start = std::time::Instant::now();
        let (_, wake) = idle(pinged(start, 7), start + super::PING_INTERVAL);
        assert_eq!(wake, start + super::PING_TIMEOUT);
    }

    #[test]
    fn next_ping_is_due_ping_interval_after_the_last_ping_went() {
        // The `pong` came at once: the next `ping` waits until `PING_INTERVAL` after ours went.
        let start = std::time::Instant::now();
        let due = start + super::PING_INTERVAL;
        let peer = accept(pinged(start, 7), &pong(7));
        let (peer, wake) = idle(peer, due - NANOSECOND);
        assert_eq!(wake, due);
        let ticked = peer.tick(due, 8);
        let Ok((_, Some(super::PeerOutbound::Ping(8)), wake)) = ticked else {
            panic!("{ticked:?}");
        };
        assert_eq!(wake, due + super::PING_TIMEOUT);

        // The `pong` came after `PING_INTERVAL`: the next `ping` is due at once.
        let late = due + std::time::Duration::from_mins(1);
        let (peer, _) = idle(pinged(start, 7), late);
        let ticked = accept(peer, &pong(7)).tick(late, 8);
        assert!(
            matches!(ticked, Ok((_, Some(super::PeerOutbound::Ping(8)), _))),
            "{ticked:?}"
        );
    }

    #[test]
    fn ping_without_its_pong_for_ping_timeout_is_ping_timeout() {
        let start = std::time::Instant::now();
        let timeout = start + super::PING_TIMEOUT;
        let (peer, wake) = idle(pinged(start, 7), timeout - NANOSECOND);
        assert_eq!(wake, timeout);
        assert_eq!(
            peer.tick(timeout, 8).err(),
            Some(super::PeerError::PingTimeout)
        );
    }

    #[test]
    fn their_pong_needs_a_nonce_and_may_have_bytes_after_it() {
        let start = std::time::Instant::now();
        // The payload is checked first, also when no `ping` is outstanding.
        let short = pong_message(&7_u64.to_le_bytes()[..size_of::<u64>() - 1]);
        for peer in [peer(), pinged(start, 7)] {
            assert_eq!(
                peer.receive(&short).err(),
                Some(super::PeerError::Pong(
                    crate::serialize::Error::UnexpectedEnd
                ))
            );
        }

        let mut longer = 7_u64.to_le_bytes().to_vec();
        longer.push(0xaa);
        accept(pinged(start, 7), &pong_message(&longer));
    }

    #[test]
    fn pong_without_our_ping_is_unsolicited_pong() {
        // Before our first `ping`, and after the `pong` to our last one.
        let start = std::time::Instant::now();
        let answered = accept(pinged(start, 7), &pong(7));
        for peer in [peer(), answered] {
            assert_eq!(
                peer.receive(&pong(7)).err(),
                Some(super::PeerError::UnsolicitedPong)
            );
        }
    }

    #[test]
    fn pong_with_another_nonce_is_pong_nonce() {
        let start = std::time::Instant::now();
        assert_eq!(
            pinged(start, 7).receive(&pong(8)).err(),
            Some(super::PeerError::PongNonce)
        );
    }

    #[test]
    fn peer_skips_every_message_but_ping_and_pong() {
        // Core sends `sendcmpct` and `feefilter` after the handshake, and a block `inv` for each
        // new tip. The messages of the handshake are skipped too. A `version` is skipped without
        // a decode, so an empty payload passes.
        for message in [
            core_message(crate::fixtures::SENDCMPCT_FRAME),
            core_message(crate::fixtures::FEEFILTER_FRAME),
            core_message(crate::fixtures::BLOCK_INV_FRAME),
            version_message(Vec::clear),
            core_message(crate::fixtures::VERACK_FRAME),
            core_message(crate::fixtures::WTXIDRELAY_FRAME),
            core_message(crate::fixtures::SENDADDRV2_FRAME),
        ] {
            let outbound = peer().receive(&message);
            assert!(
                matches!(outbound, Ok((_, None))),
                "{:?}: {outbound:?}",
                message.msg_type()
            );
        }
    }
}
