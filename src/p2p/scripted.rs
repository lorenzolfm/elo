//! The peer a test writes: a script of moves, a clock the script moves,
//! and everything we sent kept for the test to read. It is a
//! [`Link`](crate::p2p::link::Link), so it reaches `peer::run`
//! with no socket, no thread and no real time: a timeout is a
//! return value, and a run is replayable (issue #21).
//!
//! The peer keeps the read side of the [`Link`](crate::p2p::link::Link)
//! contract that `link::Tcp` keeps: a read that reaches the deadline fails
//! with [`std::io::ErrorKind::TimedOut`], and a read after that one fails
//! the same way until a new deadline is set. Here the second read panics
//! instead, because against a real peer a loop that reads on after a
//! timeout spins, and that is our bug.

/// One move by the peer. A script is a list of them, used in order.
pub enum Step {
    /// These bytes, over as many reads as the reader asks for, at most
    /// `chunk` of them per read. They cost no time; a peer that takes its
    /// time to speak says [`Step::Wait`] first.
    Send(Vec<u8>),
    /// Nothing for this long, and then the script goes on. Both clocks move
    /// by it. A wait that reaches the read deadline stops there and the
    /// read fails with [`std::io::ErrorKind::TimedOut`]; the step is used
    /// up either way.
    ///
    /// This is the step that tells a deadline on the whole wait from one
    /// re-armed before each read: two waits that each fit the bound, and
    /// together do not, end the wait only under the first (issue #4).
    Wait(std::time::Duration),
    /// Nothing until the deadline. The clock moves to the deadline and the
    /// read fails with [`std::io::ErrorKind::TimedOut`]. A `Silence` with no
    /// deadline set is a test that waits forever, which is our bug, so it
    /// panics.
    Silence,
    /// The peer closed the connection: `Ok(0)`, as std reports the end of a
    /// stream. A script with no steps left does the same, so that "nothing
    /// left to say" is never an implicit timeout.
    HangUp,
}

/// A peer that does what its script says.
pub struct Peer {
    script: Vec<Step>,
    /// The read cursor: which step, and how many of its bytes are served.
    step: usize,
    served: usize,
    sent: Vec<u8>,
    /// The most bytes one read serves, or `None` for as many as asked.
    chunk: Option<usize>,
    deadline: Option<std::time::Instant>,
    /// Set by the read that reached the deadline, cleared by a new one. The
    /// next read while it is set is our bug: see the module doc.
    timed_out: bool,
    now: std::time::Instant,
    wall: std::time::SystemTime,
}

impl Peer {
    /// Everything the loop wrote to the peer, in order.
    pub fn sent(&self) -> &[u8] {
        &self.sent
    }

    /// The script bytes no read has taken yet: what the peer still had to
    /// say when the loop stopped.
    pub fn unread(&self) -> usize {
        let scripted: usize = self
            .script
            .iter()
            .skip(self.step)
            .map(|step| match step {
                Step::Send(bytes) => bytes.len(),
                Step::Wait(_) | Step::Silence | Step::HangUp => 0,
            })
            .sum();
        scripted - self.served
    }

    /// What is left of the read deadline, or `None` with none set.
    fn left_to_deadline(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(self.now))
    }

    /// Both clocks move by the same amount, so that a test can read either
    /// one.
    fn advance(&mut self, waited: std::time::Duration) {
        self.now += waited;
        self.wall += waited;
    }

    /// The error of a read that reached the deadline, and the latch that
    /// makes the next one a panic.
    fn timed_out(&mut self) -> std::io::Error {
        self.timed_out = true;
        std::io::Error::from(std::io::ErrorKind::TimedOut)
    }
}

impl std::io::Read for Peer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        assert!(
            !self.timed_out,
            "a read after the read that timed out, with the same deadline: \
             against a real peer this loop spins"
        );
        // As `link::Tcp::read` does with the remainder it would pass to
        // `set_read_timeout`: a deadline already reached fails the read
        // before the peer is asked for anything.
        if self.left_to_deadline().is_some_and(|left| left.is_zero()) {
            return Err(self.timed_out());
        }
        loop {
            match self.script.get(self.step) {
                None | Some(Step::HangUp) => return Ok(0),
                Some(Step::Send(bytes)) if self.served < bytes.len() => {
                    let left = &bytes[self.served..];
                    let take = left
                        .len()
                        .min(buf.len())
                        .min(self.chunk.unwrap_or(usize::MAX));
                    buf[..take].copy_from_slice(&left[..take]);
                    self.served += take;
                    return Ok(take);
                }
                // A step that is served out; the next read starts the next.
                Some(Step::Send(_)) => {
                    self.step += 1;
                    self.served = 0;
                }
                Some(Step::Wait(waited)) => {
                    let waited = *waited;
                    self.step += 1;
                    match self.left_to_deadline() {
                        // The wait runs into the deadline: the clocks stop
                        // there, and the step behind this one never speaks.
                        Some(left) if left <= waited => {
                            self.advance(left);
                            return Err(self.timed_out());
                        }
                        _ => self.advance(waited),
                    }
                }
                Some(Step::Silence) => {
                    let Some(left) = self.left_to_deadline() else {
                        panic!("a Silence with no deadline set waits forever");
                    };
                    self.advance(left);
                    self.step += 1;
                    return Err(self.timed_out());
                }
            }
        }
    }
}

impl std::io::Write for Peer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.sent.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl crate::p2p::link::Link for Peer {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> std::io::Result<()> {
        self.deadline = deadline;
        self.timed_out = false;
        Ok(())
    }

    fn now(&self) -> std::time::Instant {
        self.now
    }

    fn wall(&self) -> std::time::SystemTime {
        self.wall
    }
}

/// A connection on `Regtest` to a peer that reads this script, serving as
/// many bytes per read as the reader asks for. `wall` is where its wall
/// clock starts; the monotonic clock starts now, because
/// [`std::time::Instant`] has no other constructor, and only a
/// [`Step::Silence`] moves it after that.
pub fn connect(
    script: Vec<Step>,
    wall: std::time::SystemTime,
) -> crate::p2p::connection::Connection<Peer> {
    connection(script, None, wall)
}

/// The same peer, serving at most `chunk` bytes per read: the one that
/// drips a frame.
pub fn connect_in_chunks(
    script: Vec<Step>,
    chunk: usize,
    wall: std::time::SystemTime,
) -> crate::p2p::connection::Connection<Peer> {
    assert!(
        chunk > 0,
        "a chunk of zero serves no bytes: every read would be a hang-up"
    );
    connection(script, Some(chunk), wall)
}

fn connection(
    script: Vec<Step>,
    chunk: Option<usize>,
    wall: std::time::SystemTime,
) -> crate::p2p::connection::Connection<Peer> {
    crate::p2p::connection::Connection::new(
        Peer {
            script,
            step: 0,
            served: 0,
            sent: Vec::new(),
            chunk,
            deadline: None,
            timed_out: false,
            now: std::time::Instant::now(),
            wall,
        },
        crate::chain::network::Network::Regtest,
    )
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    const WALL: std::time::SystemTime = std::time::UNIX_EPOCH;

    #[test]
    fn a_chunk_bounds_one_read_not_the_step() {
        // Mutant: `chunk` bounds the whole `Send` step, so the second read
        // of a three-byte step serves nothing and reads as a hang-up.
        let mut connection =
            super::connect_in_chunks(vec![super::Step::Send(b"abc".to_vec())], 2, WALL);
        let peer = connection.link_mut();
        let mut buf = [0u8; 3];
        assert_eq!(peer.read(&mut buf).unwrap(), 2);
        assert_eq!(peer.read(&mut buf[2..]).unwrap(), 1);
        assert_eq!(&buf, b"abc");
        println!("three bytes, two per read: {:?}", std::str::from_utf8(&buf));
    }

    #[test]
    fn one_read_never_crosses_two_steps() {
        // Mutant: `read` goes on to the next step when the buffer has room;
        // a hang-up after a frame would then be invisible to `read_exact`.
        let mut connection = super::connect(
            vec![
                super::Step::Send(b"ab".to_vec()),
                super::Step::Send(b"cd".to_vec()),
            ],
            WALL,
        );
        let peer = connection.link_mut();
        let mut buf = [0u8; 4];
        assert_eq!(peer.read(&mut buf).unwrap(), 2);
        assert_eq!(peer.read(&mut buf[2..]).unwrap(), 2);
        assert_eq!(&buf, b"abcd");
        println!("two steps, two reads");
    }

    #[test]
    fn an_exhausted_script_is_a_hang_up_not_a_timeout() {
        // Mutant: `read` returns `TimedOut` when the script is out and a
        // deadline is set. That is the ambiguity the step kinds remove: a
        // peer with nothing left to say is a peer that left.
        let mut connection = super::connect(vec![super::Step::Send(b"a".to_vec())], WALL);
        connection
            .set_read_deadline(Some(connection.now() + std::time::Duration::from_secs(1)))
            .unwrap();
        let peer = connection.link_mut();
        assert_eq!(peer.read(&mut [0u8; 4]).unwrap(), 1);
        assert_eq!(peer.read(&mut [0u8; 4]).unwrap(), 0, "end of stream");
        println!("script out, deadline set: end of stream");
    }

    #[test]
    fn a_hang_up_ends_the_script() {
        // Mutant: `HangUp` moves the cursor on like a served-out `Send`, so
        // the step behind it — a silence here — still speaks.
        let mut connection = super::connect(vec![super::Step::HangUp, super::Step::Silence], WALL);
        connection
            .set_read_deadline(Some(connection.now() + std::time::Duration::from_secs(1)))
            .unwrap();
        let peer = connection.link_mut();
        assert_eq!(peer.read(&mut [0u8; 4]).unwrap(), 0);
        assert_eq!(peer.read(&mut [0u8; 4]).unwrap(), 0, "and it stays ended");
        println!("hang-up with a silence behind it: end of stream, twice");
    }

    #[test]
    fn what_the_loop_writes_is_kept_in_order() {
        // Mutant: `write` keeps the last buffer only, so a test that reads
        // `sent` sees the last frame and misses every one before it.
        let mut connection = super::connect(Vec::new(), WALL);
        let verack = crate::p2p::frame::Command::from_static("verack");
        connection.write_frame(verack, &[]).unwrap();
        connection.write_frame(verack, &[]).unwrap();
        let sent = connection.link().sent();
        assert_eq!(sent.len(), 2 * crate::p2p::frame::HEADER_BYTES);
        assert_eq!(
            &sent[..crate::p2p::frame::HEADER_BYTES],
            &sent[crate::p2p::frame::HEADER_BYTES..],
            "two veracks, byte for byte"
        );
        println!("two frames kept whole: {sent:02x?}");
    }

    #[test]
    fn a_silence_moves_both_clocks_to_the_deadline() {
        // Mutant: `Silence` moves `now` and leaves `wall` behind, or moves
        // either one past the deadline.
        let mut connection = super::connect(vec![super::Step::Silence], WALL);
        let started = connection.now();
        let wait = std::time::Duration::from_secs(120);
        connection.set_read_deadline(Some(started + wait)).unwrap();
        let err = connection.link_mut().read(&mut [0u8; 4]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert_eq!(connection.now() - started, wait);
        assert_eq!(connection.wall(), WALL + wait);
        println!("{err} after {wait:?}; wall is {:?}", connection.wall());
    }

    #[test]
    fn a_wait_under_the_deadline_lets_the_script_go_on() {
        // Mutant: `Wait` fails the read like a `Silence`, or serves the
        // step behind it without moving either clock. A peer that is slow
        // is not a peer that is gone.
        let mut connection = super::connect(
            vec![
                super::Step::Wait(std::time::Duration::from_secs(30)),
                super::Step::Send(b"abc".to_vec()),
            ],
            WALL,
        );
        let started = connection.now();
        connection
            .set_read_deadline(Some(started + std::time::Duration::from_secs(100)))
            .unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(connection.link_mut().read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"abc");
        assert_eq!(
            connection.now() - started,
            std::time::Duration::from_secs(30)
        );
        assert_eq!(connection.wall(), WALL + std::time::Duration::from_secs(30));
        println!("quiet for 30 s, then three bytes on the same read");
    }

    #[test]
    fn a_wait_past_the_deadline_stops_at_the_deadline() {
        // Mutant: the wait moves the clocks by the whole of itself, so a
        // test reads a timeout later than the bound it set; or the step
        // behind the wait speaks although the bound had passed.
        let mut connection = super::connect(
            vec![
                super::Step::Wait(std::time::Duration::from_secs(120)),
                super::Step::Send(b"abc".to_vec()),
            ],
            WALL,
        );
        let started = connection.now();
        let bound = std::time::Duration::from_secs(100);
        connection.set_read_deadline(Some(started + bound)).unwrap();
        let err = connection.link_mut().read(&mut [0u8; 3]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert_eq!(connection.now() - started, bound);
        assert_eq!(connection.wall(), WALL + bound);
        assert_eq!(connection.link().unread(), 3, "the bytes behind it");
        println!("{err} at the bound, with three bytes never said");
    }

    #[test]
    fn a_deadline_already_reached_fails_the_read_at_once() {
        // Mutant: `read` asks the script before it asks the clock, as it
        // did while only a `Silence` could fail a read. `link::Tcp` fails
        // this read; the fake that stands in for it must fail it too.
        let mut connection = super::connect(vec![super::Step::Send(b"abc".to_vec())], WALL);
        let past = connection
            .now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        connection.set_read_deadline(Some(past)).unwrap();
        let err = connection.link_mut().read(&mut [0u8; 3]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert_eq!(connection.link().unread(), 3, "nothing was served");
        println!("deadline one second ago: {err}");
    }

    #[test]
    fn a_new_deadline_lets_the_loop_read_again() {
        // Mutant: the latch is never cleared, so a loop that answers a
        // timeout with a fresh bound — which is what `peer::await_headers`
        // does per batch — panics on its next read.
        let mut connection = super::connect(
            vec![
                super::Step::Wait(std::time::Duration::from_secs(120)),
                super::Step::Send(b"abc".to_vec()),
            ],
            WALL,
        );
        connection
            .set_read_deadline(Some(connection.now() + std::time::Duration::from_secs(100)))
            .unwrap();
        assert!(connection.link_mut().read(&mut [0u8; 3]).is_err());
        connection
            .set_read_deadline(Some(connection.now() + std::time::Duration::from_secs(100)))
            .unwrap();
        let mut buf = [0u8; 3];
        assert_eq!(connection.link_mut().read(&mut buf).unwrap(), 3);
        assert_eq!(&buf, b"abc");
        println!("a new bound, and the peer speaks again");
    }

    #[test]
    #[should_panic(expected = "this loop spins")]
    fn a_read_after_the_timeout_is_our_bug() {
        // Mutant: the latch is missing, so the fake answers the read the
        // way `link::Tcp` does. Against a real peer the loop under test
        // spins on a deadline it never re-arms; here it must say so.
        let mut connection = super::connect(vec![super::Step::Silence], WALL);
        connection
            .set_read_deadline(Some(connection.now() + std::time::Duration::from_secs(1)))
            .unwrap();
        assert!(connection.link_mut().read(&mut [0u8; 4]).is_err());
        let _ = connection.link_mut().read(&mut [0u8; 4]);
    }

    #[test]
    #[should_panic(expected = "a chunk of zero")]
    fn a_chunk_of_zero_is_our_bug() {
        // Mutant: the assertion is missing, so every read serves nothing
        // and the test reads a peer that hung up before its first byte.
        let _ = super::connect_in_chunks(vec![super::Step::Send(b"abc".to_vec())], 0, WALL);
    }

    #[test]
    #[should_panic(expected = "waits forever")]
    fn a_silence_with_no_deadline_is_our_bug() {
        // Mutant: the assertion is missing, so a test that would wait
        // forever against a real peer passes as a timeout here.
        let mut connection = super::connect(vec![super::Step::Silence], WALL);
        let _ = connection.link_mut().read(&mut [0u8; 4]);
    }

    #[test]
    fn unread_counts_the_bytes_the_peer_never_got_to_say() {
        // Mutant: `unread` forgets the part of the current step already
        // served, or counts from the start of the script.
        let mut connection = super::connect(
            vec![
                super::Step::Send(b"abc".to_vec()),
                super::Step::Send(b"de".to_vec()),
            ],
            WALL,
        );
        assert_eq!(connection.link().unread(), 5);
        assert_eq!(connection.link_mut().read(&mut [0u8; 2]).unwrap(), 2);
        assert_eq!(connection.link().unread(), 3);
        println!("five scripted bytes, two read, three unread");
    }
}
