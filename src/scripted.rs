//! The peer a test writes: a script of moves, a clock only silence moves,
//! and everything we sent kept for the test to read. It is a
//! [`Link`](crate::link::Link), so it reaches `handshake::run` and
//! `sync::run` with no socket, no thread and no real time: a timeout is a
//! return value, and a run is replayable (issue #21).

/// One move by the peer. A script is a list of them, used in order.
pub enum Step {
    /// These bytes, over as many reads as the reader asks for, at most
    /// `chunk` of them per read.
    Send(Vec<u8>),
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
                Step::Silence | Step::HangUp => 0,
            })
            .sum();
        scripted - self.served
    }
}

impl std::io::Read for Peer {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
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
                Some(Step::Silence) => {
                    let Some(deadline) = self.deadline else {
                        panic!("a Silence with no deadline set waits forever");
                    };
                    // Both clocks move by the same amount, so that a test
                    // can read either one. A deadline already passed moves
                    // neither.
                    let waited = deadline.saturating_duration_since(self.now);
                    self.now += waited;
                    self.wall += waited;
                    self.step += 1;
                    return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
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

impl crate::link::Link for Peer {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> std::io::Result<()> {
        self.deadline = deadline;
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
) -> crate::connection::Connection<Peer> {
    connection(script, None, wall)
}

/// The same peer, serving at most `chunk` bytes per read: the one that
/// drips a frame.
pub fn connect_in_chunks(
    script: Vec<Step>,
    chunk: usize,
    wall: std::time::SystemTime,
) -> crate::connection::Connection<Peer> {
    connection(script, Some(chunk), wall)
}

fn connection(
    script: Vec<Step>,
    chunk: Option<usize>,
    wall: std::time::SystemTime,
) -> crate::connection::Connection<Peer> {
    crate::connection::Connection::new(
        Peer {
            script,
            step: 0,
            served: 0,
            sent: Vec::new(),
            chunk,
            deadline: None,
            now: std::time::Instant::now(),
            wall,
        },
        crate::message::Network::Regtest,
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
        let verack = crate::message::Command::from_static("verack");
        connection.write_frame(verack, &[]).unwrap();
        connection.write_frame(verack, &[]).unwrap();
        let sent = connection.link().sent();
        assert_eq!(sent.len(), 2 * crate::message::HEADER_BYTES);
        assert_eq!(
            &sent[..crate::message::HEADER_BYTES],
            &sent[crate::message::HEADER_BYTES..],
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
