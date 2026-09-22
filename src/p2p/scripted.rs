pub enum Step {
    Send(Vec<u8>),
    Wait(std::time::Duration),
    Silence,
    HangUp,
}

pub struct Peer {
    script: Vec<Step>,
    step: usize,
    served: usize,
    sent: Vec<u8>,
    chunk: Option<usize>,
    deadline: Option<std::time::Instant>,
    timed_out: bool,
    now: std::time::Instant,
    wall: std::time::SystemTime,
}

impl Peer {
    pub fn sent(&self) -> &[u8] {
        &self.sent
    }

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

    fn left_to_deadline(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(self.now))
    }

    fn advance(&mut self, waited: std::time::Duration) {
        self.now += waited;
        self.wall += waited;
    }

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
                Some(Step::Send(_)) => {
                    self.step += 1;
                    self.served = 0;
                }
                Some(Step::Wait(waited)) => {
                    let waited = *waited;
                    self.step += 1;
                    match self.left_to_deadline() {
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

pub fn connect(
    script: Vec<Step>,
    wall: std::time::SystemTime,
) -> crate::p2p::connection::Connection<Peer> {
    connection(script, None, wall)
}

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
        let _ = super::connect_in_chunks(vec![super::Step::Send(b"abc".to_vec())], 0, WALL);
    }

    #[test]
    #[should_panic(expected = "waits forever")]
    fn a_silence_with_no_deadline_is_our_bug() {
        let mut connection = super::connect(vec![super::Step::Silence], WALL);
        let _ = connection.link_mut().read(&mut [0u8; 4]);
    }

    #[test]
    fn unread_counts_the_bytes_the_peer_never_got_to_say() {
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
