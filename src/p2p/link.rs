//! The seam between the node and the outside world. Bytes from the peer and
//! the time both come through a [`Link`], so a simulator can stand in for
//! the socket and the clock at once without the code above noticing.

/// The node's whole view of the outside world: a byte stream to one peer,
/// and the clock. One trait, not two, because in a simulation a read that
/// blocks past its deadline *is* how time advances; the stream and the clock
/// cannot be faked apart.
///
/// The contract every implementation keeps: a read that reaches its deadline
/// fails with [`std::io::ErrorKind::TimedOut`] and no other kind. The peer
/// hanging up is reported as std reports it (`UnexpectedEof`, `BrokenPipe`,
/// `ConnectionReset`); that is the peer's act, not a timeout.
pub trait Link: std::io::Read + std::io::Write {
    /// Bounds every read from now until the next call, as a point in time,
    /// not a duration per read: a peer that drips one byte per read cannot
    /// stretch it. `None` lifts the bound.
    ///
    /// # Errors
    ///
    /// If the operating system refuses the bound.
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> std::io::Result<()>;

    /// Monotonic time, for deadlines.
    fn now(&self) -> std::time::Instant;

    /// Wall-clock time, for the `version` timestamp, and later for the check
    /// that a header is not more than `MAX_FUTURE_BLOCK_TIME` ahead of us
    /// (`../bitcoin/src/chain.h:29`, `validation.cpp:4156` at v31.1).
    fn wall(&self) -> std::time::SystemTime;
}

/// A TCP connection on the operating system's clock: the [`Link`] the binary
/// uses. Tests and simulations use their own.
#[derive(Debug)]
pub struct Tcp {
    stream: std::net::TcpStream,
    deadline: Option<std::time::Instant>,
}

impl Tcp {
    #[must_use]
    pub fn new(stream: std::net::TcpStream) -> Self {
        Tcp {
            stream,
            deadline: None,
        }
    }
}

impl std::io::Read for Tcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // `set_read_timeout` bounds one syscall. Setting it again before each
        // one, from what is left of the deadline, bounds the whole sequence:
        // `read_exact` loops over `read`, so a dripping peer runs into the
        // deadline all the same (issue #4). std turns a sub-microsecond
        // timeout into one microsecond rather than "no timeout".
        if let Some(deadline) = self.deadline {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
            }
            self.stream.set_read_timeout(Some(remaining))?;
        }
        // Unix reports the timeout as `WouldBlock`, Windows as `TimedOut`
        // (`library/std/src/net/tcp.rs:273`). The contract says one kind.
        self.stream.read(buf).map_err(|e| match e.kind() {
            std::io::ErrorKind::WouldBlock => std::io::Error::new(std::io::ErrorKind::TimedOut, e),
            _ => e,
        })
    }
}

impl std::io::Write for Tcp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Link for Tcp {
    fn set_read_deadline(&mut self, deadline: Option<std::time::Instant>) -> std::io::Result<()> {
        self.deadline = deadline;
        if deadline.is_none() {
            self.stream.set_read_timeout(None)?;
        }
        Ok(())
    }

    fn now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }

    fn wall(&self) -> std::time::SystemTime {
        std::time::SystemTime::now()
    }
}

#[cfg(test)]
mod tests {
    use super::Link;
    use std::io::Read;

    /// A loopback pair: our `Tcp`, and the peer's end for the test to drive.
    fn pair() -> (super::Tcp, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let ours = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (theirs, _) = listener.accept().unwrap();
        (super::Tcp::new(ours), theirs)
    }

    #[test]
    fn a_read_at_its_deadline_is_timed_out_not_would_block() {
        // Mutant: drop the `WouldBlock` mapping in `read`; Linux then says WouldBlock.
        let (mut tcp, _peer) = pair();
        let started = std::time::Instant::now();
        tcp.set_read_deadline(Some(started + std::time::Duration::from_millis(50)))
            .unwrap();
        let err = tcp.read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert!(started.elapsed() >= std::time::Duration::from_millis(50));
        println!(
            "silent peer, 50 ms deadline: {err} after {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_deadline_bounds_the_sequence_not_one_syscall() {
        // Mutant: convert the deadline to a duration once, in `set_read_deadline`;
        // the second syscall then gets a fresh 200 ms and the read ends near 300 ms.
        let (mut tcp, mut peer) = pair();
        let started = std::time::Instant::now();
        tcp.set_read_deadline(Some(started + std::time::Duration::from_millis(200)))
            .unwrap();
        let dripper = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(100));
            std::io::Write::write_all(&mut peer, b"ab").unwrap();
            peer
        });
        let err = tcp.read_exact(&mut [0u8; 4]).unwrap_err();
        let elapsed = started.elapsed();
        drop(dripper.join().unwrap());
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        assert!(
            elapsed < std::time::Duration::from_millis(280),
            "two bytes at 100 ms then silence: deadline at 200 ms, not 300 ms; took {elapsed:?}"
        );
        println!("read_exact(4) got two bytes then {err} at {elapsed:?}");
    }

    #[test]
    fn a_deadline_already_reached_fails_the_read_at_once() {
        // Mutant: pass the zero remainder to `set_read_timeout`; std rejects
        // a zero duration with InvalidInput.
        let (mut tcp, _peer) = pair();
        let past = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        tcp.set_read_deadline(Some(past)).unwrap();
        let err = tcp.read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
        println!("deadline one second ago: {err}");
    }

    #[test]
    fn none_lifts_the_bound() {
        // Mutant: `set_read_deadline(None)` keeps the old deadline; the byte
        // that arrives after it is never read.
        let (mut tcp, mut peer) = pair();
        let now = std::time::Instant::now();
        tcp.set_read_deadline(Some(now + std::time::Duration::from_millis(20)))
            .unwrap();
        tcp.set_read_deadline(None).unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            std::io::Write::write_all(&mut peer, b"x").unwrap();
            peer
        });
        let mut byte = [0u8; 1];
        tcp.read_exact(&mut byte).unwrap();
        drop(writer.join().unwrap());
        assert_eq!(&byte, b"x");
        println!("bound lifted; a byte 60 ms later is read");
    }
}
