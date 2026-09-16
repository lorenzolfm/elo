//! One peer: the [`Link`](crate::link::Link) its bytes travel, and the
//! network whose magic frames them. Every frame in or out goes through here.

/// A connection to one peer. Holds the network so that a frame cannot be
/// read with one magic and answered with another, and so callers stop
/// passing it on every call (ROADMAP step 8).
#[derive(Debug)]
pub struct Connection<L: crate::link::Link> {
    link: L,
    network: crate::message::Network,
}

impl<L: crate::link::Link> Connection<L> {
    #[must_use]
    pub fn new(link: L, network: crate::message::Network) -> Self {
        Connection { link, network }
    }

    /// One frame from the peer.
    ///
    /// # Errors
    ///
    /// As [`crate::message::read`]. `Io` with kind `TimedOut` when the
    /// deadline from [`Self::set_read_deadline`] passes first.
    pub fn read_frame(&mut self) -> Result<crate::message::Frame, crate::message::Error> {
        crate::message::read(&mut self.link, self.network)
    }

    /// One frame to the peer.
    ///
    /// # Errors
    ///
    /// As [`crate::message::write`].
    pub fn write_frame(
        &mut self,
        command: crate::message::Command,
        payload: &[u8],
    ) -> Result<(), crate::message::Error> {
        crate::message::write(&mut self.link, self.network, command, payload)
    }

    /// See [`crate::link::Link::set_read_deadline`].
    ///
    /// # Errors
    ///
    /// If the link refuses the bound.
    pub fn set_read_deadline(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> std::io::Result<()> {
        self.link.set_read_deadline(deadline)
    }

    /// See [`crate::link::Link::now`].
    pub fn now(&self) -> std::time::Instant {
        self.link.now()
    }

    /// See [`crate::link::Link::wall`].
    pub fn wall(&self) -> std::time::SystemTime {
        self.link.wall()
    }
}

#[cfg(test)]
mod tests {
    /// A peer that says nothing and keeps what we send.
    struct Mute(Vec<u8>);

    impl std::io::Read for Mute {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Ok(0)
        }
    }

    impl std::io::Write for Mute {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::io::Write::write(&mut self.0, buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::link::Link for Mute {
        fn set_read_deadline(&mut self, _: Option<std::time::Instant>) -> std::io::Result<()> {
            Ok(())
        }

        fn now(&self) -> std::time::Instant {
            std::time::Instant::now()
        }

        fn wall(&self) -> std::time::SystemTime {
            std::time::UNIX_EPOCH
        }
    }

    #[test]
    fn frames_carry_the_connections_network() {
        // Mutant: `write_frame` passes `Network::Regtest` instead of `self.network`.
        let mut connection =
            super::Connection::new(Mute(Vec::new()), crate::message::Network::Mainnet);
        connection
            .write_frame(crate::message::Command::from_static("verack"), &[])
            .unwrap();
        assert_eq!(
            &connection.link.0[..4],
            b"\xf9\xbe\xb4\xd9",
            "mainnet magic"
        );
        println!(
            "verack framed with the connection's magic: {:02x?}",
            &connection.link.0[..4]
        );
    }
}
