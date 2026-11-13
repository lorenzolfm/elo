//! The log: one line for each event, in logfmt. Each line is `level=<level> event=<name>`, then
//! the fields of the event, each as `<key>=<value>`. A value that is empty, or that has a space, a
//! `=`, a `"` or a control character, is in quotes, with the escapes `\"`, `\\`, `\n`, `\r`, `\t`
//! and `\u00XX`. In a value with no quotes, a `\` is only a `\`. The line has no time, because the
//! collector of the log adds one.

use std::fmt::Write;

/// The most bytes of a value before its escapes. A longer value is cut, and ends with `...`. So
/// a peer that sends a long string cannot make a long line.
const VALUE_LENGTH_MAX: usize = 256;

/// What `...` adds to a value that is cut.
const CUT: &str = "...";

/// The most fields of a line, `level` and `event` too. A `version` line has the most.
const FIELDS_COUNT_MAX: usize = 8;

/// The most bytes of a key.
const KEY_LENGTH_MAX: usize = 16;

/// The most bytes that one escape writes for one byte of a value: `\u0001`.
const ESCAPE_LENGTH_MAX: usize = 6;

/// The most bytes of a field: a space, the key, `=`, two quotes, the escaped value and the `...`
/// of a cut. The `...` needs no escape.
const FIELD_LENGTH_MAX: usize =
    1 + KEY_LENGTH_MAX + 1 + 2 + ESCAPE_LENGTH_MAX * VALUE_LENGTH_MAX + CUT.len();

/// The most bytes of a line. The first field has no space before it, and the line has a newline
/// after it.
const LINE_LENGTH_MAX: usize = FIELDS_COUNT_MAX * FIELD_LENGTH_MAX;

// Docker cuts a line of more than 16 KiB into parts, and a collector reads each part as a line.
const _: () = assert!(LINE_LENGTH_MAX <= 16 * 1024);

/// An event that elo logs. The name of each event and the key of each field are an interface:
/// dashboards and alerts match on them, so a rename breaks them. `Event::name` and `Event::line`
/// are the one list of them. Only the fields here go into a line, so no secret, such as the salt
/// of a peer, can.
#[derive(Clone, Copy)]
pub enum Event<'a> {
    /// The handshake with `peer` is done, and it sent `version`.
    Version {
        peer: std::net::SocketAddr,
        version: &'a crate::protocol::Version,
    },
    /// The sync with `peer` ended, with our chain at `tip`.
    Tip {
        peer: std::net::SocketAddr,
        tip: &'a crate::chain::Tip,
    },
    /// The connection to `peer` ended for `reason`, and elo dials it again after `wait`.
    End {
        peer: std::net::SocketAddr,
        reason: &'a dyn std::fmt::Display,
        wait: std::time::Duration,
    },
    /// A fault of this host ends elo, with exit code 1.
    Exit { reason: &'a dyn std::fmt::Display },
    /// `signal` stops elo, with exit code 0.
    Stop { signal: &'a dyn std::fmt::Display },
}

impl Event<'_> {
    /// Writes the line of the event, with its newline, to `out` in one write, and flushes `out`.
    /// stdout is not always line buffered.
    pub fn write(&self, out: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        out.write_all(self.line().as_bytes())?;
        out.flush()
    }

    fn name(&self) -> &'static str {
        match self {
            Event::Version { .. } => "version",
            Event::Tip { .. } => "tip",
            Event::End { .. } => "end",
            Event::Exit { .. } => "exit",
            Event::Stop { .. } => "stop",
        }
    }

    fn level(&self) -> Level {
        match self {
            Event::Version { .. } | Event::Tip { .. } | Event::Stop { .. } => Level::Info,
            Event::End { .. } => Level::Warn,
            Event::Exit { .. } => Level::Error,
        }
    }

    fn line(&self) -> String {
        let mut line = Line::default();
        line.field("level", self.level().name());
        line.field("event", self.name());
        match *self {
            Event::Version { peer, version } => {
                line.field("peer", peer);
                line.field("version", version.version());
                line.field("services", format_args!("{:016x}", version.services()));
                line.field("user_agent", version.user_agent());
                line.field("start_height", version.start_height());
                line.field("relay", version.relay());
            }
            Event::Tip { peer, tip } => {
                line.field("peer", peer);
                line.field("height", tip.height());
                // In display order: the reverse of the wire order.
                let hash = tip.hash();
                line.field(
                    "hash",
                    std::fmt::from_fn(|f| {
                        hash.as_byte_array()
                            .iter()
                            .rev()
                            .try_for_each(|byte| write!(f, "{byte:02x}"))
                    }),
                );
                line.field("work", tip.work());
            }
            Event::End { peer, reason, wait } => {
                line.field("peer", peer);
                line.field("reason", reason);
                line.field("wait_ms", wait.as_millis());
            }
            Event::Exit { reason } => line.field("reason", reason),
            Event::Stop { signal } => line.field("signal", signal),
        }
        line.end()
    }
}

#[derive(Clone, Copy)]
enum Level {
    /// What elo does when all goes well.
    Info,
    /// A fault that elo gets past, such as a peer that drops.
    Warn,
    /// A fault that ends elo.
    Error,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// A line that `field` writes to, one field at a time.
#[derive(Default)]
struct Line {
    text: String,
    fields_count: usize,
}

impl Line {
    fn field(&mut self, key: &'static str, value: impl std::fmt::Display) {
        assert!(
            self.fields_count < FIELDS_COUNT_MAX,
            "{key}: too many fields"
        );
        assert!(!key.is_empty() && key.len() <= KEY_LENGTH_MAX, "{key}");
        assert!(
            key.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{key}"
        );
        if self.fields_count > 0 {
            self.text.push(' ');
        }
        self.fields_count += 1;
        self.text.push_str(key);
        self.text.push('=');

        let mut value_text = Capped::default();
        // `Capped` never fails, so only a `Display` that fails by itself can fail here. That is a
        // bug of the `Display`: `std` asks a `Display` to fail only when its writer fails.
        let written = write!(value_text, "{value}");
        assert!(written.is_ok(), "{key}: the value failed to write");
        let Capped { mut text, cut } = value_text;
        if cut {
            text.push_str(CUT);
        }
        let quoted = text.is_empty()
            || text
                .chars()
                .any(|char| char <= ' ' || char == '=' || char == '"' || char.is_control());
        if !quoted {
            self.text.push_str(&text);
            return;
        }
        self.text.push('"');
        for char in text.chars() {
            match char {
                '"' => self.text.push_str("\\\""),
                '\\' => self.text.push_str("\\\\"),
                '\n' => self.text.push_str("\\n"),
                '\r' => self.text.push_str("\\r"),
                '\t' => self.text.push_str("\\t"),
                // Each control character is below U+00A0.
                char if char.is_control() => {
                    // A write to a `String` never fails.
                    let written = write!(self.text, "\\u{:04x}", u32::from(char));
                    assert!(written.is_ok());
                }
                char => self.text.push(char),
            }
        }
        self.text.push('"');
    }

    fn end(mut self) -> String {
        // Each line has its level and its event.
        assert!(self.fields_count >= 2, "{}", self.fields_count);
        // The escapes keep each newline out of a value, so a value from a peer cannot start a
        // line of its own. The one newline is the end of the line.
        assert!(!self.text.contains('\n'), "{}", self.text);
        self.text.push('\n');
        assert!(self.text.len() <= LINE_LENGTH_MAX, "{}", self.text.len());
        self.text
    }
}

/// The text of a value, up to `VALUE_LENGTH_MAX` bytes. At the first character that does not fit,
/// `cut` is set and the rest is dropped, so the text ends on a whole character.
#[derive(Default)]
struct Capped {
    text: String,
    cut: bool,
}

impl std::fmt::Write for Capped {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        if self.cut {
            return Ok(());
        }
        for char in text.chars() {
            if self.text.len() + char.len_utf8() <= VALUE_LENGTH_MAX {
                self.text.push(char);
            } else {
                self.cut = true;
                break;
            }
        }
        assert!(self.text.len() <= VALUE_LENGTH_MAX, "{}", self.text.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    const PEER: std::net::SocketAddr =
        std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 18444);

    fn line(event: super::Event<'_>) -> String {
        let mut out = Vec::new();
        event.write(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// The value of `text` in an `exit` line.
    fn value(text: &str) -> String {
        let line = line(super::Event::Exit { reason: &text });
        let value = line
            .strip_prefix("level=error event=exit reason=")
            .and_then(|value| value.strip_suffix('\n'));
        value.unwrap().to_owned()
    }

    #[test]
    fn each_event_has_its_level_its_name_and_its_fields() {
        let mut payload: &[u8] = &crate::fixtures::version_payload();
        let version: crate::protocol::Version =
            crate::serialize::Decode::decode(&mut payload).unwrap();
        let tip = crate::chain::Chain::new(crate::chainparams::Network::Regtest).tip();
        for (event, expected) in [
            (
                super::Event::Version {
                    peer: PEER,
                    version: &version,
                },
                "level=info event=version peer=127.0.0.1:18444 version=70016 \
                 services=0000000000000c09 user_agent=/Satoshi:31.1.0/ start_height=0 relay=true",
            ),
            (
                super::Event::Tip {
                    peer: PEER,
                    tip: &tip,
                },
                "level=info event=tip peer=127.0.0.1:18444 height=0 \
                 hash=0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206 \
                 work=0000000000000000000000000000000000000000000000000000000000000002",
            ),
            (
                super::Event::End {
                    peer: PEER,
                    reason: &"the peer closed the connection",
                    wait: std::time::Duration::from_secs(5),
                },
                "level=warn event=end peer=127.0.0.1:18444 \
                 reason=\"the peer closed the connection\" wait_ms=5000",
            ),
            (
                super::Event::Exit {
                    reason: &"stdout: Broken pipe (os error 32)",
                },
                "level=error event=exit reason=\"stdout: Broken pipe (os error 32)\"",
            ),
            (
                super::Event::Stop { signal: &"SIGTERM" },
                "level=info event=stop signal=SIGTERM",
            ),
        ] {
            assert_eq!(line(event), format!("{expected}\n"));
        }
    }

    #[test]
    fn a_value_with_a_space_an_equals_sign_a_quote_or_a_control_character_is_in_quotes() {
        for (text, expected) in [
            ("", r#""""#),
            ("a", "a"),
            (r"a\b", r"a\b"),
            ("/Satoshi:31.1.0/", "/Satoshi:31.1.0/"),
            ("é", "é"),
            ("a b", r#""a b""#),
            ("a=b", r#""a=b""#),
            (r#"a"b"#, r#""a\"b""#),
            (r"a\ b", r#""a\\ b""#),
            ("\n\r\t", r#""\n\r\t""#),
            ("\u{0}", r#""\u0000""#),
            ("\u{1f}", r#""\u001f""#),
            ("\u{7f}", r#""\u007f""#),
            ("\u{9f}", r#""\u009f""#),
            ("\u{a0}", "\u{a0}"),
        ] {
            assert_eq!(value(text), expected, "{text:?}");
        }
    }

    #[test]
    fn a_long_value_is_cut_on_a_whole_character() {
        let fits = "a".repeat(super::VALUE_LENGTH_MAX);
        assert_eq!(value(&fits), fits);

        let long = "a".repeat(super::VALUE_LENGTH_MAX + 1);
        assert_eq!(value(&long), format!("{fits}..."));

        // The last `é` needs 2 bytes, and only 1 is left.
        let first = "a".repeat(super::VALUE_LENGTH_MAX - 1);
        assert_eq!(value(&format!("{first}é")), format!("{first}..."));

        // A `Display` that writes in parts: after the cut, a part that fits is dropped too, so the
        // value is only the start of the text.
        let parts = line(super::Event::Exit {
            reason: &format_args!("{first}{}{}", 'é', 'b'),
        });
        assert_eq!(
            parts,
            format!("level=error event=exit reason={first}...\n")
        );
    }

    #[test]
    fn the_longest_line_is_the_maximum() {
        // Each byte is a control character, which needs the longest escape, and the value is cut.
        let value = "\u{1}".repeat(super::VALUE_LENGTH_MAX + 1);
        let mut line = super::Line::default();
        for _ in 0..super::FIELDS_COUNT_MAX {
            line.field("abcdefghijklmnop", &value);
        }
        let line = line.end();
        let field = format!(
            "abcdefghijklmnop=\"{}...\"",
            r"\u0001".repeat(super::VALUE_LENGTH_MAX)
        );
        let fields = vec![field; super::FIELDS_COUNT_MAX];
        assert_eq!(line, format!("{}\n", fields.join(" ")));
        assert_eq!(line.len(), super::LINE_LENGTH_MAX);
    }

    #[test]
    fn a_failed_write_is_an_error() {
        struct Full;
        impl std::io::Write for Full {
            fn write(&mut self, _: &[u8]) -> Result<usize, std::io::Error> {
                Err(std::io::Error::other("full"))
            }
            fn flush(&mut self) -> Result<(), std::io::Error> {
                Ok(())
            }
        }
        let event = super::Event::Stop { signal: &"SIGTERM" };
        assert!(event.write(&mut Full).is_err());
    }
}
