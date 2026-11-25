use std::fmt::Write;

const VALUE_LENGTH_MAX: usize = 260;

const _: () = assert!(crate::net::DESTINATION_LENGTH_MAX <= VALUE_LENGTH_MAX);

const CUT_MARK: &str = "...";

const FIELDS_COUNT_MAX: usize = 8;

const KEY_LENGTH_MAX: usize = 16;

const ESCAPE_LENGTH_MAX: usize = 6;

const FIELD_LENGTH_MAX: usize =
    1 + KEY_LENGTH_MAX + 1 + 2 + ESCAPE_LENGTH_MAX * VALUE_LENGTH_MAX + CUT_MARK.len();

const LINE_LENGTH_MAX: usize = FIELDS_COUNT_MAX * FIELD_LENGTH_MAX;

const _: () = assert!(LINE_LENGTH_MAX <= 16 * 1024);

#[derive(Clone, Copy)]
pub enum Event<'a> {
    Version {
        peer: std::net::SocketAddr,
        version: &'a crate::protocol::Version,
    },
    Tip {
        peer: std::net::SocketAddr,
        tip: &'a crate::chain::Tip,
    },
    Block {
        peer: std::net::SocketAddr,
        position: &'a crate::chain::Position,
        transactions: usize,
    },
    Metrics {
        address: std::net::SocketAddr,
    },
    End {
        destination: &'a crate::net::Destination,
        reason: &'a dyn std::fmt::Display,
        wait: std::time::Duration,
    },
}

pub enum Last<'a> {
    Exit { reason: &'a dyn std::fmt::Display },
    Stdout { error: &'a std::io::Error },
    Stop { signal: &'a dyn std::fmt::Display },
    Panic { reason: &'a dyn std::fmt::Display },
}

fn write_line(out: &mut impl std::io::Write, line: &str) -> Result<(), std::io::Error> {
    out.write_all(line.as_bytes())?;
    out.flush()
}

impl Event<'_> {
    pub fn write(&self, out: &mut impl std::io::Write) -> Result<(), std::io::Error> {
        write_line(out, &self.line())
    }

    fn name(&self) -> &'static str {
        match self {
            Event::Version { .. } => "version",
            Event::Tip { .. } => "tip",
            Event::Block { .. } => "block",
            Event::Metrics { .. } => "metrics",
            Event::End { .. } => "end",
        }
    }

    fn level(&self) -> Level {
        match self {
            Event::Version { .. }
            | Event::Tip { .. }
            | Event::Block { .. }
            | Event::Metrics { .. } => Level::Info,
            Event::End { .. } => Level::Warn,
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
                line.field("hash", tip.hash_display());
                line.field("work", tip.work());
            }
            Event::Block {
                peer,
                position,
                transactions,
            } => {
                line.field("peer", peer);
                line.field("height", position.height());
                line.field("hash", position.hash_display());
                line.field("transactions", transactions);
            }
            Event::Metrics { address } => line.field("address", address),
            Event::End {
                destination,
                reason,
                wait,
            } => {
                line.field("destination", destination);
                line.field("reason", reason);
                line.field("wait_ms", wait.as_millis());
            }
        }
        line.end()
    }
}

impl Last<'_> {
    pub fn write(&self, stdout: &mut impl std::io::Write, stderr: &mut impl std::io::Write) {
        let line = self.line();
        let to_stdout = match self {
            Last::Exit { .. } | Last::Stop { .. } | Last::Panic { .. } => true,
            Last::Stdout { .. } => false,
        };
        if !to_stdout || write_line(stdout, &line).is_err() {
            let _ = write_line(stderr, &line);
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Last::Exit { .. } | Last::Stdout { .. } => "exit",
            Last::Stop { .. } => "stop",
            Last::Panic { .. } => "panic",
        }
    }

    fn level(&self) -> Level {
        match self {
            Last::Stop { .. } => Level::Info,
            Last::Exit { .. } | Last::Stdout { .. } | Last::Panic { .. } => Level::Error,
        }
    }

    fn line(&self) -> String {
        let mut line = Line::default();
        line.field("level", self.level().name());
        line.field("event", self.name());
        match *self {
            Last::Exit { reason } | Last::Panic { reason } => line.field("reason", reason),
            Last::Stdout { error } => line.field("reason", format_args!("stdout: {error}")),
            Last::Stop { signal } => line.field("signal", signal),
        }
        line.end()
    }
}

#[derive(Clone, Copy)]
enum Level {
    Info,
    Warn,
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
        assert!(!key.is_empty());
        assert!(key.len() <= KEY_LENGTH_MAX, "{key}");
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

        let mut capped = Capped::default();
        let written = write!(capped, "{value}");
        assert!(written.is_ok(), "{key}: the value failed to write");
        let Capped {
            text: mut value_text,
            cut,
        } = capped;
        if cut {
            value_text.push_str(CUT_MARK);
        }
        let quoted = value_text.is_empty() || value_text.chars().any(quotes);
        if !quoted {
            self.text.push_str(&value_text);
            return;
        }
        self.text.push('"');
        for character in value_text.chars() {
            match character {
                '"' => self.text.push_str("\\\""),
                '\\' => self.text.push_str("\\\\"),
                '\n' => self.text.push_str("\\n"),
                '\r' => self.text.push_str("\\r"),
                '\t' => self.text.push_str("\\t"),
                character if character.is_control() => {
                    let written = write!(self.text, "\\u{:04x}", u32::from(character));
                    assert!(written.is_ok());
                }
                character => self.text.push(character),
            }
        }
        self.text.push('"');
    }

    fn end(mut self) -> String {
        assert!(self.fields_count >= 2, "{}", self.fields_count);
        assert!(!self.text.contains('\n'), "{:?}", self.text);
        self.text.push('\n');
        assert!(self.text.len() <= LINE_LENGTH_MAX, "{}", self.text.len());
        self.text
    }
}

fn quotes(character: char) -> bool {
    match character {
        ' ' | '=' | '"' => true,
        character => character.is_control(),
    }
}

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
        for character in text.chars() {
            if self.text.len() + character.len_utf8() <= VALUE_LENGTH_MAX {
                self.text.push(character);
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

    fn last_line(event: super::Last<'_>) -> String {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        event.write(&mut stdout, &mut stderr);
        assert_eq!(stderr, b"");
        String::from_utf8(stdout).unwrap()
    }

    fn value(text: &str) -> String {
        let line = last_line(super::Last::Exit { reason: &text });
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
        let chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let tip = chain.tip();
        let position = chain.position(0).unwrap();
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
                super::Event::Block {
                    peer: PEER,
                    position: &position,
                    transactions: 3,
                },
                "level=info event=block peer=127.0.0.1:18444 height=0 \
                 hash=0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206 \
                 transactions=3",
            ),
            (
                super::Event::Metrics { address: PEER },
                "level=info event=metrics address=127.0.0.1:18444",
            ),
            (
                super::Event::End {
                    destination: &crate::net::Destination::Address(
                        crate::net::PeerAddress::new(PEER).unwrap(),
                    ),
                    reason: &"the peer closed the connection",
                    wait: std::time::Duration::from_secs(5),
                },
                "level=warn event=end destination=127.0.0.1:18444 \
                 reason=\"the peer closed the connection\" wait_ms=5000",
            ),
        ] {
            assert_eq!(line(event), format!("{expected}\n"));
        }
        for (event, expected) in [
            (
                super::Last::Exit {
                    reason: &"runtime: out of memory",
                },
                "level=error event=exit reason=\"runtime: out of memory\"",
            ),
            (
                super::Last::Stop { signal: &"SIGTERM" },
                "level=info event=stop signal=SIGTERM",
            ),
            (
                super::Last::Panic {
                    reason: &"panicked at src/main.rs:1:1:\nboom",
                },
                r#"level=error event=panic reason="panicked at src/main.rs:1:1:\nboom""#,
            ),
        ] {
            assert_eq!(last_line(event), format!("{expected}\n"));
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

        let first = "a".repeat(super::VALUE_LENGTH_MAX - 1);
        assert_eq!(value(&format!("{first}é")), format!("{first}..."));

        let parts = last_line(super::Last::Exit {
            reason: &format_args!("{first}{}{}", 'é', 'b'),
        });
        assert_eq!(parts, format!("level=error event=exit reason={first}...\n"));
    }

    #[test]
    fn the_longest_line_is_the_maximum() {
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

    struct Full;

    impl std::io::Write for Full {
        fn write(&mut self, _: &[u8]) -> Result<usize, std::io::Error> {
            Err(std::io::Error::other("full"))
        }
        fn flush(&mut self) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    #[test]
    fn a_failed_write_is_an_error() {
        let event = super::Event::Metrics { address: PEER };
        assert!(event.write(&mut Full).is_err());
    }

    #[test]
    fn a_last_line_goes_to_stderr_when_stdout_fails() {
        for (event, expected) in [
            (
                super::Last::Exit {
                    reason: &"runtime: out of memory",
                },
                "level=error event=exit reason=\"runtime: out of memory\"\n",
            ),
            (
                super::Last::Stop { signal: &"SIGTERM" },
                "level=info event=stop signal=SIGTERM\n",
            ),
            (
                super::Last::Panic { reason: &"boom" },
                "level=error event=panic reason=boom\n",
            ),
        ] {
            let mut stderr = Vec::new();
            event.write(&mut Full, &mut stderr);
            assert_eq!(String::from_utf8(stderr).unwrap(), expected);
        }
    }

    #[test]
    fn a_stdout_fault_goes_to_stderr_only() {
        let error = std::io::Error::from_raw_os_error(32);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        super::Last::Stdout { error: &error }.write(&mut stdout, &mut stderr);
        assert_eq!(stdout, b"");
        assert_eq!(
            String::from_utf8(stderr).unwrap(),
            "level=error event=exit reason=\"stdout: Broken pipe (os error 32)\"\n"
        );
    }
}
