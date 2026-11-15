use std::fmt::Write;

const PATH: &str = "/metrics";

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const BODY_LENGTH_MAX: usize = 1024;

#[derive(Debug)]
pub struct Metrics {
    tip: std::cell::Cell<crate::chain::Tip>,
    peer: std::cell::Cell<PeerState>,
    reconnects: std::cell::Cell<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Dial,
    Sync,
    Synced,
    Wait,
}

impl PeerState {
    const ALL: [PeerState; 4] = [
        PeerState::Dial,
        PeerState::Sync,
        PeerState::Synced,
        PeerState::Wait,
    ];

    fn name(self) -> &'static str {
        match self {
            PeerState::Dial => "dial",
            PeerState::Sync => "sync",
            PeerState::Synced => "synced",
            PeerState::Wait => "wait",
        }
    }
}

impl Metrics {
    pub fn new(chain: &crate::chain::Chain) -> Metrics {
        Metrics {
            tip: std::cell::Cell::new(chain.tip()),
            peer: std::cell::Cell::new(PeerState::Dial),
            reconnects: std::cell::Cell::new(0),
        }
    }

    pub fn tip(&self, tip: &crate::chain::Tip) {
        assert!(tip.work() >= self.tip.get().work());
        self.tip.set(*tip);
    }

    pub fn peer(&self, state: PeerState) {
        let before = self.peer.get();
        match state {
            PeerState::Dial => assert_eq!(before, PeerState::Wait),
            PeerState::Sync => assert_eq!(before, PeerState::Dial),
            PeerState::Synced => assert_eq!(before, PeerState::Sync),
            PeerState::Wait => {
                assert_ne!(before, PeerState::Wait);
                self.reconnects.set(self.reconnects.get().saturating_add(1));
            }
        }
        self.peer.set(state);
    }

    pub async fn serve(&self, listener: tokio::net::TcpListener) -> std::convert::Infallible {
        crate::http::serve(listener, |request| self.answer(request)).await
    }

    fn answer(&self, request: crate::http::Request<'_>) -> crate::http::Response {
        if request.target != PATH {
            return crate::http::Response::NotFound;
        }
        if request.method != "GET" {
            return crate::http::Response::MethodNotAllowed { allow: "GET" };
        }
        crate::http::Response::Ok {
            content_type: CONTENT_TYPE,
            body: self.text(),
        }
    }

    fn text(&self) -> String {
        let tip = self.tip.get();
        let mut text = Text::default();
        text.family(
            "elo_header_tip_height",
            "gauge",
            "The height of the tip of the header chain.",
        );
        text.sample("elo_header_tip_height", "", tip.height());
        text.family(
            "elo_header_tip_work",
            "gauge",
            "The work of the header chain up to its tip: the expected number of hashes.",
        );
        text.sample("elo_header_tip_work", "", tip.work().decimal());
        text.family(
            "elo_peer_state",
            "gauge",
            "The step of the connection to the peer: 1 for the step it is in, 0 for each other.",
        );
        let peer = self.peer.get();
        for state in PeerState::ALL {
            text.sample(
                "elo_peer_state",
                format_args!("state=\"{}\"", state.name()),
                u8::from(state == peer),
            );
        }
        text.family(
            "elo_reconnects_total",
            "counter",
            "The connections that ended, and that elo dials again after a wait.",
        );
        text.sample("elo_reconnects_total", "", self.reconnects.get());
        text.end()
    }
}

#[derive(Default)]
struct Text {
    text: String,
}

impl Text {
    fn family(&mut self, name: &'static str, kind: &'static str, help: &'static str) {
        assert!(name.starts_with("elo_"), "{name}");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{name}"
        );
        assert!(!help.contains(['\\', '\n']), "{name}");
        let written = write!(self.text, "# HELP {name} {help}\n# TYPE {name} {kind}\n");
        assert!(written.is_ok(), "{name}");
    }

    fn sample(
        &mut self,
        name: &'static str,
        labels: impl std::fmt::Display,
        value: impl std::fmt::Display,
    ) {
        let mut labels_text = labels.to_string();
        if !labels_text.is_empty() {
            labels_text = format!("{{{labels_text}}}");
        }
        let written = writeln!(self.text, "{name}{labels_text} {value}");
        assert!(written.is_ok(), "{name}");
    }

    fn end(self) -> String {
        assert!(self.text.ends_with('\n'));
        assert!(self.text.len() <= BODY_LENGTH_MAX, "{}", self.text.len());
        self.text
    }
}

#[cfg(test)]
mod tests {
    const EXPECTED_START: &str = "\
# HELP elo_header_tip_height The height of the tip of the header chain.
# TYPE elo_header_tip_height gauge
elo_header_tip_height 0
# HELP elo_header_tip_work The work of the header chain up to its tip: the expected number of hashes.
# TYPE elo_header_tip_work gauge
elo_header_tip_work 2
# HELP elo_peer_state The step of the connection to the peer: 1 for the step it is in, 0 for each other.
# TYPE elo_peer_state gauge
";

    const EXPECTED_END: &str = "\
# HELP elo_reconnects_total The connections that ended, and that elo dials again after a wait.
# TYPE elo_reconnects_total counter
";

    fn metrics() -> super::Metrics {
        super::Metrics::new(&crate::chain::Chain::new(
            crate::chainparams::Network::Regtest,
        ))
    }

    fn metrics_in(state: super::PeerState) -> super::Metrics {
        let metrics = metrics();
        let path: &[super::PeerState] = match state {
            super::PeerState::Dial => &[],
            super::PeerState::Sync => &[super::PeerState::Sync],
            super::PeerState::Synced => &[super::PeerState::Sync, super::PeerState::Synced],
            super::PeerState::Wait => &[super::PeerState::Wait],
        };
        for step in path {
            metrics.peer(*step);
        }
        assert_eq!(metrics.peer.get(), state);
        metrics
    }

    fn states(dial: u8, sync: u8, synced: u8, wait: u8) -> String {
        format!(
            "elo_peer_state{{state=\"dial\"}} {dial}\nelo_peer_state{{state=\"sync\"}} {sync}\n\
             elo_peer_state{{state=\"synced\"}} {synced}\nelo_peer_state{{state=\"wait\"}} {wait}\n"
        )
    }

    #[test]
    fn text_has_the_tip_of_the_chain_the_dial_and_no_reconnect_at_start() {
        let expected = format!(
            "{EXPECTED_START}{}{EXPECTED_END}elo_reconnects_total 0\n",
            states(1, 0, 0, 0)
        );
        assert_eq!(metrics().text(), expected);
    }

    #[test]
    fn text_has_the_last_tip_the_state_and_each_wait_as_a_reconnect() {
        let metrics = metrics();
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let headers = crate::fixtures::headers_on_genesis(3);
        let extended = chain.extend(
            crate::fixtures::headers_batch(&headers),
            crate::fixtures::CLOCK,
        );
        assert_eq!(extended, Ok(()));
        metrics.tip(&chain.tip());
        for (state, expected, reconnects) in [
            (super::PeerState::Wait, states(0, 0, 0, 1), 1),
            (super::PeerState::Dial, states(1, 0, 0, 0), 1),
            (super::PeerState::Sync, states(0, 1, 0, 0), 1),
            (super::PeerState::Wait, states(0, 0, 0, 1), 2),
            (super::PeerState::Dial, states(1, 0, 0, 0), 2),
            (super::PeerState::Sync, states(0, 1, 0, 0), 2),
            (super::PeerState::Synced, states(0, 0, 1, 0), 2),
            (super::PeerState::Wait, states(0, 0, 0, 1), 3),
        ] {
            metrics.peer(state);
            let text = metrics.text();
            assert!(text.contains("elo_header_tip_height 3\n"), "{text}");
            assert!(text.contains("elo_header_tip_work 8\n"), "{text}");
            assert!(text.contains(&expected), "{state:?}: {text}");
            let reconnects_line = format!("elo_reconnects_total {reconnects}\n");
            assert!(text.ends_with(&reconnects_line), "{state:?}: {text}");
        }
    }

    #[test]
    fn peer_state_moves_only_on_the_steps_of_a_connection() {
        for before in super::PeerState::ALL {
            for after in super::PeerState::ALL {
                let allowed = matches!(
                    (before, after),
                    (super::PeerState::Dial, super::PeerState::Sync)
                        | (super::PeerState::Sync, super::PeerState::Synced)
                        | (
                            super::PeerState::Dial
                                | super::PeerState::Sync
                                | super::PeerState::Synced,
                            super::PeerState::Wait
                        )
                        | (super::PeerState::Wait, super::PeerState::Dial)
                );
                let metrics = metrics_in(before);
                let moved = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    metrics.peer(after);
                }));
                assert_eq!(moved.is_ok(), allowed, "{before:?} -> {after:?}");
            }
        }
    }

    #[test]
    #[should_panic(expected = "tip.work() >= self.tip.get().work()")]
    fn tip_with_less_work_than_the_last_is_a_bug() {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        let genesis = chain.tip();
        let headers = crate::fixtures::headers_on_genesis(1);
        let extended = chain.extend(
            crate::fixtures::headers_batch(&headers),
            crate::fixtures::CLOCK,
        );
        assert_eq!(extended, Ok(()));
        let metrics = super::Metrics::new(&chain);
        metrics.tip(&chain.tip());
        metrics.tip(&genesis);
    }

    #[test]
    fn answer_is_the_text_for_a_get_of_the_path_only() {
        let metrics = metrics();
        let request = |method, target| crate::http::Request { method, target };
        for (request, expected) in [
            (
                request("GET", "/metrics"),
                crate::http::Response::Ok {
                    content_type: "text/plain; version=0.0.4; charset=utf-8",
                    body: metrics.text(),
                },
            ),
            (
                request("HEAD", "/metrics"),
                crate::http::Response::MethodNotAllowed { allow: "GET" },
            ),
            (request("GET", "/"), crate::http::Response::NotFound),
            (request("GET", "/metrics/"), crate::http::Response::NotFound),
            (
                request("GET", "/metrics?a=b"),
                crate::http::Response::NotFound,
            ),
            (request("POST", "/"), crate::http::Response::NotFound),
        ] {
            assert_eq!(metrics.answer(request), expected, "{request:?}");
        }
    }

    #[test]
    fn longest_text_is_below_the_maximum() {
        let text = metrics().text();
        let one_digit_values_length = 3;
        let longest_values_length = usize::MAX.to_string().len() + 78 + u64::MAX.to_string().len();
        let longest = text.len() - one_digit_values_length + longest_values_length;
        assert!(longest <= super::BODY_LENGTH_MAX, "{longest}");
    }
}
