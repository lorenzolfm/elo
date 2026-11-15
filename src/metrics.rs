use std::fmt::Write;

const PATH: &str = "/metrics";

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const BODY_LENGTH_MAX: usize = 2 * 1024;

const SCRAPE_TIMEOUT_DEFAULT: std::time::Duration = std::time::Duration::from_secs(10);

const _: () =
    assert!(crate::http::EXCHANGE_TIMEOUT.as_millis() < SCRAPE_TIMEOUT_DEFAULT.as_millis());

#[derive(Debug)]
pub struct Metrics {
    tip: std::cell::Cell<crate::chain::Tip>,
    peer: std::cell::Cell<PeerState>,
    reconnects: std::cell::Cell<u64>,
    accept_failures: std::cell::Cell<u64>,
    io_failures: std::cell::Cell<u64>,
    timeout_failures: std::cell::Cell<u64>,
    evicted_failures: std::cell::Cell<u64>,
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
            accept_failures: std::cell::Cell::new(0),
            io_failures: std::cell::Cell::new(0),
            timeout_failures: std::cell::Cell::new(0),
            evicted_failures: std::cell::Cell::new(0),
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

    pub fn listen(
        address: std::net::SocketAddr,
    ) -> Result<tokio::net::TcpListener, std::io::Error> {
        crate::http::listen(address)
    }

    pub async fn serve(&self, listener: tokio::net::TcpListener) -> std::convert::Infallible {
        crate::http::serve(
            listener,
            |request| self.answer(request),
            |failure| self.failed(failure),
        )
        .await
    }

    fn failed(&self, failure: crate::http::Failure) {
        let failures = match failure {
            crate::http::Failure::Accept => &self.accept_failures,
            crate::http::Failure::Io => &self.io_failures,
            crate::http::Failure::Timeout => &self.timeout_failures,
            crate::http::Failure::Evicted => &self.evicted_failures,
        };
        failures.set(failures.get().saturating_add(1));
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
        let mut text = Text::new();
        text.family(
            "elo_header_tip_height",
            Kind::Gauge,
            "The height of the tip of the header chain.",
        )
        .sample(tip.height());
        text.family(
            "elo_header_tip_work",
            Kind::Gauge,
            "The work of the header chain up to its tip: the expected number of hashes.",
        )
        .sample(tip.work().decimal());
        let mut family = text.family(
            "elo_peer_state",
            Kind::Gauge,
            "The step of the connection to the peer: 1 for the step it is in, 0 for each other.",
        );
        let peer = self.peer.get();
        for state in PeerState::ALL {
            family.sample_labelled("state", state.name(), u8::from(state == peer));
        }
        text.family(
            "elo_reconnects_total",
            Kind::Counter,
            "The connections that ended, and that elo dials again after a wait.",
        )
        .sample(self.reconnects.get());
        let mut family = text.family(
            "elo_metrics_failures_total",
            Kind::Counter,
            "The connections to the metrics that failed: an accept error, a read or write error, no answer in time, or a newer connection in its place.",
        );
        for (kind, failures) in [
            ("accept", &self.accept_failures),
            ("io", &self.io_failures),
            ("timeout", &self.timeout_failures),
            ("evicted", &self.evicted_failures),
        ] {
            family.sample_labelled("kind", kind, failures.get());
        }
        text.end()
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Gauge,
    Counter,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Gauge => "gauge",
            Kind::Counter => "counter",
        }
    }
}

trait Value: std::fmt::Display {
    const LENGTH_MAX: usize;
}

impl Value for u64 {
    const LENGTH_MAX: usize = 20;
}

const _: () = assert!(usize::BITS <= u64::BITS);

impl Value for usize {
    const LENGTH_MAX: usize = <u64 as Value>::LENGTH_MAX;
}

impl Value for u8 {
    const LENGTH_MAX: usize = 3;
}

impl Value for crate::pow::Decimal {
    const LENGTH_MAX: usize = crate::pow::Decimal::LENGTH_MAX;
}

struct Text {
    text: String,
    growth: usize,
}

struct Family<'a> {
    text: &'a mut Text,
    name: &'static str,
}

impl Text {
    fn new() -> Text {
        Text {
            text: String::with_capacity(BODY_LENGTH_MAX),
            growth: 0,
        }
    }

    fn family(&mut self, name: &'static str, kind: Kind, help: &'static str) -> Family<'_> {
        assert!(name.starts_with("elo_"), "{name}");
        assert!(name.bytes().all(name_byte), "{name}");
        assert_eq!(
            name.ends_with("_total"),
            matches!(kind, Kind::Counter),
            "{name}"
        );
        assert!(!help.contains(['\\', '\n']), "{name}");
        let kind = kind.name();
        let written = write!(self.text, "# HELP {name} {help}\n# TYPE {name} {kind}\n");
        assert!(written.is_ok(), "{name}");
        Family { text: self, name }
    }

    fn value<V: Value>(&mut self, value: V) {
        let start = self.text.len();
        let written = writeln!(self.text, "{value}");
        assert!(written.is_ok());
        let length = self.text.len() - start - 1;
        assert!(length <= V::LENGTH_MAX, "{length}");
        self.growth += V::LENGTH_MAX - length;
    }

    fn end(self) -> String {
        assert!(self.text.ends_with('\n'));
        let length_max = self.text.len() + self.growth;
        assert!(length_max <= BODY_LENGTH_MAX, "{length_max}");
        self.text
    }
}

impl Family<'_> {
    fn sample(&mut self, value: impl Value) {
        let name = self.name;
        let written = write!(self.text.text, "{name} ");
        assert!(written.is_ok(), "{name}");
        self.text.value(value);
    }

    fn sample_labelled(
        &mut self,
        label: &'static str,
        label_value: &'static str,
        value: impl Value,
    ) {
        let name = self.name;
        assert!(!label.is_empty(), "{name}");
        assert!(label.bytes().all(name_byte), "{name}");
        assert!(!label_value.contains(['"', '\\', '\n']), "{name}");
        let written = write!(self.text.text, "{name}{{{label}=\"{label_value}\"}} ");
        assert!(written.is_ok(), "{name}");
        self.text.value(value);
    }
}

fn name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte == b'_'
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

    const EXPECTED_FAILURES_HEAD: &str = "\
# HELP elo_metrics_failures_total The connections to the metrics that failed: an accept error, a read or write error, no answer in time, or a newer connection in its place.
# TYPE elo_metrics_failures_total counter
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

    fn failures(accept: u8, io: u8, timeout: u8, evicted: u8) -> String {
        format!(
            "elo_metrics_failures_total{{kind=\"accept\"}} {accept}\n\
             elo_metrics_failures_total{{kind=\"io\"}} {io}\n\
             elo_metrics_failures_total{{kind=\"timeout\"}} {timeout}\n\
             elo_metrics_failures_total{{kind=\"evicted\"}} {evicted}\n"
        )
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
            "{EXPECTED_START}{}{EXPECTED_END}elo_reconnects_total 0\n{EXPECTED_FAILURES_HEAD}{}",
            states(1, 0, 0, 0),
            failures(0, 0, 0, 0)
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
            assert!(text.contains(&reconnects_line), "{state:?}: {text}");
        }
    }

    #[test]
    fn text_has_each_failure_of_its_kind() {
        let metrics = metrics();
        for (failure, expected) in [
            (crate::http::Failure::Timeout, failures(0, 0, 1, 0)),
            (crate::http::Failure::Io, failures(0, 1, 1, 0)),
            (crate::http::Failure::Evicted, failures(0, 1, 1, 1)),
            (crate::http::Failure::Accept, failures(1, 1, 1, 1)),
            (crate::http::Failure::Timeout, failures(1, 1, 2, 1)),
        ] {
            metrics.failed(failure);
            let text = metrics.text();
            assert!(text.ends_with(&expected), "{failure:?}: {text}");
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
    fn longest_text_of_each_value_has_its_maximum_length() {
        use super::Value;
        assert_eq!(u64::MAX.to_string().len(), u64::LENGTH_MAX);
        assert!(usize::MAX.to_string().len() <= usize::LENGTH_MAX);
        assert_eq!(u8::MAX.to_string().len(), u8::LENGTH_MAX);
    }

    #[test]
    fn text_whose_values_can_grow_past_the_maximum_is_a_bug() {
        let text = |samples| {
            let mut text = super::Text::new();
            let mut family = text.family("elo_a", super::Kind::Gauge, "AAAAAAAAAAAAAAAAA");
            for _ in 0..samples {
                family.sample(0_u64);
            }
            text.end()
        };
        assert_eq!(text(74).len() + 74 * 19, super::BODY_LENGTH_MAX);
        let ended = std::panic::catch_unwind(|| text(75));
        assert!(ended.is_err());
    }

    #[test]
    fn label_of_other_bytes_or_a_label_value_with_a_quote_a_backslash_or_a_newline_is_a_bug() {
        for (label, label_value) in [
            ("b", "a\"b"),
            ("b", "a\\b"),
            ("b", "a\nb"),
            ("", "c"),
            ("B", "c"),
            ("b-c", "c"),
        ] {
            let sampled = std::panic::catch_unwind(|| {
                let mut text = super::Text::new();
                text.family("elo_a", super::Kind::Gauge, "A.")
                    .sample_labelled(label, label_value, 0_u8);
            });
            assert!(sampled.is_err(), "{label:?} {label_value:?}");
        }
        let mut text = super::Text::new();
        text.family("elo_a", super::Kind::Gauge, "A.")
            .sample_labelled("b", "c_d", 0_u8);
        assert_eq!(
            text.end(),
            "# HELP elo_a A.\n# TYPE elo_a gauge\nelo_a{b=\"c_d\"} 0\n"
        );
    }

    #[test]
    fn counter_name_ends_with_total_and_a_gauge_name_does_not() {
        for (name, kind) in [
            ("elo_a", super::Kind::Counter),
            ("elo_a_total", super::Kind::Gauge),
        ] {
            let written = std::panic::catch_unwind(|| {
                super::Text::new().family(name, kind, "A.").sample(0_u8);
            });
            assert!(written.is_err(), "{name} {kind:?}");
        }
        let mut text = super::Text::new();
        text.family("elo_a_total", super::Kind::Counter, "A.")
            .sample(0_u8);
        assert_eq!(
            text.end(),
            "# HELP elo_a_total A.\n# TYPE elo_a_total counter\nelo_a_total 0\n"
        );
    }
}
