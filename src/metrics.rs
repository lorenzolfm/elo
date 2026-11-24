use std::fmt::Write;

const PATH: &str = "/metrics";

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const BODY_LENGTH_MAX: usize = 8 * 1024;

const SCRAPE_TIMEOUT_DEFAULT: std::time::Duration = std::time::Duration::from_secs(10);

const _: () =
    assert!(crate::http::EXCHANGE_TIMEOUT.as_millis() < SCRAPE_TIMEOUT_DEFAULT.as_millis());

const COMMAND_OTHER: &str = "other";

const COMMAND_OTHER_INDEX: usize = crate::protocol::MESSAGE_TYPES.len();

const COMMAND_LABELS_COUNT: usize = COMMAND_OTHER_INDEX + 1;

const TIP_HEIGHT: Definition = Definition::gauge(
    "elo_header_tip_height",
    "The height of the tip of the header chain at the end of the last sync, or at the last new tip after it.",
);

const TIP_WORK: Definition = Definition::gauge(
    "elo_header_tip_work",
    "The work of the header chain up to that tip: the expected number of hashes.",
);

const CHAIN_HEIGHT: Definition = Definition::gauge(
    "elo_header_chain_height",
    "The height of the header chain after the last message from the peer, the start of the last handshake or the start of the last wait, also in a sync.",
);

const PRESYNC_HEIGHT: Definition = Definition::gauge(
    "elo_header_presync_height",
    "The height of the last header that the first download of a low-work sync checked and did not put in the chain: 0 when no such download runs.",
);

const REDOWNLOAD_HEIGHT: Definition = Definition::gauge(
    "elo_header_redownload_height",
    "The height of the last header that the second download of a low-work sync checked, or the height where the sync starts before its first header: 0 when no such download runs, and elo_header_low_work_download tells that 0 from a start at height 0.",
);

const LOW_WORK_DOWNLOAD: Definition = Definition::gauge(
    "elo_header_low_work_download",
    "The download of a low-work sync that runs: 1 for it, 0 for each other.",
);

const PEER_STATE: Definition = Definition::gauge(
    "elo_peer_state",
    "The step of the connection to the peer: 1 for the step it is in, 0 for each other.",
);

const RECONNECTS: Definition = Definition::counter(
    "elo_reconnects_total",
    "Each failed lookup, dial or handshake and each connection that ended, after which elo waits and dials again.",
);

const RECEIVED_MESSAGES: Definition = Definition::counter(
    "elo_peer_received_messages_total",
    "The messages from the peer that elo read whole and checked, by command: other for each command that elo does not know.",
);

const RECEIVED_BYTES: Definition = Definition::counter(
    "elo_peer_received_bytes_total",
    "The bytes of the messages from the peer, with their headers, by command.",
);

const SENT_MESSAGES: Definition = Definition::counter(
    "elo_peer_sent_messages_total",
    "The messages to the peer that elo wrote whole, by command.",
);

const SENT_BYTES: Definition = Definition::counter(
    "elo_peer_sent_bytes_total",
    "The bytes of the messages to the peer, with their headers, by command.",
);

const METRICS_FAILURES: Definition = Definition::counter(
    "elo_metrics_failures_total",
    "The connections to the metrics that failed: an accept error, a read or write error, no answer in time, or a newer connection in its place.",
);

#[derive(Debug)]
pub struct Metrics {
    tip: std::cell::Cell<crate::chain::Tip>,
    progress: std::cell::Cell<crate::net_processing::Progress>,
    peer: std::cell::Cell<PeerState>,
    reconnects: std::cell::Cell<u64>,
    received: Traffic,
    sent: Traffic,
    accept_failures: std::cell::Cell<u64>,
    io_failures: std::cell::Cell<u64>,
    timeout_failures: std::cell::Cell<u64>,
    evicted_failures: std::cell::Cell<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerState {
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
            progress: std::cell::Cell::new(crate::net_processing::Progress {
                tip: chain.tip(),
                low_work_download: None,
            }),
            peer: std::cell::Cell::new(PeerState::Dial),
            reconnects: std::cell::Cell::new(0),
            received: Traffic::new(),
            sent: Traffic::new(),
            accept_failures: std::cell::Cell::new(0),
            io_failures: std::cell::Cell::new(0),
            timeout_failures: std::cell::Cell::new(0),
            evicted_failures: std::cell::Cell::new(0),
        }
    }

    pub(crate) fn synced(&self) {
        let tip = self.progress.get().tip;
        assert!(tip.work() >= self.tip.get().work());
        self.tip.set(tip);
    }

    pub(crate) fn progress(&self, progress: crate::net_processing::Progress) {
        self.progress.set(progress);
    }

    pub fn peer_dial(&self) {
        assert_eq!(self.peer.get(), PeerState::Wait);
        self.peer.set(PeerState::Dial);
    }

    pub fn peer_sync(&self) {
        assert_eq!(self.peer.get(), PeerState::Dial);
        self.peer.set(PeerState::Sync);
    }

    pub fn peer_synced(&self) {
        assert_eq!(self.peer.get(), PeerState::Sync);
        self.peer.set(PeerState::Synced);
    }

    pub fn peer_wait(&self, chain: &crate::chain::Chain) {
        assert_ne!(self.peer.get(), PeerState::Wait);
        assert!(chain.tip().work() >= self.progress.get().tip.work());
        self.peer.set(PeerState::Wait);
        self.reconnects.set(self.reconnects.get().saturating_add(1));
        self.progress.set(crate::net_processing::Progress {
            tip: chain.tip(),
            low_work_download: None,
        });
    }

    pub(crate) fn received(&self, msg_type: crate::protocol::MessageType, payload_length: usize) {
        self.received.count(msg_type, payload_length);
    }

    pub(crate) fn sent(&self, msg_type: crate::protocol::MessageType, payload_length: usize) {
        self.sent.count(msg_type, payload_length);
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
        text.family(TIP_HEIGHT).sample(tip.height());
        text.family(TIP_WORK).sample(tip.work().decimal());
        let progress = self.progress.get();
        text.family(CHAIN_HEIGHT).sample(progress.tip.height());
        let (presync_height, redownload_height) = match progress.low_work_download {
            Some(crate::net_processing::LowWorkDownload::Presync(height)) => {
                (Some(height.get()), None)
            }
            Some(crate::net_processing::LowWorkDownload::Redownload(height)) => {
                (None, Some(height))
            }
            None => (None, None),
        };
        text.family(PRESYNC_HEIGHT)
            .sample(presync_height.unwrap_or(0));
        text.family(REDOWNLOAD_HEIGHT)
            .sample(redownload_height.unwrap_or(0));
        let mut family = text.family(LOW_WORK_DOWNLOAD);
        for (download, height) in [
            ("presync", presync_height),
            ("redownload", redownload_height),
        ] {
            family.sample_labelled("download", download, u8::from(height.is_some()));
        }
        let mut family = text.family(PEER_STATE);
        let peer = self.peer.get();
        for state in PeerState::ALL {
            family.sample_labelled("state", state.name(), u8::from(state == peer));
        }
        text.family(RECONNECTS).sample(self.reconnects.get());
        for (definition, counts) in [
            (RECEIVED_MESSAGES, &self.received.messages),
            (RECEIVED_BYTES, &self.received.bytes),
            (SENT_MESSAGES, &self.sent.messages),
            (SENT_BYTES, &self.sent.bytes),
        ] {
            let mut family = text.family(definition);
            for (command, count) in command_names().zip(counts) {
                family.sample_labelled("command", command, count.get());
            }
        }
        let mut family = text.family(METRICS_FAILURES);
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

#[derive(Debug)]
struct Traffic {
    messages: [std::cell::Cell<u64>; COMMAND_LABELS_COUNT],
    bytes: [std::cell::Cell<u64>; COMMAND_LABELS_COUNT],
}

impl Traffic {
    fn new() -> Traffic {
        Traffic {
            messages: [const { std::cell::Cell::new(0) }; COMMAND_LABELS_COUNT],
            bytes: [const { std::cell::Cell::new(0) }; COMMAND_LABELS_COUNT],
        }
    }

    fn count(&self, msg_type: crate::protocol::MessageType, payload_length: usize) {
        let index = crate::protocol::MESSAGE_TYPES
            .iter()
            .position(|(known, _)| *known == msg_type)
            .unwrap_or(COMMAND_OTHER_INDEX);
        let payload_length = payload_length as u64;
        assert!(
            payload_length <= u64::from(crate::transport::PAYLOAD_LENGTH_MAX),
            "{payload_length}"
        );
        let length = crate::transport::MESSAGE_HEADER_SIZE as u64 + payload_length;
        let messages = &self.messages[index];
        messages.set(messages.get().saturating_add(1));
        let bytes = &self.bytes[index];
        bytes.set(bytes.get().saturating_add(length));
    }
}

fn command_names() -> impl Iterator<Item = &'static str> {
    crate::protocol::MESSAGE_TYPES
        .iter()
        .map(|(_, name)| *name)
        .chain([COMMAND_OTHER])
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

#[derive(Clone, Copy, Debug)]
struct Definition {
    name: &'static str,
    kind: Kind,
    help: &'static str,
}

impl Definition {
    const fn gauge(name: &'static str, help: &'static str) -> Definition {
        assert!(!ends_with(name, "_total"));
        Definition::new(name, Kind::Gauge, help)
    }

    const fn counter(name: &'static str, help: &'static str) -> Definition {
        assert!(ends_with(name, "_total"));
        Definition::new(name, Kind::Counter, help)
    }

    const fn new(name: &'static str, kind: Kind, help: &'static str) -> Definition {
        assert!(starts_with(name, "elo_"));
        let name_bytes = name.as_bytes();
        let mut index = 0;
        while index < name_bytes.len() {
            assert!(name_byte(name_bytes[index]));
            index += 1;
        }
        let help_bytes = help.as_bytes();
        let mut index = 0;
        while index < help_bytes.len() {
            assert!(!matches!(help_bytes[index], b'\\' | b'\n'));
            index += 1;
        }
        Definition { name, kind, help }
    }
}

const fn starts_with(text: &str, start: &str) -> bool {
    text.len() >= start.len() && bytes_at(text.as_bytes(), 0, start.as_bytes())
}

const fn ends_with(text: &str, end: &str) -> bool {
    text.len() >= end.len() && bytes_at(text.as_bytes(), text.len() - end.len(), end.as_bytes())
}

const fn bytes_at(text: &[u8], at: usize, part: &[u8]) -> bool {
    let mut index = 0;
    while index < part.len() {
        if text[at + index] != part[index] {
            return false;
        }
        index += 1;
    }
    true
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

    fn family(&mut self, definition: Definition) -> Family<'_> {
        let Definition { name, kind, help } = definition;
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

const fn name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte == b'_'
}

#[cfg(test)]
mod tests {
    const EXPECTED_START: &str = "\
# HELP elo_header_tip_height The height of the tip of the header chain at the end of the last sync, or at the last new tip after it.
# TYPE elo_header_tip_height gauge
elo_header_tip_height 0
# HELP elo_header_tip_work The work of the header chain up to that tip: the expected number of hashes.
# TYPE elo_header_tip_work gauge
elo_header_tip_work 2
# HELP elo_header_chain_height The height of the header chain after the last message from the peer, the start of the last handshake or the start of the last wait, also in a sync.
# TYPE elo_header_chain_height gauge
elo_header_chain_height 0
# HELP elo_header_presync_height The height of the last header that the first download of a low-work sync checked and did not put in the chain: 0 when no such download runs.
# TYPE elo_header_presync_height gauge
elo_header_presync_height 0
# HELP elo_header_redownload_height The height of the last header that the second download of a low-work sync checked, or the height where the sync starts before its first header: 0 when no such download runs, and elo_header_low_work_download tells that 0 from a start at height 0.
# TYPE elo_header_redownload_height gauge
elo_header_redownload_height 0
# HELP elo_header_low_work_download The download of a low-work sync that runs: 1 for it, 0 for each other.
# TYPE elo_header_low_work_download gauge
elo_header_low_work_download{download=\"presync\"} 0
elo_header_low_work_download{download=\"redownload\"} 0
# HELP elo_peer_state The step of the connection to the peer: 1 for the step it is in, 0 for each other.
# TYPE elo_peer_state gauge
";

    const EXPECTED_END: &str = "\
# HELP elo_reconnects_total Each failed lookup, dial or handshake and each connection that ended, after which elo waits and dials again.
# TYPE elo_reconnects_total counter
";

    const EXPECTED_FAILURES_HEAD: &str = "\
# HELP elo_metrics_failures_total The connections to the metrics that failed: an accept error, a read or write error, no answer in time, or a newer connection in its place.
# TYPE elo_metrics_failures_total counter
";

    const EXPECTED_TRAFFIC_HEADS: [&str; 4] = [
        "\
# HELP elo_peer_received_messages_total The messages from the peer that elo read whole and checked, by command: other for each command that elo does not know.
# TYPE elo_peer_received_messages_total counter
",
        "\
# HELP elo_peer_received_bytes_total The bytes of the messages from the peer, with their headers, by command.
# TYPE elo_peer_received_bytes_total counter
",
        "\
# HELP elo_peer_sent_messages_total The messages to the peer that elo wrote whole, by command.
# TYPE elo_peer_sent_messages_total counter
",
        "\
# HELP elo_peer_sent_bytes_total The bytes of the messages to the peer, with their headers, by command.
# TYPE elo_peer_sent_bytes_total counter
",
    ];

    const COMMAND_NAMES: [&str; 11] = [
        "version",
        "verack",
        "ping",
        "pong",
        "getheaders",
        "headers",
        "wtxidrelay",
        "sendaddrv2",
        "sendheaders",
        "inv",
        "other",
    ];

    fn metrics() -> super::Metrics {
        super::Metrics::new(&chain_at(0))
    }

    fn chain_at(height: usize) -> crate::chain::Chain {
        let mut chain = crate::chain::Chain::new(crate::chainparams::Network::Regtest);
        if height > 0 {
            let headers = crate::fixtures::headers_on_genesis(height);
            let extended = chain.extend(
                crate::fixtures::headers_batch(&headers),
                crate::fixtures::CLOCK,
            );
            assert_eq!(extended, Ok(()));
        }
        chain
    }

    fn tip_at(height: usize) -> crate::chain::Tip {
        chain_at(height).tip()
    }

    fn move_to(metrics: &super::Metrics, state: super::PeerState) {
        match state {
            super::PeerState::Dial => metrics.peer_dial(),
            super::PeerState::Sync => metrics.peer_sync(),
            super::PeerState::Synced => metrics.peer_synced(),
            super::PeerState::Wait => {
                let chain = chain_at(metrics.progress.get().tip.height());
                metrics.peer_wait(&chain);
            }
        }
    }

    fn progress(
        height: usize,
        low_work_download: Option<crate::net_processing::LowWorkDownload>,
    ) -> crate::net_processing::Progress {
        crate::net_processing::Progress {
            tip: tip_at(height),
            low_work_download,
        }
    }

    fn presync(height: usize) -> Option<crate::net_processing::LowWorkDownload> {
        let height = std::num::NonZeroUsize::new(height).unwrap();
        Some(crate::net_processing::LowWorkDownload::Presync(height))
    }

    fn redownload(height: usize) -> Option<crate::net_processing::LowWorkDownload> {
        Some(crate::net_processing::LowWorkDownload::Redownload(height))
    }

    fn metrics_in(state: super::PeerState) -> super::Metrics {
        let metrics = metrics();
        let path: &[super::PeerState] = match state {
            super::PeerState::Dial => &[],
            super::PeerState::Sync => &[super::PeerState::Sync],
            super::PeerState::Synced => &[super::PeerState::Sync, super::PeerState::Synced],
            super::PeerState::Wait => &[super::PeerState::Wait],
        };
        for state in path {
            move_to(&metrics, *state);
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

    fn traffic(family: usize, counts: [u64; 11]) -> String {
        let name = [
            "elo_peer_received_messages_total",
            "elo_peer_received_bytes_total",
            "elo_peer_sent_messages_total",
            "elo_peer_sent_bytes_total",
        ][family];
        let mut traffic = String::from(EXPECTED_TRAFFIC_HEADS[family]);
        for (command, count) in COMMAND_NAMES.into_iter().zip(counts) {
            traffic.push_str(&format!("{name}{{command=\"{command}\"}} {count}\n"));
        }
        traffic
    }

    fn message_type(name: &str) -> crate::protocol::MessageType {
        let mut bytes = [0; crate::protocol::MESSAGE_TYPE_SIZE];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        crate::protocol::MessageType::new(bytes).unwrap()
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
            "{EXPECTED_START}{}{EXPECTED_END}elo_reconnects_total 0\n{}{}{}{}{EXPECTED_FAILURES_HEAD}{}",
            states(1, 0, 0, 0),
            traffic(0, [0; 11]),
            traffic(1, [0; 11]),
            traffic(2, [0; 11]),
            traffic(3, [0; 11]),
            failures(0, 0, 0, 0)
        );
        assert_eq!(metrics().text(), expected);
    }

    #[test]
    fn text_has_the_last_tip_the_state_and_each_wait_as_a_reconnect() {
        let metrics = metrics();
        metrics.progress(progress(3, None));
        metrics.synced();
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
            move_to(&metrics, state);
            let text = metrics.text();
            assert!(text.contains("elo_header_tip_height 3\n"), "{text}");
            assert!(text.contains("elo_header_tip_work 8\n"), "{text}");
            assert!(text.contains(&expected), "{state:?}: {text}");
            let reconnects_line = format!("elo_reconnects_total {reconnects}\n");
            assert!(text.contains(&reconnects_line), "{state:?}: {text}");
        }
    }

    #[test]
    fn text_has_the_height_of_the_chain_and_of_each_download_of_the_last_progress_apart_from_the_tip()
     {
        let metrics = metrics();
        for (
            chain_height,
            low_work_download,
            expected_presync_height,
            expected_redownload_height,
            (expected_presync, expected_redownload),
        ) in [
            (0, presync(2_000), 2_000, 0, (1, 0)),
            (0, redownload(0), 0, 0, (0, 1)),
            (983, redownload(8_000), 0, 8_000, (0, 1)),
            (12, None, 0, 0, (0, 0)),
            (5, presync(2_050), 2_050, 0, (1, 0)),
            (5, redownload(2_050), 0, 2_050, (0, 1)),
            (7, None, 0, 0, (0, 0)),
        ] {
            metrics.progress(progress(chain_height, low_work_download));
            let text = metrics.text();
            for line in [
                String::from("elo_header_tip_height 0\n"),
                format!("elo_header_chain_height {chain_height}\n"),
                format!("elo_header_presync_height {expected_presync_height}\n"),
                format!("elo_header_redownload_height {expected_redownload_height}\n"),
                format!(
                    "elo_header_low_work_download{{download=\"presync\"}} {expected_presync}\n"
                ),
                format!(
                    "elo_header_low_work_download{{download=\"redownload\"}} {expected_redownload}\n"
                ),
            ] {
                assert!(text.contains(&line), "{line}: {text}");
            }
        }
    }

    #[test]
    fn peer_wait_sets_the_height_of_each_download_to_0_and_the_chain_height_to_the_chain() {
        for low_work_download in [presync(2_000), redownload(2_000)] {
            let metrics = metrics_in(super::PeerState::Sync);
            metrics.progress(progress(7, low_work_download));
            metrics.peer_wait(&chain_at(9));
            let text = metrics.text();
            for line in [
                "elo_header_chain_height 9\n",
                "elo_header_presync_height 0\n",
                "elo_header_redownload_height 0\n",
                "elo_header_low_work_download{download=\"presync\"} 0\n",
                "elo_header_low_work_download{download=\"redownload\"} 0\n",
            ] {
                assert!(text.contains(line), "{low_work_download:?}, {line}: {text}");
            }
        }
    }

    #[test]
    fn text_has_each_message_and_its_bytes_with_the_header_by_its_command_and_other_for_an_unknown_one()
     {
        let metrics = metrics();
        let none = [0; 11];
        for (step, received, expected) in [
            (
                (crate::protocol::VERSION, 102),
                true,
                [
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    none,
                    none,
                ],
            ),
            (
                (message_type("sendcmpct"), 9),
                true,
                [
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                    [126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33],
                    none,
                    none,
                ],
            ),
            (
                (message_type("feefilter"), 8),
                true,
                [
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                    [126, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65],
                    none,
                    none,
                ],
            ),
            (
                (crate::protocol::INV, 37),
                true,
                [
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2],
                    [126, 0, 0, 0, 0, 0, 0, 0, 0, 61, 65],
                    none,
                    none,
                ],
            ),
            (
                (crate::protocol::VERSION, 0),
                false,
                [
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2],
                    [126, 0, 0, 0, 0, 0, 0, 0, 0, 61, 65],
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    [24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                ],
            ),
            (
                (crate::protocol::GETHEADERS, 1029),
                false,
                [
                    [1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2],
                    [126, 0, 0, 0, 0, 0, 0, 0, 0, 61, 65],
                    [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                    [24, 0, 0, 0, 1053, 0, 0, 0, 0, 0, 0],
                ],
            ),
            (
                (crate::protocol::VERSION, 102),
                true,
                [
                    [2, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2],
                    [252, 0, 0, 0, 0, 0, 0, 0, 0, 61, 65],
                    [1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                    [24, 0, 0, 0, 1053, 0, 0, 0, 0, 0, 0],
                ],
            ),
        ] {
            let (msg_type, payload_length) = step;
            if received {
                metrics.received(msg_type, payload_length);
            } else {
                metrics.sent(msg_type, payload_length);
            }
            let text = metrics.text();
            let expected: String = (0..4)
                .map(|family| traffic(family, expected[family]))
                .collect();
            assert!(text.contains(&expected), "{msg_type:?}: {text}");
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
                    move_to(&metrics, after);
                }));
                assert_eq!(moved.is_ok(), allowed, "{before:?} -> {after:?}");
            }
        }
    }

    #[test]
    #[should_panic(expected = "chain.tip().work() >= self.progress.get().tip.work()")]
    fn peer_wait_with_a_chain_of_less_work_than_the_last_progress_is_a_bug() {
        let metrics = metrics_in(super::PeerState::Sync);
        metrics.progress(progress(2, None));
        metrics.peer_wait(&chain_at(1));
    }

    #[test]
    #[should_panic(expected = "tip.work() >= self.tip.get().work()")]
    fn synced_tip_with_less_work_than_the_last_is_a_bug() {
        let metrics = metrics();
        metrics.progress(progress(1, None));
        metrics.synced();
        metrics.progress(progress(0, None));
        metrics.synced();
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
            let mut family = text.family(super::Definition::gauge(
                "elo_a",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ));
            for _ in 0..samples {
                family.sample(0_u64);
            }
            text.end()
        };
        assert_eq!(text(301).len() + 301 * 19, super::BODY_LENGTH_MAX);
        let ended = std::panic::catch_unwind(|| text(302));
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
                text.family(super::Definition::gauge("elo_a", "A."))
                    .sample_labelled(label, label_value, 0_u8);
            });
            assert!(sampled.is_err(), "{label:?} {label_value:?}");
        }
        let mut text = super::Text::new();
        text.family(super::Definition::gauge("elo_a", "A."))
            .sample_labelled("b", "c_d", 0_u8);
        assert_eq!(
            text.end(),
            "# HELP elo_a A.\n# TYPE elo_a gauge\nelo_a{b=\"c_d\"} 0\n"
        );
    }

    #[test]
    fn counter_name_ends_with_total_and_a_gauge_name_does_not() {
        for (name, define) in [
            ("elo_a", super::Definition::counter as fn(_, _) -> _),
            ("elo_", super::Definition::counter),
            ("elo_a_total", super::Definition::gauge),
        ] {
            let defined = std::panic::catch_unwind(|| define(name, "A."));
            assert!(defined.is_err(), "{name}");
        }
        let mut text = super::Text::new();
        text.family(super::Definition::counter("elo_a_total", "A."))
            .sample(0_u8);
        assert_eq!(
            text.end(),
            "# HELP elo_a_total A.\n# TYPE elo_a_total counter\nelo_a_total 0\n"
        );
    }

    #[test]
    fn definition_of_a_name_out_of_elo_or_of_other_bytes_or_of_a_help_with_a_backslash_or_a_newline_is_a_bug()
     {
        for (name, help) in [
            ("elo", "A."),
            ("eloa", "A."),
            ("ole_a", "A."),
            ("elo_A", "A."),
            ("elo_a-b", "A."),
            ("elo_a", "A\\."),
            ("elo_a", "A\n."),
        ] {
            let defined = std::panic::catch_unwind(|| super::Definition::gauge(name, help));
            assert!(defined.is_err(), "{name:?} {help:?}");
        }
        let defined = super::Definition::gauge("elo_a_b", "A b.");
        let mut text = super::Text::new();
        text.family(defined).sample(0_u8);
        assert_eq!(
            text.end(),
            "# HELP elo_a_b A b.\n# TYPE elo_a_b gauge\nelo_a_b 0\n"
        );
    }
}
