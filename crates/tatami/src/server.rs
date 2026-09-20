//! Reusable SSH server composition.
//!
//! This module will assemble the shared engines with a selected transport
//! binding into a server usable as a library. CLI entry points are thin
//! wrappers over it.
//!
//! Server-side admission callbacks may refuse a requested channel
//! independently of transport resources. User authorization
//! (`authorized_keys`) remains a caller-supplied policy distinct from host
//! trust and signature validity.
//!
//! # Available today
//!
//! Only the TCP **diagnostic observer** ([`observe`], requires `std` and
//! `tcp`). It sends a server identification, records what connecting
//! clients send up to their first `KEXINIT`, and closes. It performs no key
//! exchange, has no host key, and never authenticates anyone. It is not an
//! SSH service.

#[cfg(all(feature = "std", feature = "tcp"))]
pub mod observe {
    //! TCP diagnostic observer: options, JSON Lines records and a blocking
    //! `run` that owns the listener lifecycle.
    //!
    //! # Record schema (`schema` = 1)
    //!
    //! Every line is one JSON object with `schema`, `event` and `time`
    //! (RFC 3339 UTC). Event types:
    //!
    //! | `event` | Fields |
    //! |---|---|
    //! | `listener_started` | `bound` |
    //! | `connection_observation` | see [`observation_record`] |
    //! | `overload` | `dropped_since_last`, `total_dropped` |
    //! | `listener_stopped` | `reason`, `accepted`, `observed`, `dropped_at_capacity`, `records_dropped`, `workers_abandoned`, `elapsed_ms`, `error` |
    //!
    //! Records larger than [`Options::max_record_bytes`] are re-emitted with
    //! the proposal and messages removed and `record_truncated: true`.
    //! Records that cannot be queued because the sink is slow are counted in
    //! `records_dropped` of the final summary, not silently lost.
    //!
    //! For long-running deployments redirect stdout to a file and rotate it
    //! externally (for example with `logrotate` and `copytruncate`, or by
    //! running finite `--run-for` batches). No history is kept in memory.

    use alloc::boxed::Box;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use std::io::Write;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use tatami_tcp::ident::OwnedIdentification;
    use tatami_tcp::initial::SkippedMessage;
    use tatami_tcp::io::{
        BindError, Listener, ListenerConfig, ListenerEvent, Observation, ObservationEnd,
        StopHandle, Summary,
    };
    use tatami_tcp::observer::{ObservationOutcome, ObserverConfig};
    use tatami_tcp::probe::Proposal;
    use tatami_tcp::wire::kexinit::{KexName, classify_kex_name};
    use tatami_tcp::wire::transport::disconnect_reason;

    use crate::json::Value;

    /// Schema version written in every record.
    pub const SCHEMA_VERSION: u64 = 1;

    /// Options for one observer run.
    #[derive(Clone, Debug)]
    pub struct Options {
        /// Listener policy (bind address, limits, deadlines).
        pub listener: ListenerConfig,
        /// Largest record emitted before truncation is applied.
        pub max_record_bytes: usize,
        /// Bound on raw-byte fields (`*_hex`, samples, debug text) per field.
        pub max_field_bytes: usize,
    }

    impl Default for Options {
        fn default() -> Self {
            Options {
                listener: ListenerConfig::default(),
                max_record_bytes: 256 * 1024,
                max_field_bytes: 512,
            }
        }
    }

    impl Options {
        /// Convenience: banner-only mode toggle.
        #[must_use]
        pub fn banner_only(mut self, on: bool) -> Self {
            self.listener.observer = ObserverConfig {
                banner_only: on,
                ..self.listener.observer
            };
            self
        }
    }

    /// Failure to start a run.
    #[derive(Debug)]
    pub enum RunError {
        /// Bind or configuration failure.
        Bind(BindError),
    }

    impl core::fmt::Display for RunError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                RunError::Bind(e) => write!(f, "{e}"),
            }
        }
    }

    impl std::error::Error for RunError {}

    /// A bound observer that has not started running.
    pub struct Prepared {
        listener: Listener,
        options: Options,
    }

    impl Prepared {
        /// Actual bound address.
        #[must_use]
        pub fn local_addr(&self) -> SocketAddr {
            self.listener.local_addr()
        }

        /// Handle to stop the run from another thread.
        #[must_use]
        pub fn stop_handle(&self) -> StopHandle {
            self.listener.stop_handle()
        }

        /// Runs to completion, writing JSON Lines to `out`. Each record is
        /// written and flushed as a unit from a single thread. A write
        /// error stops the run with `StopReason::SinkFailed`.
        pub fn run_jsonl(self, mut out: impl Write + Send + 'static) -> Summary {
            let encoder = Encoder {
                max_record_bytes: self.options.max_record_bytes,
                max_field_bytes: self.options.max_field_bytes,
            };
            self.listener.run(Box::new(move |event| {
                let mut line = encoder.encode(&event).to_json();
                line.push('\n');
                out.write_all(line.as_bytes())?;
                out.flush()?;
                Ok(())
            }))
        }
    }

    /// Validates options and binds the listener without accepting yet.
    pub fn prepare(options: Options) -> Result<Prepared, RunError> {
        let listener = Listener::bind(options.listener.clone()).map_err(RunError::Bind)?;
        Ok(Prepared { listener, options })
    }

    /// Encodes listener events as JSON records.
    #[derive(Clone, Copy, Debug)]
    pub struct Encoder {
        /// See [`Options::max_record_bytes`].
        pub max_record_bytes: usize,
        /// See [`Options::max_field_bytes`].
        pub max_field_bytes: usize,
    }

    impl Encoder {
        /// Encodes one event. Never fails; oversized observation records
        /// are truncated as documented.
        #[must_use]
        pub fn encode(&self, event: &ListenerEvent) -> Value {
            match event {
                ListenerEvent::Started { bound } => envelope("listener_started")
                    .field("bound", bound.to_string())
                    .build(),
                ListenerEvent::Overload {
                    dropped_since_last,
                    total_dropped,
                } => envelope("overload")
                    .field("dropped_since_last", *dropped_since_last)
                    .field("total_dropped", *total_dropped)
                    .build(),
                ListenerEvent::Stopped(s) => summary_record(s),
                ListenerEvent::Observation(o) => {
                    let full = observation_record(o, self.max_field_bytes, false);
                    if full.to_json().len() <= self.max_record_bytes {
                        full
                    } else {
                        observation_record(o, self.max_field_bytes, true)
                    }
                }
            }
        }
    }

    fn envelope(event: &str) -> crate::json::Object {
        Value::object()
            .field("schema", SCHEMA_VERSION)
            .field("event", event)
            .field("time", now_rfc3339())
    }

    /// Encodes the final summary.
    #[must_use]
    pub fn summary_record(s: &Summary) -> Value {
        envelope("listener_stopped")
            .field("bound", s.bound.to_string())
            .field("reason", s.reason.code())
            .field("accepted", s.accepted)
            .field("observed", s.observed)
            .field("dropped_at_capacity", s.dropped_at_capacity)
            .field("records_dropped", s.records_dropped)
            .field("workers_abandoned", s.workers_abandoned)
            .field("elapsed_ms", millis(s.elapsed))
            .opt("error", s.error.clone())
            .build()
    }

    /// Encodes one connection observation.
    ///
    /// Field summary: `id`, `transport`, `local_addr`, `peer_addr`,
    /// `accepted_at`, `elapsed_ms`, `bytes_read`, `bytes_written`,
    /// `server_identification`, `client_identification` (object or null),
    /// `messages` (array), `proposal` (object or null), `stage`, `outcome`,
    /// `reason`, `detail`, `diagnostics`, `key_exchange_completed` (always
    /// `false`), `peer_authenticated` (always `false`), `record_truncated`.
    #[must_use]
    pub fn observation_record(o: &Observation, max_field: usize, truncated: bool) -> Value {
        let (outcome, reason, detail, diagnostics) = end_fields(&o.end, max_field);
        let mut rec = envelope("connection_observation")
            .field("id", o.id)
            .field("transport", "tcp")
            .field("local_addr", o.local.to_string())
            .field("peer_addr", o.peer.to_string())
            .field("accepted_at", rfc3339(o.accepted_unix))
            .field("elapsed_ms", millis(o.elapsed))
            .field("bytes_read", o.bytes_read)
            .field("bytes_written", o.bytes_written)
            .field(
                "server_identification",
                Value::lossy_text(&o.server_identification),
            )
            .opt(
                "client_identification",
                o.client_identification
                    .as_ref()
                    .map(|i| identification_record(i, max_field)),
            );
        if truncated {
            rec = rec
                .field("messages", Value::Array(Vec::new()))
                .field("proposal", Value::Null);
        } else {
            rec = rec
                .field(
                    "messages",
                    Value::Array(
                        o.messages
                            .iter()
                            .map(|m| message_record(m, max_field))
                            .collect(),
                    ),
                )
                .opt("proposal", o.proposal.as_ref().map(proposal_record));
        }
        rec.field("stage", o.stage.code())
            .field("outcome", outcome)
            .opt("reason", reason)
            .field("detail", detail)
            .opt("diagnostics", diagnostics)
            .field("key_exchange_completed", false)
            .field("peer_authenticated", false)
            .field("record_truncated", truncated)
            .build()
    }

    fn identification_record(i: &OwnedIdentification, max_field: usize) -> Value {
        let (line_hex, line_trunc) = bounded_hex(&i.line, max_field);
        let mut obj = Value::object()
            .field("line", Value::lossy_text(&i.line))
            .field("line_hex", line_hex)
            .field("protocol_version", i.protocol_version.as_str())
            .field("software_version", i.software_version.as_str())
            .opt("comments", i.comments.as_deref().map(Value::lossy_text))
            .field(
                "terminator",
                match i.terminator {
                    tatami_tcp::ident::LineTerminator::CrLf => "crlf",
                    tatami_tcp::ident::LineTerminator::Lf => "lf",
                },
            )
            .field("anomalies", Value::strings(i.anomalies().map(|a| a.code())));
        if line_trunc {
            obj = obj.field("line_hex_truncated", true);
        }
        obj.build()
    }

    fn message_record(m: &SkippedMessage, max_field: usize) -> Value {
        match m {
            SkippedMessage::Ignored { data_len } => Value::object()
                .field("type", "ignore")
                .field("data_len", *data_len)
                .build(),
            SkippedMessage::Debug {
                always_display,
                message,
                language_tag,
            } => {
                let (text, text_trunc) = bounded_text(message, max_field);
                Value::object()
                    .field("type", "debug")
                    .field("always_display", *always_display)
                    .field("message", text)
                    .field("message_truncated", text_trunc)
                    .field("language_tag", bounded_text(language_tag, max_field).0)
                    .build()
            }
            SkippedMessage::Unimplemented { sequence_number } => Value::object()
                .field("type", "unimplemented")
                .field("sequence_number", *sequence_number)
                .build(),
        }
    }

    fn proposal_record(p: &Proposal) -> Value {
        let k = &p.kexinit;
        let markers: Vec<Value> = k
            .kex_algorithms
            .iter()
            .filter_map(|n| {
                let kind = match classify_kex_name(n.as_bytes()) {
                    KexName::Method => return None,
                    KexName::ExtInfoClient => "ext_info_client",
                    KexName::ExtInfoServer => "ext_info_server",
                    KexName::StrictKexClient => "strict_kex_client",
                    KexName::StrictKexServer => "strict_kex_server",
                };
                Some(
                    Value::object()
                        .field("name", n.as_str())
                        .field("kind", kind)
                        .build(),
                )
            })
            .collect();
        Value::object()
            .field("role", "client")
            .field("cookie_hex", Value::hex(&k.cookie))
            .field(
                "kex_algorithms",
                Value::strings(k.kex_algorithms.iter().cloned()),
            )
            .field("kex_markers", Value::Array(markers))
            .field(
                "server_host_key_algorithms",
                Value::strings(k.server_host_key_algorithms.iter().cloned()),
            )
            .field(
                "encryption_client_to_server",
                Value::strings(k.encryption_client_to_server.iter().cloned()),
            )
            .field(
                "encryption_server_to_client",
                Value::strings(k.encryption_server_to_client.iter().cloned()),
            )
            .field(
                "mac_client_to_server",
                Value::strings(k.mac_client_to_server.iter().cloned()),
            )
            .field(
                "mac_server_to_client",
                Value::strings(k.mac_server_to_client.iter().cloned()),
            )
            .field(
                "compression_client_to_server",
                Value::strings(k.compression_client_to_server.iter().cloned()),
            )
            .field(
                "compression_server_to_client",
                Value::strings(k.compression_server_to_client.iter().cloned()),
            )
            .field(
                "languages_client_to_server",
                Value::strings(k.languages_client_to_server.iter().cloned()),
            )
            .field(
                "languages_server_to_client",
                Value::strings(k.languages_server_to_client.iter().cloned()),
            )
            .field("first_kex_packet_follows", k.first_kex_packet_follows)
            .field("reserved", k.reserved)
            .field(
                "anomalies",
                Value::strings(p.anomalies.iter().map(|a| a.code())),
            )
            .field("payload_len", p.raw_payload.len())
            .field("unexamined_bytes", p.unexamined_bytes)
            .build()
    }

    /// Returns `(outcome, reason, detail, diagnostics)`.
    fn end_fields(
        end: &ObservationEnd,
        max_field: usize,
    ) -> (&'static str, Option<String>, String, Option<Value>) {
        match end {
            ObservationEnd::Observer(o) => match o {
                ObservationOutcome::BannerOnly => (
                    o.code(),
                    None,
                    String::from("client identification received; banner-only mode"),
                    None,
                ),
                ObservationOutcome::Proposal(p) => (
                    o.code(),
                    None,
                    if p.anomalies.is_empty() {
                        String::from("client identification and initial KEXINIT received")
                    } else {
                        String::from("KEXINIT decoded with anomalies; see proposal.anomalies")
                    },
                    None,
                ),
                ObservationOutcome::Disconnected {
                    reason_code,
                    description,
                    language_tag,
                } => {
                    let (text, trunc) = bounded_text(description, max_field);
                    (
                        o.code(),
                        Some(alloc::format!("disconnect_{reason_code}")),
                        alloc::format!(
                            "client sent SSH_MSG_DISCONNECT{}",
                            disconnect_reason::name(*reason_code)
                                .map(|n| alloc::format!(" ({n})"))
                                .unwrap_or_default()
                        ),
                        Some(
                            Value::object()
                                .field("reason_code", *reason_code)
                                .opt("reason_name", disconnect_reason::name(*reason_code))
                                .field("description", text)
                                .field("description_truncated", trunc)
                                .field("language_tag", bounded_text(language_tag, max_field).0)
                                .build(),
                        ),
                    )
                }
                ObservationOutcome::UnexpectedInput { sample, truncated } => {
                    let (hex, hex_trunc) = bounded_hex(sample, max_field);
                    (
                        o.code(),
                        Some(String::from("not_ssh_identification")),
                        String::from("first bytes did not begin an SSH identification"),
                        Some(
                            Value::object()
                                .field("sample", bounded_text(sample, max_field).0)
                                .field("sample_hex", hex)
                                .field("sample_len", sample.len())
                                .field("sample_truncated", *truncated || hex_trunc)
                                .build(),
                        ),
                    )
                }
                ObservationOutcome::Eof {
                    stage,
                    pending_bytes,
                } => (
                    o.code(),
                    Some(String::from(if *pending_bytes == 0 {
                        "eof_at_boundary"
                    } else {
                        "eof_truncated"
                    })),
                    alloc::format!("peer closed while {stage}"),
                    Some(
                        Value::object()
                            .field("pending_bytes", *pending_bytes)
                            .build(),
                    ),
                ),
                ObservationOutcome::Error(e) => (
                    o.code(),
                    Some(String::from(e.code())),
                    alloc::format!("{e}"),
                    None,
                ),
            },
            ObservationEnd::TimedOut => (
                end.code(),
                Some(String::from("connection_deadline")),
                String::from(
                    "connection deadline passed (this observer sends no server KEXINIT; \
                     a client waiting for it will time out here)",
                ),
                None,
            ),
            ObservationEnd::Shutdown => (
                end.code(),
                Some(String::from("listener_stopping")),
                String::from("listener stopped while the connection was active"),
                None,
            ),
            ObservationEnd::Io(e) => (
                end.code(),
                Some(String::from(io_kind_code(e.kind()))),
                alloc::format!("socket error: {e}"),
                None,
            ),
        }
    }

    fn io_kind_code(kind: std::io::ErrorKind) -> &'static str {
        match kind {
            std::io::ErrorKind::ConnectionReset => "connection_reset",
            std::io::ErrorKind::ConnectionAborted => "connection_aborted",
            std::io::ErrorKind::BrokenPipe => "broken_pipe",
            std::io::ErrorKind::TimedOut => "timed_out",
            _ => "io_other",
        }
    }

    fn bounded_text(bytes: &[u8], max: usize) -> (Value, bool) {
        let n = bytes.len().min(max);
        (Value::lossy_text(&bytes[..n]), bytes.len() > n)
    }

    fn bounded_hex(bytes: &[u8], max: usize) -> (Value, bool) {
        let n = bytes.len().min(max);
        (Value::hex(&bytes[..n]), bytes.len() > n)
    }

    fn millis(d: Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    }

    fn now_rfc3339() -> String {
        rfc3339(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
        )
    }

    /// Formats seconds since the Unix epoch as RFC 3339 UTC with
    /// millisecond precision, e.g. `2026-09-20T12:34:56.789Z`.
    #[must_use]
    pub fn rfc3339(since_epoch: Duration) -> String {
        let secs = since_epoch.as_secs();
        let millis = since_epoch.subsec_millis();
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(i64::MAX));
        alloc::format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }

    /// Howard Hinnant's `civil_from_days`, valid for the proleptic Gregorian
    /// calendar.
    fn civil_from_days(z: i64) -> (i64, u32, u32) {
        let z = z + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
        let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
        (if m <= 2 { y + 1 } else { y }, m, d)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rfc3339_known_values() {
            assert_eq!(rfc3339(Duration::ZERO), "1970-01-01T00:00:00.000Z");
            // 2000-03-01T00:00:00Z = 951868800 (day after a leap day).
            assert_eq!(
                rfc3339(Duration::from_secs(951_868_800)),
                "2000-03-01T00:00:00.000Z"
            );
            // 2026-09-20T12:34:56.789Z = 1789907696.789
            assert_eq!(
                rfc3339(Duration::from_millis(1_789_907_696_789)),
                "2026-09-20T12:34:56.789Z"
            );
            // 2024-02-29T23:59:59Z = 1709251199
            assert_eq!(
                rfc3339(Duration::from_secs(1_709_251_199)),
                "2024-02-29T23:59:59.000Z"
            );
        }
    }
}
