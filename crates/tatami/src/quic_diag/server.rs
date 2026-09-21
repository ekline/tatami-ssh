//! `tatami-quic-server observe`: options, identity loading, JSON Lines
//! records and a blocking `run` over [`tatami_quic::diag::server`].
//!
//! # `quic_handshake_observation` record
//!
//! | Field | Meaning |
//! |---|---|
//! | `id`, `transport`, `local_addr`, `peer_addr`, `accepted_at`, `elapsed_ms` | as for the TCP observer; `peer_addr` is the Initial's source address |
//! | `peer_address_validated`, `may_retry`, `retry_sent`, `validation_method` | `quinn-proto` address-validation state at acceptance; validation ≠ identity |
//! | `orig_dst_cid_hex` | identifies the attempt, not the peer |
//! | `quic_version`, `quic_version_note` | always `1`; the endpoint accepts no other version and the library does not expose the negotiated one |
//! | `offered_alpn`, `offered_sni`, `offered_cipher_suites`, `offered_signature_schemes`, `offered_named_groups`, `offered_server_cert_types`, `offered_hellos_seen` | **untrusted** ClientHello contents from the certificate-resolver hook; `null` with `offered_note` when no ClientHello was processed |
//! | `negotiated_alpn`, `sni` | rustls's view once the ClientHello was processed |
//! | `handshake_outcome`, `reason`, `close_reason` | `completed`, `failed`, `timed_out`, `accept_failed`, `shutdown`; error text; who closed |
//! | `unexpected_streams`, `unexpected_datagrams` | events counted and ignored (limits are 0) |
//! | `zero_rtt`, `peer_authenticated`, `application_data`, `tls_version` | always `false`, `false`, `false`, `"1.3"` |

use alloc::boxed::Box;
use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tatami_quic::diag::identity::{CertificateSha256, IdentityError, TestIdentity};
use tatami_quic::diag::server::{
    BindError, DiagServer, DiagServerConfig, HandshakeObservation, ServerEvent, StopHandle, Summary,
};
use tatami_quic::diag::{DEFAULT_HANDSHAKE_TIMEOUT, QUIC_VERSION_1};

use super::time::{millis, now_rfc3339, rfc3339};
use super::{bytes_list, bytes_value, string_list};
use crate::json::Value;

/// Schema version written in every record.
pub const SCHEMA_VERSION: u64 = 1;

/// Options for one observer run.
#[derive(Clone, Debug)]
pub struct Options {
    /// UDP address to bind.
    pub bind: SocketAddr,
    /// ALPN values accepted (required, explicit, unregistered).
    pub alpn: Vec<Vec<u8>>,
    /// Directory holding `cert.pem` and `key.pem`.
    pub identity_dir: PathBuf,
    /// Generate an identity if the directory has none. Never implicit.
    pub generate_identity: bool,
    /// `subjectAltName` entries for a generated identity.
    pub identity_names: Vec<String>,
    /// Answer unvalidated Initials with Retry.
    pub require_validation: bool,
    /// Per-handshake deadline (also the QUIC idle timeout).
    pub handshake_timeout: Duration,
    /// Stop after this many accepted-or-refused connections.
    pub max_connections: Option<u64>,
    /// Stop after this long.
    pub run_for: Option<Duration>,
    /// Handshakes in progress at once.
    pub max_concurrent: usize,
    /// Record channel capacity.
    pub pending_records: usize,
    /// Bound on hex renderings of peer bytes per field.
    pub max_field_bytes: usize,
}

impl Options {
    /// Defaults for everything but the two required inputs.
    #[must_use]
    pub fn new(alpn: Vec<Vec<u8>>, identity_dir: PathBuf) -> Self {
        Options {
            bind: SocketAddr::from(([127, 0, 0, 1], 4433)),
            alpn,
            identity_dir,
            generate_identity: false,
            identity_names: alloc::vec![
                String::from("localhost"),
                String::from("127.0.0.1"),
                String::from("::1"),
            ],
            require_validation: false,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            max_connections: None,
            run_for: None,
            max_concurrent: 32,
            pending_records: 128,
            max_field_bytes: 512,
        }
    }
}

/// Failure to start a run.
#[derive(Debug)]
pub enum RunError {
    /// Identity could not be loaded or generated.
    Identity(IdentityError),
    /// Configuration or bind failure.
    Bind(BindError),
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RunError::Identity(e) => write!(f, "{e}"),
            RunError::Bind(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RunError {}

/// A bound server that has not started running.
pub struct Prepared {
    server: DiagServer,
    options: Options,
    identity_generated: bool,
}

impl Prepared {
    /// Actual bound address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.server.local_addr()
    }

    /// Fingerprint of the certificate that will be presented (SHA-256 of
    /// the certificate DER; not an SSH host-key fingerprint).
    #[must_use]
    pub fn certificate_sha256(&self) -> CertificateSha256 {
        self.server.certificate_sha256()
    }

    /// `true` if the identity was generated by this call to [`prepare`].
    #[must_use]
    pub fn identity_generated(&self) -> bool {
        self.identity_generated
    }

    /// Handle to stop the run from another thread.
    #[must_use]
    pub fn stop_handle(&self) -> StopHandle {
        self.server.stop_handle()
    }

    /// Runs to completion, writing JSON Lines to `out`. Each record is
    /// written and flushed as a unit from one thread; a write error stops
    /// the run with `StopReason::SinkFailed`.
    pub fn run_jsonl(self, mut out: impl Write + Send + 'static) -> Summary {
        let encoder = Encoder {
            max_field_bytes: self.options.max_field_bytes,
            require_validation: self.options.require_validation,
        };
        self.server.run(Box::new(move |event| {
            let mut line = encoder.encode(&event).to_json();
            line.push('\n');
            out.write_all(line.as_bytes())?;
            out.flush()?;
            Ok(())
        }))
    }
}

/// Loads (or, if asked, generates) the identity, validates the options and
/// binds the socket without accepting yet.
pub fn prepare(options: Options) -> Result<Prepared, RunError> {
    let (identity, generated) = TestIdentity::load_or_generate(
        &options.identity_dir,
        options.generate_identity,
        &options.identity_names,
    )
    .map_err(RunError::Identity)?;
    let mut config = DiagServerConfig::new(identity, options.alpn.clone());
    config.bind = options.bind;
    config.handshake_timeout = options.handshake_timeout;
    config.require_validation = options.require_validation;
    config.max_connections = options.max_connections;
    config.run_for = options.run_for;
    config.max_concurrent = options.max_concurrent;
    config.pending_records = options.pending_records;
    let server = DiagServer::bind(config).map_err(RunError::Bind)?;
    Ok(Prepared {
        server,
        options,
        identity_generated: generated,
    })
}

/// Encodes server events as JSON records.
#[derive(Clone, Copy, Debug)]
pub struct Encoder {
    /// See [`Options::max_field_bytes`].
    pub max_field_bytes: usize,
    /// Echoed in the start record.
    pub require_validation: bool,
}

impl Encoder {
    /// Encodes one event. Never fails.
    #[must_use]
    pub fn encode(&self, event: &ServerEvent) -> Value {
        match event {
            ServerEvent::Started {
                bound,
                certificate_sha256,
                alpn,
            } => envelope("quic_listener_started")
                .field("bound", bound.to_string())
                .field("certificate_sha256", certificate_sha256.to_string())
                .field(
                    "certificate_sha256_note",
                    "SHA-256 of the certificate DER; not an SSH host-key fingerprint",
                )
                .field("alpn", bytes_list(alpn, self.max_field_bytes))
                .field("alpn_registered", false)
                .field("require_validation", self.require_validation)
                .field("quic_version", u64::from(QUIC_VERSION_1))
                .field("tls_version", "1.3")
                .field("zero_rtt", false)
                .field("experimental", true)
                .field("ssh_service", false)
                .build(),
            ServerEvent::Overload {
                dropped_since_last,
                total_dropped,
            } => envelope("overload")
                .field("dropped_since_last", *dropped_since_last)
                .field("total_dropped", *total_dropped)
                .build(),
            ServerEvent::Stopped(s) => summary_record(s),
            ServerEvent::Connection(o) => observation_record(o, self.max_field_bytes),
        }
    }
}

fn envelope(event: &str) -> crate::json::Object {
    Value::object()
        .field("schema", SCHEMA_VERSION)
        .field("event", event)
        .field("time", now_rfc3339())
        .field("transport", "quic")
}

/// Encodes the final summary.
#[must_use]
pub fn summary_record(s: &Summary) -> Value {
    let st = &s.stats;
    envelope("quic_listener_stopped")
        .field("bound", s.bound.to_string())
        .field("reason", s.reason.code())
        .field("incoming", st.incoming)
        .field("accepted", st.accepted)
        .field("observed", st.observed)
        .field("completed", st.completed)
        .field("failed", st.failed)
        .field("timed_out", st.timed_out)
        .field("dropped_at_capacity", st.dropped_at_capacity)
        .field("retries_sent", st.retries_sent)
        .field("version_negotiations_sent", st.version_negotiations_sent)
        .field("endpoint_responses_sent", st.endpoint_responses_sent)
        .field("datagrams_received", st.datagrams_received)
        .field("datagrams_sent", st.datagrams_sent)
        .field("records_dropped", s.records_dropped)
        .field("abandoned", s.abandoned)
        .field("elapsed_ms", millis(s.elapsed))
        .opt("error", s.error.clone())
        .build()
}

/// Encodes one handshake observation (fields in the module docs).
#[must_use]
pub fn observation_record(o: &HandshakeObservation, max_field: usize) -> Value {
    let mut rec = envelope("quic_handshake_observation")
        .field("id", o.id)
        .field("local_addr", o.local.to_string())
        .field("peer_addr", o.peer.to_string())
        .field("peer_address_validated", o.peer_address_validated)
        .field("may_retry", o.may_retry)
        .field("retry_sent", o.retry_sent)
        .field("validation_method", o.validation_method.code())
        .field("orig_dst_cid_hex", Value::hex(&o.orig_dst_cid))
        .field("accepted_at", rfc3339(o.accepted_unix))
        .field("elapsed_ms", millis(o.elapsed))
        .field("quic_version", u64::from(o.quic_version))
        .field(
            "quic_version_note",
            "by construction: the endpoint supports only v1; quinn-proto 0.11 exposes no negotiated version",
        );
    match &o.offered {
        Some(h) => {
            rec = rec
                .opt(
                    "offered_alpn",
                    h.alpn.as_ref().map(|a| bytes_list(a, max_field)),
                )
                .opt("offered_sni", h.server_name.clone())
                .field("offered_cipher_suites", string_list(&h.cipher_suites))
                .field(
                    "offered_signature_schemes",
                    string_list(&h.signature_schemes),
                )
                .opt(
                    "offered_named_groups",
                    h.named_groups.as_deref().map(string_list),
                )
                .opt(
                    "offered_server_cert_types",
                    h.server_cert_types.as_deref().map(string_list),
                )
                .field("offered_hellos_seen", h.hellos_seen)
                .field(
                    "offered_note",
                    "untrusted: copied from the peer's ClientHello before any authentication",
                );
        }
        None => {
            rec = rec
                .field("offered_alpn", Value::Null)
                .field("offered_sni", Value::Null)
                .field(
                    "offered_note",
                    "unavailable: no ClientHello was processed for this attempt",
                );
        }
    }
    rec.opt(
        "negotiated_alpn",
        o.negotiated_alpn
            .as_ref()
            .map(|a| bytes_value(a, max_field)),
    )
    .opt("sni", o.sni.clone())
    .field("handshake_outcome", o.outcome.code())
    .opt("reason", o.outcome.reason().map(String::from))
    .field("close_reason", o.close.code())
    .field("unexpected_streams", o.unexpected_streams)
    .field("unexpected_datagrams", o.unexpected_datagrams)
    .field("zero_rtt", o.zero_rtt_attempted)
    .field("tls_version", "1.3")
    .field("peer_authenticated", false)
    .field("application_data", false)
    .build()
}
