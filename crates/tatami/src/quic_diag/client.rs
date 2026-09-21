//! `tatami-quic-client handshake`: options, name resolution, report and
//! text/JSON rendering over [`tatami_quic::diag::client`].
//!
//! [`run`] returns data and prints nothing. The report never contains
//! exporter output, key material or the peer's certificate.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::fmt;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::time::Duration;

use tatami_quic::diag::DEFAULT_HANDSHAKE_TIMEOUT;
use tatami_quic::diag::client::{
    ClientOutcome, DiagClientConfig, ExporterProbe, HandshakeResult, run as run_client,
};
use tatami_quic::diag::tls::ClientTrust;

use super::time::millis;
use super::{bytes_list, bytes_value};
use crate::json::Value;
use crate::text::escape_bytes;

/// Options for one handshake.
#[derive(Clone, Debug)]
pub struct Options {
    /// Host name or numeric address (IPv6 bare, no brackets).
    pub host: String,
    /// UDP port.
    pub port: u16,
    /// TLS server name; defaults to `host`.
    pub server_name: Option<String>,
    /// ALPN values to offer (required, explicit, unregistered).
    pub alpn: Vec<Vec<u8>>,
    /// Trust policy: a pinned certificate SHA-256 or a test root.
    pub trust: ClientTrust,
    /// Deadline for the handshake.
    pub handshake_timeout: Duration,
    /// Confirm exporter availability after completion.
    pub exporter_probe: bool,
}

impl Options {
    /// Defaults with the required inputs.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, alpn: Vec<Vec<u8>>, trust: ClientTrust) -> Self {
        Options {
            host: host.into(),
            port,
            server_name: None,
            alpn,
            trust,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            exporter_probe: false,
        }
    }

    /// The server name that will be used.
    #[must_use]
    pub fn effective_server_name(&self) -> &str {
        self.server_name.as_deref().unwrap_or(&self.host)
    }
}

/// Structured result of a handshake attempt.
#[derive(Debug)]
pub struct Report {
    /// Requested host.
    pub host: String,
    /// Requested port.
    pub port: u16,
    /// Server name used.
    pub server_name: String,
    /// Address the handshake was attempted with, if resolution succeeded.
    pub resolved: Option<SocketAddr>,
    /// The outcome, or why no handshake could be attempted.
    pub result: Result<ClientOutcome, String>,
}

impl Report {
    /// `true` only when the handshake completed.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.result.as_ref().is_ok_and(ClientOutcome::is_completed)
    }
}

/// Resolves the host and runs one handshake. Blocks for name resolution
/// plus at most the handshake deadline and a short linger.
#[must_use]
pub fn run(options: &Options) -> Report {
    let server_name = options.effective_server_name().to_string();
    let mut report = Report {
        host: options.host.clone(),
        port: options.port,
        server_name: server_name.clone(),
        resolved: None,
        result: Err(String::from("not attempted")),
    };
    let remote = match resolve(&options.host, options.port) {
        Ok(a) => a,
        Err(e) => {
            report.result = Err(e);
            return report;
        }
    };
    report.resolved = Some(remote);
    let mut config = DiagClientConfig::new(
        remote,
        server_name,
        options.alpn.clone(),
        options.trust.clone(),
    );
    config.handshake_timeout = options.handshake_timeout;
    config.exporter = options.exporter_probe.then(ExporterProbe::default);
    report.result = run_client(&config).map_err(|e| e.to_string());
    report
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| alloc::format!("could not resolve {host:?}: {e}"))?;
    addrs
        .next()
        .ok_or_else(|| alloc::format!("{host:?} resolved to no addresses"))
}

fn target(host: &str, port: u16) -> String {
    if host.contains(':') {
        alloc::format!("[{host}]:{port}")
    } else {
        alloc::format!("{host}:{port}")
    }
}

fn alpn_text(items: &[Vec<u8>]) -> String {
    let mut out = String::from("[");
    for (i, p) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&escape_bytes(p));
    }
    out.push(']');
    out
}

impl Report {
    /// Human-readable report; peer-supplied text is escaped.
    pub fn write_text(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        writeln!(
            w,
            "Target: {} (QUIC v1, UDP)",
            target(&self.host, self.port)
        )?;
        match self.resolved {
            Some(a) => writeln!(w, "Remote address: {a}")?,
            None => writeln!(w, "Remote address: (unresolved)")?,
        }
        writeln!(
            w,
            "Server name: {}",
            escape_bytes(self.server_name.as_bytes())
        )?;
        match &self.result {
            Err(e) => {
                writeln!(w, "Handshake: not attempted; {e}")?;
            }
            Ok(o) => {
                if let Some(l) = o.local {
                    writeln!(w, "Local address: {l}")?;
                }
                writeln!(w, "SNI sent: {}", o.sni_sent)?;
                writeln!(
                    w,
                    "ALPN offered (experimental, unregistered): {}",
                    alpn_text(&o.offered_alpn)
                )?;
                match &o.handshake {
                    HandshakeResult::Completed => {
                        writeln!(w, "Handshake: completed (TLS 1.3 over QUIC v1)")?
                    }
                    HandshakeResult::Failed { reason } => {
                        writeln!(w, "Handshake: failed; {}", escape_bytes(reason.as_bytes()))?;
                    }
                    HandshakeResult::TimedOut => writeln!(w, "Handshake: timed out")?,
                }
                match &o.negotiated_alpn {
                    Some(a) => writeln!(w, "ALPN negotiated: {}", escape_bytes(a))?,
                    None => writeln!(w, "ALPN negotiated: none")?,
                }
                writeln!(w, "Server identity check: {}", o.trust)?;
                writeln!(w, "TLS version: {}", o.tls_version_note)?;
                writeln!(
                    w,
                    "QUIC version: 0x{:08x} ({})",
                    o.quic_version, o.quic_version_note
                )?;
                writeln!(w, "0-RTT attempted: {}", o.zero_rtt_attempted)?;
                match o.exporter {
                    Some(e) => writeln!(
                        w,
                        "TLS exporter probe: {} ({} bytes requested; output discarded, never a session binding)",
                        if e.available {
                            "available"
                        } else {
                            "unavailable"
                        },
                        e.len
                    )?,
                    None => writeln!(w, "TLS exporter probe: not requested")?,
                }
                writeln!(w, "Close: {}", escape_bytes(o.close_reason.as_bytes()))?;
                writeln!(
                    w,
                    "Datagrams: {} sent, {} received",
                    o.datagrams_sent, o.datagrams_received
                )?;
                writeln!(w, "Elapsed: {:.3}s", o.elapsed.as_secs_f64())?;
            }
        }
        writeln!(w, "Application data: none (no streams, no datagrams)")?;
        writeln!(
            w,
            "SSH: nothing sent or expected; this is not an SSH client"
        )?;
        writeln!(w, "User authentication: not attempted")?;
        Ok(())
    }

    /// One JSON object with the same content as [`Report::write_text`].
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut rec = Value::object()
            .field("schema", super::server::SCHEMA_VERSION)
            .field("event", "quic_client_handshake")
            .field("time", super::time::now_rfc3339())
            .field("transport", "quic")
            .field("host", self.host.clone())
            .field("port", u64::from(self.port))
            .field("server_name", self.server_name.clone())
            .opt("remote_addr", self.resolved.map(|a| a.to_string()));
        match &self.result {
            Err(e) => {
                rec = rec
                    .field("handshake_outcome", "not_attempted")
                    .field("reason", e.clone());
            }
            Ok(o) => {
                rec = rec
                    .opt("local_addr", o.local.map(|a| a.to_string()))
                    .field("sni_sent", o.sni_sent)
                    .field("offered_alpn", bytes_list(&o.offered_alpn, 512))
                    .field("alpn_registered", false)
                    .field("handshake_outcome", o.handshake.code())
                    .opt(
                        "reason",
                        match &o.handshake {
                            HandshakeResult::Failed { reason } => Some(reason.clone()),
                            _ => None,
                        },
                    )
                    .opt(
                        "negotiated_alpn",
                        o.negotiated_alpn.as_ref().map(|a| bytes_value(a, 512)),
                    )
                    .field("server_identity_check", o.trust)
                    .field("server_identity_verified", o.handshake.is_completed())
                    .field("tls_version", "1.3")
                    .field("tls_version_note", o.tls_version_note)
                    .field("quic_version", u64::from(o.quic_version))
                    .field("quic_version_note", o.quic_version_note)
                    .field("zero_rtt", o.zero_rtt_attempted)
                    .opt(
                        "exporter",
                        o.exporter.map(|e| {
                            Value::object()
                                .field("available", e.available)
                                .field("len", e.len)
                                .build()
                        }),
                    )
                    .field("close_reason", o.close_reason.clone())
                    .field("datagrams_sent", o.datagrams_sent)
                    .field("datagrams_received", o.datagrams_received)
                    .field("elapsed_ms", millis(o.elapsed));
            }
        }
        rec.field("user_authenticated", false)
            .field("application_data", false)
            .field("experimental", true)
            .build()
    }
}
