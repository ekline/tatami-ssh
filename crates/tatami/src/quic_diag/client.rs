//! `tatami-client handshake --transport quic`: options, name resolution, report and
//! text/JSON rendering over [`tatami_quic::diag::client`].
//!
//! [`run`] returns data and prints nothing. The report never contains
//! exporter output, key material or the peer's certificate.
//!
//! # Trust
//!
//! [`Trust::Tls`] keeps the X.509/SPKI diagnostic modes. [`Trust::SshHostKey`]
//! requires an RFC 7250 raw public key and judges it as an SSH host key with
//! the same [`TrustConfig`] policy as the TCP handshake (an SSH-blob
//! `SHA256:` pin or an explicit `known_hosts` file). The `known_hosts`
//! lookup name is bound to the typed host and the requested port before
//! name resolution; `--server-name` is only the TLS name and never
//! redirects the lookup. A trusted key alone is not proof of possession:
//! TLS `CertificateVerify` is verified by the provider in every mode.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;
use core::fmt;
use std::net::{SocketAddr, ToSocketAddrs as _};
use std::time::Duration;

use tatami_keys::sshfp::Sshfp;
use tatami_keys::trust::TrustDecision;
use tatami_quic::diag::DEFAULT_HANDSHAKE_TIMEOUT;
use tatami_quic::diag::client::{
    ClientOutcome, DiagClientConfig, ExporterProbe, HandshakeResult, run as run_client,
};
use tatami_quic::diag::tls::{ClientTrust, SshHostTrust, SshIdentityCheck};

use super::time::millis;
use super::{bytes_list, bytes_value};
use crate::json::Value;
use crate::text::escape_bytes;
use crate::trust::TrustConfig;

/// How the server's identity is judged.
#[derive(Clone, Debug)]
pub enum Trust {
    /// X.509 certificate pin, test root, or SPKI pin (diagnostic modes).
    Tls(ClientTrust),
    /// SSH host key sent as an RFC 7250 raw public key.
    SshHostKey(TrustConfig),
}

impl From<ClientTrust> for Trust {
    fn from(t: ClientTrust) -> Self {
        Trust::Tls(t)
    }
}

impl From<TrustConfig> for Trust {
    fn from(t: TrustConfig) -> Self {
        Trust::SshHostKey(t)
    }
}

impl Trust {
    /// Stable identity-mode code for reports.
    #[must_use]
    pub const fn identity_mode(&self) -> &'static str {
        match self {
            Trust::Tls(ClientTrust::PinnedRawPublicKeySha256(_)) => "raw_public_key_spki_pin",
            Trust::Tls(_) => "x509_certificate",
            Trust::SshHostKey(_) => "ssh_host_key_raw_public_key",
        }
    }
}

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
    /// How the server's identity is judged.
    pub trust: Trust,
    /// Deadline for the handshake.
    pub handshake_timeout: Duration,
    /// Confirm exporter availability after completion.
    pub exporter_probe: bool,
}

impl Options {
    /// Defaults with the required inputs.
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        port: u16,
        alpn: Vec<Vec<u8>>,
        trust: impl Into<Trust>,
    ) -> Self {
        Options {
            host: host.into(),
            port,
            server_name: None,
            alpn,
            trust: trust.into(),
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
    /// Identity mode code ([`Trust::identity_mode`]).
    pub identity_mode: &'static str,
    /// SSH trust source, in SSH host-key mode.
    pub ssh_trust: Option<TrustConfig>,
    /// The `known_hosts` lookup name bound before resolution.
    pub lookup_name: Option<String>,
    /// Stable code when the trust configuration was unusable
    /// (`io_error`, `malformed_configuration`, `invalid_lookup_name`).
    pub trust_error: Option<&'static str>,
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
        identity_mode: options.trust.identity_mode(),
        ssh_trust: None,
        lookup_name: None,
        trust_error: None,
        result: Err(String::from("not attempted")),
    };
    let trust = match &options.trust {
        Trust::Tls(t) => t.clone(),
        Trust::SshHostKey(config) => {
            report.ssh_trust = Some(config.clone());
            // The logical name: typed host and requested port, before any
            // resolution and independent of --server-name.
            match config.prepare(&options.host, options.port) {
                Ok(p) => {
                    report.lookup_name = p.lookup_name.clone();
                    ClientTrust::SshHostKey(SshHostTrust {
                        policy: p.policy,
                        source: config.mode(),
                        lookup_name: p.lookup_name,
                    })
                }
                Err(e) => {
                    report.trust_error = Some(e.code());
                    report.result = Err(alloc::format!("trust configuration unusable: {e}"));
                    return report;
                }
            }
        }
    };
    let remote = match resolve(&options.host, options.port) {
        Ok(a) => a,
        Err(e) => {
            report.result = Err(e);
            return report;
        }
    };
    report.resolved = Some(remote);
    let mut config = DiagClientConfig::new(remote, server_name, options.alpn.clone(), trust);
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
                writeln!(
                    w,
                    "Handshake: not attempted; {}",
                    escape_bytes(e.as_bytes())
                )?;
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
                self.write_ssh_identity(w, o)?;
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
        if self.ssh_trust.is_some() {
            writeln!(
                w,
                "SSH session: none (a trusted host key over QUIC/TLS is not an SSH session)"
            )?;
        }
        writeln!(w, "User authentication: not attempted")?;
        Ok(())
    }

    fn write_ssh_identity(&self, w: &mut dyn fmt::Write, o: &ClientOutcome) -> fmt::Result {
        let Some(config) = &self.ssh_trust else {
            return Ok(());
        };
        writeln!(w, "Identity mode: SSH host key as RFC 7250 raw public key")?;
        match config {
            TrustConfig::Pin(pin) => writeln!(w, "Trust source: SSH fingerprint pin {pin}")?,
            TrustConfig::KnownHostsFile(path) => {
                writeln!(
                    w,
                    "Trust source: known_hosts file {}",
                    escape_bytes(path.display().to_string().as_bytes())
                )?;
                if let Some(name) = &self.lookup_name {
                    writeln!(w, "Lookup name: {}", escape_bytes(name.as_bytes()))?;
                }
            }
        }
        match &o.ssh_identity {
            Some(SshIdentityCheck::Judged {
                algorithm,
                blob,
                fingerprint,
                decision,
            }) => {
                writeln!(w, "SSH host key: {algorithm} {fingerprint}")?;
                if let Ok(fp) = Sshfp::sha256_of_blob(blob) {
                    writeln!(w, "SSHFP (equivalent value, not DNS-verified): {fp}")?;
                }
                writeln!(
                    w,
                    "Host trust: {}",
                    crate::trust::trust_text(Some(*decision))
                )?;
            }
            Some(SshIdentityCheck::NotConvertible { reason }) => {
                writeln!(
                    w,
                    "SSH host key: not a supported raw public key ({})",
                    escape_bytes(reason.as_bytes())
                )?;
            }
            None => writeln!(w, "SSH host key: not received")?,
        }
        Ok(())
    }

    fn ssh_identity_json(&self, o: Option<&ClientOutcome>) -> Vec<(&'static str, Value)> {
        let Some(config) = &self.ssh_trust else {
            return Vec::new();
        };
        let mut out = alloc::vec![
            ("trust_policy", Value::from(config.mode())),
            (
                "pinned_fingerprint_sha256",
                config
                    .pin()
                    .map_or(Value::Null, |p| Value::from(p.to_string()))
            ),
            (
                "known_hosts_file",
                config
                    .known_hosts_file()
                    .map_or(Value::Null, |p| Value::from(p.display().to_string()))
            ),
            (
                "known_hosts_lookup",
                self.lookup_name.clone().map_or(Value::Null, Value::from)
            ),
        ];
        let check = o.and_then(|o| o.ssh_identity.as_ref());
        let (key, decision) = match check {
            Some(SshIdentityCheck::Judged {
                algorithm,
                blob,
                fingerprint,
                decision,
            }) => (
                Value::object()
                    .field("algorithm", algorithm.as_str())
                    .field("fingerprint_sha256", fingerprint.to_string())
                    .opt(
                        "sshfp",
                        Sshfp::sha256_of_blob(blob).ok().map(|f| f.to_string()),
                    )
                    .field("blob_len", blob.len())
                    .build(),
                Some(*decision),
            ),
            Some(SshIdentityCheck::NotConvertible { reason }) => (
                Value::object()
                    .field("unsupported", reason.as_str())
                    .build(),
                None,
            ),
            None => (Value::Null, None),
        };
        out.push(("ssh_host_key", key));
        out.push((
            "host_trusted",
            decision.map_or(Value::Null, |d| Value::from(d.is_trusted())),
        ));
        let (source, reason, line) = match decision {
            Some(TrustDecision::Trusted { source }) => (Some(source.code()), None, source.line()),
            Some(TrustDecision::Untrusted { reason }) => (None, Some(reason.code()), reason.line()),
            None => (None, self.trust_error, None),
        };
        out.push(("trust_source", source.map_or(Value::Null, Value::from)));
        out.push((
            "trust_line",
            line.map_or(Value::Null, |l| Value::from(l as u64)),
        ));
        out.push(("untrusted_reason", reason.map_or(Value::Null, Value::from)));
        out
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
            .opt("remote_addr", self.resolved.map(|a| a.to_string()))
            .field("identity_mode", self.identity_mode);
        for (k, v) in self.ssh_identity_json(self.result.as_ref().ok()) {
            rec = rec.field(k, v);
        }
        if let Some(code) = self.trust_error {
            rec = rec.field("trust_error", code);
        }
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
            .field("ssh_session", false)
            .field("application_data", false)
            .field("experimental", true)
            .build()
    }
}
