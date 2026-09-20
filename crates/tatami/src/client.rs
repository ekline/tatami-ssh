//! Reusable SSH client composition.
//!
//! This module assembles the shared engines with a selected transport
//! binding into a client usable as a library. CLI entry points are thin
//! wrappers over it.
//!
//! Callers configure and inspect the TCP and QUIC bindings separately; there
//! is no common transport trait. Host trust (`known_hosts`) remains a
//! caller-supplied policy distinct from user authentication.
//!
//! # Available today
//!
//! Only the TCP **initial-offer probe** ([`probe`], requires `std` and
//! `tcp`). It observes a server's identification and first `KEXINIT` and
//! stops. It does not perform key exchange, verify a host key, or
//! authenticate.

#[cfg(all(feature = "std", feature = "tcp"))]
pub mod probe {
    //! TCP initial-offer probe: options, structured report and text output.
    //!
    //! [`run`] returns data; it prints nothing. [`Report::write_text`]
    //! renders the human-readable form used by `tatami-client probe`.

    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt;
    use std::net::SocketAddr;
    use std::time::Duration;

    use tatami_tcp::io::{ConnectError, IoConfig, ProbeRun, RunEnd, connect, run_probe};
    use tatami_tcp::probe::{
        OwnedIdentification, ProbeConfig, ProbeEnd, ProbeError, ProbeEvent, Proposal, Stage,
    };
    use tatami_tcp::wire::kexinit::{KexName, classify_kex_name};
    use tatami_tcp::wire::transport::disconnect_reason;

    use crate::text::{escape_bytes, quoted};

    /// Options for one probe.
    #[derive(Clone, Debug)]
    pub struct Options {
        /// Host name or numeric address. IPv6 literals are given bare
        /// (no brackets); the port is always separate.
        pub host: String,
        /// TCP port.
        pub port: u16,
        /// Host timing and connection policy.
        pub io: IoConfig,
        /// Portable probe limits and client identification.
        pub probe: ProbeConfig,
    }

    impl Options {
        /// Options with default timeouts and limits.
        #[must_use]
        pub fn new(host: impl Into<String>, port: u16) -> Self {
            Options {
                host: host.into(),
                port,
                io: IoConfig::default(),
                probe: ProbeConfig::default(),
            }
        }
    }

    /// How the probe ended.
    #[derive(Debug)]
    pub enum Completion {
        /// Identification and a clean `KEXINIT` were observed.
        Complete,
        /// A `KEXINIT` was decoded but contained protocol anomalies; the
        /// proposal is reported but the observation is not counted complete.
        ProposalWithAnomalies,
        /// Server sent `DISCONNECT`.
        Disconnected {
            /// Reason code.
            reason_code: u32,
            /// Raw description bytes.
            description: Vec<u8>,
        },
        /// Server closed the connection.
        Eof {
            /// Stage at close.
            stage: Stage,
            /// Buffered unconsumed bytes.
            pending_bytes: usize,
        },
        /// Read deadline passed.
        TimedOut {
            /// Stage at deadline.
            stage: Stage,
        },
        /// Protocol error or exhausted budget.
        ProtocolError(ProbeError),
        /// Socket error after connecting.
        Io {
            /// Stage at error.
            stage: Stage,
            /// The error.
            error: std::io::Error,
        },
        /// No connection could be established.
        ConnectFailed(ConnectError),
    }

    impl Completion {
        /// `true` only for [`Completion::Complete`].
        #[must_use]
        pub const fn is_complete(&self) -> bool {
            matches!(self, Completion::Complete)
        }
    }

    /// Structured result of a probe. Every field that could be observed
    /// before the end is populated even when the probe did not complete.
    #[derive(Debug)]
    pub struct Report {
        /// Requested host.
        pub host: String,
        /// Requested port.
        pub port: u16,
        /// Address that actually connected, if any.
        pub peer: Option<SocketAddr>,
        /// Local address, if connected.
        pub local: Option<SocketAddr>,
        /// Client identification sent (`V_C` form, no terminator).
        pub client_identification: Option<Vec<u8>>,
        /// Pre-identification lines, raw.
        pub prelude: Vec<Vec<u8>>,
        /// Server identification, if received.
        pub server_identification: Option<OwnedIdentification>,
        /// Pre-`KEXINIT` messages other than the identification.
        pub messages: Vec<ProbeEvent>,
        /// The advertised proposal, if a `KEXINIT` was decoded.
        pub proposal: Option<Proposal>,
        /// Outcome.
        pub completion: Completion,
        /// Time from connect success to end, if connected.
        pub elapsed: Option<Duration>,
    }

    impl Report {
        /// `true` only when the requested observation was fully collected.
        #[must_use]
        pub const fn is_complete(&self) -> bool {
            self.completion.is_complete()
        }
    }

    /// Runs the probe. Blocks for at most connect + read deadlines plus
    /// name resolution (see `tatami_tcp::io` for the resolution caveat).
    #[must_use]
    pub fn run(options: &Options) -> Report {
        let mut report = Report {
            host: options.host.clone(),
            port: options.port,
            peer: None,
            local: None,
            client_identification: None,
            prelude: Vec::new(),
            server_identification: None,
            messages: Vec::new(),
            proposal: None,
            completion: Completion::TimedOut {
                stage: Stage::Identification,
            },
            elapsed: None,
        };

        let stream = match connect(&options.host, options.port, &options.io) {
            Ok(s) => s,
            Err(e) => {
                report.completion = Completion::ConnectFailed(e);
                return report;
            }
        };

        let run = match run_probe(stream, options.probe.clone(), &options.io) {
            Ok(r) => r,
            Err(error) => {
                report.completion = Completion::Io {
                    stage: Stage::Identification,
                    error,
                };
                return report;
            }
        };
        fill_from_run(&mut report, run);
        report
    }

    fn fill_from_run(report: &mut Report, run: ProbeRun) {
        report.peer = Some(run.peer);
        report.local = Some(run.local);
        let mut ident = run.client_identification;
        ident.truncate(ident.len().saturating_sub(2));
        report.client_identification = Some(ident);
        report.elapsed = Some(run.elapsed);
        for event in run.events {
            match event {
                ProbeEvent::PreludeLine { line, .. } => report.prelude.push(line),
                ProbeEvent::ServerIdentification(i) => report.server_identification = Some(i),
                other => report.messages.push(other),
            }
        }
        report.completion = match run.end {
            RunEnd::Probe(ProbeEnd::Proposal(p)) => {
                let complete = p.anomalies.is_empty();
                report.proposal = Some(*p);
                if complete {
                    Completion::Complete
                } else {
                    Completion::ProposalWithAnomalies
                }
            }
            RunEnd::Probe(ProbeEnd::Disconnected {
                reason_code,
                description,
                ..
            }) => Completion::Disconnected {
                reason_code,
                description,
            },
            RunEnd::Probe(ProbeEnd::Eof {
                stage,
                pending_bytes,
            }) => Completion::Eof {
                stage,
                pending_bytes,
            },
            RunEnd::Probe(ProbeEnd::Error(e)) => Completion::ProtocolError(e),
            RunEnd::TimedOut { stage, .. } => Completion::TimedOut { stage },
            RunEnd::Io { stage, error } => Completion::Io { stage, error },
        };
    }

    impl Report {
        /// Writes the human-readable report. All peer-supplied text is
        /// escaped. Lists are printed in advertised order and each
        /// direction separately.
        pub fn write_text(&self, w: &mut dyn fmt::Write) -> fmt::Result {
            writeln!(w, "Target: {}", target(&self.host, self.port))?;
            match self.peer {
                Some(peer) => writeln!(w, "Connected to: {peer}")?,
                None => writeln!(w, "Connected to: (not connected)")?,
            }
            if let Some(ident) = &self.client_identification {
                writeln!(w, "Client identification sent: {}", escape_bytes(ident))?;
            }
            for line in &self.prelude {
                writeln!(w, "Server pre-identification line: {}", quoted(line))?;
            }
            match &self.server_identification {
                Some(i) => {
                    writeln!(w, "Server identification: {}", escape_bytes(&i.line))?;
                    writeln!(
                        w,
                        "  protocol version: {} ({})",
                        i.protocol_version,
                        match i.support {
                            tatami_tcp::ident::VersionSupport::Ssh2 => "SSH-2",
                            tatami_tcp::ident::VersionSupport::Ssh2Compatibility =>
                                "SSH-2 compatibility mode",
                        }
                    )?;
                    writeln!(w, "  software version: {}", i.software_version)?;
                    if let Some(c) = &i.comments {
                        writeln!(w, "  comments: {}", quoted(c))?;
                    }
                    if i.terminator == tatami_tcp::ident::LineTerminator::Lf {
                        writeln!(
                            w,
                            "  note: line terminated by LF only (RFC 4253 requires CR LF)"
                        )?;
                    }
                }
                None => writeln!(w, "Server identification: not received")?,
            }
            for m in &self.messages {
                match m {
                    ProbeEvent::Ignored { data_len } => {
                        writeln!(w, "Server SSH_MSG_IGNORE: {data_len} data byte(s)")?;
                    }
                    ProbeEvent::Debug {
                        always_display,
                        message,
                        language_tag,
                    } => {
                        writeln!(
                            w,
                            "Server SSH_MSG_DEBUG (always_display={always_display}, lang={}): {}",
                            quoted(language_tag),
                            quoted(message)
                        )?;
                    }
                    ProbeEvent::Unimplemented { sequence_number } => {
                        writeln!(
                            w,
                            "Server SSH_MSG_UNIMPLEMENTED for sequence {sequence_number}"
                        )?;
                    }
                    ProbeEvent::PreludeLine { .. } | ProbeEvent::ServerIdentification(_) => {}
                }
            }

            writeln!(w, "Observation: {}", completion_line(&self.completion))?;

            if let Some(p) = &self.proposal {
                let k = &p.kexinit;
                writeln!(w, "Initial server proposal (advertised, unauthenticated):")?;
                write_kex_list(w, &k.kex_algorithms)?;
                writeln!(
                    w,
                    "  Server host-key algorithms: {}",
                    list(&k.server_host_key_algorithms)
                )?;
                writeln!(
                    w,
                    "  Ciphers client->server: {}",
                    list(&k.encryption_client_to_server)
                )?;
                writeln!(
                    w,
                    "  Ciphers server->client: {}",
                    list(&k.encryption_server_to_client)
                )?;
                writeln!(
                    w,
                    "  MACs client->server: {}",
                    list(&k.mac_client_to_server)
                )?;
                writeln!(
                    w,
                    "  MACs server->client: {}",
                    list(&k.mac_server_to_client)
                )?;
                writeln!(
                    w,
                    "  Compression client->server: {}",
                    list(&k.compression_client_to_server)
                )?;
                writeln!(
                    w,
                    "  Compression server->client: {}",
                    list(&k.compression_server_to_client)
                )?;
                writeln!(
                    w,
                    "  Languages client->server: {}",
                    list(&k.languages_client_to_server)
                )?;
                writeln!(
                    w,
                    "  Languages server->client: {}",
                    list(&k.languages_server_to_client)
                )?;
                writeln!(
                    w,
                    "  First KEX packet follows: {}",
                    k.first_kex_packet_follows
                )?;
                writeln!(w, "  Reserved field: {}", k.reserved)?;
                for a in &p.anomalies {
                    writeln!(w, "  Anomaly: {a}")?;
                }
                if p.unexamined_bytes > 0 {
                    writeln!(
                        w,
                        "  Note: {} byte(s) received after KEXINIT were not examined",
                        p.unexamined_bytes
                    )?;
                }
            }

            writeln!(w, "Key exchange: not performed")?;
            writeln!(w, "Server public key / fingerprint: not obtained")?;
            writeln!(w, "Server trust verification: not performed")?;
            writeln!(w, "User authentication: not attempted")?;
            if let Some(e) = self.elapsed {
                writeln!(w, "Elapsed after connect: {:.3}s", e.as_secs_f64())?;
            }
            Ok(())
        }
    }

    fn target(host: &str, port: u16) -> String {
        if host.contains(':') {
            alloc::format!("[{host}]:{port}")
        } else {
            alloc::format!("{host}:{port}")
        }
    }

    fn list(names: &[String]) -> String {
        let mut out = String::from("[");
        for (i, n) in names.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&escape_bytes(n.as_bytes()));
        }
        out.push(']');
        out
    }

    fn write_kex_list(w: &mut dyn fmt::Write, names: &[String]) -> fmt::Result {
        writeln!(w, "  KEX algorithms, in advertised order: {}", list(names))?;
        for n in names {
            let note = match classify_kex_name(n.as_bytes()) {
                KexName::Method => continue,
                KexName::ExtInfoClient => {
                    "client extension-negotiation marker (RFC 8308), not a method"
                }
                KexName::ExtInfoServer => {
                    "server extension-negotiation marker (RFC 8308), not a method"
                }
                KexName::StrictKexClient => "client OpenSSH strict-KEX marker, not a method",
                KexName::StrictKexServer => "server OpenSSH strict-KEX marker, not a method",
            };
            writeln!(w, "    {}: {note}", escape_bytes(n.as_bytes()))?;
        }
        Ok(())
    }

    fn completion_line(c: &Completion) -> String {
        match c {
            Completion::Complete => String::from("complete; initial server proposal received"),
            Completion::ProposalWithAnomalies => {
                String::from("incomplete; KEXINIT decoded but contains protocol anomalies")
            }
            Completion::Disconnected {
                reason_code,
                description,
            } => alloc::format!(
                "server disconnected; reason {reason_code}{}: {}",
                disconnect_reason::name(*reason_code)
                    .map(|n| alloc::format!(" ({n})"))
                    .unwrap_or_default(),
                quoted(description)
            ),
            Completion::Eof {
                stage,
                pending_bytes,
            } => alloc::format!(
                "incomplete; connection closed by peer while {stage} ({pending_bytes} unparsed byte(s))"
            ),
            Completion::TimedOut { stage } => alloc::format!(
                "incomplete; deadline passed while {stage} (this probe does not send a client KEXINIT; \
                 a server that waits for it will not respond)"
            ),
            Completion::ProtocolError(e) => alloc::format!("incomplete; {e}"),
            Completion::Io { stage, error } => {
                alloc::format!("incomplete; socket error while {stage}: {error}")
            }
            Completion::ConnectFailed(e) => alloc::format!("not connected; {e}"),
        }
    }
}
