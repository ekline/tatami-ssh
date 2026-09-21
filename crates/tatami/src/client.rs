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
//! - The TCP **initial-offer probe** (`probe`, requires `std` and `tcp`).
//!   It observes a server's identification and first `KEXINIT` and stops. It
//!   does not perform key exchange, verify a host key, or authenticate.
//! - The TCP **active handshake** (`handshake`, requires `std` and `kex`).
//!   It performs the first interoperability profile's key exchange, verifies
//!   the host signature, checks the host key against an operator-supplied
//!   `SHA256:` pin, switches to protected packets and requests the
//!   `ssh-userauth` service. It never authenticates a user.
//!
//! Both are documented in their modules; the links are plain code spans
//! here because the modules exist only with their features enabled.

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
                KexName::StrictKexClient => {
                    "client strict-KEX marker (draft-ietf-sshm-strict-kex), not a method"
                }
                KexName::StrictKexServer => {
                    "server strict-KEX marker (draft-ietf-sshm-strict-kex), not a method"
                }
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

#[cfg(all(feature = "std", feature = "kex"))]
pub mod handshake {
    //! TCP active handshake: options, structured report, text and JSON
    //! output.
    //!
    //! [`run`] connects, drives `tatami_tcp::io::handshake::run_handshake`
    //! with a pinned-fingerprint trust policy ([`PinnedSha256`]) and returns
    //! a [`Report`]; it prints nothing. [`Report::write_text`] renders the
    //! human-readable form used by `tatami-client handshake` and
    //! [`Report::to_json`] the machine-readable one (`--json`). Every
    //! peer-supplied byte string is escaped in the text form and rendered as
    //! lossy UTF-8 (plus bounded hex where fidelity matters) in JSON. Neither
    //! form contains key material: the state machine's report never does.
    //!
    //! # What "complete" means
    //!
    //! [`Report::is_complete`] is `true` only for
    //! [`HandshakeOutcome::Completed`]: negotiation succeeded, the host
    //! signature over the exchange hash verified, the presented host key's
    //! fingerprint equals the operator's pin, `NEWKEYS` was exchanged in both
    //! directions and the server accepted the requested service
    //! (`ssh-userauth`). Nothing is ever authenticated: the report's
    //! `user_authenticated` is always `false`, and re-exchange is not
    //! supported.
    //!
    //! # Trust
    //!
    //! The only trust source is the pin. There is no `known_hosts`, no
    //! prompting and no enrollment; a fingerprint mismatch ends the run
    //! before `NEWKEYS` is sent ([`HandshakeOutcome::HostNotTrusted`]).
    //! The pin must come from an independent channel, for example
    //! `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` run on the server.
    //!
    //! # JSON record (`schema` = 1, `event` = `tcp_handshake`)
    //!
    //! One object with, in order: `target {host, port}`, `peer`, `local`,
    //! `pinned_fingerprint_sha256`, `phase`, `client_identification`,
    //! `server_prelude_lines`, `server_identification`, `skipped_messages`,
    //! `advertised {client, server}`, `selected`, `strict_kex
    //! {offered_pre_standard, offered_standard, server_pre_standard,
    //! server_standard, negotiated}`, `kexinit_was_first_packet`,
    //! `server_guess_discarded`, `host_key {algorithm, fingerprint_sha256,
    //! blob_len}`, `fingerprint_sha256`, `host_key_signature_valid`,
    //! `signature_error`, `trust_policy`, `host_trusted`, `trust_source`,
    //! `untrusted_reason`, `key_exchange_completed`, `newkeys_sent`,
    //! `newkeys_received`, `protected_packets_sent`,
    //! `protected_packets_received`, `ext_info {received, server_sig_algs,
    //! extension_names}`, `service_accepted`, `server_disconnect`, `outcome`,
    //! `outcome_code`, `negotiation_error_code`, `user_authenticated`
    //! (always `false`), `rekey_supported` (always `false`), `elapsed_ms`.
    //! Fields that could not be observed are `null`, never guessed.

    use alloc::string::{String, ToString};
    use alloc::vec::Vec;
    use core::fmt;
    use std::net::SocketAddr;
    use std::time::Duration;

    use tatami_keys::fingerprint::Sha256Fingerprint;
    use tatami_keys::trust::{PinnedSha256, TrustDecision, TrustSource, UntrustedReason};
    use tatami_tcp::handshake::{
        HandshakeConfig, HandshakeOutcome, HandshakeReport, LimitKind, OwnedIdentification, Phase,
        ProtocolViolation, SkippedMessage,
    };
    use tatami_tcp::initial::InputOverflow;
    use tatami_tcp::io::ConnectError;
    use tatami_tcp::io::handshake::{HandshakeEnd, HandshakeIo, HandshakeRun, run_handshake};
    use tatami_tcp::negotiate::{Direction, Negotiated, NegotiationError, StrictKex, is_aead};
    use tatami_tcp::wire::kexinit::{KexName, OwnedKexInit, classify_kex_name};
    use tatami_tcp::wire::msg;
    use tatami_tcp::wire::transport::disconnect_reason;

    use crate::json::Value;
    use crate::text::{escape_bytes, quoted};

    /// Options for one handshake.
    #[derive(Clone, Debug)]
    pub struct Options {
        /// Host name or numeric address. IPv6 literals are given bare
        /// (no brackets); the port is always separate.
        pub host: String,
        /// TCP port.
        pub port: u16,
        /// The only host-key fingerprint that will be trusted.
        pub pin: Sha256Fingerprint,
        /// Host timing policy (connect deadline, overall deadline).
        pub io: HandshakeIo,
        /// Portable handshake configuration (markers, limits, service).
        pub config: HandshakeConfig,
    }

    impl Options {
        /// Options with the library's default deadlines and limits.
        #[must_use]
        pub fn new(host: impl Into<String>, port: u16, pin: Sha256Fingerprint) -> Self {
            Options {
                host: host.into(),
                port,
                pin,
                io: HandshakeIo::default(),
                config: HandshakeConfig::default(),
            }
        }
    }

    /// How the run ended. The first thirteen variants mirror
    /// [`HandshakeOutcome`]; the rest are host-side ends.
    #[derive(Debug)]
    pub enum Completion {
        /// Service accepted after a verified, trusted, protected exchange.
        Complete,
        /// The pin did not match (or no policy applied). No `NEWKEYS` sent.
        HostNotTrusted {
            /// Why.
            reason: UntrustedReason,
        },
        /// The host signature over the exchange hash did not verify.
        SignatureInvalid,
        /// RFC 4253 §7.1 negotiation failed.
        NegotiationFailed(NegotiationError),
        /// A strict-KEX rule was broken.
        StrictKexViolation {
            /// What was seen.
            detail: String,
        },
        /// A protocol violation.
        ProtocolError(ProtocolViolation),
        /// The server sent `DISCONNECT`.
        ServerDisconnected {
            /// Reason code.
            reason_code: u32,
            /// Raw description bytes.
            description: Vec<u8>,
        },
        /// The server requested a re-exchange; a `DISCONNECT` was sent.
        RekeyNotSupported,
        /// A message that is not valid in the phase it arrived in.
        UnexpectedMessage {
            /// Message number.
            number: u8,
            /// Phase it arrived in.
            phase: Phase,
        },
        /// A protected packet failed authentication.
        TagMismatch,
        /// The server closed the connection.
        Eof {
            /// Phase at close.
            phase: Phase,
        },
        /// Input exceeded the state machine's buffer bound.
        InputOverflow(InputOverflow),
        /// A local budget was exhausted.
        Limit(LimitKind),
        /// The overall deadline passed.
        TimedOut {
            /// Phase at the deadline.
            phase: Phase,
            /// Buffered unconsumed bytes at that point.
            pending_bytes: usize,
        },
        /// Socket error after connecting.
        Io {
            /// Phase at the error.
            phase: Phase,
            /// The error.
            error: std::io::Error,
        },
        /// No connection could be established.
        ConnectFailed(ConnectError),
        /// Connected, but the handshake could not start (socket addresses
        /// unreadable, invalid configured identification, or OS entropy
        /// failure). No byte was exchanged.
        NotStarted(std::io::Error),
    }

    impl Completion {
        /// `true` only for [`Completion::Complete`].
        #[must_use]
        pub const fn is_complete(&self) -> bool {
            matches!(self, Completion::Complete)
        }

        /// Stable, machine-readable code. Equal to
        /// [`HandshakeOutcome::code`] for the mirrored variants.
        #[must_use]
        pub const fn code(&self) -> &'static str {
            match self {
                Completion::Complete => "completed",
                Completion::HostNotTrusted { .. } => "host_not_trusted",
                Completion::SignatureInvalid => "signature_invalid",
                Completion::NegotiationFailed(_) => "negotiation_failed",
                Completion::StrictKexViolation { .. } => "strict_kex_violation",
                Completion::ProtocolError(_) => "protocol_error",
                Completion::ServerDisconnected { .. } => "server_disconnected",
                Completion::RekeyNotSupported => "rekey_not_supported",
                Completion::UnexpectedMessage { .. } => "unexpected_message",
                Completion::TagMismatch => "tag_mismatch",
                Completion::Eof { .. } => "eof",
                Completion::InputOverflow(_) => "input_overflow",
                Completion::Limit(_) => "limit",
                Completion::TimedOut { .. } => "timed_out",
                Completion::Io { .. } => "io_error",
                Completion::ConnectFailed(_) => "connect_failed",
                Completion::NotStarted(_) => "not_started",
            }
        }

        fn from_outcome(outcome: HandshakeOutcome) -> Self {
            match outcome {
                HandshakeOutcome::Completed => Completion::Complete,
                HandshakeOutcome::HostNotTrusted { reason } => {
                    Completion::HostNotTrusted { reason }
                }
                HandshakeOutcome::SignatureInvalid => Completion::SignatureInvalid,
                HandshakeOutcome::NegotiationFailed(e) => Completion::NegotiationFailed(e),
                HandshakeOutcome::StrictKexViolation { detail } => {
                    Completion::StrictKexViolation { detail }
                }
                HandshakeOutcome::ProtocolError(v) => Completion::ProtocolError(v),
                HandshakeOutcome::ServerDisconnected {
                    reason_code,
                    description,
                } => Completion::ServerDisconnected {
                    reason_code,
                    description,
                },
                HandshakeOutcome::RekeyNotSupported => Completion::RekeyNotSupported,
                HandshakeOutcome::UnexpectedMessage { number, phase } => {
                    Completion::UnexpectedMessage { number, phase }
                }
                HandshakeOutcome::TagMismatch => Completion::TagMismatch,
                HandshakeOutcome::Eof { phase } => Completion::Eof { phase },
                HandshakeOutcome::InputOverflow(o) => Completion::InputOverflow(o),
                HandshakeOutcome::Limit(l) => Completion::Limit(l),
            }
        }
    }

    /// Structured result of a handshake. Everything observed before the end
    /// is populated even when the run did not complete.
    #[derive(Debug)]
    pub struct Report {
        /// Requested host.
        pub host: String,
        /// Requested port.
        pub port: u16,
        /// The pinned fingerprint the run was configured with.
        pub pin: Sha256Fingerprint,
        /// Address that actually connected, if any.
        pub peer: Option<SocketAddr>,
        /// Local address, if connected.
        pub local: Option<SocketAddr>,
        /// The state machine's report; `None` when no connection was made
        /// or the handshake could not start.
        pub handshake: Option<HandshakeReport>,
        /// Outcome.
        pub completion: Completion,
        /// Time from connect success to end, if connected.
        pub elapsed: Option<Duration>,
    }

    impl Report {
        /// `true` only when the service was accepted after a verified and
        /// trusted exchange ([`Completion::Complete`]).
        #[must_use]
        pub const fn is_complete(&self) -> bool {
            self.completion.is_complete()
        }

        fn unconnected(options: &Options, completion: Completion) -> Self {
            Report {
                host: options.host.clone(),
                port: options.port,
                pin: options.pin,
                peer: None,
                local: None,
                handshake: None,
                completion,
                elapsed: None,
            }
        }
    }

    /// Runs the handshake. Blocks for at most the connect deadline plus the
    /// overall deadline plus name resolution (see `tatami_tcp::io` for the
    /// resolution caveat). Never prints.
    #[must_use]
    pub fn run(options: &Options) -> Report {
        let stream = match options.io.connect(&options.host, options.port) {
            Ok(s) => s,
            Err(e) => return Report::unconnected(options, Completion::ConnectFailed(e)),
        };
        let policy = PinnedSha256(options.pin);
        match run_handshake(stream, options.config.clone(), &policy, &options.io) {
            Ok(run) => from_run(options, run),
            Err(e) => Report::unconnected(options, Completion::NotStarted(e)),
        }
    }

    fn from_run(options: &Options, run: HandshakeRun) -> Report {
        let completion = match run.end {
            HandshakeEnd::Finished(outcome) => Completion::from_outcome(outcome),
            HandshakeEnd::TimedOut {
                phase,
                pending_bytes,
            } => Completion::TimedOut {
                phase,
                pending_bytes,
            },
            HandshakeEnd::Io { phase, error } => Completion::Io { phase, error },
        };
        Report {
            host: options.host.clone(),
            port: options.port,
            pin: options.pin,
            peer: Some(run.peer),
            local: Some(run.local),
            handshake: Some(run.report),
            completion,
            elapsed: Some(run.elapsed),
        }
    }

    // ----- text ----------------------------------------------------------

    impl Report {
        /// Writes the human-readable report. All peer-supplied text is
        /// escaped; lists are printed in advertised order and each direction
        /// separately; advertised and selected values are shown side by side.
        pub fn write_text(&self, w: &mut dyn fmt::Write) -> fmt::Result {
            writeln!(w, "Target: {}", target(&self.host, self.port))?;
            match (self.peer, self.local) {
                (Some(peer), Some(local)) => {
                    writeln!(w, "Connected to: {peer} (local address {local})")?;
                }
                (Some(peer), None) => writeln!(w, "Connected to: {peer}")?,
                _ => writeln!(w, "Connected to: (not connected)")?,
            }

            if let Some(h) = &self.handshake {
                self.write_observed(w, h)?;
            }

            writeln!(
                w,
                "Outcome: {} (code: {})",
                completion_line(&self.completion, self.handshake.as_ref()),
                self.completion.code()
            )?;
            writeln!(w, "User authentication: not attempted")?;
            writeln!(w, "user_authenticated: false")?;
            writeln!(w, "Rekeying: not supported by this diagnostic")?;
            if let Some(e) = self.elapsed {
                writeln!(w, "Elapsed after connect: {:.3}s", e.as_secs_f64())?;
            }
            Ok(())
        }

        fn write_observed(&self, w: &mut dyn fmt::Write, h: &HandshakeReport) -> fmt::Result {
            writeln!(
                w,
                "Client identification sent: {}",
                escape_bytes(&h.client_identification)
            )?;
            for line in &h.server_prelude_lines {
                writeln!(w, "Server pre-identification line: {}", quoted(line))?;
            }
            match &h.server_identification {
                Some(i) => {
                    writeln!(w, "Server identification: {}", escape_bytes(&i.line))?;
                    writeln!(w, "  protocol version: {}", i.protocol_version)?;
                    writeln!(w, "  software version: {}", i.software_version)?;
                    if let Some(c) = &i.comments {
                        writeln!(w, "  comments: {}", quoted(c))?;
                    }
                    for a in &h.server_identification_anomalies {
                        writeln!(w, "  anomaly: {a}")?;
                    }
                }
                None => writeln!(w, "Server identification: not received")?,
            }
            for m in &h.skipped_messages {
                write_skipped(w, m)?;
            }

            write_negotiation(w, h, &self.completion)?;
            write_strict_kex(w, h)?;
            write_host_key(w, h)?;
            write_trust(w, self.pin, h)?;

            writeln!(w, "Protected transport:")?;
            writeln!(w, "  NEWKEYS sent: {}", yes_no(h.newkeys_sent))?;
            writeln!(w, "  NEWKEYS received: {}", yes_no(h.newkeys_received))?;
            writeln!(w, "  protected packets sent: {}", h.protected_packets_sent)?;
            writeln!(
                w,
                "  protected packets received: {}",
                h.protected_packets_received
            )?;

            write_ext_info(w, h)?;

            match &h.service_accepted {
                Some(s) => writeln!(w, "Service accepted: {}", escape_bytes(s.as_bytes()))?,
                None => writeln!(w, "Service: SERVICE_ACCEPT not received")?,
            }
            if let Some(d) = &h.server_disconnect {
                writeln!(
                    w,
                    "Server DISCONNECT: reason {}{}: {}",
                    d.reason_code,
                    reason_suffix(d.reason_code),
                    quoted(&d.description)
                )?;
            }
            Ok(())
        }
    }

    fn write_skipped(w: &mut dyn fmt::Write, m: &SkippedMessage) -> fmt::Result {
        match m {
            SkippedMessage::Ignored { data_len } => {
                writeln!(w, "Server SSH_MSG_IGNORE: {data_len} data byte(s)")
            }
            SkippedMessage::Debug {
                always_display,
                message,
                language_tag,
            } => writeln!(
                w,
                "Server SSH_MSG_DEBUG (always_display={always_display}, lang={}): {}",
                quoted(language_tag),
                quoted(message)
            ),
            SkippedMessage::Unimplemented { sequence_number } => {
                writeln!(
                    w,
                    "Server SSH_MSG_UNIMPLEMENTED for sequence {sequence_number}"
                )
            }
        }
    }

    /// One negotiated field: both advertised lists and the selection.
    fn write_field(
        w: &mut dyn fmt::Write,
        label: &str,
        client: &[String],
        server: Option<&[String]>,
        selected: Option<&str>,
        note: Option<&str>,
    ) -> fmt::Result {
        writeln!(w, "  {label}:")?;
        writeln!(w, "    client advertised: {}", list(client))?;
        match server {
            Some(s) => writeln!(w, "    server advertised: {}", list(s))?,
            None => writeln!(w, "    server advertised: (no server KEXINIT)")?,
        }
        match selected {
            Some(s) => writeln!(w, "    selected: {}", escape_bytes(s.as_bytes()))?,
            None => writeln!(w, "    selected: (none)")?,
        }
        if let Some(n) = note {
            writeln!(w, "    note: {n}")?;
        }
        Ok(())
    }

    fn write_negotiation(
        w: &mut dyn fmt::Write,
        h: &HandshakeReport,
        completion: &Completion,
    ) -> fmt::Result {
        let c = &h.advertised.client;
        let s = h.advertised.server.as_ref();
        let sel = h.selected.as_ref();
        writeln!(
            w,
            "Algorithm negotiation (RFC 4253 §7.1; markers are never selected):"
        )?;
        write_field(
            w,
            "KEX",
            &c.kex_algorithms,
            s.map(|s| &s.kex_algorithms[..]),
            sel.map(|n| n.kex.as_str()),
            None,
        )?;
        write_field(
            w,
            "Host-key algorithm",
            &c.server_host_key_algorithms,
            s.map(|s| &s.server_host_key_algorithms[..]),
            sel.map(|n| n.host_key.as_str()),
            None,
        )?;
        write_field(
            w,
            "Cipher client->server",
            &c.encryption_client_to_server,
            s.map(|s| &s.encryption_client_to_server[..]),
            sel.map(|n| n.encryption_client_to_server.as_str()),
            None,
        )?;
        write_field(
            w,
            "Cipher server->client",
            &c.encryption_server_to_client,
            s.map(|s| &s.encryption_server_to_client[..]),
            sel.map(|n| n.encryption_server_to_client.as_str()),
            None,
        )?;
        let aead_note = "MAC lists ignored per draft-miller-sshm-aes-gcm-01 §2 (AEAD cipher)";
        write_field(
            w,
            "MAC client->server",
            &c.mac_client_to_server,
            s.map(|s| &s.mac_client_to_server[..]),
            sel.map(|n| n.mac_client_to_server.as_str()),
            sel.filter(|n| is_aead(n.encryption_client_to_server.as_bytes()))
                .map(|_| aead_note),
        )?;
        write_field(
            w,
            "MAC server->client",
            &c.mac_server_to_client,
            s.map(|s| &s.mac_server_to_client[..]),
            sel.map(|n| n.mac_server_to_client.as_str()),
            sel.filter(|n| is_aead(n.encryption_server_to_client.as_bytes()))
                .map(|_| aead_note),
        )?;
        write_field(
            w,
            "Compression client->server",
            &c.compression_client_to_server,
            s.map(|s| &s.compression_client_to_server[..]),
            sel.map(|n| n.compression_client_to_server.as_str()),
            None,
        )?;
        write_field(
            w,
            "Compression server->client",
            &c.compression_server_to_client,
            s.map(|s| &s.compression_server_to_client[..]),
            sel.map(|n| n.compression_server_to_client.as_str()),
            None,
        )?;
        writeln!(
            w,
            "  Markers offered by client: {}",
            list(&markers(&c.kex_algorithms))
        )?;
        match s {
            Some(s) => {
                writeln!(
                    w,
                    "  Markers offered by server: {}",
                    list(&markers(&s.kex_algorithms))
                )?;
                writeln!(
                    w,
                    "  EXT_INFO advertised by server (ext-info-s): {}",
                    yes_no(s.kex_algorithms.iter().any(|n| n == "ext-info-s"))
                )?;
                writeln!(
                    w,
                    "  Server first_kex_packet_follows: {}",
                    s.first_kex_packet_follows
                )?;
                if h.server_guess_discarded {
                    writeln!(
                        w,
                        "  Server guessed wrong; its first KEX packet was discarded"
                    )?;
                }
            }
            None => writeln!(w, "  Markers offered by server: (no server KEXINIT)")?,
        }
        let result = match (sel, completion, s) {
            (Some(_), _, _) => String::from("negotiated"),
            (None, Completion::NegotiationFailed(e), _) => {
                alloc::format!("failed; {}", negotiation_failure(e, c, s))
            }
            (None, _, None) => String::from("not reached (no server KEXINIT)"),
            (None, _, Some(_)) => String::from("not performed"),
        };
        writeln!(w, "  Result: {result}")
    }

    /// Names of the failing field's two lists, for a negotiation failure
    /// message that shows what each side offered.
    fn negotiation_failure(
        e: &NegotiationError,
        c: &OwnedKexInit,
        s: Option<&OwnedKexInit>,
    ) -> String {
        let offered = |what: &str, cl: &[String], sv: Option<&[String]>| {
            alloc::format!(
                "no common {what}; client offered {}, server offered {}",
                list(cl),
                sv.map(list).unwrap_or_else(|| String::from("(nothing)"))
            )
        };
        match e {
            NegotiationError::NoCommonKex => offered(
                "key-exchange method (markers excluded)",
                &c.kex_algorithms,
                s.map(|s| &s.kex_algorithms[..]),
            ),
            NegotiationError::NoCommonHostKey => offered(
                "host-key algorithm",
                &c.server_host_key_algorithms,
                s.map(|s| &s.server_host_key_algorithms[..]),
            ),
            NegotiationError::NoCommonCipher(d) => {
                let (cl, sv) = match d {
                    Direction::ClientToServer => (
                        &c.encryption_client_to_server,
                        s.map(|s| &s.encryption_client_to_server[..]),
                    ),
                    Direction::ServerToClient => (
                        &c.encryption_server_to_client,
                        s.map(|s| &s.encryption_server_to_client[..]),
                    ),
                };
                offered(&alloc::format!("cipher {d}"), cl, sv)
            }
            NegotiationError::NoCommonCompression(d) => {
                let (cl, sv) = match d {
                    Direction::ClientToServer => (
                        &c.compression_client_to_server,
                        s.map(|s| &s.compression_client_to_server[..]),
                    ),
                    Direction::ServerToClient => (
                        &c.compression_server_to_client,
                        s.map(|s| &s.compression_server_to_client[..]),
                    ),
                };
                offered(&alloc::format!("compression algorithm {d}"), cl, sv)
            }
            NegotiationError::NoMacImplemented(_)
            | NegotiationError::UnsupportedSelection { .. } => e.to_string(),
        }
    }

    fn write_strict_kex(w: &mut dyn fmt::Write, h: &HandshakeReport) -> fmt::Result {
        let s: &StrictKex = &h.strict_kex;
        writeln!(w, "Strict KEX (draft-ietf-sshm-strict-kex):")?;
        writeln!(
            w,
            "  offered by client: {}",
            marker_names(s.offered_pre_standard, s.offered_standard, "kex-strict-c")
        )?;
        if h.advertised.server.is_some() {
            writeln!(
                w,
                "  offered by server: {}",
                marker_names(s.server_pre_standard, s.server_standard, "kex-strict-s")
            )?;
        } else {
            writeln!(w, "  offered by server: (no server KEXINIT)")?;
        }
        writeln!(w, "  negotiated: {}", s.negotiated)?;
        writeln!(
            w,
            "  KEXINIT was first packet: {}",
            match h.kexinit_was_first_packet {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            }
        )
    }

    fn marker_names(pre_standard: bool, standard: bool, base: &str) -> String {
        let mut names = Vec::new();
        if pre_standard {
            names.push(alloc::format!("{base}-v00@openssh.com (pre-standard)"));
        }
        if standard {
            names.push(alloc::format!("{base} (standard)"));
        }
        if names.is_empty() {
            String::from("(none)")
        } else {
            names.join(", ")
        }
    }

    fn write_host_key(w: &mut dyn fmt::Write, h: &HandshakeReport) -> fmt::Result {
        let Some(k) = &h.host_key else {
            return writeln!(w, "Server host key: not received");
        };
        writeln!(w, "Server host key:")?;
        writeln!(w, "  algorithm: {}", escape_bytes(k.algorithm.as_bytes()))?;
        writeln!(w, "  fingerprint: {}", k.fingerprint)?;
        writeln!(w, "  blob length: {} byte(s)", k.blob_len)?;
        writeln!(
            w,
            "  signature: {}",
            match h.signature_valid {
                Some(true) => "valid",
                Some(false) => "invalid",
                None => "not verified",
            }
        )?;
        if let Some(e) = &h.signature_error {
            writeln!(w, "  signature error: {}", escape_bytes(e.as_bytes()))?;
        }
        Ok(())
    }

    fn write_trust(
        w: &mut dyn fmt::Write,
        pin: Sha256Fingerprint,
        h: &HandshakeReport,
    ) -> fmt::Result {
        writeln!(w, "Host trust:")?;
        writeln!(w, "  source: pinned fingerprint (--host-key-sha256)")?;
        writeln!(w, "  pinned: {pin}")?;
        writeln!(w, "  result: {}", trust_text(h.trust))
    }

    fn trust_text(t: Option<TrustDecision>) -> &'static str {
        match t {
            Some(TrustDecision::Trusted {
                source: TrustSource::PinnedFingerprint,
            }) => "trusted",
            Some(TrustDecision::Untrusted {
                reason: UntrustedReason::FingerprintMismatch,
            }) => "untrusted (fingerprint mismatch)",
            Some(TrustDecision::Untrusted {
                reason: UntrustedReason::NoPolicy,
            }) => "untrusted (no policy)",
            None => "not decided (host key not verified)",
        }
    }

    fn write_ext_info(w: &mut dyn fmt::Write, h: &HandshakeReport) -> fmt::Result {
        let Some(e) = &h.ext_info else {
            return writeln!(w, "EXT_INFO (RFC 8308): protected phase not reached");
        };
        writeln!(w, "EXT_INFO (RFC 8308):")?;
        writeln!(w, "  received: {}", yes_no(e.received))?;
        match &e.server_sig_algs {
            Some(algs) => writeln!(w, "  server-sig-algs: {}", list(algs))?,
            None => writeln!(w, "  server-sig-algs: (absent)")?,
        }
        let others: Vec<String> = e
            .extension_names
            .iter()
            .filter(|n| n.as_str() != "server-sig-algs")
            .cloned()
            .collect();
        writeln!(w, "  other extensions: {}", list(&others))
    }

    fn completion_line(c: &Completion, h: Option<&HandshakeReport>) -> String {
        match c {
            Completion::Complete => String::from(
                "completed; key exchange, host-key verification, pinned-fingerprint \
                 match and service request all succeeded",
            ),
            Completion::HostNotTrusted {
                reason: UntrustedReason::FingerprintMismatch,
            } => String::from(
                "host key not trusted; presented fingerprint does not match \
                 --host-key-sha256 (no NEWKEYS sent)",
            ),
            Completion::HostNotTrusted {
                reason: UntrustedReason::NoPolicy,
            } => String::from("host key not trusted; no trust policy (no NEWKEYS sent)"),
            Completion::SignatureInvalid => {
                String::from("host signature over the exchange hash is invalid")
            }
            Completion::NegotiationFailed(e) => match h {
                Some(h) => alloc::format!(
                    "negotiation failed; {}",
                    negotiation_failure(e, &h.advertised.client, h.advertised.server.as_ref())
                ),
                None => alloc::format!("negotiation failed; {e}"),
            },
            Completion::StrictKexViolation { detail } => {
                alloc::format!("strict KEX violation: {}", escape_bytes(detail.as_bytes()))
            }
            Completion::ProtocolError(v) => alloc::format!("protocol error: {v}"),
            Completion::ServerDisconnected {
                reason_code,
                description,
            } => alloc::format!(
                "server disconnected; reason {reason_code}{}: {}",
                reason_suffix(*reason_code),
                quoted(description)
            ),
            Completion::RekeyNotSupported => String::from(
                "server requested a re-exchange; not supported by this diagnostic (DISCONNECT sent)",
            ),
            Completion::UnexpectedMessage { number, phase } => alloc::format!(
                "unexpected {} while {phase}",
                msg::name(*number)
                    .map(String::from)
                    .unwrap_or_else(|| alloc::format!("message number {number}"))
            ),
            Completion::TagMismatch => String::from("protected packet failed authentication"),
            Completion::Eof { phase } => {
                alloc::format!("incomplete; connection closed by peer while {phase}")
            }
            Completion::InputOverflow(o) => alloc::format!("incomplete; {o}"),
            Completion::Limit(l) => alloc::format!("incomplete; limit exceeded: {l}"),
            Completion::TimedOut {
                phase,
                pending_bytes,
            } => alloc::format!(
                "incomplete; deadline passed while {phase} ({pending_bytes} unparsed byte(s))"
            ),
            Completion::Io { phase, error } => {
                alloc::format!("incomplete; socket error while {phase}: {error}")
            }
            Completion::ConnectFailed(e) => alloc::format!("not connected; {e}"),
            Completion::NotStarted(e) => alloc::format!("not started; {e}"),
        }
    }

    fn reason_suffix(code: u32) -> String {
        disconnect_reason::name(code)
            .map(|n| alloc::format!(" ({n})"))
            .unwrap_or_default()
    }

    fn markers(names: &[String]) -> Vec<String> {
        names
            .iter()
            .filter(|n| classify_kex_name(n.as_bytes()) != KexName::Method)
            .cloned()
            .collect()
    }

    const fn yes_no(b: bool) -> &'static str {
        if b { "yes" } else { "no" }
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

    // ----- JSON ----------------------------------------------------------

    impl Report {
        /// One JSON object (schema 1, `event: "tcp_handshake"`); see the
        /// module documentation for the field list. Raw bytes are lossy UTF-8
        /// text plus hex; no key material is present.
        #[must_use]
        pub fn to_json(&self) -> Value {
            let h = self.handshake.as_ref();
            let (trust_source, untrusted_reason) = match h.and_then(|h| h.trust) {
                Some(TrustDecision::Trusted {
                    source: TrustSource::PinnedFingerprint,
                }) => (Some("pinned_fingerprint"), None),
                Some(TrustDecision::Untrusted {
                    reason: UntrustedReason::FingerprintMismatch,
                }) => (None, Some("fingerprint_mismatch")),
                Some(TrustDecision::Untrusted {
                    reason: UntrustedReason::NoPolicy,
                }) => (None, Some("no_policy")),
                None => (None, None),
            };
            let negotiation_error_code = match &self.completion {
                Completion::NegotiationFailed(e) => Some(e.code()),
                _ => None,
            };
            Value::object()
                .field("schema", 1u64)
                .field("event", "tcp_handshake")
                .field(
                    "target",
                    Value::object()
                        .field("host", self.host.as_str())
                        .field("port", u64::from(self.port)),
                )
                .opt("peer", self.peer.map(|a| a.to_string()))
                .opt("local", self.local.map(|a| a.to_string()))
                .field("pinned_fingerprint_sha256", self.pin.to_string())
                .opt("phase", h.map(|h| h.phase.code()))
                .opt(
                    "client_identification",
                    h.map(|h| Value::lossy_text(&h.client_identification)),
                )
                .field(
                    "server_prelude_lines",
                    Value::Array(
                        h.map(|h| {
                            h.server_prelude_lines
                                .iter()
                                .map(|l| bytes_record(l))
                                .collect()
                        })
                        .unwrap_or_default(),
                    ),
                )
                .opt(
                    "server_identification",
                    h.and_then(|h| h.server_identification.as_ref().map(|i| ident_record(i, h))),
                )
                .field(
                    "skipped_messages",
                    Value::Array(
                        h.map(|h| h.skipped_messages.iter().map(skipped_record).collect())
                            .unwrap_or_default(),
                    ),
                )
                .opt(
                    "advertised",
                    h.map(|h| {
                        Value::object()
                            .field("client", kexinit_record(&h.advertised.client))
                            .opt("server", h.advertised.server.as_ref().map(kexinit_record))
                    }),
                )
                .opt(
                    "selected",
                    h.and_then(|h| h.selected.as_ref()).map(selected_record),
                )
                .opt("strict_kex", h.map(|h| strict_kex_record(&h.strict_kex)))
                .opt(
                    "kexinit_was_first_packet",
                    h.and_then(|h| h.kexinit_was_first_packet),
                )
                .field(
                    "server_guess_discarded",
                    h.is_some_and(|h| h.server_guess_discarded),
                )
                .opt(
                    "host_key",
                    h.and_then(|h| h.host_key.as_ref()).map(|k| {
                        Value::object()
                            .field("algorithm", k.algorithm.as_str())
                            .field("fingerprint_sha256", k.fingerprint.to_string())
                            .field("blob_len", k.blob_len)
                    }),
                )
                .opt(
                    "fingerprint_sha256",
                    h.and_then(|h| h.host_key.as_ref())
                        .map(|k| k.fingerprint.to_string()),
                )
                .opt(
                    "host_key_signature_valid",
                    h.and_then(|h| h.signature_valid),
                )
                .opt(
                    "signature_error",
                    h.and_then(|h| h.signature_error.as_deref()),
                )
                .field("trust_policy", "pinned_fingerprint")
                .opt(
                    "host_trusted",
                    h.and_then(|h| h.trust).map(|t| t.is_trusted()),
                )
                .opt("trust_source", trust_source)
                .opt("untrusted_reason", untrusted_reason)
                .field(
                    "key_exchange_completed",
                    h.is_some_and(|h| h.newkeys_sent && h.newkeys_received),
                )
                .field("newkeys_sent", h.is_some_and(|h| h.newkeys_sent))
                .field("newkeys_received", h.is_some_and(|h| h.newkeys_received))
                .field(
                    "protected_packets_sent",
                    h.map_or(0, |h| h.protected_packets_sent),
                )
                .field(
                    "protected_packets_received",
                    h.map_or(0, |h| h.protected_packets_received),
                )
                .opt(
                    "ext_info",
                    h.and_then(|h| h.ext_info.as_ref()).map(|e| {
                        Value::object()
                            .field("received", e.received)
                            .opt(
                                "server_sig_algs",
                                e.server_sig_algs
                                    .as_ref()
                                    .map(|a| Value::strings(a.iter().cloned())),
                            )
                            .field(
                                "extension_names",
                                Value::strings(e.extension_names.iter().cloned()),
                            )
                    }),
                )
                .opt(
                    "service_accepted",
                    h.and_then(|h| h.service_accepted.as_deref()),
                )
                .opt(
                    "server_disconnect",
                    h.and_then(|h| h.server_disconnect.as_ref()).map(|d| {
                        Value::object()
                            .field("reason_code", d.reason_code)
                            .opt("reason_name", disconnect_reason::name(d.reason_code))
                            .field("description", Value::lossy_text(&d.description))
                            .field("description_hex", Value::hex(&d.description))
                    }),
                )
                .field("outcome", completion_line(&self.completion, h))
                .field("outcome_code", self.completion.code())
                .opt("negotiation_error_code", negotiation_error_code)
                .field("user_authenticated", false)
                .field("rekey_supported", false)
                .opt(
                    "elapsed_ms",
                    self.elapsed
                        .map(|e| u64::try_from(e.as_millis()).unwrap_or(u64::MAX)),
                )
                .build()
        }
    }

    fn bytes_record(bytes: &[u8]) -> Value {
        Value::object()
            .field("text", Value::lossy_text(bytes))
            .field("hex", Value::hex(bytes))
            .build()
    }

    fn ident_record(i: &OwnedIdentification, h: &HandshakeReport) -> Value {
        Value::object()
            .field("line", Value::lossy_text(&i.line))
            .field("protocol_version", i.protocol_version.as_str())
            .field("software_version", i.software_version.as_str())
            .opt("comments", i.comments.as_deref().map(Value::lossy_text))
            .opt("comments_hex", i.comments.as_deref().map(Value::hex))
            .field(
                "anomalies",
                Value::strings(h.server_identification_anomalies.iter().map(|a| a.code())),
            )
            .build()
    }

    fn skipped_record(m: &SkippedMessage) -> Value {
        match m {
            SkippedMessage::Ignored { data_len } => Value::object()
                .field("type", "ignore")
                .field("data_len", *data_len)
                .build(),
            SkippedMessage::Debug {
                always_display,
                message,
                language_tag,
            } => Value::object()
                .field("type", "debug")
                .field("always_display", *always_display)
                .field("message", Value::lossy_text(message))
                .field("message_hex", Value::hex(message))
                .field("language_tag", Value::lossy_text(language_tag))
                .build(),
            SkippedMessage::Unimplemented { sequence_number } => Value::object()
                .field("type", "unimplemented")
                .field("sequence_number", *sequence_number)
                .build(),
        }
    }

    fn kexinit_record(k: &OwnedKexInit) -> Value {
        let strings = |v: &[String]| Value::strings(v.iter().cloned());
        Value::object()
            .field("cookie_hex", Value::hex(&k.cookie))
            .field("kex_algorithms", strings(&k.kex_algorithms))
            .field("kex_markers", strings(&markers(&k.kex_algorithms)))
            .field(
                "server_host_key_algorithms",
                strings(&k.server_host_key_algorithms),
            )
            .field(
                "encryption_client_to_server",
                strings(&k.encryption_client_to_server),
            )
            .field(
                "encryption_server_to_client",
                strings(&k.encryption_server_to_client),
            )
            .field("mac_client_to_server", strings(&k.mac_client_to_server))
            .field("mac_server_to_client", strings(&k.mac_server_to_client))
            .field(
                "compression_client_to_server",
                strings(&k.compression_client_to_server),
            )
            .field(
                "compression_server_to_client",
                strings(&k.compression_server_to_client),
            )
            .field(
                "languages_client_to_server",
                strings(&k.languages_client_to_server),
            )
            .field(
                "languages_server_to_client",
                strings(&k.languages_server_to_client),
            )
            .field("first_kex_packet_follows", k.first_kex_packet_follows)
            .field("reserved", k.reserved)
            .build()
    }

    fn selected_record(n: &Negotiated) -> Value {
        Value::object()
            .field("kex", n.kex.as_str())
            .field("host_key", n.host_key.as_str())
            .field(
                "encryption_client_to_server",
                n.encryption_client_to_server.as_str(),
            )
            .field(
                "encryption_server_to_client",
                n.encryption_server_to_client.as_str(),
            )
            .field("mac_client_to_server", n.mac_client_to_server.as_str())
            .field("mac_server_to_client", n.mac_server_to_client.as_str())
            .field(
                "compression_client_to_server",
                n.compression_client_to_server.as_str(),
            )
            .field(
                "compression_server_to_client",
                n.compression_server_to_client.as_str(),
            )
            .field("ext_info", n.ext_info)
            .field("server_guess_wrong", n.server_guess_wrong)
            .build()
    }

    fn strict_kex_record(s: &StrictKex) -> Value {
        Value::object()
            .field("offered_pre_standard", s.offered_pre_standard)
            .field("offered_standard", s.offered_standard)
            .field("server_pre_standard", s.server_pre_standard)
            .field("server_standard", s.server_standard)
            .field("negotiated", s.negotiated)
            .build()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::TcpListener;

        fn pin() -> Sha256Fingerprint {
            "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
                .parse()
                .unwrap()
        }

        #[test]
        fn connect_refused_is_reported_without_a_handshake_report() {
            let port = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            let mut options = Options::new("127.0.0.1", port, pin());
            options.io.connect_timeout = Duration::from_secs(2);
            let report = run(&options);
            assert!(!report.is_complete());
            assert!(matches!(report.completion, Completion::ConnectFailed(_)));
            assert!(report.handshake.is_none());
            assert_eq!(report.completion.code(), "connect_failed");

            let mut text = String::new();
            report.write_text(&mut text).unwrap();
            assert!(text.contains("Connected to: (not connected)"));
            assert!(text.contains("Outcome: not connected;"));
            assert!(text.contains("(code: connect_failed)"));
            assert!(text.contains("user_authenticated: false"));
            assert!(text.contains("Rekeying: not supported by this diagnostic"));

            let json = report.to_json().to_json();
            assert!(json.starts_with("{\"schema\":1,\"event\":\"tcp_handshake\","));
            assert!(json.contains("\"outcome_code\":\"connect_failed\""));
            assert!(json.contains("\"user_authenticated\":false"));
            assert!(json.contains("\"key_exchange_completed\":false"));
            assert!(json.contains("\"host_trusted\":null"));
            assert!(json.contains("\"advertised\":null"));
            assert!(json.contains("\"strict_kex\":null"));
            assert!(json.contains(&alloc::format!(
                "\"pinned_fingerprint_sha256\":\"{}\"",
                pin()
            )));
        }

        #[test]
        fn peer_that_closes_after_identification_is_eof() {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let peer = std::thread::spawn(move || {
                use std::io::{Read, Write};
                let (mut s, _) = listener.accept().unwrap();
                let mut b = [0u8; 1];
                let mut got = Vec::new();
                while !got.ends_with(b"\n") {
                    s.read_exact(&mut b).unwrap();
                    got.push(b[0]);
                }
                s.write_all(b"Hello \x1b[1m!\r\nSSH-2.0-Closer c\"m\r\n")
                    .unwrap();
                // Signal EOF, then drain the client's KEXINIT so the close
                // is a FIN rather than an RST for unread data.
                s.shutdown(std::net::Shutdown::Write).unwrap();
                let mut sink = [0u8; 1024];
                while matches!(s.read(&mut sink), Ok(n) if n > 0) {}
            });
            let mut options = Options::new("127.0.0.1", port, pin());
            options.io.overall_timeout = Duration::from_secs(5);
            let report = run(&options);
            peer.join().unwrap();

            assert!(matches!(
                report.completion,
                Completion::Eof {
                    phase: Phase::ServerKexInit
                }
            ));
            let h = report.handshake.as_ref().unwrap();
            assert_eq!(
                h.server_identification.as_ref().unwrap().software_version,
                "Closer"
            );

            let mut text = String::new();
            report.write_text(&mut text).unwrap();
            assert!(text.contains("Server pre-identification line: \"Hello \\x1b[1m!\""));
            assert!(
                !text.contains('\x1b'),
                "escape sequences must not reach the text"
            );
            assert!(text.contains("Server identification: SSH-2.0-Closer c\"m"));
            assert!(text.contains("  comments: \"c\\\"m\""));
            assert!(text.contains("    server advertised: (no server KEXINIT)"));
            assert!(text.contains("  Result: not reached (no server KEXINIT)"));
            assert!(text.contains("  offered by client: kex-strict-c-v00@openssh.com (pre-standard), kex-strict-c (standard)"));
            assert!(text.contains("  negotiated: false"));
            assert!(text.contains("  KEXINIT was first packet: unknown"));
            assert!(text.contains("Server host key: not received"));
            assert!(text.contains("  result: not decided (host key not verified)"));
            assert!(text.contains("  NEWKEYS sent: no"));
            assert!(text.contains("EXT_INFO (RFC 8308): protected phase not reached"));
            assert!(text.contains("Service: SERVICE_ACCEPT not received"));
            assert!(!text.contains("Service accepted"));
            assert!(text.contains(
                "Outcome: incomplete; connection closed by peer while awaiting server KEXINIT (code: eof)"
            ));

            let json = report.to_json().to_json();
            assert!(json.contains("\"outcome_code\":\"eof\""));
            assert!(json.contains("\"software_version\":\"Closer\""));
            assert!(json.contains("\"text\":\"Hello \\u001b[1m!\""));
            assert!(json.contains("\"offered_pre_standard\":true"));
            assert!(json.contains(
                "\"kex_markers\":[\"ext-info-c\",\"kex-strict-c-v00@openssh.com\",\"kex-strict-c\"]"
            ));
            assert!(json.contains("\"server\":null"));
            assert!(json.contains("\"service_accepted\":null"));
        }

        #[test]
        fn completion_codes_and_marker_names() {
            assert_eq!(Completion::Complete.code(), "completed");
            assert!(Completion::Complete.is_complete());
            assert!(
                !Completion::HostNotTrusted {
                    reason: UntrustedReason::FingerprintMismatch
                }
                .is_complete()
            );
            assert_eq!(
                Completion::from_outcome(HandshakeOutcome::TagMismatch).code(),
                HandshakeOutcome::TagMismatch.code()
            );
            assert_eq!(marker_names(false, false, "kex-strict-s"), "(none)");
            assert_eq!(
                marker_names(true, false, "kex-strict-s"),
                "kex-strict-s-v00@openssh.com (pre-standard)"
            );
            assert_eq!(target("2001:db8::1", 22), "[2001:db8::1]:22");
            assert_eq!(
                completion_line(
                    &Completion::UnexpectedMessage {
                        number: msg::KEXINIT,
                        phase: Phase::Service
                    },
                    None
                ),
                "unexpected SSH_MSG_KEXINIT while awaiting SERVICE_ACCEPT"
            );
            assert_eq!(
                completion_line(
                    &Completion::UnexpectedMessage {
                        number: 200,
                        phase: Phase::EcdhReply
                    },
                    None
                ),
                "unexpected message number 200 while awaiting KEX_ECDH_REPLY"
            );
        }
    }
}
