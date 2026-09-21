//! Diagnostic QUIC/TLS handshake client: connects, completes (or fails) one
//! TLS 1.3 handshake over QUIC v1, optionally confirms that the TLS
//! exporter is available, and closes. No application data is ever sent:
//! the client opens no stream, sends no DATAGRAM frame and therefore
//! cannot emit an SSH identification or `KEXINIT` by construction.
//!
//! [`ClientCore`] is sans-I/O; [`run`] drives it over a blocking UDP socket
//! with one deadline. The result never contains exporter output, key
//! material or the peer's certificate: only outcomes, names and sizes.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::string::{String, ToString as _};
use std::time::{Duration, Instant};
use std::vec::Vec;

use quinn_proto::crypto::rustls::HandshakeData;
use quinn_proto::{Connection, ConnectionHandle, DatagramEvent, Endpoint, Event, VarInt};

use super::server::connection_error_text;
use super::tls::{ClientTrust, ServerNameKind, check_server_name, client_crypto};
use super::udp::{recv_with_timeout, send_all};
use super::{
    ConfigError, DEFAULT_HANDSHAKE_TIMEOUT, Datagram, QUIC_VERSION_1, endpoint_config,
    transport_config,
};

/// Exporter label used by the diagnostic probe. Experimental; it is not the
/// session-binding label (P-04 is open) and its output is never persisted.
pub const PROBE_LABEL: &[u8] = b"EXPERIMENTAL-tatami-ssh-binding-v0";
/// Exporter context used by the diagnostic probe.
pub const PROBE_CONTEXT: &[u8] = b"tatami-diag-probe";

/// TLS exporter availability probe (RFC 8446 §7.5 via `quinn-proto`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExporterProbe {
    /// Exporter label.
    pub label: Vec<u8>,
    /// Exporter context.
    pub context: Vec<u8>,
    /// Output length requested (1..=255).
    pub len: usize,
}

impl Default for ExporterProbe {
    fn default() -> Self {
        ExporterProbe {
            label: PROBE_LABEL.to_vec(),
            context: PROBE_CONTEXT.to_vec(),
            len: 32,
        }
    }
}

/// Client policy.
#[derive(Clone, Debug)]
pub struct DiagClientConfig {
    /// Server address.
    pub remote: SocketAddr,
    /// TLS server name. A DNS name is sent as SNI; an IP literal is not
    /// (RFC 6066 §3).
    pub server_name: String,
    /// ALPN protocols to offer, in preference order. Required, explicit,
    /// experimental and unregistered.
    pub alpn: Vec<Vec<u8>>,
    /// How to judge the server's identity.
    pub trust: ClientTrust,
    /// Deadline for the whole handshake; also the QUIC idle timeout.
    pub handshake_timeout: Duration,
    /// After completing, wait this long for the server's `CONNECTION_CLOSE`
    /// before closing locally (keeps both records deterministic).
    pub linger: Duration,
    /// Optional exporter availability probe run after completion.
    pub exporter: Option<ExporterProbe>,
}

impl DiagClientConfig {
    /// Defaults with the given required inputs.
    #[must_use]
    pub fn new(
        remote: SocketAddr,
        server_name: impl Into<String>,
        alpn: Vec<Vec<u8>>,
        trust: ClientTrust,
    ) -> Self {
        DiagClientConfig {
            remote,
            server_name: server_name.into(),
            alpn,
            trust,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            linger: Duration::from_secs(1),
            exporter: None,
        }
    }

    /// Checks the configuration without touching the network.
    pub fn validate(&self) -> Result<ServerNameKind, ConfigError> {
        super::validate_alpn(&self.alpn)?;
        if self.handshake_timeout.is_zero() {
            return Err(ConfigError::BadDuration("handshake_timeout"));
        }
        if let Some(p) = &self.exporter {
            if p.len == 0 || p.len > 255 {
                return Err(ConfigError::Exporter("len must be 1..=255"));
            }
            if p.label.is_empty() {
                return Err(ConfigError::Exporter("label must not be empty"));
            }
        }
        check_server_name(&self.server_name)
    }
}

/// How the handshake ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeResult {
    /// Completed.
    Completed,
    /// Lost before completion; `reason` is the `quinn-proto` error text
    /// (peer reason phrases escaped).
    Failed {
        /// Error text.
        reason: String,
    },
    /// The deadline passed.
    TimedOut,
}

impl HandshakeResult {
    /// Stable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            HandshakeResult::Completed => "completed",
            HandshakeResult::Failed { .. } => "failed",
            HandshakeResult::TimedOut => "timed_out",
        }
    }

    /// `true` only for [`HandshakeResult::Completed`].
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        matches!(self, HandshakeResult::Completed)
    }
}

/// Result of the exporter probe: availability and requested size only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExporterResult {
    /// `export_keying_material` succeeded after the handshake.
    pub available: bool,
    /// Bytes requested.
    pub len: usize,
}

/// Everything the client observed. Contains no secrets.
#[derive(Clone, Debug)]
pub struct ClientOutcome {
    /// Server address.
    pub remote: SocketAddr,
    /// Local socket address, if a socket was bound.
    pub local: Option<SocketAddr>,
    /// Outcome.
    pub handshake: HandshakeResult,
    /// Negotiated ALPN (`HandshakeData::protocol`).
    pub negotiated_alpn: Option<Vec<u8>>,
    /// What we offered.
    pub offered_alpn: Vec<Vec<u8>>,
    /// Server name given to the TLS stack.
    pub server_name_sent: String,
    /// Whether an SNI extension was sent (DNS names only).
    pub sni_sent: bool,
    /// Trust policy code.
    pub trust: &'static str,
    /// Note on the TLS version.
    pub tls_version_note: &'static str,
    /// QUIC version used.
    pub quic_version: u32,
    /// Note on how the QUIC version is known.
    pub quic_version_note: &'static str,
    /// Exporter probe result, if requested and the handshake completed.
    pub exporter: Option<ExporterResult>,
    /// How the connection ended.
    pub close_reason: String,
    /// From the first Initial to the end.
    pub elapsed: Duration,
    /// `Connection::has_0rtt()`; always false here.
    pub zero_rtt_attempted: bool,
    /// Datagrams handed to the socket.
    pub datagrams_sent: u64,
    /// Datagrams received from the socket.
    pub datagrams_received: u64,
}

impl ClientOutcome {
    /// `true` only when the handshake completed.
    #[must_use]
    pub const fn is_completed(&self) -> bool {
        self.handshake.is_completed()
    }
}

/// Sans-I/O client state: one endpoint, one connection.
pub struct ClientCore {
    endpoint: Endpoint,
    ch: ConnectionHandle,
    conn: Connection,
    exporter: Option<ExporterProbe>,
    started: Instant,
    deadline: Instant,
    linger: Duration,
    linger_until: Option<Instant>,
    outcome: ClientOutcome,
    decided: bool,
    buf: Vec<u8>,
}

impl ClientCore {
    /// Starts a connection at `now`; the Initial(s) are appended to `out`.
    pub fn new(
        config: &DiagClientConfig,
        now: Instant,
        out: &mut Vec<Datagram>,
    ) -> Result<Self, ConfigError> {
        let name_kind = config.validate()?;
        let crypto = client_crypto(&config.trust, &config.alpn)?;
        let mut client_config = quinn_proto::ClientConfig::new(crypto);
        client_config.transport_config(transport_config(config.handshake_timeout)?);
        client_config.version(QUIC_VERSION_1);
        let mut endpoint = Endpoint::new(endpoint_config(), None, false, None);
        let (ch, conn) = endpoint
            .connect(now, client_config, config.remote, &config.server_name)
            .map_err(|e| match e {
                quinn_proto::ConnectError::InvalidServerName(n) => ConfigError::ServerName(n),
                other => ConfigError::Quic(other.to_string()),
            })?;
        let outcome = ClientOutcome {
            remote: config.remote,
            local: None,
            handshake: HandshakeResult::TimedOut,
            negotiated_alpn: None,
            offered_alpn: config.alpn.clone(),
            server_name_sent: config.server_name.clone(),
            sni_sent: name_kind.sends_sni(),
            trust: config.trust.code(),
            tls_version_note: "TLS 1.3 by construction: the only version enabled; QUIC requires it (RFC 9001 §4.2)",
            quic_version: QUIC_VERSION_1,
            quic_version_note: "configured; quinn-proto 0.11 does not expose the negotiated version and the endpoint supports only v1",
            exporter: None,
            close_reason: String::from("pending"),
            elapsed: Duration::ZERO,
            zero_rtt_attempted: false,
            datagrams_sent: 0,
            datagrams_received: 0,
        };
        let mut core = ClientCore {
            endpoint,
            ch,
            conn,
            exporter: config.exporter.clone(),
            started: now,
            deadline: now + config.handshake_timeout,
            linger: config.linger,
            linger_until: None,
            outcome,
            decided: false,
            buf: Vec::with_capacity(1500),
        };
        core.drive(now, out);
        Ok(core)
    }

    /// `true` once the outcome is decided and our `CONNECTION_CLOSE` (if
    /// any) has been queued.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.decided && self.conn.is_closed()
    }

    /// Earliest instant with pending work.
    #[must_use]
    pub fn next_timeout(&mut self) -> Option<Instant> {
        let mut next = self.conn.poll_timeout();
        if !self.decided {
            next = Some(next.map_or(self.deadline, |n| n.min(self.deadline)));
        }
        if let Some(l) = self.linger_until {
            next = Some(next.map_or(l, |n| n.min(l)));
        }
        next
    }

    /// Feeds one received datagram.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        from: SocketAddr,
        data: &[u8],
        out: &mut Vec<Datagram>,
    ) {
        self.outcome.datagrams_received += 1;
        self.buf.clear();
        match self
            .endpoint
            .handle(now, from, None, None, data.into(), &mut self.buf)
        {
            Some(DatagramEvent::ConnectionEvent(ch, ev)) if ch == self.ch => {
                self.conn.handle_event(ev);
            }
            Some(DatagramEvent::Response(t)) => {
                let payload = self.buf[..t.size].to_vec();
                self.outcome.datagrams_sent += 1;
                out.push(Datagram {
                    destination: t.destination,
                    payload,
                });
            }
            // A client endpoint never accepts connections.
            Some(DatagramEvent::NewConnection(incoming)) => self.endpoint.ignore(incoming),
            Some(DatagramEvent::ConnectionEvent(..)) | None => {}
        }
        self.drive(now, out);
    }

    /// Fires timers and the handshake deadline.
    pub fn handle_timeouts(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        if self.conn.poll_timeout().is_some_and(|t| t <= now) {
            self.conn.handle_timeout(now);
        }
        if !self.decided && now >= self.deadline && !self.conn.is_closed() {
            self.outcome.handshake = HandshakeResult::TimedOut;
            self.outcome.close_reason = String::from("local_close_handshake_deadline");
            self.decide(now);
            self.conn.close(
                now,
                VarInt::from_u32(1),
                (&b"tatami-diag: handshake deadline"[..]).into(),
            );
        }
        if self.linger_until.is_some_and(|l| now >= l) && !self.conn.is_closed() {
            self.outcome.close_reason = String::from("local_close_after_handshake");
            self.conn.close(
                now,
                VarInt::from_u32(0),
                (&b"tatami-diag: handshake observed; no application data"[..]).into(),
            );
            self.linger_until = None;
        }
        self.drive(now, out);
    }

    /// Consumes the core. `local` is recorded as the socket address.
    #[must_use]
    pub fn finish(mut self, now: Instant, local: Option<SocketAddr>) -> ClientOutcome {
        if !self.decided {
            self.outcome.handshake = HandshakeResult::TimedOut;
            self.outcome.close_reason = String::from("abandoned");
            self.decide(now);
        }
        self.outcome.local = local;
        self.outcome.elapsed = now.saturating_duration_since(self.started);
        self.outcome
    }

    fn read_handshake_data(&mut self) {
        if let Some(hd) = self
            .conn
            .crypto_session()
            .handshake_data()
            .and_then(|d| d.downcast::<HandshakeData>().ok())
        {
            self.outcome.negotiated_alpn = hd.protocol;
        }
    }

    fn decide(&mut self, now: Instant) {
        self.decided = true;
        self.outcome.elapsed = now.saturating_duration_since(self.started);
        self.outcome.zero_rtt_attempted = self.conn.has_0rtt();
    }

    fn drive(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        while let Some(ev) = self.conn.poll_endpoint_events() {
            if let Some(ce) = self.endpoint.handle_event(self.ch, ev) {
                self.conn.handle_event(ce);
            }
        }
        while let Some(ev) = self.conn.poll() {
            match ev {
                // ALPN arrives in EncryptedExtensions before the server is
                // authenticated; report it only once the handshake completed.
                Event::HandshakeDataReady => {}
                Event::Connected => {
                    self.read_handshake_data();
                    if let Some(probe) = &self.exporter {
                        let mut material = std::vec![0u8; probe.len];
                        let available = self
                            .conn
                            .crypto_session()
                            .export_keying_material(&mut material, &probe.label, &probe.context)
                            .is_ok();
                        // Best-effort hygiene; the bytes are never reported.
                        material.iter_mut().for_each(|b| *b = 0);
                        self.outcome.exporter = Some(ExporterResult {
                            available,
                            len: probe.len,
                        });
                    }
                    if !self.decided {
                        self.outcome.handshake = HandshakeResult::Completed;
                        self.decide(now);
                        self.linger_until = Some(now + self.linger);
                    }
                }
                Event::ConnectionLost { reason } => {
                    let text = connection_error_text(&reason);
                    if self.decided {
                        self.outcome.close_reason = text;
                    } else {
                        // The QUIC idle timeout equals the handshake deadline;
                        // whichever timer fires first, an unanswered
                        // handshake is a timeout, not a peer failure.
                        self.outcome.handshake =
                            if matches!(reason, quinn_proto::ConnectionError::TimedOut) {
                                HandshakeResult::TimedOut
                            } else {
                                HandshakeResult::Failed {
                                    reason: text.clone(),
                                }
                            };
                        self.outcome.close_reason = text;
                        self.decide(now);
                    }
                    self.linger_until = None;
                }
                Event::Stream(_) | Event::DatagramReceived | Event::DatagramsUnblocked => {}
            }
        }
        loop {
            self.buf.clear();
            match self.conn.poll_transmit(now, 1, &mut self.buf) {
                Some(t) => {
                    self.outcome.datagrams_sent += 1;
                    out.push(Datagram {
                        destination: t.destination,
                        payload: self.buf[..t.size].to_vec(),
                    });
                }
                None => break,
            }
        }
        while let Some(ev) = self.conn.poll_endpoint_events() {
            if let Some(ce) = self.endpoint.handle_event(self.ch, ev) {
                self.conn.handle_event(ce);
            }
        }
    }
}

/// Failure to run a client handshake at all (as opposed to a handshake
/// that ran and failed, which is a [`ClientOutcome`]).
#[derive(Debug)]
pub enum ClientError {
    /// Invalid configuration.
    Config(ConfigError),
    /// Socket error.
    Io(io::Error),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Config(e) => write!(f, "invalid configuration: {e}"),
            ClientError::Io(e) => write!(f, "socket error: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Runs one handshake over a fresh UDP socket, blocking for at most the
/// handshake deadline plus the linger period.
pub fn run(config: &DiagClientConfig) -> Result<ClientOutcome, ClientError> {
    // Loopback targets get a loopback source so `local` is meaningful;
    // anything else binds the unspecified address of the same family.
    let bind: SocketAddr = if config.remote.ip().is_loopback() {
        SocketAddr::new(config.remote.ip(), 0)
    } else if config.remote.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let socket = UdpSocket::bind(bind).map_err(ClientError::Io)?;
    let local = socket.local_addr().ok();
    let mut out = Vec::new();
    let mut core =
        ClientCore::new(config, Instant::now(), &mut out).map_err(ClientError::Config)?;
    let mut recv_buf = std::vec![0u8; 65_535];
    let poll = Duration::from_millis(25);
    loop {
        send_all(&socket, &mut out).map_err(ClientError::Io)?;
        if core.is_finished() {
            break;
        }
        let now = Instant::now();
        let wait = core
            .next_timeout()
            .map_or(poll, |t| t.saturating_duration_since(now).min(poll));
        if let Some((n, from)) =
            recv_with_timeout(&socket, &mut recv_buf, wait).map_err(ClientError::Io)?
        {
            core.handle_datagram(Instant::now(), from, &recv_buf[..n], &mut out);
        }
        core.handle_timeouts(Instant::now(), &mut out);
    }
    send_all(&socket, &mut out).map_err(ClientError::Io)?;
    Ok(core.finish(Instant::now(), local))
}
