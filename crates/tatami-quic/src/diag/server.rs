//! Diagnostic QUIC/TLS handshake server: accepts connections, drives each
//! handshake to completion or failure, records what was offered and
//! negotiated, closes, and never carries application data.
//!
//! [`ServerCore`] is sans-I/O: it consumes datagrams and time and produces
//! datagrams and [`HandshakeObservation`]s. [`DiagServer`] binds a UDP
//! socket and runs the core from one blocking thread, mirroring the TCP
//! listener's finite-run, bounded-record conventions (W-21, W-22): stop
//! conditions are `run_for`, `max_connections`, a [`StopHandle`], a failed
//! sink or a socket error; records go through a bounded channel to a single
//! sink thread and drops are counted, never hidden.
//!
//! # What a record means
//!
//! `peer_addr` is the source address of the client's Initial. It is an
//! **unvalidated** address unless `peer_address_validated` is true, which
//! this server can only achieve by sending a Retry (`require_validation`)
//! and receiving the token back. Validation says the peer can receive at
//! that address; it says nothing about identity. Offered ClientHello values
//! (`offered`) are peer-supplied bytes; negotiated values (`negotiated_alpn`,
//! `sni`) are what rustls agreed to. `handshake_outcome = completed` means
//! the TLS 1.3 handshake finished; the peer was **not** authenticated (the
//! server requests no client certificate) and no application data exists.

use std::boxed::Box;
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::string::{String, ToString as _};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use quinn_proto::crypto::rustls::HandshakeData;
use quinn_proto::{
    AcceptError, Connection, ConnectionError, ConnectionHandle, DatagramEvent, Endpoint, Event,
    Incoming, VarInt,
};

use super::identity::{CertificateSha256, TestIdentity};
use super::tls::{ClientHelloRecord, HelloSlot, ServerIdentityMode, hello_slot, server_crypto};
use super::udp::{recv_with_timeout, send_all};
use super::{
    ConfigError, DEFAULT_HANDSHAKE_TIMEOUT, Datagram, EndpointResponse, QUIC_VERSION_1,
    endpoint_config, transport_config,
};

/// Application close code sent after a completed handshake. Experimental;
/// no registry meaning.
pub const CLOSE_CODE_OBSERVED: u32 = 0;
/// Application close code sent when the handshake deadline passes.
pub const CLOSE_CODE_DEADLINE: u32 = 1;
/// Application close code sent when the server is stopping.
pub const CLOSE_CODE_SHUTDOWN: u32 = 2;

/// Server policy. Defaults are local policy, not protocol requirements.
#[derive(Clone, Debug)]
pub struct DiagServerConfig {
    /// UDP address to bind. Port 0 requests an ephemeral port.
    pub bind: SocketAddr,
    /// ALPN protocols accepted, in preference order. **Required and
    /// explicit**: there is no default value; an empty list is rejected.
    /// Values are experimental and unregistered (AQ-019 / P-08).
    pub alpn: Vec<Vec<u8>>,
    /// The test identity presented to clients.
    pub identity: TestIdentity,
    /// How the identity is presented (certificate by default).
    pub identity_mode: ServerIdentityMode,
    /// Per-connection deadline from acceptance to handshake completion;
    /// also the QUIC idle timeout.
    pub handshake_timeout: Duration,
    /// Answer unvalidated Initials with Retry and accept only token-bearing
    /// Initials.
    pub require_validation: bool,
    /// Stop after this many accepted-or-refused connections (Retries are
    /// not counted; the returning Initial is). `None` means unlimited.
    pub max_connections: Option<u64>,
    /// Stop after this long. `None` means until stopped.
    pub run_for: Option<Duration>,
    /// Handshakes in progress at once; further Initials are refused
    /// (`CONNECTION_REFUSED`) and counted. Closing/draining connections
    /// (bounded by 3×PTO) do not count.
    pub max_concurrent: usize,
    /// Capacity of the record channel to the sink thread.
    pub pending_records: usize,
    /// Longest blocking wait on the socket; bounds stop latency.
    pub poll_interval: Duration,
    /// How long active handshakes may finish after a stop condition.
    pub shutdown_grace: Duration,
    /// Minimum spacing between overload records.
    pub overload_report_interval: Duration,
}

impl DiagServerConfig {
    /// Defaults for everything except the two required inputs.
    #[must_use]
    pub fn new(identity: TestIdentity, alpn: Vec<Vec<u8>>) -> Self {
        DiagServerConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 4433)),
            alpn,
            identity,
            identity_mode: ServerIdentityMode::Certificate,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            require_validation: false,
            max_connections: None,
            run_for: None,
            max_concurrent: 32,
            pending_records: 128,
            poll_interval: Duration::from_millis(25),
            shutdown_grace: Duration::from_secs(5),
            overload_report_interval: Duration::from_secs(1),
        }
    }

    /// Checks limits and durations without touching the network.
    pub fn validate(&self) -> Result<(), ConfigError> {
        super::validate_alpn(&self.alpn)?;
        if self.handshake_timeout.is_zero() {
            return Err(ConfigError::BadDuration("handshake_timeout"));
        }
        if self.max_concurrent == 0 {
            return Err(ConfigError::ZeroLimit("max_concurrent"));
        }
        if self.pending_records == 0 {
            return Err(ConfigError::ZeroLimit("pending_records"));
        }
        if self.poll_interval.is_zero() {
            return Err(ConfigError::BadDuration("poll_interval"));
        }
        if self.run_for.is_some_and(|d| d.is_zero()) {
            return Err(ConfigError::BadDuration("run_for"));
        }
        if self.max_connections == Some(0) {
            return Err(ConfigError::ZeroLimit("max_connections"));
        }
        Ok(())
    }
}

/// How one handshake attempt ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeOutcome {
    /// TLS 1.3 handshake completed; ALPN and SNI are authoritative.
    Completed,
    /// The connection was lost before completion; `reason` is the
    /// `quinn-proto` `ConnectionError` text (peer close reason phrases are
    /// peer-supplied and escaped).
    Failed {
        /// Error text.
        reason: String,
    },
    /// The per-connection deadline passed while handshaking.
    TimedOut,
    /// `Endpoint::accept` rejected the Initial; no connection existed.
    AcceptFailed {
        /// Error text.
        reason: String,
    },
    /// The server stopped while the handshake was in progress.
    Shutdown,
}

impl HandshakeOutcome {
    /// Stable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            HandshakeOutcome::Completed => "completed",
            HandshakeOutcome::Failed { .. } => "failed",
            HandshakeOutcome::TimedOut => "timed_out",
            HandshakeOutcome::AcceptFailed { .. } => "accept_failed",
            HandshakeOutcome::Shutdown => "shutdown",
        }
    }

    /// Error text, if any.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            HandshakeOutcome::Failed { reason } | HandshakeOutcome::AcceptFailed { reason } => {
                Some(reason)
            }
            _ => None,
        }
    }
}

/// Who ended the connection and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// We sent `CONNECTION_CLOSE` (application code 0) after completion.
    LocalAfterHandshake,
    /// We sent `CONNECTION_CLOSE` (application code 1) at the deadline.
    LocalDeadline,
    /// We sent `CONNECTION_CLOSE` (application code 2) while stopping.
    LocalShutdown,
    /// The connection was lost (peer close, transport error, idle timeout).
    ConnectionLost,
    /// No connection was created.
    NotEstablished,
}

impl CloseReason {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            CloseReason::LocalAfterHandshake => "local_close_after_handshake",
            CloseReason::LocalDeadline => "local_close_handshake_deadline",
            CloseReason::LocalShutdown => "local_close_shutdown",
            CloseReason::ConnectionLost => "connection_lost",
            CloseReason::NotEstablished => "not_established",
        }
    }
}

/// How the client's address came to be validated, if it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidationMethod {
    /// Not validated at acceptance.
    None,
    /// The Initial carried the token from our Retry.
    RetryToken,
    /// The Initial carried a NEW_TOKEN token (this server never issues
    /// them, so this indicates a token from elsewhere).
    ValidationToken,
}

impl ValidationMethod {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            ValidationMethod::None => "none",
            ValidationMethod::RetryToken => "retry_token",
            ValidationMethod::ValidationToken => "validation_token",
        }
    }
}

/// One handshake attempt, from Initial to close.
#[derive(Clone, Debug)]
pub struct HandshakeObservation {
    /// Sequence number within the run (1-based).
    pub id: u64,
    /// Local bound address.
    pub local: SocketAddr,
    /// Source address of the Initial. Unvalidated unless
    /// `peer_address_validated`.
    pub peer: SocketAddr,
    /// Unix time at acceptance.
    pub accepted_unix: Duration,
    /// From acceptance to the outcome decision.
    pub elapsed: Duration,
    /// The client's original destination connection ID: identifies the
    /// attempt, not the peer.
    pub orig_dst_cid: Vec<u8>,
    /// `Incoming::remote_address_validated()` at acceptance.
    pub peer_address_validated: bool,
    /// `Incoming::may_retry()` at acceptance.
    pub may_retry: bool,
    /// `true` when the accepted Initial carried the token from a Retry we
    /// sent earlier (equivalently `!may_retry`).
    pub retry_sent: bool,
    /// Derived from the two flags above.
    pub validation_method: ValidationMethod,
    /// Always QUIC v1: the endpoint accepts no other version.
    pub quic_version: u32,
    /// The most recent ClientHello as seen by the certificate resolver, or
    /// `None` if no ClientHello was processed (e.g. accept failure).
    pub offered: Option<ClientHelloRecord>,
    /// Negotiated ALPN (`HandshakeData::protocol`), once known.
    pub negotiated_alpn: Option<Vec<u8>>,
    /// SNI as accepted by rustls (`HandshakeData::server_name`).
    pub sni: Option<String>,
    /// Outcome.
    pub outcome: HandshakeOutcome,
    /// Who closed.
    pub close: CloseReason,
    /// Stream events observed and ignored (the limit is 0, so this counts
    /// protocol violations by the peer, never accepted work).
    pub unexpected_streams: u64,
    /// Datagram events observed and ignored.
    pub unexpected_datagrams: u64,
    /// `Connection::has_0rtt()`: whether 0-RTT was possible. Always false
    /// with this configuration.
    pub zero_rtt_attempted: bool,
}

/// Why the server stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    /// `run_for` elapsed.
    RunDurationElapsed,
    /// `max_connections` reached.
    ConnectionLimitReached,
    /// A [`StopHandle`] was triggered.
    StopRequested,
    /// The record sink returned an error.
    SinkFailed,
    /// The socket failed with a non-transient error.
    SocketFailed,
}

impl StopReason {
    /// Stable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            StopReason::RunDurationElapsed => "run_duration_elapsed",
            StopReason::ConnectionLimitReached => "connection_limit_reached",
            StopReason::StopRequested => "stop_requested",
            StopReason::SinkFailed => "sink_failed",
            StopReason::SocketFailed => "socket_failed",
        }
    }
}

/// Counters kept by the core.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoreStats {
    /// Initials that produced an `Incoming` (including ones answered with
    /// Retry and the returning ones).
    pub incoming: u64,
    /// `Incoming`s passed to `Endpoint::accept` (success or failure).
    pub accepted: u64,
    /// Connections created and driven.
    pub observed: u64,
    /// Handshakes that completed.
    pub completed: u64,
    /// Handshakes that failed or were refused at accept.
    pub failed: u64,
    /// Handshakes that hit the deadline.
    pub timed_out: u64,
    /// `Incoming`s refused with `CONNECTION_REFUSED` because `max_concurrent`
    /// handshakes were in progress or the server was winding down.
    pub dropped_at_capacity: u64,
    /// Retry packets sent.
    pub retries_sent: u64,
    /// Version Negotiation packets the endpoint produced (classified from
    /// our own outgoing bytes; not an event in quinn-proto 0.11).
    pub version_negotiations_sent: u64,
    /// Other endpoint-level responses (stateless resets, Initial closes).
    pub endpoint_responses_sent: u64,
    /// Datagrams received.
    pub datagrams_received: u64,
    /// Datagrams sent (as reported to the caller).
    pub datagrams_sent: u64,
}

/// Final counters of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Bound address.
    pub bound: SocketAddr,
    /// Certificate fingerprint presented.
    pub certificate_sha256: CertificateSha256,
    /// Counters.
    pub stats: CoreStats,
    /// Records that could not be queued.
    pub records_dropped: u64,
    /// Handshakes closed by the shutdown.
    pub abandoned: u64,
    /// Why the run ended.
    pub reason: StopReason,
    /// Fatal error text.
    pub error: Option<String>,
    /// Wall time.
    pub elapsed: Duration,
}

/// Records delivered to the sink, in order.
#[derive(Debug)]
pub enum ServerEvent {
    /// Listening.
    Started {
        /// Bound address.
        bound: SocketAddr,
        /// Certificate fingerprint, so a client can pin it.
        certificate_sha256: CertificateSha256,
        /// ALPN values accepted.
        alpn: Vec<Vec<u8>>,
    },
    /// One attempt.
    Connection(Box<HandshakeObservation>),
    /// Initials refused at capacity since the previous overload record.
    Overload {
        /// Since last report.
        dropped_since_last: u64,
        /// Total.
        total_dropped: u64,
    },
    /// The run ended.
    Stopped(Summary),
}

/// Error a sink may return; the run then stops with
/// [`StopReason::SinkFailed`].
pub type SinkError = Box<dyn std::error::Error + Send + Sync>;

/// Consumer of [`ServerEvent`]s, called from one dedicated thread.
pub type Sink = Box<dyn FnMut(ServerEvent) -> Result<(), SinkError> + Send>;

/// Requests a running server to stop.
#[derive(Clone, Debug)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    /// Asks the server to stop.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// `true` once stop has been requested.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

struct Attempt {
    ch: ConnectionHandle,
    conn: Connection,
    obs: HandshakeObservation,
    accepted_at: Instant,
    deadline: Instant,
    decided: bool,
}

/// Sans-I/O server state: one `Endpoint`, many connections, one thread.
pub struct ServerCore {
    endpoint: Endpoint,
    bound: SocketAddr,
    handshake_timeout: Duration,
    require_validation: bool,
    max_concurrent: usize,
    slot: HelloSlot,
    attempts: HashMap<usize, Attempt>,
    buf: Vec<u8>,
    next_id: u64,
    stats: CoreStats,
    pending: Vec<HandshakeObservation>,
    accepting: bool,
    certificate_sha256: CertificateSha256,
}

impl ServerCore {
    /// Builds the endpoint for `config`, reporting `bound` as the local
    /// address in records. Performs no I/O.
    pub fn new(config: &DiagServerConfig, bound: SocketAddr) -> Result<Self, ConfigError> {
        config.validate()?;
        let slot = hello_slot();
        let crypto = server_crypto(
            &config.identity,
            &config.alpn,
            slot.clone(),
            config.identity_mode,
        )?;
        let mut server_config = quinn_proto::ServerConfig::with_crypto(crypto);
        server_config.transport_config(transport_config(config.handshake_timeout)?);
        let endpoint = Endpoint::new(
            endpoint_config(),
            Some(Arc::new(server_config)),
            false,
            None,
        );
        Ok(ServerCore {
            endpoint,
            bound,
            handshake_timeout: config.handshake_timeout,
            require_validation: config.require_validation,
            max_concurrent: config.max_concurrent,
            slot,
            attempts: HashMap::new(),
            buf: Vec::with_capacity(1500),
            next_id: 0,
            stats: CoreStats::default(),
            pending: Vec::new(),
            accepting: true,
            certificate_sha256: config.identity.certificate_sha256_fingerprint(),
        })
    }

    /// Counters so far.
    #[must_use]
    pub fn stats(&self) -> CoreStats {
        self.stats
    }

    /// Fingerprint of the presented certificate.
    #[must_use]
    pub fn certificate_sha256(&self) -> CertificateSha256 {
        self.certificate_sha256
    }

    /// Handshakes in progress (not yet decided).
    #[must_use]
    pub fn handshaking(&self) -> usize {
        self.attempts.values().filter(|a| !a.decided).count()
    }

    /// Connections still held (including closing/draining ones).
    #[must_use]
    pub fn connections(&self) -> usize {
        self.attempts.len()
    }

    /// Stops accepting new Initials (they are refused). Existing handshakes
    /// continue until [`ServerCore::shutdown`].
    pub fn stop_accepting(&mut self) {
        self.accepting = false;
    }

    /// Takes the observations decided since the last call.
    pub fn drain_observations(&mut self) -> Vec<HandshakeObservation> {
        core::mem::take(&mut self.pending)
    }

    /// Earliest instant at which [`ServerCore::handle_timeouts`] has work.
    #[must_use]
    pub fn next_timeout(&mut self) -> Option<Instant> {
        let mut next: Option<Instant> = None;
        for a in self.attempts.values_mut() {
            let mut candidates = std::vec![a.conn.poll_timeout()];
            if !a.decided {
                candidates.push(Some(a.deadline));
            }
            for c in candidates.into_iter().flatten() {
                next = Some(next.map_or(c, |n: Instant| n.min(c)));
            }
        }
        next
    }

    /// Feeds one received datagram. Outgoing datagrams are appended to
    /// `out`.
    pub fn handle_datagram(
        &mut self,
        now: Instant,
        remote: SocketAddr,
        data: &[u8],
        out: &mut Vec<Datagram>,
    ) {
        self.stats.datagrams_received += 1;
        self.buf.clear();
        // A concrete local IP is part of quinn-proto's routing tuple; a
        // wildcard bind has none to offer.
        let local_ip = (!self.bound.ip().is_unspecified()).then_some(self.bound.ip());
        let event = self
            .endpoint
            .handle(now, remote, local_ip, None, data.into(), &mut self.buf);
        match event {
            None => {}
            Some(DatagramEvent::Response(t)) => {
                let payload = self.buf[..t.size].to_vec();
                match EndpointResponse::classify(&payload) {
                    EndpointResponse::VersionNegotiation => {
                        self.stats.version_negotiations_sent += 1;
                    }
                    EndpointResponse::Other => self.stats.endpoint_responses_sent += 1,
                }
                self.push_out(out, t.destination, payload);
            }
            Some(DatagramEvent::ConnectionEvent(ch, ev)) => {
                if let Some(att) = self.attempts.get_mut(&ch.0) {
                    att.conn.handle_event(ev);
                    self.attach_hello(ch);
                    self.drive(ch, now, out);
                }
            }
            Some(DatagramEvent::NewConnection(incoming)) => {
                self.handle_incoming(incoming, now, out);
            }
        }
    }

    /// Fires connection timers and handshake deadlines that are due.
    pub fn handle_timeouts(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        let keys: Vec<usize> = self.attempts.keys().copied().collect();
        for key in keys {
            let ch = ConnectionHandle(key);
            let Some(att) = self.attempts.get_mut(&key) else {
                continue;
            };
            if att.conn.poll_timeout().is_some_and(|t| t <= now) {
                att.conn.handle_timeout(now);
            }
            if !att.decided && now >= att.deadline && !att.conn.is_closed() {
                att.conn.close(
                    now,
                    VarInt::from_u32(CLOSE_CODE_DEADLINE),
                    (&b"tatami-diag: handshake deadline"[..]).into(),
                );
                let obs = &mut att.obs;
                obs.outcome = HandshakeOutcome::TimedOut;
                obs.close = CloseReason::LocalDeadline;
                self.stats.timed_out += 1;
                Self::decide(att, now, &mut self.pending);
            }
            self.drive(ch, now, out);
        }
    }

    /// Closes every connection still open (records `Shutdown` for undecided
    /// ones) and queues the resulting `CONNECTION_CLOSE` datagrams. Returns
    /// how many handshakes were cut short.
    pub fn shutdown(&mut self, now: Instant, out: &mut Vec<Datagram>) -> u64 {
        self.accepting = false;
        let mut abandoned = 0;
        let keys: Vec<usize> = self.attempts.keys().copied().collect();
        for key in keys {
            let ch = ConnectionHandle(key);
            if let Some(att) = self.attempts.get_mut(&key) {
                if !att.decided {
                    abandoned += 1;
                    att.conn.close(
                        now,
                        VarInt::from_u32(CLOSE_CODE_SHUTDOWN),
                        (&b"tatami-diag: server stopping"[..]).into(),
                    );
                    att.obs.outcome = HandshakeOutcome::Shutdown;
                    att.obs.close = CloseReason::LocalShutdown;
                    Self::decide(att, now, &mut self.pending);
                }
            }
            self.drive(ch, now, out);
        }
        abandoned
    }

    fn handle_incoming(&mut self, incoming: Incoming, now: Instant, out: &mut Vec<Datagram>) {
        self.stats.incoming += 1;
        let validated = incoming.remote_address_validated();
        let may_retry = incoming.may_retry();
        if self.require_validation && !validated {
            self.buf.clear();
            match self.endpoint.retry(incoming, &mut self.buf) {
                Ok(t) => {
                    self.stats.retries_sent += 1;
                    let payload = self.buf[..t.size].to_vec();
                    self.push_out(out, t.destination, payload);
                }
                Err(e) => {
                    // Unreachable per quinn-proto's contract (`!validated`
                    // implies `may_retry`); release the state anyway.
                    self.endpoint.ignore(e.into_incoming());
                }
            }
            return;
        }
        if !self.accepting || self.handshaking() >= self.max_concurrent {
            self.buf.clear();
            let t = self.endpoint.refuse(incoming, &mut self.buf);
            self.stats.dropped_at_capacity += 1;
            let payload = self.buf[..t.size].to_vec();
            self.push_out(out, t.destination, payload);
            return;
        }

        self.stats.accepted += 1;
        self.next_id += 1;
        let peer = incoming.remote_address();
        let orig_dst_cid = incoming.orig_dst_cid().to_vec();
        let obs = HandshakeObservation {
            id: self.next_id,
            local: self.bound,
            peer,
            accepted_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default(),
            elapsed: Duration::ZERO,
            orig_dst_cid,
            peer_address_validated: validated,
            may_retry,
            retry_sent: !may_retry,
            validation_method: match (validated, may_retry) {
                (_, false) => ValidationMethod::RetryToken,
                (true, true) => ValidationMethod::ValidationToken,
                (false, true) => ValidationMethod::None,
            },
            quic_version: QUIC_VERSION_1,
            offered: None,
            negotiated_alpn: None,
            sni: None,
            outcome: HandshakeOutcome::TimedOut,
            close: CloseReason::NotEstablished,
            unexpected_streams: 0,
            unexpected_datagrams: 0,
            zero_rtt_attempted: false,
        };
        self.buf.clear();
        match self.endpoint.accept(incoming, now, &mut self.buf, None) {
            Ok((ch, conn)) => {
                self.stats.observed += 1;
                let deadline = now + self.handshake_timeout;
                self.attempts.insert(
                    ch.0,
                    Attempt {
                        ch,
                        conn,
                        obs,
                        accepted_at: now,
                        deadline,
                        decided: false,
                    },
                );
                self.attach_hello(ch);
                self.drive(ch, now, out);
            }
            Err(AcceptError { cause, response }) => {
                if let Some(t) = response {
                    let payload = self.buf[..t.size].to_vec();
                    self.push_out(out, t.destination, payload);
                }
                self.stats.failed += 1;
                let mut obs = obs;
                obs.offered = self.take_hello();
                obs.outcome = HandshakeOutcome::AcceptFailed {
                    reason: cause.to_string(),
                };
                obs.close = CloseReason::NotEstablished;
                self.pending.push(obs);
            }
        }
    }

    fn take_hello(&self) -> Option<ClientHelloRecord> {
        self.slot.lock().ok().and_then(|mut s| s.take())
    }

    /// Moves a ClientHello recorded during the last call into `quinn-proto`
    /// onto connection `ch`. Exact: the core is single-threaded and the slot
    /// is emptied after every such call.
    fn attach_hello(&mut self, ch: ConnectionHandle) {
        if let Some(rec) = self.take_hello() {
            if let Some(att) = self.attempts.get_mut(&ch.0) {
                let seen = att.obs.offered.as_ref().map_or(0, |r| r.hellos_seen);
                att.obs.offered = Some(ClientHelloRecord {
                    hellos_seen: seen + 1,
                    ..rec
                });
            }
        }
    }

    fn decide(att: &mut Attempt, now: Instant, pending: &mut Vec<HandshakeObservation>) {
        att.decided = true;
        att.obs.elapsed = now.saturating_duration_since(att.accepted_at);
        att.obs.zero_rtt_attempted = att.conn.has_0rtt();
        pending.push(att.obs.clone());
    }

    fn drive(&mut self, ch: ConnectionHandle, now: Instant, out: &mut Vec<Datagram>) {
        let Some(att) = self.attempts.get_mut(&ch.0) else {
            return;
        };
        while let Some(ev) = att.conn.poll_endpoint_events() {
            if let Some(ce) = self.endpoint.handle_event(att.ch, ev) {
                att.conn.handle_event(ce);
            }
        }
        while let Some(ev) = att.conn.poll() {
            match ev {
                Event::HandshakeDataReady => Self::read_handshake_data(att),
                Event::Connected => {
                    Self::read_handshake_data(att);
                    if !att.decided {
                        att.obs.outcome = HandshakeOutcome::Completed;
                        att.obs.close = CloseReason::LocalAfterHandshake;
                        self.stats.completed += 1;
                        Self::decide(att, now, &mut self.pending);
                    }
                    att.conn.close(
                        now,
                        VarInt::from_u32(CLOSE_CODE_OBSERVED),
                        (&b"tatami-diag: handshake observed; no application data"[..]).into(),
                    );
                }
                Event::ConnectionLost { reason } => {
                    if !att.decided {
                        att.obs.outcome = HandshakeOutcome::Failed {
                            reason: connection_error_text(&reason),
                        };
                        att.obs.close = CloseReason::ConnectionLost;
                        self.stats.failed += 1;
                        Self::decide(att, now, &mut self.pending);
                    }
                }
                Event::Stream(_) => att.obs.unexpected_streams += 1,
                Event::DatagramReceived => att.obs.unexpected_datagrams += 1,
                Event::DatagramsUnblocked => {}
            }
        }
        loop {
            self.buf.clear();
            match att.conn.poll_transmit(now, 1, &mut self.buf) {
                Some(t) => {
                    let payload = self.buf[..t.size].to_vec();
                    self.stats.datagrams_sent += 1;
                    out.push(Datagram {
                        destination: t.destination,
                        payload,
                    });
                }
                None => break,
            }
        }
        // A closed connection may have queued endpoint events (Drained)
        // during transmit polling; deliver them before checking drain.
        while let Some(ev) = att.conn.poll_endpoint_events() {
            if let Some(ce) = self.endpoint.handle_event(att.ch, ev) {
                att.conn.handle_event(ce);
            }
        }
        if att.conn.is_drained() {
            self.attempts.remove(&ch.0);
        }
    }

    /// Copies negotiated ALPN and SNI out of rustls. Available from
    /// `HandshakeDataReady` (after the ClientHello is processed), i.e. also
    /// for handshakes that later fail.
    fn read_handshake_data(att: &mut Attempt) {
        if let Some(hd) = att
            .conn
            .crypto_session()
            .handshake_data()
            .and_then(|d| d.downcast::<HandshakeData>().ok())
        {
            att.obs.negotiated_alpn = hd.protocol;
            att.obs.sni = hd.server_name;
        }
    }

    fn push_out(&mut self, out: &mut Vec<Datagram>, destination: SocketAddr, payload: Vec<u8>) {
        self.stats.datagrams_sent += 1;
        out.push(Datagram {
            destination,
            payload,
        });
    }
}

/// Renders a `ConnectionError` for reports, escaping the peer-supplied
/// reason phrase of a `CONNECTION_CLOSE`.
#[must_use]
pub fn connection_error_text(e: &ConnectionError) -> String {
    match e {
        ConnectionError::ConnectionClosed(c) => std::format!(
            "aborted by peer: {} (reason phrase: {})",
            c.error_code,
            super::bounded_escaped(&c.reason, 256)
        ),
        ConnectionError::ApplicationClosed(c) => std::format!(
            "closed by peer: application code {} (reason phrase: {})",
            c.error_code,
            super::bounded_escaped(&c.reason, 256)
        ),
        other => other.to_string(),
    }
}

/// Failure of [`DiagServer::bind`].
#[derive(Debug)]
pub enum BindError {
    /// Invalid configuration.
    Config(ConfigError),
    /// The OS refused the bind.
    Io(io::Error),
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BindError::Config(e) => write!(f, "invalid configuration: {e}"),
            BindError::Io(e) => write!(f, "bind failed: {e}"),
        }
    }
}

impl std::error::Error for BindError {}

/// A bound, not yet running diagnostic server.
pub struct DiagServer {
    config: DiagServerConfig,
    socket: UdpSocket,
    bound: SocketAddr,
    stop: Arc<AtomicBool>,
    core: ServerCore,
}

impl DiagServer {
    /// Validates the configuration, builds the endpoint and binds the
    /// socket.
    pub fn bind(config: DiagServerConfig) -> Result<Self, BindError> {
        config.validate().map_err(BindError::Config)?;
        let socket = UdpSocket::bind(config.bind).map_err(BindError::Io)?;
        let bound = socket.local_addr().map_err(BindError::Io)?;
        let core = ServerCore::new(&config, bound).map_err(BindError::Config)?;
        Ok(DiagServer {
            config,
            socket,
            bound,
            stop: Arc::new(AtomicBool::new(false)),
            core,
        })
    }

    /// Actual bound address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound
    }

    /// Fingerprint of the certificate that will be presented.
    #[must_use]
    pub fn certificate_sha256(&self) -> CertificateSha256 {
        self.core.certificate_sha256()
    }

    /// Handle for stopping the run from another thread.
    #[must_use]
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle(self.stop.clone())
    }

    /// Runs until a stop condition, delivering events to `sink` on a
    /// dedicated thread. Returns the same summary delivered as
    /// [`ServerEvent::Stopped`].
    pub fn run(mut self, sink: Sink) -> Summary {
        let started = Instant::now();
        let run_deadline = self.config.run_for.map(|d| started + d);
        let (tx, rx) = mpsc::sync_channel::<ServerEvent>(self.config.pending_records);
        let sink_failed = Arc::new(AtomicBool::new(false));
        let sink_done = Arc::new(AtomicBool::new(false));
        let sink_error = Arc::new(std::sync::Mutex::new(None::<String>));
        {
            let failed = sink_failed.clone();
            let done = sink_done.clone();
            let error = sink_error.clone();
            let mut sink = sink;
            thread::spawn(move || {
                for event in rx {
                    if failed.load(Ordering::SeqCst) {
                        continue;
                    }
                    if let Err(e) = sink(event) {
                        failed.store(true, Ordering::SeqCst);
                        if let Ok(mut slot) = error.lock() {
                            *slot = Some(e.to_string());
                        }
                    }
                }
                done.store(true, Ordering::SeqCst);
            });
        }
        let mut records_dropped: u64 = 0;
        let emit = |event: ServerEvent, dropped: &mut u64| match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => *dropped += 1,
        };
        emit(
            ServerEvent::Started {
                bound: self.bound,
                certificate_sha256: self.core.certificate_sha256(),
                alpn: self.config.alpn.clone(),
            },
            &mut records_dropped,
        );

        let mut out: Vec<Datagram> = Vec::new();
        let mut recv_buf = std::vec![0u8; 65_535];
        let mut dropped_reported: u64 = 0;
        let mut last_overload_report: Option<Instant> = None;
        let mut error: Option<String> = None;

        let reason = loop {
            if self.stop.load(Ordering::SeqCst) {
                break StopReason::StopRequested;
            }
            if sink_failed.load(Ordering::SeqCst) {
                break StopReason::SinkFailed;
            }
            let now = Instant::now();
            if run_deadline.is_some_and(|d| now >= d) {
                break StopReason::RunDurationElapsed;
            }
            let stats = self.core.stats();
            if self
                .config
                .max_connections
                .is_some_and(|m| stats.accepted + stats.dropped_at_capacity >= m)
            {
                break StopReason::ConnectionLimitReached;
            }
            if stats.dropped_at_capacity > dropped_reported
                && last_overload_report
                    .is_none_or(|t| t.elapsed() >= self.config.overload_report_interval)
            {
                emit(
                    ServerEvent::Overload {
                        dropped_since_last: stats.dropped_at_capacity - dropped_reported,
                        total_dropped: stats.dropped_at_capacity,
                    },
                    &mut records_dropped,
                );
                dropped_reported = stats.dropped_at_capacity;
                last_overload_report = Some(now);
            }

            if let Err(e) = self.step(now, &mut out, &mut recv_buf, run_deadline) {
                error = Some(e.to_string());
                break StopReason::SocketFailed;
            }
            for obs in self.core.drain_observations() {
                emit(ServerEvent::Connection(Box::new(obs)), &mut records_dropped);
            }
        };

        // Wind down: refuse new Initials, let handshakes in progress finish
        // within the grace period (each also has its own deadline), then
        // close whatever is left.
        self.core.stop_accepting();
        let immediate = matches!(reason, StopReason::SinkFailed | StopReason::SocketFailed);
        let grace_end = Instant::now() + self.config.shutdown_grace;
        while !immediate && self.core.handshaking() > 0 && Instant::now() < grace_end {
            if self
                .step(Instant::now(), &mut out, &mut recv_buf, Some(grace_end))
                .is_err()
            {
                break;
            }
            for obs in self.core.drain_observations() {
                emit(ServerEvent::Connection(Box::new(obs)), &mut records_dropped);
            }
        }
        let abandoned = self.core.shutdown(Instant::now(), &mut out);
        let _ = send_all(&self.socket, &mut out);
        for obs in self.core.drain_observations() {
            emit(ServerEvent::Connection(Box::new(obs)), &mut records_dropped);
        }
        let stats = self.core.stats();
        if stats.dropped_at_capacity > dropped_reported {
            emit(
                ServerEvent::Overload {
                    dropped_since_last: stats.dropped_at_capacity - dropped_reported,
                    total_dropped: stats.dropped_at_capacity,
                },
                &mut records_dropped,
            );
        }
        if reason == StopReason::SinkFailed {
            error = sink_error.lock().ok().and_then(|e| e.clone());
        }
        let summary = Summary {
            bound: self.bound,
            certificate_sha256: self.core.certificate_sha256(),
            stats,
            records_dropped,
            abandoned,
            reason,
            error,
            elapsed: started.elapsed(),
        };
        // Bounded: never wait on a wedged sink forever.
        let mut pending = Some(ServerEvent::Stopped(summary.clone()));
        let give_up = Instant::now() + self.config.shutdown_grace;
        while let Some(event) = pending.take() {
            match tx.try_send(event) {
                Ok(()) => {}
                Err(TrySendError::Full(event)) if Instant::now() < give_up => {
                    pending = Some(event);
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => records_dropped += 1,
            }
        }
        drop(tx);
        let wait_end = Instant::now() + self.config.shutdown_grace;
        while !sink_done.load(Ordering::SeqCst) && Instant::now() < wait_end {
            thread::sleep(Duration::from_millis(5));
        }
        Summary {
            records_dropped,
            ..summary
        }
    }

    /// One iteration: flush, wait for a datagram or the next timer, feed
    /// the core, fire timers.
    fn step(
        &mut self,
        now: Instant,
        out: &mut Vec<Datagram>,
        recv_buf: &mut [u8],
        hard_deadline: Option<Instant>,
    ) -> io::Result<()> {
        send_all(&self.socket, out)?;
        let mut wait = self.config.poll_interval;
        if let Some(t) = self.core.next_timeout() {
            wait = wait.min(t.saturating_duration_since(now));
        }
        if let Some(d) = hard_deadline {
            wait = wait.min(d.saturating_duration_since(now));
        }
        if let Some((n, from)) = recv_with_timeout(&self.socket, recv_buf, wait)? {
            self.core
                .handle_datagram(Instant::now(), from, &recv_buf[..n], out);
        }
        self.core.handle_timeouts(Instant::now(), out);
        send_all(&self.socket, out)
    }
}
