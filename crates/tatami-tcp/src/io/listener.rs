//! Bounded diagnostic listener that runs one [`Observer`] per accepted TCP
//! connection.
//!
//! # Concurrency and admission
//!
//! Blocking sockets, one worker thread per admitted connection, at most
//! [`ListenerConfig::max_concurrent`] at a time. Capacity is acquired
//! before a worker is spawned. Worker threads are detached; they release
//! capacity when they finish, so no handle or report is retained by the
//! listener. When capacity is exhausted, further connections are accepted
//! and closed immediately without a worker (so the peer sees a connection,
//! not a backlog stall), counted as `dropped_at_capacity`, and reported in
//! rate-limited [`ListenerEvent::Overload`] records. Dropped connections
//! count toward [`ListenerConfig::max_connections`].
//!
//! # Deadlines
//!
//! Each observation has one deadline, [`ListenerConfig::connection_timeout`]
//! from acceptance, covering the banner write and all reads. Remaining time
//! is recomputed on every operation; a trickling peer cannot extend it.
//! Worker reads are additionally capped at a short poll interval so a stop
//! request is noticed promptly.
//!
//! # Stopping
//!
//! The accept loop polls a non-blocking listener, so a run ends when the
//! run duration elapses, the connection limit is reached, a [`StopHandle`]
//! is triggered, or the record sink fails, without needing another client
//! to connect. On a finite-run stop, active observations may complete
//! normally for up to [`ListenerConfig::shutdown_grace`]; any still active
//! are then cancelled (ending with [`ObservationEnd::Shutdown`]) and
//! waited for up to one more grace period. A [`StopHandle`] or a fatal
//! error cancels immediately.
//!
//! # Records
//!
//! Events go through a bounded channel to a single sink thread, so records
//! never interleave and a slow or blocked sink cannot hold sockets open:
//! workers use a non-blocking send and count a dropped record instead of
//! waiting. The final summary reports every drop counter.
//!
//! # Testing seam
//!
//! The per-connection driver (`drive`) is written against the crate-private
//! `Conn`/`Clock` traits in `super::seam`; workers always pass the accepted
//! `TcpStream` and the system clock. The unit tests in this module drive it
//! with a scripted connection and a virtual clock and cover: the banner
//! delivered across short writes, `Interrupted` on read and write, trickling
//! reads that cannot extend the deadline, EOF at a boundary and mid-line/
//! mid-packet, a zero-length write, a deadline that has already passed
//! before the banner, deadline exhaustion inside a packet body, reads bounded
//! by [`Observer::room`], a stop requested mid-observation, and a silent peer
//! polled until the deadline. Sink failure, capacity saturation and stop
//! handling at the listener level are covered by the loopback tests in
//! `tests/observer_loopback.rs`, which remain the real-socket evidence.

use std::boxed::Box;
use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::string::{String, ToString};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::vec::Vec;

use super::seam::{Clock, Conn, SystemClock, remaining_until, write_all_by};
use crate::ident::OwnedIdentification;
use crate::initial::SkippedMessage;
use crate::observer::{
    ObservationOutcome, Observer, ObserverConfig, ObserverEvent, ObserverStage, ObserverStep,
    Proposal,
};

/// Listener policy. Defaults are local policy, not protocol requirements.
#[derive(Clone, Debug)]
pub struct ListenerConfig {
    /// Address to bind. Port 0 requests an ephemeral port; the actual
    /// address is reported by [`Listener::local_addr`].
    pub bind: SocketAddr,
    /// Maximum simultaneous observations.
    pub max_concurrent: usize,
    /// Total time allowed per connection from acceptance.
    pub connection_timeout: Duration,
    /// Stop after this many accepted connections (including ones dropped
    /// at capacity). `None` means unlimited.
    pub max_connections: Option<u64>,
    /// Stop after this long. `None` means until stopped.
    pub run_for: Option<Duration>,
    /// Observer behaviour and limits.
    pub observer: ObserverConfig,
    /// Size of each socket read.
    pub read_chunk: usize,
    /// Capacity of the record channel between workers and the sink.
    pub pending_records: usize,
    /// How long to wait for active workers after a stop condition.
    pub shutdown_grace: Duration,
    /// Poll interval for the non-blocking accept loop and worker reads.
    pub poll_interval: Duration,
    /// Minimum spacing between overload records.
    pub overload_report_interval: Duration,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        ListenerConfig {
            bind: SocketAddr::from(([127, 0, 0, 1], 2222)),
            max_concurrent: 32,
            connection_timeout: Duration::from_secs(5),
            max_connections: None,
            run_for: None,
            observer: ObserverConfig::default(),
            read_chunk: 4096,
            pending_records: 128,
            shutdown_grace: Duration::from_secs(5),
            poll_interval: Duration::from_millis(25),
            overload_report_interval: Duration::from_secs(1),
        }
    }
}

/// Configuration problems detected before binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// A duration is zero or too large to add to an instant.
    BadDuration(&'static str),
    /// `max_concurrent` or `pending_records` is zero.
    ZeroLimit(&'static str),
    /// The observer's software version is invalid.
    Identification(crate::ident::InvalidLocalIdentification),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::BadDuration(name) => write!(f, "{name} must be positive and finite"),
            ConfigError::ZeroLimit(name) => write!(f, "{name} must be at least 1"),
            ConfigError::Identification(e) => write!(f, "server identification: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl ListenerConfig {
    /// Validates durations and limits.
    pub fn validate(&self) -> Result<(), ConfigError> {
        fn usable(d: Duration) -> bool {
            !d.is_zero() && Instant::now().checked_add(d).is_some()
        }
        if !usable(self.connection_timeout) {
            return Err(ConfigError::BadDuration("connection_timeout"));
        }
        if let Some(d) = self.run_for {
            if !usable(d) {
                return Err(ConfigError::BadDuration("run_for"));
            }
        }
        if !usable(self.poll_interval) {
            return Err(ConfigError::BadDuration("poll_interval"));
        }
        if !usable(self.overload_report_interval) {
            return Err(ConfigError::BadDuration("overload_report_interval"));
        }
        if Instant::now().checked_add(self.shutdown_grace).is_none() {
            return Err(ConfigError::BadDuration("shutdown_grace"));
        }
        if self.max_concurrent == 0 {
            return Err(ConfigError::ZeroLimit("max_concurrent"));
        }
        if self.pending_records == 0 {
            return Err(ConfigError::ZeroLimit("pending_records"));
        }
        if self.read_chunk == 0 {
            return Err(ConfigError::ZeroLimit("read_chunk"));
        }
        Observer::new(&self.observer).map_err(ConfigError::Identification)?;
        Ok(())
    }
}

/// How an observation ended, from the host's point of view.
#[derive(Debug)]
pub enum ObservationEnd {
    /// The observer produced an outcome.
    Observer(ObservationOutcome),
    /// The connection deadline passed.
    TimedOut,
    /// The listener was stopping.
    Shutdown,
    /// Socket error.
    Io(io::Error),
}

impl ObservationEnd {
    /// Stable outcome code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ObservationEnd::Observer(o) => o.code(),
            ObservationEnd::TimedOut => "timeout",
            ObservationEnd::Shutdown => "shutdown",
            ObservationEnd::Io(_) => "io_error",
        }
    }
}

/// Everything recorded about one connection.
#[derive(Debug)]
pub struct Observation {
    /// Process-local sequence number, starting at 1.
    pub id: u64,
    /// Our address for the connection.
    pub local: SocketAddr,
    /// The peer's address as seen by the OS. This is where the packets came
    /// from, not proof of who operated the client.
    pub peer: SocketAddr,
    /// Acceptance time as seconds and nanoseconds since the Unix epoch.
    pub accepted_unix: Duration,
    /// Monotonic time from acceptance to end.
    pub elapsed: Duration,
    /// Bytes read from the peer.
    pub bytes_read: u64,
    /// Bytes written to the peer.
    pub bytes_written: u64,
    /// Server identification sent, without `CR LF`.
    pub server_identification: Vec<u8>,
    /// Client identification, if one was received.
    pub client_identification: Option<OwnedIdentification>,
    /// Pre-`KEXINIT` messages skipped, in order.
    pub messages: Vec<SkippedMessage>,
    /// Client proposal, if a `KEXINIT` was decoded.
    pub proposal: Option<Proposal>,
    /// Last stage reached before the end.
    pub stage: ObserverStage,
    /// How it ended.
    pub end: ObservationEnd,
}

/// Why the listener stopped.
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
    /// `accept` failed with a non-transient error.
    AcceptFailed,
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
            StopReason::AcceptFailed => "accept_failed",
        }
    }
}

/// Final counters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// Address that was bound.
    pub bound: SocketAddr,
    /// Connections accepted, including those dropped at capacity.
    pub accepted: u64,
    /// Connections that received a worker.
    pub observed: u64,
    /// Connections accepted and closed because capacity was exhausted.
    pub dropped_at_capacity: u64,
    /// Observation records that could not be queued for the sink.
    pub records_dropped: u64,
    /// Workers still running when the shutdown grace period expired.
    pub workers_abandoned: usize,
    /// Why the run ended.
    pub reason: StopReason,
    /// Description of the fatal error, if any.
    pub error: Option<String>,
    /// Wall time of the run.
    pub elapsed: Duration,
}

/// Records delivered to the sink, in order.
#[derive(Debug)]
pub enum ListenerEvent {
    /// The listener is accepting on `bound`.
    Started {
        /// Actual bound address.
        bound: SocketAddr,
    },
    /// One connection's observation.
    Observation(Box<Observation>),
    /// Connections were dropped at capacity since the previous overload
    /// record.
    Overload {
        /// Drops since the previous overload record.
        dropped_since_last: u64,
        /// Drops so far.
        total_dropped: u64,
    },
    /// The run ended.
    Stopped(Summary),
}

/// Error a sink may return; the run then stops with
/// [`StopReason::SinkFailed`].
pub type SinkError = Box<dyn std::error::Error + Send + Sync>;

/// Consumer of [`ListenerEvent`]s. Called from one dedicated thread.
pub type Sink = Box<dyn FnMut(ListenerEvent) -> Result<(), SinkError> + Send>;

/// Requests a running listener to stop.
#[derive(Clone, Debug)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    /// Asks the listener to stop accepting and to wind down workers.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// `true` once stop has been requested.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// A bound, not yet running listener.
pub struct Listener {
    config: ListenerConfig,
    socket: TcpListener,
    bound: SocketAddr,
    stop: Arc<AtomicBool>,
}

struct Shared {
    stop: Arc<AtomicBool>,
    active: AtomicUsize,
    records_dropped: AtomicU64,
    tx: mpsc::SyncSender<ListenerEvent>,
}

impl Listener {
    /// Validates the configuration and binds the socket.
    pub fn bind(config: ListenerConfig) -> Result<Self, BindError> {
        config.validate().map_err(BindError::Config)?;
        let socket = TcpListener::bind(config.bind).map_err(BindError::Io)?;
        socket.set_nonblocking(true).map_err(BindError::Io)?;
        let bound = socket.local_addr().map_err(BindError::Io)?;
        Ok(Listener {
            config,
            socket,
            bound,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The actual bound address (meaningful when port 0 was requested).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound
    }

    /// Handle for stopping the run from another thread.
    #[must_use]
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle(self.stop.clone())
    }

    /// Runs until a stop condition, delivering events to `sink` on a
    /// dedicated thread. Returns the same summary that was delivered as
    /// [`ListenerEvent::Stopped`].
    pub fn run(self, sink: Sink) -> Summary {
        let started = Instant::now();
        let deadline = self.config.run_for.map(|d| started + d);
        let (tx, rx) = mpsc::sync_channel::<ListenerEvent>(self.config.pending_records);
        let shared = Arc::new(Shared {
            stop: self.stop.clone(),
            active: AtomicUsize::new(0),
            records_dropped: AtomicU64::new(0),
            tx,
        });

        let sink_failed = Arc::new(AtomicBool::new(false));
        let sink_done = Arc::new(AtomicBool::new(false));
        let sink_error = Arc::new(std::sync::Mutex::new(None::<String>));
        {
            let failed = sink_failed.clone();
            let done = sink_done.clone();
            let error = sink_error.clone();
            let mut sink = sink;
            // Detached: a sink blocked inside a write cannot be joined, so
            // completion is signalled through `done` and waited for with a
            // bound below.
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

        let _ = shared.tx.send(ListenerEvent::Started { bound: self.bound });

        let mut accepted: u64 = 0;
        let mut observed: u64 = 0;
        let mut dropped: u64 = 0;
        let mut dropped_reported: u64 = 0;
        let mut last_overload_report: Option<Instant> = None;
        let mut error: Option<String> = None;

        let reason = loop {
            if shared.stop.load(Ordering::SeqCst) {
                break StopReason::StopRequested;
            }
            if sink_failed.load(Ordering::SeqCst) {
                break StopReason::SinkFailed;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break StopReason::RunDurationElapsed;
            }
            if self.config.max_connections.is_some_and(|m| accepted >= m) {
                break StopReason::ConnectionLimitReached;
            }

            // Flush an aggregated overload record at most once per interval.
            if dropped > dropped_reported
                && last_overload_report
                    .is_none_or(|t| t.elapsed() >= self.config.overload_report_interval)
            {
                let _ = try_emit(
                    &shared,
                    ListenerEvent::Overload {
                        dropped_since_last: dropped - dropped_reported,
                        total_dropped: dropped,
                    },
                );
                dropped_reported = dropped;
                last_overload_report = Some(Instant::now());
            }

            match self.socket.accept() {
                Ok((stream, peer)) => {
                    accepted += 1;
                    let accepted_at = Instant::now();
                    // Acquire capacity before spawning.
                    let admitted = shared
                        .active
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                            (n < self.config.max_concurrent).then_some(n + 1)
                        })
                        .is_ok();
                    if !admitted {
                        dropped += 1;
                        let _ = stream.shutdown(Shutdown::Both);
                        drop(stream);
                        continue;
                    }
                    observed += 1;
                    let id = observed;
                    let shared = shared.clone();
                    let config = self.config.clone();
                    let local = self.bound;
                    thread::spawn(move || {
                        let obs = observe_connection(
                            stream,
                            id,
                            local,
                            peer,
                            accepted_at,
                            &config,
                            &shared.stop,
                        );
                        let _ = try_emit(&shared, ListenerEvent::Observation(Box::new(obs)));
                        shared.active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(self.config.poll_interval);
                }
                Err(e) if is_transient_accept_error(&e) => {
                    thread::sleep(self.config.poll_interval);
                }
                Err(e) => {
                    error = Some(e.to_string());
                    break StopReason::AcceptFailed;
                }
            }
        };

        // Stop accepting. Active observations may finish on their own
        // (bounded by their connection deadlines) within the grace period;
        // after that they are cancelled and given one more grace period.
        // A stop request or fatal error cancels immediately.
        drop(self.socket);
        if matches!(reason, StopReason::SinkFailed | StopReason::AcceptFailed) {
            shared.stop.store(true, Ordering::SeqCst);
        }
        let wait_step = self.config.poll_interval.min(Duration::from_millis(10));
        let grace_end = Instant::now() + self.config.shutdown_grace;
        while shared.active.load(Ordering::SeqCst) > 0 && Instant::now() < grace_end {
            thread::sleep(wait_step);
        }
        if shared.active.load(Ordering::SeqCst) > 0 {
            shared.stop.store(true, Ordering::SeqCst);
            let cancel_end = Instant::now() + self.config.shutdown_grace;
            while shared.active.load(Ordering::SeqCst) > 0 && Instant::now() < cancel_end {
                thread::sleep(wait_step);
            }
        }
        let workers_abandoned = shared.active.load(Ordering::SeqCst);

        if dropped > dropped_reported {
            let _ = try_emit(
                &shared,
                ListenerEvent::Overload {
                    dropped_since_last: dropped - dropped_reported,
                    total_dropped: dropped,
                },
            );
        }

        if reason == StopReason::SinkFailed {
            error = sink_error.lock().ok().and_then(|e| e.clone());
        }

        let summary = Summary {
            bound: self.bound,
            accepted,
            observed,
            dropped_at_capacity: dropped,
            records_dropped: shared.records_dropped.load(Ordering::SeqCst),
            workers_abandoned,
            reason,
            error,
            elapsed: started.elapsed(),
        };
        // Bounded: never wait on a wedged sink forever. If the summary
        // cannot be queued within the grace period it is counted as dropped
        // in the returned value (the sink never sees it either way).
        let mut pending = Some(ListenerEvent::Stopped(summary.clone()));
        let give_up = Instant::now() + self.config.shutdown_grace;
        while let Some(event) = pending.take() {
            match shared.tx.try_send(event) {
                Ok(()) => {}
                Err(TrySendError::Full(event)) if Instant::now() < give_up => {
                    pending = Some(event);
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => {
                    shared.records_dropped.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let final_dropped = shared.records_dropped.load(Ordering::SeqCst);
        drop(shared); // closes the channel; the sink thread exits after draining
        let wait_end = Instant::now() + self.config.shutdown_grace;
        while !sink_done.load(Ordering::SeqCst) && Instant::now() < wait_end {
            thread::sleep(Duration::from_millis(5));
        }
        Summary {
            records_dropped: final_dropped,
            ..summary
        }
    }
}

/// Failure of [`Listener::bind`].
#[derive(Debug)]
pub enum BindError {
    /// Invalid configuration.
    Config(ConfigError),
    /// The OS refused the bind.
    Io(io::Error),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::Config(e) => write!(f, "invalid configuration: {e}"),
            BindError::Io(e) => write!(f, "bind failed: {e}"),
        }
    }
}

impl std::error::Error for BindError {}

fn try_emit(shared: &Shared, event: ListenerEvent) -> bool {
    match shared.tx.try_send(event) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            shared.records_dropped.fetch_add(1, Ordering::SeqCst);
            false
        }
    }
}

/// Errors after which `accept` is worth retrying after a pause: a peer that
/// vanished between SYN and accept, or a temporary descriptor shortage
/// (`EMFILE` 24 / `ENFILE` 23 on Linux), which clears as workers finish.
fn is_transient_accept_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::Interrupted
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::TimedOut
    ) || matches!(e.raw_os_error(), Some(23 | 24))
}

fn observe_connection(
    mut stream: TcpStream,
    id: u64,
    local: SocketAddr,
    peer: SocketAddr,
    accepted_at: Instant,
    config: &ListenerConfig,
    stop: &AtomicBool,
) -> Observation {
    let accepted_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let deadline = accepted_at + config.connection_timeout;
    let mut observer = Observer::new(&config.observer).expect("validated at bind");
    let mut obs = Observation {
        id,
        local,
        peer,
        accepted_unix,
        elapsed: Duration::ZERO,
        bytes_read: 0,
        bytes_written: 0,
        server_identification: observer.server_identification_line().to_vec(),
        client_identification: None,
        messages: Vec::new(),
        proposal: None,
        stage: ObserverStage::ClientIdentification,
        end: ObservationEnd::TimedOut,
    };

    let _ = stream.set_nodelay(true);
    let end = drive(
        &mut stream,
        &SystemClock,
        &mut observer,
        &mut obs,
        deadline,
        config,
        stop,
    );
    let _ = stream.shutdown(Shutdown::Both);
    drop(stream);

    obs.end = end;
    obs.elapsed = accepted_at.elapsed();
    obs
}

fn drive<C: Conn, K: Clock>(
    conn: &mut C,
    clock: &K,
    observer: &mut Observer,
    obs: &mut Observation,
    deadline: Instant,
    config: &ListenerConfig,
    stop: &AtomicBool,
) -> ObservationEnd {
    // Banner first, before any read.
    let banner = observer.server_identification().to_vec();
    match write_all_by(conn, clock, &banner, deadline) {
        Ok(()) => obs.bytes_written += banner.len() as u64,
        Err(e) if e.kind() == io::ErrorKind::TimedOut => return ObservationEnd::TimedOut,
        Err(e) => return ObservationEnd::Io(e),
    }

    let mut buf = std::vec![0u8; config.read_chunk];
    loop {
        loop {
            match observer.step() {
                ObserverStep::NeedMore => break,
                ObserverStep::Event(ObserverEvent::ClientIdentification(i)) => {
                    obs.client_identification = Some(i);
                }
                ObserverStep::Event(ObserverEvent::Skipped(m)) => obs.messages.push(m),
                ObserverStep::Finished(outcome) => {
                    if let ObservationOutcome::Proposal(p) = &outcome {
                        obs.proposal = Some((**p).clone());
                    }
                    obs.stage = ObserverStage::Finished;
                    return ObservationEnd::Observer(outcome);
                }
            }
        }
        obs.stage = observer.stage();

        if stop.load(Ordering::SeqCst) {
            return ObservationEnd::Shutdown;
        }
        let Some(remaining) = remaining_until(clock, deadline) else {
            return ObservationEnd::TimedOut;
        };
        let slice = remaining.min(config.poll_interval.max(Duration::from_millis(1)));
        if let Err(e) = conn.set_read_timeout(Some(slice)) {
            return ObservationEnd::Io(e);
        }
        let want = buf.len().min(observer.room()).max(1);
        match conn.read(&mut buf[..want]) {
            Ok(0) => {
                let outcome = observer.input_ended();
                obs.stage = ObserverStage::Finished;
                return ObservationEnd::Observer(outcome);
            }
            Ok(n) => {
                obs.bytes_read += n as u64;
                observer.feed(&buf[..n]);
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return ObservationEnd::Io(e),
        }
    }
}

/// Deterministic fault tests for the per-connection driver, on a scripted
/// connection and a virtual clock. No sockets, threads or sleeps; see
/// `super::seam::scripted`. Listener-level behaviour (admission, sink
/// failure, stop handling across workers) is covered by the loopback tests.
#[cfg(test)]
mod tests {
    use super::super::seam::scripted::{ReadEvent, ScriptedConn, VirtualClock, WriteEvent};
    use super::*;
    use crate::initial::InitialLimits;
    use crate::packet::{HEADER_LEN, PacketLimits, encode_initial_packet};
    use tatami_wire::Writer;

    const CLIENT_IDENT: &[u8] = b"SSH-2.0-Fixture_1.0\r\n";

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn data(bytes: &[u8]) -> ReadEvent {
        ReadEvent::Data(bytes.to_vec())
    }

    fn kexinit_packet() -> Vec<u8> {
        let mut buf = [0u8; 512];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).unwrap();
        w.write_bytes(&[0xAB; 16]).unwrap();
        w.write_string(b"curve25519-sha256,ext-info-c").unwrap();
        w.write_string(b"ssh-ed25519").unwrap();
        w.write_string(b"aes128-ctr").unwrap();
        w.write_string(b"aes256-ctr").unwrap();
        w.write_string(b"hmac-sha2-256").unwrap();
        w.write_string(b"hmac-sha2-512").unwrap();
        w.write_string(b"none").unwrap();
        w.write_string(b"zlib@openssh.com").unwrap();
        w.write_string(b"").unwrap();
        w.write_string(b"").unwrap();
        w.write_bool(false).unwrap();
        w.write_u32(0).unwrap();
        let payload = w.written().to_vec();
        let mut out = std::vec![0u8; payload.len() + 64];
        let n = encode_initial_packet(&payload, 0x11, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// A packet header claiming a small body that never fully arrives.
    fn partial_header() -> Vec<u8> {
        std::vec![0, 0, 0, 60, 4]
    }

    fn config(poll_ms: u64, read_chunk: usize) -> ListenerConfig {
        ListenerConfig {
            poll_interval: ms(poll_ms),
            read_chunk,
            ..ListenerConfig::default()
        }
    }

    /// An observer configuration whose buffer is smaller than a 4 KiB chunk.
    fn tiny_observer() -> ObserverConfig {
        ObserverConfig {
            initial: InitialLimits {
                packet: PacketLimits {
                    max_packet_length: 64,
                },
                ..InitialLimits::default()
            },
            max_identification_line: 64,
            ..ObserverConfig::default()
        }
    }

    struct Outcome {
        end: ObservationEnd,
        obs: Observation,
        observer: Observer,
        conn: ScriptedConn,
        clock: VirtualClock,
        deadline: Duration,
        poll: Duration,
    }

    impl Outcome {
        fn banner_len(&self) -> u64 {
            self.observer.server_identification().len() as u64
        }

        /// Every read timeout is at most the poll interval and never reaches
        /// past the deadline; every write timeout is exactly the time then
        /// remaining; the virtual clock never passes the deadline.
        fn assert_deadline_discipline(&self) {
            for (at, timeout) in &self.conn.read_timeouts {
                assert!(
                    *timeout <= self.poll,
                    "read timeout {timeout:?} exceeds the poll"
                );
                assert!(
                    *at + *timeout <= self.deadline,
                    "read timeout {timeout:?} at {at:?} reaches past the deadline"
                );
            }
            for (at, timeout) in &self.conn.write_timeouts {
                assert_eq!(*at + *timeout, self.deadline);
            }
            assert!(self.clock.elapsed() <= self.deadline);
        }

        fn outcome(&self) -> &ObservationOutcome {
            match &self.end {
                ObservationEnd::Observer(o) => o,
                other => panic!("expected an observer outcome, got {other:?}"),
            }
        }
    }

    fn run_with(
        config: &ListenerConfig,
        reads: Vec<ReadEvent>,
        writes: Vec<WriteEvent>,
        deadline: Duration,
        stop: &AtomicBool,
    ) -> Outcome {
        let clock = VirtualClock::new();
        let mut conn = ScriptedConn::new(&clock, reads, writes);
        let mut observer = Observer::new(&config.observer).unwrap();
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut obs = Observation {
            id: 1,
            local: addr,
            peer: addr,
            accepted_unix: Duration::ZERO,
            elapsed: Duration::ZERO,
            bytes_read: 0,
            bytes_written: 0,
            server_identification: observer.server_identification_line().to_vec(),
            client_identification: None,
            messages: Vec::new(),
            proposal: None,
            stage: ObserverStage::ClientIdentification,
            end: ObservationEnd::TimedOut,
        };
        let end = drive(
            &mut conn,
            &clock,
            &mut observer,
            &mut obs,
            clock.now() + deadline,
            config,
            stop,
        );
        Outcome {
            end,
            obs,
            observer,
            conn,
            clock,
            deadline,
            poll: config.poll_interval,
        }
    }

    fn run(reads: Vec<ReadEvent>, writes: Vec<WriteEvent>, deadline: Duration) -> Outcome {
        run_with(
            &config(25, 4096),
            reads,
            writes,
            deadline,
            &AtomicBool::new(false),
        )
    }

    #[test]
    fn banner_is_written_across_short_writes() {
        let out = run(
            std::vec![data(CLIENT_IDENT), data(&kexinit_packet())],
            std::vec![
                WriteEvent::Accept(3),
                WriteEvent::Accept(5),
                WriteEvent::Accept(1),
            ],
            ms(1_000),
        );
        assert!(matches!(
            out.outcome(),
            ObservationOutcome::Proposal(p) if p.anomalies.is_empty()
        ));
        assert_eq!(out.conn.written, out.observer.server_identification());
        assert_eq!(out.obs.bytes_written, out.banner_len());
        // 3 + 5 + 1, then the rest in one write; a timeout set before each.
        assert_eq!(out.conn.write_calls, 4);
        assert_eq!(out.conn.write_timeouts.len(), 4);
        assert_eq!(
            out.obs.bytes_read,
            (CLIENT_IDENT.len() + kexinit_packet().len()) as u64
        );
        assert!(out.obs.proposal.is_some());
        assert_eq!(out.obs.stage, ObserverStage::Finished);
        out.assert_deadline_discipline();
    }

    #[test]
    fn interrupted_read_and_write_are_retried_without_resetting_the_deadline() {
        let out = run(
            std::vec![
                ReadEvent::Elapse(ms(10)),
                data(CLIENT_IDENT),
                ReadEvent::Err(io::ErrorKind::Interrupted),
                ReadEvent::Elapse(ms(10)),
                data(&kexinit_packet()),
            ],
            std::vec![
                WriteEvent::Err(io::ErrorKind::Interrupted),
                WriteEvent::Elapse(ms(50)),
                WriteEvent::Accept(4),
                WriteEvent::Err(io::ErrorKind::Interrupted),
            ],
            ms(1_000),
        );
        assert!(matches!(out.outcome(), ObservationOutcome::Proposal(_)));
        assert_eq!(out.obs.bytes_written, out.banner_len());
        assert_eq!(out.clock.elapsed(), ms(70));
        assert_eq!(
            out.conn.write_timeouts,
            [
                (ms(0), ms(1_000)),
                (ms(0), ms(1_000)),
                (ms(50), ms(950)),
                (ms(50), ms(950)),
            ]
        );
        // Reads are sliced to the poll interval; an Interrupted read does
        // not move the clock and the next slice is identical.
        assert_eq!(
            out.conn.read_timeouts,
            [(ms(50), ms(25)), (ms(60), ms(25)), (ms(60), ms(25))]
        );
        out.assert_deadline_discipline();
    }

    #[test]
    fn trickling_client_cannot_extend_the_deadline() {
        // One byte of a valid identification prefix every 300 ms against a
        // 1 s deadline: three bytes arrive, the fourth silence hits it. The
        // silence is consumed in 25 ms poll slices.
        let mut reads = Vec::new();
        for b in b"SSH-2.0-" {
            reads.push(ReadEvent::Elapse(ms(300)));
            reads.push(data(&[*b]));
        }
        let out = run(reads, Vec::new(), ms(1_000));
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(
            out.clock.elapsed(),
            ms(1_000),
            "ended exactly at the deadline"
        );
        assert_eq!(out.obs.bytes_read, 3);
        assert_eq!(out.observer.pending_bytes(), 3);
        assert_eq!(out.obs.stage, ObserverStage::ClientIdentification);
        assert!(out.obs.client_identification.is_none());
        // 3 x 12 empty polls, 3 data reads, 4 empty polls to the deadline.
        assert_eq!(out.conn.read_requests.len(), 43);
        assert!(out.conn.unread_events() > 0, "the line was never completed");
        out.assert_deadline_discipline();
    }

    #[test]
    fn eof_at_boundary_and_mid_stream() {
        let k = kexinit_packet();
        let half = k.len() / 2;
        let cases: [(Vec<ReadEvent>, ObserverStage, usize, bool); 4] = [
            (
                std::vec![ReadEvent::Eof],
                ObserverStage::ClientIdentification,
                0,
                false,
            ),
            (
                std::vec![data(b"SSH-2.0-Tru"), ReadEvent::Eof],
                ObserverStage::ClientIdentification,
                11,
                false,
            ),
            (
                std::vec![data(CLIENT_IDENT), ReadEvent::Eof],
                ObserverStage::InitialPackets,
                0,
                true,
            ),
            (
                std::vec![data(CLIENT_IDENT), data(&k[..half]), ReadEvent::Eof],
                ObserverStage::InitialPackets,
                half,
                true,
            ),
        ];
        for (reads, stage, pending, ident_seen) in cases {
            let out = run(reads, Vec::new(), ms(1_000));
            assert_eq!(
                out.outcome(),
                &ObservationOutcome::Eof {
                    stage,
                    pending_bytes: pending
                }
            );
            assert_eq!(out.obs.stage, ObserverStage::Finished);
            assert_eq!(out.obs.client_identification.is_some(), ident_seen);
            assert_eq!(out.obs.bytes_written, out.banner_len());
            assert_eq!(out.clock.elapsed(), Duration::ZERO);
        }
    }

    #[test]
    fn zero_length_banner_write_is_an_io_error() {
        let out = run(Vec::new(), std::vec![WriteEvent::Zero], ms(1_000));
        match &out.end {
            ObservationEnd::Io(e) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
            other => panic!("{other:?}"),
        }
        assert_eq!(out.obs.bytes_written, 0);
        assert!(
            out.conn.read_requests.is_empty(),
            "no read after a failed banner"
        );

        let out = run(
            Vec::new(),
            std::vec![WriteEvent::Err(io::ErrorKind::BrokenPipe)],
            ms(1_000),
        );
        assert!(matches!(&out.end, ObservationEnd::Io(e) if e.kind() == io::ErrorKind::BrokenPipe));
        assert_eq!(out.obs.bytes_written, 0);
    }

    #[test]
    fn deadline_already_passed_before_the_banner() {
        let out = run(
            std::vec![data(CLIENT_IDENT), data(&kexinit_packet())],
            Vec::new(),
            Duration::ZERO,
        );
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(out.conn.write_calls, 0, "no write was attempted");
        assert_eq!(out.obs.bytes_written, 0);
        assert!(out.conn.read_requests.is_empty());

        // A banner write that blocks until the deadline is also a timeout.
        let out = run(
            std::vec![data(CLIENT_IDENT)],
            std::vec![WriteEvent::Elapse(ms(5_000))],
            ms(1_000),
        );
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert_eq!(out.obs.bytes_written, 0);
        assert!(out.conn.read_requests.is_empty());
    }

    #[test]
    fn deadline_exhausted_inside_a_packet_body() {
        let k = kexinit_packet();
        let mut reads = std::vec![data(CLIENT_IDENT), data(&k[..HEADER_LEN])];
        for b in &k[HEADER_LEN..HEADER_LEN + 6] {
            reads.push(ReadEvent::Elapse(ms(200)));
            reads.push(data(&[*b]));
        }
        let out = run(reads, Vec::new(), ms(1_000));
        // Header at t=0, one body byte at 200/400/600/800 ms, deadline at
        // 1000 ms while waiting for the fifth.
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(out.obs.stage, ObserverStage::InitialPackets);
        assert_eq!(out.observer.pending_bytes(), HEADER_LEN + 4);
        assert_eq!(
            out.obs.bytes_read,
            (CLIENT_IDENT.len() + HEADER_LEN + 4) as u64
        );
        assert!(out.obs.client_identification.is_some());
        assert!(out.obs.proposal.is_none());
        assert_eq!(out.clock.elapsed(), ms(1_000));
        out.assert_deadline_discipline();
    }

    #[test]
    fn reads_never_exceed_chunk_or_room() {
        // Chunk smaller than room: every read asks for exactly the chunk.
        let out = run_with(
            &config(25, 7),
            std::vec![data(CLIENT_IDENT), data(&kexinit_packet())],
            Vec::new(),
            ms(1_000),
            &AtomicBool::new(false),
        );
        assert!(matches!(out.outcome(), ObservationOutcome::Proposal(_)));
        assert!(out.conn.read_requests.len() > 10);
        assert!(out.conn.read_requests.iter().all(|&n| n == 7));

        // Chunk larger than room: reads shrink as unconsumed bytes pile up.
        let mut c = config(25, 4096);
        c.observer = tiny_observer();
        let cap = c.observer.buffer_capacity();
        assert!(cap < 4096);
        let out = run_with(
            &c,
            std::vec![
                data(CLIENT_IDENT),
                data(&partial_header()),
                data(&[1]),
                data(&[2]),
            ],
            Vec::new(),
            ms(1_000),
            &AtomicBool::new(false),
        );
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(out.observer.pending_bytes(), 7);
        // Four data reads, then 40 empty polls until the deadline, all
        // bounded by the room left in the observer buffer.
        assert_eq!(out.conn.read_requests.len(), 44);
        assert_eq!(
            out.conn.read_requests[..5],
            [cap, cap, cap - 5, cap - 6, cap - 7]
        );
        assert!(out.conn.read_requests.iter().all(|&n| n <= cap));
        assert!(out.conn.read_requests[4..].iter().all(|&n| n == cap - 7));
    }

    #[test]
    fn stop_requested_mid_observation_yields_shutdown() {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let k = kexinit_packet();
        let out = run_with(
            &config(25, 4096),
            std::vec![
                data(CLIENT_IDENT),
                ReadEvent::Hook(Box::new(move || flag.store(true, Ordering::SeqCst))),
                data(&k[..HEADER_LEN]),
            ],
            Vec::new(),
            ms(1_000),
            &stop,
        );
        assert!(matches!(out.end, ObservationEnd::Shutdown));
        // The identification was recorded before the stop was noticed; the
        // partial packet read alongside the stop is left undecoded.
        assert!(out.obs.client_identification.is_some());
        assert!(out.obs.proposal.is_none());
        assert_eq!(out.obs.stage, ObserverStage::InitialPackets);
        assert_eq!(out.obs.bytes_read, (CLIENT_IDENT.len() + HEADER_LEN) as u64);
        assert_eq!(out.observer.pending_bytes(), HEADER_LEN);
        assert_eq!(out.obs.bytes_written, out.banner_len());
        assert_eq!(out.conn.read_requests.len(), 2, "no read after the stop");

        // The stop is checked only once the observer needs more input: an
        // outcome already in hand is never discarded by a stop.
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let out = run_with(
            &config(25, 4096),
            std::vec![
                data(CLIENT_IDENT),
                ReadEvent::Hook(Box::new(move || flag.store(true, Ordering::SeqCst))),
                data(&k),
            ],
            Vec::new(),
            ms(1_000),
            &stop,
        );
        assert!(matches!(out.outcome(), ObservationOutcome::Proposal(_)));
        assert!(stop.load(Ordering::SeqCst));

        // A stop already requested is honoured after the banner, before the
        // first read.
        let out = run_with(
            &config(25, 4096),
            std::vec![data(CLIENT_IDENT)],
            Vec::new(),
            ms(1_000),
            &AtomicBool::new(true),
        );
        assert!(matches!(out.end, ObservationEnd::Shutdown));
        assert_eq!(out.obs.bytes_written, out.banner_len());
        assert!(out.conn.read_requests.is_empty());
        assert_eq!(out.obs.stage, ObserverStage::ClientIdentification);
    }

    #[test]
    fn silent_client_is_polled_until_the_deadline_not_spun_on() {
        // An empty script is a connected, silent peer: each poll consumes
        // its slice; the scripted connection's call cap would panic on a spin.
        let out = run(Vec::new(), Vec::new(), ms(1_000));
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert_eq!(out.conn.read_requests.len(), 40);
        assert!(out.conn.read_timeouts.iter().all(|(_, t)| *t == ms(25)));
        assert_eq!(out.obs.bytes_written, out.banner_len());
        out.assert_deadline_discipline();

        // Explicit WouldBlock results behave the same way.
        let reads = (0..100)
            .map(|_| ReadEvent::Err(io::ErrorKind::WouldBlock))
            .collect();
        let out = run(reads, Vec::new(), ms(1_000));
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert_eq!(out.conn.read_requests.len(), 40);
        assert_eq!(out.conn.unread_events(), 60);

        // A poll interval that does not divide the deadline: the last slice
        // is the shorter remainder, never an overshoot.
        let out = run_with(
            &config(30, 4096),
            Vec::new(),
            Vec::new(),
            ms(1_000),
            &AtomicBool::new(false),
        );
        assert!(matches!(out.end, ObservationEnd::TimedOut));
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert_eq!(out.conn.read_requests.len(), 34);
        assert_eq!(out.conn.read_timeouts.last(), Some(&(ms(990), ms(10))));
        out.assert_deadline_discipline();
    }
}
