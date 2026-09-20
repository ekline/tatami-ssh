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

use std::boxed::Box;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::string::{String, ToString};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::vec::Vec;

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
    let end = drive(&mut stream, &mut observer, &mut obs, deadline, config, stop);
    let _ = stream.shutdown(Shutdown::Both);
    drop(stream);

    obs.end = end;
    obs.elapsed = accepted_at.elapsed();
    obs
}

fn drive(
    stream: &mut TcpStream,
    observer: &mut Observer,
    obs: &mut Observation,
    deadline: Instant,
    config: &ListenerConfig,
    stop: &AtomicBool,
) -> ObservationEnd {
    // Banner first, before any read.
    let banner = observer.server_identification().to_vec();
    match write_all_by(stream, &banner, deadline) {
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
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return ObservationEnd::TimedOut;
        };
        let slice = remaining.min(config.poll_interval.max(Duration::from_millis(1)));
        if let Err(e) = stream.set_read_timeout(Some(slice)) {
            return ObservationEnd::Io(e);
        }
        let want = buf.len().min(observer.room()).max(1);
        match stream.read(&mut buf[..want]) {
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

fn write_all_by(stream: &mut TcpStream, data: &[u8], deadline: Instant) -> io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline passed"))?;
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(&data[written..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "peer stopped reading",
                ));
            }
            Ok(n) => written += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "write timed out"));
            }
            Err(e) => return Err(e),
        }
    }
    stream.flush()
}
