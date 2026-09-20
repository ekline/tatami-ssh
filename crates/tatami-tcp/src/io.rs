//! Host socket adapters for the TCP binding (requires `std`).
//!
//! This module owns everything the portable modules must not: name
//! resolution, connecting, blocking reads and writes, OS deadlines and socket
//! cleanup. It drives the portable [`Probe`] state machine.
//!
//! # Deadlines
//!
//! Two phase deadlines are enforced, not per-byte timeouts that reset:
//!
//! - **Connect:** the whole connect phase, across all resolved addresses,
//!   must finish within [`IoConfig::connect_timeout`].
//! - **Read:** from a successful connect until the probe finishes, all
//!   reading must complete within [`IoConfig::read_timeout`]. Each socket
//!   read is bounded by the time remaining in the phase.
//!
//! # Name resolution
//!
//! Resolution uses the standard library's synchronous `ToSocketAddrs`, which
//! is **not** covered by either deadline; a slow resolver can block for as
//! long as the OS allows. Numeric IPv4/IPv6 addresses never hit the
//! resolver. Bounded resolution is a possible later improvement.
//!
//! For a name with several addresses, at most [`IoConfig::max_connect_attempts`]
//! are tried in resolver order, each with the time remaining in the connect
//! phase. The address that actually connected is reported.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::string::{String, ToString};
use std::time::{Duration, Instant};
use std::vec::Vec;

use crate::probe::{Probe, ProbeConfig, ProbeEnd, ProbeEvent, Stage, Step};

/// Host-side timing and connection policy for a probe run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoConfig {
    /// Deadline for the connect phase across all address attempts.
    pub connect_timeout: Duration,
    /// Deadline for the read phase (identification through `KEXINIT`).
    pub read_timeout: Duration,
    /// Maximum number of resolved addresses to try.
    pub max_connect_attempts: usize,
    /// Size of each socket read.
    pub read_chunk: usize,
}

impl Default for IoConfig {
    fn default() -> Self {
        IoConfig {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(10),
            max_connect_attempts: 4,
            read_chunk: 4096,
        }
    }
}

/// Why a run stopped, from the host's point of view.
#[derive(Debug)]
pub enum RunEnd {
    /// The portable probe produced a terminal outcome.
    Probe(ProbeEnd),
    /// The read-phase deadline passed.
    TimedOut {
        /// Probe stage when the deadline passed.
        stage: Stage,
        /// Bytes buffered but unconsumed at that point.
        pending_bytes: usize,
    },
    /// The socket failed.
    Io {
        /// Probe stage when the error occurred.
        stage: Stage,
        /// The error.
        error: io::Error,
    },
}

/// Everything observed during one probe run.
#[derive(Debug)]
pub struct ProbeRun {
    /// Address that actually connected.
    pub peer: SocketAddr,
    /// Local address of the connection.
    pub local: SocketAddr,
    /// Client identification bytes sent, including `CR LF`.
    pub client_identification: Vec<u8>,
    /// Observations in order.
    pub events: Vec<ProbeEvent>,
    /// Terminal outcome.
    pub end: RunEnd,
    /// Wall-clock time from connect success to `end`.
    pub elapsed: Duration,
}

/// Failure before any connection was established.
#[derive(Debug)]
pub enum ConnectError {
    /// The target resolved to no addresses.
    NoAddresses,
    /// Name resolution failed.
    Resolve(io::Error),
    /// Every attempted address failed. Attempts are in order tried.
    AllAttemptsFailed(Vec<(SocketAddr, io::Error)>),
    /// The connect deadline passed before any attempt succeeded.
    TimedOut(Vec<(SocketAddr, io::Error)>),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::NoAddresses => f.write_str("target resolved to no addresses"),
            ConnectError::Resolve(e) => write!(f, "name resolution failed: {e}"),
            ConnectError::AllAttemptsFailed(attempts) => {
                write!(f, "all {} connection attempt(s) failed", attempts.len())?;
                for (addr, e) in attempts {
                    write!(f, "; {addr}: {e}")?;
                }
                Ok(())
            }
            ConnectError::TimedOut(attempts) => {
                write!(
                    f,
                    "connect deadline passed after {} attempt(s)",
                    attempts.len()
                )?;
                for (addr, e) in attempts {
                    write!(f, "; {addr}: {e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConnectError {}

/// Resolves `host`/`port` and connects under the connect deadline.
pub fn connect(host: &str, port: u16, io: &IoConfig) -> Result<TcpStream, ConnectError> {
    let deadline = Instant::now() + io.connect_timeout;
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(ConnectError::Resolve)?
        .collect();
    if addrs.is_empty() {
        return Err(ConnectError::NoAddresses);
    }
    let mut failures = Vec::new();
    for addr in addrs.into_iter().take(io.max_connect_attempts.max(1)) {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(ConnectError::TimedOut(failures));
        };
        if remaining.is_zero() {
            return Err(ConnectError::TimedOut(failures));
        }
        match TcpStream::connect_timeout(&addr, remaining) {
            Ok(stream) => return Ok(stream),
            Err(e) => failures.push((addr, e)),
        }
    }
    if Instant::now() >= deadline {
        Err(ConnectError::TimedOut(failures))
    } else {
        Err(ConnectError::AllAttemptsFailed(failures))
    }
}

/// Runs a probe over an already connected stream, then shuts the socket
/// down. The read deadline starts when this function is called.
pub fn run_probe(
    mut stream: TcpStream,
    config: ProbeConfig,
    io: &IoConfig,
) -> io::Result<ProbeRun> {
    let started = Instant::now();
    let deadline = started + io.read_timeout;
    let peer = stream.peer_addr()?;
    let local = stream.local_addr()?;
    let mut probe = Probe::new(config)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let client_identification = probe.client_identification().to_vec();
    let mut events = Vec::new();

    let _ = stream.set_nodelay(true);

    let end = drive(
        &mut stream,
        &mut probe,
        &mut events,
        deadline,
        io.read_chunk,
    );

    // Best effort: the peer will see EOF, which is expected in this mode.
    let _ = stream.shutdown(Shutdown::Both);

    Ok(ProbeRun {
        peer,
        local,
        client_identification,
        events,
        end,
        elapsed: started.elapsed(),
    })
}

fn drive(
    stream: &mut TcpStream,
    probe: &mut Probe,
    events: &mut Vec<ProbeEvent>,
    deadline: Instant,
    chunk: usize,
) -> RunEnd {
    // Send our identification first, without waiting for the server.
    if let Err(error) = write_all_by(stream, probe.client_identification(), deadline) {
        return RunEnd::Io {
            stage: probe.stage(),
            error,
        };
    }

    let mut buf = std::vec![0u8; chunk.max(1)];
    loop {
        // Drain everything the probe can say about what it already has.
        loop {
            match probe.step() {
                Step::NeedMore => break,
                Step::Event(e) => events.push(e),
                Step::Finished(end) => return RunEnd::Probe(end),
            }
        }

        let Some(remaining) = remaining_until(deadline) else {
            return RunEnd::TimedOut {
                stage: probe.stage(),
                pending_bytes: probe.pending_bytes(),
            };
        };
        if let Err(error) = stream.set_read_timeout(Some(remaining)) {
            return RunEnd::Io {
                stage: probe.stage(),
                error,
            };
        }
        match stream.read(&mut buf) {
            Ok(0) => return RunEnd::Probe(probe.input_ended()),
            Ok(n) => probe.feed(&buf[..n]),
            Err(e) if is_timeout(&e) => {
                return RunEnd::TimedOut {
                    stage: probe.stage(),
                    pending_bytes: probe.pending_bytes(),
                };
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return RunEnd::Io {
                    stage: probe.stage(),
                    error,
                };
            }
        }
    }
}

fn write_all_by(stream: &mut TcpStream, data: &[u8], deadline: Instant) -> io::Result<()> {
    let remaining = remaining_until(deadline)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline passed before write"))?;
    stream.set_write_timeout(Some(remaining))?;
    stream.write_all(data)?;
    stream.flush()
}

/// Time left until `deadline`, or `None` if it has passed. Never returns a
/// zero duration, which `set_read_timeout` would reject.
fn remaining_until(deadline: Instant) -> Option<Duration> {
    let remaining = deadline.checked_duration_since(Instant::now())?;
    if remaining.is_zero() {
        None
    } else {
        Some(remaining)
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

impl RunEnd {
    /// Short label for reports.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            RunEnd::Probe(ProbeEnd::Proposal(p)) if p.anomalies.is_empty() => {
                String::from("complete: initial server proposal received")
            }
            RunEnd::Probe(ProbeEnd::Proposal(_)) => {
                String::from("proposal received with anomalies")
            }
            RunEnd::Probe(ProbeEnd::Disconnected { .. }) => String::from("server disconnected"),
            RunEnd::Probe(ProbeEnd::Eof { stage, .. }) => {
                std::format!("connection closed by peer while {stage}")
            }
            RunEnd::Probe(ProbeEnd::Error(e)) => std::format!("protocol error: {e}"),
            RunEnd::TimedOut { stage, .. } => std::format!("timed out while {stage}"),
            RunEnd::Io { stage, error } => std::format!("socket error while {stage}: {error}"),
        }
    }

    /// `true` only for a complete, anomaly-free proposal.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(
            self,
            RunEnd::Probe(ProbeEnd::Proposal(p)) if p.anomalies.is_empty()
        )
    }
}
