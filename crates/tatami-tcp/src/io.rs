//! Host socket adapters for the TCP binding (requires `std`).
//!
//! This module owns everything the portable modules must not: name
//! resolution, connecting, accepting, blocking reads and writes, OS
//! deadlines, bounded concurrency and socket cleanup. It drives the
//! portable [`Probe`] state machine (client side) and, through
//! [`listener`], the portable observer (server side).
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
//!
//! # Testing seam
//!
//! The probe driver is written against two crate-private traits in `seam`
//! (`Conn`: timed read/write/flush and the timeout setters; `Clock`: `now`)
//! so that its deadline arithmetic and fault handling can be exercised
//! deterministically. Production always passes a real `TcpStream` and the
//! system clock; the seam is not a public transport abstraction. The unit
//! tests in this module drive it with a scripted connection and a virtual
//! clock and cover: short writes of the client identification, `Interrupted`
//! on read and write, trickling reads that cannot extend the deadline,
//! EOF at a boundary and mid-line/mid-packet, zero-length writes, a deadline
//! that has already passed before the first write, deadline exhaustion inside
//! a packet body, reads bounded by [`Probe::room`], and a silent peer that
//! never sends anything. Real-socket concurrency and cleanup remain covered
//! by the loopback tests in `tests/probe_loopback.rs`.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::string::{String, ToString};
use std::time::{Duration, Instant};
use std::vec::Vec;

use crate::probe::{Probe, ProbeConfig, ProbeEnd, ProbeEvent, Stage, Step};

pub mod listener;
mod seam;

pub use listener::{
    BindError, ConfigError, Listener, ListenerConfig, ListenerEvent, Observation, ObservationEnd,
    Sink, SinkError, StopHandle, StopReason, Summary,
};
use seam::{Clock, Conn, SystemClock, remaining_until, write_all_by};

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
        &SystemClock,
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

fn drive<C: Conn, K: Clock>(
    conn: &mut C,
    clock: &K,
    probe: &mut Probe,
    events: &mut Vec<ProbeEvent>,
    deadline: Instant,
    chunk: usize,
) -> RunEnd {
    // Send our identification first, without waiting for the server. The
    // write shares the read-phase deadline, so running out of time here is
    // a timeout, not a socket fault.
    match write_all_by(conn, clock, probe.client_identification(), deadline) {
        Ok(()) => {}
        Err(e) if is_timeout(&e) => {
            return RunEnd::TimedOut {
                stage: probe.stage(),
                pending_bytes: probe.pending_bytes(),
            };
        }
        Err(error) => {
            return RunEnd::Io {
                stage: probe.stage(),
                error,
            };
        }
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

        let Some(remaining) = remaining_until(clock, deadline) else {
            return RunEnd::TimedOut {
                stage: probe.stage(),
                pending_bytes: probe.pending_bytes(),
            };
        };
        if let Err(error) = conn.set_read_timeout(Some(remaining)) {
            return RunEnd::Io {
                stage: probe.stage(),
                error,
            };
        }
        // Never read more than the probe can hold; a zero-room read of one
        // byte lets the probe report the overflow itself.
        let want = buf.len().min(probe.room()).max(1);
        match conn.read(&mut buf[..want]) {
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

/// Deterministic fault tests for the probe driver, on a scripted connection
/// and a virtual clock. No sockets, threads or sleeps; see `seam::scripted`.
#[cfg(test)]
mod tests {
    use super::seam::scripted::{ReadEvent, ScriptedConn, VirtualClock, WriteEvent};
    use super::*;
    use crate::ident::IdentLimits;
    use crate::packet::{HEADER_LEN, PacketLimits, encode_initial_packet};
    use tatami_wire::Writer;

    const CLIENT_IDENT: &[u8] = b"SSH-2.0-tatami_0.1.0\r\n";
    const SERVER_IDENT: &[u8] = b"SSH-2.0-Fixture_1.0 test peer\r\n";

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
        w.write_bytes(&[0x42; 16]).unwrap();
        w.write_string(b"curve25519-sha256,ext-info-s").unwrap();
        w.write_string(b"ssh-ed25519").unwrap();
        w.write_string(b"aes128-ctr").unwrap();
        w.write_string(b"aes256-gcm@openssh.com").unwrap();
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
        let n = encode_initial_packet(&payload, 0x5a, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// A packet header claiming a small body that never fully arrives.
    fn partial_header() -> Vec<u8> {
        std::vec![0, 0, 0, 60, 4]
    }

    /// A probe configuration with a buffer small enough that a 4 KiB chunk
    /// exceeds `room()`.
    fn tiny_config() -> ProbeConfig {
        ProbeConfig {
            packet: PacketLimits {
                max_packet_length: 64,
            },
            ident: IdentLimits {
                max_prelude_line: 32,
                max_identification_line: 64,
                ..IdentLimits::default()
            },
            ..ProbeConfig::default()
        }
    }

    struct Outcome {
        end: RunEnd,
        events: Vec<ProbeEvent>,
        probe: Probe,
        conn: ScriptedConn,
        clock: VirtualClock,
        deadline: Duration,
    }

    impl Outcome {
        /// Every timeout the driver requested, on either side, must equal
        /// the time then remaining until the deadline (the probe driver
        /// bounds each call by the whole remaining phase), and the virtual
        /// clock must never pass the deadline.
        fn assert_deadline_discipline(&self) {
            for (at, timeout) in self
                .conn
                .read_timeouts
                .iter()
                .chain(&self.conn.write_timeouts)
            {
                assert_eq!(
                    *at + *timeout,
                    self.deadline,
                    "timeout {timeout:?} requested at {at:?} does not end at the deadline"
                );
            }
            assert!(self.clock.elapsed() <= self.deadline);
        }

        fn end_probe(&self) -> &ProbeEnd {
            match &self.end {
                RunEnd::Probe(end) => end,
                other => panic!("expected a probe outcome, got {other:?}"),
            }
        }
    }

    fn run_with(
        config: ProbeConfig,
        reads: Vec<ReadEvent>,
        writes: Vec<WriteEvent>,
        deadline: Duration,
        chunk: usize,
    ) -> Outcome {
        let clock = VirtualClock::new();
        let mut conn = ScriptedConn::new(&clock, reads, writes);
        let mut probe = Probe::new(config).unwrap();
        let mut events = Vec::new();
        let end = drive(
            &mut conn,
            &clock,
            &mut probe,
            &mut events,
            clock.now() + deadline,
            chunk,
        );
        Outcome {
            end,
            events,
            probe,
            conn,
            clock,
            deadline,
        }
    }

    fn run(reads: Vec<ReadEvent>, writes: Vec<WriteEvent>, deadline: Duration) -> Outcome {
        run_with(ProbeConfig::default(), reads, writes, deadline, 4096)
    }

    #[test]
    fn identification_is_written_across_short_writes() {
        let out = run(
            std::vec![data(SERVER_IDENT), data(&kexinit_packet())],
            std::vec![
                WriteEvent::Accept(3),
                WriteEvent::Accept(5),
                WriteEvent::Accept(1),
            ],
            ms(1_000),
        );
        assert!(out.end.is_complete(), "{}", out.end.label());
        assert_eq!(out.conn.written, CLIENT_IDENT);
        // 3 + 5 + 1, then the remaining 13 bytes in one write.
        assert_eq!(out.conn.write_calls, 4);
        // The write timeout is recomputed before every partial write.
        assert_eq!(out.conn.write_timeouts.len(), 4);
        assert!(matches!(
            out.events.as_slice(),
            [ProbeEvent::ServerIdentification(i)] if i.software_version == "Fixture_1.0"
        ));
        out.assert_deadline_discipline();
    }

    #[test]
    fn interrupted_read_and_write_are_retried_without_resetting_the_deadline() {
        let out = run(
            std::vec![
                ReadEvent::Elapse(ms(100)),
                data(SERVER_IDENT),
                ReadEvent::Err(io::ErrorKind::Interrupted),
                ReadEvent::Elapse(ms(100)),
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
        assert!(out.end.is_complete(), "{}", out.end.label());
        assert_eq!(out.conn.written, CLIENT_IDENT);
        assert_eq!(out.clock.elapsed(), ms(250));
        // Each retry re-derives the timeout from the same deadline: the
        // sequence shrinks as time passes and never grows back.
        assert_eq!(
            out.conn.write_timeouts,
            [
                (ms(0), ms(1_000)),
                (ms(0), ms(1_000)),
                (ms(50), ms(950)),
                (ms(50), ms(950)),
            ]
        );
        assert_eq!(
            out.conn.read_timeouts,
            [(ms(50), ms(950)), (ms(150), ms(850)), (ms(150), ms(850))]
        );
        out.assert_deadline_discipline();
    }

    #[test]
    fn trickling_server_cannot_extend_the_deadline() {
        // One byte of a never-ending line every 300 ms against a 1 s deadline:
        // three bytes arrive, the fourth silence hits the deadline.
        let mut reads = Vec::new();
        for _ in 0..8 {
            reads.push(ReadEvent::Elapse(ms(300)));
            reads.push(data(b"S"));
        }
        let out = run(reads, Vec::new(), ms(1_000));
        assert!(matches!(
            out.end,
            RunEnd::TimedOut {
                stage: Stage::Identification,
                pending_bytes: 3,
            }
        ));
        assert_eq!(
            out.clock.elapsed(),
            ms(1_000),
            "ended exactly at the deadline"
        );
        assert!(out.events.is_empty());
        assert!(out.conn.unread_events() > 0, "the line was never completed");
        out.assert_deadline_discipline();
    }

    #[test]
    fn eof_at_boundary_and_mid_stream() {
        let k = kexinit_packet();
        let half = k.len() / 2;
        let cases: [(Vec<ReadEvent>, Stage, usize); 4] = [
            (std::vec![ReadEvent::Eof], Stage::Identification, 0),
            (
                std::vec![data(b"SSH-2.0-Trunc"), ReadEvent::Eof],
                Stage::Identification,
                13,
            ),
            (
                std::vec![data(SERVER_IDENT), ReadEvent::Eof],
                Stage::InitialPackets,
                0,
            ),
            (
                std::vec![data(SERVER_IDENT), data(&k[..half]), ReadEvent::Eof],
                Stage::InitialPackets,
                half,
            ),
        ];
        for (reads, stage, pending) in cases {
            let out = run(reads, Vec::new(), ms(1_000));
            assert_eq!(
                out.end_probe(),
                &ProbeEnd::Eof {
                    stage,
                    pending_bytes: pending
                }
            );
            assert_eq!(out.clock.elapsed(), Duration::ZERO);
        }
    }

    #[test]
    fn zero_length_write_is_an_io_error() {
        let out = run(Vec::new(), std::vec![WriteEvent::Zero], ms(1_000));
        match &out.end {
            RunEnd::Io {
                stage: Stage::Identification,
                error,
            } => assert_eq!(error.kind(), io::ErrorKind::WriteZero),
            other => panic!("{other:?}"),
        }
        assert!(out.conn.written.is_empty());
        assert!(
            out.conn.read_requests.is_empty(),
            "no read after a failed write"
        );

        let out = run(
            Vec::new(),
            std::vec![WriteEvent::Err(io::ErrorKind::ConnectionReset)],
            ms(1_000),
        );
        assert!(matches!(
            &out.end,
            RunEnd::Io { stage: Stage::Identification, error }
                if error.kind() == io::ErrorKind::ConnectionReset
        ));
    }

    #[test]
    fn deadline_already_passed_before_the_first_write() {
        let out = run(
            std::vec![data(SERVER_IDENT), data(&kexinit_packet())],
            Vec::new(),
            Duration::ZERO,
        );
        assert!(matches!(
            out.end,
            RunEnd::TimedOut {
                stage: Stage::Identification,
                pending_bytes: 0,
            }
        ));
        assert_eq!(out.conn.write_calls, 0, "no write was attempted");
        assert!(out.conn.write_timeouts.is_empty());
        assert!(out.conn.read_requests.is_empty());
    }

    #[test]
    fn write_that_times_out_is_a_timeout_not_a_socket_error() {
        // The peer never drains its receive buffer; the identification write
        // blocks until the deadline.
        let out = run(
            std::vec![data(SERVER_IDENT)],
            std::vec![WriteEvent::Elapse(ms(5_000))],
            ms(1_000),
        );
        assert!(matches!(
            out.end,
            RunEnd::TimedOut {
                stage: Stage::Identification,
                pending_bytes: 0,
            }
        ));
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert!(out.conn.written.is_empty());
        assert!(out.conn.read_requests.is_empty());
    }

    #[test]
    fn deadline_exhausted_inside_a_packet_body() {
        let k = kexinit_packet();
        let mut reads = std::vec![data(SERVER_IDENT), data(&k[..HEADER_LEN])];
        for b in &k[HEADER_LEN..HEADER_LEN + 6] {
            reads.push(ReadEvent::Elapse(ms(200)));
            reads.push(data(&[*b]));
        }
        let out = run(reads, Vec::new(), ms(1_000));
        // Header at t=0, one body byte at 200/400/600/800 ms, deadline at
        // 1000 ms while waiting for the fifth.
        assert!(matches!(
            out.end,
            RunEnd::TimedOut {
                stage: Stage::InitialPackets,
                pending_bytes: 9,
            }
        ));
        assert_eq!(out.probe.pending_bytes(), HEADER_LEN + 4);
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert!(matches!(
            out.events.as_slice(),
            [ProbeEvent::ServerIdentification(_)]
        ));
        out.assert_deadline_discipline();
    }

    #[test]
    fn reads_never_exceed_chunk_or_room() {
        // Chunk smaller than room: every read asks for exactly the chunk.
        let out = run_with(
            ProbeConfig::default(),
            std::vec![data(SERVER_IDENT), data(&kexinit_packet())],
            Vec::new(),
            ms(1_000),
            7,
        );
        assert!(out.end.is_complete(), "{}", out.end.label());
        assert!(out.conn.read_requests.len() > 10);
        assert!(out.conn.read_requests.iter().all(|&n| n == 7));

        // Chunk larger than room: reads shrink as unconsumed bytes pile up.
        let config = tiny_config();
        let cap = config.buffer_capacity();
        assert!(cap < 4096);
        let out = run_with(
            config,
            std::vec![
                data(SERVER_IDENT),
                data(&partial_header()),
                data(&[1]),
                data(&[2]),
            ],
            Vec::new(),
            ms(1_000),
            4096,
        );
        assert!(matches!(
            out.end,
            RunEnd::TimedOut {
                stage: Stage::InitialPackets,
                pending_bytes: 7,
            }
        ));
        assert_eq!(
            out.conn.read_requests,
            [cap, cap, cap - 5, cap - 6, cap - 7],
            "each read is bounded by the room left in the probe buffer"
        );
        assert!(out.conn.read_requests.iter().all(|&n| n <= cap));
    }

    #[test]
    fn silent_server_is_waited_for_once_not_spun_on() {
        // An empty script is a connected, silent peer. The probe bounds one
        // read by the whole remaining phase, so a single read reaches the
        // deadline; the scripted connection's call cap would panic on a spin.
        let out = run(Vec::new(), Vec::new(), ms(1_000));
        assert!(matches!(
            out.end,
            RunEnd::TimedOut {
                stage: Stage::Identification,
                pending_bytes: 0,
            }
        ));
        assert_eq!(out.conn.read_requests.len(), 1);
        assert_eq!(out.conn.read_timeouts, [(ms(0), ms(1_000))]);
        assert_eq!(out.clock.elapsed(), ms(1_000));

        // Explicit WouldBlock after the identification: same discipline, at
        // the later stage.
        let out = run(
            std::vec![
                ReadEvent::Elapse(ms(400)),
                data(SERVER_IDENT),
                ReadEvent::Err(io::ErrorKind::WouldBlock),
                data(&kexinit_packet()),
            ],
            Vec::new(),
            ms(1_000),
        );
        assert!(matches!(
            out.end,
            RunEnd::TimedOut {
                stage: Stage::InitialPackets,
                pending_bytes: 0,
            }
        ));
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert_eq!(
            out.conn.read_timeouts,
            [(ms(0), ms(1_000)), (ms(400), ms(600))]
        );
        assert_eq!(out.conn.unread_events(), 1, "the KEXINIT arrived too late");
        out.assert_deadline_discipline();
    }
}
