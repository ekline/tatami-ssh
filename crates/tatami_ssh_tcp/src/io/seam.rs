//! Internal seam between the blocking drivers and the OS socket and clock.
//!
//! The two drivers in this adapter, the client probe driver in the parent
//! module and the server observer driver in [`super::listener`], are written
//! against two tiny crate-private traits rather than `TcpStream` and
//! `Instant::now` directly:
//!
//! - [`Conn`], the five socket operations the drivers use (timed read and
//!   write, flush, and the two timeout setters);
//! - [`Clock`], which is only `now()`.
//!
//! Production code always passes a real [`TcpStream`] and [`SystemClock`];
//! the blocking runtime, socket options and public API are unchanged. The
//! seam exists so the drivers' deadline arithmetic and fault handling (short
//! writes, `Interrupted`, `WouldBlock`, EOF mid-packet, zero-length writes,
//! trickling peers, stop requests) can be exercised deterministically under
//! `cfg(test)` with [`scripted::ScriptedConn`] and [`scripted::VirtualClock`],
//! in milliseconds, without loopback sockets or sleeps.
//!
//! This is deliberately **not** a transport abstraction. It is `pub(crate)`,
//! TCP-only calls (`set_nodelay`, `shutdown`, `peer_addr`) stay with the
//! callers that own the real stream, and nothing else in the workspace is
//! expected to implement it.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The socket operations the drivers use.
pub(crate) trait Conn {
    /// Reads into `buf`, bounded by the most recently set read timeout.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    /// Writes from `buf`, bounded by the most recently set write timeout.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    /// Flushes buffered output (a no-op for TCP sockets).
    fn flush(&mut self) -> io::Result<()>;
    /// Bounds subsequent reads. A zero duration is rejected, as by the OS.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
    /// Bounds subsequent writes. A zero duration is rejected, as by the OS.
    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()>;
}

/// Source of monotonic time for deadline arithmetic.
pub(crate) trait Clock {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real monotonic clock.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

impl Conn for TcpStream {
    // Fully qualified calls throughout: the inherent `TcpStream::set_*_timeout`
    // and the `Read`/`Write` methods share names with this trait's methods,
    // and `self.set_read_timeout(..)` here would resolve to the trait method
    // and recurse.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Read::read(self, buf)
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Write::write(self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Write::flush(self)
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

/// Time left until `deadline` on `clock`, or `None` once it has passed.
/// Never returns a zero duration, which the socket timeout setters reject.
pub(crate) fn remaining_until<K: Clock>(clock: &K, deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(clock.now())
        .filter(|d| !d.is_zero())
}

/// Writes all of `data` before `deadline`, recomputing the remaining time
/// before every partial write. `Interrupted` is retried. A write that times
/// out, or a deadline that has already passed, is reported as `TimedOut`; a
/// zero-length write as `WriteZero`.
pub(crate) fn write_all_by<C: Conn, K: Clock>(
    conn: &mut C,
    clock: &K,
    data: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    let mut written = 0;
    while written < data.len() {
        let remaining = remaining_until(clock, deadline)
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "deadline passed"))?;
        conn.set_write_timeout(Some(remaining))?;
        match conn.write(&data[written..]) {
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
    conn.flush()
}

/// Scripted connection and virtual clock for deterministic driver tests.
///
/// A [`ScriptedConn`] answers each `read`/`write` from a queue of events and
/// moves a shared [`VirtualClock`] the way a real timed socket call would
/// move wall time: silence consumes the timeout the driver requested, and a
/// read or write that runs out of timeout fails with `WouldBlock`. It records
/// every timeout the driver requested (paired with the virtual time of the
/// request), every read buffer length, and every byte written, so tests can
/// assert that remaining time is recomputed, never exceeds the deadline, and
/// that reads never ask for more than the state machine can hold.
///
/// A hard cap on socket calls turns an accidental spin into a test failure
/// instead of a hang.
#[cfg(test)]
pub(crate) mod scripted {
    use std::boxed::Box;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io;
    use std::rc::Rc;
    use std::time::{Duration, Instant};
    use std::vec::Vec;

    use super::{Clock, Conn};

    /// A clock that moves only when [`VirtualClock::advance`] is called. The
    /// epoch is one real instant captured at construction and never
    /// consulted again, so tests are independent of wall time.
    #[derive(Clone)]
    pub(crate) struct VirtualClock {
        epoch: Instant,
        offset: Rc<Cell<Duration>>,
    }

    impl VirtualClock {
        pub(crate) fn new() -> Self {
            VirtualClock {
                epoch: Instant::now(),
                offset: Rc::new(Cell::new(Duration::ZERO)),
            }
        }

        /// Virtual time passed since construction.
        pub(crate) fn elapsed(&self) -> Duration {
            self.offset.get()
        }

        pub(crate) fn advance(&self, by: Duration) {
            self.offset.set(self.offset.get() + by);
        }
    }

    impl Default for VirtualClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Clock for VirtualClock {
        fn now(&self) -> Instant {
            self.epoch + self.offset.get()
        }
    }

    /// What the next `read` finds.
    pub(crate) enum ReadEvent {
        /// Bytes from the peer. A read takes at most `buf.len()` of them; the
        /// remainder stays queued for the next read. Must be non-empty.
        Data(Vec<u8>),
        /// Orderly close (`Ok(0)`). Sticky: later reads see it again.
        Eof,
        /// An error. `WouldBlock`/`TimedOut` first consume the whole read
        /// timeout the driver requested, as a real timed-out read does.
        Err(io::ErrorKind),
        /// Silence for this long. Silence shorter than the requested timeout
        /// passes and the read continues with the next event; silence that
        /// outlasts the timeout returns `WouldBlock` when the timeout is used
        /// up and the rest of it carries over to the next read.
        Elapse(Duration),
        /// Runs a side effect (such as requesting a stop) and continues with
        /// the next event in the same read.
        Hook(Box<dyn FnMut()>),
    }

    /// What the next `write` meets.
    pub(crate) enum WriteEvent {
        /// Accepts at most this many bytes (a short write).
        Accept(usize),
        /// `Ok(0)`.
        Zero,
        /// An error. Timeout kinds first consume the requested write timeout.
        Err(io::ErrorKind),
        /// Silence, with the same semantics as for reads.
        Elapse(Duration),
    }

    /// Socket calls allowed per connection before the seam panics. Far above
    /// any legitimate script: the longest deadline used in tests divided by
    /// the shortest poll interval is in the low hundreds.
    const MAX_CALLS: usize = 10_000;

    pub(crate) struct ScriptedConn {
        clock: VirtualClock,
        reads: VecDeque<ReadEvent>,
        writes: VecDeque<WriteEvent>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
        calls: usize,
        /// Every byte accepted by `write`, in order.
        pub(crate) written: Vec<u8>,
        /// `(virtual time of the call, timeout)` for each `set_read_timeout`.
        pub(crate) read_timeouts: Vec<(Duration, Duration)>,
        /// `(virtual time of the call, timeout)` for each `set_write_timeout`.
        pub(crate) write_timeouts: Vec<(Duration, Duration)>,
        /// Buffer length passed to each `read`, in order.
        pub(crate) read_requests: Vec<usize>,
        /// Number of `write` calls.
        pub(crate) write_calls: usize,
    }

    impl ScriptedConn {
        /// A connection that answers reads and writes from the given scripts.
        /// Once a script is exhausted, reads see a connected but silent peer
        /// (each read consumes its whole timeout and fails with
        /// `WouldBlock`) and writes are accepted in full.
        pub(crate) fn new(
            clock: &VirtualClock,
            reads: Vec<ReadEvent>,
            writes: Vec<WriteEvent>,
        ) -> Self {
            for event in &reads {
                if let ReadEvent::Data(d) = event {
                    assert!(!d.is_empty(), "use ReadEvent::Eof for a zero-length read");
                }
            }
            ScriptedConn {
                clock: clock.clone(),
                reads: reads.into(),
                writes: writes.into(),
                read_timeout: None,
                write_timeout: None,
                calls: 0,
                written: Vec::new(),
                read_timeouts: Vec::new(),
                write_timeouts: Vec::new(),
                read_requests: Vec::new(),
                write_calls: 0,
            }
        }

        /// Read events the driver never got to.
        pub(crate) fn unread_events(&self) -> usize {
            self.reads.len()
        }

        fn count_call(&mut self) {
            self.calls += 1;
            assert!(
                self.calls <= MAX_CALLS,
                "scripted conn: more than {MAX_CALLS} socket calls; \
                 the driver is spinning without consuming time"
            );
        }
    }

    fn is_timeout_kind(kind: io::ErrorKind) -> bool {
        matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
    }

    /// Mirrors the OS: `None` is never used by the drivers (a real socket
    /// would then block forever, so it is a test failure), zero is rejected.
    fn checked_timeout(timeout: Option<Duration>) -> io::Result<Duration> {
        let t =
            timeout.expect("driver cleared a socket timeout; a real socket would block forever");
        if t.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot set a 0 duration timeout",
            ));
        }
        Ok(t)
    }

    impl Conn for ScriptedConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.count_call();
            self.read_requests.push(buf.len());
            let mut budget = self
                .read_timeout
                .expect("driver read without a timeout; a real socket would block forever");
            loop {
                match self.reads.pop_front() {
                    None => {
                        // Script exhausted: the peer stays connected but silent.
                        self.clock.advance(budget);
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    Some(ReadEvent::Elapse(silence)) => {
                        if silence >= budget {
                            self.clock.advance(budget);
                            if silence > budget {
                                self.reads.push_front(ReadEvent::Elapse(silence - budget));
                            }
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        self.clock.advance(silence);
                        budget -= silence;
                    }
                    Some(ReadEvent::Hook(mut f)) => f(),
                    Some(ReadEvent::Data(data)) => {
                        let n = data.len().min(buf.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        if n < data.len() {
                            self.reads.push_front(ReadEvent::Data(data[n..].to_vec()));
                        }
                        return Ok(n);
                    }
                    Some(ReadEvent::Eof) => {
                        self.reads.push_front(ReadEvent::Eof);
                        return Ok(0);
                    }
                    Some(ReadEvent::Err(kind)) => {
                        if is_timeout_kind(kind) {
                            self.clock.advance(budget);
                        }
                        return Err(kind.into());
                    }
                }
            }
        }

        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.count_call();
            self.write_calls += 1;
            let mut budget = self
                .write_timeout
                .expect("driver wrote without a timeout; a real socket could block forever");
            loop {
                match self.writes.pop_front() {
                    None => {
                        self.written.extend_from_slice(buf);
                        return Ok(buf.len());
                    }
                    Some(WriteEvent::Accept(n)) => {
                        let n = n.min(buf.len());
                        self.written.extend_from_slice(&buf[..n]);
                        return Ok(n);
                    }
                    Some(WriteEvent::Zero) => return Ok(0),
                    Some(WriteEvent::Err(kind)) => {
                        if is_timeout_kind(kind) {
                            self.clock.advance(budget);
                        }
                        return Err(kind.into());
                    }
                    Some(WriteEvent::Elapse(silence)) => {
                        if silence >= budget {
                            self.clock.advance(budget);
                            if silence > budget {
                                self.writes.push_front(WriteEvent::Elapse(silence - budget));
                            }
                            return Err(io::ErrorKind::WouldBlock.into());
                        }
                        self.clock.advance(silence);
                        budget -= silence;
                    }
                }
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            let t = checked_timeout(timeout)?;
            self.read_timeouts.push((self.clock.elapsed(), t));
            self.read_timeout = Some(t);
            Ok(())
        }

        fn set_write_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
            let t = checked_timeout(timeout)?;
            self.write_timeouts.push((self.clock.elapsed(), t));
            self.write_timeout = Some(t);
            Ok(())
        }
    }

    /// The seam's own guarantees, which the driver tests rely on.
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn data_is_delivered_in_buffer_sized_pieces_and_eof_is_sticky() {
            let clock = VirtualClock::new();
            let mut c = ScriptedConn::new(
                &clock,
                std::vec![ReadEvent::Data(b"abcdefg".to_vec()), ReadEvent::Eof],
                Vec::new(),
            );
            c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut buf = [0u8; 3];
            assert_eq!(c.read(&mut buf).unwrap(), 3);
            assert_eq!(&buf, b"abc");
            assert_eq!(c.read(&mut buf).unwrap(), 3);
            assert_eq!(&buf, b"def");
            assert_eq!(c.read(&mut buf).unwrap(), 1);
            assert_eq!(buf[0], b'g');
            assert_eq!(c.read(&mut buf).unwrap(), 0);
            assert_eq!(c.read(&mut buf).unwrap(), 0);
            assert_eq!(c.read_requests, [3, 3, 3, 3, 3]);
            assert_eq!(clock.elapsed(), Duration::ZERO);
        }

        #[test]
        fn silence_consumes_the_requested_timeout_and_carries_over() {
            let clock = VirtualClock::new();
            let mut c = ScriptedConn::new(
                &clock,
                std::vec![
                    ReadEvent::Elapse(Duration::from_millis(70)),
                    ReadEvent::Data(std::vec![1]),
                ],
                Vec::new(),
            );
            c.set_read_timeout(Some(Duration::from_millis(25))).unwrap();
            let mut buf = [0u8; 8];
            for expected in [25, 50] {
                assert_eq!(
                    c.read(&mut buf).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
                assert_eq!(clock.elapsed(), Duration::from_millis(expected));
            }
            // 20 ms of silence left, then the byte arrives within this read.
            assert_eq!(c.read(&mut buf).unwrap(), 1);
            assert_eq!(clock.elapsed(), Duration::from_millis(70));
            // Script exhausted: a silent peer consumes whole timeouts.
            assert!(c.read(&mut buf).is_err());
            assert_eq!(clock.elapsed(), Duration::from_millis(95));
        }

        #[test]
        fn zero_timeouts_are_rejected_like_the_os() {
            let clock = VirtualClock::new();
            let mut c = ScriptedConn::new(&clock, Vec::new(), Vec::new());
            assert_eq!(
                c.set_read_timeout(Some(Duration::ZERO)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            assert_eq!(
                c.set_write_timeout(Some(Duration::ZERO))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        }

        #[test]
        #[should_panic(expected = "spinning")]
        fn a_spinning_driver_is_a_test_failure_not_a_hang() {
            let clock = VirtualClock::new();
            let mut c = ScriptedConn::new(&clock, Vec::new(), Vec::new());
            c.set_read_timeout(Some(Duration::from_millis(1))).unwrap();
            let mut buf = [0u8; 1];
            loop {
                let _ = c.read(&mut buf);
            }
        }
    }
}
