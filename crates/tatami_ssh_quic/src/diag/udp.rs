//! Blocking UDP helpers shared by the server and client runners.
//!
//! No async runtime: the socket is driven with `set_read_timeout` so a
//! single thread can alternate between waiting for datagrams and firing
//! `quinn-proto` timers.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use std::vec::Vec;

use super::Datagram;

/// Waits at most `wait` for one datagram. `Ok(None)` on timeout or
/// interruption. `wait` is clamped to at least 1 ms because a zero timeout
/// means "block forever" to the OS.
pub(crate) fn recv_with_timeout(
    socket: &UdpSocket,
    buf: &mut [u8],
    wait: Duration,
) -> io::Result<Option<(usize, SocketAddr)>> {
    socket.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
    match socket.recv_from(buf) {
        Ok(x) => Ok(Some(x)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(None)
        }
        // An ICMP error surfaced on an unconnected socket (Linux reports
        // some as `ConnectionRefused`/`ConnectionReset`); not fatal for a
        // server, and for a client the handshake deadline governs.
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Sends every queued datagram, draining `out`. Per-datagram send errors
/// that are transient (`WouldBlock`, `Interrupted`, ICMP-derived) are
/// ignored; QUIC treats a lost datagram as loss. Other errors are fatal.
pub(crate) fn send_all(socket: &UdpSocket, out: &mut Vec<Datagram>) -> io::Result<()> {
    for d in out.drain(..) {
        match socket.send_to(&d.payload, d.destination) {
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::PermissionDenied
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
