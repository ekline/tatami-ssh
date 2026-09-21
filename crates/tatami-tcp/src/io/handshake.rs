//! Blocking host driver for the portable client handshake (requires `std`
//! and `kex`).
//!
//! [`run_handshake`] drives a [`ClientHandshake`] over a connected
//! `TcpStream`: it writes whatever the state machine queues (handling
//! partial writes; the serialized bytes are written from one buffer and
//! the state machine is never asked to reserialize), reads at most
//! [`ClientHandshake::room`] bytes at a time, answers the trust question
//! with the caller's [`HostTrustPolicy`], and shuts the socket down when the
//! state machine finishes.
//!
//! # Deadline
//!
//! One deadline, [`HandshakeIo::overall_timeout`], runs from the call to
//! `run_handshake` (connect success) until the state machine finishes and
//! covers every write and read. The time remaining is recomputed before
//! each socket operation; a write or read that runs out of it ends the run
//! as [`HandshakeEnd::TimedOut`] with the phase reached.
//!
//! # Entropy
//!
//! [`OsEntropy`] adapts `getrandom` to `rand_core`. The state machine uses
//! only the fallible `try_fill_bytes`; an entropy failure is reported as an
//! `io::Error` from `run_handshake`, never panicked on.
//!
//! # Testing seam
//!
//! The driver body (`run_handshake_on`, crate-private) is generic over the
//! crate-private `Conn`/`Clock` seam so its deadline arithmetic and fault
//! handling can be exercised deterministically against a scripted server
//! (see the tests).

use std::io;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::string::{String, ToString};
use std::time::{Duration, Instant};

use rand_core::{CryptoRng, RngCore};
use tatami_keys::trust::HostTrustPolicy;

use super::seam::{Clock, Conn, SystemClock, remaining_until, write_all_by};
use super::{ConnectError, IoConfig, connect, is_timeout};
use crate::handshake::{
    ClientHandshake, HandshakeConfig, HandshakeOutcome, HandshakeReport, Phase, Step,
};

/// Host-side timing policy for a handshake run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeIo {
    /// Deadline for the connect phase across all address attempts.
    pub connect_timeout: Duration,
    /// Single deadline from connect success to a terminal outcome,
    /// covering every write and read.
    pub overall_timeout: Duration,
    /// Size of each socket read (further bounded by the state machine's
    /// remaining buffer room).
    pub read_chunk: usize,
}

impl Default for HandshakeIo {
    fn default() -> Self {
        HandshakeIo {
            connect_timeout: Duration::from_secs(10),
            overall_timeout: Duration::from_secs(15),
            read_chunk: 4096,
        }
    }
}

impl HandshakeIo {
    /// Resolves and connects under [`HandshakeIo::connect_timeout`] (see
    /// [`connect`] for the address-attempt policy).
    pub fn connect(&self, host: &str, port: u16) -> Result<TcpStream, ConnectError> {
        connect(
            host,
            port,
            &IoConfig {
                connect_timeout: self.connect_timeout,
                read_timeout: self.overall_timeout,
                max_connect_attempts: IoConfig::default().max_connect_attempts,
                read_chunk: self.read_chunk,
            },
        )
    }
}

/// Why a run stopped, from the host's point of view.
#[derive(Debug)]
pub enum HandshakeEnd {
    /// The state machine produced a terminal outcome.
    Finished(HandshakeOutcome),
    /// The overall deadline passed.
    TimedOut {
        /// Phase when the deadline passed.
        phase: Phase,
        /// Bytes buffered but unconsumed at that point.
        pending_bytes: usize,
    },
    /// The socket failed.
    Io {
        /// Phase when the error occurred.
        phase: Phase,
        /// The error.
        error: io::Error,
    },
}

impl HandshakeEnd {
    /// Short label for reports.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            HandshakeEnd::Finished(o) => o.to_string(),
            HandshakeEnd::TimedOut { phase, .. } => std::format!("timed out while {phase}"),
            HandshakeEnd::Io { phase, error } => {
                std::format!("socket error while {phase}: {error}")
            }
        }
    }

    /// `true` only for [`HandshakeOutcome::Completed`].
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, HandshakeEnd::Finished(o) if o.is_complete())
    }
}

/// Everything observed during one run.
#[derive(Debug)]
pub struct HandshakeRun {
    /// Address that actually connected.
    pub peer: SocketAddr,
    /// Local address of the connection.
    pub local: SocketAddr,
    /// The state machine's report at the end.
    pub report: HandshakeReport,
    /// How the run ended.
    pub end: HandshakeEnd,
    /// Wall-clock time from the call to `end`.
    pub elapsed: Duration,
}

/// OS entropy through `getrandom`, for [`ClientHandshake::new`].
///
/// The handshake calls only `try_fill_bytes`. The infallible `fill_bytes`
/// required by the trait panics on an OS failure, as `rand_core` specifies
/// for generators that cannot otherwise report one; nothing in this crate
/// calls it.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

impl RngCore for OsEntropy {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_ne_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_ne_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest)
            .expect("OS entropy source failed; use try_fill_bytes to handle this");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        getrandom::getrandom(dest).map_err(|e| rand_core::Error::from(e.code()))
    }
}

impl CryptoRng for OsEntropy {}

/// Runs a handshake over an already connected stream, then shuts the socket
/// down. The overall deadline starts when this function is called.
///
/// Returns `Err` only for failures before any byte is exchanged: the
/// socket's addresses could not be read, the configured software version is
/// invalid, or the OS entropy source failed.
pub fn run_handshake(
    mut stream: TcpStream,
    config: HandshakeConfig,
    policy: &dyn HostTrustPolicy,
    io: &HandshakeIo,
) -> io::Result<HandshakeRun> {
    let started = Instant::now();
    let deadline = started + io.overall_timeout;
    let peer = stream.peer_addr()?;
    let local = stream.local_addr()?;
    let mut handshake = ClientHandshake::new(config, &mut OsEntropy)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let _ = stream.set_nodelay(true);

    let end = run_handshake_on(
        &mut stream,
        &SystemClock,
        &mut handshake,
        policy,
        deadline,
        io.read_chunk,
    );

    // Best effort: our DISCONNECT (if any) has been written; the peer sees
    // an orderly close either way.
    let _ = stream.shutdown(Shutdown::Both);

    Ok(HandshakeRun {
        peer,
        local,
        report: handshake.report(),
        end,
        elapsed: started.elapsed(),
    })
}

/// The driver body over the testing seam.
pub(crate) fn run_handshake_on<C: Conn, K: Clock>(
    conn: &mut C,
    clock: &K,
    handshake: &mut ClientHandshake,
    policy: &dyn HostTrustPolicy,
    deadline: Instant,
    chunk: usize,
) -> HandshakeEnd {
    let mut buf = std::vec![0u8; chunk.max(1)];
    loop {
        match handshake.step() {
            Step::Finished(outcome) => return HandshakeEnd::Finished(*outcome),
            Step::Send => {
                let out = handshake.take_output();
                match write_all_by(conn, clock, &out, deadline) {
                    Ok(()) => {}
                    Err(e) if is_timeout(&e) => {
                        return HandshakeEnd::TimedOut {
                            phase: handshake.phase(),
                            pending_bytes: handshake.pending_bytes(),
                        };
                    }
                    Err(error) => {
                        return HandshakeEnd::Io {
                            phase: handshake.phase(),
                            error,
                        };
                    }
                }
            }
            Step::TrustDecisionRequired(identity) => {
                handshake.provide_trust(policy.decide(&identity.as_identity()));
            }
            Step::NeedMore => {
                let Some(remaining) = remaining_until(clock, deadline) else {
                    return HandshakeEnd::TimedOut {
                        phase: handshake.phase(),
                        pending_bytes: handshake.pending_bytes(),
                    };
                };
                if let Err(error) = conn.set_read_timeout(Some(remaining)) {
                    return HandshakeEnd::Io {
                        phase: handshake.phase(),
                        error,
                    };
                }
                // Never read more than the state machine can hold; a
                // zero-room read of one byte lets it report the overflow.
                let want = buf.len().min(handshake.room()).max(1);
                match conn.read(&mut buf[..want]) {
                    Ok(0) => return HandshakeEnd::Finished(handshake.input_ended()),
                    Ok(n) => handshake.feed(&buf[..n]),
                    Err(e) if is_timeout(&e) => {
                        return HandshakeEnd::TimedOut {
                            phase: handshake.phase(),
                            pending_bytes: handshake.pending_bytes(),
                        };
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        return HandshakeEnd::Io {
                            phase: handshake.phase(),
                            error,
                        };
                    }
                }
            }
        }
    }
}

/// Deterministic tests against a scripted server on the `Conn`/`Clock`
/// seam. The server-side bytes come from `handshake::scripted`: an
/// independent minimal implementation (provider calls plus Python-signed
/// fixtures), never from the code under test.
#[cfg(test)]
mod tests {
    use super::super::seam::scripted::{ReadEvent, ScriptedConn, VirtualClock, WriteEvent};
    use super::*;
    use crate::handshake::scripted::{
        Script, Sealer, client_rng, ecdh_reply, ext_info_payload, packet, plain,
        service_accept_payload, strict, string,
    };
    use crate::handshake::{COMPLETE_DESCRIPTION, REKEY_DESCRIPTION};
    use crate::transcript::fixtures::{ALICE_PUBLIC, V_S, i_c, k_s};
    use std::vec::Vec;
    use tatami_keys::fingerprint::Sha256Fingerprint;
    use tatami_keys::trust::{NoTrustPolicy, PinnedSha256, UntrustedReason};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn data(bytes: &[u8]) -> ReadEvent {
        ReadEvent::Data(bytes.to_vec())
    }

    fn config() -> HandshakeConfig {
        HandshakeConfig {
            software_version: String::from("tatami_0.1.0"),
            ..HandshakeConfig::default()
        }
    }

    fn pin() -> PinnedSha256 {
        PinnedSha256(Sha256Fingerprint::of_blob(&k_s()))
    }

    /// Server bytes through NEWKEYS.
    fn to_newkeys(script: &Script) -> Vec<u8> {
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&script.i_s));
        wire.extend(packet(&ecdh_reply(&script.signature)));
        wire.extend(packet(&[21]));
        wire
    }

    /// Server protected bytes: optional EXT_INFO, then SERVICE_ACCEPT.
    fn protected(script: &Script) -> Vec<u8> {
        let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
        let mut wire = Vec::new();
        if script.ext_info {
            wire.extend(sealer.seal(&ext_info_payload()));
        }
        wire.extend(sealer.seal(&service_accept_payload(b"ssh-userauth")));
        wire
    }

    fn full_transcript(script: &Script) -> Vec<u8> {
        let mut wire = to_newkeys(script);
        wire.extend(protected(script));
        wire
    }

    struct Outcome {
        end: HandshakeEnd,
        report: HandshakeReport,
        conn: ScriptedConn,
        clock: VirtualClock,
        deadline: Duration,
    }

    impl Outcome {
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

        fn outcome(&self) -> &HandshakeOutcome {
            match &self.end {
                HandshakeEnd::Finished(o) => o,
                other => panic!("expected a handshake outcome, got {other:?}"),
            }
        }
    }

    fn run_with(
        config: HandshakeConfig,
        policy: &dyn HostTrustPolicy,
        reads: Vec<ReadEvent>,
        writes: Vec<WriteEvent>,
        deadline: Duration,
        chunk: usize,
    ) -> Outcome {
        let clock = VirtualClock::new();
        let mut conn = ScriptedConn::new(&clock, reads, writes);
        let mut hs = ClientHandshake::new(config, &mut client_rng()).unwrap();
        let end = run_handshake_on(
            &mut conn,
            &clock,
            &mut hs,
            policy,
            clock.now() + deadline,
            chunk,
        );
        Outcome {
            end,
            report: hs.report(),
            conn,
            clock,
            deadline,
        }
    }

    fn run(reads: Vec<ReadEvent>, writes: Vec<WriteEvent>) -> Outcome {
        run_with(config(), &pin(), reads, writes, ms(5_000), 4096)
    }

    /// Splits the client's output into the identification line, the
    /// unprotected payloads and the remaining protected bytes.
    fn split_client_output(written: &[u8], unprotected_packets: usize) -> (Vec<Vec<u8>>, &[u8]) {
        let ident_end = written.iter().position(|&b| b == b'\n').unwrap() + 1;
        assert_eq!(&written[..ident_end], b"SSH-2.0-tatami_0.1.0\r\n");
        let mut rest = &written[ident_end..];
        let mut payloads = Vec::new();
        for _ in 0..unprotected_packets {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let pad = rest[4] as usize;
            payloads.push(rest[5..4 + len - pad].to_vec());
            rest = &rest[4 + len..];
        }
        (payloads, rest)
    }

    fn expected_disconnect(description: &[u8]) -> Vec<u8> {
        let mut d = std::vec![1u8, 0, 0, 0, 11];
        d.extend(string(description));
        d.extend(string(b""));
        d
    }

    #[test]
    fn full_scripted_handshake_completes_with_short_writes() {
        let script = strict();
        let out = run(
            std::vec![data(&full_transcript(&script))],
            std::vec![
                WriteEvent::Accept(3),
                WriteEvent::Accept(40),
                WriteEvent::Accept(1),
            ],
        );
        assert!(out.end.is_complete(), "{}", out.end.label());
        assert_eq!(out.end.label(), "complete: service accepted");
        out.assert_deadline_discipline();

        let (payloads, protected) = split_client_output(&out.conn.written, 3);
        assert_eq!(payloads[0], i_c());
        let mut ecdh_init = std::vec![30u8];
        ecdh_init.extend(string(&ALICE_PUBLIC));
        assert_eq!(payloads[1], ecdh_init);
        assert_eq!(payloads[2], [21]);
        // The two protected client packets decrypt with the independent
        // opener under key C / IV A.
        let mut opener = Sealer::new(&script.key_c, &script.iv_a);
        let (request, n) = opener.open(protected);
        let mut expected = std::vec![5u8];
        expected.extend(string(b"ssh-userauth"));
        assert_eq!(request, expected);
        let (disconnect, m) = opener.open(&protected[n..]);
        assert_eq!(disconnect, expected_disconnect(COMPLETE_DESCRIPTION));
        assert_eq!(n + m, protected.len(), "nothing after our DISCONNECT");

        // Five write calls for the first set (3 + 40 + 1 + rest), then one
        // each for ECDH_INIT, NEWKEYS, SERVICE_REQUEST, DISCONNECT.
        assert_eq!(out.conn.write_calls, 8);
        let r = &out.report;
        assert_eq!(r.outcome, Some(HandshakeOutcome::Completed));
        assert!(r.strict_kex.negotiated);
        assert_eq!(r.kexinit_was_first_packet, Some(true));
        assert_eq!(r.trust.map(|t| t.is_trusted()), Some(true));
        assert_eq!(r.service_accepted.as_deref(), Some("ssh-userauth"));
        assert!(r.ext_info.as_ref().unwrap().received);
        assert_eq!(r.protected_packets_sent, 2);
        assert_eq!(r.protected_packets_received, 2);
        assert!(!r.user_authenticated);
    }

    #[test]
    fn wrong_pin_writes_no_newkeys() {
        let script = strict();
        let wrong = PinnedSha256(Sha256Fingerprint::from_bytes([0x42; 32]));
        let out = run_with(
            config(),
            &wrong,
            std::vec![data(&full_transcript(&script))],
            Vec::new(),
            ms(5_000),
            4096,
        );
        assert_eq!(
            out.outcome(),
            &HandshakeOutcome::HostNotTrusted {
                reason: UntrustedReason::FingerprintMismatch
            }
        );
        let (payloads, rest) = split_client_output(&out.conn.written, 2);
        assert_eq!(payloads[0][0], 20);
        assert_eq!(payloads[1][0], 30);
        assert!(rest.is_empty(), "nothing after ECDH_INIT");
        assert!(!out.report.newkeys_sent);
        assert_eq!(out.report.signature_valid, Some(true));
        // With no pin at all the default is to refuse.
        let out = run_with(
            config(),
            &NoTrustPolicy,
            std::vec![data(&full_transcript(&script))],
            Vec::new(),
            ms(5_000),
            4096,
        );
        assert_eq!(
            out.outcome(),
            &HandshakeOutcome::HostNotTrusted {
                reason: UntrustedReason::NoPolicy
            }
        );
    }

    #[test]
    fn flipped_signature_byte_is_signature_invalid() {
        let script = strict();
        let mut sig = script.signature;
        sig[17] ^= 0x10;
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&script.i_s));
        wire.extend(packet(&ecdh_reply(&sig)));
        let out = run(std::vec![data(&wire)], Vec::new());
        assert_eq!(out.outcome(), &HandshakeOutcome::SignatureInvalid);
        assert_eq!(out.report.signature_valid, Some(false));
        assert_eq!(out.report.trust, None);
        let (_, rest) = split_client_output(&out.conn.written, 2);
        assert!(rest.is_empty());
    }

    #[test]
    fn tampered_protected_byte_is_tag_mismatch() {
        let script = strict();
        let mut wire = full_transcript(&script);
        let tail = wire.len();
        wire[tail - 30] ^= 0x01;
        let out = run(std::vec![data(&wire)], Vec::new());
        assert_eq!(out.outcome(), &HandshakeOutcome::TagMismatch);
        // EXT_INFO was fine; SERVICE_ACCEPT was not.
        assert_eq!(out.report.protected_packets_received, 1);
        let (_, protected) = split_client_output(&out.conn.written, 3);
        let mut opener = Sealer::new(&script.key_c, &script.iv_a);
        let (_, n) = opener.open(protected);
        assert_eq!(n, protected.len(), "only SERVICE_REQUEST, no DISCONNECT");
    }

    #[test]
    fn ignore_before_kexinit_is_fatal_under_strict_kex_and_fine_otherwise() {
        let ignore = packet(&[2, 0, 0, 0, 3, 1, 2, 3]);
        let mut strict_wire = V_S.to_vec();
        strict_wire.extend_from_slice(b"\r\n");
        strict_wire.extend(&ignore);
        strict_wire.extend(&full_transcript(&strict())[V_S.len() + 2..]);
        let out = run(std::vec![data(&strict_wire)], Vec::new());
        assert_eq!(
            out.outcome(),
            &HandshakeOutcome::StrictKexViolation {
                detail: String::from("KEXINIT was not the first packet received")
            }
        );
        assert_eq!(out.report.kexinit_was_first_packet, Some(false));
        let (_, rest) = split_client_output(&out.conn.written, 1);
        assert!(rest.is_empty(), "no ECDH_INIT after the violation");

        let plain_script = plain();
        let mut plain_wire = V_S.to_vec();
        plain_wire.extend_from_slice(b"\r\n");
        plain_wire.extend(&ignore);
        plain_wire.extend(&full_transcript(&plain_script)[V_S.len() + 2..]);
        let out = run(std::vec![data(&plain_wire)], Vec::new());
        assert!(out.end.is_complete(), "{}", out.end.label());
        assert!(!out.report.strict_kex.negotiated);
        assert_eq!(out.report.kexinit_was_first_packet, Some(false));
        assert_eq!(out.report.skipped_messages.len(), 1);
    }

    #[test]
    fn server_kexinit_after_newkeys_is_rekey_not_supported_with_our_disconnect() {
        let script = strict();
        let mut wire = to_newkeys(&script);
        let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
        wire.extend(sealer.seal(&ext_info_payload()));
        wire.extend(sealer.seal(&script.i_s));
        let out = run(std::vec![data(&wire)], Vec::new());
        assert_eq!(out.outcome(), &HandshakeOutcome::RekeyNotSupported);
        let (_, protected) = split_client_output(&out.conn.written, 3);
        let mut opener = Sealer::new(&script.key_c, &script.iv_a);
        let (_, n) = opener.open(protected);
        let (disconnect, m) = opener.open(&protected[n..]);
        assert_eq!(disconnect, expected_disconnect(REKEY_DESCRIPTION));
        assert_eq!(n + m, protected.len());
        assert_eq!(out.report.protected_packets_sent, 2);
    }

    #[test]
    fn newkeys_tail_and_protected_head_in_one_read() {
        let script = strict();
        let pre = to_newkeys(&script);
        let post = protected(&script);
        // Everything up to the middle of the NEWKEYS packet, then a chunk
        // holding NEWKEYS' last 9 bytes plus the first 11 protected bytes
        // (inside the EXT_INFO length+ciphertext), then the rest.
        let cut1 = pre.len() - 9;
        let mut mixed = pre[cut1..].to_vec();
        mixed.extend_from_slice(&post[..11]);
        let out = run(
            std::vec![data(&pre[..cut1]), data(&mixed), data(&post[11..])],
            Vec::new(),
        );
        assert!(out.end.is_complete(), "{}", out.end.label());
        assert_eq!(out.report.protected_packets_received, 2);
        assert!(out.report.ext_info.as_ref().unwrap().received);
        out.assert_deadline_discipline();
    }

    #[test]
    fn byte_at_a_time_delivery_equals_all_at_once() {
        let script = strict();
        let wire = full_transcript(&script);
        let all = run(std::vec![data(&wire)], Vec::new());
        // chunk = 1 makes every read return one byte.
        let one = run_with(
            config(),
            &pin(),
            std::vec![data(&wire)],
            Vec::new(),
            ms(5_000),
            1,
        );
        assert!(all.end.is_complete());
        assert!(one.end.is_complete());
        assert_eq!(one.conn.written, all.conn.written);
        assert_eq!(one.report, all.report);
        assert_eq!(one.conn.read_requests.len(), wire.len());
        assert!(one.conn.read_requests.iter().all(|&n| n == 1));
        one.assert_deadline_discipline();
    }

    #[test]
    fn reads_never_exceed_room_and_eof_is_reported_with_phase() {
        let script = strict();
        let mut cfg = config();
        cfg.packet.max_packet_length = 1024;
        cfg.ident.max_prelude_line = 64;
        cfg.ident.max_identification_line = 64;
        let capacity = cfg.buffer_capacity();
        let wire = to_newkeys(&script);
        let out = run_with(
            cfg,
            &pin(),
            std::vec![data(&wire), ReadEvent::Eof],
            Vec::new(),
            ms(5_000),
            8192,
        );
        assert_eq!(
            out.outcome(),
            &HandshakeOutcome::Eof {
                phase: Phase::Service
            }
        );
        assert!(out.conn.read_requests.iter().all(|&n| n <= capacity));
        assert_eq!(
            out.end.label(),
            "connection closed by peer while awaiting SERVICE_ACCEPT"
        );
        assert!(out.report.newkeys_sent && out.report.newkeys_received);
    }

    #[test]
    fn deadline_exhaustion_mid_protected_read() {
        let script = strict();
        let pre = to_newkeys(&script);
        let post = protected(&script);
        let out = run_with(
            config(),
            &pin(),
            std::vec![
                ReadEvent::Elapse(ms(100)),
                data(&pre),
                ReadEvent::Elapse(ms(200)),
                data(&post[..20]),
                ReadEvent::Elapse(ms(10_000)),
                data(&post[20..]),
            ],
            Vec::new(),
            ms(1_000),
            4096,
        );
        match &out.end {
            HandshakeEnd::TimedOut {
                phase,
                pending_bytes,
            } => {
                assert_eq!(*phase, Phase::Service);
                assert_eq!(*pending_bytes, 20);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(out.clock.elapsed(), ms(1_000));
        assert_eq!(out.end.label(), "timed out while awaiting SERVICE_ACCEPT");
        // The remaining silence and the never-read tail are still queued.
        assert_eq!(out.conn.unread_events(), 2);
        out.assert_deadline_discipline();
        // The report is still a complete picture of what happened.
        assert!(out.report.newkeys_received);
        assert_eq!(out.report.outcome, None);
    }

    #[test]
    fn write_timeout_and_write_errors_carry_the_phase() {
        let script = strict();
        let out = run_with(
            config(),
            &pin(),
            std::vec![data(&full_transcript(&script))],
            std::vec![WriteEvent::Elapse(ms(10_000))],
            ms(1_000),
            4096,
        );
        assert!(matches!(
            out.end,
            HandshakeEnd::TimedOut {
                phase: Phase::ServerIdentification,
                pending_bytes: 0
            }
        ));
        assert_eq!(out.clock.elapsed(), ms(1_000));

        let out = run_with(
            config(),
            &pin(),
            std::vec![data(&full_transcript(&script))],
            std::vec![WriteEvent::Zero],
            ms(1_000),
            4096,
        );
        assert!(matches!(
            out.end,
            HandshakeEnd::Io {
                phase: Phase::ServerIdentification,
                ref error
            } if error.kind() == io::ErrorKind::WriteZero
        ));

        // A reset while writing NEWKEYS: the trust decision was made.
        let out = run_with(
            config(),
            &pin(),
            std::vec![data(&full_transcript(&script))],
            std::vec![
                WriteEvent::Accept(usize::MAX),
                WriteEvent::Accept(usize::MAX),
                WriteEvent::Err(io::ErrorKind::ConnectionReset),
            ],
            ms(1_000),
            4096,
        );
        assert!(matches!(
            out.end,
            HandshakeEnd::Io {
                phase: Phase::ServerNewKeys,
                ref error
            } if error.kind() == io::ErrorKind::ConnectionReset
        ));
        assert!(out.report.newkeys_sent);
    }

    #[test]
    fn interrupted_reads_are_retried_and_silence_times_out() {
        let script = strict();
        let wire = full_transcript(&script);
        let out = run(
            std::vec![
                ReadEvent::Err(io::ErrorKind::Interrupted),
                data(&wire[..10]),
                ReadEvent::Err(io::ErrorKind::Interrupted),
                data(&wire[10..]),
            ],
            Vec::new(),
        );
        assert!(out.end.is_complete(), "{}", out.end.label());

        let out = run_with(
            config(),
            &pin(),
            std::vec![data(b"SSH-2.0-silent\r\n")],
            Vec::new(),
            ms(700),
            4096,
        );
        assert!(matches!(
            out.end,
            HandshakeEnd::TimedOut {
                phase: Phase::ServerKexInit,
                pending_bytes: 0
            }
        ));
        assert_eq!(out.clock.elapsed(), ms(700));
        assert_eq!(
            out.conn.read_requests.len(),
            2,
            "one read, one wait; no spin"
        );
    }

    #[test]
    fn os_entropy_fills_and_differs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsEntropy.try_fill_bytes(&mut a).unwrap();
        OsEntropy.try_fill_bytes(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(OsEntropy.next_u64(), OsEntropy.next_u64());
        let hs = ClientHandshake::new(config(), &mut OsEntropy).unwrap();
        assert_eq!(hs.phase(), Phase::ServerIdentification);
    }

    #[test]
    fn handshake_io_connect_uses_its_own_timeout() {
        // Port 1 on loopback is refused promptly; the point is that the
        // helper builds a valid IoConfig and surfaces the connect error.
        let io = HandshakeIo {
            connect_timeout: ms(2_000),
            ..HandshakeIo::default()
        };
        assert!(io.connect("127.0.0.1", 1).is_err());
    }
}
