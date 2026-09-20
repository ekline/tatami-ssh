//! Incoming-connection observer: a portable state machine for the server
//! side of the identification exchange and the client's first `KEXINIT`.
//!
//! # What the observer does
//!
//! 1. Provides a valid server identification line for the adapter to send
//!    immediately ([`Observer::server_identification`]).
//! 2. Consumes client bytes and parses the client identification.
//! 3. Unless configured banner-only, decodes initial unprotected packets
//!    until the client's first `KEXINIT`, a `DISCONNECT`, a protocol error,
//!    or a budget is exhausted.
//!
//! It never sends a server `KEXINIT`, never loads or generates a host key,
//! and never solicits credentials. It is a deliberately incomplete SSH
//! endpoint for observing what connecting clients offer.
//!
//! # Differences from the client probe
//!
//! - RFC 4253 §4.2 allows a **server** to send lines before its
//!   identification; a client may not. Anything from the client that does
//!   not begin with `SSH-` ends the observation as
//!   [`ObservationOutcome::UnexpectedInput`] with a bounded sample. It is not
//!   treated as a prelude.
//! - The observed proposal is the **client's**. Its
//!   `server_host_key_algorithms` list is the client's statement of which
//!   server host-key algorithms it accepts, not a client key.
//! - A client `1.99` version or LF-only terminator is reported as an
//!   [`crate::ident::IdentAnomaly`], never used to change behaviour.
//!
//! # Buffering bound
//!
//! Input lives in an [`InputBuffer`] sized from the configured limits;
//! [`Observer::feed`] rejects excess input before copying. Adapters should
//! read at most [`Observer::room`] bytes per read.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use crate::ident::OwnedIdentification;
use crate::ident::{
    IdentLimits, IdentStep, IdentificationReader, InvalidLocalIdentification,
    MAX_IDENTIFICATION_LINE, build_identification, starts_identification,
};
pub use crate::initial::{InitialError, SkippedMessage};
use crate::initial::{InitialLimits, InitialPackets, InitialStep, InputBuffer};
use crate::packet::HEADER_LEN;
pub use crate::probe::Proposal;

/// Software version token sent in the server identification.
pub const DEFAULT_SOFTWARE_VERSION: &str = "tatami_observer_0.1.0";

/// Configuration for an observer. All numeric limits are local policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObserverConfig {
    /// `softwareversion` token for the server identification.
    pub software_version: String,
    /// Initial packet budgets.
    pub initial: InitialLimits,
    /// Stop after a valid client identification instead of waiting for a
    /// `KEXINIT`.
    pub banner_only: bool,
    /// Maximum bytes of unexpected (non-`SSH-`) input retained as a sample.
    pub unexpected_sample: usize,
    /// Maximum accepted client identification line including `CR LF`.
    /// Defaults to the RFC limit of 255.
    pub max_identification_line: usize,
}

impl Default for ObserverConfig {
    fn default() -> Self {
        ObserverConfig {
            software_version: String::from(DEFAULT_SOFTWARE_VERSION),
            initial: InitialLimits::default(),
            banner_only: false,
            unexpected_sample: 256,
            max_identification_line: MAX_IDENTIFICATION_LINE,
        }
    }
}

impl ObserverConfig {
    /// Largest amount of unconsumed input the observer will hold.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        let packet = self.initial.packet.max_packet_length as usize + HEADER_LEN;
        packet.max(self.max_identification_line) + self.max_identification_line
    }
}

/// Which phase the observer is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserverStage {
    /// Waiting for the client identification.
    ClientIdentification,
    /// Identification received; decoding initial packets.
    InitialPackets,
    /// A terminal outcome has been produced.
    Finished,
}

impl ObserverStage {
    /// Stable, machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            ObserverStage::ClientIdentification => "client_identification",
            ObserverStage::InitialPackets => "initial_packets",
            ObserverStage::Finished => "finished",
        }
    }
}

impl fmt::Display for ObserverStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ObserverStage::ClientIdentification => "awaiting client identification",
            ObserverStage::InitialPackets => "awaiting client KEXINIT",
            ObserverStage::Finished => "finished",
        })
    }
}

/// Non-terminal observations, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObserverEvent {
    /// The client identification.
    ClientIdentification(OwnedIdentification),
    /// A pre-`KEXINIT` message that was reported and skipped.
    Skipped(SkippedMessage),
}

/// Terminal outcome of the portable observer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservationOutcome {
    /// Banner-only mode: a valid client identification was received.
    BannerOnly,
    /// The client's first `KEXINIT` was received and decoded.
    Proposal(Box<Proposal>),
    /// The client sent `SSH_MSG_DISCONNECT`.
    Disconnected {
        /// Reason code.
        reason_code: u32,
        /// Raw description. Untrusted.
        description: Vec<u8>,
        /// Raw language tag. Untrusted.
        language_tag: Vec<u8>,
    },
    /// The client sent something other than an identification first.
    UnexpectedInput {
        /// Bounded sample of what arrived. Untrusted bytes.
        sample: Vec<u8>,
        /// `true` if more bytes were buffered than the sample holds.
        truncated: bool,
    },
    /// The adapter reported end of input.
    Eof {
        /// Stage at which input ended.
        stage: ObserverStage,
        /// Unconsumed bytes buffered at EOF (a truncated line or packet).
        pending_bytes: usize,
    },
    /// A protocol error or exhausted budget.
    Error(InitialError),
}

impl ObservationOutcome {
    /// Stable, machine-readable outcome code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ObservationOutcome::BannerOnly => "banner_only",
            ObservationOutcome::Proposal(p) if p.anomalies.is_empty() => "proposal",
            ObservationOutcome::Proposal(_) => "proposal_with_anomalies",
            ObservationOutcome::Disconnected { .. } => "disconnected",
            ObservationOutcome::UnexpectedInput { .. } => "unexpected_input",
            ObservationOutcome::Eof { .. } => "eof",
            ObservationOutcome::Error(_) => "protocol_error",
        }
    }
}

/// Result of [`Observer::step`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObserverStep {
    /// No progress possible without more input.
    NeedMore,
    /// An observation; call [`Observer::step`] again.
    Event(ObserverEvent),
    /// Finished. Further calls return this same value.
    Finished(ObservationOutcome),
}

/// The portable observer state machine.
#[derive(Debug)]
pub struct Observer {
    server_line: Vec<u8>,
    banner_only: bool,
    unexpected_sample: usize,
    stage: ObserverStage,
    ident: IdentificationReader,
    packets: InitialPackets,
    buf: InputBuffer,
    end: Option<ObservationOutcome>,
}

impl Observer {
    /// Creates an observer, validating the outgoing identification.
    pub fn new(config: &ObserverConfig) -> Result<Self, InvalidLocalIdentification> {
        let server_line = build_identification(&config.software_version)?;
        // The reader's prelude support is disabled: clients may not send
        // prelude text, and `step_identification` intercepts it first.
        let limits = IdentLimits {
            max_prelude_lines: 0,
            max_prelude_bytes: 0,
            max_prelude_line: config.max_identification_line,
            max_identification_line: config.max_identification_line,
        };
        Ok(Observer {
            server_line,
            banner_only: config.banner_only,
            unexpected_sample: config.unexpected_sample,
            stage: ObserverStage::ClientIdentification,
            ident: IdentificationReader::new(limits),
            packets: InitialPackets::new(config.initial),
            buf: InputBuffer::new(config.buffer_capacity()),
            end: None,
        })
    }

    /// The full server identification line including `CR LF`. The adapter
    /// must send this before reading anything.
    #[must_use]
    pub fn server_identification(&self) -> &[u8] {
        &self.server_line
    }

    /// The server identification without its terminator (`V_S` form).
    #[must_use]
    pub fn server_identification_line(&self) -> &[u8] {
        &self.server_line[..self.server_line.len() - 2]
    }

    /// Current stage.
    #[must_use]
    pub const fn stage(&self) -> ObserverStage {
        self.stage
    }

    /// Bytes fed but not yet consumed.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Bytes that may still be fed without overflowing the buffer bound.
    #[must_use]
    pub fn room(&self) -> usize {
        self.buf.room()
    }

    /// Appends received bytes. Input exceeding [`Observer::room`] is
    /// rejected before copying and ends the observation with
    /// [`InitialError::InputOverflow`].
    pub fn feed(&mut self, data: &[u8]) {
        if self.stage == ObserverStage::Finished {
            return;
        }
        if let Err(e) = self.buf.push(data) {
            self.finish(ObservationOutcome::Error(InitialError::InputOverflow(e)));
        }
    }

    /// Signals end of input.
    pub fn input_ended(&mut self) -> ObservationOutcome {
        if let Some(end) = &self.end {
            return end.clone();
        }
        self.finish(ObservationOutcome::Eof {
            stage: self.stage,
            pending_bytes: self.buf.len(),
        })
    }

    /// Advances by at most one observation.
    pub fn step(&mut self) -> ObserverStep {
        if let Some(end) = &self.end {
            return ObserverStep::Finished(end.clone());
        }
        match self.stage {
            ObserverStage::ClientIdentification => self.step_identification(),
            ObserverStage::InitialPackets => self.step_packet(),
            ObserverStage::Finished => unreachable!("finished without outcome"),
        }
    }

    fn finish(&mut self, end: ObservationOutcome) -> ObservationOutcome {
        self.stage = ObserverStage::Finished;
        self.end = Some(end.clone());
        end
    }

    fn step_identification(&mut self) -> ObserverStep {
        let buf = self.buf.as_slice();
        if starts_identification(buf) == Some(false) {
            let n = buf.len().min(self.unexpected_sample);
            let outcome = ObservationOutcome::UnexpectedInput {
                sample: buf[..n].to_vec(),
                truncated: buf.len() > n,
            };
            self.buf.clear();
            return ObserverStep::Finished(self.finish(outcome));
        }
        match self.ident.feed(buf) {
            Ok(IdentStep::NeedMore) => ObserverStep::NeedMore,
            Ok(IdentStep::Prelude { .. }) => {
                unreachable!("non-SSH lines are intercepted before the reader")
            }
            Ok(IdentStep::Identification { ident, consumed }) => {
                let owned = OwnedIdentification::from(ident);
                self.buf.consume(consumed);
                if self.banner_only {
                    // Report the identification now; the next `step` returns
                    // the recorded outcome.
                    self.finish(ObservationOutcome::BannerOnly);
                } else {
                    self.stage = ObserverStage::InitialPackets;
                }
                ObserverStep::Event(ObserverEvent::ClientIdentification(owned))
            }
            Err(e) => ObserverStep::Finished(
                self.finish(ObservationOutcome::Error(InitialError::Ident(e))),
            ),
        }
    }

    fn step_packet(&mut self) -> ObserverStep {
        let step = self.packets.step(self.buf.as_slice());
        let (end, consumed) = match step {
            InitialStep::NeedMore => return ObserverStep::NeedMore,
            InitialStep::Skipped { message, consumed } => {
                self.buf.consume(consumed);
                return ObserverStep::Event(ObserverEvent::Skipped(message));
            }
            InitialStep::KexInit {
                kexinit,
                payload,
                consumed,
            } => {
                let proposal = Proposal::from_kexinit(&kexinit, payload, self.buf.len() - consumed);
                (ObservationOutcome::Proposal(Box::new(proposal)), consumed)
            }
            InitialStep::Disconnect {
                disconnect,
                consumed,
            } => (
                ObservationOutcome::Disconnected {
                    reason_code: disconnect.reason_code,
                    description: disconnect.description.to_vec(),
                    language_tag: disconnect.language_tag.to_vec(),
                },
                consumed,
            ),
            InitialStep::Error(e) => (ObservationOutcome::Error(e), 0),
        };
        self.buf.consume(consumed);
        ObserverStep::Finished(self.finish(end))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    use crate::ident::{IdentAnomaly, IdentError};
    use crate::packet::{PacketError, encode_initial_packet};
    use tatami_wire::Writer;

    /// A client-direction KEXINIT with client markers and distinct lists.
    fn client_kexinit_payload() -> Vec<u8> {
        let mut buf = [0u8; 512];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).unwrap();
        w.write_bytes(&[0xC1; 16]).unwrap();
        w.write_string(b"sntrup761x25519-sha512@openssh.com,curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com")
            .unwrap();
        w.write_string(b"ssh-ed25519-cert-v01@openssh.com,ssh-ed25519,rsa-sha2-512")
            .unwrap();
        w.write_string(b"chacha20-poly1305@openssh.com,aes128-ctr")
            .unwrap();
        w.write_string(b"aes256-gcm@openssh.com,made-up-cipher")
            .unwrap();
        w.write_string(b"umac-64-etm@openssh.com").unwrap();
        w.write_string(b"hmac-sha2-256").unwrap();
        w.write_string(b"none,zlib@openssh.com").unwrap();
        w.write_string(b"zlib@openssh.com,none").unwrap();
        w.write_string(b"").unwrap();
        w.write_string(b"en-US").unwrap();
        w.write_bool(false).unwrap();
        w.write_u32(0).unwrap();
        w.written().to_vec()
    }

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; payload.len() + 64];
        let n = encode_initial_packet(payload, 0, &mut out).unwrap();
        out.truncate(n);
        out
    }

    fn observer() -> Observer {
        Observer::new(&ObserverConfig::default()).unwrap()
    }

    fn drain(o: &mut Observer) -> (Vec<ObserverEvent>, Option<ObservationOutcome>) {
        let mut events = Vec::new();
        loop {
            match o.step() {
                ObserverStep::NeedMore => return (events, None),
                ObserverStep::Event(e) => events.push(e),
                ObserverStep::Finished(end) => return (events, Some(end)),
            }
        }
    }

    #[test]
    fn server_identification_is_valid() {
        let o = observer();
        assert_eq!(
            o.server_identification(),
            b"SSH-2.0-tatami_observer_0.1.0\r\n"
        );
        assert_eq!(
            o.server_identification_line(),
            b"SSH-2.0-tatami_observer_0.1.0"
        );
        assert_eq!(o.server_identification().len(), 31);
        let bad = ObserverConfig {
            software_version: String::from("has space"),
            ..ObserverConfig::default()
        };
        assert!(Observer::new(&bad).is_err());
        let long = ObserverConfig {
            software_version: "y".repeat(250),
            ..ObserverConfig::default()
        };
        assert_eq!(
            Observer::new(&long).err(),
            Some(InvalidLocalIdentification::TooLong { len: 260 })
        );
    }

    #[test]
    fn client_identification_then_proposal_coalesced_with_trailing_bytes() {
        let mut o = observer();
        let mut wire = b"SSH-2.0-OpenSSH_9.9 comment\r\n".to_vec();
        wire.extend(packet(&client_kexinit_payload()));
        wire.extend([0xde, 0xad, 0xbe, 0xef]);
        o.feed(&wire);
        let (events, end) = drain(&mut o);
        assert_eq!(events.len(), 1);
        match &events[0] {
            ObserverEvent::ClientIdentification(i) => {
                assert_eq!(i.software_version, "OpenSSH_9.9");
                assert_eq!(i.comments.as_deref(), Some(&b"comment"[..]));
                assert_eq!(i.anomalies().count(), 0);
            }
            other => panic!("{other:?}"),
        }
        let Some(ObservationOutcome::Proposal(p)) = end else {
            panic!("{end:?}")
        };
        assert_eq!(p.kexinit.kex_algorithms.len(), 4);
        assert_eq!(p.kexinit.kex_algorithms[2], "ext-info-c");
        assert_eq!(p.kexinit.kex_algorithms[3], "kex-strict-c-v00@openssh.com");
        assert_eq!(
            p.kexinit.server_host_key_algorithms,
            [
                "ssh-ed25519-cert-v01@openssh.com",
                "ssh-ed25519",
                "rsa-sha2-512"
            ]
        );
        assert_eq!(
            p.kexinit.encryption_client_to_server,
            ["chacha20-poly1305@openssh.com", "aes128-ctr"]
        );
        assert_eq!(
            p.kexinit.encryption_server_to_client,
            ["aes256-gcm@openssh.com", "made-up-cipher"]
        );
        assert_eq!(
            p.kexinit.compression_client_to_server,
            ["none", "zlib@openssh.com"]
        );
        assert_eq!(
            p.kexinit.compression_server_to_client,
            ["zlib@openssh.com", "none"]
        );
        assert!(p.kexinit.languages_client_to_server.is_empty());
        assert_eq!(p.kexinit.languages_server_to_client, ["en-US"]);
        assert_eq!(p.kexinit.cookie, [0xC1; 16]);
        assert!(p.anomalies.is_empty());
        assert_eq!(p.unexamined_bytes, 4);
        assert_eq!(o.stage(), ObserverStage::Finished);
    }

    #[test]
    fn fragmented_client_input_byte_by_byte() {
        let mut wire = b"SSH-2.0-frag\r\n".to_vec();
        wire.extend(packet(&[2, 0, 0, 0, 0]));
        wire.extend(packet(&client_kexinit_payload()));
        let mut o = observer();
        let mut events = Vec::new();
        let mut end = None;
        for b in wire {
            o.feed(&[b]);
            let (ev, e) = drain(&mut o);
            events.extend(ev);
            if e.is_some() {
                end = e;
                break;
            }
        }
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[1],
            ObserverEvent::Skipped(SkippedMessage::Ignored { data_len: 0 })
        ));
        assert!(matches!(end, Some(ObservationOutcome::Proposal(_))));
    }

    #[test]
    fn banner_only_stops_after_identification() {
        let config = ObserverConfig {
            banner_only: true,
            ..ObserverConfig::default()
        };
        let mut o = Observer::new(&config).unwrap();
        let mut wire = b"SSH-2.0-x\r\n".to_vec();
        wire.extend(packet(&client_kexinit_payload()));
        o.feed(&wire);
        let (events, end) = drain(&mut o);
        assert_eq!(events.len(), 1);
        assert_eq!(end, Some(ObservationOutcome::BannerOnly));
        assert_eq!(end.unwrap().code(), "banner_only");
    }

    #[test]
    fn unexpected_prelude_from_client_ends_observation_with_sample() {
        let mut o = observer();
        o.feed(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        let (events, end) = drain(&mut o);
        assert!(events.is_empty());
        assert_eq!(
            end,
            Some(ObservationOutcome::UnexpectedInput {
                sample: b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
                truncated: false,
            })
        );

        let config = ObserverConfig {
            unexpected_sample: 4,
            ..ObserverConfig::default()
        };
        let mut o = Observer::new(&config).unwrap();
        o.feed(b"\x16\x03\x01\x02\x00\x01\x00");
        let (_, end) = drain(&mut o);
        assert_eq!(
            end,
            Some(ObservationOutcome::UnexpectedInput {
                sample: vec![0x16, 0x03, 0x01, 0x02],
                truncated: true,
            })
        );
        assert_eq!(o.pending_bytes(), 0);
    }

    #[test]
    fn partial_prefix_waits_then_decides() {
        let mut o = observer();
        o.feed(b"SS");
        assert_eq!(o.step(), ObserverStep::NeedMore);
        o.feed(b"H-2.0-ok\r\n");
        assert!(matches!(
            o.step(),
            ObserverStep::Event(ObserverEvent::ClientIdentification(_))
        ));

        let mut o = observer();
        o.feed(b"SS");
        assert_eq!(o.step(), ObserverStep::NeedMore);
        o.feed(b"X");
        assert!(matches!(
            o.step(),
            ObserverStep::Finished(ObservationOutcome::UnexpectedInput { .. })
        ));
    }

    #[test]
    fn identification_anomalies_and_lengths() {
        let mut o = observer();
        o.feed(b"SSH-1.99-old\n");
        let (events, _) = drain(&mut o);
        let ObserverEvent::ClientIdentification(i) = &events[0] else {
            panic!()
        };
        let a: Vec<_> = i.anomalies().collect();
        assert_eq!(
            a,
            [
                IdentAnomaly::LfOnlyTerminator,
                IdentAnomaly::CompatibilityVersion
            ]
        );
        assert_eq!(o.stage(), ObserverStage::InitialPackets);

        let mut o = observer();
        o.feed(b"SSH-1.5-ancient\r\n");
        let (_, end) = drain(&mut o);
        assert_eq!(
            end,
            Some(ObservationOutcome::Error(InitialError::Ident(
                IdentError::UnsupportedVersion
            )))
        );

        let mut line = vec![b'z'; 256];
        line[..8].copy_from_slice(b"SSH-2.0-");
        line[254] = b'\r';
        line[255] = b'\n';
        let mut o = observer();
        o.feed(&line);
        let (_, end) = drain(&mut o);
        assert_eq!(
            end,
            Some(ObservationOutcome::Error(InitialError::Ident(
                IdentError::IdentificationTooLong
            )))
        );
        let mut o = observer();
        o.feed(&line[..253]);
        o.feed(b"\r\n");
        let (events, _) = drain(&mut o);
        assert!(matches!(events[0], ObserverEvent::ClientIdentification(_)));
    }

    #[test]
    fn disconnect_debug_and_flood_budget() {
        let mut o = observer();
        o.feed(b"SSH-2.0-x\r\n");
        o.feed(&packet(&[4, 0, 0, 0, 0, 3, b'd', b'b', b'g', 0, 0, 0, 0]));
        o.feed(&packet(&[1, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0]));
        let (events, end) = drain(&mut o);
        assert!(matches!(
            &events[1],
            ObserverEvent::Skipped(SkippedMessage::Debug { always_display: false, message, .. })
                if message == b"dbg"
        ));
        assert_eq!(
            end,
            Some(ObservationOutcome::Disconnected {
                reason_code: 11,
                description: Vec::new(),
                language_tag: Vec::new(),
            })
        );

        let mut o = observer();
        o.feed(b"SSH-2.0-x\r\n");
        let ig = packet(&[2, 0, 0, 0, 0]);
        for _ in 0..20 {
            o.feed(&ig);
        }
        let (events, end) = drain(&mut o);
        assert_eq!(events.len(), 1 + 16);
        assert_eq!(
            end,
            Some(ObservationOutcome::Error(
                InitialError::PacketBudgetExceeded { limit: 16 }
            ))
        );
    }

    #[test]
    fn oversized_packet_claim_and_overflowing_feed() {
        let mut o = observer();
        o.feed(b"SSH-2.0-x\r\n\x00\x01\x00\x08"); // 65544 > 64 KiB cap
        let (_, end) = drain(&mut o);
        assert!(matches!(
            end,
            Some(ObservationOutcome::Error(InitialError::Packet(
                PacketError::TooLarge { .. }
            )))
        ));

        let mut o = observer();
        let cap = o.room();
        o.feed(&vec![b'S'; cap + 1]);
        assert_eq!(o.pending_bytes(), 0);
        assert!(matches!(
            o.step(),
            ObserverStep::Finished(ObservationOutcome::Error(InitialError::InputOverflow(_)))
        ));
    }

    #[test]
    fn unexpected_newkeys_and_eof_variants() {
        let mut o = observer();
        o.feed(b"SSH-2.0-x\r\n");
        o.feed(&packet(&[21]));
        let (_, end) = drain(&mut o);
        assert_eq!(
            end,
            Some(ObservationOutcome::Error(
                InitialError::UnsupportedTransition { number: 21 }
            ))
        );

        let mut o = observer();
        assert_eq!(
            o.input_ended(),
            ObservationOutcome::Eof {
                stage: ObserverStage::ClientIdentification,
                pending_bytes: 0
            }
        );
        let mut o = observer();
        o.feed(b"SSH-2.0-x\r\n\x00\x00");
        let _ = drain(&mut o);
        assert_eq!(
            o.input_ended(),
            ObservationOutcome::Eof {
                stage: ObserverStage::InitialPackets,
                pending_bytes: 2
            }
        );
        assert_eq!(o.input_ended().code(), "eof");
    }
}
