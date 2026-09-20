//! Initial-offer probe: a portable state machine that observes a server's
//! identification and first `KEXINIT` without negotiating anything.
//!
//! # What the probe does
//!
//! 1. Provides a valid client identification line for the adapter to send
//!    immediately ([`Probe::client_identification`]).
//! 2. Consumes server bytes fed by the adapter, parsing pre-identification
//!    lines and the server identification.
//! 3. Decodes initial unprotected packets until the first `KEXINIT`, a
//!    `DISCONNECT`, a protocol error, or a resource budget is exhausted.
//!
//! It never sends a client `KEXINIT`: Tatami has no implemented algorithm
//! set to advertise, and inventing one would be a false claim on the wire.
//! This is a deliberately incomplete SSH exchange. A server that waits for
//! the client's proposal before sending its own will not produce a `KEXINIT`
//! for this probe; the adapter's deadline then yields a partial observation
//! containing whatever identification was seen.
//!
//! # What the result means
//!
//! A [`ProbeEnd::Proposal`] is the server's **advertised** proposal. Nothing
//! is negotiated, no host key is obtained, and nothing is authenticated.
//!
//! # Message handling before `KEXINIT`
//!
//! Shared with the server observer; see [`crate::initial`].
//!
//! # Buffering bound
//!
//! Input is held in an [`InputBuffer`] whose capacity is the packet cap plus
//! framing plus the identification-phase limits. [`Probe::feed`] rejects
//! (without copying) input that would exceed it and ends the probe with
//! [`ProbeError::InputOverflow`]. Adapters should read at most
//! [`Probe::room`] bytes per read.
//!
//! # Portability
//!
//! This module uses `alloc` only for owned copies of observed data. It has
//! no sockets, clocks or output; deadlines belong to the adapter.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use tatami_wire::kexinit::OwnedKexInit;

pub use crate::ident::OwnedIdentification;
use crate::ident::{
    IdentLimits, IdentStep, IdentificationReader, InvalidLocalIdentification, LineTerminator,
    build_identification,
};
pub use crate::initial::InitialError as ProbeError;
use crate::initial::{InitialLimits, InitialPackets, InitialStep, InputBuffer, SkippedMessage};
use crate::packet::{HEADER_LEN, PacketLimits};

/// Software version token sent in the client identification. Validated by
/// [`Probe::new`] and by a unit test against RFC 4253 §4.2 token rules.
pub const DEFAULT_SOFTWARE_VERSION: &str = "tatami_0.1.0";

/// Configuration for a probe. All numeric limits are local policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeConfig {
    /// `softwareversion` token for the client identification. Must satisfy
    /// [`crate::ident::is_version_token`] and fit the 255-byte line limit.
    pub software_version: String,
    /// Identification phase limits.
    pub ident: IdentLimits,
    /// Initial packet framing limits.
    pub packet: PacketLimits,
    /// Maximum number of packets accepted before `KEXINIT`, counting the
    /// `KEXINIT` itself.
    pub max_packets_before_kexinit: usize,
    /// Maximum total packet bytes (including framing) accepted before and
    /// including `KEXINIT`.
    pub max_bytes_before_kexinit: usize,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        let initial = InitialLimits::default();
        ProbeConfig {
            software_version: String::from(DEFAULT_SOFTWARE_VERSION),
            ident: IdentLimits::default(),
            packet: initial.packet,
            max_packets_before_kexinit: initial.max_packets,
            max_bytes_before_kexinit: initial.max_bytes,
        }
    }
}

impl ProbeConfig {
    fn initial_limits(&self) -> InitialLimits {
        InitialLimits {
            packet: self.packet,
            max_packets: self.max_packets_before_kexinit,
            max_bytes: self.max_bytes_before_kexinit,
        }
    }

    /// Largest amount of unconsumed input the probe will hold.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        let packet = self.packet.max_packet_length as usize + HEADER_LEN;
        let ident = self
            .ident
            .max_prelude_line
            .max(self.ident.max_identification_line);
        packet.max(ident) + ident
    }
}

/// Which phase of the exchange the probe is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Waiting for the server identification (prelude lines may arrive).
    Identification,
    /// Identification received; decoding initial packets.
    InitialPackets,
    /// A terminal outcome has been produced.
    Finished,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Stage::Identification => "awaiting server identification",
            Stage::InitialPackets => "awaiting server KEXINIT",
            Stage::Finished => "finished",
        })
    }
}

/// Non-terminal observations, in order of occurrence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeEvent {
    /// A line before the identification. Untrusted text.
    PreludeLine {
        /// Line content without terminator.
        line: Vec<u8>,
        /// Terminator observed.
        terminator: LineTerminator,
    },
    /// The server identification.
    ServerIdentification(OwnedIdentification),
    /// An `SSH_MSG_IGNORE` was received and skipped.
    Ignored {
        /// Length of its data field.
        data_len: usize,
    },
    /// An `SSH_MSG_DEBUG` was received.
    Debug {
        /// The `always_display` flag.
        always_display: bool,
        /// Raw message bytes. Untrusted.
        message: Vec<u8>,
        /// Raw language tag. Untrusted.
        language_tag: Vec<u8>,
    },
    /// An `SSH_MSG_UNIMPLEMENTED` was received.
    Unimplemented {
        /// Sequence number it refers to.
        sequence_number: u32,
    },
}

impl From<SkippedMessage> for ProbeEvent {
    fn from(m: SkippedMessage) -> Self {
        match m {
            SkippedMessage::Ignored { data_len } => ProbeEvent::Ignored { data_len },
            SkippedMessage::Debug {
                always_display,
                message,
                language_tag,
            } => ProbeEvent::Debug {
                always_display,
                message,
                language_tag,
            },
            SkippedMessage::Unimplemented { sequence_number } => {
                ProbeEvent::Unimplemented { sequence_number }
            }
        }
    }
}

/// Something about a syntactically valid `KEXINIT` that a conforming peer
/// would not send. Reported alongside the proposal rather than hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalAnomaly {
    /// The reserved field was not zero.
    NonzeroReserved(u32),
    /// A required algorithm list was empty.
    EmptyAlgorithmList(&'static str),
}

impl ProposalAnomaly {
    /// Stable, machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            ProposalAnomaly::NonzeroReserved(_) => "kexinit_nonzero_reserved",
            ProposalAnomaly::EmptyAlgorithmList(_) => "kexinit_empty_algorithm_list",
        }
    }
}

impl fmt::Display for ProposalAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProposalAnomaly::NonzeroReserved(v) => write!(f, "reserved field is {v}, expected 0"),
            ProposalAnomaly::EmptyAlgorithmList(name) => {
                write!(f, "required list `{name}` is empty")
            }
        }
    }
}

/// A peer's first `KEXINIT`, as advertised. Nothing here is negotiated or
/// authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// Decoded, owned proposal.
    pub kexinit: OwnedKexInit,
    /// Exact payload bytes (`I_S`/`I_C` form) for a future exchange hash.
    pub raw_payload: Vec<u8>,
    /// Deviations from RFC 4253 found in an otherwise decodable message.
    pub anomalies: Vec<ProposalAnomaly>,
    /// Bytes received after the `KEXINIT` packet that were not examined.
    pub unexamined_bytes: usize,
}

impl Proposal {
    /// Builds a proposal record from a decoded `KEXINIT`, collecting
    /// anomalies.
    #[must_use]
    pub fn from_kexinit(
        kexinit: &tatami_wire::kexinit::KexInit<'_>,
        payload: &[u8],
        unexamined_bytes: usize,
    ) -> Self {
        let mut anomalies = Vec::new();
        if kexinit.reserved != 0 {
            anomalies.push(ProposalAnomaly::NonzeroReserved(kexinit.reserved));
        }
        anomalies.extend(
            kexinit
                .empty_algorithm_lists()
                .map(ProposalAnomaly::EmptyAlgorithmList),
        );
        Proposal {
            kexinit: kexinit.to_owned(),
            raw_payload: payload.to_vec(),
            anomalies,
            unexamined_bytes,
        }
    }
}

/// Terminal outcome of the portable probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeEnd {
    /// The server's first `KEXINIT` was received and decoded.
    Proposal(Box<Proposal>),
    /// The server sent `SSH_MSG_DISCONNECT`.
    Disconnected {
        /// Reason code.
        reason_code: u32,
        /// Raw description. Untrusted.
        description: Vec<u8>,
        /// Raw language tag. Untrusted.
        language_tag: Vec<u8>,
    },
    /// The adapter reported end of input.
    Eof {
        /// Stage at which input ended.
        stage: Stage,
        /// Unconsumed bytes buffered at EOF (a truncated line or packet).
        pending_bytes: usize,
    },
    /// A protocol error or exhausted budget.
    Error(ProbeError),
}

/// Result of [`Probe::step`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// No progress possible without more input.
    NeedMore,
    /// An observation; call [`Probe::step`] again.
    Event(ProbeEvent),
    /// The probe has finished. Further calls return this same value.
    Finished(ProbeEnd),
}

/// Error from [`Probe::new`].
pub type InvalidSoftwareVersion = InvalidLocalIdentification;

/// The portable probe state machine.
#[derive(Debug)]
pub struct Probe {
    client_line: Vec<u8>,
    stage: Stage,
    ident: IdentificationReader,
    packets: InitialPackets,
    buf: InputBuffer,
    end: Option<ProbeEnd>,
}

impl Probe {
    /// Creates a probe, validating the configured software version token
    /// and the resulting identification length.
    pub fn new(config: ProbeConfig) -> Result<Self, InvalidSoftwareVersion> {
        let client_line = build_identification(&config.software_version)?;
        Ok(Probe {
            client_line,
            stage: Stage::Identification,
            ident: IdentificationReader::new(config.ident),
            packets: InitialPackets::new(config.initial_limits()),
            buf: InputBuffer::new(config.buffer_capacity()),
            end: None,
        })
    }

    /// The full client identification line including `CR LF`. The adapter
    /// must send this before reading anything.
    #[must_use]
    pub fn client_identification(&self) -> &[u8] {
        &self.client_line
    }

    /// The client identification without its terminator (`V_C` form).
    #[must_use]
    pub fn client_identification_line(&self) -> &[u8] {
        &self.client_line[..self.client_line.len() - 2]
    }

    /// Current stage.
    #[must_use]
    pub const fn stage(&self) -> Stage {
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

    /// Appends received bytes. Input exceeding [`Probe::room`] is rejected
    /// before copying and ends the probe with [`ProbeError::InputOverflow`].
    /// Ignored once finished.
    pub fn feed(&mut self, data: &[u8]) {
        if self.stage == Stage::Finished {
            return;
        }
        if let Err(e) = self.buf.push(data) {
            self.finish(ProbeEnd::Error(ProbeError::InputOverflow(e)));
        }
    }

    /// Signals end of input. Produces [`ProbeEnd::Eof`] unless already
    /// finished.
    pub fn input_ended(&mut self) -> ProbeEnd {
        if let Some(end) = &self.end {
            return end.clone();
        }
        self.finish(ProbeEnd::Eof {
            stage: self.stage,
            pending_bytes: self.buf.len(),
        })
    }

    /// Advances the state machine by at most one observation.
    pub fn step(&mut self) -> Step {
        if let Some(end) = &self.end {
            return Step::Finished(end.clone());
        }
        match self.stage {
            Stage::Identification => self.step_identification(),
            Stage::InitialPackets => self.step_packet(),
            Stage::Finished => unreachable!("finished without end"),
        }
    }

    fn finish(&mut self, end: ProbeEnd) -> ProbeEnd {
        self.stage = Stage::Finished;
        self.end = Some(end.clone());
        end
    }

    fn step_identification(&mut self) -> Step {
        match self.ident.feed(self.buf.as_slice()) {
            Ok(IdentStep::NeedMore) => Step::NeedMore,
            Ok(IdentStep::Prelude {
                line,
                terminator,
                consumed,
            }) => {
                let event = ProbeEvent::PreludeLine {
                    line: line.to_vec(),
                    terminator,
                };
                self.buf.consume(consumed);
                Step::Event(event)
            }
            Ok(IdentStep::Identification { ident, consumed }) => {
                let owned = OwnedIdentification::from(ident);
                self.buf.consume(consumed);
                self.stage = Stage::InitialPackets;
                Step::Event(ProbeEvent::ServerIdentification(owned))
            }
            Err(e) => Step::Finished(self.finish(ProbeEnd::Error(ProbeError::Ident(e)))),
        }
    }

    fn step_packet(&mut self) -> Step {
        let step = self.packets.step(self.buf.as_slice());
        let (end, consumed): (Option<ProbeEnd>, usize) = match step {
            InitialStep::NeedMore => return Step::NeedMore,
            InitialStep::Skipped { message, consumed } => {
                self.buf.consume(consumed);
                return Step::Event(message.into());
            }
            InitialStep::KexInit {
                kexinit,
                payload,
                consumed,
            } => {
                let proposal = Proposal::from_kexinit(&kexinit, payload, self.buf.len() - consumed);
                (Some(ProbeEnd::Proposal(Box::new(proposal))), consumed)
            }
            InitialStep::Disconnect {
                disconnect,
                consumed,
            } => (
                Some(ProbeEnd::Disconnected {
                    reason_code: disconnect.reason_code,
                    description: disconnect.description.to_vec(),
                    language_tag: disconnect.language_tag.to_vec(),
                }),
                consumed,
            ),
            InitialStep::Error(e) => (Some(ProbeEnd::Error(e)), 0),
        };
        self.buf.consume(consumed);
        match end {
            Some(end) => Step::Finished(self.finish(end)),
            None => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ident::{IdentError, is_version_token};
    use crate::packet::{PacketError, encode_initial_packet};
    use alloc::vec;
    use tatami_wire::{MessageError, Writer};

    fn kexinit_payload() -> Vec<u8> {
        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).unwrap();
        w.write_bytes(&[7; 16]).unwrap();
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
        w.written().to_vec()
    }

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut out = [0u8; 512];
        let n = encode_initial_packet(payload, 0, &mut out).unwrap();
        out[..n].to_vec()
    }

    fn probe() -> Probe {
        Probe::new(ProbeConfig::default()).unwrap()
    }

    fn drain(p: &mut Probe) -> (Vec<ProbeEvent>, Option<ProbeEnd>) {
        let mut events = Vec::new();
        loop {
            match p.step() {
                Step::NeedMore => return (events, None),
                Step::Event(e) => events.push(e),
                Step::Finished(end) => return (events, Some(end)),
            }
        }
    }

    #[test]
    fn default_software_version_is_valid_token() {
        assert!(is_version_token(DEFAULT_SOFTWARE_VERSION.as_bytes()));
        assert_eq!(probe().client_identification(), b"SSH-2.0-tatami_0.1.0\r\n");
        assert_eq!(
            probe().client_identification_line(),
            b"SSH-2.0-tatami_0.1.0"
        );
        // The crate version is embedded so a bump is noticed here.
        assert!(DEFAULT_SOFTWARE_VERSION.ends_with(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn rejects_bad_or_overlong_software_version() {
        let config = ProbeConfig {
            software_version: String::from("0.2.0-alpha"),
            ..ProbeConfig::default()
        };
        assert_eq!(
            Probe::new(config).err(),
            Some(InvalidLocalIdentification::BadSoftwareVersion)
        );
        let config = ProbeConfig {
            software_version: "x".repeat(246),
            ..ProbeConfig::default()
        };
        assert_eq!(
            Probe::new(config).err(),
            Some(InvalidLocalIdentification::TooLong { len: 256 })
        );
    }

    #[test]
    fn full_exchange_in_one_feed() {
        let mut p = probe();
        let mut wire = b"banner\r\nSSH-2.0-Fixture_1 hi\r\n".to_vec();
        wire.extend(packet(&[2, 0, 0, 0, 1, 9])); // IGNORE
        wire.extend(packet(&kexinit_payload()));
        wire.extend(b"leftover");
        p.feed(&wire);
        let (events, end) = drain(&mut p);
        assert_eq!(events.len(), 3);
        assert!(matches!(&events[0], ProbeEvent::PreludeLine { line, .. } if line == b"banner"));
        match &events[1] {
            ProbeEvent::ServerIdentification(i) => {
                assert_eq!(i.software_version, "Fixture_1");
                assert_eq!(i.comments.as_deref(), Some(&b"hi"[..]));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(events[2], ProbeEvent::Ignored { data_len: 1 });
        match end.unwrap() {
            ProbeEnd::Proposal(proposal) => {
                assert_eq!(
                    proposal.kexinit.kex_algorithms,
                    ["curve25519-sha256", "ext-info-s"]
                );
                assert_eq!(
                    proposal.kexinit.encryption_server_to_client,
                    ["aes256-gcm@openssh.com"]
                );
                assert_eq!(proposal.raw_payload, kexinit_payload());
                assert!(proposal.anomalies.is_empty());
                assert_eq!(proposal.unexamined_bytes, 8);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(p.stage(), Stage::Finished);
        assert!(matches!(p.step(), Step::Finished(ProbeEnd::Proposal(_))));
    }

    #[test]
    fn byte_at_a_time_feed() {
        let mut wire = b"SSH-2.0-x\n".to_vec();
        wire.extend(packet(&[4, 1, 0, 0, 0, 2, b'h', b'i', 0, 0, 0, 0])); // DEBUG
        wire.extend(packet(&kexinit_payload()));
        let mut p = probe();
        let mut events = Vec::new();
        let mut end = None;
        for b in wire {
            p.feed(&[b]);
            let (ev, e) = drain(&mut p);
            events.extend(ev);
            if e.is_some() {
                end = e;
                break;
            }
        }
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[1],
            ProbeEvent::Debug { always_display: true, message, .. } if message == b"hi"
        ));
        assert!(matches!(end, Some(ProbeEnd::Proposal(_))));
    }

    #[test]
    fn disconnect_ends_probe() {
        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n");
        p.feed(&packet(&[
            1, 0, 0, 0, 2, 0, 0, 0, 3, b'b', b'y', b'e', 0, 0, 0, 0,
        ]));
        let (_, end) = drain(&mut p);
        assert_eq!(
            end,
            Some(ProbeEnd::Disconnected {
                reason_code: 2,
                description: b"bye".to_vec(),
                language_tag: Vec::new(),
            })
        );
    }

    #[test]
    fn eof_reports_stage_and_pending() {
        let mut p = probe();
        assert_eq!(
            p.input_ended(),
            ProbeEnd::Eof {
                stage: Stage::Identification,
                pending_bytes: 0
            }
        );

        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n\x00\x00\x01");
        let _ = drain(&mut p);
        assert_eq!(
            p.input_ended(),
            ProbeEnd::Eof {
                stage: Stage::InitialPackets,
                pending_bytes: 3
            }
        );
        assert!(matches!(p.step(), Step::Finished(ProbeEnd::Eof { .. })));
    }

    #[test]
    fn unexpected_and_unsupported_messages() {
        for (payload, expected) in [
            (vec![21], ProbeError::UnsupportedTransition { number: 21 }),
            (
                vec![31, 0],
                ProbeError::UnsupportedTransition { number: 31 },
            ),
            (
                vec![6, 0, 0, 0, 0],
                ProbeError::UnexpectedMessage { number: 6 },
            ),
        ] {
            let mut p = probe();
            p.feed(b"SSH-2.0-x\r\n");
            p.feed(&packet(&payload));
            let (_, end) = drain(&mut p);
            assert_eq!(end, Some(ProbeEnd::Error(expected)));
        }
    }

    #[test]
    fn malformed_kexinit_and_empty_payload() {
        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n");
        let mut k = kexinit_payload();
        k.truncate(k.len() - 3);
        p.feed(&packet(&k));
        let (_, end) = drain(&mut p);
        assert!(matches!(
            end,
            Some(ProbeEnd::Error(ProbeError::Message {
                number: 20,
                error: MessageError::Field {
                    field: "reserved",
                    ..
                }
            }))
        ));

        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n");
        p.feed(&[0, 0, 0, 12, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let (_, end) = drain(&mut p);
        assert_eq!(end, Some(ProbeEnd::Error(ProbeError::EmptyPayload)));
    }

    #[test]
    fn anomalies_are_reported_with_proposal() {
        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n");
        let mut k = kexinit_payload();
        let n = k.len();
        k[n - 1] = 1;
        p.feed(&packet(&k));
        let (_, end) = drain(&mut p);
        match end {
            Some(ProbeEnd::Proposal(proposal)) => {
                assert_eq!(proposal.anomalies, [ProposalAnomaly::NonzeroReserved(1)]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn packet_and_byte_budgets() {
        let config = ProbeConfig {
            max_packets_before_kexinit: 2,
            ..ProbeConfig::default()
        };
        let mut p = Probe::new(config).unwrap();
        p.feed(b"SSH-2.0-x\r\n");
        p.feed(&packet(&[2, 0, 0, 0, 0]));
        p.feed(&packet(&[2, 0, 0, 0, 0]));
        p.feed(&packet(&kexinit_payload()));
        let (events, end) = drain(&mut p);
        assert_eq!(events.len(), 3);
        assert_eq!(
            end,
            Some(ProbeEnd::Error(ProbeError::PacketBudgetExceeded {
                limit: 2
            }))
        );

        let config = ProbeConfig {
            max_bytes_before_kexinit: 20,
            ..ProbeConfig::default()
        };
        let mut p = Probe::new(config).unwrap();
        p.feed(b"SSH-2.0-x\r\n");
        p.feed(&packet(&[2, 0, 0, 0, 0]));
        p.feed(&packet(&[2, 0, 0, 0, 0]));
        let (_, end) = drain(&mut p);
        assert_eq!(
            end,
            Some(ProbeEnd::Error(ProbeError::ByteBudgetExceeded {
                limit: 20
            }))
        );
    }

    #[test]
    fn oversized_packet_claim_rejected_before_body() {
        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n\xff\xff\xff\xff");
        let (_, end) = drain(&mut p);
        assert!(matches!(
            end,
            Some(ProbeEnd::Error(ProbeError::Packet(
                PacketError::TooLarge { .. }
            )))
        ));
    }

    #[test]
    fn single_oversized_feed_is_rejected_before_copy() {
        let config = ProbeConfig {
            packet: PacketLimits {
                max_packet_length: 64,
            },
            ident: IdentLimits {
                max_prelude_line: 32,
                max_identification_line: 32,
                ..IdentLimits::default()
            },
            ..ProbeConfig::default()
        };
        let mut p = Probe::new(config).unwrap();
        let cap = p.room();
        assert_eq!(cap, 64 + HEADER_LEN + 32);
        let too_much = vec![b'A'; cap + 1];
        p.feed(&too_much);
        assert_eq!(p.pending_bytes(), 0, "nothing copied");
        assert!(matches!(
            p.step(),
            Step::Finished(ProbeEnd::Error(ProbeError::InputOverflow(_)))
        ));
    }

    #[test]
    fn ssh1_peer_is_unsupported() {
        let mut p = probe();
        p.feed(b"SSH-1.5-old\r\n");
        let (_, end) = drain(&mut p);
        assert_eq!(
            end,
            Some(ProbeEnd::Error(ProbeError::Ident(
                IdentError::UnsupportedVersion
            )))
        );
    }
}
