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
//! | Message | Behaviour |
//! |---|---|
//! | `IGNORE`, `DEBUG`, `UNIMPLEMENTED` | Decoded, reported as an event, skipped. |
//! | `DISCONNECT` | Decoded; ends the probe with [`ProbeEnd::Disconnected`]. |
//! | `KEXINIT` | Decoded; ends the probe with [`ProbeEnd::Proposal`]. |
//! | `NEWKEYS`, method-specific 30–49 | Ends the probe: the initial decoder is not valid past this point. |
//! | anything else | Ends the probe with [`ProbeError::UnexpectedMessage`]. |
//!
//! No bytes are ever skipped without being framed as a packet.
//!
//! # Portability
//!
//! This module uses `alloc` only for owned copies of observed data. It has
//! no sockets, clocks or output; deadlines belong to the adapter.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use tatami_wire::kexinit::{KexInit, OwnedKexInit};
use tatami_wire::transport::{Debug, Disconnect, Ignore, Unimplemented};
use tatami_wire::{MessageError, msg};

use crate::ident::{
    IdentError, IdentLimits, IdentStep, Identification, IdentificationReader, LineTerminator,
    VersionSupport, is_version_token,
};
use crate::packet::{PacketError, PacketLimits, PacketStep, decode_initial_packet};

/// Software version token sent in the client identification. Validated by
/// [`Probe::new`] and by a unit test against RFC 4253 §4.2 token rules.
pub const DEFAULT_SOFTWARE_VERSION: &str = "tatami_0.1.0";

/// Configuration for a probe. All numeric limits are local policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeConfig {
    /// `softwareversion` token for the client identification. Must satisfy
    /// [`is_version_token`].
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
        ProbeConfig {
            software_version: String::from(DEFAULT_SOFTWARE_VERSION),
            ident: IdentLimits::default(),
            packet: PacketLimits::default(),
            max_packets_before_kexinit: 16,
            max_bytes_before_kexinit: 256 * 1024,
        }
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

/// Owned copy of a server [`Identification`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedIdentification {
    /// Exact bytes without the terminator.
    pub line: Vec<u8>,
    /// Terminator observed.
    pub terminator: LineTerminator,
    /// `protoversion` (always printable ASCII).
    pub protocol_version: String,
    /// `softwareversion` (always printable ASCII).
    pub software_version: String,
    /// Raw comment bytes, if present. Untrusted.
    pub comments: Option<Vec<u8>>,
    /// Version classification.
    pub support: VersionSupport,
}

impl From<Identification<'_>> for OwnedIdentification {
    fn from(i: Identification<'_>) -> Self {
        OwnedIdentification {
            line: i.line.to_vec(),
            terminator: i.terminator,
            protocol_version: String::from_utf8_lossy(i.protocol_version).into_owned(),
            software_version: String::from_utf8_lossy(i.software_version).into_owned(),
            comments: i.comments.map(<[u8]>::to_vec),
            support: i.support,
        }
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

/// Something about a syntactically valid `KEXINIT` that a conforming peer
/// would not send. Reported alongside the proposal rather than hidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalAnomaly {
    /// The reserved field was not zero.
    NonzeroReserved(u32),
    /// A required algorithm list was empty.
    EmptyAlgorithmList(&'static str),
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

/// Protocol-level failure that ends the probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// Identification phase failure.
    Ident(IdentError),
    /// Packet framing failure.
    Packet(PacketError),
    /// A packet had an empty payload.
    EmptyPayload,
    /// A recognised message failed to decode.
    Message {
        /// Message number.
        number: u8,
        /// Decoder error.
        error: MessageError,
    },
    /// A message that is not valid before `KEXINIT` in this probe.
    UnexpectedMessage {
        /// Message number.
        number: u8,
    },
    /// `NEWKEYS` or a key-exchange-method-specific message arrived before
    /// `KEXINIT`; the initial decoder cannot continue past this point.
    UnsupportedTransition {
        /// Message number.
        number: u8,
    },
    /// More than [`ProbeConfig::max_packets_before_kexinit`] packets.
    PacketBudgetExceeded {
        /// The configured limit.
        limit: usize,
    },
    /// More than [`ProbeConfig::max_bytes_before_kexinit`] bytes.
    ByteBudgetExceeded {
        /// The configured limit.
        limit: usize,
    },
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProbeError::Ident(e) => write!(f, "identification: {e}"),
            ProbeError::Packet(e) => write!(f, "packet framing: {e}"),
            ProbeError::EmptyPayload => f.write_str("packet with empty payload"),
            ProbeError::Message { number, error } => {
                write!(f, "malformed {}: {error}", describe_msg(*number))
            }
            ProbeError::UnexpectedMessage { number } => {
                write!(f, "unexpected {} before KEXINIT", describe_msg(*number))
            }
            ProbeError::UnsupportedTransition { number } => write!(
                f,
                "{} before KEXINIT; initial packet decoding cannot continue",
                describe_msg(*number)
            ),
            ProbeError::PacketBudgetExceeded { limit } => {
                write!(f, "more than {limit} packets before KEXINIT")
            }
            ProbeError::ByteBudgetExceeded { limit } => {
                write!(f, "more than {limit} bytes before KEXINIT")
            }
        }
    }
}

impl core::error::Error for ProbeError {}

fn describe_msg(number: u8) -> MsgName {
    MsgName(number)
}

struct MsgName(u8);

impl fmt::Display for MsgName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match msg::name(self.0) {
            Some(n) => write!(f, "{n} ({})", self.0),
            None => write!(f, "message number {}", self.0),
        }
    }
}

/// The server's first `KEXINIT`, as advertised. Nothing here is negotiated
/// or authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    /// Decoded, owned proposal.
    pub kexinit: OwnedKexInit,
    /// Exact payload bytes (`I_S` form) for a future exchange hash.
    pub raw_payload: Vec<u8>,
    /// Deviations from RFC 4253 found in an otherwise decodable message.
    pub anomalies: Vec<ProposalAnomaly>,
    /// Bytes received after the `KEXINIT` packet that were not examined.
    pub unexamined_bytes: usize,
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSoftwareVersion;

impl fmt::Display for InvalidSoftwareVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("software version must be printable ASCII without whitespace or '-'")
    }
}

impl core::error::Error for InvalidSoftwareVersion {}

/// The portable probe state machine.
#[derive(Debug)]
pub struct Probe {
    config: ProbeConfig,
    client_line: Vec<u8>,
    stage: Stage,
    ident: IdentificationReader,
    buf: Vec<u8>,
    packets: usize,
    bytes: usize,
    end: Option<ProbeEnd>,
}

impl Probe {
    /// Creates a probe, validating the configured software version token.
    pub fn new(config: ProbeConfig) -> Result<Self, InvalidSoftwareVersion> {
        if !is_version_token(config.software_version.as_bytes()) {
            return Err(InvalidSoftwareVersion);
        }
        let mut client_line = Vec::with_capacity(16 + config.software_version.len());
        client_line.extend_from_slice(b"SSH-2.0-");
        client_line.extend_from_slice(config.software_version.as_bytes());
        client_line.extend_from_slice(b"\r\n");
        Ok(Probe {
            ident: IdentificationReader::new(config.ident),
            client_line,
            stage: Stage::Identification,
            buf: Vec::new(),
            packets: 0,
            bytes: 0,
            end: None,
            config,
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

    /// Appends received bytes. Ignored once finished. Callers must drain
    /// [`Probe::step`] after each feed; unconsumed input is bounded only by
    /// the caller doing so.
    pub fn feed(&mut self, data: &[u8]) {
        if self.stage != Stage::Finished {
            self.buf.extend_from_slice(data);
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

    fn fail(&mut self, error: ProbeError) -> Step {
        Step::Finished(self.finish(ProbeEnd::Error(error)))
    }

    fn step_identification(&mut self) -> Step {
        let result = self.ident.feed(&self.buf);
        match result {
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
                self.buf.drain(..consumed);
                Step::Event(event)
            }
            Ok(IdentStep::Identification { ident, consumed }) => {
                let owned = OwnedIdentification::from(ident);
                self.buf.drain(..consumed);
                self.stage = Stage::InitialPackets;
                Step::Event(ProbeEvent::ServerIdentification(owned))
            }
            Err(e) => self.fail(ProbeError::Ident(e)),
        }
    }

    fn step_packet(&mut self) -> Step {
        let packet = match decode_initial_packet(&self.buf, &self.config.packet) {
            Ok(PacketStep::NeedMore { .. }) => return Step::NeedMore,
            Ok(PacketStep::Complete(p)) => p,
            Err(e) => return self.fail(ProbeError::Packet(e)),
        };
        let total_len = packet.total_len;

        // Budgets: count this packet before interpreting it.
        if self.packets >= self.config.max_packets_before_kexinit {
            let limit = self.config.max_packets_before_kexinit;
            return self.fail(ProbeError::PacketBudgetExceeded { limit });
        }
        let bytes = self.bytes.saturating_add(total_len);
        if bytes > self.config.max_bytes_before_kexinit {
            let limit = self.config.max_bytes_before_kexinit;
            return self.fail(ProbeError::ByteBudgetExceeded { limit });
        }
        self.packets += 1;
        self.bytes = bytes;

        let Some(&number) = packet.payload.first() else {
            return self.fail(ProbeError::EmptyPayload);
        };
        let payload = packet.payload;

        let outcome: Result<Option<ProbeEvent>, ProbeError> = match number {
            msg::IGNORE => Ignore::decode(payload)
                .map(|i| {
                    Some(ProbeEvent::Ignored {
                        data_len: i.data.len(),
                    })
                })
                .map_err(|error| ProbeError::Message { number, error }),
            msg::DEBUG => Debug::decode(payload)
                .map(|d| {
                    Some(ProbeEvent::Debug {
                        always_display: d.always_display,
                        message: d.message.to_vec(),
                        language_tag: d.language_tag.to_vec(),
                    })
                })
                .map_err(|error| ProbeError::Message { number, error }),
            msg::UNIMPLEMENTED => Unimplemented::decode(payload)
                .map(|u| {
                    Some(ProbeEvent::Unimplemented {
                        sequence_number: u.sequence_number,
                    })
                })
                .map_err(|error| ProbeError::Message { number, error }),
            msg::DISCONNECT => match Disconnect::decode(payload) {
                Ok(d) => {
                    let end = ProbeEnd::Disconnected {
                        reason_code: d.reason_code,
                        description: d.description.to_vec(),
                        language_tag: d.language_tag.to_vec(),
                    };
                    self.buf.drain(..total_len);
                    return Step::Finished(self.finish(end));
                }
                Err(error) => Err(ProbeError::Message { number, error }),
            },
            msg::KEXINIT => match KexInit::decode(payload) {
                Ok(k) => {
                    let mut anomalies = Vec::new();
                    if k.reserved != 0 {
                        anomalies.push(ProposalAnomaly::NonzeroReserved(k.reserved));
                    }
                    anomalies.extend(
                        k.empty_algorithm_lists()
                            .map(ProposalAnomaly::EmptyAlgorithmList),
                    );
                    let end = ProbeEnd::Proposal(Box::new(Proposal {
                        kexinit: k.to_owned(),
                        raw_payload: payload.to_vec(),
                        anomalies,
                        unexamined_bytes: self.buf.len() - total_len,
                    }));
                    self.buf.drain(..total_len);
                    return Step::Finished(self.finish(end));
                }
                Err(error) => Err(ProbeError::Message { number, error }),
            },
            msg::NEWKEYS => Err(ProbeError::UnsupportedTransition { number }),
            n if msg::is_kex_method_specific(n) => {
                Err(ProbeError::UnsupportedTransition { number })
            }
            _ => Err(ProbeError::UnexpectedMessage { number }),
        };

        match outcome {
            Ok(Some(event)) => {
                self.buf.drain(..total_len);
                Step::Event(event)
            }
            Ok(None) => unreachable!("every continuing message yields an event"),
            Err(e) => self.fail(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::encode_initial_packet;
    use tatami_wire::Writer;

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
    fn rejects_bad_software_version() {
        let config = ProbeConfig {
            software_version: String::from("0.2.0-alpha"),
            ..ProbeConfig::default()
        };
        assert!(Probe::new(config).is_err());
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
        // Stable after finish.
        assert!(matches!(p.step(), Step::Finished(ProbeEnd::Eof { .. })));
    }

    #[test]
    fn unexpected_and_unsupported_messages() {
        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n");
        p.feed(&packet(&[21])); // NEWKEYS
        let (_, end) = drain(&mut p);
        assert_eq!(
            end,
            Some(ProbeEnd::Error(ProbeError::UnsupportedTransition {
                number: 21
            }))
        );

        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n");
        p.feed(&packet(&[31, 0])); // KEX method-specific
        let (_, end) = drain(&mut p);
        assert_eq!(
            end,
            Some(ProbeEnd::Error(ProbeError::UnsupportedTransition {
                number: 31
            }))
        );

        let mut p = probe();
        p.feed(b"SSH-2.0-x\r\n");
        p.feed(&packet(&[6, 0, 0, 0, 0])); // SERVICE_ACCEPT
        let (_, end) = drain(&mut p);
        assert_eq!(
            end,
            Some(ProbeEnd::Error(ProbeError::UnexpectedMessage { number: 6 }))
        );
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

        // packet_length 12, padding 11 -> empty payload.
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
        k[n - 1] = 1; // reserved = 1
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
        p.feed(&packet(&[2, 0, 0, 0, 0])); // 16 bytes
        p.feed(&packet(&[2, 0, 0, 0, 0])); // 32 > 20
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
