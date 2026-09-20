//! Role-independent pieces of the pre-`NEWKEYS` phase shared by the client
//! probe and the server observer.
//!
//! - [`InputBuffer`]: a byte buffer with a hard capacity that rejects excess
//!   input *before* copying it, so no caller can grow it without bound.
//! - [`InitialPackets`]: decodes initial packets from a buffer, applies the
//!   packet/byte budgets, and classifies messages the same way for both
//!   roles: `IGNORE`/`DEBUG`/`UNIMPLEMENTED` are reported and skipped,
//!   `DISCONNECT` and `KEXINIT` end the phase, `NEWKEYS` and method-specific
//!   messages end it as unsupported, anything else is unexpected.
//! - [`InitialError`]: the protocol-level failures of that phase.
//!
//! Nothing here sends anything or knows which side it is on.

use alloc::vec::Vec;
use core::fmt;

use tatami_wire::kexinit::KexInit;
use tatami_wire::transport::{Debug, Disconnect, Ignore, Unimplemented};
use tatami_wire::{MessageError, msg};

use crate::ident::IdentError;
use crate::packet::{PacketError, PacketLimits, PacketStep, decode_initial_packet};

/// Byte buffer with an enforced capacity.
///
/// [`InputBuffer::push`] fails without copying when the data would exceed
/// the capacity. Callers read at most [`InputBuffer::room`] bytes at a time.
#[derive(Clone, Debug)]
pub struct InputBuffer {
    buf: Vec<u8>,
    capacity: usize,
}

/// Returned by [`InputBuffer::push`] when input would exceed capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputOverflow {
    /// Configured capacity.
    pub capacity: usize,
    /// Bytes already buffered.
    pub pending: usize,
    /// Bytes offered.
    pub offered: usize,
}

impl fmt::Display for InputOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "input of {} bytes exceeds buffer capacity {} ({} pending)",
            self.offered, self.capacity, self.pending
        )
    }
}

impl core::error::Error for InputOverflow {}

impl InputBuffer {
    /// Creates an empty buffer that will never hold more than `capacity`.
    #[must_use]
    pub const fn new(capacity: usize) -> Self {
        InputBuffer {
            buf: Vec::new(),
            capacity,
        }
    }

    /// Bytes that may still be pushed.
    #[must_use]
    pub fn room(&self) -> usize {
        self.capacity - self.buf.len()
    }

    /// Bytes currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// `true` when nothing is buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Buffered bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Appends `data`, or fails before copying if it would not fit.
    pub fn push(&mut self, data: &[u8]) -> Result<(), InputOverflow> {
        if data.len() > self.room() {
            return Err(InputOverflow {
                capacity: self.capacity,
                pending: self.buf.len(),
                offered: data.len(),
            });
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Removes the first `n` bytes.
    pub fn consume(&mut self, n: usize) {
        self.buf.drain(..n);
    }

    /// Discards everything.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

/// Budgets for the initial packet phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialLimits {
    /// Framing limits (packet-length cap).
    pub packet: PacketLimits,
    /// Maximum packets accepted through and including `KEXINIT`.
    pub max_packets: usize,
    /// Maximum total framed bytes accepted through and including `KEXINIT`.
    pub max_bytes: usize,
}

impl Default for InitialLimits {
    fn default() -> Self {
        InitialLimits {
            packet: PacketLimits::default(),
            max_packets: 16,
            max_bytes: 256 * 1024,
        }
    }
}

/// Protocol-level failure of the identification or initial packet phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitialError {
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
    /// A message that is not valid before `KEXINIT` in this phase.
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
    /// More than [`InitialLimits::max_packets`] packets.
    PacketBudgetExceeded {
        /// The configured limit.
        limit: usize,
    },
    /// More than [`InitialLimits::max_bytes`] bytes.
    ByteBudgetExceeded {
        /// The configured limit.
        limit: usize,
    },
    /// The caller offered more input than the buffer bound allows.
    InputOverflow(InputOverflow),
}

impl InitialError {
    /// Stable, machine-readable reason code for reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            InitialError::Ident(IdentError::PreludeLineTooLong) => "ident_prelude_line_too_long",
            InitialError::Ident(IdentError::TooManyPreludeLines) => "ident_too_many_prelude_lines",
            InitialError::Ident(IdentError::PreludeBytesExceeded) => "ident_prelude_too_large",
            InitialError::Ident(IdentError::IdentificationTooLong) => "ident_too_long",
            InitialError::Ident(IdentError::InvalidIdentification(_)) => "ident_invalid",
            InitialError::Ident(IdentError::UnsupportedVersion) => "ident_unsupported_version",
            InitialError::Packet(_) => "packet_framing",
            InitialError::EmptyPayload => "packet_empty_payload",
            InitialError::Message { .. } => "message_malformed",
            InitialError::UnexpectedMessage { .. } => "message_unexpected",
            InitialError::UnsupportedTransition { .. } => "unsupported_transition",
            InitialError::PacketBudgetExceeded { .. } => "packet_budget_exceeded",
            InitialError::ByteBudgetExceeded { .. } => "byte_budget_exceeded",
            InitialError::InputOverflow(_) => "input_overflow",
        }
    }
}

impl fmt::Display for InitialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitialError::Ident(e) => write!(f, "identification: {e}"),
            InitialError::Packet(e) => write!(f, "packet framing: {e}"),
            InitialError::EmptyPayload => f.write_str("packet with empty payload"),
            InitialError::Message { number, error } => {
                write!(f, "malformed {}: {error}", MsgName(*number))
            }
            InitialError::UnexpectedMessage { number } => {
                write!(f, "unexpected {} before KEXINIT", MsgName(*number))
            }
            InitialError::UnsupportedTransition { number } => write!(
                f,
                "{} before KEXINIT; initial packet decoding cannot continue",
                MsgName(*number)
            ),
            InitialError::PacketBudgetExceeded { limit } => {
                write!(f, "more than {limit} packets before KEXINIT")
            }
            InitialError::ByteBudgetExceeded { limit } => {
                write!(f, "more than {limit} bytes before KEXINIT")
            }
            InitialError::InputOverflow(e) => write!(f, "{e}"),
        }
    }
}

impl core::error::Error for InitialError {}

/// Message number with its registered name, for diagnostics.
pub(crate) struct MsgName(pub u8);

impl fmt::Display for MsgName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match msg::name(self.0) {
            Some(n) => write!(f, "{n} ({})", self.0),
            None => write!(f, "message number {}", self.0),
        }
    }
}

/// A pre-`KEXINIT` message that is reported and skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SkippedMessage {
    /// `SSH_MSG_IGNORE`.
    Ignored {
        /// Length of its data field.
        data_len: usize,
    },
    /// `SSH_MSG_DEBUG`.
    Debug {
        /// The `always_display` flag.
        always_display: bool,
        /// Raw message bytes. Untrusted.
        message: Vec<u8>,
        /// Raw language tag. Untrusted.
        language_tag: Vec<u8>,
    },
    /// `SSH_MSG_UNIMPLEMENTED`.
    Unimplemented {
        /// Sequence number it refers to.
        sequence_number: u32,
    },
}

/// Result of [`InitialPackets::step`]. Borrowed variants reference the
/// caller's buffer; the caller converts them to owned data and then consumes
/// `consumed` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitialStep<'a> {
    /// No complete packet buffered.
    NeedMore,
    /// A message that was reported and should be skipped.
    Skipped {
        /// The message.
        message: SkippedMessage,
        /// Bytes to consume.
        consumed: usize,
    },
    /// The first `KEXINIT`.
    KexInit {
        /// Decoded message, borrowing `payload`.
        kexinit: KexInit<'a>,
        /// Exact payload bytes.
        payload: &'a [u8],
        /// Bytes to consume.
        consumed: usize,
    },
    /// `SSH_MSG_DISCONNECT`.
    Disconnect {
        /// Decoded message.
        disconnect: Disconnect<'a>,
        /// Bytes to consume.
        consumed: usize,
    },
    /// Terminal protocol error. Nothing should be consumed.
    Error(InitialError),
}

/// Initial-packet decoder with budgets.
#[derive(Clone, Debug)]
pub struct InitialPackets {
    limits: InitialLimits,
    packets: usize,
    bytes: usize,
}

impl InitialPackets {
    /// Creates a decoder with the given budgets.
    #[must_use]
    pub const fn new(limits: InitialLimits) -> Self {
        InitialPackets {
            limits,
            packets: 0,
            bytes: 0,
        }
    }

    /// Packets accepted so far.
    #[must_use]
    pub const fn packets(&self) -> usize {
        self.packets
    }

    /// Framed bytes accepted so far.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Examines the front of `buf` for one complete packet.
    pub fn step<'a>(&mut self, buf: &'a [u8]) -> InitialStep<'a> {
        let packet = match decode_initial_packet(buf, &self.limits.packet) {
            Ok(PacketStep::NeedMore { .. }) => return InitialStep::NeedMore,
            Ok(PacketStep::Complete(p)) => p,
            Err(e) => return InitialStep::Error(InitialError::Packet(e)),
        };
        let consumed = packet.total_len;

        if self.packets >= self.limits.max_packets {
            return InitialStep::Error(InitialError::PacketBudgetExceeded {
                limit: self.limits.max_packets,
            });
        }
        let bytes = self.bytes.saturating_add(consumed);
        if bytes > self.limits.max_bytes {
            return InitialStep::Error(InitialError::ByteBudgetExceeded {
                limit: self.limits.max_bytes,
            });
        }
        self.packets += 1;
        self.bytes = bytes;

        let payload = packet.payload;
        let Some(&number) = payload.first() else {
            return InitialStep::Error(InitialError::EmptyPayload);
        };
        let malformed = |error| InitialError::Message { number, error };

        match number {
            msg::IGNORE => match Ignore::decode(payload) {
                Ok(i) => InitialStep::Skipped {
                    message: SkippedMessage::Ignored {
                        data_len: i.data.len(),
                    },
                    consumed,
                },
                Err(e) => InitialStep::Error(malformed(e)),
            },
            msg::DEBUG => match Debug::decode(payload) {
                Ok(d) => InitialStep::Skipped {
                    message: SkippedMessage::Debug {
                        always_display: d.always_display,
                        message: d.message.to_vec(),
                        language_tag: d.language_tag.to_vec(),
                    },
                    consumed,
                },
                Err(e) => InitialStep::Error(malformed(e)),
            },
            msg::UNIMPLEMENTED => match Unimplemented::decode(payload) {
                Ok(u) => InitialStep::Skipped {
                    message: SkippedMessage::Unimplemented {
                        sequence_number: u.sequence_number,
                    },
                    consumed,
                },
                Err(e) => InitialStep::Error(malformed(e)),
            },
            msg::DISCONNECT => match Disconnect::decode(payload) {
                Ok(disconnect) => InitialStep::Disconnect {
                    disconnect,
                    consumed,
                },
                Err(e) => InitialStep::Error(malformed(e)),
            },
            msg::KEXINIT => match KexInit::decode(payload) {
                Ok(kexinit) => InitialStep::KexInit {
                    kexinit,
                    payload,
                    consumed,
                },
                Err(e) => InitialStep::Error(malformed(e)),
            },
            msg::NEWKEYS => InitialStep::Error(InitialError::UnsupportedTransition { number }),
            n if msg::is_kex_method_specific(n) => {
                InitialStep::Error(InitialError::UnsupportedTransition { number })
            }
            _ => InitialStep::Error(InitialError::UnexpectedMessage { number }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_buffer_rejects_before_copying() {
        let mut b = InputBuffer::new(4);
        assert_eq!(b.room(), 4);
        b.push(&[1, 2, 3]).unwrap();
        assert_eq!(b.room(), 1);
        assert_eq!(
            b.push(&[4, 5]),
            Err(InputOverflow {
                capacity: 4,
                pending: 3,
                offered: 2
            })
        );
        assert_eq!(b.as_slice(), &[1, 2, 3], "nothing copied on overflow");
        b.push(&[4]).unwrap();
        assert_eq!(b.room(), 0);
        b.consume(2);
        assert_eq!(b.as_slice(), &[3, 4]);
        assert_eq!(b.room(), 2);
        b.clear();
        assert!(b.is_empty());
    }

    #[test]
    fn budgets_are_enforced_before_interpretation() {
        let limits = InitialLimits {
            max_packets: 1,
            ..InitialLimits::default()
        };
        let mut p = InitialPackets::new(limits);
        // packet_length 12, padding 6, payload IGNORE with empty data.
        let ig = [0, 0, 0, 12, 6, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(
            p.step(&ig),
            InitialStep::Skipped { consumed: 16, .. }
        ));
        assert_eq!(
            p.step(&ig),
            InitialStep::Error(InitialError::PacketBudgetExceeded { limit: 1 })
        );
        assert_eq!(p.packets(), 1);
        assert_eq!(p.bytes(), 16);
    }

    #[test]
    fn error_codes_are_stable_strings() {
        assert_eq!(InitialError::EmptyPayload.code(), "packet_empty_payload");
        assert_eq!(
            InitialError::Ident(IdentError::UnsupportedVersion).code(),
            "ident_unsupported_version"
        );
    }
}
