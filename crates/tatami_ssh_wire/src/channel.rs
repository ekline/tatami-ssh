//! Channel-opening message codecs (RFC 4254 §5.1): `CHANNEL_OPEN`,
//! `CHANNEL_OPEN_CONFIRMATION` and `CHANNEL_OPEN_FAILURE`.
//!
//! These decoders consume an already delimited payload and never need to
//! understand a channel type to find the end of the message: the
//! type-specific tail of `OPEN` and `OPEN_CONFIRMATION` is simply the
//! remainder of the payload, exposed as a bounded byte slice.
//!
//! A confirmation does not repeat the channel type, so interpreting its
//! tail requires the type recorded for the pending open. That correlation is
//! the connection engine's job, not this module's.
//!
//! Window and maximum-packet fields are decoded and preserved as plain
//! integers. This module assigns them no transport-specific meaning.

use crate::EncodeError;
use crate::error::MessageError;
use crate::message::{expect_message, field, finish};
use crate::msg;
use crate::primitives::{Reader, Writer};

/// Reason codes for `CHANNEL_OPEN_FAILURE` (RFC 4254 §5.1). Unknown codes are
/// preserved as the raw `u32` in [`ChannelOpenFailure::reason_code`].
pub mod open_failure_reason {
    /// `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`.
    pub const ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    /// `SSH_OPEN_CONNECT_FAILED`.
    pub const CONNECT_FAILED: u32 = 2;
    /// `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`.
    pub const UNKNOWN_CHANNEL_TYPE: u32 = 3;
    /// `SSH_OPEN_RESOURCE_SHORTAGE`.
    pub const RESOURCE_SHORTAGE: u32 = 4;

    /// Registered symbolic name for a reason code, if known.
    #[must_use]
    pub const fn name(code: u32) -> Option<&'static str> {
        Some(match code {
            ADMINISTRATIVELY_PROHIBITED => "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED",
            CONNECT_FAILED => "SSH_OPEN_CONNECT_FAILED",
            UNKNOWN_CHANNEL_TYPE => "SSH_OPEN_UNKNOWN_CHANNEL_TYPE",
            RESOURCE_SHORTAGE => "SSH_OPEN_RESOURCE_SHORTAGE",
            _ => return None,
        })
    }
}

/// `SSH_MSG_CHANNEL_OPEN`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelOpen<'a> {
    /// Channel type name, e.g. `session`. Unknown types are preserved.
    pub channel_type: &'a [u8],
    /// The opener's channel number for this channel.
    pub sender_channel: u32,
    /// The opener's initial receive window, in bytes.
    pub initial_window_size: u32,
    /// The opener's maximum packet size, in bytes.
    pub maximum_packet_size: u32,
    /// Type-specific data: everything after the fixed fields, bounded by the
    /// payload. Empty for `session`.
    pub type_specific: &'a [u8],
}

impl<'a> ChannelOpen<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::CHANNEL_OPEN)?;
        let channel_type = field(&mut r, "channel_type", Reader::read_string)?;
        let sender_channel = field(&mut r, "sender_channel", Reader::read_u32)?;
        let initial_window_size = field(&mut r, "initial_window_size", Reader::read_u32)?;
        let maximum_packet_size = field(&mut r, "maximum_packet_size", Reader::read_u32)?;
        let type_specific = r.remaining();
        Ok(ChannelOpen {
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            type_specific,
        })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::CHANNEL_OPEN)?;
        w.write_string(self.channel_type)?;
        w.write_u32(self.sender_channel)?;
        w.write_u32(self.initial_window_size)?;
        w.write_u32(self.maximum_packet_size)?;
        w.write_bytes(self.type_specific)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelOpenConfirmation<'a> {
    /// The opener's channel number, echoed back.
    pub recipient_channel: u32,
    /// The confirmer's channel number for this channel.
    pub sender_channel: u32,
    /// The confirmer's initial receive window, in bytes.
    pub initial_window_size: u32,
    /// The confirmer's maximum packet size, in bytes.
    pub maximum_packet_size: u32,
    /// Type-specific data, bounded by the payload. Its interpretation
    /// depends on the channel type from the corresponding `OPEN`.
    pub type_specific: &'a [u8],
}

impl<'a> ChannelOpenConfirmation<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::CHANNEL_OPEN_CONFIRMATION)?;
        let recipient_channel = field(&mut r, "recipient_channel", Reader::read_u32)?;
        let sender_channel = field(&mut r, "sender_channel", Reader::read_u32)?;
        let initial_window_size = field(&mut r, "initial_window_size", Reader::read_u32)?;
        let maximum_packet_size = field(&mut r, "maximum_packet_size", Reader::read_u32)?;
        let type_specific = r.remaining();
        Ok(ChannelOpenConfirmation {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            type_specific,
        })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::CHANNEL_OPEN_CONFIRMATION)?;
        w.write_u32(self.recipient_channel)?;
        w.write_u32(self.sender_channel)?;
        w.write_u32(self.initial_window_size)?;
        w.write_u32(self.maximum_packet_size)?;
        w.write_bytes(self.type_specific)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_CHANNEL_OPEN_FAILURE`.
///
/// This message has no type-specific tail, so trailing bytes are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelOpenFailure<'a> {
    /// The opener's channel number, echoed back.
    pub recipient_channel: u32,
    /// Reason code; see [`open_failure_reason`]. Unknown codes preserved.
    pub reason_code: u32,
    /// Human-readable description, nominally UTF-8, untrusted.
    pub description: &'a [u8],
    /// RFC 3066 language tag, untrusted.
    pub language_tag: &'a [u8],
}

impl<'a> ChannelOpenFailure<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::CHANNEL_OPEN_FAILURE)?;
        let recipient_channel = field(&mut r, "recipient_channel", Reader::read_u32)?;
        let reason_code = field(&mut r, "reason_code", Reader::read_u32)?;
        let description = field(&mut r, "description", Reader::read_string)?;
        let language_tag = field(&mut r, "language_tag", Reader::read_string)?;
        finish(&r)?;
        Ok(ChannelOpenFailure {
            recipient_channel,
            reason_code,
            description,
            language_tag,
        })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::CHANNEL_OPEN_FAILURE)?;
        w.write_u32(self.recipient_channel)?;
        w.write_u32(self.reason_code)?;
        w.write_string(self.description)?;
        w.write_string(self.language_tag)?;
        Ok(w.position())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodeError;

    #[test]
    fn open_session_fixture() {
        // RFC 4254 §6.1 session open: type "session", sender 0,
        // window 0x200000, max packet 0x8000, no tail.
        let payload = [
            90, 0, 0, 0, 7, b's', b'e', b's', b's', b'i', b'o', b'n', 0, 0, 0, 0, 0, 0x20, 0, 0, 0,
            0, 0x80, 0,
        ];
        let o = ChannelOpen::decode(&payload).unwrap();
        assert_eq!(o.channel_type, b"session");
        assert_eq!(o.sender_channel, 0);
        assert_eq!(o.initial_window_size, 0x0020_0000);
        assert_eq!(o.maximum_packet_size, 0x8000);
        assert!(o.type_specific.is_empty());

        let mut out = [0u8; 32];
        let n = o.encode(&mut out).unwrap();
        assert_eq!(&out[..n], &payload);
    }

    #[test]
    fn open_unknown_type_keeps_bounded_tail() {
        // Unknown type "x@example" with a 5-byte opaque tail.
        let payload = [
            90, 0, 0, 0, 9, b'x', b'@', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 0, 5, 0, 0,
            0, 1, 0, 0, 0, 2, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        ];
        let o = ChannelOpen::decode(&payload).unwrap();
        assert_eq!(o.channel_type, b"x@example");
        assert_eq!(o.sender_channel, 5);
        assert_eq!(o.type_specific, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn open_truncated_in_fixed_fields() {
        let payload = [90, 0, 0, 0, 1, b's', 0, 0, 0, 1, 0, 0];
        match ChannelOpen::decode(&payload) {
            Err(MessageError::Field {
                field: "initial_window_size",
                offset: 10,
                error:
                    DecodeError::Truncated {
                        needed: 4,
                        available: 2,
                    },
            }) => {}
            other => panic!("unexpected: {other:?}"),
        }
        assert_eq!(
            ChannelOpen::decode(&[90, 0, 0, 0, 9, b'a']),
            Err(MessageError::Field {
                field: "channel_type",
                offset: 1,
                error: DecodeError::LengthOverflow {
                    claimed: 9,
                    available: 1
                },
            })
        );
    }

    #[test]
    fn confirmation_fixture_with_tail() {
        let payload = [91, 0, 0, 0, 3, 0, 0, 0, 9, 0, 0, 1, 0, 0, 0, 0, 0x40, 1, 2];
        let c = ChannelOpenConfirmation::decode(&payload).unwrap();
        assert_eq!(c.recipient_channel, 3);
        assert_eq!(c.sender_channel, 9);
        assert_eq!(c.initial_window_size, 0x100);
        assert_eq!(c.maximum_packet_size, 0x40);
        assert_eq!(c.type_specific, &[1, 2]);

        let mut out = [0u8; 32];
        let n = c.encode(&mut out).unwrap();
        assert_eq!(&out[..n], &payload);

        assert_eq!(
            ChannelOpenConfirmation::decode(&payload[..16]),
            Err(MessageError::Field {
                field: "maximum_packet_size",
                offset: 13,
                error: DecodeError::Truncated {
                    needed: 4,
                    available: 3
                },
            })
        );
    }

    #[test]
    fn failure_fixture_unknown_code_and_trailing_rejected() {
        let payload = [
            92, 0, 0, 0, 7, 0, 0, 0, 200, 0, 0, 0, 2, b'n', b'o', 0, 0, 0, 0,
        ];
        let f = ChannelOpenFailure::decode(&payload).unwrap();
        assert_eq!(f.recipient_channel, 7);
        assert_eq!(f.reason_code, 200);
        assert_eq!(open_failure_reason::name(200), None);
        assert_eq!(
            open_failure_reason::name(open_failure_reason::UNKNOWN_CHANNEL_TYPE),
            Some("SSH_OPEN_UNKNOWN_CHANNEL_TYPE")
        );
        assert_eq!(f.description, b"no");
        assert_eq!(f.language_tag, b"");

        let mut out = [0u8; 32];
        let n = f.encode(&mut out).unwrap();
        assert_eq!(&out[..n], &payload);

        let mut extended = [0u8; 20];
        extended[..19].copy_from_slice(&payload);
        assert_eq!(
            ChannelOpenFailure::decode(&extended),
            Err(MessageError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn wrong_message_numbers() {
        assert_eq!(
            ChannelOpenConfirmation::decode(&[90, 0, 0, 0, 0]),
            Err(MessageError::UnexpectedMessage {
                expected: 91,
                found: 90
            })
        );
        assert_eq!(ChannelOpenFailure::decode(&[]), Err(MessageError::Empty));
    }
}
