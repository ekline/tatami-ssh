//! Transport-layer generic messages (RFC 4253 §11): `DISCONNECT`, `IGNORE`,
//! `UNIMPLEMENTED` and `DEBUG`; and service negotiation (RFC 4253 §10):
//! `SERVICE_REQUEST` and `SERVICE_ACCEPT`.
//!
//! These are payload codecs only; they say nothing about the packet envelope
//! that carries them. All string fields are returned as raw bytes. RFC 4253
//! says descriptions and debug messages are ISO-10646 UTF-8, but a peer may
//! not comply, so display code must escape them rather than trust them.
//! Service names are typed `string` by the RFC even though the registered
//! values (`ssh-userauth`, `ssh-connection`) look like names; they are kept
//! as raw bytes and not restricted here.

use crate::EncodeError;
use crate::error::MessageError;
use crate::message::{expect_message, field, finish};
use crate::msg;
use crate::primitives::{Reader, Writer};

/// Reason codes for `SSH_MSG_DISCONNECT` (RFC 4253 §11.1). Unknown codes are
/// preserved as the raw `u32` in [`Disconnect::reason_code`].
pub mod disconnect_reason {
    /// `SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT`.
    pub const HOST_NOT_ALLOWED_TO_CONNECT: u32 = 1;
    /// `SSH_DISCONNECT_PROTOCOL_ERROR`.
    pub const PROTOCOL_ERROR: u32 = 2;
    /// `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`.
    pub const KEY_EXCHANGE_FAILED: u32 = 3;
    /// `SSH_DISCONNECT_RESERVED`.
    pub const RESERVED: u32 = 4;
    /// `SSH_DISCONNECT_MAC_ERROR`.
    pub const MAC_ERROR: u32 = 5;
    /// `SSH_DISCONNECT_COMPRESSION_ERROR`.
    pub const COMPRESSION_ERROR: u32 = 6;
    /// `SSH_DISCONNECT_SERVICE_NOT_AVAILABLE`.
    pub const SERVICE_NOT_AVAILABLE: u32 = 7;
    /// `SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED`.
    pub const PROTOCOL_VERSION_NOT_SUPPORTED: u32 = 8;
    /// `SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE`.
    pub const HOST_KEY_NOT_VERIFIABLE: u32 = 9;
    /// `SSH_DISCONNECT_CONNECTION_LOST`.
    pub const CONNECTION_LOST: u32 = 10;
    /// `SSH_DISCONNECT_BY_APPLICATION`.
    pub const BY_APPLICATION: u32 = 11;
    /// `SSH_DISCONNECT_TOO_MANY_CONNECTIONS`.
    pub const TOO_MANY_CONNECTIONS: u32 = 12;
    /// `SSH_DISCONNECT_AUTH_CANCELLED_BY_USER`.
    pub const AUTH_CANCELLED_BY_USER: u32 = 13;
    /// `SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE`.
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
    /// `SSH_DISCONNECT_ILLEGAL_USER_NAME`.
    pub const ILLEGAL_USER_NAME: u32 = 15;

    /// Registered symbolic name for a reason code, if known.
    #[must_use]
    pub const fn name(code: u32) -> Option<&'static str> {
        Some(match code {
            HOST_NOT_ALLOWED_TO_CONNECT => "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT",
            PROTOCOL_ERROR => "SSH_DISCONNECT_PROTOCOL_ERROR",
            KEY_EXCHANGE_FAILED => "SSH_DISCONNECT_KEY_EXCHANGE_FAILED",
            RESERVED => "SSH_DISCONNECT_RESERVED",
            MAC_ERROR => "SSH_DISCONNECT_MAC_ERROR",
            COMPRESSION_ERROR => "SSH_DISCONNECT_COMPRESSION_ERROR",
            SERVICE_NOT_AVAILABLE => "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE",
            PROTOCOL_VERSION_NOT_SUPPORTED => "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED",
            HOST_KEY_NOT_VERIFIABLE => "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE",
            CONNECTION_LOST => "SSH_DISCONNECT_CONNECTION_LOST",
            BY_APPLICATION => "SSH_DISCONNECT_BY_APPLICATION",
            TOO_MANY_CONNECTIONS => "SSH_DISCONNECT_TOO_MANY_CONNECTIONS",
            AUTH_CANCELLED_BY_USER => "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER",
            NO_MORE_AUTH_METHODS_AVAILABLE => "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE",
            ILLEGAL_USER_NAME => "SSH_DISCONNECT_ILLEGAL_USER_NAME",
            _ => return None,
        })
    }
}

/// `SSH_MSG_DISCONNECT` (RFC 4253 §11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Disconnect<'a> {
    /// Reason code; see [`disconnect_reason`].
    pub reason_code: u32,
    /// Human-readable description, nominally UTF-8, untrusted.
    pub description: &'a [u8],
    /// RFC 3066 language tag, untrusted.
    pub language_tag: &'a [u8],
}

impl<'a> Disconnect<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::DISCONNECT)?;
        let reason_code = field(&mut r, "reason_code", Reader::read_u32)?;
        let description = field(&mut r, "description", Reader::read_string)?;
        let language_tag = field(&mut r, "language_tag", Reader::read_string)?;
        finish(&r)?;
        Ok(Disconnect {
            reason_code,
            description,
            language_tag,
        })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::DISCONNECT)?;
        w.write_u32(self.reason_code)?;
        w.write_string(self.description)?;
        w.write_string(self.language_tag)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_IGNORE` (RFC 4253 §11.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ignore<'a> {
    /// Arbitrary data that receivers must ignore.
    pub data: &'a [u8],
}

impl<'a> Ignore<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::IGNORE)?;
        let data = field(&mut r, "data", Reader::read_string)?;
        finish(&r)?;
        Ok(Ignore { data })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::IGNORE)?;
        w.write_string(self.data)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_UNIMPLEMENTED` (RFC 4253 §11.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unimplemented {
    /// Packet sequence number of the rejected message.
    pub sequence_number: u32,
}

impl Unimplemented {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &[u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::UNIMPLEMENTED)?;
        let sequence_number = field(&mut r, "sequence_number", Reader::read_u32)?;
        finish(&r)?;
        Ok(Unimplemented { sequence_number })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::UNIMPLEMENTED)?;
        w.write_u32(self.sequence_number)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_DEBUG` (RFC 4253 §11.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Debug<'a> {
    /// Whether the sender asks for the message to be shown to the user.
    pub always_display: bool,
    /// Debug text, nominally UTF-8, untrusted.
    pub message: &'a [u8],
    /// RFC 3066 language tag, untrusted.
    pub language_tag: &'a [u8],
}

impl<'a> Debug<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::DEBUG)?;
        let always_display = field(&mut r, "always_display", Reader::read_bool)?;
        let message = field(&mut r, "message", Reader::read_string)?;
        let language_tag = field(&mut r, "language_tag", Reader::read_string)?;
        finish(&r)?;
        Ok(Debug {
            always_display,
            message,
            language_tag,
        })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::DEBUG)?;
        w.write_bool(self.always_display)?;
        w.write_string(self.message)?;
        w.write_string(self.language_tag)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_SERVICE_REQUEST` (RFC 4253 §10).
///
/// ```text
/// byte      SSH_MSG_SERVICE_REQUEST
/// string    service name
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceRequest<'a> {
    /// Requested service, e.g. `ssh-userauth`. Unknown names are preserved.
    pub service_name: &'a [u8],
}

impl<'a> ServiceRequest<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::SERVICE_REQUEST)?;
        let service_name = field(&mut r, "service_name", Reader::read_string)?;
        finish(&r)?;
        Ok(ServiceRequest { service_name })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::SERVICE_REQUEST)?;
        w.write_string(self.service_name)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_SERVICE_ACCEPT` (RFC 4253 §10).
///
/// ```text
/// byte      SSH_MSG_SERVICE_ACCEPT
/// string    service name
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceAccept<'a> {
    /// Accepted service; the requester checks it echoes the request.
    pub service_name: &'a [u8],
}

impl<'a> ServiceAccept<'a> {
    /// Decodes a complete payload starting at the message number.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::SERVICE_ACCEPT)?;
        let service_name = field(&mut r, "service_name", Reader::read_string)?;
        finish(&r)?;
        Ok(ServiceAccept { service_name })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::SERVICE_ACCEPT)?;
        w.write_string(self.service_name)?;
        Ok(w.position())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodeError;

    #[test]
    fn disconnect_fixture() {
        // code 2, "bye", "" -- hand-assembled.
        let payload = [1, 0, 0, 0, 2, 0, 0, 0, 3, b'b', b'y', b'e', 0, 0, 0, 0];
        let d = Disconnect::decode(&payload).unwrap();
        assert_eq!(d.reason_code, disconnect_reason::PROTOCOL_ERROR);
        assert_eq!(d.description, b"bye");
        assert_eq!(d.language_tag, b"");
        assert_eq!(
            disconnect_reason::name(d.reason_code),
            Some("SSH_DISCONNECT_PROTOCOL_ERROR")
        );
        assert_eq!(disconnect_reason::name(999), None);

        let mut out = [0u8; 16];
        assert_eq!(d.encode(&mut out).unwrap(), 16);
        assert_eq!(out, payload);
    }

    #[test]
    fn disconnect_truncated_description_names_field() {
        let payload = [1, 0, 0, 0, 2, 0, 0, 0, 9, b'b'];
        match Disconnect::decode(&payload) {
            Err(MessageError::Field {
                field: "description",
                offset: 5,
                error:
                    DecodeError::LengthOverflow {
                        claimed: 9,
                        available: 1,
                    },
            }) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ignore_and_unimplemented_and_debug() {
        let ignore = [2, 0, 0, 0, 2, 0xde, 0xad];
        assert_eq!(Ignore::decode(&ignore).unwrap().data, &[0xde, 0xad]);
        assert_eq!(
            Ignore::decode(&[2, 0, 0, 0, 2, 0xde, 0xad, 0]),
            Err(MessageError::TrailingBytes { count: 1 })
        );

        let unimpl = [3, 0, 0, 0, 42];
        assert_eq!(Unimplemented::decode(&unimpl).unwrap().sequence_number, 42);

        let debug = [4, 0x05, 0, 0, 0, 1, b'x', 0, 0, 0, 2, b'e', b'n'];
        let d = Debug::decode(&debug).unwrap();
        assert!(d.always_display, "nonzero boolean is true");
        assert_eq!(d.message, b"x");
        assert_eq!(d.language_tag, b"en");

        let mut out = [0u8; 16];
        let n = d.encode(&mut out).unwrap();
        assert_eq!(out[1], 1, "booleans encode canonically");
        assert_eq!(n, debug.len());
    }

    #[test]
    fn wrong_message_numbers() {
        assert_eq!(
            Ignore::decode(&[4, 0, 0, 0, 0]),
            Err(MessageError::UnexpectedMessage {
                expected: 2,
                found: 4
            })
        );
        assert_eq!(Debug::decode(&[]), Err(MessageError::Empty));
    }

    // Hand-assembled: 5, string(12) "ssh-userauth".
    const SERVICE_REQUEST_USERAUTH: [u8; 17] = [
        5, 0, 0, 0, 12, b's', b's', b'h', b'-', b'u', b's', b'e', b'r', b'a', b'u', b't', b'h',
    ];
    // Hand-assembled: 6, string(14) "ssh-connection".
    const SERVICE_ACCEPT_CONNECTION: [u8; 19] = [
        6, 0, 0, 0, 14, b's', b's', b'h', b'-', b'c', b'o', b'n', b'n', b'e', b'c', b't', b'i',
        b'o', b'n',
    ];

    #[test]
    fn service_request_fixture() {
        let m = ServiceRequest::decode(&SERVICE_REQUEST_USERAUTH).unwrap();
        assert_eq!(m.service_name, b"ssh-userauth");
        let mut out = [0u8; 17];
        assert_eq!(m.encode(&mut out).unwrap(), 17);
        assert_eq!(out, SERVICE_REQUEST_USERAUTH);
    }

    #[test]
    fn service_accept_fixture() {
        let m = ServiceAccept::decode(&SERVICE_ACCEPT_CONNECTION).unwrap();
        assert_eq!(m.service_name, b"ssh-connection");
        let mut out = [0u8; 19];
        assert_eq!(m.encode(&mut out).unwrap(), 19);
        assert_eq!(out, SERVICE_ACCEPT_CONNECTION);
    }

    #[test]
    fn service_messages_reject_trailing_and_wrong_numbers() {
        let mut trailing = [0u8; 18];
        trailing[..17].copy_from_slice(&SERVICE_REQUEST_USERAUTH);
        assert_eq!(
            ServiceRequest::decode(&trailing),
            Err(MessageError::TrailingBytes { count: 1 })
        );
        assert_eq!(
            ServiceAccept::decode(&SERVICE_REQUEST_USERAUTH),
            Err(MessageError::UnexpectedMessage {
                expected: 6,
                found: 5
            })
        );
        assert_eq!(
            ServiceRequest::decode(&SERVICE_ACCEPT_CONNECTION),
            Err(MessageError::UnexpectedMessage {
                expected: 5,
                found: 6
            })
        );
        assert_eq!(
            ServiceRequest::decode(&[5, 0, 0, 0, 9, b'x']),
            Err(MessageError::Field {
                field: "service_name",
                offset: 1,
                error: DecodeError::LengthOverflow {
                    claimed: 9,
                    available: 1
                }
            })
        );
    }

    #[test]
    fn service_names_are_not_restricted() {
        // Typed `string` by RFC 4253 §10: arbitrary bytes are preserved so
        // a peer's odd request can be reported rather than mis-parsed.
        let m = ServiceRequest::decode(&[5, 0, 0, 0, 3, 0x00, 0xff, b' ']).unwrap();
        assert_eq!(m.service_name, &[0x00, 0xff, b' ']);
        let m = ServiceAccept::decode(&[6, 0, 0, 0, 0]).unwrap();
        assert!(m.service_name.is_empty());
    }
}
