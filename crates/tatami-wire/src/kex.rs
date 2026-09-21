//! Key-exchange message codecs: the ECDH pair of RFC 5656 §4 (used verbatim
//! by RFC 8731 `curve25519-sha256`) and `SSH_MSG_NEWKEYS` (RFC 4253 §7.3).
//!
//! These decoders are syntactic. They check the message number, borrow each
//! `string` field and reject trailing bytes. They do **not** check that an
//! ephemeral public value has the length the negotiated method requires
//! (32 bytes for X25519), that a host-key blob parses, or that a signature
//! verifies: those are the key-exchange driver's and `tatami-keys`' job.
//!
//! Field names in [`MessageError::Field`] are the ones RFC 5656 §4 uses in
//! the message definitions (`Q_C`, `K_S`, `Q_S`, `signature`).
//!
//! Message numbers 30 and 31 are method-specific (RFC 4253 §12). A caller
//! must only apply these decoders after negotiating an ECDH-family method;
//! see [`msg`].

use crate::EncodeError;
use crate::error::MessageError;
use crate::message::{expect_message, field, finish};
use crate::msg;
use crate::primitives::{Reader, Writer};

/// `SSH_MSG_KEX_ECDH_INIT` (RFC 5656 §4, message 30).
///
/// ```text
/// byte     SSH_MSG_KEX_ECDH_INIT
/// string   Q_C, client's ephemeral public key octet string
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KexEcdhInit<'a> {
    /// `Q_C`: the client's ephemeral public value, exactly as sent.
    pub client_ephemeral: &'a [u8],
}

impl<'a> KexEcdhInit<'a> {
    /// Decodes a complete, already delimited payload starting at the
    /// message number byte.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::KEX_ECDH_INIT)?;
        let client_ephemeral = field(&mut r, "Q_C", Reader::read_string)?;
        finish(&r)?;
        Ok(KexEcdhInit { client_ephemeral })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::KEX_ECDH_INIT)?;
        w.write_string(self.client_ephemeral)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_KEX_ECDH_REPLY` (RFC 5656 §4, message 31).
///
/// ```text
/// byte     SSH_MSG_KEX_ECDH_REPLY
/// string   K_S, server's public host key
/// string   Q_S, server's ephemeral public key octet string
/// string   the signature on the exchange hash
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KexEcdhReply<'a> {
    /// `K_S`: the complete server host-key blob (`string algorithm` followed
    /// by the algorithm-specific body), exactly as sent. The exchange hash
    /// and the host fingerprint both cover these exact bytes.
    pub host_key_blob: &'a [u8],
    /// `Q_S`: the server's ephemeral public value, exactly as sent.
    pub server_ephemeral: &'a [u8],
    /// The signature blob over the exchange hash (`string algorithm`,
    /// `string signature`), exactly as sent.
    pub signature_blob: &'a [u8],
}

impl<'a> KexEcdhReply<'a> {
    /// Decodes a complete, already delimited payload starting at the
    /// message number byte.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::KEX_ECDH_REPLY)?;
        let host_key_blob = field(&mut r, "K_S", Reader::read_string)?;
        let server_ephemeral = field(&mut r, "Q_S", Reader::read_string)?;
        let signature_blob = field(&mut r, "signature", Reader::read_string)?;
        finish(&r)?;
        Ok(KexEcdhReply {
            host_key_blob,
            server_ephemeral,
            signature_blob,
        })
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::KEX_ECDH_REPLY)?;
        w.write_string(self.host_key_blob)?;
        w.write_string(self.server_ephemeral)?;
        w.write_string(self.signature_blob)?;
        Ok(w.position())
    }
}

/// `SSH_MSG_NEWKEYS` (RFC 4253 §7.3, message 21): a payload of exactly the
/// message number byte.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NewKeys;

impl NewKeys {
    /// Encoded length of the message: one byte.
    pub const LEN: usize = 1;

    /// Decodes a complete payload, rejecting anything after the message
    /// number.
    pub fn decode(payload: &[u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::NEWKEYS)?;
        finish(&r)?;
        Ok(NewKeys)
    }

    /// Encodes the message into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_u8(msg::NEWKEYS)?;
        Ok(w.position())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::DecodeError;

    // Hand-assembled: 30, string(4) aa bb cc dd.
    const INIT: [u8; 9] = [30, 0, 0, 0, 4, 0xaa, 0xbb, 0xcc, 0xdd];

    // Hand-assembled: 31, string(3) "ks!", string(2) 01 02, string(1) 99.
    const REPLY: [u8; 19] = [
        31, 0, 0, 0, 3, b'k', b's', b'!', 0, 0, 0, 2, 0x01, 0x02, 0, 0, 0, 1, 0x99,
    ];

    #[test]
    fn ecdh_init_fixture() {
        let m = KexEcdhInit::decode(&INIT).unwrap();
        assert_eq!(m.client_ephemeral, &[0xaa, 0xbb, 0xcc, 0xdd]);

        let mut out = [0u8; 9];
        assert_eq!(m.encode(&mut out).unwrap(), INIT.len());
        assert_eq!(out, INIT);
    }

    #[test]
    fn ecdh_init_errors_name_the_field() {
        assert_eq!(KexEcdhInit::decode(&[]), Err(MessageError::Empty));
        assert_eq!(
            KexEcdhInit::decode(&[31, 0, 0, 0, 0]),
            Err(MessageError::UnexpectedMessage {
                expected: 30,
                found: 31
            })
        );
        assert_eq!(
            KexEcdhInit::decode(&[30, 0, 0, 0, 5, 1]),
            Err(MessageError::Field {
                field: "Q_C",
                offset: 1,
                error: DecodeError::LengthOverflow {
                    claimed: 5,
                    available: 1
                }
            })
        );
        assert_eq!(
            KexEcdhInit::decode(&[30, 0, 0]),
            Err(MessageError::Field {
                field: "Q_C",
                offset: 1,
                error: DecodeError::Truncated {
                    needed: 4,
                    available: 2
                }
            })
        );
        let mut trailing = [0u8; 10];
        trailing[..9].copy_from_slice(&INIT);
        assert_eq!(
            KexEcdhInit::decode(&trailing),
            Err(MessageError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn ecdh_init_empty_value_is_syntactically_valid() {
        // Length checks belong to the method driver, not the codec.
        let m = KexEcdhInit::decode(&[30, 0, 0, 0, 0]).unwrap();
        assert!(m.client_ephemeral.is_empty());
    }

    #[test]
    fn ecdh_reply_fixture() {
        let m = KexEcdhReply::decode(&REPLY).unwrap();
        assert_eq!(m.host_key_blob, b"ks!");
        assert_eq!(m.server_ephemeral, &[0x01, 0x02]);
        assert_eq!(m.signature_blob, &[0x99]);

        let mut out = [0u8; 19];
        assert_eq!(m.encode(&mut out).unwrap(), REPLY.len());
        assert_eq!(out, REPLY);
    }

    #[test]
    fn ecdh_reply_truncation_at_every_field_names_it() {
        // Field offsets in REPLY: K_S at 1, Q_S at 8, signature at 14.
        let cases: [(usize, &str, usize); 3] =
            [(5, "K_S", 1), (12, "Q_S", 8), (17, "signature", 14)];
        for (cut, field, offset) in cases {
            match KexEcdhReply::decode(&REPLY[..cut]) {
                Err(MessageError::Field {
                    field: f,
                    offset: o,
                    ..
                }) => {
                    assert_eq!(f, field, "cut at {cut}");
                    assert_eq!(o, offset, "cut at {cut}");
                }
                other => panic!("cut at {cut}: unexpected {other:?}"),
            }
        }
    }

    #[test]
    fn ecdh_reply_trailing_and_wrong_number() {
        let mut trailing = [0u8; 20];
        trailing[..19].copy_from_slice(&REPLY);
        assert_eq!(
            KexEcdhReply::decode(&trailing),
            Err(MessageError::TrailingBytes { count: 1 })
        );
        assert_eq!(
            KexEcdhReply::decode(&INIT),
            Err(MessageError::UnexpectedMessage {
                expected: 31,
                found: 30
            })
        );
    }

    #[test]
    fn ecdh_encode_reports_capacity() {
        let m = KexEcdhReply::decode(&REPLY).unwrap();
        let mut small = [0u8; 10];
        assert_eq!(
            m.encode(&mut small),
            Err(EncodeError::InsufficientCapacity {
                needed: 6,
                available: 2
            })
        );
    }

    #[test]
    fn newkeys_is_exactly_one_byte() {
        assert_eq!(NewKeys::decode(&[21]), Ok(NewKeys));
        assert_eq!(
            NewKeys::decode(&[21, 0]),
            Err(MessageError::TrailingBytes { count: 1 })
        );
        assert_eq!(NewKeys::decode(&[]), Err(MessageError::Empty));
        assert_eq!(
            NewKeys::decode(&[20]),
            Err(MessageError::UnexpectedMessage {
                expected: 21,
                found: 20
            })
        );

        let mut out = [0u8; 1];
        assert_eq!(NewKeys.encode(&mut out).unwrap(), NewKeys::LEN);
        assert_eq!(out, [21]);
        let mut none = [0u8; 0];
        assert_eq!(
            NewKeys.encode(&mut none),
            Err(EncodeError::InsufficientCapacity {
                needed: 1,
                available: 0
            })
        );
    }
}
