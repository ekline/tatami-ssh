//! Strict conversion between an Ed25519 `SubjectPublicKeyInfo` (RFC 8410
//! §4, what an RFC 7250 raw-public-key TLS handshake carries) and the SSH
//! `ssh-ed25519` public-key blob (RFC 8709 §4) that SSH trust decisions use.
//!
//! This is the one authoritative implementation; the QUIC backend calls it
//! rather than keeping its own. The DER is parsed field by field so that
//! every deviation has its own error, and each of these is rejected:
//!
//! - any algorithm other than id-Ed25519 (OID 1.3.101.112), including
//!   Ed448 and X25519, which have the same shape;
//! - algorithm parameters of any kind (RFC 8410 §3: "MUST be absent"),
//!   including an explicit `NULL`;
//! - a `BIT STRING` whose unused-bits count is not zero;
//! - a key that is not exactly 32 bytes, or not a canonical curve point
//!   (checked with `ed25519-dalek`);
//! - non-canonical DER lengths (long form where short form fits, the
//!   indefinite form), wrong tags, truncation, and bytes after any field or
//!   after the whole structure.
//!
//! For a well-formed key there is exactly one accepted encoding: the fixed
//! 12-byte [`ED25519_SPKI_PREFIX`] followed by the key. Tests compare
//! against that independently written constant, not only round trips.

use core::fmt;

use crate::blob::{ED25519_BLOB_LEN, ED25519_PUBLIC_KEY_LEN, encode_ed25519_blob};
use crate::ed25519::{Ed25519PublicKey, HostKey};
use crate::error::KeyError;

/// DER prefix of every Ed25519 SPKI (RFC 8410 §4):
/// `SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.112 }, BIT STRING(33) { 0, key } }`.
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of an Ed25519 SPKI DER.
pub const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_LEN;

/// Content octets of OID 1.3.101.112 (id-Ed25519).
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// Other OIDs worth naming in an error (RFC 8410 §3, RFC 8017, RFC 5480).
const KNOWN_OIDS: &[(&[u8], &str)] = &[
    (&[0x2b, 0x65, 0x71], "Ed448"),
    (&[0x2b, 0x65, 0x6e], "X25519"),
    (&[0x2b, 0x65, 0x6f], "X448"),
    (
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
        "rsaEncryption",
    ),
    (
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        "id-ecPublicKey",
    ),
];

const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_BIT_STRING: u8 = 0x03;

/// Why bytes are not a supported Ed25519 SPKI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpkiError {
    /// Input ended inside `field`.
    Truncated {
        /// The structure being read.
        field: &'static str,
    },
    /// A tag other than the one the structure requires.
    UnexpectedTag {
        /// The structure being read.
        field: &'static str,
        /// Tag required there.
        expected: u8,
        /// Tag found.
        found: u8,
    },
    /// A length that is not the minimal DER encoding (or is indefinite).
    NonCanonicalLength {
        /// The structure being read.
        field: &'static str,
    },
    /// Bytes remained after `field`.
    TrailingBytes {
        /// The structure that should have ended.
        field: &'static str,
        /// How many bytes remained.
        count: usize,
    },
    /// The algorithm is not id-Ed25519.
    UnsupportedAlgorithm {
        /// Name of a recognised other algorithm, if any.
        known: Option<&'static str>,
    },
    /// The `AlgorithmIdentifier` carries parameters (RFC 8410 §3 forbids).
    ParametersPresent,
    /// The `BIT STRING` declares unused bits.
    NonZeroUnusedBits(u8),
    /// The key is not 32 bytes.
    WrongKeyLength(usize),
    /// 32 bytes that are not a canonical Ed25519 point.
    InvalidKey,
}

impl fmt::Display for SpkiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpkiError::Truncated { field } => write!(f, "SPKI truncated in {field}"),
            SpkiError::UnexpectedTag {
                field,
                expected,
                found,
            } => write!(
                f,
                "SPKI {field}: tag 0x{found:02x}, expected 0x{expected:02x}"
            ),
            SpkiError::NonCanonicalLength { field } => {
                write!(f, "SPKI {field}: length is not minimal DER")
            }
            SpkiError::TrailingBytes { field, count } => {
                write!(f, "SPKI {field}: {count} unexpected trailing byte(s)")
            }
            SpkiError::UnsupportedAlgorithm { known: Some(name) } => {
                write!(f, "SPKI algorithm is {name}, not Ed25519")
            }
            SpkiError::UnsupportedAlgorithm { known: None } => {
                f.write_str("SPKI algorithm is not Ed25519 (OID 1.3.101.112)")
            }
            SpkiError::ParametersPresent => {
                f.write_str("SPKI Ed25519 algorithm parameters must be absent (RFC 8410 §3)")
            }
            SpkiError::NonZeroUnusedBits(n) => {
                write!(f, "SPKI key BIT STRING declares {n} unused bit(s)")
            }
            SpkiError::WrongKeyLength(n) => write!(f, "SPKI key is {n} bytes, Ed25519 is 32"),
            SpkiError::InvalidKey => f.write_str("SPKI key is not a valid Ed25519 public key"),
        }
    }
}

impl core::error::Error for SpkiError {}

/// A minimal strict DER reader for the fixed SPKI shape.
struct Der<'a> {
    rest: &'a [u8],
}

impl<'a> Der<'a> {
    /// Reads one TLV with tag `tag`, returning its content.
    fn read(&mut self, tag: u8, field: &'static str) -> Result<&'a [u8], SpkiError> {
        let (&found, after_tag) = self
            .rest
            .split_first()
            .ok_or(SpkiError::Truncated { field })?;
        if found != tag {
            return Err(SpkiError::UnexpectedTag {
                field,
                expected: tag,
                found,
            });
        }
        let (&first, mut after_len) = after_tag
            .split_first()
            .ok_or(SpkiError::Truncated { field })?;
        let len = match first {
            0..=0x7f => usize::from(first),
            0x81 => {
                let (&b, rest) = after_len
                    .split_first()
                    .ok_or(SpkiError::Truncated { field })?;
                if b < 0x80 {
                    return Err(SpkiError::NonCanonicalLength { field });
                }
                after_len = rest;
                usize::from(b)
            }
            0x82 => {
                if after_len.len() < 2 {
                    return Err(SpkiError::Truncated { field });
                }
                let (bytes, rest) = after_len.split_at(2);
                let n = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
                if n < 0x100 {
                    return Err(SpkiError::NonCanonicalLength { field });
                }
                after_len = rest;
                n
            }
            // Indefinite (0x80) is forbidden in DER; longer forms cannot
            // describe anything that fits a key structure honestly.
            _ => return Err(SpkiError::NonCanonicalLength { field }),
        };
        if after_len.len() < len {
            return Err(SpkiError::Truncated { field });
        }
        let (content, rest) = after_len.split_at(len);
        self.rest = rest;
        Ok(content)
    }

    fn finish(&self, field: &'static str) -> Result<(), SpkiError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(SpkiError::TrailingBytes {
                field,
                count: self.rest.len(),
            })
        }
    }
}

/// Parses an Ed25519 SPKI and validates the key point.
pub fn ed25519_public_key_from_spki(spki: &[u8]) -> Result<Ed25519PublicKey, SpkiError> {
    let mut outer = Der { rest: spki };
    let body = outer.read(TAG_SEQUENCE, "SubjectPublicKeyInfo")?;
    outer.finish("SubjectPublicKeyInfo")?;

    let mut fields = Der { rest: body };
    let alg = fields.read(TAG_SEQUENCE, "AlgorithmIdentifier")?;
    let mut alg_fields = Der { rest: alg };
    let oid = alg_fields.read(TAG_OID, "algorithm OID")?;
    if oid != OID_ED25519 {
        let known = KNOWN_OIDS
            .iter()
            .find(|(o, _)| *o == oid)
            .map(|(_, name)| *name);
        return Err(SpkiError::UnsupportedAlgorithm { known });
    }
    if !alg_fields.rest.is_empty() {
        return Err(SpkiError::ParametersPresent);
    }

    let bits = fields.read(TAG_BIT_STRING, "subjectPublicKey")?;
    fields.finish("SubjectPublicKeyInfo body")?;
    let (&unused, key) = bits.split_first().ok_or(SpkiError::Truncated {
        field: "subjectPublicKey",
    })?;
    if unused != 0 {
        return Err(SpkiError::NonZeroUnusedBits(unused));
    }
    let key: &[u8; ED25519_PUBLIC_KEY_LEN] = key
        .try_into()
        .map_err(|_| SpkiError::WrongKeyLength(key.len()))?;
    Ed25519PublicKey::from_bytes(key).map_err(|_| SpkiError::InvalidKey)
}

/// The DER SPKI for `key` (always [`ED25519_SPKI_LEN`] bytes).
#[must_use]
pub fn ed25519_spki(key: &Ed25519PublicKey) -> [u8; ED25519_SPKI_LEN] {
    let mut out = [0u8; ED25519_SPKI_LEN];
    out[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
    out[ED25519_SPKI_PREFIX.len()..].copy_from_slice(key.as_bytes());
    out
}

/// Converts an Ed25519 SPKI into the canonical `ssh-ed25519` blob.
pub fn spki_to_ssh_blob(spki: &[u8]) -> Result<[u8; ED25519_BLOB_LEN], SpkiError> {
    let key = ed25519_public_key_from_spki(spki)?;
    Ok(ssh_blob_of(&key))
}

/// Converts a complete `ssh-ed25519` blob into its SPKI. The blob is parsed
/// strictly (algorithm, exact length, no trailing bytes, valid point).
pub fn ssh_blob_to_spki(blob: &[u8]) -> Result<[u8; ED25519_SPKI_LEN], KeyError> {
    match HostKey::parse(blob)? {
        HostKey::Ed25519(key) => Ok(ed25519_spki(&key)),
    }
}

/// The canonical `ssh-ed25519` blob of `key`.
#[must_use]
pub fn ssh_blob_of(key: &Ed25519PublicKey) -> [u8; ED25519_BLOB_LEN] {
    let mut out = [0u8; ED25519_BLOB_LEN];
    // The buffer is exactly the blob length, so encoding cannot fail.
    let written = encode_ed25519_blob(key.as_bytes(), &mut out);
    debug_assert_eq!(written, Ok(ED25519_BLOB_LEN));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::fixtures::{TEST1_PUBLIC_KEY, test1_key_blob};
    use alloc::vec::Vec;

    /// Hand-written, independent of `ed25519_spki`: RFC 8410 §10.1 layout
    /// with the RFC 8032 TEST 1 public key.
    fn test1_spki() -> Vec<u8> {
        let mut v = alloc::vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        v.extend_from_slice(&TEST1_PUBLIC_KEY);
        v
    }

    #[test]
    fn rfc8410_example_spki_decodes() {
        // RFC 8410 §10.1 example public key, as printed in the RFC:
        // MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
        let example: [u8; 44] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x19, 0xbf,
            0x44, 0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b, 0x96,
            0xc8, 0x50, 0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31,
            0x66, 0xe1,
        ];
        let key = ed25519_public_key_from_spki(&example).unwrap();
        assert_eq!(key.as_bytes(), &example[12..]);
        assert_eq!(ed25519_spki(&key), example);
    }

    #[test]
    fn conversion_matches_independent_encodings() {
        let spki = test1_spki();
        let blob = spki_to_ssh_blob(&spki).unwrap();
        assert_eq!(blob.as_slice(), test1_key_blob().as_slice());
        assert_eq!(ssh_blob_to_spki(&blob).unwrap().as_slice(), spki.as_slice());
    }

    fn err(bytes: &[u8]) -> SpkiError {
        ed25519_public_key_from_spki(bytes).unwrap_err()
    }

    #[test]
    fn other_algorithms_are_rejected_by_name() {
        for (last, name) in [(0x71, "Ed448"), (0x6e, "X25519"), (0x6f, "X448")] {
            let mut s = test1_spki();
            s[8] = last;
            assert_eq!(
                err(&s),
                SpkiError::UnsupportedAlgorithm { known: Some(name) }
            );
        }
        let mut s = test1_spki();
        s[6] = 0x2c;
        assert_eq!(err(&s), SpkiError::UnsupportedAlgorithm { known: None });
    }

    #[test]
    fn parameters_must_be_absent() {
        // AlgorithmIdentifier with an explicit NULL: SEQUENCE(7){OID, NULL}.
        let mut s = alloc::vec![
            0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00
        ];
        s.extend_from_slice(&[0x03, 0x21, 0x00]);
        s.extend_from_slice(&TEST1_PUBLIC_KEY);
        assert_eq!(err(&s), SpkiError::ParametersPresent);
    }

    #[test]
    fn bit_string_rules() {
        let mut s = test1_spki();
        s[11] = 1;
        assert_eq!(err(&s), SpkiError::NonZeroUnusedBits(1));

        // 31-byte key: all lengths adjusted consistently.
        let mut short = alloc::vec![0x30, 0x29, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        short.extend_from_slice(&[0x03, 0x20, 0x00]);
        short.extend_from_slice(&TEST1_PUBLIC_KEY[..31]);
        assert_eq!(err(&short), SpkiError::WrongKeyLength(31));

        // Empty BIT STRING.
        let s = [
            0x30, 0x09, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x00,
        ];
        assert_eq!(
            err(&s),
            SpkiError::Truncated {
                field: "subjectPublicKey"
            }
        );
    }

    #[test]
    fn invalid_point_is_rejected() {
        // Roughly half of all y coordinates are not on the curve; take the
        // first small one the provider rejects and check it propagates.
        let off_curve = (2u8..=255)
            .map(|y| {
                let mut k = [0u8; 32];
                k[0] = y;
                k
            })
            .find(|k| Ed25519PublicKey::from_bytes(k).is_err())
            .expect("some small y is off the curve");
        let mut s = test1_spki();
        s[12..].copy_from_slice(&off_curve);
        assert_eq!(err(&s), SpkiError::InvalidKey);
    }

    #[test]
    fn der_structure_is_strict() {
        let good = test1_spki();
        // Every strict prefix is truncated somewhere.
        for n in 0..good.len() {
            assert!(
                matches!(err(&good[..n]), SpkiError::Truncated { .. }),
                "prefix {n}: {:?}",
                err(&good[..n])
            );
        }
        // Trailing byte after the whole structure.
        let mut t = good.clone();
        t.push(0);
        assert_eq!(
            err(&t),
            SpkiError::TrailingBytes {
                field: "SubjectPublicKeyInfo",
                count: 1
            }
        );
        // Trailing TLV inside the outer SEQUENCE.
        let mut inner = alloc::vec![0x30, 0x2c];
        inner.extend_from_slice(&good[2..]);
        inner.extend_from_slice(&[0x05, 0x00]);
        assert_eq!(
            err(&inner),
            SpkiError::TrailingBytes {
                field: "SubjectPublicKeyInfo body",
                count: 2
            }
        );
        // Long-form length where short form fits.
        let mut long = alloc::vec![0x30, 0x81, 0x2a];
        long.extend_from_slice(&good[2..]);
        assert_eq!(
            err(&long),
            SpkiError::NonCanonicalLength {
                field: "SubjectPublicKeyInfo"
            }
        );
        // Indefinite length.
        let mut indef = alloc::vec![0x30, 0x80];
        indef.extend_from_slice(&good[2..]);
        indef.extend_from_slice(&[0, 0]);
        assert_eq!(
            err(&indef),
            SpkiError::NonCanonicalLength {
                field: "SubjectPublicKeyInfo"
            }
        );
        // Wrong outer tag (SET).
        let mut set = good.clone();
        set[0] = 0x31;
        assert_eq!(
            err(&set),
            SpkiError::UnexpectedTag {
                field: "SubjectPublicKeyInfo",
                expected: 0x30,
                found: 0x31
            }
        );
        // An SSH blob is not an SPKI.
        assert!(matches!(
            err(&test1_key_blob()),
            SpkiError::UnexpectedTag { .. }
        ));
        // Raw 32 bytes are not an SPKI either.
        assert!(ed25519_public_key_from_spki(&TEST1_PUBLIC_KEY).is_err());
    }

    #[test]
    fn blob_to_spki_is_strict() {
        let mut blob = test1_key_blob().to_vec();
        blob.push(0);
        assert!(ssh_blob_to_spki(&blob).is_err());
        assert!(ssh_blob_to_spki(&TEST1_PUBLIC_KEY).is_err());
    }
}
