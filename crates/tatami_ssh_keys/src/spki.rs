//! Strict conversion between a `SubjectPublicKeyInfo` (what an RFC 7250
//! raw-public-key TLS handshake carries) and the canonical SSH public-key
//! blob that SSH trust decisions use, for every supported key type.
//!
//! This is the one authoritative implementation; the QUIC backend calls it
//! rather than keeping its own. The DER is parsed field by field so that
//! every deviation has its own error. Accepted forms, one per key type:
//!
//! | Key type (feature) | `AlgorithmIdentifier` | `subjectPublicKey` |
//! |---|---|---|
//! | Ed25519 (`ed25519`) | id-Ed25519 1.3.101.112, parameters **absent** (RFC 8410 §3) | the 32-byte key, a canonical point (checked with `ed25519-dalek`) |
//! | RSA (`rsa`) | rsaEncryption 1.2.840.113549.1.1.1, parameters exactly `NULL` (RFC 3279 §2.3.1, RFC 4055 §1.2) | DER `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (RFC 8017 A.1.1), both minimal positive INTEGERs, within the [`crate::rsa`] policy |
//! | ECDSA P-256 (`ecdsa-p256`) | id-ecPublicKey 1.2.840.10045.2.1 with the named curve prime256v1 1.2.840.10045.3.1.7 (RFC 5480 §2.1.1) | the 65-byte SEC1 uncompressed point `04 || X || Y` (RFC 5480 §2.2) |
//!
//! Rejected in every build: any other algorithm (Ed448, X25519, RSA-PSS
//! `id-RSASSA-PSS`, DSA, ...), other curves (P-384, P-521, explicit curve
//! parameters), compressed points, a `BIT STRING` with unused bits,
//! non-canonical DER lengths (long form where short form fits, indefinite
//! form), non-minimal or negative INTEGERs, wrong tags, truncation, and
//! bytes after any field or after the whole structure. An X.509
//! certificate is not an SPKI.
//!
//! For a given key there is exactly one accepted encoding, and conversion
//! in either direction is deterministic: [`spki_to_ssh_blob`] and
//! [`ssh_blob_to_spki`] are inverse on valid inputs. The SSH blob, the SPKI
//! DER and an X.509 certificate are different byte strings with different
//! SHA-256 digests; reports label which one they show.
//!
//! Point validity for P-256 is left to the provider that uses the key (a
//! TLS signature check or SSH signature verification), as for SSH blobs;
//! see [`crate::ecdsa`].

use alloc::vec::Vec;
use core::fmt;

#[cfg(feature = "ed25519")]
use crate::blob::{ED25519_BLOB_LEN, ED25519_PUBLIC_KEY_LEN, encode_ed25519_blob};
#[cfg(feature = "ed25519")]
use crate::ed25519::Ed25519PublicKey;
use crate::error::KeyError;
use crate::host_key::HostKey;

/// DER prefix of every Ed25519 SPKI (RFC 8410 §4):
/// `SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.112 }, BIT STRING(33) { 0, key } }`.
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of an Ed25519 SPKI DER.
pub const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// DER prefix of every P-256 SPKI (RFC 5480): `SEQUENCE(89) {
/// SEQUENCE(19) { OID id-ecPublicKey, OID prime256v1 }, BIT STRING(66) { 0,
/// point } }`, followed by the 65-byte uncompressed point.
pub const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Content octets of OID 1.3.101.112 (id-Ed25519).
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// Content octets of OID 1.2.840.113549.1.1.1 (rsaEncryption).
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// Content octets of OID 1.2.840.10045.2.1 (id-ecPublicKey).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// Content octets of OID 1.2.840.10045.3.1.7 (prime256v1 / secp256r1).
#[cfg(feature = "ecdsa-p256")]
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Other algorithm OIDs worth naming in an error (RFC 8410 §3, RFC 4055,
/// RFC 3279), and the supported ones for builds without their feature.
const KNOWN_OIDS: &[(&[u8], &str)] = &[
    (OID_ED25519, "Ed25519"),
    (&[0x2b, 0x65, 0x71], "Ed448"),
    (&[0x2b, 0x65, 0x6e], "X25519"),
    (&[0x2b, 0x65, 0x6f], "X448"),
    (OID_RSA_ENCRYPTION, "rsaEncryption"),
    (
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a],
        "id-RSASSA-PSS",
    ),
    (OID_EC_PUBLIC_KEY, "id-ecPublicKey"),
    (&[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01], "id-dsa"),
];

/// Named curves worth naming in an error (RFC 5480 §2.1.1.1).
#[cfg(feature = "ecdsa-p256")]
const KNOWN_CURVES: &[(&[u8], &str)] = &[
    (&[0x2b, 0x81, 0x04, 0x00, 0x22], "secp384r1"),
    (&[0x2b, 0x81, 0x04, 0x00, 0x23], "secp521r1"),
    (&[0x2b, 0x81, 0x04, 0x00, 0x0a], "secp256k1"),
];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
#[cfg(feature = "rsa")]
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

/// Why bytes are not a supported SPKI.
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
    /// The algorithm is not one this build accepts.
    UnsupportedAlgorithm {
        /// Name of a recognised algorithm, if any.
        known: Option<&'static str>,
    },
    /// Ed25519 `AlgorithmIdentifier` parameters are present (RFC 8410 §3
    /// forbids them).
    ParametersPresent,
    /// Required parameters are absent or not the required value (RSA:
    /// exactly `NULL`; EC: a named-curve OID).
    ParametersInvalid,
    /// The named curve is not prime256v1.
    UnsupportedCurve {
        /// Name of a recognised curve, if any.
        known: Option<&'static str>,
    },
    /// The `BIT STRING` declares unused bits.
    NonZeroUnusedBits(u8),
    /// An Ed25519 key that is not 32 bytes.
    WrongKeyLength(usize),
    /// 32 bytes that are not a canonical Ed25519 point.
    InvalidKey,
    /// A DER INTEGER that is empty, negative or not minimal.
    NonCanonicalInteger {
        /// Which INTEGER.
        field: &'static str,
    },
    /// An RSA modulus outside the policy, or even.
    RsaModulus {
        /// Bit length found.
        bits: usize,
    },
    /// An RSA exponent outside the policy.
    RsaExponent,
    /// An EC point that is not a 65-byte uncompressed encoding.
    PointEncoding,
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
                write!(f, "SPKI algorithm {name} is not supported by this build")
            }
            SpkiError::UnsupportedAlgorithm { known: None } => {
                f.write_str("SPKI algorithm is not supported (unrecognised OID)")
            }
            SpkiError::ParametersPresent => {
                f.write_str("SPKI Ed25519 algorithm parameters must be absent (RFC 8410 §3)")
            }
            SpkiError::ParametersInvalid => f.write_str(
                "SPKI algorithm parameters must be NULL for RSA or a named curve for EC",
            ),
            SpkiError::UnsupportedCurve { known: Some(name) } => {
                write!(f, "SPKI curve {name} is not supported (only prime256v1)")
            }
            SpkiError::UnsupportedCurve { known: None } => {
                f.write_str("SPKI curve is not supported (only prime256v1)")
            }
            SpkiError::NonZeroUnusedBits(n) => {
                write!(f, "SPKI key BIT STRING declares {n} unused bit(s)")
            }
            SpkiError::WrongKeyLength(n) => write!(f, "SPKI key is {n} bytes, Ed25519 is 32"),
            SpkiError::InvalidKey => f.write_str("SPKI key is not a valid Ed25519 public key"),
            SpkiError::NonCanonicalInteger { field } => {
                write!(f, "SPKI {field} is not a minimal positive DER INTEGER")
            }
            SpkiError::RsaModulus { bits } => write!(
                f,
                "SPKI RSA modulus of {bits} bits is not accepted (odd, 2048 to 8192 bits)"
            ),
            SpkiError::RsaExponent => {
                f.write_str("SPKI RSA exponent is not accepted (odd, at least 3, at most 4 bytes)")
            }
            SpkiError::PointEncoding => {
                f.write_str("SPKI EC point is not a 65-byte uncompressed encoding")
            }
        }
    }
}

impl core::error::Error for SpkiError {}

/// A minimal strict DER reader for the fixed SPKI shapes.
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

    /// Reads a minimal positive INTEGER and returns its magnitude without
    /// the sign-padding zero.
    #[cfg(feature = "rsa")]
    fn positive_integer(&mut self, field: &'static str) -> Result<&'a [u8], SpkiError> {
        let v = self.read(TAG_INTEGER, field)?;
        match v {
            [] => Err(SpkiError::NonCanonicalInteger { field }),
            [b, ..] if b & 0x80 != 0 => Err(SpkiError::NonCanonicalInteger { field }),
            [0, next, ..] if next & 0x80 == 0 => Err(SpkiError::NonCanonicalInteger { field }),
            [0] => Err(SpkiError::NonCanonicalInteger { field }),
            [0, rest @ ..] => Ok(rest),
            _ => Ok(v),
        }
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

/// DER tag-length-value with a minimal length (lengths up to 65535).
fn tlv(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        debug_assert!(len <= 0xffff, "SPKI structures are far below 64 KiB");
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
}

/// A minimal positive DER INTEGER for a magnitude with no leading zero.
#[cfg_attr(not(feature = "rsa"), allow(dead_code))]
fn positive_integer(magnitude: &[u8], out: &mut Vec<u8>) {
    let mut content = Vec::with_capacity(magnitude.len() + 1);
    if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(magnitude);
    tlv(TAG_INTEGER, &content, out);
}

fn known(table: &[(&[u8], &'static str)], oid: &[u8]) -> Option<&'static str> {
    table.iter().find(|(o, _)| *o == oid).map(|(_, name)| *name)
}

/// Parses any supported SPKI into a validated [`HostKey`].
pub fn host_key_from_spki(spki: &[u8]) -> Result<HostKey, SpkiError> {
    let mut outer = Der { rest: spki };
    let body = outer.read(TAG_SEQUENCE, "SubjectPublicKeyInfo")?;
    outer.finish("SubjectPublicKeyInfo")?;

    let mut fields = Der { rest: body };
    let alg = fields.read(TAG_SEQUENCE, "AlgorithmIdentifier")?;
    let mut alg_fields = Der { rest: alg };
    let oid = alg_fields.read(TAG_OID, "algorithm OID")?;
    let params = alg_fields.rest;

    let bits = fields.read(TAG_BIT_STRING, "subjectPublicKey")?;
    fields.finish("SubjectPublicKeyInfo body")?;
    let (&unused, key) = bits.split_first().ok_or(SpkiError::Truncated {
        field: "subjectPublicKey",
    })?;

    let unsupported = || SpkiError::UnsupportedAlgorithm {
        known: known(KNOWN_OIDS, oid),
    };
    let _ = (&params, &key, &unused);
    match oid {
        #[cfg(feature = "ed25519")]
        OID_ED25519 => {
            if !params.is_empty() {
                return Err(SpkiError::ParametersPresent);
            }
            if unused != 0 {
                return Err(SpkiError::NonZeroUnusedBits(unused));
            }
            let key: &[u8; ED25519_PUBLIC_KEY_LEN] = key
                .try_into()
                .map_err(|_| SpkiError::WrongKeyLength(key.len()))?;
            Ed25519PublicKey::from_bytes(key)
                .map(HostKey::Ed25519)
                .map_err(|_| SpkiError::InvalidKey)
        }
        #[cfg(feature = "rsa")]
        OID_RSA_ENCRYPTION => {
            let mut p = Der { rest: params };
            let null = p
                .read(TAG_NULL, "RSA parameters")
                .map_err(|_| SpkiError::ParametersInvalid)?;
            if !null.is_empty() || !p.rest.is_empty() {
                return Err(SpkiError::ParametersInvalid);
            }
            if unused != 0 {
                return Err(SpkiError::NonZeroUnusedBits(unused));
            }
            let mut k = Der { rest: key };
            let seq = k.read(TAG_SEQUENCE, "RSAPublicKey")?;
            k.finish("RSAPublicKey")?;
            let mut ints = Der { rest: seq };
            let n = ints.positive_integer("modulus")?;
            let e = ints.positive_integer("publicExponent")?;
            ints.finish("RSAPublicKey body")?;
            crate::rsa::RsaPublicKey::from_components(e, n)
                .map(HostKey::Rsa)
                .map_err(|e| match e {
                    KeyError::RsaModulus { bits } => SpkiError::RsaModulus { bits },
                    _ => SpkiError::RsaExponent,
                })
        }
        #[cfg(feature = "ecdsa-p256")]
        OID_EC_PUBLIC_KEY => {
            let mut p = Der { rest: params };
            let curve = p
                .read(TAG_OID, "EC parameters")
                .map_err(|_| SpkiError::ParametersInvalid)?;
            if !p.rest.is_empty() {
                return Err(SpkiError::ParametersInvalid);
            }
            if curve != OID_PRIME256V1 {
                return Err(SpkiError::UnsupportedCurve {
                    known: known(KNOWN_CURVES, curve),
                });
            }
            if unused != 0 {
                return Err(SpkiError::NonZeroUnusedBits(unused));
            }
            crate::ecdsa::EcdsaP256PublicKey::from_point(key)
                .map(HostKey::EcdsaP256)
                .map_err(|_| SpkiError::PointEncoding)
        }
        _ => Err(unsupported()),
    }
}

/// The canonical SPKI DER of `key`.
#[must_use]
pub fn host_key_spki(key: &HostKey) -> Vec<u8> {
    match key {
        #[cfg(feature = "ed25519")]
        HostKey::Ed25519(k) => ed25519_spki(k).to_vec(),
        #[cfg(feature = "rsa")]
        HostKey::Rsa(k) => {
            let mut alg = Vec::new();
            tlv(TAG_OID, OID_RSA_ENCRYPTION, &mut alg);
            tlv(TAG_NULL, &[], &mut alg);
            let mut ints = Vec::new();
            positive_integer(k.modulus(), &mut ints);
            positive_integer(k.exponent(), &mut ints);
            let mut rsa_key = Vec::new();
            tlv(TAG_SEQUENCE, &ints, &mut rsa_key);
            let mut bit_string = alloc::vec![0u8];
            bit_string.extend_from_slice(&rsa_key);
            let mut body = Vec::new();
            tlv(TAG_SEQUENCE, &alg, &mut body);
            tlv(TAG_BIT_STRING, &bit_string, &mut body);
            let mut out = Vec::new();
            tlv(TAG_SEQUENCE, &body, &mut out);
            out
        }
        #[cfg(feature = "ecdsa-p256")]
        HostKey::EcdsaP256(k) => {
            let mut out = Vec::with_capacity(P256_SPKI_PREFIX.len() + 65);
            out.extend_from_slice(&P256_SPKI_PREFIX);
            out.extend_from_slice(k.point());
            out
        }
    }
}

/// Converts any supported SPKI into its canonical SSH public-key blob.
pub fn spki_to_ssh_blob(spki: &[u8]) -> Result<Vec<u8>, SpkiError> {
    host_key_from_spki(spki).map(|k| k.to_blob())
}

/// Converts a complete SSH public-key blob into its SPKI. The blob is
/// parsed strictly for its type (exact lengths, canonical integers, no
/// trailing bytes, key policy).
pub fn ssh_blob_to_spki(blob: &[u8]) -> Result<Vec<u8>, KeyError> {
    HostKey::parse(blob).map(|k| host_key_spki(&k))
}

/// Parses an Ed25519 SPKI and validates the key point. Any other algorithm
/// is [`SpkiError::UnsupportedAlgorithm`].
#[cfg(feature = "ed25519")]
pub fn ed25519_public_key_from_spki(spki: &[u8]) -> Result<Ed25519PublicKey, SpkiError> {
    match host_key_from_spki(spki)? {
        HostKey::Ed25519(k) => Ok(k),
        #[allow(unreachable_patterns)]
        _ => Err(SpkiError::UnsupportedAlgorithm {
            known: known(KNOWN_OIDS, spki_algorithm_oid(spki).unwrap_or_default()),
        }),
    }
}

/// The algorithm OID of a (well-formed) SPKI, for error reporting.
#[cfg(feature = "ed25519")]
fn spki_algorithm_oid(spki: &[u8]) -> Option<&[u8]> {
    let mut outer = Der { rest: spki };
    let body = outer.read(TAG_SEQUENCE, "").ok()?;
    let mut fields = Der { rest: body };
    let alg = fields.read(TAG_SEQUENCE, "").ok()?;
    Der { rest: alg }.read(TAG_OID, "").ok()
}

/// The DER SPKI for an Ed25519 `key` (always [`ED25519_SPKI_LEN`] bytes).
#[cfg(feature = "ed25519")]
#[must_use]
pub fn ed25519_spki(key: &Ed25519PublicKey) -> [u8; ED25519_SPKI_LEN] {
    let mut out = [0u8; ED25519_SPKI_LEN];
    out[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
    out[ED25519_SPKI_PREFIX.len()..].copy_from_slice(key.as_bytes());
    out
}

/// The canonical `ssh-ed25519` blob of `key`.
#[cfg(feature = "ed25519")]
#[must_use]
pub fn ssh_blob_of(key: &Ed25519PublicKey) -> [u8; ED25519_BLOB_LEN] {
    let mut out = [0u8; ED25519_BLOB_LEN];
    // The buffer is exactly the blob length, so encoding cannot fail.
    let written = encode_ed25519_blob(key.as_bytes(), &mut out);
    debug_assert_eq!(written, Ok(ED25519_BLOB_LEN));
    out
}
#[cfg(all(test, feature = "ed25519"))]
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

#[cfg(all(test, feature = "rsa"))]
mod rsa_tests {
    use super::*;
    use crate::test_vectors::*;

    #[test]
    fn matches_ssh_keygen_pkcs8_export() {
        let spki = b64(RSA_2048_SPKI);
        let blob = b64(RSA_2048_PUB);
        assert_eq!(spki_to_ssh_blob(&spki).unwrap(), blob);
        assert_eq!(ssh_blob_to_spki(&blob).unwrap(), spki);
        assert_eq!(spki.len(), 294);
        // The three digests differ: SSH blob, SPKI and neither is the other.
        assert_ne!(
            crate::Sha256Fingerprint::of_blob(&blob),
            crate::Sha256Fingerprint::of_blob(&spki)
        );
    }

    fn err(bytes: &[u8]) -> SpkiError {
        host_key_from_spki(bytes).unwrap_err()
    }

    /// Rebuilds an RSA SPKI from parts so each deviation is isolated.
    fn build(params: &[u8], unused: u8, rsa_key: &[u8]) -> Vec<u8> {
        let mut alg = Vec::new();
        tlv(TAG_OID, OID_RSA_ENCRYPTION, &mut alg);
        alg.extend_from_slice(params);
        let mut bits = alloc::vec![unused];
        bits.extend_from_slice(rsa_key);
        let mut body = Vec::new();
        tlv(TAG_SEQUENCE, &alg, &mut body);
        tlv(TAG_BIT_STRING, &bits, &mut body);
        let mut out = Vec::new();
        tlv(TAG_SEQUENCE, &body, &mut out);
        out
    }

    fn rsa_key(n: &[u8], e: &[u8]) -> Vec<u8> {
        let mut ints = Vec::new();
        tlv(TAG_INTEGER, n, &mut ints);
        tlv(TAG_INTEGER, e, &mut ints);
        let mut out = Vec::new();
        tlv(TAG_SEQUENCE, &ints, &mut out);
        out
    }

    #[test]
    fn rsa_forms_are_strict() {
        let spki = b64(RSA_2048_SPKI);
        let k = match host_key_from_spki(&spki).unwrap() {
            HostKey::Rsa(k) => k,
            #[allow(unreachable_patterns)]
            _ => panic!("not RSA"),
        };
        let mut n = alloc::vec![0u8];
        n.extend_from_slice(k.modulus());
        let good = rsa_key(&n, &[1, 0, 1]);
        assert_eq!(build(&[TAG_NULL, 0], 0, &good), spki, "builder is faithful");

        // Parameters: absent, non-NULL, NULL with content, extra field.
        assert_eq!(err(&build(&[], 0, &good)), SpkiError::ParametersInvalid);
        assert_eq!(
            err(&build(&[TAG_OID, 1, 0x2a], 0, &good)),
            SpkiError::ParametersInvalid
        );
        assert_eq!(
            err(&build(&[TAG_NULL, 1, 0], 0, &good)),
            SpkiError::ParametersInvalid
        );
        assert_eq!(
            err(&build(&[TAG_NULL, 0, TAG_NULL, 0], 0, &good)),
            SpkiError::ParametersInvalid
        );
        assert_eq!(
            err(&build(&[TAG_NULL, 0], 1, &good)),
            SpkiError::NonZeroUnusedBits(1)
        );
        // INTEGER encodings: missing sign pad (negative), redundant zero,
        // empty exponent.
        assert_eq!(
            err(&build(&[TAG_NULL, 0], 0, &rsa_key(&n[1..], &[1, 0, 1]))),
            SpkiError::NonCanonicalInteger { field: "modulus" }
        );
        assert_eq!(
            err(&build(&[TAG_NULL, 0], 0, &rsa_key(&n, &[0, 1, 0, 1]))),
            SpkiError::NonCanonicalInteger {
                field: "publicExponent"
            }
        );
        assert_eq!(
            err(&build(&[TAG_NULL, 0], 0, &rsa_key(&n, &[]))),
            SpkiError::NonCanonicalInteger {
                field: "publicExponent"
            }
        );
        // Policy.
        assert_eq!(
            err(&build(&[TAG_NULL, 0], 0, &rsa_key(&n, &[2]))),
            SpkiError::RsaExponent
        );
        assert_eq!(
            err(&build(&[TAG_NULL, 0], 0, &rsa_key(&n[..129], &[1, 0, 1]))),
            SpkiError::RsaModulus { bits: 1024 }
        );
        // Trailing data inside RSAPublicKey, after it, and after the SPKI.
        let mut ints = Vec::new();
        tlv(TAG_INTEGER, &n, &mut ints);
        tlv(TAG_INTEGER, &[1, 0, 1], &mut ints);
        tlv(TAG_NULL, &[], &mut ints);
        let mut extra = Vec::new();
        tlv(TAG_SEQUENCE, &ints, &mut extra);
        assert!(matches!(
            err(&build(&[TAG_NULL, 0], 0, &extra)),
            SpkiError::TrailingBytes { .. }
        ));
        let mut after = good.clone();
        after.push(0);
        assert!(matches!(
            err(&build(&[TAG_NULL, 0], 0, &after)),
            SpkiError::TrailingBytes { .. }
        ));
        let mut t = spki.clone();
        t.push(0);
        assert!(matches!(err(&t), SpkiError::TrailingBytes { .. }));
        // Every strict prefix fails.
        for len in 0..spki.len() {
            assert!(host_key_from_spki(&spki[..len]).is_err(), "{len}");
        }
    }

    #[test]
    fn rsa_pss_and_other_algorithms_are_named() {
        let mut spki = b64(RSA_2048_SPKI);
        // rsaEncryption ...01.01.01 -> id-RSASSA-PSS ...01.01.0a
        assert_eq!(
            &spki[6..17],
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
            ]
        );
        spki[16] = 0x0a;
        assert_eq!(
            err(&spki),
            SpkiError::UnsupportedAlgorithm {
                known: Some("id-RSASSA-PSS")
            }
        );
        // An RSA SPKI is not an Ed25519 one.
        #[cfg(feature = "ed25519")]
        assert_eq!(
            ed25519_public_key_from_spki(&b64(RSA_2048_SPKI)),
            Err(SpkiError::UnsupportedAlgorithm {
                known: Some("rsaEncryption")
            })
        );
    }
}

#[cfg(all(test, feature = "ecdsa-p256"))]
mod p256_tests {
    use super::*;
    use crate::test_vectors::*;

    fn err(bytes: &[u8]) -> SpkiError {
        host_key_from_spki(bytes).unwrap_err()
    }

    #[test]
    fn matches_ssh_keygen_pkcs8_export() {
        let spki = b64(P256_SPKI);
        let blob = b64(P256_PUB);
        assert_eq!(&spki[..26], &P256_SPKI_PREFIX);
        assert_eq!(spki_to_ssh_blob(&spki).unwrap(), blob);
        assert_eq!(ssh_blob_to_spki(&blob).unwrap(), spki);
    }

    #[test]
    fn curves_points_and_parameters() {
        let spki = b64(P256_SPKI);
        let point = &spki[26..];

        // secp384r1 named curve (lengths adjusted), secp256k1, unknown.
        for (curve, known) in [
            (&[0x2b, 0x81, 0x04, 0x00, 0x22][..], Some("secp384r1")),
            (&[0x2b, 0x81, 0x04, 0x00, 0x0a], Some("secp256k1")),
            (&[0x2b, 0x01], None),
        ] {
            let mut alg = Vec::new();
            tlv(TAG_OID, OID_EC_PUBLIC_KEY, &mut alg);
            tlv(TAG_OID, curve, &mut alg);
            let mut bits = alloc::vec![0u8];
            bits.extend_from_slice(point);
            let mut body = Vec::new();
            tlv(TAG_SEQUENCE, &alg, &mut body);
            tlv(TAG_BIT_STRING, &bits, &mut body);
            let mut out = Vec::new();
            tlv(TAG_SEQUENCE, &body, &mut out);
            assert_eq!(err(&out), SpkiError::UnsupportedCurve { known });
        }
        // Implicit/absent or explicit (SEQUENCE) parameters.
        for params in [&[][..], &[0x05, 0x00], &[0x30, 0x00]] {
            let mut alg = Vec::new();
            tlv(TAG_OID, OID_EC_PUBLIC_KEY, &mut alg);
            alg.extend_from_slice(params);
            let mut bits = alloc::vec![0u8];
            bits.extend_from_slice(point);
            let mut body = Vec::new();
            tlv(TAG_SEQUENCE, &alg, &mut body);
            tlv(TAG_BIT_STRING, &bits, &mut body);
            let mut out = Vec::new();
            tlv(TAG_SEQUENCE, &body, &mut out);
            assert_eq!(err(&out), SpkiError::ParametersInvalid, "{params:?}");
        }
        // Compressed point (same curve), wrong prefix byte, unused bits.
        let mut compressed = Vec::new();
        {
            let mut alg = Vec::new();
            tlv(TAG_OID, OID_EC_PUBLIC_KEY, &mut alg);
            tlv(TAG_OID, OID_PRIME256V1, &mut alg);
            let mut bits = alloc::vec![0u8, 0x02];
            bits.extend_from_slice(&point[1..33]);
            let mut body = Vec::new();
            tlv(TAG_SEQUENCE, &alg, &mut body);
            tlv(TAG_BIT_STRING, &bits, &mut body);
            tlv(TAG_SEQUENCE, &body, &mut compressed);
        }
        assert_eq!(err(&compressed), SpkiError::PointEncoding);
        let mut hybrid = spki.clone();
        hybrid[26] = 0x06;
        assert_eq!(err(&hybrid), SpkiError::PointEncoding);
        let mut unused = spki.clone();
        unused[25] = 1;
        assert_eq!(err(&unused), SpkiError::NonZeroUnusedBits(1));
        for len in 0..spki.len() {
            assert!(host_key_from_spki(&spki[..len]).is_err(), "{len}");
        }
    }
}
