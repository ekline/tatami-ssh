//! Error types for blob parsing, key construction and verification.

use alloc::vec::Vec;
use core::fmt;

use tatami_ssh_wire::DecodeError;

/// A public-key or signature blob is malformed at the encoding level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlobError {
    /// A named field failed to decode.
    Field {
        /// Field name from the blob definition (RFC 4253 §6.6).
        field: &'static str,
        /// Offset of the field within the blob.
        offset: usize,
        /// The primitive-level error.
        error: DecodeError,
    },
    /// Bytes remained after the last defined field.
    TrailingBytes {
        /// Number of unconsumed bytes.
        count: usize,
    },
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlobError::Field {
                field,
                offset,
                error,
            } => write!(f, "field `{field}` at offset {offset}: {error}"),
            BlobError::TrailingBytes { count } => {
                write!(f, "{count} unexpected trailing byte(s) after blob")
            }
        }
    }
}

impl core::error::Error for BlobError {}

/// A blob decoded but does not describe a key or signature this crate can
/// use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// The blob encoding itself is malformed.
    Blob(BlobError),
    /// The algorithm name is not one this crate implements. Carries the
    /// name as sent so it can be reported; nothing is inferred from it.
    UnsupportedAlgorithm(Vec<u8>),
    /// A fixed-size field had the wrong length.
    WrongLength {
        /// Which field: `key` or `signature`.
        field: &'static str,
        /// Length the algorithm requires.
        expected: usize,
        /// Length found in the blob.
        found: usize,
    },
    /// The key bytes have the right length but do not encode a valid public
    /// key (for Ed25519: not a canonical point on the curve).
    InvalidKey,
    /// An `mpint` is negative, zero where a positive value is required, or
    /// not in the minimal encoding RFC 4251 §5 requires.
    NonCanonicalInteger {
        /// Which field (`e`, `n`, `r`, `s`, ...).
        field: &'static str,
    },
    /// An RSA modulus outside the accepted size range, or even.
    RsaModulus {
        /// Bit length of the modulus found.
        bits: usize,
    },
    /// An RSA public exponent that is even, below 3, or longer than four
    /// bytes.
    RsaExponent,
    /// The curve identifier inside an ECDSA blob does not match its
    /// algorithm name (`ecdsa-sha2-nistp256` requires `nistp256`).
    CurveMismatch,
    /// An ECDSA point that is not a 65-byte SEC1 uncompressed encoding.
    PointEncoding,
    /// An ECDSA signature component (`r` or `s`) wider than the curve's
    /// scalar size.
    ScalarTooLong {
        /// Which component.
        field: &'static str,
    },
    /// The presented key is of a different type than the one negotiated.
    UnexpectedKeyType {
        /// Key type the negotiated scheme requires.
        expected: &'static [u8],
        /// Key type found in the blob.
        found: Vec<u8>,
    },
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Blob(e) => write!(f, "malformed blob: {e}"),
            KeyError::UnsupportedAlgorithm(name) => {
                write!(f, "unsupported algorithm {}", Escaped(name))
            }
            KeyError::WrongLength {
                field,
                expected,
                found,
            } => write!(f, "{field} is {found} bytes, expected {expected}"),
            KeyError::InvalidKey => f.write_str("key bytes do not encode a valid public key"),
            KeyError::NonCanonicalInteger { field } => {
                write!(f, "{field} is not a minimal positive mpint")
            }
            KeyError::RsaModulus { bits } => write!(
                f,
                "RSA modulus of {bits} bits is not accepted (odd, 2048 to 8192 bits)"
            ),
            KeyError::RsaExponent => f.write_str(
                "RSA public exponent is not accepted (odd, at least 3, at most 4 bytes)",
            ),
            KeyError::CurveMismatch => {
                f.write_str("ECDSA curve identifier does not match the key algorithm")
            }
            KeyError::PointEncoding => {
                f.write_str("ECDSA point is not a 65-byte uncompressed SEC1 encoding")
            }
            KeyError::ScalarTooLong { field } => {
                write!(f, "ECDSA signature {field} is wider than the curve order")
            }
            KeyError::UnexpectedKeyType { expected, found } => write!(
                f,
                "host key is {}, but the negotiated algorithm needs {}",
                Escaped(found),
                Escaped(expected)
            ),
        }
    }
}

impl core::error::Error for KeyError {}

impl From<BlobError> for KeyError {
    fn from(e: BlobError) -> Self {
        KeyError::Blob(e)
    }
}

/// Signature verification did not succeed.
///
/// Every variant is a hard failure for the caller: a handshake must be
/// aborted whichever one it sees. They are distinguished so a report can say
/// *why*, not so that any of them can be tolerated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature blob names a different algorithm than the key blob.
    /// Detected before any cryptographic work.
    AlgorithmMismatch {
        /// Algorithm of the host key.
        key_algorithm: Vec<u8>,
        /// Algorithm named in the signature blob.
        signature_algorithm: Vec<u8>,
    },
    /// The signature blob is labelled with another scheme than the one
    /// negotiated. Detected before any cryptographic work.
    UnexpectedSignatureAlgorithm {
        /// The negotiated scheme.
        expected: &'static [u8],
        /// The label in the signature blob.
        found: Vec<u8>,
    },
    /// The signature blob is malformed or has the wrong length.
    MalformedSignature(KeyError),
    /// The scheme needs a host signature provider and none that supports it
    /// was supplied.
    ProviderUnavailable {
        /// The scheme.
        scheme: &'static [u8],
    },
    /// The signature is well-formed but does not verify for this key and
    /// message.
    Invalid,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::AlgorithmMismatch {
                key_algorithm,
                signature_algorithm,
            } => write!(
                f,
                "signature algorithm {} does not match key algorithm {}",
                Escaped(signature_algorithm),
                Escaped(key_algorithm)
            ),
            VerifyError::UnexpectedSignatureAlgorithm { expected, found } => write!(
                f,
                "signature is labelled {}, but {} was negotiated",
                Escaped(found),
                Escaped(expected)
            ),
            VerifyError::MalformedSignature(e) => write!(f, "malformed signature: {e}"),
            VerifyError::ProviderUnavailable { scheme } => write!(
                f,
                "no signature provider for {} in this build",
                Escaped(scheme)
            ),
            VerifyError::Invalid => f.write_str("signature does not verify"),
        }
    }
}

impl core::error::Error for VerifyError {}

/// Renders peer-supplied name bytes for messages: printable ASCII verbatim,
/// everything else as `\xNN`, so a hostile name cannot inject control
/// characters into a log line.
struct Escaped<'a>(&'a [u8]);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("`")?;
        for &b in self.0 {
            if (0x20..0x7f).contains(&b) && b != b'`' && b != b'\\' {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\x{b:02x}")?;
            }
        }
        f.write_str("`")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn unsupported_algorithm_is_escaped_in_messages() {
        let e = KeyError::UnsupportedAlgorithm(b"ssh-rsa\n\x00`".to_vec());
        assert_eq!(
            format!("{e}"),
            "unsupported algorithm `ssh-rsa\\x0a\\x00\\x60`"
        );
    }

    #[test]
    fn mismatch_message_names_both_algorithms() {
        let e = VerifyError::AlgorithmMismatch {
            key_algorithm: b"ssh-ed25519".to_vec(),
            signature_algorithm: b"ssh-rsa".to_vec(),
        };
        assert_eq!(
            format!("{e}"),
            "signature algorithm `ssh-rsa` does not match key algorithm `ssh-ed25519`"
        );
    }
}
