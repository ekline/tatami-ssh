//! Error types for blob parsing, key construction and verification.

use alloc::vec::Vec;
use core::fmt;

use tatami_wire::DecodeError;

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
    /// The signature blob is malformed or has the wrong length.
    MalformedSignature(KeyError),
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
            VerifyError::MalformedSignature(e) => write!(f, "malformed signature: {e}"),
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
