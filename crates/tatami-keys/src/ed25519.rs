//! `ssh-ed25519` host keys and signatures (RFC 8709) — verification only.
//!
//! Cryptography is delegated to `ed25519-dalek` and never re-implemented:
//! keys are parsed with `VerifyingKey::from_bytes` and signatures checked
//! with `verify_strict`, which rejects non-canonical encodings and small-
//! order components that the plain `verify` would accept.
//!
//! Nothing here handles private keys, signing, or any other algorithm.
//! A successful verification proves that the holder of the private key for
//! `K_S` signed the exchange hash; it says nothing about whether `K_S` is the
//! key the user expects. That is a separate decision made through
//! [`crate::trust`].

use ed25519_dalek::{Signature, VerifyingKey};
use tatami_wire::{EncodeError, Reader};

use crate::blob::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, PublicKeyBlob, SSH_ED25519, SignatureBlob,
    encode_ed25519_blob, field, finish,
};
use crate::error::{KeyError, VerifyError};

/// A validated Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519PublicKey {
    key: VerifyingKey,
}

impl Ed25519PublicKey {
    /// Validates 32 key bytes as a canonical point on the curve.
    pub fn from_bytes(bytes: &[u8; ED25519_PUBLIC_KEY_LEN]) -> Result<Self, KeyError> {
        VerifyingKey::from_bytes(bytes)
            .map(|key| Ed25519PublicKey { key })
            .map_err(|_| KeyError::InvalidKey)
    }

    /// Parses an `ssh-ed25519` public-key blob (RFC 8709 §4): the algorithm
    /// must be `ssh-ed25519`, the body exactly one 32-byte `string key`
    /// with nothing after it.
    pub fn from_blob(blob: &PublicKeyBlob<'_>) -> Result<Self, KeyError> {
        if blob.algorithm != SSH_ED25519 {
            return Err(KeyError::UnsupportedAlgorithm(blob.algorithm.to_vec()));
        }
        // Offsets reported relative to the whole blob, not the body.
        let mut r = Reader::new(blob.as_bytes());
        let _algorithm = field(&mut r, "algorithm", Reader::read_string)?;
        let key = field(&mut r, "key", Reader::read_string)?;
        finish(&r)?;
        let key: &[u8; ED25519_PUBLIC_KEY_LEN] =
            key.try_into().map_err(|_| KeyError::WrongLength {
                field: "key",
                expected: ED25519_PUBLIC_KEY_LEN,
                found: key.len(),
            })?;
        Self::from_bytes(key)
    }

    /// The compressed point encoding (RFC 8032 §5.1.2).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LEN] {
        self.key.as_bytes()
    }

    /// Encodes the `ssh-ed25519` public-key blob for this key into `out`.
    pub fn encode_blob(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        encode_ed25519_blob(self.as_bytes(), out)
    }

    /// Verifies `sig` over `message` with `verify_strict`.
    pub fn verify(&self, message: &[u8], sig: &Ed25519Signature) -> Result<(), VerifyError> {
        self.key
            .verify_strict(message, &sig.sig)
            .map_err(|_| VerifyError::Invalid)
    }
}

/// A 64-byte Ed25519 signature.
///
/// Construction checks only the length; validity is decided by
/// [`Ed25519PublicKey::verify`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Signature {
    sig: Signature,
}

impl Ed25519Signature {
    /// Wraps raw signature bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; ED25519_SIGNATURE_LEN]) -> Self {
        Ed25519Signature {
            sig: Signature::from_bytes(bytes),
        }
    }

    /// Parses an `ssh-ed25519` signature blob (RFC 8709 §6): the algorithm
    /// must be `ssh-ed25519` and the signature exactly 64 bytes.
    pub fn from_blob(blob: &SignatureBlob<'_>) -> Result<Self, KeyError> {
        if blob.algorithm != SSH_ED25519 {
            return Err(KeyError::UnsupportedAlgorithm(blob.algorithm.to_vec()));
        }
        let bytes: &[u8; ED25519_SIGNATURE_LEN] =
            blob.signature
                .try_into()
                .map_err(|_| KeyError::WrongLength {
                    field: "signature",
                    expected: ED25519_SIGNATURE_LEN,
                    found: blob.signature.len(),
                })?;
        Ok(Self::from_bytes(bytes))
    }

    /// The raw `R || S` bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ED25519_SIGNATURE_LEN] {
        self.sig.to_bytes()
    }
}

/// A server host key of a supported algorithm.
///
/// Only `ssh-ed25519` exists in this profile; other blobs are reported as
/// [`KeyError::UnsupportedAlgorithm`] with the name preserved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKey {
    /// An `ssh-ed25519` key (RFC 8709).
    Ed25519(Ed25519PublicKey),
}

impl HostKey {
    /// Interprets a parsed public-key blob.
    pub fn from_blob(blob: &PublicKeyBlob<'_>) -> Result<Self, KeyError> {
        if blob.algorithm == SSH_ED25519 {
            Ed25519PublicKey::from_blob(blob).map(HostKey::Ed25519)
        } else {
            Err(KeyError::UnsupportedAlgorithm(blob.algorithm.to_vec()))
        }
    }

    /// Decodes and interprets raw blob bytes (`K_S`).
    pub fn parse(blob: &[u8]) -> Result<Self, KeyError> {
        Self::from_blob(&PublicKeyBlob::decode(blob)?)
    }

    /// The public-key algorithm name of this key.
    #[must_use]
    pub const fn algorithm(&self) -> &'static [u8] {
        match self {
            HostKey::Ed25519(_) => SSH_ED25519,
        }
    }

    /// Verifies a signature blob over `message`.
    ///
    /// The signature blob's algorithm must equal the key's; a mismatch is
    /// reported as [`VerifyError::AlgorithmMismatch`] before the signature
    /// bytes are looked at, so a peer cannot make the verifier interpret
    /// bytes under an algorithm the key was not published for.
    pub fn verify_signature_blob(
        &self,
        message: &[u8],
        sig: &SignatureBlob<'_>,
    ) -> Result<(), VerifyError> {
        if sig.algorithm != self.algorithm() {
            return Err(VerifyError::AlgorithmMismatch {
                key_algorithm: self.algorithm().to_vec(),
                signature_algorithm: sig.algorithm.to_vec(),
            });
        }
        match self {
            HostKey::Ed25519(key) => {
                let sig =
                    Ed25519Signature::from_blob(sig).map_err(VerifyError::MalformedSignature)?;
                key.verify(message, &sig)
            }
        }
    }

    /// Encodes the public-key blob for this key into `out`.
    pub fn encode_blob(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        match self {
            HostKey::Ed25519(key) => key.encode_blob(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::fixtures::*;
    use crate::error::BlobError;
    use tatami_wire::DecodeError;

    fn key(bytes: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes(bytes).unwrap()
    }

    #[test]
    fn rfc8032_vectors_verify() {
        key(&TEST1_PUBLIC_KEY)
            .verify(&[], &Ed25519Signature::from_bytes(&TEST1_SIGNATURE))
            .unwrap();
        key(&TEST2_PUBLIC_KEY)
            .verify(
                &TEST2_MESSAGE,
                &Ed25519Signature::from_bytes(&TEST2_SIGNATURE),
            )
            .unwrap();
        key(&TEST3_PUBLIC_KEY)
            .verify(
                &TEST3_MESSAGE,
                &Ed25519Signature::from_bytes(&TEST3_SIGNATURE),
            )
            .unwrap();
    }

    #[test]
    fn flipped_bit_wrong_message_and_wrong_key_are_invalid() {
        let k1 = key(&TEST1_PUBLIC_KEY);
        let sig1 = Ed25519Signature::from_bytes(&TEST1_SIGNATURE);

        // One bit flipped in R and one in S, separately.
        for index in [0usize, 63] {
            let mut bad = TEST1_SIGNATURE;
            bad[index] ^= 0x01;
            assert_eq!(
                k1.verify(&[], &Ed25519Signature::from_bytes(&bad)),
                Err(VerifyError::Invalid),
                "flip at {index}"
            );
        }
        // Wrong message (RFC 8032 Appendix B uses "x" for the empty case).
        assert_eq!(k1.verify(b"x", &sig1), Err(VerifyError::Invalid));
        // Right message, wrong key.
        assert_eq!(
            key(&TEST2_PUBLIC_KEY).verify(&[], &sig1),
            Err(VerifyError::Invalid)
        );
        // TEST 2's signature does not verify under TEST 1's key.
        assert_eq!(
            k1.verify(
                &TEST2_MESSAGE,
                &Ed25519Signature::from_bytes(&TEST2_SIGNATURE)
            ),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn invalid_point_is_rejected_at_construction() {
        // y = 2 (little-endian, sign bit clear): (y^2 - 1) / (d y^2 + 1) is
        // not a square mod p, so no x exists and decoding fails at RFC 8032
        // §5.1.3 step 3. Found by running the RFC's reference `recover_x`
        // over small y; y = 2 is the first that fails.
        let mut y2 = [0u8; 32];
        y2[0] = 0x02;
        assert_eq!(Ed25519PublicKey::from_bytes(&y2), Err(KeyError::InvalidKey));

        // The same bytes inside a well-formed blob are rejected the same way,
        // after the length check passed.
        assert_eq!(HostKey::parse(&key_blob(&y2)), Err(KeyError::InvalidKey));
    }

    #[test]
    fn key_blob_wrappers() {
        let blob = test1_key_blob();
        let parsed = PublicKeyBlob::decode(&blob).unwrap();
        let k = Ed25519PublicKey::from_blob(&parsed).unwrap();
        assert_eq!(k.as_bytes(), &TEST1_PUBLIC_KEY);

        let mut out = [0u8; 51];
        assert_eq!(k.encode_blob(&mut out).unwrap(), 51);
        assert_eq!(out, blob);

        let host = HostKey::parse(&blob).unwrap();
        assert_eq!(host, HostKey::Ed25519(k));
        assert_eq!(host.algorithm(), b"ssh-ed25519");
        let mut out = [0u8; 51];
        assert_eq!(host.encode_blob(&mut out).unwrap(), 51);
        assert_eq!(out, blob);
    }

    #[test]
    fn signature_blob_wrappers_verify_rfc_vectors() {
        let host = HostKey::parse(&test1_key_blob()).unwrap();
        let sig = sig_blob(&TEST1_SIGNATURE);
        host.verify_signature_blob(&[], &SignatureBlob::decode(&sig).unwrap())
            .unwrap();

        let host3 = HostKey::parse(&key_blob(&TEST3_PUBLIC_KEY)).unwrap();
        let sig3 = sig_blob(&TEST3_SIGNATURE);
        host3
            .verify_signature_blob(&TEST3_MESSAGE, &SignatureBlob::decode(&sig3).unwrap())
            .unwrap();
        assert_eq!(
            host3.verify_signature_blob(&TEST2_MESSAGE, &SignatureBlob::decode(&sig3).unwrap()),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn unsupported_key_algorithm_keeps_the_name() {
        // string "ssh-rsa" with an ed25519-shaped body.
        let mut blob = [0u8; 47];
        blob[..11].copy_from_slice(&[0, 0, 0, 7, b's', b's', b'h', b'-', b'r', b's', b'a']);
        blob[11..15].copy_from_slice(&[0, 0, 0, 32]);
        blob[15..].copy_from_slice(&TEST1_PUBLIC_KEY);
        let parsed = PublicKeyBlob::decode(&blob).unwrap();
        assert_eq!(
            HostKey::from_blob(&parsed),
            Err(KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec()))
        );
        assert_eq!(
            Ed25519PublicKey::from_blob(&parsed),
            Err(KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec()))
        );
    }

    #[test]
    fn algorithm_mismatch_is_detected_before_signature_bytes() {
        let host = HostKey::parse(&test1_key_blob()).unwrap();
        // "ssh-rsa" signature blob carrying a 3-byte signature: if length
        // were checked first this would be WrongLength, not a mismatch.
        let rsa_sig = SignatureBlob {
            algorithm: b"ssh-rsa",
            signature: b"abc",
        };
        assert_eq!(
            host.verify_signature_blob(&[], &rsa_sig),
            Err(VerifyError::AlgorithmMismatch {
                key_algorithm: b"ssh-ed25519".to_vec(),
                signature_algorithm: b"ssh-rsa".to_vec(),
            })
        );
        // An ed25519 signature blob under an ssh-rsa key never gets this far:
        // the key itself is unsupported.
        assert!(matches!(
            Ed25519Signature::from_blob(&rsa_sig),
            Err(KeyError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn trailing_bytes_in_key_blob_are_rejected() {
        let mut blob = [0u8; 52];
        blob[..51].copy_from_slice(&test1_key_blob());
        let parsed = PublicKeyBlob::decode(&blob).unwrap();
        assert_eq!(parsed.body.len(), 37, "PublicKeyBlob itself keeps the tail");
        assert_eq!(
            Ed25519PublicKey::from_blob(&parsed),
            Err(KeyError::Blob(BlobError::TrailingBytes { count: 1 }))
        );
        assert_eq!(
            HostKey::parse(&blob),
            Err(KeyError::Blob(BlobError::TrailingBytes { count: 1 }))
        );
    }

    #[test]
    fn wrong_key_lengths_are_rejected() {
        for found in [31usize, 33] {
            let mut blob = [0u8; 15 + 4 + 33];
            blob[..15].copy_from_slice(&ALG_PREFIX);
            blob[15..19].copy_from_slice(&(found as u32).to_be_bytes());
            let blob = &blob[..19 + found];
            assert_eq!(
                HostKey::parse(blob),
                Err(KeyError::WrongLength {
                    field: "key",
                    expected: 32,
                    found
                }),
                "{found} bytes"
            );
        }
        // Missing key string entirely.
        assert_eq!(
            HostKey::parse(&ALG_PREFIX),
            Err(KeyError::Blob(BlobError::Field {
                field: "key",
                offset: 15,
                error: DecodeError::Truncated {
                    needed: 4,
                    available: 0
                }
            }))
        );
    }

    #[test]
    fn wrong_signature_lengths_are_rejected() {
        let host = HostKey::parse(&test1_key_blob()).unwrap();
        for found in [0usize, 63, 65] {
            let sig_bytes = [0u8; 65];
            let sig = SignatureBlob {
                algorithm: b"ssh-ed25519",
                signature: &sig_bytes[..found],
            };
            assert_eq!(
                host.verify_signature_blob(&[], &sig),
                Err(VerifyError::MalformedSignature(KeyError::WrongLength {
                    field: "signature",
                    expected: 64,
                    found
                })),
                "{found} bytes"
            );
        }
        // Trailing bytes in the signature blob are caught by the blob codec.
        let mut blob = [0u8; 84];
        blob[..83].copy_from_slice(&sig_blob(&TEST1_SIGNATURE));
        assert_eq!(
            SignatureBlob::decode(&blob),
            Err(BlobError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn signature_bytes_round_trip() {
        let s = Ed25519Signature::from_bytes(&TEST2_SIGNATURE);
        assert_eq!(s.to_bytes(), TEST2_SIGNATURE);
    }
}
