//! `ssh-rsa` host keys with RSA/SHA-2 signatures (RFC 8332) — parsing,
//! policy and signature preparation. Feature `rsa`.
//!
//! The mathematical check is delegated to a host
//! [`SignatureProvider`]; this module
//! does everything before it, so no peer-controlled size reaches the
//! provider unchecked:
//!
//! - **Blob** (RFC 4253 §6.6): `string "ssh-rsa", mpint e, mpint n`, with
//!   nothing after `n`. Both integers must be positive, non-zero and in the
//!   minimal `mpint` encoding.
//! - **Policy**: the modulus is odd and 2048–8192 bits long (counted from
//!   its top set bit); the public exponent is odd, at least 3 and at most
//!   four bytes. Keys outside the policy are rejected when parsed, before
//!   any provider work, and so can never be verified or trusted.
//! - **Signatures**: `string "rsa-sha2-256" | "rsa-sha2-512", string S`.
//!   The label must be the negotiated scheme (checked by
//!   [`crate::host_key::HostKey::verify`]); `ssh-rsa` (RSA/SHA-1) is never a
//!   scheme. `S` is RSASSA-PKCS1-v1_5, not RSA-PSS. It must not be longer
//!   than the modulus. RFC 8332 §3 lets a verifier accept an `S` whose
//!   leading zero octets were omitted; Tatami does (OpenSSH does too), by
//!   left-padding with zeros to the modulus length. An empty `S` is
//!   malformed. Nothing is ever truncated.

use alloc::vec::Vec;

use tatami_ssh_wire::primitives::mpint_positive_len;
use tatami_ssh_wire::{Reader, Writer, algorithms};

use crate::blob::{PublicKeyBlob, field, finish, positive_mpint};
use crate::error::{KeyError, VerifyError};
use crate::provider::{ProviderRequest, RsaHash, SignatureProvider};

/// Smallest accepted modulus, in bits.
pub const MIN_MODULUS_BITS: usize = 2048;
/// Largest accepted modulus, in bits.
pub const MAX_MODULUS_BITS: usize = 8192;
/// Longest accepted public exponent, in bytes (`e < 2^32`).
pub const MAX_EXPONENT_BYTES: usize = 4;

/// A validated RSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// Big-endian magnitude, no leading zero.
    e: Vec<u8>,
    /// Big-endian magnitude, no leading zero.
    n: Vec<u8>,
}

impl core::fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("modulus_bits", &self.modulus_bits())
            .field("exponent", &self.e)
            .finish()
    }
}

/// Bit length of a magnitude with no leading zero byte.
fn bit_len(magnitude: &[u8]) -> usize {
    match magnitude.first() {
        None => 0,
        Some(&top) => (magnitude.len() - 1) * 8 + (8 - top.leading_zeros() as usize),
    }
}

impl RsaPublicKey {
    /// Applies the key policy to big-endian magnitudes (leading zero bytes
    /// are not accepted: pass minimal encodings).
    pub fn from_components(exponent: &[u8], modulus: &[u8]) -> Result<Self, KeyError> {
        if exponent.first() == Some(&0) || modulus.first() == Some(&0) {
            return Err(KeyError::NonCanonicalInteger {
                field: if exponent.first() == Some(&0) {
                    "e"
                } else {
                    "n"
                },
            });
        }
        if exponent.is_empty()
            || exponent.len() > MAX_EXPONENT_BYTES
            || exponent.last().is_some_and(|b| b & 1 == 0)
            || (exponent.len() == 1 && exponent[0] < 3)
        {
            return Err(KeyError::RsaExponent);
        }
        let bits = bit_len(modulus);
        if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits)
            || modulus.last().is_some_and(|b| b & 1 == 0)
        {
            return Err(KeyError::RsaModulus { bits });
        }
        Ok(RsaPublicKey {
            e: exponent.to_vec(),
            n: modulus.to_vec(),
        })
    }

    /// Parses an `ssh-rsa` blob strictly and applies the key policy.
    pub fn from_blob(blob: &PublicKeyBlob<'_>) -> Result<Self, KeyError> {
        if blob.algorithm != algorithms::SSH_RSA {
            return Err(KeyError::UnsupportedAlgorithm(blob.algorithm.to_vec()));
        }
        let mut r = Reader::new(blob.as_bytes());
        let _algorithm = field(&mut r, "algorithm", Reader::read_string)?;
        let e = positive_mpint(&mut r, "e")?;
        let n = positive_mpint(&mut r, "n")?;
        finish(&r)?;
        Self::from_components(e, n)
    }

    /// Modulus `n`, big-endian, no leading zero.
    #[must_use]
    pub fn modulus(&self) -> &[u8] {
        &self.n
    }

    /// Public exponent `e`, big-endian, no leading zero.
    #[must_use]
    pub fn exponent(&self) -> &[u8] {
        &self.e
    }

    /// Modulus size in bits.
    #[must_use]
    pub fn modulus_bits(&self) -> usize {
        bit_len(&self.n)
    }

    /// The canonical `ssh-rsa` blob.
    #[must_use]
    pub fn to_blob(&self) -> Vec<u8> {
        let len = 4
            + algorithms::SSH_RSA.len()
            + mpint_positive_len(&self.e)
            + mpint_positive_len(&self.n);
        let mut out = alloc::vec![0u8; len];
        let mut w = Writer::new(&mut out);
        // The buffer is sized exactly; none of these can fail.
        let ok = w
            .write_string(algorithms::SSH_RSA)
            .and_then(|()| w.write_mpint_positive(&self.e))
            .and_then(|()| w.write_mpint_positive(&self.n));
        debug_assert!(ok.is_ok() && w.position() == len);
        out
    }

    /// Checks the RSA `signature` bytes (the inner `string` of the
    /// signature blob) over `message` through `provider`.
    pub(crate) fn verify(
        &self,
        hash: RsaHash,
        message: &[u8],
        signature: &[u8],
        provider: &dyn SignatureProvider,
    ) -> Result<(), VerifyError> {
        let k = self.n.len();
        if signature.is_empty() || signature.len() > k {
            return Err(VerifyError::MalformedSignature(KeyError::WrongLength {
                field: "signature",
                expected: k,
                found: signature.len(),
            }));
        }
        // RFC 8332 §3: accept an S with omitted leading zero octets by
        // restoring them.
        let mut padded = alloc::vec![0u8; k];
        padded[k - signature.len()..].copy_from_slice(signature);
        provider
            .verify(
                message,
                &ProviderRequest::RsaPkcs1v15 {
                    hash,
                    modulus: &self.n,
                    exponent: &self.e,
                    signature: &padded,
                },
            )
            .map_err(|_| VerifyError::Invalid)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn blob_with(e: &[u8], n: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [algorithms::SSH_RSA, e, n] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    /// An odd modulus magnitude of exactly `bits` bits (not a real key:
    /// the policy and encodings do not depend on primality).
    pub(crate) fn modulus(bits: usize) -> Vec<u8> {
        let bytes = bits.div_ceil(8);
        let mut n = alloc::vec![0x5au8; bytes];
        n[0] = 1u8 << (bits - (bytes - 1) * 8 - 1);
        n[bytes - 1] |= 1;
        n
    }

    pub(crate) fn mpint_body(magnitude: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        if magnitude.first().is_some_and(|b| b & 0x80 != 0) {
            v.push(0);
        }
        v.extend_from_slice(magnitude);
        v
    }

    fn parse(blob: &[u8]) -> Result<RsaPublicKey, KeyError> {
        RsaPublicKey::from_blob(&PublicKeyBlob::decode(blob).unwrap())
    }

    #[test]
    fn policy_bounds() {
        let e = [1, 0, 1];
        for bits in [2048usize, 3072, 4096, 8192, 2049, 8191] {
            let n = modulus(bits);
            let key = parse(&blob_with(&e, &mpint_body(&n))).unwrap();
            assert_eq!(key.modulus_bits(), bits, "{bits}");
            assert_eq!(key.to_blob(), blob_with(&e, &mpint_body(&n)));
        }
        for bits in [1024usize, 2047, 8193, 16384] {
            let n = modulus(bits);
            assert_eq!(
                parse(&blob_with(&e, &mpint_body(&n))),
                Err(KeyError::RsaModulus { bits }),
                "{bits}"
            );
        }
        // Even modulus.
        let mut n = modulus(2048);
        let last = n.len() - 1;
        n[last] &= 0xfe;
        assert_eq!(
            parse(&blob_with(&e, &mpint_body(&n))),
            Err(KeyError::RsaModulus { bits: 2048 })
        );
    }

    #[test]
    fn exponent_policy() {
        let n = mpint_body(&modulus(2048));
        for good in [&[3u8][..], &[1, 0, 1], &[0x7f, 0xff, 0xff, 0xff]] {
            assert!(parse(&blob_with(good, &n)).is_ok(), "{good:?}");
        }
        for bad in [
            &[1u8][..],
            &[2],
            &[1, 0, 0],
            &[0x01, 0x00, 0x00, 0x00, 0x01],
        ] {
            assert_eq!(
                parse(&blob_with(bad, &n)),
                Err(KeyError::RsaExponent),
                "{bad:?}"
            );
        }
        // The bound is on the magnitude: a four-byte exponent with its high
        // bit set is encoded in five mpint bytes and still accepted.
        let key = parse(&blob_with(&[0x00, 0x80, 0, 0, 1], &n)).unwrap();
        assert_eq!(key.exponent(), &[0x80, 0, 0, 1]);
    }

    #[test]
    fn integers_must_be_strict() {
        let n = mpint_body(&modulus(2048));
        // Redundant leading zero on e, negative e, zero e.
        for (e, field) in [(&[0u8, 1, 0, 1][..], "e"), (&[0x81], "e"), (&[], "e")] {
            assert_eq!(
                parse(&blob_with(e, &n)),
                Err(KeyError::NonCanonicalInteger { field }),
                "{e:?}"
            );
        }
        // Modulus with its required leading zero removed is negative.
        let raw = modulus(2048);
        assert_eq!(
            parse(&blob_with(&[1, 0, 1], &raw)),
            Err(KeyError::NonCanonicalInteger { field: "n" })
        );
        // Two leading zeros.
        let mut two = alloc::vec![0u8];
        two.extend_from_slice(&n);
        assert_eq!(
            parse(&blob_with(&[1, 0, 1], &two)),
            Err(KeyError::NonCanonicalInteger { field: "n" })
        );
        // Trailing bytes and truncation.
        let mut t = blob_with(&[1, 0, 1], &n);
        t.push(0);
        assert!(matches!(
            parse(&t),
            Err(KeyError::Blob(crate::error::BlobError::TrailingBytes {
                count: 1
            }))
        ));
        let full = blob_with(&[1, 0, 1], &n);
        assert!(matches!(
            parse(&full[..full.len() - 1]),
            Err(KeyError::Blob(_))
        ));
        // Wrong algorithm name.
        assert_eq!(
            RsaPublicKey::from_blob(
                &PublicKeyBlob::decode(&crate::blob::fixtures::test1_key_blob()).unwrap()
            ),
            Err(KeyError::UnsupportedAlgorithm(b"ssh-ed25519".to_vec()))
        );
    }

    #[test]
    fn components_reject_leading_zeros() {
        let n = modulus(2048);
        assert!(RsaPublicKey::from_components(&[1, 0, 1], &n).is_ok());
        assert_eq!(
            RsaPublicKey::from_components(&[0, 1, 0, 1], &n),
            Err(KeyError::NonCanonicalInteger { field: "e" })
        );
        let mut z = alloc::vec![0u8];
        z.extend_from_slice(&n);
        assert_eq!(
            RsaPublicKey::from_components(&[1, 0, 1], &z),
            Err(KeyError::NonCanonicalInteger { field: "n" })
        );
    }

    struct Recorder(core::cell::RefCell<Vec<Vec<u8>>>);

    impl SignatureProvider for Recorder {
        fn supports(&self, _: crate::algorithm::SignatureScheme) -> bool {
            true
        }
        fn verify(
            &self,
            _message: &[u8],
            request: &ProviderRequest<'_>,
        ) -> Result<(), crate::provider::ProviderRejected> {
            match request {
                ProviderRequest::RsaPkcs1v15 { signature, .. } => {
                    self.0.borrow_mut().push(signature.to_vec());
                    Ok(())
                }
                ProviderRequest::EcdsaP256Sha256 { .. } => Err(crate::provider::ProviderRejected),
            }
        }
    }

    #[test]
    fn signatures_are_padded_never_truncated() {
        let key = parse(&blob_with(&[1, 0, 1], &mpint_body(&modulus(2048)))).unwrap();
        let rec = Recorder(core::cell::RefCell::new(Vec::new()));
        let full = alloc::vec![0x11u8; 256];
        key.verify(RsaHash::Sha256, b"m", &full, &rec).unwrap();
        let short = alloc::vec![0x22u8; 254];
        key.verify(RsaHash::Sha512, b"m", &short, &rec).unwrap();
        let seen = rec.0.borrow();
        assert_eq!(seen[0], full);
        assert_eq!(seen[1].len(), 256);
        assert_eq!(&seen[1][..2], &[0, 0]);
        assert_eq!(&seen[1][2..], &short[..]);
        drop(seen);
        for bad in [0usize, 257] {
            assert_eq!(
                key.verify(RsaHash::Sha256, b"m", &alloc::vec![0u8; bad], &rec),
                Err(VerifyError::MalformedSignature(KeyError::WrongLength {
                    field: "signature",
                    expected: 256,
                    found: bad
                })),
                "{bad}"
            );
        }
        assert_eq!(
            rec.0.borrow().len(),
            2,
            "rejected sizes never reach the provider"
        );
    }
}
