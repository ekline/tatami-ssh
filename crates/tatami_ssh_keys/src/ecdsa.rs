//! `ecdsa-sha2-nistp256` host keys and signatures (RFC 5656) — parsing
//! and signature preparation. Feature `ecdsa-p256`.
//!
//! - **Blob** (RFC 5656 §3.1): `string "ecdsa-sha2-nistp256",
//!   string "nistp256", string Q`, nothing after `Q`. The curve identifier
//!   must match the algorithm name, and `Q` must be the 65-byte SEC1
//!   uncompressed encoding `04 || X || Y` (the only form OpenSSH writes;
//!   compressed points are rejected).
//! - **Signature** (RFC 5656 §3.1.2): `string "ecdsa-sha2-nistp256",
//!   string (mpint r || mpint s)`, with nothing after `s`. `r` and `s` must
//!   be strict, positive, non-zero `mpint`s of at most 32 magnitude bytes;
//!   they are left-padded into the fixed `r || s` form for the provider.
//!   This is not the DER `ECDSA-Sig-Value` TLS uses.
//! - **Left to the provider**: whether `Q` is on the curve (and not the
//!   point at infinity) and whether `r`, `s` lie below the group order.
//!   No low-S rule is imposed: OpenSSH signatures are not normalised, and
//!   rejecting high-S would refuse valid peers.
//!
//! Because point validity is decided by the provider when a signature is
//! checked, an off-curve key parses here but can never verify, and so can
//! never complete a handshake.

use alloc::vec::Vec;

use tatami_ssh_wire::{Reader, Writer, algorithms};

use crate::blob::{PublicKeyBlob, field, finish, positive_mpint};
use crate::error::{KeyError, VerifyError};
use crate::provider::{ProviderRequest, SignatureProvider};

/// Length of a SEC1 uncompressed P-256 point.
pub const P256_POINT_LEN: usize = 65;
/// Length of a P-256 scalar (and of `r`, `s`).
pub const P256_SCALAR_LEN: usize = 32;
/// Encoded length of an `ecdsa-sha2-nistp256` blob.
pub const P256_BLOB_LEN: usize = 4 + 19 + 4 + 8 + 4 + P256_POINT_LEN;

/// A structurally valid P-256 public key (see the module notes on point
/// validation).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EcdsaP256PublicKey {
    point: [u8; P256_POINT_LEN],
}

impl core::fmt::Debug for EcdsaP256PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EcdsaP256PublicKey(")?;
        for b in &self.point {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

impl EcdsaP256PublicKey {
    /// Accepts exactly a 65-byte `04 || X || Y` encoding.
    pub fn from_point(point: &[u8]) -> Result<Self, KeyError> {
        let point: [u8; P256_POINT_LEN] = point.try_into().map_err(|_| KeyError::PointEncoding)?;
        if point[0] != 0x04 {
            return Err(KeyError::PointEncoding);
        }
        Ok(EcdsaP256PublicKey { point })
    }

    /// Parses an `ecdsa-sha2-nistp256` blob strictly.
    pub fn from_blob(blob: &PublicKeyBlob<'_>) -> Result<Self, KeyError> {
        if blob.algorithm != algorithms::ECDSA_SHA2_NISTP256 {
            return Err(KeyError::UnsupportedAlgorithm(blob.algorithm.to_vec()));
        }
        let mut r = Reader::new(blob.as_bytes());
        let _algorithm = field(&mut r, "algorithm", Reader::read_string)?;
        let curve = field(&mut r, "curve", Reader::read_string)?;
        let q = field(&mut r, "Q", Reader::read_string)?;
        finish(&r)?;
        if curve != algorithms::NISTP256 {
            return Err(KeyError::CurveMismatch);
        }
        Self::from_point(q)
    }

    /// The SEC1 uncompressed point.
    #[must_use]
    pub fn point(&self) -> &[u8; P256_POINT_LEN] {
        &self.point
    }

    /// The canonical `ecdsa-sha2-nistp256` blob.
    #[must_use]
    pub fn to_blob(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; P256_BLOB_LEN];
        let mut w = Writer::new(&mut out);
        let ok = w
            .write_string(algorithms::ECDSA_SHA2_NISTP256)
            .and_then(|()| w.write_string(algorithms::NISTP256))
            .and_then(|()| w.write_string(&self.point));
        debug_assert!(ok.is_ok() && w.position() == P256_BLOB_LEN);
        out
    }

    /// Checks the inner signature bytes (`mpint r || mpint s`) over
    /// `message` through `provider`.
    pub(crate) fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        provider: &dyn SignatureProvider,
    ) -> Result<(), VerifyError> {
        let rs = fixed_signature(signature).map_err(VerifyError::MalformedSignature)?;
        provider
            .verify(
                message,
                &ProviderRequest::EcdsaP256Sha256 {
                    public_point: &self.point,
                    signature: &rs,
                },
            )
            .map_err(|_| VerifyError::Invalid)
    }
}

/// `mpint r || mpint s` (RFC 5656 §3.1.2) to fixed-width `r || s`.
pub fn fixed_signature(inner: &[u8]) -> Result<[u8; 2 * P256_SCALAR_LEN], KeyError> {
    let mut rd = Reader::new(inner);
    let r = positive_mpint(&mut rd, "r")?;
    let s = positive_mpint(&mut rd, "s")?;
    finish(&rd)?;
    let mut out = [0u8; 2 * P256_SCALAR_LEN];
    for (value, name, half) in [(r, "r", 0usize), (s, "s", 1)] {
        if value.len() > P256_SCALAR_LEN {
            return Err(KeyError::ScalarTooLong { field: name });
        }
        let end = (half + 1) * P256_SCALAR_LEN;
        out[end - value.len()..end].copy_from_slice(value);
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::error::BlobError;

    pub(crate) fn blob_parts(alg: &[u8], curve: &[u8], q: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for part in [alg, curve, q] {
            out.extend_from_slice(&(part.len() as u32).to_be_bytes());
            out.extend_from_slice(part);
        }
        out
    }

    fn point() -> [u8; 65] {
        let mut p = [0x33u8; 65];
        p[0] = 4;
        p
    }

    fn parse(blob: &[u8]) -> Result<EcdsaP256PublicKey, KeyError> {
        EcdsaP256PublicKey::from_blob(&PublicKeyBlob::decode(blob).unwrap())
    }

    #[test]
    fn blob_round_trip_and_strictness() {
        let good = blob_parts(b"ecdsa-sha2-nistp256", b"nistp256", &point());
        assert_eq!(good.len(), P256_BLOB_LEN);
        let key = parse(&good).unwrap();
        assert_eq!(key.to_blob(), good);
        assert_eq!(key.point(), &point());

        for curve in [&b"nistp384"[..], b"NISTP256", b"", b"secp256r1"] {
            assert_eq!(
                parse(&blob_parts(b"ecdsa-sha2-nistp256", curve, &point())),
                Err(KeyError::CurveMismatch)
            );
        }
        let mut compressed = [0u8; 33];
        compressed[0] = 2;
        for q in [&compressed[..], &point()[..64], &[0u8; 65][..], &[]] {
            assert_eq!(
                parse(&blob_parts(b"ecdsa-sha2-nistp256", b"nistp256", q)),
                Err(KeyError::PointEncoding)
            );
        }
        let mut t = good.clone();
        t.push(0);
        assert_eq!(
            parse(&t),
            Err(KeyError::Blob(BlobError::TrailingBytes { count: 1 }))
        );
        assert!(matches!(
            parse(&good[..good.len() - 1]),
            Err(KeyError::Blob(_))
        ));
        assert_eq!(
            parse(&blob_parts(b"ecdsa-sha2-nistp384", b"nistp256", &point())),
            Err(KeyError::UnsupportedAlgorithm(
                b"ecdsa-sha2-nistp384".to_vec()
            ))
        );
    }

    pub(crate) fn mpint(m: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let pad = m.first().is_some_and(|b| b & 0x80 != 0);
        out.extend_from_slice(&((m.len() + usize::from(pad)) as u32).to_be_bytes());
        if pad {
            out.push(0);
        }
        out.extend_from_slice(m);
        out
    }

    #[test]
    fn signature_components_are_strict_and_padded() {
        let r = [0x80u8; 32];
        let s = [0x01u8; 31];
        let inner = [mpint(&r), mpint(&s)].concat();
        let fixed = fixed_signature(&inner).unwrap();
        assert_eq!(&fixed[..32], &r);
        assert_eq!(fixed[32], 0);
        assert_eq!(&fixed[33..], &s);

        // Zero, negative, non-minimal, too wide, trailing, truncated.
        let zero = [0u8, 0, 0, 0];
        assert_eq!(
            fixed_signature(&[zero.to_vec(), mpint(&s)].concat()),
            Err(KeyError::NonCanonicalInteger { field: "r" })
        );
        let negative = [0u8, 0, 0, 1, 0x80];
        assert_eq!(
            fixed_signature(&[mpint(&r), negative.to_vec()].concat()),
            Err(KeyError::NonCanonicalInteger { field: "s" })
        );
        let redundant = [0u8, 0, 0, 2, 0x00, 0x01];
        assert_eq!(
            fixed_signature(&[redundant.to_vec(), mpint(&s)].concat()),
            Err(KeyError::NonCanonicalInteger { field: "r" })
        );
        assert_eq!(
            fixed_signature(&[mpint(&[0x7f; 33]), mpint(&s)].concat()),
            Err(KeyError::ScalarTooLong { field: "r" })
        );
        let mut t = inner.clone();
        t.push(0);
        assert_eq!(
            fixed_signature(&t),
            Err(KeyError::Blob(BlobError::TrailingBytes { count: 1 }))
        );
        assert!(matches!(
            fixed_signature(&inner[..inner.len() - 1]),
            Err(KeyError::Blob(_))
        ));
        // A DER ECDSA-Sig-Value is not an SSH signature.
        let der = [0x30u8, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert!(fixed_signature(&der).is_err());
    }
}
