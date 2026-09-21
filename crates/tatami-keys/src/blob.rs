//! Public-key and signature blob encodings (RFC 4253 §6.6, RFC 8709 §§4, 6).
//!
//! These codecs are algorithm-agnostic and need no cryptographic provider.
//! A public-key blob is `string algorithm` followed by an algorithm-specific
//! body; a signature blob is `string algorithm, string signature`. The
//! algorithm-specific interpretation (for `ssh-ed25519`: one 32-byte
//! `string key`; a 64-byte signature) lives in [`crate::ed25519`].
//!
//! The complete public-key blob bytes are what both the exchange hash (`K_S`
//! in RFC 4253 §8 / RFC 5656 §4) and the OpenSSH `SHA256:` fingerprint cover,
//! so [`PublicKeyBlob::as_bytes`] always returns them intact.
//!
//! RFC 8332 uses the same `ssh-rsa` key blob under the signature-algorithm
//! names `rsa-sha2-256` / `rsa-sha2-512`; that is why the key blob's
//! algorithm and the signature blob's algorithm are separate fields here
//! even though for `ssh-ed25519` they are always equal.

use tatami_wire::{DecodeError, EncodeError, Reader, Writer};

use crate::error::BlobError;

/// Wire name of the Ed25519 public-key and signature algorithm (RFC 8709).
pub const SSH_ED25519: &[u8] = tatami_wire::algorithms::SSH_ED25519;

/// Length of an Ed25519 public key in bytes (RFC 8032 §5.1.5).
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes (RFC 8032 §5.1.6).
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Encoded length of an `ssh-ed25519` public-key blob:
/// `string "ssh-ed25519"` (4 + 11) then `string key` (4 + 32).
pub const ED25519_BLOB_LEN: usize = 4 + 11 + 4 + ED25519_PUBLIC_KEY_LEN;

/// Encoded length of an `ssh-ed25519` signature blob:
/// `string "ssh-ed25519"` (4 + 11) then `string signature` (4 + 64).
pub const ED25519_SIGNATURE_BLOB_LEN: usize = 4 + 11 + 4 + ED25519_SIGNATURE_LEN;

/// Borrowed view of a public-key blob: the algorithm name and the rest.
///
/// Holding one proves only that the leading `string` parsed. The body is
/// opaque here; [`crate::ed25519::Ed25519PublicKey::from_blob`] validates it
/// for `ssh-ed25519`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyBlob<'a> {
    /// Public-key format name, e.g. `ssh-ed25519`. Unknown names preserved.
    pub algorithm: &'a [u8],
    /// Everything after the algorithm string, exactly as received.
    pub body: &'a [u8],
    bytes: &'a [u8],
}

impl<'a> PublicKeyBlob<'a> {
    /// Splits `blob` into algorithm name and body. Never rejects trailing
    /// bytes: what follows the name is the body by definition.
    pub fn decode(blob: &'a [u8]) -> Result<Self, BlobError> {
        let mut r = Reader::new(blob);
        let algorithm = field(&mut r, "algorithm", Reader::read_string)?;
        Ok(PublicKeyBlob {
            algorithm,
            body: r.remaining(),
            bytes: blob,
        })
    }

    /// The complete blob, exactly as received (`K_S`).
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Borrowed view of a signature blob: `string algorithm, string signature`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureBlob<'a> {
    /// Signature algorithm name, e.g. `ssh-ed25519` or `rsa-sha2-256`.
    pub algorithm: &'a [u8],
    /// Raw signature bytes; format depends on the algorithm.
    pub signature: &'a [u8],
}

impl<'a> SignatureBlob<'a> {
    /// Decodes a complete signature blob, rejecting trailing bytes.
    pub fn decode(blob: &'a [u8]) -> Result<Self, BlobError> {
        let mut r = Reader::new(blob);
        let algorithm = field(&mut r, "algorithm", Reader::read_string)?;
        let signature = field(&mut r, "signature", Reader::read_string)?;
        finish(&r)?;
        Ok(SignatureBlob {
            algorithm,
            signature,
        })
    }

    /// Encodes the blob into `out`, returning the number of bytes written.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(out);
        w.write_string(self.algorithm)?;
        w.write_string(self.signature)?;
        Ok(w.position())
    }
}

/// Encodes an `ssh-ed25519` public-key blob (RFC 8709 §4) into `out`,
/// returning the number of bytes written (always [`ED25519_BLOB_LEN`] on
/// success).
pub fn encode_ed25519_blob(
    key_bytes: &[u8; ED25519_PUBLIC_KEY_LEN],
    out: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut w = Writer::new(out);
    w.write_string(SSH_ED25519)?;
    w.write_string(key_bytes)?;
    Ok(w.position())
}

/// Decodes one named field, attaching its name and offset to any error.
pub(crate) fn field<'a, T>(
    r: &mut Reader<'a>,
    name: &'static str,
    read: impl FnOnce(&mut Reader<'a>) -> Result<T, DecodeError>,
) -> Result<T, BlobError> {
    let offset = r.position();
    read(r).map_err(|error| BlobError::Field {
        field: name,
        offset,
        error,
    })
}

/// Fails with [`BlobError::TrailingBytes`] unless the reader is exhausted.
pub(crate) fn finish(r: &Reader<'_>) -> Result<(), BlobError> {
    r.finish()
        .map_err(|t| BlobError::TrailingBytes { count: t.count })
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Fixed vectors shared by the test modules of this crate. Nothing here
    //! is generated at test time. Vectors only the `ed25519` tests consume
    //! are gated with the feature so a feature-less test build has no dead
    //! code.

    /// RFC 8032 §7.1 TEST 1 public key (`PUBLIC KEY:` line). The task brief
    /// quoted `9d61b19d…` for this key; that hex is TEST 1's *secret* key in
    /// the RFC, so the public key below was taken from the RFC text itself.
    pub const TEST1_PUBLIC_KEY: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    /// RFC 8032 §7.1 TEST 1 signature over the empty message.
    pub const TEST1_SIGNATURE: [u8; 64] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    /// RFC 8032 §7.1 TEST 2 public key; message is the single byte `0x72`.
    #[cfg(feature = "ed25519")]
    pub const TEST2_PUBLIC_KEY: [u8; 32] = [
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e,
        0xbc, 0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4,
        0x66, 0x0c,
    ];
    /// RFC 8032 §7.1 TEST 2 message.
    #[cfg(feature = "ed25519")]
    pub const TEST2_MESSAGE: [u8; 1] = [0x72];
    /// RFC 8032 §7.1 TEST 2 signature.
    #[cfg(feature = "ed25519")]
    pub const TEST2_SIGNATURE: [u8; 64] = [
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25,
        0x40, 0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb,
        0x69, 0xda, 0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e, 0x45, 0x8f, 0x36, 0x13, 0xd0,
        0xf1, 0x1d, 0x8c, 0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee, 0xb0, 0x0d, 0x29, 0x16,
        0x12, 0xbb, 0x0c, 0x00,
    ];

    /// RFC 8032 §7.1 TEST 3 public key; message is `af 82`.
    #[cfg(feature = "ed25519")]
    pub const TEST3_PUBLIC_KEY: [u8; 32] = [
        0xfc, 0x51, 0xcd, 0x8e, 0x62, 0x18, 0xa1, 0xa3, 0x8d, 0xa4, 0x7e, 0xd0, 0x02, 0x30, 0xf0,
        0x58, 0x08, 0x16, 0xed, 0x13, 0xba, 0x33, 0x03, 0xac, 0x5d, 0xeb, 0x91, 0x15, 0x48, 0x90,
        0x80, 0x25,
    ];
    /// RFC 8032 §7.1 TEST 3 message.
    #[cfg(feature = "ed25519")]
    pub const TEST3_MESSAGE: [u8; 2] = [0xaf, 0x82];
    /// RFC 8032 §7.1 TEST 3 signature.
    #[cfg(feature = "ed25519")]
    pub const TEST3_SIGNATURE: [u8; 64] = [
        0x62, 0x91, 0xd6, 0x57, 0xde, 0xec, 0x24, 0x02, 0x48, 0x27, 0xe6, 0x9c, 0x3a, 0xbe, 0x01,
        0xa3, 0x0c, 0xe5, 0x48, 0xa2, 0x84, 0x74, 0x3a, 0x44, 0x5e, 0x36, 0x80, 0xd7, 0xdb, 0x5a,
        0xc3, 0xac, 0x18, 0xff, 0x9b, 0x53, 0x8d, 0x16, 0xf2, 0x90, 0xae, 0x67, 0xf7, 0x60, 0x98,
        0x4d, 0xc6, 0x59, 0x4a, 0x7c, 0x15, 0xe9, 0x71, 0x6e, 0xd2, 0x8d, 0xc0, 0x27, 0xbe, 0xce,
        0xea, 0x1e, 0xc4, 0x0a,
    ];

    /// `string "ssh-ed25519"` prefix shared by key and signature blobs:
    /// `00 00 00 0b` then the eleven ASCII bytes.
    pub const ALG_PREFIX: [u8; 15] = [
        0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9',
    ];

    /// Hand-built `ssh-ed25519` public-key blob for TEST 1:
    /// `ALG_PREFIX || 00 00 00 20 || TEST1_PUBLIC_KEY` (51 bytes).
    pub fn test1_key_blob() -> [u8; 51] {
        let mut b = [0u8; 51];
        b[..15].copy_from_slice(&ALG_PREFIX);
        b[15..19].copy_from_slice(&[0, 0, 0, 32]);
        b[19..].copy_from_slice(&TEST1_PUBLIC_KEY);
        b
    }

    /// Hand-built `ssh-ed25519` public-key blob for an arbitrary key.
    #[cfg(feature = "ed25519")]
    pub fn key_blob(key: &[u8; 32]) -> [u8; 51] {
        let mut b = test1_key_blob();
        b[19..].copy_from_slice(key);
        b
    }

    /// Hand-built `ssh-ed25519` signature blob:
    /// `ALG_PREFIX || 00 00 00 40 || sig` (83 bytes).
    pub fn sig_blob(sig: &[u8; 64]) -> [u8; 83] {
        let mut b = [0u8; 83];
        b[..15].copy_from_slice(&ALG_PREFIX);
        b[15..19].copy_from_slice(&[0, 0, 0, 64]);
        b[19..].copy_from_slice(sig);
        b
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn public_key_blob_splits_algorithm_and_body() {
        let blob = test1_key_blob();
        let k = PublicKeyBlob::decode(&blob).unwrap();
        assert_eq!(k.algorithm, b"ssh-ed25519");
        assert_eq!(k.body.len(), 36);
        assert_eq!(&k.body[..4], &[0, 0, 0, 32]);
        assert_eq!(&k.body[4..], &TEST1_PUBLIC_KEY);
        assert_eq!(k.as_bytes(), &blob);
    }

    #[test]
    fn public_key_blob_keeps_unknown_algorithms_and_any_body() {
        // string "ssh-rsa" then arbitrary body bytes.
        let blob = [
            0, 0, 0, 7, b's', b's', b'h', b'-', b'r', b's', b'a', 0xff, 0x00,
        ];
        let k = PublicKeyBlob::decode(&blob).unwrap();
        assert_eq!(k.algorithm, b"ssh-rsa");
        assert_eq!(k.body, &[0xff, 0x00]);
        // An empty body is syntactically fine at this level.
        let k = PublicKeyBlob::decode(&blob[..11]).unwrap();
        assert!(k.body.is_empty());
    }

    #[test]
    fn public_key_blob_errors_name_the_field() {
        assert_eq!(
            PublicKeyBlob::decode(&[]),
            Err(BlobError::Field {
                field: "algorithm",
                offset: 0,
                error: DecodeError::Truncated {
                    needed: 4,
                    available: 0
                }
            })
        );
        assert_eq!(
            PublicKeyBlob::decode(&[0, 0, 0, 11, b's']),
            Err(BlobError::Field {
                field: "algorithm",
                offset: 0,
                error: DecodeError::LengthOverflow {
                    claimed: 11,
                    available: 1
                }
            })
        );
    }

    #[test]
    fn encode_ed25519_blob_matches_hand_built_bytes() {
        let mut out = [0u8; ED25519_BLOB_LEN];
        assert_eq!(
            encode_ed25519_blob(&TEST1_PUBLIC_KEY, &mut out).unwrap(),
            ED25519_BLOB_LEN
        );
        assert_eq!(out, test1_key_blob());
        assert_eq!(ED25519_BLOB_LEN, 51);

        let mut small = [0u8; 20];
        assert_eq!(
            encode_ed25519_blob(&TEST1_PUBLIC_KEY, &mut small),
            Err(EncodeError::InsufficientCapacity {
                needed: 36,
                available: 5
            })
        );
    }

    #[test]
    fn signature_blob_fixture_and_round_trip() {
        let blob = sig_blob(&TEST1_SIGNATURE);
        let s = SignatureBlob::decode(&blob).unwrap();
        assert_eq!(s.algorithm, b"ssh-ed25519");
        assert_eq!(s.signature, &TEST1_SIGNATURE);

        let mut out = [0u8; ED25519_SIGNATURE_BLOB_LEN];
        assert_eq!(s.encode(&mut out).unwrap(), 83);
        assert_eq!(out, blob);
    }

    #[test]
    fn signature_blob_rejects_trailing_and_truncation() {
        let blob = sig_blob(&TEST1_SIGNATURE);
        let mut trailing = [0u8; 84];
        trailing[..83].copy_from_slice(&blob);
        assert_eq!(
            SignatureBlob::decode(&trailing),
            Err(BlobError::TrailingBytes { count: 1 })
        );
        assert_eq!(
            SignatureBlob::decode(&blob[..40]),
            Err(BlobError::Field {
                field: "signature",
                offset: 15,
                error: DecodeError::LengthOverflow {
                    claimed: 64,
                    available: 21
                }
            })
        );
        assert_eq!(
            SignatureBlob::decode(&blob[..15]),
            Err(BlobError::Field {
                field: "signature",
                offset: 15,
                error: DecodeError::Truncated {
                    needed: 4,
                    available: 0
                }
            })
        );
    }

    #[test]
    fn signature_blob_is_algorithm_agnostic() {
        // string "rsa-sha2-256", string "xy": RFC 8332 names differ from the
        // `ssh-rsa` key format and must survive intact.
        let blob = [
            0, 0, 0, 12, b'r', b's', b'a', b'-', b's', b'h', b'a', b'2', b'-', b'2', b'5', b'6', 0,
            0, 0, 2, b'x', b'y',
        ];
        let s = SignatureBlob::decode(&blob).unwrap();
        assert_eq!(s.algorithm, b"rsa-sha2-256");
        assert_eq!(s.signature, b"xy");
    }
}
