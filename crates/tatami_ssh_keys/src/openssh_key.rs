//! Unencrypted `openssh-key-v1` host private keys (feature `openssh-key`),
//! decoded from bytes and converted in memory for a TLS stack.
//!
//! Supported subset: exactly what `ssh-keygen -t ed25519|rsa|ecdsa -N ''`
//! writes, for the enabled key types (Ed25519 always; RSA with `rsa`;
//! ECDSA P-256 with `ecdsa-p256`). A passphrase-protected key is rejected
//! with [`PrivateKeyError::Encrypted`] before any KDF runs (none is
//! linked); there is no prompt, environment variable or argument for a
//! passphrase. Other algorithms (DSA, P-384, P-521, `sk-*`), other container
//! formats (PKCS#8, legacy PEM) and anything malformed are rejected.
//!
//! Parsing is delegated to RustCrypto `ssh-key` 0.6 (see
//! `docs/crypto-provider-audit.md`), which verifies the magic,
//! `nkeys == 1`, `cipher`/`kdf` consistency, equal check integers, that the
//! outer public key equals the private section's public key (so an
//! unrelated embedded public key is refused), the padding bytes, the ECDSA
//! curve name against the algorithm, minimal `mpint`s, and that nothing
//! trails. Built without its own crypto features it does **not** check that
//! the private half belongs to the public half. That is established as
//! follows, without writing anything to disk:
//!
//! | Key type | Checked here | Checked when the host loads the converted key |
//! |---|---|---|
//! | Ed25519 | public key re-derived from the seed (`ed25519-dalek`) | — |
//! | RSA | public key within the [`crate::rsa`] policy; `p · q = n` and `d < n` (`crypto-bigint`, constant time) | `ring` validates the PKCS#1 components (and a probe signature, in the QUIC adapter) |
//! | ECDSA P-256 | point encoding | `ring` re-derives the public point from the scalar and compares |
//!
//! The QUIC host adapter always loads the converted key with `ring` and
//! compares the provider's public key with the file's before any socket is
//! opened, so an inconsistent RSA or P-256 key never reaches a handshake.
//!
//! RSA keys are converted to PKCS#1 `RSAPrivateKey` (RFC 8017 A.1.2).
//! OpenSSH stores `n, e, d, iqmp, p, q` but not the CRT exponents
//! `dP = d mod (p−1)` and `dQ = d mod (q−1)`; they are computed with
//! `crypto-bigint` (`Uint::rem`, constant time in the dividend, variable
//! only in the divisor's bit length, which is public: half the modulus
//! size). No RSA signing or decryption happens here, and the `rsa` crate
//! (RUSTSEC-2023-0071) is not used. P-256 keys become a SEC1
//! `ECPrivateKey` (RFC 5915) with the public key included; Ed25519 keys an
//! RFC 8410 PKCS#8 `OneAsymmetricKey`.
//!
//! Secrets are held in [`Zeroizing`] storage, never appear in `Debug`,
//! `Display` or errors, and each converted DER is written into one
//! exactly-sized zeroizing buffer (no reallocation leaves copies). Copies
//! inside `ssh-key` are zeroized by it on drop; copies the TLS provider
//! makes are outside this crate's control. File access (size bound,
//! permission check) belongs to the caller's host layer.
//!
//! Known limitation: OpenSSH writes an ECDSA private scalar as a minimal
//! `mpint`, so about one P-256 key in 256 has a 31-byte scalar; `ssh-key`
//! 0.6.7 expects 32 bytes and rejects such a key as malformed.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use ed25519_dalek::SigningKey;
use ssh_key::private::KeypairData;
/// Zeroizing storage for secret buffers, re-exported so callers (the host
/// layer reading key files) use the same implementation.
pub use zeroize::Zeroizing;

use crate::algorithm::KeyType;
use crate::blob::ED25519_BLOB_LEN;
use crate::ed25519::Ed25519PublicKey;
use crate::error::KeyError;
use crate::fingerprint::Sha256Fingerprint;
use crate::spki::ssh_blob_of;

/// Upper bound on accepted key text. An `ssh-keygen` Ed25519 key is about
/// 400 bytes and an 8192-bit RSA key about 6.5 KiB; 16 KiB leaves room for
/// long comments and rejects anything else before decoding.
pub const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;

/// DER prefix of an RFC 8410 §7 Ed25519 `OneAsymmetricKey` (version 0, no
/// attributes, no public key): `SEQUENCE(46) { INTEGER 0, SEQUENCE(5) { OID
/// 1.3.101.112 }, OCTET STRING(34) { OCTET STRING(32) seed } }`.
pub const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Why key bytes were not accepted. Never contains secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateKeyError {
    /// More than [`MAX_PRIVATE_KEY_BYTES`].
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// Not an `-----BEGIN OPENSSH PRIVATE KEY-----` container.
    NotOpenssh,
    /// The key is passphrase-protected. Encrypted keys are not supported;
    /// nothing was decrypted.
    Encrypted,
    /// A well-formed key of another algorithm (or of a type whose feature
    /// is off).
    UnsupportedAlgorithm(String),
    /// The container is malformed or internally inconsistent (as reported
    /// by the parser).
    Malformed(String),
    /// The stored public key does not belong to the private key.
    PublicKeyMismatch,
    /// The public key is outside Tatami's key policy (for example an RSA
    /// modulus below 2048 bits).
    Policy(KeyError),
}

impl fmt::Display for PrivateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivateKeyError::TooLarge { limit } => {
                write!(f, "private key file exceeds {limit} bytes")
            }
            PrivateKeyError::NotOpenssh => f.write_str(
                "not an OpenSSH private key (expected -----BEGIN OPENSSH PRIVATE KEY-----)",
            ),
            PrivateKeyError::Encrypted => f.write_str(
                "private key is passphrase-protected; encrypted keys are not supported (use an unencrypted host key)",
            ),
            PrivateKeyError::UnsupportedAlgorithm(alg) => write!(
                f,
                "unsupported private key algorithm {alg:?}; this build accepts {}",
                enabled_types()
            ),
            PrivateKeyError::Malformed(why) => write!(f, "malformed OpenSSH private key: {why}"),
            PrivateKeyError::PublicKeyMismatch => {
                f.write_str("private key's public key does not belong to its secret")
            }
            PrivateKeyError::Policy(e) => write!(f, "host key not accepted: {e}"),
        }
    }
}

impl core::error::Error for PrivateKeyError {}

/// The key types this build imports, for messages.
fn enabled_types() -> &'static str {
    match (cfg!(feature = "rsa"), cfg!(feature = "ecdsa-p256")) {
        (true, true) => "ssh-ed25519, ssh-rsa and ecdsa-sha2-nistp256",
        (true, false) => "ssh-ed25519 and ssh-rsa",
        (false, true) => "ssh-ed25519 and ecdsa-sha2-nistp256",
        (false, false) => "only ssh-ed25519",
    }
}

/// Size bound, container marker, parse, encryption check.
fn decode(text: &[u8]) -> Result<ssh_key::PrivateKey, PrivateKeyError> {
    if text.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(PrivateKeyError::TooLarge {
            limit: MAX_PRIVATE_KEY_BYTES,
        });
    }
    if !text
        .windows(35)
        .any(|w| w == b"-----BEGIN OPENSSH PRIVATE KEY-----")
    {
        return Err(PrivateKeyError::NotOpenssh);
    }
    let key = ssh_key::PrivateKey::from_openssh(text).map_err(|e| match e {
        // Built without other algorithms, the parser cannot name them.
        ssh_key::Error::AlgorithmUnknown => {
            PrivateKeyError::UnsupportedAlgorithm(String::from("(unrecognised)"))
        }
        ssh_key::Error::AlgorithmUnsupported { algorithm } => {
            PrivateKeyError::UnsupportedAlgorithm(String::from(algorithm.as_str()))
        }
        other => PrivateKeyError::Malformed(alloc::format!("{other}")),
    })?;
    if key.is_encrypted() {
        return Err(PrivateKeyError::Encrypted);
    }
    Ok(key)
}

fn unsupported(key: &ssh_key::PrivateKey) -> PrivateKeyError {
    PrivateKeyError::UnsupportedAlgorithm(String::from(key.algorithm().as_str()))
}

/// A validated Ed25519 host private key.
pub struct Ed25519HostPrivateKey {
    seed: Zeroizing<[u8; 32]>,
    public: Ed25519PublicKey,
}

impl fmt::Debug for Ed25519HostPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519HostPrivateKey")
            .field("public_sha256", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Ed25519HostPrivateKey {
    /// Decodes an unencrypted Ed25519 `openssh-key-v1` PEM container; any
    /// other algorithm is [`PrivateKeyError::UnsupportedAlgorithm`].
    pub fn from_openssh(text: &[u8]) -> Result<Self, PrivateKeyError> {
        let key = decode(text)?;
        Self::from_keypair(&key)
    }

    fn from_keypair(key: &ssh_key::PrivateKey) -> Result<Self, PrivateKeyError> {
        let KeypairData::Ed25519(pair) = key.key_data() else {
            return Err(unsupported(key));
        };
        let stored: [u8; 32] = pair.public.0;
        let public = Ed25519PublicKey::from_bytes(&stored)
            .map_err(|_| PrivateKeyError::Malformed(String::from("invalid Ed25519 public key")))?;
        let seed = Zeroizing::new(pair.private.to_bytes());
        // ssh-key (without its ed25519 feature) does not derive; do it here.
        let derived = SigningKey::from_bytes(&seed).verifying_key();
        if derived.as_bytes() != public.as_bytes() {
            return Err(PrivateKeyError::PublicKeyMismatch);
        }
        Ok(Ed25519HostPrivateKey { seed, public })
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public
    }

    /// The canonical `ssh-ed25519` public-key blob.
    #[must_use]
    pub fn ssh_blob(&self) -> [u8; ED25519_BLOB_LEN] {
        ssh_blob_of(&self.public)
    }

    /// OpenSSH `SHA256:` fingerprint of the public key.
    #[must_use]
    pub fn fingerprint(&self) -> Sha256Fingerprint {
        Sha256Fingerprint::of_blob(&self.ssh_blob())
    }

    /// RFC 8410 §7 PKCS#8 encoding of the private key, for a TLS stack.
    /// Held in zeroizing storage; callers must not log or persist it.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32));
        out.extend_from_slice(&ED25519_PKCS8_PREFIX);
        out.extend_from_slice(&*self.seed);
        out
    }
}

/// Container format of a converted private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateKeyFormat {
    /// PKCS#8 `OneAsymmetricKey` (Ed25519).
    Pkcs8,
    /// PKCS#1 `RSAPrivateKey` (RSA).
    Pkcs1,
    /// SEC1 `ECPrivateKey` with named curve and public key (P-256).
    Sec1,
}

/// A converted private key for a TLS stack, in zeroizing storage.
pub struct PrivateKeyDer {
    /// The DER container format.
    pub format: PrivateKeyFormat,
    /// The DER bytes. Never log or persist.
    pub der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PrivateKeyDer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKeyDer")
            .field("format", &self.format)
            .field("len", &self.der.len())
            .finish_non_exhaustive()
    }
}

/// A validated host private key of any enabled type.
#[derive(Debug)]
pub enum HostPrivateKey {
    /// `ssh-ed25519`.
    Ed25519(Ed25519HostPrivateKey),
    /// `ssh-rsa` (feature `rsa`).
    #[cfg(feature = "rsa")]
    Rsa(RsaHostPrivateKey),
    /// `ecdsa-sha2-nistp256` (feature `ecdsa-p256`).
    #[cfg(feature = "ecdsa-p256")]
    EcdsaP256(EcdsaP256HostPrivateKey),
}

impl HostPrivateKey {
    /// Decodes an unencrypted `openssh-key-v1` PEM container of any
    /// enabled key type.
    pub fn from_openssh(text: &[u8]) -> Result<Self, PrivateKeyError> {
        let key = decode(text)?;
        match key.key_data() {
            KeypairData::Ed25519(_) => Ed25519HostPrivateKey::from_keypair(&key).map(Self::Ed25519),
            #[cfg(feature = "rsa")]
            KeypairData::Rsa(pair) => RsaHostPrivateKey::from_keypair(pair).map(Self::Rsa),
            #[cfg(feature = "ecdsa-p256")]
            KeypairData::Ecdsa(ssh_key::private::EcdsaKeypair::NistP256 { public, private }) => {
                EcdsaP256HostPrivateKey::from_parts(public.as_bytes(), private.as_slice())
                    .map(Self::EcdsaP256)
            }
            _ => Err(unsupported(&key)),
        }
    }

    /// The key type.
    #[must_use]
    pub fn key_type(&self) -> KeyType {
        match self {
            HostPrivateKey::Ed25519(_) => KeyType::Ed25519,
            #[cfg(feature = "rsa")]
            HostPrivateKey::Rsa(_) => KeyType::Rsa,
            #[cfg(feature = "ecdsa-p256")]
            HostPrivateKey::EcdsaP256(_) => KeyType::EcdsaP256,
        }
    }

    /// The canonical SSH public-key blob.
    #[must_use]
    pub fn ssh_blob(&self) -> Vec<u8> {
        match self {
            HostPrivateKey::Ed25519(k) => k.ssh_blob().to_vec(),
            #[cfg(feature = "rsa")]
            HostPrivateKey::Rsa(k) => k.public.to_blob(),
            #[cfg(feature = "ecdsa-p256")]
            HostPrivateKey::EcdsaP256(k) => k.public.to_blob(),
        }
    }

    /// OpenSSH `SHA256:` fingerprint of the public key.
    #[must_use]
    pub fn fingerprint(&self) -> Sha256Fingerprint {
        Sha256Fingerprint::of_blob(&self.ssh_blob())
    }

    /// The private key converted for a TLS stack (see the module notes).
    #[must_use]
    pub fn to_private_key_der(&self) -> PrivateKeyDer {
        match self {
            HostPrivateKey::Ed25519(k) => PrivateKeyDer {
                format: PrivateKeyFormat::Pkcs8,
                der: k.to_pkcs8_der(),
            },
            #[cfg(feature = "rsa")]
            HostPrivateKey::Rsa(k) => PrivateKeyDer {
                format: PrivateKeyFormat::Pkcs1,
                der: k.to_pkcs1_der(),
            },
            #[cfg(feature = "ecdsa-p256")]
            HostPrivateKey::EcdsaP256(k) => PrivateKeyDer {
                format: PrivateKeyFormat::Sec1,
                der: k.to_sec1_der(),
            },
        }
    }
}

/// DER writing into a pre-sized buffer, so secret bytes are never copied
/// by a reallocation.
#[cfg(feature = "rsa")]
mod der {
    use alloc::vec::Vec;

    pub(super) const INTEGER: u8 = 0x02;
    pub(super) const SEQUENCE: u8 = 0x30;

    pub(super) fn header_len(len: usize) -> usize {
        1 + match len {
            0..0x80 => 1,
            0x80..0x100 => 2,
            _ => 3,
        }
    }

    pub(super) fn push_header(out: &mut Vec<u8>, tag: u8, len: usize) {
        out.push(tag);
        match len {
            0..0x80 => out.push(len as u8),
            0x80..0x100 => out.extend_from_slice(&[0x81, len as u8]),
            _ => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        }
    }

    /// Content length of the minimal positive INTEGER for `magnitude`
    /// (no leading zero bytes; empty is zero).
    pub(super) fn integer_content_len(magnitude: &[u8]) -> usize {
        magnitude.len() + usize::from(magnitude.first().is_none_or(|b| b & 0x80 != 0))
    }

    pub(super) fn integer_len(magnitude: &[u8]) -> usize {
        let c = integer_content_len(magnitude);
        header_len(c) + c
    }

    pub(super) fn push_integer(out: &mut Vec<u8>, magnitude: &[u8]) {
        push_header(out, INTEGER, integer_content_len(magnitude));
        if magnitude.first().is_none_or(|b| b & 0x80 != 0) {
            out.push(0);
        }
        out.extend_from_slice(magnitude);
    }
}

/// A validated RSA host private key (feature `rsa`).
#[cfg(feature = "rsa")]
pub struct RsaHostPrivateKey {
    public: crate::rsa::RsaPublicKey,
    d: Zeroizing<Vec<u8>>,
    p: Zeroizing<Vec<u8>>,
    q: Zeroizing<Vec<u8>>,
    iqmp: Zeroizing<Vec<u8>>,
    dp: Zeroizing<Vec<u8>>,
    dq: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "rsa")]
impl fmt::Debug for RsaHostPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaHostPrivateKey")
            .field("modulus_bits", &self.public.modulus_bits())
            .field(
                "public_sha256",
                &Sha256Fingerprint::of_blob(&self.public.to_blob()),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "rsa")]
impl RsaHostPrivateKey {
    fn from_keypair(pair: &ssh_key::private::RsaKeypair) -> Result<Self, PrivateKeyError> {
        use crypto_bigint::{Encoding as _, NonZero, U8192};

        let positive = |m: &ssh_key::Mpint, what: &str| -> Result<Vec<u8>, PrivateKeyError> {
            match m.as_positive_bytes() {
                Some(b) if !b.is_empty() => Ok(b.to_vec()),
                _ => Err(PrivateKeyError::Malformed(alloc::format!(
                    "RSA {what} is not a positive integer"
                ))),
            }
        };
        let n = positive(&pair.public.n, "n")?;
        let e = positive(&pair.public.e, "e")?;
        let public =
            crate::rsa::RsaPublicKey::from_components(&e, &n).map_err(PrivateKeyError::Policy)?;
        let d = Zeroizing::new(positive(&pair.private.d, "d")?);
        let p = Zeroizing::new(positive(&pair.private.p, "p")?);
        let q = Zeroizing::new(positive(&pair.private.q, "q")?);
        let iqmp = Zeroizing::new(positive(&pair.private.iqmp, "iqmp")?);
        if d.len() > n.len() || p.len() > n.len() || q.len() > n.len() || iqmp.len() > p.len() {
            return Err(PrivateKeyError::PublicKeyMismatch);
        }

        // Fixed-width values; every magnitude fits (n is at most 8192 bits).
        let wide = |m: &[u8]| -> Zeroizing<U8192> {
            let mut buf = Zeroizing::new([0u8; 1024]);
            buf[1024 - m.len()..].copy_from_slice(m);
            Zeroizing::new(U8192::from_be_slice(&*buf))
        };
        let (nw, dw, pw, qw) = (wide(&n), wide(&d), wide(&p), wide(&q));
        if *dw >= *nw {
            return Err(PrivateKeyError::PublicKeyMismatch);
        }
        // Full double-width product: p·q = n exactly, with no wrap-around.
        let (lo, hi) = pw.mul_wide(&*qw);
        let (lo, hi) = (Zeroizing::new(lo), Zeroizing::new(hi));
        if *hi != U8192::ZERO || *lo != *nw {
            return Err(PrivateKeyError::PublicKeyMismatch);
        }
        let crt = |prime: &U8192| -> Result<Zeroizing<Vec<u8>>, PrivateKeyError> {
            let pm1 = Zeroizing::new(prime.wrapping_sub(&U8192::ONE));
            let divisor: Option<NonZero<U8192>> = NonZero::new(*pm1).into();
            let divisor = divisor.ok_or(PrivateKeyError::PublicKeyMismatch)?;
            let r = Zeroizing::new(dw.rem(&divisor));
            let bytes = Zeroizing::new(r.to_be_bytes());
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
            Ok(Zeroizing::new(bytes[start..].to_vec()))
        };
        let dp = crt(&pw)?;
        let dq = crt(&qw)?;
        if dp.is_empty() || dq.is_empty() {
            return Err(PrivateKeyError::PublicKeyMismatch);
        }
        Ok(RsaHostPrivateKey {
            public,
            d,
            p,
            q,
            iqmp,
            dp,
            dq,
        })
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &crate::rsa::RsaPublicKey {
        &self.public
    }

    /// PKCS#1 `RSAPrivateKey` (RFC 8017 A.1.2), version 0.
    #[must_use]
    pub fn to_pkcs1_der(&self) -> Zeroizing<Vec<u8>> {
        let parts: [&[u8]; 9] = [
            &[],
            self.public.modulus(),
            self.public.exponent(),
            &self.d,
            &self.p,
            &self.q,
            &self.dp,
            &self.dq,
            &self.iqmp,
        ];
        let body: usize = parts.iter().map(|m| der::integer_len(m)).sum();
        let total = der::header_len(body) + body;
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        der::push_header(&mut out, der::SEQUENCE, body);
        for m in parts {
            der::push_integer(&mut out, m);
        }
        debug_assert_eq!(out.len(), total);
        out
    }
}

/// A P-256 host private key (feature `ecdsa-p256`). The scalar/point
/// consistency is checked by the provider that loads the SEC1 form; see
/// the module notes.
#[cfg(feature = "ecdsa-p256")]
pub struct EcdsaP256HostPrivateKey {
    public: crate::ecdsa::EcdsaP256PublicKey,
    scalar: Zeroizing<[u8; 32]>,
}

#[cfg(feature = "ecdsa-p256")]
impl fmt::Debug for EcdsaP256HostPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP256HostPrivateKey")
            .field(
                "public_sha256",
                &Sha256Fingerprint::of_blob(&self.public.to_blob()),
            )
            .finish_non_exhaustive()
    }
}

/// SEC1 `ECPrivateKey` prefix up to the scalar: `SEQUENCE(119) { INTEGER
/// 1, OCTET STRING(32) ...`.
#[cfg(feature = "ecdsa-p256")]
const P256_SEC1_PREFIX: [u8; 7] = [0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20];

/// Between scalar and point: `[0] { OID prime256v1 }, [1] { BIT STRING(66)
/// { 0, ...`.
#[cfg(feature = "ecdsa-p256")]
const P256_SEC1_MIDDLE: [u8; 17] = [
    0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
    0x00,
];

#[cfg(feature = "ecdsa-p256")]
impl EcdsaP256HostPrivateKey {
    fn from_parts(point: &[u8], scalar: &[u8]) -> Result<Self, PrivateKeyError> {
        let public =
            crate::ecdsa::EcdsaP256PublicKey::from_point(point).map_err(PrivateKeyError::Policy)?;
        let scalar: [u8; 32] = scalar.try_into().map_err(|_| {
            PrivateKeyError::Malformed(String::from("P-256 scalar is not 32 bytes"))
        })?;
        let scalar = Zeroizing::new(scalar);
        if scalar.iter().all(|&b| b == 0) {
            return Err(PrivateKeyError::Malformed(String::from(
                "P-256 scalar is zero",
            )));
        }
        Ok(EcdsaP256HostPrivateKey { public, scalar })
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &crate::ecdsa::EcdsaP256PublicKey {
        &self.public
    }

    /// SEC1 `ECPrivateKey` (RFC 5915) with the named curve and public key.
    #[must_use]
    pub fn to_sec1_der(&self) -> Zeroizing<Vec<u8>> {
        let total = P256_SEC1_PREFIX.len() + 32 + P256_SEC1_MIDDLE.len() + 65;
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.extend_from_slice(&P256_SEC1_PREFIX);
        out.extend_from_slice(&*self.scalar);
        out.extend_from_slice(&P256_SEC1_MIDDLE);
        out.extend_from_slice(self.public.point());
        debug_assert_eq!(out.len(), total);
        out
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::string::ToString;
    use base64ct::{Base64, Encoding as _};

    /// Independent `openssh-key-v1` writer (PROTOCOL.key), so tampered
    /// containers can be built without the parser under test.
    pub(crate) struct Container {
        pub cipher: &'static str,
        pub kdf: &'static str,
        pub nkeys: u32,
        pub outer_public: [u8; 32],
        pub checkints: (u32, u32),
        pub inner_public: [u8; 32],
        pub seed: [u8; 32],
        pub embedded_public: [u8; 32],
        pub comment: &'static str,
        pub trailing: &'static [u8],
    }

    fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }

    fn ed_blob(key: &[u8; 32]) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, key);
        b
    }

    impl Container {
        pub fn valid(seed: [u8; 32]) -> Self {
            let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            Container {
                cipher: "none",
                kdf: "none",
                nkeys: 1,
                outer_public: public,
                checkints: (0x1234_5678, 0x1234_5678),
                inner_public: public,
                seed,
                embedded_public: public,
                comment: "test@tatami",
                trailing: b"",
            }
        }

        pub fn pem(&self) -> String {
            let mut bin = b"openssh-key-v1\0".to_vec();
            put_string(&mut bin, self.cipher.as_bytes());
            put_string(&mut bin, self.kdf.as_bytes());
            put_string(&mut bin, b"");
            bin.extend_from_slice(&self.nkeys.to_be_bytes());
            put_string(&mut bin, &ed_blob(&self.outer_public));
            let mut private = Vec::new();
            private.extend_from_slice(&self.checkints.0.to_be_bytes());
            private.extend_from_slice(&self.checkints.1.to_be_bytes());
            put_string(&mut private, b"ssh-ed25519");
            put_string(&mut private, &self.inner_public);
            put_string(&mut private, &[self.seed, self.embedded_public].concat());
            put_string(&mut private, self.comment.as_bytes());
            let mut pad = 1u8;
            while private.len() % 8 != 0 {
                private.push(pad);
                pad += 1;
            }
            put_string(&mut bin, &private);
            bin.extend_from_slice(self.trailing);
            let b64 = Base64::encode_string(&bin);
            let mut text = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            for chunk in b64.as_bytes().chunks(70) {
                text.push_str(core::str::from_utf8(chunk).unwrap());
                text.push('\n');
            }
            text.push_str("-----END OPENSSH PRIVATE KEY-----\n");
            text
        }
    }

    /// Generated with OpenSSH_10.2p1 `ssh-keygen -t ed25519 -N ''
    /// -C tatami-test` solely as a test fixture; never a host key.
    pub(crate) const SSH_KEYGEN_ED25519: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAVLWK1ftLx0InVYu2foOnSyAliFz4B74toZBL/pFHD4AAAAJCrOFvQqzhb
0AAAAAtzc2gtZWQyNTUxOQAAACAVLWK1ftLx0InVYu2foOnSyAliFz4B74toZBL/pFHD4A
AAAEAmQ4GXFztqiqLJdqoLjuINpRyhW/vLsXxAXqaEjgWjQBUtYrV+0vHQidVi7Z+g6dLI
CWIXPgHvi2hkEv+kUcPgAAAAC3RhdGFtaS10ZXN0AQI=
-----END OPENSSH PRIVATE KEY-----
";
    /// The fixture's `.pub` line as written by `ssh-keygen`.
    pub(crate) const SSH_KEYGEN_ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBUtYrV+0vHQidVi7Z+g6dLICWIXPgHvi2hkEv+kUcPg tatami-test";
    /// `ssh-keygen -lf` of the fixture's public key.
    pub(crate) const SSH_KEYGEN_ED25519_FP: &str =
        "SHA256:aCw4D+swMrV7HEVZQKMEkLpI5HWOuB071Q2qcU1bCRo";
    /// Same generator with `-N 'fixture passphrase'` (aes256-ctr, bcrypt).
    const SSH_KEYGEN_ED25519_ENCRYPTED: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDB1NgavX
giGkMuInNCexFHAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEJWwOddIgCDfyjr
409NYXlFbEFOqeE6JvKP6anNLHDeAAAAoB3iNNskHInBfTmwW55B83fvYyuWxzDuRax18H
Hu5KH6X+JNfjCcntmG2WQvO/ycBFhvTRbvqsl1ed+0kdidtuF0c6HIFZv4YLv35JefJhBa
8XixQ0rtuk6g5wMvV/wsXoBncf9zdiNDuv5yCZvtLtDq2tCYi6j4uGirv+Z5/LeUR6JQpG
U41OJBpFoQct7/Asjo0NeVqaXi6mcD7hWaLaA=
-----END OPENSSH PRIVATE KEY-----
";
    /// Same generator with `-t ecdsa -b 256 -N ''`.
    const SSH_KEYGEN_ECDSA: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSDfOtRP3fAjHUNlOVC0Lr9tRChm+mo
hSLasfnPV8RKD9gFjO4NsINDa4SblPRjNBy7lJKJ40CtCb7hBtOAZA+rAAAAqIeLQiiHi0
IoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIN861E/d8CMdQ2U
5ULQuv21EKGb6aiFItqx+c9XxEoP2AWM7g2wg0NrhJuU9GM0HLuUkonjQK0JvuEG04BkD6
sAAAAhAIQl+G3PqkfIpK0PJIEbJj0bBHG/M6hhig/Mxoh+hp62AAAADHRhdGFtaS1lY2Rz
YQECAw==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn encrypted_and_other_algorithms_are_rejected() {
        assert_eq!(
            Ed25519HostPrivateKey::from_openssh(SSH_KEYGEN_ED25519_ENCRYPTED.as_bytes())
                .unwrap_err(),
            PrivateKeyError::Encrypted
        );
        assert!(matches!(
            Ed25519HostPrivateKey::from_openssh(SSH_KEYGEN_ECDSA.as_bytes()).unwrap_err(),
            PrivateKeyError::UnsupportedAlgorithm(_)
        ));
    }

    #[test]
    fn rfc8410_pkcs8_example() {
        // RFC 8410 §10.3: MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
        let expected =
            Base64::decode_vec("MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC")
                .unwrap();
        let seed: [u8; 32] = expected[16..].try_into().unwrap();
        let key =
            Ed25519HostPrivateKey::from_openssh(Container::valid(seed).pem().as_bytes()).unwrap();
        assert_eq!(key.to_pkcs8_der().as_slice(), expected.as_slice());
    }

    #[test]
    fn ssh_keygen_fixture_decodes() {
        let key = Ed25519HostPrivateKey::from_openssh(SSH_KEYGEN_ED25519.as_bytes()).unwrap();
        assert_eq!(key.fingerprint().to_string(), SSH_KEYGEN_ED25519_FP);
        let pub_b64 = SSH_KEYGEN_ED25519_PUB.split(' ').nth(1).unwrap();
        assert_eq!(
            key.ssh_blob().as_slice(),
            Base64::decode_vec(pub_b64).unwrap().as_slice()
        );
        let dbg = alloc::format!("{key:?}");
        assert!(dbg.contains("public_sha256"));
        assert!(!dbg.contains("seed"));
    }

    #[test]
    fn independent_writer_matches_parser() {
        let seed = [9u8; 32];
        let key =
            Ed25519HostPrivateKey::from_openssh(Container::valid(seed).pem().as_bytes()).unwrap();
        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(key.public_key().as_bytes(), &expected);
        assert_eq!(&key.ssh_blob()[..], ed_blob(&expected).as_slice());
    }

    fn reject(c: &Container) -> PrivateKeyError {
        Ed25519HostPrivateKey::from_openssh(c.pem().as_bytes()).unwrap_err()
    }

    #[test]
    fn inconsistent_containers_are_rejected() {
        let seed = [3u8; 32];
        let other = SigningKey::from_bytes(&[4u8; 32])
            .verifying_key()
            .to_bytes();

        // Seed does not derive the (consistently repeated) public key: only
        // the explicit derivation check catches this.
        let mut c = Container::valid(seed);
        c.outer_public = other;
        c.inner_public = other;
        c.embedded_public = other;
        assert_eq!(reject(&c), PrivateKeyError::PublicKeyMismatch);

        // Outer public differs from the private section.
        let mut c = Container::valid(seed);
        c.outer_public = other;
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Embedded public differs from the private section's public.
        let mut c = Container::valid(seed);
        c.embedded_public = other;
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Check integers differ.
        let mut c = Container::valid(seed);
        c.checkints = (1, 2);
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Two keys claimed.
        let mut c = Container::valid(seed);
        c.nkeys = 2;
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // KDF named on an unencrypted key.
        let mut c = Container::valid(seed);
        c.kdf = "bcrypt";
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Bytes after the private section.
        let mut c = Container::valid(seed);
        c.trailing = b"\x00";
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));
    }

    #[test]
    fn other_formats_and_sizes() {
        assert_eq!(
            Ed25519HostPrivateKey::from_openssh(
                b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n"
            )
            .unwrap_err(),
            PrivateKeyError::NotOpenssh
        );
        assert_eq!(
            Ed25519HostPrivateKey::from_openssh(&[b'a'; MAX_PRIVATE_KEY_BYTES + 1]).unwrap_err(),
            PrivateKeyError::TooLarge {
                limit: MAX_PRIVATE_KEY_BYTES
            }
        );
        let truncated =
            SSH_KEYGEN_ED25519.replace("CWIXPgHvi2hkEv+kUcPgAAAAC3RhdGFtaS10ZXN0AQI=\n", "");
        assert!(matches!(
            Ed25519HostPrivateKey::from_openssh(truncated.as_bytes()).unwrap_err(),
            PrivateKeyError::Malformed(_)
        ));
    }

    #[test]
    fn errors_never_carry_secrets() {
        let e = PrivateKeyError::Encrypted.to_string();
        assert!(e.contains("passphrase"));
    }
}

#[cfg(test)]
mod other_type_tests {
    use super::*;
    use crate::test_vectors::*;
    use alloc::string::ToString;

    #[test]
    fn ed25519_only_decoder_refuses_other_types_by_name() {
        assert_eq!(
            Ed25519HostPrivateKey::from_openssh(RSA_2048_OPENSSH.as_bytes()).unwrap_err(),
            PrivateKeyError::UnsupportedAlgorithm(String::from("ssh-rsa"))
        );
        assert!(matches!(
            Ed25519HostPrivateKey::from_openssh(P256_OPENSSH.as_bytes()).unwrap_err(),
            PrivateKeyError::UnsupportedAlgorithm(_)
        ));
        let generic = HostPrivateKey::from_openssh(tests::SSH_KEYGEN_ED25519.as_bytes()).unwrap();
        assert_eq!(generic.key_type(), KeyType::Ed25519);
        assert_eq!(generic.to_private_key_der().format, PrivateKeyFormat::Pkcs8);
        assert_eq!(
            generic.fingerprint().to_string(),
            tests::SSH_KEYGEN_ED25519_FP
        );
    }

    #[test]
    fn unsupported_types_are_refused() {
        // P-384 in every build; RSA / P-256 when their feature is off.
        assert!(matches!(
            HostPrivateKey::from_openssh(P384_OPENSSH.as_bytes()).unwrap_err(),
            PrivateKeyError::UnsupportedAlgorithm(_)
        ));
        #[cfg(not(feature = "rsa"))]
        assert_eq!(
            HostPrivateKey::from_openssh(RSA_2048_OPENSSH.as_bytes()).unwrap_err(),
            PrivateKeyError::UnsupportedAlgorithm(String::from("ssh-rsa"))
        );
        #[cfg(not(feature = "ecdsa-p256"))]
        assert!(matches!(
            HostPrivateKey::from_openssh(P256_OPENSSH.as_bytes()).unwrap_err(),
            PrivateKeyError::UnsupportedAlgorithm(_)
        ));
    }

    #[cfg(feature = "rsa")]
    mod rsa {
        use super::*;
        use ssh_key::Mpint;
        use ssh_key::private::{KeypairData, RsaKeypair};

        fn keypair() -> RsaKeypair {
            let key = ssh_key::PrivateKey::from_openssh(RSA_2048_OPENSSH).unwrap();
            let KeypairData::Rsa(pair) = key.key_data() else {
                panic!()
            };
            pair.clone()
        }

        #[test]
        fn converts_to_the_same_pkcs1_as_openssl() {
            let key = HostPrivateKey::from_openssh(RSA_2048_OPENSSH.as_bytes()).unwrap();
            assert_eq!(key.key_type(), KeyType::Rsa);
            assert_eq!(key.ssh_blob(), b64(RSA_2048_PUB));
            assert_eq!(key.fingerprint().to_string(), RSA_2048_FP);
            let der = key.to_private_key_der();
            assert_eq!(der.format, PrivateKeyFormat::Pkcs1);
            // Byte-for-byte what OpenSSL wrote, CRT exponents included.
            assert_eq!(der.der.as_slice(), b64(RSA_2048_PKCS1).as_slice());
            let dbg = alloc::format!("{key:?} {der:?}");
            assert!(dbg.contains("modulus_bits: 2048"), "{dbg}");
            assert!(!dbg.contains("d:") && !dbg.contains("dp"), "{dbg}");
        }

        #[test]
        fn policy_and_consistency() {
            assert_eq!(
                HostPrivateKey::from_openssh(RSA_1024_OPENSSH.as_bytes()).unwrap_err(),
                PrivateKeyError::Policy(KeyError::RsaModulus { bits: 1024 })
            );
            let reject = |pair: &RsaKeypair| RsaHostPrivateKey::from_keypair(pair).unwrap_err();
            let bump = |m: &Mpint| {
                let mut b = m.as_positive_bytes().unwrap().to_vec();
                let last = b.len() - 1;
                b[last] ^= 0x02;
                Mpint::from_positive_bytes(&b).unwrap()
            };
            // A different p (so p·q != n).
            let mut pair = keypair();
            pair.private.p = bump(&pair.private.p);
            assert_eq!(reject(&pair), PrivateKeyError::PublicKeyMismatch);
            // Swapped in another modulus of the same size (public/private
            // from different keys).
            let mut pair = keypair();
            pair.public.n = bump(&pair.public.n);
            assert_eq!(reject(&pair), PrivateKeyError::PublicKeyMismatch);
            // d >= n.
            let mut pair = keypair();
            pair.private.d = pair.public.n.clone();
            assert_eq!(reject(&pair), PrivateKeyError::PublicKeyMismatch);
            // Zero components.
            let mut pair = keypair();
            pair.private.q = Mpint::from_positive_bytes(&[]).unwrap();
            assert!(matches!(reject(&pair), PrivateKeyError::Malformed(_)));
            // The unmodified pair is accepted.
            assert!(RsaHostPrivateKey::from_keypair(&keypair()).is_ok());
        }
    }

    #[cfg(feature = "ecdsa-p256")]
    #[test]
    fn p256_converts_to_the_same_sec1_as_openssl() {
        let key = HostPrivateKey::from_openssh(P256_OPENSSH.as_bytes()).unwrap();
        assert_eq!(key.key_type(), KeyType::EcdsaP256);
        assert_eq!(key.ssh_blob(), b64(P256_PUB));
        assert_eq!(key.fingerprint().to_string(), P256_FP);
        let der = key.to_private_key_der();
        assert_eq!(der.format, PrivateKeyFormat::Sec1);
        assert_eq!(der.der.as_slice(), b64(P256_SEC1).as_slice());
        let dbg = alloc::format!("{key:?}");
        assert!(
            dbg.contains("public_sha256") && !dbg.contains("scalar"),
            "{dbg}"
        );
        // A compressed or foreign point in the container is refused.
        assert!(matches!(
            EcdsaP256HostPrivateKey::from_parts(&[2u8; 33], &[1u8; 32]),
            Err(PrivateKeyError::Policy(KeyError::PointEncoding))
        ));
        assert!(matches!(
            EcdsaP256HostPrivateKey::from_parts(&b64(P256_PUB)[39..], &[0u8; 32]),
            Err(PrivateKeyError::Malformed(_))
        ));
    }
}
