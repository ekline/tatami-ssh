//! The narrow hook through which a host supplies RSA and ECDSA P-256
//! signature verification.
//!
//! This crate stays `no_std` and links no C or assembly, so it does not
//! carry an RSA or NIST-curve implementation. Everything up to the final
//! mathematical check happens here: blob and signature parsing, strict
//! `mpint` rules, the RSA key-size and exponent policy, binding to the
//! negotiated scheme, and conversion to the fixed encodings a provider
//! expects. The host then answers one question per signature through
//! [`SignatureProvider::verify`]. Tatami's host adapter implements it with
//! `ring` (the provider rustls already uses); a bare-metal build can supply
//! its own or offer Ed25519 only.
//!
//! Requests are fully validated before they reach a provider:
//!
//! - [`ProviderRequest::RsaPkcs1v15`]: `modulus` and `exponent` are the
//!   minimal big-endian magnitudes of a key that passed
//!   `crate::rsa`'s policy (2048–8192-bit odd modulus, odd exponent of at
//!   most four bytes and at least 3), and `signature` is exactly as long as
//!   the modulus (RFC 8332 shortened signatures are left-padded here, never
//!   truncated).
//! - [`ProviderRequest::EcdsaP256Sha256`]: `public_point` is a 65-byte SEC1
//!   uncompressed encoding (`04 || X || Y`) and `signature` is `r || s`,
//!   each left-padded to 32 bytes from strict non-zero SSH `mpint`s. Whether
//!   the point is on the curve and `r`, `s` are below the group order is the
//!   provider's to decide.

use crate::algorithm::SignatureScheme;

/// Hash used under RSASSA-PKCS1-v1_5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaHash {
    /// SHA-256 (`rsa-sha2-256`).
    Sha256,
    /// SHA-512 (`rsa-sha2-512`).
    Sha512,
}

/// A signature check, in the provider-neutral form described in the module
/// documentation. The message is passed separately and is hashed by the
/// provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderRequest<'a> {
    /// RSASSA-PKCS1-v1_5 (RFC 8017 §8.2.2) — not RSA-PSS.
    RsaPkcs1v15 {
        /// Digest algorithm.
        hash: RsaHash,
        /// Modulus `n`, big-endian, no leading zero byte.
        modulus: &'a [u8],
        /// Public exponent `e`, big-endian, no leading zero byte.
        exponent: &'a [u8],
        /// Signature, exactly `modulus.len()` bytes.
        signature: &'a [u8],
    },
    /// ECDSA over P-256 with SHA-256 (FIPS 186-4), fixed-width `r || s`.
    EcdsaP256Sha256 {
        /// SEC1 uncompressed point, `04 || X || Y`.
        public_point: &'a [u8; 65],
        /// `r || s`, 32 bytes each, big-endian.
        signature: &'a [u8; 64],
    },
}

/// The provider refused the signature (or could not evaluate it). Carries
/// nothing: every refusal is a hard verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderRejected;

/// Host-supplied RSA / ECDSA P-256 signature verification.
///
/// Implementations must be pure verification: no key generation, signing,
/// decryption or I/O.
pub trait SignatureProvider {
    /// `true` when [`SignatureProvider::verify`] can evaluate `scheme`.
    /// Ed25519 is never asked about; it does not go through a provider.
    fn supports(&self, scheme: SignatureScheme) -> bool;

    /// Verifies `request` over `message`.
    fn verify(&self, message: &[u8], request: &ProviderRequest<'_>)
    -> Result<(), ProviderRejected>;
}

impl<P: SignatureProvider + ?Sized> SignatureProvider for &P {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        (**self).supports(scheme)
    }

    fn verify(
        &self,
        message: &[u8],
        request: &ProviderRequest<'_>,
    ) -> Result<(), ProviderRejected> {
        (**self).verify(message, request)
    }
}

impl<P: SignatureProvider + ?Sized> SignatureProvider for alloc::boxed::Box<P> {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        (**self).supports(scheme)
    }

    fn verify(
        &self,
        message: &[u8],
        request: &ProviderRequest<'_>,
    ) -> Result<(), ProviderRejected> {
        (**self).verify(message, request)
    }
}
