//! Host-key types and SSH host signature schemes, kept separate.
//!
//! A **key type** names a public-key blob format (`ssh-ed25519`, `ssh-rsa`,
//! `ecdsa-sha2-nistp256`); a **signature scheme** names what the peers
//! negotiate in `server_host_key_algorithms` and what the signature blob is
//! labelled with (`ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`,
//! `ecdsa-sha2-nistp256`). They coincide except for RSA, where one `ssh-rsa`
//! key is used with two SHA-2 schemes (RFC 8332). The `ssh-rsa` *signature*
//! scheme (RSA/SHA-1) has no variant here and can never be selected.
//!
//! These are names only; no provider is needed. Whether a scheme can be
//! verified in a given build is [`SignatureScheme::is_enabled`] (the key
//! type's Cargo feature) plus, for everything but Ed25519, a
//! [`crate::provider::SignatureProvider`] supplied by the host.

use core::fmt;

use tatami_ssh_wire::algorithms;

/// A supported public-key blob format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyType {
    /// `ssh-ed25519` (RFC 8709 §4). Feature `ed25519`.
    Ed25519,
    /// `ssh-rsa` (RFC 4253 §6.6), used only with RSA/SHA-2 signatures.
    /// Feature `rsa`.
    Rsa,
    /// `ecdsa-sha2-nistp256` (RFC 5656 §3.1). Feature `ecdsa-p256`.
    EcdsaP256,
}

impl KeyType {
    /// The blob algorithm name.
    #[must_use]
    pub const fn name(self) -> &'static [u8] {
        match self {
            KeyType::Ed25519 => algorithms::SSH_ED25519,
            KeyType::Rsa => algorithms::SSH_RSA,
            KeyType::EcdsaP256 => algorithms::ECDSA_SHA2_NISTP256,
        }
    }

    /// The key type named `name`, whether or not it is enabled.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        [KeyType::Ed25519, KeyType::Rsa, KeyType::EcdsaP256]
            .into_iter()
            .find(|k| k.name() == name)
    }

    /// `true` when this build parses and verifies keys of this type (its
    /// Cargo feature is on).
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        match self {
            KeyType::Ed25519 => cfg!(feature = "ed25519"),
            KeyType::Rsa => cfg!(feature = "rsa"),
            KeyType::EcdsaP256 => cfg!(feature = "ecdsa-p256"),
        }
    }

    /// SSHFP algorithm number (RFC 4255 §3.1.1, RFC 6594 §5.1, RFC 7479
    /// §3.1).
    #[must_use]
    pub const fn sshfp_algorithm(self) -> u8 {
        match self {
            KeyType::Rsa => 1,
            KeyType::EcdsaP256 => 3,
            KeyType::Ed25519 => 4,
        }
    }
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ascii(self.name()))
    }
}

/// A supported SSH host signature scheme (the negotiated
/// `server_host_key_algorithms` entry and the signature blob's label).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    /// `ssh-ed25519` (RFC 8709 §6).
    Ed25519,
    /// `ecdsa-sha2-nistp256`: ECDSA P-256 with SHA-256 (RFC 5656 §3.1.2).
    EcdsaP256Sha256,
    /// `rsa-sha2-512`: RSASSA-PKCS1-v1_5 with SHA-512 (RFC 8332 §3).
    RsaSha2_512,
    /// `rsa-sha2-256`: RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8332 §3).
    RsaSha2_256,
}

impl SignatureScheme {
    /// Every scheme in Tatami's client preference order: Ed25519 first,
    /// then ECDSA P-256, then RSA with SHA-512 before SHA-256. This follows
    /// OpenSSH's default `HostKeyAlgorithms` order for these entries.
    pub const PREFERENCE: [SignatureScheme; 4] = [
        SignatureScheme::Ed25519,
        SignatureScheme::EcdsaP256Sha256,
        SignatureScheme::RsaSha2_512,
        SignatureScheme::RsaSha2_256,
    ];

    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static [u8] {
        match self {
            SignatureScheme::Ed25519 => algorithms::SSH_ED25519,
            SignatureScheme::EcdsaP256Sha256 => algorithms::ECDSA_SHA2_NISTP256,
            SignatureScheme::RsaSha2_512 => algorithms::RSA_SHA2_512,
            SignatureScheme::RsaSha2_256 => algorithms::RSA_SHA2_256,
        }
    }

    /// The scheme named `name`, whether or not it is enabled. `ssh-rsa`
    /// (RSA/SHA-1) and every other name return `None`.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        Self::PREFERENCE.into_iter().find(|s| s.name() == name)
    }

    /// The key type this scheme signs with.
    #[must_use]
    pub const fn key_type(self) -> KeyType {
        match self {
            SignatureScheme::Ed25519 => KeyType::Ed25519,
            SignatureScheme::EcdsaP256Sha256 => KeyType::EcdsaP256,
            SignatureScheme::RsaSha2_512 | SignatureScheme::RsaSha2_256 => KeyType::Rsa,
        }
    }

    /// `true` when the key type's feature is on in this build.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.key_type().is_enabled()
    }

    /// `true` when verification needs a host-supplied
    /// [`crate::provider::SignatureProvider`] (everything but Ed25519, which
    /// is verified in this crate with `ed25519-dalek`).
    #[must_use]
    pub const fn needs_provider(self) -> bool {
        !matches!(self, SignatureScheme::Ed25519)
    }
}

impl fmt::Display for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ascii(self.name()))
    }
}

/// The constants above are ASCII.
fn ascii(name: &'static [u8]) -> &'static str {
    core::str::from_utf8(name).unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn names_round_trip_and_sha1_has_no_scheme() {
        for s in SignatureScheme::PREFERENCE {
            assert_eq!(SignatureScheme::from_name(s.name()), Some(s));
            assert_eq!(s.to_string().as_bytes(), s.name());
        }
        for k in [KeyType::Ed25519, KeyType::Rsa, KeyType::EcdsaP256] {
            assert_eq!(KeyType::from_name(k.name()), Some(k));
        }
        // `ssh-rsa` is a key type, never a signature scheme.
        assert_eq!(SignatureScheme::from_name(b"ssh-rsa"), None);
        assert_eq!(KeyType::from_name(b"ssh-rsa"), Some(KeyType::Rsa));
        for other in [
            &b"ssh-dss"[..],
            b"rsa-sha2-384",
            b"ecdsa-sha2-nistp384",
            b"ssh-ed25519-cert-v01@openssh.com",
            b"",
        ] {
            assert_eq!(SignatureScheme::from_name(other), None);
        }
    }

    #[test]
    fn preference_order_and_key_types() {
        assert_eq!(
            SignatureScheme::PREFERENCE.map(SignatureScheme::name),
            [
                &b"ssh-ed25519"[..],
                b"ecdsa-sha2-nistp256",
                b"rsa-sha2-512",
                b"rsa-sha2-256"
            ]
        );
        assert_eq!(SignatureScheme::RsaSha2_256.key_type(), KeyType::Rsa);
        assert_eq!(SignatureScheme::RsaSha2_512.key_type(), KeyType::Rsa);
        assert!(!SignatureScheme::Ed25519.needs_provider());
        assert!(SignatureScheme::RsaSha2_512.needs_provider());
        assert_eq!(KeyType::Rsa.sshfp_algorithm(), 1);
        assert_eq!(KeyType::EcdsaP256.sshfp_algorithm(), 3);
        assert_eq!(KeyType::Ed25519.sshfp_algorithm(), 4);
    }
}
