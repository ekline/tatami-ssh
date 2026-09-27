//! Host-key trust decisions, kept separate from signature verification.
//!
//! A verified `KEX_ECDH_REPLY` signature proves that whoever holds the
//! private key for the presented `K_S` participated in this exchange. It
//! does **not** prove that `K_S` belongs to the host the user intended to
//! reach; an attacker in the path can present their own key and sign
//! correctly. Deciding whether to trust `K_S` is therefore a distinct step
//! with its own inputs, expressed here as [`HostTrustPolicy`].
//!
//! Rules:
//!
//! - A policy returns a [`TrustDecision`]; the caller aborts on
//!   [`TrustDecision::Untrusted`]. There is no "ask" or "warn" outcome at
//!   this layer, and nothing here writes anywhere.
//! - Never auto-enroll. Seeing a key for the first time is not a reason to
//!   trust it; [`NoTrustPolicy`] makes that the default when no pin is
//!   configured, so absence of configuration fails closed.
//! - Policies: a pinned SHA-256 fingerprint ([`PinnedSha256`]), nothing
//!   ([`NoTrustPolicy`]), and (feature `known-hosts`) a read-only OpenSSH
//!   `known_hosts` file bound to one lookup name
//!   (`known_hosts::KnownHostsPolicy`). Every transport reaches the same
//!   trait with the same [`HostIdentity`]: the complete SSH public-key blob.
//!
//! Configuration problems (a malformed file, an unreadable path) are not
//! decisions: they are reported when the policy is built, before any
//! connection, so a broken configuration can never look like "unknown
//! host".
//!
//! This module is feature-free and key-type agnostic: policies compare the
//! complete blob (and its algorithm name), so Ed25519, RSA and ECDSA P-256
//! keys are judged the same way. Computing the fingerprint in a
//! [`HostIdentity`] needs the `fingerprint` feature (`sha2`); the decision
//! itself does not.

use crate::fingerprint::Sha256Fingerprint;

/// Outcome of a host trust decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustDecision {
    /// The host key is acceptable; `source` says why.
    Trusted {
        /// What established the trust.
        source: TrustSource,
    },
    /// The host key must not be accepted; `reason` says why.
    Untrusted {
        /// Why the key was refused.
        reason: UntrustedReason,
    },
}

impl TrustDecision {
    /// Returns `true` for [`TrustDecision::Trusted`].
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, TrustDecision::Trusted { .. })
    }
}

/// What established trust in a host key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustSource {
    /// The key's fingerprint equals a fingerprint the operator pinned.
    PinnedFingerprint,
    /// A `known_hosts` entry applicable to the lookup name lists exactly
    /// this public key.
    KnownHosts {
        /// 1-based line number of the matching entry.
        line: usize,
    },
}

impl TrustSource {
    /// Stable code for reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            TrustSource::PinnedFingerprint => "pinned_fingerprint",
            TrustSource::KnownHosts { .. } => "known_hosts",
        }
    }

    /// The `known_hosts` line that established trust, if any.
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        match self {
            TrustSource::PinnedFingerprint => None,
            TrustSource::KnownHosts { line } => Some(*line),
        }
    }
}

/// Why a host key was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UntrustedReason {
    /// A pin is configured and the presented key's fingerprint differs.
    FingerprintMismatch,
    /// No policy can vouch for this key (for example no pin is configured).
    /// This is the fail-closed default, not an error in the configuration.
    NoPolicy,
    /// No `known_hosts` entry applies to the lookup name. A noninteractive
    /// client never enrolls, so this always fails.
    UnknownHost,
    /// Entries for this key algorithm apply to the lookup name, and none of
    /// them lists the presented key: the host key changed (or the name
    /// reached a different host).
    KeyChanged {
        /// 1-based line of the first applicable entry for the algorithm.
        line: usize,
    },
    /// An applicable `@revoked` entry lists the presented key. Overrides
    /// any positive match, whatever the line order.
    Revoked {
        /// 1-based line of the revocation.
        line: usize,
    },
    /// Only `@cert-authority` entries apply. OpenSSH host certificates are
    /// not supported, and a CA key is never treated as a pinned host key.
    CertificateAuthorityOnly,
    /// Only entries for other key algorithms apply; they confer no trust on
    /// the presented key.
    NoKeyForAlgorithm,
    /// The presented identity is not a key type this policy can judge.
    UnsupportedIdentity,
}

impl UntrustedReason {
    /// Stable code for reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            UntrustedReason::FingerprintMismatch => "fingerprint_mismatch",
            UntrustedReason::NoPolicy => "no_policy",
            UntrustedReason::UnknownHost => "unknown_host",
            UntrustedReason::KeyChanged { .. } => "key_changed",
            UntrustedReason::Revoked { .. } => "revoked",
            UntrustedReason::CertificateAuthorityOnly => "certificate_authority_only",
            UntrustedReason::NoKeyForAlgorithm => "no_key_for_algorithm",
            UntrustedReason::UnsupportedIdentity => "unsupported_identity",
        }
    }

    /// The `known_hosts` line the reason refers to, if any.
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        match self {
            UntrustedReason::KeyChanged { line } | UntrustedReason::Revoked { line } => Some(*line),
            _ => None,
        }
    }

    /// One-line human description.
    #[must_use]
    pub const fn describe(&self) -> &'static str {
        match self {
            UntrustedReason::FingerprintMismatch => "fingerprint mismatch",
            UntrustedReason::NoPolicy => "no trust policy",
            UntrustedReason::UnknownHost => "host not listed in known_hosts",
            UntrustedReason::KeyChanged { .. } => {
                "known_hosts lists a different key for this host (key changed)"
            }
            UntrustedReason::Revoked { .. } => "key is revoked in known_hosts",
            UntrustedReason::CertificateAuthorityOnly => {
                "only @cert-authority entries apply; host certificates are not supported"
            }
            UntrustedReason::NoKeyForAlgorithm => {
                "known_hosts lists this host only with other key algorithms"
            }
            UntrustedReason::UnsupportedIdentity => "unsupported host identity",
        }
    }
}

/// What a policy gets to look at: the presented host key and its
/// fingerprint. The blob is the complete `K_S` so a future `known_hosts`
/// policy can compare the whole key, not only a digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostIdentity<'a> {
    /// Public-key algorithm name from the blob.
    pub algorithm: &'a [u8],
    /// The complete public-key blob (`K_S`).
    pub blob: &'a [u8],
    /// SHA-256 of `blob`.
    pub sha256: Sha256Fingerprint,
}

#[cfg(feature = "fingerprint")]
impl<'a> HostIdentity<'a> {
    /// Builds the identity for a parsed blob, computing its fingerprint.
    #[must_use]
    pub fn from_blob(blob: &crate::blob::PublicKeyBlob<'a>) -> Self {
        HostIdentity {
            algorithm: blob.algorithm,
            blob: blob.as_bytes(),
            sha256: Sha256Fingerprint::of_blob(blob.as_bytes()),
        }
    }
}

/// Decides whether a presented host key may be trusted.
///
/// Implementations must be pure with respect to the connection: no
/// enrollment, no prompting, no persistence. Those belong to an application
/// layer that can be audited separately.
pub trait HostTrustPolicy {
    /// Decides for `host`.
    fn decide(&self, host: &HostIdentity<'_>) -> TrustDecision;
}

/// Trusts exactly one fingerprint (the CLI `SHA256:` pin format).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedSha256(pub Sha256Fingerprint);

impl HostTrustPolicy for PinnedSha256 {
    fn decide(&self, host: &HostIdentity<'_>) -> TrustDecision {
        // `Sha256Fingerprint::eq` compares all 32 bytes without early exit.
        if self.0 == host.sha256 {
            TrustDecision::Trusted {
                source: TrustSource::PinnedFingerprint,
            }
        } else {
            TrustDecision::Untrusted {
                reason: UntrustedReason::FingerprintMismatch,
            }
        }
    }
}

/// A policy that can be shared with a TLS verifier on another thread.
pub trait SharedHostTrustPolicy: HostTrustPolicy + Send + Sync + core::fmt::Debug {}

impl<T: HostTrustPolicy + Send + Sync + core::fmt::Debug + ?Sized> SharedHostTrustPolicy for T {}

/// Trusts nothing. Use when no pin is configured so that the handshake
/// fails closed instead of silently accepting the first key seen.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoTrustPolicy;

impl HostTrustPolicy for NoTrustPolicy {
    fn decide(&self, _host: &HostIdentity<'_>) -> TrustDecision {
        TrustDecision::Untrusted {
            reason: UntrustedReason::NoPolicy,
        }
    }
}

impl<P: HostTrustPolicy + ?Sized> HostTrustPolicy for &P {
    fn decide(&self, host: &HostIdentity<'_>) -> TrustDecision {
        (**self).decide(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(digest: [u8; 32]) -> HostIdentity<'static> {
        HostIdentity {
            algorithm: b"ssh-ed25519",
            blob: b"not inspected by these policies",
            sha256: Sha256Fingerprint::from_bytes(digest),
        }
    }

    #[test]
    fn pinned_fingerprint_matches_or_mismatches() {
        let pin = PinnedSha256(Sha256Fingerprint::from_bytes([0xab; 32]));
        let ok = pin.decide(&identity([0xab; 32]));
        assert_eq!(
            ok,
            TrustDecision::Trusted {
                source: TrustSource::PinnedFingerprint
            }
        );
        assert!(ok.is_trusted());

        let mut other = [0xab; 32];
        other[0] = 0xac;
        let no = pin.decide(&identity(other));
        assert_eq!(
            no,
            TrustDecision::Untrusted {
                reason: UntrustedReason::FingerprintMismatch
            }
        );
        assert!(!no.is_trusted());
    }

    #[test]
    fn no_policy_fails_closed() {
        let d = NoTrustPolicy.decide(&identity([0; 32]));
        assert_eq!(
            d,
            TrustDecision::Untrusted {
                reason: UntrustedReason::NoPolicy
            }
        );
        // Through a trait object and a reference, as a driver would hold it.
        let dynamic: &dyn HostTrustPolicy = &NoTrustPolicy;
        assert!(!dynamic.decide(&identity([0; 32])).is_trusted());
        let by_ref = &PinnedSha256(Sha256Fingerprint::from_bytes([1; 32]));
        assert!(by_ref.decide(&identity([1; 32])).is_trusted());
    }

    #[test]
    fn codes_and_lines_are_stable() {
        assert_eq!(TrustSource::PinnedFingerprint.code(), "pinned_fingerprint");
        assert_eq!(TrustSource::PinnedFingerprint.line(), None);
        assert_eq!(TrustSource::KnownHosts { line: 3 }.code(), "known_hosts");
        assert_eq!(TrustSource::KnownHosts { line: 3 }.line(), Some(3));
        let reasons = [
            (
                UntrustedReason::FingerprintMismatch,
                "fingerprint_mismatch",
                None,
            ),
            (UntrustedReason::NoPolicy, "no_policy", None),
            (UntrustedReason::UnknownHost, "unknown_host", None),
            (
                UntrustedReason::KeyChanged { line: 2 },
                "key_changed",
                Some(2),
            ),
            (UntrustedReason::Revoked { line: 7 }, "revoked", Some(7)),
            (
                UntrustedReason::CertificateAuthorityOnly,
                "certificate_authority_only",
                None,
            ),
            (
                UntrustedReason::NoKeyForAlgorithm,
                "no_key_for_algorithm",
                None,
            ),
            (
                UntrustedReason::UnsupportedIdentity,
                "unsupported_identity",
                None,
            ),
        ];
        for (reason, code, line) in reasons {
            assert_eq!(reason.code(), code);
            assert_eq!(reason.line(), line);
            assert!(!reason.describe().is_empty());
        }
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn identity_from_blob_uses_the_complete_blob() {
        use crate::blob::PublicKeyBlob;
        use crate::blob::fixtures::test1_key_blob;

        let blob = test1_key_blob();
        let parsed = PublicKeyBlob::decode(&blob).unwrap();
        let id = HostIdentity::from_blob(&parsed);
        assert_eq!(id.algorithm, b"ssh-ed25519");
        assert_eq!(id.blob, &blob);
        assert_eq!(id.sha256, Sha256Fingerprint::of_blob(&blob));

        // A pin parsed from the CLI format trusts exactly this key.
        let pin = PinnedSha256(
            "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
                .parse()
                .unwrap(),
        );
        assert!(pin.decide(&id).is_trusted());
        let mut other = blob;
        other[50] ^= 1;
        let other_id = HostIdentity::from_blob(&PublicKeyBlob::decode(&other).unwrap());
        assert_eq!(
            pin.decide(&other_id),
            TrustDecision::Untrusted {
                reason: UntrustedReason::FingerprintMismatch
            }
        );
    }
}
