//! SSH public-key and signature representations, host-key verification and
//! trust-decision contracts.
//!
//! This package owns the SSH public-key and signature blob encodings
//! (RFC 4253 §6.6, RFC 8709), thin verification wrappers around a maintained
//! cryptographic provider, the OpenSSH `SHA256:` fingerprint presentation,
//! and the host trust-policy contract. It does not own key-exchange
//! orchestration, TLS, user authentication policy, or any home-grown
//! cryptographic primitive.
//!
//! # What is implemented
//!
//! | Module | Feature | Contents |
//! |---|---|---|
//! | [`blob`] | none | `PublicKeyBlob` / `SignatureBlob` codecs, `encode_ed25519_blob` |
//! | [`error`] | none | `BlobError`, `KeyError`, `VerifyError` |
//! | [`fingerprint`] | type: none; compute/text: `ed25519` | `Sha256Fingerprint`, `SHA256:` base64 rendering and parsing |
//! | [`trust`] | none (`HostIdentity::from_blob`: `ed25519`) | `HostTrustPolicy`, `TrustDecision`, `PinnedSha256`, `NoTrustPolicy` |
//! | [`ed25519`] | `ed25519` | `Ed25519PublicKey`, `Ed25519Signature`, `HostKey`; verification with `ed25519-dalek` `verify_strict` |
//! | [`spki`] | `ed25519` | Strict Ed25519 `SubjectPublicKeyInfo` ⇄ `ssh-ed25519` blob conversion (RFC 8410 / RFC 7250 identity) |
//! | [`sshfp`] | `ed25519` | SSHFP values (RFC 4255/6594/7479) from a blob; no DNS |
//! | [`known_hosts`] | `known-hosts` | Read-only, bounded OpenSSH `known_hosts` parser and `KnownHostsPolicy` |
//! | [`openssh_key`] | `openssh-key` | Unencrypted Ed25519 `openssh-key-v1` host private keys, PKCS#8 in memory |
//!
//! # What is not implemented
//!
//! - Signing. The only private-key support is decoding an Ed25519 host key
//!   so a TLS stack can sign with it; encrypted keys are rejected.
//! - RSA (`ssh-rsa`, `rsa-sha2-*`), ECDSA (`ecdsa-sha2-nistp*`), DSA, or
//!   Ed448. Unknown algorithms are reported with their name preserved.
//! - OpenSSH certificates (`*-cert-v01@openssh.com`) and
//!   `@cert-authority` trust.
//! - Host-key prompting, enrollment or writing `known_hosts`; reading
//!   `$HOME/.ssh` or system files implicitly.
//!
//! # Provider
//!
//! With the `ed25519` feature the crate uses `ed25519-dalek` (verification
//! only), `sha2` (fingerprints) and `base64ct` (fingerprint text), all
//! pure-Rust and `no_std`; see `docs/crypto-provider-audit.md` for versions
//! and the rules that govern them. Without the feature the crate still
//! builds: the blob codecs, error types, fingerprint type and trust policy
//! contract are available so higher layers can be written against them.
//!
//! # Portability
//!
//! Always `no_std` with `alloc`. There is no `std` feature. Allocation is
//! used only to carry peer-supplied algorithm names inside error values.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub use tatami_wire as wire;

pub mod blob;
#[cfg(feature = "ed25519")]
pub mod ed25519;
pub mod error;
pub mod fingerprint;
#[cfg(feature = "known-hosts")]
pub mod known_hosts;
#[cfg(feature = "openssh-key")]
pub mod openssh_key;
#[cfg(feature = "ed25519")]
pub mod spki;
#[cfg(feature = "ed25519")]
pub mod sshfp;
pub mod trust;

pub use blob::{PublicKeyBlob, SignatureBlob};
pub use error::{BlobError, KeyError, VerifyError};
pub use fingerprint::Sha256Fingerprint;
pub use trust::{HostIdentity, HostTrustPolicy, TrustDecision};

#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519PublicKey, Ed25519Signature, HostKey};
