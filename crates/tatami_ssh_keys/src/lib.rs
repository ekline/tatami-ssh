//! SSH public-key and signature representations, host-key verification and
//! trust-decision contracts.
//!
//! This package owns the SSH public-key and signature blob encodings
//! (RFC 4253 §6.6, RFC 8709, RFC 8332, RFC 5656), verification bound to the
//! negotiated signature scheme, the OpenSSH `SHA256:` fingerprint
//! presentation, and the host trust-policy contract. It does not own
//! key-exchange orchestration, TLS, user authentication policy, or any
//! home-grown cryptographic primitive.
//!
//! # Key types
//!
//! Each key type is an explicit feature; defaults are empty.
//!
//! | Feature | Key blob | Host signature schemes | Verified by |
//! |---|---|---|---|
//! | `ed25519` | `ssh-ed25519` | `ssh-ed25519` | this crate (`ed25519-dalek`) |
//! | `rsa` | `ssh-rsa` (2048–8192-bit) | `rsa-sha2-512`, `rsa-sha2-256` | a host [`provider::SignatureProvider`] |
//! | `ecdsa-p256` | `ecdsa-sha2-nistp256` | `ecdsa-sha2-nistp256` | a host [`provider::SignatureProvider`] |
//!
//! RSA and P-256 are parsed, policed and bound to the negotiated scheme
//! here; only the final mathematical check is handed to the provider, so
//! the crate stays `no_std` without C or assembly. The `ssh-rsa` signature
//! scheme (RSA/SHA-1) does not exist in [`algorithm::SignatureScheme`].
//!
//! # Modules
//!
//! | Module | Feature | Contents |
//! |---|---|---|
//! | [`algorithm`] | none | `KeyType`, `SignatureScheme` (names, preference order) |
//! | [`provider`] | none | `SignatureProvider` hook and its request type |
//! | [`blob`] | none | `PublicKeyBlob` / `SignatureBlob` codecs, `encode_ed25519_blob` |
//! | [`error`] | none | `BlobError`, `KeyError`, `VerifyError` |
//! | [`fingerprint`] | type: none; compute/text: `fingerprint` | `Sha256Fingerprint`, `SHA256:` base64 rendering and parsing |
//! | [`trust`] | none (`HostIdentity::from_blob`: `fingerprint`) | `HostTrustPolicy`, `TrustDecision`, `PinnedSha256`, `NoTrustPolicy` |
//! | `ed25519` | `ed25519` | `Ed25519PublicKey`, `Ed25519Signature`; `verify_strict` |
//! | `rsa` | `rsa` | `RsaPublicKey`: blob, policy, signature preparation |
//! | `ecdsa` | `ecdsa-p256` | `EcdsaP256PublicKey`: blob, signature preparation |
//! | `host_key` | any key type | `HostKey` and scheme-bound `verify` |
//! | `spki` | any key type | Strict `SubjectPublicKeyInfo` ⇄ SSH blob conversion (RFC 7250 identity) |
//! | `sshfp` | any key type | SSHFP SHA-256 values (RFC 4255/6594/7479) from a blob; no DNS |
//! | `known_hosts` | `known-hosts` (hashed names: `openssh-hashed-hosts`) | Read-only, bounded OpenSSH `known_hosts` parser and `KnownHostsPolicy` |
//! | `openssh_key` | `openssh-key` (+ `rsa` / `ecdsa-p256`) | Unencrypted `openssh-key-v1` host private keys, converted in memory for a TLS stack |
//!
//! Feature-gated modules are named with plain code spans so this
//! documentation builds under every feature combination.
//!
//! # What is not implemented
//!
//! - Signing. The only private-key support is decoding a host key so a TLS
//!   stack can sign with it; encrypted keys are rejected.
//! - DSA, ECDSA P-384/P-521, Ed448, security-key (`sk-*`) keys. Unknown
//!   algorithms are reported with their name preserved.
//! - OpenSSH certificates (`*-cert-v01@openssh.com`) and
//!   `@cert-authority` trust.
//! - Host-key prompting, enrollment or writing `known_hosts`; reading
//!   `$HOME/.ssh` or system files implicitly.
//!
//! # Providers
//!
//! `fingerprint` uses `sha2` and `base64ct`; `ed25519` adds `ed25519-dalek`
//! (verification only); `openssh-key` adds `ssh-key` (parsing), `zeroize`
//! and `crypto-bigint` (the RSA CRT exponents a TLS stack needs), all
//! pure-Rust and `no_std`; see `docs/crypto-provider-audit.md` for versions
//! and the rules that govern them. Without any feature the crate still
//! builds: the blob codecs, names, error types, fingerprint type, provider
//! hook and trust policy contract are available.
//!
//! No SHA-1 is linked unless `openssh-hashed-hosts` is enabled; it then
//! comes only through the legacy hashed-hostname matcher crate, called only
//! by `known_hosts` (enforced by `scripts/check-sha1-boundary.py`).
//!
//! # Portability
//!
//! Always `no_std` with `alloc`. There is no `std` feature. Allocation is
//! used for peer-supplied names in errors and for RSA key material.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub use tatami_ssh_wire as wire;

pub mod algorithm;
pub mod blob;
#[cfg(feature = "ecdsa-p256")]
pub mod ecdsa;
#[cfg(feature = "ed25519")]
pub mod ed25519;
pub mod error;
pub mod fingerprint;
#[cfg(any(feature = "ed25519", feature = "rsa", feature = "ecdsa-p256"))]
pub mod host_key;
#[cfg(feature = "known-hosts")]
pub mod known_hosts;
#[cfg(feature = "openssh-key")]
pub mod openssh_key;
pub mod provider;
#[cfg(feature = "rsa")]
pub mod rsa;
#[cfg(any(feature = "ed25519", feature = "rsa", feature = "ecdsa-p256"))]
pub mod spki;
#[cfg(any(feature = "ed25519", feature = "rsa", feature = "ecdsa-p256"))]
pub mod sshfp;
pub mod trust;

#[cfg(test)]
mod test_vectors;

pub use algorithm::{KeyType, SignatureScheme};
pub use blob::{PublicKeyBlob, SignatureBlob};
pub use error::{BlobError, KeyError, VerifyError};
pub use fingerprint::Sha256Fingerprint;
pub use provider::SignatureProvider;
pub use trust::{HostIdentity, HostTrustPolicy, TrustDecision};

#[cfg(feature = "ed25519")]
pub use ed25519::{Ed25519PublicKey, Ed25519Signature};
#[cfg(any(feature = "ed25519", feature = "rsa", feature = "ecdsa-p256"))]
pub use host_key::HostKey;
