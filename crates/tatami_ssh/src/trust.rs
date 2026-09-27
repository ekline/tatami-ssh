//! Host trust selection shared by the TCP and QUIC client handshakes.
//!
//! Exactly one [`TrustConfig`] per run: an SSH `SHA256:` pin, or an
//! explicitly named `known_hosts` file. [`TrustConfig::prepare`] reads and
//! validates the file (bounded, through [`crate::host::files`]) and binds
//! it to the logical lookup name for the requested host and port **before
//! any connection**, producing one immutable policy object that both
//! transports hand to their verifiers. Nothing here reads `$HOME/.ssh`,
//! prompts, enrolls or writes.
//!
//! The lookup name is formed from the host the operator typed and the
//! requested port (`tatami_ssh_keys::known_hosts::lookup_name`). Resolved
//! addresses, TLS `--server-name` and QUIC path changes never replace it.

use alloc::string::String;
use alloc::sync::Arc;
use core::fmt;
use std::path::PathBuf;

use tatami_ssh_keys::fingerprint::Sha256Fingerprint;
use tatami_ssh_keys::known_hosts::{KnownHosts, KnownHostsError, Limits, LookupNameError};
use tatami_ssh_keys::trust::{PinnedSha256, SharedHostTrustPolicy, TrustDecision};

use crate::host::files::{FileError, read_bounded};

/// How the host key is judged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustConfig {
    /// SHA-256 of the complete SSH public-key blob (`ssh-keygen -lf`).
    Pin(Sha256Fingerprint),
    /// An explicitly named OpenSSH `known_hosts` file.
    KnownHostsFile(PathBuf),
}

impl From<Sha256Fingerprint> for TrustConfig {
    fn from(pin: Sha256Fingerprint) -> Self {
        TrustConfig::Pin(pin)
    }
}

impl TrustConfig {
    /// Stable code: `pinned_fingerprint` or `known_hosts`.
    #[must_use]
    pub const fn mode(&self) -> &'static str {
        match self {
            TrustConfig::Pin(_) => "pinned_fingerprint",
            TrustConfig::KnownHostsFile(_) => "known_hosts",
        }
    }

    /// The pin, in pin mode.
    #[must_use]
    pub const fn pin(&self) -> Option<Sha256Fingerprint> {
        match self {
            TrustConfig::Pin(p) => Some(*p),
            TrustConfig::KnownHostsFile(_) => None,
        }
    }

    /// The file, in `known_hosts` mode.
    #[must_use]
    pub fn known_hosts_file(&self) -> Option<&std::path::Path> {
        match self {
            TrustConfig::Pin(_) => None,
            TrustConfig::KnownHostsFile(p) => Some(p),
        }
    }

    /// Builds the policy for `host`/`port`. For `known_hosts`, reads and
    /// validates the whole file and binds the lookup name now.
    pub fn prepare(&self, host: &str, port: u16) -> Result<PreparedTrust, TrustConfigError> {
        match self {
            TrustConfig::Pin(pin) => Ok(PreparedTrust {
                policy: Arc::new(PinnedSha256(*pin)),
                lookup_name: None,
            }),
            TrustConfig::KnownHostsFile(path) => {
                let limits = Limits::default();
                let bytes =
                    read_bounded(path, limits.max_file_bytes).map_err(TrustConfigError::File)?;
                let parsed = KnownHosts::parse(&bytes, &limits).map_err(|error| {
                    TrustConfigError::Malformed {
                        path: path.clone(),
                        error,
                    }
                })?;
                let policy = parsed
                    .policy_for(host, port)
                    .map_err(TrustConfigError::LookupName)?;
                let lookup_name = Some(String::from(policy.lookup_name()));
                Ok(PreparedTrust {
                    policy: Arc::new(policy),
                    lookup_name,
                })
            }
        }
    }
}

/// Human-readable trust result, shared by the TCP and QUIC reports.
#[must_use]
pub fn trust_text(t: Option<TrustDecision>) -> String {
    match t {
        Some(TrustDecision::Trusted { source }) => match source.line() {
            Some(line) => alloc::format!("trusted (known_hosts line {line})"),
            None => String::from("trusted (pinned fingerprint)"),
        },
        Some(TrustDecision::Untrusted { reason }) => match reason.line() {
            Some(line) => {
                alloc::format!("untrusted ({}; known_hosts line {line})", reason.describe())
            }
            None => alloc::format!("untrusted ({})", reason.describe()),
        },
        None => String::from("not decided (host key not verified)"),
    }
}

/// A policy ready to hand to a verifier.
#[derive(Clone, Debug)]
pub struct PreparedTrust {
    /// The immutable decision object.
    pub policy: Arc<dyn SharedHostTrustPolicy>,
    /// The bound `known_hosts` lookup name, if any.
    pub lookup_name: Option<String>,
}

/// A trust configuration that cannot be used. Reported before connecting;
/// never confused with an untrusted key.
#[derive(Debug)]
pub enum TrustConfigError {
    /// The `known_hosts` file could not be read.
    File(FileError),
    /// The `known_hosts` file is malformed, or uses a format this build
    /// does not support (hashed host names without the
    /// `openssh-hashed-hosts` feature: [`KnownHostsError::Unsupported`]).
    Malformed {
        /// The file.
        path: PathBuf,
        /// What and where.
        error: KnownHostsError,
    },
    /// The host cannot form a lookup name.
    LookupName(LookupNameError),
}

impl TrustConfigError {
    /// Stable code: `io_error`, `malformed_configuration`,
    /// `unsupported_configuration` or `invalid_lookup_name`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            TrustConfigError::File(_) => "io_error",
            TrustConfigError::Malformed {
                error: KnownHostsError::Unsupported { .. },
                ..
            } => "unsupported_configuration",
            TrustConfigError::Malformed { .. } => "malformed_configuration",
            TrustConfigError::LookupName(_) => "invalid_lookup_name",
        }
    }
}

impl fmt::Display for TrustConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustConfigError::File(e) => write!(f, "cannot read known_hosts file {e}"),
            TrustConfigError::Malformed { path, error } => {
                write!(f, "{}: {error}", path.display())
            }
            TrustConfigError::LookupName(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for TrustConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use tatami_ssh_keys::trust::{HostIdentity, TrustDecision, TrustSource, UntrustedReason};

    const BLOB_B64: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIBUtYrV+0vHQidVi7Z+g6dLICWIXPgHvi2hkEv+kUcPg";

    fn blob() -> alloc::vec::Vec<u8> {
        use base64ct::{Base64, Encoding as _};
        Base64::decode_vec(BLOB_B64).unwrap()
    }

    fn temp_file(tag: &str, contents: &str) -> PathBuf {
        let p = std::env::temp_dir().join(alloc::format!(
            "tatami-trust-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(&p, contents).unwrap();
        p
    }

    fn decide(p: &PreparedTrust) -> TrustDecision {
        let b = blob();
        p.policy.decide(&HostIdentity {
            algorithm: b"ssh-ed25519",
            blob: &b,
            sha256: Sha256Fingerprint::of_blob(&b),
        })
    }

    #[test]
    fn known_hosts_file_binds_the_lookup_name_before_use() {
        let p = temp_file(
            "ok",
            &alloc::format!("[Host.Example]:2222 ssh-ed25519 {BLOB_B64}\n"),
        );
        let t = TrustConfig::KnownHostsFile(p.clone());
        assert_eq!(t.mode(), "known_hosts");
        let prepared = t.prepare("HOST.example", 2222).unwrap();
        assert_eq!(prepared.lookup_name.as_deref(), Some("[host.example]:2222"));
        assert_eq!(
            decide(&prepared),
            TrustDecision::Trusted {
                source: TrustSource::KnownHosts { line: 1 }
            }
        );
        let other_port = t.prepare("host.example", 22).unwrap();
        assert_eq!(
            decide(&other_port),
            TrustDecision::Untrusted {
                reason: UntrustedReason::UnknownHost
            }
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn configuration_errors_are_distinct() {
        let bad = temp_file("bad", "host ssh-ed25519\n");
        let e = TrustConfig::KnownHostsFile(bad.clone())
            .prepare("host", 22)
            .unwrap_err();
        assert_eq!(e.code(), "malformed_configuration");
        assert!(e.to_string().contains("line 1"), "{e}");
        let _ = std::fs::remove_file(bad);

        let e = TrustConfig::KnownHostsFile(PathBuf::from("/nonexistent/known_hosts"))
            .prepare("host", 22)
            .unwrap_err();
        assert_eq!(e.code(), "io_error");

        let ok = temp_file("name", "");
        let e = TrustConfig::KnownHostsFile(ok.clone())
            .prepare("bad host", 22)
            .unwrap_err();
        assert_eq!(e.code(), "invalid_lookup_name");
        let _ = std::fs::remove_file(ok);
    }

    /// `ssh-keygen -H` output (OpenSSH_10.2p1) for `host`: accepted with
    /// `openssh-hashed-hosts`, an explicit unsupported-configuration error
    /// (not "malformed", not "unknown host") without it.
    #[test]
    fn hashed_known_hosts_depend_on_the_compatibility_feature() {
        let p = temp_file(
            "hashed",
            &alloc::format!(
                "|1|GxqmlqIssNcv8hLxLEdYFzdXm1M=|NySrkNSholebEQAwLuvQRB5BT2g= ssh-ed25519 {BLOB_B64}\n"
            ),
        );
        let t = TrustConfig::KnownHostsFile(p.clone());
        let result = t.prepare("host", 22);
        let _ = std::fs::remove_file(p);
        #[cfg(feature = "openssh-hashed-hosts")]
        assert_eq!(
            decide(&result.unwrap()),
            TrustDecision::Trusted {
                source: TrustSource::KnownHosts { line: 1 }
            }
        );
        #[cfg(not(feature = "openssh-hashed-hosts"))]
        {
            let e = result.unwrap_err();
            assert_eq!(e.code(), "unsupported_configuration");
            let text = e.to_string();
            assert!(text.contains("line 1"), "{text}");
            assert!(text.contains("openssh-hashed-hosts"), "{text}");
        }
    }

    #[test]
    fn pin_mode() {
        let t = TrustConfig::from(Sha256Fingerprint::of_blob(&blob()));
        assert_eq!(t.mode(), "pinned_fingerprint");
        assert!(decide(&t.prepare("anything", 1).unwrap()).is_trusted());
    }
}
