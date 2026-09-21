//! Algorithm, marker and service names used by the first interoperability
//! profile (`docs/crypto-provider-audit.md`).
//!
//! These are byte-string constants for building and comparing name lists
//! and `string` fields. Listing a name here is not a claim that the
//! workspace implements it; negotiation policy lives in the transport
//! drivers. Markers are entries of `kex_algorithms` that are never
//! key-exchange methods; see [`crate::kexinit::classify_kex_name`].

/// Key-exchange method `curve25519-sha256` (RFC 8731 §3).
pub const CURVE25519_SHA256: &[u8] = b"curve25519-sha256";

/// Public-key algorithm `ssh-ed25519` (RFC 8709 §4).
pub const SSH_ED25519: &[u8] = b"ssh-ed25519";

/// AEAD cipher `aes128-gcm@openssh.com` (RFC 5647 construction under the
/// OpenSSH name; negotiation per OpenSSH `PROTOCOL` §1.6 /
/// draft-miller-sshm-aes-gcm-01 §2).
pub const AES128_GCM_OPENSSH: &[u8] = b"aes128-gcm@openssh.com";

/// MAC `hmac-sha2-256` (RFC 6668 §2). Advertised only to satisfy the
/// non-empty-list rule of RFC 4253 §7.1 when the cipher is an AEAD.
pub const HMAC_SHA2_256: &[u8] = b"hmac-sha2-256";

/// Compression `none` (RFC 4253 §6.2).
pub const NONE: &[u8] = b"none";

/// Client extension-negotiation marker `ext-info-c` (RFC 8308 §2.1).
pub const EXT_INFO_C: &[u8] = b"ext-info-c";

/// Server extension-negotiation marker `ext-info-s` (RFC 8308 §2.1).
pub const EXT_INFO_S: &[u8] = b"ext-info-s";

/// Pre-standard client strict-KEX marker `kex-strict-c-v00@openssh.com`
/// (draft-ietf-sshm-strict-kex-02 §3.1; OpenSSH `PROTOCOL` §1.9).
pub const KEX_STRICT_C_OPENSSH: &[u8] = b"kex-strict-c-v00@openssh.com";

/// Pre-standard server strict-KEX marker `kex-strict-s-v00@openssh.com`
/// (draft-ietf-sshm-strict-kex-02 §3.1; OpenSSH `PROTOCOL` §1.9).
pub const KEX_STRICT_S_OPENSSH: &[u8] = b"kex-strict-s-v00@openssh.com";

/// Standard client strict-KEX marker `kex-strict-c`
/// (draft-ietf-sshm-strict-kex-02 §3.1).
pub const KEX_STRICT_C: &[u8] = b"kex-strict-c";

/// Standard server strict-KEX marker `kex-strict-s`
/// (draft-ietf-sshm-strict-kex-02 §3.1).
pub const KEX_STRICT_S: &[u8] = b"kex-strict-s";

/// Service name `ssh-userauth` (RFC 4253 §10, RFC 4252 §5).
pub const SSH_USERAUTH: &[u8] = b"ssh-userauth";

/// Service name `ssh-connection` (RFC 4253 §10, RFC 4254).
pub const SSH_CONNECTION: &[u8] = b"ssh-connection";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kexinit::{KexName, classify_kex_name};
    use crate::namelist::is_valid_name;

    #[test]
    fn every_constant_is_a_valid_ssh_name() {
        for name in [
            CURVE25519_SHA256,
            SSH_ED25519,
            AES128_GCM_OPENSSH,
            HMAC_SHA2_256,
            NONE,
            EXT_INFO_C,
            EXT_INFO_S,
            KEX_STRICT_C_OPENSSH,
            KEX_STRICT_S_OPENSSH,
            KEX_STRICT_C,
            KEX_STRICT_S,
            SSH_USERAUTH,
            SSH_CONNECTION,
        ] {
            assert!(is_valid_name(name), "{name:?}");
        }
    }

    #[test]
    fn markers_classify_as_markers_and_methods_do_not() {
        for marker in [
            EXT_INFO_C,
            EXT_INFO_S,
            KEX_STRICT_C_OPENSSH,
            KEX_STRICT_S_OPENSSH,
            KEX_STRICT_C,
            KEX_STRICT_S,
        ] {
            assert!(classify_kex_name(marker).is_marker(), "{marker:?}");
        }
        assert_eq!(classify_kex_name(CURVE25519_SHA256), KexName::Method);
    }
}
