//! Legacy OpenSSH hashed-hostname **reader/matcher** for `known_hosts`.
//!
//! OpenSSH's `HashKnownHosts` / `ssh-keygen -H` replaces a host name in
//! `known_hosts` with `|1|base64(salt)|base64(HMAC-SHA1(salt, name))`.
//! Existing operator files contain such lines, so reading them needs
//! HMAC-SHA1. This crate is the **only** place in Tatami that uses SHA-1,
//! and it uses it for nothing but this comparison: no SSH signature, key
//! exchange, MAC, fingerprint, pin, SSHFP digest or TLS operation. It is
//! isolated here so the SHA-1 dependency can be left out of every build
//! that does not opt in (`tatami_ssh_keys` feature `openssh-hashed-hosts`),
//! and so an automated check (`scripts/check-sha1-boundary.py`) can prove
//! from the resolved dependency graph that SHA-1 is reachable only through
//! this crate.
//!
//! The capability is deliberately narrow: one function,
//! [`matches_hashed_hostname`], that validates a stored field and answers
//! whether it names a given lookup name. There is no writer (Tatami never
//! creates hashed records), no generic digest or HMAC function, no hash
//! state, no algorithm selection and no re-export of the providers.
//!
//! # Accepted grammar
//!
//! Exactly `|1|` + salt + `|` + digest, where salt and digest are canonical
//! padded standard base64 (RFC 4648 §4) of exactly 20 bytes each. The field
//! is at most 128 bytes and the lookup name at most 1024 bytes; longer
//! inputs are refused before any decoding or hashing. The digest comparison
//! uses the `hmac` crate's constant-time `verify_slice`.
//!
//! The lookup name is hashed byte for byte. Callers pass the OpenSSH lookup
//! name (`host` or `[host]:port`, ASCII-lowercased); this crate does not
//! normalise case.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use core::fmt;

use base64ct::{Base64, Encoding as _};
use hmac::{Hmac, Mac as _};
use sha1::Sha1;

/// Salt and digest length (SHA-1 output size, and the salt size OpenSSH
/// writes).
const HASH_LEN: usize = 20;
/// Upper bound on a stored field. A valid field is exactly 60 bytes.
const MAX_STORED_FIELD_LEN: usize = 128;
/// Upper bound on a lookup name (a DNS name is at most 253 bytes; the
/// bracketed form adds a port).
const MAX_LOOKUP_NAME_LEN: usize = 1024;
/// Enough for any base64 part of a bounded field.
const DECODE_BUF_LEN: usize = MAX_STORED_FIELD_LEN / 4 * 3;

/// Why a stored hashed-hostname field or lookup name was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashedHostnameError {
    /// The stored field exceeds the input-size bound (128 bytes).
    StoredFieldTooLong,
    /// The lookup name exceeds the input-size bound (1024 bytes).
    LookupNameTooLong,
    /// The field is not exactly `|1|salt|digest`.
    Grammar,
    /// The salt or digest is not canonical padded standard base64.
    Base64,
    /// The salt does not decode to 20 bytes.
    SaltLength,
    /// The digest does not decode to 20 bytes.
    DigestLength,
}

impl fmt::Display for HashedHostnameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HashedHostnameError::StoredFieldTooLong => "hashed host field exceeds 128 bytes",
            HashedHostnameError::LookupNameTooLong => "lookup name exceeds 1024 bytes",
            HashedHostnameError::Grammar => "hashed host field is not |1|salt|hash",
            HashedHostnameError::Base64 => {
                "hashed host salt or hash is not canonical padded base64"
            }
            HashedHostnameError::SaltLength => "hashed host salt is not 20 bytes",
            HashedHostnameError::DigestLength => "hashed host hash is not 20 bytes",
        })
    }
}

impl core::error::Error for HashedHostnameError {}

/// Validates the complete `|1|salt|hash` `stored_field` and reports whether
/// it is the HMAC-SHA1 of `lookup_name` under its salt.
///
/// Returns an error for any malformed or oversized input, whatever the
/// lookup name; calling it with an empty `lookup_name` therefore validates
/// a field without matching anything real. `Ok(false)` means well formed
/// but not this name.
pub fn matches_hashed_hostname(
    stored_field: &[u8],
    lookup_name: &[u8],
) -> Result<bool, HashedHostnameError> {
    if stored_field.len() > MAX_STORED_FIELD_LEN {
        return Err(HashedHostnameError::StoredFieldTooLong);
    }
    if lookup_name.len() > MAX_LOOKUP_NAME_LEN {
        return Err(HashedHostnameError::LookupNameTooLong);
    }
    let rest = stored_field
        .strip_prefix(b"|1|")
        .ok_or(HashedHostnameError::Grammar)?;
    let mut parts = rest.split(|&b| b == b'|');
    let (Some(salt), Some(digest), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(HashedHostnameError::Grammar);
    };
    let salt = decode_part(salt, HashedHostnameError::SaltLength)?;
    let digest = decode_part(digest, HashedHostnameError::DigestLength)?;
    // HMAC accepts keys of any length; the error arm cannot be taken.
    let mut mac =
        Hmac::<Sha1>::new_from_slice(&salt).map_err(|_| HashedHostnameError::SaltLength)?;
    mac.update(lookup_name);
    Ok(mac.verify_slice(&digest).is_ok())
}

/// Strict padded base64 of exactly [`HASH_LEN`] bytes. Canonical form is
/// enforced by re-encoding, so non-zero trailing bits are refused.
fn decode_part(
    text: &[u8],
    length_error: HashedHostnameError,
) -> Result<[u8; HASH_LEN], HashedHostnameError> {
    let mut buf = [0u8; DECODE_BUF_LEN];
    let decoded = Base64::decode(text, &mut buf).map_err(|_| HashedHostnameError::Base64)?;
    let mut encoded = [0u8; MAX_STORED_FIELD_LEN];
    let canonical =
        Base64::encode(decoded, &mut encoded).map_err(|_| HashedHostnameError::Base64)?;
    if canonical.as_bytes() != text {
        return Err(HashedHostnameError::Base64);
    }
    decoded.try_into().map_err(|_| length_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Produced by OpenSSH_10.2p1 `ssh-keygen -H` on a plaintext file listing
    // these names (one `ssh-ed25519` line each); hard-coded here.
    const HOST: &[u8] = b"|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=";
    const HOST_2222: &[u8] = b"|1|fSQdr5FTkUKRtYdUfMerMOhv9tg=|o7YYvARat2xvQ/xK/bsO6jq+ULY=";
    const OTHER: &[u8] = b"|1|RlS2qd0peVedQkw9lPQIZpqCXYg=|7f076qNh6IMy9djepot4ddmjj1I=";
    const LOOPBACK_2200: &[u8] = b"|1|nwp0jFC4rcFSRhAlL/VGHk+FdgM=|6Z2ImSanAZ6EeD/YRXUDQTCR/D8=";

    const SALT: &str = "IU1cA2qjw9KDYpT5wGRttwN2vVU=";
    const DIGEST: &str = "MjpmhQnQTZr/FMAlIczcdX61uVU=";

    fn field(salt: &str, digest: &str) -> ([u8; 256], usize) {
        let mut out = [0u8; 256];
        let mut n = 0;
        for part in [b"|1|".as_slice(), salt.as_bytes(), b"|", digest.as_bytes()] {
            out[n..n + part.len()].copy_from_slice(part);
            n += part.len();
        }
        (out, n)
    }

    fn check(salt: &str, digest: &str) -> Result<bool, HashedHostnameError> {
        let (buf, n) = field(salt, digest);
        matches_hashed_hostname(&buf[..n], b"host.example")
    }

    #[test]
    fn openssh_fixtures_match_their_names() {
        assert_eq!(matches_hashed_hostname(HOST, b"host.example"), Ok(true));
        assert_eq!(
            matches_hashed_hostname(HOST_2222, b"[host.example]:2222"),
            Ok(true)
        );
        assert_eq!(matches_hashed_hostname(OTHER, b"other.example"), Ok(true));
        assert_eq!(
            matches_hashed_hostname(LOOPBACK_2200, b"[127.0.0.1]:2200"),
            Ok(true)
        );
    }

    #[test]
    fn other_names_do_not_match() {
        for name in [
            &b"other.example"[..],
            b"[host.example]:2222",
            b"[host.example]:22",
            b"host.example.",
            b"host.exampl",
            b"",
        ] {
            assert_eq!(matches_hashed_hostname(HOST, name), Ok(false), "{name:?}");
        }
        assert_eq!(
            matches_hashed_hostname(HOST_2222, b"host.example"),
            Ok(false)
        );
    }

    #[test]
    fn names_are_hashed_verbatim_so_callers_lowercase() {
        assert_eq!(matches_hashed_hostname(HOST, b"HOST.example"), Ok(false));
        assert_eq!(
            matches_hashed_hostname(HOST_2222, b"[HOST.EXAMPLE]:2222"),
            Ok(false)
        );
    }

    #[test]
    fn grammar_is_exact() {
        for bad in [
            &b""[..],
            b"|",
            b"|1|",
            b"1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=",
            b"|2|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=",
            b"|01|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=",
            b" |1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=",
            b"|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=",
            b"|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=|",
            b"|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=|x",
            b"host.example",
        ] {
            assert_eq!(
                matches_hashed_hostname(bad, b"host.example"),
                Err(HashedHostnameError::Grammar),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn base64_is_strict_and_canonical() {
        for (salt, digest) in [
            // Unpadded.
            ("IU1cA2qjw9KDYpT5wGRttwN2vVU", DIGEST),
            (SALT, "MjpmhQnQTZr/FMAlIczcdX61uVU"),
            // Non-zero trailing bits (U -> V): decodes loosely, not canonical.
            ("IU1cA2qjw9KDYpT5wGRttwN2vVV=", DIGEST),
            (SALT, "MjpmhQnQTZr/FMAlIczcdX61uVV="),
            // Invalid characters, URL-safe alphabet, whitespace, extra padding.
            ("IU1cA2qjw9KDYpT5wGRttwN2vV!=", DIGEST),
            (SALT, "MjpmhQnQTZr_FMAlIczcdX61uVU="),
            ("IU1cA2qjw9KDYpT5wGRttwN2 vVU=", DIGEST),
            (SALT, "MjpmhQnQTZr/FMAlIczcdX61uVU=="),
        ] {
            assert_eq!(
                check(salt, digest),
                Err(HashedHostnameError::Base64),
                "{salt} {digest}"
            );
        }
        // The unmodified parts are accepted.
        assert_eq!(check(SALT, DIGEST), Ok(true));
    }

    #[test]
    fn decoded_lengths_are_exactly_twenty_bytes() {
        // 3, 0, 19 and 21 bytes.
        for short in [
            "AAAA",
            "",
            "AAAAAAAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                check(short, DIGEST),
                Err(HashedHostnameError::SaltLength),
                "{short}"
            );
            assert_eq!(
                check(SALT, short),
                Err(HashedHostnameError::DigestLength),
                "{short}"
            );
        }
    }

    #[test]
    fn inputs_are_bounded() {
        let long = [b'A'; MAX_STORED_FIELD_LEN + 1];
        assert_eq!(
            matches_hashed_hostname(&long, b""),
            Err(HashedHostnameError::StoredFieldTooLong)
        );
        let name = [b'a'; MAX_LOOKUP_NAME_LEN + 1];
        assert_eq!(
            matches_hashed_hostname(HOST, &name),
            Err(HashedHostnameError::LookupNameTooLong)
        );
        // The bounds themselves are accepted; the size check precedes grammar.
        assert_eq!(
            matches_hashed_hostname(HOST, &name[..MAX_LOOKUP_NAME_LEN]),
            Ok(false)
        );
        assert_eq!(
            matches_hashed_hostname(&long[..MAX_STORED_FIELD_LEN], b""),
            Err(HashedHostnameError::Grammar)
        );
    }

    #[test]
    fn errors_render() {
        use core::fmt::Write as _;
        struct Sink(usize);
        impl fmt::Write for Sink {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                self.0 += s.len();
                Ok(())
            }
        }
        for e in [
            HashedHostnameError::StoredFieldTooLong,
            HashedHostnameError::LookupNameTooLong,
            HashedHostnameError::Grammar,
            HashedHostnameError::Base64,
            HashedHostnameError::SaltLength,
            HashedHostnameError::DigestLength,
        ] {
            let mut sink = Sink(0);
            write!(sink, "{e}").unwrap();
            assert!(sink.0 > 0);
            let _: &dyn core::error::Error = &e;
        }
    }
}
