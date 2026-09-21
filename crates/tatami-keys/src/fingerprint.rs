//! SHA-256 host-key fingerprints in the OpenSSH `SHA256:` presentation.
//!
//! The fingerprint is SHA-256 over the *complete* public-key blob (`string
//! algorithm` plus the algorithm-specific body), which is what
//! `ssh-keygen -lf` and the client's host-key prompt print. Rendering is
//! `SHA256:` followed by the digest in standard-alphabet base64 **without**
//! padding (43 characters for 32 bytes).
//!
//! [`Sha256Fingerprint`] itself is feature-free so that trust policy can be
//! expressed without a hash provider; computing one from a blob and
//! rendering/parsing the text form need `sha2` and `base64ct` and are gated
//! behind the `ed25519` feature.

use core::fmt;

/// Digest length of SHA-256.
pub const SHA256_LEN: usize = 32;

/// Text prefix of the presentation form.
pub const PREFIX: &str = "SHA256:";

/// Length of the unpadded base64 body: `ceil(32 * 8 / 6)`.
pub const BASE64_LEN: usize = 43;

/// SHA-256 of a complete public-key blob.
#[derive(Clone, Copy, Eq)]
pub struct Sha256Fingerprint([u8; SHA256_LEN]);

impl Sha256Fingerprint {
    /// Wraps a digest obtained elsewhere (for example a configured pin that
    /// was parsed at startup).
    #[must_use]
    pub const fn from_bytes(digest: [u8; SHA256_LEN]) -> Self {
        Sha256Fingerprint(digest)
    }

    /// The raw digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }
}

/// Equality is evaluated over every byte with no early exit.
///
/// A fingerprint is public data and its comparison time does not leak a
/// secret, so this is hygiene rather than a security boundary: the audit
/// (`docs/crypto-provider-audit.md`) asks for constant-time comparison of
/// fingerprints and pins, and a fold over XOR/OR costs nothing here.
impl PartialEq for Sha256Fingerprint {
    fn eq(&self, other: &Self) -> bool {
        let diff = self
            .0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        diff == 0
    }
}

/// Feature-independent rendering: the digest as lowercase hex, so a
/// fingerprint can always be reported even without the text codec.
impl fmt::Debug for Sha256Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sha256Fingerprint(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// Why a `SHA256:` string could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintParseError {
    /// The string does not start with `SHA256:` (case-sensitive).
    MissingPrefix,
    /// The body contains `=`; OpenSSH prints fingerprints unpadded.
    Padding,
    /// The body is not exactly 43 characters.
    WrongLength {
        /// Characters found after the prefix.
        found: usize,
    },
    /// The body contains a character outside the standard base64 alphabet,
    /// or its trailing bits are non-zero (non-canonical encoding).
    InvalidBase64,
}

impl fmt::Display for FingerprintParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FingerprintParseError::MissingPrefix => {
                write!(f, "fingerprint must start with `{PREFIX}`")
            }
            FingerprintParseError::Padding => {
                f.write_str("fingerprint base64 must not be padded with `=`")
            }
            FingerprintParseError::WrongLength { found } => write!(
                f,
                "fingerprint base64 must be {BASE64_LEN} characters, found {found}"
            ),
            FingerprintParseError::InvalidBase64 => {
                f.write_str("fingerprint is not valid standard base64")
            }
        }
    }
}

impl core::error::Error for FingerprintParseError {}

#[cfg(feature = "ed25519")]
mod text {
    use core::fmt;
    use core::str::FromStr;

    use base64ct::{Base64Unpadded, Encoding};
    use sha2::{Digest, Sha256};

    use super::{BASE64_LEN, FingerprintParseError, PREFIX, SHA256_LEN, Sha256Fingerprint};

    impl Sha256Fingerprint {
        /// SHA-256 of `complete_blob_bytes`, which must be the whole
        /// public-key blob (`K_S`), not just the key material.
        #[must_use]
        pub fn of_blob(complete_blob_bytes: &[u8]) -> Self {
            Sha256Fingerprint(Sha256::digest(complete_blob_bytes).into())
        }

        /// Parses the `SHA256:<43 unpadded base64 chars>` presentation.
        pub fn parse(text: &str) -> Result<Self, FingerprintParseError> {
            let body = text
                .strip_prefix(PREFIX)
                .ok_or(FingerprintParseError::MissingPrefix)?;
            if body.contains('=') {
                return Err(FingerprintParseError::Padding);
            }
            if body.len() != BASE64_LEN {
                return Err(FingerprintParseError::WrongLength { found: body.len() });
            }
            let mut digest = [0u8; SHA256_LEN];
            let decoded = Base64Unpadded::decode(body, &mut digest)
                .map_err(|_| FingerprintParseError::InvalidBase64)?;
            if decoded.len() != SHA256_LEN {
                return Err(FingerprintParseError::InvalidBase64);
            }
            Ok(Sha256Fingerprint(digest))
        }
    }

    impl fmt::Display for Sha256Fingerprint {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let mut buf = [0u8; BASE64_LEN];
            let body = Base64Unpadded::encode(&self.0, &mut buf).map_err(|_| fmt::Error)?;
            f.write_str(PREFIX)?;
            f.write_str(body)
        }
    }

    impl FromStr for Sha256Fingerprint {
        type Err = FingerprintParseError;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Sha256Fingerprint::parse(s)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn equality_and_debug_are_feature_free() {
        let a = Sha256Fingerprint::from_bytes([0x01; 32]);
        let b = Sha256Fingerprint::from_bytes([0x01; 32]);
        let mut c_bytes = [0x01; 32];
        c_bytes[31] = 0x02;
        let c = Sha256Fingerprint::from_bytes(c_bytes);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), &[0x01; 32]);
        let dbg = format!("{a:?}");
        assert!(dbg.starts_with("Sha256Fingerprint(0101"));
        assert!(dbg.ends_with("01)"));
        assert_eq!(dbg.len(), "Sha256Fingerprint(".len() + 64 + 1);
    }

    #[cfg(feature = "ed25519")]
    mod with_provider {
        use super::super::*;
        use crate::blob::fixtures::{TEST1_PUBLIC_KEY, test1_key_blob};
        use alloc::string::ToString;

        /// SHA-256 of the 51-byte TEST 1 blob. Provenance: computed with
        /// `python3 -c 'import hashlib,struct; ...'` over
        /// `00 00 00 0b "ssh-ed25519" 00 00 00 20 <TEST1_PUBLIC_KEY>` and
        /// cross-checked with `ssh-keygen -lf` on the same key, which
        /// printed `256 SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8`.
        const TEST1_BLOB_SHA256: [u8; 32] = [
            0x6d, 0xb5, 0xe9, 0xb8, 0xa1, 0xba, 0xce, 0x1c, 0xdd, 0x9a, 0x7c, 0x6a, 0xdb, 0x9e,
            0x93, 0x96, 0xac, 0xc5, 0x07, 0x34, 0x65, 0xd9, 0xfe, 0x8e, 0x3a, 0x0e, 0xf6, 0xd9,
            0xc6, 0x0d, 0x6d, 0x4f,
        ];
        const TEST1_TEXT: &str = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";

        #[test]
        fn fingerprint_of_known_blob() {
            let blob = test1_key_blob();
            assert_eq!(blob.len(), 51);
            let fp = Sha256Fingerprint::of_blob(&blob);
            assert_eq!(fp.as_bytes(), &TEST1_BLOB_SHA256);

            // Independent recomputation with the provider in the test.
            let again: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(blob).into();
            assert_eq!(again, TEST1_BLOB_SHA256);

            // The fingerprint covers the whole blob, not the key alone.
            assert_ne!(
                Sha256Fingerprint::of_blob(&TEST1_PUBLIC_KEY).as_bytes(),
                &TEST1_BLOB_SHA256
            );
        }

        #[test]
        fn display_matches_openssh_format() {
            let fp = Sha256Fingerprint::from_bytes(TEST1_BLOB_SHA256);
            let text = fp.to_string();
            assert_eq!(text, TEST1_TEXT);
            assert_eq!(text.len(), PREFIX.len() + BASE64_LEN);
            assert!(!text.contains('='));
        }

        #[test]
        fn parse_round_trips_and_is_strict() {
            let fp: Sha256Fingerprint = TEST1_TEXT.parse().unwrap();
            assert_eq!(fp.as_bytes(), &TEST1_BLOB_SHA256);
            assert_eq!(Sha256Fingerprint::parse(TEST1_TEXT), Ok(fp));

            assert_eq!(
                Sha256Fingerprint::parse("bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"),
                Err(FingerprintParseError::MissingPrefix)
            );
            assert_eq!(
                Sha256Fingerprint::parse("sha256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"),
                Err(FingerprintParseError::MissingPrefix),
                "prefix is case-sensitive"
            );
            assert_eq!(
                Sha256Fingerprint::parse("SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8="),
                Err(FingerprintParseError::Padding)
            );
            assert_eq!(
                Sha256Fingerprint::parse("SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU"),
                Err(FingerprintParseError::WrongLength { found: 42 })
            );
            assert_eq!(
                Sha256Fingerprint::parse("SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8A"),
                Err(FingerprintParseError::WrongLength { found: 44 })
            );
            assert_eq!(
                Sha256Fingerprint::parse("SHA256:"),
                Err(FingerprintParseError::WrongLength { found: 0 })
            );
            assert_eq!(
                Sha256Fingerprint::parse("SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU!"),
                Err(FingerprintParseError::InvalidBase64)
            );
            assert_eq!(
                Sha256Fingerprint::parse("SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNb_8"),
                Err(FingerprintParseError::InvalidBase64),
                "URL-safe alphabet is not accepted"
            );
            // Last character `8` (index 60, low two bits zero) is canonical;
            // `9` (index 61) sets a trailing bit that has no byte to land in.
            assert_eq!(
                Sha256Fingerprint::parse("SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU9"),
                Err(FingerprintParseError::InvalidBase64),
                "non-canonical trailing bits are rejected"
            );
        }

        #[test]
        fn parse_error_messages_are_actionable() {
            assert_eq!(
                FingerprintParseError::WrongLength { found: 3 }.to_string(),
                "fingerprint base64 must be 43 characters, found 3"
            );
            assert_eq!(
                FingerprintParseError::MissingPrefix.to_string(),
                "fingerprint must start with `SHA256:`"
            );
        }
    }
}
