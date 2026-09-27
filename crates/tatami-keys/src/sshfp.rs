//! SSHFP resource-record values (RFC 4255, RFC 6594, RFC 7479) computed
//! from an SSH public-key blob. No DNS is involved: this is the value a
//! zone would publish, so fingerprint *equivalence* across transports can
//! be shown and compared with `ssh-keygen -r`. It is not DNSSEC trust and
//! not live SSHFP verification.
//!
//! For Ed25519 with SHA-256 the record is algorithm 4 (RFC 7479), type 2
//! (RFC 6594), and the digest is SHA-256 over the **complete** canonical
//! public-key blob — not the certificate DER, not the SPKI DER, and not the
//! raw 32 key bytes.

use core::fmt;

use sha2::{Digest as _, Sha256};

use crate::ed25519::HostKey;
use crate::error::KeyError;

/// SSHFP algorithm number for Ed25519 (RFC 7479).
pub const ALGORITHM_ED25519: u8 = 4;
/// SSHFP fingerprint type for SHA-256 (RFC 6594).
pub const TYPE_SHA256: u8 = 2;

/// An SSHFP `algorithm fp-type fingerprint` triple with a SHA-256 digest.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sshfp {
    /// SSHFP algorithm number.
    pub algorithm: u8,
    /// SSHFP fingerprint type (always [`TYPE_SHA256`] here).
    pub fingerprint_type: u8,
    /// SHA-256 over the complete public-key blob.
    pub digest: [u8; 32],
}

impl Sshfp {
    /// The SHA-256 SSHFP value for a complete public-key blob. The blob is
    /// parsed strictly; only `ssh-ed25519` is supported.
    pub fn sha256_of_blob(blob: &[u8]) -> Result<Self, KeyError> {
        let algorithm = match HostKey::parse(blob)? {
            HostKey::Ed25519(_) => ALGORITHM_ED25519,
        };
        Ok(Sshfp {
            algorithm,
            fingerprint_type: TYPE_SHA256,
            digest: Sha256::digest(blob).into(),
        })
    }

    /// Parses RDATA presentation text `4 2 <64 hex digits>` (hex in either
    /// case, whitespace-separated), as printed by `ssh-keygen -r`.
    pub fn parse_rdata(text: &str) -> Option<Self> {
        let mut it = text.split_ascii_whitespace();
        let algorithm = it.next()?.parse().ok()?;
        let fingerprint_type = it.next()?.parse().ok()?;
        let hex = it.next()?;
        if it.next().is_some() || fingerprint_type != TYPE_SHA256 || hex.len() != 64 {
            return None;
        }
        let mut digest = [0u8; 32];
        for (i, pair) in hex.as_bytes().chunks(2).enumerate() {
            let hi = char::from(pair[0]).to_digit(16)?;
            let lo = char::from(pair[1]).to_digit(16)?;
            digest[i] = (hi * 16 + lo) as u8;
        }
        Some(Sshfp {
            algorithm,
            fingerprint_type,
            digest,
        })
    }
}

/// RDATA presentation form: `4 2 <lowercase hex>`.
impl fmt::Display for Sshfp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} ", self.algorithm, self.fingerprint_type)?;
        for b in &self.digest {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sshfp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sshfp({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::fixtures::{TEST1_PUBLIC_KEY, test1_key_blob};
    use crate::fingerprint::Sha256Fingerprint;
    use alloc::string::ToString;

    #[test]
    fn digest_covers_the_complete_blob_only() {
        let blob = test1_key_blob();
        let fp = Sshfp::sha256_of_blob(&blob).unwrap();
        assert_eq!(fp.algorithm, 4);
        assert_eq!(fp.fingerprint_type, 2);
        // Same digest as the OpenSSH SHA256: fingerprint of the blob.
        assert_eq!(&fp.digest, Sha256Fingerprint::of_blob(&blob).as_bytes());
        // Hashing the raw key or the SPKI gives something else.
        let raw: [u8; 32] = Sha256::digest(TEST1_PUBLIC_KEY).into();
        assert_ne!(fp.digest, raw);
        let spki = crate::spki::ssh_blob_to_spki(&blob).unwrap();
        let spki_digest: [u8; 32] = Sha256::digest(spki).into();
        assert_ne!(fp.digest, spki_digest);
    }

    #[test]
    fn matches_ssh_keygen_r() {
        use base64ct::{Base64, Encoding as _};
        // OpenSSH_10.2p1 fixture: `.pub` blob and `ssh-keygen -r` output.
        let blob = Base64::decode_vec(
            "AAAAC3NzaC1lZDI1NTE5AAAAIBUtYrV+0vHQidVi7Z+g6dLICWIXPgHvi2hkEv+kUcPg",
        )
        .unwrap();
        let keygen = "fixture.example IN SSHFP 4 2 682c380feb3032b57b1c455940a30490ba48e4758eb81d3bd50daa714d5b091a";
        let rdata = keygen.split_once("SSHFP ").unwrap().1;
        let fp = Sshfp::sha256_of_blob(&blob).unwrap();
        assert_eq!(fp.to_string(), rdata);
        assert_eq!(Sshfp::parse_rdata(rdata), Some(fp));
    }

    #[test]
    fn presentation_round_trips() {
        let fp = Sshfp::sha256_of_blob(&test1_key_blob()).unwrap();
        let text = fp.to_string();
        assert!(text.starts_with("4 2 "));
        assert_eq!(text.len(), 4 + 64);
        assert_eq!(Sshfp::parse_rdata(&text), Some(fp));
        assert_eq!(Sshfp::parse_rdata(&text.to_uppercase()), Some(fp));
        assert_eq!(Sshfp::parse_rdata("4 1 00"), None);
        assert_eq!(Sshfp::parse_rdata(&text[..text.len() - 1]), None);
        assert_eq!(Sshfp::parse_rdata(&alloc::format!("{text} extra")), None);
    }

    #[test]
    fn only_valid_ed25519_blobs() {
        let mut blob = test1_key_blob().to_vec();
        blob.push(0);
        assert!(Sshfp::sha256_of_blob(&blob).is_err());
        assert!(Sshfp::sha256_of_blob(&TEST1_PUBLIC_KEY).is_err());
    }
}
