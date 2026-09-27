//! Unencrypted Ed25519 `openssh-key-v1` host private keys (feature
//! `openssh-key`), decoded from bytes.
//!
//! Supported subset: exactly what `ssh-keygen -t ed25519 -N ''` writes. A
//! passphrase-protected key is rejected with [`PrivateKeyError::Encrypted`]
//! before any KDF runs (none is linked); there is no prompt, environment
//! variable or argument for a passphrase. Other algorithms, other container
//! formats (PKCS#8, legacy PEM) and anything malformed are rejected.
//!
//! Parsing is delegated to RustCrypto `ssh-key` 0.6 (see
//! `docs/crypto-provider-audit.md`), which verifies the magic, `nkeys == 1`,
//! `cipher`/`kdf` consistency, equal check integers, that the outer public
//! key equals the private section's public key, that the `seed || public`
//! copy repeats that public key, the padding bytes, and that nothing trails.
//! Built without its own `ed25519` feature it does **not** check that the
//! public key is the one derived from the seed, so that is done here with
//! `ed25519-dalek`. Check integers alone would not establish consistency.
//!
//! The seed is held in [`Zeroizing`] storage, never appears in `Debug`,
//! `Display` or errors, and the PKCS#8 form for a TLS stack is produced in
//! memory, also zeroizing. File access (size bound, permission check)
//! belongs to the caller's host layer.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use ed25519_dalek::SigningKey;
use ssh_key::private::KeypairData;
/// Zeroizing storage for secret buffers, re-exported so callers (the host
/// layer reading key files) use the same implementation.
pub use zeroize::Zeroizing;

use crate::blob::ED25519_BLOB_LEN;
use crate::ed25519::Ed25519PublicKey;
use crate::fingerprint::Sha256Fingerprint;
use crate::spki::ssh_blob_of;

/// Upper bound on accepted key text. An `ssh-keygen` Ed25519 key is about
/// 400 bytes; 16 KiB leaves room for long comments and rejects anything
/// else before decoding.
pub const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1024;

/// DER prefix of an RFC 8410 §7 Ed25519 `OneAsymmetricKey` (version 0, no
/// attributes, no public key): `SEQUENCE(46) { INTEGER 0, SEQUENCE(5) { OID
/// 1.3.101.112 }, OCTET STRING(34) { OCTET STRING(32) seed } }`.
pub const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Why key bytes were not accepted. Never contains secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateKeyError {
    /// More than [`MAX_PRIVATE_KEY_BYTES`].
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// Not an `-----BEGIN OPENSSH PRIVATE KEY-----` container.
    NotOpenssh,
    /// The key is passphrase-protected. Encrypted keys are not supported;
    /// nothing was decrypted.
    Encrypted,
    /// A well-formed key of another algorithm.
    UnsupportedAlgorithm(String),
    /// The container is malformed or internally inconsistent (as reported
    /// by the parser).
    Malformed(String),
    /// The stored public key is not the one derived from the private seed.
    PublicKeyMismatch,
}

impl fmt::Display for PrivateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivateKeyError::TooLarge { limit } => {
                write!(f, "private key file exceeds {limit} bytes")
            }
            PrivateKeyError::NotOpenssh => f.write_str(
                "not an OpenSSH private key (expected -----BEGIN OPENSSH PRIVATE KEY-----)",
            ),
            PrivateKeyError::Encrypted => f.write_str(
                "private key is passphrase-protected; encrypted keys are not supported (use an unencrypted host key)",
            ),
            PrivateKeyError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported private key algorithm {alg:?}; only ssh-ed25519")
            }
            PrivateKeyError::Malformed(why) => write!(f, "malformed OpenSSH private key: {why}"),
            PrivateKeyError::PublicKeyMismatch => {
                f.write_str("private key's public key is not derived from its secret")
            }
        }
    }
}

impl core::error::Error for PrivateKeyError {}

/// A validated Ed25519 host private key.
pub struct Ed25519HostPrivateKey {
    seed: Zeroizing<[u8; 32]>,
    public: Ed25519PublicKey,
}

impl fmt::Debug for Ed25519HostPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519HostPrivateKey")
            .field("public_sha256", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Ed25519HostPrivateKey {
    /// Decodes an unencrypted Ed25519 `openssh-key-v1` PEM container.
    pub fn from_openssh(text: &[u8]) -> Result<Self, PrivateKeyError> {
        if text.len() > MAX_PRIVATE_KEY_BYTES {
            return Err(PrivateKeyError::TooLarge {
                limit: MAX_PRIVATE_KEY_BYTES,
            });
        }
        if !text
            .windows(35)
            .any(|w| w == b"-----BEGIN OPENSSH PRIVATE KEY-----")
        {
            return Err(PrivateKeyError::NotOpenssh);
        }
        let key = ssh_key::PrivateKey::from_openssh(text).map_err(|e| match e {
            // Built without other algorithms, the parser cannot name them.
            ssh_key::Error::AlgorithmUnknown => {
                PrivateKeyError::UnsupportedAlgorithm(String::from("(not ssh-ed25519)"))
            }
            ssh_key::Error::AlgorithmUnsupported { algorithm } => {
                PrivateKeyError::UnsupportedAlgorithm(String::from(algorithm.as_str()))
            }
            other => PrivateKeyError::Malformed(alloc::format!("{other}")),
        })?;
        if key.is_encrypted() {
            return Err(PrivateKeyError::Encrypted);
        }
        let KeypairData::Ed25519(pair) = key.key_data() else {
            return Err(PrivateKeyError::UnsupportedAlgorithm(String::from(
                key.algorithm().as_str(),
            )));
        };
        let stored: [u8; 32] = pair.public.0;
        let public = Ed25519PublicKey::from_bytes(&stored)
            .map_err(|_| PrivateKeyError::Malformed(String::from("invalid Ed25519 public key")))?;
        let seed = Zeroizing::new(pair.private.to_bytes());
        // ssh-key (without its ed25519 feature) does not derive; do it here.
        let derived = SigningKey::from_bytes(&seed).verifying_key();
        if derived.as_bytes() != public.as_bytes() {
            return Err(PrivateKeyError::PublicKeyMismatch);
        }
        Ok(Ed25519HostPrivateKey { seed, public })
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public
    }

    /// The canonical `ssh-ed25519` public-key blob.
    #[must_use]
    pub fn ssh_blob(&self) -> [u8; ED25519_BLOB_LEN] {
        ssh_blob_of(&self.public)
    }

    /// OpenSSH `SHA256:` fingerprint of the public key.
    #[must_use]
    pub fn fingerprint(&self) -> Sha256Fingerprint {
        Sha256Fingerprint::of_blob(&self.ssh_blob())
    }

    /// RFC 8410 §7 PKCS#8 encoding of the private key, for a TLS stack.
    /// Held in zeroizing storage; callers must not log or persist it.
    #[must_use]
    pub fn to_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32));
        out.extend_from_slice(&ED25519_PKCS8_PREFIX);
        out.extend_from_slice(&*self.seed);
        out
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::string::ToString;
    use base64ct::{Base64, Encoding as _};

    /// Independent `openssh-key-v1` writer (PROTOCOL.key), so tampered
    /// containers can be built without the parser under test.
    pub(crate) struct Container {
        pub cipher: &'static str,
        pub kdf: &'static str,
        pub nkeys: u32,
        pub outer_public: [u8; 32],
        pub checkints: (u32, u32),
        pub inner_public: [u8; 32],
        pub seed: [u8; 32],
        pub embedded_public: [u8; 32],
        pub comment: &'static str,
        pub trailing: &'static [u8],
    }

    fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }

    fn ed_blob(key: &[u8; 32]) -> Vec<u8> {
        let mut b = Vec::new();
        put_string(&mut b, b"ssh-ed25519");
        put_string(&mut b, key);
        b
    }

    impl Container {
        pub fn valid(seed: [u8; 32]) -> Self {
            let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            Container {
                cipher: "none",
                kdf: "none",
                nkeys: 1,
                outer_public: public,
                checkints: (0x1234_5678, 0x1234_5678),
                inner_public: public,
                seed,
                embedded_public: public,
                comment: "test@tatami",
                trailing: b"",
            }
        }

        pub fn pem(&self) -> String {
            let mut bin = b"openssh-key-v1\0".to_vec();
            put_string(&mut bin, self.cipher.as_bytes());
            put_string(&mut bin, self.kdf.as_bytes());
            put_string(&mut bin, b"");
            bin.extend_from_slice(&self.nkeys.to_be_bytes());
            put_string(&mut bin, &ed_blob(&self.outer_public));
            let mut private = Vec::new();
            private.extend_from_slice(&self.checkints.0.to_be_bytes());
            private.extend_from_slice(&self.checkints.1.to_be_bytes());
            put_string(&mut private, b"ssh-ed25519");
            put_string(&mut private, &self.inner_public);
            put_string(&mut private, &[self.seed, self.embedded_public].concat());
            put_string(&mut private, self.comment.as_bytes());
            let mut pad = 1u8;
            while private.len() % 8 != 0 {
                private.push(pad);
                pad += 1;
            }
            put_string(&mut bin, &private);
            bin.extend_from_slice(self.trailing);
            let b64 = Base64::encode_string(&bin);
            let mut text = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
            for chunk in b64.as_bytes().chunks(70) {
                text.push_str(core::str::from_utf8(chunk).unwrap());
                text.push('\n');
            }
            text.push_str("-----END OPENSSH PRIVATE KEY-----\n");
            text
        }
    }

    /// Generated with OpenSSH_10.2p1 `ssh-keygen -t ed25519 -N ''
    /// -C tatami-test` solely as a test fixture; never a host key.
    pub(crate) const SSH_KEYGEN_ED25519: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAVLWK1ftLx0InVYu2foOnSyAliFz4B74toZBL/pFHD4AAAAJCrOFvQqzhb
0AAAAAtzc2gtZWQyNTUxOQAAACAVLWK1ftLx0InVYu2foOnSyAliFz4B74toZBL/pFHD4A
AAAEAmQ4GXFztqiqLJdqoLjuINpRyhW/vLsXxAXqaEjgWjQBUtYrV+0vHQidVi7Z+g6dLI
CWIXPgHvi2hkEv+kUcPgAAAAC3RhdGFtaS10ZXN0AQI=
-----END OPENSSH PRIVATE KEY-----
";
    /// The fixture's `.pub` line as written by `ssh-keygen`.
    pub(crate) const SSH_KEYGEN_ED25519_PUB: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBUtYrV+0vHQidVi7Z+g6dLICWIXPgHvi2hkEv+kUcPg tatami-test";
    /// `ssh-keygen -lf` of the fixture's public key.
    pub(crate) const SSH_KEYGEN_ED25519_FP: &str =
        "SHA256:aCw4D+swMrV7HEVZQKMEkLpI5HWOuB071Q2qcU1bCRo";
    /// Same generator with `-N 'fixture passphrase'` (aes256-ctr, bcrypt).
    const SSH_KEYGEN_ED25519_ENCRYPTED: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDB1NgavX
giGkMuInNCexFHAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEJWwOddIgCDfyjr
409NYXlFbEFOqeE6JvKP6anNLHDeAAAAoB3iNNskHInBfTmwW55B83fvYyuWxzDuRax18H
Hu5KH6X+JNfjCcntmG2WQvO/ycBFhvTRbvqsl1ed+0kdidtuF0c6HIFZv4YLv35JefJhBa
8XixQ0rtuk6g5wMvV/wsXoBncf9zdiNDuv5yCZvtLtDq2tCYi6j4uGirv+Z5/LeUR6JQpG
U41OJBpFoQct7/Asjo0NeVqaXi6mcD7hWaLaA=
-----END OPENSSH PRIVATE KEY-----
";
    /// Same generator with `-t ecdsa -b 256 -N ''`.
    const SSH_KEYGEN_ECDSA: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQSDfOtRP3fAjHUNlOVC0Lr9tRChm+mo
hSLasfnPV8RKD9gFjO4NsINDa4SblPRjNBy7lJKJ40CtCb7hBtOAZA+rAAAAqIeLQiiHi0
IoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIN861E/d8CMdQ2U
5ULQuv21EKGb6aiFItqx+c9XxEoP2AWM7g2wg0NrhJuU9GM0HLuUkonjQK0JvuEG04BkD6
sAAAAhAIQl+G3PqkfIpK0PJIEbJj0bBHG/M6hhig/Mxoh+hp62AAAADHRhdGFtaS1lY2Rz
YQECAw==
-----END OPENSSH PRIVATE KEY-----
";

    #[test]
    fn encrypted_and_other_algorithms_are_rejected() {
        assert_eq!(
            Ed25519HostPrivateKey::from_openssh(SSH_KEYGEN_ED25519_ENCRYPTED.as_bytes())
                .unwrap_err(),
            PrivateKeyError::Encrypted
        );
        assert!(matches!(
            Ed25519HostPrivateKey::from_openssh(SSH_KEYGEN_ECDSA.as_bytes()).unwrap_err(),
            PrivateKeyError::UnsupportedAlgorithm(_)
        ));
    }

    #[test]
    fn rfc8410_pkcs8_example() {
        // RFC 8410 §10.3: MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
        let expected =
            Base64::decode_vec("MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC")
                .unwrap();
        let seed: [u8; 32] = expected[16..].try_into().unwrap();
        let key =
            Ed25519HostPrivateKey::from_openssh(Container::valid(seed).pem().as_bytes()).unwrap();
        assert_eq!(key.to_pkcs8_der().as_slice(), expected.as_slice());
    }

    #[test]
    fn ssh_keygen_fixture_decodes() {
        let key = Ed25519HostPrivateKey::from_openssh(SSH_KEYGEN_ED25519.as_bytes()).unwrap();
        assert_eq!(key.fingerprint().to_string(), SSH_KEYGEN_ED25519_FP);
        let pub_b64 = SSH_KEYGEN_ED25519_PUB.split(' ').nth(1).unwrap();
        assert_eq!(
            key.ssh_blob().as_slice(),
            Base64::decode_vec(pub_b64).unwrap().as_slice()
        );
        let dbg = alloc::format!("{key:?}");
        assert!(dbg.contains("public_sha256"));
        assert!(!dbg.contains("seed"));
    }

    #[test]
    fn independent_writer_matches_parser() {
        let seed = [9u8; 32];
        let key =
            Ed25519HostPrivateKey::from_openssh(Container::valid(seed).pem().as_bytes()).unwrap();
        let expected = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(key.public_key().as_bytes(), &expected);
        assert_eq!(&key.ssh_blob()[..], ed_blob(&expected).as_slice());
    }

    fn reject(c: &Container) -> PrivateKeyError {
        Ed25519HostPrivateKey::from_openssh(c.pem().as_bytes()).unwrap_err()
    }

    #[test]
    fn inconsistent_containers_are_rejected() {
        let seed = [3u8; 32];
        let other = SigningKey::from_bytes(&[4u8; 32])
            .verifying_key()
            .to_bytes();

        // Seed does not derive the (consistently repeated) public key: only
        // the explicit derivation check catches this.
        let mut c = Container::valid(seed);
        c.outer_public = other;
        c.inner_public = other;
        c.embedded_public = other;
        assert_eq!(reject(&c), PrivateKeyError::PublicKeyMismatch);

        // Outer public differs from the private section.
        let mut c = Container::valid(seed);
        c.outer_public = other;
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Embedded public differs from the private section's public.
        let mut c = Container::valid(seed);
        c.embedded_public = other;
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Check integers differ.
        let mut c = Container::valid(seed);
        c.checkints = (1, 2);
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Two keys claimed.
        let mut c = Container::valid(seed);
        c.nkeys = 2;
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // KDF named on an unencrypted key.
        let mut c = Container::valid(seed);
        c.kdf = "bcrypt";
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));

        // Bytes after the private section.
        let mut c = Container::valid(seed);
        c.trailing = b"\x00";
        assert!(matches!(reject(&c), PrivateKeyError::Malformed(_)));
    }

    #[test]
    fn other_formats_and_sizes() {
        assert_eq!(
            Ed25519HostPrivateKey::from_openssh(
                b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n"
            )
            .unwrap_err(),
            PrivateKeyError::NotOpenssh
        );
        assert_eq!(
            Ed25519HostPrivateKey::from_openssh(&[b'a'; MAX_PRIVATE_KEY_BYTES + 1]).unwrap_err(),
            PrivateKeyError::TooLarge {
                limit: MAX_PRIVATE_KEY_BYTES
            }
        );
        let truncated =
            SSH_KEYGEN_ED25519.replace("CWIXPgHvi2hkEv+kUcPgAAAAC3RhdGFtaS10ZXN0AQI=\n", "");
        assert!(matches!(
            Ed25519HostPrivateKey::from_openssh(truncated.as_bytes()).unwrap_err(),
            PrivateKeyError::Malformed(_)
        ));
    }

    #[test]
    fn errors_never_carry_secrets() {
        let e = PrivateKeyError::Encrypted.to_string();
        assert!(e.contains("passphrase"));
    }
}
