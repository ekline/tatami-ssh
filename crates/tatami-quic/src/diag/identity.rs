//! Generated Ed25519 **test** identity for the diagnostic handshake.
//!
//! The identity is a self-signed X.509 certificate produced by `rcgen`
//! (`PKCS_ED25519`) with its PKCS#8 private key. It exists only so a TLS 1.3
//! handshake can complete; it is not a production identity (P-06 remains
//! open) and no trust decision beyond an explicit pin is derived from it.
//!
//! # Three fingerprints that are not the same thing
//!
//! | Name | Input | Where it appears |
//! |---|---|---|
//! | [`CertificateSha256`] | the whole certificate DER | what `tatami-quic-server observe` prints and `--cert-sha256` pins |
//! | SPKI SHA-256 ([`SpkiSha256`]) | the `SubjectPublicKeyInfo` DER (RFC 7250 raw public key) | the raw-public-key experiment |
//! | SSH host-key fingerprint (`tatami_keys::Sha256Fingerprint`) | the `ssh-ed25519` public-key blob (`string "ssh-ed25519", string key`) | SSH `known_hosts`, `ssh-keygen -l` |
//!
//! All three are rendered `SHA256:` + unpadded base64 and all three differ
//! even for the same 32-byte Ed25519 key, because the hashed encodings
//! differ. A certificate fingerprint also changes whenever the certificate
//! is re-issued for the same key. Reports label which one they carry.

use std::format;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::string::String;
use std::vec::Vec;

use base64ct::{Base64Unpadded, Encoding as _};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest as _, Sha256};

/// File name of the PEM certificate inside an identity directory.
pub const CERT_FILE: &str = "cert.pem";
/// File name of the PEM PKCS#8 private key inside an identity directory.
pub const KEY_FILE: &str = "key.pem";

/// Fixed 12-byte prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410 §4):
/// `SEQUENCE(42) { SEQUENCE(5) { OID 1.3.101.112 }, BIT STRING(33) { 0 pad, key } }`.
pub const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Total length of an Ed25519 SPKI DER.
pub const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// Failure to create, store or load a test identity.
#[derive(Debug)]
pub enum IdentityError {
    /// Certificate or key generation failed.
    Generate(rcgen::Error),
    /// Filesystem error at `path`.
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying error.
        source: io::Error,
    },
    /// A PEM file did not contain the expected object.
    Pem {
        /// File involved.
        path: PathBuf,
        /// Description.
        detail: String,
    },
    /// The key is not an Ed25519 PKCS#8 key this experiment supports.
    UnsupportedKey,
    /// The identity directory already contains an identity.
    AlreadyExists(PathBuf),
    /// No identity in the directory and generation was not requested.
    NotFound(PathBuf),
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IdentityError::Generate(e) => write!(f, "identity generation failed: {e}"),
            IdentityError::Io { path, source } => {
                write!(f, "identity file {}: {source}", path.display())
            }
            IdentityError::Pem { path, detail } => {
                write!(f, "identity file {}: {detail}", path.display())
            }
            IdentityError::UnsupportedKey => {
                f.write_str("identity key is not an Ed25519 PKCS#8 key")
            }
            IdentityError::AlreadyExists(p) => write!(
                f,
                "identity already exists in {}; refusing to overwrite",
                p.display()
            ),
            IdentityError::NotFound(p) => write!(
                f,
                "no identity in {} (expected {CERT_FILE} and {KEY_FILE}); pass --generate-identity to create one",
                p.display()
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

/// SHA-256 of a complete X.509 certificate DER, rendered `SHA256:` +
/// unpadded base64 like an OpenSSH fingerprint. **Not** an SSH host-key
/// fingerprint and not the RFC 7250 SPKI hash; see the module docs.
#[derive(Clone, Copy, Eq)]
pub struct CertificateSha256([u8; 32]);

/// SHA-256 of a `SubjectPublicKeyInfo` DER (what RFC 7250 raw public keys
/// transmit). Same rendering, different input than [`CertificateSha256`].
#[derive(Clone, Copy, Eq)]
pub struct SpkiSha256([u8; 32]);

macro_rules! sha256_newtype {
    ($t:ident, $what:literal) => {
        impl $t {
            /// Digest of `der`.
            #[must_use]
            pub fn of_der(der: &[u8]) -> Self {
                $t(Sha256::digest(der).into())
            }

            /// Wraps a digest parsed or configured elsewhere.
            #[must_use]
            pub const fn from_bytes(digest: [u8; 32]) -> Self {
                $t(digest)
            }

            /// The raw digest.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Parses `SHA256:<43 unpadded base64 chars>`.
            pub fn parse(text: &str) -> Result<Self, FingerprintParseError> {
                let body = text
                    .strip_prefix("SHA256:")
                    .ok_or(FingerprintParseError::MissingPrefix)?;
                if body.contains('=') {
                    return Err(FingerprintParseError::Padding);
                }
                if body.len() != 43 {
                    return Err(FingerprintParseError::WrongLength { found: body.len() });
                }
                let mut digest = [0u8; 32];
                let n = Base64Unpadded::decode(body, &mut digest)
                    .map_err(|_| FingerprintParseError::InvalidBase64)?
                    .len();
                if n != 32 {
                    return Err(FingerprintParseError::InvalidBase64);
                }
                Ok($t(digest))
            }
        }

        /// Constant-time-style equality (fold over XOR, no early exit).
        impl PartialEq for $t {
            fn eq(&self, other: &Self) -> bool {
                self.0
                    .iter()
                    .zip(other.0.iter())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let mut buf = [0u8; 43];
                let body =
                    Base64Unpadded::encode(&self.0, &mut buf).map_err(|_| core::fmt::Error)?;
                f.write_str("SHA256:")?;
                f.write_str(body)
            }
        }

        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!($what, "({})"), self)
            }
        }

        impl core::str::FromStr for $t {
            type Err = FingerprintParseError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $t::parse(s)
            }
        }
    };
}

sha256_newtype!(CertificateSha256, "CertificateSha256");
sha256_newtype!(SpkiSha256, "SpkiSha256");

/// Why a `SHA256:` string could not be parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintParseError {
    /// Missing the case-sensitive `SHA256:` prefix.
    MissingPrefix,
    /// Contains `=` padding.
    Padding,
    /// Body is not 43 characters.
    WrongLength {
        /// Characters found after the prefix.
        found: usize,
    },
    /// Not canonical standard-alphabet base64.
    InvalidBase64,
}

impl core::fmt::Display for FingerprintParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FingerprintParseError::MissingPrefix => f.write_str("must start with `SHA256:`"),
            FingerprintParseError::Padding => f.write_str("must not be padded with `=`"),
            FingerprintParseError::WrongLength { found } => {
                write!(f, "base64 body must be 43 characters, found {found}")
            }
            FingerprintParseError::InvalidBase64 => f.write_str("not valid standard base64"),
        }
    }
}

impl std::error::Error for FingerprintParseError {}

/// Why an SPKI could not be reduced to a raw Ed25519 key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpkiError {
    /// Length is not 44 bytes.
    Length(usize),
    /// The 12-byte prefix is not the Ed25519 `SubjectPublicKeyInfo` header.
    Prefix,
}

impl core::fmt::Display for SpkiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SpkiError::Length(n) => write!(f, "SPKI is {n} bytes, Ed25519 SPKI is 44"),
            SpkiError::Prefix => f.write_str("SPKI prefix is not the Ed25519 header (RFC 8410 §4)"),
        }
    }
}

impl std::error::Error for SpkiError {}

/// Extracts the 32-byte Ed25519 public key from its `SubjectPublicKeyInfo`
/// DER by checking the exact fixed prefix of RFC 8410 §4. This is a typed
/// conversion, not a parser: any other algorithm or encoding is rejected.
pub fn spki_ed25519_to_raw(spki: &[u8]) -> Result<[u8; 32], SpkiError> {
    if spki.len() != ED25519_SPKI_LEN {
        return Err(SpkiError::Length(spki.len()));
    }
    let (prefix, key) = spki.split_at(ED25519_SPKI_PREFIX.len());
    if prefix != ED25519_SPKI_PREFIX {
        return Err(SpkiError::Prefix);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(key);
    Ok(out)
}

/// Wraps a raw Ed25519 public key in its `SubjectPublicKeyInfo` DER.
#[must_use]
pub fn raw_ed25519_to_spki(key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ED25519_SPKI_LEN);
    out.extend_from_slice(&ED25519_SPKI_PREFIX);
    out.extend_from_slice(key);
    out
}

/// A self-signed Ed25519 certificate with its private key.
///
/// `Debug` prints fingerprints only; the key never appears in any output.
pub struct TestIdentity {
    certificate: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    spki: Vec<u8>,
}

impl Clone for TestIdentity {
    fn clone(&self) -> Self {
        TestIdentity {
            certificate: self.certificate.clone(),
            key: self.key.clone_key(),
            spki: self.spki.clone(),
        }
    }
}

impl core::fmt::Debug for TestIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestIdentity")
            .field("certificate_sha256", &self.certificate_sha256_fingerprint())
            .field("spki_sha256", &self.spki_sha256())
            .finish_non_exhaustive()
    }
}

/// An in-memory issuing certificate for the `RootCertificate` trust path.
/// Kept only in memory: this experiment never persists a CA key.
pub struct TestRoot {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

impl core::fmt::Debug for TestRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TestRoot")
            .field(
                "certificate_sha256",
                &CertificateSha256::of_der(self.cert.der()),
            )
            .finish_non_exhaustive()
    }
}

impl TestRoot {
    /// Generates an Ed25519 CA certificate named `common_name`.
    pub fn generate_ed25519(common_name: &str) -> Result<Self, IdentityError> {
        let key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(IdentityError::Generate)?;
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.key_usages = std::vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).map_err(IdentityError::Generate)?;
        Ok(TestRoot { cert, key })
    }

    /// The root certificate DER, to be given to the client as its anchor.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.cert.der()
    }
}

impl TestIdentity {
    /// Generates a fresh self-signed Ed25519 certificate valid for `names`
    /// (DNS names or IP literals, placed in `subjectAltName`).
    pub fn generate_ed25519(names: &[String]) -> Result<Self, IdentityError> {
        let key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(IdentityError::Generate)?;
        let params = Self::leaf_params(names)?;
        let cert = params.self_signed(&key).map_err(IdentityError::Generate)?;
        Self::from_rcgen(cert, &key)
    }

    /// Generates an Ed25519 end-entity certificate for `names` issued by
    /// `root`, for exercising the `RootCertificate` trust path.
    pub fn generate_ed25519_issued_by(
        names: &[String],
        root: &TestRoot,
    ) -> Result<Self, IdentityError> {
        let key =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).map_err(IdentityError::Generate)?;
        let mut params = Self::leaf_params(names)?;
        params.use_authority_key_identifier_extension = true;
        let cert = params
            .signed_by(&key, &root.cert, &root.key)
            .map_err(IdentityError::Generate)?;
        Self::from_rcgen(cert, &key)
    }

    fn leaf_params(names: &[String]) -> Result<rcgen::CertificateParams, IdentityError> {
        let mut params =
            rcgen::CertificateParams::new(names.to_vec()).map_err(IdentityError::Generate)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            "tatami-quic diagnostic test identity",
        );
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = std::vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = std::vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        Ok(params)
    }

    fn from_rcgen(cert: rcgen::Certificate, key: &rcgen::KeyPair) -> Result<Self, IdentityError> {
        let spki = key.public_key_der();
        if spki_ed25519_to_raw(&spki).is_err() {
            return Err(IdentityError::UnsupportedKey);
        }
        Ok(TestIdentity {
            certificate: cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()),
            spki,
        })
    }

    /// The certificate DER.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate.as_ref()
    }

    /// The certificate as a rustls type.
    #[must_use]
    pub fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }

    /// The private key for the TLS stack. Callers must not log it.
    #[must_use]
    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.key.clone_key())
    }

    /// The `SubjectPublicKeyInfo` DER of the public key (44 bytes).
    #[must_use]
    pub fn subject_public_key_info_der(&self) -> &[u8] {
        &self.spki
    }

    /// The raw 32-byte Ed25519 public key.
    #[must_use]
    pub fn raw_public_key(&self) -> [u8; 32] {
        // Checked in `from_rcgen`/`load_pem`; the SPKI is always Ed25519 here.
        spki_ed25519_to_raw(&self.spki).unwrap_or([0u8; 32])
    }

    /// The `ssh-ed25519` public-key blob (RFC 8709 §4) for the same key:
    /// `string "ssh-ed25519", string key`. A different encoding of the same
    /// 32 bytes than the SPKI; hashing it gives the SSH host-key fingerprint.
    #[must_use]
    pub fn ssh_ed25519_blob(&self) -> Vec<u8> {
        let mut out = std::vec![0u8; tatami_keys::blob::ED25519_BLOB_LEN];
        let n =
            tatami_keys::blob::encode_ed25519_blob(&self.raw_public_key(), &mut out).unwrap_or(0);
        out.truncate(n);
        out
    }

    /// SHA-256 over the certificate DER (see the module docs for what this
    /// is not).
    #[must_use]
    pub fn certificate_sha256_fingerprint(&self) -> CertificateSha256 {
        CertificateSha256::of_der(self.certificate_der())
    }

    /// SHA-256 over the SPKI DER (RFC 7250 raw public key).
    #[must_use]
    pub fn spki_sha256(&self) -> SpkiSha256 {
        SpkiSha256::of_der(&self.spki)
    }

    /// Writes `cert.pem` and `key.pem` into `dir` (created if missing).
    /// Refuses to overwrite an existing identity.
    pub fn save_pem(&self, dir: &Path) -> Result<(), IdentityError> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        if cert_path.exists() || key_path.exists() {
            return Err(IdentityError::AlreadyExists(dir.to_path_buf()));
        }
        fs::create_dir_all(dir).map_err(|source| IdentityError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        write_new(
            &cert_path,
            pem("CERTIFICATE", self.certificate_der()).as_bytes(),
            false,
        )?;
        write_new(
            &key_path,
            pem("PRIVATE KEY", self.key.secret_pkcs8_der()).as_bytes(),
            true,
        )
    }

    /// Loads `cert.pem` and `key.pem` from `dir`.
    pub fn load_pem(dir: &Path) -> Result<Self, IdentityError> {
        let cert_path = dir.join(CERT_FILE);
        let key_path = dir.join(KEY_FILE);
        if !cert_path.exists() && !key_path.exists() {
            return Err(IdentityError::NotFound(dir.to_path_buf()));
        }
        let cert_pem = fs::read(&cert_path).map_err(|source| IdentityError::Io {
            path: cert_path.clone(),
            source,
        })?;
        let key_pem = fs::read(&key_path).map_err(|source| IdentityError::Io {
            path: key_path.clone(),
            source,
        })?;
        let certificate =
            CertificateDer::from_pem_slice(&cert_pem).map_err(|e| IdentityError::Pem {
                path: cert_path,
                detail: format!("expected one CERTIFICATE PEM block: {e}"),
            })?;
        let key = match PrivateKeyDer::from_pem_slice(&key_pem) {
            Ok(PrivateKeyDer::Pkcs8(k)) => k,
            Ok(_) => return Err(IdentityError::UnsupportedKey),
            Err(e) => {
                return Err(IdentityError::Pem {
                    path: key_path,
                    detail: format!("expected one PRIVATE KEY PEM block: {e}"),
                });
            }
        };
        // Recover the SPKI from the key with the same provider the TLS
        // stack will use; this also proves the key loads.
        let provider = rustls::crypto::ring::default_provider();
        let signing = provider
            .key_provider
            .load_private_key(PrivateKeyDer::Pkcs8(key.clone_key()))
            .map_err(|_| IdentityError::UnsupportedKey)?;
        let spki = signing
            .public_key()
            .ok_or(IdentityError::UnsupportedKey)?
            .as_ref()
            .to_vec();
        spki_ed25519_to_raw(&spki).map_err(|_| IdentityError::UnsupportedKey)?;
        Ok(TestIdentity {
            certificate,
            key,
            spki,
        })
    }

    /// Loads the identity from `dir`, generating and saving one for `names`
    /// first when `generate` is set and none exists. Never generates
    /// silently: without `generate`, a missing identity is an error.
    pub fn load_or_generate(
        dir: &Path,
        generate: bool,
        names: &[String],
    ) -> Result<(Self, bool), IdentityError> {
        match Self::load_pem(dir) {
            Ok(id) => Ok((id, false)),
            Err(IdentityError::NotFound(_)) if generate => {
                let id = Self::generate_ed25519(names)?;
                id.save_pem(dir)?;
                Ok((id, true))
            }
            Err(e) => Err(e),
        }
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let mut body = String::with_capacity(der.len() * 4 / 3 + 4);
    // base64ct pads; PEM uses padded base64 in 64-column lines.
    let encoded = base64ct::Base64::encode_string(der);
    for chunk in encoded.as_bytes().chunks(64) {
        body.push_str(core::str::from_utf8(chunk).unwrap_or(""));
        body.push('\n');
    }
    format!("-----BEGIN {label}-----\n{body}-----END {label}-----\n")
}

fn write_new(path: &Path, contents: &[u8], private: bool) -> Result<(), IdentityError> {
    use std::io::Write as _;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = opts.open(path).map_err(|source| IdentityError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(contents)
        .and_then(|()| file.flush())
        .map_err(|source| IdentityError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    fn names() -> Vec<String> {
        std::vec![String::from("localhost"), String::from("127.0.0.1")]
    }

    #[test]
    fn generated_identity_has_ed25519_spki_and_distinct_fingerprints() {
        let id = TestIdentity::generate_ed25519(&names()).unwrap();
        let spki = id.subject_public_key_info_der();
        assert_eq!(spki.len(), ED25519_SPKI_LEN);
        assert_eq!(&spki[..12], &ED25519_SPKI_PREFIX);
        let raw = spki_ed25519_to_raw(spki).unwrap();
        assert_eq!(raw_ed25519_to_spki(&raw), spki);

        let cert_fp = id.certificate_sha256_fingerprint();
        let spki_fp = id.spki_sha256();
        let ssh_fp = tatami_keys::Sha256Fingerprint::of_blob(&id.ssh_ed25519_blob());
        assert_ne!(cert_fp.as_bytes(), spki_fp.as_bytes());
        assert_ne!(spki_fp.as_bytes(), ssh_fp.as_bytes());
        assert_ne!(cert_fp.as_bytes(), ssh_fp.as_bytes());
        let text = cert_fp.to_string();
        assert!(text.starts_with("SHA256:"));
        assert_eq!(text.len(), 7 + 43);
        assert_eq!(CertificateSha256::parse(&text).unwrap(), cert_fp);
        assert!(!std::format!("{id:?}").contains("PRIVATE"));
    }

    #[test]
    fn spki_conversion_rejects_other_encodings() {
        assert_eq!(spki_ed25519_to_raw(&[0u8; 43]), Err(SpkiError::Length(43)));
        let mut bad = raw_ed25519_to_spki(&[7u8; 32]);
        bad[8] = 0x71; // Ed448 OID would be 1.3.101.113
        assert_eq!(spki_ed25519_to_raw(&bad), Err(SpkiError::Prefix));
        let blob = TestIdentity::generate_ed25519(&names())
            .unwrap()
            .ssh_ed25519_blob();
        assert_eq!(blob.len(), 51);
        assert!(blob.starts_with(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"));
        assert!(
            spki_ed25519_to_raw(&blob).is_err(),
            "SSH blob is not an SPKI"
        );
    }

    #[test]
    fn fingerprint_parsing_is_strict() {
        let fp = CertificateSha256::from_bytes([0x5a; 32]);
        let text = fp.to_string();
        assert_eq!(text.parse::<CertificateSha256>().unwrap(), fp);
        assert_eq!(
            CertificateSha256::parse(&text[7..]),
            Err(FingerprintParseError::MissingPrefix)
        );
        assert_eq!(
            CertificateSha256::parse(&std::format!("{text}=")),
            Err(FingerprintParseError::Padding)
        );
        assert_eq!(
            CertificateSha256::parse("SHA256:abc"),
            Err(FingerprintParseError::WrongLength { found: 3 })
        );
        assert_eq!(
            CertificateSha256::parse(&std::format!("{}!", &text[..text.len() - 1])),
            Err(FingerprintParseError::InvalidBase64)
        );
    }

    #[test]
    fn pem_round_trip_and_no_silent_generation() {
        let dir = std::env::temp_dir().join(std::format!(
            "tatami-quic-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        assert!(matches!(
            TestIdentity::load_or_generate(&dir, false, &names()),
            Err(IdentityError::NotFound(_))
        ));
        let (a, generated) = TestIdentity::load_or_generate(&dir, true, &names()).unwrap();
        assert!(generated);
        let (b, generated) = TestIdentity::load_or_generate(&dir, true, &names()).unwrap();
        assert!(!generated);
        assert_eq!(a.certificate_der(), b.certificate_der());
        assert_eq!(
            a.subject_public_key_info_der(),
            b.subject_public_key_info_der()
        );
        assert_eq!(
            a.certificate_sha256_fingerprint(),
            b.certificate_sha256_fingerprint()
        );
        assert!(matches!(
            a.save_pem(&dir),
            Err(IdentityError::AlreadyExists(_))
        ));
        let key_pem = fs::read_to_string(dir.join(KEY_FILE)).unwrap();
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(dir.join(KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn issued_identity_differs_from_root() {
        let root = TestRoot::generate_ed25519("tatami test root").unwrap();
        let id = TestIdentity::generate_ed25519_issued_by(&names(), &root).unwrap();
        assert_ne!(id.certificate_der(), root.certificate_der());
        assert!(std::format!("{root:?}").contains("certificate_sha256"));
    }
}
