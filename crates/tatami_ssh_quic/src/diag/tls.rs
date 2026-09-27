//! rustls glue for the diagnostic handshake.
//!
//! - [`RecordingResolver`]: a `ResolvesServerCert` that always returns the
//!   test identity and copies the **offered** ClientHello values (SNI, ALPN
//!   list, cipher suites, signature schemes, named groups, certificate
//!   types) into a slot. `quinn-proto` exposes only the *negotiated* values
//!   (`HandshakeData`), so this hook is the only source of what the client
//!   asked for. Correlation with a connection is exact, not heuristic: the
//!   server core is single-threaded and empties the slot after every call
//!   into `quinn-proto` that can process a ClientHello (`Endpoint::accept`
//!   and `Connection::handle_event`), attaching whatever it finds to the
//!   connection it just drove. The values are peer-supplied and untrusted.
//! - [`PinnedCertificateVerifier`]: accepts exactly one certificate (by
//!   SHA-256 of its DER) and still lets rustls verify the TLS 1.3
//!   `CertificateVerify` signature with the `ring` provider, so proof of
//!   possession is enforced. It is not an accept-anything verifier.
//! - [`PinnedRawPublicKeyVerifier`]: the RFC 7250 counterpart, pinning the
//!   SPKI SHA-256 and verifying with `verify_tls13_signature_with_raw_key`.
//! - [`SshHostKeyVerifier`]: RFC 7250 raw public key judged as an **SSH host
//!   key**: the SPKI is converted strictly to the canonical SSH blob
//!   (`ssh-ed25519`, and `ssh-rsa` / `ecdsa-sha2-nistp256` with the `rsa` /
//!   `ecdsa-p256` features) and handed to the same `HostTrustPolicy` the
//!   TCP handshake uses (a `known_hosts` file bound to the lookup name, or
//!   an SSH `SHA256:` pin). The policy is preloaded and immutable; the
//!   verifier does no file or DNS I/O. `CertificateVerify` is still verified
//!   by the provider: a matching key alone never counts as proof of
//!   possession. The TLS signature scheme must also belong to the key's
//!   type (Ed25519; RSA-PSS for RSA; ECDSA P-256/SHA-256 for P-256).
//! - Config builders producing `quinn-proto` crypto configs with 0-RTT and
//!   resumption disabled.

use std::format;
use std::string::{String, ToString as _};
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::{AlwaysResolvesServerRawPublicKeys, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, DigitallySignedStruct, OtherError, RootCertStore, SignatureScheme};

use tatami_ssh_keys::Sha256Fingerprint;
use tatami_ssh_keys::trust::{HostIdentity, SharedHostTrustPolicy, TrustDecision, UntrustedReason};

use super::ConfigError;
use super::identity::{CertificateSha256, ServerIdentity, SpkiSha256};

/// Upper bound on entries copied from any ClientHello list.
pub const MAX_HELLO_LIST: usize = 32;

/// The crypto provider used everywhere in this backend.
#[must_use]
pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// What the client *offered* in its most recent ClientHello. Untrusted
/// metadata: it is whatever bytes the peer sent, bounded and copied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHelloRecord {
    /// SNI as sent (a DNS name; absent for IP literals or when omitted).
    pub server_name: Option<String>,
    /// ALPN protocol names in offered order, or `None` if the extension
    /// was absent. Raw bytes; render escaped.
    pub alpn: Option<Vec<Vec<u8>>>,
    /// Cipher suites, rustls `Debug` names, offered order.
    pub cipher_suites: Vec<String>,
    /// Signature schemes, rustls `Debug` names.
    pub signature_schemes: Vec<String>,
    /// Named groups (key exchange), or `None` if absent.
    pub named_groups: Option<Vec<String>>,
    /// `server_certificate_type` values, or `None` if absent (RFC 7250).
    pub server_cert_types: Option<Vec<String>>,
    /// How many times a ClientHello was resolved on this connection (2
    /// after a HelloRetryRequest). The record holds the latest.
    pub hellos_seen: u32,
}

/// Slot the resolver writes into and the server core drains.
pub type HelloSlot = Arc<Mutex<Option<ClientHelloRecord>>>;

/// Creates an empty slot.
#[must_use]
pub fn hello_slot() -> HelloSlot {
    Arc::new(Mutex::new(None))
}

/// `ResolvesServerCert` that records the ClientHello and serves one key.
#[derive(Debug)]
pub struct RecordingResolver {
    certified: Arc<CertifiedKey>,
    slot: HelloSlot,
    raw_public_keys: bool,
}

impl RecordingResolver {
    /// Wraps `certified` (a certificate chain, or a single SPKI when
    /// `raw_public_keys` is set) and records into `slot`.
    #[must_use]
    pub fn new(certified: Arc<CertifiedKey>, slot: HelloSlot, raw_public_keys: bool) -> Self {
        RecordingResolver {
            certified,
            slot,
            raw_public_keys,
        }
    }
}

fn debug_list<T: core::fmt::Debug>(items: impl Iterator<Item = T>) -> Vec<String> {
    items
        .take(MAX_HELLO_LIST)
        .map(|x| format!("{x:?}"))
        .collect()
}

impl ResolvesServerCert for RecordingResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let record = ClientHelloRecord {
            server_name: client_hello.server_name().map(String::from),
            alpn: client_hello.alpn().map(|it| {
                it.take(MAX_HELLO_LIST)
                    .map(|p| p[..p.len().min(255)].to_vec())
                    .collect()
            }),
            cipher_suites: debug_list(client_hello.cipher_suites().iter()),
            signature_schemes: debug_list(client_hello.signature_schemes().iter()),
            named_groups: client_hello.named_groups().map(|g| debug_list(g.iter())),
            server_cert_types: client_hello
                .server_cert_types()
                .map(|t| debug_list(t.iter())),
            hellos_seen: 1,
        };
        if let Ok(mut slot) = self.slot.lock() {
            let seen = slot.as_ref().map_or(0, |r| r.hellos_seen);
            *slot = Some(ClientHelloRecord {
                hellos_seen: seen + 1,
                ..record
            });
        }
        Some(self.certified.clone())
    }

    fn only_raw_public_keys(&self) -> bool {
        self.raw_public_keys
    }
}

/// Error returned to rustls when the presented identity is not the pin.
/// rustls maps `CertificateError::Other` to the `certificate_unknown` alert
/// (46) and renders it with `Debug`, so `Debug` carries the message.
pub struct PinMismatch {
    what: &'static str,
}

impl core::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "presented {} does not match the configured SHA-256 pin",
            self.what
        )
    }
}

impl core::fmt::Debug for PinMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for PinMismatch {}

fn pin_mismatch(what: &'static str) -> rustls::Error {
    rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(PinMismatch {
        what,
    }))))
}

/// Accepts exactly the certificate whose DER hashes to the pin; signature
/// verification is delegated to rustls/webpki with the provider's schemes.
///
/// Name, validity period and chain are deliberately not checked: the pin
/// identifies one exact certificate, which is a stronger statement than any
/// of those. `intermediates` are ignored (a self-signed test identity sends
/// none).
#[derive(Debug)]
pub struct PinnedCertificateVerifier {
    pin: CertificateSha256,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedCertificateVerifier {
    /// Pins `pin` and verifies signatures with `provider`'s algorithms.
    #[must_use]
    pub fn new(pin: CertificateSha256, provider: &CryptoProvider) -> Self {
        PinnedCertificateVerifier {
            pin,
            algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if CertificateSha256::of_der(end_entity.as_ref()) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(pin_mismatch("certificate"))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// RFC 7250 raw-public-key verifier pinning the SPKI SHA-256. rustls sends
/// `server_certificate_type = RawPublicKey` because
/// `requires_raw_public_keys` is true; the `Certificate` message then
/// carries the SPKI as the single "certificate", and proof of possession is
/// still checked via `verify_tls13_signature_with_raw_key`.
#[derive(Debug)]
pub struct PinnedRawPublicKeyVerifier {
    pin: SpkiSha256,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedRawPublicKeyVerifier {
    /// Pins `pin`.
    #[must_use]
    pub fn new(pin: SpkiSha256, provider: &CryptoProvider) -> Self {
        PinnedRawPublicKeyVerifier {
            pin,
            algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedRawPublicKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if SpkiSha256::of_der(end_entity.as_ref()) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(pin_mismatch("raw public key"))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is never negotiated over QUIC".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        rustls::crypto::verify_tls13_signature_with_raw_key(message, &spki, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// What the SSH host-key verifier saw and decided. Public data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshIdentityCheck {
    /// The raw public key converted to an SSH identity and was judged.
    Judged {
        /// SSH public-key algorithm (`ssh-ed25519`, `ssh-rsa` or
        /// `ecdsa-sha2-nistp256`).
        algorithm: String,
        /// The canonical SSH public-key blob.
        blob: Vec<u8>,
        /// OpenSSH `SHA256:` fingerprint of `blob`.
        fingerprint: Sha256Fingerprint,
        /// The policy's decision.
        decision: TrustDecision,
    },
    /// The presented bytes are not a supported SPKI (for example a
    /// certificate where a raw key was required, an unsupported algorithm or
    /// curve, or malformed DER).
    NotConvertible {
        /// Why, from `tatami_ssh_keys::spki`.
        reason: String,
    },
}

impl SshIdentityCheck {
    /// `true` when judged and trusted.
    #[must_use]
    pub fn is_trusted(&self) -> bool {
        matches!(self, SshIdentityCheck::Judged { decision, .. } if decision.is_trusted())
    }
}

/// Where the verifier records its [`SshIdentityCheck`] for the report.
pub type IdentitySlot = Arc<Mutex<Option<SshIdentityCheck>>>;

/// SSH host-key trust for the QUIC client: a preloaded policy plus labels
/// for reports.
#[derive(Clone)]
pub struct SshHostTrust {
    /// The decision (a `known_hosts` policy bound to `lookup_name`, or an
    /// SSH-blob `SHA256:` pin).
    pub policy: Arc<dyn SharedHostTrustPolicy>,
    /// Stable code of the policy: `known_hosts` or `pinned_fingerprint`.
    pub source: &'static str,
    /// Logical lookup name bound before connecting (`known_hosts` only).
    pub lookup_name: Option<String>,
}

impl core::fmt::Debug for SshHostTrust {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SshHostTrust")
            .field("source", &self.source)
            .field("lookup_name", &self.lookup_name)
            .finish_non_exhaustive()
    }
}

/// Error returned to rustls when the SSH host policy refuses the key.
pub struct HostNotTrusted {
    reason: UntrustedReason,
}

impl core::fmt::Display for HostNotTrusted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "SSH host key not trusted: {} ({})",
            self.reason.describe(),
            self.reason.code()
        )
    }
}

impl core::fmt::Debug for HostNotTrusted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for HostNotTrusted {}

/// RFC 7250 raw public key judged as an SSH host key through a shared
/// [`tatami_ssh_keys::trust::HostTrustPolicy`]. See the module docs.
#[derive(Debug)]
pub struct SshHostKeyVerifier {
    trust: SshHostTrust,
    slot: IdentitySlot,
    algs: WebPkiSupportedAlgorithms,
}

impl SshHostKeyVerifier {
    /// Judges with `trust`, records into `slot`, verifies signatures with
    /// `provider`'s algorithms.
    #[must_use]
    pub fn new(trust: SshHostTrust, slot: IdentitySlot, provider: &CryptoProvider) -> Self {
        SshHostKeyVerifier {
            trust,
            slot,
            algs: provider.signature_verification_algorithms,
        }
    }

    fn record(&self, check: SshIdentityCheck) {
        if let Ok(mut s) = self.slot.lock() {
            *s = Some(check);
        }
    }
}

impl ServerCertVerifier for SshHostKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let key = match tatami_ssh_keys::spki::host_key_from_spki(end_entity.as_ref()) {
            Ok(k) => k,
            Err(e) => {
                self.record(SshIdentityCheck::NotConvertible {
                    reason: e.to_string(),
                });
                return Err(rustls::Error::InvalidCertificate(
                    CertificateError::BadEncoding,
                ));
            }
        };
        let blob = key.to_blob();
        let fingerprint = Sha256Fingerprint::of_blob(&blob);
        let identity = HostIdentity {
            algorithm: key.algorithm(),
            blob: &blob,
            sha256: fingerprint,
        };
        let decision = self.trust.policy.decide(&identity);
        self.record(SshIdentityCheck::Judged {
            algorithm: key.key_type().to_string(),
            blob,
            fingerprint,
            decision,
        });
        match decision {
            TrustDecision::Trusted { .. } => Ok(ServerCertVerified::assertion()),
            TrustDecision::Untrusted { reason } => Err(rustls::Error::InvalidCertificate(
                CertificateError::Other(OtherError(Arc::new(HostNotTrusted { reason }))),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "TLS 1.2 is never negotiated over QUIC".to_string(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // The scheme must be the TLS 1.3 scheme for this key type; webpki
        // also ties the scheme to the SPKI algorithm, this makes the
        // expectation explicit and independent of that mapping.
        let key = tatami_ssh_keys::spki::host_key_from_spki(cert.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if !scheme_matches_key(dss.scheme, key.key_type()) {
            return Err(rustls::Error::General(format!(
                "TLS signature scheme {:?} does not belong to the {} host key",
                dss.scheme,
                key.key_type()
            )));
        }
        // Proof of possession, independent of the trust decision above.
        let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
        rustls::crypto::verify_tls13_signature_with_raw_key(message, &spki, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The TLS 1.3 `CertificateVerify` schemes acceptable for an SSH host key
/// of type `key_type` (RFC 8446 §4.2.3): Ed25519 for Ed25519; RSA-PSS
/// (rsaEncryption key) for RSA — never PKCS#1 v1.5 in TLS 1.3; ECDSA with
/// SHA-256 on P-256 for P-256.
#[must_use]
pub fn scheme_matches_key(scheme: SignatureScheme, key_type: tatami_ssh_keys::KeyType) -> bool {
    use tatami_ssh_keys::KeyType;
    matches!(
        (key_type, scheme),
        (KeyType::Ed25519, SignatureScheme::ED25519)
            | (
                KeyType::Rsa,
                SignatureScheme::RSA_PSS_SHA256
                    | SignatureScheme::RSA_PSS_SHA384
                    | SignatureScheme::RSA_PSS_SHA512
            )
            | (KeyType::EcdsaP256, SignatureScheme::ECDSA_NISTP256_SHA256)
    )
}

/// How the server presents its identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerIdentityMode {
    /// X.509 certificate (the observer's default).
    Certificate,
    /// RFC 7250 raw public key through rustls's own
    /// `AlwaysResolvesServerRawPublicKeys`, verbatim. That resolver consumes
    /// the `ClientHello`, so nothing is recorded in this mode (experiment
    /// only).
    RawPublicKey,
    /// RFC 7250 raw public key through [`RecordingResolver`] with
    /// `only_raw_public_keys() == true`: same wire behaviour, plus the
    /// offered `server_certificate_type` list is captured.
    RawPublicKeyRecording,
}

/// How the client decides whether the server's identity is acceptable.
#[derive(Clone, Debug)]
pub enum ClientTrust {
    /// Accept only the certificate with this DER SHA-256.
    PinnedCertificateSha256(CertificateSha256),
    /// Accept certificates chaining to this single root (DER) that are
    /// valid for the requested server name, via `WebPkiServerVerifier`.
    RootCertificate(Vec<u8>),
    /// Accept only the RFC 7250 raw public key with this SPKI SHA-256.
    PinnedRawPublicKeySha256(SpkiSha256),
    /// Require an RFC 7250 raw public key and judge it as an SSH host key
    /// (`known_hosts` or SSH-blob pin). Certificates are refused.
    SshHostKey(SshHostTrust),
}

impl ClientTrust {
    /// Stable code for reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            ClientTrust::PinnedCertificateSha256(_) => "pinned_certificate_sha256",
            ClientTrust::RootCertificate(_) => "root_certificate",
            ClientTrust::PinnedRawPublicKeySha256(_) => "pinned_raw_public_key_sha256",
            ClientTrust::SshHostKey(t) => match t.source.as_bytes() {
                b"known_hosts" => "ssh_host_key_known_hosts",
                _ => "ssh_host_key_pinned_fingerprint",
            },
        }
    }

    /// `true` when the server must present an RFC 7250 raw public key.
    #[must_use]
    pub const fn requires_raw_public_key(&self) -> bool {
        matches!(
            self,
            ClientTrust::PinnedRawPublicKeySha256(_) | ClientTrust::SshHostKey(_)
        )
    }
}

/// Builds the server's QUIC crypto config with 0-RTT and tickets disabled.
///
/// The resolver records offered ClientHello values into `slot`. In
/// `RawPublicKey` mode the certified key's "chain" is the SPKI DER and the
/// resolver reports `only_raw_public_keys`, so rustls answers a client's
/// `server_certificate_type` extension with `RawPublicKey` (and fails the
/// handshake for clients that do not offer it, RFC 7250 §4.1).
pub fn server_crypto(
    identity: &ServerIdentity,
    alpn: &[Vec<u8>],
    slot: HelloSlot,
    mode: ServerIdentityMode,
) -> Result<Arc<QuicServerConfig>, ConfigError> {
    super::validate_alpn(alpn)?;
    let provider = provider();
    let (key, chain) = match (identity, mode) {
        (ServerIdentity::HostKey(_), ServerIdentityMode::Certificate) => {
            return Err(ConfigError::IdentityMode(
                "an SSH host key is presented only as an RFC 7250 raw public key; no certificate is manufactured",
            ));
        }
        (ServerIdentity::HostKey(h), _) => (
            h.signing_key(),
            std::vec![CertificateDer::from(
                h.subject_public_key_info_der().to_vec()
            )],
        ),
        (ServerIdentity::Test(t), mode) => {
            let key = provider
                .key_provider
                .load_private_key(t.private_key())
                .map_err(ConfigError::Key)?;
            let chain = match mode {
                ServerIdentityMode::Certificate => std::vec![t.certificate()],
                ServerIdentityMode::RawPublicKey | ServerIdentityMode::RawPublicKeyRecording => {
                    // RFC 7250: the "certificate" is the SubjectPublicKeyInfo DER.
                    std::vec![CertificateDer::from(
                        t.subject_public_key_info_der().to_vec(),
                    )]
                }
            };
            (key, chain)
        }
    };
    let certified = Arc::new(CertifiedKey::new(chain, key));
    let resolver: Arc<dyn ResolvesServerCert> = match mode {
        ServerIdentityMode::Certificate => Arc::new(RecordingResolver::new(certified, slot, false)),
        ServerIdentityMode::RawPublicKey => {
            Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified))
        }
        ServerIdentityMode::RawPublicKeyRecording => {
            Arc::new(RecordingResolver::new(certified, slot, true))
        }
    };
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(ConfigError::Tls)?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    tls.alpn_protocols = alpn.to_vec();
    // 0-RTT off: quinn-proto's own `with_single_cert` path would set this to
    // u32::MAX; we build the rustls config ourselves and keep the default.
    tls.max_early_data_size = 0;
    // No session tickets: nothing to resume, nothing to replay.
    tls.send_tls13_tickets = 0;
    QuicServerConfig::try_from(tls)
        .map(Arc::new)
        .map_err(|e| ConfigError::Quic(e.to_string()))
}

/// Builds the client's QUIC crypto config with early data and resumption
/// disabled. `alpn` is what will be offered.
pub fn client_crypto(
    trust: &ClientTrust,
    alpn: &[Vec<u8>],
) -> Result<Arc<QuicClientConfig>, ConfigError> {
    client_crypto_recording(trust, alpn, identity_slot())
}

/// Creates an empty identity slot.
#[must_use]
pub fn identity_slot() -> IdentitySlot {
    Arc::new(Mutex::new(None))
}

/// [`client_crypto`], recording SSH host-key checks into `slot`.
pub fn client_crypto_recording(
    trust: &ClientTrust,
    alpn: &[Vec<u8>],
    slot: IdentitySlot,
) -> Result<Arc<QuicClientConfig>, ConfigError> {
    super::validate_alpn(alpn)?;
    let provider = provider();
    let verifier: Arc<dyn ServerCertVerifier> = match trust {
        ClientTrust::SshHostKey(t) => Arc::new(SshHostKeyVerifier::new(t.clone(), slot, &provider)),
        ClientTrust::PinnedCertificateSha256(pin) => {
            Arc::new(PinnedCertificateVerifier::new(*pin, &provider))
        }
        ClientTrust::PinnedRawPublicKeySha256(pin) => {
            Arc::new(PinnedRawPublicKeyVerifier::new(*pin, &provider))
        }
        ClientTrust::RootCertificate(der) => {
            let mut roots = RootCertStore::empty();
            roots
                .add(CertificateDer::from(der.clone()))
                .map_err(ConfigError::Tls)?;
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
                .build()
                .map_err(|e| ConfigError::Tls(rustls::Error::General(e.to_string())))?
        }
    };
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(ConfigError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = alpn.to_vec();
    tls.enable_early_data = false;
    tls.resumption = Resumption::disabled();
    QuicClientConfig::try_from(tls)
        .map(Arc::new)
        .map_err(|e| ConfigError::Quic(e.to_string()))
}

/// Parses a TLS server name for `Endpoint::connect`; rustls sends SNI only
/// for DNS names, never for IP literals (RFC 6066 §3).
pub fn check_server_name(name: &str) -> Result<ServerNameKind, ConfigError> {
    match ServerName::try_from(name).map_err(|_| ConfigError::ServerName(name.to_string()))? {
        ServerName::DnsName(_) => Ok(ServerNameKind::DnsName),
        ServerName::IpAddress(_) => Ok(ServerNameKind::IpAddress),
        _ => Ok(ServerNameKind::Other),
    }
}

/// Classification of a server name for reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerNameKind {
    /// A DNS name; SNI will be sent.
    DnsName,
    /// An IP literal; no SNI is sent.
    IpAddress,
    /// Another `ServerName` variant.
    Other,
}

impl ServerNameKind {
    /// `true` when rustls will include the `server_name` extension.
    #[must_use]
    pub const fn sends_sni(self) -> bool {
        matches!(self, ServerNameKind::DnsName)
    }
}
