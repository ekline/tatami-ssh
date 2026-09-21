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

use super::ConfigError;
use super::identity::{CertificateSha256, SpkiSha256, TestIdentity};

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
}

impl ClientTrust {
    /// Stable code for reports.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            ClientTrust::PinnedCertificateSha256(_) => "pinned_certificate_sha256",
            ClientTrust::RootCertificate(_) => "root_certificate",
            ClientTrust::PinnedRawPublicKeySha256(_) => "pinned_raw_public_key_sha256",
        }
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
    identity: &TestIdentity,
    alpn: &[Vec<u8>],
    slot: HelloSlot,
    mode: ServerIdentityMode,
) -> Result<Arc<QuicServerConfig>, ConfigError> {
    super::validate_alpn(alpn)?;
    let provider = provider();
    let key = provider
        .key_provider
        .load_private_key(identity.private_key())
        .map_err(ConfigError::Key)?;
    let chain = match mode {
        ServerIdentityMode::Certificate => std::vec![identity.certificate()],
        ServerIdentityMode::RawPublicKey | ServerIdentityMode::RawPublicKeyRecording => {
            // RFC 7250: the "certificate" is the SubjectPublicKeyInfo DER.
            std::vec![CertificateDer::from(
                identity.subject_public_key_info_der().to_vec(),
            )]
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
    super::validate_alpn(alpn)?;
    let provider = provider();
    let verifier: Arc<dyn ServerCertVerifier> = match trust {
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
