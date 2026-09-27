//! Enabled TLS algorithm configuration of the QUIC diagnostic backend: no
//! SHA-1 signature scheme or cipher suite is usable by the verifiers, and
//! QUIC carries TLS 1.3 only.
//!
//! The bundled provider (`ring`) may still contain SHA-1 code internally;
//! the enforceable boundary is the dependency graph
//! (`scripts/check-sha1-boundary.py`) plus this enabled-algorithm
//! configuration, not the physical absence of every SHA-1 instruction.

#![cfg(feature = "quinn-backend")]

use std::sync::Arc;

use tatami_ssh_keys::Sha256Fingerprint;
use tatami_ssh_keys::trust::PinnedSha256;
use tatami_ssh_quic::diag::identity::{CertificateSha256, SpkiSha256};
use tatami_ssh_quic::diag::rustls;
use tatami_ssh_quic::diag::rustls::SignatureScheme;
use tatami_ssh_quic::diag::rustls::client::danger::ServerCertVerifier;
use tatami_ssh_quic::diag::tls::{
    PinnedCertificateVerifier, PinnedRawPublicKeyVerifier, SshHostKeyVerifier, SshHostTrust,
    identity_slot, provider,
};

const SHA1_SCHEMES: [SignatureScheme; 2] = [
    SignatureScheme::RSA_PKCS1_SHA1,
    SignatureScheme::ECDSA_SHA1_Legacy,
];

fn assert_no_sha1(schemes: &[SignatureScheme], who: &str) {
    assert!(!schemes.is_empty(), "{who}: no schemes");
    for s in schemes {
        assert!(!SHA1_SCHEMES.contains(s), "{who} offers SHA-1 scheme {s:?}");
        let name = format!("{s:?}");
        assert!(!name.contains("SHA1"), "{who} offers {name}");
    }
}

#[test]
fn provider_and_verifier_signature_schemes_exclude_sha1() {
    let p = provider();
    assert_no_sha1(
        &p.signature_verification_algorithms.supported_schemes(),
        "provider",
    );

    let verifiers: Vec<(&str, Arc<dyn ServerCertVerifier>)> = vec![
        (
            "certificate pin",
            Arc::new(PinnedCertificateVerifier::new(
                CertificateSha256::from_bytes([1; 32]),
                &p,
            )),
        ),
        (
            "raw public key pin",
            Arc::new(PinnedRawPublicKeyVerifier::new(
                SpkiSha256::from_bytes([2; 32]),
                &p,
            )),
        ),
        (
            "SSH host key",
            Arc::new(SshHostKeyVerifier::new(
                SshHostTrust {
                    policy: Arc::new(PinnedSha256(Sha256Fingerprint::from_bytes([3; 32]))),
                    source: "pinned_fingerprint",
                    lookup_name: None,
                },
                identity_slot(),
                &p,
            )),
        ),
        (
            "root certificate",
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new({
                    let mut roots = rustls::RootCertStore::empty();
                    let id = tatami_ssh_quic::diag::identity::TestIdentity::generate_ed25519(&[
                        "localhost".to_string(),
                    ])
                    .unwrap();
                    roots.add(id.certificate()).unwrap();
                    roots
                }),
                p.clone(),
            )
            .build()
            .unwrap(),
        ),
    ];
    for (who, v) in verifiers {
        assert_no_sha1(&v.supported_verify_schemes(), who);
    }
}

#[test]
fn provider_has_no_sha1_cipher_suite() {
    // TLS 1.2 SHA-1 suites are named `..._SHA`; TLS 1.3 suites never use
    // SHA-1. The TLS 1.2 suites present (rustls `tls12` feature) are
    // unreachable over QUIC, see below.
    for cs in &provider().cipher_suites {
        let name = format!("{:?}", cs.suite());
        assert!(!name.ends_with("_SHA"), "SHA-1 cipher suite {name}");
        assert!(!name.contains("SHA1"), "SHA-1 cipher suite {name}");
    }
}

#[test]
fn quic_carries_tls13_only() {
    // The diagnostic configs pass `with_protocol_versions(&[TLS13])`; in
    // addition, rustls's QUIC mode refuses any configuration without TLS
    // 1.3, so there is no TLS 1.2 path through QUIC at all.
    let tls12_only = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    let quic = rustls::quic::ClientConnection::new(
        Arc::new(tls12_only),
        rustls::quic::Version::V1,
        "localhost".try_into().unwrap(),
        Vec::new(),
    );
    assert!(quic.is_err(), "rustls QUIC accepted a TLS 1.2-only config");
}
