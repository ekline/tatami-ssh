//! RFC 7250 raw-public-key experiment over QUIC with rustls 0.23.45.
//!
//! Server: `AlwaysResolvesServerRawPublicKeys` (rustls's own type) or the
//! recording resolver with `only_raw_public_keys() == true`, both handing
//! out the Ed25519 `SubjectPublicKeyInfo` DER as the single "certificate".
//! Client: a `ServerCertVerifier` with `requires_raw_public_keys() == true`
//! that pins the SPKI SHA-256 and verifies the TLS 1.3 `CertificateVerify`
//! signature with `verify_tls13_signature_with_raw_key`, so proof of
//! possession is still enforced by rustls/webpki/ring.
//!
//! Also fixes the typed conversion between the three encodings of the same
//! 32-byte Ed25519 key (SPKI DER, raw, `ssh-ed25519` blob) and shows that
//! their SHA-256 fingerprints all differ.

#![cfg(feature = "quinn-backend")]

use std::net::SocketAddr;
use std::time::Duration;

use tatami_quic::diag::client::{DiagClientConfig, ExporterProbe, HandshakeResult};
use tatami_quic::diag::identity::{
    ED25519_SPKI_PREFIX, SpkiSha256, TestIdentity, raw_ed25519_to_spki, spki_ed25519_to_raw,
};
use tatami_quic::diag::inmem::Pair;
use tatami_quic::diag::inmem::raw_handshake;
use tatami_quic::diag::rustls::pki_types::CertificateDer;
use tatami_quic::diag::server::{DiagServerConfig, HandshakeOutcome};
use tatami_quic::diag::tls::{ClientTrust, ServerIdentityMode};
use tatami_quic::diag::tls::{client_crypto, hello_slot, server_crypto};
use tatami_quic::keys::Sha256Fingerprint;

const ALPN: &[u8] = b"tatami-diag/0";

fn addrs() -> (SocketAddr, SocketAddr) {
    (
        "127.0.0.1:4433".parse().unwrap(),
        "127.0.0.1:50002".parse().unwrap(),
    )
}

fn identity() -> TestIdentity {
    TestIdentity::generate_ed25519(&["localhost".to_string()]).unwrap()
}

fn configs(
    id: TestIdentity,
    mode: ServerIdentityMode,
    trust: ClientTrust,
) -> (DiagServerConfig, DiagClientConfig) {
    let (s_addr, _) = addrs();
    let mut sc = DiagServerConfig::new(id, vec![ALPN.to_vec()]);
    sc.bind = s_addr;
    sc.identity_mode = mode;
    let mut cc = DiagClientConfig::new(s_addr, "localhost", vec![ALPN.to_vec()], trust);
    cc.handshake_timeout = Duration::from_secs(5);
    cc.exporter = Some(ExporterProbe::default());
    (sc, cc)
}

fn run(
    sc: &DiagServerConfig,
    cc: &DiagClientConfig,
) -> (
    HandshakeResult,
    String,
    HandshakeOutcome,
    Option<Vec<String>>,
) {
    let (_, c_addr) = addrs();
    let mut pair = Pair::new(sc, cc, c_addr).unwrap();
    assert!(pair.run(10_000), "client did not finish");
    let (client, observations, _) = pair.finish_client();
    assert_eq!(observations.len(), 1, "{observations:?}");
    let o = &observations[0];
    let cert_types = o.offered.as_ref().and_then(|h| h.server_cert_types.clone());
    (
        client.handshake,
        client.close_reason,
        o.outcome.clone(),
        cert_types,
    )
}

#[test]
fn three_encodings_of_one_key_have_three_fingerprints() {
    let id = identity();
    let spki = id.subject_public_key_info_der();
    assert_eq!(spki.len(), 44);
    assert_eq!(&spki[..12], &ED25519_SPKI_PREFIX);
    let raw = spki_ed25519_to_raw(spki).unwrap();
    assert_eq!(raw, id.raw_public_key());
    assert_eq!(raw_ed25519_to_spki(&raw), spki);

    let blob = id.ssh_ed25519_blob();
    assert_eq!(blob.len(), 51);
    assert_eq!(&blob[..15], b"\x00\x00\x00\x0bssh-ed25519");
    assert_eq!(&blob[15..19], &[0, 0, 0, 32]);
    assert_eq!(&blob[19..], &raw);

    let cert_fp = id.certificate_sha256_fingerprint();
    let spki_fp = id.spki_sha256();
    let ssh_fp = Sha256Fingerprint::of_blob(&blob);
    assert_ne!(cert_fp.as_bytes(), spki_fp.as_bytes());
    assert_ne!(spki_fp.as_bytes(), ssh_fp.as_bytes());
    assert_ne!(cert_fp.as_bytes(), ssh_fp.as_bytes());
    // Same presentation, different meaning: all three render as SHA256:…
    for text in [cert_fp.to_string(), spki_fp.to_string(), ssh_fp.to_string()] {
        assert!(text.starts_with("SHA256:") && text.len() == 50, "{text}");
    }
    // The SSH fingerprint is over the blob, not the raw key or the SPKI.
    assert_ne!(Sha256Fingerprint::of_blob(&raw), ssh_fp);
    assert_ne!(Sha256Fingerprint::of_blob(spki), ssh_fp);
    assert_eq!(
        Sha256Fingerprint::of_blob(spki).as_bytes(),
        spki_fp.as_bytes(),
        "SpkiSha256 is exactly SHA-256 over the SPKI DER"
    );
}

#[test]
fn raw_public_key_peer_identity_is_the_spki_and_x509_peer_identity_is_the_certificate() {
    let id = identity();
    // RPK: `peer_identity()` (rustls `peer_certificates()`) holds exactly
    // one element and it is the SPKI DER, not a certificate.
    let rpk = raw_handshake(
        client_crypto(
            &ClientTrust::PinnedRawPublicKeySha256(id.spki_sha256()),
            &[ALPN.to_vec()],
        )
        .unwrap(),
        server_crypto(
            &id,
            &[ALPN.to_vec()],
            hello_slot(),
            ServerIdentityMode::RawPublicKey,
        )
        .unwrap(),
        "localhost",
        Duration::from_secs(5),
        1_000,
    )
    .unwrap();
    assert!(
        rpk.completed(),
        "{:?} / {:?}",
        rpk.client_result,
        rpk.server_result
    );
    let peer = rpk
        .client
        .crypto_session()
        .peer_identity()
        .expect("peer identity")
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("rustls session: Vec<CertificateDer>");
    assert_eq!(peer.len(), 1);
    assert_eq!(peer[0].as_ref(), id.subject_public_key_info_der());
    assert_eq!(
        SpkiSha256::of_der(peer[0].as_ref()),
        id.spki_sha256(),
        "the pin compared exactly this DER"
    );
    // Exporter works over an RPK-authenticated connection too.
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    assert!(
        rpk.client
            .crypto_session()
            .export_keying_material(&mut a, b"EXPERIMENTAL-tatami-ssh-binding-v0", b"ctx")
            .is_ok()
    );
    assert!(
        rpk.server
            .as_ref()
            .unwrap()
            .crypto_session()
            .export_keying_material(&mut b, b"EXPERIMENTAL-tatami-ssh-binding-v0", b"ctx")
            .is_ok()
    );
    assert_eq!(a, b);

    // X.509: the same accessor yields the certificate DER.
    let x509 = raw_handshake(
        client_crypto(
            &ClientTrust::PinnedCertificateSha256(id.certificate_sha256_fingerprint()),
            &[ALPN.to_vec()],
        )
        .unwrap(),
        server_crypto(
            &id,
            &[ALPN.to_vec()],
            hello_slot(),
            ServerIdentityMode::Certificate,
        )
        .unwrap(),
        "localhost",
        Duration::from_secs(5),
        1_000,
    )
    .unwrap();
    assert!(x509.completed());
    let peer = x509
        .client
        .crypto_session()
        .peer_identity()
        .unwrap()
        .downcast::<Vec<CertificateDer<'static>>>()
        .unwrap();
    assert_eq!(peer.len(), 1);
    assert_eq!(peer[0].as_ref(), id.certificate_der());
    assert_ne!(peer[0].as_ref(), id.subject_public_key_info_der());
}

#[test]
fn raw_public_key_handshake_completes_with_rustls_resolver() {
    let id = identity();
    let pin = id.spki_sha256();
    let (sc, cc) = configs(
        id,
        ServerIdentityMode::RawPublicKey,
        ClientTrust::PinnedRawPublicKeySha256(pin),
    );
    let (client, close, server, _) = run(&sc, &cc);
    assert_eq!(client, HandshakeResult::Completed, "{close}");
    assert_eq!(server, HandshakeOutcome::Completed);
}

#[test]
fn raw_public_key_handshake_completes_with_recording_resolver_and_records_cert_type() {
    let id = identity();
    let pin = id.spki_sha256();
    let (sc, cc) = configs(
        id,
        ServerIdentityMode::RawPublicKeyRecording,
        ClientTrust::PinnedRawPublicKeySha256(pin),
    );
    let (client, _, server, cert_types) = run(&sc, &cc);
    assert_eq!(client, HandshakeResult::Completed);
    assert_eq!(server, HandshakeOutcome::Completed);
    assert_eq!(
        cert_types.as_deref(),
        Some(&["RawPublicKey".to_string()][..]),
        "client offered server_certificate_type = raw_public_key"
    );
}

#[test]
fn raw_public_key_with_wrong_pin_fails_but_proof_of_possession_path_is_exercised() {
    let id = identity();
    let other = identity();
    let (sc, cc) = configs(
        id,
        ServerIdentityMode::RawPublicKey,
        ClientTrust::PinnedRawPublicKeySha256(other.spki_sha256()),
    );
    let (client, _, server, _) = run(&sc, &cc);
    let HandshakeResult::Failed { reason } = client else {
        panic!("{client:?}");
    };
    assert!(reason.contains("raw public key does not match"), "{reason}");
    assert!(
        matches!(server, HandshakeOutcome::Failed { .. }),
        "{server:?}"
    );
}

#[test]
fn x509_client_against_raw_public_key_server_does_not_silently_downgrade() {
    let id = identity();
    let cert_pin = id.certificate_sha256_fingerprint();
    let (sc, cc) = configs(
        id,
        ServerIdentityMode::RawPublicKey,
        ClientTrust::PinnedCertificateSha256(cert_pin),
    );
    let (client, _, server, cert_types) = run(&sc, &cc);
    assert!(
        matches!(client, HandshakeResult::Failed { .. }),
        "an X.509-only client must not complete against an RPK-only server: {client:?}"
    );
    assert!(!matches!(server, HandshakeOutcome::Completed), "{server:?}");
    assert!(cert_types.is_none(), "no cert-type extension offered");
}

#[test]
fn raw_public_key_client_against_x509_server_fails() {
    let id = identity();
    let pin = id.spki_sha256();
    let (sc, cc) = configs(
        id,
        ServerIdentityMode::Certificate,
        ClientTrust::PinnedRawPublicKeySha256(pin),
    );
    let (client, _, server, cert_types) = run(&sc, &cc);
    let HandshakeResult::Failed { reason } = client else {
        panic!("{client:?}");
    };
    assert!(!reason.is_empty());
    assert!(!matches!(server, HandshakeOutcome::Completed), "{server:?}");
    assert_eq!(
        cert_types.as_deref(),
        Some(&["RawPublicKey".to_string()][..])
    );
    // A certificate's SHA-256 is never an SPKI's.
    let cert_as_spki = SpkiSha256::of_der(sc.identity.certificate_der());
    assert_ne!(cert_as_spki, pin);
}
