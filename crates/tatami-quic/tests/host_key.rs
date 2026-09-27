//! An SSH Ed25519 host key presented over QUIC as an RFC 7250 raw public
//! key and judged by the same `HostTrustPolicy` as the TCP handshake.
//!
//! In memory, no sockets. Covers: SSH-blob pin and `known_hosts` success
//! with the reported SSH fingerprint; changed, revoked and unknown keys;
//! a certificate peer refused by SSH trust; an X.509 client refused by a
//! host-key server; a host-key server that cannot be configured for
//! certificates; and a matching trusted key whose `CertificateVerify` is
//! made with a different private key (fails: trust is not possession).

#![cfg(feature = "quinn-backend")]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64ct::{Base64, Encoding as _};
use tatami_keys::known_hosts::{KnownHosts, Limits};
use tatami_keys::trust::{PinnedSha256, SharedHostTrustPolicy, TrustDecision, UntrustedReason};
use tatami_quic::diag::ConfigError;
use tatami_quic::diag::client::{DiagClientConfig, HandshakeResult};
use tatami_quic::diag::identity::{HostKeyIdentity, TestIdentity};
use tatami_quic::diag::inmem::{Pair, raw_handshake};
use tatami_quic::diag::quinn_proto::crypto::rustls::QuicServerConfig;
use tatami_quic::diag::rustls;
use tatami_quic::diag::server::{DiagServerConfig, HandshakeOutcome};
use tatami_quic::diag::tls::{
    ClientTrust, ServerIdentityMode, SshHostTrust, SshIdentityCheck, client_crypto_recording,
    identity_slot, provider,
};
use tatami_quic::keys::Sha256Fingerprint;

const ALPN: &[u8] = b"tatami-diag/0";

fn server_addr() -> SocketAddr {
    "127.0.0.1:4433".parse().unwrap()
}

/// An Ed25519 key standing in for a converted OpenSSH host key: its PKCS#8
/// bytes and canonical SSH blob.
struct Key {
    pkcs8: Vec<u8>,
    blob: Vec<u8>,
    test: TestIdentity,
}

fn key() -> Key {
    let test = TestIdentity::generate_ed25519(&["localhost".to_string()]).unwrap();
    Key {
        pkcs8: test.private_key().secret_der().to_vec(),
        blob: test.ssh_ed25519_blob(),
        test,
    }
}

fn host(k: &Key) -> HostKeyIdentity {
    HostKeyIdentity::from_pkcs8(&k.pkcs8, &k.blob).unwrap()
}

fn ssh_trust(policy: impl SharedHostTrustPolicy + 'static, source: &'static str) -> ClientTrust {
    ClientTrust::SshHostKey(SshHostTrust {
        policy: Arc::new(policy),
        source,
        lookup_name: None,
    })
}

fn pin(k: &Key) -> ClientTrust {
    ssh_trust(
        PinnedSha256(Sha256Fingerprint::of_blob(&k.blob)),
        "pinned_fingerprint",
    )
}

fn known_hosts(text: &str) -> ClientTrust {
    let kh = KnownHosts::parse(text.as_bytes(), &Limits::default()).unwrap();
    let policy = kh.policy_for("localhost", 4433).unwrap();
    ssh_trust(policy, "known_hosts")
}

fn entry(hosts: &str, k: &Key) -> String {
    format!("{hosts} ssh-ed25519 {}\n", Base64::encode_string(&k.blob))
}

fn run(
    sc: &DiagServerConfig,
    trust: ClientTrust,
) -> (tatami_quic::diag::client::ClientOutcome, HandshakeOutcome) {
    let mut cc = DiagClientConfig::new(server_addr(), "localhost", vec![ALPN.to_vec()], trust);
    cc.handshake_timeout = Duration::from_secs(5);
    let mut pair = Pair::new(sc, &cc, "127.0.0.1:50003".parse().unwrap()).unwrap();
    assert!(pair.run(10_000), "client did not finish");
    let (client, observations, _) = pair.finish_client();
    assert_eq!(observations.len(), 1, "{observations:?}");
    (client, observations[0].outcome.clone())
}

fn server(identity: impl Into<tatami_quic::diag::identity::ServerIdentity>) -> DiagServerConfig {
    let mut sc = DiagServerConfig::new(identity, vec![ALPN.to_vec()]);
    sc.bind = server_addr();
    sc
}

fn judged(check: &Option<SshIdentityCheck>) -> (Sha256Fingerprint, TrustDecision) {
    match check {
        Some(SshIdentityCheck::Judged {
            fingerprint,
            decision,
            algorithm,
            ..
        }) => {
            assert_eq!(algorithm, "ssh-ed25519");
            (*fingerprint, *decision)
        }
        other => panic!("expected a judged identity, got {other:?}"),
    }
}

#[test]
fn host_key_with_ssh_pin_completes_and_reports_the_ssh_fingerprint() {
    let k = key();
    let sc = server(host(&k));
    assert_eq!(sc.identity_mode, ServerIdentityMode::RawPublicKeyRecording);
    let (client, server_outcome) = run(&sc, pin(&k));
    assert_eq!(client.handshake, HandshakeResult::Completed, "{client:?}");
    assert_eq!(client.trust, "ssh_host_key_pinned_fingerprint");
    assert_eq!(server_outcome, HandshakeOutcome::Completed);
    let (fp, decision) = judged(&client.ssh_identity);
    assert_eq!(fp, Sha256Fingerprint::of_blob(&k.blob));
    assert!(decision.is_trusted());
}

#[test]
fn known_hosts_accepts_the_listed_key_and_names_the_line() {
    let k = key();
    let other = key();
    let sc = server(host(&k));
    let text = format!(
        "# rotation: old and new keys both listed\n{}{}",
        entry("[localhost]:4433", &other),
        entry("[localhost]:4433", &k)
    );
    let (client, _) = run(&sc, known_hosts(&text));
    assert_eq!(client.handshake, HandshakeResult::Completed, "{client:?}");
    assert_eq!(client.trust, "ssh_host_key_known_hosts");
    let (_, decision) = judged(&client.ssh_identity);
    assert_eq!(
        decision,
        TrustDecision::Trusted {
            source: tatami_keys::trust::TrustSource::KnownHosts { line: 3 }
        }
    );
}

fn refused(sc: &DiagServerConfig, trust: ClientTrust) -> UntrustedReason {
    let (client, server_outcome) = run(sc, trust);
    let HandshakeResult::Failed { reason } = &client.handshake else {
        panic!("expected failure, got {client:?}");
    };
    assert!(reason.contains("SSH host key not trusted"), "{reason}");
    assert_ne!(server_outcome, HandshakeOutcome::Completed);
    match judged(&client.ssh_identity).1 {
        TrustDecision::Untrusted { reason } => reason,
        t => panic!("expected untrusted, got {t:?}"),
    }
}

#[test]
fn changed_revoked_unknown_and_wrong_port_fail() {
    let k = key();
    let other = key();
    let sc = server(host(&k));
    assert_eq!(
        refused(&sc, pin(&other)),
        UntrustedReason::FingerprintMismatch
    );
    assert_eq!(
        refused(&sc, known_hosts(&entry("[localhost]:4433", &other))),
        UntrustedReason::KeyChanged { line: 1 }
    );
    assert_eq!(
        refused(
            &sc,
            known_hosts(&format!(
                "{}@revoked * ssh-ed25519 {}\n",
                entry("[localhost]:4433", &k),
                Base64::encode_string(&k.blob)
            ))
        ),
        UntrustedReason::Revoked { line: 2 }
    );
    // Port 22 entry does not cover UDP 4433.
    assert_eq!(
        refused(&sc, known_hosts(&entry("localhost", &k))),
        UntrustedReason::UnknownHost
    );
    assert_eq!(
        refused(
            &sc,
            known_hosts(&entry("[localhost]:4433,![localhost]:*", &k))
        ),
        UntrustedReason::UnknownHost
    );
}

#[test]
fn certificate_peer_is_refused_by_ssh_trust() {
    // Same key, but presented inside an X.509 certificate.
    let k = key();
    let sc = server(k.test.clone());
    assert_eq!(sc.identity_mode, ServerIdentityMode::Certificate);
    let (client, server_outcome) = run(&sc, pin(&k));
    assert!(
        matches!(client.handshake, HandshakeResult::Failed { .. }),
        "{client:?}"
    );
    assert_ne!(server_outcome, HandshakeOutcome::Completed);
    assert!(
        !client
            .ssh_identity
            .as_ref()
            .is_some_and(SshIdentityCheck::is_trusted),
        "{:?}",
        client.ssh_identity
    );
}

#[test]
fn x509_client_is_refused_by_a_host_key_server() {
    let k = key();
    let sc = server(host(&k));
    let (client, server_outcome) = run(
        &sc,
        ClientTrust::PinnedCertificateSha256(k.test.certificate_sha256_fingerprint()),
    );
    assert!(
        matches!(client.handshake, HandshakeResult::Failed { .. }),
        "{client:?}"
    );
    assert_ne!(server_outcome, HandshakeOutcome::Completed);
    assert!(client.ssh_identity.is_none());
}

#[test]
fn host_key_cannot_be_presented_as_a_certificate() {
    let k = key();
    let mut sc = server(host(&k));
    sc.identity_mode = ServerIdentityMode::Certificate;
    assert!(matches!(sc.validate(), Err(ConfigError::IdentityMode(_))));
}

#[test]
fn trusted_key_with_a_foreign_signature_fails() {
    // The server advertises key B (trusted by the client) but signs
    // CertificateVerify with key A. The trust decision says "trusted";
    // the provider's signature check must still fail the handshake.
    let a = key();
    let b = key();
    let signer_a = host(&a).signing_key();
    let certified = Arc::new(rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(
            b.test.subject_public_key_info_der().to_vec(),
        )],
        signer_a,
    ));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified),
        ));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let server_crypto = Arc::new(QuicServerConfig::try_from(tls).unwrap());

    let slot = identity_slot();
    let client_crypto = client_crypto_recording(&pin(&b), &[ALPN.to_vec()], slot.clone()).unwrap();
    let hs = raw_handshake(
        client_crypto,
        server_crypto,
        "localhost",
        Duration::from_secs(5),
        1_000,
    )
    .unwrap();
    assert!(hs.client_result.is_err(), "client must not complete");
    let check = slot.lock().unwrap().clone();
    let (fp, decision) = judged(&check);
    assert_eq!(fp, Sha256Fingerprint::of_blob(&b.blob));
    assert!(decision.is_trusted(), "the key itself matched the pin");
}
