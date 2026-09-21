//! Sans-I/O handshake tests: a `ServerCore` and a `ClientCore` exchange
//! datagrams through in-memory queues under a virtual clock. No sockets.
//!
//! Cases: matching identity/ALPN completes on both sides with consistent
//! offered vs negotiated fields; a client pinning the wrong certificate
//! fails with a certificate error on both sides; an ALPN mismatch fails
//! with the `no_application_protocol` alert; a client whose datagrams are
//! all dropped times out at its deadline; the `RootCertificate` trust path
//! works with an issued certificate; and no datagram in any direction ever
//! contains an SSH identification.

#![cfg(feature = "quinn-backend")]

use std::net::SocketAddr;
use std::time::Duration;

use tatami_quic::diag::client::{DiagClientConfig, ExporterProbe, HandshakeResult};
use tatami_quic::diag::identity::{CertificateSha256, TestIdentity, TestRoot};
use tatami_quic::diag::inmem::{Direction, Pair, run_client_into_blackhole};
use tatami_quic::diag::server::{
    CloseReason, DiagServerConfig, HandshakeOutcome, ValidationMethod,
};
use tatami_quic::diag::tls::ClientTrust;
use tatami_quic::diag::{ConfigError, QUIC_VERSION_1};

const ALPN: &[u8] = b"tatami-diag/0";

fn server_addr() -> SocketAddr {
    "127.0.0.1:4433".parse().unwrap()
}

fn client_addr() -> SocketAddr {
    "127.0.0.1:50000".parse().unwrap()
}

fn identity() -> TestIdentity {
    TestIdentity::generate_ed25519(&["localhost".to_string(), "127.0.0.1".to_string()]).unwrap()
}

fn server_config(identity: TestIdentity, alpn: &[u8]) -> DiagServerConfig {
    let mut c = DiagServerConfig::new(identity, vec![alpn.to_vec()]);
    c.bind = server_addr();
    c.handshake_timeout = Duration::from_secs(5);
    c
}

fn client_config(trust: ClientTrust, alpn: &[u8]) -> DiagClientConfig {
    let mut c = DiagClientConfig::new(server_addr(), "localhost", vec![alpn.to_vec()], trust);
    c.handshake_timeout = Duration::from_secs(5);
    c.exporter = Some(ExporterProbe::default());
    c
}

fn assert_no_ssh_bytes(wire: &[tatami_quic::diag::inmem::Captured]) {
    assert!(!wire.is_empty());
    for c in wire {
        assert!(
            !c.payload.windows(4).any(|w| w == b"SSH-"),
            "datagram {:?} contains an SSH identification prefix",
            c.direction
        );
    }
}

#[test]
fn matching_identity_and_alpn_completes_on_both_sides() {
    let id = identity();
    let pin = id.certificate_sha256_fingerprint();
    let sc = server_config(id, ALPN);
    let cc = client_config(ClientTrust::PinnedCertificateSha256(pin), ALPN);
    let mut pair = Pair::new(&sc, &cc, client_addr()).unwrap();
    assert!(pair.run(10_000), "client did not finish");
    let (client, observations, wire) = pair.finish_client();

    assert_eq!(client.handshake, HandshakeResult::Completed, "{client:?}");
    assert_eq!(client.negotiated_alpn.as_deref(), Some(ALPN));
    assert_eq!(client.offered_alpn, vec![ALPN.to_vec()]);
    assert!(client.sni_sent);
    assert_eq!(client.quic_version, QUIC_VERSION_1);
    assert!(!client.zero_rtt_attempted);
    let exporter = client.exporter.expect("probe requested");
    assert!(exporter.available);
    assert_eq!(exporter.len, 32);
    assert!(
        client.close_reason.contains("application code 0"),
        "server should have closed first: {}",
        client.close_reason
    );

    assert_eq!(observations.len(), 1, "{observations:?}");
    let o = &observations[0];
    assert_eq!(o.outcome, HandshakeOutcome::Completed);
    assert_eq!(o.close, CloseReason::LocalAfterHandshake);
    assert_eq!(o.peer, client_addr());
    assert!(!o.peer_address_validated, "no Retry: source is unvalidated");
    assert!(o.may_retry);
    assert!(!o.retry_sent);
    assert_eq!(o.validation_method, ValidationMethod::None);
    assert_eq!(o.quic_version, QUIC_VERSION_1);
    assert_eq!(o.negotiated_alpn.as_deref(), Some(ALPN));
    assert_eq!(o.sni.as_deref(), Some("localhost"));
    let offered = o.offered.as_ref().expect("ClientHello recorded");
    assert_eq!(offered.alpn.as_deref(), Some(&[ALPN.to_vec()][..]));
    assert_eq!(offered.server_name.as_deref(), Some("localhost"));
    assert!(!offered.cipher_suites.is_empty());
    assert!(
        offered
            .signature_schemes
            .iter()
            .any(|s| s.contains("ED25519")),
        "{offered:?}"
    );
    assert_eq!(offered.hellos_seen, 1);
    assert_eq!(o.unexpected_streams, 0);
    assert_eq!(o.unexpected_datagrams, 0);
    assert!(!o.zero_rtt_attempted);
    assert!(
        (8..=20).contains(&o.orig_dst_cid.len()),
        "RFC 9000 §7.2 initial DCID length: {}",
        o.orig_dst_cid.len()
    );

    assert_no_ssh_bytes(&wire);
    assert!(wire.iter().any(|c| c.direction == Direction::ToClient));
}

#[test]
fn wrong_pin_fails_with_certificate_error_on_both_sides() {
    let id = identity();
    let other = identity();
    let sc = server_config(id, ALPN);
    let cc = client_config(
        ClientTrust::PinnedCertificateSha256(other.certificate_sha256_fingerprint()),
        ALPN,
    );
    let mut pair = Pair::new(&sc, &cc, client_addr()).unwrap();
    assert!(pair.run(10_000));
    let (client, observations, wire) = pair.finish_client();

    let HandshakeResult::Failed { reason } = &client.handshake else {
        panic!("expected failure, got {:?}", client.handshake);
    };
    assert!(
        reason.contains("invalid peer certificate")
            && reason.contains("does not match the configured SHA-256 pin"),
        "{reason}"
    );
    assert!(client.negotiated_alpn.is_none());
    assert!(client.exporter.is_none(), "no probe on a failed handshake");

    assert_eq!(observations.len(), 1);
    let o = &observations[0];
    let HandshakeOutcome::Failed { reason } = &o.outcome else {
        panic!("{o:?}");
    };
    // The client aborts with a TLS alert carried in CONNECTION_CLOSE; the
    // server sees the crypto error code (0x100 + alert) and reason phrase.
    assert!(
        reason.contains("cryptographic handshake failed"),
        "{reason}"
    );
    assert!(reason.contains("SHA-256 pin"), "{reason}");
    assert_eq!(o.close, CloseReason::ConnectionLost);
    assert!(o.offered.is_some(), "ClientHello was still recorded");
    assert!(
        o.negotiated_alpn.is_some(),
        "ALPN is selected while processing the ClientHello, before the client rejects the certificate"
    );
    assert_no_ssh_bytes(&wire);
}

#[test]
fn alpn_mismatch_fails_with_no_application_protocol() {
    let id = identity();
    let pin = id.certificate_sha256_fingerprint();
    let sc = server_config(id, b"tatami-diag/1");
    let cc = client_config(ClientTrust::PinnedCertificateSha256(pin), b"tatami-diag/0");
    let mut pair = Pair::new(&sc, &cc, client_addr()).unwrap();
    assert!(pair.run(10_000));
    let (client, observations, wire) = pair.finish_client();

    let HandshakeResult::Failed { reason } = &client.handshake else {
        panic!("expected failure, got {:?}", client.handshake);
    };
    // Alert no_application_protocol is 120; quinn renders crypto errors as
    // "the cryptographic handshake failed: error 120" and forwards the
    // server's reason phrase.
    assert!(reason.contains("error 120"), "{reason}");
    assert!(
        reason.contains("peer doesn't support any known protocol"),
        "{reason}"
    );

    // Finding: the ClientHello in the first Initial is processed inside
    // `Endpoint::accept`, so an ALPN mismatch fails there with an Initial
    // CONNECTION_CLOSE and no `Connection` ever exists on the server. The
    // resolver hook still ran, so the offered list is recorded.
    let o = &observations[0];
    let HandshakeOutcome::AcceptFailed { reason } = &o.outcome else {
        panic!("{o:?}");
    };
    assert!(reason.contains("error 120"), "{reason}");
    assert!(
        reason.contains("peer doesn't support any known protocol"),
        "{reason}"
    );
    assert_eq!(o.close, CloseReason::NotEstablished);
    let offered = o.offered.as_ref().unwrap();
    assert_eq!(
        offered.alpn.as_deref(),
        Some(&[b"tatami-diag/0".to_vec()][..])
    );
    assert!(o.negotiated_alpn.is_none(), "nothing was negotiated");
    assert!(o.sni.is_none(), "HandshakeData is only read on Connected");
    assert_eq!(o.elapsed, Duration::ZERO);
    assert_no_ssh_bytes(&wire);
}

#[test]
fn client_into_blackhole_times_out_at_its_deadline() {
    let id = identity();
    let mut cc = client_config(
        ClientTrust::PinnedCertificateSha256(id.certificate_sha256_fingerprint()),
        ALPN,
    );
    cc.handshake_timeout = Duration::from_millis(1500);
    let (outcome, virtual_elapsed) = run_client_into_blackhole(&cc, 10_000).unwrap();
    assert_eq!(outcome.handshake, HandshakeResult::TimedOut, "{outcome:?}");
    assert_eq!(outcome.close_reason, "local_close_handshake_deadline");
    assert!(
        virtual_elapsed >= Duration::from_millis(1500)
            && virtual_elapsed < Duration::from_millis(1600),
        "deadline fired at {virtual_elapsed:?}"
    );
    assert!(
        outcome.datagrams_sent >= 2,
        "Initial should have been retransmitted: {}",
        outcome.datagrams_sent
    );
    assert!(outcome.exporter.is_none());
}

#[test]
fn root_certificate_trust_verifies_an_issued_certificate() {
    let root = TestRoot::generate_ed25519("tatami test root").unwrap();
    let id = TestIdentity::generate_ed25519_issued_by(&["localhost".to_string()], &root).unwrap();
    let sc = server_config(id, ALPN);
    let cc = client_config(
        ClientTrust::RootCertificate(root.certificate_der().to_vec()),
        ALPN,
    );
    let mut pair = Pair::new(&sc, &cc, client_addr()).unwrap();
    assert!(pair.run(10_000));
    let (client, observations, _) = pair.finish_client();
    assert_eq!(client.handshake, HandshakeResult::Completed, "{client:?}");
    assert_eq!(client.trust, "root_certificate");
    assert_eq!(observations[0].outcome, HandshakeOutcome::Completed);

    // Same root, different server name: webpki rejects the name.
    let id2 = TestIdentity::generate_ed25519_issued_by(&["localhost".to_string()], &root).unwrap();
    let sc2 = server_config(id2, ALPN);
    let mut cc2 = cc.clone();
    cc2.server_name = "other.example".to_string();
    let mut pair = Pair::new(&sc2, &cc2, client_addr()).unwrap();
    assert!(pair.run(10_000));
    let (client, _, _) = pair.finish_client();
    let HandshakeResult::Failed { reason } = &client.handshake else {
        panic!("{client:?}");
    };
    assert!(reason.contains("not valid for name"), "{reason}");

    // A self-signed identity does not chain to that root.
    let sc3 = server_config(identity(), ALPN);
    let mut pair = Pair::new(&sc3, &cc, client_addr()).unwrap();
    assert!(pair.run(10_000));
    let (client, _, _) = pair.finish_client();
    let HandshakeResult::Failed { reason } = &client.handshake else {
        panic!("{client:?}");
    };
    assert!(reason.contains("UnknownIssuer"), "{reason}");
}

#[test]
fn empty_alpn_is_rejected_before_any_io() {
    let id = identity();
    let pin = id.certificate_sha256_fingerprint();
    let sc = DiagServerConfig::new(id, Vec::new());
    assert!(matches!(sc.validate(), Err(ConfigError::Alpn(_))));
    let cc = DiagClientConfig::new(
        server_addr(),
        "localhost",
        Vec::new(),
        ClientTrust::PinnedCertificateSha256(pin),
    );
    assert!(matches!(cc.validate(), Err(ConfigError::Alpn(_))));
    let bad_pin: Result<CertificateSha256, _> = "SHA256:short".parse();
    assert!(bad_pin.is_err());
}
