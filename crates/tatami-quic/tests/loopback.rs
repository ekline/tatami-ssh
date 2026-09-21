//! Loopback UDP tests: `DiagServer` on `127.0.0.1:0` in a thread, the
//! blocking client against it. Nothing external is contacted.
//!
//! Evidence collected: matching identity/ALPN completes on both sides and
//! the exporter probe is available; a client pinning another certificate
//! fails with a certificate error and the server records the failure; an
//! ALPN mismatch fails with the `no_application_protocol` alert (120); a
//! client aimed at a port nobody listens on times out at its deadline;
//! `require_validation` produces a Retry, and the accepted connection
//! reports `retry_sent` and `peer_address_validated`; a `StopHandle` ends a
//! run without another client connecting.

#![cfg(feature = "quinn-backend")]

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use tatami_quic::diag::client::{DiagClientConfig, ExporterProbe, HandshakeResult, run};
use tatami_quic::diag::identity::TestIdentity;
use tatami_quic::diag::server::{
    CloseReason, DiagServer, DiagServerConfig, HandshakeObservation, HandshakeOutcome, ServerEvent,
    StopReason, Summary, ValidationMethod,
};
use tatami_quic::diag::tls::ClientTrust;

const ALPN: &[u8] = b"tatami-diag/0";

fn identity() -> TestIdentity {
    TestIdentity::generate_ed25519(&["localhost".to_string(), "127.0.0.1".to_string()]).unwrap()
}

fn server_config(identity: TestIdentity, alpn: &[u8]) -> DiagServerConfig {
    let mut c = DiagServerConfig::new(identity, vec![alpn.to_vec()]);
    c.bind = "127.0.0.1:0".parse().unwrap();
    c.handshake_timeout = Duration::from_secs(3);
    c.shutdown_grace = Duration::from_secs(2);
    c
}

struct Running {
    addr: SocketAddr,
    events: Arc<Mutex<Vec<ServerEvent>>>,
    handle: thread::JoinHandle<Summary>,
    stop: tatami_quic::diag::server::StopHandle,
}

fn start(config: DiagServerConfig) -> Running {
    let server = DiagServer::bind(config).unwrap();
    let addr = server.local_addr();
    let stop = server.stop_handle();
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = events.clone();
    let handle = thread::spawn(move || {
        server.run(Box::new(move |e| {
            sink_events.lock().unwrap().push(e);
            Ok(())
        }))
    });
    Running {
        addr,
        events,
        handle,
        stop,
    }
}

impl Running {
    fn finish(self) -> (Summary, Vec<HandshakeObservation>) {
        let summary = self.handle.join().unwrap();
        let events = std::mem::take(&mut *self.events.lock().unwrap());
        assert!(matches!(events.first(), Some(ServerEvent::Started { .. })));
        assert!(matches!(events.last(), Some(ServerEvent::Stopped(_))));
        let observations = events
            .into_iter()
            .filter_map(|e| match e {
                ServerEvent::Connection(o) => Some(*o),
                _ => None,
            })
            .collect();
        (summary, observations)
    }
}

fn client_config(addr: SocketAddr, trust: ClientTrust, alpn: &[u8]) -> DiagClientConfig {
    let mut c = DiagClientConfig::new(addr, "localhost", vec![alpn.to_vec()], trust);
    c.handshake_timeout = Duration::from_secs(3);
    c.exporter = Some(ExporterProbe::default());
    c
}

#[test]
fn matching_handshake_over_loopback() {
    let id = identity();
    let pin = id.certificate_sha256_fingerprint();
    let mut sc = server_config(id, ALPN);
    sc.max_connections = Some(1);
    let running = start(sc);

    let outcome = run(&client_config(
        running.addr,
        ClientTrust::PinnedCertificateSha256(pin),
        ALPN,
    ))
    .unwrap();
    assert_eq!(outcome.handshake, HandshakeResult::Completed, "{outcome:?}");
    assert_eq!(outcome.negotiated_alpn.as_deref(), Some(ALPN));
    assert_eq!(outcome.remote, running.addr);
    assert!(outcome.local.is_some());
    assert!(outcome.exporter.unwrap().available);
    assert!(
        outcome.close_reason.contains("application code 0"),
        "{}",
        outcome.close_reason
    );

    let (summary, observations) = running.finish();
    assert_eq!(summary.reason, StopReason::ConnectionLimitReached);
    assert_eq!(summary.stats.accepted, 1);
    assert_eq!(summary.stats.completed, 1);
    assert_eq!(summary.stats.retries_sent, 0);
    assert_eq!(summary.records_dropped, 0);
    assert_eq!(summary.abandoned, 0);
    assert_eq!(summary.certificate_sha256, pin);
    assert_eq!(observations.len(), 1);
    let o = &observations[0];
    assert_eq!(o.outcome, HandshakeOutcome::Completed);
    assert_eq!(o.close, CloseReason::LocalAfterHandshake);
    assert_eq!(o.peer, outcome.local.unwrap());
    assert!(!o.peer_address_validated);
    assert!(o.may_retry && !o.retry_sent);
    assert_eq!(o.validation_method, ValidationMethod::None);
    assert_eq!(o.negotiated_alpn.as_deref(), Some(ALPN));
    assert_eq!(o.sni.as_deref(), Some("localhost"));
    let offered = o.offered.as_ref().unwrap();
    assert_eq!(offered.alpn.as_deref(), Some(&[ALPN.to_vec()][..]));
    assert_eq!(offered.server_name.as_deref(), Some("localhost"));
    assert!(o.elapsed < Duration::from_secs(3));
}

#[test]
fn wrong_identity_over_loopback() {
    let id = identity();
    let other = identity();
    let mut sc = server_config(id, ALPN);
    sc.max_connections = Some(1);
    let running = start(sc);
    let outcome = run(&client_config(
        running.addr,
        ClientTrust::PinnedCertificateSha256(other.certificate_sha256_fingerprint()),
        ALPN,
    ))
    .unwrap();
    let HandshakeResult::Failed { reason } = &outcome.handshake else {
        panic!("{outcome:?}");
    };
    assert!(
        reason.contains("does not match the configured SHA-256 pin"),
        "{reason}"
    );
    assert!(outcome.exporter.is_none());
    let (summary, observations) = running.finish();
    assert_eq!(summary.stats.failed, 1);
    assert_eq!(summary.stats.completed, 0);
    let HandshakeOutcome::Failed { reason } = &observations[0].outcome else {
        panic!("{observations:?}");
    };
    assert!(
        reason.contains("cryptographic handshake failed"),
        "{reason}"
    );
    assert_eq!(observations[0].close, CloseReason::ConnectionLost);
}

#[test]
fn wrong_alpn_over_loopback() {
    let id = identity();
    let pin = id.certificate_sha256_fingerprint();
    let mut sc = server_config(id, b"tatami-diag/1");
    sc.max_connections = Some(1);
    let running = start(sc);
    let outcome = run(&client_config(
        running.addr,
        ClientTrust::PinnedCertificateSha256(pin),
        b"tatami-diag/0",
    ))
    .unwrap();
    let HandshakeResult::Failed { reason } = &outcome.handshake else {
        panic!("{outcome:?}");
    };
    assert!(reason.contains("error 120"), "{reason}");
    let (summary, observations) = running.finish();
    assert_eq!(summary.stats.failed, 1);
    assert_eq!(
        summary.stats.observed, 0,
        "accept failed; no connection was driven"
    );
    let HandshakeOutcome::AcceptFailed { reason } = &observations[0].outcome else {
        panic!("{observations:?}");
    };
    assert!(reason.contains("error 120"), "{reason}");
    assert_eq!(
        observations[0]
            .offered
            .as_ref()
            .and_then(|h| h.alpn.clone()),
        Some(vec![b"tatami-diag/0".to_vec()])
    );
}

#[test]
fn no_listener_times_out_within_the_deadline() {
    // Reserve a port and close it so nothing answers.
    let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = holder.local_addr().unwrap();
    drop(holder);
    let id = identity();
    let mut cc = client_config(
        addr,
        ClientTrust::PinnedCertificateSha256(id.certificate_sha256_fingerprint()),
        ALPN,
    );
    cc.handshake_timeout = Duration::from_millis(700);
    let t = Instant::now();
    let outcome = run(&cc).unwrap();
    let took = t.elapsed();
    assert_eq!(outcome.handshake, HandshakeResult::TimedOut, "{outcome:?}");
    assert!(
        took >= Duration::from_millis(650) && took < Duration::from_secs(3),
        "took {took:?}"
    );
    assert_eq!(outcome.close_reason, "local_close_handshake_deadline");
    assert!(outcome.datagrams_received == 0);
    assert!(outcome.datagrams_sent >= 1);
}

#[test]
fn require_validation_sends_retry_and_reports_validated_peer() {
    let id = identity();
    let pin = id.certificate_sha256_fingerprint();
    let mut sc = server_config(id, ALPN);
    sc.require_validation = true;
    sc.max_connections = Some(1);
    let running = start(sc);
    let outcome = run(&client_config(
        running.addr,
        ClientTrust::PinnedCertificateSha256(pin),
        ALPN,
    ))
    .unwrap();
    assert_eq!(outcome.handshake, HandshakeResult::Completed, "{outcome:?}");
    let (summary, observations) = running.finish();
    assert_eq!(summary.stats.retries_sent, 1);
    assert_eq!(
        summary.stats.incoming, 2,
        "first Initial (retried) + token-bearing Initial"
    );
    assert_eq!(summary.stats.accepted, 1);
    let o = &observations[0];
    assert_eq!(o.outcome, HandshakeOutcome::Completed);
    assert!(o.peer_address_validated);
    assert!(o.retry_sent);
    assert!(!o.may_retry);
    assert_eq!(o.validation_method, ValidationMethod::RetryToken);
}

#[test]
fn stop_handle_ends_an_unbounded_run() {
    let sc = server_config(identity(), ALPN);
    let running = start(sc);
    thread::sleep(Duration::from_millis(100));
    running.stop.stop();
    let t = Instant::now();
    let (summary, observations) = running.finish();
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(summary.reason, StopReason::StopRequested);
    assert!(observations.is_empty());
    assert_eq!(summary.stats.incoming, 0);
}

#[test]
fn finite_run_with_no_clients() {
    let mut sc = server_config(identity(), ALPN);
    sc.run_for = Some(Duration::from_millis(200));
    let running = start(sc);
    let (summary, observations) = running.finish();
    assert_eq!(summary.reason, StopReason::RunDurationElapsed);
    assert!(observations.is_empty());
    assert!(summary.elapsed >= Duration::from_millis(200));
}
