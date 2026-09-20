//! Loopback tests for the TCP probe adapter.
//!
//! Each test binds an ephemeral loopback listener and runs a deterministic
//! fixture peer on a thread. The peer is not an SSH server: it writes
//! precomputed initial packets, optionally in fragments, and can wait for
//! client bytes or simply go quiet. Readiness is synchronised by the
//! listener being bound before the client connects; no fixed sleeps are used
//! except to force fragmentation boundaries.

#![cfg(feature = "std")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use tatami_tcp::io::{IoConfig, RunEnd, connect, run_probe};
use tatami_tcp::packet::encode_initial_packet;
use tatami_tcp::probe::{ProbeConfig, ProbeEnd, ProbeError, ProbeEvent, Stage};
use tatami_wire::Writer;

fn kexinit_payload() -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = Writer::new(&mut buf);
    w.write_u8(20).unwrap();
    w.write_bytes(&[0x42; 16]).unwrap();
    w.write_string(b"curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com")
        .unwrap();
    w.write_string(b"ssh-ed25519,rsa-sha2-512").unwrap();
    w.write_string(b"chacha20-poly1305@openssh.com,aes128-ctr")
        .unwrap();
    w.write_string(b"aes256-gcm@openssh.com").unwrap();
    w.write_string(b"hmac-sha2-256").unwrap();
    w.write_string(b"hmac-sha2-512,hmac-sha2-256").unwrap();
    w.write_string(b"none,zlib@openssh.com").unwrap();
    w.write_string(b"none").unwrap();
    w.write_string(b"").unwrap();
    w.write_string(b"").unwrap();
    w.write_bool(false).unwrap();
    w.write_u32(0).unwrap();
    w.written().to_vec()
}

fn packet(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; payload.len() + 64];
    let n = encode_initial_packet(payload, 0x5a, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Spawns a peer that runs `script` on the accepted connection.
fn peer<F>(script: F) -> (u16, JoinHandle<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        script(stream);
    });
    (port, handle)
}

fn io_config(read_timeout_ms: u64) -> IoConfig {
    IoConfig {
        connect_timeout: Duration::from_secs(5),
        read_timeout: Duration::from_millis(read_timeout_ms),
        max_connect_attempts: 2,
        read_chunk: 7, // deliberately tiny to exercise boundaries
    }
}

fn run(port: u16, io: &IoConfig) -> tatami_tcp::io::ProbeRun {
    let stream = connect("127.0.0.1", port, io).expect("connect");
    run_probe(stream, ProbeConfig::default(), io).expect("run")
}

fn read_client_ident(stream: &mut TcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n") {
        stream.read_exact(&mut b).unwrap();
        got.push(b[0]);
    }
    got
}

#[test]
fn fragmented_banner_and_proposal() {
    let (port, peer) = peer(|mut s| {
        let mut wire =
            b"Welcome to fixture\r\nsecond line\nSSH-2.0-Fixture_1.0 test peer\r\n".to_vec();
        wire.extend(packet(&[2, 0, 0, 0, 3, 1, 2, 3])); // IGNORE
        wire.extend(packet(&[
            4, 1, 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', 0, 0, 0, 2, b'e', b'n',
        ]));
        wire.extend(packet(&kexinit_payload()));
        // Write in awkward fragments with pauses so TCP delivers them apart.
        for chunk in wire.chunks(5) {
            s.write_all(chunk).unwrap();
            s.flush().unwrap();
            thread::sleep(Duration::from_millis(2));
        }
        // Hold the connection open briefly; the client should finish on its own.
        let _ = read_client_ident(&mut s);
    });

    let run = run(port, &io_config(5_000));
    peer.join().unwrap();

    assert_eq!(run.client_identification, b"SSH-2.0-tatami_0.1.0\r\n");
    assert_eq!(run.peer.port(), port);
    let mut events = run.events.iter();
    assert!(matches!(
        events.next(),
        Some(ProbeEvent::PreludeLine { line, .. }) if line == b"Welcome to fixture"
    ));
    assert!(matches!(
        events.next(),
        Some(ProbeEvent::PreludeLine { line, .. }) if line == b"second line"
    ));
    match events.next() {
        Some(ProbeEvent::ServerIdentification(i)) => {
            assert_eq!(i.software_version, "Fixture_1.0");
            assert_eq!(i.comments.as_deref(), Some(&b"test peer"[..]));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(events.next(), Some(&ProbeEvent::Ignored { data_len: 3 }));
    assert!(matches!(
        events.next(),
        Some(ProbeEvent::Debug { always_display: true, message, .. }) if message == b"hello"
    ));
    assert!(events.next().is_none());

    assert!(run.end.is_complete(), "{}", run.end.label());
    let RunEnd::Probe(ProbeEnd::Proposal(p)) = &run.end else {
        panic!("{:?}", run.end)
    };
    assert_eq!(
        p.kexinit.kex_algorithms,
        [
            "curve25519-sha256",
            "ext-info-s",
            "kex-strict-s-v00@openssh.com"
        ]
    );
    assert_eq!(
        p.kexinit.encryption_client_to_server,
        ["chacha20-poly1305@openssh.com", "aes128-ctr"]
    );
    assert_eq!(
        p.kexinit.encryption_server_to_client,
        ["aes256-gcm@openssh.com"]
    );
    assert_eq!(
        p.kexinit.mac_server_to_client,
        ["hmac-sha2-512", "hmac-sha2-256"]
    );
    assert!(p.anomalies.is_empty());
}

#[test]
fn peer_waits_for_client_identification_first() {
    let (port, peer) = peer(|mut s| {
        let ident = read_client_ident(&mut s);
        assert_eq!(ident, b"SSH-2.0-tatami_0.1.0\r\n");
        s.write_all(b"SSH-2.0-Waiter_1\r\n").unwrap();
        s.write_all(&packet(&kexinit_payload())).unwrap();
    });
    let run = run(port, &io_config(5_000));
    peer.join().unwrap();
    assert!(run.end.is_complete(), "{}", run.end.label());
}

#[test]
fn peer_waits_for_client_kexinit_yields_partial_on_deadline() {
    let (port, peer) = peer(|mut s| {
        let _ = read_client_ident(&mut s);
        s.write_all(b"SSH-2.0-Silent_1\r\n").unwrap();
        // Never sends KEXINIT; wait for the client to give up and close.
        let mut sink = [0u8; 16];
        let _ = s.read(&mut sink);
    });
    let run = run(port, &io_config(300));
    peer.join().unwrap();

    assert!(matches!(
        run.events.as_slice(),
        [ProbeEvent::ServerIdentification(i)] if i.software_version == "Silent_1"
    ));
    match &run.end {
        RunEnd::TimedOut {
            stage: Stage::InitialPackets,
            pending_bytes: 0,
        } => {}
        other => panic!("{other:?}"),
    }
    assert!(!run.end.is_complete());
    assert!(run.elapsed >= Duration::from_millis(250));
    assert!(run.elapsed < Duration::from_secs(3));
}

#[test]
fn silent_peer_times_out_before_identification() {
    let (port, peer) = peer(|mut s| {
        let mut sink = [0u8; 64];
        let _ = s.read(&mut sink);
        let _ = s.read(&mut sink);
    });
    let run = run(port, &io_config(200));
    peer.join().unwrap();
    assert!(run.events.is_empty());
    assert!(matches!(
        run.end,
        RunEnd::TimedOut {
            stage: Stage::Identification,
            ..
        }
    ));
}

#[test]
fn disconnect_after_identification() {
    let (port, peer) = peer(|mut s| {
        let _ = read_client_ident(&mut s);
        s.write_all(b"SSH-2.0-Refuser\r\n").unwrap();
        let mut p = vec![1, 0, 0, 0, 12];
        p.extend_from_slice(&[0, 0, 0, 8]);
        p.extend_from_slice(b"too many");
        p.extend_from_slice(&[0, 0, 0, 0]);
        s.write_all(&packet(&p)).unwrap();
    });
    let run = run(port, &io_config(5_000));
    peer.join().unwrap();
    match &run.end {
        RunEnd::Probe(ProbeEnd::Disconnected {
            reason_code: 12,
            description,
            ..
        }) => assert_eq!(description, b"too many"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn eof_mid_packet_is_reported_as_truncated() {
    let (port, peer) = peer(|mut s| {
        s.write_all(b"SSH-2.0-Cutoff\r\n").unwrap();
        let k = packet(&kexinit_payload());
        s.write_all(&k[..k.len() / 2]).unwrap();
        // Consume the client identification so close() sends FIN, not RST.
        let _ = read_client_ident(&mut s);
    });
    let run = run(port, &io_config(5_000));
    peer.join().unwrap();
    match &run.end {
        RunEnd::Probe(ProbeEnd::Eof {
            stage: Stage::InitialPackets,
            pending_bytes,
        }) => assert!(*pending_bytes > 0),
        other => panic!("{other:?}"),
    }
}

#[test]
fn eof_before_identification() {
    let (port, peer) = peer(|mut s| {
        s.write_all(b"partial line without newline").unwrap();
        let _ = read_client_ident(&mut s);
    });
    let run = run(port, &io_config(5_000));
    peer.join().unwrap();
    assert!(matches!(
        run.end,
        RunEnd::Probe(ProbeEnd::Eof {
            stage: Stage::Identification,
            pending_bytes: 28
        })
    ));
}

#[test]
fn packet_budget_exhausted_by_ignore_flood() {
    let (port, peer) = peer(|mut s| {
        s.write_all(b"SSH-2.0-Flood\r\n").unwrap();
        let ig = packet(&[2, 0, 0, 0, 0]);
        for _ in 0..40 {
            if s.write_all(&ig).is_err() {
                break;
            }
        }
    });
    let run = run(port, &io_config(5_000));
    peer.join().unwrap();
    let limit = ProbeConfig::default().max_packets_before_kexinit;
    assert_eq!(
        run.events
            .iter()
            .filter(|e| matches!(e, ProbeEvent::Ignored { .. }))
            .count(),
        limit
    );
    assert!(matches!(
        run.end,
        RunEnd::Probe(ProbeEnd::Error(ProbeError::PacketBudgetExceeded { .. }))
    ));
}

#[test]
fn oversized_length_claim_is_rejected_immediately() {
    let (port, peer) = peer(|mut s| {
        s.write_all(b"SSH-2.0-Huge\r\n\xff\xff\xff\xf0").unwrap();
        let mut sink = [0u8; 16];
        let _ = s.read(&mut sink);
    });
    let run = run(port, &io_config(5_000));
    peer.join().unwrap();
    assert!(matches!(
        run.end,
        RunEnd::Probe(ProbeEnd::Error(ProbeError::Packet(_)))
    ));
}

#[test]
fn ssh1_only_peer_is_unsupported() {
    let (port, peer) = peer(|mut s| {
        s.write_all(b"SSH-1.5-Ancient\r\n").unwrap();
        let _ = read_client_ident(&mut s);
    });
    let run = run(port, &io_config(5_000));
    peer.join().unwrap();
    assert!(matches!(
        run.end,
        RunEnd::Probe(ProbeEnd::Error(ProbeError::Ident(
            tatami_tcp::ident::IdentError::UnsupportedVersion
        )))
    ));
}

#[test]
fn connect_refused_is_reported() {
    // Bind then drop to obtain a port that is (very likely) closed.
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = connect("127.0.0.1", port, &io_config(1_000)).unwrap_err();
    assert!(matches!(err, tatami_tcp::io::ConnectError::AllAttemptsFailed(v) if v.len() == 1));
}
