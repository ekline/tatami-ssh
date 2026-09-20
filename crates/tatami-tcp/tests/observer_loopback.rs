//! Loopback tests for the diagnostic listener.
//!
//! Each test binds port 0 on loopback, runs the listener on a thread with a
//! collecting sink, drives fixture clients, and inspects the delivered
//! events. Readiness is guaranteed by binding before spawning; the bound
//! address is taken from the listener, never guessed.

#![cfg(feature = "std")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tatami_tcp::initial::{InitialError, SkippedMessage};
use tatami_tcp::io::{
    IoConfig, Listener, ListenerConfig, ListenerEvent, Observation, ObservationEnd, StopHandle,
    StopReason, Summary, connect, run_probe,
};
use tatami_tcp::observer::{ObservationOutcome, ObserverConfig, ObserverStage};
use tatami_tcp::packet::encode_initial_packet;
use tatami_tcp::probe::{ProbeConfig, ProbeEvent};
use tatami_wire::Writer;

type Events = Arc<Mutex<Vec<ListenerEvent>>>;

fn client_kexinit_packet() -> Vec<u8> {
    let mut buf = [0u8; 512];
    let mut w = Writer::new(&mut buf);
    w.write_u8(20).unwrap();
    w.write_bytes(&[0xAB; 16]).unwrap();
    w.write_string(b"curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com")
        .unwrap();
    w.write_string(b"ssh-ed25519,rsa-sha2-256").unwrap();
    w.write_string(b"aes128-ctr").unwrap();
    w.write_string(b"aes256-ctr").unwrap();
    w.write_string(b"hmac-sha2-256").unwrap();
    w.write_string(b"hmac-sha2-512").unwrap();
    w.write_string(b"none").unwrap();
    w.write_string(b"zlib@openssh.com").unwrap();
    w.write_string(b"").unwrap();
    w.write_string(b"").unwrap();
    w.write_bool(false).unwrap();
    w.write_u32(0).unwrap();
    let payload = w.written().to_vec();
    let mut out = vec![0u8; payload.len() + 64];
    let n = encode_initial_packet(&payload, 0x11, &mut out).unwrap();
    out.truncate(n);
    out
}

fn config() -> ListenerConfig {
    ListenerConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        connection_timeout: Duration::from_millis(600),
        shutdown_grace: Duration::from_secs(2),
        poll_interval: Duration::from_millis(10),
        ..ListenerConfig::default()
    }
}

struct Running {
    addr: SocketAddr,
    stop: StopHandle,
    events: Events,
    handle: JoinHandle<Summary>,
}

impl Running {
    fn finish(self) -> (Summary, Vec<ListenerEvent>) {
        let summary = self.handle.join().unwrap();
        let events = std::mem::take(&mut *self.events.lock().unwrap());
        (summary, events)
    }

    fn stop_and_finish(self) -> (Summary, Vec<ListenerEvent>) {
        self.stop.stop();
        self.finish()
    }
}

fn start(config: ListenerConfig) -> Running {
    let listener = Listener::bind(config).expect("bind");
    let addr = listener.local_addr();
    let stop = listener.stop_handle();
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = events.clone();
    let handle = thread::spawn(move || {
        listener.run(Box::new(move |e| {
            sink_events.lock().unwrap().push(e);
            Ok(())
        }))
    });
    Running {
        addr,
        stop,
        events,
        handle,
    }
}

fn observations(events: &[ListenerEvent]) -> Vec<&Observation> {
    events
        .iter()
        .filter_map(|e| match e {
            ListenerEvent::Observation(o) => Some(&**o),
            _ => None,
        })
        .collect()
}

fn read_banner(s: &mut TcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n") {
        s.read_exact(&mut b).unwrap();
        got.push(b[0]);
    }
    got
}

/// Waits until `n` observations have been delivered or the bound elapses.
fn wait_for_observations(events: &Events, n: usize, bound: Duration) {
    let end = Instant::now() + bound;
    while Instant::now() < end {
        if observations(&events.lock().unwrap()).len() >= n {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn reports_actual_port_and_started_event() {
    let r = start(config());
    assert_ne!(r.addr.port(), 0);
    let addr = r.addr;
    let (summary, events) = r.stop_and_finish();
    assert_eq!(summary.bound, addr);
    assert!(matches!(events.first(), Some(ListenerEvent::Started { bound }) if *bound == addr));
    assert!(
        matches!(events.last(), Some(ListenerEvent::Stopped(s)) if s.reason == StopReason::StopRequested)
    );
    assert_eq!(summary.accepted, 0);
}

#[test]
fn banner_is_sent_promptly_to_a_silent_peer_then_times_out() {
    let r = start(config());
    let started = Instant::now();
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let banner = read_banner(&mut s);
    assert_eq!(banner, b"SSH-2.0-tatami_observer_0.1.0\r\n");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "banner not prompt"
    );
    // Say nothing; the observer must close us at its deadline.
    let mut sink = [0u8; 8];
    let n = s.read(&mut sink).unwrap_or(0);
    assert_eq!(n, 0, "peer should see EOF after the deadline");
    wait_for_observations(&r.events, 1, Duration::from_secs(3));
    let (summary, events) = r.stop_and_finish();
    let obs = observations(&events);
    assert_eq!(obs.len(), 1);
    assert!(matches!(obs[0].end, ObservationEnd::TimedOut));
    assert_eq!(obs[0].stage, ObserverStage::ClientIdentification);
    assert!(obs[0].client_identification.is_none());
    assert_eq!(obs[0].bytes_written, 31);
    assert_eq!(obs[0].bytes_read, 0);
    assert!(obs[0].elapsed >= Duration::from_millis(550));
    assert_eq!(summary.observed, 1);
}

#[test]
fn fragmented_client_identification_and_proposal() {
    let r = start(config());
    let mut s = TcpStream::connect(r.addr).unwrap();
    let mut wire = b"SSH-2.0-Fixture_client c1\r\n".to_vec();
    wire.extend(encode_ignore());
    wire.extend(client_kexinit_packet());
    wire.extend(b"trailing-guess-bytes");
    // Trickle everything up to the last few KEXINIT bytes, then send those
    // together with the trailing bytes so the observer sees a coalesced tail.
    let split = wire.len() - 23;
    for chunk in wire[..split].chunks(3) {
        s.write_all(chunk).unwrap();
        s.flush().unwrap();
        thread::sleep(Duration::from_millis(1));
    }
    s.write_all(&wire[split..]).unwrap();
    let _ = read_banner(&mut s);
    wait_for_observations(&r.events, 1, Duration::from_secs(3));
    let (_, events) = r.stop_and_finish();
    let obs = observations(&events);
    assert_eq!(obs.len(), 1);
    let o = obs[0];
    let ident = o.client_identification.as_ref().unwrap();
    assert_eq!(ident.software_version, "Fixture_client");
    assert_eq!(ident.comments.as_deref(), Some(&b"c1"[..]));
    assert_eq!(o.messages, [SkippedMessage::Ignored { data_len: 2 }]);
    let ObservationEnd::Observer(ObservationOutcome::Proposal(p)) = &o.end else {
        panic!("{:?}", o.end)
    };
    assert_eq!(
        p.kexinit.kex_algorithms,
        [
            "curve25519-sha256",
            "ext-info-c",
            "kex-strict-c-v00@openssh.com"
        ]
    );
    assert_eq!(
        p.kexinit.server_host_key_algorithms,
        ["ssh-ed25519", "rsa-sha2-256"]
    );
    assert_eq!(p.kexinit.encryption_client_to_server, ["aes128-ctr"]);
    assert_eq!(p.kexinit.encryption_server_to_client, ["aes256-ctr"]);
    assert!(p.unexamined_bytes <= 20, "{}", p.unexamined_bytes);
    assert_eq!(o.end.code(), "proposal");
    assert!(o.bytes_read as usize <= wire.len());
    assert!(o.bytes_read as usize >= wire.len() - 20);
}

fn encode_ignore() -> Vec<u8> {
    let mut out = [0u8; 32];
    let n = encode_initial_packet(&[2, 0, 0, 0, 2, 7, 7], 0, &mut out).unwrap();
    out[..n].to_vec()
}

#[test]
fn banner_only_mode() {
    let mut c = config();
    c.observer.banner_only = true;
    let r = start(c);
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.write_all(b"SSH-2.0-only\r\n").unwrap();
    s.write_all(&client_kexinit_packet()).unwrap();
    let _ = read_banner(&mut s);
    wait_for_observations(&r.events, 1, Duration::from_secs(3));
    let (_, events) = r.stop_and_finish();
    let o = observations(&events)[0];
    assert!(matches!(
        o.end,
        ObservationEnd::Observer(ObservationOutcome::BannerOnly)
    ));
    assert!(o.proposal.is_none());
    assert_eq!(
        o.client_identification.as_ref().unwrap().software_version,
        "only"
    );
}

#[test]
fn unexpected_input_disconnect_and_eof_outcomes() {
    let r = start(config());

    let mut a = TcpStream::connect(r.addr).unwrap();
    a.write_all(b"HTTP/1.1 nonsense\r\n").unwrap();
    let _ = read_banner(&mut a);

    let mut b = TcpStream::connect(r.addr).unwrap();
    b.write_all(b"SSH-2.0-bye\r\n").unwrap();
    let mut out = [0u8; 64];
    let n = encode_initial_packet(
        &[1, 0, 0, 0, 11, 0, 0, 0, 3, b'b', b'y', b'e', 0, 0, 0, 0],
        0,
        &mut out,
    )
    .unwrap();
    b.write_all(&out[..n]).unwrap();
    let _ = read_banner(&mut b);

    let mut c = TcpStream::connect(r.addr).unwrap();
    c.write_all(b"SSH-2.0-cut\r\n\x00\x00\x00").unwrap();
    let _ = read_banner(&mut c);
    drop(c);

    wait_for_observations(&r.events, 3, Duration::from_secs(3));
    let (summary, events) = r.stop_and_finish();
    let obs = observations(&events);
    assert_eq!(obs.len(), 3);
    let by_code = |code: &str| obs.iter().find(|o| o.end.code() == code).copied();
    let u = by_code("unexpected_input").expect("unexpected_input");
    assert!(matches!(
        &u.end,
        ObservationEnd::Observer(ObservationOutcome::UnexpectedInput { sample, truncated: false })
            if sample == b"HTTP/1.1 nonsense\r\n"
    ));
    let d = by_code("disconnected").expect("disconnected");
    assert!(matches!(
        &d.end,
        ObservationEnd::Observer(ObservationOutcome::Disconnected {
            reason_code: 11,
            ..
        })
    ));
    let e = by_code("eof").expect("eof");
    assert!(matches!(
        e.end,
        ObservationEnd::Observer(ObservationOutcome::Eof {
            stage: ObserverStage::InitialPackets,
            pending_bytes: 3
        })
    ));
    assert_eq!(summary.observed, 3);
    assert_eq!(summary.reason, StopReason::StopRequested);
}

#[test]
fn malformed_peers_do_not_stop_acceptance() {
    let r = start(config());
    for _ in 0..3 {
        let mut s = TcpStream::connect(r.addr).unwrap();
        s.write_all(b"SSH-2.0-x\r\n\xff\xff\xff\xff").unwrap();
        let _ = read_banner(&mut s);
    }
    let mut good = TcpStream::connect(r.addr).unwrap();
    good.write_all(b"SSH-2.0-good\r\n").unwrap();
    good.write_all(&client_kexinit_packet()).unwrap();
    let _ = read_banner(&mut good);
    wait_for_observations(&r.events, 4, Duration::from_secs(3));
    let (summary, events) = r.stop_and_finish();
    let obs = observations(&events);
    assert_eq!(obs.len(), 4);
    assert_eq!(
        obs.iter()
            .filter(|o| o.end.code() == "protocol_error")
            .count(),
        3
    );
    assert_eq!(obs.iter().filter(|o| o.end.code() == "proposal").count(), 1);
    assert!(summary.error.is_none());
}

#[test]
fn slow_client_does_not_block_a_second_client() {
    let r = start(config());
    let mut slow = TcpStream::connect(r.addr).unwrap();
    slow.write_all(b"SSH-2.0-slo").unwrap(); // never finishes its line
    let _ = read_banner(&mut slow);

    let t = Instant::now();
    let mut fast = TcpStream::connect(r.addr).unwrap();
    fast.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let banner = read_banner(&mut fast);
    assert_eq!(banner, b"SSH-2.0-tatami_observer_0.1.0\r\n");
    assert!(t.elapsed() < Duration::from_millis(400));
    fast.write_all(b"SSH-2.0-fast\r\n").unwrap();
    fast.write_all(&client_kexinit_packet()).unwrap();

    wait_for_observations(&r.events, 2, Duration::from_secs(3));
    let (_, events) = r.stop_and_finish();
    let obs = observations(&events);
    let fast_obs = obs.iter().find(|o| {
        o.client_identification
            .as_ref()
            .is_some_and(|i| i.software_version == "fast")
    });
    assert!(fast_obs.is_some_and(|o| o.end.code() == "proposal"));
    let slow_obs = obs
        .iter()
        .find(|o| o.client_identification.is_none())
        .unwrap();
    assert!(matches!(slow_obs.end, ObservationEnd::TimedOut));
    assert_eq!(slow_obs.bytes_read, 11);
}

#[test]
fn capacity_exhaustion_drops_and_counts() {
    let mut c = config();
    c.max_concurrent = 1;
    c.overload_report_interval = Duration::from_millis(10);
    let r = start(c);
    let mut held = TcpStream::connect(r.addr).unwrap();
    let _ = read_banner(&mut held);
    // Give the listener time to register the worker before the next accept.
    thread::sleep(Duration::from_millis(50));

    let mut dropped = TcpStream::connect(r.addr).unwrap();
    dropped
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 8];
    let n = dropped.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "excess connection must be closed without a banner");

    wait_for_observations(&r.events, 1, Duration::from_secs(3));
    thread::sleep(Duration::from_millis(50));
    let (summary, events) = r.stop_and_finish();
    assert_eq!(summary.accepted, 2);
    assert_eq!(summary.observed, 1);
    assert_eq!(summary.dropped_at_capacity, 1);
    assert!(events.iter().any(|e| matches!(
        e,
        ListenerEvent::Overload {
            dropped_since_last: 1,
            total_dropped: 1
        }
    )));
}

#[test]
fn finite_run_ends_without_clients() {
    let mut c = config();
    c.run_for = Some(Duration::from_millis(200));
    let r = start(c);
    let t = Instant::now();
    let (summary, _) = r.finish();
    assert_eq!(summary.reason, StopReason::RunDurationElapsed);
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(summary.accepted, 0);
}

#[test]
fn connection_limit_stops_after_counting_drops() {
    let mut c = config();
    c.max_connections = Some(2);
    c.max_concurrent = 1;
    let r = start(c);
    let mut a = TcpStream::connect(r.addr).unwrap();
    let _ = read_banner(&mut a);
    thread::sleep(Duration::from_millis(50));
    let _b = TcpStream::connect(r.addr).unwrap(); // dropped at capacity, still counted
    let (summary, _) = r.finish();
    assert_eq!(summary.reason, StopReason::ConnectionLimitReached);
    assert_eq!(summary.accepted, 2);
    assert_eq!(summary.dropped_at_capacity, 1);
}

#[test]
fn stop_with_active_client_yields_shutdown_outcome() {
    let mut c = config();
    c.connection_timeout = Duration::from_secs(30);
    let r = start(c);
    let mut s = TcpStream::connect(r.addr).unwrap();
    let _ = read_banner(&mut s);
    thread::sleep(Duration::from_millis(50));
    let t = Instant::now();
    let (summary, events) = r.stop_and_finish();
    assert!(t.elapsed() < Duration::from_secs(3));
    assert_eq!(summary.workers_abandoned, 0);
    let obs = observations(&events);
    assert_eq!(obs.len(), 1);
    assert!(matches!(obs[0].end, ObservationEnd::Shutdown));
    let mut buf = [0u8; 4];
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    assert_eq!(
        s.read(&mut buf).unwrap_or(0),
        0,
        "socket closed on shutdown"
    );
}

#[test]
fn bind_failure_is_reported() {
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut c = config();
    c.bind = holder.local_addr().unwrap();
    match Listener::bind(c) {
        Err(tatami_tcp::io::BindError::Io(_)) => {}
        Err(other) => panic!("{other:?}"),
        Ok(_) => panic!("bind to an occupied port succeeded"),
    }

    let mut c = config();
    c.connection_timeout = Duration::ZERO;
    assert!(matches!(
        Listener::bind(c),
        Err(tatami_tcp::io::BindError::Config(_))
    ));
    let mut c = config();
    c.max_concurrent = 0;
    assert!(matches!(
        Listener::bind(c),
        Err(tatami_tcp::io::BindError::Config(_))
    ));
}

#[test]
fn sink_failure_stops_the_run() {
    let listener = Listener::bind(config()).unwrap();
    let addr = listener.local_addr();
    let handle = thread::spawn(move || {
        listener.run(Box::new(|e| match e {
            ListenerEvent::Observation(_) => Err("disk full".into()),
            _ => Ok(()),
        }))
    });
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"SSH-2.0-x\r\n").unwrap();
    s.write_all(&client_kexinit_packet()).unwrap();
    let _ = read_banner(&mut s);
    let summary = handle.join().unwrap();
    assert_eq!(summary.reason, StopReason::SinkFailed);
    assert_eq!(summary.error.as_deref(), Some("disk full"));
}

#[derive(Default)]
struct AtomicBoolWrap(std::sync::atomic::AtomicBool);

impl AtomicBoolWrap {
    fn get(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn set(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn blocked_sink_drop_accounting_with_finite_run() {
    let mut c = config();
    c.pending_records = 1;
    c.run_for = Some(Duration::from_millis(700));
    c.shutdown_grace = Duration::from_millis(300);
    let listener = Listener::bind(c).unwrap();
    let addr = listener.local_addr();
    let release = Arc::new(AtomicBoolWrap::default());
    let rel = release.clone();
    let delivered = Arc::new(Mutex::new(0usize));
    let del = delivered.clone();
    let handle = thread::spawn(move || {
        listener.run(Box::new(move |_e| {
            while !rel.get() {
                thread::sleep(Duration::from_millis(5));
            }
            *del.lock().unwrap() += 1;
            Ok(())
        }))
    });
    for _ in 0..4 {
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"SSH-2.0-x\r\n").unwrap();
        s.write_all(&client_kexinit_packet()).unwrap();
        let _ = read_banner(&mut s);
        let mut buf = [0u8; 4];
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let _ = s.read(&mut buf);
    }
    let summary = handle.join().unwrap();
    // Started blocked the sink; one record fit in the queue; the rest dropped.
    assert_eq!(summary.observed, 4);
    assert!(summary.records_dropped >= 2, "{summary:?}");
    assert_eq!(summary.reason, StopReason::RunDurationElapsed);
    release.set();
    thread::sleep(Duration::from_millis(50));
    assert!(*delivered.lock().unwrap() >= 1);
}

#[test]
fn client_probe_against_observer_is_the_documented_partial_exchange() {
    let r = start(config());
    let io = IoConfig {
        connect_timeout: Duration::from_secs(2),
        read_timeout: Duration::from_millis(300),
        max_connect_attempts: 1,
        read_chunk: 64,
    };
    let stream = connect("127.0.0.1", r.addr.port(), &io).unwrap();
    let run = run_probe(stream, ProbeConfig::default(), &io).unwrap();
    // Client side: saw the observer's identification, then no KEXINIT.
    assert!(matches!(
        run.events.as_slice(),
        [ProbeEvent::ServerIdentification(i)] if i.software_version == "tatami_observer_0.1.0"
    ));
    assert!(matches!(
        run.end,
        tatami_tcp::io::RunEnd::TimedOut {
            stage: tatami_tcp::probe::Stage::InitialPackets,
            ..
        }
    ));
    wait_for_observations(&r.events, 1, Duration::from_secs(3));
    let (_, events) = r.stop_and_finish();
    let o = observations(&events)[0];
    // Server side: saw the probe's identification, then EOF when the probe gave up.
    assert_eq!(
        o.client_identification.as_ref().unwrap().software_version,
        "tatami_0.1.0"
    );
    assert!(o.proposal.is_none());
    assert!(matches!(
        o.end,
        ObservationEnd::Observer(ObservationOutcome::Eof {
            stage: ObserverStage::InitialPackets,
            pending_bytes: 0
        })
    ));
}

#[test]
fn ipv6_loopback_if_available() {
    let mut c = config();
    c.bind = "[::1]:0".parse().unwrap();
    let listener = match Listener::bind(c) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("skipping IPv6 loopback test: {e}");
            return;
        }
    };
    let addr = listener.local_addr();
    assert!(addr.is_ipv6());
    let stop = listener.stop_handle();
    let events: Events = Arc::new(Mutex::new(Vec::new()));
    let sink_events = events.clone();
    let handle = thread::spawn(move || {
        listener.run(Box::new(move |e| {
            sink_events.lock().unwrap().push(e);
            Ok(())
        }))
    });
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"SSH-2.0-v6\r\n").unwrap();
    s.write_all(&client_kexinit_packet()).unwrap();
    let _ = read_banner(&mut s);
    wait_for_observations(&events, 1, Duration::from_secs(3));
    stop.stop();
    let summary = handle.join().unwrap();
    let evs = events.lock().unwrap();
    let o = observations(&evs)[0];
    assert!(o.peer.is_ipv6());
    assert_eq!(o.end.code(), "proposal");
    assert_eq!(summary.observed, 1);
}

#[test]
fn trickling_client_cannot_extend_the_deadline() {
    let mut c = config();
    c.connection_timeout = Duration::from_millis(400);
    let r = start(c);
    let mut s = TcpStream::connect(r.addr).unwrap();
    let _ = read_banner(&mut s);
    let t = Instant::now();
    s.write_all(b"SSH-2.0-").unwrap();
    // One byte every 50 ms of a never-ending identification line.
    loop {
        if s.write_all(b"x").is_err() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
        if t.elapsed() > Duration::from_secs(3) {
            panic!("deadline was extended by trickle");
        }
        let mut buf = [0u8; 1];
        s.set_read_timeout(Some(Duration::from_millis(1))).unwrap();
        if matches!(s.read(&mut buf), Ok(0)) {
            break;
        }
    }
    assert!(t.elapsed() < Duration::from_millis(1500));
    wait_for_observations(&r.events, 1, Duration::from_secs(3));
    let (_, events) = r.stop_and_finish();
    let o = observations(&events)[0];
    assert!(matches!(o.end, ObservationEnd::TimedOut));
    assert!(o.elapsed < Duration::from_millis(1000));
}

#[test]
fn ignore_flood_is_bounded() {
    let r = start(config());
    let mut s = TcpStream::connect(r.addr).unwrap();
    s.write_all(b"SSH-2.0-flood\r\n").unwrap();
    let ig = encode_ignore();
    for _ in 0..64 {
        if s.write_all(&ig).is_err() {
            break;
        }
    }
    let _ = read_banner(&mut s);
    wait_for_observations(&r.events, 1, Duration::from_secs(3));
    let (_, events) = r.stop_and_finish();
    let o = observations(&events)[0];
    assert_eq!(
        o.messages.len(),
        ObserverConfig::default().initial.max_packets
    );
    assert!(matches!(
        o.end,
        ObservationEnd::Observer(ObservationOutcome::Error(
            InitialError::PacketBudgetExceeded { .. }
        ))
    ));
}
