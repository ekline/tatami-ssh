//! End-to-end tests for `tatami-server observe` and its JSON Lines output.
//!
//! The binary is spawned with `--listen 127.0.0.1:0`; the bound port is
//! taken from the first stdout record. Every line is parsed with
//! `serde_json`, an independent parser. Nothing external is contacted.

#![cfg(all(feature = "std", feature = "tcp"))]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tatami::server::observe::{Encoder, SCHEMA_VERSION};
use tatami_tcp::io::{ListenerEvent, Observation, ObservationEnd};
use tatami_tcp::observer::{ObservationOutcome, ObserverStage};
use tatami_tcp::packet::encode_initial_packet;
use tatami_tcp::wire::Writer;

const SERVER: &str = env!("CARGO_BIN_EXE_tatami-server");

fn kexinit_packet(names: &str) -> Vec<u8> {
    let mut buf = vec![0u8; names.len() * 10 + 256];
    let mut w = Writer::new(&mut buf);
    w.write_u8(20).unwrap();
    w.write_bytes(&[9; 16]).unwrap();
    w.write_string(format!("{names},ext-info-c").as_bytes())
        .unwrap();
    w.write_string(b"ssh-ed25519").unwrap();
    w.write_string(b"aes128-ctr").unwrap();
    w.write_string(b"aes256-ctr").unwrap();
    w.write_string(b"hmac-sha2-256").unwrap();
    w.write_string(b"hmac-sha2-512").unwrap();
    w.write_string(b"none").unwrap();
    w.write_string(b"zlib").unwrap();
    w.write_string(b"").unwrap();
    w.write_string(b"").unwrap();
    w.write_bool(false).unwrap();
    w.write_u32(0).unwrap();
    let payload = w.written().to_vec();
    let mut out = vec![0u8; payload.len() + 64];
    let n = encode_initial_packet(&payload, 0, &mut out).unwrap();
    out.truncate(n);
    out
}

struct Observer {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    addr: SocketAddr,
}

fn spawn(args: &[&str]) -> Observer {
    let mut child = Command::new(SERVER)
        .arg("observe")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    stdout.read_line(&mut first).unwrap();
    let v: Value = serde_json::from_str(&first).expect("first line is JSON");
    assert_eq!(v["event"], "listener_started");
    assert_eq!(v["schema"], SCHEMA_VERSION);
    let addr: SocketAddr = v["bound"].as_str().unwrap().parse().unwrap();
    assert_ne!(addr.port(), 0, "bound port must be reported, not 0");
    Observer {
        child,
        stdout,
        addr,
    }
}

impl Observer {
    /// Waits for exit and returns (status, parsed stdout lines, stderr).
    fn finish(mut self) -> (i32, Vec<Value>, String) {
        let mut rest = String::new();
        self.stdout.read_to_string(&mut rest).unwrap();
        let mut stderr = String::new();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        let status = self.child.wait().unwrap().code().unwrap();
        let lines: Vec<Value> = rest
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad JSON {e}: {l}")))
            .collect();
        (status, lines, stderr)
    }
}

fn read_banner(s: &mut TcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    while !got.ends_with(b"\r\n") {
        s.read_exact(&mut b).unwrap();
        got.push(b[0]);
    }
    got
}

fn wait_close(s: &mut TcpStream) {
    let mut buf = [0u8; 16];
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    while let Ok(n) = s.read(&mut buf) {
        if n == 0 {
            break;
        }
    }
}

#[test]
fn help_version_and_usage_statuses() {
    let o = Command::new(SERVER).arg("--help").output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stdout).contains("tatami-server observe"));

    let o = Command::new(SERVER)
        .args(["observe", "--help"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));

    let o = Command::new(SERVER).arg("--version").output().unwrap();
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        format!("tatami-server {}", env!("CARGO_PKG_VERSION"))
    );

    for args in [
        &[][..],
        &["serve"],
        &["observe", "--listen", "nonsense"],
        &["observe", "--timeout", "0s"],
        &["observe", "--max-concurrent", "0"],
        &["observe", "--format", "csv"],
        &["observe", "--quic"],
    ] {
        let o = Command::new(SERVER).args(args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(
            o.stdout.is_empty(),
            "{args:?}: usage errors must not write stdout"
        );
        assert!(String::from_utf8_lossy(&o.stderr).contains("Usage:"));
    }
}

#[test]
fn finite_run_with_no_clients_exits_0() {
    let obs = spawn(&["--run-for", "300ms"]);
    let (status, lines, stderr) = obs.finish();
    assert_eq!(status, 0, "{stderr}");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["event"], "listener_stopped");
    assert_eq!(lines[0]["reason"], "run_duration_elapsed");
    assert_eq!(lines[0]["accepted"], 0);
}

#[test]
fn observations_are_valid_json_with_escaping_and_exit_0() {
    let obs = spawn(&["--max-connections", "3", "--timeout", "2s"]);

    // 1: clean proposal with quotes/backslashes/control/non-UTF-8 in comments.
    let mut a = TcpStream::connect(obs.addr).unwrap();
    a.write_all(b"SSH-2.0-Fixture_A say \"hi\" back\\slash \x01\x1b[0m \xff\xfe end\r\n")
        .unwrap();
    a.write_all(&kexinit_packet("curve25519-sha256")).unwrap();
    let banner = read_banner(&mut a);
    assert_eq!(banner, b"SSH-2.0-tatami_observer_0.1.0\r\n");
    wait_close(&mut a);

    // 2: unexpected input with binary bytes.
    let mut b = TcpStream::connect(obs.addr).unwrap();
    b.write_all(b"\x16\x03\x01\x00\xc8\x01\x00\x00\xc4\x03\x03")
        .unwrap();
    let _ = read_banner(&mut b);
    wait_close(&mut b);

    // 3: malformed packet -> protocol_error, must not fail the process.
    let mut c = TcpStream::connect(obs.addr).unwrap();
    c.write_all(b"SSH-1.99-Old\n").unwrap();
    c.write_all(&[0, 0, 0, 13]).unwrap();
    let _ = read_banner(&mut c);
    wait_close(&mut c);

    let (status, lines, stderr) = obs.finish();
    assert_eq!(status, 0, "{stderr}");
    let observations: Vec<&Value> = lines
        .iter()
        .filter(|l| l["event"] == "connection_observation")
        .collect();
    assert_eq!(observations.len(), 3, "{lines:?}");
    for o in &observations {
        assert_eq!(o["schema"], SCHEMA_VERSION);
        assert_eq!(o["transport"], "tcp");
        assert_eq!(o["key_exchange_completed"], false);
        assert_eq!(o["peer_authenticated"], false);
        assert_eq!(o["record_truncated"], false);
        assert_eq!(o["server_identification"], "SSH-2.0-tatami_observer_0.1.0");
        assert!(o["accepted_at"].as_str().unwrap().ends_with('Z'));
        assert!(o["peer_addr"].as_str().unwrap().starts_with("127.0.0.1:"));
        assert!(o["id"].as_u64().unwrap() >= 1);
    }

    let a = observations
        .iter()
        .find(|o| o["outcome"] == "proposal")
        .unwrap();
    let ident = &a["client_identification"];
    assert_eq!(ident["software_version"], "Fixture_A");
    assert_eq!(ident["terminator"], "crlf");
    let comments = ident["comments"].as_str().unwrap();
    assert_eq!(
        comments,
        "say \"hi\" back\\slash \u{1}\u{1b}[0m \u{fffd}\u{fffd} end"
    );
    assert!(
        ident["line_hex"]
            .as_str()
            .unwrap()
            .ends_with("fffe20656e64")
    );
    assert_eq!(a["proposal"]["role"], "client");
    assert_eq!(a["proposal"]["kex_algorithms"][0], "curve25519-sha256");
    assert_eq!(a["proposal"]["kex_markers"][0]["kind"], "ext_info_client");
    assert_eq!(
        a["proposal"]["server_host_key_algorithms"][0],
        "ssh-ed25519"
    );
    assert_eq!(
        a["proposal"]["encryption_client_to_server"][0],
        "aes128-ctr"
    );
    assert_eq!(
        a["proposal"]["encryption_server_to_client"][0],
        "aes256-ctr"
    );
    assert_eq!(a["proposal"]["cookie_hex"], "09".repeat(16));
    assert_eq!(a["stage"], "finished");

    let b = observations
        .iter()
        .find(|o| o["outcome"] == "unexpected_input")
        .unwrap();
    assert_eq!(b["reason"], "not_ssh_identification");
    assert_eq!(b["diagnostics"]["sample_hex"], "16030100c8010000c40303");
    assert_eq!(b["diagnostics"]["sample_truncated"], false);
    assert!(b["client_identification"].is_null());
    assert!(b["proposal"].is_null());

    let c = observations
        .iter()
        .find(|o| o["outcome"] == "protocol_error")
        .unwrap();
    assert_eq!(c["reason"], "packet_framing");
    let anomalies = c["client_identification"]["anomalies"].as_array().unwrap();
    assert!(anomalies.contains(&Value::from("lf_only_terminator")));
    assert!(anomalies.contains(&Value::from("compatibility_version_1_99")));

    let stopped = lines.last().unwrap();
    assert_eq!(stopped["event"], "listener_stopped");
    assert_eq!(stopped["reason"], "connection_limit_reached");
    assert_eq!(stopped["accepted"], 3);
    assert_eq!(stopped["records_dropped"], 0);
    assert!(stderr.contains("not an SSH service"));
}

#[test]
fn banner_only_flag() {
    let obs = spawn(&["--banner-only", "--max-connections", "1"]);
    let mut s = TcpStream::connect(obs.addr).unwrap();
    s.write_all(b"SSH-2.0-b\r\n").unwrap();
    s.write_all(&kexinit_packet("curve25519-sha256")).unwrap();
    let _ = read_banner(&mut s);
    wait_close(&mut s);
    let (status, lines, _) = obs.finish();
    assert_eq!(status, 0);
    let o = lines
        .iter()
        .find(|l| l["event"] == "connection_observation")
        .unwrap();
    assert_eq!(o["outcome"], "banner_only");
    assert!(o["proposal"].is_null());
}

#[test]
fn bind_failure_exits_1_without_output() {
    let holder = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = holder.local_addr().unwrap().to_string();
    let o = Command::new(SERVER)
        .args(["observe", "--listen", &addr, "--run-for", "1s"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(o.stdout.is_empty());
    assert!(String::from_utf8_lossy(&o.stderr).contains("bind failed"));
}

#[test]
fn closed_stdout_is_an_output_failure_exit_1() {
    let mut child = Command::new(SERVER)
        .args(["observe", "--listen", "127.0.0.1:0", "--run-for", "20s"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    stdout.read_line(&mut first).unwrap();
    let v: Value = serde_json::from_str(&first).unwrap();
    let addr: SocketAddr = v["bound"].as_str().unwrap().parse().unwrap();
    drop(stdout); // the next record write hits a closed pipe

    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(b"SSH-2.0-x\r\n").unwrap();
    s.write_all(&kexinit_packet("curve25519-sha256")).unwrap();
    let _ = read_banner(&mut s);
    wait_close(&mut s);

    let t = Instant::now();
    let status = child.wait().unwrap();
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "did not stop on sink failure"
    );
    assert_eq!(status.code(), Some(1));
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("sink_failed"), "{stderr}");
}

#[test]
fn oversized_record_is_truncated_not_dropped() {
    let names: Vec<String> = (0..3000).map(|i| format!("alg{i}")).collect();
    let packet = kexinit_packet(&names.join(","));
    let payload = &packet[5..packet.len() - packet[4] as usize];
    let kexinit = tatami_tcp::wire::kexinit::KexInit::decode(payload).unwrap();
    let proposal = tatami_tcp::probe::Proposal::from_kexinit(&kexinit, payload, 0);
    let obs = Observation {
        id: 7,
        local: "127.0.0.1:2222".parse().unwrap(),
        peer: "127.0.0.1:5".parse().unwrap(),
        accepted_unix: Duration::from_secs(1_789_907_696),
        elapsed: Duration::from_millis(12),
        bytes_read: 10,
        bytes_written: 31,
        server_identification: b"SSH-2.0-tatami_observer_0.1.0".to_vec(),
        client_identification: None,
        messages: Vec::new(),
        proposal: Some(proposal.clone()),
        stage: ObserverStage::Finished,
        end: ObservationEnd::Observer(ObservationOutcome::Proposal(Box::new(proposal))),
    };
    let event = ListenerEvent::Observation(Box::new(obs));

    let big = Encoder {
        max_record_bytes: 1 << 20,
        max_field_bytes: 512,
    }
    .encode(&event)
    .to_json();
    let v: Value = serde_json::from_str(&big).unwrap();
    assert_eq!(v["record_truncated"], false);
    assert_eq!(
        v["proposal"]["kex_algorithms"].as_array().unwrap().len(),
        3001
    );

    let small = Encoder {
        max_record_bytes: 2048,
        max_field_bytes: 512,
    }
    .encode(&event)
    .to_json();
    assert!(small.len() <= 2048, "{}", small.len());
    let v: Value = serde_json::from_str(&small).unwrap();
    assert_eq!(v["record_truncated"], true);
    assert!(v["proposal"].is_null());
    assert_eq!(v["outcome"], "proposal");
    assert_eq!(v["accepted_at"], "2026-09-20T12:34:56.000Z");
}

#[test]
fn records_are_not_interleaved_under_concurrency() {
    let obs = spawn(&["--max-connections", "12", "--timeout", "3s"]);
    let addr = obs.addr;
    let handles: Vec<_> = (0..12)
        .map(|i| {
            std::thread::spawn(move || {
                let mut s = TcpStream::connect(addr).unwrap();
                let line = format!("SSH-2.0-Conc_{i}\r\n");
                s.write_all(line.as_bytes()).unwrap();
                s.write_all(&kexinit_packet("curve25519-sha256")).unwrap();
                let _ = read_banner(&mut s);
                wait_close(&mut s);
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let (status, lines, _) = obs.finish();
    assert_eq!(status, 0);
    let mut seen: Vec<String> = lines
        .iter()
        .filter(|l| l["event"] == "connection_observation")
        .map(|l| {
            l["client_identification"]["software_version"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    seen.sort();
    let mut expected: Vec<String> = (0..12).map(|i| format!("Conc_{i}")).collect();
    expected.sort();
    assert_eq!(seen, expected);
}
