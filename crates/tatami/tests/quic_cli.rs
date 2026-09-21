//! End-to-end tests for `tatami-quic-server observe` and
//! `tatami-quic-client handshake` on loopback UDP.
//!
//! The server is spawned with `--listen 127.0.0.1:0`; the bound port and
//! certificate fingerprint are read from its first stdout record. Every
//! stdout line is parsed with `serde_json`, an independent parser. Nothing
//! external is contacted, and no SSH bytes exist anywhere in this exchange
//! (the client opens no stream; see the library tests that inspect every
//! datagram).

#![cfg(feature = "quic-diag")]

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use tatami::quic_diag::server::SCHEMA_VERSION;

const SERVER: &str = env!("CARGO_BIN_EXE_tatami-quic-server");
const CLIENT: &str = env!("CARGO_BIN_EXE_tatami-quic-client");
const ALPN: &str = "tatami-diag/0";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tatami-quic-cli-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

struct Server {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
    addr: SocketAddr,
    fingerprint: String,
    dir: PathBuf,
}

fn spawn_server(dir: &PathBuf, args: &[&str]) -> Server {
    let mut child = Command::new(SERVER)
        .args(["observe", "--listen", "127.0.0.1:0", "--alpn", ALPN])
        .arg("--identity-dir")
        .arg(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    stdout.read_line(&mut first).unwrap();
    let v: Value = serde_json::from_str(&first).expect("first line is JSON");
    assert_eq!(v["event"], "quic_listener_started");
    assert_eq!(v["schema"], SCHEMA_VERSION);
    assert_eq!(v["transport"], "quic");
    assert_eq!(v["zero_rtt"], false);
    assert_eq!(v["experimental"], true);
    assert_eq!(v["alpn_registered"], false);
    assert_eq!(v["ssh_service"], false);
    assert_eq!(v["alpn"][0], ALPN);
    let addr: SocketAddr = v["bound"].as_str().unwrap().parse().unwrap();
    assert_ne!(addr.port(), 0);
    let fingerprint = v["certificate_sha256"].as_str().unwrap().to_string();
    assert!(fingerprint.starts_with("SHA256:") && fingerprint.len() == 50);
    Server {
        child,
        stdout,
        addr,
        fingerprint,
        dir: dir.clone(),
    }
}

impl Server {
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
        let _ = std::fs::remove_dir_all(&self.dir);
        (status, lines, stderr)
    }
}

fn client(addr: SocketAddr, args: &[&str]) -> (i32, Value, String) {
    let o = Command::new(CLIENT)
        .args(["handshake", "127.0.0.1", "--port", &addr.port().to_string()])
        .args(["--server-name", "localhost", "--json"])
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(o.stdout).unwrap();
    let v: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout}"));
    (
        o.status.code().unwrap(),
        v,
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn help_version_and_usage_statuses() {
    for (bin, cmd) in [(SERVER, "observe"), (CLIENT, "handshake")] {
        let o = Command::new(bin).arg("--help").output().unwrap();
        assert_eq!(o.status.code(), Some(0));
        let help = String::from_utf8_lossy(&o.stdout);
        for word in [
            "EXPERIMENTAL",
            "UNREGISTERED",
            "0-RTT",
            "no interoperability",
        ] {
            assert!(help.contains(word), "{bin} help lacks {word}");
        }
        assert!(help.contains("not an SSH"), "{bin}");
        let o = Command::new(bin).args([cmd, "--help"]).output().unwrap();
        assert_eq!(o.status.code(), Some(0));
        let o = Command::new(bin).arg("--version").output().unwrap();
        assert_eq!(o.status.code(), Some(0));
    }
    for args in [
        &[][..],
        &["serve"],
        &["observe"],
        &["observe", "--identity-dir", "/tmp/x"],
        &["observe", "--alpn", ALPN],
        &[
            "observe",
            "--alpn",
            ALPN,
            "--identity-dir",
            "/tmp/x",
            "--listen",
            "nonsense",
        ],
        &[
            "observe",
            "--alpn",
            ALPN,
            "--identity-dir",
            "/tmp/x",
            "--ssh",
        ],
    ] {
        let o = Command::new(SERVER).args(args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(
            o.stdout.is_empty(),
            "{args:?}: usage errors must not write stdout"
        );
        assert!(String::from_utf8_lossy(&o.stderr).contains("Usage:"));
    }
    for args in [
        &[][..],
        &["handshake"],
        &["handshake", "127.0.0.1"],
        &["handshake", "127.0.0.1", "--alpn", ALPN],
        &[
            "handshake",
            "127.0.0.1",
            "--alpn",
            ALPN,
            "--cert-sha256",
            "nope",
        ],
        &["probe", "127.0.0.1"],
    ] {
        let o = Command::new(CLIENT).args(args).output().unwrap();
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty(), "{args:?}");
        assert!(String::from_utf8_lossy(&o.stderr).contains("Usage:"));
    }
}

#[test]
fn missing_identity_without_generate_flag_exits_1() {
    let dir = temp_dir("noid");
    let o = Command::new(SERVER)
        .args([
            "observe",
            "--listen",
            "127.0.0.1:0",
            "--alpn",
            ALPN,
            "--identity-dir",
        ])
        .arg(&dir)
        .args(["--run-for", "1s"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(o.stdout.is_empty());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("no identity"), "{err}");
    assert!(err.contains("--generate-identity"), "{err}");
    assert!(!dir.exists(), "nothing may be generated silently");
}

#[test]
fn end_to_end_handshake_with_pin_and_exporter_probe() {
    let dir = temp_dir("e2e");
    let server = spawn_server(
        &dir,
        &[
            "--generate-identity",
            "--max-connections",
            "1",
            "--timeout",
            "3s",
        ],
    );
    assert!(dir.join("cert.pem").exists() && dir.join("key.pem").exists());

    let (status, v, stderr) = client(
        server.addr,
        &[
            "--alpn",
            ALPN,
            "--cert-sha256",
            &server.fingerprint,
            "--exporter-probe",
        ],
    );
    assert_eq!(status, 0, "{v}\n{stderr}");
    assert_eq!(v["event"], "quic_client_handshake");
    assert_eq!(v["transport"], "quic");
    assert_eq!(v["handshake_outcome"], "completed");
    assert_eq!(v["negotiated_alpn"], ALPN);
    assert_eq!(v["offered_alpn"][0], ALPN);
    assert_eq!(v["alpn_registered"], false);
    assert_eq!(v["sni_sent"], true);
    assert_eq!(v["server_name"], "localhost");
    assert_eq!(v["server_identity_check"], "pinned_certificate_sha256");
    assert_eq!(v["server_identity_verified"], true);
    assert_eq!(v["tls_version"], "1.3");
    assert_eq!(v["quic_version"], 1);
    assert_eq!(v["zero_rtt"], false);
    assert_eq!(v["exporter"]["available"], true);
    assert_eq!(v["exporter"]["len"], 32);
    assert_eq!(v["user_authenticated"], false);
    assert_eq!(v["application_data"], false);
    assert!(
        v["close_reason"]
            .as_str()
            .unwrap()
            .contains("application code 0"),
        "{v}"
    );
    assert!(stderr.contains("not an SSH client"), "{stderr}");

    let (status, lines, stderr) = server.finish();
    assert_eq!(status, 0, "{stderr}");
    assert!(stderr.contains("certificate SHA-256"), "{stderr}");
    assert!(stderr.contains("not an SSH service"), "{stderr}");
    assert!(
        stderr.contains("generated a self-signed Ed25519 TEST identity"),
        "{stderr}"
    );
    let obs: Vec<&Value> = lines
        .iter()
        .filter(|l| l["event"] == "quic_handshake_observation")
        .collect();
    assert_eq!(obs.len(), 1, "{lines:?}");
    let o = obs[0];
    assert_eq!(o["schema"], SCHEMA_VERSION);
    assert_eq!(o["transport"], "quic");
    assert_eq!(o["handshake_outcome"], "completed");
    assert_eq!(o["close_reason"], "local_close_after_handshake");
    assert!(o["peer_addr"].as_str().unwrap().starts_with("127.0.0.1:"));
    assert_eq!(o["peer_address_validated"], false);
    assert_eq!(o["may_retry"], true);
    assert_eq!(o["retry_sent"], false);
    assert_eq!(o["validation_method"], "none");
    assert_eq!(o["quic_version"], 1);
    assert_eq!(o["offered_alpn"][0], ALPN);
    assert_eq!(o["offered_sni"], "localhost");
    assert_eq!(o["negotiated_alpn"], ALPN);
    assert_eq!(o["sni"], "localhost");
    assert!(!o["offered_cipher_suites"].as_array().unwrap().is_empty());
    assert!(o["offered_note"].as_str().unwrap().contains("untrusted"));
    assert_eq!(o["unexpected_streams"], 0);
    assert_eq!(o["unexpected_datagrams"], 0);
    assert_eq!(o["zero_rtt"], false);
    assert_eq!(o["peer_authenticated"], false);
    assert_eq!(o["application_data"], false);
    assert!(o["accepted_at"].as_str().unwrap().ends_with('Z'));
    assert!(o["orig_dst_cid_hex"].as_str().unwrap().len() >= 16);
    let stopped = lines.last().unwrap();
    assert_eq!(stopped["event"], "quic_listener_stopped");
    assert_eq!(stopped["reason"], "connection_limit_reached");
    assert_eq!(stopped["accepted"], 1);
    assert_eq!(stopped["completed"], 1);
    assert_eq!(stopped["records_dropped"], 0);
}

#[test]
fn wrong_pin_and_wrong_alpn_are_records_not_server_failures() {
    let dir = temp_dir("wrong");
    let server = spawn_server(
        &dir,
        &[
            "--generate-identity",
            "--max-connections",
            "2",
            "--timeout",
            "3s",
        ],
    );
    // Wrong pin: a valid fingerprint of something else.
    let (status, v, _) = client(
        server.addr,
        &[
            "--alpn",
            ALPN,
            "--cert-sha256",
            "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
        ],
    );
    assert_eq!(status, 1, "{v}");
    assert_eq!(v["handshake_outcome"], "failed");
    assert!(v["reason"].as_str().unwrap().contains("SHA-256 pin"), "{v}");
    assert_eq!(v["server_identity_verified"], false);
    assert!(v["exporter"].is_null());
    // Wrong ALPN.
    let (status, v, _) = client(
        server.addr,
        &[
            "--alpn",
            "tatami-diag/other",
            "--cert-sha256",
            &server.fingerprint,
        ],
    );
    assert_eq!(status, 1, "{v}");
    assert_eq!(v["handshake_outcome"], "failed");
    assert!(v["reason"].as_str().unwrap().contains("error 120"), "{v}");
    assert!(v["negotiated_alpn"].is_null());

    let (status, lines, _) = server.finish();
    assert_eq!(status, 0);
    let outcomes: Vec<&str> = lines
        .iter()
        .filter(|l| l["event"] == "quic_handshake_observation")
        .map(|l| l["handshake_outcome"].as_str().unwrap())
        .collect();
    assert_eq!(outcomes, ["failed", "accept_failed"], "{lines:?}");
    let accept_failed = lines
        .iter()
        .find(|l| l["handshake_outcome"] == "accept_failed")
        .unwrap();
    assert_eq!(accept_failed["offered_alpn"][0], "tatami-diag/other");
    assert!(accept_failed["negotiated_alpn"].is_null());
    assert_eq!(accept_failed["close_reason"], "not_established");
}

#[test]
fn no_listener_times_out_and_exits_1() {
    let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = holder.local_addr().unwrap();
    drop(holder);
    let t = Instant::now();
    let (status, v, _) = client(
        addr,
        &[
            "--alpn",
            ALPN,
            "--cert-sha256",
            "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8",
            "--timeout",
            "600ms",
        ],
    );
    assert!(t.elapsed() < Duration::from_secs(5));
    assert_eq!(status, 1);
    assert_eq!(v["handshake_outcome"], "timed_out");
    assert_eq!(v["datagrams_received"], 0);
}

#[test]
fn require_validation_is_visible_in_records() {
    let dir = temp_dir("retry");
    let server = spawn_server(
        &dir,
        &[
            "--generate-identity",
            "--require-validation",
            "--max-connections",
            "1",
        ],
    );
    let (status, v, _) = client(
        server.addr,
        &["--alpn", ALPN, "--cert-sha256", &server.fingerprint],
    );
    assert_eq!(status, 0, "{v}");
    let (status, lines, _) = server.finish();
    assert_eq!(status, 0);
    let o = lines
        .iter()
        .find(|l| l["event"] == "quic_handshake_observation")
        .unwrap();
    assert_eq!(o["retry_sent"], true);
    assert_eq!(o["peer_address_validated"], true);
    assert_eq!(o["may_retry"], false);
    assert_eq!(o["validation_method"], "retry_token");
    let stopped = lines.last().unwrap();
    assert_eq!(stopped["retries_sent"], 1);
    assert_eq!(stopped["incoming"], 2);
}

#[test]
fn text_report_reuses_identity_and_finite_run_exits_0() {
    let dir = temp_dir("text");
    // First run generates; second run must reuse the same certificate.
    let first = spawn_server(&dir, &["--generate-identity", "--run-for", "200ms"]);
    let fp = first.fingerprint.clone();
    let (status, lines, _) = {
        let mut rest = String::new();
        let mut s = first;
        s.stdout.read_to_string(&mut rest).unwrap();
        let status = s.child.wait().unwrap().code().unwrap();
        let lines: Vec<Value> = rest
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (status, lines, ())
    };
    assert_eq!(status, 0);
    assert_eq!(lines.last().unwrap()["reason"], "run_duration_elapsed");
    assert_eq!(lines.last().unwrap()["incoming"], 0);

    let second = spawn_server(&dir, &["--max-connections", "1"]);
    assert_eq!(
        second.fingerprint, fp,
        "identity must be reused, not regenerated"
    );
    let o = Command::new(CLIENT)
        .args([
            "handshake",
            "127.0.0.1",
            "--port",
            &second.addr.port().to_string(),
        ])
        .args([
            "--server-name",
            "localhost",
            "--alpn",
            ALPN,
            "--cert-sha256",
            &fp,
        ])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0));
    let text = String::from_utf8_lossy(&o.stdout);
    assert!(
        text.contains("Handshake: completed (TLS 1.3 over QUIC v1)"),
        "{text}"
    );
    assert!(text.contains("ALPN negotiated: tatami-diag/0"), "{text}");
    assert!(text.contains("SSH: nothing sent or expected"), "{text}");
    assert!(text.contains("TLS exporter probe: not requested"), "{text}");
    let (status, _, _) = second.finish();
    assert_eq!(status, 0);
}
