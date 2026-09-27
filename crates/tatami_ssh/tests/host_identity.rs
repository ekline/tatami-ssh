//! One host identity across TCP and QUIC (round 5 acceptance).
//!
//! An ephemeral Ed25519 host key from the installed `ssh-keygen` is served
//! by a real OpenSSH `sshd` on TCP port P and by `tatami-server observe
//! --transport quic --host-key` on UDP port P (the same number, so one
//! `known_hosts` entry `[127.0.0.1]:P` covers both, as UDP 22 and TCP 22
//! would). Both `tatami-client handshake` transports must accept it under
//! that one entry and report the fingerprint `ssh-keygen -lf` prints, and
//! must refuse it for a changed key, unknown host, wrong port, negation,
//! revocation (before and after the positive line), a replaced server key
//! and a malformed file. Hashed entries from `ssh-keygen -H` and rotation
//! files work. The SSHFP value seen over TCP equals the one derived from
//! the QUIC raw public key and `ssh-keygen -r`. No run modifies the file.
//!
//! Skips with a notice when `/usr/sbin/sshd` or `/usr/bin/ssh-keygen` is
//! missing; a present-but-failing OpenSSH is a test failure.

#![cfg(all(
    feature = "std",
    feature = "tcp",
    feature = "kex",
    feature = "quic-diag"
))]

use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use base64ct::{Base64, Encoding as _};
use serde_json::Value;

const CLIENT: &str = env!("CARGO_BIN_EXE_tatami-client");
const SERVER: &str = env!("CARGO_BIN_EXE_tatami-server");
const SSHD: &str = "/usr/sbin/sshd";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
const ALPN: &str = "tatami-diag/0";

fn openssh_available(test: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    for bin in [SSHD, SSH_KEYGEN] {
        let ok = std::fs::metadata(bin)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false);
        if !ok {
            assert!(
                std::env::var_os("TATAMI_REQUIRE_OPENSSH").is_none(),
                "{test}: {bin} is not executable but TATAMI_REQUIRE_OPENSSH is set"
            );
            eprintln!("SKIP {test}: {bin} is not executable; identity continuity not exercised");
            return false;
        }
    }
    true
}

fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let dir = target.join("host-identity").join(format!(
        "{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An ephemeral host key: private file, `.pub` line, fingerprint.
struct Key {
    path: PathBuf,
    pub_b64: String,
    fingerprint: String,
}

fn keygen(dir: &Path, name: &str) -> Key {
    let path = dir.join(name);
    let st = Command::new(SSH_KEYGEN)
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "tatami-fixture",
            "-f",
        ])
        .arg(&path)
        .status()
        .unwrap();
    assert!(st.success());
    let pub_line = std::fs::read_to_string(path.with_extension("pub")).unwrap();
    let pub_b64 = pub_line.split_whitespace().nth(1).unwrap().to_string();
    let lf = Command::new(SSH_KEYGEN)
        .arg("-lf")
        .arg(path.with_extension("pub"))
        .output()
        .unwrap();
    let fingerprint = String::from_utf8_lossy(&lf.stdout)
        .split_whitespace()
        .find(|t| t.starts_with("SHA256:"))
        .unwrap()
        .to_string();
    Key {
        path,
        pub_b64,
        fingerprint,
    }
}

/// `ssh-keygen -r` SSHFP SHA-256 RDATA (`4 2 <hex>`) for a key.
fn keygen_sshfp(key: &Key) -> String {
    let o = Command::new(SSH_KEYGEN)
        .args(["-r", "fixture.example", "-f"])
        .arg(key.path.with_extension("pub"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&o.stdout);
    let line = text
        .lines()
        .find(|l| l.contains("SSHFP 4 2 "))
        .expect("ssh-keygen -r printed a 4 2 record");
    line.split_once("SSHFP ").unwrap().1.trim().to_string()
}

/// Captured sshd stderr lines.
type Log = Arc<Mutex<Vec<String>>>;

/// A `sshd` on TCP and a `tatami-server` QUIC observer on UDP, same port,
/// same host key.
struct Pair {
    port: u16,
    sshd: Child,
    quic: Child,
    quic_started: Value,
    _sshd_log: Log,
}

impl Drop for Pair {
    fn drop(&mut self) {
        for c in [&mut self.sshd, &mut self.quic] {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn free_port_pair() -> u16 {
    for _ in 0..20 {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
    panic!("no TCP/UDP port pair free on loopback");
}

fn sshd_supports_penalties(key: &Path) -> bool {
    let o = Command::new(SSHD)
        .args(["-T", "-f", "/dev/null", "-h"])
        .arg(key)
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "sshd -T failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .any(|l| l.split_whitespace().next() == Some("persourcepenalties"))
}

fn start_sshd(key: &Path, port: u16) -> Result<(Child, Log), String> {
    let mut args: Vec<String> = [
        "-D",
        "-e",
        "-f",
        "/dev/null",
        "-o",
        "ListenAddress=127.0.0.1",
        "-o",
        "UsePAM=no",
        "-o",
        "PidFile=none",
        "-o",
        "LogLevel=VERBOSE",
        "-o",
        "MaxStartups=20",
        "-o",
        "DenyUsers=*",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(["-p".into(), port.to_string(), "-h".into()]);
    args.push(key.display().to_string());
    if sshd_supports_penalties(key) {
        args.extend(["-o".into(), "PerSourcePenalties=no".into()]);
    }
    let mut child = Command::new(SSHD)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&log);
    let stderr = child.stderr.take().unwrap();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            sink.lock().unwrap().push(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let text = log.lock().unwrap().join("\n");
        if text.contains("Server listening on") {
            return Ok((child, log));
        }
        if let Ok(Some(st)) = child.try_wait() {
            return Err(format!("sshd exited ({st}):\n{text}"));
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err(format!("sshd did not start:\n{text}"));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn start_quic(args: &[&str], port: u16) -> Result<(Child, Value), String> {
    let mut child = Command::new(SERVER)
        .args(["observe", "--transport", "quic", "--alpn", ALPN, "--listen"])
        .arg(format!("127.0.0.1:{port}"))
        .args(["--run-for", "120s", "--timeout", "3s"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdout: BufReader<ChildStdout> = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    if stdout.read_line(&mut first).unwrap_or(0) == 0 {
        let st = child.wait().unwrap();
        return Err(format!("tatami-server exited before listening ({st})"));
    }
    // Keep draining so the server never blocks on a full pipe.
    thread::spawn(move || for _ in stdout.lines() {});
    Ok((child, serde_json::from_str(&first).unwrap()))
}

fn start_pair(key: &Key) -> Pair {
    let mut last = String::new();
    for _ in 0..5 {
        let port = free_port_pair();
        let (sshd, log) = match start_sshd(&key.path, port) {
            Ok(s) => s,
            Err(e) if e.contains("Address already in use") => {
                last = e;
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        match start_quic(&["--host-key", key.path.to_str().unwrap()], port) {
            Ok((quic, started)) => {
                return Pair {
                    port,
                    sshd,
                    quic,
                    quic_started: started,
                    _sshd_log: log,
                };
            }
            Err(e) => {
                let mut sshd = sshd;
                let _ = sshd.kill();
                let _ = sshd.wait();
                last = e;
            }
        }
    }
    panic!("could not start the TCP/UDP pair: {last}");
}

fn client(args: &[&str]) -> Output {
    Command::new(CLIENT).args(args).output().unwrap()
}

fn json(o: &Output) -> Value {
    let text = String::from_utf8_lossy(&o.stdout);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| {
        panic!(
            "bad JSON ({e}): {text}\nstderr: {}",
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn tcp(port: u16, trust: &[&str]) -> (i32, Value) {
    let port = port.to_string();
    let mut args = vec!["handshake", "127.0.0.1", "--port", &port, "--json"];
    args.extend_from_slice(trust);
    args.extend_from_slice(&["--connect-timeout", "5s", "--timeout", "10s"]);
    let o = client(&args);
    (o.status.code().unwrap(), json(&o))
}

fn quic(port: u16, trust: &[&str]) -> (i32, Value) {
    let port = port.to_string();
    let mut args = vec![
        "handshake",
        "127.0.0.1",
        "--transport",
        "quic",
        "--port",
        &port,
        "--alpn",
        ALPN,
        "--json",
        "--timeout",
        "3s",
    ];
    args.extend_from_slice(trust);
    let o = client(&args);
    (o.status.code().unwrap(), json(&o))
}

fn write_kh(dir: &Path, name: &str, text: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, text).unwrap();
    p
}

fn entry(hosts: &str, key: &Key) -> String {
    format!("{hosts} ssh-ed25519 {}\n", key.pub_b64)
}

/// Runs both transports with `--known-hosts file` and returns the two
/// untrusted reasons (or `"trusted"`), asserting the file is unchanged.
fn both(pair: &Pair, file: &Path) -> (String, String) {
    let before = std::fs::read(file).unwrap();
    let f = file.to_str().unwrap();
    let (tc, tv) = tcp(pair.port, &["--known-hosts", f]);
    let (qc, qv) = quic(pair.port, &["--known-hosts", f]);
    assert_eq!(
        std::fs::read(file).unwrap(),
        before,
        "known_hosts was modified"
    );
    let outcome = |code: i32, v: &Value| {
        if v["host_trusted"] == true {
            assert_eq!(code, 0, "{v}");
            String::from("trusted")
        } else {
            assert_eq!(code, 1, "{v}");
            v["untrusted_reason"].as_str().unwrap_or("none").to_string()
        }
    };
    (outcome(tc, &tv), outcome(qc, &qv))
}

#[test]
fn one_known_hosts_entry_covers_tcp_and_quic() {
    if !openssh_available("one_known_hosts_entry_covers_tcp_and_quic") {
        return;
    }
    let dir = scratch();
    let key = keygen(&dir, "host_key");
    let other = keygen(&dir, "other_key");
    let pair = start_pair(&key);
    let port = pair.port;
    let bracket = format!("[127.0.0.1]:{port}");

    // The QUIC server announces the SSH fingerprint ssh-keygen prints.
    assert_eq!(
        pair.quic_started["identity_mode"],
        "ssh_host_key_raw_public_key"
    );
    assert_eq!(
        pair.quic_started["ssh_host_key_sha256"],
        key.fingerprint.as_str()
    );
    assert!(pair.quic_started["certificate_sha256"].is_null());

    // 1. One entry, both transports, same fingerprint.
    let kh = write_kh(&dir, "known_hosts", &entry(&bracket, &key));
    let f = kh.to_str().unwrap();
    let (tc, tv) = tcp(port, &["--known-hosts", f]);
    assert_eq!(tc, 0, "{tv}");
    assert_eq!(tv["trust_policy"], "known_hosts");
    assert_eq!(tv["known_hosts_lookup"], bracket.as_str());
    assert_eq!(tv["trust_source"], "known_hosts");
    assert_eq!(tv["trust_line"], 1);
    assert_eq!(tv["fingerprint_sha256"], key.fingerprint.as_str());
    assert_eq!(tv["host_key_signature_valid"], true);
    assert_eq!(tv["user_authenticated"], false);
    let (qc, qv) = quic(port, &["--known-hosts", f]);
    assert_eq!(qc, 0, "{qv}");
    assert_eq!(qv["identity_mode"], "ssh_host_key_raw_public_key");
    assert_eq!(qv["known_hosts_lookup"], bracket.as_str());
    assert_eq!(qv["trust_source"], "known_hosts");
    assert_eq!(qv["trust_line"], 1);
    assert_eq!(qv["ssh_host_key"]["algorithm"], "ssh-ed25519");
    assert_eq!(
        qv["ssh_host_key"]["fingerprint_sha256"],
        key.fingerprint.as_str()
    );
    assert_eq!(qv["handshake_outcome"], "completed");
    assert_eq!(qv["application_data"], false);
    assert_eq!(qv["ssh_session"], false);
    assert_eq!(qv["user_authenticated"], false);

    // SSHFP equivalence: TCP blob digest == QUIC RPK SSHFP == ssh-keygen -r.
    let sshfp = keygen_sshfp(&key);
    assert_eq!(qv["ssh_host_key"]["sshfp"], sshfp.as_str());
    let tcp_digest = Base64::decode_vec(&format!(
        "{}=",
        tv["fingerprint_sha256"]
            .as_str()
            .unwrap()
            .strip_prefix("SHA256:")
            .unwrap()
    ))
    .unwrap();
    let hex = tcp_digest.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    assert_eq!(format!("4 2 {hex}"), sshfp);

    // The SSH pin means the same on both transports.
    let (tc, _) = tcp(port, &["--host-key-sha256", &key.fingerprint]);
    let (qc, qv) = quic(port, &["--host-key-sha256", &key.fingerprint]);
    assert_eq!((tc, qc), (0, 0), "{qv}");
    assert_eq!(qv["trust_source"], "pinned_fingerprint");
    let (tc, tv) = tcp(port, &["--host-key-sha256", &other.fingerprint]);
    let (qc, qv) = quic(port, &["--host-key-sha256", &other.fingerprint]);
    assert_eq!((tc, qc), (1, 1));
    assert_eq!(tv["untrusted_reason"], "fingerprint_mismatch");
    assert_eq!(qv["untrusted_reason"], "fingerprint_mismatch");

    // 2. Failures, identical on both transports.
    let cases = [
        ("changed", entry(&bracket, &other), "key_changed"),
        ("unknown", entry("[other.example]:22", &key), "unknown_host"),
        (
            "port",
            entry(&format!("[127.0.0.1]:{}", port.wrapping_add(1)), &key),
            "unknown_host",
        ),
        ("port22", entry("127.0.0.1", &key), "unknown_host"),
        (
            "negated",
            entry(&format!("[127.0.0.1]:*,!{bracket}"), &key),
            "unknown_host",
        ),
        (
            "revoked_before",
            format!(
                "@revoked * ssh-ed25519 {}\n{}",
                key.pub_b64,
                entry(&bracket, &key)
            ),
            "revoked",
        ),
        (
            "revoked_after",
            format!(
                "{}@revoked {bracket} ssh-ed25519 {}\n",
                entry(&bracket, &key),
                key.pub_b64
            ),
            "revoked",
        ),
    ];
    for (name, text, expected) in cases {
        let file = write_kh(&dir, name, &text);
        let (t, q) = both(&pair, &file);
        assert_eq!(
            (t.as_str(), q.as_str()),
            (expected, expected),
            "case {name}"
        );
    }

    // A malformed key is a configuration error, before any connection.
    let bad = write_kh(
        &dir,
        "malformed",
        &format!("{bracket} ssh-ed25519 AAAA!!!!\n"),
    );
    let (tc, tv) = tcp(port, &["--known-hosts", bad.to_str().unwrap()]);
    let (qc, qv) = quic(port, &["--known-hosts", bad.to_str().unwrap()]);
    assert_eq!((tc, qc), (1, 1));
    assert_eq!(tv["outcome_code"], "trust_configuration_error");
    assert_eq!(tv["untrusted_reason"], "malformed_configuration");
    assert!(tv["peer"].is_null(), "no connection may be made: {tv}");
    assert_eq!(qv["trust_error"], "malformed_configuration");
    assert_eq!(qv["handshake_outcome"], "not_attempted");

    // 3. Rotation and ssh-keygen -H hashed entries.
    let rotation = write_kh(
        &dir,
        "rotation",
        &format!("{}{}", entry(&bracket, &other), entry(&bracket, &key)),
    );
    assert_eq!(both(&pair, &rotation), ("trusted".into(), "trusted".into()));
    let hashed = write_kh(
        &dir,
        "hashed",
        &format!(
            "{}{}",
            entry(&bracket, &key),
            entry("unrelated.example", &other)
        ),
    );
    let st = Command::new(SSH_KEYGEN)
        .args(["-q", "-H", "-f"])
        .arg(&hashed)
        .status()
        .unwrap();
    assert!(st.success());
    let hashed_text = std::fs::read_to_string(&hashed).unwrap();
    assert!(
        hashed_text.lines().all(|l| l.starts_with("|1|")),
        "{hashed_text}"
    );
    assert_eq!(both(&pair, &hashed), ("trusted".into(), "trusted".into()));

    drop(pair);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replaced_server_keys_fail_on_both_transports() {
    if !openssh_available("replaced_server_keys_fail_on_both_transports") {
        return;
    }
    let dir = scratch();
    let listed = keygen(&dir, "listed");
    let replacement = keygen(&dir, "replacement");
    // Both endpoints now run with a key that is not the listed one.
    let pair = start_pair(&replacement);
    let kh = write_kh(
        &dir,
        "known_hosts",
        &entry(&format!("[127.0.0.1]:{}", pair.port), &listed),
    );
    let (t, q) = both(&pair, &kh);
    assert_eq!((t.as_str(), q.as_str()), ("key_changed", "key_changed"));
    drop(pair);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn certificate_server_is_refused_by_ssh_trust() {
    if !openssh_available("certificate_server_is_refused_by_ssh_trust") {
        return;
    }
    let dir = scratch();
    let key = keygen(&dir, "host_key");
    let port = free_port_pair();
    let id_dir = dir.join("x509");
    let (mut server, started) = start_quic(
        &[
            "--identity-dir",
            id_dir.to_str().unwrap(),
            "--generate-identity",
        ],
        port,
    )
    .unwrap();
    assert_eq!(started["identity_mode"], "x509_test_certificate");
    let kh = write_kh(
        &dir,
        "known_hosts",
        &entry(&format!("[127.0.0.1]:{port}"), &key),
    );
    let (qc, qv) = quic(port, &["--known-hosts", kh.to_str().unwrap()]);
    assert_eq!(qc, 1, "{qv}");
    assert_ne!(qv["handshake_outcome"], "completed");
    assert_ne!(qv["host_trusted"], true);
    let _ = server.kill();
    let _ = server.wait();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_key_file_problems_are_startup_errors() {
    if !openssh_available("host_key_file_problems_are_startup_errors") {
        return;
    }
    use std::os::unix::fs::PermissionsExt as _;
    let dir = scratch();
    let key = keygen(&dir, "host_key");
    let run = |args: &[&str]| {
        Command::new(SERVER)
            .args(["observe", "--transport", "quic", "--alpn", ALPN])
            .args(["--listen", "127.0.0.1:0", "--run-for", "1s"])
            .args(args)
            .output()
            .unwrap()
    };
    // Group-readable private key.
    let loose = dir.join("loose");
    std::fs::copy(&key.path, &loose).unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o640)).unwrap();
    let o = run(&["--host-key", loose.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("permissions"));
    assert!(o.stdout.is_empty());
    // Passphrase-protected key.
    let enc = dir.join("enc");
    let st = Command::new(SSH_KEYGEN)
        .args(["-q", "-t", "ed25519", "-N", "fixture passphrase", "-f"])
        .arg(&enc)
        .status()
        .unwrap();
    assert!(st.success());
    let o = run(&["--host-key", enc.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr).contains("passphrase"));
    // A public key is not a private key.
    let o = run(&[
        "--host-key",
        key.path.with_extension("pub").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    // Conflicting identities are usage errors.
    let o = run(&[
        "--host-key",
        key.path.to_str().unwrap(),
        "--identity-dir",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&[
        "--host-key",
        key.path.to_str().unwrap(),
        "--generate-identity",
    ]);
    assert_eq!(o.status.code(), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Line numbers `ssh-keygen -F name -f file` reports as matching.
fn keygen_matches(file: &Path, name: &str) -> Vec<usize> {
    let o = Command::new(SSH_KEYGEN)
        .args(["-F", name, "-f"])
        .arg(file)
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| l.split_once("found: line "))
        .map(|(_, n)| n.trim().parse().unwrap())
        .collect()
}

#[test]
fn matching_agrees_with_ssh_keygen_f() {
    // Only ssh-keygen is needed here.
    if !Path::new(SSH_KEYGEN).exists() {
        eprintln!("SKIP matching_agrees_with_ssh_keygen_f: {SSH_KEYGEN} missing");
        return;
    }
    use tatami_ssh::keys::known_hosts::{KnownHosts, Limits, lookup_name};
    let dir = scratch();
    let key = keygen(&dir, "k");
    let text: String = [
        "Host.Example",
        "[host.example]:2222",
        "*.wild.example,!bad.wild.example",
        "h?st",
        "[*.wild.example]:2200",
        "10.0.0.*,!10.0.0.9",
        "2001:db8::1",
        "[2001:db8::1]:2200",
        "a.example,b.example",
    ]
    .iter()
    .map(|h| entry(h, &key))
    .collect();
    let plain = write_kh(&dir, "plain", &text);
    let hashed = write_kh(&dir, "hashed", &text);
    // Hashes the non-wildcard lines in place (line numbers unchanged).
    assert!(
        Command::new(SSH_KEYGEN)
            .args(["-q", "-H", "-f"])
            .arg(&hashed)
            .status()
            .unwrap()
            .success()
    );
    let queries: &[(&str, u16)] = &[
        ("host.example", 22),
        ("HOST.Example", 22),
        ("host.example", 2222),
        ("HOST.EXAMPLE", 2222),
        ("host.example", 2223),
        ("a.wild.example", 22),
        ("bad.wild.example", 22),
        ("x.wild.example", 2200),
        ("host", 22),
        ("hoost", 22),
        ("10.0.0.5", 22),
        ("10.0.0.9", 22),
        ("2001:db8::1", 22),
        ("2001:DB8::1", 2200),
        ("b.example", 22),
        ("c.example", 22),
    ];
    for file in [&plain, &hashed] {
        let parsed = KnownHosts::parse(&std::fs::read(file).unwrap(), &Limits::default()).unwrap();
        for &(host, port) in queries {
            let name = lookup_name(host, port).unwrap();
            let ours: Vec<usize> = parsed
                .entries()
                .iter()
                .filter(|e| e.applies_to(&name))
                .map(|e| e.line())
                .collect();
            assert_eq!(
                ours,
                keygen_matches(file, &name),
                "{host} port {port} (lookup {name}) in {}",
                file.display()
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn conflicting_trust_options_are_usage_errors() {
    let pin = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";
    for args in [
        &[
            "handshake",
            "h",
            "--known-hosts",
            "kh",
            "--host-key-sha256",
            pin,
        ][..],
        &[
            "handshake",
            "h",
            "--transport",
            "quic",
            "--alpn",
            ALPN,
            "--known-hosts",
            "kh",
            "--cert-sha256",
            pin,
        ],
    ] {
        let o = client(args);
        assert_eq!(o.status.code(), Some(2), "{args:?}");
        assert!(o.stdout.is_empty());
    }
}
