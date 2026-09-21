//! End-to-end tests for `tatami-client handshake`.
//!
//! Compiled only with `std,tcp,kex`, which is when the command exists. Usage
//! errors and the connect-refused case need nothing external. The
//! interoperability cases start a real OpenSSH `sshd` on a loopback port
//! with an ephemeral Ed25519 host key (the same fixture logic as
//! `tatami-tcp/tests/openssh_handshake.rs` and `scripts/openssh-fixture.sh`)
//! and take the pin from `ssh-keygen -lf`, an independent source. When
//! `/usr/sbin/sshd` or `/usr/bin/ssh-keygen` is missing those tests print a
//! skip notice and return.

#![cfg(all(feature = "std", feature = "tcp", feature = "kex"))]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CLIENT: &str = env!("CARGO_BIN_EXE_tatami-client");
const SSHD: &str = "/usr/sbin/sshd";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";
const VALID_PIN: &str = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";

fn client(args: &[&str]) -> Output {
    Command::new(CLIENT).args(args).output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exit code")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// `true` when both binaries exist; otherwise prints why the test skips.
fn openssh_available(test: &str) -> bool {
    for bin in [SSHD, SSH_KEYGEN] {
        if !is_executable(bin) {
            eprintln!(
                "SKIP {test}: {bin} is not executable; OpenSSH interoperability not exercised"
            );
            return false;
        }
    }
    true
}

/// A fresh directory under the workspace `target/` (not `/tmp`, which is
/// wiped between commands in some environments). Distinct from the
/// directory `scripts/openssh-fixture.sh` uses.
fn scratch_dir() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("..")
                .join("target")
        });
    let dir = target.join("openssh-handshake-cli").join(format!(
        "{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// A running `sshd` with its captured log.
struct Sshd {
    child: Child,
    port: u16,
    pin: String,
    command_line: String,
    log: Arc<Mutex<Vec<String>>>,
    reader: Option<JoinHandle<()>>,
    dir: PathBuf,
}

impl Sshd {
    /// Starts sshd, retrying on an ephemeral-port race ("Address already in
    /// use" when another process bound the port between our probe bind and
    /// sshd's bind). Bounded to a few attempts.
    fn start(extra_options: &[&str]) -> Sshd {
        let mut last = String::new();
        for _ in 0..5 {
            match Self::try_start(extra_options) {
                Ok(sshd) => return sshd,
                Err(log) if log.contains("Address already in use") => last = log,
                Err(log) => panic!("sshd exited early:\n{log}"),
            }
        }
        panic!("sshd could not bind an ephemeral port after 5 attempts:\n{last}");
    }

    fn try_start(extra_options: &[&str]) -> Result<Sshd, String> {
        let version = Command::new(SSHD).arg("-V").output().expect("sshd -V");
        eprintln!(
            "--- OpenSSH: {}{}",
            String::from_utf8_lossy(&version.stdout).trim(),
            String::from_utf8_lossy(&version.stderr).trim()
        );

        let dir = scratch_dir();
        let key_path = dir.join("hostkey");
        let status = Command::new(SSH_KEYGEN)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key_path)
            .status()
            .expect("run ssh-keygen");
        assert!(status.success(), "ssh-keygen failed: {status}");

        // The operator's independent fingerprint source.
        let output = Command::new(SSH_KEYGEN)
            .arg("-lf")
            .arg(dir.join("hostkey.pub"))
            .output()
            .expect("run ssh-keygen -l");
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        let pin = text
            .split_whitespace()
            .find(|tok| tok.starts_with("SHA256:"))
            .expect("SHA256: token in ssh-keygen -l output")
            .to_string();

        // Ephemeral port: bind, read, release. The small race with another
        // process grabbing it is accepted.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();

        let mut args: Vec<String> = [
            "-D",
            "-e",
            "-f",
            "/dev/null",
            "-p",
            &port.to_string(),
            "-o",
            "ListenAddress=127.0.0.1",
            "-h",
            key_path.to_str().unwrap(),
            "-o",
            "UsePAM=no",
            "-o",
            "PidFile=none",
            "-o",
            "LogLevel=VERBOSE",
            "-o",
            "MaxStartups=10",
            "-o",
            "PerSourcePenalties=no",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        for opt in extra_options {
            args.push("-o".to_string());
            args.push(opt.to_string());
        }
        let command_line = format!("{SSHD} {}", args.join(" "));
        let mut child = Command::new(SSHD)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sshd");

        let stderr = child.stderr.take().unwrap();
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&log);
        let reader = thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                sink.lock().unwrap().push(line);
            }
        });

        let mut sshd = Sshd {
            child,
            port,
            pin,
            command_line,
            log,
            reader: Some(reader),
            dir,
        };
        sshd.wait_for_listening()?;
        eprintln!("--- sshd command: {}", sshd.command_line);
        eprintln!("--- ssh-keygen -lf pin: {}", sshd.pin);
        Ok(sshd)
    }

    fn wait_for_listening(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if self.log_text().contains("Server listening on") {
                return Ok(());
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                if let Some(reader) = self.reader.take() {
                    let _ = reader.join();
                }
                return Err(format!("({status})\n{}", self.log_text()));
            }
            assert!(
                Instant::now() < deadline,
                "sshd did not report listening:\n{}",
                self.log_text()
            );
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }

    /// Waits (bounded) until the log contains `needle`; sshd-session logs
    /// the connection close slightly after the client's socket is shut down.
    fn wait_for_log(&self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = self.log_text();
            if text.contains(needle) || Instant::now() >= deadline {
                return text;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn port(&self) -> String {
        self.port.to_string()
    }

    /// Runs `tatami-client handshake` against this daemon.
    fn handshake(&self, pin: &str, extra: &[&str]) -> Output {
        let port = self.port();
        let mut args = vec![
            "handshake",
            "127.0.0.1",
            "--port",
            &port,
            "--host-key-sha256",
            pin,
            "--connect-timeout",
            "5s",
            "--timeout",
            "10s",
        ];
        args.extend_from_slice(extra);
        let o = client(&args);
        eprintln!("--- exit: {:?}", o.status.code());
        eprintln!("--- stdout:\n{}", stdout(&o));
        eprintln!("--- stderr:\n{}", stderr(&o));
        o
    }
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn assert_no_authentication_attempt(log: &str) {
    for forbidden in [
        "Accepted ",
        "Failed ",
        "Invalid user",
        "userauth_request",
        "Postponed",
    ] {
        assert!(
            !log.contains(forbidden),
            "log shows an authentication attempt ({forbidden}):\n{log}"
        );
    }
}

/// Flips one character of a `SHA256:` pin so it still parses but differs.
fn flip_pin(pin: &str) -> String {
    let mut chars: Vec<char> = pin.chars().collect();
    let idx = 10;
    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
    let flipped: String = chars.into_iter().collect();
    assert_ne!(flipped, pin);
    flipped
}

#[test]
fn help_documents_the_handshake_command() {
    let o = client(&["--help"]);
    assert_eq!(code(&o), 0);
    let out = stdout(&o);
    assert!(out.contains("tatami-client handshake HOST"));
    assert!(out.contains("--host-key-sha256 'SHA256:...'"));
    assert!(out.contains("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"));
    assert!(out.contains("No user is ever authenticated"));
}

#[test]
fn handshake_usage_errors_exit_2() {
    let padded = format!("{VALID_PIN}=");
    let cases: &[(&[&str], &str)] = &[
        (&["handshake", "127.0.0.1"], "requires --host-key-sha256"),
        (
            &["handshake", "127.0.0.1", "--host-key-sha256"],
            "requires a value",
        ),
        (
            &["handshake", "127.0.0.1", "--host-key-sha256", "SHA256:abc"],
            "43 characters, found 3",
        ),
        (
            &["handshake", "127.0.0.1", "--host-key-sha256", &padded],
            "padded",
        ),
        (
            &[
                "handshake",
                "127.0.0.1",
                "--host-key-sha256",
                &VALID_PIN[7..],
            ],
            "must start with `SHA256:`",
        ),
        (
            &[
                "handshake",
                "127.0.0.1",
                "--host-key-sha256",
                VALID_PIN,
                "--port",
                "0",
            ],
            "invalid port",
        ),
        (
            &[
                "handshake",
                "127.0.0.1",
                "--host-key-sha256",
                VALID_PIN,
                "--port",
                "99999",
            ],
            "invalid port",
        ),
        (
            &[
                "handshake",
                "127.0.0.1",
                "--host-key-sha256",
                VALID_PIN,
                "--timeout",
                "0s",
            ],
            "greater than zero",
        ),
        (
            &["handshake", "--host-key-sha256", VALID_PIN],
            "requires a HOST",
        ),
        (
            &["handshake", "h", "--host-key-sha256", VALID_PIN, "--nope"],
            "unknown option",
        ),
    ];
    for (args, expected) in cases {
        let o = client(args);
        let err = stderr(&o);
        assert_eq!(code(&o), 2, "args {args:?}: {err}");
        assert!(stdout(&o).is_empty(), "usage errors must not write stdout");
        assert!(err.contains("Usage:"), "{err}");
        assert!(err.contains(expected), "args {args:?}: {err}");
    }

    // Pin errors tell the operator where to get the pin, and never to copy
    // it from a probe of the same (unauthenticated) connection.
    for args in [
        &["handshake", "127.0.0.1"][..],
        &["handshake", "127.0.0.1", "--host-key-sha256", "SHA256:abc"],
    ] {
        let err = stderr(&client(args));
        let first_line = err.lines().next().unwrap_or_default();
        assert!(
            first_line.contains("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"),
            "{first_line}"
        );
        assert!(!first_line.contains("probe"), "{first_line}");
    }
}

#[test]
fn handshake_connect_refused_exits_1() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let o = client(&[
        "handshake",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--host-key-sha256",
        VALID_PIN,
        "--connect-timeout",
        "2s",
    ]);
    let out = stdout(&o);
    assert_eq!(code(&o), 1, "{out}");
    assert!(out.contains("Connected to: (not connected)"));
    assert!(out.contains("Outcome: not connected;"));
    assert!(out.contains("(code: connect_failed)"));
    assert!(out.contains("user_authenticated: false"));
    assert!(stderr(&o).contains("handshake incomplete (connect_failed)"));

    let o = client(&[
        "handshake",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--host-key-sha256",
        VALID_PIN,
        "--connect-timeout",
        "2s",
        "--json",
    ]);
    assert_eq!(code(&o), 1);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("valid JSON");
    assert_eq!(v["outcome_code"], "connect_failed");
    assert_eq!(v["user_authenticated"], false);
    assert_eq!(v["key_exchange_completed"], false);
    assert!(v["host_trusted"].is_null());
    assert!(v["peer"].is_null());
}

#[test]
fn correct_pin_against_sshd_exits_0() {
    if !openssh_available("correct_pin_against_sshd_exits_0") {
        return;
    }
    let sshd = Sshd::start(&[]);
    let o = sshd.handshake(&sshd.pin, &[]);
    let log = sshd.wait_for_log("[preauth]");
    eprintln!("--- sshd log:\n{log}\n---");

    let out = stdout(&o);
    assert_eq!(code(&o), 0, "{out}\n{}", stderr(&o));
    assert!(!stderr(&o).contains("incomplete"), "{}", stderr(&o));
    assert!(
        !out.contains('\x1b'),
        "escape sequences must not reach stdout"
    );

    assert!(out.contains("Server identification: SSH-2.0-OpenSSH_"));
    assert!(out.contains("    selected: curve25519-sha256"));
    assert!(out.contains("    selected: ssh-ed25519"));
    assert!(out.contains("    selected: aes128-gcm@openssh.com"));
    assert!(out.contains("    selected: implicit (AEAD)"));
    assert!(out.contains("MAC lists ignored per draft-miller-sshm-aes-gcm-01 §2"));
    assert!(out.contains("    selected: none"));
    assert!(out.contains(
        "  Markers offered by client: [ext-info-c, kex-strict-c-v00@openssh.com, kex-strict-c]"
    ));
    assert!(out.contains("  EXT_INFO advertised by server (ext-info-s): yes"));
    assert!(out.contains("  Result: negotiated"));

    assert!(out.contains("Strict KEX (draft-ietf-sshm-strict-kex):"));
    assert!(out.contains(
        "  offered by client: kex-strict-c-v00@openssh.com (pre-standard), kex-strict-c (standard)"
    ));
    assert!(out.contains("  offered by server: kex-strict-s-v00@openssh.com (pre-standard)"));
    assert!(out.contains("  negotiated: true"));
    assert!(out.contains("  KEXINIT was first packet: yes"));

    assert!(out.contains("Server host key:"));
    assert!(out.contains("  algorithm: ssh-ed25519"));
    assert!(out.contains(&format!("  fingerprint: {}", sshd.pin)));
    assert!(out.contains("  blob length: 51 byte(s)"));
    assert!(out.contains("  signature: valid"));
    assert!(out.contains("  source: pinned fingerprint (--host-key-sha256)"));
    assert!(out.contains(&format!("  pinned: {}", sshd.pin)));
    assert!(out.contains("  result: trusted"));

    assert!(out.contains("  NEWKEYS sent: yes"));
    assert!(out.contains("  NEWKEYS received: yes"));
    assert!(out.contains("  protected packets sent: 2"));
    assert!(out.contains("EXT_INFO (RFC 8308):\n  received: yes"));
    assert!(out.contains("  server-sig-algs: ["));
    assert!(out.contains("ssh-ed25519"));
    assert!(out.contains("Service accepted: ssh-userauth"));
    assert!(out.contains("Outcome: completed"));
    assert!(out.contains("(code: completed)"));
    assert!(out.contains("User authentication: not attempted"));
    assert!(out.contains("user_authenticated: false"));
    assert!(out.contains("Rekeying: not supported by this diagnostic"));
    assert!(out.contains("Elapsed after connect: "));

    // sshd decrypted our protected DISCONNECT and closed in the userauth
    // phase; no authentication was attempted.
    assert!(log.contains("tatami diagnostic complete"), "{log}");
    assert!(log.contains("[preauth]"), "{log}");
    assert_no_authentication_attempt(&log);
}

#[test]
fn wrong_pin_against_sshd_exits_1_without_newkeys() {
    if !openssh_available("wrong_pin_against_sshd_exits_1_without_newkeys") {
        return;
    }
    let sshd = Sshd::start(&[]);
    let wrong = flip_pin(&sshd.pin);
    let o = sshd.handshake(&wrong, &[]);
    let log = sshd.wait_for_log("Connection closed by");
    eprintln!("--- sshd log:\n{log}\n---");

    let out = stdout(&o);
    assert_eq!(code(&o), 1, "{out}");
    assert!(stderr(&o).contains("handshake incomplete (host_not_trusted)"));

    // The key is genuine (signature verified); it is just not the pinned one.
    assert!(out.contains("  signature: valid"));
    assert!(out.contains(&format!("  fingerprint: {}", sshd.pin)));
    assert!(out.contains(&format!("  pinned: {wrong}")));
    assert!(out.contains("  result: untrusted (fingerprint mismatch)"));
    assert!(out.contains("  NEWKEYS sent: no"));
    assert!(out.contains("  NEWKEYS received: no"));
    assert!(out.contains("  protected packets sent: 0"));
    assert!(out.contains("EXT_INFO (RFC 8308): protected phase not reached"));
    assert!(!out.contains("Service accepted"), "{out}");
    assert!(out.contains("Outcome: host key not trusted"));
    assert!(out.contains("(code: host_not_trusted)"));
    assert!(out.contains("user_authenticated: false"));

    // Closed during KEX: no DISCONNECT from us, no service request.
    assert!(log.contains("Connection closed by"), "{log}");
    assert!(!log.contains("Received disconnect"), "{log}");
    assert!(!log.contains("tatami diagnostic complete"), "{log}");
    assert_no_authentication_attempt(&log);
}

#[test]
fn json_output_against_sshd_parses() {
    if !openssh_available("json_output_against_sshd_parses") {
        return;
    }
    let sshd = Sshd::start(&[]);
    let o = sshd.handshake(&sshd.pin, &["--json"]);
    let log = sshd.wait_for_log("[preauth]");
    eprintln!("--- sshd log:\n{log}\n---");

    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let text = stdout(&o);
    assert_eq!(text.matches('\n').count(), 1, "exactly one line:\n{text}");
    assert!(text.ends_with('\n'));
    let v: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    assert_eq!(v["schema"], 1);
    assert_eq!(v["event"], "tcp_handshake");
    assert_eq!(v["target"]["host"], "127.0.0.1");
    assert_eq!(v["target"]["port"], u64::from(sshd.port));
    assert_eq!(v["user_authenticated"], false);
    assert_eq!(v["rekey_supported"], false);
    assert_eq!(v["host_trusted"], true);
    assert_eq!(v["trust_policy"], "pinned_fingerprint");
    assert_eq!(v["trust_source"], "pinned_fingerprint");
    assert!(v["untrusted_reason"].is_null());
    assert_eq!(v["outcome_code"], "completed");
    assert_eq!(v["key_exchange_completed"], true);
    assert_eq!(v["host_key_signature_valid"], true);
    assert_eq!(v["fingerprint_sha256"], sshd.pin.as_str());
    assert_eq!(v["host_key"]["fingerprint_sha256"], sshd.pin.as_str());
    assert_eq!(v["pinned_fingerprint_sha256"], sshd.pin.as_str());
    assert_eq!(v["host_key"]["algorithm"], "ssh-ed25519");
    assert_eq!(v["host_key"]["blob_len"], 51);
    assert_eq!(v["selected"]["kex"], "curve25519-sha256");
    assert_eq!(
        v["selected"]["encryption_client_to_server"],
        "aes128-gcm@openssh.com"
    );
    assert_eq!(
        v["selected"]["encryption_server_to_client"],
        "aes128-gcm@openssh.com"
    );
    assert_eq!(v["selected"]["mac_client_to_server"], "implicit (AEAD)");
    assert_eq!(v["selected"]["compression_client_to_server"], "none");
    assert_eq!(v["selected"]["ext_info"], true);
    assert_eq!(v["strict_kex"]["offered_pre_standard"], true);
    assert_eq!(v["strict_kex"]["offered_standard"], true);
    assert_eq!(v["strict_kex"]["server_pre_standard"], true);
    assert_eq!(v["strict_kex"]["negotiated"], true);
    assert_eq!(v["kexinit_was_first_packet"], true);
    assert_eq!(
        v["advertised"]["client"]["kex_algorithms"][0],
        "curve25519-sha256"
    );
    assert_eq!(
        v["advertised"]["client"]["encryption_client_to_server"][0],
        "aes128-gcm@openssh.com"
    );
    assert!(
        v["advertised"]["server"]["kex_algorithms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|k| k == "curve25519-sha256")
    );
    assert!(
        v["server_identification"]["software_version"]
            .as_str()
            .unwrap()
            .starts_with("OpenSSH_")
    );
    assert_eq!(v["newkeys_sent"], true);
    assert_eq!(v["newkeys_received"], true);
    assert_eq!(v["protected_packets_sent"], 2);
    assert_eq!(v["ext_info"]["received"], true);
    assert!(
        v["ext_info"]["server_sig_algs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == "ssh-ed25519")
    );
    assert_eq!(v["service_accepted"], "ssh-userauth");
    assert!(v["server_disconnect"].is_null());
    assert!(v["negotiation_error_code"].is_null());
    assert!(v["elapsed_ms"].is_u64());

    // No key material anywhere: the only 32-byte-looking values are the
    // fingerprint and the two public cookies.
    let all = text.to_lowercase();
    for forbidden in ["private", "secret", "shared_secret", "session_id", "iv"] {
        assert!(
            !all.contains(&format!("\"{forbidden}\"")),
            "field named {forbidden} in JSON:\n{text}"
        );
    }
    assert_no_authentication_attempt(&log);
}

#[test]
fn mismatch_profile_sshd_fails_negotiation_and_exits_1() {
    if !openssh_available("mismatch_profile_sshd_fails_negotiation_and_exits_1") {
        return;
    }
    let sshd = Sshd::start(&["Ciphers=aes256-ctr"]);
    let o = sshd.handshake(&sshd.pin, &[]);
    let log = sshd.wait_for_log("no matching cipher");
    eprintln!("--- sshd log:\n{log}\n---");

    let out = stdout(&o);
    assert_eq!(code(&o), 1, "{out}");
    assert!(stderr(&o).contains("handshake incomplete (negotiation_failed)"));
    assert!(out.contains("no common cipher"), "{out}");
    assert!(out.contains("    server advertised: [aes256-ctr]"));
    assert!(out.contains("    client advertised: [aes128-gcm@openssh.com]"));
    assert!(out.contains("  Result: failed; no common cipher client-to-server"));
    assert!(out.contains("Server host key: not received"));
    assert!(out.contains("  NEWKEYS sent: no"));
    assert!(!out.contains("Service accepted"));
    assert!(out.contains("Outcome: negotiation failed;"));
    assert!(out.contains("(code: negotiation_failed)"));
    assert!(log.contains("no matching cipher found"), "{log}");

    let o = sshd.handshake(&sshd.pin, &["--json"]);
    assert_eq!(code(&o), 1);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).expect("valid JSON");
    assert_eq!(v["outcome_code"], "negotiation_failed");
    assert_eq!(v["negotiation_error_code"], "no_common_cipher");
    assert!(v["selected"].is_null());
    assert!(v["host_key"].is_null());
    assert!(v["host_trusted"].is_null());
    assert_eq!(v["key_exchange_completed"], false);
    assert_eq!(v["user_authenticated"], false);
    assert_eq!(
        v["advertised"]["server"]["encryption_client_to_server"][0],
        "aes256-ctr"
    );
    assert_no_authentication_attempt(&log);
}

#[test]
fn matching_profile_sshd_with_markers_disabled_still_completes() {
    if !openssh_available("matching_profile_sshd_with_markers_disabled_still_completes") {
        return;
    }
    let sshd = Sshd::start(&[
        "KexAlgorithms=curve25519-sha256",
        "HostKeyAlgorithms=ssh-ed25519",
        "Ciphers=aes128-gcm@openssh.com",
    ]);
    let o = sshd.handshake(&sshd.pin, &["--no-ext-info", "--no-strict-kex"]);
    let log = sshd.wait_for_log("[preauth]");
    eprintln!("--- sshd log:\n{log}\n---");

    let out = stdout(&o);
    assert_eq!(code(&o), 0, "{out}\n{}", stderr(&o));
    assert!(out.contains(
        "    server advertised: [curve25519-sha256, ext-info-s, kex-strict-s-v00@openssh.com]"
    ));
    assert!(out.contains("  Markers offered by client: []"));
    assert!(out.contains("  offered by client: (none)"));
    assert!(out.contains("  negotiated: false"));
    assert!(out.contains("Service accepted: ssh-userauth"));
    assert!(out.contains("Outcome: completed"));
    assert!(log.contains("tatami diagnostic complete"), "{log}");
    assert_no_authentication_attempt(&log);
}
