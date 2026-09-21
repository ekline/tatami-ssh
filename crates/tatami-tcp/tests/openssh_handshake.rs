//! Interoperability tests against a real, locally started OpenSSH `sshd`.
//!
//! Each test generates an ephemeral Ed25519 host key with `ssh-keygen`,
//! takes the operator's pin from `ssh-keygen -lf` (an independent source
//! for the fingerprint), starts `sshd -D -e -f /dev/null` on an ephemeral
//! loopback port with stderr captured, waits for its "Server listening"
//! line, runs the handshake, then kills the daemon and removes the key.
//!
//! When `/usr/sbin/sshd` or `/usr/bin/ssh-keygen` is not executable the
//! tests print a skip notice and return, so CI without OpenSSH stays green;
//! locally they run.

#![cfg(all(feature = "std", feature = "kex"))]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use tatami_keys::fingerprint::Sha256Fingerprint;
use tatami_keys::trust::PinnedSha256;
use tatami_tcp::handshake::{HandshakeConfig, HandshakeOutcome};
use tatami_tcp::io::handshake::{HandshakeEnd, HandshakeIo, HandshakeRun, run_handshake};
use tatami_tcp::negotiate::NegotiationError;

const SSHD: &str = "/usr/sbin/sshd";
const SSH_KEYGEN: &str = "/usr/bin/ssh-keygen";

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
/// wiped between commands in some environments).
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
    let dir = target.join("openssh-handshake").join(format!(
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
    pin: Sha256Fingerprint,
    fingerprint_text: String,
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
        let dir = scratch_dir();
        let key_path = dir.join("hostkey");
        let status = Command::new(SSH_KEYGEN)
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key_path)
            .status()
            .expect("run ssh-keygen");
        assert!(status.success(), "ssh-keygen failed: {status}");

        let config = Command::new(SSHD)
            .args(["-T", "-f", "/dev/null", "-h"])
            .arg(&key_path)
            .output()
            .expect("query sshd configuration");
        assert!(
            config.status.success(),
            "sshd configuration query failed ({}):\n{}",
            config.status,
            String::from_utf8_lossy(&config.stderr)
        );
        let supports_penalties = String::from_utf8_lossy(&config.stdout)
            .lines()
            .any(|line| line.split_whitespace().next() == Some("persourcepenalties"));

        // The operator's independent fingerprint source.
        let output = Command::new(SSH_KEYGEN)
            .arg("-lf")
            .arg(dir.join("hostkey.pub"))
            .output()
            .expect("run ssh-keygen -l");
        assert!(output.status.success());
        let text = String::from_utf8_lossy(&output.stdout);
        let fingerprint_text = text
            .split_whitespace()
            .find(|tok| tok.starts_with("SHA256:"))
            .expect("SHA256: token in ssh-keygen -l output")
            .to_string();
        let pin: Sha256Fingerprint = fingerprint_text.parse().expect("parse fingerprint");

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
            "DenyUsers=*",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        // Avoid diagnostic disconnect penalties on newer OpenSSH releases;
        // older releases do not recognize this option.
        if supports_penalties {
            args.extend(["-o".to_string(), "PerSourcePenalties=no".to_string()]);
        }
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
            fingerprint_text,
            command_line,
            log,
            reader: Some(reader),
            dir,
        };
        sshd.wait_for_listening()?;
        Ok(sshd)
    }

    /// Bounded polling for sshd's own readiness line; no probe connection
    /// is made, so the log stays about the test's connection only.
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
    /// the connection close slightly after our socket is shut down.
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

    fn run(&self, config: HandshakeConfig, pin: Sha256Fingerprint) -> HandshakeRun {
        let io = HandshakeIo {
            connect_timeout: Duration::from_secs(5),
            overall_timeout: Duration::from_secs(10),
            read_chunk: 4096,
        };
        let stream = io.connect("127.0.0.1", self.port).expect("connect to sshd");
        run_handshake(stream, config, &PinnedSha256(pin), &io).expect("run handshake")
    }

    fn print_evidence(&self, run: &HandshakeRun, log: &str) {
        let r = &run.report;
        eprintln!("--- sshd command: {}", self.command_line);
        eprintln!("--- ssh-keygen -lf pin: {}", self.fingerprint_text);
        eprintln!(
            "--- server identification: {}",
            r.server_identification
                .as_ref()
                .map(|i| String::from_utf8_lossy(&i.line).into_owned())
                .unwrap_or_default()
        );
        eprintln!("--- end: {}", run.end.label());
        eprintln!("--- selected: {:?}", r.selected);
        eprintln!("--- strict_kex: {:?}", r.strict_kex);
        eprintln!(
            "--- kexinit_was_first_packet: {:?}",
            r.kexinit_was_first_packet
        );
        eprintln!("--- host_key: {:?}", r.host_key);
        eprintln!(
            "--- signature_valid: {:?}, trust: {:?}",
            r.signature_valid, r.trust
        );
        eprintln!(
            "--- newkeys sent/received: {}/{}, protected sent/received: {}/{}",
            r.newkeys_sent,
            r.newkeys_received,
            r.protected_packets_sent,
            r.protected_packets_received
        );
        eprintln!("--- ext_info: {:?}", r.ext_info);
        eprintln!("--- service_accepted: {:?}", r.service_accepted);
        eprintln!("--- user_authenticated: {}", r.user_authenticated);
        eprintln!("--- elapsed: {:?}", run.elapsed);
        eprintln!("--- sshd log:\n{log}\n---");
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

fn outcome(run: &HandshakeRun) -> &HandshakeOutcome {
    match &run.end {
        HandshakeEnd::Finished(o) => o,
        other => panic!("handshake did not finish: {other:?}"),
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

#[test]
fn default_sshd_completes_the_profile_handshake() {
    if !openssh_available("default_sshd_completes_the_profile_handshake") {
        return;
    }
    let sshd = Sshd::start(&[]);
    let run = sshd.run(HandshakeConfig::default(), sshd.pin);
    let log = sshd.wait_for_log("[preauth]");
    sshd.print_evidence(&run, &log);

    assert_eq!(
        outcome(&run),
        &HandshakeOutcome::Completed,
        "{}",
        run.end.label()
    );
    let r = &run.report;
    let ident = r
        .server_identification
        .as_ref()
        .expect("server identification");
    assert!(ident.software_version.starts_with("OpenSSH_"), "{ident:?}");
    let selected = r.selected.as_ref().expect("negotiated");
    assert_eq!(selected.kex, "curve25519-sha256");
    assert_eq!(selected.host_key, "ssh-ed25519");
    assert_eq!(
        selected.encryption_client_to_server,
        "aes128-gcm@openssh.com"
    );
    assert_eq!(
        selected.encryption_server_to_client,
        "aes128-gcm@openssh.com"
    );
    assert_eq!(selected.mac_client_to_server.as_str(), "implicit (AEAD)");
    assert_eq!(selected.compression_client_to_server, "none");
    assert!(selected.ext_info, "OpenSSH offers ext-info-s");
    assert!(
        r.strict_kex.negotiated,
        "OpenSSH offers kex-strict-s-v00@openssh.com"
    );
    assert!(r.strict_kex.server_pre_standard);
    assert_eq!(r.kexinit_was_first_packet, Some(true));
    let host_key = r.host_key.as_ref().expect("host key");
    assert_eq!(host_key.algorithm, "ssh-ed25519");
    assert_eq!(
        host_key.fingerprint, sshd.pin,
        "fingerprint equals ssh-keygen -l"
    );
    assert_eq!(host_key.fingerprint.to_string(), sshd.fingerprint_text);
    assert_eq!(r.signature_valid, Some(true));
    assert!(r.trust.map(|t| t.is_trusted()).unwrap_or(false));
    assert!(r.newkeys_sent && r.newkeys_received);
    let ext = r.ext_info.as_ref().expect("protected phase reached");
    assert!(ext.received, "OpenSSH sends EXT_INFO right after NEWKEYS");
    let sig_algs = ext
        .server_sig_algs
        .as_ref()
        .expect("server-sig-algs present");
    assert!(sig_algs.iter().any(|a| a == "ssh-ed25519"), "{sig_algs:?}");
    assert!(ext.extension_names.iter().any(|n| n == "server-sig-algs"));
    assert_eq!(r.service_accepted.as_deref(), Some("ssh-userauth"));
    assert_eq!(
        r.protected_packets_sent, 2,
        "SERVICE_REQUEST and DISCONNECT"
    );
    assert!(
        r.protected_packets_received >= 2,
        "EXT_INFO and SERVICE_ACCEPT"
    );
    assert!(!r.user_authenticated);

    // sshd decrypted our protected DISCONNECT and closed in the userauth
    // phase; no authentication was attempted.
    assert!(log.contains("[preauth]"), "no preauth close in log:\n{log}");
    assert!(
        log.contains("tatami diagnostic complete"),
        "sshd did not log our DISCONNECT description:\n{log}"
    );
    assert!(
        log.contains("Received disconnect") || log.contains("Disconnected from"),
        "no disconnect line:\n{log}"
    );
    assert_no_authentication_attempt(&log);
}

#[test]
fn wrong_pin_stops_before_newkeys_against_sshd() {
    if !openssh_available("wrong_pin_stops_before_newkeys_against_sshd") {
        return;
    }
    let sshd = Sshd::start(&[]);
    // Flip one character of the operator's fingerprint (keep it valid
    // base64 so the pin still parses).
    let mut chars: Vec<char> = sshd.fingerprint_text.chars().collect();
    let idx = 10;
    chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
    let flipped: String = chars.into_iter().collect();
    assert_ne!(flipped, sshd.fingerprint_text);
    let wrong_pin: Sha256Fingerprint = flipped.parse().expect("flipped pin parses");

    let run = sshd.run(HandshakeConfig::default(), wrong_pin);
    let log = sshd.wait_for_log("Connection closed by");
    sshd.print_evidence(&run, &log);

    assert!(
        matches!(outcome(&run), HandshakeOutcome::HostNotTrusted { .. }),
        "{}",
        run.end.label()
    );
    let r = &run.report;
    assert_eq!(
        r.signature_valid,
        Some(true),
        "the key is genuine, just not the pinned one"
    );
    assert_eq!(r.host_key.as_ref().unwrap().fingerprint, sshd.pin);
    assert!(!r.newkeys_sent);
    assert!(!r.newkeys_received);
    assert_eq!(r.protected_packets_sent, 0);
    assert!(r.ext_info.is_none(), "protected phase never began");
    assert!(r.service_accepted.is_none());

    // The connection closed during KEX: no disconnect message from us, no
    // service request, no authentication.
    assert!(log.contains("Connection closed by"), "{log}");
    assert!(!log.contains("Received disconnect"), "{log}");
    assert!(!log.contains("tatami diagnostic complete"), "{log}");
    assert_no_authentication_attempt(&log);
}

#[test]
fn sshd_restricted_to_the_profile_completes() {
    if !openssh_available("sshd_restricted_to_the_profile_completes") {
        return;
    }
    let sshd = Sshd::start(&[
        "KexAlgorithms=curve25519-sha256",
        "HostKeyAlgorithms=ssh-ed25519",
        "Ciphers=aes128-gcm@openssh.com",
    ]);
    let run = sshd.run(HandshakeConfig::default(), sshd.pin);
    let log = sshd.wait_for_log("[preauth]");
    sshd.print_evidence(&run, &log);

    assert_eq!(
        outcome(&run),
        &HandshakeOutcome::Completed,
        "{}",
        run.end.label()
    );
    let r = &run.report;
    let server = r.advertised.server.as_ref().expect("server KEXINIT");
    // With the restriction the server's method list is exactly our method
    // plus its markers.
    assert!(
        server
            .kex_algorithms
            .iter()
            .any(|k| k == "curve25519-sha256")
    );
    assert!(
        server
            .kex_algorithms
            .iter()
            .all(|k| k == "curve25519-sha256"
                || k.starts_with("ext-info")
                || k.starts_with("kex-strict")),
        "{:?}",
        server.kex_algorithms
    );
    assert_eq!(
        server.encryption_client_to_server,
        ["aes128-gcm@openssh.com"]
    );
    assert_eq!(server.server_host_key_algorithms, ["ssh-ed25519"]);
    assert_eq!(r.selected.as_ref().unwrap().kex, "curve25519-sha256");
    assert_eq!(r.service_accepted.as_deref(), Some("ssh-userauth"));
    assert!(log.contains("tatami diagnostic complete"), "{log}");
    assert_no_authentication_attempt(&log);
}

#[test]
fn sshd_outside_the_profile_fails_negotiation_cleanly() {
    if !openssh_available("sshd_outside_the_profile_fails_negotiation_cleanly") {
        return;
    }
    let sshd = Sshd::start(&["Ciphers=aes256-ctr"]);
    let run = sshd.run(HandshakeConfig::default(), sshd.pin);
    let log = sshd.wait_for_log("no matching cipher");
    sshd.print_evidence(&run, &log);

    assert!(
        matches!(
            outcome(&run),
            HandshakeOutcome::NegotiationFailed(NegotiationError::NoCommonCipher(_))
        ),
        "{}",
        run.end.label()
    );
    let r = &run.report;
    assert!(r.selected.is_none());
    let server = r
        .advertised
        .server
        .as_ref()
        .expect("server KEXINIT was received");
    assert_eq!(server.encryption_client_to_server, ["aes256-ctr"]);
    assert!(r.host_key.is_none());
    assert!(!r.newkeys_sent);
    // sshd reached the same conclusion from its side.
    assert!(log.contains("no matching cipher found"), "{log}");
    assert!(
        log.contains("aes128-gcm@openssh.com"),
        "our offer is in sshd's log:\n{log}"
    );
    assert_no_authentication_attempt(&log);
}
