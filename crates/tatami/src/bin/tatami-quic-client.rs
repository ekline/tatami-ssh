//! `tatami-quic-client`: thin command-line entry point over
//! `tatami::quic_diag::client`.
//!
//! The only command is `handshake`, an **experimental** QUIC v1 / TLS 1.3
//! handshake against a server whose certificate (or test root) the caller
//! names explicitly. It sends no application data of any kind — no stream,
//! no datagram, and therefore no SSH identification or `KEXINIT` — and
//! closes after the handshake. The ALPN value is configurable and
//! unregistered; no interoperability with any other implementation is
//! claimed; 0-RTT and resumption are disabled.
//!
//! Exit status: 0 for a completed handshake; 1 for a failed or timed-out
//! handshake or a runtime failure; 2 for usage errors.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use tatami::quic::diag::identity::CertificateSha256;
use tatami::quic::diag::tls::ClientTrust;
use tatami::quic_diag::client::{Options, run};

const NAME: &str = "tatami-quic-client";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-quic-client handshake HOST --alpn PROTO
                               (--cert-sha256 FINGERPRINT | --root-cert FILE)
                               [--port PORT] [--server-name NAME]
                               [--exporter-probe] [--timeout DURATION] [--json]
  tatami-quic-client --help
  tatami-quic-client --version

Commands:
  handshake  EXPERIMENTAL. Open a QUIC v1 connection to HOST:PORT over UDP,
             complete a TLS 1.3 handshake, report the outcome, negotiated
             ALPN and whether the TLS exporter is available, then close with
             an application CONNECTION_CLOSE. No stream is opened and no
             datagram is sent, so nothing SSH (no identification, no
             KEXINIT) can be sent; this is not an SSH client and not an
             SSH-over-QUIC client. 0-RTT and session resumption are disabled.

Options:
  --alpn PROTO             ALPN value to offer (required; repeat for several,
                           in preference order). Experimental, UNREGISTERED;
                           no interoperability with any other implementation
                           is claimed. There is no default.
  --cert-sha256 FP         Accept only the server certificate whose DER hashes
                           to FP ('SHA256:' + 43 unpadded base64 chars, as
                           printed by tatami-quic-server). FP is a certificate
                           fingerprint, not an SSH host-key fingerprint. The
                           TLS signature is still verified.
  --root-cert FILE         Instead of a pin, trust certificates chaining to
                           the single PEM certificate in FILE and valid for
                           --server-name. No system trust store is used.
  --port PORT              UDP port (default 4433).
  --server-name NAME       TLS server name (default HOST). A DNS name is sent
                           as SNI; an IP literal is not.
  --exporter-probe         After completion, call the TLS exporter with an
                           experimental label and report only whether it
                           succeeded. Output is discarded; it is not a
                           session binding.
  --timeout DURATION       Handshake deadline (default 5s).
  --json                   Print one JSON object instead of text.
  DURATION                 e.g. 5s, 500ms, 2m; must be > 0.

HOST may be a name or a numeric IPv4/IPv6 address. IPv6 addresses are given
bare (no brackets); the port is always a separate option.

Exit status: 0 completed handshake; 1 failed/timed out/runtime error; 2 usage.
";

enum Command {
    Help,
    Version,
    Handshake(Options, bool),
}

#[derive(Debug)]
struct UsageError(String);

fn parse_duration(s: &str) -> Result<Duration, UsageError> {
    let bad = || {
        UsageError(format!(
            "invalid duration {s:?}; use forms like 5s, 500ms or 2m"
        ))
    };
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(i) => s.split_at(i),
        None => (s, "s"),
    };
    let value: f64 = num.parse().map_err(|_| bad())?;
    let secs = match unit {
        "ms" => value / 1000.0,
        "s" => value,
        "m" => value * 60.0,
        _ => return Err(bad()),
    };
    if !secs.is_finite() || secs <= 0.0 {
        return Err(UsageError(format!(
            "duration {s:?} must be greater than zero"
        )));
    }
    Ok(Duration::from_secs_f64(secs))
}

fn parse_alpn(s: &str) -> Result<Vec<u8>, UsageError> {
    if s.is_empty() || s.len() > 255 {
        return Err(UsageError(format!(
            "--alpn value must be 1-255 bytes, got {} bytes",
            s.len()
        )));
    }
    Ok(s.as_bytes().to_vec())
}

fn read_root_cert(path: &str) -> Result<Vec<u8>, UsageError> {
    use tatami::quic::diag::rustls::pki_types::CertificateDer;
    use tatami::quic::diag::rustls::pki_types::pem::PemObject as _;
    let pem = std::fs::read(path)
        .map_err(|e| UsageError(format!("cannot read --root-cert {path:?}: {e}")))?;
    let der = CertificateDer::from_pem_slice(&pem).map_err(|e| {
        UsageError(format!(
            "--root-cert {path:?} does not contain one CERTIFICATE PEM block: {e}"
        ))
    })?;
    Ok(der.as_ref().to_vec())
}

fn parse_args(args: &[String]) -> Result<Command, UsageError> {
    let mut it = args.iter();
    let Some(first) = it.next() else {
        return Err(UsageError(String::from("missing command")));
    };
    match first.as_str() {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" | "version" => return Ok(Command::Version),
        "handshake" => {}
        s if s.starts_with('-') => return Err(UsageError(format!("unknown option {s:?}"))),
        other => {
            return Err(UsageError(format!(
                "unsupported command {other:?}; only `handshake` exists (this is not an SSH client)"
            )));
        }
    }

    let mut host: Option<String> = None;
    let mut port: u16 = 4433;
    let mut server_name: Option<String> = None;
    let mut alpn: Vec<Vec<u8>> = Vec::new();
    let mut trust: Option<ClientTrust> = None;
    let mut timeout = Duration::from_secs(5);
    let mut exporter_probe = false;
    let mut json = false;
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| {
            it.next()
                .ok_or_else(|| UsageError(format!("{flag} requires a value")))
        };
        match arg.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--port" => {
                let v = value("--port")?;
                port =
                    v.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| {
                        UsageError(format!("invalid port {v:?}; expected 1-65535"))
                    })?;
            }
            "--server-name" => {
                let v = value("--server-name")?;
                if v.is_empty() {
                    return Err(UsageError(String::from("--server-name must not be empty")));
                }
                server_name = Some(v.clone());
            }
            "--alpn" => alpn.push(parse_alpn(value("--alpn")?)?),
            "--cert-sha256" => {
                let v = value("--cert-sha256")?;
                let fp = CertificateSha256::parse(v)
                    .map_err(|e| UsageError(format!("invalid --cert-sha256 {v:?}: {e}")))?;
                if trust.is_some() {
                    return Err(UsageError(String::from(
                        "give exactly one of --cert-sha256 or --root-cert",
                    )));
                }
                trust = Some(ClientTrust::PinnedCertificateSha256(fp));
            }
            "--root-cert" => {
                let v = value("--root-cert")?;
                if trust.is_some() {
                    return Err(UsageError(String::from(
                        "give exactly one of --cert-sha256 or --root-cert",
                    )));
                }
                trust = Some(ClientTrust::RootCertificate(read_root_cert(v)?));
            }
            "--exporter-probe" => exporter_probe = true,
            "--timeout" => timeout = parse_duration(value("--timeout")?)?,
            "--json" => json = true,
            s if s.starts_with('-') => return Err(UsageError(format!("unknown option {s:?}"))),
            s => {
                if host.is_some() {
                    return Err(UsageError(format!("unexpected extra argument {s:?}")));
                }
                host = Some(String::from(s));
            }
        }
    }
    let host = host.ok_or_else(|| UsageError(String::from("handshake requires a HOST")))?;
    if host.is_empty() {
        return Err(UsageError(String::from("HOST must not be empty")));
    }
    if alpn.is_empty() {
        return Err(UsageError(String::from(
            "--alpn is required: the value is experimental and must be chosen explicitly",
        )));
    }
    let trust = trust.ok_or_else(|| {
        UsageError(String::from(
            "a trust anchor is required: --cert-sha256 FINGERPRINT (from the server's stderr) or --root-cert FILE",
        ))
    })?;
    let mut options = Options::new(host, port, alpn, trust);
    options.server_name = server_name;
    options.handshake_timeout = timeout;
    options.exporter_probe = exporter_probe;
    Ok(Command::Handshake(options, json))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(c) => c,
        Err(UsageError(msg)) => {
            eprintln!("{NAME}: {msg}");
            eprintln!();
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    match command {
        Command::Help => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Command::Version => {
            println!("{NAME} {VERSION}");
            ExitCode::SUCCESS
        }
        Command::Handshake(options, json) => {
            eprintln!(
                "{NAME}: EXPERIMENTAL QUIC v1/TLS 1.3 handshake to {}:{} (server name {}, ALPN {}, unregistered; timeout {:?}); 0-RTT disabled; no application data; not an SSH client",
                options.host,
                options.port,
                options.effective_server_name(),
                options
                    .alpn
                    .iter()
                    .map(|a| tatami::text::escape_bytes(a))
                    .collect::<Vec<_>>()
                    .join(","),
                options.handshake_timeout
            );
            let report = run(&options);
            let mut text = if json {
                report.to_json().to_json()
            } else {
                let mut s = String::new();
                // Writing into a String cannot fail.
                let _ = report.write_text(&mut s);
                s
            };
            if !text.ends_with('\n') {
                text.push('\n');
            }
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
            if report.is_complete() {
                ExitCode::SUCCESS
            } else {
                eprintln!("{NAME}: handshake not completed");
                ExitCode::from(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| String::from(*s)).collect()
    }

    #[test]
    fn parses_handshake() {
        let Command::Handshake(o, json) = parse_args(&args(&[
            "handshake",
            "2001:db8::10",
            "--port",
            "4434",
            "--server-name",
            "example.test",
            "--alpn",
            "tatami-diag/0",
            "--cert-sha256",
            FP,
            "--exporter-probe",
            "--timeout",
            "2s",
            "--json",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(o.host, "2001:db8::10");
        assert_eq!(o.port, 4434);
        assert_eq!(o.effective_server_name(), "example.test");
        assert_eq!(o.alpn, vec![b"tatami-diag/0".to_vec()]);
        assert!(matches!(o.trust, ClientTrust::PinnedCertificateSha256(_)));
        assert!(o.exporter_probe);
        assert_eq!(o.handshake_timeout, Duration::from_secs(2));
        assert!(json);

        let Command::Handshake(o, json) = parse_args(&args(&[
            "handshake",
            "h",
            "--alpn",
            "x",
            "--cert-sha256",
            FP,
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(o.port, 4433);
        assert_eq!(o.effective_server_name(), "h");
        assert!(!o.exporter_probe);
        assert!(!json);
    }

    #[test]
    fn rejects_bad_usage() {
        for a in [
            &[][..],
            &["handshake"],
            &["handshake", "h"],
            &["handshake", "h", "--alpn", "x"],
            &["handshake", "h", "--cert-sha256", FP],
            &[
                "handshake",
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                "SHA256:short",
            ],
            &[
                "handshake",
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                FP,
                "--port",
                "0",
            ],
            &[
                "handshake",
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                FP,
                "--timeout",
                "0s",
            ],
            &[
                "handshake",
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                FP,
                "--cert-sha256",
                FP,
            ],
            &[
                "handshake",
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                FP,
                "--bogus",
            ],
            &[
                "handshake",
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                FP,
                "extra",
            ],
            &[
                "handshake",
                "h",
                "--alpn",
                "x",
                "--root-cert",
                "/nonexistent/root.pem",
            ],
            &["connect", "h"],
        ] {
            assert!(parse_args(&args(a)).is_err(), "{a:?}");
        }
        assert!(matches!(parse_args(&args(&["--help"])), Ok(Command::Help)));
        assert!(matches!(
            parse_args(&args(&["--version"])),
            Ok(Command::Version)
        ));
    }

    #[test]
    fn help_states_the_caveats() {
        for word in [
            "EXPERIMENTAL",
            "UNREGISTERED",
            "no interoperability",
            "not an SSH client",
            "0-RTT",
            "not an SSH host-key fingerprint",
        ] {
            assert!(USAGE.contains(word), "help text lacks {word:?}");
        }
    }
}
