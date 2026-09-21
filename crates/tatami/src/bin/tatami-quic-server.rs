//! `tatami-quic-server`: thin command-line entry point over
//! `tatami::quic_diag::server`.
//!
//! The only command is `observe`, an **experimental** QUIC v1 / TLS 1.3
//! handshake observer. It completes handshakes with a generated test
//! identity and records what each client offered and what was negotiated,
//! then closes. The ALPN value is configurable and unregistered; no
//! interoperability with any other implementation is claimed; 0-RTT is
//! disabled; no stream or datagram is ever accepted. It is not an SSH
//! service: nothing SSH is sent or expected.
//!
//! Exit status: 0 for a clean finite or requested stop; 1 for an identity,
//! bind, output or runtime failure; 2 for usage errors. Individual peer
//! outcomes (failed handshakes, timeouts) are records, not process failures.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tatami::quic::diag::server::StopReason;
use tatami::quic_diag::server::{Options, prepare};

const NAME: &str = "tatami-quic-server";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-quic-server observe --alpn PROTO --identity-dir DIR
                             [--listen ADDR] [--generate-identity]
                             [--require-validation] [--timeout DURATION]
                             [--max-concurrent N] [--max-connections N]
                             [--run-for DURATION] [--format jsonl]
  tatami-quic-server observe --help
  tatami-quic-server --help
  tatami-quic-server --version

Commands:
  observe   EXPERIMENTAL. Listen for QUIC v1 connections on UDP, complete a
            TLS 1.3 handshake with a generated test certificate, record each
            attempt (source address and its validation state, offered vs
            negotiated ALPN, SNI, outcome) as JSON Lines on stdout, then
            close the connection with an application CONNECTION_CLOSE. No
            stream is accepted, no datagram is read, 0-RTT and resumption
            are disabled, nobody is authenticated. This is a handshake
            observer, not an SSH service and not an SSH-over-QUIC endpoint.

Options for observe:
  --alpn PROTO           ALPN value to accept (required; repeat for several,
                         in preference order). The value is experimental and
                         UNREGISTERED; no interoperability with any other
                         implementation is claimed. There is no default.
  --identity-dir DIR     Directory holding cert.pem and key.pem (required).
  --generate-identity    Generate a self-signed Ed25519 test identity into
                         DIR if none exists. Without this flag a missing
                         identity is an error; nothing is generated silently.
  --listen ADDR          UDP address to bind (default 127.0.0.1:4433). Use
                         IP:PORT or [IPv6]:PORT; port 0 picks an ephemeral
                         port and the bound address is reported.
  --require-validation   Answer each unvalidated Initial with a Retry and
                         accept only Initials carrying the token. Validation
                         proves reachability of the source address, nothing
                         about identity.
  --timeout DURATION     Per-connection handshake deadline; also the QUIC
                         idle timeout (default 5s).
  --max-concurrent N     Handshakes in progress at once (default 32). Excess
                         Initials are refused (CONNECTION_REFUSED) and
                         counted as dropped_at_capacity.
  --max-connections N    Stop after N accepted-or-refused connections
                         (default: unlimited). Retries are not counted.
  --run-for DURATION     Stop after this long (default: until stopped).
  --format jsonl         Output format; only jsonl is supported.
  DURATION               e.g. 5s, 500ms, 10m; must be > 0.

Output:
  JSON Lines on stdout (schema 1, transport \"quic\": quic_listener_started,
  quic_handshake_observation, overload, quic_listener_stopped). The
  certificate SHA-256 fingerprint is printed to stderr at start so a client
  can pin it with --cert-sha256; it is a certificate fingerprint, not an SSH
  host-key fingerprint. Offered ClientHello values in records are untrusted
  metadata supplied by the peer.

Exit status: 0 clean stop; 1 identity/bind/output/runtime failure; 2 usage.
";

#[derive(Debug)]
struct UsageError(String);

enum Command {
    Help,
    Version,
    Observe(Options),
}

fn parse_duration(s: &str) -> Result<Duration, UsageError> {
    let bad = || {
        UsageError(format!(
            "invalid duration {s:?}; use forms like 5s, 500ms or 10m"
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
        "h" => value * 3600.0,
        _ => return Err(bad()),
    };
    if !secs.is_finite() || secs <= 0.0 {
        return Err(UsageError(format!(
            "duration {s:?} must be greater than zero"
        )));
    }
    if secs > 366.0 * 86_400.0 {
        return Err(UsageError(format!("duration {s:?} is unreasonably large")));
    }
    Ok(Duration::from_secs_f64(secs))
}

fn parse_count(name: &str, s: &str) -> Result<u64, UsageError> {
    s.parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| UsageError(format!("{name} must be a positive integer, got {s:?}")))
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

fn parse_args(args: &[String]) -> Result<Command, UsageError> {
    let mut it = args.iter();
    let Some(first) = it.next() else {
        return Err(UsageError(String::from(
            "missing command; this build only offers `observe` (an experimental handshake observer, not an SSH service)",
        )));
    };
    match first.as_str() {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" | "version" => return Ok(Command::Version),
        "observe" => {}
        s if s.starts_with('-') => return Err(UsageError(format!("unknown option {s:?}"))),
        other => {
            return Err(UsageError(format!(
                "unsupported command {other:?}; only `observe` exists (no SSH service is implemented)"
            )));
        }
    }

    let mut alpn: Vec<Vec<u8>> = Vec::new();
    let mut identity_dir: Option<PathBuf> = None;
    let mut options = Options::new(Vec::new(), PathBuf::new());
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| {
            it.next()
                .ok_or_else(|| UsageError(format!("{flag} requires a value")))
        };
        match arg.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--alpn" => alpn.push(parse_alpn(value("--alpn")?)?),
            "--identity-dir" => identity_dir = Some(PathBuf::from(value("--identity-dir")?)),
            "--generate-identity" => options.generate_identity = true,
            "--listen" => {
                let v = value("--listen")?;
                let addr: SocketAddr = v.parse().map_err(|_| {
                    UsageError(format!(
                        "invalid listen address {v:?}; use IP:PORT or [IPv6]:PORT"
                    ))
                })?;
                options.bind = addr;
            }
            "--require-validation" => options.require_validation = true,
            "--timeout" => options.handshake_timeout = parse_duration(value("--timeout")?)?,
            "--max-concurrent" => {
                let n = parse_count("--max-concurrent", value("--max-concurrent")?)?;
                options.max_concurrent = usize::try_from(n)
                    .map_err(|_| UsageError(String::from("--max-concurrent too large")))?;
            }
            "--max-connections" => {
                options.max_connections = Some(parse_count(
                    "--max-connections",
                    value("--max-connections")?,
                )?);
            }
            "--run-for" => options.run_for = Some(parse_duration(value("--run-for")?)?),
            "--format" => {
                let v = value("--format")?;
                if v != "jsonl" {
                    return Err(UsageError(format!(
                        "unsupported format {v:?}; only jsonl is available"
                    )));
                }
            }
            s if s.starts_with('-') => return Err(UsageError(format!("unknown option {s:?}"))),
            s => return Err(UsageError(format!("unexpected argument {s:?}"))),
        }
    }
    if alpn.is_empty() {
        return Err(UsageError(String::from(
            "--alpn is required: the value is experimental and must be chosen explicitly",
        )));
    }
    options.alpn = alpn;
    options.identity_dir = identity_dir.ok_or_else(|| {
        UsageError(String::from(
            "--identity-dir is required (add --generate-identity to create a test identity there)",
        ))
    })?;
    Ok(Command::Observe(options))
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
        Command::Observe(options) => observe(options),
    }
}

fn observe(options: Options) -> ExitCode {
    let prepared = match prepare(options.clone()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{NAME}: {e}");
            return ExitCode::from(1);
        }
    };
    let bound = prepared.local_addr();
    if prepared.identity_generated() {
        eprintln!(
            "{NAME}: generated a self-signed Ed25519 TEST identity in {}",
            options.identity_dir.display()
        );
    }
    eprintln!(
        "{NAME}: certificate SHA-256 (pin this with --cert-sha256; certificate DER hash, not an SSH host-key fingerprint): {}",
        prepared.certificate_sha256()
    );
    eprintln!(
        "{NAME}: EXPERIMENTAL QUIC v1/TLS 1.3 handshake observer on {bound} (ALPN {}, unregistered; handshake timeout {:?}; max concurrent {}{}{}{}); 0-RTT disabled; not an SSH service",
        options
            .alpn
            .iter()
            .map(|a| tatami::text::escape_bytes(a))
            .collect::<Vec<_>>()
            .join(","),
        options.handshake_timeout,
        options.max_concurrent,
        options
            .max_connections
            .map(|n| format!(", max connections {n}"))
            .unwrap_or_default(),
        options
            .run_for
            .map(|d| format!(", run for {d:?}"))
            .unwrap_or_default(),
        if options.require_validation {
            ", Retry required"
        } else {
            ""
        },
    );
    if options.run_for.is_none() && options.max_connections.is_none() {
        eprintln!("{NAME}: no --run-for or --max-connections given; running until interrupted");
    }

    let stdout = std::io::stdout();
    let summary = prepared.run_jsonl(LineWriter(stdout));
    let _ = std::io::stderr().flush();
    match summary.reason {
        StopReason::RunDurationElapsed
        | StopReason::ConnectionLimitReached
        | StopReason::StopRequested => {
            eprintln!(
                "{NAME}: stopped ({}); incoming {}, accepted {}, completed {}, failed {}, timed out {}, retries {}, dropped at capacity {}, records dropped {}",
                summary.reason.code(),
                summary.stats.incoming,
                summary.stats.accepted,
                summary.stats.completed,
                summary.stats.failed,
                summary.stats.timed_out,
                summary.stats.retries_sent,
                summary.stats.dropped_at_capacity,
                summary.records_dropped
            );
            if summary.records_dropped > 0 || summary.abandoned > 0 {
                eprintln!(
                    "{NAME}: warning: logging incomplete (records dropped {}, handshakes abandoned {})",
                    summary.records_dropped, summary.abandoned
                );
            }
            ExitCode::SUCCESS
        }
        StopReason::SinkFailed | StopReason::SocketFailed => {
            eprintln!(
                "{NAME}: failed ({}): {}",
                summary.reason.code(),
                summary.error.as_deref().unwrap_or("unknown error")
            );
            ExitCode::from(1)
        }
    }
}

/// Stdout wrapper that takes the lock per record so records are written
/// whole.
struct LineWriter(std::io::Stdout);

impl Write for LineWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut lock = self.0.lock();
        lock.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| String::from(*s)).collect()
    }

    #[test]
    fn parses_observe_options() {
        let Command::Observe(o) = parse_args(&args(&[
            "observe",
            "--alpn",
            "tatami-diag/0",
            "--alpn",
            "tatami-diag/1",
            "--identity-dir",
            "/tmp/id",
            "--generate-identity",
            "--listen",
            "[::1]:0",
            "--require-validation",
            "--timeout",
            "2s",
            "--max-concurrent",
            "4",
            "--max-connections",
            "10",
            "--run-for",
            "1m",
            "--format",
            "jsonl",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            o.alpn,
            vec![b"tatami-diag/0".to_vec(), b"tatami-diag/1".to_vec()]
        );
        assert_eq!(o.identity_dir, PathBuf::from("/tmp/id"));
        assert!(o.generate_identity);
        assert!(o.bind.is_ipv6());
        assert!(o.require_validation);
        assert_eq!(o.handshake_timeout, Duration::from_secs(2));
        assert_eq!(o.max_concurrent, 4);
        assert_eq!(o.max_connections, Some(10));
        assert_eq!(o.run_for, Some(Duration::from_secs(60)));

        let Command::Observe(o) =
            parse_args(&args(&["observe", "--alpn", "x", "--identity-dir", "d"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(o.bind, "127.0.0.1:4433".parse().unwrap());
        assert!(!o.generate_identity);
        assert!(!o.require_validation);
    }

    #[test]
    fn rejects_bad_usage() {
        for a in [
            &[][..],
            &["serve"],
            &["observe"],
            &["observe", "--alpn", "x"],
            &["observe", "--identity-dir", "d"],
            &["observe", "--alpn", "", "--identity-dir", "d"],
            &[
                "observe",
                "--alpn",
                "x",
                "--identity-dir",
                "d",
                "--listen",
                "localhost:1",
            ],
            &[
                "observe",
                "--alpn",
                "x",
                "--identity-dir",
                "d",
                "--timeout",
                "0s",
            ],
            &[
                "observe",
                "--alpn",
                "x",
                "--identity-dir",
                "d",
                "--max-concurrent",
                "0",
            ],
            &[
                "observe",
                "--alpn",
                "x",
                "--identity-dir",
                "d",
                "--format",
                "yaml",
            ],
            &["observe", "--alpn", "x", "--identity-dir", "d", "--ssh"],
            &["observe", "--alpn", "x", "--identity-dir", "d", "extra"],
        ] {
            assert!(parse_args(&args(a)).is_err(), "{a:?}");
        }
        assert!(matches!(parse_args(&args(&["--help"])), Ok(Command::Help)));
        assert!(matches!(
            parse_args(&args(&["observe", "--help"])),
            Ok(Command::Help)
        ));
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
            "not an SSH service",
            "0-RTT",
            "untrusted",
        ] {
            assert!(USAGE.contains(word), "help text lacks {word:?}");
        }
    }
}
