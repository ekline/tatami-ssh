//! `tatami-server`: thin command-line entry point over `tatami::server`.
//!
//! The only command is `observe`. With `--transport tcp` (the default) it is
//! a TCP diagnostic listener that records what connecting clients send up
//! to their first `KEXINIT`. It performs no key exchange, has no host key
//! and never authenticates anyone. With `--transport quic` (builds with the
//! `quic-diag` feature) it is an experimental QUIC v1 / TLS 1.3 handshake
//! observer that accepts no stream or datagram. Neither is an SSH service,
//! and neither must be pointed at a port that one uses.
//!
//! Exit status: 0 for a clean finite or requested stop; 1 for a listener,
//! output or runtime failure; 2 for usage errors or unsupported commands.
//! Individual peer outcomes (malformed input, timeouts) are records, not
//! process failures.

use std::io::Write;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

#[cfg(feature = "quic-diag")]
use tatami::quic::diag::server::StopReason as QuicStopReason;
#[cfg(feature = "quic-diag")]
use tatami::quic_diag::server as quic_server;
use tatami::server::observe::{Options, prepare};
use tatami::tcp::io::StopReason;

const NAME: &str = "tatami-server";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-server observe [--listen ADDR] [--timeout DURATION]
                        [--max-concurrent N] [--max-connections N]
                        [--run-for DURATION] [--banner-only] [--format jsonl]
  tatami-server observe --transport quic --alpn PROTO --identity-dir DIR
                        [--listen ADDR] [--generate-identity]
                        [--require-validation] [--timeout DURATION]
                        [--max-concurrent N] [--max-connections N]
                        [--run-for DURATION] [--format jsonl]
  tatami-server observe --help
  tatami-server --help
  tatami-server --version

Commands:
  observe   With --transport tcp (the default): listen for TCP connections,
            send an SSH-2 server identification, record each client's
            identification and initial KEXINIT proposal as JSON Lines on
            stdout, then close the connection. No server KEXINIT is sent, no
            key exchange is performed, no host key is loaded or generated,
            and nobody is authenticated. This is a diagnostic observer,
            not an SSH service.

            With --transport quic: EXPERIMENTAL. Listen for QUIC v1
            connections on UDP, complete a TLS 1.3 handshake with a
            generated test certificate, record each attempt (source address
            and its validation state, offered vs negotiated ALPN, SNI,
            outcome) as JSON Lines on stdout, then close the connection with
            an application CONNECTION_CLOSE. No stream is accepted, no
            datagram is read, 0-RTT and resumption are disabled, nobody is
            authenticated. This is a handshake observer, not an SSH service
            and not an SSH-over-QUIC endpoint. Requires a build with
            --features std,tcp,quic-diag.

Options for observe (both transports):
  --transport tcp|quic   Transport to observe (default tcp).
  --listen ADDR          Socket address to bind (default 127.0.0.1:2222 for
                         TCP, 127.0.0.1:4433 for QUIC).
                         Use a numeric IPv4 address or a bracketed IPv6
                         address, e.g. '[::1]:2222'. Port 0 picks an
                         ephemeral port; the bound address is reported.
  --timeout DURATION     TCP: total time allowed per connection from
                         acceptance, including sending the banner. QUIC:
                         per-connection handshake deadline, also the QUIC
                         idle timeout. Default 5s.
  --max-concurrent N     Simultaneous observations (default 32). Excess TCP
                         connections are accepted and closed at once, with
                         no banner; excess QUIC Initials are refused
                         (CONNECTION_REFUSED). Both are counted as
                         dropped_at_capacity.
  --max-connections N    Stop after N accepted-or-dropped connections
                         (default: unlimited). QUIC Retries are not counted.
  --run-for DURATION     Stop after this long (default: until stopped).
  --format jsonl         Output format; only jsonl is supported.
  DURATION               e.g. 5s, 500ms, 10m; must be > 0.

Options for observe (TCP only):
  --banner-only          End each observation after a valid client
                         identification instead of waiting for KEXINIT.

Options for observe (QUIC only):
  --alpn PROTO           ALPN value to accept (required; repeat for several,
                         in preference order). The value is experimental and
                         UNREGISTERED; no interoperability with any other
                         implementation is claimed. There is no default.
  --identity-dir DIR     Directory holding cert.pem and key.pem (required).
  --generate-identity    Generate a self-signed Ed25519 test identity into
                         DIR if none exists. Without this flag a missing
                         identity is an error; nothing is generated silently.
  --require-validation   Answer each unvalidated Initial with a Retry and
                         accept only Initials carrying the token. Validation
                         proves reachability of the source address, nothing
                         about identity.

Output:
  JSON Lines on stdout. TCP (schema 1): listener_started,
  connection_observation, overload, listener_stopped. QUIC (schema 1,
  transport \"quic\"): quic_listener_started, quic_handshake_observation,
  overload, quic_listener_stopped. Diagnostics go to stderr. Redirect stdout
  to a file and rotate it externally for long runs.

  For QUIC, the certificate SHA-256 fingerprint is printed to stderr at
  start so a client can pin it with --cert-sha256; it is a certificate
  fingerprint, not an SSH host-key fingerprint. Offered ClientHello values
  in records are untrusted metadata supplied by the peer.

Binding port 22 requires OS privileges and must not displace an existing
SSH service; this program will not change firewall or service settings.
One address per process: run separate instances for IPv4 and IPv6.

Exit status: 0 clean stop; 1 listener/output/runtime failure; 2 usage error.
";

#[derive(Debug)]
struct UsageError(String);

enum Command {
    Help,
    Version,
    Observe(Box<Options>),
    #[cfg(feature = "quic-diag")]
    QuicObserve(Box<quic_server::Options>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Tcp,
    Quic,
}

fn parse_transport(v: &str) -> Result<Transport, UsageError> {
    match v {
        "tcp" => Ok(Transport::Tcp),
        "quic" => Ok(Transport::Quic),
        _ => Err(UsageError(format!(
            "invalid --transport {v:?}; expected tcp or quic"
        ))),
    }
}

/// Finds the `--transport` choice before the transport-specific parse,
/// because each transport accepts a different option set. Repeats must
/// agree.
fn select_transport(args: &[String]) -> Result<Transport, UsageError> {
    let mut selected: Option<Transport> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == "--transport" {
            let v = it
                .next()
                .ok_or_else(|| UsageError(String::from("--transport requires a value")))?;
            let t = parse_transport(v)?;
            if selected.is_some_and(|s| s != t) {
                return Err(UsageError(String::from("conflicting --transport values")));
            }
            selected = Some(t);
        }
    }
    Ok(selected.unwrap_or(Transport::Tcp))
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

fn parse_args(args: &[String]) -> Result<Command, UsageError> {
    let mut it = args.iter();
    let Some(first) = it.next() else {
        return Err(UsageError(String::from(
            "missing command; this build only offers `observe` (no SSH service is implemented)",
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
    match select_transport(it.as_slice())? {
        Transport::Tcp => parse_tcp_observe(it),
        Transport::Quic => parse_quic_observe(it),
    }
}

fn parse_listen(v: &str) -> Result<SocketAddr, UsageError> {
    v.parse().map_err(|_| {
        UsageError(format!(
            "invalid listen address {v:?}; use IP:PORT or [IPv6]:PORT"
        ))
    })
}

fn parse_format(v: &str) -> Result<(), UsageError> {
    if v == "jsonl" {
        Ok(())
    } else {
        Err(UsageError(format!(
            "unsupported format {v:?}; only jsonl is available"
        )))
    }
}

fn parse_tcp_observe(mut it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    let mut options = Options::default();
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| {
            it.next()
                .ok_or_else(|| UsageError(format!("{flag} requires a value")))
        };
        match arg.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--listen" => options.listener.bind = parse_listen(value("--listen")?)?,
            "--timeout" => {
                options.listener.connection_timeout = parse_duration(value("--timeout")?)?
            }
            "--max-concurrent" => {
                let n = parse_count("--max-concurrent", value("--max-concurrent")?)?;
                options.listener.max_concurrent = usize::try_from(n)
                    .map_err(|_| UsageError(String::from("--max-concurrent too large")))?;
            }
            "--max-connections" => {
                options.listener.max_connections = Some(parse_count(
                    "--max-connections",
                    value("--max-connections")?,
                )?);
            }
            "--run-for" => options.listener.run_for = Some(parse_duration(value("--run-for")?)?),
            "--banner-only" => options = options.banner_only(true),
            "--format" => parse_format(value("--format")?)?,
            // Already validated by `select_transport`.
            "--transport" => {
                value("--transport")?;
            }
            s if s.starts_with('-') => return Err(UsageError(format!("unknown option {s:?}"))),
            s => return Err(UsageError(format!("unexpected argument {s:?}"))),
        }
    }
    Ok(Command::Observe(Box::new(options)))
}

#[cfg(not(feature = "quic-diag"))]
fn parse_quic_observe(_it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    Err(UsageError(String::from(
        "observe --transport quic requires a build with --features std,tcp,quic-diag (this build lacks the quic-diag feature)",
    )))
}

#[cfg(feature = "quic-diag")]
fn parse_alpn(s: &str) -> Result<Vec<u8>, UsageError> {
    if s.is_empty() || s.len() > 255 {
        return Err(UsageError(format!(
            "--alpn value must be 1-255 bytes, got {} bytes",
            s.len()
        )));
    }
    Ok(s.as_bytes().to_vec())
}

#[cfg(feature = "quic-diag")]
fn parse_quic_observe(mut it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    use std::path::PathBuf;

    let mut alpn: Vec<Vec<u8>> = Vec::new();
    let mut identity_dir: Option<PathBuf> = None;
    let mut options = quic_server::Options::new(Vec::new(), PathBuf::new());
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
            "--listen" => options.bind = parse_listen(value("--listen")?)?,
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
            "--format" => parse_format(value("--format")?)?,
            // Already validated by `select_transport`.
            "--transport" => {
                value("--transport")?;
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
    Ok(Command::QuicObserve(Box::new(options)))
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
        Command::Observe(options) => observe(*options),
        #[cfg(feature = "quic-diag")]
        Command::QuicObserve(options) => observe_quic(*options),
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
    eprintln!(
        "{NAME}: observing on {bound} (per-connection timeout {:?}, max concurrent {}{}{}{}); \
         this is a diagnostic observer, not an SSH service",
        options.listener.connection_timeout,
        options.listener.max_concurrent,
        options
            .listener
            .max_connections
            .map(|n| format!(", max connections {n}"))
            .unwrap_or_default(),
        options
            .listener
            .run_for
            .map(|d| format!(", run for {d:?}"))
            .unwrap_or_default(),
        if options.listener.observer.banner_only {
            ", banner-only"
        } else {
            ""
        },
    );
    if options.listener.run_for.is_none() && options.listener.max_connections.is_none() {
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
                "{NAME}: stopped ({}); accepted {}, observed {}, dropped at capacity {}, records dropped {}",
                summary.reason.code(),
                summary.accepted,
                summary.observed,
                summary.dropped_at_capacity,
                summary.records_dropped
            );
            if summary.records_dropped > 0 || summary.workers_abandoned > 0 {
                eprintln!(
                    "{NAME}: warning: logging incomplete (records dropped {}, workers abandoned {})",
                    summary.records_dropped, summary.workers_abandoned
                );
            }
            ExitCode::SUCCESS
        }
        StopReason::SinkFailed | StopReason::AcceptFailed => {
            eprintln!(
                "{NAME}: failed ({}): {}",
                summary.reason.code(),
                summary.error.as_deref().unwrap_or("unknown error")
            );
            ExitCode::from(1)
        }
    }
}

#[cfg(feature = "quic-diag")]
fn observe_quic(options: quic_server::Options) -> ExitCode {
    let prepared = match quic_server::prepare(options.clone()) {
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
        QuicStopReason::RunDurationElapsed
        | QuicStopReason::ConnectionLimitReached
        | QuicStopReason::StopRequested => {
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
        QuicStopReason::SinkFailed | QuicStopReason::SocketFailed => {
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
            "--listen",
            "[::1]:0",
            "--timeout",
            "2s",
            "--max-concurrent",
            "4",
            "--max-connections",
            "10",
            "--run-for",
            "1m",
            "--banner-only",
            "--format",
            "jsonl",
        ]))
        .unwrap() else {
            panic!()
        };
        assert!(o.listener.bind.is_ipv6());
        assert_eq!(o.listener.bind.port(), 0);
        assert_eq!(o.listener.connection_timeout, Duration::from_secs(2));
        assert_eq!(o.listener.max_concurrent, 4);
        assert_eq!(o.listener.max_connections, Some(10));
        assert_eq!(o.listener.run_for, Some(Duration::from_secs(60)));
        assert!(o.listener.observer.banner_only);

        let Command::Observe(o) = parse_args(&args(&["observe"])).unwrap() else {
            panic!()
        };
        assert_eq!(o.listener.bind, "127.0.0.1:2222".parse().unwrap());
    }

    #[test]
    fn rejects_bad_usage() {
        for a in [
            &[][..],
            &["serve"],
            &["--listen", "x"],
            &["observe", "--listen", "localhost:22"],
            &["observe", "--listen", "::1:22"],
            &["observe", "--timeout", "0s"],
            &["observe", "--max-concurrent", "0"],
            &["observe", "--max-connections", "-1"],
            &["observe", "--run-for", "soon"],
            &["observe", "--format", "yaml"],
            &["observe", "--quic"],
            &["observe", "extra"],
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
    fn transport_selection() {
        let t = |a: &[&str]| select_transport(&args(a));
        assert_eq!(t(&[]).unwrap(), Transport::Tcp);
        assert_eq!(t(&["--transport", "tcp"]).unwrap(), Transport::Tcp);
        assert_eq!(t(&["--transport", "quic"]).unwrap(), Transport::Quic);
        assert!(t(&["--transport", "udp"]).is_err());
        assert!(t(&["--transport"]).is_err());
        assert!(t(&["--transport", "tcp", "--transport", "quic"]).is_err());

        assert!(matches!(
            parse_args(&args(&["observe", "--transport", "tcp", "--banner-only"])),
            Ok(Command::Observe(_))
        ));
        // QUIC-only options are not accepted by the TCP observer.
        assert!(parse_args(&args(&["observe", "--alpn", "x"])).is_err());
        assert!(parse_args(&args(&["observe", "--identity-dir", "d"])).is_err());
    }

    #[cfg(not(feature = "quic-diag"))]
    #[test]
    fn quic_observe_is_a_usage_error_without_quic_diag() {
        let e = parse_args(&args(&[
            "observe",
            "--transport",
            "quic",
            "--alpn",
            "x",
            "--identity-dir",
            "d",
        ]))
        .err()
        .expect("usage error")
        .0;
        assert!(
            e.contains("requires a build with --features std,tcp,quic-diag"),
            "{e}"
        );
    }

    #[cfg(feature = "quic-diag")]
    #[test]
    fn parses_quic_observe_options() {
        use std::path::PathBuf;

        let Command::QuicObserve(o) = parse_args(&args(&[
            "observe",
            "--transport",
            "quic",
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

        let Command::QuicObserve(o) = parse_args(&args(&[
            "observe",
            "--alpn",
            "x",
            "--identity-dir",
            "d",
            "--transport",
            "quic",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(o.bind, "127.0.0.1:4433".parse().unwrap());
        assert!(!o.generate_identity);
        assert!(!o.require_validation);
    }

    #[cfg(feature = "quic-diag")]
    #[test]
    fn rejects_bad_quic_usage() {
        let q = |rest: &[&str]| {
            let mut a = vec!["observe", "--transport", "quic"];
            a.extend_from_slice(rest);
            parse_args(&args(&a))
        };
        for rest in [
            &[][..],
            &["--alpn", "x"],
            &["--identity-dir", "d"],
            &["--alpn", "", "--identity-dir", "d"],
            &[
                "--alpn",
                "x",
                "--identity-dir",
                "d",
                "--listen",
                "localhost:1",
            ],
            &["--alpn", "x", "--identity-dir", "d", "--timeout", "0s"],
            &[
                "--alpn",
                "x",
                "--identity-dir",
                "d",
                "--max-concurrent",
                "0",
            ],
            &["--alpn", "x", "--identity-dir", "d", "--format", "yaml"],
            &["--alpn", "x", "--identity-dir", "d", "--ssh"],
            &["--alpn", "x", "--identity-dir", "d", "extra"],
            // TCP-only option.
            &["--alpn", "x", "--identity-dir", "d", "--banner-only"],
        ] {
            assert!(q(rest).is_err(), "{rest:?}");
        }
        assert!(matches!(q(&["--help"]), Ok(Command::Help)));
    }

    #[test]
    fn help_states_the_quic_caveats() {
        for word in [
            "EXPERIMENTAL",
            "UNREGISTERED",
            "no interoperability",
            "not an SSH service",
            "0-RTT",
            "untrusted",
            "--transport quic",
        ] {
            assert!(USAGE.contains(word), "help text lacks {word:?}");
        }
    }
}
