//! `tatami-server`: thin command-line entry point over `tatami::server`.
//!
//! The only command is `observe`, a TCP diagnostic listener that records
//! what connecting clients send up to their first `KEXINIT`. It performs
//! no key exchange, has no host key and never authenticates anyone. It is
//! not an SSH service and must not be pointed at a port that one uses.
//!
//! Exit status: 0 for a clean finite or requested stop; 1 for a listener,
//! output or runtime failure; 2 for usage errors or unsupported commands.
//! Individual peer outcomes (malformed input, timeouts) are records, not
//! process failures.

use std::io::Write;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use tatami::server::observe::{Options, prepare};
use tatami::tcp::io::StopReason;

const NAME: &str = "tatami-server";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-server observe [--listen ADDR] [--timeout DURATION]
                        [--max-concurrent N] [--max-connections N]
                        [--run-for DURATION] [--banner-only] [--format jsonl]
  tatami-server observe --help
  tatami-server --help
  tatami-server --version

Commands:
  observe   Listen for TCP connections, send an SSH-2 server identification,
            record each client's identification and initial KEXINIT proposal
            as JSON Lines on stdout, then close the connection. No server
            KEXINIT is sent, no key exchange is performed, no host key is
            loaded or generated, and nobody is authenticated. This is a
            diagnostic observer, not an SSH service.

Options for observe:
  --listen ADDR          Socket address to bind (default 127.0.0.1:2222).
                         Use a numeric IPv4 address or a bracketed IPv6
                         address, e.g. '[::1]:2222'. Port 0 picks an
                         ephemeral port; the bound address is reported.
  --timeout DURATION     Total time allowed per connection from acceptance,
                         including sending the banner (default 5s).
  --max-concurrent N     Simultaneous observations (default 32). Excess
                         connections are accepted and closed at once, with
                         no banner, and counted as dropped_at_capacity.
  --max-connections N    Stop after N accepted connections, counting dropped
                         ones (default: unlimited).
  --run-for DURATION     Stop after this long (default: until stopped).
  --banner-only          End each observation after a valid client
                         identification instead of waiting for KEXINIT.
  --format jsonl         Output format; only jsonl is supported.
  DURATION               e.g. 5s, 500ms, 10m; must be > 0.

Output:
  JSON Lines on stdout (schema 1: listener_started, connection_observation,
  overload, listener_stopped). Diagnostics go to stderr. Redirect stdout to
  a file and rotate it externally for long runs.

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

    let mut options = Options::default();
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| {
            it.next()
                .ok_or_else(|| UsageError(format!("{flag} requires a value")))
        };
        match arg.as_str() {
            "--help" | "-h" => return Ok(Command::Help),
            "--listen" => {
                let v = value("--listen")?;
                let addr: SocketAddr = v.parse().map_err(|_| {
                    UsageError(format!(
                        "invalid listen address {v:?}; use IP:PORT or [IPv6]:PORT"
                    ))
                })?;
                options.listener.bind = addr;
            }
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
    Ok(Command::Observe(Box::new(options)))
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
}
