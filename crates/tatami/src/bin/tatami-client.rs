//! `tatami-client`: thin command-line entry point over `tatami::client`.
//!
//! Exit status: 0 for a complete requested observation, 1 for an
//! incomplete observation or a network/protocol failure, 2 for usage
//! errors or unsupported commands.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use tatami::client::probe::{Options, run};

const NAME: &str = "tatami-client";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-client probe HOST [--port PORT] [--connect-timeout DURATION]
                           [--read-timeout DURATION]
  tatami-client --help
  tatami-client --version

Commands:
  probe   Connect to HOST:PORT, send a client identification, and report the
          server identification and its initial KEXINIT proposal. No key
          exchange is performed and no client KEXINIT is sent; a server that
          waits for the client's proposal will time out with a partial result.

Options:
  --port PORT                TCP port (default 22)
  --connect-timeout DURATION Deadline for the whole connect phase (default 10s)
  --read-timeout DURATION    Deadline from connect to KEXINIT (default 10s)
  DURATION                   e.g. 5s, 500ms, 2m; must be > 0

HOST may be a name or a numeric IPv4/IPv6 address. IPv6 addresses are given
bare (no brackets); the port is always a separate option.

Exit status: 0 complete observation; 1 incomplete or failed; 2 usage error.
";

enum Command {
    Help,
    Version,
    Probe(Options),
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

fn parse_args(args: &[String]) -> Result<Command, UsageError> {
    let mut it = args.iter();
    let Some(first) = it.next() else {
        return Err(UsageError(String::from("missing command")));
    };
    match first.as_str() {
        "--help" | "-h" | "help" => return Ok(Command::Help),
        "--version" | "-V" | "version" => return Ok(Command::Version),
        "probe" => {}
        other => return Err(UsageError(format!("unsupported command {other:?}"))),
    }

    let mut host: Option<String> = None;
    let mut options = Options::new("", 22);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => {
                let v = it
                    .next()
                    .ok_or_else(|| UsageError(String::from("--port requires a value")))?;
                options.port =
                    v.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| {
                        UsageError(format!("invalid port {v:?}; expected 1-65535"))
                    })?;
            }
            "--connect-timeout" => {
                let v = it.next().ok_or_else(|| {
                    UsageError(String::from("--connect-timeout requires a value"))
                })?;
                options.io.connect_timeout = parse_duration(v)?;
            }
            "--read-timeout" => {
                let v = it
                    .next()
                    .ok_or_else(|| UsageError(String::from("--read-timeout requires a value")))?;
                options.io.read_timeout = parse_duration(v)?;
            }
            "--help" | "-h" => return Ok(Command::Help),
            s if s.starts_with('-') => return Err(UsageError(format!("unknown option {s:?}"))),
            s => {
                if host.is_some() {
                    return Err(UsageError(format!("unexpected extra argument {s:?}")));
                }
                host = Some(String::from(s));
            }
        }
    }
    let host = host.ok_or_else(|| UsageError(String::from("probe requires a HOST")))?;
    if host.is_empty() {
        return Err(UsageError(String::from("HOST must not be empty")));
    }
    options.host = host;
    Ok(Command::Probe(options))
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
        Command::Probe(options) => {
            eprintln!(
                "{NAME}: probing {}:{} (connect timeout {:?}, read timeout {:?})",
                options.host, options.port, options.io.connect_timeout, options.io.read_timeout
            );
            let report = run(&options);
            let mut text = String::new();
            // Writing into a String cannot fail.
            let _ = report.write_text(&mut text);
            let stdout = std::io::stdout();
            let mut out = stdout.lock();
            let _ = out.write_all(text.as_bytes());
            let _ = out.flush();
            if report.is_complete() {
                ExitCode::SUCCESS
            } else {
                eprintln!("{NAME}: observation incomplete");
                ExitCode::from(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("3").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("5h").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
    }

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| String::from(*s)).collect()
    }

    #[test]
    fn parses_probe() {
        let Command::Probe(o) =
            parse_args(&args(&["probe", "2001:db8::10", "--port", "2222"])).unwrap()
        else {
            panic!()
        };
        assert_eq!(o.host, "2001:db8::10");
        assert_eq!(o.port, 2222);

        let Command::Probe(o) = parse_args(&args(&["probe", "h"])).unwrap() else {
            panic!()
        };
        assert_eq!(o.port, 22);
    }

    #[test]
    fn rejects_bad_usage() {
        assert!(parse_args(&args(&[])).is_err());
        assert!(parse_args(&args(&["probe"])).is_err());
        assert!(parse_args(&args(&["probe", "h", "--port", "0"])).is_err());
        assert!(parse_args(&args(&["probe", "h", "--port", "70000"])).is_err());
        assert!(parse_args(&args(&["probe", "h", "--port"])).is_err());
        assert!(parse_args(&args(&["probe", "h", "--read-timeout", "0s"])).is_err());
        assert!(parse_args(&args(&["probe", "h", "--bogus"])).is_err());
        assert!(parse_args(&args(&["probe", "h", "extra"])).is_err());
        assert!(parse_args(&args(&["connect", "h"])).is_err());
        assert!(matches!(parse_args(&args(&["--help"])), Ok(Command::Help)));
        assert!(matches!(
            parse_args(&args(&["--version"])),
            Ok(Command::Version)
        ));
    }
}
