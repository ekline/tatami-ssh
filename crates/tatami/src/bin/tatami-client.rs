//! `tatami-client`: thin command-line entry point over `tatami::client`.
//!
//! Exit status: 0 for a complete requested observation or handshake, 1 for
//! an incomplete observation, an incomplete or failed handshake (including
//! an untrusted host key) or a network/protocol/output failure, 2 for usage
//! errors or unsupported commands.
//!
//! The `handshake` command exists only in builds with the `kex` feature; in
//! other builds it is reported as a usage error so scripts can tell the two
//! situations apart.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use tatami::client::probe::{Options, run};

#[cfg(feature = "kex")]
use tatami::client::handshake;

const NAME: &str = "tatami-client";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-client probe HOST [--port PORT] [--connect-timeout DURATION]
                           [--read-timeout DURATION]
  tatami-client handshake HOST --host-key-sha256 'SHA256:...' [--port PORT]
                           [--connect-timeout DURATION] [--timeout DURATION]
                           [--no-ext-info] [--no-strict-kex] [--json]
  tatami-client --help
  tatami-client --version

Commands:
  probe       Connect to HOST:PORT, send a client identification, and report
              the server identification and its initial KEXINIT proposal. No
              key exchange is performed and no client KEXINIT is sent; a
              server that waits for the client's proposal will time out with
              a partial result.
  handshake   Connect to HOST:PORT and perform the first interoperability
              profile's key exchange (curve25519-sha256, ssh-ed25519,
              aes128-gcm@openssh.com, strict KEX): verify the host signature,
              compare the host key's SHA-256 fingerprint with the pin given
              by --host-key-sha256, exchange NEWKEYS, request the ssh-userauth
              service and disconnect. No user is ever authenticated. Requires
              a build with --features std,tcp,kex.

Options (probe):
  --port PORT                TCP port (default 22)
  --connect-timeout DURATION Deadline for the whole connect phase (default 10s)
  --read-timeout DURATION    Deadline from connect to KEXINIT (default 10s)

Options (handshake):
  --host-key-sha256 'SHA256:...'
                             REQUIRED. The only host-key fingerprint that will
                             be trusted: 'SHA256:' followed by 43 unpadded
                             base64 characters, as printed by ssh-keygen.
                             Obtain it independently of this connection, for
                             example on the server itself:
                               ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
  --port PORT                TCP port (default 22)
  --connect-timeout DURATION Deadline for the whole connect phase (default 10s)
  --timeout DURATION         Overall deadline from connect to the outcome,
                             covering every read and write (default 10s)
  --no-ext-info              Do not offer ext-info-c
  --no-strict-kex            Do not offer the strict-KEX markers
  --json                     Print one JSON object instead of the text report

  DURATION                   e.g. 5s, 500ms, 2m; must be > 0

HOST may be a name or a numeric IPv4/IPv6 address. IPv6 addresses are given
bare (no brackets); the port is always a separate option.

Exit status: 0 complete observation or handshake; 1 incomplete or failed
(including an untrusted host key or a mismatched pin); 2 usage error.
";

#[cfg(feature = "kex")]
const PIN_HELP: &str = "expected 'SHA256:' followed by 43 unpadded base64 characters; obtain the \
                        server's host-key fingerprint independently, for example by running \
                        `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server";

enum Command {
    Help,
    Version,
    Probe(Options),
    #[cfg(feature = "kex")]
    Handshake {
        options: handshake::Options,
        json: bool,
    },
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

fn parse_port(v: &str) -> Result<u16, UsageError> {
    v.parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| UsageError(format!("invalid port {v:?}; expected 1-65535")))
}

fn value<'a>(
    it: &mut std::slice::Iter<'a, String>,
    option: &str,
) -> Result<&'a String, UsageError> {
    it.next()
        .ok_or_else(|| UsageError(format!("{option} requires a value")))
}

fn check_host(host: Option<String>, command: &str) -> Result<String, UsageError> {
    let host = host.ok_or_else(|| UsageError(format!("{command} requires a HOST")))?;
    if host.is_empty() {
        return Err(UsageError(String::from("HOST must not be empty")));
    }
    Ok(host)
}

fn parse_args(args: &[String]) -> Result<Command, UsageError> {
    let mut it = args.iter();
    let Some(first) = it.next() else {
        return Err(UsageError(String::from("missing command")));
    };
    match first.as_str() {
        "--help" | "-h" | "help" => Ok(Command::Help),
        "--version" | "-V" | "version" => Ok(Command::Version),
        "probe" => parse_probe(it),
        "handshake" => parse_handshake(it),
        other => Err(UsageError(format!("unsupported command {other:?}"))),
    }
}

fn parse_probe(mut it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    let mut host: Option<String> = None;
    let mut options = Options::new("", 22);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => options.port = parse_port(value(&mut it, "--port")?)?,
            "--connect-timeout" => {
                options.io.connect_timeout = parse_duration(value(&mut it, "--connect-timeout")?)?;
            }
            "--read-timeout" => {
                options.io.read_timeout = parse_duration(value(&mut it, "--read-timeout")?)?;
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
    options.host = check_host(host, "probe")?;
    Ok(Command::Probe(options))
}

#[cfg(not(feature = "kex"))]
fn parse_handshake(_it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    Err(UsageError(String::from(
        "handshake requires a build with --features std,tcp,kex (this build lacks the kex feature)",
    )))
}

#[cfg(feature = "kex")]
fn parse_handshake(mut it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    use tatami::keys::fingerprint::Sha256Fingerprint;

    let mut host: Option<String> = None;
    let mut port = 22u16;
    let mut pin: Option<Sha256Fingerprint> = None;
    let mut io = tatami::tcp::io::handshake::HandshakeIo {
        connect_timeout: Duration::from_secs(10),
        overall_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let mut config = tatami::tcp::handshake::HandshakeConfig::default();
    let mut json = false;

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => port = parse_port(value(&mut it, "--port")?)?,
            "--host-key-sha256" => {
                let v = value(&mut it, "--host-key-sha256")?;
                pin = Some(Sha256Fingerprint::parse(v).map_err(|e| {
                    UsageError(format!("invalid --host-key-sha256 {v:?}: {e}; {PIN_HELP}"))
                })?);
            }
            "--connect-timeout" => {
                io.connect_timeout = parse_duration(value(&mut it, "--connect-timeout")?)?;
            }
            "--timeout" => io.overall_timeout = parse_duration(value(&mut it, "--timeout")?)?,
            "--no-ext-info" => config.advertise_ext_info = false,
            "--no-strict-kex" => config.offer_strict_kex = false,
            "--json" => json = true,
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
    let host = check_host(host, "handshake")?;
    let pin = pin.ok_or_else(|| {
        UsageError(format!(
            "handshake requires --host-key-sha256 'SHA256:...'; {PIN_HELP}"
        ))
    })?;
    let mut options = handshake::Options::new(host, port, pin);
    options.io = io;
    options.config = config;
    Ok(Command::Handshake { options, json })
}

/// Writes the whole report to stdout; a failure here (for example a closed
/// pipe) is an output failure and therefore exit status 1.
fn emit(text: &str) -> Result<(), std::io::Error> {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(text.as_bytes())?;
    out.flush()
}

#[cfg(feature = "kex")]
fn run_handshake(options: &handshake::Options, json: bool) -> ExitCode {
    eprintln!(
        "{NAME}: handshaking with {}:{} (connect timeout {:?}, overall timeout {:?}, pin {})",
        options.host,
        options.port,
        options.io.connect_timeout,
        options.io.overall_timeout,
        options.pin
    );
    let report = handshake::run(options);
    let text = if json {
        let mut line = report.to_json().to_json();
        line.push('\n');
        line
    } else {
        let mut text = String::new();
        // Writing into a String cannot fail.
        let _ = report.write_text(&mut text);
        text
    };
    if let Err(e) = emit(&text) {
        eprintln!("{NAME}: failed to write the report to stdout: {e}");
        return ExitCode::from(1);
    }
    if report.is_complete() {
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "{NAME}: handshake incomplete ({})",
            report.completion.code()
        );
        ExitCode::from(1)
    }
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
            if let Err(e) = emit(&text) {
                eprintln!("{NAME}: failed to write the report to stdout: {e}");
                return ExitCode::from(1);
            }
            if report.is_complete() {
                ExitCode::SUCCESS
            } else {
                eprintln!("{NAME}: observation incomplete");
                ExitCode::from(1)
            }
        }
        #[cfg(feature = "kex")]
        Command::Handshake { options, json } => run_handshake(&options, json),
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

    const PIN: &str = "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8";

    #[cfg(feature = "kex")]
    #[test]
    fn parses_handshake() {
        let Command::Handshake { options: o, json } = parse_args(&args(&[
            "handshake",
            "2001:db8::10",
            "--port",
            "2222",
            "--host-key-sha256",
            PIN,
            "--timeout",
            "3s",
            "--connect-timeout",
            "1s",
            "--no-ext-info",
            "--no-strict-kex",
            "--json",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(o.host, "2001:db8::10");
        assert_eq!(o.port, 2222);
        assert_eq!(o.pin.to_string(), PIN);
        assert_eq!(o.io.overall_timeout, Duration::from_secs(3));
        assert_eq!(o.io.connect_timeout, Duration::from_secs(1));
        assert!(!o.config.advertise_ext_info);
        assert!(!o.config.offer_strict_kex);
        assert!(json);

        let Command::Handshake { options: o, json } =
            parse_args(&args(&["handshake", "h", "--host-key-sha256", PIN])).unwrap()
        else {
            panic!()
        };
        assert_eq!(o.port, 22);
        assert_eq!(o.io.overall_timeout, Duration::from_secs(10));
        assert_eq!(o.io.connect_timeout, Duration::from_secs(10));
        assert!(o.config.advertise_ext_info);
        assert!(o.config.offer_strict_kex);
        assert!(!json);
    }

    #[cfg(feature = "kex")]
    #[test]
    fn handshake_pin_is_required_and_validated() {
        let err = |a: &[&str]| parse_args(&args(a)).err().expect("usage error").0;

        let e = err(&["handshake", "h"]);
        assert!(e.contains("--host-key-sha256"), "{e}");
        assert!(
            e.contains("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"),
            "{e}"
        );
        assert!(
            !e.contains("probe"),
            "must not suggest copying from probe: {e}"
        );

        let e = err(&["handshake", "h", "--host-key-sha256", "SHA256:abc"]);
        assert!(e.contains("43 characters, found 3"), "{e}");
        assert!(e.contains("ssh-keygen -lf"), "{e}");

        let padded = format!("{PIN}=");
        let e = err(&["handshake", "h", "--host-key-sha256", &padded]);
        assert!(e.contains("padded"), "{e}");

        let e = err(&["handshake", "h", "--host-key-sha256", &PIN[7..]]);
        assert!(e.contains("must start with `SHA256:`"), "{e}");

        assert!(parse_args(&args(&["handshake", "--host-key-sha256", PIN])).is_err());
        assert!(parse_args(&args(&["handshake", "h", "--host-key-sha256"])).is_err());
        assert!(
            parse_args(&args(&[
                "handshake",
                "h",
                "--host-key-sha256",
                PIN,
                "--port",
                "0"
            ]))
            .is_err()
        );
        assert!(
            parse_args(&args(&[
                "handshake",
                "h",
                "--host-key-sha256",
                PIN,
                "--timeout",
                "0s"
            ]))
            .is_err()
        );
        assert!(
            parse_args(&args(&[
                "handshake",
                "h",
                "--host-key-sha256",
                PIN,
                "--read-timeout",
                "1s"
            ]))
            .is_err(),
            "--read-timeout belongs to probe"
        );
        assert!(parse_args(&args(&["handshake", "h", "x", "--host-key-sha256", PIN])).is_err());
    }

    #[cfg(not(feature = "kex"))]
    #[test]
    fn handshake_is_a_usage_error_without_kex() {
        let e = parse_args(&args(&["handshake", "h", "--host-key-sha256", PIN]))
            .err()
            .expect("usage error")
            .0;
        assert!(
            e.contains("requires a build with --features std,tcp,kex"),
            "{e}"
        );
    }
}
