//! `tatami-client`: thin command-line entry point over `tatami::client`.
//!
//! Exit status: 0 for a complete requested observation or handshake, 1 for
//! an incomplete observation, an incomplete or failed handshake (including
//! an untrusted host key) or a network/protocol/output failure, 2 for usage
//! errors or unsupported commands.
//!
//! `handshake` selects its transport with `--transport tcp|quic` (default
//! `tcp`). The TCP handshake exists only in builds with the `kex` feature and
//! the experimental QUIC/TLS handshake only in builds with `quic-diag`; a
//! transport missing from the build is reported as a usage error so scripts
//! can tell the two situations apart.

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use tatami::client::probe::{Options, run};

#[cfg(feature = "kex")]
use tatami::client::handshake;
#[cfg(feature = "quic-diag")]
use tatami::quic_diag::client as quic_client;

const NAME: &str = "tatami-client";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-client probe HOST [--port PORT] [--connect-timeout DURATION]
                           [--read-timeout DURATION]
  tatami-client handshake HOST (--host-key-sha256 'SHA256:...' |
                           --known-hosts FILE) [--port PORT]
                           [--connect-timeout DURATION] [--timeout DURATION]
                           [--no-ext-info] [--no-strict-kex] [--json]
  tatami-client handshake HOST --transport quic --alpn PROTO
                           (--host-key-sha256 'SHA256:...' | --known-hosts FILE
                            | --cert-sha256 FINGERPRINT | --root-cert FILE)
                           [--port PORT] [--server-name NAME]
                           [--exporter-probe] [--timeout DURATION] [--json]
  tatami-client --help
  tatami-client --version

Commands:
  probe       Connect to HOST:PORT over TCP, send a client identification,
              and report the server identification and its initial KEXINIT
              proposal. No key exchange is performed and no client KEXINIT is
              sent; a server that waits for the client's proposal will time
              out with a partial result. TCP only.
  handshake   With --transport tcp (the default): connect to HOST:PORT and
              perform the first interoperability profile's key exchange
              (curve25519-sha256, ssh-ed25519, aes128-gcm@openssh.com, strict
              KEX): verify the host signature, decide trust with the pin
              (--host-key-sha256) or the known_hosts file (--known-hosts),
              exchange NEWKEYS, request the ssh-userauth service and
              disconnect.
              No user is ever authenticated. Requires a build with
              --features std,tcp,kex.

              With --transport quic: EXPERIMENTAL. Open a QUIC v1 connection
              to HOST:PORT over UDP, complete a TLS 1.3 handshake, report the
              outcome, negotiated ALPN and whether the TLS exporter is
              available, then close with an application CONNECTION_CLOSE. No
              stream is opened and no datagram is sent, so nothing SSH (no
              identification, no KEXINIT) can be sent; this is
              not an SSH client and not an SSH-over-QUIC client. 0-RTT and
              session resumption are disabled. With --host-key-sha256 or
              --known-hosts the server must present its SSH host key as an
              RFC 7250 raw public key, judged exactly as on TCP; a trusted
              key is still not an SSH session. Requires a build with
              --features std,tcp,quic-diag.

Options (probe):
  --port PORT                TCP port (default 22)
  --connect-timeout DURATION Deadline for the whole connect phase (default 10s)
  --read-timeout DURATION    Deadline from connect to KEXINIT (default 10s)

Options (handshake, TCP):
  --transport tcp            Select the SSH transport handshake (default)
  --host-key-sha256 'SHA256:...'
                             The only host-key fingerprint that will be
                             trusted: 'SHA256:' followed by 43 unpadded
                             base64 characters, as printed by ssh-keygen.
                             Obtain it independently of this connection, for
                             example on the server itself:
                               ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
  --known-hosts FILE         Instead of a pin, an OpenSSH known_hosts file,
                             read-only. Looked up as HOST (port 22) or
                             [HOST]:PORT, lowercased; supports patterns,
                             negation, hashed names and @revoked. Unknown
                             hosts fail; nothing is prompted or written.
                             ~/.ssh/known_hosts is never read implicitly.
                             Exactly one of --host-key-sha256/--known-hosts.
  --port PORT                TCP port (default 22)
  --connect-timeout DURATION Deadline for the whole connect phase (default 10s)
  --timeout DURATION         Overall deadline from connect to the outcome,
                             covering every read and write (default 10s)
  --no-ext-info              Do not offer ext-info-c
  --no-strict-kex            Do not offer the strict-KEX markers
  --json                     Print one JSON object instead of the text report

Options (handshake --transport quic):
  --transport quic           Select the experimental QUIC/TLS handshake
  --alpn PROTO               ALPN value to offer (required; repeat for
                             several, in preference order). Experimental,
                             UNREGISTERED; no interoperability with any other
                             implementation is claimed. There is no default.
  Exactly one trust option:
  --host-key-sha256 'SHA256:...'
                             SSH host-key fingerprint (same meaning as on
                             TCP); requires an RFC 7250 raw public key.
  --known-hosts FILE         known_hosts file (same rules as on TCP; the
                             lookup uses HOST and --port, never
                             --server-name); requires a raw public key.
  --cert-sha256 FP           Accept only the server certificate whose DER
                             hashes to FP ('SHA256:' + 43 unpadded base64
                             chars, as printed by
                             `tatami-server observe --transport quic`). FP is
                             a certificate fingerprint,
                             not an SSH host-key fingerprint. The TLS
                             signature is still verified.
  --root-cert FILE           Instead of a pin, trust certificates chaining to
                             the single PEM certificate in FILE and valid for
                             --server-name. No system trust store is used.
  --port PORT                UDP port (default 4433, an experiment default;
                             the intended service convention is TCP and UDP
                             22, which share one known_hosts entry)
  --server-name NAME         TLS server name (default HOST). A DNS name is
                             sent as SNI; an IP literal is not.
  --exporter-probe           After completion, call the TLS exporter with an
                             experimental label and report only whether it
                             succeeded. Output is discarded; it is not a
                             session binding.
  --timeout DURATION         Handshake deadline (default 5s)
  --json                     Print one JSON object instead of the text report

  DURATION                   e.g. 5s, 500ms, 2m; must be > 0

HOST may be a name or a numeric IPv4/IPv6 address. IPv6 addresses are given
bare (no brackets); the port is always a separate option.

Exit status: 0 complete observation or handshake; 1 incomplete, failed or
timed out (including an untrusted host key or a mismatched pin); 2 usage
error.
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
    #[cfg(feature = "quic-diag")]
    QuicHandshake {
        options: quic_client::Options,
        json: bool,
    },
}

#[derive(Debug)]
struct UsageError(String);

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
            let t = parse_transport(value(&mut it, "--transport")?)?;
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
        "handshake" => match select_transport(it.as_slice())? {
            Transport::Tcp => parse_tcp_handshake(it),
            Transport::Quic => parse_quic_handshake(it),
        },
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
            "--transport" => {
                if parse_transport(value(&mut it, "--transport")?)? != Transport::Tcp {
                    return Err(UsageError(String::from(
                        "probe is TCP-only; for QUIC use `handshake --transport quic`",
                    )));
                }
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
fn parse_tcp_handshake(_it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    Err(UsageError(String::from(
        "handshake requires a build with --features std,tcp,kex (this build lacks the kex feature)",
    )))
}

#[cfg(feature = "kex")]
fn parse_tcp_handshake(mut it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    use tatami::keys::fingerprint::Sha256Fingerprint;

    let mut host: Option<String> = None;
    let mut port = 22u16;
    let mut trust: Option<handshake::TrustConfig> = None;
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
                let pin = Sha256Fingerprint::parse(v).map_err(|e| {
                    UsageError(format!("invalid --host-key-sha256 {v:?}: {e}; {PIN_HELP}"))
                })?;
                set_once(&mut trust, handshake::TrustConfig::Pin(pin), ONE_SSH_TRUST)?;
            }
            "--known-hosts" => {
                let v = value(&mut it, "--known-hosts")?;
                set_once(&mut trust, known_hosts_config(v)?, ONE_SSH_TRUST)?;
            }
            "--connect-timeout" => {
                io.connect_timeout = parse_duration(value(&mut it, "--connect-timeout")?)?;
            }
            "--timeout" => io.overall_timeout = parse_duration(value(&mut it, "--timeout")?)?,
            "--no-ext-info" => config.advertise_ext_info = false,
            "--no-strict-kex" => config.offer_strict_kex = false,
            "--json" => json = true,
            // Already validated by `select_transport`.
            "--transport" => {
                value(&mut it, "--transport")?;
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
    let host = check_host(host, "handshake")?;
    let trust = trust.ok_or_else(|| {
        UsageError(format!(
            "handshake requires --host-key-sha256 'SHA256:...' or --known-hosts FILE; {PIN_HELP}"
        ))
    })?;
    let mut options = handshake::Options::new(host, port, trust);
    options.io = io;
    options.config = config;
    Ok(Command::Handshake { options, json })
}

#[cfg(feature = "kex")]
const ONE_SSH_TRUST: &str = "give exactly one trust option (--host-key-sha256 or --known-hosts)";

/// Sets a trust option once; a second one is a usage error, so policies are
/// never combined by accident.
#[cfg(any(feature = "kex", feature = "quic-diag"))]
fn set_once<T>(slot: &mut Option<T>, value: T, message: &str) -> Result<(), UsageError> {
    if slot.is_some() {
        return Err(UsageError(String::from(message)));
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(any(feature = "kex", feature = "quic-diag"))]
fn known_hosts_config(v: &str) -> Result<tatami::trust::TrustConfig, UsageError> {
    if v.is_empty() {
        return Err(UsageError(String::from("--known-hosts requires a file")));
    }
    Ok(tatami::trust::TrustConfig::KnownHostsFile(
        std::path::PathBuf::from(v),
    ))
}

#[cfg(not(feature = "quic-diag"))]
fn parse_quic_handshake(_it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    Err(UsageError(String::from(
        "handshake --transport quic requires a build with --features std,tcp,quic-diag (this build lacks the quic-diag feature)",
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

#[cfg(feature = "quic-diag")]
fn parse_quic_handshake(mut it: std::slice::Iter<'_, String>) -> Result<Command, UsageError> {
    use tatami::keys::fingerprint::Sha256Fingerprint;
    use tatami::quic::diag::identity::CertificateSha256;
    use tatami::quic::diag::tls::ClientTrust;
    use tatami::quic_diag::client::Trust;
    use tatami::trust::TrustConfig;

    const ONE_TRUST: &str = "give exactly one trust option (--host-key-sha256, --known-hosts, --cert-sha256 or --root-cert)";

    let mut host: Option<String> = None;
    let mut port: u16 = 4433;
    let mut server_name: Option<String> = None;
    let mut alpn: Vec<Vec<u8>> = Vec::new();
    let mut trust: Option<Trust> = None;
    let mut timeout = Duration::from_secs(5);
    let mut exporter_probe = false;
    let mut json = false;

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => port = parse_port(value(&mut it, "--port")?)?,
            "--server-name" => {
                let v = value(&mut it, "--server-name")?;
                if v.is_empty() {
                    return Err(UsageError(String::from("--server-name must not be empty")));
                }
                server_name = Some(v.clone());
            }
            "--alpn" => alpn.push(parse_alpn(value(&mut it, "--alpn")?)?),
            "--cert-sha256" => {
                let v = value(&mut it, "--cert-sha256")?;
                let fp = CertificateSha256::parse(v)
                    .map_err(|e| UsageError(format!("invalid --cert-sha256 {v:?}: {e}")))?;
                set_once(
                    &mut trust,
                    ClientTrust::PinnedCertificateSha256(fp).into(),
                    ONE_TRUST,
                )?;
            }
            "--root-cert" => {
                let v = value(&mut it, "--root-cert")?;
                if trust.is_some() {
                    return Err(UsageError(String::from(ONE_TRUST)));
                }
                trust = Some(ClientTrust::RootCertificate(read_root_cert(v)?).into());
            }
            "--host-key-sha256" => {
                let v = value(&mut it, "--host-key-sha256")?;
                let pin = Sha256Fingerprint::parse(v).map_err(|e| {
                    UsageError(format!(
                        "invalid --host-key-sha256 {v:?}: {e}; expected the SSH host-key fingerprint ('SHA256:' + 43 unpadded base64 characters, as printed by ssh-keygen -lf)"
                    ))
                })?;
                set_once(&mut trust, TrustConfig::Pin(pin).into(), ONE_TRUST)?;
            }
            "--known-hosts" => {
                let v = value(&mut it, "--known-hosts")?;
                set_once(&mut trust, known_hosts_config(v)?.into(), ONE_TRUST)?;
            }
            "--exporter-probe" => exporter_probe = true,
            "--timeout" => timeout = parse_duration(value(&mut it, "--timeout")?)?,
            "--json" => json = true,
            // Already validated by `select_transport`.
            "--transport" => {
                value(&mut it, "--transport")?;
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
    let host = check_host(host, "handshake")?;
    if alpn.is_empty() {
        return Err(UsageError(String::from(
            "--alpn is required: the value is experimental and must be chosen explicitly",
        )));
    }
    let trust = trust.ok_or_else(|| {
        UsageError(String::from(
            "a trust anchor is required: --host-key-sha256 or --known-hosts (SSH host key), or --cert-sha256 FINGERPRINT (from the server's stderr) or --root-cert FILE (X.509 test identity)",
        ))
    })?;
    let mut options = quic_client::Options::new(host, port, alpn, trust);
    options.server_name = server_name;
    options.handshake_timeout = timeout;
    options.exporter_probe = exporter_probe;
    Ok(Command::QuicHandshake { options, json })
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
    let trust = match &options.trust {
        handshake::TrustConfig::Pin(pin) => format!("pin {pin}"),
        handshake::TrustConfig::KnownHostsFile(p) => format!("known_hosts {}", p.display()),
    };
    eprintln!(
        "{NAME}: handshaking with {}:{} (connect timeout {:?}, overall timeout {:?}, {trust})",
        options.host, options.port, options.io.connect_timeout, options.io.overall_timeout,
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

#[cfg(feature = "quic-diag")]
fn run_quic_handshake(options: &quic_client::Options, json: bool) -> ExitCode {
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
    let report = quic_client::run(options);
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
    if let Err(e) = emit(&text) {
        eprintln!("{NAME}: failed to write the report to stdout: {e}");
        return ExitCode::from(1);
    }
    if report.is_complete() {
        ExitCode::SUCCESS
    } else {
        eprintln!("{NAME}: QUIC handshake not completed");
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
        #[cfg(feature = "quic-diag")]
        Command::QuicHandshake { options, json } => run_quic_handshake(&options, json),
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
        assert_eq!(o.trust.pin().unwrap().to_string(), PIN);
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

    #[test]
    fn transport_selection() {
        let t = |a: &[&str]| select_transport(&args(a));
        assert_eq!(t(&["h"]).unwrap(), Transport::Tcp);
        assert_eq!(t(&["h", "--transport", "tcp"]).unwrap(), Transport::Tcp);
        assert_eq!(t(&["--transport", "quic", "h"]).unwrap(), Transport::Quic);
        assert_eq!(
            t(&["--transport", "quic", "h", "--transport", "quic"]).unwrap(),
            Transport::Quic
        );
        assert!(t(&["h", "--transport", "udp"]).is_err());
        assert!(t(&["h", "--transport"]).is_err());
        let e = t(&["--transport", "tcp", "--transport", "quic"])
            .err()
            .unwrap()
            .0;
        assert!(e.contains("conflicting"), "{e}");

        assert!(parse_args(&args(&["probe", "h", "--transport", "tcp"])).is_ok());
        let e = parse_args(&args(&["probe", "h", "--transport", "quic"]))
            .err()
            .unwrap()
            .0;
        assert!(e.contains("TCP-only"), "{e}");
    }

    #[cfg(feature = "kex")]
    #[test]
    fn explicit_tcp_transport_and_quic_options_rejected_for_tcp() {
        assert!(matches!(
            parse_args(&args(&[
                "handshake",
                "h",
                "--transport",
                "tcp",
                "--host-key-sha256",
                PIN
            ])),
            Ok(Command::Handshake { .. })
        ));
        assert!(
            parse_args(&args(&[
                "handshake",
                "h",
                "--host-key-sha256",
                PIN,
                "--alpn",
                "x"
            ]))
            .is_err(),
            "--alpn belongs to the QUIC transport"
        );
    }

    #[cfg(not(feature = "quic-diag"))]
    #[test]
    fn quic_handshake_is_a_usage_error_without_quic_diag() {
        let e = parse_args(&args(&[
            "handshake",
            "h",
            "--transport",
            "quic",
            "--alpn",
            "x",
            "--cert-sha256",
            PIN,
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
    fn parses_quic_handshake() {
        use tatami::quic::diag::tls::ClientTrust;

        let Command::QuicHandshake { options: o, json } = parse_args(&args(&[
            "handshake",
            "2001:db8::10",
            "--transport",
            "quic",
            "--port",
            "4434",
            "--server-name",
            "example.test",
            "--alpn",
            "tatami-diag/0",
            "--cert-sha256",
            PIN,
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
        assert!(matches!(
            o.trust,
            tatami::quic_diag::client::Trust::Tls(ClientTrust::PinnedCertificateSha256(_))
        ));
        assert!(o.exporter_probe);
        assert_eq!(o.handshake_timeout, Duration::from_secs(2));
        assert!(json);

        let Command::QuicHandshake { options: o, json } = parse_args(&args(&[
            "handshake",
            "--transport",
            "quic",
            "h",
            "--alpn",
            "x",
            "--cert-sha256",
            PIN,
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(o.port, 4433);
        assert_eq!(o.handshake_timeout, Duration::from_secs(5));
        assert_eq!(o.effective_server_name(), "h");
        assert!(!o.exporter_probe);
        assert!(!json);
    }

    #[cfg(feature = "quic-diag")]
    #[test]
    fn rejects_bad_quic_usage() {
        let q = |rest: &[&str]| {
            let mut a = vec!["handshake", "--transport", "quic"];
            a.extend_from_slice(rest);
            parse_args(&args(&a))
        };
        for rest in [
            &[][..],
            &["h"],
            &["h", "--alpn", "x"],
            &["h", "--cert-sha256", PIN],
            &["h", "--alpn", "", "--cert-sha256", PIN],
            &["h", "--alpn", "x", "--cert-sha256", "SHA256:short"],
            &["h", "--alpn", "x", "--cert-sha256", PIN, "--port", "0"],
            &["h", "--alpn", "x", "--cert-sha256", PIN, "--timeout", "0s"],
            &[
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                PIN,
                "--cert-sha256",
                PIN,
            ],
            &["h", "--alpn", "x", "--cert-sha256", PIN, "--bogus"],
            &["h", "--alpn", "x", "--cert-sha256", PIN, "extra"],
            &["h", "--alpn", "x", "--root-cert", "/nonexistent/root.pem"],
            // Trust options are never combined.
            &[
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                PIN,
                "--host-key-sha256",
                PIN,
            ],
            &[
                "h",
                "--alpn",
                "x",
                "--known-hosts",
                "kh",
                "--host-key-sha256",
                PIN,
            ],
            &["h", "--alpn", "x", "--known-hosts", ""],
            &["h", "--alpn", "x", "--host-key-sha256", "SHA256:short"],
            // TCP-only options are not accepted by the QUIC transport.
            &["h", "--alpn", "x", "--cert-sha256", PIN, "--no-strict-kex"],
            &[
                "h",
                "--alpn",
                "x",
                "--cert-sha256",
                PIN,
                "--transport",
                "tcp",
            ],
        ] {
            assert!(q(rest).is_err(), "{rest:?}");
        }
    }

    #[cfg(feature = "quic-diag")]
    #[test]
    fn parses_quic_ssh_host_key_trust() {
        use tatami::quic_diag::client::Trust;
        use tatami::trust::TrustConfig;

        let parse = |extra: &[&str]| {
            let mut a = vec!["handshake", "h", "--transport", "quic", "--alpn", "x"];
            a.extend_from_slice(extra);
            match parse_args(&args(&a)).unwrap() {
                Command::QuicHandshake { options, .. } => options,
                _ => panic!(),
            }
        };
        let o = parse(&["--host-key-sha256", PIN]);
        let Trust::SshHostKey(TrustConfig::Pin(p)) = &o.trust else {
            panic!("{:?}", o.trust)
        };
        assert_eq!(p.to_string(), PIN);
        assert_eq!(o.trust.identity_mode(), "ssh_host_key_raw_public_key");
        let o = parse(&[
            "--known-hosts",
            "/some/known_hosts",
            "--server-name",
            "tls.example",
        ]);
        assert!(matches!(
            &o.trust,
            Trust::SshHostKey(TrustConfig::KnownHostsFile(p)) if p.to_str() == Some("/some/known_hosts")
        ));
        // --server-name stays a TLS parameter.
        assert_eq!(o.effective_server_name(), "tls.example");
        assert_eq!(o.host, "h");
    }

    #[cfg(feature = "kex")]
    #[test]
    fn parses_tcp_known_hosts_and_refuses_two_trust_options() {
        let Command::Handshake { options: o, .. } = parse_args(&args(&[
            "handshake",
            "h",
            "--known-hosts",
            "/some/known_hosts",
        ]))
        .unwrap() else {
            panic!()
        };
        assert_eq!(
            o.trust.known_hosts_file().and_then(|p| p.to_str()),
            Some("/some/known_hosts")
        );
        let e = parse_args(&args(&[
            "handshake",
            "h",
            "--known-hosts",
            "kh",
            "--host-key-sha256",
            PIN,
        ]))
        .err()
        .unwrap()
        .0;
        assert!(e.contains("exactly one"), "{e}");
        assert!(
            parse_args(&args(&[
                "handshake",
                "h",
                "--host-key-sha256",
                PIN,
                "--host-key-sha256",
                PIN
            ]))
            .is_err()
        );
    }

    #[test]
    fn help_states_the_quic_caveats() {
        for word in [
            "EXPERIMENTAL",
            "UNREGISTERED",
            "no interoperability",
            "not an SSH client",
            "0-RTT",
            "not an SSH host-key fingerprint",
            "--transport quic",
        ] {
            assert!(USAGE.contains(word), "help text lacks {word:?}");
        }
    }
}
