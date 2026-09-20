//! `tatami-server`: reserved command entry point.
//!
//! No server functionality exists yet. This binary answers `--help` and
//! `--version` and otherwise explains that listening and key exchange are
//! not implemented. It does not open a listener and does not generate host
//! keys. When `tatami::server` gains real functionality, this file becomes
//! a thin call into it.
//!
//! Exit status: 0 for `--help`/`--version`; 1 for any other invocation
//! (not implemented); 2 for unknown options.

use std::process::ExitCode;

const NAME: &str = "tatami-server";
const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage:
  tatami-server --help
  tatami-server --version

Status:
  tatami-server is an entry-point stub. It does not yet listen for
  connections, perform key exchange, load or generate host keys, or accept
  SSH sessions. Any invocation other than --help/--version exits with
  status 1 after printing this notice.

Exit status: 0 help/version; 1 not implemented; 2 unknown option.
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--help" | "-h" | "help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("--version" | "-V" | "version") => {
            println!("{NAME} {VERSION}");
            ExitCode::SUCCESS
        }
        Some(opt) if opt.starts_with('-') => {
            eprintln!("{NAME}: unknown option {opt:?}");
            eprintln!();
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
        _ => {
            eprintln!(
                "{NAME}: not implemented: this build cannot listen for connections or \
                 perform key exchange. No listener was opened and no host key was created."
            );
            eprintln!();
            eprint!("{USAGE}");
            ExitCode::from(1)
        }
    }
}
