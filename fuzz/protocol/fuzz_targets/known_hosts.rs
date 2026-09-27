#![no_main]
//! `tatami_ssh_keys::known_hosts`: parsing, matching and the trust decision of
//! `KnownHostsPolicy`. Pattern: trust policy.
//!
//! 1. API/input: a small description is decoded into `known_hosts` text,
//!    a lookup (host, port) and an offered key; the text goes through
//!    `KnownHosts::parse`, the lookup through `policy_for`, the key through
//!    `HostTrustPolicy::decide`. Structure is generated because raw
//!    mutation almost never produces a valid base64 Ed25519 blob, so it
//!    would not reach matching or the decision at all.
//!
//!    ```text
//!    byte 0   bits 0-1 lookup (host.example:22, HOST.Example:22,
//!             host.example:2222, other.example:22); bits 2-3 offered key
//!             K0/K1/K2 (3 = K0); bit 4 inject one malformed line; bits 5-7
//!             malformed kind (unknown marker, bad base64, key-type mismatch,
//!             missing key, empty pattern; 5-7 wrap)
//!    byte 1   lines: 1 + b % 8
//!    byte 2   position of the malformed line (b % (lines + 1))
//!    per line marker (b % 3: none, @revoked, @cert-authority), key (b % 4:
//!             K0, K1, K2, a well-formed ssh-rsa blob), hosts h, p1, p2, p3:
//!             h bit 7 = one hashed name (lookup (h >> 3) % 4, HMAC-SHA1 by
//!             the harness), else 1 + h % 3 patterns from a 10-entry
//!             vocabulary (bit 7 of p = negated)
//!    rest     glob check: pattern and name over {a, b, ., *, ?}
//!    ```
//!
//! 2. Outcomes: `KnownHostsError` with line numbers, or entries; decisions
//!    `Trusted { KnownHosts { line } }` / `Untrusted { reason }`. At most 9
//!    lines of at most 3 patterns.
//! 3. Properties:
//!    - An injected malformed line fails the whole file with exactly that
//!      line number and kind; a malformed `@revoked` line is never skipped.
//!    - `Entry::applies_to` equals the harness's view of each generated line
//!      (`glob_ref` DP matcher on lowercased patterns, negation excludes,
//!      harness HMAC-SHA1 for hashed names).
//!    - `decide` equals the contract computed over the generated entries:
//!      an applicable revocation of the offered key wins (first such line),
//!      else the first applicable plain line listing it trusts, else
//!      `KeyChanged` (first applicable `ssh-ed25519` line),
//!      `NoKeyForAlgorithm`, `CertificateAuthorityOnly`, `UnknownHost`.
//!    - Appending an entry that cannot apply leaves the decision unchanged;
//!      reversing the lines keeps the outcome code; appending an applicable
//!      `@revoked` line for the offered key turns any decision into
//!      `Revoked` at that line; a CA line with the offered key never trusts.
//!    - `glob_match` equals `glob_ref`.
//!
//!    Exact semantics (OpenSSH `ssh-keygen -F` agreement, limits, bounded
//!    glob) are unit/integration tests in `tatami_ssh_keys` and
//!    `crates/tatami_ssh/tests/host_identity.rs`.
//! 4. Not covered: `Limits` errors (unit tests), arbitrary bytes beyond the
//!    malformed kinds above, file I/O (host layer).

use std::sync::OnceLock;

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use tatami_ssh_fuzz_protocol::keys_support::{b64_encode, ed25519_blob, glob_ref, hmac_sha1};
use tatami_ssh_fuzz_protocol::tcp_support::Cursor;
use tatami_ssh_keys::fingerprint::Sha256Fingerprint;
use tatami_ssh_keys::known_hosts::{KnownHosts, KnownHostsError, Limits, Malformed, glob_match};
use tatami_ssh_keys::trust::{
    HostIdentity, HostTrustPolicy, TrustDecision, TrustSource, UntrustedReason,
};

const VOCAB: [&str; 10] = [
    "host.example",
    "HOST.EXAMPLE",
    "*",
    "*.example",
    "h?st.example",
    "[host.example]:2222",
    "[*.example]:2222",
    "other.example",
    "[host.example]:*",
    "*:2222",
];

const LOOKUPS: [(&str, u16, &str); 4] = [
    ("host.example", 22, "host.example"),
    ("HOST.Example", 22, "host.example"),
    ("host.example", 2222, "[host.example]:2222"),
    ("other.example", 22, "other.example"),
];

fn keys() -> &'static [Vec<u8>; 4] {
    static KEYS: OnceLock<[Vec<u8>; 4]> = OnceLock::new();
    KEYS.get_or_init(|| {
        let ed = |s: u8| ed25519_blob(SigningKey::from_bytes(&[s; 32]).verifying_key().as_bytes());
        let mut rsa = Vec::new();
        for part in [&b"ssh-rsa"[..], &[1, 2, 3]] {
            rsa.extend_from_slice(&(part.len() as u32).to_be_bytes());
            rsa.extend_from_slice(part);
        }
        [ed(1), ed(2), ed(3), rsa]
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mark {
    None,
    Revoked,
    Ca,
}

#[derive(Clone, Debug)]
enum Hosts {
    Patterns(Vec<(bool, &'static str)>),
    Hashed { lookup: usize, salt: [u8; 20] },
}

#[derive(Clone, Debug)]
struct Line {
    mark: Mark,
    key: usize,
    hosts: Hosts,
}

impl Line {
    fn text(&self) -> String {
        let marker = match self.mark {
            Mark::None => "",
            Mark::Revoked => "@revoked ",
            Mark::Ca => "@cert-authority ",
        };
        let hosts = match &self.hosts {
            Hosts::Patterns(p) => p
                .iter()
                .map(|(neg, t)| format!("{}{t}", if *neg { "!" } else { "" }))
                .collect::<Vec<_>>()
                .join(","),
            Hosts::Hashed { lookup, salt } => format!(
                "|1|{}|{}",
                b64_encode(salt),
                b64_encode(&hmac_sha1(salt, LOOKUPS[*lookup].2.as_bytes()))
            ),
        };
        let alg = if self.key == 3 {
            "ssh-rsa"
        } else {
            "ssh-ed25519"
        };
        format!(
            "{marker}{hosts} {alg} {} c\n",
            b64_encode(&keys()[self.key])
        )
    }

    fn applies(&self, name: &str) -> bool {
        match &self.hosts {
            Hosts::Hashed { lookup, .. } => LOOKUPS[*lookup].2 == name,
            Hosts::Patterns(p) => {
                let hit = |t: &str| glob_ref(t.to_ascii_lowercase().as_bytes(), name.as_bytes());
                !p.iter().any(|(neg, t)| *neg && hit(t)) && p.iter().any(|(neg, t)| !*neg && hit(t))
            }
        }
    }
}

/// The documented decision order over the harness's own entries.
fn expected(lines: &[Line], name: &str, offered: usize) -> TrustDecision {
    let applicable: Vec<(usize, &Line)> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.applies(name))
        .map(|(i, l)| (i + 1, l))
        .collect();
    let untrusted = |reason| TrustDecision::Untrusted { reason };
    let first = |f: &dyn Fn(&Line) -> bool| applicable.iter().find(|(_, l)| f(l)).map(|(n, _)| *n);
    if let Some(line) = first(&|l| l.mark == Mark::Revoked && l.key == offered) {
        return untrusted(UntrustedReason::Revoked { line });
    }
    if let Some(line) = first(&|l| l.mark == Mark::None && l.key == offered) {
        return TrustDecision::Trusted {
            source: TrustSource::KnownHosts { line },
        };
    }
    if let Some(line) = first(&|l| l.mark == Mark::None && l.key != 3) {
        return untrusted(UntrustedReason::KeyChanged { line });
    }
    if first(&|l| l.mark == Mark::None).is_some() {
        return untrusted(UntrustedReason::NoKeyForAlgorithm);
    }
    if first(&|l| l.mark == Mark::Ca).is_some() {
        return untrusted(UntrustedReason::CertificateAuthorityOnly);
    }
    untrusted(UntrustedReason::UnknownHost)
}

fn code(d: &TrustDecision) -> &'static str {
    match d {
        TrustDecision::Trusted { source } => source.code(),
        TrustDecision::Untrusted { reason } => reason.code(),
    }
}

fn decide(text: &str, lookup: usize, offered: usize) -> TrustDecision {
    let kh = KnownHosts::parse(text.as_bytes(), &Limits::default())
        .unwrap_or_else(|e| panic!("generated file refused: {e}\n{text}"));
    let (host, port, name) = LOOKUPS[lookup];
    let policy = kh
        .policy_for(host, port)
        .expect("vocabulary hosts are valid");
    assert_eq!(policy.lookup_name(), name);
    let blob = &keys()[offered];
    policy.decide(&HostIdentity {
        algorithm: b"ssh-ed25519",
        blob,
        sha256: Sha256Fingerprint::of_blob(blob),
    })
}

fn render(lines: &[Line]) -> String {
    lines.iter().map(Line::text).collect()
}

fn malformed(kind: u8) -> (String, Malformed) {
    let key = b64_encode(&keys()[0]);
    match kind % 5 {
        0 => (
            format!("@bogus host.example ssh-ed25519 {key}\n"),
            Malformed::UnknownMarker,
        ),
        1 => (
            String::from("@revoked * ssh-ed25519 !!!!\n"),
            Malformed::Base64,
        ),
        2 => (
            format!("host.example ssh-rsa {key}\n"),
            Malformed::KeyTypeMismatch,
        ),
        3 => (
            String::from("host.example ssh-ed25519\n"),
            Malformed::MissingField("key"),
        ),
        _ => (format!("a,,b ssh-ed25519 {key}\n"), Malformed::EmptyPattern),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let flags = cur.u8();
    let lookup = usize::from(flags & 3);
    let offered = usize::from((flags >> 2) & 3) % 3;
    let n = 1 + usize::from(cur.u8()) % 8;
    let bad_at = usize::from(cur.u8()) % (n + 1);
    let mut lines = Vec::with_capacity(n);
    for i in 0..n {
        let mark = [Mark::None, Mark::Revoked, Mark::Ca][usize::from(cur.u8()) % 3];
        let key = usize::from(cur.u8()) % 4;
        let h = cur.u8();
        let p = [cur.u8(), cur.u8(), cur.u8()];
        let hosts = if h & 0x80 != 0 {
            Hosts::Hashed {
                lookup: usize::from(h >> 3) % 4,
                salt: [i as u8 ^ h; 20],
            }
        } else {
            Hosts::Patterns(
                p[..1 + usize::from(h) % 3]
                    .iter()
                    .map(|&b| (b & 0x80 != 0, VOCAB[usize::from(b & 0x7f) % VOCAB.len()]))
                    .collect(),
            )
        };
        lines.push(Line { mark, key, hosts });
    }
    let name = LOOKUPS[lookup].2;

    if flags & 0x10 != 0 {
        let (bad, kind) = malformed(flags >> 5);
        let mut text = render(&lines[..bad_at]);
        text.push_str(&bad);
        text.push_str(&render(&lines[bad_at..]));
        assert_eq!(
            KnownHosts::parse(text.as_bytes(), &Limits::default()),
            Err(KnownHostsError::Malformed {
                line: bad_at + 1,
                what: kind
            }),
            "{text}"
        );
        return;
    }

    let text = render(&lines);
    let kh = KnownHosts::parse(text.as_bytes(), &Limits::default()).expect("well-formed");
    assert_eq!(kh.entries().len(), n);
    for (e, l) in kh.entries().iter().zip(&lines) {
        assert_eq!(
            e.applies_to(name),
            l.applies(name),
            "line {}: {text}",
            e.line()
        );
        assert_eq!(e.blob(), &keys()[l.key][..]);
        assert_eq!(e.is_hashed(), matches!(l.hosts, Hosts::Hashed { .. }));
    }

    let got = decide(&text, lookup, offered);
    assert_eq!(
        got,
        expected(&lines, name, offered),
        "lookup {name}:\n{text}"
    );

    // An entry that cannot apply changes nothing.
    let mut more = lines.clone();
    more.push(Line {
        mark: [Mark::None, Mark::Revoked, Mark::Ca][usize::from(flags >> 5) % 3],
        key: offered,
        hosts: Hosts::Patterns(vec![(false, "unrelated.invalid")]),
    });
    assert_eq!(decide(&render(&more), lookup, offered), got);

    // Order changes line numbers, never the outcome.
    let reversed: Vec<Line> = lines.iter().rev().cloned().collect();
    assert_eq!(
        code(&decide(&render(&reversed), lookup, offered)),
        code(&got)
    );

    // An applicable revocation of the offered key always wins.
    let mut revoked = lines.clone();
    revoked.push(Line {
        mark: Mark::Revoked,
        key: offered,
        hosts: Hosts::Patterns(vec![(false, "*")]),
    });
    let r = decide(&render(&revoked), lookup, offered);
    let first_revocation = match got {
        TrustDecision::Untrusted {
            reason: UntrustedReason::Revoked { line },
        } => line,
        _ => n + 1,
    };
    assert_eq!(
        r,
        TrustDecision::Untrusted {
            reason: UntrustedReason::Revoked {
                line: first_revocation
            }
        }
    );

    // A CA entry for the offered key is never a pinned host key.
    let ca_only = [Line {
        mark: Mark::Ca,
        key: offered,
        hosts: Hosts::Patterns(vec![(false, "*")]),
    }];
    assert!(!decide(&render(&ca_only), lookup, offered).is_trusted());

    // Bounded glob against the DP reference.
    let alphabet = b"ab.*?";
    let rest = cur.rest();
    let (pat, nm) = rest.split_at(rest.len().min(12) / 2);
    let pat: Vec<u8> = pat.iter().map(|b| alphabet[usize::from(*b) % 5]).collect();
    let nm: Vec<u8> = nm
        .iter()
        .take(24)
        .map(|b| alphabet[usize::from(*b) % 3])
        .collect();
    assert_eq!(glob_match(&pat, &nm), glob_ref(&pat, &nm), "{pat:?} {nm:?}");
});
