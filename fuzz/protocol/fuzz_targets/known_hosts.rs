#![no_main]
//! `tatami_ssh_keys::known_hosts`: parsing, matching and the trust decision of
//! `KnownHostsPolicy`. Pattern: trust policy. Built with
//! `openssh-hashed-hosts`, so hashed names reach the matcher in
//! `tatami_ssh_openssh_compat`; the build without it (explicit unsupported
//! error) is covered by unit and integration tests.
//!
//! 1. API/input: a small description is decoded into `known_hosts` text,
//!    a lookup (host, port) and an offered key; the text goes through
//!    `KnownHosts::parse`, the lookup through `policy_for`, the key through
//!    `HostKey::parse` (as the handshake does) and then
//!    `HostTrustPolicy::decide`. Structure is generated because raw
//!    mutation almost never produces a valid base64 key blob, so it would
//!    not reach matching or the decision at all.
//!
//!    Keys: K0-K2 Ed25519 (derived), RSA = the `ssh-keygen` RSA 2048
//!    fixture, P256 = the P-256 fixture, RSA1024 = the 1024-bit fixture
//!    (structurally valid, outside the RSA policy: an inert entry), P384 =
//!    the P-384 fixture (a type this crate does not implement: opaque).
//!
//!    ```text
//!    byte 0   bits 0-1 lookup (host.example:22, HOST.Example:22,
//!             host.example:2222, other.example:22); bits 2-3 offered key
//!             K0/K1/K2, 3 = RSA/P256/RSA1024 by (bits 5-7) % 3; bit 4
//!             inject one malformed line; bits 5-7 malformed kind (unknown
//!             marker, bad base64, key-type mismatch, missing key, empty
//!             pattern, Ed25519 key of 31 bytes, @revoked RSA with a
//!             non-minimal e, P-256 with curve nistp254)
//!    byte 1   lines: 1 + b % 8
//!    byte 2   position of the malformed line (b % (lines + 1))
//!    per line marker (b % 3: none, @revoked, @cert-authority), key (b % 7:
//!             K0, K1, K2, RSA, P256, RSA1024, P384), hosts h, p1, p2, p3:
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
//!      line number and kind; a malformed `@revoked` line is never skipped;
//!      `InvalidKey(kt)` names the (enabled) type of the broken key. Lines of
//!      every key above parse: RSA1024 (policy only) and P384 (not
//!      implemented) are kept as entries and are never `InvalidKey`.
//!    - The inert RSA1024 entry never leads to trust: presented, that key
//!      fails `HostKey::parse` with `RsaModulus{1024}` before any decision
//!      (the handshake and the QUIC verifier both parse first), so the
//!      decision is only evaluated for keys that parse.
//!    - `Entry::applies_to` equals the harness's view of each generated line
//!      (`glob_ref` DP matcher on lowercased patterns, negation excludes,
//!      harness HMAC-SHA1 for hashed names).
//!    - `decide` equals the contract computed over the generated entries:
//!      an applicable revocation of the offered key wins (first such line),
//!      else the first applicable plain line listing it trusts, else
//!      `KeyChanged` (first applicable plain line of the offered key's
//!      algorithm: an RSA1024 line is `ssh-rsa` and so "changed" for the
//!      RSA 2048 key), `NoKeyForAlgorithm`, `CertificateAuthorityOnly`,
//!      `UnknownHost`.
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
use tatami_ssh_fuzz_protocol::keys_support::{
    b64_encode, ed25519_blob, fixtures, glob_ref, hmac_sha1, ssh_string,
};
use tatami_ssh_fuzz_protocol::tcp_support::Cursor;
use tatami_ssh_keys::algorithm::KeyType;
use tatami_ssh_keys::error::KeyError;
use tatami_ssh_keys::fingerprint::Sha256Fingerprint;
use tatami_ssh_keys::host_key::HostKey;
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

const RSA: usize = 3;
const P256: usize = 4;
const RSA1024: usize = 5;
const P384: usize = 6;

/// Key-type field of each key.
const ALG: [&str; 7] = [
    "ssh-ed25519",
    "ssh-ed25519",
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ssh-rsa",
    "ecdsa-sha2-nistp384",
];

fn keys() -> &'static [Vec<u8>; 7] {
    static KEYS: OnceLock<[Vec<u8>; 7]> = OnceLock::new();
    KEYS.get_or_init(|| {
        let ed = |s: u8| ed25519_blob(SigningKey::from_bytes(&[s; 32]).verifying_key().as_bytes());
        let keys = [
            ed(1),
            ed(2),
            ed(3),
            fixtures::bytes("RSA_2048_PUB"),
            fixtures::bytes("P256_PUB"),
            fixtures::bytes("RSA_1024_PUB"),
            fixtures::bytes("P384_PUB"),
        ];
        for (k, alg) in keys.iter().zip(ALG) {
            assert_eq!(&k[4..4 + alg.len()], alg.as_bytes(), "blob names its type");
        }
        keys
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
        format!(
            "{marker}{hosts} {} {} c\n",
            ALG[self.key],
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
    if let Some(line) = first(&|l| l.mark == Mark::None && ALG[l.key] == ALG[offered]) {
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
    // Presented keys are parsed before any decision (handshake, QUIC).
    let presented = HostKey::parse(blob).expect("only parseable keys reach decide");
    assert_eq!(presented.algorithm(), ALG[offered].as_bytes());
    policy.decide(&HostIdentity {
        algorithm: ALG[offered].as_bytes(),
        blob,
        sha256: Sha256Fingerprint::of_blob(blob),
    })
}

fn render(lines: &[Line]) -> String {
    lines.iter().map(Line::text).collect()
}

fn malformed(kind: u8) -> (String, Malformed) {
    let key = b64_encode(&keys()[0]);
    match kind % 8 {
        5 => {
            let mut short = ssh_string(b"ssh-ed25519");
            short.extend(ssh_string(&[7; 31]));
            (
                format!("host.example ssh-ed25519 {}\n", b64_encode(&short)),
                Malformed::InvalidKey(KeyType::Ed25519),
            )
        }
        6 => {
            // RSA 2048 with a redundant leading zero on e, revoked.
            let good = &keys()[RSA];
            let mut bad = ssh_string(b"ssh-rsa");
            bad.extend(ssh_string(&[0, 1, 0, 1]));
            bad.extend_from_slice(&good[4 + 7 + 4 + 3..]);
            (
                format!("@revoked * ssh-rsa {}\n", b64_encode(&bad)),
                Malformed::InvalidKey(KeyType::Rsa),
            )
        }
        7 => {
            let mut bad = keys()[P256].clone();
            bad[34] = b'4'; // nistp256 -> nistp254
            (
                format!("host.example ecdsa-sha2-nistp256 {}\n", b64_encode(&bad)),
                Malformed::InvalidKey(KeyType::EcdsaP256),
            )
        }
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
    let offered = match (flags >> 2) & 3 {
        3 => [RSA, P256, RSA1024][usize::from(flags >> 5) % 3],
        k => usize::from(k),
    };
    let n = 1 + usize::from(cur.u8()) % 8;
    let bad_at = usize::from(cur.u8()) % (n + 1);
    let mut lines = Vec::with_capacity(n);
    for i in 0..n {
        let mark = [Mark::None, Mark::Revoked, Mark::Ca][usize::from(cur.u8()) % 3];
        let key = usize::from(cur.u8()) % 7;
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

    // The inert entry: kept, but its key can never be presented.
    if offered == RSA1024 {
        assert_eq!(
            HostKey::parse(&keys()[RSA1024]),
            Err(KeyError::RsaModulus { bits: 1024 }),
            "a policy-violating key is refused before any trust decision"
        );
        assert_eq!(
            HostKey::parse(&keys()[P384]),
            Err(KeyError::UnsupportedAlgorithm(
                b"ecdsa-sha2-nistp384".to_vec()
            ))
        );
        return;
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
