//! Read-only OpenSSH `known_hosts` parsing, matching and trust decisions
//! (feature `known-hosts`).
//!
//! This module never reads files, prompts, enrolls or writes: the caller
//! supplies bytes (the facade's host layer reads an explicitly named file
//! with a size bound), [`KnownHosts::parse`] validates all of it up front,
//! and [`KnownHosts::policy_for`] binds the parsed file to one logical
//! lookup name, producing a [`KnownHostsPolicy`] that implements
//! [`HostTrustPolicy`]. The TCP handshake and the QUIC raw-public-key
//! verifier both use that same policy object.
//!
//! # Supported subset (deliberately stricter than OpenSSH)
//!
//! - Lines: `[marker] hostpatterns keytype base64-key [comment]`; blank lines
//!   and lines starting with `#` (after optional whitespace) are ignored; a
//!   trailing `\r` is stripped.
//! - Markers: `@revoked` and `@cert-authority`. Any other `@` marker is a
//!   configuration error.
//! - Host patterns: comma-separated, `*` and `?` wildcards, `!` negation,
//!   `[host]:port` for non-default ports, all matched ASCII
//!   case-insensitively.
//! - Hashed host names (`ssh-keygen -H`, `HashKnownHosts`): a host field
//!   that begins with `|` is a hashed entry. **Only with the
//!   `openssh-hashed-hosts` feature** is it accepted: it must then be
//!   exactly one `|1|salt|hash` (canonical padded base64, 20-byte salt and
//!   HMAC-SHA1 digest), validated at parse time and matched by the
//!   `tatami_ssh_openssh_compat` crate — the only SHA-1 use in Tatami, which
//!   enables no SHA-1 signature, key exchange, MAC, fingerprint or SSHFP
//!   digest. Without the feature, any hashed entry — including in an
//!   `@revoked` or `@cert-authority` line — fails the whole file with
//!   [`KnownHostsError::Unsupported`] (never skipped). A `|` pattern inside
//!   a comma-separated list is malformed in both builds.
//! - Keys: the key type must equal the algorithm named inside the decoded
//!   blob. Keys of every enabled type are validated structurally with the
//!   same parser the handshake uses: `ssh-ed25519` (length, point),
//!   `ssh-rsa` (feature `rsa`: strict positive `mpint`s, no trailing
//!   bytes) and `ecdsa-sha2-nistp256` (feature `ecdsa-p256`: curve name,
//!   uncompressed point, no trailing bytes). A structurally valid RSA key
//!   outside the size/exponent policy (for example a legacy 1024-bit key of
//!   another host) is kept as an entry but can never match: a presented key
//!   outside the policy is refused before any trust decision. Other key
//!   types are accepted as opaque entries and confer no trust on another
//!   type. Malformed structure, base64 or blobs — including in `@revoked`
//!   lines — make the whole file a configuration error with a line number:
//!   a broken revocation is never skipped.
//! - Not supported: SSH-1 (`bits e n`) lines, `@cert-authority` host
//!   certificates (a CA line is recorded but never trusted as a host key),
//!   and `known_hosts` options beyond the above.
//!
//! # Lookup name
//!
//! [`lookup_name`] lowercases the host (ASCII) and, for any port other than
//! 22, writes `[host]:port` — OpenSSH's rule, on both transports. TCP and
//! UDP at the same numeric port therefore share an entry; different ports do
//! not. The name is logical: resolution results, TLS SNI and QUIC path
//! changes never replace it.
//!
//! # Decision (all applicable entries are considered, in any order)
//!
//! 1. An applicable `@revoked` line listing the presented key → `Revoked`,
//!    whatever else matches.
//! 2. An applicable plain line listing the presented key → trusted. Several
//!    keys for one host (rotation) are fine; a stale one does not defeat a
//!    separate valid match.
//! 3. Applicable plain lines for the key's algorithm, none listing it →
//!    `KeyChanged`.
//! 4. Applicable plain lines only for other algorithms →
//!    `NoKeyForAlgorithm`; only `@cert-authority` lines →
//!    `CertificateAuthorityOnly`; nothing → `UnknownHost`.
//!
//! A line applies when some positive pattern matches the lookup name and no
//! negated pattern does, or when its hashed field is the HMAC of the lookup
//! name.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use base64ct::{Base64, Encoding as _};

use crate::algorithm::KeyType;
use crate::blob::PublicKeyBlob;
use crate::error::KeyError;
use crate::host_key::HostKey;
use crate::trust::{HostIdentity, HostTrustPolicy, TrustDecision, TrustSource, UntrustedReason};

/// The default SSH port, written without brackets in lookup names.
pub const DEFAULT_PORT: u16 = 22;

/// Longest lookup name [`lookup_name`] forms, in bytes (the same bound the
/// hashed-name matcher applies). A policy bound to a longer name through
/// [`KnownHosts::policy_for_name`] has no applicable entries.
pub const MAX_LOOKUP_NAME_BYTES: usize = 1024;

/// Resource bounds applied while parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum file size in bytes.
    pub max_file_bytes: usize,
    /// Maximum line length in bytes (excluding the newline).
    pub max_line_bytes: usize,
    /// Maximum number of entries (non-comment lines).
    pub max_entries: usize,
    /// Maximum comma-separated patterns on one line.
    pub max_patterns_per_line: usize,
}

impl Default for Limits {
    /// 1 MiB file, 16 KiB lines (room for 16384-bit RSA entries), 10 000
    /// entries, 256 patterns per line.
    fn default() -> Self {
        Limits {
            max_file_bytes: 1 << 20,
            max_line_bytes: 16 * 1024,
            max_entries: 10_000,
            max_patterns_per_line: 256,
        }
    }
}

/// Line marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    /// An ordinary host key line.
    None,
    /// `@revoked`: the key must never be accepted for matching hosts.
    Revoked,
    /// `@cert-authority`: a CA for host certificates (unsupported; never
    /// trusted as a host key).
    CertAuthority,
}

/// What is wrong with one line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// A marker other than `@revoked` / `@cert-authority`.
    UnknownMarker,
    /// A required field is missing.
    MissingField(&'static str),
    /// A comma-separated pattern is empty (or only `!`).
    EmptyPattern,
    /// A hashed host field is not exactly one `|1|salt|hash` with
    /// canonical base64 20-byte values (checked with
    /// `openssh-hashed-hosts`), or a `|` pattern is combined with other
    /// patterns (in every build).
    HashedHost,
    /// The key is not valid padded standard base64.
    Base64,
    /// The decoded key does not start with a valid algorithm string.
    Blob,
    /// The key type field differs from the algorithm inside the blob.
    KeyTypeMismatch,
    /// A key of an enabled type that does not parse: for `ssh-ed25519` the
    /// wrong length, trailing bytes or an invalid point; for `ssh-rsa`
    /// non-canonical or missing integers or trailing bytes; for
    /// `ecdsa-sha2-nistp256` a wrong curve name, point encoding or trailing
    /// bytes.
    InvalidKey(KeyType),
    /// The line contains a NUL byte.
    NulByte,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Malformed::UnknownMarker => "unknown marker (only @revoked and @cert-authority)",
            Malformed::MissingField(what) => return write!(f, "missing {what}"),
            Malformed::EmptyPattern => "empty host pattern",
            Malformed::HashedHost => "malformed hashed host (expected one |1|salt|hash)",
            Malformed::Base64 => "key is not valid base64",
            Malformed::Blob => "key blob does not start with an algorithm name",
            Malformed::KeyTypeMismatch => "key type does not match the key blob",
            Malformed::InvalidKey(key_type) => return write!(f, "invalid {key_type} key"),
            Malformed::NulByte => "NUL byte in line",
        })
    }
}

/// A well-formed construct this build does not support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unsupported {
    /// A hashed host field (`|1|salt|hash`) in a build without the
    /// `openssh-hashed-hosts` feature.
    HashedHostnames,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Unsupported::HashedHostnames => {
                "hashed host names (|1|...) are not supported by this build; rebuild with the \
                 `openssh-hashed-hosts` feature or list plaintext host names"
            }
        })
    }
}

/// A configuration error: the file as a whole is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownHostsError {
    /// The file exceeds [`Limits::max_file_bytes`].
    FileTooLarge {
        /// The limit.
        limit: usize,
    },
    /// A line exceeds [`Limits::max_line_bytes`].
    LineTooLong {
        /// 1-based line number.
        line: usize,
        /// The limit.
        limit: usize,
    },
    /// More entries than [`Limits::max_entries`].
    TooManyEntries {
        /// The limit.
        limit: usize,
    },
    /// More patterns on one line than [`Limits::max_patterns_per_line`].
    TooManyPatterns {
        /// 1-based line number.
        line: usize,
        /// The limit.
        limit: usize,
    },
    /// A malformed line.
    Malformed {
        /// 1-based line number.
        line: usize,
        /// What is wrong.
        what: Malformed,
    },
    /// A line uses a format this build does not support. Distinct from
    /// [`KnownHostsError::Malformed`]: the file may be valid for OpenSSH.
    Unsupported {
        /// 1-based line number.
        line: usize,
        /// What is unsupported.
        what: Unsupported,
    },
}

impl KnownHostsError {
    /// The line the error refers to, if any.
    #[must_use]
    pub const fn line(&self) -> Option<usize> {
        match self {
            KnownHostsError::LineTooLong { line, .. }
            | KnownHostsError::TooManyPatterns { line, .. }
            | KnownHostsError::Malformed { line, .. }
            | KnownHostsError::Unsupported { line, .. } => Some(*line),
            KnownHostsError::FileTooLarge { .. } | KnownHostsError::TooManyEntries { .. } => None,
        }
    }
}

impl fmt::Display for KnownHostsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KnownHostsError::FileTooLarge { limit } => {
                write!(f, "known_hosts file exceeds {limit} bytes")
            }
            KnownHostsError::LineTooLong { line, limit } => {
                write!(f, "known_hosts line {line} exceeds {limit} bytes")
            }
            KnownHostsError::TooManyEntries { limit } => {
                write!(f, "known_hosts has more than {limit} entries")
            }
            KnownHostsError::TooManyPatterns { line, limit } => {
                write!(
                    f,
                    "known_hosts line {line} has more than {limit} host patterns"
                )
            }
            KnownHostsError::Malformed { line, what } => {
                write!(f, "known_hosts line {line}: {what}")
            }
            KnownHostsError::Unsupported { line, what } => {
                write!(f, "known_hosts line {line}: {what}")
            }
        }
    }
}

impl core::error::Error for KnownHostsError {}

/// Why a host/port cannot form a lookup name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupNameError {
    /// The host is empty.
    Empty,
    /// The host contains whitespace, a control byte, `,`, `[`, `]` or a
    /// pattern metacharacter (`*`, `?`, `!`), which would change how it
    /// matches.
    InvalidCharacter,
    /// The lookup name would exceed [`MAX_LOOKUP_NAME_BYTES`].
    TooLong,
}

impl fmt::Display for LookupNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LookupNameError::Empty => "host name for known_hosts lookup is empty",
            LookupNameError::InvalidCharacter => {
                "host name for known_hosts lookup contains a character that cannot appear in a host"
            }
            LookupNameError::TooLong => "host name for known_hosts lookup is too long",
        })
    }
}

impl core::error::Error for LookupNameError {}

/// The logical `known_hosts` lookup name for `host` and `port`: ASCII
/// lowercase, bare for port 22, `[host]:port` otherwise; at most
/// [`MAX_LOOKUP_NAME_BYTES`].
pub fn lookup_name(host: &str, port: u16) -> Result<String, LookupNameError> {
    if host.is_empty() {
        return Err(LookupNameError::Empty);
    }
    if host
        .bytes()
        .any(|b| b <= b' ' || b == 0x7f || matches!(b, b',' | b'[' | b']' | b'*' | b'?' | b'!'))
    {
        return Err(LookupNameError::InvalidCharacter);
    }
    let lower = host.to_ascii_lowercase();
    let name = if port == DEFAULT_PORT {
        lower
    } else {
        alloc::format!("[{lower}]:{port}")
    };
    if name.len() > MAX_LOOKUP_NAME_BYTES {
        return Err(LookupNameError::TooLong);
    }
    Ok(name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Pattern {
    negated: bool,
    /// ASCII-lowercased pattern bytes.
    text: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Hosts {
    Patterns(Vec<Pattern>),
    /// The raw `|1|salt|hash` field, validated at parse time.
    #[cfg(feature = "openssh-hashed-hosts")]
    Hashed(Vec<u8>),
}

/// One validated entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    line: usize,
    marker: Marker,
    hosts: Hosts,
    key_type: Vec<u8>,
    blob: Vec<u8>,
}

impl Entry {
    /// 1-based line number.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line
    }

    /// The line's marker.
    #[must_use]
    pub const fn marker(&self) -> Marker {
        self.marker
    }

    /// Key type field (equals the blob's algorithm).
    #[must_use]
    pub fn key_type(&self) -> &[u8] {
        &self.key_type
    }

    /// The complete decoded public-key blob.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }

    /// `true` for a `|1|salt|hash` host field (only possible with the
    /// `openssh-hashed-hosts` feature; otherwise such a file does not
    /// parse).
    #[must_use]
    pub const fn is_hashed(&self) -> bool {
        match self.hosts {
            #[cfg(feature = "openssh-hashed-hosts")]
            Hosts::Hashed(_) => true,
            Hosts::Patterns(_) => false,
        }
    }

    /// Whether this line applies to `name` (a [`lookup_name`]). A hashed
    /// entry never applies to a name longer than [`MAX_LOOKUP_NAME_BYTES`]
    /// ([`lookup_name`] cannot form one; [`KnownHosts::policy_for_name`]
    /// treats such a name as matching nothing at all).
    #[must_use]
    pub fn applies_to(&self, name: &str) -> bool {
        match &self.hosts {
            #[cfg(feature = "openssh-hashed-hosts")]
            Hosts::Hashed(field) => {
                // The field was validated by `parse`; an error here can only
                // be an oversized name.
                tatami_ssh_openssh_compat::matches_hashed_hostname(field, name.as_bytes())
                    .unwrap_or(false)
            }
            Hosts::Patterns(patterns) => {
                let name = name.as_bytes();
                let mut positive = false;
                for p in patterns {
                    if glob_match(&p.text, name) {
                        if p.negated {
                            return false;
                        }
                        positive = true;
                    }
                }
                positive
            }
        }
    }
}

/// A parsed, fully validated `known_hosts` file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KnownHosts {
    entries: Vec<Entry>,
}

impl KnownHosts {
    /// Parses and validates `bytes` completely.
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Self, KnownHostsError> {
        if bytes.len() > limits.max_file_bytes {
            return Err(KnownHostsError::FileTooLarge {
                limit: limits.max_file_bytes,
            });
        }
        let mut entries = Vec::new();
        for (index, raw) in bytes.split(|&b| b == b'\n').enumerate() {
            let line = index + 1;
            let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
            if raw.len() > limits.max_line_bytes {
                return Err(KnownHostsError::LineTooLong {
                    line,
                    limit: limits.max_line_bytes,
                });
            }
            let content = trim_start(raw);
            if content.is_empty() || content[0] == b'#' {
                continue;
            }
            if entries.len() >= limits.max_entries {
                return Err(KnownHostsError::TooManyEntries {
                    limit: limits.max_entries,
                });
            }
            entries.push(parse_line(content, line, limits)?);
        }
        Ok(KnownHosts { entries })
    }

    /// The entries, in file order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Binds the file to the logical lookup name for `host`/`port`.
    pub fn policy_for(&self, host: &str, port: u16) -> Result<KnownHostsPolicy, LookupNameError> {
        let name = lookup_name(host, port)?;
        Ok(self.policy_for_name(name))
    }

    /// Binds the file to an already-formed lookup name. A name longer than
    /// [`MAX_LOOKUP_NAME_BYTES`] matches no entry (so it is never trusted,
    /// and no hashed revocation can be missed on the way to a match).
    #[must_use]
    pub fn policy_for_name(&self, name: String) -> KnownHostsPolicy {
        let too_long = name.len() > MAX_LOOKUP_NAME_BYTES;
        let applicable = self
            .entries
            .iter()
            .filter(|e| !too_long && e.applies_to(&name))
            .map(|e| Applicable {
                line: e.line,
                marker: e.marker,
                key_type: e.key_type.clone(),
                blob: e.blob.clone(),
            })
            .collect();
        KnownHostsPolicy {
            lookup_name: name,
            applicable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Applicable {
    line: usize,
    marker: Marker,
    key_type: Vec<u8>,
    blob: Vec<u8>,
}

/// A `known_hosts` file bound to one lookup name. Immutable; performs no
/// I/O; safe to share with a TLS verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownHostsPolicy {
    lookup_name: String,
    applicable: Vec<Applicable>,
}

impl KnownHostsPolicy {
    /// The logical name entries were matched against.
    #[must_use]
    pub fn lookup_name(&self) -> &str {
        &self.lookup_name
    }

    /// How many lines apply to the lookup name.
    #[must_use]
    pub fn applicable_entries(&self) -> usize {
        self.applicable.len()
    }
}

impl HostTrustPolicy for KnownHostsPolicy {
    fn decide(&self, host: &HostIdentity<'_>) -> TrustDecision {
        let untrusted = |reason| TrustDecision::Untrusted { reason };
        if let Some(r) = self
            .applicable
            .iter()
            .find(|a| a.marker == Marker::Revoked && a.blob == host.blob)
        {
            return untrusted(UntrustedReason::Revoked { line: r.line });
        }
        if let Some(t) = self
            .applicable
            .iter()
            .find(|a| a.marker == Marker::None && a.blob == host.blob)
        {
            return TrustDecision::Trusted {
                source: TrustSource::KnownHosts { line: t.line },
            };
        }
        let mut plain = self.applicable.iter().filter(|a| a.marker == Marker::None);
        if let Some(same_alg) = plain.clone().find(|a| a.key_type == host.algorithm) {
            return untrusted(UntrustedReason::KeyChanged {
                line: same_alg.line,
            });
        }
        if plain.next().is_some() {
            return untrusted(UntrustedReason::NoKeyForAlgorithm);
        }
        if self
            .applicable
            .iter()
            .any(|a| a.marker == Marker::CertAuthority)
        {
            return untrusted(UntrustedReason::CertificateAuthorityOnly);
        }
        untrusted(UntrustedReason::UnknownHost)
    }
}

fn is_space(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim_start(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&b| is_space(b)).count();
    &s[n..]
}

/// Splits off the next whitespace-delimited field.
fn next_field(s: &[u8]) -> Option<(&[u8], &[u8])> {
    let s = trim_start(s);
    if s.is_empty() {
        return None;
    }
    let end = s.iter().position(|&b| is_space(b)).unwrap_or(s.len());
    Some((&s[..end], &s[end..]))
}

fn parse_line(content: &[u8], line: usize, limits: &Limits) -> Result<Entry, KnownHostsError> {
    let bad = |what| KnownHostsError::Malformed { line, what };
    if content.contains(&0) {
        return Err(bad(Malformed::NulByte));
    }
    let (mut first, mut rest) =
        next_field(content).ok_or(bad(Malformed::MissingField("host patterns")))?;
    let marker = if first.first() == Some(&b'@') {
        let m = match first {
            b"@revoked" => Marker::Revoked,
            b"@cert-authority" => Marker::CertAuthority,
            _ => return Err(bad(Malformed::UnknownMarker)),
        };
        (first, rest) = next_field(rest).ok_or(bad(Malformed::MissingField("host patterns")))?;
        m
    } else {
        Marker::None
    };
    let hosts = parse_hosts(first, line, limits)?;
    let (key_type, rest) = next_field(rest).ok_or(bad(Malformed::MissingField("key type")))?;
    let (key_b64, _comment) = next_field(rest).ok_or(bad(Malformed::MissingField("key")))?;
    let blob =
        Base64::decode_vec(core::str::from_utf8(key_b64).map_err(|_| bad(Malformed::Base64))?)
            .map_err(|_| bad(Malformed::Base64))?;
    let parsed = PublicKeyBlob::decode(&blob).map_err(|_| bad(Malformed::Blob))?;
    if parsed.algorithm != key_type {
        return Err(bad(Malformed::KeyTypeMismatch));
    }
    if let Some(kt) = KeyType::from_name(key_type).filter(|k| k.is_enabled()) {
        match HostKey::parse(&blob) {
            // Well formed but outside the RSA size/exponent policy: an inert
            // entry (see the module notes), not a broken file.
            Ok(_) | Err(KeyError::RsaModulus { .. } | KeyError::RsaExponent) => {}
            Err(_) => return Err(bad(Malformed::InvalidKey(kt))),
        }
    }
    Ok(Entry {
        line,
        marker,
        hosts,
        key_type: key_type.to_vec(),
        blob,
    })
}

/// A host field starting with `|` is a hashed entry. With the feature it is
/// validated completely now (an empty lookup name matches nothing, so the
/// call only checks grammar, base64 and lengths); without it the file is
/// refused as unsupported, never skipped.
#[cfg(feature = "openssh-hashed-hosts")]
fn parse_hashed(field: &[u8], line: usize) -> Result<Hosts, KnownHostsError> {
    match tatami_ssh_openssh_compat::matches_hashed_hostname(field, b"") {
        Ok(_) => Ok(Hosts::Hashed(field.to_vec())),
        Err(_) => Err(KnownHostsError::Malformed {
            line,
            what: Malformed::HashedHost,
        }),
    }
}

#[cfg(not(feature = "openssh-hashed-hosts"))]
fn parse_hashed(_field: &[u8], line: usize) -> Result<Hosts, KnownHostsError> {
    Err(KnownHostsError::Unsupported {
        line,
        what: Unsupported::HashedHostnames,
    })
}

fn parse_hosts(field: &[u8], line: usize, limits: &Limits) -> Result<Hosts, KnownHostsError> {
    let bad = |what| KnownHostsError::Malformed { line, what };
    if field.first() == Some(&b'|') {
        return parse_hashed(field, line);
    }
    let mut patterns = Vec::new();
    for raw in field.split(|&b| b == b',') {
        if patterns.len() >= limits.max_patterns_per_line {
            return Err(KnownHostsError::TooManyPatterns {
                line,
                limit: limits.max_patterns_per_line,
            });
        }
        let (negated, text) = match raw.strip_prefix(b"!") {
            Some(t) => (true, t),
            None => (false, raw),
        };
        if text.is_empty() {
            return Err(bad(Malformed::EmptyPattern));
        }
        if text.first() == Some(&b'|') {
            return Err(bad(Malformed::HashedHost));
        }
        patterns.push(Pattern {
            negated,
            text: text.to_ascii_lowercase(),
        });
    }
    Ok(Hosts::Patterns(patterns))
}

/// Glob match with `*` (any run, including empty) and `?` (one byte).
///
/// Iterative with a single backtrack point, so the cost is bounded by
/// `pattern.len() * name.len()` steps whatever the pattern; there is no
/// recursion to exhaust.
#[must_use]
pub fn glob_match(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((sp, sn)) = star {
            p = sp + 1;
            n = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&b| b == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::fixtures::{TEST1_PUBLIC_KEY, TEST2_PUBLIC_KEY, TEST3_PUBLIC_KEY};
    use crate::blob::{SSH_ED25519, encode_ed25519_blob};
    use crate::fingerprint::Sha256Fingerprint;
    use alloc::format;
    use alloc::string::ToString;

    fn blob(key: &[u8; 32]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; 51];
        encode_ed25519_blob(key, &mut out).unwrap();
        out
    }

    fn b64(key: &[u8; 32]) -> String {
        Base64::encode_string(&blob(key))
    }

    fn line(hosts: &str, key: &[u8; 32]) -> String {
        format!("{hosts} ssh-ed25519 {} comment here\n", b64(key))
    }

    fn parse(text: &str) -> KnownHosts {
        KnownHosts::parse(text.as_bytes(), &Limits::default()).unwrap()
    }

    fn parse_err(text: &str) -> KnownHostsError {
        KnownHosts::parse(text.as_bytes(), &Limits::default()).unwrap_err()
    }

    fn decide(kh: &KnownHosts, host: &str, port: u16, key: &[u8; 32]) -> TrustDecision {
        let b = blob(key);
        let id = HostIdentity {
            algorithm: SSH_ED25519,
            blob: &b,
            sha256: Sha256Fingerprint::of_blob(&b),
        };
        kh.policy_for(host, port).unwrap().decide(&id)
    }

    fn trusted(line: usize) -> TrustDecision {
        TrustDecision::Trusted {
            source: TrustSource::KnownHosts { line },
        }
    }

    fn untrusted(reason: UntrustedReason) -> TrustDecision {
        TrustDecision::Untrusted { reason }
    }

    #[test]
    fn lookup_names_follow_openssh() {
        assert_eq!(lookup_name("Example.COM", 22).unwrap(), "example.com");
        assert_eq!(
            lookup_name("example.com", 2222).unwrap(),
            "[example.com]:2222"
        );
        assert_eq!(lookup_name("2001:DB8::1", 22).unwrap(), "2001:db8::1");
        assert_eq!(
            lookup_name("2001:db8::1", 2200).unwrap(),
            "[2001:db8::1]:2200"
        );
        assert_eq!(lookup_name("", 22), Err(LookupNameError::Empty));
        for bad in ["a b", "a,b", "[a]", "a*", "a?", "!a", "a\tb", "a\u{7f}"] {
            assert_eq!(
                lookup_name(bad, 22),
                Err(LookupNameError::InvalidCharacter),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn plain_match_and_port_rules() {
        let kh = parse(&format!(
            "{}{}",
            line("host.example,10.0.0.1", &TEST1_PUBLIC_KEY),
            line("[host.example]:2222", &TEST2_PUBLIC_KEY)
        ));
        assert_eq!(
            decide(&kh, "host.example", 22, &TEST1_PUBLIC_KEY),
            trusted(1)
        );
        assert_eq!(
            decide(&kh, "HOST.Example", 22, &TEST1_PUBLIC_KEY),
            trusted(1)
        );
        assert_eq!(decide(&kh, "10.0.0.1", 22, &TEST1_PUBLIC_KEY), trusted(1));
        assert_eq!(
            decide(&kh, "host.example", 2222, &TEST2_PUBLIC_KEY),
            trusted(2)
        );
        // Wrong port: the port-22 entry does not apply to 2222 and vice versa.
        assert_eq!(
            decide(&kh, "host.example", 2222, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::KeyChanged { line: 2 })
        );
        assert_eq!(
            decide(&kh, "host.example", 2223, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::UnknownHost)
        );
        assert_eq!(
            decide(&kh, "other.example", 22, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::UnknownHost)
        );
    }

    #[test]
    fn wildcards_and_negation() {
        let kh = parse(&line("*.example,!bad.example,h?st", &TEST1_PUBLIC_KEY));
        assert_eq!(decide(&kh, "a.example", 22, &TEST1_PUBLIC_KEY), trusted(1));
        assert_eq!(decide(&kh, "host", 22, &TEST1_PUBLIC_KEY), trusted(1));
        assert_eq!(
            decide(&kh, "bad.example", 22, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::UnknownHost)
        );
        assert_eq!(
            decide(&kh, "hoost", 22, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::UnknownHost)
        );
        // Negation alone never makes a line apply.
        let kh = parse(&line("!a.example", &TEST1_PUBLIC_KEY));
        assert_eq!(
            decide(&kh, "b.example", 22, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::UnknownHost)
        );
        // Wildcards cover the bracketed form too.
        let kh = parse(&line("[*.example]:2222", &TEST1_PUBLIC_KEY));
        assert_eq!(
            decide(&kh, "x.example", 2222, &TEST1_PUBLIC_KEY),
            trusted(1)
        );
    }

    #[test]
    fn glob_is_correct_and_bounded() {
        assert!(glob_match(b"*", b""));
        assert!(glob_match(b"a*b*c", b"aXXbYYc"));
        assert!(!glob_match(b"a*b*c", b"aXXbYY"));
        assert!(glob_match(b"??", b"ab"));
        assert!(!glob_match(b"??", b"abc"));
        assert!(glob_match(b"*a", b"aaa"));
        assert!(!glob_match(b"", b"a"));
        // Pathological for naive recursion: many stars, no match.
        let pattern = b"*a".repeat(100);
        let name = alloc::vec![b'a'; 1000];
        assert!(glob_match(&pattern, &name));
        let mut miss = name.clone();
        miss.push(b'b');
        assert!(!glob_match(&[pattern.as_slice(), b"c"].concat(), &miss));
    }

    // Hashed host fields produced by OpenSSH_10.2p1 `ssh-keygen -H` from a
    // plaintext file listing these names; hard-coded (no writer exists).
    /// `host.example`
    const HASHED_HOST: &str = "|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=";
    /// `[host.example]:2222`
    const HASHED_HOST_2222: &str = "|1|fSQdr5FTkUKRtYdUfMerMOhv9tg=|o7YYvARat2xvQ/xK/bsO6jq+ULY=";
    /// `other.example`
    const HASHED_OTHER: &str = "|1|RlS2qd0peVedQkw9lPQIZpqCXYg=|7f076qNh6IMy9djepot4ddmjj1I=";

    #[test]
    fn mixed_hashed_pattern_is_malformed_in_every_build() {
        assert_eq!(
            parse_err(&line(&format!("a,{HASHED_HOST}"), &TEST1_PUBLIC_KEY)),
            KnownHostsError::Malformed {
                line: 1,
                what: Malformed::HashedHost
            }
        );
    }

    #[test]
    fn overlong_lookup_names_match_nothing() {
        let host = "a".repeat(MAX_LOOKUP_NAME_BYTES);
        assert!(lookup_name(&host, 22).is_ok());
        assert_eq!(lookup_name(&host, 2222), Err(LookupNameError::TooLong));
        let kh = parse(&line("*", &TEST1_PUBLIC_KEY));
        let long = "a".repeat(MAX_LOOKUP_NAME_BYTES + 1);
        assert_eq!(kh.policy_for_name(long).applicable_entries(), 0);
        assert_eq!(kh.policy_for_name(host).applicable_entries(), 1);
    }

    #[cfg(feature = "openssh-hashed-hosts")]
    mod hashed_supported {
        use super::*;

        #[test]
        fn openssh_hashed_entries_match() {
            let kh = parse(&format!(
                "{}{}",
                line(HASHED_HOST_2222, &TEST1_PUBLIC_KEY),
                line(HASHED_OTHER, &TEST2_PUBLIC_KEY)
            ));
            assert!(kh.entries()[0].is_hashed());
            assert_eq!(
                decide(&kh, "host.example", 2222, &TEST1_PUBLIC_KEY),
                trusted(1)
            );
            // The lookup name is lowercased before hashing.
            assert_eq!(
                decide(&kh, "HOST.example", 2222, &TEST1_PUBLIC_KEY),
                trusted(1)
            );
            assert_eq!(
                decide(&kh, "host.example", 22, &TEST1_PUBLIC_KEY),
                untrusted(UntrustedReason::UnknownHost)
            );
            assert_eq!(
                decide(&kh, "other.example", 22, &TEST2_PUBLIC_KEY),
                trusted(2)
            );
            assert_eq!(
                decide(&kh, "other.example", 22, &TEST1_PUBLIC_KEY),
                untrusted(UntrustedReason::KeyChanged { line: 2 })
            );
        }

        #[test]
        fn hashed_revocation_wins_before_and_after() {
            for (text, rline) in [
                (
                    format!(
                        "@revoked {HASHED_HOST} ssh-ed25519 {}\n{}",
                        b64(&TEST1_PUBLIC_KEY),
                        line("host.example", &TEST1_PUBLIC_KEY)
                    ),
                    1,
                ),
                (
                    format!(
                        "{}@revoked {HASHED_HOST} ssh-ed25519 {}\n",
                        line(HASHED_HOST, &TEST1_PUBLIC_KEY),
                        b64(&TEST1_PUBLIC_KEY)
                    ),
                    2,
                ),
            ] {
                let kh = parse(&text);
                assert_eq!(
                    decide(&kh, "host.example", 22, &TEST1_PUBLIC_KEY),
                    untrusted(UntrustedReason::Revoked { line: rline }),
                    "{text}"
                );
            }
            // A hashed revocation for another name does not apply.
            let kh = parse(&format!(
                "@revoked {HASHED_OTHER} ssh-ed25519 {}\n{}",
                b64(&TEST1_PUBLIC_KEY),
                line(HASHED_HOST, &TEST1_PUBLIC_KEY)
            ));
            assert_eq!(
                decide(&kh, "host.example", 22, &TEST1_PUBLIC_KEY),
                trusted(2)
            );
        }

        #[test]
        fn malformed_hashes_are_configuration_errors() {
            for bad in [
                "|1|AAAA|AAAA",
                "|2|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=",
                "|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=",
                "|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=|x",
                // Unpadded and non-canonical base64.
                "|1|IU1cA2qjw9KDYpT5wGRttwN2vVU|MjpmhQnQTZr/FMAlIczcdX61uVU=",
                "|1|IU1cA2qjw9KDYpT5wGRttwN2vVV=|MjpmhQnQTZr/FMAlIczcdX61uVU=",
                "|1|IU1cA2qjw9KDYpT5wGRttwN2vVU=|MjpmhQnQTZr/FMAlIczcdX61uVU=,host",
                "|",
            ] {
                for marker in ["", "@revoked ", "@cert-authority "] {
                    let text = format!(
                        "{}{marker}{}",
                        line("host", &TEST1_PUBLIC_KEY),
                        line(bad, &TEST1_PUBLIC_KEY)
                    );
                    assert_eq!(
                        parse_err(&text),
                        KnownHostsError::Malformed {
                            line: 2,
                            what: Malformed::HashedHost
                        },
                        "{text}"
                    );
                }
            }
        }
    }

    #[cfg(not(feature = "openssh-hashed-hosts"))]
    mod hashed_unsupported {
        use super::*;

        #[test]
        fn any_hashed_entry_is_an_explicit_unsupported_error() {
            // Well-formed OpenSSH entries, a malformed one, and every marker:
            // none is skipped, the file is refused at that line.
            for field in [HASHED_HOST, HASHED_HOST_2222, HASHED_OTHER, "|2|junk", "|"] {
                for marker in ["", "@revoked ", "@cert-authority "] {
                    let text = format!(
                        "# c\n{}{marker}{}",
                        line("host.example", &TEST1_PUBLIC_KEY),
                        line(field, &TEST1_PUBLIC_KEY)
                    );
                    let e = parse_err(&text);
                    assert_eq!(
                        e,
                        KnownHostsError::Unsupported {
                            line: 3,
                            what: Unsupported::HashedHostnames
                        },
                        "{text}"
                    );
                    assert_eq!(e.line(), Some(3));
                }
            }
        }

        #[test]
        fn hashed_revocation_is_not_dropped() {
            // Without support a hashed revocation cannot be evaluated, so the
            // positive plaintext line must not be used either.
            let text = format!(
                "{}@revoked {HASHED_HOST} ssh-ed25519 {}\n",
                line("host.example", &TEST1_PUBLIC_KEY),
                b64(&TEST1_PUBLIC_KEY)
            );
            let e = parse_err(&text);
            assert!(matches!(e, KnownHostsError::Unsupported { line: 2, .. }));
            let msg = e.to_string();
            assert!(msg.starts_with("known_hosts line 2: "), "{msg}");
            assert!(msg.contains("openssh-hashed-hosts"), "{msg}");
            assert!(msg.contains("plaintext"), "{msg}");
        }
    }

    #[test]
    fn revocation_overrides_regardless_of_order() {
        for (text, rline) in [
            (
                format!(
                    "@revoked * ssh-ed25519 {}\n{}",
                    b64(&TEST1_PUBLIC_KEY),
                    line("host", &TEST1_PUBLIC_KEY)
                ),
                1,
            ),
            (
                format!(
                    "{}@revoked host ssh-ed25519 {}\n",
                    line("host", &TEST1_PUBLIC_KEY),
                    b64(&TEST1_PUBLIC_KEY)
                ),
                2,
            ),
        ] {
            let kh = parse(&text);
            assert_eq!(
                decide(&kh, "host", 22, &TEST1_PUBLIC_KEY),
                untrusted(UntrustedReason::Revoked { line: rline })
            );
        }
        // A revocation that does not apply to the name is ignored.
        let kh = parse(&format!(
            "@revoked other ssh-ed25519 {}\n{}",
            b64(&TEST1_PUBLIC_KEY),
            line("host", &TEST1_PUBLIC_KEY)
        ));
        assert_eq!(decide(&kh, "host", 22, &TEST1_PUBLIC_KEY), trusted(2));
        // A malformed revocation is never skipped.
        assert_eq!(
            parse_err(&format!(
                "@revoked host ssh-ed25519 !!!!\n{}",
                line("host", &TEST1_PUBLIC_KEY)
            )),
            KnownHostsError::Malformed {
                line: 1,
                what: Malformed::Base64
            }
        );
    }

    #[test]
    fn rotation_and_changed_keys() {
        let kh = parse(&format!(
            "{}{}",
            line("host", &TEST2_PUBLIC_KEY),
            line("host", &TEST1_PUBLIC_KEY)
        ));
        // A stale entry does not defeat a separate valid one.
        assert_eq!(decide(&kh, "host", 22, &TEST1_PUBLIC_KEY), trusted(2));
        assert_eq!(decide(&kh, "host", 22, &TEST2_PUBLIC_KEY), trusted(1));
        assert_eq!(
            decide(&kh, "host", 22, &TEST3_PUBLIC_KEY),
            untrusted(UntrustedReason::KeyChanged { line: 1 })
        );
        // Duplicate identical entries are harmless.
        let kh = parse(&format!(
            "{}{}",
            line("host", &TEST1_PUBLIC_KEY),
            line("host", &TEST1_PUBLIC_KEY)
        ));
        assert_eq!(decide(&kh, "host", 22, &TEST1_PUBLIC_KEY), trusted(1));
    }

    fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        out.extend_from_slice(&(s.len() as u32).to_be_bytes());
        out.extend_from_slice(s);
    }

    fn other_alg_line(marker: &str, hosts: &str, alg: &str) -> String {
        let mut b = Vec::new();
        put_string(&mut b, alg.as_bytes());
        put_string(&mut b, &[1, 2, 3]);
        format!("{marker}{hosts} {alg} {}\n", Base64::encode_string(&b))
    }

    #[test]
    fn other_algorithms_and_cas_confer_no_trust() {
        let kh = parse(&other_alg_line("", "host", "ssh-dss"));
        assert_eq!(
            decide(&kh, "host", 22, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::NoKeyForAlgorithm)
        );
        // A CA with the very same Ed25519 key is still not a host key.
        let kh = parse(&format!(
            "@cert-authority host ssh-ed25519 {}\n",
            b64(&TEST1_PUBLIC_KEY)
        ));
        assert_eq!(kh.entries()[0].marker(), Marker::CertAuthority);
        assert_eq!(
            decide(&kh, "host", 22, &TEST1_PUBLIC_KEY),
            untrusted(UntrustedReason::CertificateAuthorityOnly)
        );
        let kh = parse(&format!(
            "{}{}",
            other_alg_line("@cert-authority ", "*", "ssh-dss"),
            line("host", &TEST1_PUBLIC_KEY)
        ));
        assert_eq!(decide(&kh, "host", 22, &TEST1_PUBLIC_KEY), trusted(2));
    }

    #[test]
    fn malformed_lines_are_configuration_errors() {
        let key = b64(&TEST1_PUBLIC_KEY);
        let cases: &[(String, Malformed)] = &[
            (
                format!("@bogus host ssh-ed25519 {key}"),
                Malformed::UnknownMarker,
            ),
            (
                String::from("@revoked"),
                Malformed::MissingField("host patterns"),
            ),
            (String::from("host"), Malformed::MissingField("key type")),
            (
                String::from("host ssh-ed25519"),
                Malformed::MissingField("key"),
            ),
            (format!("a,,b ssh-ed25519 {key}"), Malformed::EmptyPattern),
            (format!("! ssh-ed25519 {key}"), Malformed::EmptyPattern),
            (format!("host ssh-ed25519 {key}x"), Malformed::Base64),
            (String::from("host ssh-ed25519 AAAA"), Malformed::Blob),
            (format!("host ssh-rsa {key}"), Malformed::KeyTypeMismatch),
            (format!("host ssh-ed25519 {key}\0"), Malformed::NulByte),
            // SSH-1 format is not supported.
            (String::from("host 2048 35 123456"), Malformed::Base64),
        ];
        for (text, what) in cases {
            assert_eq!(
                parse_err(&format!("# comment\n\n{text}\n")),
                KnownHostsError::Malformed {
                    line: 3,
                    what: *what
                },
                "{text:?}"
            );
        }
        // Wrong-length and trailing-byte ed25519 blobs.
        let mut long = blob(&TEST1_PUBLIC_KEY);
        long.push(0);
        let text = format!("host ssh-ed25519 {}\n", Base64::encode_string(&long));
        assert_eq!(
            parse_err(&text),
            KnownHostsError::Malformed {
                line: 1,
                what: Malformed::InvalidKey(KeyType::Ed25519)
            }
        );
        // Unpadded base64 (OpenSSH writes padding) is rejected. The
        // 51-byte Ed25519 blob needs no padding, so use a 17-byte blob.
        let mut short = Vec::new();
        put_string(&mut short, b"ssh-dss");
        put_string(&mut short, &[1, 2]);
        let padded = Base64::encode_string(&short);
        assert!(padded.ends_with('='));
        assert!(parse(&format!("host ssh-dss {padded}\n")).entries().len() == 1);
        let unpadded = padded.trim_end_matches('=');
        assert_eq!(
            parse_err(&format!("host ssh-dss {unpadded}\n")),
            KnownHostsError::Malformed {
                line: 1,
                what: Malformed::Base64
            }
        );
    }

    #[test]
    fn whitespace_comments_and_crlf() {
        let text = format!(
            "  # indented comment\r\n\t\r\n\thost\tssh-ed25519\t{}\r\n",
            b64(&TEST1_PUBLIC_KEY)
        );
        let kh = parse(&text);
        assert_eq!(kh.entries().len(), 1);
        assert_eq!(kh.entries()[0].line(), 3);
        assert_eq!(decide(&kh, "host", 22, &TEST1_PUBLIC_KEY), trusted(3));
    }

    #[test]
    fn limits_are_enforced() {
        let one = line("host", &TEST1_PUBLIC_KEY);
        let tight = Limits {
            max_file_bytes: one.len(),
            max_line_bytes: one.len(),
            max_entries: 1,
            max_patterns_per_line: 2,
        };
        assert!(KnownHosts::parse(one.as_bytes(), &tight).is_ok());
        let two = one.repeat(2);
        assert_eq!(
            KnownHosts::parse(two.as_bytes(), &tight),
            Err(KnownHostsError::FileTooLarge { limit: one.len() })
        );
        let roomy = Limits {
            max_file_bytes: 1 << 20,
            ..tight
        };
        assert_eq!(
            KnownHosts::parse(two.as_bytes(), &roomy),
            Err(KnownHostsError::TooManyEntries { limit: 1 })
        );
        let wide = line("a,b,c", &TEST1_PUBLIC_KEY);
        assert_eq!(
            KnownHosts::parse(
                wide.as_bytes(),
                &Limits {
                    max_line_bytes: 1 << 10,
                    ..roomy
                }
            ),
            Err(KnownHostsError::TooManyPatterns { line: 1, limit: 2 })
        );
        let long = format!(
            "host ssh-ed25519 {} {}\n",
            b64(&TEST1_PUBLIC_KEY),
            "c".repeat(100)
        );
        assert_eq!(
            KnownHosts::parse(long.as_bytes(), &roomy),
            Err(KnownHostsError::LineTooLong {
                line: 1,
                limit: one.len()
            })
        );
    }

    #[test]
    fn errors_render_with_line_numbers() {
        let e = parse_err("host ssh-ed25519\n");
        assert_eq!(e.line(), Some(1));
        assert_eq!(e.to_string(), "known_hosts line 1: missing key");
    }
}

#[cfg(all(test, feature = "rsa", feature = "ecdsa-p256"))]
mod other_type_tests {
    //! RSA and ECDSA P-256 entries through the same policy: exact-blob
    //! matching, rotation, revocation precedence and the distinct reasons.
    use super::*;
    use crate::blob::fixtures::TEST1_PUBLIC_KEY;
    use crate::fingerprint::Sha256Fingerprint;
    use crate::test_vectors::*;
    use alloc::format;

    fn parse(text: &str) -> Result<KnownHosts, KnownHostsError> {
        KnownHosts::parse(text.as_bytes(), &Limits::default())
    }

    fn decide(kh: &KnownHosts, host: &str, port: u16, blob: &[u8]) -> TrustDecision {
        let parsed = PublicKeyBlob::decode(blob).unwrap();
        let id = HostIdentity {
            algorithm: parsed.algorithm,
            blob,
            sha256: Sha256Fingerprint::of_blob(blob),
        };
        kh.policy_for(host, port).unwrap().decide(&id)
    }

    fn ed25519_line(hosts: &str) -> String {
        let mut b = alloc::vec![0u8; 51];
        crate::blob::encode_ed25519_blob(&TEST1_PUBLIC_KEY, &mut b).unwrap();
        format!("{hosts} ssh-ed25519 {}\n", Base64::encode_string(&b))
    }

    /// Another valid RSA key: the fixture modulus with a different (still
    /// odd, still 2048-bit) low byte. Structurally valid; never a real key.
    fn other_rsa() -> Vec<u8> {
        let mut b = b64(RSA_2048_PUB);
        let last = b.len() - 1;
        b[last] ^= 0x02;
        b
    }

    const TRUSTED: fn(usize) -> TrustDecision = |line| TrustDecision::Trusted {
        source: TrustSource::KnownHosts { line },
    };

    fn untrusted(reason: UntrustedReason) -> TrustDecision {
        TrustDecision::Untrusted { reason }
    }

    #[test]
    fn rsa_and_p256_entries_are_judged_like_ed25519() {
        let rsa = b64(RSA_2048_PUB);
        let p256 = b64(P256_PUB);
        let text = format!(
            "host,[host]:2222 ssh-rsa {RSA_2048_PUB}\nhost ecdsa-sha2-nistp256 {P256_PUB}\n{}",
            ed25519_line("host")
        );
        let kh = parse(&text).unwrap();
        assert_eq!(decide(&kh, "host", 22, &rsa), TRUSTED(1));
        assert_eq!(decide(&kh, "host", 2222, &rsa), TRUSTED(1));
        assert_eq!(decide(&kh, "HOST", 22, &p256), TRUSTED(2));
        // Changed RSA key for a host with an RSA entry.
        assert_eq!(
            decide(&kh, "host", 22, &other_rsa()),
            untrusted(UntrustedReason::KeyChanged { line: 1 })
        );
        // Only other key types listed for [host]:2222.
        assert_eq!(
            decide(&kh, "host", 2222, &p256),
            untrusted(UntrustedReason::NoKeyForAlgorithm)
        );
        assert_eq!(
            decide(&kh, "other", 22, &rsa),
            untrusted(UntrustedReason::UnknownHost)
        );
    }

    #[test]
    fn revocation_wins_before_and_after_for_every_type() {
        for (kind, pubkey) in [("ssh-rsa", RSA_2048_PUB), ("ecdsa-sha2-nistp256", P256_PUB)] {
            let blob = b64(pubkey);
            let plain = format!("host {kind} {pubkey}\n");
            let revoked = format!("@revoked * {kind} {pubkey}\n");
            for (text, line) in [
                (format!("{plain}{revoked}"), 2),
                (format!("{revoked}{plain}"), 1),
            ] {
                let kh = parse(&text).unwrap();
                assert_eq!(
                    decide(&kh, "host", 22, &blob),
                    untrusted(UntrustedReason::Revoked { line }),
                    "{kind}"
                );
            }
        }
        // Revoking one RSA key leaves a rotated one trusted.
        let other = Base64::encode_string(&other_rsa());
        let kh = parse(&format!(
            "@revoked host ssh-rsa {RSA_2048_PUB}\nhost ssh-rsa {other}\n"
        ))
        .unwrap();
        assert_eq!(decide(&kh, "host", 22, &other_rsa()), TRUSTED(2));
    }

    #[test]
    fn malformed_rsa_and_p256_entries_break_the_file() {
        // Redundant leading zero on e.
        let mut bad_rsa = Vec::new();
        for part in [&b"ssh-rsa"[..], &[0, 1, 0, 1], &b64(RSA_2048_PUB)[22..]] {
            bad_rsa.extend_from_slice(&(part.len() as u32).to_be_bytes());
            bad_rsa.extend_from_slice(part);
        }
        let mut wrong_curve = b64(P256_PUB);
        wrong_curve[34] = b'4'; // "nistp256" -> "nistp254"
        let mut trailing = b64(P256_PUB);
        trailing.push(0);
        for (kind, blob, kt) in [
            ("ssh-rsa", bad_rsa, KeyType::Rsa),
            ("ecdsa-sha2-nistp256", wrong_curve, KeyType::EcdsaP256),
            ("ecdsa-sha2-nistp256", trailing, KeyType::EcdsaP256),
        ] {
            let text = format!("@revoked host {kind} {}\n", Base64::encode_string(&blob));
            assert_eq!(
                parse(&text).unwrap_err(),
                KnownHostsError::Malformed {
                    line: 1,
                    what: Malformed::InvalidKey(kt)
                },
                "{kind}"
            );
        }
    }

    #[test]
    fn policy_violations_are_inert_entries_and_other_curves_opaque() {
        let text = format!("host ssh-rsa {RSA_1024_PUB}\nhost ecdsa-sha2-nistp384 {P384_PUB}\n");
        let kh = parse(&text).unwrap();
        assert_eq!(kh.entries().len(), 2);
        // The 1024-bit key could never be presented (it fails to parse in
        // the handshake); a valid RSA key sees "key changed".
        assert_eq!(
            decide(&kh, "host", 22, &b64(RSA_2048_PUB)),
            untrusted(UntrustedReason::KeyChanged { line: 1 })
        );
        assert_eq!(
            decide(&kh, "host", 22, &b64(P256_PUB)),
            untrusted(UntrustedReason::NoKeyForAlgorithm)
        );
    }
}
