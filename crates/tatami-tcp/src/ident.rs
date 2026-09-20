//! Protocol version exchange: identification strings (RFC 4253 §4.2).
//!
//! The server may send any number of lines before its identification; a
//! client must ignore them. The identification line itself is
//!
//! ```text
//! SSH-protoversion-softwareversion SP comments CR LF
//! ```
//!
//! and is at most 255 bytes including CR LF.
//!
//! # Incremental parsing
//!
//! [`IdentificationReader::feed`] scans a caller-owned buffer for the next
//! complete line and tells the caller how many bytes it consumed. It works
//! for any read boundary: a line split across reads, several lines in one
//! read, or the identification followed by the first binary packet in the
//! same read. Bytes after the identification terminator are never touched.
//!
//! # Compatibility policy
//!
//! - **LF-only terminators are accepted** for both prelude lines and the
//!   identification. RFC 4253 requires CR LF but notes that clients should
//!   tolerate lines ending in LF alone from older servers. The terminator
//!   actually seen is reported so callers can flag it.
//! - Protocol version `1.99` is accepted as the SSH-2 compatibility
//!   indication (RFC 4253 §5.1). Any other version that is not `2.0` is
//!   reported as [`IdentError::UnsupportedVersion`], including actual SSH-1.
//! - The exact identification bytes without the terminator are exposed as
//!   [`Identification::line`], which is the form a future exchange hash
//!   needs (`V_S` excludes CR and LF).
//!
//! # Division of responsibility
//!
//! Identification *content* syntax (`SSH-proto-software [comments]`) is
//! parsed and encoded by [`tatami_wire::ident`], which is shared with any
//! future binding. This module owns everything TCP-specific: terminator
//! scanning across read boundaries, server pre-identification lines, the
//! 255-byte line limit measured with the observed terminator, LF-only
//! acceptance, and the supported-version policy (`2.0` and `1.99` only).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use tatami_wire::ident as wire;

/// Maximum identification line length including `CR LF` (RFC 4253 §4.2).
pub const MAX_IDENTIFICATION_LINE: usize = 255;

/// Resource limits for the identification phase.
///
/// The defaults are local policy, not protocol constants. RFC 4253 bounds
/// only the identification line itself (255 bytes); prelude text has no
/// protocol limit, so the caller must bound it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentLimits {
    /// Maximum number of lines before the identification.
    pub max_prelude_lines: usize,
    /// Maximum total bytes of prelude lines, including terminators.
    pub max_prelude_bytes: usize,
    /// Maximum length of one prelude line, including its terminator.
    pub max_prelude_line: usize,
    /// Maximum length of the identification line including CR LF. RFC 4253
    /// fixes this at 255; raising it accepts non-conforming peers.
    pub max_identification_line: usize,
}

impl Default for IdentLimits {
    fn default() -> Self {
        IdentLimits {
            max_prelude_lines: 64,
            max_prelude_bytes: 8 * 1024,
            max_prelude_line: 1024,
            max_identification_line: 255,
        }
    }
}

/// Line terminator observed on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineTerminator {
    /// `CR LF`, as RFC 4253 requires.
    CrLf,
    /// Bare `LF`, accepted for compatibility.
    Lf,
}

impl LineTerminator {
    /// Length of the terminator in bytes.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        match self {
            LineTerminator::CrLf => 2,
            LineTerminator::Lf => 1,
        }
    }
}

/// How the peer's protocol version relates to SSH-2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionSupport {
    /// `2.0`.
    Ssh2,
    /// `1.99`: an SSH-1-capable peer that also supports SSH-2 (RFC 4253 §5.1).
    Ssh2Compatibility,
}

/// A parsed identification line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identification<'a> {
    /// Exact line bytes with the terminator removed (`V_S` / `V_C` form).
    pub line: &'a [u8],
    /// Terminator that followed the line.
    pub terminator: LineTerminator,
    /// The `protoversion` token.
    pub protocol_version: &'a [u8],
    /// The `softwareversion` token.
    pub software_version: &'a [u8],
    /// Optional comments after a single space. Untrusted text.
    pub comments: Option<&'a [u8]>,
    /// Classification of `protocol_version`.
    pub support: VersionSupport,
}

/// Something about a syntactically valid identification that a conforming
/// modern SSH-2 peer would not send. Reported, never silently normalised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentAnomaly {
    /// Line ended with bare `LF`; RFC 4253 requires `CR LF`.
    LfOnlyTerminator,
    /// Protocol version `1.99`: an SSH-1-era compatibility indication, not
    /// evidence of a normal SSH-2 peer.
    CompatibilityVersion,
}

impl IdentAnomaly {
    /// Stable, machine-readable code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            IdentAnomaly::LfOnlyTerminator => "lf_only_terminator",
            IdentAnomaly::CompatibilityVersion => "compatibility_version_1_99",
        }
    }
}

impl fmt::Display for IdentAnomaly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IdentAnomaly::LfOnlyTerminator => {
                "line terminated by LF only (RFC 4253 requires CR LF)"
            }
            IdentAnomaly::CompatibilityVersion => {
                "protocol version 1.99 (SSH-1 compatibility indication)"
            }
        })
    }
}

impl Identification<'_> {
    /// Anomalies present in this identification.
    pub fn anomalies(&self) -> impl Iterator<Item = IdentAnomaly> {
        let lf = (self.terminator == LineTerminator::Lf).then_some(IdentAnomaly::LfOnlyTerminator);
        let compat = (self.support == VersionSupport::Ssh2Compatibility)
            .then_some(IdentAnomaly::CompatibilityVersion);
        lf.into_iter().chain(compat)
    }
}

/// Owned copy of an [`Identification`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedIdentification {
    /// Exact bytes without the terminator.
    pub line: Vec<u8>,
    /// Terminator observed.
    pub terminator: LineTerminator,
    /// `protoversion` (always printable ASCII).
    pub protocol_version: String,
    /// `softwareversion` (always printable ASCII).
    pub software_version: String,
    /// Raw comment bytes, if present. Untrusted.
    pub comments: Option<Vec<u8>>,
    /// Version classification.
    pub support: VersionSupport,
}

impl OwnedIdentification {
    /// Anomalies present in this identification.
    pub fn anomalies(&self) -> impl Iterator<Item = IdentAnomaly> {
        let lf = (self.terminator == LineTerminator::Lf).then_some(IdentAnomaly::LfOnlyTerminator);
        let compat = (self.support == VersionSupport::Ssh2Compatibility)
            .then_some(IdentAnomaly::CompatibilityVersion);
        lf.into_iter().chain(compat)
    }
}

impl From<Identification<'_>> for OwnedIdentification {
    fn from(i: Identification<'_>) -> Self {
        OwnedIdentification {
            line: i.line.to_vec(),
            terminator: i.terminator,
            protocol_version: String::from_utf8_lossy(i.protocol_version).into_owned(),
            software_version: String::from_utf8_lossy(i.software_version).into_owned(),
            comments: i.comments.map(<[u8]>::to_vec),
            support: i.support,
        }
    }
}

/// Why an outgoing identification could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidLocalIdentification {
    /// The software version token is empty or contains whitespace, `-`, or
    /// a non-printable/non-ASCII byte.
    BadSoftwareVersion,
    /// The complete line including `CR LF` would exceed
    /// [`MAX_IDENTIFICATION_LINE`] bytes.
    TooLong {
        /// Length the line would have had.
        len: usize,
    },
}

impl fmt::Display for InvalidLocalIdentification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidLocalIdentification::BadSoftwareVersion => {
                f.write_str("software version must be printable ASCII without whitespace or '-'")
            }
            InvalidLocalIdentification::TooLong { len } => write!(
                f,
                "identification line would be {len} bytes; RFC 4253 allows at most {MAX_IDENTIFICATION_LINE} including CR LF"
            ),
        }
    }
}

impl core::error::Error for InvalidLocalIdentification {}

/// Builds our own identification line `SSH-2.0-<software_version>\r\n`.
///
/// The content is encoded by [`tatami_wire::ident::encode`]; this function
/// appends `CR LF` and validates the whole line against
/// [`MAX_IDENTIFICATION_LINE`], which is the TCP binding's rule.
pub fn build_identification(software_version: &str) -> Result<Vec<u8>, InvalidLocalIdentification> {
    let content_len = wire::encoded_len(b"2.0", software_version.as_bytes(), None)
        .ok_or(InvalidLocalIdentification::BadSoftwareVersion)?;
    let len = content_len
        .checked_add(2)
        .ok_or(InvalidLocalIdentification::TooLong { len: usize::MAX })?;
    if len > MAX_IDENTIFICATION_LINE {
        return Err(InvalidLocalIdentification::TooLong { len });
    }
    let mut line = alloc::vec![0u8; len];
    let written = wire::encode(b"2.0", software_version.as_bytes(), None, &mut line)
        .map_err(|_| InvalidLocalIdentification::BadSoftwareVersion)?;
    debug_assert_eq!(written, content_len);
    line[content_len..].copy_from_slice(b"\r\n");
    Ok(line)
}

/// Reason an identification line was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentError {
    /// A prelude line exceeded [`IdentLimits::max_prelude_line`].
    PreludeLineTooLong,
    /// More prelude lines than [`IdentLimits::max_prelude_lines`].
    TooManyPreludeLines,
    /// Total prelude bytes exceeded [`IdentLimits::max_prelude_bytes`].
    PreludeBytesExceeded,
    /// The identification line exceeded
    /// [`IdentLimits::max_identification_line`].
    IdentificationTooLong,
    /// The line began with `SSH-` but did not match the required syntax.
    InvalidIdentification(InvalidIdentification),
    /// The protocol version is neither `2.0` nor `1.99`.
    UnsupportedVersion,
}

/// Detail for [`IdentError::InvalidIdentification`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidIdentification {
    /// No `-` separating `protoversion` from `softwareversion`.
    MissingSeparator,
    /// `protoversion` was empty or contained a forbidden byte.
    BadProtocolVersion,
    /// `softwareversion` was empty or contained a forbidden byte.
    BadSoftwareVersion,
    /// A `CR` or `NUL` appeared inside the line.
    ControlCharacter,
}

impl fmt::Display for IdentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentError::PreludeLineTooLong => f.write_str("pre-identification line too long"),
            IdentError::TooManyPreludeLines => f.write_str("too many pre-identification lines"),
            IdentError::PreludeBytesExceeded => f.write_str("pre-identification text too large"),
            IdentError::IdentificationTooLong => f.write_str("identification line too long"),
            IdentError::InvalidIdentification(e) => write!(f, "invalid identification: {e}"),
            IdentError::UnsupportedVersion => f.write_str("unsupported SSH protocol version"),
        }
    }
}

impl fmt::Display for InvalidIdentification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InvalidIdentification::MissingSeparator => "missing '-' after protocol version",
            InvalidIdentification::BadProtocolVersion => "malformed protocol version",
            InvalidIdentification::BadSoftwareVersion => "malformed software version",
            InvalidIdentification::ControlCharacter => "control character in line",
        })
    }
}

impl core::error::Error for IdentError {}
impl core::error::Error for InvalidIdentification {}

/// Result of one [`IdentificationReader::feed`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentStep<'a> {
    /// No complete line is buffered yet; read more and call again with the
    /// same (extended) buffer. Nothing was consumed.
    NeedMore,
    /// A pre-identification line. `consumed` bytes (line plus terminator)
    /// should be dropped from the buffer before the next call.
    Prelude {
        /// Line content without its terminator. Untrusted text.
        line: &'a [u8],
        /// Terminator that followed the line.
        terminator: LineTerminator,
        /// Total bytes consumed, including the terminator.
        consumed: usize,
    },
    /// The identification line. `consumed` bytes should be dropped from the
    /// buffer; anything after them belongs to the binary packet protocol.
    Identification {
        /// The parsed identification.
        ident: Identification<'a>,
        /// Total bytes consumed, including the terminator.
        consumed: usize,
    },
}

/// Incremental reader for the server's prelude and identification.
#[derive(Clone, Debug)]
pub struct IdentificationReader {
    limits: IdentLimits,
    prelude_lines: usize,
    prelude_bytes: usize,
}

impl IdentificationReader {
    /// Creates a reader with the given limits.
    #[must_use]
    pub const fn new(limits: IdentLimits) -> Self {
        IdentificationReader {
            limits,
            prelude_lines: 0,
            prelude_bytes: 0,
        }
    }

    /// Number of prelude lines accepted so far.
    #[must_use]
    pub const fn prelude_lines(&self) -> usize {
        self.prelude_lines
    }

    /// Examines `buf` (all unconsumed bytes received so far) for the next
    /// complete line.
    ///
    /// Errors are terminal: the caller should stop and report. Every check
    /// that can be made on a partial line (length limits) is made before a
    /// terminator arrives, so a peer cannot make the caller buffer without
    /// bound.
    pub fn feed<'a>(&mut self, buf: &'a [u8]) -> Result<IdentStep<'a>, IdentError> {
        let is_ident = starts_identification(buf);
        let line_limit = match is_ident {
            Some(true) => self.limits.max_identification_line,
            Some(false) => self.limits.max_prelude_line,
            // Fewer than 4 bytes: cannot tell yet; use the looser bound.
            None => self
                .limits
                .max_prelude_line
                .max(self.limits.max_identification_line),
        };

        let Some((content_len, terminator)) = find_line(buf) else {
            if buf.len() >= line_limit {
                return Err(match is_ident {
                    Some(true) => IdentError::IdentificationTooLong,
                    _ => IdentError::PreludeLineTooLong,
                });
            }
            return Ok(IdentStep::NeedMore);
        };
        let consumed = content_len + terminator.byte_len();
        let line = &buf[..content_len];

        if is_ident == Some(true) {
            if consumed > self.limits.max_identification_line {
                return Err(IdentError::IdentificationTooLong);
            }
            let ident = parse_identification(line, terminator)?;
            return Ok(IdentStep::Identification { ident, consumed });
        }

        if consumed > self.limits.max_prelude_line {
            return Err(IdentError::PreludeLineTooLong);
        }
        if self.prelude_lines >= self.limits.max_prelude_lines {
            return Err(IdentError::TooManyPreludeLines);
        }
        let total = self.prelude_bytes.saturating_add(consumed);
        if total > self.limits.max_prelude_bytes {
            return Err(IdentError::PreludeBytesExceeded);
        }
        self.prelude_lines += 1;
        self.prelude_bytes = total;
        Ok(IdentStep::Prelude {
            line,
            terminator,
            consumed,
        })
    }
}

/// Returns `Some(true)` if `buf` starts with `SSH-`, `Some(false)` if it
/// definitely does not, and `None` if fewer than four bytes are available
/// and they are all consistent with that prefix.
#[must_use]
pub fn starts_identification(buf: &[u8]) -> Option<bool> {
    let prefix = wire::PREFIX;
    if buf.len() >= prefix.len() {
        Some(&buf[..prefix.len()] == prefix)
    } else if buf == &prefix[..buf.len()] {
        None
    } else {
        Some(false)
    }
}

/// Finds the first line terminator. Returns the content length (excluding
/// the terminator) and which terminator was found.
fn find_line(buf: &[u8]) -> Option<(usize, LineTerminator)> {
    let lf = buf.iter().position(|&b| b == b'\n')?;
    if lf > 0 && buf[lf - 1] == b'\r' {
        Some((lf - 1, LineTerminator::CrLf))
    } else {
        Some((lf, LineTerminator::Lf))
    }
}

/// Parses an identification line (without terminator) with the shared
/// syntax parser, then applies the TCP version policy.
fn parse_identification(
    line: &[u8],
    terminator: LineTerminator,
) -> Result<Identification<'_>, IdentError> {
    let content = wire::Identification::parse(line).map_err(|e| {
        IdentError::InvalidIdentification(match e {
            // The reader only calls this for lines that start with `SSH-`.
            wire::IdentSyntaxError::MissingPrefix | wire::IdentSyntaxError::MissingSeparator => {
                InvalidIdentification::MissingSeparator
            }
            wire::IdentSyntaxError::BadProtocolVersion => InvalidIdentification::BadProtocolVersion,
            wire::IdentSyntaxError::BadSoftwareVersion => InvalidIdentification::BadSoftwareVersion,
            wire::IdentSyntaxError::ControlCharacter => InvalidIdentification::ControlCharacter,
        })
    })?;
    let support = match content.protocol_version_class() {
        wire::ProtocolVersionClass::Ssh2 => VersionSupport::Ssh2,
        wire::ProtocolVersionClass::Ssh2Compatibility => VersionSupport::Ssh2Compatibility,
        wire::ProtocolVersionClass::Other => return Err(IdentError::UnsupportedVersion),
    };
    Ok(Identification {
        line: content.as_bytes(),
        terminator,
        protocol_version: content.protocol_version(),
        software_version: content.software_version(),
        comments: content.comments(),
        support,
    })
}

/// Returns `true` if `token` is a valid `protoversion`/`softwareversion`.
/// Re-export of [`tatami_wire::ident::is_version_token`].
#[must_use]
pub fn is_version_token(token: &[u8]) -> bool {
    wire::is_version_token(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader() -> IdentificationReader {
        IdentificationReader::new(IdentLimits::default())
    }

    #[test]
    fn parses_plain_identification() {
        let mut r = reader();
        let buf = b"SSH-2.0-OpenSSH_9.6\r\n";
        match r.feed(buf).unwrap() {
            IdentStep::Identification { ident, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(ident.line, b"SSH-2.0-OpenSSH_9.6");
                assert_eq!(ident.terminator, LineTerminator::CrLf);
                assert_eq!(ident.protocol_version, b"2.0");
                assert_eq!(ident.software_version, b"OpenSSH_9.6");
                assert_eq!(ident.comments, None);
                assert_eq!(ident.support, VersionSupport::Ssh2);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn comments_and_1_99_and_lf_only() {
        let mut r = reader();
        let buf = b"SSH-1.99-Foo_1 some comment here\n";
        match r.feed(buf).unwrap() {
            IdentStep::Identification { ident, consumed } => {
                assert_eq!(consumed, buf.len());
                assert_eq!(ident.line, b"SSH-1.99-Foo_1 some comment here");
                assert_eq!(ident.terminator, LineTerminator::Lf);
                assert_eq!(ident.software_version, b"Foo_1");
                assert_eq!(ident.comments, Some(&b"some comment here"[..]));
                assert_eq!(ident.support, VersionSupport::Ssh2Compatibility);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn fragmented_input_including_split_crlf() {
        let full = b"SSH-2.0-x\r\n";
        for split in 0..full.len() {
            let mut r = reader();
            assert_eq!(
                r.feed(&full[..split]),
                Ok(IdentStep::NeedMore),
                "split {split}"
            );
            match r.feed(full).unwrap() {
                IdentStep::Identification { consumed, .. } => assert_eq!(consumed, full.len()),
                other => panic!("split {split}: {other:?}"),
            }
        }
    }

    #[test]
    fn prelude_lines_then_identification_then_packet_bytes_preserved() {
        let mut r = reader();
        let mut buf: &[u8] = b"Welcome\r\nline two\nSSH-2.0-srv\r\n\x00\x00\x01\x0c\x0a\x14";
        match r.feed(buf).unwrap() {
            IdentStep::Prelude {
                line,
                terminator,
                consumed,
            } => {
                assert_eq!(line, b"Welcome");
                assert_eq!(terminator, LineTerminator::CrLf);
                buf = &buf[consumed..];
            }
            other => panic!("{other:?}"),
        }
        match r.feed(buf).unwrap() {
            IdentStep::Prelude {
                line,
                terminator,
                consumed,
            } => {
                assert_eq!(line, b"line two");
                assert_eq!(terminator, LineTerminator::Lf);
                buf = &buf[consumed..];
            }
            other => panic!("{other:?}"),
        }
        match r.feed(buf).unwrap() {
            IdentStep::Identification { ident, consumed } => {
                assert_eq!(ident.software_version, b"srv");
                buf = &buf[consumed..];
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(buf, b"\x00\x00\x01\x0c\x0a\x14");
        assert_eq!(r.prelude_lines(), 2);
    }

    #[test]
    fn identification_length_boundary() {
        // 253 content bytes + CRLF = 255: accepted.
        let mut line = [b'x'; 255];
        line[..8].copy_from_slice(b"SSH-2.0-");
        line[253] = b'\r';
        line[254] = b'\n';
        assert!(matches!(
            reader().feed(&line),
            Ok(IdentStep::Identification { consumed: 255, .. })
        ));

        // 254 content bytes + CRLF = 256: rejected.
        let mut long = [b'x'; 256];
        long[..8].copy_from_slice(b"SSH-2.0-");
        long[254] = b'\r';
        long[255] = b'\n';
        assert_eq!(reader().feed(&long), Err(IdentError::IdentificationTooLong));

        // 255 bytes with no terminator yet: rejected without waiting.
        assert_eq!(
            reader().feed(&long[..255]),
            Err(IdentError::IdentificationTooLong)
        );
        // 254 bytes, no terminator: still possible (CRLF could follow? no,
        // that would be 256) -- but an LF alone could make it 255, so wait.
        assert_eq!(reader().feed(&long[..254]), Ok(IdentStep::NeedMore));
    }

    #[test]
    fn prelude_limits() {
        let limits = IdentLimits {
            max_prelude_lines: 2,
            max_prelude_bytes: 100,
            max_prelude_line: 10,
            max_identification_line: 255,
        };
        let mut r = IdentificationReader::new(limits);
        assert!(matches!(r.feed(b"a\r\n"), Ok(IdentStep::Prelude { .. })));
        assert!(matches!(r.feed(b"b\r\n"), Ok(IdentStep::Prelude { .. })));
        assert_eq!(r.feed(b"c\r\n"), Err(IdentError::TooManyPreludeLines));

        let mut r = IdentificationReader::new(limits);
        assert_eq!(r.feed(b"0123456789"), Err(IdentError::PreludeLineTooLong));
        assert_eq!(
            r.feed(b"012345678\r\n"),
            Err(IdentError::PreludeLineTooLong)
        );
        assert!(matches!(
            r.feed(b"01234567\r\n"),
            Ok(IdentStep::Prelude { .. })
        ));

        let limits = IdentLimits {
            max_prelude_bytes: 5,
            ..limits
        };
        let mut r = IdentificationReader::new(limits);
        assert!(matches!(r.feed(b"ab\r\n"), Ok(IdentStep::Prelude { .. })));
        assert_eq!(r.feed(b"cd\r\n"), Err(IdentError::PreludeBytesExceeded));
    }

    #[test]
    fn unsupported_and_malformed() {
        assert_eq!(
            reader().feed(b"SSH-1.5-old\r\n"),
            Err(IdentError::UnsupportedVersion)
        );
        assert_eq!(
            reader().feed(b"SSH-2.0\r\n"),
            Err(IdentError::InvalidIdentification(
                InvalidIdentification::MissingSeparator
            ))
        );
        assert_eq!(
            reader().feed(b"SSH--x\r\n"),
            Err(IdentError::InvalidIdentification(
                InvalidIdentification::BadProtocolVersion
            ))
        );
        assert_eq!(
            reader().feed(b"SSH-2.0-\r\n"),
            Err(IdentError::InvalidIdentification(
                InvalidIdentification::BadSoftwareVersion
            ))
        );
        assert_eq!(
            reader().feed(b"SSH-2.0-a\tb\r\n"),
            Err(IdentError::InvalidIdentification(
                InvalidIdentification::BadSoftwareVersion
            ))
        );
        assert_eq!(
            reader().feed(b"SSH-2.0-a\rb\r\n"),
            Err(IdentError::InvalidIdentification(
                InvalidIdentification::ControlCharacter
            ))
        );
    }

    #[test]
    fn short_prefix_is_ambiguous_until_four_bytes() {
        assert_eq!(starts_identification(b""), None);
        assert_eq!(starts_identification(b"SS"), None);
        assert_eq!(starts_identification(b"SSH-"), Some(true));
        assert_eq!(starts_identification(b"SSX"), Some(false));
        assert_eq!(starts_identification(b"Hello"), Some(false));
    }

    #[test]
    fn build_identification_validates_token_and_total_length() {
        assert_eq!(
            build_identification("tatami_0.1.0").unwrap(),
            b"SSH-2.0-tatami_0.1.0\r\n"
        );
        assert_eq!(
            build_identification("0.2.0-alpha"),
            Err(InvalidLocalIdentification::BadSoftwareVersion)
        );
        assert_eq!(
            build_identification(""),
            Err(InvalidLocalIdentification::BadSoftwareVersion)
        );
        // 8 + 245 + 2 = 255: accepted. 8 + 246 + 2 = 256: rejected.
        let ok = "x".repeat(245);
        assert_eq!(build_identification(&ok).unwrap().len(), 255);
        let long = "x".repeat(246);
        assert_eq!(
            build_identification(&long),
            Err(InvalidLocalIdentification::TooLong { len: 256 })
        );
    }

    #[test]
    fn anomalies_are_reported() {
        let mut r = reader();
        let IdentStep::Identification { ident, .. } = r.feed(b"SSH-1.99-x\n").unwrap() else {
            panic!()
        };
        let a: Vec<IdentAnomaly> = ident.anomalies().collect();
        assert_eq!(
            a,
            [
                IdentAnomaly::LfOnlyTerminator,
                IdentAnomaly::CompatibilityVersion
            ]
        );
        let owned = OwnedIdentification::from(ident);
        assert_eq!(owned.anomalies().count(), 2);
        assert_eq!(owned.line, b"SSH-1.99-x");

        let mut r = reader();
        let IdentStep::Identification { ident, .. } = r.feed(b"SSH-2.0-x\r\n").unwrap() else {
            panic!()
        };
        assert_eq!(ident.anomalies().count(), 0);
    }

    #[test]
    fn version_token_rules() {
        assert!(is_version_token(b"tatami_0.1.0"));
        assert!(!is_version_token(b""));
        assert!(!is_version_token(b"a-b"));
        assert!(!is_version_token(b"a b"));
        assert!(!is_version_token(b"\xc3\xa9"));
    }
}
