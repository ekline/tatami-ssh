//! Transport-independent SSH identification content (RFC 4253 §4.2).
//!
//! An identification is
//!
//! ```text
//! SSH-protoversion-softwareversion [SP comments]
//! ```
//!
//! This module parses and encodes that **content only**: no line
//! terminator, no length accounting, no version policy. Those belong to the
//! transport binding that carries the identification (`tatami-tcp::ident`
//! for the TCP line exchange; a future QUIC binding must define its own
//! record limits and placement).
//!
//! # Contracts
//!
//! - [`Identification::parse`] validates the `SSH-` prefix itself, the two
//!   separators, the token character rules for `protoversion` and
//!   `softwareversion`, and rejects CR, LF and NUL anywhere. It does not
//!   trim, normalise or lossily decode anything; every field is a borrowed
//!   slice of the input, and [`Identification::as_bytes`] is the exact
//!   input.
//! - Absent comments (`None`) and present-but-empty comments (`Some(b"")`,
//!   from a trailing space) are distinct.
//! - Any syntactically valid `protoversion` parses. Whether a version is
//!   *supported* is a binding decision; [`classify_protocol_version`] is a
//!   shared helper that only names the well-known values.
//! - [`encode`] writes content only. It validates before writing and never
//!   partially fills the output on failure.

use core::fmt;

use crate::error::EncodeError;

/// The mandatory prefix.
pub const PREFIX: &[u8] = b"SSH-";

/// Parsed identification content, borrowed from the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identification<'a> {
    input: &'a [u8],
    protocol_version: &'a [u8],
    software_version: &'a [u8],
    comments: Option<&'a [u8]>,
}

/// Why content failed to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentSyntaxError {
    /// Input does not begin with `SSH-`.
    MissingPrefix,
    /// No `-` after `protoversion`.
    MissingSeparator,
    /// `protoversion` is empty or contains a forbidden byte.
    BadProtocolVersion,
    /// `softwareversion` is empty or contains a forbidden byte.
    BadSoftwareVersion,
    /// A CR, LF or NUL byte appeared anywhere in the content.
    ControlCharacter,
}

impl fmt::Display for IdentSyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IdentSyntaxError::MissingPrefix => "identification does not start with 'SSH-'",
            IdentSyntaxError::MissingSeparator => "missing '-' after protocol version",
            IdentSyntaxError::BadProtocolVersion => "malformed protocol version",
            IdentSyntaxError::BadSoftwareVersion => "malformed software version",
            IdentSyntaxError::ControlCharacter => "CR, LF or NUL in identification",
        })
    }
}

impl core::error::Error for IdentSyntaxError {}

impl<'a> Identification<'a> {
    /// Parses complete identification content (no terminator).
    pub fn parse(input: &'a [u8]) -> Result<Self, IdentSyntaxError> {
        if input.iter().any(|&b| is_forbidden_byte(b)) {
            return Err(IdentSyntaxError::ControlCharacter);
        }
        let rest = input
            .strip_prefix(PREFIX)
            .ok_or(IdentSyntaxError::MissingPrefix)?;
        let dash = rest
            .iter()
            .position(|&b| b == b'-')
            .ok_or(IdentSyntaxError::MissingSeparator)?;
        let protocol_version = &rest[..dash];
        if !is_version_token(protocol_version) {
            return Err(IdentSyntaxError::BadProtocolVersion);
        }
        let after = &rest[dash + 1..];
        let (software_version, comments) = match after.iter().position(|&b| b == b' ') {
            Some(sp) => (&after[..sp], Some(&after[sp + 1..])),
            None => (after, None),
        };
        if !is_version_token(software_version) {
            return Err(IdentSyntaxError::BadSoftwareVersion);
        }
        Ok(Identification {
            input,
            protocol_version,
            software_version,
            comments,
        })
    }

    /// The exact input bytes (the `V_C`/`V_S` form used by RFC 4253 §8,
    /// which excludes CR and LF).
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.input
    }

    /// The `protoversion` token.
    #[must_use]
    pub const fn protocol_version(&self) -> &'a [u8] {
        self.protocol_version
    }

    /// The `softwareversion` token.
    #[must_use]
    pub const fn software_version(&self) -> &'a [u8] {
        self.software_version
    }

    /// Comments after the single separating space, if present. Raw bytes;
    /// untrusted; may be empty.
    #[must_use]
    pub const fn comments(&self) -> Option<&'a [u8]> {
        self.comments
    }

    /// Well-known classification of the protocol version. Not a support
    /// decision.
    #[must_use]
    pub fn protocol_version_class(&self) -> ProtocolVersionClass {
        classify_protocol_version(self.protocol_version)
    }
}

/// Well-known `protoversion` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVersionClass {
    /// `2.0`.
    Ssh2,
    /// `1.99`: RFC 4253 §5.1 compatibility indication from an SSH-1-capable
    /// implementation that also speaks SSH-2.
    Ssh2Compatibility,
    /// Anything else (including SSH-1 versions and future values).
    Other,
}

/// Classifies a `protoversion` token. Bindings decide what to accept.
#[must_use]
pub fn classify_protocol_version(token: &[u8]) -> ProtocolVersionClass {
    match token {
        b"2.0" => ProtocolVersionClass::Ssh2,
        b"1.99" => ProtocolVersionClass::Ssh2Compatibility,
        _ => ProtocolVersionClass::Other,
    }
}

/// Bytes that may never appear in identification content.
#[must_use]
pub const fn is_forbidden_byte(b: u8) -> bool {
    matches!(b, b'\r' | b'\n' | 0)
}

/// Returns `true` if `token` is a valid `protoversion` / `softwareversion`:
/// non-empty printable US-ASCII with no whitespace and no `-`
/// (RFC 4253 §4.2).
#[must_use]
pub fn is_version_token(token: &[u8]) -> bool {
    !token.is_empty() && token.iter().all(|&b| is_token_byte(b))
}

/// Returns `true` for a byte allowed inside a version token.
#[must_use]
pub const fn is_token_byte(b: u8) -> bool {
    b > 0x20 && b < 0x7f && b != b'-'
}

/// Number of bytes [`encode`] will write for these fields, or `None` if
/// the fields are invalid or the size overflows.
#[must_use]
pub fn encoded_len(
    protocol_version: &[u8],
    software_version: &[u8],
    comments: Option<&[u8]>,
) -> Option<usize> {
    if !is_version_token(protocol_version) || !is_version_token(software_version) {
        return None;
    }
    if let Some(c) = comments {
        if c.iter().any(|&b| is_forbidden_byte(b)) {
            return None;
        }
    }
    let mut n = PREFIX.len();
    n = n.checked_add(protocol_version.len())?.checked_add(1)?;
    n = n.checked_add(software_version.len())?;
    if let Some(c) = comments {
        n = n.checked_add(1)?.checked_add(c.len())?;
    }
    Some(n)
}

/// Why [`encode`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentEncodeError {
    /// `protoversion` is not a valid token.
    BadProtocolVersion,
    /// `softwareversion` is not a valid token.
    BadSoftwareVersion,
    /// Comments contain CR, LF or NUL.
    BadComments,
    /// Output buffer too small.
    InsufficientCapacity {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// Combined length overflows `usize`.
    LengthOverflow,
}

impl fmt::Display for IdentEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentEncodeError::BadProtocolVersion => f.write_str("malformed protocol version"),
            IdentEncodeError::BadSoftwareVersion => f.write_str("malformed software version"),
            IdentEncodeError::BadComments => f.write_str("comments contain CR, LF or NUL"),
            IdentEncodeError::InsufficientCapacity { needed, available } => write!(
                f,
                "output buffer too small: needed {needed}, available {available}"
            ),
            IdentEncodeError::LengthOverflow => f.write_str("identification length overflows"),
        }
    }
}

impl core::error::Error for IdentEncodeError {}

impl From<IdentEncodeError> for EncodeError {
    fn from(e: IdentEncodeError) -> Self {
        match e {
            IdentEncodeError::InsufficientCapacity { needed, available } => {
                EncodeError::InsufficientCapacity { needed, available }
            }
            IdentEncodeError::LengthOverflow => EncodeError::LengthOverflow { len: usize::MAX },
            IdentEncodeError::BadProtocolVersion => EncodeError::InvalidName { index: 0 },
            IdentEncodeError::BadSoftwareVersion => EncodeError::InvalidName { index: 1 },
            IdentEncodeError::BadComments => EncodeError::InvalidName { index: 2 },
        }
    }
}

/// Encodes identification content (no terminator) into `out`, returning
/// the number of bytes written.
///
/// All validation happens before any byte is written; on error `out` is
/// unchanged. The result always parses back with [`Identification::parse`]
/// to the same fields.
pub fn encode(
    protocol_version: &[u8],
    software_version: &[u8],
    comments: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize, IdentEncodeError> {
    if !is_version_token(protocol_version) {
        return Err(IdentEncodeError::BadProtocolVersion);
    }
    if !is_version_token(software_version) {
        return Err(IdentEncodeError::BadSoftwareVersion);
    }
    if comments.is_some_and(|c| c.iter().any(|&b| is_forbidden_byte(b))) {
        return Err(IdentEncodeError::BadComments);
    }
    let needed = encoded_len(protocol_version, software_version, comments)
        .ok_or(IdentEncodeError::LengthOverflow)?;
    if out.len() < needed {
        return Err(IdentEncodeError::InsufficientCapacity {
            needed,
            available: out.len(),
        });
    }
    let mut pos = 0;
    for part in [PREFIX, protocol_version, b"-", software_version] {
        out[pos..pos + part.len()].copy_from_slice(part);
        pos += part.len();
    }
    if let Some(c) = comments {
        out[pos] = b' ';
        pos += 1;
        out[pos..pos + c.len()].copy_from_slice(c);
        pos += c.len();
    }
    debug_assert_eq!(pos, needed);
    Ok(pos)
}

#[cfg(feature = "alloc")]
pub use owned::OwnedIdentification;

#[cfg(feature = "alloc")]
mod owned {
    use alloc::vec::Vec;

    use super::{IdentSyntaxError, Identification, ProtocolVersionClass};

    /// Owned identification content. Stores the exact bytes once and
    /// re-derives borrowed views on demand, so it cannot get out of sync
    /// with itself.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct OwnedIdentification {
        bytes: Vec<u8>,
        protocol_end: usize,
        software_end: usize,
        has_comments: bool,
    }

    impl OwnedIdentification {
        /// Copies a borrowed identification.
        #[must_use]
        pub fn from_borrowed(id: &Identification<'_>) -> Self {
            let protocol_end = super::PREFIX.len() + id.protocol_version.len();
            let software_end = protocol_end + 1 + id.software_version.len();
            OwnedIdentification {
                bytes: id.input.to_vec(),
                protocol_end,
                software_end,
                has_comments: id.comments.is_some(),
            }
        }

        /// Parses and copies content.
        pub fn parse(input: &[u8]) -> Result<Self, IdentSyntaxError> {
            Identification::parse(input).map(|id| Self::from_borrowed(&id))
        }

        /// Borrowed view over the stored bytes.
        #[must_use]
        pub fn as_borrowed(&self) -> Identification<'_> {
            let comments = if self.has_comments {
                Some(&self.bytes[self.software_end + 1..])
            } else {
                None
            };
            Identification {
                input: &self.bytes,
                protocol_version: &self.bytes[super::PREFIX.len()..self.protocol_end],
                software_version: &self.bytes[self.protocol_end + 1..self.software_end],
                comments,
            }
        }

        /// Exact content bytes.
        #[must_use]
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }

        /// The `protoversion` token.
        #[must_use]
        pub fn protocol_version(&self) -> &[u8] {
            self.as_borrowed().protocol_version
        }

        /// The `softwareversion` token.
        #[must_use]
        pub fn software_version(&self) -> &[u8] {
            self.as_borrowed().software_version
        }

        /// Raw comments, if present.
        #[must_use]
        pub fn comments(&self) -> Option<&[u8]> {
            self.as_borrowed().comments
        }

        /// See [`Identification::protocol_version_class`].
        #[must_use]
        pub fn protocol_version_class(&self) -> ProtocolVersionClass {
            self.as_borrowed().protocol_version_class()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_exactly() {
        let id = Identification::parse(b"SSH-2.0-OpenSSH_9.6 some comment").unwrap();
        assert_eq!(id.as_bytes(), b"SSH-2.0-OpenSSH_9.6 some comment");
        assert_eq!(id.protocol_version(), b"2.0");
        assert_eq!(id.software_version(), b"OpenSSH_9.6");
        assert_eq!(id.comments(), Some(&b"some comment"[..]));
        assert_eq!(id.protocol_version_class(), ProtocolVersionClass::Ssh2);

        let id = Identification::parse(b"SSH-1.99-x").unwrap();
        assert_eq!(id.comments(), None);
        assert_eq!(
            id.protocol_version_class(),
            ProtocolVersionClass::Ssh2Compatibility
        );

        // Empty-but-present comments, raw high bytes, no trimming.
        let id = Identification::parse(b"SSH-2.0-x ").unwrap();
        assert_eq!(id.comments(), Some(&b""[..]));
        let id = Identification::parse(b"SSH-2.0-x  two spaces\xff ").unwrap();
        assert_eq!(id.comments(), Some(&b" two spaces\xff "[..]));

        // Unknown versions parse; policy is the binding's job.
        let id = Identification::parse(b"SSH-1.5-ancient").unwrap();
        assert_eq!(id.protocol_version_class(), ProtocolVersionClass::Other);
    }

    #[test]
    fn rejects_malformed_content() {
        use IdentSyntaxError as E;
        for (input, err) in [
            (&b""[..], E::MissingPrefix),
            (b"S", E::MissingPrefix),
            (b"SSH", E::MissingPrefix),
            (b"ssh-2.0-x", E::MissingPrefix),
            (b"XSSH-2.0-x", E::MissingPrefix),
            (b"SSH-", E::MissingSeparator),
            (b"SSH-2.0", E::MissingSeparator),
            (b"SSH--x", E::BadProtocolVersion),
            (b"SSH-2 0-x", E::BadProtocolVersion),
            (b"SSH-2.0-", E::BadSoftwareVersion),
            (b"SSH-2.0- c", E::BadSoftwareVersion),
            (b"SSH-2.0-a\tb", E::BadSoftwareVersion),
            (b"SSH-2.0-a\xffb", E::BadSoftwareVersion),
            (b"SSH-2.0-x\r", E::ControlCharacter),
            (b"SSH-2.0-x\n", E::ControlCharacter),
            (b"SSH-2.0-x c\x00", E::ControlCharacter),
            (b"\r", E::ControlCharacter),
        ] {
            assert_eq!(Identification::parse(input), Err(err), "{input:?}");
        }
    }

    #[test]
    fn encode_matches_hand_derived_bytes_and_parses_back() {
        let mut out = [0u8; 64];
        let n = encode(b"2.0", b"tatami_0.1.0", None, &mut out).unwrap();
        assert_eq!(&out[..n], b"SSH-2.0-tatami_0.1.0");
        assert_eq!(n, encoded_len(b"2.0", b"tatami_0.1.0", None).unwrap());

        let n = encode(b"2.0", b"x", Some(b"c d"), &mut out).unwrap();
        assert_eq!(&out[..n], b"SSH-2.0-x c d");
        let id = Identification::parse(&out[..n]).unwrap();
        assert_eq!(id.comments(), Some(&b"c d"[..]));

        let n = encode(b"2.0", b"x", Some(b""), &mut out).unwrap();
        assert_eq!(&out[..n], b"SSH-2.0-x ");
    }

    #[test]
    fn encode_validates_before_writing() {
        let mut out = [0xEEu8; 16];
        assert_eq!(
            encode(b"2 0", b"x", None, &mut out),
            Err(IdentEncodeError::BadProtocolVersion)
        );
        assert_eq!(
            encode(b"2.0", b"", None, &mut out),
            Err(IdentEncodeError::BadSoftwareVersion)
        );
        assert_eq!(
            encode(b"2.0", b"x", Some(b"a\nb"), &mut out),
            Err(IdentEncodeError::BadComments)
        );
        assert_eq!(
            encode(b"2.0", b"longer_than_sixteen", None, &mut out),
            Err(IdentEncodeError::InsufficientCapacity {
                needed: 27,
                available: 16
            })
        );
        assert_eq!(out, [0xEE; 16], "output untouched on every failure");
        assert!(encoded_len(b"2.0", b"x", Some(b"\r")).is_none());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_round_trips_to_borrowed_views() {
        let owned = OwnedIdentification::parse(b"SSH-2.0-sw c\xff").unwrap();
        assert_eq!(owned.as_bytes(), b"SSH-2.0-sw c\xff");
        assert_eq!(owned.protocol_version(), b"2.0");
        assert_eq!(owned.software_version(), b"sw");
        assert_eq!(owned.comments(), Some(&b"c\xff"[..]));
        let b = owned.as_borrowed();
        assert_eq!(b, Identification::parse(b"SSH-2.0-sw c\xff").unwrap());

        let owned = OwnedIdentification::parse(b"SSH-2.0-sw").unwrap();
        assert_eq!(owned.comments(), None);
        let owned = OwnedIdentification::parse(b"SSH-2.0-sw ").unwrap();
        assert_eq!(owned.comments(), Some(&b""[..]));
    }
}
