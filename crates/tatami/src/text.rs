//! Safe rendering of untrusted protocol bytes.
//!
//! Peer-supplied text (identification comments, `DEBUG`/`DISCONNECT`
//! messages, unknown algorithm names, prelude banners) must never reach a
//! terminal unescaped. These helpers keep printable ASCII and escape
//! everything else, so the original bytes stay recoverable from the output.

use alloc::string::String;
use core::fmt::Write as _;

/// Escapes `bytes` for display: printable ASCII other than `\` is kept;
/// `\` becomes `\\`; everything else becomes `\xNN`.
#[must_use]
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out
}

/// Renders `bytes` as a quoted, escaped string literal.
#[must_use]
pub fn quoted(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_control_and_high_bytes() {
        assert_eq!(escape_bytes(b"abc"), "abc");
        assert_eq!(escape_bytes(b"a\r\nb"), "a\\x0d\\x0ab");
        assert_eq!(escape_bytes(b"\x1b[31mred"), "\\x1b[31mred");
        assert_eq!(escape_bytes(b"\xc3\xa9"), "\\xc3\\xa9");
        assert_eq!(escape_bytes(b"back\\slash"), "back\\\\slash");
    }

    #[test]
    fn quoted_escapes_quotes() {
        assert_eq!(quoted(b"say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(quoted(b""), "\"\"");
    }
}
