//! Minimal JSON value model and serializer (RFC 8259).
//!
//! Used for JSON Lines output. It is deliberately small: objects preserve
//! insertion order, numbers are integers, and strings are Rust `String`s
//! (therefore valid UTF-8). Raw protocol bytes are rendered with
//! [`Value::lossy_text`] and, where fidelity matters, [`Value::hex`].
//!
//! Escaping follows RFC 8259 §7: `"`, `\` and U+0000–U+001F are always
//! escaped; everything else is emitted as UTF-8. The `\xNN` form produced
//! by [`crate::text`] is a terminal convention and is never used here.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

/// A JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// Unsigned integer.
    UInt(u64),
    /// Signed integer.
    Int(i64),
    /// String (valid UTF-8 by construction).
    Str(String),
    /// Ordered array.
    Array(Vec<Value>),
    /// Ordered object.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// String from anything string-like.
    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    /// Lossy UTF-8 rendering of raw bytes (invalid sequences become
    /// U+FFFD). Pair with [`Value::hex`] when exact bytes matter.
    #[must_use]
    pub fn lossy_text(bytes: &[u8]) -> Value {
        Value::Str(String::from_utf8_lossy(bytes).into_owned())
    }

    /// Lowercase hex of `bytes`.
    #[must_use]
    pub fn hex(bytes: &[u8]) -> Value {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        Value::Str(s)
    }

    /// Array of strings.
    pub fn strings<I, S>(items: I) -> Value
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Value::Array(items.into_iter().map(|s| Value::Str(s.into())).collect())
    }

    /// Empty object builder.
    #[must_use]
    pub fn object() -> Object {
        Object(Vec::new())
    }

    /// Serializes to a compact single-line string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    /// Appends the compact serialization to `out`.
    pub fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::UInt(n) => {
                let _ = write!(out, "{n}");
            }
            Value::Int(n) => {
                let _ = write!(out, "{n}");
            }
            Value::Str(s) => write_string(out, s),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(out, k);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// Ordered object builder.
#[derive(Clone, Debug, Default)]
pub struct Object(Vec<(String, Value)>);

impl Object {
    /// Adds a field.
    #[must_use]
    pub fn field(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.0.push((String::from(key), value.into()));
        self
    }

    /// Adds a field only if `value` is `Some`.
    #[must_use]
    pub fn opt(self, key: &str, value: Option<impl Into<Value>>) -> Self {
        match value {
            Some(v) => self.field(key, v),
            None => self.field(key, Value::Null),
        }
    }

    /// Finishes the object.
    #[must_use]
    pub fn build(self) -> Value {
        Value::Object(self.0)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<u64> for Value {
    fn from(n: u64) -> Self {
        Value::UInt(n)
    }
}
impl From<u32> for Value {
    fn from(n: u32) -> Self {
        Value::UInt(u64::from(n))
    }
}
impl From<usize> for Value {
    fn from(n: usize) -> Self {
        Value::UInt(n as u64)
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Value::Int(n)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(String::from(s))
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}
impl From<Object> for Value {
    fn from(o: Object) -> Self {
        o.build()
    }
}
impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self {
        Value::Array(v)
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn escapes_per_rfc_8259() {
        assert_eq!(Value::str("plain").to_json(), "\"plain\"");
        assert_eq!(Value::str("q\"b\\").to_json(), "\"q\\\"b\\\\\"");
        assert_eq!(
            Value::str("\n\r\t\u{08}\u{0c}").to_json(),
            "\"\\n\\r\\t\\b\\f\""
        );
        assert_eq!(Value::str("\u{01}\u{1f}").to_json(), "\"\\u0001\\u001f\"");
        assert_eq!(Value::str("\u{7f}é✓").to_json(), "\"\u{7f}é✓\"");
        assert_eq!(Value::str("/").to_json(), "\"/\"");
    }

    #[test]
    fn lossy_and_hex() {
        assert_eq!(Value::lossy_text(b"ok\xff!").to_json(), "\"ok\u{fffd}!\"");
        assert_eq!(Value::hex(b"\x00\xab\xff").to_json(), "\"00abff\"");
        assert_eq!(Value::lossy_text(b"\x1b[31m").to_json(), "\"\\u001b[31m\"");
    }

    #[test]
    fn structures_preserve_order() {
        let v = Value::object()
            .field("b", 1u64)
            .field("a", true)
            .field("n", Value::Null)
            .field("s", Value::strings(["x", "y"]))
            .field("neg", -5i64)
            .opt("none", None::<u64>)
            .opt("some", Some(3u32))
            .field("nested", Value::object().field("k", "v"))
            .build();
        assert_eq!(
            v.to_json(),
            r#"{"b":1,"a":true,"n":null,"s":["x","y"],"neg":-5,"none":null,"some":3,"nested":{"k":"v"}}"#
        );
        assert_eq!(Value::Array(vec![]).to_json(), "[]");
        assert_eq!(Value::object().build().to_json(), "{}");
    }
}
