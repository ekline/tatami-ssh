#![no_main]
//! `tatami::json::Value` serialization and `tatami::text` escaping against
//! independent references (`state_support::json_ref`) and `serde_json`.
//!
//! # Input layout
//!
//! A recursive tree generator over the bytes; at most 64 nodes and depth 6
//! (deeper levels are forced to scalars; an exhausted budget yields `null`).
//! Each node starts with a tag byte `t`; `t % 12` selects the kind and
//! `t >> 4` is a selector:
//!
//! ```text
//!  0 null
//!  1 bool            selector bit 0
//!  2 UInt            sel 0:0 1:1 2:u64::MAX 3:2^63 4:2^53 5:2^53+1 6:10^18
//!                    else: explicit u64 (8 bytes)
//!  3 Int             sel 0:0 1:-1 2:i64::MIN 3:i64::MAX 4:-(2^53)-1 5:2^53
//!                    6:-10^18 else: explicit i64 (8 bytes)
//!  4 lossy_text      [len u8] raw bytes (also fed to text::escape_bytes /
//!                    text::quoted, see below)
//!  5 hex             [len u8] raw bytes (likewise)
//!  6 str (classes)   [len u8 mod 65] one byte per char; `b >> 5` picks the
//!                    class: 0 U+0000-001F, 1 U+0020-003F (`"` `/`),
//!                    2 U+0040-005F (`\`), 3 U+0060-007F (DEL), 4 two-byte
//!                    (U+0080-04FB), 5 three-byte table (U+2028, U+FFFD,
//!                    U+FEFF, U+D7FF, U+E000, ...), 6 non-BMP table
//!                    (U+10000, U+1F600, U+10FFFF, ...), 7 U+007F-00FF
//!  7 str (raw)       [len u8] bytes -> String::from_utf8_lossy
//!  8,9 array         [n u8 mod 9] children
//! 10,11 object       [n u8 mod 9] x ([klen u8 mod 9] class-chars key, child);
//!                    duplicate keys are allowed (last wins semantically)
//! ```
//!
//! # Oracles
//!
//! - `to_json()` equals an independent compact RFC 8259 serializer byte for
//!   byte (escaping of `"`, `\` and U+0000–U+001F with the documented short
//!   forms and lowercase `\u00xx`, raw UTF-8 otherwise, decimal integers,
//!   insertion order of object members).
//! - `serde_json` parses the output and the parsed value equals an
//!   independent semantic conversion of the shadow tree (last-wins for
//!   duplicate keys; UInt as u64, Int as i64).
//! - A tokenizer over the emitted text yields every key and string value in
//!   tree order with the original content, and rejects raw bytes below
//!   0x20 anywhere, unknown escapes (in particular the terminal `\xNN`
//!   convention), lone surrogates and unterminated strings.
//! - `Value::write` appends exactly `to_json()`.
//! - `lossy_text(b)` equals `String::from_utf8_lossy(b)`; `hex(b)` is
//!   lowercase, `2 * len` long and decodes back to `b`.
//! - `text::escape_bytes(b)` is printable ASCII and an independent unescaper
//!   recovers `b` (identity when `b` is printable ASCII without `\`);
//!   `text::quoted(b)` is `"`-wrapped and unescapes likewise; embedding the
//!   quoted form in a JSON string round-trips through the tokenizer.

use libfuzzer_sys::fuzz_target;
use tatami::json::Value;
use tatami::text::{escape_bytes, quoted};
use tatami_fuzz_protocol::state_support::json_ref::{
    self, Node, collect_strings, decode_hex_lower, scan_strings, unescape_terminal,
};
use tatami_fuzz_protocol::tcp_support::Cursor;

const MAX_NODES: usize = 64;
const MAX_DEPTH: usize = 6;

const THREE_BYTE: [char; 12] = [
    '\u{2028}', '\u{2029}', '\u{FFFD}', '\u{FEFF}', '\u{FFFF}', '\u{D7FF}', '\u{E000}', '\u{3042}',
    '\u{20AC}', '\u{FFFE}', '\u{0800}', '\u{1E9E}',
];

const NON_BMP: [char; 6] = [
    '\u{10000}',
    '\u{1F600}',
    '\u{10FFFF}',
    '\u{1F4A9}',
    '\u{E0001}',
    '\u{F0000}',
];

fn class_char(b: u8) -> char {
    let low = u32::from(b & 0x1f);
    match b >> 5 {
        0 => char::from_u32(low).expect("control"),
        1 => char::from_u32(0x20 + low).expect("ascii"),
        2 => char::from_u32(0x40 + low).expect("ascii"),
        3 => char::from_u32(0x60 + low).expect("ascii"),
        4 => char::from_u32(0x80 + low * 37).expect("two-byte"),
        5 => THREE_BYTE[usize::from(b & 0x1f) % THREE_BYTE.len()],
        6 => NON_BMP[usize::from(b & 0x1f) % NON_BMP.len()],
        _ => char::from_u32(0x7f + low * 4).expect("latin-1"),
    }
}

fn class_string(cur: &mut Cursor<'_>, len: usize) -> String {
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        s.push(class_char(cur.u8()));
    }
    s
}

/// Checks the terminal escaping helpers on one raw byte string.
fn check_text(bytes: &[u8]) {
    let escaped = escape_bytes(bytes);
    assert_eq!(
        unescape_terminal(&escaped, false),
        bytes,
        "escape_bytes must be invertible"
    );
    if bytes
        .iter()
        .all(|&b| (0x20..=0x7e).contains(&b) && b != b'\\')
    {
        assert_eq!(
            escaped.as_bytes(),
            bytes,
            "printable ASCII is kept verbatim"
        );
    }
    assert!(escaped.len() >= bytes.len() && escaped.len() <= 4 * bytes.len());

    let q = quoted(bytes);
    assert!(q.len() >= 2 && q.starts_with('"') && q.ends_with('"'));
    assert_eq!(
        unescape_terminal(&q[1..q.len() - 1], true),
        bytes,
        "quoted must be invertible"
    );

    // Terminal and JSON conventions compose without mixing: JSON escaping
    // of the quoted form doubles the backslashes and the tokenizer recovers
    // the quoted text; no `\x` escape reaches the JSON layer.
    let json = Value::str(q.as_str()).to_json();
    assert_eq!(scan_strings(&json), std::slice::from_ref(&q));
    assert_eq!(json, json_ref::serialize(&Node::Str(q)));
}

fn gen_node(cur: &mut Cursor<'_>, depth: usize, budget: &mut usize) -> (Value, Node) {
    if *budget == 0 {
        return (Value::Null, Node::Null);
    }
    *budget -= 1;
    let tag = cur.u8();
    let sel = tag >> 4;
    let mut kind = tag % 12;
    if depth >= MAX_DEPTH {
        kind %= 8;
    }
    match kind {
        0 => (Value::Null, Node::Null),
        1 => {
            let b = sel & 1 == 1;
            (Value::Bool(b), Node::Bool(b))
        }
        2 => {
            let n = match sel {
                0 => 0,
                1 => 1,
                2 => u64::MAX,
                3 => 1 << 63,
                4 => 1 << 53,
                5 => (1 << 53) + 1,
                6 => 1_000_000_000_000_000_000,
                _ => (u64::from(cur.u32()) << 32) | u64::from(cur.u32()),
            };
            (Value::UInt(n), Node::UInt(n))
        }
        3 => {
            let n = match sel {
                0 => 0,
                1 => -1,
                2 => i64::MIN,
                3 => i64::MAX,
                4 => -(1 << 53) - 1,
                5 => 1 << 53,
                6 => -1_000_000_000_000_000_000,
                _ => ((u64::from(cur.u32()) << 32) | u64::from(cur.u32())) as i64,
            };
            (Value::Int(n), Node::Int(n))
        }
        4 => {
            let len = usize::from(cur.u8());
            let bytes = cur.take(len);
            check_text(bytes);
            let v = Value::lossy_text(bytes);
            let expected = String::from_utf8_lossy(bytes).into_owned();
            assert_eq!(v, Value::Str(expected.clone()), "lossy_text");
            (v, Node::Str(expected))
        }
        5 => {
            let len = usize::from(cur.u8());
            let bytes = cur.take(len);
            check_text(bytes);
            let v = Value::hex(bytes);
            let Value::Str(h) = &v else {
                panic!("hex must be a string")
            };
            assert_eq!(h.len(), 2 * bytes.len(), "hex length");
            assert_eq!(decode_hex_lower(h), bytes, "hex must decode back");
            let h = h.clone();
            (v, Node::Str(h))
        }
        6 => {
            let len = usize::from(cur.u8()) % 65;
            let s = class_string(cur, len);
            (Value::str(s.clone()), Node::Str(s))
        }
        7 => {
            let len = usize::from(cur.u8());
            let s = String::from_utf8_lossy(cur.take(len)).into_owned();
            (Value::str(s.as_str()), Node::Str(s))
        }
        8 | 9 => {
            let n = usize::from(cur.u8()) % 9;
            let mut items = Vec::with_capacity(n);
            let mut nodes = Vec::with_capacity(n);
            for _ in 0..n {
                if *budget == 0 {
                    break;
                }
                let (v, m) = gen_node(cur, depth + 1, budget);
                items.push(v);
                nodes.push(m);
            }
            (Value::Array(items), Node::Array(nodes))
        }
        _ => {
            let n = usize::from(cur.u8()) % 9;
            let mut fields = Vec::with_capacity(n);
            let mut nodes = Vec::with_capacity(n);
            for _ in 0..n {
                if *budget == 0 {
                    break;
                }
                let klen = usize::from(cur.u8()) % 9;
                let key = class_string(cur, klen);
                let (v, m) = gen_node(cur, depth + 1, budget);
                fields.push((key.clone(), v));
                nodes.push((key, m));
            }
            (Value::Object(fields), Node::Object(nodes))
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let mut budget = MAX_NODES;
    let (value, node) = gen_node(&mut cur, 1, &mut budget);
    assert!(node.count() <= MAX_NODES && node.depth() <= MAX_DEPTH);

    let json = value.to_json();

    // 1. Byte-exact agreement with the independent serializer (covers
    //    escaping, number formatting and member order).
    assert_eq!(json, json_ref::serialize(&node), "serialization differs");

    // 2. Valid JSON with the intended semantics, per an unrelated parser.
    let parsed: serde_json::Value =
        serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid JSON {e}: {json}"));
    assert_eq!(parsed, json_ref::to_serde(&node), "semantic mismatch");

    // 3. Every string literal, in order, with its original content; no raw
    //    control bytes and no escapes outside RFC 8259 §7.
    let mut expected = Vec::new();
    collect_strings(&node, &mut expected);
    assert_eq!(scan_strings(&json), expected, "string literals");

    // 4. `write` appends.
    let mut appended = String::from("prefix:");
    value.write(&mut appended);
    assert_eq!(appended, format!("prefix:{json}"));

    // 5. Builder and `strings` helpers agree with direct construction.
    if let Value::Object(fields) = &value {
        let mut built = Value::object();
        for (k, v) in fields {
            built = built.field(k, v.clone());
        }
        assert_eq!(built.build(), value);
    }
    if let Value::Array(items) = &value
        && items.iter().all(|i| matches!(i, Value::Str(_)))
    {
        let strs: Vec<String> = items
            .iter()
            .map(|i| match i {
                Value::Str(s) => s.clone(),
                _ => unreachable!(),
            })
            .collect();
        assert_eq!(Value::strings(strs), value);
    }
    let opt_some = Value::object().opt("k", Some(value.clone())).build();
    let opt_none = Value::object().opt("k", None::<Value>).build();
    assert_eq!(opt_some, Value::Object(vec![(String::from("k"), value)]));
    assert_eq!(
        opt_none,
        Value::Object(vec![(String::from("k"), Value::Null)])
    );
});
