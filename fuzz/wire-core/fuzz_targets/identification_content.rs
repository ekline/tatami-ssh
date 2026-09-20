#![no_main]
//! `Identification::parse` against an independent RFC 4253 §4.2 grammar.
//!
//! Oracles:
//! - parse succeeds iff the reference grammar accepts;
//! - on success every field equals the reference slice, `as_bytes()` is the
//!   input, fields are sub-slices of the input, and re-assembling the fields
//!   reproduces the input byte-for-byte;
//! - `None` vs `Some(b"")` comments are distinguished;
//! - `classify_protocol_version` recognises exactly `2.0` and `1.99`;
//! - byte classifiers agree with the reference alphabet;
//! - each error variant implies the property it claims.

use libfuzzer_sys::fuzz_target;
use tatami_fuzz_wire_core::ident_ref;
use tatami_wire::ident::{self, IdentSyntaxError, Identification, ProtocolVersionClass};

fn is_subslice(outer: &[u8], inner: &[u8]) -> bool {
    let o = outer.as_ptr_range();
    let i = inner.as_ptr_range();
    i.start >= o.start && i.end <= o.end
}

fn expected_class(token: &[u8]) -> ProtocolVersionClass {
    if token == b"2.0" {
        ProtocolVersionClass::Ssh2
    } else if token == b"1.99" {
        ProtocolVersionClass::Ssh2Compatibility
    } else {
        ProtocolVersionClass::Other
    }
}

fn check_error_implication(data: &[u8], e: IdentSyntaxError) {
    let has_forbidden = data.iter().any(|&b| ident_ref::is_forbidden_byte(b));
    match e {
        IdentSyntaxError::ControlCharacter => {
            assert!(
                has_forbidden,
                "ControlCharacter without CR/LF/NUL: {data:?}"
            );
        }
        IdentSyntaxError::MissingPrefix => {
            assert!(
                !data.starts_with(b"SSH-"),
                "MissingPrefix but prefix present"
            );
        }
        IdentSyntaxError::MissingSeparator => {
            assert!(data.starts_with(b"SSH-"));
            assert!(
                !data[4..].contains(&b'-'),
                "MissingSeparator but a '-' follows the prefix: {data:?}"
            );
        }
        IdentSyntaxError::BadProtocolVersion => {
            assert!(data.starts_with(b"SSH-"));
            let rest = &data[4..];
            let dash = rest
                .iter()
                .position(|&b| b == b'-')
                .expect("BadProtocolVersion requires a separator");
            assert!(
                !ident_ref::is_version_token(&rest[..dash]),
                "BadProtocolVersion for a valid token: {data:?}"
            );
        }
        IdentSyntaxError::BadSoftwareVersion => {
            assert!(data.starts_with(b"SSH-"));
            let rest = &data[4..];
            let dash = rest
                .iter()
                .position(|&b| b == b'-')
                .expect("BadSoftwareVersion requires a separator");
            assert!(ident_ref::is_version_token(&rest[..dash]));
            let after = &rest[dash + 1..];
            let sw_end = after.iter().position(|&b| b == b' ').unwrap_or(after.len());
            assert!(
                !ident_ref::is_version_token(&after[..sw_end]),
                "BadSoftwareVersion for a valid token: {data:?}"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    for &b in data {
        assert_eq!(
            ident::is_token_byte(b),
            ident_ref::is_token_byte(b),
            "is_token_byte({b:#04x})"
        );
        assert_eq!(
            ident::is_forbidden_byte(b),
            ident_ref::is_forbidden_byte(b),
            "is_forbidden_byte({b:#04x})"
        );
    }

    let expected = ident_ref::parse(data);
    let actual = Identification::parse(data);

    match (expected, actual) {
        (Some(r), Ok(id)) => {
            assert_eq!(id.as_bytes(), data, "as_bytes must be the exact input");
            assert_eq!(
                id.protocol_version(),
                r.protocol_version,
                "protocol_version"
            );
            assert_eq!(
                id.software_version(),
                r.software_version,
                "software_version"
            );
            assert_eq!(id.comments(), r.comments, "comments (None vs Some)");
            assert!(is_subslice(data, id.as_bytes()));
            assert!(is_subslice(data, id.protocol_version()));
            assert!(is_subslice(data, id.software_version()));
            if let Some(c) = id.comments() {
                assert!(is_subslice(data, c));
            }
            assert!(ident::is_version_token(id.protocol_version()));
            assert!(ident::is_version_token(id.software_version()));

            let rebuilt =
                ident_ref::assemble(id.protocol_version(), id.software_version(), id.comments());
            assert_eq!(rebuilt, data, "fields must re-assemble to the input");

            let class = expected_class(r.protocol_version);
            assert_eq!(id.protocol_version_class(), class);
            assert_eq!(ident::classify_protocol_version(r.protocol_version), class);

            // encoded_len / encode must agree with what was just parsed.
            assert_eq!(
                ident::encoded_len(id.protocol_version(), id.software_version(), id.comments()),
                Some(data.len())
            );
            let mut out = vec![0u8; data.len()];
            assert_eq!(
                ident::encode(
                    id.protocol_version(),
                    id.software_version(),
                    id.comments(),
                    &mut out
                ),
                Ok(data.len())
            );
            assert_eq!(out, data, "encode(parse(x)) != x");
        }
        (None, Err(e)) => check_error_implication(data, e),
        (Some(r), Err(e)) => {
            panic!("reference accepts {data:?} as {r:?} but library rejects with {e:?}")
        }
        (None, Ok(id)) => {
            panic!("reference rejects {data:?} but library accepts as {id:?}")
        }
    }
});
