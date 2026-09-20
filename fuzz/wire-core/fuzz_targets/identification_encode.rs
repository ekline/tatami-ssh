#![no_main]
//! `ident::encode` / `ident::encoded_len` against hand-computed expectations.
//!
//! Input layout (self-describing so seeds are readable):
//! `mode:u8, plen:u16be, proto[plen], slen:u16be, software[slen],
//!  clen:u16be, comments[clen], cap:u16be, fill:u8`.
//! `mode` bits: 0 sanitize proto, 1 sanitize software, 2 comments present,
//! 3 sanitize comments (strip CR/LF/NUL); bits 4-5 select the capacity:
//! 0 arbitrary `0..=600`, 1 exactly `needed`, 2 `needed - 1`, 3 `needed + 7`.
//!
//! Oracles:
//! - `encoded_len` is `Some(4 + p + 1 + s [+ 1 + c])` iff the fields satisfy
//!   the reference grammar;
//! - `encode` fails iff the fields are invalid or the capacity is short, with
//!   the field-order error variant and exact `needed`/`available`;
//! - on error the output buffer is byte-identical to its pre-filled pattern;
//! - on success the written bytes equal the hand-assembled concatenation,
//!   nothing beyond `n` is touched, and `Identification::parse` returns the
//!   input fields exactly (including `None` vs `Some(b"")` comments);
//! - a fixed hand-derived vector is checked on every run.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tatami_fuzz_wire_core::generate;
use tatami_fuzz_wire_core::ident_ref;
use tatami_wire::ident::{self, IdentEncodeError, Identification};

const MAX_FIELD: usize = 300;
const MAX_CAPACITY: u16 = 600;

#[derive(Debug)]
struct Input {
    proto: Vec<u8>,
    software: Vec<u8>,
    comments: Option<Vec<u8>>,
    capacity: usize,
    fill: u8,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mode = generate::byte(u);
        let mut proto = generate::bounded_bytes(u, MAX_FIELD);
        if mode & 1 != 0 {
            ident_ref::sanitize_token(&mut proto);
        }
        let mut software = generate::bounded_bytes(u, MAX_FIELD);
        if mode & 2 != 0 {
            ident_ref::sanitize_token(&mut software);
        }
        let mut comments = generate::bounded_bytes(u, MAX_FIELD);
        if mode & 8 != 0 {
            comments.retain(|&b| !ident_ref::is_forbidden_byte(b));
        }
        let comments = if mode & 4 != 0 { Some(comments) } else { None };
        let arbitrary_cap = generate::small(u, MAX_CAPACITY);
        let needed = expected_len(&proto, &software, comments.as_deref());
        let capacity = match ((mode >> 4) & 3, needed) {
            (1, Some(n)) => n,
            (2, Some(n)) => n.saturating_sub(1),
            (3, Some(n)) => n + 7,
            _ => arbitrary_cap,
        };
        let fill = generate::byte(u);
        Ok(Input {
            proto,
            software,
            comments,
            capacity,
            fill,
        })
    }
}

/// Reference: `Some(size)` iff the fields are valid.
fn expected_len(proto: &[u8], software: &[u8], comments: Option<&[u8]>) -> Option<usize> {
    if !ident_ref::is_version_token(proto) || !ident_ref::is_version_token(software) {
        return None;
    }
    if comments.is_some_and(|c| c.iter().any(|&b| ident_ref::is_forbidden_byte(b))) {
        return None;
    }
    Some(4 + proto.len() + 1 + software.len() + comments.map_or(0, |c| 1 + c.len()))
}

/// Reference: the outcome `encode` must produce.
fn expected_encode(
    proto: &[u8],
    software: &[u8],
    comments: Option<&[u8]>,
    capacity: usize,
) -> Result<usize, IdentEncodeError> {
    if !ident_ref::is_version_token(proto) {
        return Err(IdentEncodeError::BadProtocolVersion);
    }
    if !ident_ref::is_version_token(software) {
        return Err(IdentEncodeError::BadSoftwareVersion);
    }
    if comments.is_some_and(|c| c.iter().any(|&b| ident_ref::is_forbidden_byte(b))) {
        return Err(IdentEncodeError::BadComments);
    }
    let needed = expected_len(proto, software, comments).expect("validated above");
    if capacity < needed {
        return Err(IdentEncodeError::InsufficientCapacity {
            needed,
            available: capacity,
        });
    }
    Ok(needed)
}

fn check(proto: &[u8], software: &[u8], comments: Option<&[u8]>, capacity: usize, fill: u8) {
    let want_len = expected_len(proto, software, comments);
    assert_eq!(
        ident::encoded_len(proto, software, comments),
        want_len,
        "encoded_len({proto:?}, {software:?}, {comments:?})"
    );

    let mut buf: Vec<u8> = (0..capacity).map(|i| fill.wrapping_add(i as u8)).collect();
    let snapshot = buf.clone();

    let want = expected_encode(proto, software, comments, capacity);
    let got = ident::encode(proto, software, comments, &mut buf);
    assert_eq!(
        got, want,
        "encode({proto:?}, {software:?}, {comments:?}, cap={capacity})"
    );

    match got {
        Err(_) => {
            assert_eq!(buf, snapshot, "encode must not touch the buffer on error");
        }
        Ok(n) => {
            let hand = ident_ref::assemble(proto, software, comments);
            assert_eq!(n, hand.len());
            assert_eq!(
                &buf[..n],
                &hand[..],
                "encoded bytes differ from hand assembly"
            );
            assert_eq!(
                &buf[n..],
                &snapshot[n..],
                "encode wrote beyond the reported length"
            );

            let id = Identification::parse(&buf[..n]).expect("encode output must parse");
            assert_eq!(id.protocol_version(), proto);
            assert_eq!(id.software_version(), software);
            assert_eq!(
                id.comments(),
                comments,
                "comments round trip (None vs Some)"
            );
            assert_eq!(id.as_bytes(), &hand[..]);

            // The reference grammar agrees about the produced bytes.
            let r = ident_ref::parse(&hand).expect("reference must accept encode output");
            assert_eq!(r.protocol_version, proto);
            assert_eq!(r.software_version, software);
            assert_eq!(r.comments, comments);
        }
    }
}

fn fixed_vectors() {
    let mut out = [0xA5u8; 32];
    assert_eq!(
        ident::encode(b"2.0", b"tatami_0.1.0", None, &mut out),
        Ok(20)
    );
    assert_eq!(&out[..20], b"SSH-2.0-tatami_0.1.0");
    assert_eq!(out[20], 0xA5);
    assert_eq!(ident::encoded_len(b"2.0", b"tatami_0.1.0", None), Some(20));

    let mut out = [0x5Au8; 40];
    assert_eq!(
        ident::encode(b"2.0", b"OpenSSH_9.6", Some(b"Debian-4"), &mut out),
        Ok(28)
    );
    assert_eq!(&out[..28], b"SSH-2.0-OpenSSH_9.6 Debian-4");

    let mut out = [0x11u8; 20];
    assert_eq!(
        ident::encode(b"2.0", b"x", Some(b""), &mut out),
        Ok(10),
        "empty comments still emit the separating space"
    );
    assert_eq!(&out[..10], b"SSH-2.0-x ");

    let mut out = [0x22u8; 19];
    assert_eq!(
        ident::encode(b"2.0", b"tatami_0.1.0", None, &mut out),
        Err(IdentEncodeError::InsufficientCapacity {
            needed: 20,
            available: 19
        })
    );
    assert!(out.iter().all(|&b| b == 0x22));
}

fuzz_target!(|input: Input| {
    fixed_vectors();
    check(
        &input.proto,
        &input.software,
        input.comments.as_deref(),
        input.capacity,
        input.fill,
    );
});
