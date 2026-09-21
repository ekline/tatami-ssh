#![no_main]
//! Key-exchange, service and extension codecs plus the `mpint` primitive
//! (`tatami-wire` without `alloc`), judged by independent reference layouts
//! and the RFC 4251 §5 canonical-form rule.
//!
//! # Input layout
//!
//! `sel:u8, rest...`
//!
//! - `sel < 0x80`: RAW. `rest` is a payload fed to all six production
//!   decoders (`KexEcdhInit`, `KexEcdhReply`, `NewKeys`, `ServiceRequest`,
//!   `ServiceAccept`, `ExtInfo`) and, as a `string`, to `Reader::read_mpint`.
//!   Each must agree with its reference on the exact `MessageError` (field
//!   names `Q_C`/`K_S`/`Q_S`/`signature`/`service_name`/`nr-extensions`/
//!   `extension-name`/`extension-value`, offsets, `TrailingBytes{count}`)
//!   and on every field. `EXT_INFO`: lazy pairs equal the reference walk,
//!   `validate(max)` for max ∈ {0, 1, 8, 64} equals the reference in the
//!   documented order, `server_sig_algs` equals the reference, and the
//!   message-number dispatch is exact (`Empty` / `UnexpectedMessage`).
//! - `sel >= 0x80`: STRUCTURED, `sel & 7` selects one of the cases below.
//!
//! Structured case 0, positive `mpint` write: a magnitude with fuzz leading
//! zeros; `write_mpint_positive` equals the reference encoding,
//! `mpint_positive_len` equals its length, a buffer one byte short fails
//! atomically with exact `InsufficientCapacity`, reading back is canonical,
//! non-negative and `positive_magnitude()` is the stripped magnitude; every
//! RFC 4251 example round-trips.
//!
//! Cases 1 `KEX_ECDH_INIT`, 2 `KEX_ECDH_REPLY`, 3 `NEWKEYS`, 4
//! `SERVICE_REQUEST`, 5 `SERVICE_ACCEPT`: hand assembly equals `encode`,
//! `decode` returns the fields, then truncate / flip / append mutations with
//! layout expectations (all five reject trailing bytes).
//!
//! Case 6 `EXT_INFO`: pairs from a pool of registered/vendor/fuzz names;
//! hand assembly equals `encode_ext_info`; `claimed_count`, `extensions()`,
//! `validate(max)` (`TooManyExtensions{claimed,max}` iff count > max),
//! `server_sig_algs` and `classify_extension` against the reference; a huge
//! count with only 12 bytes fails at `nr-extensions` before any pair is
//! read; count+1 is `CountMismatch{claimed,found}` or a header
//! `LengthOverflow`; a trailing byte is `Message(TrailingBytes{1})`.
//!
//! Case 7, raw `mpint` body inspection: `is_zero`/`is_negative`/
//! `is_canonical`/`positive_magnitude` against the rule "the first byte can
//! be dropped without changing the value", and `write(positive_magnitude(x))`
//! reproduces `x` exactly iff `x` is canonical and non-negative.

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use tatami_fuzz_wire_core::bytes::{put_string, put_u8};
use tatami_fuzz_wire_core::generate;
use tatami_fuzz_wire_core::kex_ref as kref;
use tatami_fuzz_wire_core::mpint_ref;
use tatami_wire::ext_info::{
    ExtInfo, ExtInfoError, KnownExtension, classify_extension, encode_ext_info,
};
use tatami_wire::kex::{KexEcdhInit, KexEcdhReply, NewKeys};
use tatami_wire::primitives::mpint_positive_len;
use tatami_wire::transport::{ServiceAccept, ServiceRequest};
use tatami_wire::{DecodeError, EncodeError, MessageError, Reader, Writer, msg};

const VALIDATE_MAXES: [usize; 4] = [0, 1, 8, 64];

// ---------------------------------------------------------------------------
// Raw path.
// ---------------------------------------------------------------------------

fn message_numbers_agree() {
    assert_eq!(msg::SERVICE_REQUEST, kref::SERVICE_REQUEST);
    assert_eq!(msg::SERVICE_ACCEPT, kref::SERVICE_ACCEPT);
    assert_eq!(msg::EXT_INFO, kref::EXT_INFO);
    assert_eq!(msg::NEWKEYS, kref::NEWKEYS);
    assert_eq!(msg::KEX_ECDH_INIT, kref::KEX_ECDH_INIT);
    assert_eq!(msg::KEX_ECDH_REPLY, kref::KEX_ECDH_REPLY);
    assert_eq!(tatami_wire::ext_info::MIN_PAIR_LEN, kref::MIN_PAIR_LEN);
    assert_eq!(NewKeys::LEN, 1);
    for (name, kind) in kref::KNOWN_EXTENSIONS {
        assert_eq!(kind.name(), name);
        assert_eq!(classify_extension(name), Some(kind));
    }
}

/// Re-encoding must reproduce the payload exactly and fail atomically on a
/// buffer one byte short.
fn check_reencode(
    payload: &[u8],
    encode: impl Fn(&mut [u8]) -> Result<usize, EncodeError>,
    what: &str,
) {
    let mut out = vec![0xEEu8; payload.len()];
    assert_eq!(
        encode(&mut out),
        Ok(payload.len()),
        "{what}: re-encode length"
    );
    assert_eq!(out, payload, "{what}: re-encode bytes");
    let mut short = vec![0xEEu8; payload.len() - 1];
    assert!(
        matches!(
            encode(&mut short),
            Err(EncodeError::InsufficientCapacity { .. })
        ),
        "{what}: short buffer must report capacity"
    );
}

fn check_ecdh_init_raw(payload: &[u8]) {
    match (KexEcdhInit::decode(payload), kref::ecdh_init(payload)) {
        (Err(a), Err(e)) => assert_eq!(a, e, "KEX_ECDH_INIT error for {payload:?}"),
        (Ok(m), Ok(q_c)) => {
            assert_eq!(m.client_ephemeral, q_c);
            check_reencode(payload, |out| m.encode(out), "KEX_ECDH_INIT");
        }
        (a, e) => {
            panic!("KEX_ECDH_INIT disagreement on {payload:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_ecdh_reply_raw(payload: &[u8]) {
    match (KexEcdhReply::decode(payload), kref::ecdh_reply(payload)) {
        (Err(a), Err(e)) => assert_eq!(a, e, "KEX_ECDH_REPLY error for {payload:?}"),
        (Ok(m), Ok(r)) => {
            assert_eq!(m.host_key_blob, r.k_s, "K_S");
            assert_eq!(m.server_ephemeral, r.q_s, "Q_S");
            assert_eq!(m.signature_blob, r.signature, "signature");
            check_reencode(payload, |out| m.encode(out), "KEX_ECDH_REPLY");
        }
        (a, e) => {
            panic!("KEX_ECDH_REPLY disagreement on {payload:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_newkeys_raw(payload: &[u8]) {
    match (NewKeys::decode(payload), kref::newkeys(payload)) {
        (Err(a), Err(e)) => assert_eq!(a, e, "NEWKEYS error for {payload:?}"),
        (Ok(n), Ok(())) => {
            assert_eq!(payload, [msg::NEWKEYS]);
            check_reencode(payload, |out| n.encode(out), "NEWKEYS");
        }
        (a, e) => panic!("NEWKEYS disagreement on {payload:?}:\n library {a:?}\n reference {e:?}"),
    }
}

fn check_service_request_raw(payload: &[u8]) {
    match (
        ServiceRequest::decode(payload),
        kref::service_request(payload),
    ) {
        (Err(a), Err(e)) => assert_eq!(a, e, "SERVICE_REQUEST error for {payload:?}"),
        (Ok(m), Ok(name)) => {
            assert_eq!(m.service_name, name);
            check_reencode(payload, |out| m.encode(out), "SERVICE_REQUEST");
        }
        (a, e) => {
            panic!("SERVICE_REQUEST disagreement on {payload:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_service_accept_raw(payload: &[u8]) {
    match (
        ServiceAccept::decode(payload),
        kref::service_accept(payload),
    ) {
        (Err(a), Err(e)) => assert_eq!(a, e, "SERVICE_ACCEPT error for {payload:?}"),
        (Ok(m), Ok(name)) => {
            assert_eq!(m.service_name, name);
            check_reencode(payload, |out| m.encode(out), "SERVICE_ACCEPT");
        }
        (a, e) => {
            panic!("SERVICE_ACCEPT disagreement on {payload:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

/// The whole `EXT_INFO` surface on one payload: header, lazy pairs,
/// `validate` for every limit, `server_sig_algs`, `classify_extension`.
fn check_ext_info_raw(payload: &[u8]) {
    let want_header = kref::ext_info_header(payload);
    let got = ExtInfo::decode(payload);
    match (got, want_header) {
        (Err(a), Err(e)) => assert_eq!(a, e, "EXT_INFO header error for {payload:?}"),
        (Ok(ext), Ok(h)) => {
            assert_eq!(ext.claimed_count(), h.claimed, "claimed_count");
            // Lazy iteration: exactly the reference sequence, fused after
            // the first error.
            let got_pairs: Vec<_> = ext.extensions().collect();
            let want_pairs = kref::ext_info_pairs(payload, &h);
            assert_eq!(got_pairs, want_pairs, "extensions() for {payload:?}");
            let mut it = ext.extensions();
            let (lo, hi) = it.size_hint();
            assert_eq!(lo, 0);
            assert_eq!(
                hi,
                Some(h.count),
                "size_hint upper bound is the bounded count"
            );
            for _ in 0..want_pairs.len() {
                it.next();
            }
            assert!(
                it.next().is_none(),
                "fused after the claimed pairs or the first error"
            );
            assert!(it.next().is_none());
            for (name, _) in got_pairs.iter().filter_map(|p| p.as_ref().ok()) {
                assert_eq!(
                    classify_extension(name),
                    kref::classify_extension(name),
                    "classify_extension({name:?})"
                );
            }
            for max in VALIDATE_MAXES {
                assert_eq!(
                    ext.validate(max),
                    kref::ext_info_validate(payload, &h, max),
                    "validate({max}) for {payload:?}"
                );
            }
            let got_algs = ext
                .server_sig_algs()
                .map(|r| r.map(|list| list.iter().collect::<Vec<_>>()));
            assert_eq!(
                got_algs,
                kref::server_sig_algs(payload, &h),
                "server_sig_algs for {payload:?}"
            );
            // A validated message re-encodes byte for byte from its pairs.
            if ext.validate(usize::MAX).is_ok() {
                let pairs: Vec<(&[u8], &[u8])> = got_pairs
                    .iter()
                    .map(|p| *p.as_ref().expect("validated"))
                    .collect();
                check_reencode(payload, |out| encode_ext_info(&pairs, out), "EXT_INFO");
            }
        }
        (a, e) => panic!("EXT_INFO disagreement on {payload:?}:\n library {a:?}\n reference {e:?}"),
    }
}

/// `read_mpint` is `read_string` plus inspection: exact string errors, the
/// cursor unmoved on failure, and every inspection method against the rule.
fn check_mpint_raw(input: &[u8]) {
    let mut r = Reader::new(input);
    let mut c = tatami_fuzz_wire_core::cursor::RefCursor::new(input);
    match (r.read_mpint(), c.string()) {
        (Err(a), Err(e)) => {
            assert_eq!(a, e, "read_mpint error for {input:?}");
            assert_eq!(r.position(), 0, "cursor must not move on failure");
        }
        (Ok(m), Ok(body)) => {
            assert_eq!(r.position(), c.pos);
            check_mpint_body(m, body);
        }
        (a, e) => panic!("read_mpint disagreement on {input:?}:\n library {a:?}\n reference {e:?}"),
    }
}

fn check_mpint_body(m: tatami_wire::Mpint<'_>, body: &[u8]) {
    assert_eq!(m.as_bytes(), body, "as_bytes is the raw body");
    assert_eq!(
        m.is_zero(),
        body.is_empty(),
        "is_zero is about the encoding"
    );
    assert_eq!(
        m.is_negative(),
        mpint_ref::is_negative(body),
        "is_negative({body:?})"
    );
    assert_eq!(
        m.is_canonical(),
        mpint_ref::is_canonical(body),
        "is_canonical({body:?})"
    );
    assert_eq!(
        m.positive_magnitude(),
        mpint_ref::positive_magnitude(body),
        "positive_magnitude({body:?})"
    );
    // Writing the magnitude back reproduces the body exactly iff the body was
    // the canonical encoding of a non-negative value.
    if let Some(mag) = m.positive_magnitude() {
        let mut buf = vec![0u8; 4 + mag.len() + 1];
        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(mag).expect("buffer sized");
        let written = w.written();
        assert_eq!(written, mpint_ref::positive_encoding(mag));
        let round = Reader::new(written)
            .read_mpint()
            .expect("written mpint reads back");
        assert!(
            round.is_canonical(),
            "the writer always produces canonical output"
        );
        assert_eq!(
            round.positive_magnitude(),
            Some(mag),
            "magnitude survives the round trip"
        );
        assert_eq!(
            round.as_bytes() == body,
            m.is_canonical(),
            "body {body:?} reproduces iff canonical"
        );
    } else {
        assert!(m.is_negative());
        assert!(!body.is_empty());
    }
}

fn run_raw(payload: &[u8]) {
    check_ecdh_init_raw(payload);
    check_ecdh_reply_raw(payload);
    check_newkeys_raw(payload);
    check_service_request_raw(payload);
    check_service_accept_raw(payload);
    check_ext_info_raw(payload);
    check_mpint_raw(payload);

    match payload.first() {
        None => {
            for n in ALL_NUMBERS {
                assert_eq!(decoder_for(n, payload), Err(MessageError::Empty));
            }
        }
        Some(&found) => {
            for expected in ALL_NUMBERS {
                if expected != found {
                    assert_eq!(
                        decoder_for(expected, payload),
                        Err(MessageError::UnexpectedMessage { expected, found }),
                        "decoder {expected} must reject number {found}"
                    );
                }
            }
        }
    }
}

const ALL_NUMBERS: [u8; 6] = [
    kref::KEX_ECDH_INIT,
    kref::KEX_ECDH_REPLY,
    kref::NEWKEYS,
    kref::SERVICE_REQUEST,
    kref::SERVICE_ACCEPT,
    kref::EXT_INFO,
];

fn decoder_for(n: u8, p: &[u8]) -> Result<(), MessageError> {
    match n {
        kref::KEX_ECDH_INIT => KexEcdhInit::decode(p).map(drop),
        kref::KEX_ECDH_REPLY => KexEcdhReply::decode(p).map(drop),
        kref::NEWKEYS => NewKeys::decode(p).map(drop),
        kref::SERVICE_REQUEST => ServiceRequest::decode(p).map(drop),
        kref::SERVICE_ACCEPT => ServiceAccept::decode(p).map(drop),
        kref::EXT_INFO => ExtInfo::decode(p).map(drop),
        _ => unreachable!("harness only dispatches known numbers"),
    }
}

// ---------------------------------------------------------------------------
// Structured path.
// ---------------------------------------------------------------------------

const MAX_FIELD: usize = 200;
const MAX_MAGNITUDE: usize = 48;

/// Mutations shared by the fixed-layout messages: the pristine bytes decode;
/// a strict prefix never decodes; a flipped message number is
/// `UnexpectedMessage`; appended bytes are `TrailingBytes { count }`.
fn mutate_fixed(u: &mut Unstructured<'_>, hand: &[u8]) {
    run_raw(hand);
    assert!(
        decoder_for(hand[0], hand).is_ok(),
        "hand-assembled bytes must decode"
    );
    match generate::byte(u) % 4 {
        0 => {}
        1 => {
            let keep =
                generate::small(u, u16::try_from(hand.len()).unwrap_or(u16::MAX)).min(hand.len());
            let cut = &hand[..keep];
            run_raw(cut);
            if cut.len() < hand.len() {
                assert!(
                    decoder_for(hand[0], cut).is_err(),
                    "truncated fixed-layout message must not decode: {cut:?}"
                );
            }
        }
        2 => {
            let idx = generate::small(u, u16::try_from(hand.len() - 1).unwrap_or(u16::MAX))
                .min(hand.len() - 1);
            let mut flipped = hand.to_vec();
            flipped[idx] ^= generate::byte(u) | 1;
            run_raw(&flipped);
            if idx == 0 {
                assert!(matches!(
                    decoder_for(hand[0], &flipped),
                    Err(MessageError::UnexpectedMessage { .. })
                ));
            }
        }
        _ => {
            let extra = generate::bounded_bytes(u, 8);
            let extra = if extra.is_empty() { vec![0u8] } else { extra };
            let mut appended = hand.to_vec();
            appended.extend_from_slice(&extra);
            run_raw(&appended);
            assert_eq!(
                decoder_for(hand[0], &appended),
                Err(MessageError::TrailingBytes { count: extra.len() }),
                "appended bytes must be reported as trailing"
            );
        }
    }
}

fn structured_mpint_write(u: &mut Unstructured<'_>) {
    // Magnitude with fuzz-chosen leading zeros so stripping is exercised.
    let zeros = generate::small(u, 4);
    let mut magnitude = vec![0u8; zeros];
    magnitude.extend(generate::bounded_bytes(u, MAX_MAGNITUDE));
    if generate::byte(u) & 1 == 1 && !magnitude.is_empty() {
        // Force the high-bit case half the time.
        let i = zeros.min(magnitude.len() - 1);
        magnitude[i] |= 0x80;
    }
    let want = mpint_ref::positive_encoding(&magnitude);
    assert_eq!(
        mpint_positive_len(&magnitude),
        want.len(),
        "mpint_positive_len({magnitude:?})"
    );

    let mut buf = vec![0xEEu8; want.len()];
    let mut w = Writer::new(&mut buf);
    assert_eq!(w.write_mpint_positive(&magnitude), Ok(()));
    assert_eq!(w.position(), want.len());
    assert_eq!(
        w.written(),
        &want[..],
        "write_mpint_positive({magnitude:?})"
    );

    // Atomic on a buffer one byte short.
    let mut short = vec![0xEEu8; want.len() - 1];
    let mut w = Writer::new(&mut short);
    assert_eq!(
        w.write_mpint_positive(&magnitude),
        Err(EncodeError::InsufficientCapacity {
            needed: want.len(),
            available: want.len() - 1,
        })
    );
    assert_eq!(w.position(), 0, "nothing written on capacity failure");
    assert!(
        short.iter().all(|&b| b == 0xEE),
        "buffer untouched on capacity failure"
    );

    // Read back: canonical, non-negative, magnitude preserved modulo zeros.
    let mut r = Reader::new(&want);
    let m = r.read_mpint().expect("written mpint reads");
    assert!(r.is_empty());
    assert!(m.is_canonical());
    assert!(!m.is_negative());
    let stripped = mpint_ref::strip_zeros(&magnitude);
    assert_eq!(m.positive_magnitude(), Some(stripped));
    assert_eq!(m.is_zero(), stripped.is_empty());
    check_mpint_body(m, &want[4..]);

    // Every RFC 4251 example: decode, inspect, and (positive ones) re-encode.
    for (encoding, label) in mpint_ref::RFC4251_EXAMPLES {
        let mut r = Reader::new(encoding);
        let m = r
            .read_mpint()
            .unwrap_or_else(|e| panic!("RFC example {label}: {e:?}"));
        assert!(r.is_empty(), "RFC example {label} consumed exactly");
        assert!(m.is_canonical(), "RFC example {label} is canonical");
        assert_eq!(
            m.is_negative(),
            label.starts_with('-'),
            "RFC example {label} sign"
        );
        assert_eq!(m.is_zero(), label == "0");
        check_mpint_body(m, &encoding[4..]);
        if let Some(mag) = m.positive_magnitude() {
            let mut buf = vec![0u8; encoding.len()];
            let mut w = Writer::new(&mut buf);
            w.write_mpint_positive(mag).expect("fits");
            assert_eq!(w.written(), encoding, "RFC example {label} re-encodes");
        }
    }
    run_raw(&want);
}

fn structured_mpint_body(u: &mut Unstructured<'_>) {
    let body = generate::bounded_bytes(u, MAX_MAGNITUDE);
    let mut encoded = Vec::new();
    put_string(&mut encoded, &body);
    let mut r = Reader::new(&encoded);
    let m = r.read_mpint().expect("well-formed string");
    assert!(r.is_empty());
    check_mpint_body(m, &body);
    run_raw(&encoded);
}

fn structured_ecdh_init(u: &mut Unstructured<'_>) {
    let q_c = if generate::byte(u) & 1 == 1 {
        generate::bounded_bytes(u, MAX_FIELD)
    } else {
        // The X25519 length the driver expects.
        let mut v = generate::bounded_bytes(u, 32);
        v.resize(32, 0x42);
        v
    };
    let mut hand = Vec::new();
    put_u8(&mut hand, kref::KEX_ECDH_INIT);
    put_string(&mut hand, &q_c);
    let m = KexEcdhInit {
        client_ephemeral: &q_c,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(out, hand, "KEX_ECDH_INIT encode differs from hand assembly");
    assert_eq!(KexEcdhInit::decode(&hand), Ok(m));
    mutate_fixed(u, &hand);
}

fn structured_ecdh_reply(u: &mut Unstructured<'_>) {
    let k_s = generate::bounded_bytes(u, MAX_FIELD);
    let q_s = generate::bounded_bytes(u, 64);
    let signature = generate::bounded_bytes(u, MAX_FIELD);
    let mut hand = Vec::new();
    put_u8(&mut hand, kref::KEX_ECDH_REPLY);
    put_string(&mut hand, &k_s);
    put_string(&mut hand, &q_s);
    put_string(&mut hand, &signature);
    let m = KexEcdhReply {
        host_key_blob: &k_s,
        server_ephemeral: &q_s,
        signature_blob: &signature,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(
        out, hand,
        "KEX_ECDH_REPLY encode differs from hand assembly"
    );
    let d = KexEcdhReply::decode(&hand).expect("hand-assembled reply decodes");
    assert_eq!(d, m);
    // Field offsets: K_S at 1, Q_S after it, signature after that; a cut
    // inside each field names that field at its offset.
    let q_s_off = 1 + 4 + k_s.len();
    let sig_off = q_s_off + 4 + q_s.len();
    for (cut, field, offset) in [
        (3usize, "K_S", 1usize),
        (q_s_off + 2, "Q_S", q_s_off),
        (sig_off + 3, "signature", sig_off),
    ] {
        match KexEcdhReply::decode(&hand[..cut]) {
            Err(MessageError::Field {
                field: f,
                offset: o,
                ..
            }) => {
                assert_eq!(f, field, "cut at {cut}");
                assert_eq!(o, offset, "cut at {cut}");
            }
            other => panic!("cut at {cut}: {other:?}"),
        }
    }
    mutate_fixed(u, &hand);
}

fn structured_newkeys(u: &mut Unstructured<'_>) {
    let hand = vec![kref::NEWKEYS];
    let mut out = [0xEEu8; 1];
    assert_eq!(NewKeys.encode(&mut out), Ok(1));
    assert_eq!(out, [kref::NEWKEYS]);
    assert_eq!(NewKeys::decode(&hand), Ok(NewKeys));
    let default_newkeys: NewKeys = Default::default();
    assert_eq!(default_newkeys, NewKeys);
    assert_eq!(
        NewKeys.encode(&mut []),
        Err(EncodeError::InsufficientCapacity {
            needed: 1,
            available: 0
        })
    );
    mutate_fixed(u, &hand);
}

const SERVICES: [&[u8]; 4] = [b"ssh-userauth", b"ssh-connection", b"", b"x@example"];

fn gen_service(u: &mut Unstructured<'_>) -> Vec<u8> {
    let sel = generate::byte(u);
    if sel < 0xC0 {
        SERVICES[usize::from(sel) % SERVICES.len()].to_vec()
    } else {
        generate::bounded_bytes(u, MAX_FIELD)
    }
}

fn structured_service(u: &mut Unstructured<'_>, accept: bool) {
    let name = gen_service(u);
    let number = if accept {
        kref::SERVICE_ACCEPT
    } else {
        kref::SERVICE_REQUEST
    };
    let mut hand = Vec::new();
    put_u8(&mut hand, number);
    put_string(&mut hand, &name);
    let mut out = vec![0u8; hand.len()];
    if accept {
        let m = ServiceAccept {
            service_name: &name,
        };
        assert_eq!(m.encode(&mut out), Ok(hand.len()));
        assert_eq!(ServiceAccept::decode(&hand), Ok(m));
    } else {
        let m = ServiceRequest {
            service_name: &name,
        };
        assert_eq!(m.encode(&mut out), Ok(hand.len()));
        assert_eq!(ServiceRequest::decode(&hand), Ok(m));
    }
    assert_eq!(
        out, hand,
        "service message encode differs from hand assembly"
    );
    // The two service messages differ only in number.
    let mut swapped = hand.clone();
    swapped[0] = if accept {
        kref::SERVICE_REQUEST
    } else {
        kref::SERVICE_ACCEPT
    };
    assert_eq!(
        decoder_for(number, &swapped),
        Err(MessageError::UnexpectedMessage {
            expected: number,
            found: swapped[0]
        })
    );
    assert!(decoder_for(swapped[0], &swapped).is_ok());
    mutate_fixed(u, &hand);
}

const EXT_NAMES: [&[u8]; 8] = [
    b"server-sig-algs",
    b"delay-compression",
    b"no-flow-control",
    b"elevation",
    b"publickey-hostbound@openssh.com",
    b"ping@openssh.com",
    b"",
    b"server-sig-algs ",
];

const SIG_ALG_LISTS: [&[u8]; 6] = [
    b"ssh-ed25519",
    b"ssh-ed25519,rsa-sha2-512,rsa-sha2-256",
    b"",
    b"a,,b",
    b"ok,bad name",
    b"ssh-ed25519,",
];

fn gen_ext_pair(u: &mut Unstructured<'_>) -> (Vec<u8>, Vec<u8>) {
    let sel = generate::byte(u);
    let name = if sel < 0xC0 {
        EXT_NAMES[usize::from(sel) % EXT_NAMES.len()].to_vec()
    } else {
        generate::bounded_bytes(u, 40)
    };
    let value = if name == b"server-sig-algs" && generate::byte(u) & 1 == 1 {
        SIG_ALG_LISTS[usize::from(generate::byte(u)) % SIG_ALG_LISTS.len()].to_vec()
    } else {
        generate::bounded_bytes(u, 64)
    };
    (name, value)
}

fn structured_ext_info(u: &mut Unstructured<'_>) {
    let count = generate::small(u, 8);
    let pairs: Vec<(Vec<u8>, Vec<u8>)> = (0..count).map(|_| gen_ext_pair(u)).collect();
    let hand = kref::assemble_ext_info(&pairs);
    let borrowed: Vec<(&[u8], &[u8])> = pairs
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    let mut out = vec![0u8; hand.len()];
    assert_eq!(encode_ext_info(&borrowed, &mut out), Ok(hand.len()));
    assert_eq!(out, hand, "encode_ext_info differs from hand assembly");
    let mut short = vec![0u8; hand.len() - 1];
    assert!(matches!(
        encode_ext_info(&borrowed, &mut short),
        Err(EncodeError::InsufficientCapacity { .. })
    ));

    let ext = ExtInfo::decode(&hand).expect("hand-assembled EXT_INFO decodes");
    assert_eq!(ext.claimed_count() as usize, count);
    let got: Vec<(&[u8], &[u8])> = ext
        .extensions()
        .map(|p| p.expect("well-formed pair"))
        .collect();
    assert_eq!(
        got, borrowed,
        "extensions() yields the generated pairs in order"
    );
    for max in VALIDATE_MAXES {
        let want = if count > max {
            Err(ExtInfoError::TooManyExtensions {
                claimed: count as u32,
                max,
            })
        } else {
            Ok(count)
        };
        assert_eq!(
            ext.validate(max),
            want,
            "validate({max}) with {count} pairs"
        );
    }
    // server-sig-algs: the first such pair decides; validity by the
    // name-list grammar.
    let want_algs = pairs
        .iter()
        .find(|(n, _)| n == b"server-sig-algs")
        .map(|(_, v)| {
            tatami_fuzz_wire_core::namelist_ref::parse(v)
                .map_err(ExtInfoError::InvalidServerSigAlgs)
        });
    let got_algs = ext
        .server_sig_algs()
        .map(|r| r.map(|l| l.iter().collect::<Vec<_>>()));
    assert_eq!(got_algs, want_algs, "server_sig_algs");
    for (name, _) in &pairs {
        let want = match name.as_slice() {
            b"server-sig-algs" => Some(KnownExtension::ServerSigAlgs),
            b"delay-compression" => Some(KnownExtension::DelayCompression),
            b"no-flow-control" => Some(KnownExtension::NoFlowControl),
            b"elevation" => Some(KnownExtension::Elevation),
            _ => None,
        };
        assert_eq!(
            classify_extension(name),
            want,
            "classify_extension({name:?})"
        );
    }
    run_raw(&hand);

    // Count one higher than the pairs present: either the header rejects
    // it (cannot fit) or validate reports the mismatch at the boundary.
    let mut over = hand.clone();
    let claimed = count as u32 + 1;
    over[1..5].copy_from_slice(&claimed.to_be_bytes());
    let body_len = hand.len() - 5;
    match ExtInfo::decode(&over) {
        Err(e) => {
            assert!(
                claimed as usize > body_len / 8,
                "header rejection only when the count cannot fit"
            );
            assert_eq!(
                e,
                MessageError::Field {
                    field: "nr-extensions",
                    offset: 1,
                    error: DecodeError::LengthOverflow {
                        claimed,
                        available: body_len
                    },
                }
            );
        }
        Ok(ext) => {
            assert!(claimed as usize <= body_len / 8);
            assert_eq!(
                ext.validate(64),
                Err(ExtInfoError::CountMismatch {
                    claimed,
                    found: count
                }),
                "count+1 must be a mismatch at the pair boundary"
            );
            // Lazy iteration yields the `count` real pairs, then exactly one
            // error for the missing pair (a truncated name at end of input),
            // then nothing.
            let items: Vec<_> = ext.extensions().collect();
            assert_eq!(items.len(), count + 1, "pairs then one error item");
            for (item, want) in items.iter().zip(&borrowed) {
                assert_eq!(item.as_ref().ok(), Some(want));
            }
            assert_eq!(
                items[count],
                Err(MessageError::Field {
                    field: "extension-name",
                    offset: hand.len(),
                    error: DecodeError::Truncated {
                        needed: 4,
                        available: 0
                    },
                }),
                "the missing pair is reported once at end of input"
            );
        }
    }
    run_raw(&over);

    // A huge count with only twelve bytes present fails before iteration.
    let mut huge = vec![kref::EXT_INFO];
    huge.extend_from_slice(&generate::word(u).max(2).to_be_bytes());
    huge.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(huge.len(), 12);
    let claimed = u32::from_be_bytes([huge[1], huge[2], huge[3], huge[4]]);
    assert_eq!(
        ExtInfo::decode(&huge).map(|e| e.claimed_count()),
        Err(MessageError::Field {
            field: "nr-extensions",
            offset: 1,
            error: DecodeError::LengthOverflow {
                claimed,
                available: 7
            },
        }),
        "count {claimed} cannot fit in 7 bytes"
    );
    run_raw(&huge);

    // Trailing byte after the last pair: header fine, validate rejects.
    let mut trailing = hand.clone();
    trailing.push(generate::byte(u));
    let ext = ExtInfo::decode(&trailing).expect("header still decodes");
    assert_eq!(
        ext.validate(64),
        Err(ExtInfoError::Message(MessageError::TrailingBytes {
            count: 1
        }))
    );
    let got: Vec<_> = ext
        .extensions()
        .map(|p| p.expect("pairs unaffected"))
        .collect();
    assert_eq!(got, borrowed, "lazy iteration ignores trailing bytes");
    run_raw(&trailing);

    // Truncation inside the pairs.
    if count > 0 {
        let cut = 5 + generate::small(u, u16::try_from(body_len).unwrap_or(u16::MAX))
            .min(body_len.saturating_sub(1));
        run_raw(&hand[..cut]);
        if let Ok(ext) = ExtInfo::decode(&hand[..cut]) {
            assert!(
                ext.validate(64).is_err(),
                "a truncated pair list cannot validate"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    message_numbers_agree();
    let Some((&sel, rest)) = data.split_first() else {
        run_raw(&[]);
        return;
    };
    if sel < 0x80 {
        run_raw(rest);
        return;
    }
    let mut u = Unstructured::new(rest);
    match sel & 7 {
        0 => structured_mpint_write(&mut u),
        1 => structured_ecdh_init(&mut u),
        2 => structured_ecdh_reply(&mut u),
        3 => structured_newkeys(&mut u),
        4 => structured_service(&mut u, false),
        5 => structured_service(&mut u, true),
        6 => structured_ext_info(&mut u),
        _ => structured_mpint_body(&mut u),
    }
});
