#![no_main]
//! Message codecs (KEXINIT, DISCONNECT, IGNORE, UNIMPLEMENTED, DEBUG,
//! CHANNEL_OPEN, CHANNEL_OPEN_CONFIRMATION, CHANNEL_OPEN_FAILURE) against
//! independent reference layouts.
//!
//! Input layout: `sel:u8, rest...`.
//! - `sel < 0x80`: RAW path. `rest` is a payload and is fed to ALL eight
//!   production decoders; each must agree with its reference decoder on
//!   success/failure, the exact `MessageError` (including `Empty`,
//!   `UnexpectedMessage{expected,found}`, `Field{field,offset,error}` and
//!   `TrailingBytes{count}`), and every field value. Successful decodes are
//!   re-encoded and must reproduce the payload (booleans canonicalised).
//! - `sel >= 0x80`: STRUCTURED path. `sel % 8` picks a message; a bounded
//!   harness-local value is generated from `rest`, its bytes are assembled BY
//!   HAND (big-endian lengths, comma-joined lists), the production `encode`
//!   must produce exactly those bytes, `decode` of them must return the
//!   generated fields, and then an optional mutation (truncate / flip /
//!   append) is applied and the raw path is run on the result with the
//!   additional expectations that follow from the layout (truncation of a
//!   fixed-layout message fails, appended bytes are `TrailingBytes{count}`
//!   for fixed-layout messages and extend the tail of OPEN/CONFIRMATION).
//!
//! KEXINIT extras: cookie is exactly 16 bytes at offset 1; the ten struct
//! fields map to their own wire slots (lists are generated distinct per
//! slot); `reserved` preserved even if nonzero; `first_kex_packet_follows`
//! true for any nonzero byte; `empty_algorithm_lists()` names exactly the
//! empty required lists (never languages); `classify_kex_name` marks only
//! the six exact marker names (`ext-info-c/s`, `kex-strict-c/s-v00@openssh.com`,
//! `kex-strict-c/s`); unknown names/codes preserved verbatim and
//! `disconnect_reason::name` / `open_failure_reason::name` know exactly the
//! registered codes.

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use tatami_fuzz_wire_core::bytes::{put_bool, put_string, put_u8, put_u32};
use tatami_fuzz_wire_core::generate;
use tatami_fuzz_wire_core::messages_ref as mref;
use tatami_fuzz_wire_core::namelist_ref;
use tatami_wire::channel::{
    ChannelOpen, ChannelOpenConfirmation, ChannelOpenFailure, open_failure_reason,
};
use tatami_wire::kexinit::{ALGORITHM_LIST_NAMES, COOKIE_LEN, KexInit, KexName, classify_kex_name};
use tatami_wire::transport::{Debug, Disconnect, Ignore, Unimplemented, disconnect_reason};
use tatami_wire::{EncodeError, MessageError, NameList, msg};

// ---------------------------------------------------------------------------
// Raw path: production decoder vs reference decoder on arbitrary bytes.
// ---------------------------------------------------------------------------

fn message_numbers_agree() {
    assert_eq!(msg::DISCONNECT, mref::DISCONNECT);
    assert_eq!(msg::IGNORE, mref::IGNORE);
    assert_eq!(msg::UNIMPLEMENTED, mref::UNIMPLEMENTED);
    assert_eq!(msg::DEBUG, mref::DEBUG);
    assert_eq!(msg::KEXINIT, mref::KEXINIT);
    assert_eq!(msg::CHANNEL_OPEN, mref::CHANNEL_OPEN);
    assert_eq!(
        msg::CHANNEL_OPEN_CONFIRMATION,
        mref::CHANNEL_OPEN_CONFIRMATION
    );
    assert_eq!(msg::CHANNEL_OPEN_FAILURE, mref::CHANNEL_OPEN_FAILURE);
    assert_eq!(COOKIE_LEN, mref::COOKIE_LEN);
    assert_eq!(
        &ALGORITHM_LIST_NAMES[..],
        &mref::KEXINIT_LIST_FIELDS[..mref::REQUIRED_LIST_COUNT]
    );
}

fn expected_kex_name(name: &[u8]) -> KexName {
    if name == mref::KEX_MARKERS[0] {
        KexName::ExtInfoClient
    } else if name == mref::KEX_MARKERS[1] {
        KexName::ExtInfoServer
    } else if name == mref::KEX_MARKERS[2] || name == mref::KEX_MARKERS[4] {
        // `kex-strict-c-v00@openssh.com` and the standard `kex-strict-c`.
        KexName::StrictKexClient
    } else if name == mref::KEX_MARKERS[3] || name == mref::KEX_MARKERS[5] {
        // `kex-strict-s-v00@openssh.com` and the standard `kex-strict-s`.
        KexName::StrictKexServer
    } else {
        KexName::Method
    }
}

fn check_names(list: NameList<'_>, body: &[u8], names: &[&[u8]], what: &str) {
    assert_eq!(list.as_bytes(), body, "{what}: body");
    let got: Vec<&[u8]> = list.iter().collect();
    assert_eq!(got, names, "{what}: names");
    assert_eq!(list.len(), names.len(), "{what}: len");
    assert_eq!(namelist_ref::join(&got), body, "{what}: re-join");
    for n in names {
        assert!(list.contains(n), "{what}: contains({n:?})");
        let k = classify_kex_name(n);
        assert_eq!(k, expected_kex_name(n), "classify_kex_name({n:?})");
        assert_eq!(
            k.is_marker(),
            mref::KEX_MARKERS.contains(n),
            "is_marker({n:?})"
        );
    }
}

/// Re-encoding a decoded message must reproduce the payload, except that
/// boolean bytes are canonicalised to 0/1 at `bool_offset`.
fn check_reencode(
    payload: &[u8],
    bool_offset: Option<usize>,
    encode: impl Fn(&mut [u8]) -> Result<usize, EncodeError>,
    what: &str,
) {
    let mut expected = payload.to_vec();
    if let Some(i) = bool_offset {
        expected[i] = u8::from(payload[i] != 0);
    }
    let mut out = vec![0xEEu8; payload.len()];
    assert_eq!(
        encode(&mut out),
        Ok(payload.len()),
        "{what}: re-encode length"
    );
    assert_eq!(out, expected, "{what}: re-encode bytes");
    if !payload.is_empty() {
        let mut short = vec![0u8; payload.len() - 1];
        assert!(
            matches!(
                encode(&mut short),
                Err(EncodeError::InsufficientCapacity { .. })
            ),
            "{what}: encode into a short buffer must report capacity"
        );
    }
}

fn check_kexinit_raw(payload: &[u8]) {
    let got = KexInit::decode(payload);
    let want = mref::kexinit(payload);
    match (got, want) {
        (Err(a), Err(e)) => assert_eq!(a, e, "KEXINIT error for {payload:?}"),
        (Ok(k), Ok(r)) => {
            assert_eq!(k.cookie.len(), 16);
            assert_eq!(&k.cookie[..], r.cookie, "cookie");
            assert_eq!(&k.cookie[..], &payload[1..17], "cookie offset");
            let slots: [NameList<'_>; 10] = [
                k.kex_algorithms,
                k.server_host_key_algorithms,
                k.encryption_client_to_server,
                k.encryption_server_to_client,
                k.mac_client_to_server,
                k.mac_server_to_client,
                k.compression_client_to_server,
                k.compression_server_to_client,
                k.languages_client_to_server,
                k.languages_server_to_client,
            ];
            assert_eq!(k.name_lists(), slots, "name_lists() must follow wire order");
            for (i, list) in slots.iter().enumerate() {
                check_names(*list, r.lists[i], &r.names[i], mref::KEXINIT_LIST_FIELDS[i]);
            }
            assert_eq!(
                k.first_kex_packet_follows,
                r.first_kex_packet_follows_byte != 0,
                "first_kex_packet_follows"
            );
            assert_eq!(k.reserved, r.reserved, "reserved");
            let empties: Vec<&str> = k.empty_algorithm_lists().collect();
            let want_empties: Vec<&str> = (0..mref::REQUIRED_LIST_COUNT)
                .filter(|&i| r.lists[i].is_empty())
                .map(|i| mref::KEXINIT_LIST_FIELDS[i])
                .collect();
            assert_eq!(empties, want_empties, "empty_algorithm_lists");
            check_reencode(
                payload,
                Some(r.first_kex_packet_follows_offset),
                |out| k.encode(out),
                "KEXINIT",
            );
        }
        (a, e) => panic!("KEXINIT disagreement on {payload:?}:\n library {a:?}\n reference {e:?}"),
    }
}

fn check_disconnect_raw(payload: &[u8]) {
    let got = Disconnect::decode(payload);
    let want = mref::disconnect(payload);
    match (got, want) {
        (Err(a), Err(e)) => assert_eq!(a, e, "DISCONNECT error for {payload:?}"),
        (Ok(d), Ok(r)) => {
            assert_eq!(d.reason_code, r.reason_code);
            assert_eq!(d.description, r.description);
            assert_eq!(d.language_tag, r.language_tag);
            check_disconnect_name(d.reason_code);
            check_reencode(payload, None, |out| d.encode(out), "DISCONNECT");
        }
        (a, e) => {
            panic!("DISCONNECT disagreement on {payload:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_disconnect_name(code: u32) {
    let want = mref::DISCONNECT_REASONS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| *n);
    assert_eq!(
        disconnect_reason::name(code),
        want,
        "disconnect_reason::name({code})"
    );
}

fn check_open_failure_name(code: u32) {
    let want = mref::OPEN_FAILURE_REASONS
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| *n);
    assert_eq!(
        open_failure_reason::name(code),
        want,
        "open_failure_reason::name({code})"
    );
}

fn check_ignore_raw(payload: &[u8]) {
    let got = Ignore::decode(payload);
    let want = mref::ignore(payload);
    match (got, want) {
        (Err(a), Err(e)) => assert_eq!(a, e, "IGNORE error for {payload:?}"),
        (Ok(i), Ok(data)) => {
            assert_eq!(i.data, data);
            check_reencode(payload, None, |out| i.encode(out), "IGNORE");
        }
        (a, e) => panic!("IGNORE disagreement on {payload:?}:\n library {a:?}\n reference {e:?}"),
    }
}

fn check_unimplemented_raw(payload: &[u8]) {
    let got = Unimplemented::decode(payload);
    let want = mref::unimplemented(payload);
    match (got, want) {
        (Err(a), Err(e)) => assert_eq!(a, e, "UNIMPLEMENTED error for {payload:?}"),
        (Ok(u), Ok(seq)) => {
            assert_eq!(u.sequence_number, seq);
            check_reencode(payload, None, |out| u.encode(out), "UNIMPLEMENTED");
        }
        (a, e) => {
            panic!("UNIMPLEMENTED disagreement on {payload:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_debug_raw(payload: &[u8]) {
    let got = Debug::decode(payload);
    let want = mref::debug(payload);
    match (got, want) {
        (Err(a), Err(e)) => assert_eq!(a, e, "DEBUG error for {payload:?}"),
        (Ok(d), Ok(r)) => {
            assert_eq!(d.always_display, r.always_display_byte != 0);
            assert_eq!(d.message, r.message);
            assert_eq!(d.language_tag, r.language_tag);
            check_reencode(payload, Some(1), |out| d.encode(out), "DEBUG");
        }
        (a, e) => panic!("DEBUG disagreement on {payload:?}:\n library {a:?}\n reference {e:?}"),
    }
}

fn check_open_raw(payload: &[u8]) {
    let got = ChannelOpen::decode(payload);
    let want = mref::channel_open(payload);
    match (got, want) {
        (Err(a), Err(e)) => {
            assert_eq!(a, e, "CHANNEL_OPEN error for {payload:?}");
            assert!(
                !matches!(a, MessageError::TrailingBytes { .. }),
                "CHANNEL_OPEN must never report trailing bytes"
            );
        }
        (Ok(o), Ok(r)) => {
            assert_eq!(o.channel_type, r.channel_type);
            assert_eq!(o.sender_channel, r.sender_channel);
            assert_eq!(o.initial_window_size, r.initial_window_size);
            assert_eq!(o.maximum_packet_size, r.maximum_packet_size);
            assert_eq!(o.type_specific, r.type_specific);
            let fixed = 1 + 4 + o.channel_type.len() + 12;
            assert_eq!(
                o.type_specific,
                &payload[fixed..],
                "tail must be the exact remainder"
            );
            check_reencode(payload, None, |out| o.encode(out), "CHANNEL_OPEN");
        }
        (a, e) => {
            panic!("CHANNEL_OPEN disagreement on {payload:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_confirmation_raw(payload: &[u8]) {
    let got = ChannelOpenConfirmation::decode(payload);
    let want = mref::channel_open_confirmation(payload);
    match (got, want) {
        (Err(a), Err(e)) => {
            assert_eq!(a, e, "CHANNEL_OPEN_CONFIRMATION error for {payload:?}");
            assert!(
                !matches!(a, MessageError::TrailingBytes { .. }),
                "CHANNEL_OPEN_CONFIRMATION must never report trailing bytes"
            );
        }
        (Ok(c), Ok(r)) => {
            assert_eq!(c.recipient_channel, r.recipient_channel);
            assert_eq!(c.sender_channel, r.sender_channel);
            assert_eq!(c.initial_window_size, r.initial_window_size);
            assert_eq!(c.maximum_packet_size, r.maximum_packet_size);
            assert_eq!(c.type_specific, r.type_specific);
            assert_eq!(
                c.type_specific,
                &payload[17..],
                "tail must be the exact remainder"
            );
            check_reencode(
                payload,
                None,
                |out| c.encode(out),
                "CHANNEL_OPEN_CONFIRMATION",
            );
        }
        (a, e) => panic!(
            "CHANNEL_OPEN_CONFIRMATION disagreement on {payload:?}:\n library {a:?}\n reference {e:?}"
        ),
    }
}

fn check_failure_raw(payload: &[u8]) {
    let got = ChannelOpenFailure::decode(payload);
    let want = mref::channel_open_failure(payload);
    match (got, want) {
        (Err(a), Err(e)) => assert_eq!(a, e, "CHANNEL_OPEN_FAILURE error for {payload:?}"),
        (Ok(f), Ok(r)) => {
            assert_eq!(f.recipient_channel, r.recipient_channel);
            assert_eq!(f.reason_code, r.reason_code);
            assert_eq!(f.description, r.description);
            assert_eq!(f.language_tag, r.language_tag);
            check_open_failure_name(f.reason_code);
            check_reencode(payload, None, |out| f.encode(out), "CHANNEL_OPEN_FAILURE");
        }
        (a, e) => panic!(
            "CHANNEL_OPEN_FAILURE disagreement on {payload:?}:\n library {a:?}\n reference {e:?}"
        ),
    }
}

fn run_raw(payload: &[u8]) {
    check_kexinit_raw(payload);
    check_disconnect_raw(payload);
    check_ignore_raw(payload);
    check_unimplemented_raw(payload);
    check_debug_raw(payload);
    check_open_raw(payload);
    check_confirmation_raw(payload);
    check_failure_raw(payload);

    // Message-number dispatch, stated explicitly: an empty payload is `Empty`
    // for every decoder, and every decoder whose number is not the leading
    // byte fails with exactly `UnexpectedMessage { expected, found }`.
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

const ALL_NUMBERS: [u8; 8] = [
    mref::KEXINIT,
    mref::DISCONNECT,
    mref::IGNORE,
    mref::UNIMPLEMENTED,
    mref::DEBUG,
    mref::CHANNEL_OPEN,
    mref::CHANNEL_OPEN_CONFIRMATION,
    mref::CHANNEL_OPEN_FAILURE,
];

// ---------------------------------------------------------------------------
// Structured path: generate, hand-assemble, encode, decode, mutate.
// ---------------------------------------------------------------------------

const MAX_TEXT: usize = 256;
const MAX_TAG: usize = 32;
const MAX_TAIL: usize = 256;
const MAX_LIST_NAMES: u16 = 6;
const MAX_NAME_LEN: usize = 20;

/// Whether a message has a fixed layout (rejects trailing bytes) or ends in
/// an opaque tail (OPEN, OPEN_CONFIRMATION).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    Fixed,
    Tail { fixed_len: usize },
}

/// Applies the optional mutation and runs the raw oracle plus the
/// layout-derived expectations on the result.
fn mutate_and_check(u: &mut Unstructured<'_>, hand: &[u8], layout: Layout) {
    // Run the eight decoders on the pristine hand-assembled bytes first.
    run_raw(hand);

    let decodes_ok = |p: &[u8]| -> bool { decoder_for(hand[0], p).is_ok() };
    assert!(decodes_ok(hand));

    match generate::byte(u) % 4 {
        0 => {}
        1 => {
            let keep = generate::small(u, u16::try_from(hand.len()).unwrap_or(u16::MAX));
            let cut = &hand[..keep.min(hand.len())];
            run_raw(cut);
            if cut.len() < hand.len() {
                match layout {
                    Layout::Fixed => assert!(
                        !decodes_ok(cut),
                        "truncated fixed-layout message must not decode: {cut:?}"
                    ),
                    Layout::Tail { fixed_len } => assert_eq!(
                        decodes_ok(cut),
                        cut.len() >= fixed_len,
                        "tail message truncated to {} (fixed {fixed_len})",
                        cut.len()
                    ),
                }
            }
        }
        2 => {
            if !hand.is_empty() {
                let idx = generate::small(u, u16::try_from(hand.len() - 1).unwrap_or(u16::MAX))
                    .min(hand.len() - 1);
                let xor = generate::byte(u) | 1;
                let mut flipped = hand.to_vec();
                flipped[idx] ^= xor;
                run_raw(&flipped);
                if idx == 0 {
                    assert!(
                        matches!(
                            decoder_for(hand[0], &flipped),
                            Err(MessageError::UnexpectedMessage { .. })
                        ),
                        "flipping the message number must be UnexpectedMessage"
                    );
                }
            }
        }
        _ => {
            let extra = generate::bounded_bytes(u, 8);
            let extra = if extra.is_empty() { vec![0u8] } else { extra };
            let mut appended = hand.to_vec();
            appended.extend_from_slice(&extra);
            run_raw(&appended);
            match layout {
                Layout::Fixed => assert_eq!(
                    decoder_for(hand[0], &appended),
                    Err(MessageError::TrailingBytes { count: extra.len() }),
                    "appended bytes must be reported as trailing"
                ),
                Layout::Tail { .. } => {
                    assert!(decodes_ok(&appended), "tail messages absorb appended bytes");
                    let tail = tail_of(hand[0], &appended).expect("decodes");
                    assert_eq!(
                        &tail[tail.len() - extra.len()..],
                        &extra[..],
                        "appended tail"
                    );
                }
            }
        }
    }
}

/// Success/failure of the production decoder for message number `n`.
fn decoder_for(n: u8, p: &[u8]) -> Result<(), MessageError> {
    match n {
        mref::KEXINIT => KexInit::decode(p).map(drop),
        mref::DISCONNECT => Disconnect::decode(p).map(drop),
        mref::IGNORE => Ignore::decode(p).map(drop),
        mref::UNIMPLEMENTED => Unimplemented::decode(p).map(drop),
        mref::DEBUG => Debug::decode(p).map(drop),
        mref::CHANNEL_OPEN => ChannelOpen::decode(p).map(drop),
        mref::CHANNEL_OPEN_CONFIRMATION => ChannelOpenConfirmation::decode(p).map(drop),
        mref::CHANNEL_OPEN_FAILURE => ChannelOpenFailure::decode(p).map(drop),
        _ => unreachable!("harness only generates known message numbers"),
    }
}

fn tail_of(n: u8, p: &[u8]) -> Option<&[u8]> {
    match n {
        mref::CHANNEL_OPEN => ChannelOpen::decode(p).ok().map(|o| o.type_specific),
        mref::CHANNEL_OPEN_CONFIRMATION => ChannelOpenConfirmation::decode(p)
            .ok()
            .map(|c| c.type_specific),
        _ => None,
    }
}

fn gen_code(u: &mut Unstructured<'_>, small_max: u16) -> u32 {
    if generate::byte(u) & 1 == 1 {
        generate::small(u, small_max) as u32
    } else {
        generate::word(u)
    }
}

fn structured_kexinit(u: &mut Unstructured<'_>) {
    let mut cookie = [0u8; 16];
    for b in &mut cookie {
        *b = generate::byte(u);
    }
    let marker_bits = generate::byte(u);
    let mut lists: Vec<Vec<Vec<u8>>> = Vec::with_capacity(10);
    for slot in 0..10u8 {
        let count = generate::small(u, MAX_LIST_NAMES);
        let mut names = Vec::with_capacity(count + 4);
        for _ in 0..count {
            let mut name = generate::valid_name(u, MAX_NAME_LEN);
            // Slot suffix makes every list distinct from every other slot.
            name.push(b'@');
            name.push(b'0' + slot);
            names.push(name);
        }
        if slot == 0 {
            for (i, marker) in mref::KEX_MARKERS.iter().enumerate() {
                if marker_bits & (1 << i) != 0 {
                    names.push(marker.to_vec());
                }
            }
        }
        lists.push(names);
    }
    let first = generate::byte(u) & 1 == 1;
    let reserved = if generate::byte(u) & 1 == 1 {
        0
    } else {
        generate::word(u)
    };

    // Hand assembly.
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::KEXINIT);
    hand.extend_from_slice(&cookie);
    for names in &lists {
        tatami_fuzz_wire_core::bytes::put_name_list(&mut hand, names);
    }
    put_bool(&mut hand, first);
    put_u32(&mut hand, reserved);

    // Production value and encoder.
    let bodies: Vec<Vec<u8>> = lists.iter().map(|n| namelist_ref::join(n)).collect();
    let parsed: Vec<NameList<'_>> = bodies
        .iter()
        .map(|b| NameList::parse(b).expect("generated names are valid"))
        .collect();
    let k = KexInit {
        cookie: &cookie,
        kex_algorithms: parsed[0],
        server_host_key_algorithms: parsed[1],
        encryption_client_to_server: parsed[2],
        encryption_server_to_client: parsed[3],
        mac_client_to_server: parsed[4],
        mac_server_to_client: parsed[5],
        compression_client_to_server: parsed[6],
        compression_server_to_client: parsed[7],
        languages_client_to_server: parsed[8],
        languages_server_to_client: parsed[9],
        first_kex_packet_follows: first,
        reserved,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(k.encode(&mut out), Ok(hand.len()), "KEXINIT encode length");
    assert_eq!(out, hand, "KEXINIT encode bytes differ from hand assembly");

    let d = KexInit::decode(&hand).expect("hand-assembled KEXINIT must decode");
    assert_eq!(d, k, "KEXINIT decode(encode(k)) != k");
    assert_eq!(d.cookie, &cookie);
    let expected_names: Vec<Vec<&[u8]>> = lists
        .iter()
        .map(|names| names.iter().map(|n| &n[..]).collect())
        .collect();
    let slots = [
        d.kex_algorithms,
        d.server_host_key_algorithms,
        d.encryption_client_to_server,
        d.encryption_server_to_client,
        d.mac_client_to_server,
        d.mac_server_to_client,
        d.compression_client_to_server,
        d.compression_server_to_client,
        d.languages_client_to_server,
        d.languages_server_to_client,
    ];
    for (i, slot) in slots.iter().enumerate() {
        check_names(
            *slot,
            &bodies[i],
            &expected_names[i],
            mref::KEXINIT_LIST_FIELDS[i],
        );
        // Directional pairs must not be swapped: a non-empty list from one
        // slot never equals another slot's list.
        for (j, other) in bodies.iter().enumerate() {
            if i != j && !bodies[i].is_empty() {
                assert_ne!(slot.as_bytes(), &other[..], "slot {i} equals slot {j}");
            }
        }
    }
    assert_eq!(d.first_kex_packet_follows, first);
    assert_eq!(d.reserved, reserved);
    let empties: Vec<&str> = d.empty_algorithm_lists().collect();
    let want: Vec<&str> = (0..mref::REQUIRED_LIST_COUNT)
        .filter(|&i| lists[i].is_empty())
        .map(|i| mref::KEXINIT_LIST_FIELDS[i])
        .collect();
    assert_eq!(empties, want);
    for name in d.kex_algorithms.iter() {
        assert_eq!(classify_kex_name(name), expected_kex_name(name));
    }

    mutate_and_check(u, &hand, Layout::Fixed);
}

fn structured_disconnect(u: &mut Unstructured<'_>) {
    let code = gen_code(u, 20);
    let description = generate::bounded_bytes(u, MAX_TEXT);
    let language_tag = generate::bounded_bytes(u, MAX_TAG);
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::DISCONNECT);
    put_u32(&mut hand, code);
    put_string(&mut hand, &description);
    put_string(&mut hand, &language_tag);

    let m = Disconnect {
        reason_code: code,
        description: &description,
        language_tag: &language_tag,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(
        out, hand,
        "DISCONNECT encode bytes differ from hand assembly"
    );
    assert_eq!(Disconnect::decode(&hand), Ok(m));
    check_disconnect_name(code);
    mutate_and_check(u, &hand, Layout::Fixed);
}

fn structured_ignore(u: &mut Unstructured<'_>) {
    let data = generate::bounded_bytes(u, MAX_TEXT * 2);
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::IGNORE);
    put_string(&mut hand, &data);
    let m = Ignore { data: &data };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(out, hand, "IGNORE encode bytes differ from hand assembly");
    assert_eq!(Ignore::decode(&hand), Ok(m));
    mutate_and_check(u, &hand, Layout::Fixed);
}

fn structured_unimplemented(u: &mut Unstructured<'_>) {
    let seq = generate::word(u);
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::UNIMPLEMENTED);
    put_u32(&mut hand, seq);
    let m = Unimplemented {
        sequence_number: seq,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(
        out, hand,
        "UNIMPLEMENTED encode bytes differ from hand assembly"
    );
    assert_eq!(Unimplemented::decode(&hand), Ok(m));
    mutate_and_check(u, &hand, Layout::Fixed);
}

fn structured_debug(u: &mut Unstructured<'_>) {
    let always_display = generate::byte(u) & 1 == 1;
    let message = generate::bounded_bytes(u, MAX_TEXT);
    let language_tag = generate::bounded_bytes(u, MAX_TAG);
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::DEBUG);
    put_bool(&mut hand, always_display);
    put_string(&mut hand, &message);
    put_string(&mut hand, &language_tag);
    let m = Debug {
        always_display,
        message: &message,
        language_tag: &language_tag,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(out, hand, "DEBUG encode bytes differ from hand assembly");
    assert_eq!(Debug::decode(&hand), Ok(m));
    mutate_and_check(u, &hand, Layout::Fixed);
}

const KNOWN_CHANNEL_TYPES: [&[u8]; 5] = [
    b"session",
    b"x11",
    b"forwarded-tcpip",
    b"direct-tcpip",
    b"x@example",
];

fn gen_channel_type(u: &mut Unstructured<'_>) -> Vec<u8> {
    match generate::byte(u) % 3 {
        0 => KNOWN_CHANNEL_TYPES[generate::small(u, 4)].to_vec(),
        1 => generate::valid_name(u, 64),
        _ => generate::bounded_bytes(u, 64),
    }
}

fn structured_open(u: &mut Unstructured<'_>) {
    let channel_type = gen_channel_type(u);
    let sender_channel = generate::word(u);
    let initial_window_size = generate::word(u);
    let maximum_packet_size = generate::word(u);
    let type_specific = generate::bounded_bytes(u, MAX_TAIL);
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::CHANNEL_OPEN);
    put_string(&mut hand, &channel_type);
    put_u32(&mut hand, sender_channel);
    put_u32(&mut hand, initial_window_size);
    put_u32(&mut hand, maximum_packet_size);
    let fixed_len = hand.len();
    hand.extend_from_slice(&type_specific);
    let m = ChannelOpen {
        channel_type: &channel_type,
        sender_channel,
        initial_window_size,
        maximum_packet_size,
        type_specific: &type_specific,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(
        out, hand,
        "CHANNEL_OPEN encode bytes differ from hand assembly"
    );
    assert_eq!(ChannelOpen::decode(&hand), Ok(m));
    mutate_and_check(u, &hand, Layout::Tail { fixed_len });
}

fn structured_confirmation(u: &mut Unstructured<'_>) {
    let recipient_channel = generate::word(u);
    let sender_channel = generate::word(u);
    let initial_window_size = generate::word(u);
    let maximum_packet_size = generate::word(u);
    let type_specific = generate::bounded_bytes(u, MAX_TAIL);
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::CHANNEL_OPEN_CONFIRMATION);
    put_u32(&mut hand, recipient_channel);
    put_u32(&mut hand, sender_channel);
    put_u32(&mut hand, initial_window_size);
    put_u32(&mut hand, maximum_packet_size);
    assert_eq!(hand.len(), 17);
    hand.extend_from_slice(&type_specific);
    let m = ChannelOpenConfirmation {
        recipient_channel,
        sender_channel,
        initial_window_size,
        maximum_packet_size,
        type_specific: &type_specific,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(
        out, hand,
        "CHANNEL_OPEN_CONFIRMATION encode bytes differ from hand assembly"
    );
    assert_eq!(ChannelOpenConfirmation::decode(&hand), Ok(m));
    mutate_and_check(u, &hand, Layout::Tail { fixed_len: 17 });
}

fn structured_failure(u: &mut Unstructured<'_>) {
    let recipient_channel = generate::word(u);
    let reason_code = gen_code(u, 8);
    let description = generate::bounded_bytes(u, MAX_TEXT);
    let language_tag = generate::bounded_bytes(u, MAX_TAG);
    let mut hand = Vec::new();
    put_u8(&mut hand, mref::CHANNEL_OPEN_FAILURE);
    put_u32(&mut hand, recipient_channel);
    put_u32(&mut hand, reason_code);
    put_string(&mut hand, &description);
    put_string(&mut hand, &language_tag);
    let m = ChannelOpenFailure {
        recipient_channel,
        reason_code,
        description: &description,
        language_tag: &language_tag,
    };
    let mut out = vec![0u8; hand.len()];
    assert_eq!(m.encode(&mut out), Ok(hand.len()));
    assert_eq!(
        out, hand,
        "CHANNEL_OPEN_FAILURE encode bytes differ from hand assembly"
    );
    assert_eq!(ChannelOpenFailure::decode(&hand), Ok(m));
    check_open_failure_name(reason_code);
    mutate_and_check(u, &hand, Layout::Fixed);
}

fuzz_target!(|data: &[u8]| {
    message_numbers_agree();
    let Some((&sel, rest)) = data.split_first() else {
        run_raw(&[]);
        return;
    };
    if sel < 0x80 {
        run_raw(rest);
    } else {
        let mut u = Unstructured::new(rest);
        match sel % 8 {
            0 => structured_kexinit(&mut u),
            1 => structured_disconnect(&mut u),
            2 => structured_ignore(&mut u),
            3 => structured_unimplemented(&mut u),
            4 => structured_debug(&mut u),
            5 => structured_open(&mut u),
            6 => structured_confirmation(&mut u),
            _ => structured_failure(&mut u),
        }
    }
});
