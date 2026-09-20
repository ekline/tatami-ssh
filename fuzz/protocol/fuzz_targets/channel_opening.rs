#![no_main]
//! `tatami_connection::opening::OpeningEngine` driven by a bounded action
//! sequence and checked after every action against an independent model
//! (`state_support::opening_model`) written from the module's documented
//! contract.
//!
//! # Input layout
//!
//! ```text
//! byte 0   limits: bit 7 set -> OpeningLimits::default(); otherwise
//!            bits 0-1 max_pending_outgoing = 1 + v
//!            bits 2-3 max_pending_incoming = 1 + v
//!            bits 4-6 max_channels         = 1 + v
//! byte 1   bits 0-1 max_tombstones = v (0..=3); other bits unused
//! rest     actions (at most 200); each starts with an opcode byte `op`
//!          selected by `op % 10`, followed by its arguments:
//!
//!   0 Open          [arg]            arg b0-1 type, b2-3 credit (3 -> +8 bytes)
//!   1 Cancel        [hsel]
//!   2 Accept        [hsel] [arg]     arg b0-1 credit (3 -> +8 bytes), b2-3 tail
//!                                    of type[v]
//!   3 Refuse        [hsel] [arg]     arg b0-2 reason (7 -> +4 bytes), b3-4
//!                                    description index
//!   4 PeerOpen      [arg] [n]        arg b0-1 type, b4-6 sender selector
//!                                    applied to n (7 -> 4 bytes replace n),
//!                                    then b2-3 credit (3 -> +8 bytes)
//!   5 PeerConfirm   [arg] [nr] [ns]  arg b0-2 recipient selector (nr),
//!                                    b3-5 sender selector (ns), then b6-7
//!                                    credit (3 -> +8); tail = type[ns & 3]
//!   6 PeerFail      [arg] [nr]       arg b0-2 recipient selector, then b3-5
//!                                    reason (7 -> +4), b6-7 description,
//!                                    b6 also selects language tag "en"
//!   7 TransportLost
//!   8 Drain         pop every queued outgoing message
//!   9 PopOne        pop one queued outgoing message
//!
//! type    0 "session" (no tail)   1 "x11" (3-byte tail)
//!         2 "direct-tcpip" (5)    3 "x@example.com" (1)
//! credit  0 (0, 0)   1 (u32::MAX, u32::MAX)   2 (0x0020_0000, 0x8000)
//!         3 explicit: window u32, max packet u32
//! reason  0..3 codes 1..4   4 -> 0   5 -> u32::MAX   6 -> 200   7 explicit u32
//! hsel    bit 7 clear: live handles[bits 0-6 mod len]
//!         bit 7 set:   every handle ever issued[bits 0-6 mod len]
//!         (no handles yet: the action is a no-op)
//! number selector (applied to the following byte n; empty pools fall
//! back to n itself so a small raw value is always meaningful):
//!         0 n (0..=255; collides with our small local numbers)
//!         1 pending-outgoing local number [n mod len]
//!         2 tombstoned local number [n mod len]
//!         3 established local number [n mod len]
//!         4 in-use peer number (pending incoming or established) [n mod len]
//!         5 retired local number (resolved or evicted) [n mod len]
//!         6 next_local + (n mod 4): never allocated
//!         7 explicit u32 (4 bytes replace n)
//! ```
//!
//! # Oracles (after every action)
//!
//! - `live_channels()`, `pending_outgoing()`, `pending_incoming()` and
//!   `phase(handle)` for every handle ever issued equal the model (`None`
//!   for resolved, refused, cancelled, lost or stale handles).
//! - Every command result and peer-message result (event with its ids and
//!   verbatim credits/tails, or the exact `OpenError`/`HandleError`/
//!   `Violation`) equals the model's prediction; violations and errors
//!   leave state unchanged (checked by the state comparison).
//! - Handles are never reissued; local numbers on the wire strictly
//!   increase and are never reissued (tracked over drained `OPEN` and
//!   `OPEN_CONFIRMATION` sender fields), independent of cancellation.
//! - A late reply to a tombstoned number yields `LateReply`, consumes the
//!   tombstone and changes nothing else; a reply for an evicted number is
//!   `UnknownRecipient`; a reply to an established number is
//!   `DuplicateReply`; a never-allocated number naming a pending incoming
//!   open is `ReplyToIncoming`; peer reuse of an in-use sender number is
//!   `DuplicatePeerNumber`.
//! - `IncomingRefusedByLimit` exactly when `max_pending_incoming` or
//!   `max_channels` is reached, with a `RESOURCE_SHORTAGE` (4) failure
//!   queued for the peer's number.
//! - `transport_lost()` yields exactly one `TransportLost` per live channel
//!   with its phase; afterwards all counters are zero, every handle is
//!   stale and `next_outgoing()` is `None`.
//! - Drained messages equal the model's queue exactly (numbers, credits
//!   including 0 and `u32::MAX`, type-specific tails, descriptions) and
//!   round-trip through the `tatami-wire` codecs; an undersized buffer is
//!   reported, not truncated.
//!
//! The local and peer number spaces are independent: selectors 0-6 make
//! the peer pick numbers equal to ours so coinciding values are exercised.

use libfuzzer_sys::fuzz_target;
use tatami_connection::opening::{
    AcceptParams, ChannelHandle, Credit, OpenParams, OpeningEngine, OpeningLimits,
};
use tatami_fuzz_protocol::state_support::opening_model::{Model, check_wire_roundtrip};
use tatami_fuzz_protocol::tcp_support::Cursor;
use tatami_wire::channel::{ChannelOpen, ChannelOpenConfirmation, ChannelOpenFailure};

const MAX_ACTIONS: usize = 200;

const TYPES: [(&[u8], &[u8]); 4] = [
    (b"session", b""),
    (b"x11", b"\x01\x02\x03"),
    (b"direct-tcpip", b"\xaa\xbb\xcc\xdd\xee"),
    (b"x@example.com", b"\xab"),
];

const DESCRIPTIONS: [&[u8]; 4] = [
    b"",
    b"unknown",
    b"no thanks",
    b"\xff\x00 not utf-8 \x1b[31m",
];

fn credit(sel: u8, cur: &mut Cursor<'_>) -> Credit {
    match sel & 3 {
        0 => Credit {
            initial_window_size: 0,
            maximum_packet_size: 0,
        },
        1 => Credit {
            initial_window_size: u32::MAX,
            maximum_packet_size: u32::MAX,
        },
        2 => Credit {
            initial_window_size: 0x0020_0000,
            maximum_packet_size: 0x8000,
        },
        _ => Credit {
            initial_window_size: cur.u32(),
            maximum_packet_size: cur.u32(),
        },
    }
}

fn reason(sel: u8, cur: &mut Cursor<'_>) -> u32 {
    match sel & 7 {
        s @ 0..=3 => u32::from(s) + 1,
        4 => 0,
        5 => u32::MAX,
        6 => 200,
        _ => cur.u32(),
    }
}

fn pick_handle(model: &Model, hsel: u8) -> Option<ChannelHandle> {
    let pool: Vec<ChannelHandle> = if hsel & 0x80 == 0 {
        model.live_handles()
    } else {
        model.handles().to_vec()
    };
    if pool.is_empty() {
        return None;
    }
    Some(pool[usize::from(hsel & 0x7f) % pool.len()])
}

fn pick_number(model: &Model, sel: u8, cur: &mut Cursor<'_>) -> u32 {
    if sel & 7 == 7 {
        return cur.u32();
    }
    let n = cur.u8();
    let from_pool = |pool: Vec<u32>| {
        if pool.is_empty() {
            u32::from(n)
        } else {
            pool[usize::from(n) % pool.len()]
        }
    };
    match sel & 7 {
        0 => u32::from(n),
        1 => from_pool(model.pending_out_numbers()),
        2 => from_pool(model.tombstoned_numbers()),
        3 => from_pool(model.established_numbers()),
        4 => from_pool(model.in_use_peer_numbers()),
        5 => from_pool(model.retired_numbers()),
        _ => (model.next_local() + u64::from(n % 4)).min(u64::from(u32::MAX)) as u32,
    }
}

fn drain_one(engine: &mut OpeningEngine, model: &mut Model) -> bool {
    let out = engine.next_outgoing();
    model.check_outgoing(out.as_ref());
    if let Some(out) = &out {
        check_wire_roundtrip(out);
    }
    out.is_some()
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let b0 = cur.u8();
    let b1 = cur.u8();
    let limits = if b0 & 0x80 != 0 {
        OpeningLimits {
            max_tombstones: usize::from(b1 & 3),
            ..OpeningLimits::default()
        }
    } else {
        OpeningLimits {
            max_pending_outgoing: 1 + usize::from(b0 & 3),
            max_pending_incoming: 1 + usize::from((b0 >> 2) & 3),
            max_channels: 1 + usize::from((b0 >> 4) & 7),
            max_tombstones: usize::from(b1 & 3),
        }
    };

    let mut engine = OpeningEngine::new(limits);
    let mut model = Model::new(limits);
    model.check_state(&engine);

    let mut actions = 0;
    while !cur.is_empty() && actions < MAX_ACTIONS {
        actions += 1;
        match cur.u8() % 10 {
            0 => {
                let arg = cur.u8();
                let (ty, tail) = TYPES[usize::from(arg & 3)];
                let params = OpenParams {
                    channel_type: ty.to_vec(),
                    local: credit(arg >> 2, &mut cur),
                    type_specific: tail.to_vec(),
                };
                let r = engine.open(params.clone());
                model.open(&params, &r);
            }
            1 => {
                let hsel = cur.u8();
                if let Some(h) = pick_handle(&model, hsel) {
                    let r = engine.cancel(h);
                    model.cancel(h, &r);
                }
            }
            2 => {
                let hsel = cur.u8();
                let arg = cur.u8();
                let params = AcceptParams {
                    local: credit(arg, &mut cur),
                    type_specific: TYPES[usize::from(arg >> 2) & 3].1.to_vec(),
                };
                if let Some(h) = pick_handle(&model, hsel) {
                    let r = engine.accept(h, params.clone());
                    model.accept(h, &params, &r);
                }
            }
            3 => {
                let hsel = cur.u8();
                let arg = cur.u8();
                let code = reason(arg, &mut cur);
                let description = DESCRIPTIONS[usize::from(arg >> 3) & 3];
                if let Some(h) = pick_handle(&model, hsel) {
                    let r = engine.refuse(h, code, description.to_vec());
                    model.refuse(h, code, description, &r);
                }
            }
            4 => {
                let arg = cur.u8();
                let (ty, tail) = TYPES[usize::from(arg & 3)];
                let sender = pick_number(&model, arg >> 4, &mut cur);
                let peer = credit(arg >> 2, &mut cur);
                let msg = ChannelOpen {
                    channel_type: ty,
                    sender_channel: sender,
                    initial_window_size: peer.initial_window_size,
                    maximum_packet_size: peer.maximum_packet_size,
                    type_specific: tail,
                };
                let r = engine.handle_open(&msg);
                model.peer_open(&msg, &r);
            }
            5 => {
                let arg = cur.u8();
                let recipient = pick_number(&model, arg, &mut cur);
                let sender = pick_number(&model, arg >> 3, &mut cur);
                let peer = credit(arg >> 6, &mut cur);
                let msg = ChannelOpenConfirmation {
                    recipient_channel: recipient,
                    sender_channel: sender,
                    initial_window_size: peer.initial_window_size,
                    maximum_packet_size: peer.maximum_packet_size,
                    type_specific: TYPES[usize::from(sender as u8 & 3)].1,
                };
                let r = engine.handle_open_confirmation(&msg);
                model.peer_confirm(&msg, &r);
            }
            6 => {
                let arg = cur.u8();
                let recipient = pick_number(&model, arg, &mut cur);
                let code = reason(arg >> 3, &mut cur);
                let msg = ChannelOpenFailure {
                    recipient_channel: recipient,
                    reason_code: code,
                    description: DESCRIPTIONS[usize::from(arg >> 6) & 3],
                    language_tag: if arg & 0x40 != 0 { b"en" } else { b"" },
                };
                let r = engine.handle_open_failure(&msg);
                model.peer_fail(&msg, &r);
            }
            7 => {
                let events = engine.transport_lost();
                model.transport_lost(&events);
                assert!(engine.next_outgoing().is_none(), "queued sends discarded");
                assert_eq!(engine.live_channels(), 0);
                assert_eq!(engine.pending_outgoing(), 0);
                assert_eq!(engine.pending_incoming(), 0);
                for &h in model.handles() {
                    assert_eq!(engine.phase(h), None, "{h:?} live after transport loss");
                }
            }
            8 => {
                let mut popped = 0usize;
                while drain_one(&mut engine, &mut model) {
                    popped += 1;
                    assert!(popped <= MAX_ACTIONS * 2, "outgoing queue never drains");
                }
            }
            _ => {
                drain_one(&mut engine, &mut model);
            }
        }
        model.check_state(&engine);
    }

    // Final drain: everything the model expects must be there, nothing more.
    while drain_one(&mut engine, &mut model) {}
    model.check_state(&engine);
});
