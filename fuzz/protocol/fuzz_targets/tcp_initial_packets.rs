#![no_main]
//! `tatami_tcp::packet` framing and `tatami_tcp::initial::InitialPackets`
//! against independent header rules, slicing and budget accounting.
//!
//! # Input layout
//!
//! ```text
//! byte 0   bits 0-2: packet cap   0→16, 1→64, 2→1024, 3→35000, 4→65536
//!                                 (default), 5→fuzz u32 follows, 6→65532, 7→0
//!          bit 3:    also interpret the rest as structured packets
//!          bits 4-5: chunk schedule selector (`ChunkMode::from_selector`)
//!          bits 6-7: max_packets  0→16 (default), 1→1, 2→2, 3→3
//! byte 1   max_bytes (mod 5)      0→256 KiB (default), 1→16, 2→64, 3→1024,
//!                                 4→fuzz u32 follows
//! [cap u32] [max_bytes u32]
//! byte     n_sched (mod 16), then n_sched chunk sizes (0 counts as 1)
//! rest     raw stream; when bit 3 is set the same bytes are also read as:
//!          n_pkts u8 (mod 9), then per packet: kind u8 (bits 0-2 variant,
//!          bits 3-5 payload selector), pad_byte u8, payload description
//!            selector 0 IGNORE (data_len u16 mod 4097), 1 DEBUG, 2 UNIMPLEMENTED,
//!            3 DISCONNECT, 4 KEXINIT (stream_gen::gen_kexinit), 5 NEWKEYS,
//!            6 method-specific 30..=49, 7 raw bytes (1 + u8 mod 32)
//!            variant 0 valid; 1 padding_length := 3; 2 padding_length :=
//!            packet_length (mod 256); 3 packet_length += 1; 4 packet_length
//!            := 4; 5 packet_length := cap + 1; 6 hand-built empty-payload
//!            frame; 7 valid IGNORE whose packet_length is the largest the
//!            cap admits (65532 for the default cap → 65536-byte packet)
//! ```
//!
//! # Oracles
//!
//! - For every prefix examined (the first 16, the chunk boundaries, and
//!   `total_len - 1`), `decode_initial_packet` equals the reference decoder:
//!   the same `NeedMore { total_len }`, the same error (cap → minimum →
//!   alignment, then padding), or the same payload/padding slices and
//!   `total_len`. A 4-byte input claiming more than the cap is `TooLarge`,
//!   never `NeedMore`; a proper prefix is never `Complete`.
//! - `encode_initial_packet` output has `total % 8 == 0`, padding ≥ 4 and
//!   minimal (found by search), the hand-computed `packet_length`, the pad
//!   byte in every padding position, fails without writing when the output
//!   is one byte short, and decodes back to the payload.
//! - `InitialPackets` over the raw stream and over the structured valid
//!   packets matches the reference model step by step: budget errors at the
//!   reference-computed packet index, IGNORE/DEBUG/UNIMPLEMENTED skipped,
//!   DISCONNECT/KEXINIT terminate, NEWKEYS and 30..=49 are unsupported
//!   transitions, other numbers unexpected, empty payload rejected, and the
//!   `packets()`/`bytes()` counters agree. Chunked delivery yields the same
//!   sequence.
//! - Nothing in the harness allocates by a fuzzed length claim; claimed
//!   lengths are huge while inputs stay small.

use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::tcp_support::packet_ref::{self, RefStep};
use tatami_fuzz_protocol::tcp_support::stream_gen::{self, Role};
use tatami_fuzz_protocol::tcp_support::{ChunkMode, Cursor, filler, msg_ref, put_string};
use tatami_tcp::initial::InitialLimits;
use tatami_tcp::packet::{
    EncodeInitialError, PacketError, PacketLimits, PacketStep, decode_initial_packet,
    encode_initial_packet,
};

fn is_subslice(outer: &[u8], inner: &[u8]) -> bool {
    let o = outer.as_ptr_range();
    let i = inner.as_ptr_range();
    i.start >= o.start && i.end <= o.end
}

/// Library vs reference on one buffer.
fn check_decode(buf: &[u8], limits: &PacketLimits) {
    let cap = limits.max_packet_length;
    let actual = decode_initial_packet(buf, limits);
    let expected = packet_ref::decode(buf, cap);
    match (&actual, &expected) {
        (Ok(PacketStep::NeedMore { total_len }), Ok(RefStep::NeedMore { total_len: t })) => {
            assert_eq!(total_len, t, "NeedMore total_len for {} bytes", buf.len());
            if let Some(t) = total_len {
                assert!(*t > buf.len(), "NeedMore with enough bytes buffered");
                assert!(t % 8 == 0 && *t >= 16);
            }
        }
        (
            Ok(PacketStep::Complete(p)),
            Ok(RefStep::Complete {
                payload,
                padding,
                total_len,
            }),
        ) => {
            assert_eq!(p.payload, &buf[payload.clone()], "payload slice");
            assert_eq!(p.padding, &buf[padding.clone()], "padding slice");
            assert_eq!(p.total_len, *total_len, "total_len");
            assert_eq!(p.payload.len() + p.padding.len() + 5, p.total_len);
            assert!(p.padding.len() >= 4);
            assert!(is_subslice(buf, p.payload) && is_subslice(buf, p.padding));
        }
        (Err(a), Err(e)) => assert_eq!(a, e, "error for {:?} cap {cap}", &buf[..buf.len().min(5)]),
        _ => panic!(
            "library {actual:?} vs reference {expected:?} for {:?} (len {}) cap {cap}",
            &buf[..buf.len().min(5)],
            buf.len()
        ),
    }
}

/// Raw stream: prefix behaviour, incremental delivery, whole-stream framing
/// and the budgeted decoder.
fn check_raw_stream(stream: &[u8], limits: &InitialLimits, mode: &ChunkMode) {
    let packet = &limits.packet;
    let cap = packet.max_packet_length;
    for k in 0..=stream.len().min(16) {
        check_decode(&stream[..k], packet);
    }
    if stream.len() >= 4 {
        let claimed = u32::from_be_bytes([stream[0], stream[1], stream[2], stream[3]]);
        if claimed > cap {
            assert_eq!(
                decode_initial_packet(&stream[..4], packet),
                Err(PacketError::TooLarge {
                    packet_length: claimed,
                    limit: cap
                }),
                "an oversized claim must be rejected from the length field alone"
            );
        }
    }
    if let Ok(RefStep::Complete { total_len, .. }) = packet_ref::decode(stream, cap) {
        check_decode(&stream[..total_len - 1], packet);
        assert!(
            matches!(
                decode_initial_packet(&stream[..total_len - 1], packet),
                Ok(PacketStep::NeedMore { .. })
            ),
            "a proper prefix must never be Complete"
        );
        check_decode(&stream[..total_len], packet);
    }

    // Incremental delivery: decode after every chunk, dropping complete
    // packets, until the stream ends or framing fails.
    let mut acc: Vec<u8> = Vec::new();
    let mut off = 0;
    let mut desired = mode.desired();
    'outer: while off < stream.len() {
        let n = desired.next().unwrap_or(1).max(1).min(stream.len() - off);
        acc.extend_from_slice(&stream[off..off + n]);
        off += n;
        loop {
            check_decode(&acc, packet);
            match decode_initial_packet(&acc, packet) {
                Ok(PacketStep::Complete(p)) => {
                    let total = p.total_len;
                    acc.drain(..total);
                }
                Ok(PacketStep::NeedMore { .. }) => break,
                Err(_) => break 'outer,
            }
        }
    }

    msg_ref::check_initial_packets(stream, limits, mode);
}

fn structured_payload(selector: u8, cur: &mut Cursor<'_>, cap: u32, max_size: bool) -> Vec<u8> {
    if max_size {
        // packet_length = 1 + (1 + 4 + data_len) + 4 padding = data_len + 10.
        let pl = packet_ref::max_packet_length(cap.min(65536)).unwrap_or(12);
        let mut p = vec![2u8];
        put_string(&mut p, &filler(pl as usize - 10, 21));
        return p;
    }
    match selector % 8 {
        0 => {
            let len = usize::from(cur.u16()) % 4097;
            let mut p = vec![2u8];
            put_string(&mut p, &filler(len, 22));
            p
        }
        1 => {
            let mut p = vec![4u8, cur.u8()];
            let m = usize::from(cur.u8()) % 64;
            put_string(&mut p, cur.take(m));
            let l = usize::from(cur.u8()) % 8;
            put_string(&mut p, cur.take(l));
            p
        }
        2 => {
            let mut p = vec![3u8];
            p.extend_from_slice(&cur.u32().to_be_bytes());
            p
        }
        3 => {
            let mut p = vec![1u8];
            p.extend_from_slice(&cur.u32().to_be_bytes());
            let d = usize::from(cur.u8()) % 64;
            put_string(&mut p, cur.take(d));
            let l = usize::from(cur.u8()) % 8;
            put_string(&mut p, cur.take(l));
            p
        }
        4 => stream_gen::gen_kexinit(cur, Role::Server).payload,
        5 => vec![21u8],
        6 => {
            let mut p = vec![30 + cur.u8() % 20];
            let n = usize::from(cur.u8()) % 8;
            p.extend_from_slice(cur.take(n));
            p
        }
        _ => {
            let n = 1 + usize::from(cur.u8()) % 32;
            cur.take_filled(n, 23)
        }
    }
}

/// Encoder contract on one payload; returns the frame.
fn check_encode(payload: &[u8], pad_byte: u8) -> Vec<u8> {
    let expected_pad = packet_ref::minimal_padding(payload.len());
    let expected_total = 5 + payload.len() + expected_pad;
    let mut out = vec![0u8; expected_total + 8];
    let n = encode_initial_packet(payload, pad_byte, &mut out).expect("bounded payload frames");
    assert_eq!(n, expected_total, "framed length");
    assert_eq!(n % 8, 0, "alignment");
    assert!((4..12).contains(&expected_pad), "padding minimal and >= 4");
    assert_eq!(
        &out[..4],
        &((n - 4) as u32).to_be_bytes(),
        "packet_length field"
    );
    assert_eq!(usize::from(out[4]), expected_pad, "padding_length field");
    assert_eq!(
        &out[5..5 + payload.len()],
        payload,
        "payload copied verbatim"
    );
    assert!(
        out[5 + payload.len()..n].iter().all(|&b| b == pad_byte),
        "padding filled with the pad byte"
    );
    assert!(
        out[n..].iter().all(|&b| b == 0),
        "nothing written past total"
    );

    // One byte short: fails without writing.
    let mut short = vec![0xAAu8; n - 1];
    assert_eq!(
        encode_initial_packet(payload, pad_byte, &mut short),
        Err(EncodeInitialError::InsufficientCapacity {
            needed: n,
            available: n - 1,
        })
    );
    assert!(
        short.iter().all(|&b| b == 0xAA),
        "failed encode must not write"
    );

    // Decodes back under a permissive cap.
    let permissive = PacketLimits {
        max_packet_length: u32::MAX,
    };
    match decode_initial_packet(&out[..n], &permissive) {
        Ok(PacketStep::Complete(p)) => {
            assert_eq!(p.payload, payload);
            assert_eq!(p.padding.len(), expected_pad);
            assert_eq!(p.total_len, n);
        }
        other => panic!("encoded frame does not decode: {other:?}"),
    }
    out.truncate(n);
    out
}

fn check_structured(rest: &[u8], limits: &InitialLimits, mode: &ChunkMode) {
    let packet = &limits.packet;
    let cap = packet.max_packet_length;
    let mut cur = Cursor::new(rest);
    let n_pkts = usize::from(cur.u8()) % 9;
    let mut stream = Vec::new();
    let mut max_size_used = false;
    for _ in 0..n_pkts {
        let kind = cur.u8();
        let variant = kind & 7;
        let selector = (kind >> 3) & 7;
        let pad_byte = cur.u8();
        let max_size = variant == 7 && !max_size_used;
        if max_size {
            max_size_used = true;
        }
        let payload = structured_payload(selector, &mut cur, cap, max_size);
        let frame = check_encode(&payload, pad_byte);
        let packet_length = (frame.len() - 4) as u32;

        // Under the fuzz cap the intact frame is accepted iff it fits.
        check_decode(&frame, packet);
        if packet_length > cap {
            assert!(matches!(
                decode_initial_packet(&frame[..4], packet),
                Err(PacketError::TooLarge { .. })
            ));
        } else {
            assert!(matches!(
                decode_initial_packet(&frame, packet),
                Ok(PacketStep::Complete(_))
            ));
        }
        if max_size {
            assert_eq!(
                packet_length,
                packet_ref::max_packet_length(cap.min(65536)).unwrap_or(12),
                "max-size packet must hit the cap exactly"
            );
            // Eight more bytes would be the next aligned size: over the cap.
            let mut over = frame[..5].to_vec();
            over[..4].copy_from_slice(&(packet_length + 8).to_be_bytes());
            if cap <= 65536 {
                assert!(matches!(
                    decode_initial_packet(&over[..4], packet),
                    Err(PacketError::TooLarge { .. })
                ));
            }
        }

        // Header corruptions with reference-predicted outcomes.
        let mut hdr = frame[..5].to_vec();
        let expected: Option<PacketError> = match variant {
            1 => {
                hdr[4] = 3;
                Some(PacketError::BadPadding {
                    packet_length,
                    padding_length: 3,
                })
            }
            2 => {
                hdr[4] = (packet_length % 256) as u8;
                // Underflows iff packet_length < padding_length + 1.
                (packet_length < u32::from(hdr[4]) + 1 || hdr[4] < 4).then_some(
                    PacketError::BadPadding {
                        packet_length,
                        padding_length: hdr[4],
                    },
                )
            }
            3 => {
                hdr[..4].copy_from_slice(&(packet_length + 1).to_be_bytes());
                Some(PacketError::Misaligned {
                    packet_length: packet_length + 1,
                })
            }
            4 => {
                hdr[..4].copy_from_slice(&4u32.to_be_bytes());
                Some(PacketError::TooSmall { packet_length: 4 })
            }
            5 if cap < u32::MAX => {
                hdr[..4].copy_from_slice(&(cap + 1).to_be_bytes());
                Some(PacketError::TooLarge {
                    packet_length: cap + 1,
                    limit: cap,
                })
            }
            _ => None,
        };
        if matches!(variant, 1..=5) {
            check_decode(&hdr[..4], packet);
            check_decode(&hdr, packet);
            let permissive = PacketLimits {
                max_packet_length: u32::MAX,
            };
            if let Some(e) = expected {
                // Without the cap in the way the specific rule must fire
                // (variant 5 is the cap rule itself).
                let under = if variant == 5 { packet } else { &permissive };
                let result = decode_initial_packet(&hdr, under);
                assert_eq!(result, Err(e), "variant {variant} on {hdr:?}");
                if matches!(variant, 3..=5) {
                    assert_eq!(
                        decode_initial_packet(&hdr[..4], under),
                        Err(e),
                        "length-field rules fire with four bytes"
                    );
                }
            }
        }

        match variant {
            0 | 7 => stream.extend_from_slice(&frame),
            6 => stream.extend_from_slice(&[0, 0, 0, 12, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            _ => {}
        }
    }
    msg_ref::check_initial_packets(&stream, limits, mode);
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let b0 = cur.u8();
    let b1 = cur.u8();
    let cap = match b0 & 7 {
        0 => 16,
        1 => 64,
        2 => 1024,
        3 => 35_000,
        4 => 64 * 1024,
        5 => cur.u32(),
        6 => 65_532,
        _ => 0,
    };
    let structured = b0 & 8 != 0;
    let chunk_sel = (b0 >> 4) & 3;
    let max_packets = match b0 >> 6 {
        0 => 16,
        1 => 1,
        2 => 2,
        _ => 3,
    };
    let max_bytes = match b1 % 5 {
        0 => 256 * 1024,
        1 => 16,
        2 => 64,
        3 => 1024,
        _ => cur.u32() as usize,
    };
    let n_sched = usize::from(cur.u8()) % 16;
    let sched = cur.take(n_sched).to_vec();
    let mode = ChunkMode::from_selector(chunk_sel, &sched);
    let rest = cur.rest();

    let limits = InitialLimits {
        packet: PacketLimits {
            max_packet_length: cap,
        },
        max_packets,
        max_bytes,
    };
    assert_eq!(
        PacketLimits::default().max_packet_length,
        64 * 1024,
        "default cap documented as 64 KiB"
    );
    check_raw_stream(rest, &limits, &mode);
    if structured {
        check_structured(rest, &limits, &mode);
    }
});
