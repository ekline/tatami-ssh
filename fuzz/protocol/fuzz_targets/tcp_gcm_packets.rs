#![no_main]
//! `tatami_tcp::gcm::AeadDirection`: `aes128-gcm@openssh.com` protected
//! packets (RFC 5647 layout) against an independent sealer built directly
//! on `aes_gcm::Aes128Gcm`.
//!
//! # Input layout
//!
//! ```text
//! byte 0     bits 0-1: limit selector (0 default 64 KiB, 1 1024, 2 16,
//!                      3 fuzz u16 follows)
//!            bit 2:    counter boundary check from u64::MAX - (u8 mod 4)
//!            bit 3:    include one payload of 65 531 bytes (the 64 KiB cap)
//!            bits 4-5: chunk schedule (`ChunkMode::from_selector`)
//!            bit 6:    mutation path after the round trip
//!            bit 7:    open the raw remainder too
//! bytes      key 16, IV 12 (fixed 4 + counter 8; the counter's top bit is
//!            cleared so only the boundary check reaches u64::MAX), padding
//!            seed u8
//! [u16]      fuzz limit (selector 3)
//! byte       n payloads (mod 6), then per payload len u16 (mod 1200) + bytes
//! byte       n_sched (mod 8) + chunk sizes
//! bytes      mutation index u8, xor u8, fuzz length 4, boundary k u8,
//!            forged padding_length u8
//! rest       raw stream (bit 7)
//! ```
//!
//! # Oracles
//!
//! - Sealing: the library output for every payload equals the harness's
//!   own packet built with `aes_gcm` directly (length prefix as AAD,
//!   `padding_length + payload + padding` a multiple of 16 with ≥ 4 padding
//!   bytes taken from the same deterministic padding stream, nonce = fixed
//!   4 bytes || big-endian counter incremented after every packet);
//!   `packets()` and `next_nonce()` advance exactly once per seal;
//!   `AeadDirection::new(&AeadKeys)` equals `from_parts`; the 65 531-byte
//!   payload frames to `packet_length` 65 536 exactly.
//! - Opening under the fuzz schedule, byte-at-a-time and all-at-once: every
//!   proper prefix of a packet is `NeedMore { total_len }` with `total_len`
//!   known iff four bytes are present, never `Packet`; complete packets
//!   yield the original payloads in order with `total_len = 4 +
//!   packet_length + 16`; a packet over the cap is `TooLarge{len,limit}` the
//!   moment its length is readable. On success the buffer holds the
//!   plaintext in place; on any error it is byte-identical to before and
//!   `packets()`/`next_nonce()` have not moved (no plaintext exposure and no
//!   nonce consumption before the tag verifies).
//! - Mutation: a flipped byte in the body or tag is `TagMismatch`; a flipped
//!   length byte is modelled exactly (`TooLarge` / `TooSmall` / `Misaligned`
//!   from the new value before any body is waited for, else `NeedMore` when
//!   the stream is now too short, else `TagMismatch` because the AAD
//!   changed); a 4-byte oversized claim is `TooLarge` immediately; a forged
//!   `padding_length` under a valid tag is accepted iff `4 <= pad <
//!   packet_length` and otherwise `BadPadding{packet_length,padding_length}`
//!   (characterised: the tag verified, so that one counter value is spent).
//! - Counter boundary: from `u64::MAX - k`, exactly `k` seals succeed then
//!   `CounterExhausted` with nothing appended and the nonce unchanged; the
//!   receiver opens `k` packets and then reports `CounterExhausted` only for
//!   a complete, well-framed packet (`NeedMore` and length errors win).

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
use libfuzzer_sys::fuzz_target;
use rand_core::RngCore;
use tatami_fuzz_protocol::kex_support::crypto::{Gcm, HarnessRng, padding_len};
use tatami_fuzz_protocol::tcp_support::{ChunkMode, Cursor, filler};
use tatami_tcp::gcm::{
    AeadDirection, BLOCK_SIZE, KEY_LEN, LENGTH_LEN, MIN_PACKET_LENGTH, NONCE_LEN, OpenError,
    OpenStep, SealError, TAG_LEN,
};
use tatami_tcp::packet::PacketLimits;
use tatami_tcp::transcript::AeadKeys;

/// `1 + 65531 + 4 = 65536`, the default `max_packet_length`.
const CAP_PAYLOAD_LEN: usize = 65_531;

/// Expected result of `open` on a buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expect {
    NeedMore(Option<usize>),
    Packet { total_len: usize },
    Err(OpenError),
}

/// The length-field rules from the module documentation: cap, minimum,
/// alignment, then wait for `4 + packet_length + 16`; then the tag.
fn expect_from_length(buf: &[u8], limit: u32, tag_ok: bool) -> Expect {
    if buf.len() < LENGTH_LEN {
        return Expect::NeedMore(None);
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if packet_length > limit {
        return Expect::Err(OpenError::TooLarge {
            packet_length,
            limit,
        });
    }
    if packet_length < MIN_PACKET_LENGTH {
        return Expect::Err(OpenError::TooSmall { packet_length });
    }
    if !packet_length.is_multiple_of(BLOCK_SIZE as u32) {
        return Expect::Err(OpenError::Misaligned { packet_length });
    }
    let total_len = LENGTH_LEN + packet_length as usize + TAG_LEN;
    if buf.len() < total_len {
        return Expect::NeedMore(Some(total_len));
    }
    if tag_ok {
        Expect::Packet { total_len }
    } else {
        Expect::Err(OpenError::TagMismatch)
    }
}

fn limits_from(sel: u8, cur: &mut Cursor<'_>) -> PacketLimits {
    let max_packet_length = match sel & 3 {
        0 => PacketLimits::default().max_packet_length,
        1 => 1024,
        2 => 16,
        _ => u32::from(cur.u16()),
    };
    PacketLimits { max_packet_length }
}

fn packet_length_of(payload_len: usize) -> u32 {
    (1 + payload_len + padding_len(payload_len)) as u32
}

/// Runs `open` once and checks the exposure/counter contract around it.
/// `BadPadding` is excluded here (see `check_bad_padding`).
#[allow(clippy::type_complexity)]
fn open_checked(
    rx: &mut AeadDirection,
    buf: &mut [u8],
    limits: &PacketLimits,
) -> Result<Option<(Vec<u8>, usize)>, OpenError> {
    // A snapshot is needed wherever the tag might be checked (the buffer
    // could be decrypted) and is cheap for small buffers; skipping it for
    // large incomplete buffers keeps byte-at-a-time delivery linear.
    let complete = buf.len() >= LENGTH_LEN && {
        let pl = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        pl <= limits.max_packet_length && buf.len() >= LENGTH_LEN + pl as usize + TAG_LEN
    };
    let before = (complete || buf.len() <= 512).then(|| buf.to_vec());
    let packets_before = rx.packets();
    let nonce_before = rx.next_nonce();
    match rx.open(buf, limits) {
        Ok(OpenStep::NeedMore { total_len }) => {
            if let Some(b) = &before {
                assert_eq!(buf, &b[..], "NeedMore must not touch the buffer");
            }
            assert_eq!(
                rx.packets(),
                packets_before,
                "NeedMore must not advance the counter"
            );
            assert_eq!(rx.next_nonce(), nonce_before);
            assert_eq!(
                total_len.is_some(),
                buf.len() >= LENGTH_LEN,
                "total_len is known iff the length field is present"
            );
            Ok(None)
        }
        Ok(OpenStep::Packet(p)) => {
            let payload = p.payload.to_vec();
            let total = p.total_len;
            assert_eq!(
                rx.packets(),
                packets_before + 1,
                "one packet advances the counter once"
            );
            assert_ne!(rx.next_nonce(), nonce_before);
            let before = before.expect("a complete packet always has a snapshot");
            assert_eq!(
                &buf[..LENGTH_LEN],
                &before[..LENGTH_LEN],
                "the clear length is unchanged"
            );
            let pad = usize::from(buf[LENGTH_LEN]);
            assert!(pad >= 4, "accepted padding is at least 4");
            assert_eq!(
                &buf[LENGTH_LEN + 1..LENGTH_LEN + 1 + payload.len()],
                &payload[..],
                "the payload is the plaintext decrypted in place"
            );
            assert_eq!(
                LENGTH_LEN + 1 + payload.len() + pad + TAG_LEN,
                total,
                "total_len framing"
            );
            assert_eq!(
                &buf[total..],
                &before[total..],
                "bytes after the packet are untouched"
            );
            Ok(Some((payload, total)))
        }
        Err(e) => {
            assert!(
                !matches!(e, OpenError::BadPadding { .. }),
                "BadPadding is checked separately"
            );
            if let Some(b) = &before {
                assert_eq!(
                    buf,
                    &b[..],
                    "on {e:?} the buffer must be untouched (no plaintext exposure)"
                );
            }
            assert_eq!(
                rx.packets(),
                packets_before,
                "a failed open must not spend a counter value"
            );
            assert_eq!(rx.next_nonce(), nonce_before);
            Err(e)
        }
    }
}

struct Sealed {
    stream: Vec<u8>,
    /// `(payload, packet start offset, total_len)` per packet.
    packets: Vec<(Vec<u8>, usize, usize)>,
}

/// Seals every payload with the library and with the harness, byte for byte.
fn seal_all(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN], seed: u64, payloads: &[Vec<u8>]) -> Sealed {
    let mut tx = AeadDirection::from_parts(key, iv);
    let mut via_new = AeadDirection::new(&AeadKeys { key: *key, iv: *iv });
    let mut model = Gcm::new(key, iv);
    let mut pad_rng = HarnessRng::new(seed);
    let mut model_pad_rng = HarnessRng::new(seed);
    let mut alt_pad_rng = HarnessRng::new(seed);
    let mut stream = Vec::new();
    let mut packets = Vec::new();
    assert_eq!(tx.next_nonce(), *iv, "the first nonce is the IV");
    assert_eq!(tx.packets(), 0);
    assert_eq!(
        format!("{tx:?}"),
        "AeadDirection { packets: 0, .. }",
        "Debug shows no key material"
    );
    for (i, payload) in payloads.iter().enumerate() {
        let nonce_before = tx.next_nonce();
        assert_eq!(nonce_before, model.nonce());
        let start = stream.len();
        let n = tx
            .seal(payload, &mut pad_rng, &mut stream)
            .unwrap_or_else(|e| panic!("seal of {} bytes failed: {e:?}", payload.len()));
        assert_eq!(n, stream.len() - start, "seal returns the appended length");
        let pad = padding_len(payload.len());
        assert_eq!(
            n,
            LENGTH_LEN + 1 + payload.len() + pad + TAG_LEN,
            "framing length"
        );
        let mut padding = vec![0u8; pad];
        model_pad_rng.fill_bytes(&mut padding);
        let want = model.seal_with_padding(payload, &padding);
        assert_eq!(
            &stream[start..],
            &want[..],
            "packet {i} differs from the independent sealer"
        );
        assert_eq!(tx.packets(), i as u64 + 1);
        let mut expected_nonce = nonce_before;
        let c = u64::from_be_bytes(expected_nonce[4..].try_into().expect("8")) + 1;
        expected_nonce[4..].copy_from_slice(&c.to_be_bytes());
        assert_eq!(
            tx.next_nonce(),
            expected_nonce,
            "counter is a big-endian u64 in the last 8 bytes"
        );
        let mut alt = Vec::new();
        via_new
            .seal(payload, &mut alt_pad_rng, &mut alt)
            .expect("same inputs seal");
        assert_eq!(
            alt,
            &stream[start..],
            "AeadDirection::new equals from_parts"
        );
        packets.push((payload.clone(), start, n));
    }
    Sealed { stream, packets }
}

/// Delivers `stream` under `mode`, opening after every feed. Returns the
/// payloads opened before the first error (which must match the model).
fn open_stream(
    key: &[u8; KEY_LEN],
    iv: &[u8; NONCE_LEN],
    stream: &[u8],
    mode: &ChunkMode,
    limits: &PacketLimits,
) -> (Vec<Vec<u8>>, Option<OpenError>) {
    let mut rx = AeadDirection::from_parts(key, iv);
    let mut buf: Vec<u8> = Vec::new();
    let mut out = Vec::new();
    let mut off = 0;
    let mut desired = mode.desired();
    loop {
        loop {
            let want = expect_from_length(&buf, limits.max_packet_length, true);
            match open_checked(&mut rx, &mut buf, limits) {
                Ok(None) => {
                    assert!(
                        matches!(want, Expect::NeedMore(_)),
                        "expected {want:?}, got NeedMore"
                    );
                    break;
                }
                Ok(Some((payload, total))) => {
                    assert_eq!(want, Expect::Packet { total_len: total });
                    out.push(payload);
                    buf.drain(..total);
                }
                Err(e) => {
                    assert_eq!(Expect::Err(e), want);
                    return (out, Some(e));
                }
            }
        }
        if off >= stream.len() {
            break;
        }
        let n = desired.next().unwrap_or(1).max(1).min(stream.len() - off);
        buf.extend_from_slice(&stream[off..off + n]);
        off += n;
    }
    assert!(
        buf.is_empty(),
        "a well-formed stream is consumed completely"
    );
    (out, None)
}

fn check_counter_boundary(
    key: &[u8; KEY_LEN],
    iv: &[u8; NONCE_LEN],
    k: u8,
    payload: &[u8],
    limits: &PacketLimits,
) {
    let mut iv_near = *iv;
    let start = u64::MAX - u64::from(k);
    iv_near[4..].copy_from_slice(&start.to_be_bytes());
    let mut tx = AeadDirection::from_parts(key, &iv_near);
    let mut rng = HarnessRng::new(7);
    let mut stream = Vec::new();
    for i in 0..u64::from(k) {
        assert_eq!(&tx.next_nonce()[4..], &(start + i).to_be_bytes()[..]);
        tx.seal(payload, &mut rng, &mut stream)
            .expect("counter still available");
        assert_eq!(tx.packets(), i + 1);
    }
    // At u64::MAX: refused, nothing appended, no counter value spent.
    assert_eq!(&tx.next_nonce()[4..], &u64::MAX.to_be_bytes()[..]);
    let len_before = stream.len();
    let nonce_before = tx.next_nonce();
    assert_eq!(
        tx.seal(payload, &mut rng, &mut stream),
        Err(SealError::CounterExhausted)
    );
    assert_eq!(stream.len(), len_before, "a refused seal appends nothing");
    assert_eq!(
        tx.next_nonce(),
        nonce_before,
        "a refused seal consumes no counter value"
    );
    assert_eq!(tx.packets(), u64::from(k));
    assert_eq!(
        tx.seal(payload, &mut rng, &mut stream),
        Err(SealError::CounterExhausted),
        "still refused"
    );

    if packet_length_of(payload.len()) > limits.max_packet_length {
        return;
    }
    // The receiver opens exactly k packets then refuses a complete one.
    let mut rx = AeadDirection::from_parts(key, &iv_near);
    let mut buf = stream.clone();
    for _ in 0..k {
        let (p, total) = open_checked(&mut rx, &mut buf, limits)
            .expect("well-formed")
            .expect("complete");
        assert_eq!(p, payload);
        buf.drain(..total);
    }
    assert!(buf.is_empty());
    assert_eq!(&rx.next_nonce()[4..], &u64::MAX.to_be_bytes()[..]);
    let mut fake = vec![0u8; LENGTH_LEN + 16 + TAG_LEN];
    fake[3] = 16;
    if limits.max_packet_length >= 16 {
        let mut partial = fake[..LENGTH_LEN + 3].to_vec();
        assert_eq!(
            open_checked(&mut rx, &mut partial, limits),
            Ok(None),
            "NeedMore wins over the exhausted counter"
        );
        assert_eq!(
            open_checked(&mut rx, &mut fake, limits),
            Err(OpenError::CounterExhausted),
            "a complete well-framed packet is refused by the counter"
        );
    } else {
        assert!(matches!(
            open_checked(&mut rx, &mut fake, limits),
            Err(OpenError::TooLarge { .. })
        ));
    }
    let mut bad = [0u8, 0, 0, 17];
    let want = if 17 > limits.max_packet_length {
        OpenError::TooLarge {
            packet_length: 17,
            limit: limits.max_packet_length,
        }
    } else {
        OpenError::Misaligned { packet_length: 17 }
    };
    assert_eq!(
        open_checked(&mut rx, &mut bad, limits),
        Err(want),
        "length rules win over the counter"
    );
}

fn check_length_rules(
    key: &[u8; KEY_LEN],
    iv: &[u8; NONCE_LEN],
    limits: &PacketLimits,
    fuzz_len: [u8; 4],
) {
    let mut rx = AeadDirection::from_parts(key, iv);
    let limit = limits.max_packet_length;
    if limit < u32::MAX {
        let claim = limit + 1;
        let mut four = claim.to_be_bytes();
        assert_eq!(
            open_checked(&mut rx, &mut four, limits),
            Err(OpenError::TooLarge {
                packet_length: claim,
                limit
            }),
            "one over the cap in four bytes is TooLarge, not NeedMore"
        );
        let mut max = [0xffu8; 4];
        assert_eq!(
            open_checked(&mut rx, &mut max, limits),
            Err(OpenError::TooLarge {
                packet_length: u32::MAX,
                limit
            })
        );
    }
    for pl in [0u32, 1, 4, 15] {
        let mut b = pl.to_be_bytes();
        let want = if pl > limit {
            OpenError::TooLarge {
                packet_length: pl,
                limit,
            }
        } else {
            OpenError::TooSmall { packet_length: pl }
        };
        assert_eq!(open_checked(&mut rx, &mut b, limits), Err(want));
    }
    for pl in [17u32, 24, 31, 100] {
        let mut b = pl.to_be_bytes();
        let want = if pl > limit {
            OpenError::TooLarge {
                packet_length: pl,
                limit,
            }
        } else {
            OpenError::Misaligned { packet_length: pl }
        };
        assert_eq!(open_checked(&mut rx, &mut b, limits), Err(want));
    }
    // Exactly the cap in four bytes waits for the body (when aligned).
    if limit >= 16 && limit.is_multiple_of(16) {
        let mut b = limit.to_be_bytes();
        assert_eq!(open_checked(&mut rx, &mut b, limits), Ok(None));
        assert_eq!(
            rx.open(&mut b, limits),
            Ok(OpenStep::NeedMore {
                total_len: Some(LENGTH_LEN + limit as usize + TAG_LEN)
            })
        );
    }
    // A fuzz length in four bytes: exactly the model.
    let mut b = fuzz_len;
    let want = expect_from_length(&b, limit, false);
    match open_checked(&mut rx, &mut b, limits) {
        Ok(None) => assert!(matches!(want, Expect::NeedMore(Some(_))), "{want:?}"),
        Ok(Some(_)) => panic!("four bytes can never be a packet"),
        Err(e) => assert_eq!(Expect::Err(e), want),
    }
    assert_eq!(
        rx.packets(),
        0,
        "length-rule failures never move the counter"
    );
}

/// Forges `padding_length` under a valid tag with the harness cipher.
fn check_bad_padding(
    key: &[u8; KEY_LEN],
    iv: &[u8; NONCE_LEN],
    payload: &[u8],
    forged: u8,
    limits: &PacketLimits,
) {
    let pad = padding_len(payload.len());
    let packet_length = 1 + payload.len() + pad;
    if packet_length as u32 > limits.max_packet_length {
        return;
    }
    let mut body = vec![forged];
    body.extend_from_slice(payload);
    body.resize(packet_length, 0);
    let aad = (packet_length as u32).to_be_bytes();
    let cipher = Aes128Gcm::new(GenericArray::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(iv), &aad, &mut body)
        .expect("small");
    let mut buf = aad.to_vec();
    buf.extend(body);
    buf.extend_from_slice(&tag);
    let mut rx = AeadDirection::from_parts(key, iv);
    let valid = usize::from(forged) >= 4 && usize::from(forged) < packet_length;
    match rx.open(&mut buf, limits) {
        Ok(OpenStep::Packet(p)) => {
            assert!(
                valid,
                "padding_length {forged} accepted for packet_length {packet_length}"
            );
            assert_eq!(p.payload.len(), packet_length - 1 - usize::from(forged));
            assert_eq!(p.total_len, LENGTH_LEN + packet_length + TAG_LEN);
            assert_eq!(rx.packets(), 1);
        }
        Err(OpenError::BadPadding {
            packet_length: pl,
            padding_length,
        }) => {
            assert!(
                !valid,
                "padding_length {forged} rejected for packet_length {packet_length}"
            );
            assert_eq!(pl as usize, packet_length);
            assert_eq!(padding_length, forged);
            // Characterised: the tag verified before the padding check, so
            // the counter value was spent; the outcome is terminal anyway.
            assert_eq!(rx.packets(), 1);
        }
        other => panic!("forged padding {forged}: {other:?}"),
    }
}

fn structured(data: &[u8]) {
    let mut cur = Cursor::new(data);
    let flags = cur.u8();
    let key: [u8; KEY_LEN] = cur.take_filled(KEY_LEN, 3).try_into().expect("16");
    let mut iv: [u8; NONCE_LEN] = cur.take_filled(NONCE_LEN, 5).try_into().expect("12");
    // Keep the general path away from the counter's last value (a seal there
    // is correctly refused); `check_counter_boundary` covers that edge.
    iv[4] &= 0x7f;
    let pad_seed = u64::from(cur.u8());
    let limits = limits_from(flags, &mut cur);
    let n = usize::from(cur.u8()) % 6;
    let mut payloads: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            let len = usize::from(cur.u16()) % 1200;
            cur.take_filled(len, 100 + i as u32)
        })
        .collect();
    if flags & 8 != 0 {
        payloads.push(filler(CAP_PAYLOAD_LEN, 77));
    }
    let n_sched = usize::from(cur.u8()) % 8;
    let sched = cur.take(n_sched).to_vec();
    let mode = ChunkMode::from_selector(flags >> 4, &sched);
    let mut_sel = cur.u8();
    let xor = cur.u8() | 1;
    let fuzz_len: [u8; 4] = cur.take_filled(4, 9).try_into().expect("4");
    let counter_k = cur.u8() % 4;
    let forged_padding = cur.u8();

    check_length_rules(&key, &iv, &limits, fuzz_len);
    if flags & 4 != 0 {
        let sample = payloads.first().cloned().unwrap_or_else(|| vec![21]);
        if sample.len() < 1200 {
            check_counter_boundary(&key, &iv, counter_k, &sample, &limits);
        }
    }

    let sealed = seal_all(&key, &iv, pad_seed, &payloads);
    if flags & 8 != 0 {
        let (_, start, total) = sealed.packets.last().expect("cap payload present");
        let pl = u32::from_be_bytes(sealed.stream[*start..*start + 4].try_into().expect("4"));
        assert_eq!(pl, 65_536, "the cap payload frames to exactly 64 KiB");
        assert_eq!(*total, LENGTH_LEN + 65_536 + TAG_LEN);
    }

    // Round trip. A packet over the cap stops the stream there with
    // TooLarge; everything before it round-trips.
    let first_too_large = sealed
        .packets
        .iter()
        .position(|(p, _, _)| packet_length_of(p.len()) > limits.max_packet_length);
    let want_payloads: Vec<Vec<u8>> = sealed
        .packets
        .iter()
        .take(first_too_large.unwrap_or(sealed.packets.len()))
        .map(|(p, _, _)| p.clone())
        .collect();
    let want_err = first_too_large.map(|i| OpenError::TooLarge {
        packet_length: packet_length_of(sealed.packets[i].0.len()),
        limit: limits.max_packet_length,
    });
    for m in [&mode, &ChunkMode::ByteAtATime, &ChunkMode::All] {
        if *m == ChunkMode::ByteAtATime && sealed.stream.len() > 4096 {
            continue; // 64 KiB byte-at-a-time is pure overhead
        }
        let (got, err) = open_stream(&key, &iv, &sealed.stream, m, &limits);
        assert_eq!(got, want_payloads, "round trip under {m:?}");
        assert_eq!(err, want_err, "cap failure under {m:?}");
    }

    if flags & 0x40 != 0 && !sealed.packets.is_empty() {
        let (_, _, total) = sealed.packets[0];
        // Flip one byte of the first packet.
        let idx = usize::from(mut_sel) % total;
        let mut mutated = sealed.stream.clone();
        mutated[idx] ^= xor;
        let mut rx = AeadDirection::from_parts(&key, &iv);
        let want = expect_from_length(&mutated, limits.max_packet_length, false);
        match open_checked(&mut rx, &mut mutated, &limits) {
            Ok(None) => {
                assert!(
                    idx < LENGTH_LEN,
                    "only a length change turns a complete packet into NeedMore"
                );
                assert!(matches!(want, Expect::NeedMore(Some(_))), "{want:?}");
            }
            Ok(Some(_)) => panic!("a flipped byte at {idx} must not verify"),
            Err(e) => {
                assert_eq!(Expect::Err(e), want, "flip at {idx}");
                if idx >= LENGTH_LEN
                    && packet_length_of(sealed.packets[0].0.len()) <= limits.max_packet_length
                {
                    assert_eq!(
                        e,
                        OpenError::TagMismatch,
                        "a body or tag flip is always a tag mismatch"
                    );
                }
            }
        }
        assert_eq!(rx.packets(), 0);

        // Every proper prefix of the first packet: NeedMore, never Packet.
        if packet_length_of(sealed.packets[0].0.len()) <= limits.max_packet_length && total <= 2048
        {
            let mut rx = AeadDirection::from_parts(&key, &iv);
            for cut in 0..total {
                let mut prefix = sealed.stream[..cut].to_vec();
                let want = if cut < LENGTH_LEN { None } else { Some(total) };
                assert_eq!(
                    open_checked(&mut rx, &mut prefix, &limits),
                    Ok(None),
                    "prefix {cut}"
                );
                assert_eq!(
                    rx.open(&mut prefix, &limits),
                    Ok(OpenStep::NeedMore { total_len: want }),
                    "prefix {cut}"
                );
            }
            assert_eq!(rx.packets(), 0);
        }

        let sample = &sealed.packets[0].0;
        if sample.len() < 1200 {
            check_bad_padding(&key, &iv, sample, forged_padding, &limits);
        }
    }

    if flags & 0x80 != 0 {
        // A raw fuzz stream follows the length model and never verifies.
        let raw = cur.rest();
        let mut rx = AeadDirection::from_parts(&key, &iv);
        let mut buf = raw.to_vec();
        let want = expect_from_length(&buf, limits.max_packet_length, false);
        match open_checked(&mut rx, &mut buf, &limits) {
            Ok(None) => assert!(matches!(want, Expect::NeedMore(_))),
            Ok(Some(_)) => panic!("a raw fuzz stream verified"),
            Err(e) => assert_eq!(Expect::Err(e), want),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    structured(data);
});
