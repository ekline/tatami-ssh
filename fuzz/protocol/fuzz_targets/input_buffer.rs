#![no_main]
//! `tatami_tcp::initial::InputBuffer` against a `Vec<u8>` + capacity model.
//!
//! # Input layout
//!
//! ```text
//! cap u16 (mod 8193)                      buffer capacity, 0..=8192
//! then up to 256 operations, each:
//!   kind u8, kind mod 4 =
//!     0 push:     len u16 (mod 4097), then len data bytes (filler when the
//!                 input runs out, so the length still matters)
//!     1 consume:  n u16, reduced to n mod (len + 1) so n <= len always
//!     2 clear
//!     3 boundary push, (kind >> 2) mod 4 =
//!                 0 exactly room() bytes; 1 room() + 1 bytes;
//!                 2 zero bytes; 3 cap + 1 bytes (filler data)
//! ```
//!
//! `consume(n)` is only ever called with `n <= len()`: the documented
//! precondition of an internal helper. Calling it with more is harness
//! misuse (the production callers pass counts the decoders derived from the
//! buffer itself), not a network-reachable path, so it is not fuzzed.
//!
//! # Oracles (after every operation)
//!
//! - `as_slice()`, `len()`, `is_empty()`, `room()` and `capacity()` equal
//!   the model (`room == cap - len`, so the logical length never exceeds the
//!   declared bound).
//! - `push` fails iff `len + data.len() > cap`, with `InputOverflow {
//!   capacity, pending, offered }` exactly, and leaves the contents unchanged
//!   (no partial append). Otherwise the bytes are appended verbatim.
//! - `consume(n)` removes exactly the first `n` bytes; `clear` empties.
//! - Only the logical length is asserted; `Vec` allocator capacity is not
//!   part of the contract and is never inspected.

use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::tcp_support::Cursor;
use tatami_tcp::initial::{InputBuffer, InputOverflow};

const MAX_OPS: usize = 256;

fn check(buf: &InputBuffer, model: &[u8], cap: usize) {
    assert_eq!(buf.as_slice(), model, "contents");
    assert_eq!(buf.len(), model.len(), "len");
    assert_eq!(buf.is_empty(), model.is_empty(), "is_empty");
    assert_eq!(buf.capacity(), cap, "capacity");
    assert_eq!(buf.room(), cap - model.len(), "room");
    assert!(
        buf.len() <= cap,
        "logical length exceeds the declared bound"
    );
    assert_eq!(buf.len() + buf.room(), cap);
}

fn push(buf: &mut InputBuffer, model: &mut Vec<u8>, cap: usize, data: &[u8]) {
    let before = model.clone();
    let result = buf.push(data);
    if before.len() + data.len() > cap {
        assert_eq!(
            result,
            Err(InputOverflow {
                capacity: cap,
                pending: before.len(),
                offered: data.len(),
            }),
            "overflow must be reported exactly"
        );
        assert_eq!(
            buf.as_slice(),
            &before[..],
            "overflow must not append anything"
        );
    } else {
        assert_eq!(result, Ok(()), "push within room must succeed");
        model.extend_from_slice(data);
    }
    check(buf, model, cap);
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let cap = usize::from(cur.u16()) % 8193;
    let mut buf = InputBuffer::new(cap);
    let mut model: Vec<u8> = Vec::new();
    check(&buf, &model, cap);

    for i in 0..MAX_OPS {
        if cur.is_empty() {
            break;
        }
        let kind = cur.u8();
        match kind % 4 {
            0 => {
                let len = usize::from(cur.u16()) % 4097;
                let bytes = cur.take_filled(len, i as u32);
                push(&mut buf, &mut model, cap, &bytes);
            }
            1 => {
                let n = usize::from(cur.u16()) % (model.len() + 1);
                buf.consume(n);
                model.drain(..n);
                check(&buf, &model, cap);
            }
            2 => {
                buf.clear();
                model.clear();
                check(&buf, &model, cap);
            }
            _ => {
                let len = match (kind >> 2) % 4 {
                    0 => buf.room(),
                    1 => buf.room() + 1,
                    2 => 0,
                    _ => cap + 1,
                };
                let bytes = cur.take_filled(len, 0x1000 + i as u32);
                push(&mut buf, &mut model, cap, &bytes);
            }
        }
    }
});
