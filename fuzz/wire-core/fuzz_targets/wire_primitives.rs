#![no_main]
//! `Reader` / `Writer` / `NameList` against an independent cursor model.
//!
//! Input layout (self-describing so seeds are readable):
//! `ilen:u16be, input[ilen], cap:u16be, then ops until the data runs out`.
//! Each op is `code:u8` (`code % 15`) followed by its arguments:
//!  0 read_u8         1 read_bool     2 read_u32     3 read_u64
//!  4 read_string     5 read_name_list
//!  6 read_bytes      n:u16be (mod 1025)
//!  7 finish
//!  8 write_u8 v:u8   9 write_bool v:u8 (bit 0)
//! 10 write_u32 v:u32le              11 write_u64 v:u64le
//! 12 write_string len:u16be (mod 513), bytes
//! 13 write_name_list count:u8 (mod 9), sanitize_mask:u8, then per name
//!    len:u8 (mod 33), bytes  (bit i of the mask maps name i onto the name
//!    alphabet; unmasked names are raw and may be invalid)
//! 14 write_bytes len:u16be (mod 513), bytes
//!
//! Reader oracles: expected value / error (with exact `needed`, `available`,
//! `claimed`, name-list offset) computed from the raw bytes; the position
//! advances by exactly the encoded size on success and is unchanged on
//! error; `remaining`/`remaining_len`/`is_empty`/`finish` agree with the
//! model. Name lists: iteration re-joins to the body, no name is empty,
//! `len()` equals the count, `contains` agrees with a linear search.
//!
//! Writer oracles: `written()` equals a `Vec` model after every op; failures
//! leave it unchanged and carry exact `needed`/`available`; `write_bool(true)`
//! is exactly `1`; `write_name_list` rejects the FIRST invalid name with its
//! index and otherwise produces `u32 len + comma-joined body`.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use tatami_fuzz_wire_core::bytes::{be_u32, be_u64};
use tatami_fuzz_wire_core::generate;
use tatami_fuzz_wire_core::namelist_ref;
use tatami_wire::namelist;
use tatami_wire::primitives::TrailingBytes;
use tatami_wire::{DecodeError, EncodeError, NameList, Reader, Writer};

const MAX_OPS: usize = 64;
const MAX_INPUT: usize = 2048;
const MAX_CAPACITY: u16 = 1024;
const MAX_READ_BYTES: u16 = 1024;
const MAX_STRING: usize = 512;
const MAX_NAMES: u16 = 8;
const MAX_NAME: usize = 32;

#[derive(Debug)]
enum Op {
    ReadU8,
    ReadBool,
    ReadU32,
    ReadU64,
    ReadString,
    ReadNameList,
    ReadBytes(usize),
    Finish,
    WriteU8(u8),
    WriteBool(bool),
    WriteU32(u32),
    WriteU64(u64),
    WriteString(Vec<u8>),
    WriteNameList(Vec<Vec<u8>>),
    WriteBytes(Vec<u8>),
}

#[derive(Debug)]
struct Script {
    input: Vec<u8>,
    capacity: usize,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for Script {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let input = generate::bounded_bytes(u, MAX_INPUT);
        let capacity = generate::small(u, MAX_CAPACITY);
        let mut ops = Vec::new();
        while !u.is_empty() && ops.len() < MAX_OPS {
            let op = match generate::byte(u) % 15 {
                0 => Op::ReadU8,
                1 => Op::ReadBool,
                2 => Op::ReadU32,
                3 => Op::ReadU64,
                4 => Op::ReadString,
                5 => Op::ReadNameList,
                6 => Op::ReadBytes(generate::small(u, MAX_READ_BYTES)),
                7 => Op::Finish,
                8 => Op::WriteU8(generate::byte(u)),
                9 => Op::WriteBool(generate::byte(u) & 1 == 1),
                10 => Op::WriteU32(generate::word(u)),
                11 => Op::WriteU64(generate::qword(u)),
                12 => Op::WriteString(generate::bounded_bytes(u, MAX_STRING)),
                13 => {
                    let count = generate::small(u, MAX_NAMES);
                    let mask = generate::byte(u);
                    let mut names = Vec::with_capacity(count);
                    for i in 0..count {
                        let mut name = generate::bounded_bytes(u, MAX_NAME);
                        if mask & (1 << i) != 0 {
                            namelist_ref::sanitize_name(&mut name);
                        }
                        names.push(name);
                    }
                    Op::WriteNameList(names)
                }
                _ => Op::WriteBytes(generate::bounded_bytes(u, MAX_STRING)),
            };
            ops.push(op);
        }
        Ok(Script {
            input,
            capacity,
            ops,
        })
    }
}

/// Reader-side model: only the expected position; every expectation is
/// recomputed from the raw input.
struct ReadModel<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> ReadModel<'a> {
    fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Expected outcome of a fixed-width read of `n` bytes.
    fn fixed(&self, n: usize) -> Result<&'a [u8], DecodeError> {
        let available = self.remaining();
        if n > available {
            Err(DecodeError::Truncated {
                needed: n,
                available,
            })
        } else {
            Ok(&self.input[self.pos..self.pos + n])
        }
    }

    /// Expected outcome of a `string` read: `(bytes, total consumed)`.
    fn string(&self) -> Result<(&'a [u8], usize), DecodeError> {
        let available = self.remaining();
        if available < 4 {
            return Err(DecodeError::Truncated {
                needed: 4,
                available,
            });
        }
        let claimed = be_u32(&self.input[self.pos..self.pos + 4]);
        let after = available - 4;
        if claimed as usize > after {
            return Err(DecodeError::LengthOverflow {
                claimed,
                available: after,
            });
        }
        let start = self.pos + 4;
        let len = claimed as usize;
        Ok((&self.input[start..start + len], 4 + len))
    }

    fn check_state(&self, r: &Reader<'_>) {
        assert_eq!(r.position(), self.pos, "position");
        assert_eq!(r.remaining(), &self.input[self.pos..], "remaining");
        assert_eq!(r.remaining_len(), self.remaining(), "remaining_len");
        assert_eq!(r.is_empty(), self.pos == self.input.len(), "is_empty");
    }
}

/// Applies `expected` to the production result and moves the model.
fn expect_read<T: PartialEq + core::fmt::Debug>(
    model: &mut ReadModel<'_>,
    r: &Reader<'_>,
    got: Result<T, DecodeError>,
    expected: Result<(T, usize), DecodeError>,
    what: &str,
) {
    match expected {
        Ok((value, consumed)) => {
            assert_eq!(got, Ok(value), "{what}: value");
            model.pos += consumed;
        }
        Err(e) => {
            assert_eq!(got, Err(e), "{what}: error");
        }
    }
    model.check_state(r);
}

/// Every `NameList` view must agree with the reference names.
fn check_name_list(list: NameList<'_>, body: &[u8], names: &[&[u8]]) {
    assert_eq!(list.as_bytes(), body, "as_bytes");
    assert_eq!(list.as_str().as_bytes(), body, "as_str");
    assert_eq!(list.is_empty(), body.is_empty(), "is_empty");
    assert_eq!(
        list,
        NameList::parse(body).expect("reference accepted body")
    );
    if body.is_empty() {
        assert_eq!(list, NameList::EMPTY);
    }

    let iterated: Vec<&[u8]> = list.iter().collect();
    assert_eq!(iterated, names, "iteration order/content");
    let via_into: Vec<&[u8]> = list.into_iter().collect();
    assert_eq!(via_into, names, "IntoIterator");
    let via_ref: Vec<&[u8]> = (&list).into_iter().collect();
    assert_eq!(via_ref, names, "IntoIterator for &NameList");
    assert_eq!(list.len(), names.len(), "len()");
    assert!(iterated.iter().all(|n| !n.is_empty()), "empty name yielded");
    assert!(
        iterated.iter().all(|n| namelist::is_valid_name(n)),
        "invalid name yielded"
    );
    assert_eq!(
        namelist_ref::join(&iterated),
        body,
        "names must re-join to body"
    );

    for n in &iterated {
        assert!(list.contains(n), "contains({n:?}) for a present name");
        let mut probe = n.to_vec();
        probe.push(b'!');
        assert_eq!(
            list.contains(&probe),
            iterated.iter().any(|x| *x == &probe[..]),
            "contains(extended probe)"
        );
        let shorter = &n[..n.len() - 1];
        assert_eq!(
            list.contains(shorter),
            iterated.contains(&shorter),
            "contains(shortened probe)"
        );
    }
    assert!(!list.contains(b""), "contains(empty) must be false");
    assert_eq!(
        list.contains(b"none"),
        iterated.iter().any(|x| *x == b"none"),
        "contains(\"none\")"
    );
}

fuzz_target!(|script: Script| {
    let input = &script.input[..];
    let mut r = Reader::new(input);
    let mut model = ReadModel { input, pos: 0 };
    model.check_state(&r);

    let mut buf = vec![0u8; script.capacity];
    let mut w = Writer::new(&mut buf);
    let mut wmodel: Vec<u8> = Vec::with_capacity(script.capacity);
    assert_eq!(w.capacity_remaining(), script.capacity);

    for op in &script.ops {
        match op {
            Op::ReadU8 => {
                let expected = model.fixed(1).map(|b| (b[0], 1));
                let got = r.read_u8();
                expect_read(&mut model, &r, got, expected, "read_u8");
            }
            Op::ReadBool => {
                let expected = model.fixed(1).map(|b| (b[0] != 0, 1));
                let got = r.read_bool();
                expect_read(&mut model, &r, got, expected, "read_bool");
            }
            Op::ReadU32 => {
                let expected = model.fixed(4).map(|b| (be_u32(b), 4));
                let got = r.read_u32();
                expect_read(&mut model, &r, got, expected, "read_u32");
            }
            Op::ReadU64 => {
                let expected = model.fixed(8).map(|b| (be_u64(b), 8));
                let got = r.read_u64();
                expect_read(&mut model, &r, got, expected, "read_u64");
            }
            Op::ReadBytes(n) => {
                let expected = model.fixed(*n).map(|b| (b, *n));
                let got = r.read_bytes(*n);
                expect_read(&mut model, &r, got, expected, "read_bytes");
            }
            Op::ReadString => {
                let expected = model.string();
                let got = r.read_string();
                expect_read(&mut model, &r, got, expected, "read_string");
            }
            Op::ReadNameList => {
                let expected = match model.string() {
                    Err(e) => Err(e),
                    Ok((body, consumed)) => match namelist_ref::parse(body) {
                        Ok(names) => Ok((body, names, consumed)),
                        Err(e) => Err(DecodeError::InvalidEncoding(e)),
                    },
                };
                let got = r.read_name_list();
                match expected {
                    Ok((body, names, consumed)) => {
                        let list = got.unwrap_or_else(|e| {
                            panic!("read_name_list rejected valid body {body:?}: {e:?}")
                        });
                        check_name_list(list, body, &names);
                        model.pos += consumed;
                    }
                    Err(e) => assert_eq!(got, Err(e), "read_name_list: error"),
                }
                model.check_state(&r);
            }
            Op::Finish => {
                let expected = if model.remaining() == 0 {
                    Ok(())
                } else {
                    Err(TrailingBytes {
                        count: model.remaining(),
                    })
                };
                assert_eq!(r.finish(), expected, "finish");
                model.check_state(&r);
            }
            Op::WriteU8(v) => write_fixed(&mut w, &mut wmodel, &[*v], w_u8(*v), "write_u8"),
            Op::WriteBool(v) => {
                let byte = [if *v { 1 } else { 0 }];
                write_fixed(&mut w, &mut wmodel, &byte, w_bool(*v), "write_bool");
            }
            Op::WriteU32(v) => {
                let mut e = Vec::new();
                tatami_fuzz_wire_core::bytes::put_u32(&mut e, *v);
                write_fixed(&mut w, &mut wmodel, &e, w_u32(*v), "write_u32");
            }
            Op::WriteU64(v) => {
                let mut e = Vec::new();
                tatami_fuzz_wire_core::bytes::put_u64(&mut e, *v);
                write_fixed(&mut w, &mut wmodel, &e, w_u64(*v), "write_u64");
            }
            Op::WriteBytes(b) => write_fixed(&mut w, &mut wmodel, b, w_bytes(b), "write_bytes"),
            Op::WriteString(s) => {
                let mut e = Vec::new();
                tatami_fuzz_wire_core::bytes::put_string(&mut e, s);
                write_fixed(&mut w, &mut wmodel, &e, w_string(s), "write_string");
            }
            Op::WriteNameList(names) => {
                for n in names {
                    assert_eq!(
                        namelist::is_valid_name(n),
                        namelist_ref::is_valid_name(n),
                        "is_valid_name({n:?})"
                    );
                    for &b in n {
                        assert_eq!(
                            namelist::is_name_byte(b),
                            namelist_ref::is_printable(b) && b != b',',
                            "is_name_byte({b:#04x})"
                        );
                    }
                }
                let first_bad = names.iter().position(|n| !namelist_ref::is_valid_name(n));
                let got = w.write_name_list(names.iter());
                match first_bad {
                    Some(index) => {
                        assert_eq!(
                            got,
                            Err(EncodeError::InvalidName { index }),
                            "write_name_list must reject the first invalid name"
                        );
                    }
                    None => {
                        let mut e = Vec::new();
                        tatami_fuzz_wire_core::bytes::put_name_list(&mut e, names);
                        let needed = e.len();
                        let available = script.capacity - wmodel.len();
                        if needed > available {
                            assert_eq!(
                                got,
                                Err(EncodeError::InsufficientCapacity { needed, available }),
                                "write_name_list: capacity"
                            );
                        } else {
                            assert_eq!(got, Ok(()), "write_name_list");
                            wmodel.extend_from_slice(&e);
                            // The bytes we just modelled must read back as the
                            // same names through the production reader.
                            let mut back = Reader::new(&e);
                            let list = back.read_name_list().expect("model bytes are valid");
                            let expect_names: Vec<&[u8]> = names.iter().map(|n| &n[..]).collect();
                            check_name_list(list, &e[4..], &expect_names);
                            assert!(back.is_empty());
                        }
                    }
                }
                check_writer(&w, &wmodel, script.capacity);
            }
        }
    }

    model.check_state(&r);
    check_writer(&w, &wmodel, script.capacity);
    let final_written = w.into_written();
    assert_eq!(final_written, &wmodel[..], "into_written");
});

type WriteOp<'w> = Box<dyn FnOnce(&mut Writer<'_>) -> Result<(), EncodeError> + 'w>;

fn w_u8(v: u8) -> WriteOp<'static> {
    Box::new(move |w| w.write_u8(v))
}
fn w_bool(v: bool) -> WriteOp<'static> {
    Box::new(move |w| w.write_bool(v))
}
fn w_u32(v: u32) -> WriteOp<'static> {
    Box::new(move |w| w.write_u32(v))
}
fn w_u64(v: u64) -> WriteOp<'static> {
    Box::new(move |w| w.write_u64(v))
}
fn w_bytes(b: &[u8]) -> WriteOp<'_> {
    Box::new(move |w| w.write_bytes(b))
}
fn w_string(b: &[u8]) -> WriteOp<'_> {
    Box::new(move |w| w.write_string(b))
}

fn check_writer(w: &Writer<'_>, model: &[u8], capacity: usize) {
    assert_eq!(w.written(), model, "written()");
    assert_eq!(w.position(), model.len(), "position()");
    assert_eq!(
        w.capacity_remaining(),
        capacity - model.len(),
        "capacity_remaining()"
    );
}

/// Runs a write whose exact output bytes are `expected`; the write must
/// succeed iff they fit, and fail with the exact capacity report otherwise.
fn write_fixed(
    w: &mut Writer<'_>,
    model: &mut Vec<u8>,
    expected: &[u8],
    op: WriteOp<'_>,
    what: &str,
) {
    let capacity = w.position() + w.capacity_remaining();
    let available = capacity - model.len();
    let got = op(w);
    if expected.len() > available {
        assert_eq!(
            got,
            Err(EncodeError::InsufficientCapacity {
                needed: expected.len(),
                available
            }),
            "{what}: capacity error"
        );
    } else {
        assert_eq!(got, Ok(()), "{what}");
        model.extend_from_slice(expected);
    }
    check_writer(w, model, capacity);
}
