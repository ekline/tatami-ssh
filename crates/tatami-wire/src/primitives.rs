//! Checked reader and writer for the SSH primitive types of RFC 4251 §5.
//!
//! Both types are allocation-free. The reader borrows its input and the
//! writer fills a caller-supplied buffer.
//!
//! # Cursor contract
//!
//! Every `read_*` / `write_*` method is atomic with respect to the cursor: on
//! success exactly the encoded value is consumed or produced; on failure the
//! cursor is unchanged. Callers may therefore retry, inspect
//! [`Reader::position`], or fall back to another interpretation after an
//! error without accounting for partial progress.

use crate::error::{DecodeError, EncodeError};
use crate::namelist::{NameList, is_valid_name};

/// Borrowed cursor over an already delimited SSH payload.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at the start of `input`.
    #[must_use]
    pub const fn new(input: &'a [u8]) -> Self {
        Reader { input, pos: 0 }
    }

    /// Current offset from the start of the input.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    /// Number of bytes not yet consumed.
    #[must_use]
    pub const fn remaining_len(&self) -> usize {
        self.input.len() - self.pos
    }

    /// Returns `true` when every byte has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.pos == self.input.len()
    }

    /// Consumes exactly `n` bytes.
    pub fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let available = self.remaining_len();
        if n > available {
            return Err(DecodeError::Truncated {
                needed: n,
                available,
            });
        }
        let out = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Reads a `byte`.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_bytes(1)?[0])
    }

    /// Reads a `boolean`. Any nonzero value decodes as `true` (RFC 4251 §5).
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.read_u8()? != 0)
    }

    /// Reads a network-order `uint32`.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Reads a network-order `uint64`.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a `string`: a `uint32` length followed by that many arbitrary
    /// bytes. No text encoding is imposed.
    pub fn read_string(&mut self) -> Result<&'a [u8], DecodeError> {
        let start = self.pos;
        let len = self.read_u32()?;
        let available = self.remaining_len();
        let Ok(len_usize) = usize::try_from(len) else {
            self.pos = start;
            return Err(DecodeError::LengthOverflow {
                claimed: len,
                available,
            });
        };
        if len_usize > available {
            self.pos = start;
            return Err(DecodeError::LengthOverflow {
                claimed: len,
                available,
            });
        }
        // Cannot fail: bounds were checked above.
        let out = &self.input[self.pos..self.pos + len_usize];
        self.pos += len_usize;
        Ok(out)
    }

    /// Reads an `mpint` (RFC 4251 §5) and borrows its raw two's-complement
    /// bytes.
    ///
    /// No canonical-form check is applied here; RFC 4251 forbids unnecessary
    /// leading `0x00`/`0xff` bytes, and callers that care call
    /// [`Mpint::is_canonical`]. An empty body is the value zero.
    pub fn read_mpint(&mut self) -> Result<Mpint<'a>, DecodeError> {
        self.read_string().map(|bytes| Mpint { bytes })
    }

    /// Reads a `name-list` and validates its syntax without allocating.
    ///
    /// An empty list is valid at this level; individual messages decide
    /// whether a particular field may be empty.
    pub fn read_name_list(&mut self) -> Result<NameList<'a>, DecodeError> {
        let start = self.pos;
        let body = self.read_string()?;
        match NameList::parse(body) {
            Ok(list) => Ok(list),
            Err(e) => {
                self.pos = start;
                Err(DecodeError::InvalidEncoding(e))
            }
        }
    }

    /// Fails unless the input is fully consumed.
    ///
    /// Callers use this to reject unexpected trailing bytes after a complete
    /// message. The cursor is unchanged either way.
    pub fn finish(&self) -> Result<(), TrailingBytes> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(TrailingBytes {
                count: self.remaining_len(),
            })
        }
    }
}

/// Borrowed `mpint` (RFC 4251 §5): a multiple-precision integer in
/// two's-complement, network byte order, carried in a `string`.
///
/// The bytes are exposed exactly as received. Interpretation (sign,
/// canonical form, magnitude) is provided by inspection methods so that a
/// key-exchange driver can both hash the received encoding verbatim and
/// reject values that violate the encoding rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mpint<'a> {
    bytes: &'a [u8],
}

impl<'a> Mpint<'a> {
    /// The two's-complement bytes, without the length prefix.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns `true` for the empty encoding, which is the value zero.
    ///
    /// A non-empty encoding consisting only of zero bytes is *not* reported
    /// as zero here; it is non-canonical (see [`Mpint::is_canonical`]).
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns `true` when the sign bit of the first byte is set.
    /// Zero (empty) is not negative.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        match self.bytes.first() {
            Some(&b) => b & 0x80 != 0,
            None => false,
        }
    }

    /// Returns `true` when the encoding is the unique minimal one required
    /// by RFC 4251 §5: zero is empty, and no unnecessary leading `0x00` or
    /// `0xff` byte is present.
    ///
    /// Concretely: an empty encoding is canonical; a leading `0x00` is
    /// allowed only when the next byte has its high bit set; a leading
    /// `0xff` is allowed only when the next byte has its high bit clear.
    #[must_use]
    pub const fn is_canonical(&self) -> bool {
        match self.bytes {
            [] => true,
            // Zero must be empty; a lone 0x00 is a redundant leading byte.
            [0x00] => false,
            [0x00, next, ..] => *next & 0x80 != 0,
            [0xff, next, ..] => *next & 0x80 == 0,
            // Includes the lone 0xff, which is the canonical -1.
            _ => true,
        }
    }

    /// The unsigned big-endian magnitude of a non-negative value with all
    /// leading zero bytes removed (empty for zero), or `None` when the
    /// value is negative.
    ///
    /// This is the form a shared secret or public value is compared and
    /// range-checked in; hashing must still use [`Mpint::as_bytes`].
    #[must_use]
    pub fn positive_magnitude(&self) -> Option<&'a [u8]> {
        if self.is_negative() {
            None
        } else {
            Some(strip_leading_zeros(self.bytes))
        }
    }
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

/// Encoded length, including the 4-byte prefix, of the positive `mpint`
/// that [`Writer::write_mpint_positive`] produces for `magnitude`.
#[must_use]
pub fn mpint_positive_len(magnitude: &[u8]) -> usize {
    let m = strip_leading_zeros(magnitude);
    match m.first() {
        None => 4,
        Some(&b) => 4 + m.len() + usize::from(b & 0x80 != 0),
    }
}

/// Returned by [`Reader::finish`] when bytes remain after a complete message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrailingBytes {
    /// Number of unconsumed bytes.
    pub count: usize,
}

impl core::fmt::Display for TrailingBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} unexpected trailing byte(s)", self.count)
    }
}

impl core::error::Error for TrailingBytes {}

/// Cursor that encodes SSH primitives into a caller-supplied buffer.
#[derive(Debug)]
pub struct Writer<'a> {
    out: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Creates a writer positioned at the start of `out`.
    pub fn new(out: &'a mut [u8]) -> Self {
        Writer { out, pos: 0 }
    }

    /// Number of bytes written so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes still available in the output buffer.
    #[must_use]
    pub const fn capacity_remaining(&self) -> usize {
        self.out.len() - self.pos
    }

    /// The bytes written so far.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.out[..self.pos]
    }

    /// Consumes the writer and returns the written prefix of the buffer.
    #[must_use]
    pub fn into_written(self) -> &'a mut [u8] {
        &mut self.out[..self.pos]
    }

    fn reserve(&mut self, needed: usize) -> Result<(), EncodeError> {
        let available = self.capacity_remaining();
        if needed > available {
            Err(EncodeError::InsufficientCapacity { needed, available })
        } else {
            Ok(())
        }
    }

    /// Writes raw bytes with no length prefix.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        self.reserve(bytes.len())?;
        self.out[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
        Ok(())
    }

    /// Writes a `byte`.
    pub fn write_u8(&mut self, v: u8) -> Result<(), EncodeError> {
        self.write_bytes(&[v])
    }

    /// Writes a `boolean` as exactly `0` or `1`.
    pub fn write_bool(&mut self, v: bool) -> Result<(), EncodeError> {
        self.write_u8(u8::from(v))
    }

    /// Writes a network-order `uint32`.
    pub fn write_u32(&mut self, v: u32) -> Result<(), EncodeError> {
        self.write_bytes(&v.to_be_bytes())
    }

    /// Writes a network-order `uint64`.
    pub fn write_u64(&mut self, v: u64) -> Result<(), EncodeError> {
        self.write_bytes(&v.to_be_bytes())
    }

    /// Writes a `string`: `uint32` length followed by the bytes.
    pub fn write_string(&mut self, bytes: &[u8]) -> Result<(), EncodeError> {
        let len = u32::try_from(bytes.len())
            .map_err(|_| EncodeError::LengthOverflow { len: bytes.len() })?;
        self.reserve(4 + bytes.len())?;
        // Both writes are now infallible.
        let _ = self.write_u32(len);
        let _ = self.write_bytes(bytes);
        Ok(())
    }

    /// Writes an unsigned big-endian `magnitude` as a positive `mpint`
    /// (RFC 4251 §5).
    ///
    /// Leading zero bytes are stripped; an all-zero (or empty) magnitude is
    /// written as the empty `mpint` (length 0); when the high bit of the
    /// first remaining byte is set a `0x00` byte is prepended so the value
    /// stays positive. The result is always canonical.
    pub fn write_mpint_positive(&mut self, magnitude: &[u8]) -> Result<(), EncodeError> {
        let m = strip_leading_zeros(magnitude);
        let pad = m.first().is_some_and(|&b| b & 0x80 != 0);
        let body_len = m.len() + usize::from(pad);
        let len =
            u32::try_from(body_len).map_err(|_| EncodeError::LengthOverflow { len: body_len })?;
        self.reserve(4 + body_len)?;
        // Infallible from here on.
        let _ = self.write_u32(len);
        if pad {
            let _ = self.write_u8(0);
        }
        let _ = self.write_bytes(m);
        Ok(())
    }

    /// Writes a `name-list` from an iterator of names, validating each name
    /// and inserting separators. The iterator is consumed twice, so it must
    /// be `Clone` and deterministic.
    pub fn write_name_list<I, S>(&mut self, names: I) -> Result<(), EncodeError>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<[u8]>,
    {
        let mut body_len = 0usize;
        for (index, name) in names.clone().into_iter().enumerate() {
            let name = name.as_ref();
            if !is_valid_name(name) {
                return Err(EncodeError::InvalidName { index });
            }
            if index > 0 {
                body_len += 1;
            }
            body_len += name.len();
        }
        let len =
            u32::try_from(body_len).map_err(|_| EncodeError::LengthOverflow { len: body_len })?;
        self.reserve(4 + body_len)?;
        // Infallible from here on.
        let _ = self.write_u32(len);
        for (index, name) in names.into_iter().enumerate() {
            if index > 0 {
                let _ = self.write_u8(b',');
            }
            let _ = self.write_bytes(name.as_ref());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::InvalidEncoding;

    #[test]
    fn reads_fixed_width_values() {
        let input = [
            0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        ];
        let mut r = Reader::new(&input);
        assert_eq!(r.read_u8().unwrap(), 1);
        assert_eq!(r.read_u32().unwrap(), 0x0000_0001);
        assert_eq!(r.read_u32().unwrap(), 0x0203_0405);
        assert_eq!(
            r.read_u32(),
            Err(DecodeError::Truncated {
                needed: 4,
                available: 3
            })
        );
        assert_eq!(r.position(), 9, "failed read must not advance");
        assert_eq!(r.read_bytes(3).unwrap(), &[6, 7, 8]);
        assert!(r.finish().is_ok());
    }

    #[test]
    fn reads_u64() {
        let input = 0x0102_0304_0506_0708u64.to_be_bytes();
        let mut r = Reader::new(&input);
        assert_eq!(r.read_u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(r.is_empty());
    }

    #[test]
    fn noncanonical_boolean_is_true() {
        assert!(Reader::new(&[0xff]).read_bool().unwrap());
        assert!(Reader::new(&[0x02]).read_bool().unwrap());
        assert!(!Reader::new(&[0x00]).read_bool().unwrap());
    }

    #[test]
    fn reads_string_with_arbitrary_bytes() {
        let input = [0, 0, 0, 3, 0xff, 0x00, b'a', 9];
        let mut r = Reader::new(&input);
        assert_eq!(r.read_string().unwrap(), &[0xff, 0x00, b'a']);
        assert_eq!(r.remaining(), &[9]);
    }

    #[test]
    fn string_length_overflow_is_reported_without_consuming() {
        let input = [0, 0, 0, 5, 1, 2];
        let mut r = Reader::new(&input);
        assert_eq!(
            r.read_string(),
            Err(DecodeError::LengthOverflow {
                claimed: 5,
                available: 2
            })
        );
        assert_eq!(r.position(), 0);

        let huge = [0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            Reader::new(&huge).read_string(),
            Err(DecodeError::LengthOverflow {
                claimed: u32::MAX,
                available: 0
            })
        );
    }

    #[test]
    fn string_truncated_in_length_prefix() {
        let mut r = Reader::new(&[0, 0, 0]);
        assert_eq!(
            r.read_string(),
            Err(DecodeError::Truncated {
                needed: 4,
                available: 3
            })
        );
    }

    #[test]
    fn name_list_round_trip_and_validation() {
        let input = [0, 0, 0, 7, b'a', b'b', b',', b'c', b'd', b'e', b'f'];
        let mut r = Reader::new(&input);
        let list = r.read_name_list().unwrap();
        let names: [&[u8]; 2] = [b"ab", b"cdef"];
        assert!(list.iter().eq(names.iter().copied()));

        let bad = [0, 0, 0, 3, b'a', b',', b','];
        let mut r = Reader::new(&bad);
        assert_eq!(
            r.read_name_list(),
            Err(DecodeError::InvalidEncoding(
                InvalidEncoding::NameListEmptyName { offset: 2 }
            ))
        );
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn empty_name_list_is_valid() {
        let mut r = Reader::new(&[0, 0, 0, 0]);
        let list = r.read_name_list().unwrap();
        assert!(list.is_empty());
        assert_eq!(list.iter().count(), 0);
    }

    #[test]
    fn finish_reports_trailing_bytes() {
        let r = Reader::new(&[1, 2]);
        assert_eq!(r.finish(), Err(TrailingBytes { count: 2 }));
    }

    #[test]
    fn writer_encodes_and_reports_capacity() {
        let mut buf = [0u8; 16];
        let mut w = Writer::new(&mut buf);
        w.write_u8(7).unwrap();
        w.write_bool(true).unwrap();
        w.write_bool(false).unwrap();
        w.write_u32(0x0102_0304).unwrap();
        w.write_string(b"hi").unwrap();
        assert_eq!(w.position(), 13);
        assert_eq!(
            w.write_u32(1),
            Err(EncodeError::InsufficientCapacity {
                needed: 4,
                available: 3
            })
        );
        assert_eq!(w.position(), 13, "failed write must not advance");
        assert_eq!(w.written(), &[7, 1, 0, 1, 2, 3, 4, 0, 0, 0, 2, b'h', b'i']);
    }

    #[test]
    fn writer_string_too_large_for_buffer_writes_nothing() {
        let mut buf = [0u8; 5];
        let mut w = Writer::new(&mut buf);
        assert_eq!(
            w.write_string(b"abc"),
            Err(EncodeError::InsufficientCapacity {
                needed: 7,
                available: 5
            })
        );
        assert_eq!(w.position(), 0);
    }

    #[test]
    fn writer_name_list() {
        let mut buf = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        w.write_name_list([&b"a"[..], b"bc"]).unwrap();
        assert_eq!(w.written(), &[0, 0, 0, 4, b'a', b',', b'b', b'c']);

        let mut w = Writer::new(&mut buf);
        w.write_name_list::<[&[u8]; 0], &[u8]>([]).unwrap();
        assert_eq!(w.written(), &[0, 0, 0, 0]);

        let mut w = Writer::new(&mut buf);
        assert_eq!(
            w.write_name_list([&b"ok"[..], b"bad,name"]),
            Err(EncodeError::InvalidName { index: 1 })
        );
        assert_eq!(w.position(), 0);

        let mut w = Writer::new(&mut buf);
        assert_eq!(
            w.write_name_list([&b""[..]]),
            Err(EncodeError::InvalidName { index: 0 })
        );
    }

    #[test]
    fn u64_write_round_trip() {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        w.write_u64(0x0102_0304_0506_0708).unwrap();
        assert_eq!(
            Reader::new(w.written()).read_u64().unwrap(),
            0x0102_0304_0506_0708
        );
    }

    // The five `mpint` examples of RFC 4251 §5, transcribed from the RFC:
    //   value 0             -> 00 00 00 00
    //   9a378f9b2e332a7     -> 00 00 00 08 09 a3 78 f9 b2 e3 32 a7
    //   80                  -> 00 00 00 02 00 80
    //   -1234               -> 00 00 00 02 ed cc
    //   -deadbeef           -> 00 00 00 05 ff 21 52 41 11
    const RFC4251_ZERO: [u8; 4] = [0, 0, 0, 0];
    const RFC4251_POS: [u8; 12] = [0, 0, 0, 8, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7];
    const RFC4251_0X80: [u8; 6] = [0, 0, 0, 2, 0x00, 0x80];
    const RFC4251_NEG_1234: [u8; 6] = [0, 0, 0, 2, 0xed, 0xcc];
    const RFC4251_NEG_DEADBEEF: [u8; 9] = [0, 0, 0, 5, 0xff, 0x21, 0x52, 0x41, 0x11];

    #[test]
    fn reads_rfc4251_mpint_examples() {
        let z = Reader::new(&RFC4251_ZERO).read_mpint().unwrap();
        assert!(z.is_zero());
        assert!(!z.is_negative());
        assert!(z.is_canonical());
        assert_eq!(z.as_bytes(), &[]);
        assert_eq!(z.positive_magnitude(), Some(&[][..]));

        let mut r = Reader::new(&RFC4251_POS);
        let p = r.read_mpint().unwrap();
        assert!(r.is_empty());
        assert_eq!(
            p.as_bytes(),
            &[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
        );
        assert!(!p.is_zero());
        assert!(!p.is_negative());
        assert!(p.is_canonical());
        assert_eq!(p.positive_magnitude(), Some(p.as_bytes()));

        let h = Reader::new(&RFC4251_0X80).read_mpint().unwrap();
        assert_eq!(h.as_bytes(), &[0x00, 0x80]);
        assert!(!h.is_negative(), "leading 0x00 keeps 0x80 positive");
        assert!(h.is_canonical(), "the 0x00 is necessary here");
        assert_eq!(h.positive_magnitude(), Some(&[0x80][..]));

        let n = Reader::new(&RFC4251_NEG_1234).read_mpint().unwrap();
        assert_eq!(n.as_bytes(), &[0xed, 0xcc]);
        assert!(n.is_negative());
        assert!(n.is_canonical());
        assert_eq!(n.positive_magnitude(), None);

        let d = Reader::new(&RFC4251_NEG_DEADBEEF).read_mpint().unwrap();
        assert_eq!(d.as_bytes(), &[0xff, 0x21, 0x52, 0x41, 0x11]);
        assert!(d.is_negative());
        assert!(d.is_canonical(), "the 0xff is necessary here");
    }

    #[test]
    fn mpint_read_is_atomic_and_reports_string_errors() {
        let mut r = Reader::new(&[0, 0, 0, 3, 1]);
        assert_eq!(
            r.read_mpint(),
            Err(DecodeError::LengthOverflow {
                claimed: 3,
                available: 1
            })
        );
        assert_eq!(r.position(), 0);
    }

    #[test]
    fn mpint_noncanonical_forms_are_flagged_not_rejected() {
        // Redundant leading zero before a byte with the high bit clear.
        let m = Reader::new(&[0, 0, 0, 3, 0x00, 0x09, 0xa3])
            .read_mpint()
            .unwrap();
        assert!(!m.is_canonical());
        assert_eq!(m.positive_magnitude(), Some(&[0x09, 0xa3][..]));

        // Redundant leading 0xff before a byte with the high bit set.
        let m = Reader::new(&[0, 0, 0, 3, 0xff, 0xed, 0xcc])
            .read_mpint()
            .unwrap();
        assert!(!m.is_canonical());
        assert!(m.is_negative());

        // Zero encoded as one zero byte instead of the empty string.
        let m = Reader::new(&[0, 0, 0, 1, 0x00]).read_mpint().unwrap();
        assert!(!m.is_canonical());
        assert!(!m.is_zero(), "is_zero is about the encoding, not the value");
        assert_eq!(m.positive_magnitude(), Some(&[][..]));

        // Two zero bytes.
        let m = Reader::new(&[0, 0, 0, 2, 0x00, 0x00]).read_mpint().unwrap();
        assert!(!m.is_canonical());

        // A lone 0xff is -1 and canonical.
        let m = Reader::new(&[0, 0, 0, 1, 0xff]).read_mpint().unwrap();
        assert!(m.is_canonical());
        assert!(m.is_negative());
    }

    #[test]
    fn writes_rfc4251_positive_mpint_examples() {
        let mut buf = [0u8; 16];

        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&[]).unwrap();
        assert_eq!(w.written(), &RFC4251_ZERO);
        assert_eq!(mpint_positive_len(&[]), 4);

        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&[0x00, 0x00]).unwrap();
        assert_eq!(w.written(), &RFC4251_ZERO, "all-zero magnitude is zero");
        assert_eq!(mpint_positive_len(&[0x00, 0x00]), 4);

        let magnitude = [0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7];
        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&magnitude).unwrap();
        assert_eq!(w.written(), &RFC4251_POS);
        assert_eq!(mpint_positive_len(&magnitude), RFC4251_POS.len());

        // Same value with redundant leading zeros in the caller's magnitude.
        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&[0x00, 0x00, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7])
            .unwrap();
        assert_eq!(w.written(), &RFC4251_POS);

        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&[0x80]).unwrap();
        assert_eq!(w.written(), &RFC4251_0X80);
        assert_eq!(mpint_positive_len(&[0x80]), RFC4251_0X80.len());
    }

    #[test]
    fn mpint_positive_write_is_atomic_on_capacity_error() {
        let mut buf = [0u8; 5];
        let mut w = Writer::new(&mut buf);
        // Needs 4 + 1 (pad) + 1 = 6 bytes.
        assert_eq!(
            w.write_mpint_positive(&[0x80]),
            Err(EncodeError::InsufficientCapacity {
                needed: 6,
                available: 5
            })
        );
        assert_eq!(w.position(), 0);
    }

    /// RFC 8731 §3: the X25519 shared secret K is a 32-byte fixed-length
    /// string that MUST be re-encoded as an `mpint` (leading zeros
    /// stripped, `0x00` prepended when the high bit is set). The caller
    /// rejects an all-zero K; the codec must still encode it exactly.
    #[test]
    fn rfc8731_shared_secret_encodings() {
        let mut buf = [0u8; 40];

        // Leading zero bytes are stripped: K = 00 00 01 <29 bytes 0x42>.
        let mut k = [0x42u8; 32];
        k[0] = 0;
        k[1] = 0;
        k[2] = 0x01;
        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&k).unwrap();
        let out = w.written();
        assert_eq!(out.len(), 4 + 30);
        assert_eq!(&out[..4], &[0, 0, 0, 30]);
        assert_eq!(out[4], 0x01);
        assert!(out[5..].iter().all(|&b| b == 0x42));
        assert_eq!(mpint_positive_len(&k), 34);
        let back = Reader::new(out).read_mpint().unwrap();
        assert!(back.is_canonical());
        assert_eq!(back.positive_magnitude(), Some(&k[2..]));

        // First byte >= 0x80 gains a 0x00 prefix: length 33 + 4 = 37.
        let mut k = [0x11u8; 32];
        k[0] = 0x80;
        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&k).unwrap();
        let out = w.written();
        assert_eq!(out.len(), 37);
        assert_eq!(&out[..6], &[0, 0, 0, 33, 0x00, 0x80]);
        assert_eq!(&out[6..], &k[1..]);
        assert_eq!(mpint_positive_len(&k), 37);
        let back = Reader::new(out).read_mpint().unwrap();
        assert!(back.is_canonical());
        assert!(!back.is_negative());
        assert_eq!(back.positive_magnitude(), Some(&k[..]));

        // First byte 0x7f does not need a prefix: length 32 + 4 = 36.
        let mut k = [0x11u8; 32];
        k[0] = 0x7f;
        assert_eq!(mpint_positive_len(&k), 36);

        // All-zero K encodes as the empty mpint.
        let k = [0u8; 32];
        let mut w = Writer::new(&mut buf);
        w.write_mpint_positive(&k).unwrap();
        assert_eq!(w.written(), &RFC4251_ZERO);
        assert_eq!(mpint_positive_len(&k), 4);
        assert!(Reader::new(w.written()).read_mpint().unwrap().is_zero());
    }
}
