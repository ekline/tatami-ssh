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
}
