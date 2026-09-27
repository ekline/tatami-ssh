//! Error types shared by the primitive codecs.

use core::fmt;

/// Failure while decoding a value from a bounded input.
///
/// On any error the originating [`Reader`](crate::Reader) is left at the
/// position it had before the failing call, so a caller may report the offset
/// or try a different interpretation; it never observes a partially consumed
/// field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended before the value was complete.
    Truncated {
        /// Bytes required by the value being read.
        needed: usize,
        /// Bytes actually available at the cursor.
        available: usize,
    },
    /// A length prefix claimed more bytes than the input can hold, or the
    /// length arithmetic would overflow `usize`.
    LengthOverflow {
        /// The claimed length.
        claimed: u32,
        /// Bytes actually available after the length prefix.
        available: usize,
    },
    /// The bytes were present but do not form a valid encoding of the
    /// requested type.
    InvalidEncoding(InvalidEncoding),
}

/// Detail for [`DecodeError::InvalidEncoding`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvalidEncoding {
    /// A name list contained a byte outside printable US-ASCII, or a
    /// non-ASCII byte.
    NameListNonAscii {
        /// Offset of the offending byte within the name list body.
        offset: usize,
    },
    /// A name list contained an empty name (leading, trailing or doubled
    /// comma).
    NameListEmptyName {
        /// Offset within the name list body where the empty name starts.
        offset: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated { needed, available } => write!(
                f,
                "truncated input: needed {needed} bytes, {available} available"
            ),
            DecodeError::LengthOverflow { claimed, available } => write!(
                f,
                "length prefix {claimed} exceeds {available} available bytes"
            ),
            DecodeError::InvalidEncoding(e) => write!(f, "invalid encoding: {e}"),
        }
    }
}

impl fmt::Display for InvalidEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidEncoding::NameListNonAscii { offset } => {
                write!(
                    f,
                    "name list has non-printable or non-ASCII byte at offset {offset}"
                )
            }
            InvalidEncoding::NameListEmptyName { offset } => {
                write!(f, "name list has an empty name at offset {offset}")
            }
        }
    }
}

impl core::error::Error for DecodeError {}
impl core::error::Error for InvalidEncoding {}

/// Failure while encoding a value into a caller-supplied buffer.
///
/// On any error the originating [`Writer`](crate::Writer) is left at the
/// position it had before the failing call; nothing is partially written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer cannot hold the value.
    InsufficientCapacity {
        /// Bytes the value requires.
        needed: usize,
        /// Bytes remaining in the output buffer.
        available: usize,
    },
    /// A byte string or name list is longer than a `uint32` length prefix can
    /// express.
    LengthOverflow {
        /// The actual length.
        len: usize,
    },
    /// A name list element is not a valid SSH name.
    InvalidName {
        /// Index of the offending name.
        index: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::InsufficientCapacity { needed, available } => write!(
                f,
                "output buffer too small: needed {needed} bytes, {available} available"
            ),
            EncodeError::LengthOverflow { len } => {
                write!(f, "length {len} does not fit in a uint32 prefix")
            }
            EncodeError::InvalidName { index } => {
                write!(f, "name at index {index} is not a valid SSH name")
            }
        }
    }
}

impl core::error::Error for EncodeError {}

/// Failure while decoding a complete message payload.
///
/// Message decoders consume an already delimited payload beginning with the
/// message number. They report which field failed so diagnostics can point at
/// the offending part of a peer's message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageError {
    /// The payload was empty; there is no message number.
    Empty,
    /// The message number did not match the decoder.
    UnexpectedMessage {
        /// Message number the decoder handles.
        expected: u8,
        /// Message number found in the payload.
        found: u8,
    },
    /// A named field failed to decode.
    Field {
        /// Field name from the message definition.
        field: &'static str,
        /// Offset of the field within the payload.
        offset: usize,
        /// The primitive-level error.
        error: DecodeError,
    },
    /// Bytes remained after the last defined field.
    TrailingBytes {
        /// Number of unconsumed bytes.
        count: usize,
    },
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::Empty => f.write_str("empty payload"),
            MessageError::UnexpectedMessage { expected, found } => {
                write!(f, "expected message number {expected}, found {found}")
            }
            MessageError::Field {
                field,
                offset,
                error,
            } => {
                write!(f, "field `{field}` at offset {offset}: {error}")
            }
            MessageError::TrailingBytes { count } => {
                write!(f, "{count} unexpected trailing byte(s) after message")
            }
        }
    }
}

impl core::error::Error for MessageError {}
