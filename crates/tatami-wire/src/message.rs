//! Shared helpers for whole-message decoders.

use crate::error::{DecodeError, MessageError};
use crate::primitives::Reader;

/// Reads the leading message number and checks it against `expected`.
pub(crate) fn expect_message(r: &mut Reader<'_>, expected: u8) -> Result<(), MessageError> {
    let found = r.read_u8().map_err(|_| MessageError::Empty)?;
    if found == expected {
        Ok(())
    } else {
        Err(MessageError::UnexpectedMessage { expected, found })
    }
}

/// Decodes one named field, attaching its name and offset to any error.
pub(crate) fn field<'a, T>(
    r: &mut Reader<'a>,
    name: &'static str,
    read: impl FnOnce(&mut Reader<'a>) -> Result<T, DecodeError>,
) -> Result<T, MessageError> {
    let offset = r.position();
    read(r).map_err(|error| MessageError::Field {
        field: name,
        offset,
        error,
    })
}

/// Fails with [`MessageError::TrailingBytes`] unless the reader is exhausted.
pub(crate) fn finish(r: &Reader<'_>) -> Result<(), MessageError> {
    r.finish()
        .map_err(|t| MessageError::TrailingBytes { count: t.count })
}
