//! `SSH_MSG_EXT_INFO` payload codec (RFC 8308 §2.3).
//!
//! ```text
//! byte       SSH_MSG_EXT_INFO (value 7)
//! uint32     nr-extensions
//! repeat the following 2 fields "nr-extensions" times:
//!   string   extension-name
//!   string   extension-value (binary)
//! ```
//!
//! The decoder allocates nothing. [`ExtInfo::decode`] checks the message
//! number and the count field; [`ExtInfo::extensions`] then yields the
//! `(name, value)` pairs lazily, borrowing both from the payload, and
//! [`ExtInfo::validate`] walks the whole message once to enforce that
//! exactly `nr-extensions` well-formed pairs are present with nothing after
//! them.
//!
//! # Bounding the count
//!
//! `nr-extensions` is peer-controlled. Every pair occupies at least eight
//! bytes (two empty strings), so a count larger than `remaining / 8` cannot
//! be satisfied by the payload and is rejected by [`ExtInfo::decode`] before
//! anything is iterated. [`ExtInfo::validate`] additionally applies a
//! caller-chosen `max_extensions` so that a policy limit is enforced up
//! front rather than discovered after walking a large message.
//!
//! # Names and values
//!
//! RFC 8308 §2.5 requires unknown extension names to be ignored and any byte
//! sequence, including NUL bytes, to be tolerated in an unknown extension's
//! value. Nothing here restricts either; [`classify_extension`] merely
//! recognises the four names RFC 8308 §3 registers so a consumer can act on
//! them. Only `server-sig-algs` has its value interpreted (as a
//! `name-list`), and only on request via [`ExtInfo::server_sig_algs`].
//!
//! Message *placement* (after the first `NEWKEYS`, before
//! `USERAUTH_SUCCESS`) is a transport-driver rule and is not checked here.

use core::fmt;
use core::iter::FusedIterator;

use crate::error::{DecodeError, EncodeError, InvalidEncoding, MessageError};
use crate::message::{expect_message, field, finish};
use crate::msg;
use crate::namelist::NameList;
use crate::primitives::{Reader, Writer};

/// Minimum encoded size of one `(extension-name, extension-value)` pair:
/// two empty strings.
pub const MIN_PAIR_LEN: usize = 8;

/// Extension names registered by RFC 8308 §4.2. Recognition only; no
/// extension is implemented by this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnownExtension {
    /// `server-sig-algs` (§3.1): the value is a `name-list` of public-key
    /// algorithms the server accepts for `publickey` authentication.
    ServerSigAlgs,
    /// `delay-compression` (§3.2): the value encodes two `name-list`s.
    DelayCompression,
    /// `no-flow-control` (§3.3): the value is `p` or `s`.
    NoFlowControl,
    /// `elevation` (§3.4): the value is `y`, `n` or `d`.
    Elevation,
}

impl KnownExtension {
    /// The registered extension name.
    #[must_use]
    pub const fn name(self) -> &'static [u8] {
        match self {
            KnownExtension::ServerSigAlgs => b"server-sig-algs",
            KnownExtension::DelayCompression => b"delay-compression",
            KnownExtension::NoFlowControl => b"no-flow-control",
            KnownExtension::Elevation => b"elevation",
        }
    }
}

/// Recognises the extension names of RFC 8308 §3. Any other name, including
/// vendor names containing `@`, returns `None` and must be ignored by the
/// consumer (RFC 8308 §2.5), never rejected.
#[must_use]
pub fn classify_extension(name: &[u8]) -> Option<KnownExtension> {
    match name {
        b"server-sig-algs" => Some(KnownExtension::ServerSigAlgs),
        b"delay-compression" => Some(KnownExtension::DelayCompression),
        b"no-flow-control" => Some(KnownExtension::NoFlowControl),
        b"elevation" => Some(KnownExtension::Elevation),
        _ => None,
    }
}

/// Failure reported by [`ExtInfo::validate`] or [`ExtInfo::server_sig_algs`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtInfoError {
    /// A field failed to decode, or bytes followed the last claimed pair.
    Message(MessageError),
    /// `nr-extensions` exceeds the limit the caller passed.
    TooManyExtensions {
        /// The count claimed by the peer.
        claimed: u32,
        /// The caller's limit.
        max: usize,
    },
    /// The payload ended at a pair boundary before `nr-extensions` pairs
    /// had been read.
    CountMismatch {
        /// The count claimed by the peer.
        claimed: u32,
        /// Complete pairs actually present.
        found: usize,
    },
    /// The `server-sig-algs` value is not a syntactically valid `name-list`.
    InvalidServerSigAlgs(InvalidEncoding),
}

impl fmt::Display for ExtInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExtInfoError::Message(e) => write!(f, "{e}"),
            ExtInfoError::TooManyExtensions { claimed, max } => {
                write!(f, "nr-extensions {claimed} exceeds limit {max}")
            }
            ExtInfoError::CountMismatch { claimed, found } => {
                write!(
                    f,
                    "nr-extensions {claimed} but only {found} pair(s) present"
                )
            }
            ExtInfoError::InvalidServerSigAlgs(e) => {
                write!(f, "server-sig-algs value is not a name-list: {e}")
            }
        }
    }
}

impl core::error::Error for ExtInfoError {}

impl From<MessageError> for ExtInfoError {
    fn from(e: MessageError) -> Self {
        ExtInfoError::Message(e)
    }
}

/// Borrowed view of an `EXT_INFO` payload whose header has been checked.
///
/// Holding an `ExtInfo` proves only that the message number was 7 and that
/// `nr-extensions` pairs could fit in the remaining bytes. The pairs
/// themselves are decoded lazily; call [`ExtInfo::validate`] to check the
/// whole message.
#[derive(Clone, Copy, Debug)]
pub struct ExtInfo<'a> {
    claimed: u32,
    /// Bounded count, `<= body.remaining_len() / MIN_PAIR_LEN`.
    count: usize,
    /// Positioned at the first pair; positions are payload offsets.
    body: Reader<'a>,
}

impl<'a> ExtInfo<'a> {
    /// Decodes the header of a complete, already delimited payload starting
    /// at the message number byte.
    ///
    /// Fails with [`MessageError::Field`] on `nr-extensions` when the count
    /// cannot be satisfied by the remaining bytes (`claimed` is the count,
    /// `available` the remaining byte count). Nothing after the count is
    /// examined here.
    pub fn decode(payload: &'a [u8]) -> Result<Self, MessageError> {
        let mut r = Reader::new(payload);
        expect_message(&mut r, msg::EXT_INFO)?;
        let count_offset = r.position();
        let claimed = field(&mut r, "nr-extensions", Reader::read_u32)?;
        let available = r.remaining_len();
        let fits = usize::try_from(claimed)
            .ok()
            .filter(|&c| c <= available / MIN_PAIR_LEN);
        let Some(count) = fits else {
            return Err(MessageError::Field {
                field: "nr-extensions",
                offset: count_offset,
                error: DecodeError::LengthOverflow { claimed, available },
            });
        };
        Ok(ExtInfo {
            claimed,
            count,
            body: r,
        })
    }

    /// The `nr-extensions` value as sent.
    #[must_use]
    pub const fn claimed_count(&self) -> u32 {
        self.claimed
    }

    /// Iterates the claimed pairs lazily, borrowing names and values from
    /// the payload. Stops after `nr-extensions` pairs or at the first
    /// malformed one; it does not report bytes left after the last pair
    /// (see [`ExtInfo::validate`]).
    #[must_use]
    pub fn extensions(&self) -> Extensions<'a> {
        Extensions {
            r: self.body,
            remaining: self.count,
            failed: false,
        }
    }

    /// Walks the entire message and returns the number of pairs.
    ///
    /// Fails, in this order, when `nr-extensions` exceeds `max_extensions`
    /// (before touching any pair), when a pair is malformed, when the
    /// payload ends before `nr-extensions` pairs, or when bytes remain after
    /// the last pair.
    pub fn validate(&self, max_extensions: usize) -> Result<usize, ExtInfoError> {
        if self.count > max_extensions {
            return Err(ExtInfoError::TooManyExtensions {
                claimed: self.claimed,
                max: max_extensions,
            });
        }
        let mut r = self.body;
        for found in 0..self.count {
            if r.is_empty() {
                return Err(ExtInfoError::CountMismatch {
                    claimed: self.claimed,
                    found,
                });
            }
            read_pair(&mut r)?;
        }
        finish(&r)?;
        Ok(self.count)
    }

    /// Finds the first `server-sig-algs` extension and parses its value as a
    /// `name-list` (RFC 8308 §3.1).
    ///
    /// Returns `None` when the extension is absent, `Some(Err(_))` when a
    /// pair before it is malformed or its value is not a valid name-list.
    /// Does not check pairs after the match; use [`ExtInfo::validate`] for
    /// that.
    #[must_use]
    pub fn server_sig_algs(&self) -> Option<Result<NameList<'a>, ExtInfoError>> {
        for pair in self.extensions() {
            match pair {
                Err(e) => return Some(Err(ExtInfoError::Message(e))),
                Ok((name, value)) if name == KnownExtension::ServerSigAlgs.name() => {
                    return Some(
                        NameList::parse(value).map_err(ExtInfoError::InvalidServerSigAlgs),
                    );
                }
                Ok(_) => {}
            }
        }
        None
    }
}

/// Reads one pair, naming the failing field.
fn read_pair<'a>(r: &mut Reader<'a>) -> Result<(&'a [u8], &'a [u8]), MessageError> {
    let name = field(r, "extension-name", Reader::read_string)?;
    let value = field(r, "extension-value", Reader::read_string)?;
    Ok((name, value))
}

/// Lazy iterator over `(extension-name, extension-value)` pairs; see
/// [`ExtInfo::extensions`].
#[derive(Clone, Debug)]
pub struct Extensions<'a> {
    r: Reader<'a>,
    remaining: usize,
    failed: bool,
}

impl<'a> Iterator for Extensions<'a> {
    type Item = Result<(&'a [u8], &'a [u8]), MessageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.remaining == 0 {
            return None;
        }
        match read_pair(&mut self.r) {
            Ok(pair) => {
                self.remaining -= 1;
                Some(Ok(pair))
            }
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.failed {
            (0, Some(0))
        } else {
            (0, Some(self.remaining))
        }
    }
}

impl FusedIterator for Extensions<'_> {}

/// Encodes an `EXT_INFO` message from `(name, value)` pairs into `out`,
/// returning the number of bytes written. Performs no semantic validation
/// of names or values.
pub fn encode_ext_info(pairs: &[(&[u8], &[u8])], out: &mut [u8]) -> Result<usize, EncodeError> {
    let count =
        u32::try_from(pairs.len()).map_err(|_| EncodeError::LengthOverflow { len: pairs.len() })?;
    let mut w = Writer::new(out);
    w.write_u8(msg::EXT_INFO)?;
    w.write_u32(count)?;
    for (name, value) in pairs {
        w.write_string(name)?;
        w.write_string(value)?;
    }
    Ok(w.position())
}

#[cfg(feature = "alloc")]
pub use owned::OwnedExtInfo;

#[cfg(feature = "alloc")]
mod owned {
    use alloc::vec::Vec;

    use super::{ExtInfo, ExtInfoError, encode_ext_info};
    use crate::error::EncodeError;

    /// Owned copy of a validated `EXT_INFO` message, in wire order.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct OwnedExtInfo {
        /// `(extension-name, extension-value)` pairs as received.
        pub extensions: Vec<(Vec<u8>, Vec<u8>)>,
    }

    impl OwnedExtInfo {
        /// Encodes the message into `out`, returning the number of bytes
        /// written.
        pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
            let pairs: Vec<(&[u8], &[u8])> = self
                .extensions
                .iter()
                .map(|(n, v)| (n.as_slice(), v.as_slice()))
                .collect();
            encode_ext_info(&pairs, out)
        }
    }

    impl ExtInfo<'_> {
        /// Validates the message (see [`ExtInfo::validate`]) and copies
        /// every pair.
        pub fn to_owned(&self, max_extensions: usize) -> Result<OwnedExtInfo, ExtInfoError> {
            let count = self.validate(max_extensions)?;
            let mut extensions = Vec::with_capacity(count);
            for pair in self.extensions() {
                // Cannot fail: `validate` just walked the same bytes.
                let (name, value) = pair?;
                extensions.push((name.to_vec(), value.to_vec()));
            }
            Ok(OwnedExtInfo { extensions })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-assembled: 7, count 1, string(15) "server-sig-algs",
    /// string(24) "ssh-ed25519,rsa-sha2-256". 1 + 4 + 19 + 28 = 52 bytes.
    const ONE_SERVER_SIG_ALGS: [u8; 52] = [
        7, 0, 0, 0, 1, //
        0, 0, 0, 15, b's', b'e', b'r', b'v', b'e', b'r', b'-', b's', b'i', b'g', b'-', b'a', b'l',
        b'g', b's', //
        0, 0, 0, 24, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', b',', b'r',
        b's', b'a', b'-', b's', b'h', b'a', b'2', b'-', b'2', b'5', b'6',
    ];

    /// Hand-assembled: 7, count 0.
    const ZERO: [u8; 5] = [7, 0, 0, 0, 0];

    /// Hand-assembled: 7, count 2, then ONE pair (string(15)
    /// "server-sig-algs", string(11) "ssh-ed25519") = 34 body bytes, which
    /// is enough room for two minimal pairs so the header check passes.
    const CLAIMS_TWO_HAS_ONE: [u8; 39] = [
        7, 0, 0, 0, 2, //
        0, 0, 0, 15, b's', b'e', b'r', b'v', b'e', b'r', b'-', b's', b'i', b'g', b'-', b'a', b'l',
        b'g', b's', //
        0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9',
    ];

    /// RFC 8308 §3.2 example: `delay-compression` with client-to-server
    /// "foo,bar" and server-to-client "bar,baz"; the RFC gives the encoded
    /// extension-value including its length as
    /// `00000016 00000007 666f6f2c626172 00000007 6261722c62617a`.
    const RFC8308_DELAY_COMPRESSION: [u8; 52] = [
        7, 0, 0, 0, 1, //
        0, 0, 0, 17, b'd', b'e', b'l', b'a', b'y', b'-', b'c', b'o', b'm', b'p', b'r', b'e', b's',
        b's', b'i', b'o', b'n', //
        0x00, 0x00, 0x00, 0x16, //
        0x00, 0x00, 0x00, 0x07, 0x66, 0x6f, 0x6f, 0x2c, 0x62, 0x61, 0x72, //
        0x00, 0x00, 0x00, 0x07, 0x62, 0x61, 0x72, 0x2c, 0x62, 0x61, 0x7a,
    ];

    #[test]
    fn one_server_sig_algs_extension() {
        let m = ExtInfo::decode(&ONE_SERVER_SIG_ALGS).unwrap();
        assert_eq!(m.claimed_count(), 1);
        assert_eq!(m.validate(16), Ok(1));

        let mut it = m.extensions();
        let (name, value) = it.next().unwrap().unwrap();
        assert_eq!(name, b"server-sig-algs");
        assert_eq!(value, b"ssh-ed25519,rsa-sha2-256");
        assert!(it.next().is_none());
        assert!(it.next().is_none(), "fused");

        assert_eq!(
            classify_extension(name),
            Some(KnownExtension::ServerSigAlgs)
        );
        let algs = m.server_sig_algs().unwrap().unwrap();
        let expected: [&[u8]; 2] = [b"ssh-ed25519", b"rsa-sha2-256"];
        assert!(algs.iter().eq(expected.iter().copied()));

        let mut out = [0u8; 52];
        let n = encode_ext_info(
            &[(b"server-sig-algs", b"ssh-ed25519,rsa-sha2-256")],
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 52);
        assert_eq!(out, ONE_SERVER_SIG_ALGS);
    }

    #[test]
    fn zero_extensions() {
        let m = ExtInfo::decode(&ZERO).unwrap();
        assert_eq!(m.claimed_count(), 0);
        assert_eq!(m.validate(0), Ok(0));
        assert!(m.extensions().next().is_none());
        assert!(m.server_sig_algs().is_none());

        let mut out = [0u8; 5];
        assert_eq!(encode_ext_info(&[], &mut out).unwrap(), 5);
        assert_eq!(out, ZERO);
    }

    #[test]
    fn count_mismatch_is_reported() {
        let m = ExtInfo::decode(&CLAIMS_TWO_HAS_ONE).unwrap();
        assert_eq!(m.claimed_count(), 2);
        assert_eq!(
            m.validate(16),
            Err(ExtInfoError::CountMismatch {
                claimed: 2,
                found: 1
            })
        );
        // The iterator itself reports the second pair as truncated.
        let mut it = m.extensions();
        assert!(it.next().unwrap().is_ok());
        assert_eq!(
            it.next().unwrap(),
            Err(MessageError::Field {
                field: "extension-name",
                offset: 39,
                error: DecodeError::Truncated {
                    needed: 4,
                    available: 0
                }
            })
        );
        assert!(it.next().is_none(), "fused after an error");
        // server-sig-algs is still found before the mismatch.
        assert!(m.server_sig_algs().unwrap().is_ok());
    }

    #[test]
    fn count_too_large_for_bytes_fails_before_iteration() {
        // Claims 0xFFFFFFFF pairs with 12 bytes total (7 after the header).
        let payload = [7, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            ExtInfo::decode(&payload).unwrap_err(),
            MessageError::Field {
                field: "nr-extensions",
                offset: 1,
                error: DecodeError::LengthOverflow {
                    claimed: 0xffff_ffff,
                    available: 7
                }
            }
        );
        // Off by one around the 8-bytes-per-pair floor.
        let two_pairs_min = [
            7, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(ExtInfo::decode(&two_pairs_min).unwrap().validate(2), Ok(2));
        let three_claimed = [
            7, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert!(matches!(
            ExtInfo::decode(&three_claimed),
            Err(MessageError::Field {
                field: "nr-extensions",
                ..
            })
        ));
    }

    #[test]
    fn max_extensions_is_enforced_before_walking() {
        let m = ExtInfo::decode(&ONE_SERVER_SIG_ALGS).unwrap();
        assert_eq!(
            m.validate(0),
            Err(ExtInfoError::TooManyExtensions { claimed: 1, max: 0 })
        );
        assert_eq!(m.validate(1), Ok(1));
    }

    #[test]
    fn trailing_bytes_are_rejected_by_validate() {
        let mut payload = [0u8; 53];
        payload[..52].copy_from_slice(&ONE_SERVER_SIG_ALGS);
        let m = ExtInfo::decode(&payload).unwrap();
        assert_eq!(
            m.validate(16),
            Err(ExtInfoError::Message(MessageError::TrailingBytes {
                count: 1
            }))
        );
        // The lazy iterator still yields the one good pair.
        assert_eq!(m.extensions().count(), 1);
    }

    #[test]
    fn truncated_value_names_the_field() {
        // Claims 1; name "a"; value claims 9 bytes with 1 present.
        let payload = [7, 0, 0, 0, 1, 0, 0, 0, 1, b'a', 0, 0, 0, 9, 0xaa];
        let m = ExtInfo::decode(&payload).unwrap();
        let expected = MessageError::Field {
            field: "extension-value",
            offset: 10,
            error: DecodeError::LengthOverflow {
                claimed: 9,
                available: 1,
            },
        };
        assert_eq!(m.validate(16), Err(ExtInfoError::Message(expected)));
        assert_eq!(m.extensions().next(), Some(Err(expected)));
    }

    #[test]
    fn unknown_extension_and_binary_value_preserved() {
        // Claims 1; name "x@example.com"; value 00 ff 00 (NULs are legal).
        let payload = [
            7, 0, 0, 0, 1, 0, 0, 0, 13, b'x', b'@', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.',
            b'c', b'o', b'm', 0, 0, 0, 3, 0x00, 0xff, 0x00,
        ];
        let m = ExtInfo::decode(&payload).unwrap();
        assert_eq!(m.validate(16), Ok(1));
        let (name, value) = m.extensions().next().unwrap().unwrap();
        assert_eq!(name, b"x@example.com");
        assert_eq!(value, &[0x00, 0xff, 0x00]);
        assert_eq!(classify_extension(name), None);
        assert!(m.server_sig_algs().is_none());
    }

    #[test]
    fn rfc8308_delay_compression_example_is_preserved_verbatim() {
        let m = ExtInfo::decode(&RFC8308_DELAY_COMPRESSION).unwrap();
        assert_eq!(m.validate(16), Ok(1));
        let (name, value) = m.extensions().next().unwrap().unwrap();
        assert_eq!(
            classify_extension(name),
            Some(KnownExtension::DelayCompression)
        );
        assert_eq!(value.len(), 0x16);
        // The value is two name-lists; this module does not interpret it.
        let mut r = Reader::new(value);
        assert_eq!(r.read_name_list().unwrap().as_bytes(), b"foo,bar");
        assert_eq!(r.read_name_list().unwrap().as_bytes(), b"bar,baz");
        assert!(r.is_empty());
    }

    #[test]
    fn known_extension_names_round_trip() {
        for k in [
            KnownExtension::ServerSigAlgs,
            KnownExtension::DelayCompression,
            KnownExtension::NoFlowControl,
            KnownExtension::Elevation,
        ] {
            assert_eq!(classify_extension(k.name()), Some(k));
        }
        assert_eq!(
            classify_extension(b"Server-Sig-Algs"),
            None,
            "case-sensitive"
        );
    }

    #[test]
    fn invalid_server_sig_algs_value() {
        // Claims 1; "server-sig-algs" with value "a,,b".
        let payload = [
            7, 0, 0, 0, 1, //
            0, 0, 0, 15, b's', b'e', b'r', b'v', b'e', b'r', b'-', b's', b'i', b'g', b'-', b'a',
            b'l', b'g', b's', //
            0, 0, 0, 4, b'a', b',', b',', b'b',
        ];
        let m = ExtInfo::decode(&payload).unwrap();
        assert_eq!(m.validate(16), Ok(1), "syntactically a valid message");
        assert_eq!(
            m.server_sig_algs(),
            Some(Err(ExtInfoError::InvalidServerSigAlgs(
                InvalidEncoding::NameListEmptyName { offset: 2 }
            )))
        );
    }

    #[test]
    fn wrong_number_and_empty() {
        assert_eq!(ExtInfo::decode(&[]).unwrap_err(), MessageError::Empty);
        assert_eq!(
            ExtInfo::decode(&[20, 0, 0, 0, 0]).unwrap_err(),
            MessageError::UnexpectedMessage {
                expected: 7,
                found: 20
            }
        );
        assert_eq!(
            ExtInfo::decode(&[7, 0, 0]).unwrap_err(),
            MessageError::Field {
                field: "nr-extensions",
                offset: 1,
                error: DecodeError::Truncated {
                    needed: 4,
                    available: 2
                }
            }
        );
    }

    #[test]
    fn encode_reports_capacity_and_multiple_pairs() {
        let mut out = [0u8; 8];
        assert_eq!(
            encode_ext_info(&[(b"a", b"b")], &mut out),
            Err(EncodeError::InsufficientCapacity {
                needed: 5,
                available: 3
            })
        );
        let mut out = [0u8; 32];
        let n = encode_ext_info(&[(b"a", b""), (b"", b"\x00")], &mut out).unwrap();
        // 1 + 4 + (4+1 + 4+0) + (4+0 + 4+1) = 23
        assert_eq!(n, 23);
        assert_eq!(
            &out[..n],
            &[
                7, 0, 0, 0, 2, 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x00
            ]
        );
        let m = ExtInfo::decode(&out[..n]).unwrap();
        assert_eq!(m.validate(2), Ok(2));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_copy_round_trips() {
        let m = ExtInfo::decode(&ONE_SERVER_SIG_ALGS).unwrap();
        let owned = m.to_owned(16).unwrap();
        assert_eq!(owned.extensions.len(), 1);
        assert_eq!(owned.extensions[0].0, b"server-sig-algs");
        assert_eq!(owned.extensions[0].1, b"ssh-ed25519,rsa-sha2-256");
        let mut out = [0u8; 52];
        assert_eq!(owned.encode(&mut out).unwrap(), 52);
        assert_eq!(out, ONE_SERVER_SIG_ALGS);

        let bad = ExtInfo::decode(&CLAIMS_TWO_HAS_ONE).unwrap();
        assert!(matches!(
            bad.to_owned(16),
            Err(ExtInfoError::CountMismatch { .. })
        ));
    }
}
