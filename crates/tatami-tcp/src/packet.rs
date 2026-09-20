//! Initial (unprotected, uncompressed) binary packet framing (RFC 4253 §6).
//!
//! Before the first `NEWKEYS`, packets have no MAC and use the `none`
//! cipher, whose block size for padding purposes is 8:
//!
//! ```text
//! uint32    packet_length
//! byte      padding_length
//! byte[n1]  payload            n1 = packet_length - padding_length - 1
//! byte[n2]  random padding     n2 = padding_length
//! ```
//!
//! This decoder is **only** valid for that initial state. After `NEWKEYS`
//! the framing is encrypted and possibly MAC-protected; a consumer must stop
//! using this module rather than parse ciphertext as plaintext.
//!
//! # Checks before waiting for the body
//!
//! Every constraint that can be evaluated from the five-byte header is
//! evaluated as soon as those bytes arrive, so an oversized or malformed
//! claim is rejected before any body bytes are buffered or allocated:
//!
//! - `packet_length + 4` is a multiple of 8 and at least 16 bytes;
//! - `packet_length` does not exceed the configured cap;
//! - `padding_length >= 4` and leaves room for a payload.
//!
//! All arithmetic is checked.

use core::fmt;

/// Block size used for padding alignment with the `none` cipher.
pub const INITIAL_BLOCK_SIZE: usize = 8;
/// Minimum total packet size (`packet_length` field plus 4).
pub const MIN_TOTAL_LEN: usize = 16;
/// Minimum `padding_length`.
pub const MIN_PADDING: usize = 4;
/// Bytes of header needed before the body length is known.
pub const HEADER_LEN: usize = 5;

/// RFC 4253 §6.1 mandatory baseline: every implementation must accept a
/// total packet size of at least this many bytes. It is a floor for
/// [`PacketLimits::max_packet_length`], not a universal maximum.
pub const BASELINE_MAX_TOTAL: u32 = 35_000;

/// Configurable limits for initial packet decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketLimits {
    /// Largest accepted value of the `packet_length` field. Local policy;
    /// defaults to 64 KiB, comfortably above [`BASELINE_MAX_TOTAL`].
    pub max_packet_length: u32,
}

impl Default for PacketLimits {
    fn default() -> Self {
        PacketLimits {
            max_packet_length: 64 * 1024,
        }
    }
}

/// A complete initial packet borrowed from the input buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialPacket<'a> {
    /// The message payload (message number first).
    pub payload: &'a [u8],
    /// The random padding bytes, exposed for diagnostics only.
    pub padding: &'a [u8],
    /// Total bytes this packet occupied in the input, including the
    /// four-byte length field.
    pub total_len: usize,
}

/// Result of [`decode_initial_packet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketStep<'a> {
    /// Not enough input yet. `total_len` is the full packet size once the
    /// header has been validated, or `None` while fewer than
    /// [`HEADER_LEN`] bytes are available.
    NeedMore {
        /// Total packet size if already known.
        total_len: Option<usize>,
    },
    /// A complete packet.
    Complete(InitialPacket<'a>),
}

/// Reasons a packet header is malformed or refused by policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// `packet_length` exceeds [`PacketLimits::max_packet_length`].
    TooLarge {
        /// The claimed `packet_length`.
        packet_length: u32,
        /// The configured cap.
        limit: u32,
    },
    /// `packet_length + 4 < 16`.
    TooSmall {
        /// The claimed `packet_length`.
        packet_length: u32,
    },
    /// `packet_length + 4` is not a multiple of the block size.
    Misaligned {
        /// The claimed `packet_length`.
        packet_length: u32,
    },
    /// `padding_length < 4` or the padding does not fit in the packet.
    BadPadding {
        /// The claimed `packet_length`.
        packet_length: u32,
        /// The claimed `padding_length`.
        padding_length: u8,
    },
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketError::TooLarge {
                packet_length,
                limit,
            } => {
                write!(
                    f,
                    "packet_length {packet_length} exceeds local limit {limit}"
                )
            }
            PacketError::TooSmall { packet_length } => {
                write!(f, "packet_length {packet_length} below minimum")
            }
            PacketError::Misaligned { packet_length } => {
                write!(f, "packet_length {packet_length} not aligned to block size")
            }
            PacketError::BadPadding {
                packet_length,
                padding_length,
            } => write!(
                f,
                "padding_length {padding_length} invalid for packet_length {packet_length}"
            ),
        }
    }
}

impl core::error::Error for PacketError {}

/// Attempts to decode one initial packet from the front of `buf`.
///
/// On [`PacketStep::Complete`] the caller should drop `total_len` bytes from
/// its buffer before calling again. Errors are terminal for the connection.
pub fn decode_initial_packet<'a>(
    buf: &'a [u8],
    limits: &PacketLimits,
) -> Result<PacketStep<'a>, PacketError> {
    if buf.len() < 4 {
        return Ok(PacketStep::NeedMore { total_len: None });
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    // Header validation that needs only the length field.
    if packet_length > limits.max_packet_length {
        return Err(PacketError::TooLarge {
            packet_length,
            limit: limits.max_packet_length,
        });
    }
    // Cannot overflow: packet_length <= u32::MAX and we add in u64.
    let total_u64 = u64::from(packet_length) + 4;
    if total_u64 < MIN_TOTAL_LEN as u64 {
        return Err(PacketError::TooSmall { packet_length });
    }
    if total_u64 % INITIAL_BLOCK_SIZE as u64 != 0 {
        return Err(PacketError::Misaligned { packet_length });
    }
    let Ok(total_len) = usize::try_from(total_u64) else {
        return Err(PacketError::TooLarge {
            packet_length,
            limit: limits.max_packet_length,
        });
    };

    if buf.len() < HEADER_LEN {
        return Ok(PacketStep::NeedMore {
            total_len: Some(total_len),
        });
    }
    let padding_length = buf[4];

    // payload_len = packet_length - padding_length - 1, checked.
    let payload_len = usize::try_from(packet_length)
        .ok()
        .and_then(|pl| pl.checked_sub(usize::from(padding_length)))
        .and_then(|v| v.checked_sub(1));
    let Some(payload_len) = payload_len else {
        return Err(PacketError::BadPadding {
            packet_length,
            padding_length,
        });
    };
    if usize::from(padding_length) < MIN_PADDING {
        return Err(PacketError::BadPadding {
            packet_length,
            padding_length,
        });
    }

    if buf.len() < total_len {
        return Ok(PacketStep::NeedMore {
            total_len: Some(total_len),
        });
    }

    let payload = &buf[HEADER_LEN..HEADER_LEN + payload_len];
    let padding = &buf[HEADER_LEN + payload_len..total_len];
    Ok(PacketStep::Complete(InitialPacket {
        payload,
        padding,
        total_len,
    }))
}

/// Encodes `payload` as an initial packet into `out` using deterministic
/// padding, returning the number of bytes written.
///
/// Padding is the minimum that satisfies alignment and `padding_length >= 4`,
/// filled with `pad_byte`. Real senders must use random padding; this helper
/// exists for tests and fixtures, which is why it is not randomised.
pub fn encode_initial_packet(
    payload: &[u8],
    pad_byte: u8,
    out: &mut [u8],
) -> Result<usize, EncodeInitialError> {
    // total = 4 + 1 + payload + padding, padding >= 4, total % 8 == 0
    let base = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(EncodeInitialError::PayloadTooLarge)?;
    let mut padding = INITIAL_BLOCK_SIZE - (base % INITIAL_BLOCK_SIZE);
    if padding < MIN_PADDING {
        padding += INITIAL_BLOCK_SIZE;
    }
    let total = base + padding;
    let packet_length =
        u32::try_from(total - 4).map_err(|_| EncodeInitialError::PayloadTooLarge)?;
    if padding > usize::from(u8::MAX) {
        return Err(EncodeInitialError::PayloadTooLarge);
    }
    if out.len() < total {
        return Err(EncodeInitialError::InsufficientCapacity {
            needed: total,
            available: out.len(),
        });
    }
    out[..4].copy_from_slice(&packet_length.to_be_bytes());
    out[4] = padding as u8;
    out[HEADER_LEN..HEADER_LEN + payload.len()].copy_from_slice(payload);
    out[HEADER_LEN + payload.len()..total].fill(pad_byte);
    Ok(total)
}

/// Failure of [`encode_initial_packet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeInitialError {
    /// Output buffer too small.
    InsufficientCapacity {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        available: usize,
    },
    /// Payload cannot be framed.
    PayloadTooLarge,
}

impl fmt::Display for EncodeInitialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeInitialError::InsufficientCapacity { needed, available } => {
                write!(
                    f,
                    "output buffer too small: needed {needed}, available {available}"
                )
            }
            EncodeInitialError::PayloadTooLarge => f.write_str("payload too large"),
        }
    }
}

impl core::error::Error for EncodeInitialError {}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: PacketLimits = PacketLimits {
        max_packet_length: 1024,
    };

    /// Hand-derived: payload = [2, 0,0,0,0] (IGNORE with empty data).
    /// base = 5 + 5 = 10; padding = 8 - 2 = 6 -> total 16, packet_length 12.
    const IGNORE_PKT: [u8; 16] = [
        0, 0, 0, 12, 6, 2, 0, 0, 0, 0, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
    ];

    #[test]
    fn decodes_hand_derived_packet() {
        match decode_initial_packet(&IGNORE_PKT, &LIMITS).unwrap() {
            PacketStep::Complete(p) => {
                assert_eq!(p.payload, &[2, 0, 0, 0, 0]);
                assert_eq!(p.padding, &[0xEE; 6]);
                assert_eq!(p.total_len, 16);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn encoder_matches_fixture_and_round_trips() {
        let mut out = [0u8; 32];
        let n = encode_initial_packet(&[2, 0, 0, 0, 0], 0xEE, &mut out).unwrap();
        assert_eq!(&out[..n], &IGNORE_PKT);

        // Payload of 3 bytes: base 8, padding would be 8 - 0 = 8 (>=4) -> 16.
        let n = encode_initial_packet(&[1, 2, 3], 0, &mut out).unwrap();
        assert_eq!(n, 16);
        assert_eq!(out[4], 8);
        // Payload of 1 byte: base 6, padding 2 -> bump to 10 -> total 16.
        let n = encode_initial_packet(&[9], 0, &mut out).unwrap();
        assert_eq!(n, 16);
        assert_eq!(out[4], 10);
        match decode_initial_packet(&out[..n], &LIMITS).unwrap() {
            PacketStep::Complete(p) => assert_eq!(p.payload, &[9]),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn fragmentation_at_every_boundary() {
        for n in 0..IGNORE_PKT.len() {
            let step = decode_initial_packet(&IGNORE_PKT[..n], &LIMITS).unwrap();
            let expected = if n < 4 { None } else { Some(16) };
            assert_eq!(
                step,
                PacketStep::NeedMore {
                    total_len: expected
                },
                "prefix {n}"
            );
        }
    }

    #[test]
    fn coalesced_packets_report_total_len() {
        let mut two = [0u8; 32];
        two[..16].copy_from_slice(&IGNORE_PKT);
        two[16..].copy_from_slice(&IGNORE_PKT);
        let PacketStep::Complete(p) = decode_initial_packet(&two, &LIMITS).unwrap() else {
            panic!()
        };
        assert_eq!(p.total_len, 16);
        assert!(matches!(
            decode_initial_packet(&two[p.total_len..], &LIMITS),
            Ok(PacketStep::Complete(_))
        ));
    }

    #[test]
    fn oversized_claim_rejected_from_length_field_alone() {
        let hdr = [0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            decode_initial_packet(&hdr, &LIMITS),
            Err(PacketError::TooLarge {
                packet_length: u32::MAX,
                limit: 1024
            })
        );
        let hdr = [0, 0, 4, 4]; // 1028 > 1024
        assert_eq!(
            decode_initial_packet(&hdr, &LIMITS),
            Err(PacketError::TooLarge {
                packet_length: 1028,
                limit: 1024
            })
        );
    }

    #[test]
    fn too_small_and_misaligned() {
        assert_eq!(
            decode_initial_packet(&[0, 0, 0, 4], &LIMITS),
            Err(PacketError::TooSmall { packet_length: 4 })
        );
        assert_eq!(
            decode_initial_packet(&[0, 0, 0, 0], &LIMITS),
            Err(PacketError::TooSmall { packet_length: 0 })
        );
        assert_eq!(
            decode_initial_packet(&[0, 0, 0, 13], &LIMITS),
            Err(PacketError::Misaligned { packet_length: 13 })
        );
    }

    #[test]
    fn bad_padding() {
        // padding 3 < 4
        assert_eq!(
            decode_initial_packet(&[0, 0, 0, 12, 3], &LIMITS),
            Err(PacketError::BadPadding {
                packet_length: 12,
                padding_length: 3
            })
        );
        // padding 12 leaves no room for payload (12 - 12 - 1 < 0)
        assert_eq!(
            decode_initial_packet(&[0, 0, 0, 12, 12], &LIMITS),
            Err(PacketError::BadPadding {
                packet_length: 12,
                padding_length: 12
            })
        );
        // padding 11 -> payload_len 0 is permitted at this layer.
        assert!(matches!(
            decode_initial_packet(&[0, 0, 0, 12, 11], &LIMITS),
            Ok(PacketStep::NeedMore {
                total_len: Some(16)
            })
        ));
    }

    #[test]
    fn default_limit_is_above_baseline() {
        assert!(PacketLimits::default().max_packet_length >= BASELINE_MAX_TOTAL);
    }
}
