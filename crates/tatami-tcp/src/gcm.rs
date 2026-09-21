//! Protected binary packets with `aes128-gcm@openssh.com` (RFC 5647 §§6–7
//! construction under the OpenSSH name; see `docs/crypto-provider-audit.md`).
//!
//! ```text
//! uint32    packet_length        -- additional authenticated data, in clear
//! byte      padding_length       -- encrypted
//! byte[n1]  payload              -- encrypted
//! byte[n2]  random padding       -- encrypted
//! byte[16]  authentication tag
//! ```
//!
//! - `padding_length + payload + padding` is a multiple of the 16-byte
//!   block, with at least 4 bytes of padding, so `packet_length` itself is a
//!   multiple of 16.
//! - The 12-byte nonce is a 4-byte fixed field followed by an 8-byte
//!   invocation counter (both from the derived IV). The counter is
//!   incremented as a big-endian 64-bit integer after **every** packet, in
//!   each direction independently. This module never wraps the counter: a
//!   direction whose counter has reached its last value refuses to seal or
//!   open ([`SealError::CounterExhausted`], [`OpenError::CounterExhausted`]).
//!   The diagnostic sends a handful of packets; the check exists so that a
//!   nonce can never repeat under any control flow.
//!
//! # Receiving
//!
//! [`AeadDirection::open`] is incremental over a caller-owned buffer. It
//! reads the four clear length bytes, rejects a length that is too large
//! (the [`PacketLimits`] cap, W-17), too small or misaligned **before**
//! waiting for the body, then waits for `4 + packet_length + 16` bytes,
//! decrypts and verifies in place and exposes the payload only after the tag
//! verifies. A tag failure is terminal: there is no resynchronisation.
//!
//! # Sending
//!
//! [`AeadDirection::seal`] produces one complete packet into the caller's
//! output buffer and advances the counter once. The host writes those bytes
//! (with partial-write handling) without involving this module again;
//! re-writing the same buffer does not touch the counter. A second `seal`
//! call is a new packet under the next nonce. Padding bytes come from the
//! caller's RNG.
//!
//! Keys are copied once into the provider's key schedule; the fixed nonce
//! field and counter are public values.

use alloc::vec::Vec;
use core::fmt;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
use rand_core::RngCore;

use crate::packet::PacketLimits;
use crate::transcript::AeadKeys;

/// AES-128 key length.
pub const KEY_LEN: usize = 16;
/// Nonce length (RFC 5647 §7.1).
pub const NONCE_LEN: usize = 12;
/// Length of the fixed nonce field.
pub const NONCE_FIXED_LEN: usize = 4;
/// Authentication tag length.
pub const TAG_LEN: usize = 16;
/// Cipher block size, which governs padding alignment.
pub const BLOCK_SIZE: usize = 16;
/// Minimum random padding.
pub const MIN_PADDING: usize = 4;
/// Length of the clear `packet_length` field.
pub const LENGTH_LEN: usize = 4;
/// Smallest `packet_length` that can hold `padding_length`, a one-byte
/// payload and four bytes of padding after block alignment.
pub const MIN_PACKET_LENGTH: u32 = BLOCK_SIZE as u32;

/// Failure of [`AeadDirection::seal`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// The payload cannot be framed in a `uint32` packet length.
    PayloadTooLarge,
    /// The invocation counter has reached its last value; sealing again
    /// would require a repeated nonce.
    CounterExhausted,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::PayloadTooLarge => f.write_str("payload too large to frame"),
            SealError::CounterExhausted => f.write_str("AEAD invocation counter exhausted"),
        }
    }
}

impl core::error::Error for SealError {}

/// Failure of [`AeadDirection::open`]. Every variant is terminal for the
/// connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// `packet_length` exceeds the configured cap.
    TooLarge {
        /// Claimed `packet_length`.
        packet_length: u32,
        /// The cap.
        limit: u32,
    },
    /// `packet_length` is below [`MIN_PACKET_LENGTH`].
    TooSmall {
        /// Claimed `packet_length`.
        packet_length: u32,
    },
    /// `packet_length` is not a multiple of the block size.
    Misaligned {
        /// Claimed `packet_length`.
        packet_length: u32,
    },
    /// After a successful tag check, `padding_length` was below 4 or left
    /// no room for the payload.
    BadPadding {
        /// Claimed `packet_length`.
        packet_length: u32,
        /// Decrypted `padding_length`.
        padding_length: u8,
    },
    /// The authentication tag did not verify (ciphertext or the clear
    /// length was altered, or the keys/nonces disagree).
    TagMismatch,
    /// The invocation counter has reached its last value.
    CounterExhausted,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpenError::TooLarge {
                packet_length,
                limit,
            } => write!(
                f,
                "protected packet_length {packet_length} exceeds local limit {limit}"
            ),
            OpenError::TooSmall { packet_length } => {
                write!(f, "protected packet_length {packet_length} below minimum")
            }
            OpenError::Misaligned { packet_length } => write!(
                f,
                "protected packet_length {packet_length} not a multiple of the block size"
            ),
            OpenError::BadPadding {
                packet_length,
                padding_length,
            } => write!(
                f,
                "padding_length {padding_length} invalid for packet_length {packet_length}"
            ),
            OpenError::TagMismatch => f.write_str("authentication tag mismatch"),
            OpenError::CounterExhausted => f.write_str("AEAD invocation counter exhausted"),
        }
    }
}

impl core::error::Error for OpenError {}

/// A decrypted, verified packet borrowed from the caller's buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct ProtectedPacket<'a> {
    /// The message payload (message number first).
    pub payload: &'a [u8],
    /// Bytes the packet occupied in the buffer, including length and tag.
    pub total_len: usize,
}

/// Result of [`AeadDirection::open`].
#[derive(Debug, PartialEq, Eq)]
pub enum OpenStep<'a> {
    /// Not enough input yet; `total_len` is known once the length field has
    /// been read and validated.
    NeedMore {
        /// Total packet size if already known.
        total_len: Option<usize>,
    },
    /// A verified packet. The caller should consume `total_len` bytes.
    Packet(ProtectedPacket<'a>),
}

/// One direction of protected traffic: key schedule plus nonce state.
pub struct AeadDirection {
    cipher: Aes128Gcm,
    fixed: [u8; NONCE_FIXED_LEN],
    counter: u64,
    packets: u64,
}

impl fmt::Debug for AeadDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AeadDirection")
            .field("packets", &self.packets)
            .finish_non_exhaustive()
    }
}

impl AeadDirection {
    /// Installs the derived key and initial nonce for one direction.
    #[must_use]
    pub fn new(keys: &AeadKeys) -> Self {
        Self::from_parts(&keys.key, &keys.iv)
    }

    /// Builds a direction from raw key and IV bytes (RFC 5647 §7.1 layout).
    #[must_use]
    pub fn from_parts(key: &[u8; KEY_LEN], iv: &[u8; NONCE_LEN]) -> Self {
        let mut fixed = [0u8; NONCE_FIXED_LEN];
        fixed.copy_from_slice(&iv[..NONCE_FIXED_LEN]);
        let mut counter = [0u8; 8];
        counter.copy_from_slice(&iv[NONCE_FIXED_LEN..]);
        AeadDirection {
            cipher: Aes128Gcm::new(GenericArray::from_slice(key)),
            fixed,
            counter: u64::from_be_bytes(counter),
            packets: 0,
        }
    }

    /// Packets sealed or opened so far in this direction.
    #[must_use]
    pub const fn packets(&self) -> u64 {
        self.packets
    }

    /// The nonce the next packet will use. A public value.
    #[must_use]
    pub fn next_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..NONCE_FIXED_LEN].copy_from_slice(&self.fixed);
        nonce[NONCE_FIXED_LEN..].copy_from_slice(&self.counter.to_be_bytes());
        nonce
    }

    /// The counter's last value is never used, so the increment after a
    /// packet can never wrap.
    const fn counter_available(&self) -> bool {
        self.counter != u64::MAX
    }

    fn advance(&mut self) {
        // Guarded by `counter_available` at every call site.
        self.counter += 1;
        self.packets += 1;
    }

    /// Appends one sealed packet carrying `payload` to `out` and returns the
    /// number of bytes appended. Advances the counter once.
    pub fn seal(
        &mut self,
        payload: &[u8],
        padding_rng: &mut dyn RngCore,
        out: &mut Vec<u8>,
    ) -> Result<usize, SealError> {
        if !self.counter_available() {
            return Err(SealError::CounterExhausted);
        }
        // packet_length = 1 + payload + padding, a multiple of 16, padding >= 4.
        let unpadded = payload
            .len()
            .checked_add(1)
            .ok_or(SealError::PayloadTooLarge)?;
        let mut padding = BLOCK_SIZE - (unpadded % BLOCK_SIZE);
        if padding < MIN_PADDING {
            padding += BLOCK_SIZE;
        }
        let packet_length = unpadded
            .checked_add(padding)
            .ok_or(SealError::PayloadTooLarge)?;
        let length_field = u32::try_from(packet_length).map_err(|_| SealError::PayloadTooLarge)?;
        // padding <= 19 always fits a byte; keep the check explicit.
        let padding_byte = u8::try_from(padding).map_err(|_| SealError::PayloadTooLarge)?;

        let start = out.len();
        out.extend_from_slice(&length_field.to_be_bytes());
        out.push(padding_byte);
        out.extend_from_slice(payload);
        let pad_start = out.len();
        out.resize(pad_start + padding, 0);
        padding_rng.fill_bytes(&mut out[pad_start..]);

        let nonce = GenericArray::from(self.next_nonce());
        let (aad, body) = out[start..].split_at_mut(LENGTH_LEN);
        let tag = self
            .cipher
            .encrypt_in_place_detached(&nonce, aad, body)
            .map_err(|_| SealError::PayloadTooLarge)?;
        out.extend_from_slice(&tag);
        self.advance();
        Ok(out.len() - start)
    }

    /// Examines the front of `buf` for one protected packet, decrypting in
    /// place once the whole packet is present. See the module documentation
    /// for the order of checks.
    pub fn open<'a>(
        &mut self,
        buf: &'a mut [u8],
        limits: &PacketLimits,
    ) -> Result<OpenStep<'a>, OpenError> {
        if buf.len() < LENGTH_LEN {
            return Ok(OpenStep::NeedMore { total_len: None });
        }
        let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if packet_length > limits.max_packet_length {
            return Err(OpenError::TooLarge {
                packet_length,
                limit: limits.max_packet_length,
            });
        }
        if packet_length < MIN_PACKET_LENGTH {
            return Err(OpenError::TooSmall { packet_length });
        }
        if packet_length % BLOCK_SIZE as u32 != 0 {
            return Err(OpenError::Misaligned { packet_length });
        }
        let body_len = usize::try_from(packet_length).map_err(|_| OpenError::TooLarge {
            packet_length,
            limit: limits.max_packet_length,
        })?;
        let total_len = LENGTH_LEN + body_len + TAG_LEN;
        if buf.len() < total_len {
            return Ok(OpenStep::NeedMore {
                total_len: Some(total_len),
            });
        }
        if !self.counter_available() {
            return Err(OpenError::CounterExhausted);
        }

        let nonce = GenericArray::from(self.next_nonce());
        let (aad, rest) = buf.split_at_mut(LENGTH_LEN);
        let (body, rest) = rest.split_at_mut(body_len);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&rest[..TAG_LEN]);
        self.cipher
            .decrypt_in_place_detached(&nonce, aad, body, &GenericArray::from(tag))
            .map_err(|_| OpenError::TagMismatch)?;
        self.advance();

        let padding_length = body[0];
        let payload_len = body_len
            .checked_sub(1)
            .and_then(|n| n.checked_sub(usize::from(padding_length)))
            .filter(|_| usize::from(padding_length) >= MIN_PADDING)
            .ok_or(OpenError::BadPadding {
                packet_length,
                padding_length,
            })?;
        Ok(OpenStep::Packet(ProtectedPacket {
            payload: &body[1..1 + payload_len],
            total_len,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::fixtures::{KEY_A, KEY_B, KEY_C, KEY_D};
    use rand_core::{CryptoRng, RngCore};

    /// Padding source that writes a constant byte.
    struct Fill(u8);

    impl RngCore for Fill {
        fn next_u32(&mut self) -> u32 {
            u32::from_ne_bytes([self.0; 4])
        }
        fn next_u64(&mut self) -> u64 {
            u64::from_ne_bytes([self.0; 8])
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            dest.fill(self.0);
            Ok(())
        }
    }

    impl CryptoRng for Fill {}

    const LIMITS: PacketLimits = PacketLimits {
        max_packet_length: 1024,
    };

    fn key16(k: &[u8; 32]) -> [u8; 16] {
        k[..16].try_into().unwrap()
    }

    fn iv12(k: &[u8; 32]) -> [u8; 12] {
        k[..12].try_into().unwrap()
    }

    /// Server-to-client direction of the transcript fixture (key D, IV B).
    fn s2c() -> AeadDirection {
        AeadDirection::from_parts(&key16(&KEY_D), &iv12(&KEY_B))
    }

    /// Client-to-server direction of the transcript fixture (key C, IV A).
    fn c2s() -> AeadDirection {
        AeadDirection::from_parts(&key16(&KEY_C), &iv12(&KEY_A))
    }

    /// Sealed by python3 `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
    /// with key D / IV B from the transcript fixture, zero padding bytes:
    ///
    ///   def seal(key, iv, counter, payload):
    ///       n = 1 + len(payload); pad = 16 - n % 16
    ///       if pad < 4: pad += 16
    ///       length = struct.pack(">I", n + pad)
    ///       nonce = iv[:4] + struct.pack(">Q", struct.unpack(">Q", iv[4:])[0] + counter)
    ///       return length + AESGCM(key).encrypt(nonce, bytes([pad]) + payload + b"\0"*pad, length)
    ///   ext_info = bytes([7]) + struct.pack(">I", 1) + string(b"server-sig-algs") + string(b"ssh-ed25519")
    ///   service_accept = bytes([6]) + string(b"ssh-userauth")
    pub(crate) const EXT_INFO_SEALED: [u8; 68] = [
        0x00, 0x00, 0x00, 0x30, 0xba, 0xa5, 0x85, 0xcd, 0x92, 0xd3, 0xa7, 0xa5, 0x45, 0x55, 0x13,
        0x23, 0x56, 0xd6, 0xb4, 0x7f, 0x61, 0xcf, 0x30, 0x5e, 0xc8, 0x20, 0x36, 0x60, 0x4b, 0x06,
        0x2e, 0xca, 0xf0, 0x19, 0x75, 0xc7, 0x01, 0xbd, 0xd9, 0xa0, 0x49, 0x24, 0xce, 0x85, 0x6c,
        0xa3, 0x2c, 0xcc, 0x9e, 0x52, 0x86, 0x69, 0x45, 0xab, 0x08, 0xaa, 0x87, 0x74, 0x4e, 0xdd,
        0xc3, 0xf4, 0x62, 0xc9, 0x39, 0x45, 0xd2, 0x91,
    ];
    pub(crate) const SERVICE_ACCEPT_SEALED: [u8; 52] = [
        0x00, 0x00, 0x00, 0x20, 0xf8, 0x89, 0x3f, 0xf8, 0xc5, 0x1d, 0x66, 0x38, 0xc4, 0xb3, 0x05,
        0xab, 0xb3, 0x13, 0xbb, 0x0a, 0x82, 0xf0, 0xd4, 0x78, 0xcd, 0x8d, 0xf3, 0x22, 0x2e, 0xf8,
        0x88, 0x8b, 0xb8, 0x52, 0xd9, 0xac, 0x77, 0x06, 0xdf, 0x83, 0x09, 0xf9, 0xa6, 0x6b, 0x75,
        0xc3, 0x97, 0x7c, 0x99, 0x09, 0x1f, 0x81,
    ];

    fn ext_info_payload() -> Vec<u8> {
        let mut p = alloc::vec![7, 0, 0, 0, 1, 0, 0, 0, 15];
        p.extend_from_slice(b"server-sig-algs");
        p.extend_from_slice(&[0, 0, 0, 11]);
        p.extend_from_slice(b"ssh-ed25519");
        p
    }

    fn service_accept_payload() -> Vec<u8> {
        let mut p = alloc::vec![6, 0, 0, 0, 12];
        p.extend_from_slice(b"ssh-userauth");
        p
    }

    #[test]
    fn seal_reproduces_python_oracle_and_advances_the_counter() {
        let mut dir = s2c();
        assert_eq!(dir.next_nonce(), iv12(&KEY_B));
        let mut out = Vec::new();
        let n = dir
            .seal(&ext_info_payload(), &mut Fill(0), &mut out)
            .unwrap();
        assert_eq!(n, EXT_INFO_SEALED.len());
        assert_eq!(out, EXT_INFO_SEALED);
        assert_eq!(dir.packets(), 1);
        // Second packet: counter + 1, different nonce, appended after the first.
        let mut expected_nonce = iv12(&KEY_B);
        let c = u64::from_be_bytes(expected_nonce[4..].try_into().unwrap()) + 1;
        expected_nonce[4..].copy_from_slice(&c.to_be_bytes());
        assert_eq!(dir.next_nonce(), expected_nonce);
        let n2 = dir
            .seal(&service_accept_payload(), &mut Fill(0), &mut out)
            .unwrap();
        assert_eq!(n2, SERVICE_ACCEPT_SEALED.len());
        assert_eq!(&out[n..], &SERVICE_ACCEPT_SEALED);
        assert_eq!(dir.packets(), 2);
    }

    #[test]
    fn open_verifies_python_sealed_packets_in_sequence() {
        let mut dir = s2c();
        let mut buf = EXT_INFO_SEALED.to_vec();
        buf.extend_from_slice(&SERVICE_ACCEPT_SEALED);
        buf.extend_from_slice(b"tail");
        match dir.open(&mut buf, &LIMITS).unwrap() {
            OpenStep::Packet(p) => {
                assert_eq!(p.payload, ext_info_payload());
                assert_eq!(p.total_len, 68);
            }
            other => panic!("{other:?}"),
        }
        buf.drain(..68);
        match dir.open(&mut buf, &LIMITS).unwrap() {
            OpenStep::Packet(p) => {
                assert_eq!(p.payload, service_accept_payload());
                assert_eq!(p.total_len, 52);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(dir.packets(), 2);
    }

    #[test]
    fn packets_opened_out_of_order_fail_the_tag() {
        // Nonce for packet 2 used on packet 1's bytes.
        let mut dir = s2c();
        let mut buf = SERVICE_ACCEPT_SEALED.to_vec();
        assert_eq!(dir.open(&mut buf, &LIMITS), Err(OpenError::TagMismatch));
        // Wrong direction's keys.
        let mut dir = c2s();
        let mut buf = EXT_INFO_SEALED.to_vec();
        assert_eq!(dir.open(&mut buf, &LIMITS), Err(OpenError::TagMismatch));
    }

    #[test]
    fn round_trip_with_random_padding_and_various_sizes() {
        for len in [1usize, 2, 10, 11, 12, 15, 27, 100, 255, 256, 1000] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut tx = c2s();
            let mut rx = c2s();
            let mut out = Vec::new();
            let n = tx.seal(&payload, &mut Fill(0x5a), &mut out).unwrap();
            assert_eq!(n, out.len());
            let packet_length = u32::from_be_bytes(out[..4].try_into().unwrap()) as usize;
            assert_eq!(packet_length % 16, 0, "len {len}");
            assert!(packet_length >= 1 + len + 4, "len {len}");
            assert!(packet_length < 1 + len + 4 + 16, "len {len}");
            assert_eq!(n, 4 + packet_length + 16);
            let mut rx_buf = out.clone();
            match rx.open(&mut rx_buf, &PacketLimits::default()).unwrap() {
                OpenStep::Packet(p) => {
                    assert_eq!(p.payload, payload, "len {len}");
                    assert_eq!(p.total_len, n);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn need_more_progression_from_length_alone() {
        let mut dir = s2c();
        for n in 0..EXT_INFO_SEALED.len() {
            let mut buf = EXT_INFO_SEALED[..n].to_vec();
            let expected = if n < 4 { None } else { Some(68) };
            assert_eq!(
                dir.open(&mut buf, &LIMITS).unwrap(),
                OpenStep::NeedMore {
                    total_len: expected
                },
                "prefix {n}"
            );
        }
        assert_eq!(dir.packets(), 0, "no counter movement before a full packet");
    }

    #[test]
    fn length_field_is_validated_before_the_body_is_waited_for() {
        let mut dir = s2c();
        // Huge claim with only the four length bytes present: an error, not
        // NeedMore.
        assert_eq!(
            dir.open(&mut [0xff, 0xff, 0xff, 0xff], &LIMITS),
            Err(OpenError::TooLarge {
                packet_length: u32::MAX,
                limit: 1024
            })
        );
        assert_eq!(
            dir.open(&mut [0, 0, 4, 16], &LIMITS),
            Err(OpenError::TooLarge {
                packet_length: 1040,
                limit: 1024
            })
        );
        // Exactly the cap is allowed (NeedMore), one block more is not.
        assert_eq!(
            dir.open(&mut [0, 0, 4, 0], &LIMITS).unwrap(),
            OpenStep::NeedMore {
                total_len: Some(4 + 1024 + 16)
            }
        );
        assert_eq!(
            dir.open(&mut [0, 0, 0, 0], &LIMITS),
            Err(OpenError::TooSmall { packet_length: 0 })
        );
        assert_eq!(
            dir.open(&mut [0, 0, 0, 15], &LIMITS),
            Err(OpenError::TooSmall { packet_length: 15 })
        );
        assert_eq!(
            dir.open(&mut [0, 0, 0, 17], &LIMITS),
            Err(OpenError::Misaligned { packet_length: 17 })
        );
        assert_eq!(
            dir.open(&mut [0, 0, 0, 40], &LIMITS),
            Err(OpenError::Misaligned { packet_length: 40 })
        );
        assert_eq!(dir.packets(), 0);
    }

    #[test]
    fn tampered_ciphertext_byte_fails_the_tag() {
        for index in [4usize, 5, 20, 51] {
            let mut dir = s2c();
            let mut buf = EXT_INFO_SEALED.to_vec();
            buf[index] ^= 0x01;
            assert_eq!(
                dir.open(&mut buf, &LIMITS),
                Err(OpenError::TagMismatch),
                "index {index}"
            );
            assert_eq!(dir.packets(), 0);
        }
        // Tampered tag byte.
        let mut dir = s2c();
        let mut buf = EXT_INFO_SEALED.to_vec();
        buf[67] ^= 0x80;
        assert_eq!(dir.open(&mut buf, &LIMITS), Err(OpenError::TagMismatch));
    }

    #[test]
    fn tampered_length_that_stays_well_formed_fails_the_tag() {
        // EXT_INFO is 48 bytes of body; claim 32 so the buffer is still long
        // enough and the length is still aligned. The AAD changed, so the
        // tag over the (shorter) body cannot verify.
        let mut dir = s2c();
        let mut buf = EXT_INFO_SEALED.to_vec();
        buf[3] = 0x20;
        assert_eq!(dir.open(&mut buf, &LIMITS), Err(OpenError::TagMismatch));
        assert_eq!(dir.packets(), 0);
    }

    #[test]
    fn bad_padding_after_a_valid_tag_is_rejected() {
        // Seal a packet whose padding_length byte we then forge *before*
        // sealing (the tag is over the forged plaintext, so it verifies).
        let mut tx = c2s();
        let mut rx = c2s();
        let mut out = Vec::new();
        tx.seal(&[9; 11], &mut Fill(0), &mut out).unwrap(); // packet_length 16
        // Re-seal manually with padding_length = 3 (< 4): decrypt the body,
        // patch, re-encrypt with the same nonce using the provider directly.
        let cipher = Aes128Gcm::new(GenericArray::from_slice(&key16(&KEY_C)));
        let nonce = GenericArray::from(iv12(&KEY_A));
        let (aad, rest) = out.split_at_mut(4);
        let (body, tag) = rest.split_at_mut(16);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        cipher
            .decrypt_in_place_detached(&nonce, aad, body, &GenericArray::from(tag_arr))
            .unwrap();
        assert_eq!(body[0], 4);
        body[0] = 3;
        let new_tag = cipher.encrypt_in_place_detached(&nonce, aad, body).unwrap();
        tag.copy_from_slice(&new_tag);
        assert_eq!(
            rx.open(&mut out, &LIMITS),
            Err(OpenError::BadPadding {
                packet_length: 16,
                padding_length: 3
            })
        );
        // padding_length that eats the whole body.
        let mut tx = c2s();
        let mut rx = c2s();
        let mut out = Vec::new();
        tx.seal(&[9; 11], &mut Fill(0), &mut out).unwrap();
        let (aad, rest) = out.split_at_mut(4);
        let (body, tag) = rest.split_at_mut(16);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        cipher
            .decrypt_in_place_detached(&nonce, aad, body, &GenericArray::from(tag_arr))
            .unwrap();
        body[0] = 16;
        let new_tag = cipher.encrypt_in_place_detached(&nonce, aad, body).unwrap();
        tag.copy_from_slice(&new_tag);
        assert_eq!(
            rx.open(&mut out, &LIMITS),
            Err(OpenError::BadPadding {
                packet_length: 16,
                padding_length: 16
            })
        );
    }

    #[test]
    fn counter_never_wraps() {
        let mut iv = iv12(&KEY_A);
        iv[4..].copy_from_slice(&u64::MAX.to_be_bytes());
        let mut dir = AeadDirection::from_parts(&key16(&KEY_C), &iv);
        let mut out = Vec::new();
        assert_eq!(
            dir.seal(&[1], &mut Fill(0), &mut out),
            Err(SealError::CounterExhausted)
        );
        assert!(out.is_empty(), "nothing written on refusal");
        let mut buf = EXT_INFO_SEALED.to_vec();
        assert_eq!(
            dir.open(&mut buf, &LIMITS),
            Err(OpenError::CounterExhausted)
        );

        // One before the end: one packet is allowed, the next is refused.
        iv[4..].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
        let mut tx = AeadDirection::from_parts(&key16(&KEY_C), &iv);
        let mut rx = AeadDirection::from_parts(&key16(&KEY_C), &iv);
        let mut out = Vec::new();
        tx.seal(&[1], &mut Fill(0), &mut out).unwrap();
        assert_eq!(tx.next_nonce()[4..], u64::MAX.to_be_bytes());
        assert_eq!(
            tx.seal(&[1], &mut Fill(0), &mut Vec::new()),
            Err(SealError::CounterExhausted)
        );
        let mut buf = out.clone();
        assert!(matches!(
            rx.open(&mut buf, &LIMITS).unwrap(),
            OpenStep::Packet(_)
        ));
        assert_eq!(rx.open(&mut buf, &LIMITS), Err(OpenError::CounterExhausted));
    }

    #[test]
    fn rewriting_a_sealed_buffer_does_not_touch_the_counter() {
        let mut dir = c2s();
        let mut out = Vec::new();
        dir.seal(&[5, 0, 0, 0, 0], &mut Fill(0), &mut out).unwrap();
        let nonce_after = dir.next_nonce();
        // The host may write the same bytes in any number of pieces, or
        // copy them; none of that involves the direction.
        let copy_a = out.clone();
        let copy_b = out.clone();
        assert_eq!(copy_a, copy_b);
        assert_eq!(dir.packets(), 1);
        assert_eq!(dir.next_nonce(), nonce_after);
        // Two seals of identical payload produce different bytes.
        let mut second = Vec::new();
        dir.seal(&[5, 0, 0, 0, 0], &mut Fill(0), &mut second)
            .unwrap();
        assert_ne!(out, second);
        assert_ne!(dir.next_nonce(), nonce_after);
    }

    #[test]
    fn debug_shows_no_key_material() {
        let dir = c2s();
        let s = alloc::format!("{dir:?}");
        assert_eq!(s, "AeadDirection { packets: 0, .. }");
    }
}
