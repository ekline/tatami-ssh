//! Exchange hash, shared secret and key derivation for `curve25519-sha256`
//! (RFC 4253 §§7.2, 8; RFC 5656 §4; RFC 8731 §3).
//!
//! # Exchange hash
//!
//! ```text
//! H = SHA-256( string V_C || string V_S || string I_C || string I_S ||
//!              string K_S || string Q_C || string Q_S || mpint  K )
//! ```
//!
//! - `V_C`, `V_S`: identification content **without** `CR LF`
//!   ([`crate::ident::Identification::line`]).
//! - `I_C`, `I_S`: complete `KEXINIT` payloads including the message byte,
//!   excluding packet framing (the received bytes verbatim, RFC 4253 erratum
//!   4533).
//! - `K_S`: the complete host-key blob.
//! - `Q_C`, `Q_S`: the 32-byte X25519 public values as `string`.
//! - `K`: the 32-byte shared secret encoded as a positive `mpint` — leading
//!   zero bytes stripped, a `0x00` prefix added when the high bit is set
//!   (RFC 8731 §3, [`tatami_wire::Writer::write_mpint_positive`]).
//!
//! # Key derivation (RFC 4253 §7.2)
//!
//! `K1 = HASH(K || H || X || session_id)`, `K2 = HASH(K || H || K1)`,
//! `K3 = HASH(K || H || K1 || K2)`, …, concatenated to the needed length,
//! with `K` again as its `mpint` encoding. Letters: `A` IV client→server,
//! `B` IV server→client, `C` encryption key client→server, `D` encryption key
//! server→client, `E`/`F` integrity keys (unused with an AEAD). For
//! `aes128-gcm@openssh.com` the key is 16 bytes and the IV 12 bytes
//! (RFC 5647 §7.1: 4-byte fixed field followed by an 8-byte invocation
//! counter).
//!
//! # Session identifier
//!
//! The `H` of the *initial* exchange is the session identifier for the life
//! of the connection. [`SessionId`] and [`ExchangeHash`] are distinct types
//! so a later exchange hash cannot be substituted for it by mistake.
//!
//! # Secret handling
//!
//! The ephemeral scalar, the shared secret, its `mpint` encoding, the
//! derivation state and the derived keys are zeroized on drop. None of them
//! implement `Debug`; [`ExchangeHash`] and [`SessionId`] do (they are public
//! values). Entropy is injected through [`rand_core::CryptoRngCore`] and only
//! the fallible `try_fill_bytes` is used.

use core::fmt;

use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tatami_wire::Writer;
use tatami_wire::primitives::mpint_positive_len;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Length of an X25519 public value and of the shared secret.
pub const X25519_LEN: usize = 32;
/// Length of the exchange hash (SHA-256).
pub const HASH_LEN: usize = 32;
/// AES-128 key length.
pub const AES128_KEY_LEN: usize = 16;
/// GCM nonce length (RFC 5647 §7.1).
pub const GCM_IV_LEN: usize = 12;

/// Failure of the key-agreement step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KexError {
    /// `Q_S` was not exactly 32 bytes (RFC 8731 §3).
    ServerEphemeralLength {
        /// Length received.
        found: usize,
    },
    /// The shared secret was all zero; the peer's value was a low-order
    /// point (RFC 7748 §6.1, RFC 8731 §3: MUST abort).
    AllZeroSharedSecret,
}

impl fmt::Display for KexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KexError::ServerEphemeralLength { found } => {
                write!(f, "Q_S is {found} bytes, expected {X25519_LEN}")
            }
            KexError::AllZeroSharedSecret => f.write_str("X25519 shared secret is all zero"),
        }
    }
}

impl core::error::Error for KexError {}

/// The client's ephemeral X25519 key pair for one exchange.
pub struct EphemeralKeyPair {
    secret: StaticSecret,
    public: [u8; X25519_LEN],
}

impl fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKeyPair")
            .field("public", &Hex(&self.public))
            .finish_non_exhaustive()
    }
}

impl EphemeralKeyPair {
    /// Draws 32 bytes from `rng` with `try_fill_bytes` and derives the
    /// public value. An entropy failure is returned, never panicked on.
    pub fn generate(rng: &mut dyn CryptoRngCore) -> Result<Self, rand_core::Error> {
        let mut bytes = Zeroizing::new([0u8; X25519_LEN]);
        rng.try_fill_bytes(bytes.as_mut())?;
        Ok(Self::from_secret_bytes(*bytes))
    }

    fn from_secret_bytes(bytes: [u8; X25519_LEN]) -> Self {
        // `StaticSecret` (not `EphemeralSecret`) only because the scalar is
        // built from injected bytes; it is still used exactly once and
        // zeroized on drop by the provider.
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret).to_bytes();
        EphemeralKeyPair { secret, public }
    }

    /// `Q_C`, the value to send in `KEX_ECDH_INIT`.
    #[must_use]
    pub const fn public(&self) -> &[u8; X25519_LEN] {
        &self.public
    }

    /// Computes the shared secret with the server's `Q_S`, consuming the
    /// ephemeral secret. Rejects a wrong-length value and an all-zero result.
    pub fn agree(self, server_public: &[u8]) -> Result<SharedSecret, KexError> {
        let q_s: &[u8; X25519_LEN] =
            server_public
                .try_into()
                .map_err(|_| KexError::ServerEphemeralLength {
                    found: server_public.len(),
                })?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(*q_s));
        let k = Zeroizing::new(shared.to_bytes());
        // Constant-time: the comparison result is what matters, but the
        // secret bytes should not steer early exits anywhere.
        if k.ct_eq(&[0u8; X25519_LEN]).into() {
            return Err(KexError::AllZeroSharedSecret);
        }
        Ok(SharedSecret(k))
    }
}

/// The X25519 shared secret `K`. Zeroized on drop; no `Debug`.
pub struct SharedSecret(Zeroizing<[u8; X25519_LEN]>);

impl SharedSecret {
    /// Test-only constructor for synthetic secrets (mpint edge cases).
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; X25519_LEN]) -> Self {
        SharedSecret(Zeroizing::new(bytes))
    }

    /// `K` as a positive `mpint` including its length prefix, which is the
    /// form both the exchange hash and key derivation consume.
    fn mpint(&self) -> MpintK {
        let len = mpint_positive_len(self.0.as_ref());
        let mut buf = Zeroizing::new([0u8; MPINT_K_MAX]);
        let mut w = Writer::new(&mut buf[..len]);
        w.write_mpint_positive(self.0.as_ref())
            .expect("buffer sized by mpint_positive_len");
        debug_assert_eq!(w.position(), len);
        MpintK { buf, len }
    }
}

/// Largest `mpint` encoding of a 32-byte magnitude: length prefix, optional
/// `0x00`, 32 bytes.
const MPINT_K_MAX: usize = 4 + 1 + X25519_LEN;

/// The `mpint` encoding of `K`, zeroized on drop.
struct MpintK {
    buf: Zeroizing<[u8; MPINT_K_MAX]>,
    len: usize,
}

impl MpintK {
    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// The exchange hash `H` of one key exchange.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ExchangeHash([u8; HASH_LEN]);

impl ExchangeHash {
    /// The digest bytes: the message a host key signs.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for ExchangeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ExchangeHash({})", Hex(&self.0))
    }
}

/// The session identifier: `H` of the initial exchange, fixed for the
/// connection's lifetime (RFC 4253 §7.2). Distinct from [`ExchangeHash`] so
/// a re-exchange hash can never be used where the session id is required.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId([u8; HASH_LEN]);

impl SessionId {
    /// Adopts the exchange hash of the **initial** key exchange.
    #[must_use]
    pub const fn from_initial_exchange(h: ExchangeHash) -> Self {
        SessionId(h.0)
    }

    /// The identifier bytes (used later by user authentication).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HASH_LEN] {
        &self.0
    }
}

impl fmt::Debug for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionId({})", Hex(&self.0))
    }
}

/// The public inputs to the exchange hash, exactly as they appeared on the
/// wire.
#[derive(Clone, Copy, Debug)]
pub struct ExchangeHashInputs<'a> {
    /// Client identification content without terminator.
    pub v_c: &'a [u8],
    /// Server identification content without terminator.
    pub v_s: &'a [u8],
    /// Client `KEXINIT` payload.
    pub i_c: &'a [u8],
    /// Server `KEXINIT` payload as received.
    pub i_s: &'a [u8],
    /// Server host-key blob as received.
    pub k_s: &'a [u8],
    /// Client ephemeral public value.
    pub q_c: &'a [u8],
    /// Server ephemeral public value as received.
    pub q_s: &'a [u8],
}

fn update_string(hash: &mut Sha256, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("hash inputs are bounded packet fields");
    hash.update(len.to_be_bytes());
    hash.update(bytes);
}

/// Computes `H` (RFC 5656 §4 layout with RFC 8731 §3's `mpint K`).
#[must_use]
pub fn exchange_hash(inputs: &ExchangeHashInputs<'_>, k: &SharedSecret) -> ExchangeHash {
    let mut hash = Sha256::new();
    for part in [
        inputs.v_c, inputs.v_s, inputs.i_c, inputs.i_s, inputs.k_s, inputs.q_c, inputs.q_s,
    ] {
        update_string(&mut hash, part);
    }
    hash.update(k.mpint().as_slice());
    ExchangeHash(hash.finalize().into())
}

/// Key and initial nonce for one direction of `aes128-gcm@openssh.com`.
/// Zeroized on drop; no `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKeys {
    /// AES-128 key (letters `C` / `D`).
    pub key: [u8; AES128_KEY_LEN],
    /// Initial 12-byte nonce (letters `A` / `B`): 4 fixed bytes then the
    /// 8-byte invocation counter.
    pub iv: [u8; GCM_IV_LEN],
}

/// Both directions' key material.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeySet {
    /// Letters `A` and `C`.
    pub client_to_server: AeadKeys,
    /// Letters `B` and `D`.
    pub server_to_client: AeadKeys,
}

/// RFC 4253 §7.2 key expansion for one letter, filling `out` completely.
///
/// `K_{n+1} = HASH(K || H || K1 || … || Kn)`: a hasher primed with
/// `K || H` accumulates each block as it is produced, so no block is kept
/// in a separate buffer.
pub fn derive_key(
    k: &SharedSecret,
    h: &ExchangeHash,
    letter: u8,
    session_id: &SessionId,
    out: &mut [u8],
) {
    let k_mpint = k.mpint();
    let mut base = Sha256::new();
    base.update(k_mpint.as_slice());
    base.update(h.0);
    let mut block: Zeroizing<[u8; HASH_LEN]> = Zeroizing::new(
        base.clone()
            .chain_update([letter])
            .chain_update(session_id.0)
            .finalize()
            .into(),
    );
    let mut filled = 0;
    loop {
        let n = HASH_LEN.min(out.len() - filled);
        out[filled..filled + n].copy_from_slice(&block[..n]);
        filled += n;
        if filled == out.len() {
            break;
        }
        base.update(*block);
        *block = base.clone().finalize().into();
    }
}

/// Derives the four values `aes128-gcm@openssh.com` needs.
#[must_use]
pub fn derive_aes128_gcm_keys(
    k: &SharedSecret,
    h: &ExchangeHash,
    session_id: &SessionId,
) -> KeySet {
    let mut set = KeySet {
        client_to_server: AeadKeys {
            key: [0; AES128_KEY_LEN],
            iv: [0; GCM_IV_LEN],
        },
        server_to_client: AeadKeys {
            key: [0; AES128_KEY_LEN],
            iv: [0; GCM_IV_LEN],
        },
    };
    derive_key(k, h, b'A', session_id, &mut set.client_to_server.iv);
    derive_key(k, h, b'B', session_id, &mut set.server_to_client.iv);
    derive_key(k, h, b'C', session_id, &mut set.client_to_server.key);
    derive_key(k, h, b'D', session_id, &mut set.server_to_client.key);
    set
}

/// Lowercase hex rendering for public values in `Debug` output.
pub(crate) struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Deterministic entropy for tests: hands out a fixed byte queue and fails
/// (never panics) through `try_fill_bytes` once exhausted.
#[cfg(test)]
pub(crate) mod testing {
    use alloc::collections::VecDeque;
    use core::num::NonZeroU32;

    use rand_core::{CryptoRng, RngCore};

    pub(crate) struct QueueRng {
        bytes: VecDeque<u8>,
    }

    impl QueueRng {
        pub(crate) fn new(parts: &[&[u8]]) -> Self {
            QueueRng {
                bytes: parts.iter().flat_map(|p| p.iter().copied()).collect(),
            }
        }

        pub(crate) fn remaining(&self) -> usize {
            self.bytes.len()
        }
    }

    impl RngCore for QueueRng {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }

        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.try_fill_bytes(dest)
                .expect("QueueRng exhausted through the infallible path");
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            if self.bytes.len() < dest.len() {
                let code = NonZeroU32::new(rand_core::Error::CUSTOM_START + 1).unwrap();
                return Err(rand_core::Error::from(code));
            }
            for d in dest {
                *d = self.bytes.pop_front().unwrap();
            }
            Ok(())
        }
    }

    impl CryptoRng for QueueRng {}
}

/// Fixture values shared with the handshake tests. Provenance is recorded
/// per item; nothing here was produced by the code under test.
#[cfg(test)]
pub(crate) mod fixtures {
    /// RFC 7748 §6.1 Alice's private key `a`.
    pub(crate) const ALICE_SECRET: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    /// RFC 7748 §6.1 Alice's public key `A` (`Q_C`).
    pub(crate) const ALICE_PUBLIC: [u8; 32] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    /// RFC 7748 §6.1 Bob's private key `b`.
    pub(crate) const BOB_SECRET: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    /// RFC 7748 §6.1 Bob's public key `B` (`Q_S`).
    pub(crate) const BOB_PUBLIC: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    /// RFC 7748 §6.1 shared secret `K`.
    pub(crate) const SHARED_K: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    /// RFC 8032 §7.1 TEST 1 public key; the server's host key.
    pub(crate) const HOST_PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    pub(crate) const V_C: &[u8] = b"SSH-2.0-tatami_0.1.0";
    pub(crate) const V_S: &[u8] = b"SSH-2.0-Scripted_1.0";
    /// Cookie the deterministic RNG hands to the client proposal.
    pub(crate) const CLIENT_COOKIE: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    pub(crate) const SERVER_COOKIE: [u8; 16] = [0x53; 16];

    /// `I_C`: KEXINIT with `CLIENT_COOKIE`, kex
    /// `curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com,kex-strict-c`,
    /// host key `ssh-ed25519`, ciphers `aes128-gcm@openssh.com`, MACs
    /// `hmac-sha2-256`, compression `none`, empty languages, `false`, `0`.
    /// Assembled by hand (Python `kexinit()` in the snippet below).
    pub(crate) fn i_c() -> alloc::vec::Vec<u8> {
        kexinit(
            &CLIENT_COOKIE,
            b"curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com,kex-strict-c",
        )
    }

    /// `I_S`: KEXINIT with `SERVER_COOKIE` and kex
    /// `curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com`; other
    /// lists as in `i_c`.
    pub(crate) fn i_s() -> alloc::vec::Vec<u8> {
        kexinit(
            &SERVER_COOKIE,
            b"curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
        )
    }

    fn kexinit(cookie: &[u8; 16], kex: &[u8]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec![20u8];
        out.extend_from_slice(cookie);
        for list in [
            kex,
            &b"ssh-ed25519"[..],
            b"aes128-gcm@openssh.com",
            b"aes128-gcm@openssh.com",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ] {
            out.extend_from_slice(&(list.len() as u32).to_be_bytes());
            out.extend_from_slice(list);
        }
        out.push(0);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }

    /// `K_S`: `string "ssh-ed25519" || string HOST_PUBLIC`.
    pub(crate) fn k_s() -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec![0, 0, 0, 11];
        out.extend_from_slice(b"ssh-ed25519");
        out.extend_from_slice(&[0, 0, 0, 32]);
        out.extend_from_slice(&HOST_PUBLIC);
        out
    }

    // Expected values computed with python3 (hashlib + cryptography 50):
    //
    //   import hashlib, struct
    //   def string(b): return struct.pack(">I", len(b)) + b
    //   def mpint_positive(m):
    //       m = m.lstrip(b"\x00")
    //       if not m: return string(b"")
    //       if m[0] & 0x80: m = b"\x00" + m
    //       return string(m)
    //   def kexinit(cookie, kex):
    //       out = bytes([20]) + cookie
    //       for nl in [kex, "ssh-ed25519", "aes128-gcm@openssh.com",
    //                  "aes128-gcm@openssh.com", "hmac-sha2-256", "hmac-sha2-256",
    //                  "none", "none", "", ""]:
    //           out += string(nl.encode())
    //       return out + b"\x00" + b"\x00\x00\x00\x00"
    //   A = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    //   B = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    //   K = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    //   V_C = b"SSH-2.0-tatami_0.1.0"; V_S = b"SSH-2.0-Scripted_1.0"
    //   I_C = kexinit(bytes(range(16)),
    //       "curve25519-sha256,ext-info-c,kex-strict-c-v00@openssh.com,kex-strict-c")
    //   I_S = kexinit(b"\x53"*16, "curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com")
    //   pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    //   K_S = string(b"ssh-ed25519") + string(pub)
    //   def H_of(k):
    //       h = hashlib.sha256()
    //       for p in (string(V_C), string(V_S), string(I_C), string(I_S),
    //                 string(K_S), string(A), string(B), mpint_positive(k)):
    //           h.update(p)
    //       return h.digest()
    //   H = H_of(K)
    //   def derive(letter, n):
    //       out = hashlib.sha256(mpint_positive(K) + H + letter + H).digest()
    //       while len(out) < n: out += hashlib.sha256(mpint_positive(K) + H + out).digest()
    //       return out[:n]
    //   # signature: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
    //   #   "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).sign(H)
    //   H_zero = H_of(b"\x00" + bytes(range(1, 32)))
    //   H_high = H_of(b"\x80" + bytes(range(1, 32)))

    pub(crate) const H: [u8; 32] = [
        0x74, 0x17, 0x36, 0xc3, 0xb7, 0x7e, 0xc3, 0x1f, 0x98, 0xc2, 0x9c, 0x50, 0x57, 0x12, 0xa9,
        0x5f, 0x80, 0x5c, 0xa8, 0x0e, 0xd5, 0x9e, 0x2c, 0xa8, 0x98, 0x55, 0x5e, 0x44, 0x19, 0x2d,
        0x69, 0x7e,
    ];
    pub(crate) const KEY_A: [u8; 32] = [
        0xf0, 0xd9, 0xb1, 0x7e, 0xfe, 0x1c, 0xd5, 0xbe, 0x0c, 0x98, 0xe7, 0x1a, 0xbc, 0x5c, 0xff,
        0x38, 0x49, 0x07, 0xf8, 0xb4, 0x1b, 0x52, 0xe7, 0x90, 0x0e, 0x09, 0x98, 0xd0, 0xcd, 0x08,
        0xd3, 0xef,
    ];
    pub(crate) const KEY_B: [u8; 32] = [
        0xbc, 0x8b, 0xa8, 0x31, 0x23, 0x7f, 0xad, 0x4c, 0x8e, 0x41, 0xec, 0x86, 0x2d, 0xc7, 0x35,
        0x42, 0x4c, 0x38, 0x59, 0x7b, 0x5e, 0x17, 0xc4, 0x9a, 0xfc, 0xd5, 0x0e, 0xc3, 0xbb, 0xce,
        0x6d, 0x10,
    ];
    pub(crate) const KEY_C: [u8; 32] = [
        0xd6, 0x18, 0xcb, 0xb0, 0x38, 0x7d, 0x10, 0xd5, 0xf4, 0xf1, 0x99, 0x16, 0xd8, 0x9a, 0xd1,
        0x8f, 0xd5, 0xf1, 0xb0, 0xf5, 0x36, 0x2c, 0xb1, 0x76, 0x7e, 0x8f, 0x94, 0x0c, 0x41, 0xce,
        0xfa, 0x1c,
    ];
    pub(crate) const KEY_D: [u8; 32] = [
        0x19, 0xb7, 0x55, 0x58, 0x10, 0xcb, 0xd1, 0x7d, 0x73, 0x09, 0xe8, 0x31, 0x25, 0xde, 0x37,
        0x47, 0xfb, 0x76, 0x00, 0x2a, 0x56, 0xc6, 0x9b, 0xc0, 0xc9, 0x6e, 0x14, 0xe0, 0xee, 0x0b,
        0x4a, 0x2b,
    ];
    pub(crate) const KEY_E: [u8; 32] = [
        0x98, 0xa2, 0xde, 0x09, 0xdf, 0xee, 0x96, 0x62, 0xf8, 0xc5, 0xe7, 0x6a, 0x10, 0x6b, 0x5e,
        0x9d, 0xb2, 0x4f, 0xfe, 0x81, 0x69, 0xa7, 0xc2, 0xe0, 0xf9, 0x0d, 0xea, 0x19, 0xb6, 0x42,
        0x2a, 0x39,
    ];
    pub(crate) const KEY_F: [u8; 32] = [
        0x6f, 0x38, 0x7d, 0xe5, 0x70, 0x37, 0xee, 0xfe, 0x51, 0x75, 0xd6, 0xc2, 0xd8, 0x9b, 0xab,
        0x7d, 0x73, 0x55, 0x5f, 0x58, 0x37, 0x4e, 0x9b, 0x75, 0x2a, 0xc2, 0x35, 0xd4, 0x3a, 0x6d,
        0xd0, 0x76,
    ];
    /// `derive(b"C", 64)`: exercises the `K2 = HASH(K || H || K1)` step.
    pub(crate) const KEY_C_64: [u8; 64] = [
        0xd6, 0x18, 0xcb, 0xb0, 0x38, 0x7d, 0x10, 0xd5, 0xf4, 0xf1, 0x99, 0x16, 0xd8, 0x9a, 0xd1,
        0x8f, 0xd5, 0xf1, 0xb0, 0xf5, 0x36, 0x2c, 0xb1, 0x76, 0x7e, 0x8f, 0x94, 0x0c, 0x41, 0xce,
        0xfa, 0x1c, 0x8e, 0xf8, 0x81, 0xbc, 0x07, 0x3a, 0x61, 0x0c, 0xf8, 0x65, 0x75, 0x63, 0x2e,
        0x6f, 0x17, 0xc5, 0x8c, 0xda, 0x4b, 0x6f, 0x24, 0x57, 0xab, 0x5b, 0x48, 0x02, 0xd6, 0x99,
        0xda, 0x0f, 0xae, 0x63,
    ];
    /// Ed25519 signature over `H` by RFC 8032 TEST 1's secret key.
    pub(crate) const SIGNATURE: [u8; 64] = [
        0x06, 0xad, 0x34, 0x36, 0xcc, 0xcc, 0x0f, 0xd9, 0xa0, 0x70, 0x01, 0x74, 0x77, 0xa2, 0xc3,
        0x28, 0xbf, 0x90, 0xf3, 0xaf, 0x5f, 0x8c, 0x16, 0xdf, 0x42, 0xbb, 0xff, 0x94, 0x03, 0x5a,
        0x6b, 0x0a, 0xfa, 0x2d, 0x42, 0xec, 0x51, 0x43, 0x87, 0x1c, 0xb0, 0x9c, 0x6c, 0xce, 0x7b,
        0x40, 0x5c, 0xb9, 0x1c, 0xc9, 0x69, 0x3c, 0xd5, 0x19, 0xa2, 0x64, 0x93, 0x65, 0xa2, 0xe9,
        0x51, 0x02, 0x0f, 0x0f,
    ];
    /// `H` with a synthetic `K = 00 01 02 … 1f` (leading zero stripped:
    /// 31-byte mpint body).
    pub(crate) const H_LEADING_ZERO: [u8; 32] = [
        0xa9, 0x58, 0xb1, 0x8c, 0xa8, 0xf6, 0x3c, 0x16, 0x22, 0x7c, 0x7c, 0x7a, 0x20, 0x93, 0x93,
        0x24, 0xa1, 0x30, 0x45, 0x33, 0xbd, 0x21, 0x4d, 0xd3, 0xf6, 0x9c, 0xa5, 0x45, 0xe8, 0x4c,
        0x23, 0xfc,
    ];
    /// `H` with a synthetic `K = 80 01 02 … 1f` (high bit set: `0x00`
    /// prefix, 33-byte mpint body).
    pub(crate) const H_HIGH_BIT: [u8; 32] = [
        0x9a, 0x78, 0x92, 0xa1, 0x7d, 0x06, 0x77, 0x39, 0x44, 0x51, 0x88, 0xd9, 0x55, 0x07, 0xb3,
        0x5b, 0x21, 0x77, 0x7a, 0x7d, 0xc3, 0x5a, 0x2a, 0x11, 0x58, 0xdb, 0x76, 0xea, 0xea, 0x6f,
        0xdd, 0xab,
    ];

    pub(crate) fn inputs<'a>(
        i_c: &'a [u8],
        i_s: &'a [u8],
        k_s: &'a [u8],
    ) -> super::ExchangeHashInputs<'a> {
        super::ExchangeHashInputs {
            v_c: V_C,
            v_s: V_S,
            i_c,
            i_s,
            k_s,
            q_c: &ALICE_PUBLIC,
            q_s: &BOB_PUBLIC,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::testing::QueueRng;
    use super::*;

    fn alice() -> EphemeralKeyPair {
        let mut rng = QueueRng::new(&[&ALICE_SECRET]);
        let pair = EphemeralKeyPair::generate(&mut rng).unwrap();
        assert_eq!(rng.remaining(), 0);
        pair
    }

    #[test]
    fn rfc7748_vectors() {
        let pair = alice();
        assert_eq!(pair.public(), &ALICE_PUBLIC);
        let k = pair.agree(&BOB_PUBLIC).unwrap();
        assert_eq!(k.0.as_ref(), &SHARED_K);
        // Bob's side, computed with the provider directly, agrees.
        let bob = StaticSecret::from(BOB_SECRET);
        assert_eq!(PublicKey::from(&bob).to_bytes(), BOB_PUBLIC);
        assert_eq!(
            bob.diffie_hellman(&PublicKey::from(ALICE_PUBLIC))
                .to_bytes(),
            SHARED_K
        );
        // The mpint form of this K has no padding: first byte 0x4a < 0x80.
        let m = k.mpint();
        let m = m.as_slice();
        assert_eq!(m.len(), 4 + 32);
        assert_eq!(&m[..4], &[0, 0, 0, 32]);
        assert_eq!(&m[4..], &SHARED_K);
    }

    #[test]
    fn entropy_failure_is_an_error_not_a_panic() {
        let mut rng = QueueRng::new(&[&ALICE_SECRET[..31]]);
        assert!(EphemeralKeyPair::generate(&mut rng).is_err());
    }

    #[test]
    fn wrong_length_and_low_order_server_values_are_rejected() {
        // `SharedSecret` has no `Debug`, so only the error side is compared.
        let err = |q_s: &[u8]| alice().agree(q_s).err();
        assert_eq!(
            err(&BOB_PUBLIC[..31]),
            Some(KexError::ServerEphemeralLength { found: 31 })
        );
        let mut long = [0u8; 33];
        long[..32].copy_from_slice(&BOB_PUBLIC);
        assert_eq!(
            err(&long),
            Some(KexError::ServerEphemeralLength { found: 33 })
        );
        assert_eq!(err(&[]), Some(KexError::ServerEphemeralLength { found: 0 }));
        // u = 0 and u = 1 are low-order points on Curve25519: the shared
        // secret is zero (RFC 7748 §6.1).
        assert_eq!(err(&[0u8; 32]), Some(KexError::AllZeroSharedSecret));
        let mut one = [0u8; 32];
        one[0] = 1;
        assert_eq!(err(&one), Some(KexError::AllZeroSharedSecret));
        assert!(err(&BOB_PUBLIC).is_none());
    }

    #[test]
    fn exchange_hash_matches_python_oracle() {
        let (i_c, i_s, k_s) = (i_c(), i_s(), k_s());
        let k = alice().agree(&BOB_PUBLIC).unwrap();
        let h = exchange_hash(&inputs(&i_c, &i_s, &k_s), &k);
        assert_eq!(h.as_bytes(), &H);
        assert_eq!(
            alloc::format!("{h:?}"),
            "ExchangeHash(741736c3b77ec31f98c29c505712a95f805ca80ed59e2ca898555e44192d697e)"
        );
        let sid = SessionId::from_initial_exchange(h);
        assert_eq!(sid.as_bytes(), &H);
        assert!(alloc::format!("{sid:?}").starts_with("SessionId(741736c3"));
    }

    #[test]
    fn exchange_hash_is_sensitive_to_every_input() {
        let (i_c, i_s, k_s) = (i_c(), i_s(), k_s());
        let k = alice().agree(&BOB_PUBLIC).unwrap();
        let base = inputs(&i_c, &i_s, &k_s);
        let mut variants: alloc::vec::Vec<ExchangeHashInputs<'_>> = alloc::vec![base; 7];
        variants[0].v_c = b"SSH-2.0-tatami_0.1.1";
        variants[1].v_s = b"SSH-2.0-Scripted_1.1";
        let i_c2 = {
            let mut v = i_c.clone();
            v[1] ^= 1;
            v
        };
        variants[2].i_c = &i_c2;
        let i_s2 = {
            let mut v = i_s.clone();
            v[1] ^= 1;
            v
        };
        variants[3].i_s = &i_s2;
        let k_s2 = {
            let mut v = k_s.clone();
            v[20] ^= 1;
            v
        };
        variants[4].k_s = &k_s2;
        variants[5].q_c = &BOB_PUBLIC;
        variants[6].q_s = &ALICE_PUBLIC;
        for (i, v) in variants.iter().enumerate() {
            assert_ne!(exchange_hash(v, &k).as_bytes(), &H, "variant {i}");
        }
    }

    #[test]
    fn mpint_edge_cases_match_python_oracle() {
        let (i_c, i_s, k_s) = (i_c(), i_s(), k_s());
        let mut leading_zero = [0u8; 32];
        for (i, b) in leading_zero.iter_mut().enumerate() {
            *b = i as u8;
        }
        let k = SharedSecret::from_bytes(leading_zero);
        let m = k.mpint();
        let m = m.as_slice();
        assert_eq!(m.len(), 4 + 31);
        assert_eq!(&m[..4], &[0, 0, 0, 31], "leading zero stripped");
        assert_eq!(m[4], 0x01);
        assert_eq!(
            exchange_hash(&inputs(&i_c, &i_s, &k_s), &k).as_bytes(),
            &H_LEADING_ZERO
        );

        let mut high_bit = leading_zero;
        high_bit[0] = 0x80;
        let k = SharedSecret::from_bytes(high_bit);
        let m = k.mpint();
        let m = m.as_slice();
        assert_eq!(m.len(), 4 + 33);
        assert_eq!(&m[..4], &[0, 0, 0, 33], "0x00 prefix added");
        assert_eq!(&m[4..6], &[0x00, 0x80]);
        assert_eq!(
            exchange_hash(&inputs(&i_c, &i_s, &k_s), &k).as_bytes(),
            &H_HIGH_BIT
        );
    }

    #[test]
    fn key_derivation_matches_python_oracle() {
        let k = alice().agree(&BOB_PUBLIC).unwrap();
        let h = ExchangeHash(H);
        let sid = SessionId::from_initial_exchange(h);
        for (letter, expected) in [
            (b'A', KEY_A),
            (b'B', KEY_B),
            (b'C', KEY_C),
            (b'D', KEY_D),
            (b'E', KEY_E),
            (b'F', KEY_F),
        ] {
            let mut out = [0u8; 32];
            derive_key(&k, &h, letter, &sid, &mut out);
            assert_eq!(out, expected, "letter {}", letter as char);
        }
        let mut out = [0u8; 64];
        derive_key(&k, &h, b'C', &sid, &mut out);
        assert_eq!(out, KEY_C_64);
        // Shorter requests are prefixes of the same stream.
        let mut short = [0u8; 5];
        derive_key(&k, &h, b'C', &sid, &mut short);
        assert_eq!(short, KEY_C[..5]);

        let set = derive_aes128_gcm_keys(&k, &h, &sid);
        assert_eq!(set.client_to_server.iv, KEY_A[..12]);
        assert_eq!(set.server_to_client.iv, KEY_B[..12]);
        assert_eq!(set.client_to_server.key, KEY_C[..16]);
        assert_eq!(set.server_to_client.key, KEY_D[..16]);
    }

    #[test]
    fn session_id_is_a_distinct_type_from_later_hashes() {
        let h = ExchangeHash(H);
        let sid = SessionId::from_initial_exchange(h);
        let later = ExchangeHash([9; 32]);
        // The derivation for a later exchange keeps the original session id.
        let k = alice().agree(&BOB_PUBLIC).unwrap();
        let mut a = [0u8; 16];
        derive_key(&k, &later, b'A', &sid, &mut a);
        let mut b = [0u8; 16];
        derive_key(
            &k,
            &later,
            b'A',
            &SessionId::from_initial_exchange(later),
            &mut b,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn debug_output_has_no_secret() {
        let pair = alice();
        let dbg = alloc::format!("{pair:?}");
        assert!(dbg.contains("8520f009"), "{dbg}");
        assert!(!dbg.contains("77076d0a"), "{dbg}");
    }
}
