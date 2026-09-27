//! Small helpers for the `tatami_ssh_keys` round-5 targets (`spki_conversion`,
//! `known_hosts`, `openssh_private_key`). Harness-only code.
//!
//! Deliberately not a second parser: the targets call the production APIs
//! and check focused properties (see each target's comment). What lives here
//! are independent primitives those properties need:
//!
//! - [`ed25519_blob`]: the hand layout of an `ssh-ed25519` public-key blob.
//! - [`b64_encode`]: RFC 4648 §4 padded base64 (to write `known_hosts` key
//!   fields and PEM armor without the decoder under test).
//! - [`hmac_sha1`]: RFC 2104 HMAC over `sha1::Sha1`, not the `hmac` crate
//!   that `tatami_ssh_openssh_compat` uses (hashed `known_hosts` names, the
//!   harness writes them because the library has no writer); RFC 2202
//!   vectors below. A harness-only oracle.
//! - [`glob_ref`]: the textbook dynamic-programming `*`/`?` matcher.
//! - [`openssh_armor`]: `-----BEGIN OPENSSH PRIVATE KEY-----` armor.
//!
//! Round 6 (RSA and ECDSA P-256 host keys), same rule: primitives, not a
//! parser.
//!
//! - [`b64_decode`]: strict padded RFC 4648 §4 decoding (fixtures).
//! - [`mpint_body`], [`positive_mpint_magnitude`]: the RFC 4251 §5 `mpint`
//!   rule written from the RFC (minimal two's complement; positive means
//!   non-empty, sign bit clear, no redundant leading zero).
//! - [`rsa_blob`], [`p256_blob`]: hand layouts (RFC 4253 §6.6, RFC 5656
//!   §3.1).
//! - [`bignum`]: schoolbook multiplication and shift-subtract remainder on
//!   big-endian magnitudes, so the harness can build RSA private keys with
//!   `p·q = n` and predict the CRT exponents without the production
//!   `crypto-bigint`.
//! - [`der`]: minimal DER TLV/INTEGER writing (SPKI and PKCS#1 oracles).
//! - [`fixtures`]: the OpenSSH/OpenSSL fixtures of
//!   `crates/tatami_ssh_keys/src/test_vectors.rs`, read from that file at
//!   compile time (`include_str!`) so the harness never keeps a drifting
//!   copy.
//! - [`mock`]: a recording `SignatureProvider` (no RSA or NIST-curve code
//!   in the harness, no `ring`): it records every request and answers with
//!   a fixed verdict or by recomputing a harness-only *mock signature*
//!   (a hash of key, scheme and message), which lets a harness "server"
//!   sign and the client-side provider check that it was handed exactly the
//!   right message, key and fixed-width signature.

use ed25519_dalek::VerifyingKey;

/// Hand layout of an `ssh-ed25519` public-key blob (RFC 8709 §4).
#[must_use]
pub fn ed25519_blob(key: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(51);
    b.extend_from_slice(&11u32.to_be_bytes());
    b.extend_from_slice(b"ssh-ed25519");
    b.extend_from_slice(&32u32.to_be_bytes());
    b.extend_from_slice(key);
    b
}

/// `true` iff the provider accepts the 32 bytes as an Ed25519 public key.
#[must_use]
pub fn dalek_accepts(key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(key).is_ok()
}

/// RFC 4648 §4 base64 with `=` padding.
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut b = [0u8; 3];
        b[..chunk.len()].copy_from_slice(chunk);
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize])
            } else {
                '='
            });
        }
    }
    out
}

/// RFC 2104 HMAC-SHA1 (block size 64).
#[must_use]
pub fn hmac_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..20].copy_from_slice(&Sha1::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha1::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// `pattern` matches all of `name`: `*` any run (also empty), `?` one byte.
#[must_use]
pub fn glob_ref(pattern: &[u8], name: &[u8]) -> bool {
    let w = name.len() + 1;
    let mut m = vec![false; (pattern.len() + 1) * w];
    m[0] = true;
    for i in 1..=pattern.len() {
        for j in 0..=name.len() {
            m[i * w + j] = match pattern[i - 1] {
                b'*' => m[(i - 1) * w + j] || (j > 0 && m[i * w + j - 1]),
                c => j > 0 && (c == b'?' || c == name[j - 1]) && m[(i - 1) * w + j - 1],
            };
        }
    }
    m[pattern.len() * w + name.len()]
}

/// RFC 7468 armor with 70-column lines, as `ssh-keygen` writes.
#[must_use]
pub fn openssh_armor(bin: &[u8]) -> String {
    let body = b64_encode(bin);
    let mut text = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in body.as_bytes().chunks(70) {
        text.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    text
}

/// Strict RFC 4648 §4 decoding with `=` padding (length a multiple of 4,
/// canonical trailing bits). `None` on any deviation.
#[must_use]
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let t = text.as_bytes();
    if !t.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() / 4 * 3);
    for (i, chunk) in t.chunks(4).enumerate() {
        let last = i + 1 == t.len() / 4;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            let v = ALPHABET.iter().position(|&a| a == c)? as u32;
            n = (n << 6) | v;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = 3 - pad;
        if bytes[keep..].iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Some(out)
}

/// SSH `string`.
#[must_use]
pub fn ssh_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// The `mpint` body (no length prefix) of a non-negative magnitude
/// (RFC 4251 §5): leading zero bytes dropped, a `0x00` sign byte added when
/// the top bit is set; zero is the empty body.
#[must_use]
pub fn mpint_body(magnitude: &[u8]) -> Vec<u8> {
    let m = strip_zeros(magnitude);
    let mut body = Vec::with_capacity(m.len() + 1);
    if m.first().is_some_and(|&b| b & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(m);
    body
}

/// `magnitude` without leading zero bytes.
#[must_use]
pub fn strip_zeros(magnitude: &[u8]) -> &[u8] {
    let start = magnitude
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(magnitude.len());
    &magnitude[start..]
}

/// The magnitude of an `mpint` body that is a strictly positive integer in
/// the minimal encoding RFC 4251 §5 requires, else `None` (zero, negative,
/// or a redundant leading `0x00`).
#[must_use]
pub fn positive_mpint_magnitude(body: &[u8]) -> Option<&[u8]> {
    match body {
        [] => None,
        [b, ..] if b & 0x80 != 0 => None,
        [0] => None,
        [0, next, ..] if next & 0x80 == 0 => None,
        [0, rest @ ..] => Some(rest),
        _ => Some(body),
    }
}

/// Bit length of a big-endian magnitude (leading zeros ignored).
#[must_use]
pub fn bit_len(magnitude: &[u8]) -> usize {
    let m = strip_zeros(magnitude);
    match m.first() {
        None => 0,
        Some(&top) => m.len() * 8 - top.leading_zeros() as usize,
    }
}

/// Hand layout of an `ssh-rsa` blob: `string "ssh-rsa", mpint e, mpint n`.
#[must_use]
pub fn rsa_blob(e: &[u8], n: &[u8]) -> Vec<u8> {
    let mut b = ssh_string(b"ssh-rsa");
    b.extend(ssh_string(&mpint_body(e)));
    b.extend(ssh_string(&mpint_body(n)));
    b
}

/// Hand layout of an ECDSA blob: `string algorithm, string curve, string Q`.
#[must_use]
pub fn p256_blob(algorithm: &[u8], curve: &[u8], q: &[u8]) -> Vec<u8> {
    let mut b = ssh_string(algorithm);
    b.extend(ssh_string(curve));
    b.extend(ssh_string(q));
    b
}

/// Big-endian magnitudes, via little-endian `u32` limbs. Enough for the
/// harness to build `n = p·q` and `d mod (p−1)`; nothing here is constant
/// time and nothing here is used by production code.
pub mod bignum {
    use core::cmp::Ordering;

    fn limbs(be: &[u8]) -> Vec<u32> {
        let mut out = vec![0u32; be.len().div_ceil(4)];
        for (i, &b) in be.iter().rev().enumerate() {
            out[i / 4] |= u32::from(b) << (8 * (i % 4));
        }
        out
    }

    fn bytes(l: &[u32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(l.len() * 4);
        for w in l.iter().rev() {
            out.extend_from_slice(&w.to_be_bytes());
        }
        super::strip_zeros(&out).to_vec()
    }

    fn cmp_limbs(a: &[u32], b: &[u32]) -> Ordering {
        let n = a.len().max(b.len());
        for i in (0..n).rev() {
            let (x, y) = (
                a.get(i).copied().unwrap_or(0),
                b.get(i).copied().unwrap_or(0),
            );
            if x != y {
                return x.cmp(&y);
            }
        }
        Ordering::Equal
    }

    /// `a·b`, minimal big-endian.
    #[must_use]
    pub fn mul(a: &[u8], b: &[u8]) -> Vec<u8> {
        let (x, y) = (limbs(a), limbs(b));
        let mut out = vec![0u32; x.len() + y.len() + 1];
        for (i, &xi) in x.iter().enumerate() {
            let mut carry = 0u64;
            for (j, &yj) in y.iter().enumerate() {
                let t = u64::from(xi) * u64::from(yj) + u64::from(out[i + j]) + carry;
                out[i + j] = t as u32;
                carry = t >> 32;
            }
            let mut k = i + y.len();
            while carry != 0 {
                let t = u64::from(out[k]) + carry;
                out[k] = t as u32;
                carry = t >> 32;
                k += 1;
            }
        }
        bytes(&out)
    }

    /// `a mod m` by binary long division; `m` must be non-zero.
    #[must_use]
    pub fn rem(a: &[u8], m: &[u8]) -> Vec<u8> {
        let m = limbs(super::strip_zeros(m));
        assert!(m.iter().any(|&w| w != 0), "division by zero");
        let a = super::strip_zeros(a);
        let mut r = vec![0u32; m.len() + 1];
        for &byte in a {
            for bit in (0..8).rev() {
                // r = 2r + bit
                let mut carry = u32::from((byte >> bit) & 1);
                for w in &mut r {
                    let next = *w >> 31;
                    *w = (*w << 1) | carry;
                    carry = next;
                }
                if cmp_limbs(&r, &m) != Ordering::Less {
                    let mut borrow = 0i64;
                    for (i, w) in r.iter_mut().enumerate() {
                        let t = i64::from(*w) - i64::from(m.get(i).copied().unwrap_or(0)) - borrow;
                        *w = t as u32;
                        borrow = i64::from(t < 0);
                    }
                }
            }
        }
        bytes(&r)
    }

    /// `a − 1` for `a ≥ 1`, minimal big-endian.
    #[must_use]
    pub fn sub_one(a: &[u8]) -> Vec<u8> {
        let mut out = super::strip_zeros(a).to_vec();
        assert!(!out.is_empty(), "0 - 1");
        for b in out.iter_mut().rev() {
            let (v, borrow) = b.overflowing_sub(1);
            *b = v;
            if !borrow {
                break;
            }
        }
        super::strip_zeros(&out).to_vec()
    }

    /// Numeric comparison of two magnitudes.
    #[must_use]
    pub fn cmp(a: &[u8], b: &[u8]) -> Ordering {
        cmp_limbs(&limbs(a), &limbs(b))
    }
}

/// Minimal DER writing (X.690 §10: definite, minimal lengths).
pub mod der {
    /// Tag, minimal length, content.
    #[must_use]
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let be = len.to_be_bytes();
            let bytes = super::strip_zeros(&be);
            out.push(0x80 | bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
        out.extend_from_slice(content);
        out
    }

    /// Minimal non-negative INTEGER of a big-endian magnitude.
    #[must_use]
    pub fn uint(magnitude: &[u8]) -> Vec<u8> {
        let m = super::strip_zeros(magnitude);
        let mut content = Vec::with_capacity(m.len() + 1);
        if m.first().is_none_or(|&b| b & 0x80 != 0) {
            content.push(0);
        }
        content.extend_from_slice(m);
        tlv(0x02, &content)
    }

    /// `SEQUENCE` of the concatenated parts.
    #[must_use]
    pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
        tlv(0x30, &parts.concat())
    }

    /// Content octets of rsaEncryption (1.2.840.113549.1.1.1).
    pub const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// Content octets of id-RSASSA-PSS (1.2.840.113549.1.1.10).
    pub const OID_RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    /// Content octets of id-ecPublicKey (1.2.840.10045.2.1).
    pub const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// Content octets of prime256v1 (1.2.840.10045.3.1.7).
    pub const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// Content octets of secp384r1 (1.3.132.0.34).
    pub const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

    /// RFC 5280 `SubjectPublicKeyInfo` from an algorithm identifier body and
    /// the `subjectPublicKey` bytes (`unused` bits count first).
    #[must_use]
    pub fn spki(algorithm_body: &[u8], unused: u8, key: &[u8]) -> Vec<u8> {
        let alg = tlv(0x30, algorithm_body);
        let bits = tlv(0x03, &[&[unused][..], key].concat());
        seq(&[&alg, &bits])
    }

    /// RSA SPKI (RFC 3279 §2.3.1): parameters `NULL`, key
    /// `SEQUENCE { INTEGER n, INTEGER e }`.
    #[must_use]
    pub fn rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
        let alg = [tlv(0x06, OID_RSA), vec![0x05, 0x00]].concat();
        spki(&alg, 0, &seq(&[&uint(n), &uint(e)]))
    }

    /// P-256 SPKI (RFC 5480): id-ecPublicKey with the named curve.
    #[must_use]
    pub fn p256_spki(point: &[u8]) -> Vec<u8> {
        let alg = [tlv(0x06, OID_EC), tlv(0x06, OID_P256)].concat();
        spki(&alg, 0, point)
    }
}

/// The OpenSSH/OpenSSL fixtures of the production unit tests, extracted at
/// run time from the source text of `test_vectors.rs` (embedded at compile
/// time). Provenance is documented in that file (throwaway `ssh-keygen`
/// keys, never host keys).
pub mod fixtures {
    use std::collections::HashMap;
    use std::sync::OnceLock;

    const SOURCE: &str = include_str!("../../../crates/tatami_ssh_keys/src/test_vectors.rs");

    /// Every `pub const NAME: &str = "...";` of the file, with the Rust
    /// line-continuation (`\` newline) of the multi-line constants removed.
    fn table() -> &'static HashMap<&'static str, String> {
        static TABLE: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
        TABLE.get_or_init(|| {
            let mut out = HashMap::new();
            let mut rest = SOURCE;
            while let Some(at) = rest.find("pub const ") {
                rest = &rest[at + 10..];
                let Some(colon) = rest.find(':') else { break };
                let name = &rest[..colon];
                let Some(eq) = rest.find('=') else { break };
                let body = rest[eq + 1..].trim_start();
                let Some(body) = body.strip_prefix('"') else {
                    continue;
                };
                let Some(close) = body.find('"') else { break };
                let mut value = &body[..close];
                if let Some(v) = value.strip_prefix("\\\n") {
                    value = v;
                }
                out.insert(name, value.to_string());
                rest = &body[close..];
            }
            out
        })
    }

    /// The text of fixture `name`; panics if the production file lost it.
    #[must_use]
    pub fn text(name: &str) -> &'static str {
        table()
            .get(name)
            .unwrap_or_else(|| panic!("fixture {name} missing from test_vectors.rs"))
    }

    /// A base64 fixture, decoded.
    #[must_use]
    pub fn bytes(name: &str) -> Vec<u8> {
        super::b64_decode(text(name)).unwrap_or_else(|| panic!("fixture {name} is not base64"))
    }
}

/// A recording host `SignatureProvider` for the harness.
pub mod mock {
    use std::sync::{Arc, Mutex};

    use sha2::{Digest, Sha256, Sha512};
    use tatami_ssh_keys::algorithm::SignatureScheme;
    use tatami_ssh_keys::provider::{
        ProviderRejected, ProviderRequest, RsaHash, SignatureProvider,
    };

    /// An owned copy of a [`ProviderRequest`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Request {
        /// RSASSA-PKCS1-v1_5.
        Rsa {
            hash: RsaHash,
            modulus: Vec<u8>,
            exponent: Vec<u8>,
            signature: Vec<u8>,
        },
        /// ECDSA P-256 / SHA-256.
        P256 { point: [u8; 65], rs: [u8; 64] },
    }

    /// One `verify` call.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Call {
        pub message: Vec<u8>,
        pub request: Request,
    }

    /// How the provider answers.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Verdict {
        Accept,
        Reject,
        /// Accept iff the signature is the harness mock signature of the
        /// request's key over the message ([`rsa_signature`],
        /// [`p256_signature`]).
        MockSignature,
    }

    #[derive(Default, Debug)]
    struct Log {
        calls: Vec<Call>,
        asked: Vec<SignatureScheme>,
    }

    /// Records every `supports`/`verify`; `Send` so a `ClientHandshake` can
    /// own it while the harness keeps a handle to the log.
    #[derive(Clone, Debug)]
    pub struct RecordingProvider {
        supports: Vec<SignatureScheme>,
        verdict: Verdict,
        log: Arc<Mutex<Log>>,
    }

    impl RecordingProvider {
        #[must_use]
        pub fn new(supports: &[SignatureScheme], verdict: Verdict) -> Self {
            RecordingProvider {
                supports: supports.to_vec(),
                verdict,
                log: Arc::new(Mutex::new(Log::default())),
            }
        }

        /// Every non-Ed25519 scheme.
        #[must_use]
        pub fn all(verdict: Verdict) -> Self {
            Self::new(
                &[
                    SignatureScheme::EcdsaP256Sha256,
                    SignatureScheme::RsaSha2_512,
                    SignatureScheme::RsaSha2_256,
                ],
                verdict,
            )
        }

        /// The `verify` calls so far.
        #[must_use]
        pub fn calls(&self) -> Vec<Call> {
            self.log.lock().expect("log").calls.clone()
        }

        /// The schemes `supports` was asked about so far.
        #[must_use]
        pub fn asked(&self) -> Vec<SignatureScheme> {
            self.log.lock().expect("log").asked.clone()
        }

        /// What `supports` answers, without recording the question.
        #[must_use]
        pub fn supports_scheme(&self, s: SignatureScheme) -> bool {
            self.supports.contains(&s)
        }

        /// The configured verdict.
        #[must_use]
        pub fn verdict(&self) -> Verdict {
            self.verdict
        }
    }

    impl SignatureProvider for RecordingProvider {
        fn supports(&self, scheme: SignatureScheme) -> bool {
            self.log.lock().expect("log").asked.push(scheme);
            self.supports.contains(&scheme)
        }

        fn verify(
            &self,
            message: &[u8],
            request: &ProviderRequest<'_>,
        ) -> Result<(), ProviderRejected> {
            let (owned, genuine) = match *request {
                ProviderRequest::RsaPkcs1v15 {
                    hash,
                    modulus,
                    exponent,
                    signature,
                } => (
                    Request::Rsa {
                        hash,
                        modulus: modulus.to_vec(),
                        exponent: exponent.to_vec(),
                        signature: signature.to_vec(),
                    },
                    signature == rsa_signature(hash, modulus, exponent, message).as_slice(),
                ),
                ProviderRequest::EcdsaP256Sha256 {
                    public_point,
                    signature,
                } => (
                    Request::P256 {
                        point: *public_point,
                        rs: *signature,
                    },
                    *signature == p256_signature(public_point, message),
                ),
            };
            self.log.lock().expect("log").calls.push(Call {
                message: message.to_vec(),
                request: owned,
            });
            match self.verdict {
                Verdict::Accept => Ok(()),
                Verdict::Reject => Err(ProviderRejected),
                Verdict::MockSignature if genuine => Ok(()),
                Verdict::MockSignature => Err(ProviderRejected),
            }
        }
    }

    /// Mock RSA "signature": `modulus.len()` bytes of SHA-512 counter-mode
    /// output over hash, key and message, first byte zero (so a server may
    /// send it shortened, RFC 8332 §3). Not RSA; only the harness uses it.
    #[must_use]
    pub fn rsa_signature(
        hash: RsaHash,
        modulus: &[u8],
        exponent: &[u8],
        message: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(modulus.len() + 64);
        let mut counter = 0u32;
        while out.len() < modulus.len() {
            let mut h = Sha512::new();
            h.update(b"tatami-fuzz-mock-rsa");
            h.update([u8::from(hash == RsaHash::Sha512)]);
            h.update(counter.to_be_bytes());
            for part in [modulus, exponent, message] {
                h.update((part.len() as u32).to_be_bytes());
                h.update(part);
            }
            out.extend_from_slice(&h.finalize());
            counter += 1;
        }
        out.truncate(modulus.len());
        if let Some(first) = out.first_mut() {
            *first = 0;
        }
        out
    }

    /// Mock P-256 "signature" `r || s` over point and message. `r` has a
    /// zero first byte and a set second top bit, `s` a set top bit, so the
    /// SSH encoding always exercises left-padding and the sign byte.
    #[must_use]
    pub fn p256_signature(point: &[u8; 65], message: &[u8]) -> [u8; 64] {
        let half = |tag: &[u8]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"tatami-fuzz-mock-p256");
            h.update(tag);
            h.update(point);
            h.update(message);
            h.finalize().into()
        };
        let mut r = half(b"r");
        let mut s = half(b"s");
        r[0] = 0;
        r[1] |= 0x80;
        s[0] |= 0x80;
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        out
    }

    /// The SSH inner ECDSA signature `mpint r || mpint s` of fixed `r || s`.
    #[must_use]
    pub fn p256_inner(rs: &[u8; 64]) -> Vec<u8> {
        let mut out = super::ssh_string(&super::mpint_body(&rs[..32]));
        out.extend(super::ssh_string(&super::mpint_body(&rs[32..])));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decode_rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_decode(enc).as_deref(), Some(plain.as_bytes()));
        }
        for bad in ["Zg=", "Zh==", "Zg==Zg==", "Z===", "Zm9v!", "Zm8"] {
            assert_eq!(b64_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn mpint_rule_rfc4251_examples() {
        // RFC 4251 §5 examples, positive ones.
        assert_eq!(mpint_body(&[]), b"");
        assert_eq!(
            mpint_body(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]),
            [0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
        );
        assert_eq!(mpint_body(&[0x80]), [0x00, 0x80]);
        assert_eq!(mpint_body(&[0, 0, 0x7f]), [0x7f]);
        assert_eq!(positive_mpint_magnitude(&[0x00, 0x80]), Some(&[0x80][..]));
        assert_eq!(positive_mpint_magnitude(&[0x7f]), Some(&[0x7f][..]));
        for bad in [
            &[][..],
            &[0],
            &[0, 1],
            &[0x80],
            &[0xed, 0xcc],
            &[0xff, 0xff],
        ] {
            assert_eq!(positive_mpint_magnitude(bad), None, "{bad:?}");
        }
        assert_eq!(bit_len(&[0, 0x01, 0]), 9);
        assert_eq!(bit_len(&[]), 0);
    }

    #[test]
    fn bignum_against_u128() {
        let vals: [u128; 7] = [
            1,
            2,
            255,
            65537,
            0xffff_ffff,
            0x1234_5678_9abc_def1,
            u64::MAX as u128,
        ];
        let be = |v: u128| strip_zeros(&v.to_be_bytes()).to_vec();
        for &a in &vals {
            for &b in &vals {
                assert_eq!(bignum::mul(&be(a), &be(b)), be(a * b), "{a} * {b}");
                let big = a * b + 12345;
                assert_eq!(bignum::rem(&be(big), &be(b)), be(big % b), "{big} % {b}");
                assert_eq!(bignum::cmp(&be(a), &be(b)), a.cmp(&b));
            }
            assert_eq!(bignum::sub_one(&be(a)), be(a - 1));
        }
    }

    #[test]
    fn der_lengths_are_minimal() {
        assert_eq!(der::tlv(4, &[0; 3])[..2], [4, 3]);
        assert_eq!(der::tlv(4, &[0; 200])[..3], [4, 0x81, 200]);
        assert_eq!(der::tlv(4, &[0; 300])[..4], [4, 0x82, 1, 44]);
        assert_eq!(der::uint(&[]), [2, 1, 0]);
        assert_eq!(der::uint(&[0x80]), [2, 2, 0, 0x80]);
        assert_eq!(der::uint(&[0, 1]), [2, 1, 1]);
    }

    #[test]
    fn fixtures_are_extracted_and_consistent() {
        // The SPKI fixture is the RSA SPKI of the blob's (n, e), and the
        // P-256 one the SPKI of its point: the hand DER agrees with
        // `ssh-keygen -e -m PKCS8` independently of the library.
        let rsa = fixtures::bytes("RSA_2048_PUB");
        assert_eq!(&rsa[..11], b"\0\0\0\x07ssh-rsa");
        let e_len = u32::from_be_bytes(rsa[11..15].try_into().unwrap()) as usize;
        let e = &rsa[15..15 + e_len];
        let n_body = &rsa[19 + e_len..];
        assert_eq!(rsa_blob(e, positive_mpint_magnitude(n_body).unwrap()), rsa);
        assert_eq!(
            der::rsa_spki(positive_mpint_magnitude(n_body).unwrap(), e),
            fixtures::bytes("RSA_2048_SPKI")
        );
        let p = fixtures::bytes("P256_PUB");
        assert_eq!(p.len(), 104);
        assert_eq!(p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", &p[39..]), p);
        assert_eq!(der::p256_spki(&p[39..]), fixtures::bytes("P256_SPKI"));
        assert!(
            fixtures::text("RSA_2048_OPENSSH").starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        );
        assert!(fixtures::text("P256_OPENSSH").ends_with("-----END OPENSSH PRIVATE KEY-----\n"));
        assert_eq!(fixtures::bytes("P256_SEC1").len(), 121);
    }

    #[test]
    fn mock_signatures_are_shaped() {
        use tatami_ssh_keys::provider::RsaHash;
        let s = mock::rsa_signature(RsaHash::Sha256, &[0xc5; 256], &[1, 0, 1], b"m");
        assert_eq!(s.len(), 256);
        assert_eq!(s[0], 0);
        assert_ne!(
            s,
            mock::rsa_signature(RsaHash::Sha512, &[0xc5; 256], &[1, 0, 1], b"m")
        );
        let rs = mock::p256_signature(&[4; 65], b"m");
        let inner = mock::p256_inner(&rs);
        // r: 31 magnitude bytes with the top bit set -> 32-byte body; s: 33.
        assert_eq!(&inner[..4], &[0, 0, 0, 32]);
        assert_eq!(&inner[36..40], &[0, 0, 0, 33]);
    }

    #[test]
    fn base64_rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(b64_encode(plain.as_bytes()), enc);
        }
    }

    #[test]
    fn hmac_sha1_rfc2202() {
        let hex = |d: [u8; 20]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        // Key longer than the block size is hashed first (test case 6).
        assert_eq!(
            hex(hmac_sha1(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
    }

    #[test]
    fn glob_reference() {
        assert!(glob_ref(b"*", b""));
        assert!(glob_ref(b"a*b?c", b"aXXbYc"));
        assert!(!glob_ref(b"a*b?c", b"aXXbc"));
        assert!(glob_ref(b"??", b"ab"));
        assert!(!glob_ref(b"", b"a"));
        assert!(glob_ref(b"*.example", b"a.b.example"));
    }

    #[test]
    fn blob_layout() {
        let b = ed25519_blob(&[7; 32]);
        assert_eq!(b.len(), 51);
        assert_eq!(&b[..19], b"\0\0\0\x0bssh-ed25519\0\0\0\x20");
    }
}
