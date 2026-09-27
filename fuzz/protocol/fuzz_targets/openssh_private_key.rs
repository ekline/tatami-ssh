#![no_main]
//! `tatami_ssh_keys::openssh_key`: `HostPrivateKey::from_openssh` (Ed25519,
//! RSA, ECDSA P-256) and `Ed25519HostPrivateKey::from_openssh`, the
//! validation adapters over `ssh-key` 0.6. Pattern: stateless parser.
//!
//! 1. API/input: `sel:u8, rest`. `sel` even: `rest` (bounded by the
//!    library's 16 KiB cap and `-max_len`) is passed as key text to both
//!    decoders. `sel & 3 == 1`: `seed:32, kind:u8, x:u8` builds an Ed25519
//!    `openssh-key-v1` container with the small writer below (PROTOCOL.key
//!    layout, independent of the parser), then applies one tamper
//!    `kind % 11`. `sel & 3 == 3`: `kind:u8` then fuzz key material builds an
//!    RSA (`kind` even) or P-256 container the same way, with one tamper
//!    (see `structured_rsa` / `structured_p256`). Structure is generated
//!    because random mutation of base64 armor essentially never keeps check
//!    integers, the public-key copies, the padding and (for RSA) `p·q = n`
//!    consistent, so the success and consistency paths would stay
//!    unreached. RSA factors are fuzz bytes with the top two bits and the
//!    low bit set, not primes: the import checks `p·q = n` and `d < n`, not
//!    primality, and the harness computes `n`, `d mod (p−1)` and
//!    `d mod (q−1)` with its own schoolbook bignum (`keys_support::bignum`),
//!    not the production `crypto-bigint`.
//! 2. Outcomes: a key, or `PrivateKeyError` {TooLarge, NotOpenssh,
//!    Encrypted, UnsupportedAlgorithm, Malformed, PublicKeyMismatch,
//!    Policy}.
//! 3. Properties:
//!    - Any accepted key (raw or structured, any type) is internally
//!      consistent: `ssh_blob()` parses with `HostKey::parse` as the same key
//!      type, `fingerprint()` is SHA-256 of that blob, the DER format matches
//!      the type (Ed25519 → PKCS#8, exactly the RFC 8410 prefix + the seed
//!      whose derived public key is the blob's; RSA → PKCS#1 starting
//!      `SEQUENCE { INTEGER 0, INTEGER n, INTEGER e, ...` with the blob's
//!      `n`, `e`; P-256 → SEC1 of exactly 121 bytes: fixed prefix, non-zero
//!      scalar, fixed middle, and the blob's 65-byte point). The OpenSSH
//!      fixtures convert to exactly OpenSSL's PKCS#1 / SEC1 bytes.
//!      `Ed25519HostPrivateKey::from_openssh` agrees for Ed25519 keys and
//!      refuses the others with `UnsupportedAlgorithm(name)`. `Debug` never
//!      shows secrets.
//!    - Structured Ed25519 (unchanged): the untampered container is accepted
//!      with exactly the fuzz seed; public keys consistent with each other
//!      but not derived from the seed give `PublicKeyMismatch`; outer/
//!      embedded public mismatch, check-integer mismatch, two keys, a KDF on
//!      an unencrypted key, wrong padding, trailing bytes and truncation give
//!      `Malformed`; a non-`none` cipher (`aes256-ctr` + `bcrypt`, opaque
//!      block-aligned ciphertext) gives `Encrypted`, in well under 50 ms (no
//!      KDF is linked). Both decoders agree on every result.
//!    - Structured RSA: untampered → accepted, PKCS#1 equals the harness DER
//!      of `(0, n, e, d, p, q, d mod (p−1), d mod (q−1), iqmp)`; `n` with a
//!      flipped bit (both copies), a changed `q`, `d = n`, `iqmp` longer than
//!      `p` → `PublicKeyMismatch`; 1024-bit modulus → `Policy(RsaModulus)`;
//!      even `e` → `Policy(RsaExponent)`; outer ≠ inner public key or
//!      check-integer mismatch → `Malformed`.
//!    - Structured P-256: untampered → accepted with exactly the fuzz scalar
//!      and point (point validity is the TLS provider's job); zero scalar,
//!      31-byte scalar (the documented `ssh-key` limitation), outer ≠ inner
//!      point → `Malformed`; compressed-point tag → `Malformed` or
//!      `Policy(PointEncoding)`; `nistp384` inner curve → refused.
//!
//!    Seeds: `ssh-keygen`-generated test fixtures (Ed25519, encrypted,
//!    ECDSA, RSA 2048, P-256, RSA 1024, P-384; the same ones as the unit tests
//!    in `openssh_key.rs` / `test_vectors.rs`), plus structured descriptions
//!    per tamper kind. Secrets are synthetic.
//! 4. Not covered: `ssh-key`'s internal error wording; whether RSA factors
//!    are prime or the P-256 scalar matches the point (the host's `ring`
//!    load does that); file permissions and size checks (host layer,
//!    unit-tested in `crates/tatami_ssh`).

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use tatami_ssh_fuzz_protocol::keys_support::{
    bignum, der, ed25519_blob, fixtures, mpint_body, openssh_armor, p256_blob, rsa_blob, ssh_string,
};
use tatami_ssh_fuzz_protocol::tcp_support::Cursor;
use tatami_ssh_keys::algorithm::KeyType;
use tatami_ssh_keys::error::KeyError;
use tatami_ssh_keys::fingerprint::Sha256Fingerprint;
use tatami_ssh_keys::host_key::HostKey;
use tatami_ssh_keys::openssh_key::{
    Ed25519HostPrivateKey, HostPrivateKey, PrivateKeyError, PrivateKeyFormat,
};

const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// RFC 5915 `ECPrivateKey` around a P-256 scalar and point, written from
/// the ASN.1: `SEQUENCE(119) { INTEGER 1, OCTET STRING(32) d,
/// [0] { OID prime256v1 }, [1] { BIT STRING(66) { 0, Q } } }`.
fn sec1(scalar: &[u8; 32], point: &[u8]) -> Vec<u8> {
    let params = der::tlv(0xa0, &der::tlv(0x06, der::OID_P256));
    let public = der::tlv(0xa1, &der::tlv(0x03, &[&[0u8][..], point].concat()));
    der::seq(&[&der::uint(&[1]), &der::tlv(0x04, scalar), &params, &public])
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

/// Fields of one container; `valid` gives what `ssh-keygen -N ''` writes.
struct Container {
    cipher: &'static [u8],
    kdf: &'static [u8],
    nkeys: u32,
    outer: [u8; 32],
    checkints: (u32, u32),
    inner: [u8; 32],
    seed: [u8; 32],
    embedded: [u8; 32],
    bad_padding: bool,
    opaque_private: Option<Vec<u8>>,
    trailing: Vec<u8>,
}

impl Container {
    fn valid(seed: [u8; 32]) -> Self {
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Container {
            cipher: b"none",
            kdf: b"none",
            nkeys: 1,
            outer: public,
            checkints: (0x5eed_0001, 0x5eed_0001),
            inner: public,
            seed,
            embedded: public,
            bad_padding: false,
            opaque_private: None,
            trailing: Vec::new(),
        }
    }

    fn binary(&self) -> Vec<u8> {
        let mut bin = b"openssh-key-v1\0".to_vec();
        put_string(&mut bin, self.cipher);
        put_string(&mut bin, self.kdf);
        // bcrypt options: string salt (16 bytes), uint32 rounds.
        let mut kdf_options = Vec::new();
        if self.kdf != b"none" {
            put_string(&mut kdf_options, &[0x5a; 16]);
            kdf_options.extend_from_slice(&16u32.to_be_bytes());
        }
        put_string(&mut bin, &kdf_options);
        bin.extend_from_slice(&self.nkeys.to_be_bytes());
        put_string(&mut bin, &ed25519_blob(&self.outer));
        let private = match &self.opaque_private {
            Some(p) => p.clone(),
            None => {
                let mut p = Vec::new();
                p.extend_from_slice(&self.checkints.0.to_be_bytes());
                p.extend_from_slice(&self.checkints.1.to_be_bytes());
                put_string(&mut p, b"ssh-ed25519");
                put_string(&mut p, &self.inner);
                put_string(&mut p, &[self.seed, self.embedded].concat());
                // A 3-byte comment forces padding 1..=n to be present.
                put_string(&mut p, b"fz!");
                let mut pad = 1u8;
                while p.len() % 8 != 0 {
                    p.push(pad);
                    pad += 1;
                }
                if self.bad_padding {
                    *p.last_mut().expect("padding present") ^= 0x40;
                }
                p
            }
        };
        put_string(&mut bin, &private);
        bin.extend_from_slice(&self.trailing);
        bin
    }
}

/// An unencrypted single-key container with `outer` as the public blob and
/// `key_fields` (algorithm name first) as the private key body.
fn generic_container(outer: &[u8], key_fields: &[u8], checkints: (u32, u32)) -> Vec<u8> {
    let mut bin = b"openssh-key-v1\0".to_vec();
    put_string(&mut bin, b"none");
    put_string(&mut bin, b"none");
    put_string(&mut bin, b"");
    bin.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut bin, outer);
    let mut p = Vec::new();
    p.extend_from_slice(&checkints.0.to_be_bytes());
    p.extend_from_slice(&checkints.1.to_be_bytes());
    p.extend_from_slice(key_fields);
    put_string(&mut p, b"fz!");
    let mut pad = 1u8;
    while p.len() % 8 != 0 {
        p.push(pad);
        pad += 1;
    }
    put_string(&mut bin, &p);
    bin
}

fn check_accepted(key: &Ed25519HostPrivateKey) {
    let pkcs8 = key.to_pkcs8_der();
    assert_eq!(pkcs8.len(), 48);
    assert_eq!(pkcs8[..16], PKCS8_PREFIX);
    let seed: [u8; 32] = pkcs8[16..].try_into().expect("32");
    let derived = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(
        key.public_key().as_bytes(),
        &derived,
        "public not derived from seed"
    );
    assert_eq!(&key.ssh_blob()[..], &ed25519_blob(&derived)[..]);
    let dbg = format!("{key:?}");
    assert!(!dbg.contains("seed") && !dbg.contains("private"), "{dbg}");
}

/// Consistency of any accepted key; `text` is what was decoded.
fn check_accepted_any(key: &HostPrivateKey, text: &[u8]) {
    let blob = key.ssh_blob();
    let parsed = HostKey::parse(&blob).expect("an accepted key's blob parses");
    assert_eq!(parsed.key_type(), key.key_type());
    assert_eq!(parsed.to_blob(), blob, "canonical blob");
    let digest: [u8; 32] = Sha256::digest(&blob).into();
    assert_eq!(key.fingerprint(), Sha256Fingerprint::from_bytes(digest));
    let converted = key.to_private_key_der();
    let dbg = format!("{key:?} {converted:?}");
    assert!(!dbg.contains("seed") && !dbg.contains("private"), "{dbg}");
    let d = &converted.der[..];
    let ed_only = Ed25519HostPrivateKey::from_openssh(text);
    match (key, &parsed) {
        (HostPrivateKey::Ed25519(k), HostKey::Ed25519(_)) => {
            assert_eq!(converted.format, PrivateKeyFormat::Pkcs8);
            check_accepted(k);
            assert_eq!(d, &k.to_pkcs8_der()[..]);
            let other = ed_only.expect("the Ed25519 decoder accepts an Ed25519 key");
            assert_eq!(other.ssh_blob(), k.ssh_blob());
            assert_eq!(&other.ssh_blob()[..], &blob[..]);
        }
        (HostPrivateKey::Rsa(k), HostKey::Rsa(p)) => {
            assert_eq!(converted.format, PrivateKeyFormat::Pkcs1);
            assert_eq!(k.public_key(), p);
            // `SEQUENCE` with a minimal length covering the rest; at least
            // 2048 bits, so the content needs the two-byte length form.
            assert_eq!(d[..2], [0x30, 0x82]);
            assert_eq!(der::tlv(0x30, &d[4..]), d, "one SEQUENCE, nothing after");
            let head = [
                der::uint(&[]),
                der::uint(p.modulus()),
                der::uint(p.exponent()),
            ]
            .concat();
            assert_eq!(&d[4..4 + head.len()], &head[..], "version 0, n, e");
            assert_eq!(
                ed_only.map(|_| ()),
                Err(PrivateKeyError::UnsupportedAlgorithm("ssh-rsa".into()))
            );
            if blob == fixtures::bytes("RSA_2048_PUB") {
                assert_eq!(d, fixtures::bytes("RSA_2048_PKCS1"), "OpenSSL's PKCS#1");
            }
        }
        (HostPrivateKey::EcdsaP256(k), HostKey::EcdsaP256(p)) => {
            assert_eq!(converted.format, PrivateKeyFormat::Sec1);
            assert_eq!(k.public_key(), p);
            assert_eq!(d.len(), 121);
            let scalar: [u8; 32] = d[7..39].try_into().expect("32");
            assert!(scalar.iter().any(|&b| b != 0), "zero scalar exported");
            assert_eq!(
                d,
                sec1(&scalar, p.point()),
                "SEC1 layout with the blob's point"
            );
            assert_eq!(&d[56..], &blob[39..], "embeds the public point");
            assert_eq!(
                ed_only.map(|_| ()),
                Err(PrivateKeyError::UnsupportedAlgorithm(
                    "ecdsa-sha2-nistp256".into()
                ))
            );
            if blob == fixtures::bytes("P256_PUB") {
                assert_eq!(d, fixtures::bytes("P256_SEC1"), "OpenSSL's SEC1");
            }
        }
        (k, p) => panic!("private key type {:?} vs blob {p:?}", k.key_type()),
    }
}

/// Both decoders on one text: the general one decides; the Ed25519-only
/// one must agree on everything but the algorithm.
fn decode_both(text: &[u8]) -> Result<HostPrivateKey, PrivateKeyError> {
    let any = HostPrivateKey::from_openssh(text);
    match &any {
        Ok(key) => check_accepted_any(key, text),
        Err(e) => {
            let ed = Ed25519HostPrivateKey::from_openssh(text).map(|_| ());
            // Same refusal, except that an RSA / P-256 key refused by its own
            // checks is simply of the wrong algorithm for the Ed25519 decoder.
            let other_type = matches!(
                &ed,
                Err(PrivateKeyError::UnsupportedAlgorithm(name))
                    if name == "ssh-rsa" || name == "ecdsa-sha2-nistp256"
            ) && matches!(
                e,
                PrivateKeyError::Policy(_)
                    | PrivateKeyError::PublicKeyMismatch
                    | PrivateKeyError::Malformed(_)
            );
            assert!(
                other_type || ed.as_ref() == Err(e),
                "decoders disagree: {ed:?} vs {e:?}"
            );
        }
    }
    any
}

fn structured_ed25519(rest: &[u8]) {
    let mut cur = Cursor::new(rest);
    let seed: [u8; 32] = cur.take_filled(32, 7).try_into().expect("32");
    let kind = cur.u8() % 11;
    let x = cur.u8();
    let other = SigningKey::from_bytes(&[seed[0] ^ 0xa5 ^ x | 1; 32])
        .verifying_key()
        .to_bytes();
    let mut c = Container::valid(seed);
    if other == c.outer {
        return;
    }
    let mut truncate = None;
    let expect: fn(&PrivateKeyError) -> bool = match kind {
        0 => |_| false,
        1 => {
            c.outer = other;
            c.inner = other;
            c.embedded = other;
            |e| *e == PrivateKeyError::PublicKeyMismatch
        }
        2 => {
            c.outer = other;
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        3 => {
            c.embedded = other;
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        4 => {
            c.checkints.1 ^= 1 + u32::from(x);
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        5 => {
            c.nkeys = 2 + u32::from(x);
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        6 => {
            c.kdf = b"bcrypt";
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        7 => {
            c.bad_padding = true;
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        8 => {
            c.trailing = vec![x; 1 + usize::from(x % 16)];
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        9 => {
            truncate = Some(usize::from(x));
            |e| matches!(e, PrivateKeyError::Malformed(_))
        }
        _ => {
            c.cipher = b"aes256-ctr";
            c.kdf = b"bcrypt";
            c.opaque_private = Some(vec![x; 16 * (1 + usize::from(x % 8))]);
            |e| *e == PrivateKeyError::Encrypted
        }
    };
    let mut bin = c.binary();
    if let Some(t) = truncate {
        bin.truncate(t % bin.len());
    }
    let text = openssh_armor(&bin);
    let started = Instant::now();
    let result = Ed25519HostPrivateKey::from_openssh(text.as_bytes());
    let elapsed = started.elapsed();
    let any = decode_both(text.as_bytes());
    assert_eq!(any.is_ok(), result.is_ok(), "both decoders agree");
    match (kind, result) {
        (0, Ok(key)) => {
            check_accepted(&key);
            assert_eq!(key.to_pkcs8_der()[16..], seed, "exactly the fuzz seed");
            assert_eq!(any.expect("agreed").key_type(), KeyType::Ed25519);
        }
        (0, Err(e)) => panic!("valid container refused: {e}\n{text}"),
        (k, Ok(_)) => panic!("tamper kind {k} accepted\n{text}"),
        (k, Err(e)) => {
            assert!(expect(&e), "tamper kind {k}: unexpected {e:?}\n{text}");
            if k == 10 {
                assert!(
                    elapsed < Duration::from_millis(50),
                    "encrypted took {elapsed:?}"
                );
            }
        }
    }
}

/// A factor-like magnitude of `len` bytes: top two bits and low bit set.
fn factor(cur: &mut Cursor<'_>, len: usize, fill: u32) -> Vec<u8> {
    let mut f = cur.take_filled(len, fill);
    f[0] |= 0xc0;
    f[len - 1] |= 1;
    f
}

fn rsa_fields(n: &[u8], e: &[u8], d: &[u8], iqmp: &[u8], p: &[u8], q: &[u8]) -> Vec<u8> {
    let mut out = ssh_string(b"ssh-rsa");
    for m in [n, e, d, iqmp, p, q] {
        out.extend(ssh_string(&mpint_body(m)));
    }
    out
}

fn structured_rsa(cur: &mut Cursor<'_>, tamper: u8) {
    let half = if tamper == 4 { 64 } else { 128 };
    let p = factor(cur, half, 103);
    let mut q = factor(cur, half, 107);
    let n = bignum::mul(&p, &q);
    assert_eq!(
        n.len(),
        2 * half,
        "top two bits make n exactly 2*half bytes"
    );
    assert!(n[0] & 0x80 != 0);
    let e: Vec<u8> = if tamper == 5 {
        vec![1, 0, 0]
    } else {
        vec![1, 0, 1]
    };
    let d_len = 1 + usize::from(cur.u8()) % n.len();
    let mut d = cur.take_filled(d_len, 109);
    d[0] |= 1;
    if d_len == n.len() {
        d[0] = (n[0] >> 1).max(1);
    }
    let iqmp_len = if tamper == 7 {
        half + 1
    } else {
        1 + usize::from(cur.u8()) % half
    };
    let mut iqmp = cur.take_filled(iqmp_len, 113);
    iqmp[0] |= 1;
    let mut n_inner = n.clone();
    let mut n_outer = n.clone();
    let mut checkints = (0x0bad_cafe, 0x0bad_cafe);
    match tamper {
        2 => {
            n_inner[half] ^= 0x10;
            n_outer = n_inner.clone();
        }
        3 => d = n.clone(),
        6 => n_outer[half] ^= 0x10,
        8 => checkints.1 ^= 1,
        9 => q[half / 2] ^= 0x04,
        _ => {}
    }
    let bin = generic_container(
        &rsa_blob(&e, &n_outer),
        &rsa_fields(&n_inner, &e, &d, &iqmp, &p, &q),
        checkints,
    );
    let text = openssh_armor(&bin);
    let got = decode_both(text.as_bytes());
    let dp = bignum::rem(&d, &bignum::sub_one(&p));
    let dq = bignum::rem(&d, &bignum::sub_one(&q));
    match tamper {
        0 | 1 if dp.is_empty() || dq.is_empty() => {
            assert_eq!(got.map(|_| ()), Err(PrivateKeyError::PublicKeyMismatch));
        }
        0 | 1 => {
            let key = got.unwrap_or_else(|e| panic!("valid RSA container refused: {e}\n{text}"));
            assert_eq!(key.key_type(), KeyType::Rsa);
            assert_eq!(key.ssh_blob(), rsa_blob(&e, &n));
            let want = der::seq(&[
                &der::uint(&[]),
                &der::uint(&n),
                &der::uint(&e),
                &der::uint(&d),
                &der::uint(&p),
                &der::uint(&q),
                &der::uint(&dp),
                &der::uint(&dq),
                &der::uint(&iqmp),
            ]);
            let converted = key.to_private_key_der();
            assert_eq!(converted.format, PrivateKeyFormat::Pkcs1);
            assert_eq!(
                &converted.der[..],
                &want[..],
                "PKCS#1 with harness CRT values"
            );
        }
        2 | 3 | 7 | 9 => assert_eq!(
            got.map(|_| ()),
            Err(PrivateKeyError::PublicKeyMismatch),
            "tamper {tamper}\n{text}"
        ),
        4 => assert_eq!(
            got.map(|_| ()),
            Err(PrivateKeyError::Policy(KeyError::RsaModulus { bits: 1024 }))
        ),
        5 => assert_eq!(
            got.map(|_| ()),
            Err(PrivateKeyError::Policy(KeyError::RsaExponent))
        ),
        _ => assert!(
            matches!(got, Err(PrivateKeyError::Malformed(_))),
            "tamper {tamper}: {:?}",
            got.map(|_| ())
        ),
    }
}

fn p256_fields(curve: &[u8], point: &[u8], scalar_body: &[u8]) -> Vec<u8> {
    let mut out = ssh_string(b"ecdsa-sha2-nistp256");
    out.extend(ssh_string(curve));
    out.extend(ssh_string(point));
    out.extend(ssh_string(scalar_body));
    out
}

fn structured_p256(cur: &mut Cursor<'_>, tamper: u8) {
    let mut point = vec![4u8];
    point.extend(cur.take_filled(64, 127));
    let mut scalar: [u8; 32] = cur.take_filled(32, 131).try_into().expect("32");
    scalar[0] |= 1;
    let outer = p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", &point);
    let mut inner_point = point.clone();
    let mut curve: &[u8] = b"nistp256";
    let mut body = mpint_body(&scalar);
    match tamper {
        3 => body = [0u8; 33].to_vec(),
        4 => {
            // A minimal mpint shorter than 32 bytes (with scalar[1] >= 0x80
            // the sign byte would restore 32 bytes, which ssh-key reads).
            scalar[0] = 0;
            scalar[1] &= 0x7f;
            body = mpint_body(&scalar);
            assert!(body.len() < 32);
        }
        5 => inner_point[64] ^= 1,
        6 => curve = b"nistp384",
        7 => {
            point[0] = 2;
            inner_point[0] = 2;
        }
        _ => {}
    }
    let outer = if tamper == 7 {
        p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", &point)
    } else {
        outer
    };
    let bin = generic_container(
        &outer,
        &p256_fields(curve, &inner_point, &body),
        (0x0bad_f00d, 0x0bad_f00d),
    );
    let text = openssh_armor(&bin);
    let got = decode_both(text.as_bytes());
    match tamper {
        0..=2 => {
            let key = got.unwrap_or_else(|e| panic!("valid P-256 container refused: {e}\n{text}"));
            assert_eq!(key.key_type(), KeyType::EcdsaP256);
            assert_eq!(key.ssh_blob(), outer);
            let converted = key.to_private_key_der();
            assert_eq!(converted.format, PrivateKeyFormat::Sec1);
            assert_eq!(
                &converted.der[..],
                &sec1(&scalar, &point)[..],
                "exactly the fuzz scalar"
            );
        }
        3..=5 => assert!(
            matches!(got, Err(PrivateKeyError::Malformed(_))),
            "tamper {tamper}: {:?}",
            got.map(|_| ())
        ),
        6 => assert!(
            matches!(
                got,
                Err(PrivateKeyError::Malformed(_) | PrivateKeyError::UnsupportedAlgorithm(_))
            ),
            "inner curve nistp384: {:?}",
            got.map(|_| ())
        ),
        _ => assert!(
            matches!(
                got,
                Err(PrivateKeyError::Malformed(_)
                    | PrivateKeyError::Policy(KeyError::PointEncoding))
            ),
            "compressed tag: {:?}",
            got.map(|_| ())
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    match sel & 3 {
        0 | 2 => {
            let _ = decode_both(rest);
        }
        1 => structured_ed25519(rest),
        _ => {
            let mut cur = Cursor::new(rest);
            let kind = cur.u8();
            if kind & 1 == 0 {
                structured_rsa(&mut cur, (kind >> 1) % 10);
            } else {
                structured_p256(&mut cur, (kind >> 1) % 8);
            }
        }
    }
});
