#![no_main]
//! `tatami_keys::openssh_key::Ed25519HostPrivateKey::from_openssh`: the
//! validation adapter over `ssh-key` 0.6. Pattern: stateless parser.
//!
//! 1. API/input: `sel:u8, rest`. `sel` even: `rest` (bounded by the
//!    library's 16 KiB cap and `-max_len`) is passed as key text. `sel` odd:
//!    `seed:32, kind:u8, x:u8` builds an `openssh-key-v1` container with the
//!    small writer below (PROTOCOL.key layout, independent of the parser),
//!    then applies one tamper `kind % 11`. Structure is generated because
//!    random mutation of base64 armor essentially never keeps check integers,
//!    the three public-key copies and the padding consistent, so the success
//!    and consistency paths would stay unreached.
//! 2. Outcomes: a key, or `PrivateKeyError` {TooLarge, NotOpenssh,
//!    Encrypted, UnsupportedAlgorithm, Malformed, PublicKeyMismatch}.
//! 3. Properties:
//!    - Any accepted key is internally consistent: its public key is the one
//!      `ed25519-dalek` derives from the seed inside its PKCS#8, the PKCS#8 is
//!      exactly the RFC 8410 prefix `302e020100300506032b657004220420` plus
//!      32 bytes, and `ssh_blob()` is the hand-layout blob.
//!    - Structured: the untampered container is accepted with exactly the
//!      fuzz seed; public keys consistent with each other but not derived
//!      from the seed give `PublicKeyMismatch` (the check `ssh-key` does not
//!      make without its `ed25519` feature); outer/embedded public mismatch,
//!      check-integer mismatch, two keys, a KDF on an unencrypted key, wrong
//!      padding, trailing bytes and truncation give `Malformed`; a non-`none`
//!      cipher (`aes256-ctr` + `bcrypt`, opaque block-aligned ciphertext)
//!      gives `Encrypted`. No KDF can run: `ssh-key` is built without its
//!      `encryption` feature (no `bcrypt-pbkdf` in the lockfile), and the
//!      target asserts the encrypted case returns in well under 50 ms.
//!
//!    Seeds: `ssh-keygen`-generated test fixtures (unencrypted, encrypted,
//!    ECDSA; the same ones as the unit tests in `openssh_key.rs`), plus one
//!    structured description per tamper kind. Secrets are synthetic.
//! 4. Not covered: `ssh-key`'s internal error wording; file permissions and
//!    size checks (host layer, unit-tested in `crates/tatami`).

use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::keys_support::{ed25519_blob, openssh_armor};
use tatami_fuzz_protocol::tcp_support::Cursor;
use tatami_keys::openssh_key::{Ed25519HostPrivateKey, PrivateKeyError};

const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

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

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel & 1 == 0 {
        if let Ok(key) = Ed25519HostPrivateKey::from_openssh(rest) {
            check_accepted(&key);
        }
        return;
    }

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
    match (kind, result) {
        (0, Ok(key)) => {
            check_accepted(&key);
            assert_eq!(key.to_pkcs8_der()[16..], seed, "exactly the fuzz seed");
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
});
