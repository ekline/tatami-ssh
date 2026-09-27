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

#[cfg(test)]
mod tests {
    use super::*;

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
