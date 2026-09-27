#![no_main]
//! `tatami_keys::spki`: strict Ed25519 `SubjectPublicKeyInfo` (RFC 8410 §4)
//! ⇄ `ssh-ed25519` blob (RFC 8709 §4). Pattern: stateless conversion.
//!
//! 1. API/input: `sel:u8, rest`. `sel` even: `rest` (bounded by `-max_len`)
//!    goes to `ed25519_public_key_from_spki`, `spki_to_ssh_blob` and
//!    `ssh_blob_to_spki`. `sel` odd: the first 32 bytes of `rest` are an
//!    Ed25519 seed; the derived (always valid) public key is wrapped in the
//!    canonical SPKI, so the success path is always reached.
//! 2. Outcomes: `Ok` key / `SpkiError`; outputs are fixed-size arrays.
//! 3. Properties: an input is accepted **iff** it is exactly the hand-written
//!    12-byte prefix `302a300506032b6570032100` followed by 32 bytes that
//!    `ed25519-dalek` accepts — for a key there is exactly one accepted DER
//!    encoding, so this is a complete, independent oracle (no DER code in the
//!    harness). Accepted inputs convert to the hand-layout blob and back to
//!    the input bytes; `spki_to_ssh_blob` fails exactly when parsing fails.
//!    `ssh_blob_to_spki` accepts exactly a hand-layout `ssh-ed25519` blob with
//!    a valid point. An SPKI is never accepted as a blob and vice versa.
//!    Seeds (`seeds/spki_conversion/`) carry the RFC 8410 §10.1 example and
//!    one fixture per rejection class (other OIDs, NULL parameters, unused
//!    bits, key length, long-form/indefinite lengths, trailing bytes,
//!    truncation); unit tests in `crates/tatami-keys/src/spki.rs` pin the
//!    exact error for each.
//! 4. Not covered: the exact `SpkiError` variant for random inputs (error
//!    precedence is not part of the contract); rustls's own SPKI handling.

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::keys_support::{dalek_accepts, ed25519_blob};
use tatami_keys::spki::{
    ED25519_SPKI_PREFIX, ed25519_public_key_from_spki, ed25519_spki, spki_to_ssh_blob, ssh_blob_of,
    ssh_blob_to_spki,
};

const PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn check(bytes: &[u8]) {
    let exact = bytes.len() == 44
        && bytes[..12] == PREFIX
        && dalek_accepts(bytes[12..].try_into().expect("32"));
    let parsed = ed25519_public_key_from_spki(bytes);
    assert_eq!(parsed.is_ok(), exact, "{bytes:02x?} -> {parsed:?}");
    match parsed {
        Ok(key) => {
            assert_eq!(&key.as_bytes()[..], &bytes[12..]);
            let hand = ed25519_blob(key.as_bytes());
            assert_eq!(&spki_to_ssh_blob(bytes).expect("accepted")[..], &hand[..]);
            assert_eq!(&ssh_blob_of(&key)[..], &hand[..]);
            assert_eq!(&ed25519_spki(&key)[..], bytes);
            assert_eq!(&ssh_blob_to_spki(&hand).expect("hand blob")[..], bytes);
        }
        Err(e) => assert_eq!(spki_to_ssh_blob(bytes).map(|_| ()), Err(e)),
    }

    let blob = bytes.len() == 51
        && bytes[..19] == *b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
        && dalek_accepts(bytes[19..].try_into().expect("32"));
    match ssh_blob_to_spki(bytes) {
        Ok(spki) => {
            assert!(blob, "only a valid hand-layout blob converts: {bytes:02x?}");
            assert_eq!(spki[..12], PREFIX);
            assert_eq!(&spki[12..], &bytes[19..]);
        }
        Err(_) => assert!(!blob, "valid blob refused: {bytes:02x?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(ED25519_SPKI_PREFIX, PREFIX);
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel & 1 == 0 {
        check(rest);
    } else if let Some(seed) = rest.get(..32) {
        let public = SigningKey::from_bytes(seed.try_into().expect("32")).verifying_key();
        let spki = [&PREFIX[..], public.as_bytes()].concat();
        check(&spki);
        assert!(ed25519_public_key_from_spki(&spki).is_ok());
        // The SSH blob and the raw key are not SPKI encodings.
        assert!(ed25519_public_key_from_spki(&ed25519_blob(public.as_bytes())).is_err());
        assert!(ed25519_public_key_from_spki(public.as_bytes()).is_err());
        assert!(ssh_blob_to_spki(&spki).is_err());
    }
});
