#![no_main]
//! `tatami_ssh_keys::spki`: strict `SubjectPublicKeyInfo` ⇄ SSH blob
//! conversion for Ed25519 (RFC 8410 §4 / RFC 8709 §4), RSA (RFC 3279 §2.3.1 /
//! RFC 4253 §6.6) and ECDSA P-256 (RFC 5480 / RFC 5656 §3.1). Pattern:
//! stateless conversion.
//!
//! 1. API/input: `sel:u8, rest`. `sel` even: `rest` (bounded by `-max_len`)
//!    goes to `host_key_from_spki`, `ed25519_public_key_from_spki`,
//!    `spki_to_ssh_blob` and `ssh_blob_to_spki`. `sel & 3 == 1`: the first 32
//!    bytes of `rest` are an Ed25519 seed; the derived (always valid) public
//!    key is wrapped in the canonical SPKI, so the success path is always
//!    reached. `sel & 3 == 3`: STRUCTURED RSA / P-256 (`kind:u8`, then fuzz
//!    key material): the SPKI is written by the harness's own minimal DER
//!    writer (`keys_support::der`, checked against the `ssh-keygen -e -m
//!    PKCS8` fixtures by a harness unit test), optionally with one field
//!    changed (see `structured`).
//! 2. Outcomes: `Ok` key / `SpkiError`; blobs and SPKIs are `Vec`s.
//! 3. Properties:
//!    - Ed25519 (unchanged): `ed25519_public_key_from_spki` accepts an input
//!      **iff** it is exactly the hand-written 12-byte prefix
//!      `302a300506032b6570032100` followed by 32 bytes that `ed25519-dalek`
//!      accepts, and `host_key_from_spki` gives an Ed25519 key for exactly
//!      those inputs. For a well-formed SPKI of another supported type it
//!      fails with `UnsupportedAlgorithm{known: Some(name)}`.
//!    - Any accepted SPKI is canonical: `host_key_spki(k)` reproduces the
//!      input, `spki_to_ssh_blob` equals `k.to_blob()` (and equals the hand
//!      layout), `ssh_blob_to_spki(k.to_blob())` gives the input back; RSA
//!      inputs equal the hand DER of `(n, e)` and satisfy the policy
//!      (odd modulus of 2048..=8192 bits, odd exponent ≥ 3 of ≤ 4 bytes),
//!      P-256 inputs are the hand prefix plus a 65-byte `04` point.
//!      `spki_to_ssh_blob` fails exactly when parsing fails, with the same
//!      error.
//!    - `ssh_blob_to_spki` succeeds exactly when `HostKey::parse` does, and
//!      then `host_key_from_spki` of the result is that key. An SPKI is never
//!      accepted as a blob and vice versa.
//!    - Structured: the unchanged SPKI is accepted iff the RSA policy holds
//!      (P-256 always); each single-field change gives its exact error
//!      (RSA: parameters absent / non-empty `NULL` → `ParametersInvalid`,
//!      unused bits → `NonZeroUnusedBits(1)`, redundant zero in `e` or a
//!      negative `n` → `NonCanonicalInteger`, trailing byte in
//!      `RSAPublicKey` → `TrailingBytes`, RSA-PSS OID → `UnsupportedAlgorithm
//!      {Some("id-RSASSA-PSS")}`, policy → `RsaModulus{bits}` /
//!      `RsaExponent`; P-256: secp384r1 → `UnsupportedCurve{Some}`, unknown
//!      curve → `UnsupportedCurve{None}`, parameters absent / `NULL` →
//!      `ParametersInvalid`, compressed or 64-byte point → `PointEncoding`,
//!      unused bits).
//!
//!    Seeds (`seeds/spki_conversion/`) carry the RFC 8410 §10.1 example, the
//!    `ssh-keygen` RSA 2048 and P-256 SPKIs, and one fixture per rejection
//!    class; unit tests in `crates/tatami_ssh_keys/src/spki.rs` pin the exact
//!    error for each.
//! 4. Not covered: the exact `SpkiError` variant for random inputs (error
//!    precedence is not part of the contract); rustls's own SPKI handling;
//!    whether a P-256 point is on the curve (the provider's job).

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use tatami_ssh_fuzz_protocol::keys_support::{
    bit_len, dalek_accepts, der, ed25519_blob, p256_blob, rsa_blob,
};
use tatami_ssh_fuzz_protocol::tcp_support::Cursor;
use tatami_ssh_keys::algorithm::KeyType;
use tatami_ssh_keys::host_key::HostKey;
use tatami_ssh_keys::spki::{
    ED25519_SPKI_PREFIX, P256_SPKI_PREFIX, SpkiError, ed25519_public_key_from_spki, ed25519_spki,
    host_key_from_spki, host_key_spki, spki_to_ssh_blob, ssh_blob_of, ssh_blob_to_spki,
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
    let any = host_key_from_spki(bytes);
    assert_eq!(
        matches!(any, Ok(HostKey::Ed25519(_))),
        exact,
        "host_key_from_spki gives Ed25519 exactly for the exact form"
    );
    match &parsed {
        Ok(key) => {
            assert_eq!(&key.as_bytes()[..], &bytes[12..]);
            let hand = ed25519_blob(key.as_bytes());
            assert_eq!(&spki_to_ssh_blob(bytes).expect("accepted")[..], &hand[..]);
            assert_eq!(&ssh_blob_of(key)[..], &hand[..]);
            assert_eq!(&ed25519_spki(key)[..], bytes);
            assert_eq!(&ssh_blob_to_spki(&hand).expect("hand blob")[..], bytes);
        }
        Err(e) => match &any {
            Ok(k) => {
                let known = match k.key_type() {
                    KeyType::Rsa => "rsaEncryption",
                    KeyType::EcdsaP256 => "id-ecPublicKey",
                    KeyType::Ed25519 => unreachable!("exact form checked above"),
                };
                assert_eq!(
                    *e,
                    SpkiError::UnsupportedAlgorithm { known: Some(known) },
                    "another supported type through the Ed25519-only API"
                );
            }
            Err(a) => assert_eq!(a, e, "same error through both APIs"),
        },
    }
    match any {
        Ok(key) => {
            assert_eq!(host_key_spki(&key), bytes, "accepted SPKIs are canonical");
            let blob = key.to_blob();
            assert_eq!(spki_to_ssh_blob(bytes).as_deref(), Ok(&blob[..]));
            assert_eq!(ssh_blob_to_spki(&blob).as_deref(), Ok(bytes));
            assert_eq!(HostKey::parse(&blob), Ok(key.clone()));
            match &key {
                HostKey::Rsa(k) => {
                    assert_eq!(bytes, der::rsa_spki(k.modulus(), k.exponent()));
                    assert_eq!(blob, rsa_blob(k.exponent(), k.modulus()));
                    let bits = bit_len(k.modulus());
                    assert!((2048..=8192).contains(&bits), "{bits}");
                    assert_eq!(k.modulus_bits(), bits);
                    assert_eq!(k.modulus().last().map(|b| b & 1), Some(1));
                    let e = k.exponent();
                    assert!(e.len() <= 4 && e[0] != 0 && e[e.len() - 1] & 1 == 1);
                    assert_ne!(e, [1]);
                }
                HostKey::EcdsaP256(k) => {
                    assert_eq!(bytes[..26], P256_SPKI_PREFIX);
                    assert_eq!(&bytes[26..], &k.point()[..]);
                    assert_eq!(bytes, der::p256_spki(k.point()));
                    assert_eq!(k.point()[0], 4);
                    assert_eq!(
                        blob,
                        p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", k.point())
                    );
                }
                HostKey::Ed25519(_) => {}
            }
        }
        Err(e) => assert_eq!(spki_to_ssh_blob(bytes), Err(e)),
    }

    let ed_blob = bytes.len() == 51
        && bytes[..19] == *b"\0\0\0\x0bssh-ed25519\0\0\0\x20"
        && dalek_accepts(bytes[19..].try_into().expect("32"));
    match (ssh_blob_to_spki(bytes), HostKey::parse(bytes)) {
        (Ok(spki), Ok(key)) => {
            assert_eq!(key.to_blob(), bytes);
            assert_eq!(spki, host_key_spki(&key));
            assert_eq!(host_key_from_spki(&spki), Ok(key.clone()));
            assert_eq!(matches!(key, HostKey::Ed25519(_)), ed_blob);
            if ed_blob {
                assert_eq!(spki[..12], PREFIX);
                assert_eq!(&spki[12..], &bytes[19..]);
            }
        }
        (Err(a), Err(b)) => {
            assert_eq!(a, b, "ssh_blob_to_spki forwards the parse error");
            assert!(!ed_blob, "valid blob refused: {bytes:02x?}");
        }
        (a, b) => panic!("ssh_blob_to_spki {a:?} vs HostKey::parse {b:?}"),
    }
}

const RSA_BITS: [usize; 8] = [2048, 2048, 2049, 3072, 4096, 8192, 2047, 1024];

fn structured(cur: &mut Cursor<'_>) {
    let kind = cur.u8();
    if kind & 1 == 0 {
        // RSA.
        let bits = RSA_BITS[usize::from(kind >> 1) % RSA_BITS.len()];
        let len = bits.div_ceil(8);
        let mut n = cur.take_filled(len, 97);
        let top = (bits - 1) % 8;
        n[0] = (n[0] & ((1u16 << (top + 1)) - 1) as u8) | (1 << top);
        n[len - 1] |= 1;
        let e: Vec<u8> = match cur.u8() % 6 {
            0..=2 => vec![1, 0, 1],
            3 => vec![3],
            4 => vec![1, 0, 0],
            _ => vec![1, 0, 0, 0, 1],
        };
        let policy_ok = (2048..=8192).contains(&bits) && e.len() <= 4 && e[e.len() - 1] & 1 == 1;
        let alg_null = [der::tlv(0x06, der::OID_RSA), vec![0x05, 0x00]].concat();
        let key = der::seq(&[&der::uint(&n), &der::uint(&e)]);
        let (spki, want): (Vec<u8>, Result<(), SpkiError>) = match cur.u8() % 12 {
            0..=3 => (
                der::rsa_spki(&n, &e),
                if policy_ok {
                    Ok(())
                } else if e.len() > 4 || e[e.len() - 1] & 1 == 0 {
                    Err(SpkiError::RsaExponent)
                } else {
                    Err(SpkiError::RsaModulus { bits })
                },
            ),
            4 => (
                der::spki(&der::tlv(0x06, der::OID_RSA), 0, &key),
                Err(SpkiError::ParametersInvalid),
            ),
            5 => (
                der::spki(
                    &[der::tlv(0x06, der::OID_RSA), vec![0x05, 0x01, 0x00]].concat(),
                    0,
                    &key,
                ),
                Err(SpkiError::ParametersInvalid),
            ),
            6 => (
                der::spki(&alg_null, 1, &key),
                Err(SpkiError::NonZeroUnusedBits(1)),
            ),
            7 => {
                let e_bad = der::tlv(0x02, &[&[0u8][..], &e].concat());
                (
                    der::spki(&alg_null, 0, &der::seq(&[&der::uint(&n), &e_bad])),
                    Err(SpkiError::NonCanonicalInteger {
                        field: "publicExponent",
                    }),
                )
            }
            8 if n[0] & 0x80 != 0 => (
                der::spki(
                    &alg_null,
                    0,
                    &der::seq(&[&der::tlv(0x02, &n), &der::uint(&e)]),
                ),
                Err(SpkiError::NonCanonicalInteger { field: "modulus" }),
            ),
            9 => (
                der::spki(&alg_null, 0, &[&key[..], &[0][..]].concat()),
                Err(SpkiError::TrailingBytes {
                    field: "RSAPublicKey",
                    count: 1,
                }),
            ),
            10 => (
                der::spki(
                    &[der::tlv(0x06, der::OID_RSA_PSS), vec![0x05, 0x00]].concat(),
                    0,
                    &key,
                ),
                Err(SpkiError::UnsupportedAlgorithm {
                    known: Some("id-RSASSA-PSS"),
                }),
            ),
            _ => {
                // The SSH blob is not an SPKI and the SPKI not a blob.
                let spki = der::rsa_spki(&n, &e);
                assert!(HostKey::parse(&spki).is_err());
                assert!(host_key_from_spki(&rsa_blob(&e, &n)).is_err());
                check(&spki);
                return;
            }
        };
        let got = host_key_from_spki(&spki);
        match (&got, &want) {
            (Ok(HostKey::Rsa(k)), Ok(())) => {
                assert_eq!(k.modulus(), &n[..]);
                assert_eq!(k.exponent(), &e[..]);
                assert_eq!(k.modulus_bits(), bits);
                assert_eq!(
                    ssh_blob_to_spki(&rsa_blob(&e, &n)).as_deref(),
                    Ok(&spki[..]),
                    "hand blob converts to the hand SPKI"
                );
            }
            (Err(g), Err(w)) => assert_eq!(g, w, "bits={bits} e={e:?}"),
            _ => panic!("RSA SPKI: library {got:?}, expected {want:?}"),
        }
        check(&spki);
    } else {
        // P-256.
        let mut point = vec![4u8];
        point.extend(cur.take_filled(64, 101));
        let alg = |curve: &[u8]| [der::tlv(0x06, der::OID_EC), der::tlv(0x06, curve)].concat();
        let (spki, want) = match cur.u8() % 10 {
            0..=2 => (der::p256_spki(&point), Ok(())),
            3 => (
                der::spki(&alg(der::OID_P384), 0, &point),
                Err(SpkiError::UnsupportedCurve {
                    known: Some("secp384r1"),
                }),
            ),
            4 => (
                der::spki(&alg(&[0x2a, 0x03, 0x04]), 0, &point),
                Err(SpkiError::UnsupportedCurve { known: None }),
            ),
            5 => (
                der::spki(&der::tlv(0x06, der::OID_EC), 0, &point),
                Err(SpkiError::ParametersInvalid),
            ),
            6 => (
                der::spki(
                    &[der::tlv(0x06, der::OID_EC), vec![0x05, 0x00]].concat(),
                    0,
                    &point,
                ),
                Err(SpkiError::ParametersInvalid),
            ),
            7 => {
                let mut compressed = point[..33].to_vec();
                compressed[0] = 2 | (point[64] & 1);
                (
                    der::spki(&alg(der::OID_P256), 0, &compressed),
                    Err(SpkiError::PointEncoding),
                )
            }
            8 => (
                der::spki(&alg(der::OID_P256), 0, &point[..64]),
                Err(SpkiError::PointEncoding),
            ),
            _ => (
                der::spki(&alg(der::OID_P256), 1, &point),
                Err(SpkiError::NonZeroUnusedBits(1)),
            ),
        };
        let got = host_key_from_spki(&spki);
        match (&got, &want) {
            (Ok(HostKey::EcdsaP256(k)), Ok(())) => {
                assert_eq!(&k.point()[..], &point[..]);
                let blob = p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", &point);
                assert_eq!(ssh_blob_to_spki(&blob).as_deref(), Ok(&spki[..]));
                assert!(HostKey::parse(&spki).is_err());
                assert!(host_key_from_spki(&blob).is_err());
            }
            (Err(g), Err(w)) => assert_eq!(g, w),
            _ => panic!("P-256 SPKI: library {got:?}, expected {want:?}"),
        }
        check(&spki);
    }
}

fuzz_target!(|data: &[u8]| {
    assert_eq!(ED25519_SPKI_PREFIX, PREFIX);
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    match sel & 3 {
        0 | 2 => check(rest),
        1 => {
            if let Some(seed) = rest.get(..32) {
                let public = SigningKey::from_bytes(seed.try_into().expect("32")).verifying_key();
                let spki = [&PREFIX[..], public.as_bytes()].concat();
                check(&spki);
                assert!(ed25519_public_key_from_spki(&spki).is_ok());
                // The SSH blob and the raw key are not SPKI encodings.
                assert!(ed25519_public_key_from_spki(&ed25519_blob(public.as_bytes())).is_err());
                assert!(ed25519_public_key_from_spki(public.as_bytes()).is_err());
                assert!(ssh_blob_to_spki(&spki).is_err());
            }
        }
        _ => structured(&mut Cursor::new(rest)),
    }
});
