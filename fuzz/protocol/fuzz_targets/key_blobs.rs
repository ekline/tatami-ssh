#![no_main]
//! `tatami-keys`: public-key and signature blob codecs, `ssh-ed25519` host
//! keys and signatures, `SHA256:` fingerprints and the pinned trust policy.
//!
//! # Input layout
//!
//! `sel:u8, rest...`
//!
//! - `sel < 0x80`: RAW. `rest` goes to `PublicKeyBlob::decode`,
//!   `SignatureBlob::decode`, `HostKey::from_blob` / `HostKey::parse`,
//!   `Ed25519Signature::from_blob`, and (as text) `Sha256Fingerprint::parse`.
//!   Oracles: independent layouts (`string algorithm` then body; `string
//!   algorithm, string signature` with nothing after) with exact `BlobError`
//!   (field names `algorithm`/`signature`/`key`, offsets, `TrailingBytes`);
//!   `HostKey`: `UnsupportedAlgorithm(name)` for any name but `ssh-ed25519`,
//!   `WrongLength{key,32,found}`, `InvalidKey` iff the provider rejects the
//!   32 bytes; `Ed25519Signature`: `WrongLength{signature,64,found}`;
//!   fingerprint text: prefix, `=`, 43-byte length, alphabet and canonical
//!   trailing bits by an independent decoder, `Display` reproduces the text.
//! - `sel >= 0x80`: STRUCTURED. A real Ed25519 key pair from a fuzz-derived
//!   32-byte seed (`ed25519_dalek::SigningKey::from_bytes`); the key blob is
//!   assembled BY HAND (`string "ssh-ed25519" || string key`) and must be
//!   accepted by `HostKey::from_blob`, reproduced by `encode_blob` /
//!   `encode_ed25519_blob`; `Sha256Fingerprint::of_blob` equals `sha2` over
//!   the hand blob and `Display` equals `SHA256:` + the harness base64;
//!   `parse(Display)` round-trips; `PinnedSha256` decides `Trusted` iff the
//!   pins are equal and `NoTrustPolicy` never trusts. A fuzz message is
//!   signed and the signature blob assembled by hand: `verify_signature_blob`
//!   succeeds, and FAILS with the exact error for any flipped bit in the
//!   signature or message (`Invalid`), a different key (`Invalid`), algorithm
//!   `ssh-rsa` in the signature blob (`AlgorithmMismatch`) or key blob
//!   (`UnsupportedAlgorithm`), a trailing byte in either blob, key length
//!   31/33 and signature length 63/65 (`WrongLength`).
//!
//! No private key is stored anywhere: seeds are descriptions and keys are
//! derived at run time.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use tatami_fuzz_protocol::kex_support::base64;
use tatami_fuzz_protocol::kex_support::crypto::{ed25519_key_blob, ed25519_sig_blob, string};
use tatami_fuzz_protocol::tcp_support::Cursor;
use tatami_keys::blob::{
    ED25519_BLOB_LEN, ED25519_SIGNATURE_BLOB_LEN, PublicKeyBlob, SignatureBlob, encode_ed25519_blob,
};
use tatami_keys::ed25519::{Ed25519PublicKey, Ed25519Signature, HostKey};
use tatami_keys::error::{BlobError, KeyError, VerifyError};
use tatami_keys::fingerprint::{FingerprintParseError, Sha256Fingerprint};
use tatami_keys::trust::{
    HostIdentity, HostTrustPolicy, NoTrustPolicy, PinnedSha256, TrustDecision, TrustSource,
    UntrustedReason,
};
use tatami_wire::{DecodeError, EncodeError};

// ---------------------------------------------------------------------------
// Reference layouts.
// ---------------------------------------------------------------------------

/// `string` at `pos`: `(value, next_pos)` or the exact `DecodeError`.
fn ref_string(buf: &[u8], pos: usize) -> Result<(&[u8], usize), DecodeError> {
    let available = buf.len() - pos;
    if available < 4 {
        return Err(DecodeError::Truncated {
            needed: 4,
            available,
        });
    }
    let claimed = u32::from_be_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]);
    let after = available - 4;
    if claimed as usize > after {
        return Err(DecodeError::LengthOverflow {
            claimed,
            available: after,
        });
    }
    let start = pos + 4;
    let end = start + claimed as usize;
    Ok((&buf[start..end], end))
}

fn field<'a>(
    buf: &'a [u8],
    pos: usize,
    name: &'static str,
) -> Result<(&'a [u8], usize), BlobError> {
    ref_string(buf, pos).map_err(|error| BlobError::Field {
        field: name,
        offset: pos,
        error,
    })
}

/// `string algorithm`, rest is the body; trailing bytes are the body.
fn ref_public_key_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), BlobError> {
    let (algorithm, next) = field(blob, 0, "algorithm")?;
    Ok((algorithm, &blob[next..]))
}

/// `string algorithm, string signature`, nothing after.
fn ref_signature_blob(blob: &[u8]) -> Result<(&[u8], &[u8]), BlobError> {
    let (algorithm, next) = field(blob, 0, "algorithm")?;
    let (signature, end) = field(blob, next, "signature")?;
    if end != blob.len() {
        return Err(BlobError::TrailingBytes {
            count: blob.len() - end,
        });
    }
    Ok((algorithm, signature))
}

/// What `HostKey::from_blob` must say about a decoded blob, up to the
/// provider's point check (compared separately).
enum RefHostKey {
    Ok([u8; 32]),
    Err(KeyError),
}

fn ref_host_key(blob: &[u8], algorithm: &[u8]) -> RefHostKey {
    if algorithm != b"ssh-ed25519" {
        return RefHostKey::Err(KeyError::UnsupportedAlgorithm(algorithm.to_vec()));
    }
    // Re-read from the start: offsets are relative to the whole blob.
    let (_, after_alg) = match field(blob, 0, "algorithm") {
        Ok(v) => v,
        Err(e) => return RefHostKey::Err(KeyError::Blob(e)),
    };
    let (key, end) = match field(blob, after_alg, "key") {
        Ok(v) => v,
        Err(e) => return RefHostKey::Err(KeyError::Blob(e)),
    };
    if end != blob.len() {
        return RefHostKey::Err(KeyError::Blob(BlobError::TrailingBytes {
            count: blob.len() - end,
        }));
    }
    match <[u8; 32]>::try_from(key) {
        Ok(k) => RefHostKey::Ok(k),
        Err(_) => RefHostKey::Err(KeyError::WrongLength {
            field: "key",
            expected: 32,
            found: key.len(),
        }),
    }
}

/// `SHA256:` + 43 unpadded standard base64 characters, canonical.
fn ref_parse_fingerprint(text: &str) -> Result<[u8; 32], FingerprintParseError> {
    let body = text
        .strip_prefix("SHA256:")
        .ok_or(FingerprintParseError::MissingPrefix)?;
    if body.as_bytes().contains(&b'=') {
        return Err(FingerprintParseError::Padding);
    }
    if body.len() != 43 {
        return Err(FingerprintParseError::WrongLength { found: body.len() });
    }
    base64::decode_43_strict(body.as_bytes()).ok_or(FingerprintParseError::InvalidBase64)
}

fn fingerprint_text(digest: &[u8; 32]) -> String {
    let text = format!("SHA256:{}", base64::encode_unpadded(digest));
    assert_eq!(text.len(), 7 + 43);
    assert!(!text.contains('='));
    text
}

// ---------------------------------------------------------------------------
// Raw path.
// ---------------------------------------------------------------------------

fn check_public_key_blob(bytes: &[u8]) {
    match (PublicKeyBlob::decode(bytes), ref_public_key_blob(bytes)) {
        (Err(a), Err(e)) => {
            assert_eq!(a, e, "PublicKeyBlob error for {bytes:?}");
            assert_eq!(
                HostKey::parse(bytes),
                Err(KeyError::Blob(e)),
                "HostKey::parse forwards the blob error"
            );
        }
        (Ok(blob), Ok((algorithm, body))) => {
            assert_eq!(blob.algorithm, algorithm);
            assert_eq!(blob.body, body);
            assert_eq!(blob.as_bytes(), bytes, "as_bytes is the complete blob");
            let got = HostKey::from_blob(&blob);
            assert_eq!(HostKey::parse(bytes), got, "parse == from_blob(decode)");
            match ref_host_key(bytes, algorithm) {
                RefHostKey::Err(e) => assert_eq!(got, Err(e), "HostKey::from_blob({bytes:?})"),
                RefHostKey::Ok(key) => {
                    // The point check is the provider's: accept iff it does.
                    let provider = VerifyingKey::from_bytes(&key);
                    match (got, provider) {
                        (Ok(HostKey::Ed25519(k)), Ok(vk)) => {
                            assert_eq!(k.as_bytes(), vk.as_bytes());
                            assert_eq!(Ed25519PublicKey::from_bytes(&key), Ok(k));
                            assert_eq!(HostKey::Ed25519(k).algorithm(), b"ssh-ed25519");
                            let mut out = [0u8; ED25519_BLOB_LEN];
                            assert_eq!(
                                HostKey::Ed25519(k).encode_blob(&mut out),
                                Ok(ED25519_BLOB_LEN)
                            );
                            assert_eq!(&out[..], bytes, "a valid blob re-encodes to itself");
                        }
                        (Err(KeyError::InvalidKey), Err(_)) => {
                            assert_eq!(
                                Ed25519PublicKey::from_bytes(&key),
                                Err(KeyError::InvalidKey)
                            );
                        }
                        (a, b) => panic!(
                            "point validity disagreement for {key:?}: library {a:?}, provider {b:?}"
                        ),
                    }
                }
            }
            // Identity and fingerprint cover the whole blob.
            let id = HostIdentity::from_blob(&blob);
            assert_eq!(id.algorithm, algorithm);
            assert_eq!(id.blob, bytes);
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            assert_eq!(id.sha256, Sha256Fingerprint::from_bytes(digest));
            assert_eq!(id.sha256.as_bytes(), &digest);
        }
        (a, e) => {
            panic!("PublicKeyBlob disagreement on {bytes:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_signature_blob(bytes: &[u8]) {
    match (SignatureBlob::decode(bytes), ref_signature_blob(bytes)) {
        (Err(a), Err(e)) => assert_eq!(a, e, "SignatureBlob error for {bytes:?}"),
        (Ok(sig), Ok((algorithm, signature))) => {
            assert_eq!(sig.algorithm, algorithm);
            assert_eq!(sig.signature, signature);
            let mut out = vec![0xEEu8; bytes.len()];
            assert_eq!(sig.encode(&mut out), Ok(bytes.len()));
            assert_eq!(out, bytes, "re-encode reproduces the blob");
            let mut short = vec![0u8; bytes.len() - 1];
            assert!(matches!(
                sig.encode(&mut short),
                Err(EncodeError::InsufficientCapacity { .. })
            ));
            let want = if algorithm != b"ssh-ed25519" {
                Err(KeyError::UnsupportedAlgorithm(algorithm.to_vec()))
            } else if signature.len() != 64 {
                Err(KeyError::WrongLength {
                    field: "signature",
                    expected: 64,
                    found: signature.len(),
                })
            } else {
                Ok(())
            };
            let got = Ed25519Signature::from_blob(&sig);
            assert_eq!(
                got.as_ref().map(|_| ()).map_err(Clone::clone),
                want,
                "Ed25519Signature::from_blob({bytes:?})"
            );
            if let Ok(s) = got {
                assert_eq!(&s.to_bytes()[..], signature, "to_bytes is R || S verbatim");
            }
        }
        (a, e) => {
            panic!("SignatureBlob disagreement on {bytes:?}:\n library {a:?}\n reference {e:?}")
        }
    }
}

fn check_fingerprint_text(bytes: &[u8]) {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return;
    };
    let got = Sha256Fingerprint::parse(text);
    let want = ref_parse_fingerprint(text).map(Sha256Fingerprint::from_bytes);
    assert_eq!(got, want, "Sha256Fingerprint::parse({text:?})");
    assert_eq!(
        text.parse::<Sha256Fingerprint>(),
        want,
        "FromStr agrees with parse"
    );
    if let Ok(fp) = got {
        assert_eq!(fp.to_string(), text, "Display reproduces accepted text");
        assert_eq!(fp.to_string(), fingerprint_text(fp.as_bytes()));
    }
}

fn check_display(digest: [u8; 32]) {
    let fp = Sha256Fingerprint::from_bytes(digest);
    let text = fp.to_string();
    assert_eq!(
        text,
        fingerprint_text(&digest),
        "Display is SHA256: + unpadded base64"
    );
    assert_eq!(
        Sha256Fingerprint::parse(&text),
        Ok(fp),
        "Display round-trips through parse"
    );
    let dbg = format!("{fp:?}");
    assert_eq!(dbg.len(), "Sha256Fingerprint(".len() + 64 + 1);
    assert!(dbg.starts_with("Sha256Fingerprint("));
    // Equality is bytewise.
    let mut other = digest;
    other[31] ^= 1;
    assert_ne!(fp, Sha256Fingerprint::from_bytes(other));
    assert_eq!(fp, Sha256Fingerprint::from_bytes(digest));
}

fn run_raw(bytes: &[u8]) {
    check_public_key_blob(bytes);
    check_signature_blob(bytes);
    check_fingerprint_text(bytes);
    if bytes.len() >= 32 {
        check_display(bytes[..32].try_into().expect("32"));
    }
}

// ---------------------------------------------------------------------------
// Structured path.
// ---------------------------------------------------------------------------

fn check_trust(fp: Sha256Fingerprint, identity: &HostIdentity<'_>, flip: u8) {
    let pin = PinnedSha256(fp);
    assert_eq!(
        pin.decide(identity),
        TrustDecision::Trusted {
            source: TrustSource::PinnedFingerprint
        }
    );
    assert!(pin.decide(identity).is_trusted());
    let mut other = *fp.as_bytes();
    other[usize::from(flip) % 32] ^= 1 << (flip % 8);
    let wrong = PinnedSha256(Sha256Fingerprint::from_bytes(other));
    assert_eq!(
        wrong.decide(identity),
        TrustDecision::Untrusted {
            reason: UntrustedReason::FingerprintMismatch
        }
    );
    assert!(!wrong.decide(identity).is_trusted());
    assert_eq!(
        NoTrustPolicy.decide(identity),
        TrustDecision::Untrusted {
            reason: UntrustedReason::NoPolicy
        }
    );
    // Through a reference and a trait object, as a driver holds it.
    let dynamic: &dyn HostTrustPolicy = &pin;
    assert!(dynamic.decide(identity).is_trusted());
    let by_ref: &PinnedSha256 = &pin;
    assert!(by_ref.decide(identity).is_trusted());
}

fn structured(data: &[u8]) {
    let mut cur = Cursor::new(data);
    let seed: [u8; 32] = cur.take_filled(32, 41).try_into().expect("32");
    let flip_sig = cur.u8();
    let flip_msg = cur.u8();
    let flip_pin = cur.u8();
    let msg_len = usize::from(cur.u8()) % 129;
    let message = cur.take_filled(msg_len, 43);

    let signing = SigningKey::from_bytes(&seed);
    let pk: [u8; 32] = signing.verifying_key().to_bytes();
    let hand = ed25519_key_blob(&pk);
    assert_eq!(hand.len(), ED25519_BLOB_LEN);

    // Key blob: decode, interpret, re-encode.
    let blob = PublicKeyBlob::decode(&hand).expect("hand blob decodes");
    assert_eq!(blob.algorithm, b"ssh-ed25519");
    assert_eq!(blob.body, string(&pk));
    assert_eq!(blob.as_bytes(), &hand[..]);
    let host = HostKey::from_blob(&blob).expect("real key is accepted");
    let HostKey::Ed25519(key) = host;
    assert_eq!(key.as_bytes(), &pk);
    assert_eq!(HostKey::parse(&hand), Ok(host));
    let mut out = [0u8; ED25519_BLOB_LEN];
    assert_eq!(host.encode_blob(&mut out), Ok(ED25519_BLOB_LEN));
    assert_eq!(&out[..], &hand[..], "encode_blob equals the hand blob");
    let mut out = [0u8; ED25519_BLOB_LEN];
    assert_eq!(encode_ed25519_blob(&pk, &mut out), Ok(ED25519_BLOB_LEN));
    assert_eq!(
        &out[..],
        &hand[..],
        "encode_ed25519_blob equals the hand blob"
    );
    let mut short = [0u8; ED25519_BLOB_LEN - 1];
    assert_eq!(
        encode_ed25519_blob(&pk, &mut short),
        Err(EncodeError::InsufficientCapacity {
            needed: 36,
            available: 35
        })
    );

    // Fingerprint over the complete blob; text form by the harness base64.
    let digest: [u8; 32] = Sha256::digest(&hand).into();
    let fp = Sha256Fingerprint::of_blob(&hand);
    assert_eq!(
        fp.as_bytes(),
        &digest,
        "of_blob is SHA-256 of the whole blob"
    );
    assert_ne!(fp, Sha256Fingerprint::of_blob(&pk), "not the key alone");
    let text = fp.to_string();
    assert_eq!(text, fingerprint_text(&digest));
    assert_eq!(Sha256Fingerprint::parse(&text), Ok(fp));
    check_display(digest);
    let identity = HostIdentity::from_blob(&blob);
    assert_eq!(identity.sha256, fp);
    assert_eq!(identity.blob, &hand[..]);
    assert_eq!(identity.algorithm, b"ssh-ed25519");
    check_trust(fp, &identity, flip_pin);

    // Signature over a fuzz message, blob by hand.
    let sig: [u8; 64] = signing.sign(&message).to_bytes();
    let sig_hand = ed25519_sig_blob(&sig);
    assert_eq!(sig_hand.len(), ED25519_SIGNATURE_BLOB_LEN);
    let sig_blob = SignatureBlob::decode(&sig_hand).expect("hand signature blob decodes");
    assert_eq!(sig_blob.algorithm, b"ssh-ed25519");
    assert_eq!(sig_blob.signature, &sig[..]);
    let mut out = [0u8; ED25519_SIGNATURE_BLOB_LEN];
    assert_eq!(sig_blob.encode(&mut out), Ok(ED25519_SIGNATURE_BLOB_LEN));
    assert_eq!(&out[..], &sig_hand[..]);
    assert_eq!(
        host.verify_signature_blob(&message, &sig_blob),
        Ok(()),
        "genuine signature verifies"
    );
    let parsed = Ed25519Signature::from_blob(&sig_blob).expect("64-byte ssh-ed25519 signature");
    assert_eq!(parsed.to_bytes(), sig);
    assert_eq!(parsed, Ed25519Signature::from_bytes(&sig));
    assert_eq!(key.verify(&message, &parsed), Ok(()));

    // Flipped signature bit.
    let mut bad_sig = sig;
    bad_sig[usize::from(flip_sig) % 64] ^= 1 << (flip_sig % 8);
    let bad_hand = ed25519_sig_blob(&bad_sig);
    let bad_blob = SignatureBlob::decode(&bad_hand).expect("still well-formed");
    assert_eq!(
        host.verify_signature_blob(&message, &bad_blob),
        Err(VerifyError::Invalid),
        "flipped signature bit {flip_sig}"
    );
    assert_eq!(
        key.verify(&message, &Ed25519Signature::from_bytes(&bad_sig)),
        Err(VerifyError::Invalid)
    );

    // Flipped message bit (when there is a message).
    if !message.is_empty() {
        let mut bad_msg = message.clone();
        bad_msg[usize::from(flip_msg) % message.len()] ^= 1 << (flip_msg % 8);
        assert_eq!(
            host.verify_signature_blob(&bad_msg, &sig_blob),
            Err(VerifyError::Invalid)
        );
    }
    // Appended message byte.
    let mut longer = message.clone();
    longer.push(flip_msg);
    assert_eq!(
        host.verify_signature_blob(&longer, &sig_blob),
        Err(VerifyError::Invalid)
    );

    // Another key does not verify it.
    let mut other_seed = seed;
    other_seed[0] ^= 0x01;
    let other = HostKey::parse(&ed25519_key_blob(
        &SigningKey::from_bytes(&other_seed)
            .verifying_key()
            .to_bytes(),
    ))
    .expect("other key parses");
    assert_ne!(other, host);
    assert_eq!(
        other.verify_signature_blob(&message, &sig_blob),
        Err(VerifyError::Invalid)
    );

    // Algorithm mismatch in the signature blob: detected before the bytes.
    let mut rsa_sig = string(b"ssh-rsa");
    rsa_sig.extend(string(&sig));
    let rsa_blob = SignatureBlob::decode(&rsa_sig).expect("well-formed");
    assert_eq!(
        host.verify_signature_blob(&message, &rsa_blob),
        Err(VerifyError::AlgorithmMismatch {
            key_algorithm: b"ssh-ed25519".to_vec(),
            signature_algorithm: b"ssh-rsa".to_vec(),
        })
    );
    assert_eq!(
        Ed25519Signature::from_blob(&rsa_blob),
        Err(KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec()))
    );
    // Algorithm mismatch in the key blob.
    let mut rsa_key = string(b"ssh-rsa");
    rsa_key.extend(string(&pk));
    let rsa_key_blob = PublicKeyBlob::decode(&rsa_key).expect("well-formed");
    assert_eq!(
        HostKey::from_blob(&rsa_key_blob),
        Err(KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec()))
    );
    assert_eq!(
        Ed25519PublicKey::from_blob(&rsa_key_blob),
        Err(KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec()))
    );

    // Trailing byte in either blob.
    let mut sig_trailing = sig_hand.clone();
    sig_trailing.push(0);
    assert_eq!(
        SignatureBlob::decode(&sig_trailing),
        Err(BlobError::TrailingBytes { count: 1 })
    );
    let mut key_trailing = hand.clone();
    key_trailing.push(0);
    let kt = PublicKeyBlob::decode(&key_trailing).expect("the body absorbs it at this level");
    assert_eq!(kt.body.len(), 37);
    assert_eq!(
        HostKey::from_blob(&kt),
        Err(KeyError::Blob(BlobError::TrailingBytes { count: 1 }))
    );

    // Key length 31 / 33.
    for found in [31usize, 33] {
        let mut k = string(b"ssh-ed25519");
        k.extend(string(&vec![0x11u8; found]));
        let b = PublicKeyBlob::decode(&k).expect("well-formed");
        assert_eq!(
            HostKey::from_blob(&b),
            Err(KeyError::WrongLength {
                field: "key",
                expected: 32,
                found
            })
        );
    }
    // Signature length 63 / 65.
    for found in [63usize, 65] {
        let mut s = string(b"ssh-ed25519");
        let mut body = sig.to_vec();
        body.resize(found, 0x22);
        s.extend(string(&body));
        let b = SignatureBlob::decode(&s).expect("well-formed");
        assert_eq!(
            host.verify_signature_blob(&message, &b),
            Err(VerifyError::MalformedSignature(KeyError::WrongLength {
                field: "signature",
                expected: 64,
                found
            }))
        );
    }

    // Everything above through the raw oracle as well.
    run_raw(&hand);
    run_raw(&sig_hand);
    run_raw(text.as_bytes());
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        run_raw(&[]);
        return;
    };
    if sel < 0x80 {
        run_raw(rest);
    } else {
        structured(rest);
    }
});
