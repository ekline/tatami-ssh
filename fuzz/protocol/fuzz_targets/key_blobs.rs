#![no_main]
//! `tatami_ssh_keys`: public-key and signature blob codecs, host keys of all
//! three types (`ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`), scheme-bound
//! signature verification (`HostKey::verify`), `SHA256:` fingerprints, SSHFP
//! values and the pinned trust policy.
//!
//! # Input layout
//!
//! `sel:u8, rest...`
//!
//! - `sel < 0x80`: RAW. `rest` goes to `PublicKeyBlob::decode`,
//!   `SignatureBlob::decode`, `HostKey::from_blob` / `HostKey::parse`,
//!   `Ed25519Signature::from_blob`, `ecdsa::fixed_signature`, and (as text)
//!   `Sha256Fingerprint::parse`. Oracles: independent layouts (`string
//!   algorithm` then body; `string algorithm, string signature` with nothing
//!   after) with exact `BlobError` (field names, offsets, `TrailingBytes`);
//!   `HostKey`: `UnsupportedAlgorithm(name)` for any name but the three,
//!   Ed25519 `WrongLength{key,32,found}` / `InvalidKey` iff the provider
//!   rejects the 32 bytes; `ssh-rsa`: fields `e`, `n` split with the same
//!   `string` reference, the RFC 4251 §5 positive-minimal rule
//!   (`NonCanonicalInteger{field}` right after the offending field), then
//!   the documented policy (`RsaExponent`: even, < 3 or > 4 bytes;
//!   `RsaModulus{bits}`: even or outside 2048..=8192); P-256: fields
//!   `curve`, `Q`, then `CurveMismatch` unless `nistp256`, `PointEncoding`
//!   unless 65 bytes starting `04`. Accepted blobs of every type re-encode
//!   (`to_blob`, `encode_blob`) to the input. `fixed_signature`: `mpint r,
//!   mpint s`, same rule, `ScalarTooLong` over 32 bytes, output equals the
//!   left-padded magnitudes. Fingerprint text: prefix, `=`, 43-byte length,
//!   alphabet and canonical trailing bits by an independent decoder,
//!   `Display` reproduces the text.
//! - `0x80 <= sel < 0xC0`: STRUCTURED Ed25519. A real key pair from a
//!   fuzz-derived 32-byte seed (`ed25519_dalek::SigningKey::from_bytes`); the
//!   key blob is assembled BY HAND (`string "ssh-ed25519" || string key`) and
//!   must be accepted by `HostKey::from_blob`, reproduced by `encode_blob` /
//!   `encode_ed25519_blob`; `Sha256Fingerprint::of_blob` equals `sha2` over
//!   the hand blob and `Display` equals `SHA256:` + the harness base64;
//!   `parse(Display)` round-trips; `PinnedSha256` decides `Trusted` iff the
//!   pins are equal and `NoTrustPolicy` never trusts. A fuzz message is
//!   signed and the signature blob assembled by hand: `verify(Ed25519, ..)`
//!   succeeds (also with a recording provider present, which is never asked
//!   or called), and FAILS with the exact error for any flipped bit in the
//!   signature or message (`Invalid`), a different key (`Invalid`), label
//!   `ssh-rsa` (`UnexpectedSignatureAlgorithm`, before anything else), an RSA
//!   scheme with its own label (`AlgorithmMismatch`), `ssh-rsa` in the key
//!   blob (the RSA reference's error), a trailing byte in either blob, key
//!   length 31/33 and signature length 63/65 (`WrongLength`).
//! - `0xC0 <= sel < 0xE0`: STRUCTURED RSA. Modulus size from a table (2048
//!   mostly, also 2049/3072/4096/8192 and out-of-policy 1024/2047/8193, even
//!   moduli), fuzz modulus bytes (no primality: parsing and policy do not
//!   depend on it, and the provider is a mock), exponent from a table (65537,
//!   3, fuzz 4-byte odd, 0x80000001, and out-of-policy 1, 65536, 5 bytes),
//!   hand blob with an optional tamper (redundant zero on `e`, missing sign
//!   byte on `n`, trailing byte). `HostKey::parse` equals the raw reference
//!   AND, untampered, succeeds iff the policy holds; accepted keys expose
//!   exactly `(e, n)`, `modulus_bits`, `to_blob() ==` hand blob, SSHFP
//!   algorithm 1 over the blob, `spki_to_ssh_blob(host_key_spki(k)) ==` blob.
//!   `verify` with a recording mock provider under fuzz-chosen negotiated
//!   scheme, label, provider support/verdict and signature length follows the
//!   documented order exactly: label ≠ scheme → `UnexpectedSignatureAlgorithm`;
//!   scheme of another key type → `AlgorithmMismatch`; no supporting provider
//!   → `ProviderUnavailable`; empty or longer-than-modulus signature →
//!   `MalformedSignature(WrongLength)`; then the provider's verdict. The
//!   provider is called iff the last step is reached, exactly once, with the
//!   message, the key's `(n, e)`, the scheme's hash and a signature of
//!   exactly `modulus.len()` bytes whose suffix is the sent bytes and whose
//!   prefix is zeros. `ssh-rsa` (SHA-1) never verifies under any scheme.
//! - `sel >= 0xE0`: STRUCTURED P-256. Fuzz point `04 || X || Y` (not on the
//!   curve: point validity is the provider's), tampers (compressed prefix,
//!   64-byte Q, `nistp384` curve, trailing byte, `nistp384` algorithm) with
//!   the raw reference; accepted keys expose the point, SSHFP algorithm 3,
//!   SPKI round trip. Signature `mpint r || mpint s` from fuzz magnitudes of
//!   0..=34 bytes with optional non-canonical/negative encodings or a
//!   trailing byte: `fixed_signature` equals the reference, and `verify`
//!   follows the same order; a reached provider sees the key's point and
//!   `r || s` equal to the left-padded magnitudes.
//!
//! No private key is stored anywhere: seeds are descriptions and keys are
//! derived at run time.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use tatami_ssh_fuzz_protocol::kex_support::base64;
use tatami_ssh_fuzz_protocol::kex_support::crypto::{ed25519_key_blob, ed25519_sig_blob, string};
use tatami_ssh_fuzz_protocol::keys_support::mock::{RecordingProvider, Request, Verdict};
use tatami_ssh_fuzz_protocol::keys_support::{
    bit_len, mpint_body, p256_blob, positive_mpint_magnitude, rsa_blob, ssh_string, strip_zeros,
};
use tatami_ssh_fuzz_protocol::tcp_support::Cursor;
use tatami_ssh_keys::algorithm::{KeyType, SignatureScheme};
use tatami_ssh_keys::blob::{
    ED25519_BLOB_LEN, ED25519_SIGNATURE_BLOB_LEN, PublicKeyBlob, SignatureBlob, encode_ed25519_blob,
};
use tatami_ssh_keys::ecdsa::fixed_signature;
use tatami_ssh_keys::ed25519::{Ed25519PublicKey, Ed25519Signature};
use tatami_ssh_keys::error::{BlobError, KeyError, VerifyError};
use tatami_ssh_keys::fingerprint::{FingerprintParseError, Sha256Fingerprint};
use tatami_ssh_keys::host_key::HostKey;
use tatami_ssh_keys::provider::{RsaHash, SignatureProvider};
use tatami_ssh_keys::spki::{host_key_spki, spki_to_ssh_blob};
use tatami_ssh_keys::sshfp::Sshfp;
use tatami_ssh_keys::trust::{
    HostIdentity, HostTrustPolicy, NoTrustPolicy, PinnedSha256, TrustDecision, TrustSource,
    UntrustedReason,
};
use tatami_ssh_wire::{DecodeError, EncodeError};

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

/// `field` followed by the RFC 4251 §5 positive-minimal rule.
fn mpint_field<'a>(
    buf: &'a [u8],
    pos: usize,
    name: &'static str,
) -> Result<(&'a [u8], usize), KeyError> {
    let (body, next) = field(buf, pos, name)?;
    let m = positive_mpint_magnitude(body).ok_or(KeyError::NonCanonicalInteger { field: name })?;
    Ok((m, next))
}

fn finish(buf: &[u8], end: usize) -> Result<(), BlobError> {
    if end == buf.len() {
        Ok(())
    } else {
        Err(BlobError::TrailingBytes {
            count: buf.len() - end,
        })
    }
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
    finish(blob, end)?;
    Ok((algorithm, signature))
}

/// What `HostKey::from_blob` must say about a decoded blob, up to the
/// Ed25519 provider's point check (compared separately).
#[derive(Debug)]
enum RefHostKey {
    Ed25519([u8; 32]),
    Rsa { e: Vec<u8>, n: Vec<u8> },
    P256([u8; 65]),
    Err(KeyError),
}

/// Documented RSA policy over minimal magnitudes (`crate::rsa` notes).
fn rsa_policy(e: &[u8], n: &[u8]) -> Result<(), KeyError> {
    let e_odd = e.last().is_some_and(|b| b & 1 == 1);
    if e.len() > 4 || !e_odd || (e.len() == 1 && e[0] < 3) {
        return Err(KeyError::RsaExponent);
    }
    let bits = bit_len(n);
    if !(2048..=8192).contains(&bits) || n.last().is_some_and(|b| b & 1 == 0) {
        return Err(KeyError::RsaModulus { bits });
    }
    Ok(())
}

fn ref_rsa(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), KeyError> {
    let (_, p) = field(blob, 0, "algorithm")?;
    let (e, p) = mpint_field(blob, p, "e")?;
    let (n, p) = mpint_field(blob, p, "n")?;
    finish(blob, p)?;
    rsa_policy(e, n)?;
    Ok((e.to_vec(), n.to_vec()))
}

fn ref_p256(blob: &[u8]) -> Result<[u8; 65], KeyError> {
    let (_, p) = field(blob, 0, "algorithm")?;
    let (curve, p) = field(blob, p, "curve")?;
    let (q, p) = field(blob, p, "Q")?;
    finish(blob, p)?;
    if curve != b"nistp256" {
        return Err(KeyError::CurveMismatch);
    }
    match <[u8; 65]>::try_from(q) {
        Ok(point) if point[0] == 0x04 => Ok(point),
        _ => Err(KeyError::PointEncoding),
    }
}

fn ref_ed25519(blob: &[u8]) -> Result<[u8; 32], KeyError> {
    // Re-read from the start: offsets are relative to the whole blob.
    let (_, after_alg) = field(blob, 0, "algorithm")?;
    let (key, end) = field(blob, after_alg, "key")?;
    finish(blob, end)?;
    <[u8; 32]>::try_from(key).map_err(|_| KeyError::WrongLength {
        field: "key",
        expected: 32,
        found: key.len(),
    })
}

fn ref_host_key(blob: &[u8], algorithm: &[u8]) -> RefHostKey {
    let r = match algorithm {
        b"ssh-ed25519" => ref_ed25519(blob).map(RefHostKey::Ed25519),
        b"ssh-rsa" => ref_rsa(blob).map(|(e, n)| RefHostKey::Rsa { e, n }),
        b"ecdsa-sha2-nistp256" => ref_p256(blob).map(RefHostKey::P256),
        other => Err(KeyError::UnsupportedAlgorithm(other.to_vec())),
    };
    r.unwrap_or_else(RefHostKey::Err)
}

/// `mpint r || mpint s` → fixed `r || s` (RFC 5656 §3.1.2, 32-byte scalars).
fn ref_fixed(inner: &[u8]) -> Result<[u8; 64], KeyError> {
    let (r, p) = mpint_field(inner, 0, "r")?;
    let (s, p) = mpint_field(inner, p, "s")?;
    finish(inner, p)?;
    let mut out = [0u8; 64];
    for (v, name, end) in [(r, "r", 32usize), (s, "s", 64)] {
        if v.len() > 32 {
            return Err(KeyError::ScalarTooLong { field: name });
        }
        out[end - v.len()..end].copy_from_slice(v);
    }
    Ok(out)
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

/// Properties every accepted key has, whatever its type: canonical
/// re-encoding, algorithm name, SSHFP over the blob, SPKI round trip.
fn check_accepted_key(key: &HostKey, bytes: &[u8]) {
    assert_eq!(
        key.to_blob(),
        bytes,
        "an accepted blob re-encodes to itself"
    );
    let mut out = vec![0xEEu8; bytes.len() + 3];
    assert_eq!(key.encode_blob(&mut out), Ok(bytes.len()));
    assert_eq!(&out[..bytes.len()], bytes);
    assert_eq!(
        &out[bytes.len()..],
        &[0xEE; 3],
        "nothing written past the blob"
    );
    let mut short = vec![0u8; bytes.len() - 1];
    assert_eq!(
        key.encode_blob(&mut short),
        Err(EncodeError::InsufficientCapacity {
            needed: bytes.len(),
            available: bytes.len() - 1
        })
    );
    assert_eq!(key.algorithm(), key.key_type().name());
    assert_eq!(KeyType::from_name(key.algorithm()), Some(key.key_type()));
    let sshfp = Sshfp::sha256_of_blob(bytes).expect("an accepted blob has an SSHFP value");
    let want_alg = match key.key_type() {
        KeyType::Rsa => 1,
        KeyType::EcdsaP256 => 3,
        KeyType::Ed25519 => 4,
    };
    assert_eq!(sshfp.algorithm, want_alg);
    assert_eq!(sshfp.fingerprint_type, 2);
    assert_eq!(sshfp.digest, <[u8; 32]>::from(Sha256::digest(bytes)));
    let spki = host_key_spki(key);
    assert_eq!(
        spki_to_ssh_blob(&spki).as_deref(),
        Ok(bytes),
        "SPKI round trip reproduces the blob"
    );
}

fn check_public_key_blob(bytes: &[u8]) {
    match (PublicKeyBlob::decode(bytes), ref_public_key_blob(bytes)) {
        (Err(a), Err(e)) => {
            assert_eq!(a, e, "PublicKeyBlob error for {bytes:?}");
            assert_eq!(
                HostKey::parse(bytes),
                Err(KeyError::Blob(e)),
                "HostKey::parse forwards the blob error"
            );
            assert!(Sshfp::sha256_of_blob(bytes).is_err());
        }
        (Ok(blob), Ok((algorithm, body))) => {
            assert_eq!(blob.algorithm, algorithm);
            assert_eq!(blob.body, body);
            assert_eq!(blob.as_bytes(), bytes, "as_bytes is the complete blob");
            let got = HostKey::from_blob(&blob);
            assert_eq!(HostKey::parse(bytes), got, "parse == from_blob(decode)");
            match (ref_host_key(bytes, algorithm), got) {
                (RefHostKey::Err(e), got) => {
                    assert_eq!(got, Err(e), "HostKey::from_blob({bytes:?})");
                    assert!(Sshfp::sha256_of_blob(bytes).is_err());
                }
                (RefHostKey::Rsa { e, n }, Ok(HostKey::Rsa(k))) => {
                    assert_eq!(k.exponent(), &e[..]);
                    assert_eq!(k.modulus(), &n[..]);
                    assert_eq!(k.modulus_bits(), bit_len(&n));
                    assert_eq!(rsa_blob(&e, &n), bytes, "hand layout");
                    check_accepted_key(&HostKey::Rsa(k), bytes);
                }
                (RefHostKey::P256(point), Ok(HostKey::EcdsaP256(k))) => {
                    assert_eq!(k.point(), &point);
                    check_accepted_key(&HostKey::EcdsaP256(k), bytes);
                }
                (RefHostKey::Ed25519(key), got) => {
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
                            check_accepted_key(&HostKey::Ed25519(k), bytes);
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
                (want, got) => panic!("HostKey disagreement on {bytes:?}: {got:?} vs {want:?}"),
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
            // The inner bytes as an ECDSA signature.
            assert_eq!(
                fixed_signature(signature),
                ref_fixed(signature),
                "fixed_signature({signature:?})"
            );
        }
        (a, e) => {
            panic!("SignatureBlob disagreement on {bytes:?}:\n library {a:?}\n reference {e:?}")
        }
    }
    // The whole input as an inner ECDSA signature, too.
    assert_eq!(
        fixed_signature(bytes),
        ref_fixed(bytes),
        "fixed_signature raw"
    );
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
// Scheme table and the documented verification order.
// ---------------------------------------------------------------------------

const SCHEMES: [SignatureScheme; 4] = [
    SignatureScheme::Ed25519,
    SignatureScheme::EcdsaP256Sha256,
    SignatureScheme::RsaSha2_512,
    SignatureScheme::RsaSha2_256,
];

fn check_algorithm_tables() {
    assert_eq!(SignatureScheme::PREFERENCE, SCHEMES);
    let names: [&[u8]; 4] = [
        b"ssh-ed25519",
        b"ecdsa-sha2-nistp256",
        b"rsa-sha2-512",
        b"rsa-sha2-256",
    ];
    for (s, name) in SCHEMES.iter().zip(names) {
        assert_eq!(s.name(), name);
        assert_eq!(SignatureScheme::from_name(name), Some(*s));
        assert_eq!(s.needs_provider(), *s != SignatureScheme::Ed25519);
        assert!(s.is_enabled(), "every scheme is enabled in this workspace");
        let kt = s.key_type();
        assert!(kt.is_enabled());
        assert_eq!(
            kt,
            match s {
                SignatureScheme::Ed25519 => KeyType::Ed25519,
                SignatureScheme::EcdsaP256Sha256 => KeyType::EcdsaP256,
                _ => KeyType::Rsa,
            }
        );
    }
    // RSA/SHA-1 is not a scheme, whatever the key type table says.
    assert_eq!(SignatureScheme::from_name(b"ssh-rsa"), None);
    assert_eq!(SignatureScheme::from_name(b"ssh-dss"), None);
    assert_eq!(KeyType::from_name(b"ssh-rsa"), Some(KeyType::Rsa));
    assert_eq!(KeyType::from_name(b"rsa-sha2-256"), None);
    assert_eq!(KeyType::from_name(b"ecdsa-sha2-nistp384"), None);
    assert_eq!(KeyType::Rsa.sshfp_algorithm(), 1);
    assert_eq!(KeyType::EcdsaP256.sshfp_algorithm(), 3);
    assert_eq!(KeyType::Ed25519.sshfp_algorithm(), 4);
}

/// The first failing documented check of `HostKey::verify` before the
/// signature bytes are parsed, or `None` when parsing is reached.
fn pre_parse_error(
    key_type: KeyType,
    key_algorithm: &[u8],
    scheme: SignatureScheme,
    label: &[u8],
    provider: Option<&RecordingProvider>,
) -> Option<VerifyError> {
    if label != scheme.name() {
        return Some(VerifyError::UnexpectedSignatureAlgorithm {
            expected: scheme.name(),
            found: label.to_vec(),
        });
    }
    if scheme.key_type() != key_type {
        return Some(VerifyError::AlgorithmMismatch {
            key_algorithm: key_algorithm.to_vec(),
            signature_algorithm: label.to_vec(),
        });
    }
    if scheme.needs_provider() && !provider.is_some_and(|p| p.supports_scheme(scheme)) {
        return Some(VerifyError::ProviderUnavailable {
            scheme: scheme.name(),
        });
    }
    None
}

/// Fuzz choice of the negotiated scheme and label for a key whose own
/// schemes are `own` (in order): mostly consistent, sometimes another key
/// type's scheme, `ssh-rsa`, or another scheme's label.
fn choose_scheme_and_label(
    cur: &mut Cursor<'_>,
    own: &[SignatureScheme],
) -> (SignatureScheme, Vec<u8>) {
    let s = cur.u8();
    let scheme = if s & 0x80 == 0 {
        own[usize::from(s) % own.len()]
    } else {
        SCHEMES[usize::from(s) % 4]
    };
    let label: Vec<u8> = match cur.u8() % 8 {
        0..=4 => scheme.name().to_vec(),
        5 => b"ssh-rsa".to_vec(),
        6 => SCHEMES[usize::from(s >> 2) % 4].name().to_vec(),
        _ => b"ecdsa-sha2-nistp384".to_vec(),
    };
    (scheme, label)
}

/// Provider presence, support and verdict from one byte.
fn choose_provider(b: u8) -> Option<RecordingProvider> {
    let verdict = if b & 4 == 0 {
        Verdict::Accept
    } else {
        Verdict::Reject
    };
    match b % 4 {
        0 => None,
        // Supports only some schemes.
        1 => Some(RecordingProvider::new(
            &[SignatureScheme::RsaSha2_512],
            verdict,
        )),
        2 => Some(RecordingProvider::new(
            &[
                SignatureScheme::RsaSha2_256,
                SignatureScheme::EcdsaP256Sha256,
            ],
            verdict,
        )),
        _ => Some(RecordingProvider::all(verdict)),
    }
}

/// The provider's fixed verdict, as `HostKey::verify` must report it.
fn verdict_result(p: &RecordingProvider) -> Result<(), VerifyError> {
    match p.verdict() {
        Verdict::Accept => Ok(()),
        Verdict::Reject => Err(VerifyError::Invalid),
        Verdict::MockSignature => unreachable!("key_blobs uses fixed verdicts"),
    }
}

/// Runs `verify` with the optional provider and checks the result and the
/// provider log against `expect_request` (what a reached provider must see).
fn verify_and_check(
    key: &HostKey,
    scheme: SignatureScheme,
    message: &[u8],
    label: &[u8],
    sig: &[u8],
    provider: Option<&RecordingProvider>,
    parse: Result<Request, KeyError>,
) {
    let blob = SignatureBlob {
        algorithm: label,
        signature: sig,
    };
    let dyn_provider = provider.map(|p| p as &dyn SignatureProvider);
    let got = key.verify(scheme, message, &blob, dyn_provider);
    let calls = provider.map(RecordingProvider::calls).unwrap_or_default();
    let asked = provider.map(RecordingProvider::asked).unwrap_or_default();
    assert!(
        !asked.contains(&SignatureScheme::Ed25519),
        "Ed25519 is never asked about"
    );
    assert!(asked.len() <= 1, "supports asked at most once: {asked:?}");
    if let Some(e) = pre_parse_error(key.key_type(), key.algorithm(), scheme, label, provider) {
        assert_eq!(got, Err(e), "pre-parse check for {scheme:?} {label:?}");
        assert!(calls.is_empty(), "provider reached despite {got:?}");
        return;
    }
    match parse {
        Err(e) => {
            assert_eq!(got, Err(VerifyError::MalformedSignature(e)));
            assert!(calls.is_empty(), "malformed signature reached the provider");
        }
        Ok(want) => {
            assert_eq!(calls.len(), 1, "exactly one provider call");
            assert_eq!(calls[0].message, message, "the provider gets the message");
            assert_eq!(calls[0].request, want, "provider request");
            let p = provider.expect("a call implies a provider");
            assert_eq!(got, verdict_result(p));
        }
    }
}

// ---------------------------------------------------------------------------
// Structured Ed25519 path.
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

fn ed25519_verify(
    host: &HostKey,
    message: &[u8],
    blob: &SignatureBlob<'_>,
) -> Result<(), VerifyError> {
    host.verify(SignatureScheme::Ed25519, message, blob, None)
}

fn structured_ed25519(data: &[u8]) {
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
    let HostKey::Ed25519(key) = host.clone() else {
        panic!("an ssh-ed25519 blob is an Ed25519 key: {host:?}");
    };
    assert_eq!(key.as_bytes(), &pk);
    assert_eq!(host.key_type(), KeyType::Ed25519);
    assert_eq!(HostKey::parse(&hand), Ok(host.clone()));
    let mut out = [0u8; ED25519_BLOB_LEN];
    assert_eq!(host.encode_blob(&mut out), Ok(ED25519_BLOB_LEN));
    assert_eq!(&out[..], &hand[..], "encode_blob equals the hand blob");
    assert_eq!(host.to_blob(), hand, "to_blob equals the hand blob");
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
        ed25519_verify(&host, &message, &sig_blob),
        Ok(()),
        "genuine signature verifies"
    );
    // A provider changes nothing for Ed25519: never asked, never called.
    let p = RecordingProvider::all(Verdict::Reject);
    assert_eq!(
        host.verify(SignatureScheme::Ed25519, &message, &sig_blob, Some(&p)),
        Ok(())
    );
    assert!(p.calls().is_empty() && p.asked().is_empty());
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
        ed25519_verify(&host, &message, &bad_blob),
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
            ed25519_verify(&host, &bad_msg, &sig_blob),
            Err(VerifyError::Invalid)
        );
    }
    // Appended message byte.
    let mut longer = message.clone();
    longer.push(flip_msg);
    assert_eq!(
        ed25519_verify(&host, &longer, &sig_blob),
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
        ed25519_verify(&other, &message, &sig_blob),
        Err(VerifyError::Invalid)
    );

    // `ssh-rsa` label: refused as not the negotiated scheme, before the
    // bytes are looked at, under every scheme.
    let mut rsa_sig = string(b"ssh-rsa");
    rsa_sig.extend(string(&sig));
    let rsa_blob_sig = SignatureBlob::decode(&rsa_sig).expect("well-formed");
    for scheme in SCHEMES {
        assert_eq!(
            host.verify(scheme, &message, &rsa_blob_sig, Some(&p)),
            Err(VerifyError::UnexpectedSignatureAlgorithm {
                expected: scheme.name(),
                found: b"ssh-rsa".to_vec(),
            })
        );
    }
    // An RSA scheme with its own label: the key type does not match.
    let mut sha2_sig = string(b"rsa-sha2-256");
    sha2_sig.extend(string(&sig));
    let sha2_blob = SignatureBlob::decode(&sha2_sig).expect("well-formed");
    assert_eq!(
        host.verify(SignatureScheme::RsaSha2_256, &message, &sha2_blob, Some(&p)),
        Err(VerifyError::AlgorithmMismatch {
            key_algorithm: b"ssh-ed25519".to_vec(),
            signature_algorithm: b"rsa-sha2-256".to_vec(),
        })
    );
    assert!(p.calls().is_empty(), "no Ed25519 path reaches a provider");
    assert_eq!(
        Ed25519Signature::from_blob(&rsa_blob_sig),
        Err(KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec()))
    );
    // `ssh-rsa` with an Ed25519 body in the key blob: the RSA reference's
    // verdict (a non-canonical `e` or a missing `n`), never a key.
    let mut rsa_key = string(b"ssh-rsa");
    rsa_key.extend(string(&pk));
    let rsa_key_blob = PublicKeyBlob::decode(&rsa_key).expect("well-formed");
    let want = ref_rsa(&rsa_key).expect_err("32 bytes are not e and n");
    assert_eq!(HostKey::from_blob(&rsa_key_blob), Err(want));
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
            ed25519_verify(&host, &message, &b),
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

// ---------------------------------------------------------------------------
// Structured RSA path.
// ---------------------------------------------------------------------------

const RSA_BITS: [usize; 10] = [2048, 2048, 2048, 2049, 3072, 4096, 8192, 1024, 2047, 8193];

/// An exactly-`bits` magnitude from fuzz bytes, odd unless `even`.
fn modulus(cur: &mut Cursor<'_>, bits: usize, even: bool) -> Vec<u8> {
    let len = bits.div_ceil(8);
    let mut n = cur.take_filled(len, 61);
    let top_bit = (bits - 1) % 8;
    n[0] &= (1u16 << (top_bit + 1)).wrapping_sub(1) as u8;
    n[0] |= 1 << top_bit;
    if even {
        n[len - 1] &= !1;
    } else {
        n[len - 1] |= 1;
    }
    n
}

fn exponent(cur: &mut Cursor<'_>) -> Vec<u8> {
    match cur.u8() % 9 {
        0..=2 => vec![1, 0, 1],
        3 => vec![3],
        4 => {
            let mut e = cur.take_filled(4, 67);
            e[0] |= 1;
            e[3] |= 1;
            e
        }
        5 => vec![0x80, 0, 0, 1],
        6 => vec![1],
        7 => vec![1, 0, 0],
        _ => vec![1, 0, 0, 0, 1],
    }
}

fn rsa_request(
    scheme: SignatureScheme,
    key: &tatami_ssh_keys::rsa::RsaPublicKey,
    sig: &[u8],
) -> Result<Request, KeyError> {
    let k = key.modulus().len();
    if sig.is_empty() || sig.len() > k {
        return Err(KeyError::WrongLength {
            field: "signature",
            expected: k,
            found: sig.len(),
        });
    }
    let mut padded = vec![0u8; k - sig.len()];
    padded.extend_from_slice(sig);
    Ok(Request::Rsa {
        hash: if scheme == SignatureScheme::RsaSha2_512 {
            RsaHash::Sha512
        } else {
            RsaHash::Sha256
        },
        modulus: key.modulus().to_vec(),
        exponent: key.exponent().to_vec(),
        signature: padded,
    })
}

fn structured_rsa(data: &[u8]) {
    check_algorithm_tables();
    let mut cur = Cursor::new(data);
    let size = cur.u8();
    let bits = RSA_BITS[usize::from(size & 0x7f) % RSA_BITS.len()];
    let even = size & 0x80 != 0 && size & 0x0f == 0x0f;
    let n = modulus(&mut cur, bits, even);
    let e = exponent(&mut cur);
    let tamper = cur.u8() % 8;
    let hand = rsa_blob(&e, &n);
    let blob = match tamper {
        // Redundant leading zero on e.
        5 => {
            let mut b = ssh_string(b"ssh-rsa");
            b.extend(ssh_string(&[&[0u8][..], &mpint_body(&e)].concat()));
            b.extend(ssh_string(&mpint_body(&n)));
            b
        }
        // n without its sign byte (negative when the top bit is set).
        6 => {
            let mut b = ssh_string(b"ssh-rsa");
            b.extend(ssh_string(&mpint_body(&e)));
            b.extend(ssh_string(&n));
            b
        }
        7 => [&hand[..], &[0][..]].concat(),
        _ => hand.clone(),
    };
    let got = HostKey::parse(&blob);
    let want = ref_rsa(&blob);
    match (&got, &want) {
        (Ok(HostKey::Rsa(k)), Ok((we, wn))) => {
            assert_eq!(k.exponent(), &we[..]);
            assert_eq!(k.modulus(), &wn[..]);
        }
        (Err(g), Err(w)) => assert_eq!(g, w, "RSA error for bits={bits} e={e:?} tamper={tamper}"),
        _ => panic!("RSA disagreement: library {got:?}, reference {want:?}"),
    }
    if tamper < 5 || (tamper == 6 && n[0] & 0x80 == 0) {
        // Untampered (a sign byte is only needed with the top bit set).
        assert_eq!(blob, hand);
        let policy_ok = (2048..=8192).contains(&bits)
            && !even
            && e.len() <= 4
            && e[e.len() - 1] & 1 == 1
            && e != [1];
        assert_eq!(got.is_ok(), policy_ok, "bits={bits} even={even} e={e:?}");
    }
    let Ok(key) = got else {
        return;
    };
    let HostKey::Rsa(rsa) = &key else {
        panic!("ssh-rsa blob gave {key:?}");
    };
    assert_eq!(rsa.modulus_bits(), bits);
    assert_eq!(key.key_type(), KeyType::Rsa);
    assert_eq!(key.algorithm(), b"ssh-rsa");
    assert_eq!(
        Sha256Fingerprint::of_blob(&hand).as_bytes(),
        &<[u8; 32]>::from(Sha256::digest(&hand))
    );
    check_accepted_key(&key, &hand);

    // Verification through the recording mock.
    let (scheme, label) = choose_scheme_and_label(
        &mut cur,
        &[SignatureScheme::RsaSha2_512, SignatureScheme::RsaSha2_256],
    );
    let provider = choose_provider(cur.u8());
    let k = n.len();
    let len_sel = cur.u8();
    let sig_len = match len_sel % 8 {
        0 => 0,
        1 => k + 1 + usize::from(len_sel >> 3) % 3,
        2 => 1,
        3 => k - usize::from(len_sel >> 3) % 3,
        _ => k,
    };
    let mut sig = cur.take_filled(sig_len, 71);
    if len_sel % 8 == 4 && !sig.is_empty() {
        // A shortened signature, as RFC 8332 §3 allows: leading zeros
        // omitted, restored by the verifier.
        let z = usize::from(len_sel >> 4).min(sig.len() - 1);
        sig.drain(..z);
    }
    let msg_len = usize::from(cur.u8()) % 65;
    let message = cur.take_filled(msg_len, 73);
    verify_and_check(
        &key,
        scheme,
        &message,
        &label,
        &sig,
        provider.as_ref(),
        rsa_request(scheme, rsa, &sig),
    );
    // Recorded requests are always exactly modulus-sized, suffix = input.
    if let Some(p) = &provider {
        for c in p.calls() {
            let Request::Rsa { signature, .. } = &c.request else {
                panic!("RSA key produced {c:?}");
            };
            assert_eq!(signature.len(), k);
            assert_eq!(&signature[k - sig.len()..], &sig[..]);
            assert!(signature[..k - sig.len()].iter().all(|&b| b == 0));
        }
    }
    // RSA/SHA-1 never verifies, even with an accepting provider.
    let accepting = RecordingProvider::all(Verdict::Accept);
    let sha1 = SignatureBlob {
        algorithm: b"ssh-rsa",
        signature: &sig,
    };
    for s in SCHEMES {
        assert!(matches!(
            key.verify(s, &message, &sha1, Some(&accepting)),
            Err(VerifyError::UnexpectedSignatureAlgorithm { .. })
        ));
    }
    assert!(accepting.calls().is_empty());
}

// ---------------------------------------------------------------------------
// Structured P-256 path.
// ---------------------------------------------------------------------------

/// An `mpint` body for a fuzz magnitude of `len` bytes (top byte non-zero),
/// possibly with a redundant zero or without its sign byte.
fn scalar_body(cur: &mut Cursor<'_>) -> Vec<u8> {
    let b = cur.u8();
    let len = usize::from(b) % 35;
    let mut m = cur.take_filled(len, 79);
    if let Some(first) = m.first_mut() {
        *first |= if b & 0x80 != 0 { 0x80 } else { 1 };
    }
    let body = mpint_body(&m);
    match cur.u8() % 16 {
        0 => [&[0u8][..], &body].concat(),
        1 => strip_zeros(&body).to_vec(),
        _ => body,
    }
}

fn structured_p256(data: &[u8]) {
    check_algorithm_tables();
    let mut cur = Cursor::new(data);
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..].copy_from_slice(&cur.take_filled(64, 83));
    let tamper = cur.u8() % 12;
    let hand = p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", &point);
    let blob = match tamper {
        7 => {
            let mut p = point;
            p[0] = 2 + (p[64] & 1);
            p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", &p)
        }
        8 => p256_blob(b"ecdsa-sha2-nistp256", b"nistp256", &point[..64]),
        9 => p256_blob(b"ecdsa-sha2-nistp256", b"nistp384", &point),
        10 => [&hand[..], &[0][..]].concat(),
        11 => p256_blob(b"ecdsa-sha2-nistp384", b"nistp384", &point),
        _ => hand.clone(),
    };
    let got = HostKey::parse(&blob);
    let want = match &blob[4..23] {
        b"ecdsa-sha2-nistp256" => ref_p256(&blob),
        other => Err(KeyError::UnsupportedAlgorithm(other.to_vec())),
    };
    match (&got, &want) {
        (Ok(HostKey::EcdsaP256(k)), Ok(p)) => assert_eq!(k.point(), p),
        (Err(g), Err(w)) => assert_eq!(g, w, "P-256 tamper {tamper}"),
        _ => panic!("P-256 disagreement: library {got:?}, reference {want:?}"),
    }
    assert_eq!(got.is_ok(), tamper < 7, "only untampered blobs parse");
    let Ok(key) = got else {
        return;
    };
    assert_eq!(key.key_type(), KeyType::EcdsaP256);
    check_accepted_key(&key, &hand);
    let HostKey::EcdsaP256(p256) = &key else {
        unreachable!("checked above");
    };
    assert_eq!(p256.to_blob(), hand);

    let (scheme, label) = choose_scheme_and_label(&mut cur, &[SignatureScheme::EcdsaP256Sha256]);
    let provider = choose_provider(cur.u8());
    let mut inner = ssh_string(&scalar_body(&mut cur));
    inner.extend(ssh_string(&scalar_body(&mut cur)));
    if cur.u8().is_multiple_of(16) {
        inner.push(0);
    }
    let fixed = fixed_signature(&inner);
    assert_eq!(fixed, ref_fixed(&inner), "fixed_signature({inner:?})");
    let msg_len = usize::from(cur.u8()) % 65;
    let message = cur.take_filled(msg_len, 89);
    verify_and_check(
        &key,
        scheme,
        &message,
        &label,
        &inner,
        provider.as_ref(),
        fixed.map(|rs| Request::P256 { point, rs }),
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        run_raw(&[]);
        return;
    };
    match sel {
        0x00..=0x7f => run_raw(rest),
        0x80..=0xbf => structured_ed25519(rest),
        0xc0..=0xdf => structured_rsa(rest),
        _ => structured_p256(rest),
    }
});
