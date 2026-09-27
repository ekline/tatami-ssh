//! Host signature provider for RSA/SHA-2 and ECDSA P-256 SSH host keys
//! (features `rsa` / `ecdsa-p256`).
//!
//! The portable handshake (`tatami_ssh_tcp`) and key layer
//! (`tatami_ssh_keys`) parse and police host keys and signatures and bind
//! them to the negotiated scheme; this adapter performs only the final
//! mathematical check with `ring` 0.17, the provider rustls already uses
//! in this workspace:
//!
//! | Request | `ring` algorithm |
//! |---|---|
//! | RSA PKCS#1 v1.5 / SHA-256 (`rsa-sha2-256`) | `RSA_PKCS1_2048_8192_SHA256` over the raw `(n, e)` components |
//! | RSA PKCS#1 v1.5 / SHA-512 (`rsa-sha2-512`) | `RSA_PKCS1_2048_8192_SHA512` |
//! | ECDSA P-256 / SHA-256 (`ecdsa-sha2-nistp256`) | `ECDSA_P256_SHA256_FIXED` over the SEC1 point and `r || s` |
//!
//! `ring` enforces the same 2048–8192-bit RSA bounds as the portable
//! policy, requires the signature to be exactly the modulus length (the
//! portable layer has already restored RFC 8332 shortened signatures),
//! validates the P-256 point and the ranges of `r` and `s`. Only public
//! keys are handled: no signing, decryption or key generation happens here,
//! so the `rsa` crate's timing advisory (RUSTSEC-2023-0071) does not apply
//! and that crate is not linked. See `docs/crypto-provider-audit.md`.

use ring::signature as rs;
use tatami_ssh_keys::SignatureScheme;
#[cfg(feature = "rsa")]
use tatami_ssh_keys::provider::RsaHash;
use tatami_ssh_keys::provider::{ProviderRejected, ProviderRequest, SignatureProvider};

/// `ring`-backed verification of the schemes enabled in this build.
#[derive(Clone, Copy, Debug, Default)]
pub struct RingSignatureProvider;

impl SignatureProvider for RingSignatureProvider {
    fn supports(&self, scheme: SignatureScheme) -> bool {
        match scheme {
            SignatureScheme::RsaSha2_256 | SignatureScheme::RsaSha2_512 => cfg!(feature = "rsa"),
            SignatureScheme::EcdsaP256Sha256 => cfg!(feature = "ecdsa-p256"),
            SignatureScheme::Ed25519 => false,
        }
    }

    fn verify(
        &self,
        message: &[u8],
        request: &ProviderRequest<'_>,
    ) -> Result<(), ProviderRejected> {
        let result = match request {
            #[cfg(feature = "rsa")]
            ProviderRequest::RsaPkcs1v15 {
                hash,
                modulus,
                exponent,
                signature,
            } => {
                let alg = match hash {
                    RsaHash::Sha256 => &rs::RSA_PKCS1_2048_8192_SHA256,
                    RsaHash::Sha512 => &rs::RSA_PKCS1_2048_8192_SHA512,
                };
                rs::RsaPublicKeyComponents {
                    n: modulus,
                    e: exponent,
                }
                .verify(alg, message, signature)
            }
            #[cfg(feature = "ecdsa-p256")]
            ProviderRequest::EcdsaP256Sha256 {
                public_point,
                signature,
            } => rs::UnparsedPublicKey::new(&rs::ECDSA_P256_SHA256_FIXED, &public_point[..])
                .verify(message, &signature[..]),
            // A request for a scheme this build does not support.
            #[allow(unreachable_patterns)]
            _ => return Err(ProviderRejected),
        };
        result.map_err(|_| ProviderRejected)
    }
}

/// The provider to hand to the TCP handshake in this build: `Some` when an
/// RSA or ECDSA feature is enabled.
#[must_use]
pub fn provider() -> Option<alloc::boxed::Box<dyn SignatureProvider + Send>> {
    Some(alloc::boxed::Box::new(RingSignatureProvider))
}

#[cfg(test)]
mod tests {
    //! Real signatures made by OpenSSL (`openssl dgst -sha256|-sha512 -sign`
    //! over the fixed message below) with OpenSSH-generated fixture keys
    //! (`ssh-keygen -t rsa -b 2048` / `-t ecdsa -b 256`, test use only).
    use super::*;
    use alloc::vec::Vec;
    use base64ct::{Base64, Encoding as _};

    const MESSAGE: &[u8] = b"tatami provider fixture";

    fn b64(s: &str) -> Vec<u8> {
        Base64::decode_vec(s).unwrap()
    }

    #[cfg(feature = "rsa")]
    mod rsa {
        use super::*;
        use tatami_ssh_keys::HostKey;

        const PUB: &str = "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/pUSpK/bpDncU75uYgJ+xQtxuqITHzTd9IUzFgNNlp1atsMgG+plKggA93jMaPuSc/PKrn0ShISco1UWZajKeNXyO2jdcsWtwiRXLQRLWFgT308pyunpMmewS03xJg7nBhneWSPbLjvr3PxALsDZSplTTCl15Iyuwvcoq14Jp+oPJ27Jz73sRRYqcwXoyrMqfgOOb5kTeS+EG206df1zfwVkLNmzTh+N3c5krdc49eQjg3JKGszQjpIotfyJSOwtDTHrexFcrYJgXNPjaytgO3OJ5UnAvXuQCl2YeDu3pwJUuil5rGFfLNloa5pmSD0a34c/8IxUl7LZVCbSWGGtd";
        const SIG_SHA256: &str = "V7xfZcgJpXGLdShzGn3O3yl1/pkibBE37tK0QkzVsBGD1jHVDHZOgNO13BA335+H64W71nNt88IqCJY9qOOB9MHZR1UaM4wIx3DMSutIr2JcjQ25nWAVq6+dnDS1tSFZVSeNjJr0tCG0+vKQpjwSDEPjKIEBPvaXIU+hcU/FUxK1JASkGOnPLzkB4KlO64opJ7iRV5rtzFYScrje3Qp3VuXDCQTkeFMjruRyJaHnvL9tGq4x2R+6N8Jcf8INuZ5WutvLiTqutLXqRbB+LFLdQT8bHyeCiF88blAwB9sN3vU9shiHjrOeeAJY/dEH4nrlVLEroX4D1EWYju2mYBN1ow==";
        const SIG_SHA512: &str = "S6MXgsjx1iYKHCw3gfRcFrpxbtg3LPH+1CvzE1zyNrtIpZ5yO9y33y3Y2XZute7WMXluY0XNC1uPg8K2NWxS3h7HjY5Yhfj6PkE1vfVcN8QYBddlLL4C+VLZnuT3WeQ2ZPDnydLGj92DBa50AP2U8fdATZ8uX9I0lPbkyJ1AZ1RLlZqG+7MvIDnGA9VyD/Z/0glUjbLX5Uw8PjEB5FqJteMiDY3ljWTKDa1JBtxxFR8e0tUs1Htrtb4bb+hIW68Fhl9XUPmExq+l4ak9KjiKeH+jZ/0E899JxpnCin+gcALpb+czXVYkmzXma7J7LQDxK8sSAC8kb0wJsv/lc0GCbA==";

        fn verify(scheme: SignatureScheme, sig: &[u8]) -> Result<(), tatami_ssh_keys::VerifyError> {
            let key = HostKey::parse(&b64(PUB)).unwrap();
            let mut blob = Vec::new();
            for part in [scheme.name(), sig] {
                blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
                blob.extend_from_slice(part);
            }
            let sig = tatami_ssh_keys::SignatureBlob::decode(&blob).unwrap();
            key.verify(scheme, MESSAGE, &sig, Some(&RingSignatureProvider))
        }

        #[test]
        fn openssl_signatures_verify_under_their_hash_only() {
            assert!(RingSignatureProvider.supports(SignatureScheme::RsaSha2_256));
            verify(SignatureScheme::RsaSha2_256, &b64(SIG_SHA256)).unwrap();
            verify(SignatureScheme::RsaSha2_512, &b64(SIG_SHA512)).unwrap();
            // Swapped hashes, a flipped bit.
            assert!(verify(SignatureScheme::RsaSha2_512, &b64(SIG_SHA256)).is_err());
            assert!(verify(SignatureScheme::RsaSha2_256, &b64(SIG_SHA512)).is_err());
            let mut bad = b64(SIG_SHA256);
            bad[100] ^= 1;
            assert!(verify(SignatureScheme::RsaSha2_256, &bad).is_err());
        }
    }

    #[cfg(feature = "ecdsa-p256")]
    mod p256 {
        use super::*;
        use tatami_ssh_keys::HostKey;

        const PUB: &str = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPefqcX04ziwNySvMXeLEfDe8F0XSC8g003NOymUwN0vb5UpZ3nIXNJJQafT41xQzPXH9DJRby8NLEtRLgS20No=";
        /// OpenSSL's DER `ECDSA-Sig-Value`; converted to SSH mpints below.
        const SIG_DER: &str = "MEQCIGohtf8KUSFj3HImk6w2ssKHFuPegOTI0gpHXMTNxpy7AiBqAobheH2eIPrk3J7NQwiYVP+eXPgB2TlSf1onQj/new==";

        fn mpint(m: &[u8]) -> Vec<u8> {
            let m = &m[m.iter().position(|&b| b != 0).unwrap_or(m.len())..];
            let mut body = Vec::new();
            if m.first().is_some_and(|b| b & 0x80 != 0) {
                body.push(0);
            }
            body.extend_from_slice(m);
            let mut out = (body.len() as u32).to_be_bytes().to_vec();
            out.extend(body);
            out
        }

        /// SSH signature from the DER form (two short-form INTEGERs).
        fn ssh_signature() -> Vec<u8> {
            let der = b64(SIG_DER);
            let r_len = usize::from(der[3]);
            let r = &der[4..4 + r_len];
            let s = &der[6 + r_len..];
            [mpint(r), mpint(s)].concat()
        }

        fn verify(inner: &[u8], message: &[u8]) -> Result<(), tatami_ssh_keys::VerifyError> {
            let key = HostKey::parse(&b64(PUB)).unwrap();
            let sig = tatami_ssh_keys::SignatureBlob {
                algorithm: b"ecdsa-sha2-nistp256",
                signature: inner,
            };
            key.verify(
                SignatureScheme::EcdsaP256Sha256,
                message,
                &sig,
                Some(&RingSignatureProvider),
            )
        }

        #[test]
        fn openssl_signature_verifies() {
            verify(&ssh_signature(), MESSAGE).unwrap();
            assert!(verify(&ssh_signature(), b"another message").is_err());
            // The DER form itself is not an SSH signature.
            assert!(verify(&b64(SIG_DER), MESSAGE).is_err());
        }

        #[test]
        fn off_curve_point_never_verifies() {
            let mut blob = b64(PUB);
            let last = blob.len() - 1;
            blob[last] ^= 0x01;
            let key = HostKey::parse(&blob).expect("structurally valid");
            let sig = ssh_signature();
            let sig = tatami_ssh_keys::SignatureBlob {
                algorithm: b"ecdsa-sha2-nistp256",
                signature: &sig,
            };
            assert_eq!(
                key.verify(
                    SignatureScheme::EcdsaP256Sha256,
                    MESSAGE,
                    &sig,
                    Some(&RingSignatureProvider)
                ),
                Err(tatami_ssh_keys::VerifyError::Invalid)
            );
        }
    }
}
