//! A server host key of any supported type, and signature verification
//! bound to the negotiated scheme.
//!
//! [`HostKey::verify`] applies these rules, in order, before any
//! cryptographic work:
//!
//! 1. The signature blob's label must equal the negotiated scheme
//!    ([`VerifyError::UnexpectedSignatureAlgorithm`]); `ssh-rsa` (RSA/SHA-1)
//!    is not a scheme and so always fails here.
//! 2. The negotiated scheme must be one for this key's type
//!    ([`VerifyError::AlgorithmMismatch`]).
//! 3. For RSA and ECDSA P-256, a host [`SignatureProvider`] that supports
//!    the scheme must be present ([`VerifyError::ProviderUnavailable`]).
//! 4. The signature bytes are parsed strictly for the type
//!    ([`VerifyError::MalformedSignature`]).
//! 5. Ed25519 is verified here (`ed25519-dalek` `verify_strict`); RSA and
//!    ECDSA P-256 by the provider ([`VerifyError::Invalid`] on refusal).
//!
//! A successful verification proves possession of the private key for the
//! presented blob; whether that blob is trusted is decided separately
//! through [`crate::trust`].

use alloc::vec::Vec;

use crate::algorithm::{KeyType, SignatureScheme};
use crate::blob::{PublicKeyBlob, SignatureBlob};
#[cfg(feature = "ecdsa-p256")]
use crate::ecdsa::EcdsaP256PublicKey;
#[cfg(feature = "ed25519")]
use crate::ed25519::{Ed25519PublicKey, Ed25519Signature};
use crate::error::{KeyError, VerifyError};
use crate::provider::SignatureProvider;
#[cfg(feature = "rsa")]
use crate::rsa::RsaPublicKey;

/// A validated host public key. Variants exist for the enabled key-type
/// features; other blobs are [`KeyError::UnsupportedAlgorithm`] with the
/// name preserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostKey {
    /// An `ssh-ed25519` key (RFC 8709).
    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519PublicKey),
    /// An `ssh-rsa` key within the RSA policy ([`crate::rsa`]).
    #[cfg(feature = "rsa")]
    Rsa(RsaPublicKey),
    /// An `ecdsa-sha2-nistp256` key ([`crate::ecdsa`]).
    #[cfg(feature = "ecdsa-p256")]
    EcdsaP256(EcdsaP256PublicKey),
}

impl HostKey {
    /// Interprets a parsed public-key blob strictly.
    pub fn from_blob(blob: &PublicKeyBlob<'_>) -> Result<Self, KeyError> {
        match KeyType::from_name(blob.algorithm) {
            #[cfg(feature = "ed25519")]
            Some(KeyType::Ed25519) => Ed25519PublicKey::from_blob(blob).map(HostKey::Ed25519),
            #[cfg(feature = "rsa")]
            Some(KeyType::Rsa) => RsaPublicKey::from_blob(blob).map(HostKey::Rsa),
            #[cfg(feature = "ecdsa-p256")]
            Some(KeyType::EcdsaP256) => EcdsaP256PublicKey::from_blob(blob).map(HostKey::EcdsaP256),
            _ => Err(KeyError::UnsupportedAlgorithm(blob.algorithm.to_vec())),
        }
    }

    /// Decodes and interprets raw blob bytes (`K_S`).
    pub fn parse(blob: &[u8]) -> Result<Self, KeyError> {
        Self::from_blob(&PublicKeyBlob::decode(blob)?)
    }

    /// The key type.
    #[must_use]
    pub const fn key_type(&self) -> KeyType {
        match self {
            #[cfg(feature = "ed25519")]
            HostKey::Ed25519(_) => KeyType::Ed25519,
            #[cfg(feature = "rsa")]
            HostKey::Rsa(_) => KeyType::Rsa,
            #[cfg(feature = "ecdsa-p256")]
            HostKey::EcdsaP256(_) => KeyType::EcdsaP256,
        }
    }

    /// The public-key (blob) algorithm name of this key.
    #[must_use]
    pub const fn algorithm(&self) -> &'static [u8] {
        self.key_type().name()
    }

    /// The canonical public-key blob. For a key parsed with
    /// [`HostKey::parse`] this equals the input, since only canonical
    /// encodings are accepted.
    #[must_use]
    pub fn to_blob(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "ed25519")]
            HostKey::Ed25519(key) => crate::spki::ssh_blob_of(key).to_vec(),
            #[cfg(feature = "rsa")]
            HostKey::Rsa(key) => key.to_blob(),
            #[cfg(feature = "ecdsa-p256")]
            HostKey::EcdsaP256(key) => key.to_blob(),
        }
    }

    /// Encodes the public-key blob into `out`, returning its length.
    pub fn encode_blob(&self, out: &mut [u8]) -> Result<usize, tatami_ssh_wire::EncodeError> {
        let blob = self.to_blob();
        let available = out.len();
        let dst = out.get_mut(..blob.len()).ok_or(
            tatami_ssh_wire::EncodeError::InsufficientCapacity {
                needed: blob.len(),
                available,
            },
        )?;
        dst.copy_from_slice(&blob);
        Ok(blob.len())
    }

    /// Verifies `sig` over `message` under the negotiated `scheme`; see the
    /// module documentation for the order of checks. `provider` is needed
    /// for every scheme except Ed25519.
    pub fn verify(
        &self,
        scheme: SignatureScheme,
        message: &[u8],
        sig: &SignatureBlob<'_>,
        provider: Option<&dyn SignatureProvider>,
    ) -> Result<(), VerifyError> {
        if sig.algorithm != scheme.name() {
            return Err(VerifyError::UnexpectedSignatureAlgorithm {
                expected: scheme.name(),
                found: sig.algorithm.to_vec(),
            });
        }
        if scheme.key_type() != self.key_type() {
            return Err(VerifyError::AlgorithmMismatch {
                key_algorithm: self.algorithm().to_vec(),
                signature_algorithm: sig.algorithm.to_vec(),
            });
        }
        let provider = || {
            provider
                .filter(|p| p.supports(scheme))
                .ok_or(VerifyError::ProviderUnavailable {
                    scheme: scheme.name(),
                })
        };
        let _ = &provider;
        match self {
            #[cfg(feature = "ed25519")]
            HostKey::Ed25519(key) => {
                let sig =
                    Ed25519Signature::from_blob(sig).map_err(VerifyError::MalformedSignature)?;
                key.verify(message, &sig)
            }
            #[cfg(feature = "rsa")]
            HostKey::Rsa(key) => {
                let hash = match scheme {
                    SignatureScheme::RsaSha2_512 => crate::provider::RsaHash::Sha512,
                    _ => crate::provider::RsaHash::Sha256,
                };
                key.verify(hash, message, sig.signature, provider()?)
            }
            #[cfg(feature = "ecdsa-p256")]
            HostKey::EcdsaP256(key) => key.verify(message, sig.signature, provider()?),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ProviderRejected, ProviderRequest};
    use core::cell::RefCell;

    /// Records what reached the provider and answers with `verdict`.
    struct Mock {
        supports: &'static [SignatureScheme],
        verdict: Result<(), ProviderRejected>,
        seen: RefCell<alloc::vec::Vec<alloc::string::String>>,
    }

    impl Mock {
        fn new(
            supports: &'static [SignatureScheme],
            verdict: Result<(), ProviderRejected>,
        ) -> Self {
            Mock {
                supports,
                verdict,
                seen: RefCell::new(alloc::vec::Vec::new()),
            }
        }
    }

    impl SignatureProvider for Mock {
        fn supports(&self, scheme: SignatureScheme) -> bool {
            self.supports.contains(&scheme)
        }
        fn verify(
            &self,
            message: &[u8],
            request: &ProviderRequest<'_>,
        ) -> Result<(), ProviderRejected> {
            let what = match request {
                ProviderRequest::RsaPkcs1v15 {
                    hash,
                    modulus,
                    exponent,
                    signature,
                } => alloc::format!(
                    "rsa {hash:?} n={} e={exponent:?} sig={} m={message:?}",
                    modulus.len(),
                    signature.len()
                ),
                ProviderRequest::EcdsaP256Sha256 {
                    public_point,
                    signature,
                } => alloc::format!(
                    "p256 q0={} rs={} m={message:?}",
                    public_point[0],
                    signature.len()
                ),
            };
            self.seen.borrow_mut().push(what);
            self.verdict
        }
    }

    #[cfg(feature = "rsa")]
    mod rsa {
        use super::*;
        use crate::provider::RsaHash;
        use crate::test_vectors::*;

        fn key() -> HostKey {
            HostKey::parse(&b64(RSA_2048_PUB)).unwrap()
        }

        fn sig<'a>(label: &'a [u8], bytes: &'a [u8]) -> SignatureBlob<'a> {
            SignatureBlob {
                algorithm: label,
                signature: bytes,
            }
        }

        #[test]
        fn openssh_fixture_parses_canonically() {
            let blob = b64(RSA_2048_PUB);
            let k = key();
            assert_eq!(k.key_type(), KeyType::Rsa);
            assert_eq!(k.algorithm(), b"ssh-rsa");
            assert_eq!(k.to_blob(), blob);
            let r = match &k {
                HostKey::Rsa(r) => r,
                #[allow(unreachable_patterns)]
                _ => panic!("not RSA"),
            };
            assert_eq!(r.modulus_bits(), 2048);
            assert_eq!(r.exponent(), &[1, 0, 1]);
            assert_eq!(
                alloc::string::ToString::to_string(&crate::Sha256Fingerprint::of_blob(&blob)),
                RSA_2048_FP
            );
            let mut out = alloc::vec![0u8; blob.len()];
            assert_eq!(k.encode_blob(&mut out), Ok(blob.len()));
            assert_eq!(out, blob);
            assert!(k.encode_blob(&mut out[..10]).is_err());
            // Below the policy: rejected before anything else.
            assert_eq!(
                HostKey::parse(&b64(RSA_1024_PUB)),
                Err(KeyError::RsaModulus { bits: 1024 })
            );
        }

        #[test]
        fn both_sha2_schemes_reach_the_provider_with_their_hash() {
            let p = Mock::new(
                &[SignatureScheme::RsaSha2_256, SignatureScheme::RsaSha2_512],
                Ok(()),
            );
            let s = [0x42u8; 256];
            key()
                .verify(
                    SignatureScheme::RsaSha2_256,
                    b"h",
                    &sig(b"rsa-sha2-256", &s),
                    Some(&p),
                )
                .unwrap();
            key()
                .verify(
                    SignatureScheme::RsaSha2_512,
                    b"h",
                    &sig(b"rsa-sha2-512", &s),
                    Some(&p),
                )
                .unwrap();
            assert_eq!(
                *p.seen.borrow(),
                [
                    alloc::format!(
                        "rsa {:?} n=256 e=[1, 0, 1] sig=256 m=[104]",
                        RsaHash::Sha256
                    ),
                    alloc::format!(
                        "rsa {:?} n=256 e=[1, 0, 1] sig=256 m=[104]",
                        RsaHash::Sha512
                    ),
                ]
            );
        }

        #[test]
        fn verification_is_bound_to_the_negotiated_scheme() {
            let p = Mock::new(
                &[SignatureScheme::RsaSha2_256, SignatureScheme::RsaSha2_512],
                Ok(()),
            );
            let s = [0x42u8; 256];
            // RSA/SHA-1 label, under either negotiated SHA-2 scheme.
            for negotiated in [SignatureScheme::RsaSha2_256, SignatureScheme::RsaSha2_512] {
                assert_eq!(
                    key().verify(negotiated, b"h", &sig(b"ssh-rsa", &s), Some(&p)),
                    Err(VerifyError::UnexpectedSignatureAlgorithm {
                        expected: negotiated.name(),
                        found: b"ssh-rsa".to_vec()
                    })
                );
            }
            // The other SHA-2 label than negotiated.
            assert_eq!(
                key().verify(
                    SignatureScheme::RsaSha2_512,
                    b"h",
                    &sig(b"rsa-sha2-256", &s),
                    Some(&p)
                ),
                Err(VerifyError::UnexpectedSignatureAlgorithm {
                    expected: b"rsa-sha2-512",
                    found: b"rsa-sha2-256".to_vec()
                })
            );
            // A scheme for another key type.
            assert_eq!(
                key().verify(
                    SignatureScheme::Ed25519,
                    b"h",
                    &sig(b"ssh-ed25519", &s),
                    Some(&p)
                ),
                Err(VerifyError::AlgorithmMismatch {
                    key_algorithm: b"ssh-rsa".to_vec(),
                    signature_algorithm: b"ssh-ed25519".to_vec()
                })
            );
            assert!(p.seen.borrow().is_empty(), "nothing reached the provider");
        }

        #[test]
        fn provider_availability_and_refusal() {
            let s = [0x42u8; 256];
            let blob = sig(b"rsa-sha2-256", &s);
            assert_eq!(
                key().verify(SignatureScheme::RsaSha2_256, b"h", &blob, None),
                Err(VerifyError::ProviderUnavailable {
                    scheme: b"rsa-sha2-256"
                })
            );
            let only_512 = Mock::new(&[SignatureScheme::RsaSha2_512], Ok(()));
            assert_eq!(
                key().verify(SignatureScheme::RsaSha2_256, b"h", &blob, Some(&only_512)),
                Err(VerifyError::ProviderUnavailable {
                    scheme: b"rsa-sha2-256"
                })
            );
            let refuses = Mock::new(&[SignatureScheme::RsaSha2_256], Err(ProviderRejected));
            assert_eq!(
                key().verify(SignatureScheme::RsaSha2_256, b"h", &blob, Some(&refuses)),
                Err(VerifyError::Invalid)
            );
            // Oversized signatures never reach it.
            let long = [0u8; 257];
            assert!(matches!(
                key().verify(
                    SignatureScheme::RsaSha2_256,
                    b"h",
                    &sig(b"rsa-sha2-256", &long),
                    Some(&refuses)
                ),
                Err(VerifyError::MalformedSignature(
                    KeyError::WrongLength { .. }
                ))
            ));
            assert_eq!(refuses.seen.borrow().len(), 1);
        }
    }

    #[cfg(feature = "ecdsa-p256")]
    mod p256 {
        use super::*;
        use crate::ecdsa::tests::mpint;
        use crate::test_vectors::*;

        #[test]
        fn openssh_fixture_and_scheme_binding() {
            let blob = b64(P256_PUB);
            let k = HostKey::parse(&blob).unwrap();
            assert_eq!(k.key_type(), KeyType::EcdsaP256);
            assert_eq!(k.to_blob(), blob);
            assert_eq!(
                alloc::string::ToString::to_string(&crate::Sha256Fingerprint::of_blob(&blob)),
                P256_FP
            );
            assert_eq!(
                HostKey::parse(&b64(P384_PUB)),
                Err(KeyError::UnsupportedAlgorithm(
                    b"ecdsa-sha2-nistp384".to_vec()
                ))
            );

            let p = Mock::new(&[SignatureScheme::EcdsaP256Sha256], Ok(()));
            let inner = [mpint(&[0x11; 32]), mpint(&[0x22; 32])].concat();
            let good = SignatureBlob {
                algorithm: b"ecdsa-sha2-nistp256",
                signature: &inner,
            };
            k.verify(SignatureScheme::EcdsaP256Sha256, b"h", &good, Some(&p))
                .unwrap();
            assert_eq!(*p.seen.borrow(), ["p256 q0=4 rs=64 m=[104]"]);

            // Label for another curve; malformed inner; no provider.
            let p384 = SignatureBlob {
                algorithm: b"ecdsa-sha2-nistp384",
                signature: &inner,
            };
            assert!(matches!(
                k.verify(SignatureScheme::EcdsaP256Sha256, b"h", &p384, Some(&p)),
                Err(VerifyError::UnexpectedSignatureAlgorithm { .. })
            ));
            let bad = SignatureBlob {
                algorithm: b"ecdsa-sha2-nistp256",
                signature: &inner[..inner.len() - 1],
            };
            assert!(matches!(
                k.verify(SignatureScheme::EcdsaP256Sha256, b"h", &bad, Some(&p)),
                Err(VerifyError::MalformedSignature(_))
            ));
            assert_eq!(
                k.verify(SignatureScheme::EcdsaP256Sha256, b"h", &good, None),
                Err(VerifyError::ProviderUnavailable {
                    scheme: b"ecdsa-sha2-nistp256"
                })
            );
            assert_eq!(p.seen.borrow().len(), 1);
        }
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn ed25519_never_consults_a_provider() {
        let k = HostKey::parse(&crate::blob::fixtures::test1_key_blob()).unwrap();
        let p = Mock::new(&[], Err(ProviderRejected));
        let blob = crate::blob::fixtures::sig_blob(&crate::blob::fixtures::TEST1_SIGNATURE);
        let sig = SignatureBlob::decode(&blob).unwrap();
        k.verify(SignatureScheme::Ed25519, &[], &sig, Some(&p))
            .unwrap();
        k.verify(SignatureScheme::Ed25519, &[], &sig, None).unwrap();
        assert!(p.seen.borrow().is_empty());
    }
}
