//! SSH key and signature representations and cryptographic provider contracts.
//!
//! This package owns SSH public-key and signature encodings, format
//! validation, supported `SubjectPublicKeyInfo`-to-SSH conversions, thin
//! wrappers around cryptographic providers, and key-policy contracts. It does
//! not own SSH KEX orchestration, TLS handshakes, userauth policy decisions,
//! or home-grown cryptographic primitives.
//!
//! # Portability
//!
//! Always `no_std` with `alloc`. There is no `std` feature. Public APIs are
//! expressed in terms of `core`/`alloc` values; callers supply providers for
//! entropy and signing operations.
//!
//! No cryptographic provider has been selected. Future providers are expected
//! to sit behind explicit backend features, and any that require `std` must
//! say so rather than pulling it into shared protocol code.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub use tatami_wire as wire;
