//! SSH user authentication (RFC 4252) state machines.
//!
//! This package owns the client and server userauth state machines,
//! method-specific decoding context, signature-input construction,
//! method/authorization callbacks, and the session security context that
//! userauth consumes. It does not own session-identifier derivation, socket
//! I/O, or PTY/channel management.
//!
//! # Security facts, not shared KEX
//!
//! `tatami-auth` consumes a session identifier/binding plus established
//! protection and identity context. The TCP binding obtains its identifier
//! from the initial SSH key exchange; the QUIC binding derives a separate
//! binding after its bootstrap. Those facts are normalised only at the
//! driver/auth boundary, and their provenance is preserved for diagnostics.
//! This package does not define a generic fixed-size exchange hash.
//!
//! # Portability
//!
//! Always `no_std` with `alloc`. There is no `std` feature. Host trust,
//! signature validity and user authorization remain separate decisions made
//! through caller-supplied policy.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub use tatami_keys as keys;
pub use tatami_wire as wire;
