//! Conventional SSH transport binding over TCP.
//!
//! This package owns ordinary SSH transport behaviour: identification string
//! exchange, binary packet protection, key exchange, service negotiation and
//! rekeying, plus the TCP runtime driver that composes the shared auth and
//! connection engines. TCP mode is genuine SSH and targets interoperability
//! with unmodified clients and servers.
//!
//! It does not own QUIC bootstrap, TLS exporters, stream mapping or any
//! QUIC-specific policy, and it does not depend on `tatami-quic` or on the
//! `tatami` facade.
//!
//! # Portability
//!
//! The binding state machine is `no_std` with `alloc`. The `std` feature
//! enables [`io`], which is where OS socket and runtime adapters will live.
//! The two are kept separate so that the protocol state remains portable and
//! so that host-only dependencies never leak into shared engine code.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use tatami_auth as auth;
pub use tatami_connection as connection;
pub use tatami_keys as keys;
pub use tatami_wire as wire;

#[cfg(feature = "std")]
pub mod io;
