//! Conventional SSH transport binding over TCP.
//!
//! This package owns ordinary SSH transport behaviour: identification string
//! exchange, binary packet framing and (eventually) protection, key
//! exchange, service negotiation and rekeying, plus the TCP runtime driver
//! that composes the shared auth and connection engines. TCP mode is genuine
//! SSH and targets interoperability with unmodified clients and servers.
//!
//! It does not own QUIC bootstrap, TLS exporters, stream mapping or any
//! QUIC-specific policy, and it does not depend on `tatami-quic` or on the
//! `tatami` facade.
//!
//! # Implemented so far
//!
//! | Module | Status |
//! |---|---|
//! | [`ident`] | Incremental identification parsing with prelude handling and limits. |
//! | [`packet`] | Initial unprotected packet framing with checked bounds. |
//! | [`initial`] | Bounded input buffer and shared pre-`KEXINIT` message handling. |
//! | [`probe`] | Portable client-side initial-offer probe (no client `KEXINIT` sent). |
//! | [`observer`] | Portable server-side observer (no server `KEXINIT` sent). |
//! | [`io`] (`std`) | Blocking TCP client adapter and bounded diagnostic listener. |
//!
//! Key exchange, host-key verification, packet protection and service
//! negotiation are **not** implemented. The probe observes an advertised
//! proposal and stops.
//!
//! # Portability
//!
//! The parsers and the probe state machine are `no_std` with `alloc`. The
//! `std` feature enables [`io`], which is the only place sockets, clocks and
//! OS errors appear.

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

pub mod ident;
pub mod initial;
pub mod observer;
pub mod packet;
pub mod probe;

#[cfg(feature = "std")]
pub mod io;
