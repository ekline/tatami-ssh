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
//! | [`negotiate`] (`kex`) | Client proposal and RFC 4253 §7.1 negotiation for the first profile; strict-KEX and `first_kex_packet_follows` evaluation. |
//! | [`transcript`] (`kex`) | X25519 agreement, exchange hash, session id and key derivation for `curve25519-sha256`. |
//! | [`gcm`] (`kex`) | `aes128-gcm@openssh.com` protected packets with a never-repeating nonce counter. |
//! | [`handshake`] (`kex`) | Portable client state machine: identification → `KEXINIT` → `KEX_ECDH_*` → host signature → trust decision → `NEWKEYS` → `SERVICE_REQUEST`/`EXT_INFO`/`SERVICE_ACCEPT` → `DISCONNECT`. |
//! | [`io`] (`std`) | Blocking TCP client adapter and bounded diagnostic listener. |
//! | [`io::handshake`] (`std` + `kex`) | Blocking driver for the handshake with one overall deadline and OS entropy. |
//!
//! The `kex` feature implements exactly the first interoperability profile
//! of `docs/crypto-provider-audit.md`: `curve25519-sha256`, `ssh-ed25519`
//! host keys, `aes128-gcm@openssh.com` in both directions, `none`
//! compression, strict KEX and `EXT_INFO` receive. The handshake stops after
//! `SERVICE_ACCEPT` for `ssh-userauth`; user authentication, re-exchange,
//! other algorithms and the connection protocol are **not** implemented.
//!
//! # Portability
//!
//! The parsers, the probe and the handshake state machine are `no_std` with
//! `alloc`; the `kex` providers are pure Rust. The `std` feature enables
//! [`io`], which is the only place sockets, clocks, OS entropy and OS errors
//! appear.

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

#[cfg(feature = "kex")]
pub mod gcm;
#[cfg(feature = "kex")]
pub mod handshake;
#[cfg(feature = "kex")]
pub mod negotiate;
#[cfg(feature = "kex")]
pub mod transcript;

#[cfg(feature = "std")]
pub mod io;
