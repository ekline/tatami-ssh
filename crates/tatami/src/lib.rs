//! Reusable SSH client and server composition.
//!
//! `tatami` is the application-facing facade. It owns the reusable [`client`]
//! and [`server`] modules, application configuration, filesystem and policy
//! integrations, and (behind `std`) the host adapters in `host`. It does not
//! duplicate protocol state machines that belong to lower packages.
//!
//! # Features
//!
//! | Feature | Effect |
//! |---|---|
//! | `tcp` | Enables the `tatami-tcp` binding, re-exported as `tcp`. |
//! | `quic` | Enables the `tatami-quic` binding, re-exported as `quic`. |
//! | `std` | Enables `host` and forwards `std` to any enabled binding. |
//! | `kex` | Enables the portable TCP key-exchange profile in `tatami-tcp` and `tatami-keys`, and with `std` the `client::handshake` module and the `tatami-client handshake` command. |
//! | `quic-diag` | Enables the host-only QUIC/TLS diagnostic backend and the `tatami-quic-*` binaries. |
//!
//! `std` never selects a transport on its own: with `std` alone, no binding
//! is compiled. Bindings are independent; either, both or neither may be
//! enabled. Feature-gated items are referred to with plain code spans in
//! this documentation so that it builds under every feature combination.
//!
//! # Binaries
//!
//! `tatami-client` and `tatami-server` are built only with `std,tcp`. The
//! client offers the TCP initial-offer probe (`client::probe`) and, when
//! `kex` is also enabled, the active TCP handshake (`client::handshake`),
//! which performs key exchange, verifies the host signature against an
//! operator-supplied `SHA256:` pin and requests `ssh-userauth` but never
//! authenticates a user. The server offers the TCP diagnostic observer
//! (`server::observe`), which performs no key exchange.
//!
//! # Portability
//!
//! The crate is `#![no_std]` with `alloc`; `std` is linked only when the
//! feature is enabled, so the portable modules never see the `std` prelude
//! even in host builds.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use tatami_auth as auth;
pub use tatami_connection as connection;
pub use tatami_keys as keys;
#[cfg(feature = "quic")]
pub use tatami_quic as quic;
#[cfg(feature = "tcp")]
pub use tatami_tcp as tcp;

pub mod client;
pub mod json;
#[cfg(feature = "quic-diag")]
pub mod quic_diag;
pub mod server;
pub mod text;

#[cfg(feature = "std")]
pub mod host;
