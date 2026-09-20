//! Experimental SSH over QUIC transport binding.
//!
//! This package owns QUIC/TLS integration, the SSH/QUIC bootstrap and
//! session-binding derivation, the enclosing record format on QUIC streams,
//! channel-to-stream association, QUIC stream scheduling and admission,
//! migration exposure, and its own driver for the shared auth and connection
//! engines.
//!
//! It does not own conventional SSH key exchange, a fabricated common
//! transport handshake, or process/PTY persistence after connection death,
//! and it does not depend on `tatami-tcp` or on the `tatami` facade.
//!
//! # Deliberately undefined
//!
//! The scaffold does not define QUIC record framing, SSH-window to QUIC-credit
//! mapping, stream association, session-binding construction, or a crypto
//! abstraction. These remain open protocol questions; see
//! `docs/tatami-ssh-design-state-checkpoint.md`. In particular:
//!
//! - QUIC stream IDs are never SSH channel numbers. An explicit association
//!   registry will live here.
//! - Stream readiness is not channel acceptance.
//! - QUIC byte and stream-count credit is accounted here, separately from the
//!   SSH window state owned by `tatami-connection`.
//! - Path migration events do not re-run authentication or replace the
//!   logical SSH session.
//!
//! # Portability
//!
//! The binding state machine is `no_std` with `alloc`. The `std` feature
//! enables [`io`], which is where OS socket, QUIC/TLS stack and runtime
//! adapters will live. A QUIC/TLS stack that itself needs `std` must be
//! introduced behind an explicit backend feature that enables `std`, not
//! imported into shared code.

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
