//! Host socket, QUIC/TLS stack and runtime adapters for the QUIC binding.
//!
//! Available only with the `std` feature. This module will hold the glue
//! between the portable binding state machine and an OS-backed UDP socket,
//! a QUIC/TLS implementation and (if ever adopted) an async runtime. No
//! runtime has been selected.
//!
//! The `quinn-backend` feature provides `tatami_quic::diag`, a blocking,
//! single-threaded diagnostic **handshake observer** over `quinn-proto` and
//! `rustls`. It is an experiment that informs this module's future design
//! (sans-I/O core driven by a socket loop with explicit deadlines); it is
//! not the binding's transport adapter and carries no SSH bytes.
