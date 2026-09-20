//! Host socket, QUIC/TLS stack and runtime adapters for the QUIC binding.
//!
//! Available only with the `std` feature. This module will hold the glue
//! between the portable binding state machine and an OS-backed UDP socket,
//! a QUIC/TLS implementation and an async runtime. No provider, runtime,
//! entropy source or TLS exporter implementation has been selected; each
//! requires a feature/capability audit before adoption.
