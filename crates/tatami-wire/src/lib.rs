//! SSH primitive encodings and bounded message codecs.
//!
//! This package owns the byte-level representation of SSH values: primitive
//! types (`byte`, `boolean`, `uint32`, `uint64`, `string`, `mpint`,
//! `name-list`), raw message fields, checked lengths and bounded opaque
//! extension tails. It does not own sockets, TCP or QUIC records, state
//! transitions, TLS, or trust policy.
//!
//! # Portability
//!
//! `tatami-wire` is the only package in the workspace that must work without
//! an allocator. Codecs operate on borrowed input and caller-provided output
//! buffers by default. Owned helpers that return collections are gated behind
//! the optional `alloc` feature.
//!
//! # Contracts
//!
//! - A decoder consumes an already delimited payload. It never needs to
//!   understand an unknown channel type merely to locate the next record.
//! - Lengths are checked against the payload bound before any allocation.
//! - Type-specific tails of opening messages are preserved as bounded opaque
//!   byte ranges rather than being discarded or partially interpreted.
//!
//! No protocol behaviour is implemented yet; see `docs/architecture.md` for
//! the next implementation slice.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;
