//! SSH primitive encodings and bounded message codecs.
//!
//! This package owns the byte-level representation of SSH values: primitive
//! types (`byte`, `boolean`, `uint32`, `uint64`, `string`, `name-list`),
//! raw message fields, checked lengths and bounded opaque extension tails.
//! It does not own sockets, TCP or QUIC records, state transitions, TLS, or
//! trust policy.
//!
//! # Portability
//!
//! `tatami-wire` is the only package in the workspace that must work without
//! an allocator. Codecs operate on borrowed input and caller-provided output
//! buffers. Owned helpers that return collections (currently
//! [`kexinit::OwnedKexInit`]) are gated behind the optional `alloc` feature.
//!
//! # Contracts
//!
//! - A decoder consumes an already delimited payload. It never needs to
//!   understand an unknown channel type merely to locate the next record.
//! - Lengths are checked against the payload bound before any allocation.
//! - Type-specific tails of opening messages are preserved as bounded opaque
//!   byte ranges rather than being discarded or partially interpreted.
//! - On failure a [`Reader`] or [`Writer`] cursor is left where it was
//!   before the failing call; see [`primitives`].
//!
//! # Not implemented
//!
//! `mpint` has no consumer yet and is deliberately absent. Packet envelopes
//! (TCP binary packets, QUIC records) belong to the transport bindings, as
//! does the *framing* of the identification exchange: [`ident`] parses and
//! encodes identification content only.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod channel;
pub mod error;
pub mod ident;
pub mod kexinit;
mod message;
pub mod msg;
pub mod namelist;
pub mod primitives;
pub mod transport;

pub use error::{DecodeError, EncodeError, InvalidEncoding, MessageError};
pub use namelist::NameList;
pub use primitives::{Reader, Writer};
