//! SSH primitive encodings and bounded message codecs.
//!
//! This package owns the byte-level representation of SSH values: primitive
//! types (`byte`, `boolean`, `uint32`, `uint64`, `string`, `mpint`,
//! `name-list`), raw message fields, checked lengths and bounded opaque
//! extension tails. It does not own sockets, TCP or QUIC records, state
//! transitions, TLS, cryptography, or trust policy.
//!
//! # Portability
//!
//! `tatami-wire` is the only package in the workspace that must work without
//! an allocator. Codecs operate on borrowed input and caller-provided output
//! buffers. Owned helpers that return collections
//! ([`kexinit::OwnedKexInit`], [`ident::OwnedIdentification`],
//! [`ext_info::OwnedExtInfo`]) are gated behind the optional `alloc` feature.
//!
//! # Contracts
//!
//! - A decoder consumes an already delimited payload. It never needs to
//!   understand an unknown channel type merely to locate the next record.
//! - Lengths and counts are checked against the payload bound before any
//!   allocation or iteration.
//! - Type-specific tails of opening messages are preserved as bounded opaque
//!   byte ranges rather than being discarded or partially interpreted.
//! - On failure a [`Reader`] or [`Writer`] cursor is left where it was
//!   before the failing call; see [`primitives`].
//! - Codecs are syntactic. Method-specific length rules (a 32-byte X25519
//!   value), signature verification and algorithm selection belong to the
//!   drivers and to `tatami-keys`.
//!
//! # Modules
//!
//! | Module | Contents |
//! |---|---|
//! | [`primitives`], [`namelist`] | `Reader`/`Writer`, `Mpint`, `NameList` |
//! | [`ident`] | Identification content syntax (RFC 4253 §4.2) |
//! | [`kexinit`] | `KEXINIT` codec and marker classification |
//! | [`kex`] | `KEX_ECDH_INIT` / `KEX_ECDH_REPLY` (RFC 5656 §4) and `NEWKEYS` |
//! | [`transport`] | `DISCONNECT`, `IGNORE`, `UNIMPLEMENTED`, `DEBUG`, `SERVICE_REQUEST`, `SERVICE_ACCEPT` |
//! | [`ext_info`] | `EXT_INFO` lazy decoder, encoder, known extension names (RFC 8308) |
//! | [`channel`] | Channel-opening codecs (RFC 4254 §5.1) |
//! | [`algorithms`] | Name constants for the first interoperability profile |
//! | [`msg`] | Message numbers |
//!
//! # Not implemented
//!
//! Packet envelopes (TCP binary packets, QUIC records) belong to the
//! transport bindings, as does the *framing* of the identification
//! exchange: [`ident`] parses and encodes identification content only.
//! Negative `mpint` values can be read and inspected but not written; SSH
//! only ever sends positive ones.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod algorithms;
pub mod channel;
pub mod error;
pub mod ext_info;
pub mod ident;
pub mod kex;
pub mod kexinit;
mod message;
pub mod msg;
pub mod namelist;
pub mod primitives;
pub mod transport;

pub use error::{DecodeError, EncodeError, InvalidEncoding, MessageError};
pub use namelist::NameList;
pub use primitives::{Mpint, Reader, Writer};
