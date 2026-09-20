//! SSH connection protocol (RFC 4254) and channel lifecycle engine.
//!
//! This package owns connection and channel state machines, local and peer
//! channel numbers, pending-open context, channel requests and replies, SSH
//! window accounting, application events and admission decisions. It does not
//! own QUIC stream IDs, socket operations, TLS, physical stream admission or
//! external process execution.
//!
//! # Contracts
//!
//! - **Distinct identities.** Local and peer SSH channel numbers are distinct
//!   from any connection-local handle, and none of them are QUIC stream IDs.
//!   Stream association lives solely in the QUIC binding.
//! - **Opening is a lifecycle.** Pending local opens, incoming requests,
//!   application acceptance/refusal and peer confirmation/refusal are all
//!   observable states. A ready transport stream is not an accepted channel.
//!   The requested channel type is retained until its reply is decoded.
//! - **Engine outputs are intents.** The engine requests message transmission
//!   and application actions; bindings carry them over their own topology
//!   with bounded queues and per-direction ordering.
//! - **Separate credit domains.** Ordinary SSH window accounting is an
//!   identifiable module here. QUIC byte and stream-count credit stay in the
//!   QUIC binding. There is no switch to ignore windows.
//!
//! # Implemented so far
//!
//! [`opening`]: the channel-opening lifecycle engine. Data transfer,
//! window accounting, requests, EOF and close are not implemented.
//!
//! # Portability
//!
//! Always `no_std` with `alloc`. There is no `std` feature.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub use tatami_wire as wire;

pub mod opening;
