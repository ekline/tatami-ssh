//! QUIC/TLS diagnostic handshake facade (feature `quic-diag`).
//!
//! Thin composition over [`tatami_quic::diag`] for the `tatami-quic-server`
//! and `tatami-quic-client` binaries: option types, identity loading, JSON
//! Lines encoding and text rendering. It adds no protocol behaviour.
//!
//! This is observer (a) of `docs/quic-observer-readiness.md`: it completes
//! TLS 1.3 handshakes over QUIC v1 and reports them. It is **experimental**,
//! the ALPN value is configurable and **unregistered**, no interoperability
//! with any other implementation is claimed, 0-RTT is disabled, and it is
//! **not an SSH service**: no identification string, no `KEXINIT`, no
//! stream ever exists. Values copied from a ClientHello are untrusted
//! metadata supplied by the peer.
//!
//! # JSON Lines schema (`schema` = 1, `transport` = "quic")
//!
//! | `event` | Fields |
//! |---|---|
//! | `quic_listener_started` | `bound`, `certificate_sha256`, `alpn`, `require_validation`, `zero_rtt`, `experimental`, `alpn_registered` |
//! | `quic_handshake_observation` | see [`server::observation_record`] |
//! | `overload` | `dropped_since_last`, `total_dropped` |
//! | `quic_listener_stopped` | see [`server::summary_record`] |
//!
//! The client's `--json` output is one object; see [`client::Report::to_json`].

pub mod client;
pub mod server;
mod time;

pub use time::rfc3339;

use alloc::string::String;
use alloc::vec::Vec;

use crate::json::Value;

/// Renders peer-supplied bytes for JSON: lossy text plus bounded hex when
/// the bytes are not printable ASCII, so nothing is lost or misread.
#[must_use]
pub fn bytes_value(bytes: &[u8], max_hex: usize) -> Value {
    if bytes.iter().all(|b| (0x20..=0x7e).contains(b)) {
        Value::lossy_text(bytes)
    } else {
        let n = bytes.len().min(max_hex);
        Value::object()
            .field("text", Value::lossy_text(bytes))
            .field("hex", Value::hex(&bytes[..n]))
            .field("hex_truncated", bytes.len() > n)
            .build()
    }
}

/// Array of [`bytes_value`]s.
#[must_use]
pub fn bytes_list(items: &[Vec<u8>], max_hex: usize) -> Value {
    Value::Array(items.iter().map(|b| bytes_value(b, max_hex)).collect())
}

/// Array of strings.
#[must_use]
pub fn string_list(items: &[String]) -> Value {
    Value::strings(items.iter().map(String::as_str))
}
