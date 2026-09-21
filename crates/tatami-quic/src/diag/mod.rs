//! QUIC/TLS diagnostic handshake observer (experiment, host-only).
//!
//! This is observer **(a)** of `docs/quic-observer-readiness.md`: a real QUIC
//! v1 endpoint (`quinn-proto`, sans-I/O) with a real TLS 1.3 stack (`rustls`
//! on `ring`) that completes handshakes and reports what happened. It is
//! not observer (b) and it is not an SSH service: no identification string,
//! no `KEXINIT`, no stream data, no application protocol of any kind is
//! sent or accepted. Every datagram on the wire is produced by `quinn-proto`
//! from `Transmit` values; this crate never constructs a QUIC packet.
//!
//! # What is fixed here
//!
//! - **Versions.** Endpoints support QUIC v1 (`0x00000001`) only. A client
//!   offering another version receives a Version Negotiation packet from
//!   the library; because `quinn-proto` 0.11 exposes neither the negotiated
//!   version nor a VN event, the observer counts VN responses by inspecting
//!   its *own* outgoing datagram and reports `quic_version = 1` for every
//!   accepted connection by construction.
//! - **TLS.** TLS 1.3 only (QUIC requires it, RFC 9001 §4.2). The negotiated
//!   TLS version is therefore known without being read back.
//! - **0-RTT and resumption.** Disabled on both ends: the server keeps
//!   `max_early_data_size = 0` and sends no session tickets; the client sets
//!   `enable_early_data = false` and `Resumption::disabled()`. Nothing calls
//!   `into_0rtt`/`accept_0rtt`. Every run is a fresh full handshake.
//! - **Streams and datagrams.** `max_concurrent_{bidi,uni}_streams = 0` and
//!   no datagram receive buffer, so a peer that tries to open a stream or
//!   send a DATAGRAM frame commits a transport error. Any stream/datagram
//!   event that nevertheless surfaces is counted and ignored; it never
//!   creates application work.
//! - **Bounds.** Each handshake has one deadline (default 5 s) that doubles
//!   as the QUIC idle timeout; the server is bounded by `max_concurrent`,
//!   `max_connections` and `run_for`; records flow through a bounded channel
//!   with drop counting (W-22).
//! - **Identity.** A generated Ed25519 test identity ([`identity`]). The
//!   client trusts either a pinned certificate SHA-256 or an explicit test
//!   root; there is no system trust store. Pin comparison is the only trust
//!   decision made, and only its *outcome* is reported.
//!
//! # Address validation, Retry and identity are three different things
//!
//! An Initial packet's source address is unvalidated. With
//! `require_validation` the server answers the first Initial with a Retry
//! (`Endpoint::retry`) and accepts only an Initial carrying the resulting
//! token; `quinn-proto` reports this as `Incoming::remote_address_validated()`.
//! Validation proves the peer can *receive* at that address, nothing about
//! who it is. Without Retry this backend never validates before the
//! handshake (it sends no NEW_TOKEN frames), and the 3× anti-amplification
//! limit is enforced inside `quinn-proto` against that state.
//!
//! # Layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`identity`] | `TestIdentity` (rcgen Ed25519 self-signed cert, PEM persistence), certificate fingerprint, SPKI helpers |
//! | [`tls`] | rustls glue: recording `ResolvesServerCert`, pinned verifiers, QUIC crypto configs |
//! | [`server`] | `DiagServerConfig`, sans-I/O `ServerCore`, `DiagServer` (bound UDP socket, blocking run), events |
//! | [`client`] | `DiagClientConfig`, sans-I/O `ClientCore`, blocking `run`, `ClientOutcome` |
//! | [`inmem`] | Two cores exchanging datagrams through queues, for tests |

pub mod client;
pub mod identity;
pub mod inmem;
pub mod server;
pub mod tls;
mod udp;

/// The QUIC state machine this backend drives, re-exported so experiments
/// and the facade can name its types without a direct dependency.
pub use quinn_proto;
/// The TLS stack, re-exported for the same reason.
pub use rustls;

use std::net::SocketAddr;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use quinn_proto::{EndpointConfig, IdleTimeout, TransportConfig, VarInt};

/// QUIC version this backend speaks and accepts (RFC 9000).
pub const QUIC_VERSION_1: u32 = 0x0000_0001;

/// Default per-handshake deadline; also the QUIC idle timeout.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// One UDP payload the library asked us to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    /// Where to send it.
    pub destination: SocketAddr,
    /// The complete UDP payload.
    pub payload: Vec<u8>,
}

/// Configuration rejected before any socket was touched.
#[derive(Debug)]
pub enum ConfigError {
    /// ALPN list is empty (RFC 9001 §8.1 makes ALPN mandatory here) or an
    /// entry is empty or longer than 255 bytes (RFC 7301 §3.1).
    Alpn(&'static str),
    /// A duration is zero or too large for a QUIC varint of milliseconds.
    BadDuration(&'static str),
    /// A count that must be positive is zero.
    ZeroLimit(&'static str),
    /// rustls refused the TLS configuration.
    Tls(rustls::Error),
    /// The private key could not be loaded by the provider.
    Key(rustls::Error),
    /// quinn-proto refused the crypto configuration (no initial suite).
    Quic(String),
    /// The server name is not a valid TLS `ServerName`.
    ServerName(String),
    /// The exporter probe length is zero or over 255 bytes.
    Exporter(&'static str),
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConfigError::Alpn(why) => write!(f, "invalid ALPN list: {why}"),
            ConfigError::BadDuration(which) => write!(f, "{which} must be > 0 and fit a varint"),
            ConfigError::ZeroLimit(which) => write!(f, "{which} must be > 0"),
            ConfigError::Tls(e) => write!(f, "TLS configuration rejected: {e}"),
            ConfigError::Key(e) => write!(f, "private key rejected by provider: {e}"),
            ConfigError::Quic(e) => write!(f, "QUIC crypto configuration rejected: {e}"),
            ConfigError::ServerName(n) => write!(f, "invalid server name {n:?}"),
            ConfigError::Exporter(why) => write!(f, "invalid exporter probe: {why}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Validates an ALPN list: non-empty, each entry 1..=255 bytes.
pub fn validate_alpn(alpn: &[Vec<u8>]) -> Result<(), ConfigError> {
    if alpn.is_empty() {
        return Err(ConfigError::Alpn(
            "at least one protocol is required; the value is experimental and must be given explicitly",
        ));
    }
    for p in alpn {
        if p.is_empty() {
            return Err(ConfigError::Alpn("empty protocol name"));
        }
        if p.len() > 255 {
            return Err(ConfigError::Alpn("protocol name longer than 255 bytes"));
        }
    }
    Ok(())
}

/// Transport configuration shared by both ends: no streams, no datagrams,
/// no MTU discovery or GSO, idle timeout equal to the handshake deadline.
pub fn transport_config(handshake_timeout: Duration) -> Result<Arc<TransportConfig>, ConfigError> {
    if handshake_timeout.is_zero() {
        return Err(ConfigError::BadDuration("handshake_timeout"));
    }
    let idle = IdleTimeout::try_from(handshake_timeout)
        .map_err(|_| ConfigError::BadDuration("handshake_timeout"))?;
    let mut t = TransportConfig::default();
    t.max_concurrent_bidi_streams(VarInt::from_u32(0))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .datagram_receive_buffer_size(None)
        .max_idle_timeout(Some(idle))
        .keep_alive_interval(None)
        .mtu_discovery_config(None)
        .enable_segmentation_offload(false);
    Ok(Arc::new(t))
}

/// Endpoint configuration: QUIC v1 only, fresh random reset key.
#[must_use]
pub fn endpoint_config() -> Arc<EndpointConfig> {
    let mut cfg = EndpointConfig::default();
    cfg.supported_versions(std::vec![QUIC_VERSION_1]);
    Arc::new(cfg)
}

/// Classifies a datagram that the endpoint produced *itself* (not through a
/// connection). Used only for counting; the bytes are what we are about to
/// send, so this inspects nothing peer-controlled beyond what the library
/// already validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointResponse {
    /// Long header with version `0x00000000` (RFC 9000 §17.2.1).
    VersionNegotiation,
    /// Anything else (stateless reset, Initial close, Retry).
    Other,
}

impl EndpointResponse {
    /// Classifies `payload`.
    #[must_use]
    pub fn classify(payload: &[u8]) -> Self {
        if payload.len() >= 5 && payload[0] & 0x80 != 0 && payload[1..5] == [0, 0, 0, 0] {
            EndpointResponse::VersionNegotiation
        } else {
            EndpointResponse::Other
        }
    }
}

/// Bounded, escaped copy of peer-supplied text for reports: printable ASCII
/// kept, everything else as `\xNN`, truncated to `max` input bytes.
#[must_use]
pub fn bounded_escaped(bytes: &[u8], max: usize) -> String {
    let n = bytes.len().min(max);
    let mut out = String::with_capacity(n);
    for &b in &bytes[..n] {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => {
                use core::fmt::Write as _;
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    if bytes.len() > n {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_validation() {
        assert!(validate_alpn(&[]).is_err());
        assert!(validate_alpn(&[Vec::new()]).is_err());
        assert!(validate_alpn(&[std::vec![0u8; 256]]).is_err());
        assert!(validate_alpn(&[b"tatami-diag/0".to_vec()]).is_ok());
    }

    #[test]
    fn version_negotiation_classifier() {
        assert_eq!(
            EndpointResponse::classify(&[0xc0, 0, 0, 0, 0, 8]),
            EndpointResponse::VersionNegotiation
        );
        assert_eq!(
            EndpointResponse::classify(&[0xc0, 0, 0, 0, 1, 8]),
            EndpointResponse::Other
        );
        assert_eq!(
            EndpointResponse::classify(&[0x40, 0, 0, 0, 0, 8]),
            EndpointResponse::Other
        );
        assert_eq!(EndpointResponse::classify(&[]), EndpointResponse::Other);
    }

    #[test]
    fn transport_config_rejects_zero() {
        assert!(transport_config(Duration::ZERO).is_err());
        assert!(transport_config(Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn escaping_is_bounded() {
        assert_eq!(bounded_escaped(b"ab\\c\x01\xff", 64), "ab\\\\c\\x01\\xff");
        assert_eq!(bounded_escaped(b"abcdef", 3), "abc...");
    }
}
