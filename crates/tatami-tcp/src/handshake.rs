//! Portable client key-exchange and service-negotiation state machine for
//! the first interoperability profile (`curve25519-sha256`, `ssh-ed25519`,
//! `aes128-gcm@openssh.com`).
//!
//! # What it does
//!
//! 1. Queues the client identification and `KEXINIT` for the host to send.
//! 2. Reads the server identification (prelude lines allowed) and `KEXINIT`,
//!    negotiates ([`crate::negotiate`]) and sends `KEX_ECDH_INIT`.
//! 3. Reads `KEX_ECDH_REPLY`, parses `K_S`, computes the shared secret and
//!    exchange hash ([`crate::transcript`]), verifies the host signature and
//!    then **stops** with [`Step::TrustDecisionRequired`]. Nothing further is
//!    sent until [`ClientHandshake::provide_trust`] answers.
//! 4. On `Trusted`: sends `NEWKEYS`, switches its own sending direction to
//!    protected packets ([`crate::gcm`]), reads the server `NEWKEYS`,
//!    switches its receiving direction, sends `SERVICE_REQUEST`, accepts
//!    `EXT_INFO` (first protected packet only, RFC 8308 §2.4; accepted
//!    whether or not `ext-info-c` was offered, as OpenSSH does),
//!    `IGNORE`/`DEBUG` and `SERVICE_ACCEPT`, then sends `DISCONNECT` and
//!    finishes [`HandshakeOutcome::Completed`].
//!
//! It never sends `USERAUTH_REQUEST`: `HandshakeReport::user_authenticated`
//! is always `false`. A server `KEXINIT` after `NEWKEYS` (a re-exchange
//! request) ends the run as [`HandshakeOutcome::RekeyNotSupported`] after a
//! `DISCONNECT` is queued.
//!
//! # Strictness
//!
//! Unlike the passive [`crate::probe`], which skips whatever it can, this
//! state machine is a validator. When strict KEX is negotiated
//! (draft-ietf-sshm-strict-kex-02, both sides' markers of the same
//! spelling): the server `KEXINIT` must have been the first packet; only
//! `KEXINIT`, `NEWKEYS` and key-exchange-specific messages (30–49) are
//! accepted until the initial exchange completes, each the expected number
//! of times; sequence numbers reset to zero after `NEWKEYS` is sent and
//! after it is received; a sequence number that would wrap before the
//! initial exchange completes is fatal. Because strictness is only known
//! once the server `KEXINIT` has been read, a non-`KEXINIT` first packet is
//! accepted provisionally and becomes fatal at that point. Without strict
//! KEX, `IGNORE`/`DEBUG`/`UNIMPLEMENTED` are accepted (and reported) before
//! `NEWKEYS`, counted against the pre-KEX packet budget.
//!
//! If the server set `first_kex_packet_follows` and guessed wrong
//! (RFC 4253 §7.1), exactly one key-exchange-specific message is discarded
//! before the real `KEX_ECDH_REPLY`; that is permitted in strict mode
//! because it is a key-exchange message.
//!
//! # Output contract
//!
//! [`ClientHandshake::step`] returns [`Step::Send`] while serialized bytes
//! are waiting in the output queue; the host calls
//! [`ClientHandshake::take_output`] and writes them (handling partial
//! writes itself), then calls `step` again. The state machine never makes
//! progress while output is pending, so at most one message set
//! (identification + `KEXINIT`, `KEX_ECDH_INIT`, `NEWKEYS`,
//! `SERVICE_REQUEST`, or `DISCONNECT`) is ever queued. Protected packets are
//! sealed exactly once when queued; a nonce is never reused and never reset.
//!
//! # Entropy and padding
//!
//! [`ClientHandshake::new`] draws, in this order, 16 cookie bytes, 32 bytes
//! for the X25519 scalar and a 32-byte padding seed, all through the
//! fallible `try_fill_bytes`. Padding bytes for every packet are expanded
//! from the seed with SHA-256 in counter mode: padding is not key material
//! (RFC 4253 §6 asks only that it be random-looking) and the RNG is not
//! retained beyond construction.
//!
//! # Bounds
//!
//! Input lives in a bounded [`InputBuffer`]; excess input is rejected before
//! copying. Pre-`NEWKEYS` packets and bytes are budgeted
//! ([`HandshakeConfig::max_pre_kex_packets`], `max_pre_kex_bytes`), protected
//! packets by `max_protected_packets`, `EXT_INFO` entries by
//! `max_ext_info_extensions`.
//!
//! # Reports
//!
//! [`HandshakeReport`] contains no secret: algorithm names, the host-key
//! fingerprint and blob length, counters, flags and the outcome. Keys, the
//! shared secret and the ephemeral scalar are zeroized when dropped.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use rand_core::{CryptoRngCore, RngCore};
use sha2::{Digest, Sha256};
use tatami_keys::blob::{PublicKeyBlob, SignatureBlob};
use tatami_keys::ed25519::HostKey;
use tatami_keys::error::KeyError;
use tatami_keys::fingerprint::Sha256Fingerprint;
use tatami_keys::trust::{HostIdentity, TrustDecision, UntrustedReason};
use tatami_wire::ext_info::{ExtInfo, ExtInfoError};
use tatami_wire::kex::{KexEcdhInit, KexEcdhReply, NewKeys};
use tatami_wire::kexinit::{KexInit, OwnedKexInit};
use tatami_wire::transport::{
    Debug as DebugMsg, Disconnect, Ignore, ServiceAccept, ServiceRequest, Unimplemented,
    disconnect_reason,
};
use tatami_wire::{EncodeError, MessageError, msg};
use zeroize::{Zeroize, Zeroizing};

use crate::gcm::{AeadDirection, LENGTH_LEN, OpenError, OpenStep, SealError, TAG_LEN};
pub use crate::ident::OwnedIdentification;
use crate::ident::{
    IdentAnomaly, IdentError, IdentLimits, IdentStep, IdentificationReader,
    InvalidLocalIdentification, build_identification,
};
pub use crate::initial::SkippedMessage;
use crate::initial::{InitialLimits, InputBuffer, InputOverflow, MsgName};
use crate::negotiate::{ClientProposal, Negotiated, NegotiationError, StrictKex, negotiate};
use crate::packet::{
    HEADER_LEN, PacketError, PacketLimits, PacketStep, decode_initial_packet,
    encode_initial_packet_with,
};
use crate::transcript::{
    EphemeralKeyPair, ExchangeHashInputs, KexError, KeySet, SessionId, X25519_LEN,
    derive_aes128_gcm_keys, exchange_hash,
};

/// Software version token sent in the client identification.
pub const DEFAULT_SOFTWARE_VERSION: &str = crate::probe::DEFAULT_SOFTWARE_VERSION;

/// Description sent in the final `DISCONNECT` after `SERVICE_ACCEPT`.
pub const COMPLETE_DESCRIPTION: &[u8] = b"tatami diagnostic complete";

/// Description sent in the `DISCONNECT` that answers a re-exchange request.
pub const REKEY_DESCRIPTION: &[u8] = b"rekeying is not supported by this diagnostic";

/// Configuration for one handshake. Numeric limits are local policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeConfig {
    /// `softwareversion` token for the client identification.
    pub software_version: String,
    /// Offer `ext-info-c` and accept a server `EXT_INFO`.
    pub advertise_ext_info: bool,
    /// Offer both strict-KEX client markers.
    pub offer_strict_kex: bool,
    /// Identification phase limits.
    pub ident: IdentLimits,
    /// Packet-length cap for both unprotected and protected packets.
    pub packet: PacketLimits,
    /// Maximum packets accepted before the server `NEWKEYS`, inclusive.
    pub max_pre_kex_packets: usize,
    /// Maximum framed bytes accepted before the server `NEWKEYS`, inclusive.
    pub max_pre_kex_bytes: usize,
    /// Maximum protected packets accepted after the server `NEWKEYS`.
    pub max_protected_packets: usize,
    /// Maximum `nr-extensions` accepted in `EXT_INFO`.
    pub max_ext_info_extensions: usize,
    /// Service requested after `NEWKEYS`; `ssh-userauth` by default.
    pub service: Vec<u8>,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        let initial = InitialLimits::default();
        HandshakeConfig {
            software_version: String::from(DEFAULT_SOFTWARE_VERSION),
            advertise_ext_info: true,
            offer_strict_kex: true,
            ident: IdentLimits::default(),
            packet: initial.packet,
            max_pre_kex_packets: initial.max_packets,
            max_pre_kex_bytes: initial.max_bytes,
            max_protected_packets: 64,
            max_ext_info_extensions: 64,
            service: tatami_wire::algorithms::SSH_USERAUTH.to_vec(),
        }
    }
}

impl HandshakeConfig {
    /// Largest amount of unconsumed input the state machine will hold.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        let cap = self.packet.max_packet_length as usize;
        let unprotected = cap + HEADER_LEN;
        let protected = cap + LENGTH_LEN + TAG_LEN;
        let ident = self
            .ident
            .max_prelude_line
            .max(self.ident.max_identification_line);
        protected.max(unprotected).max(ident) + ident
    }
}

/// Where the handshake is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for the server identification (prelude lines may arrive).
    ServerIdentification,
    /// Waiting for the server `KEXINIT`.
    ServerKexInit,
    /// `KEX_ECDH_INIT` sent; waiting for `KEX_ECDH_REPLY`.
    EcdhReply,
    /// Signature verified; waiting for [`ClientHandshake::provide_trust`].
    TrustDecision,
    /// Client `NEWKEYS` sent; waiting for the server `NEWKEYS`.
    ServerNewKeys,
    /// Both directions protected; `SERVICE_REQUEST` sent.
    Service,
    /// A terminal outcome exists.
    Finished,
}

impl Phase {
    /// Stable, machine-readable name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Phase::ServerIdentification => "server_identification",
            Phase::ServerKexInit => "server_kexinit",
            Phase::EcdhReply => "kex_ecdh_reply",
            Phase::TrustDecision => "trust_decision",
            Phase::ServerNewKeys => "server_newkeys",
            Phase::Service => "service",
            Phase::Finished => "finished",
        }
    }
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Phase::ServerIdentification => "awaiting server identification",
            Phase::ServerKexInit => "awaiting server KEXINIT",
            Phase::EcdhReply => "awaiting KEX_ECDH_REPLY",
            Phase::TrustDecision => "awaiting host trust decision",
            Phase::ServerNewKeys => "awaiting server NEWKEYS",
            Phase::Service => "awaiting SERVICE_ACCEPT",
            Phase::Finished => "finished",
        })
    }
}

/// Owned copy of what a trust policy gets to see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostIdentityOwned {
    /// Public-key algorithm name from the blob.
    pub algorithm: String,
    /// The complete host-key blob (`K_S`).
    pub blob: Vec<u8>,
    /// SHA-256 of `blob`.
    pub sha256: Sha256Fingerprint,
}

impl HostIdentityOwned {
    /// Borrowed view for [`tatami_keys::trust::HostTrustPolicy::decide`].
    #[must_use]
    pub fn as_identity(&self) -> HostIdentity<'_> {
        HostIdentity {
            algorithm: self.algorithm.as_bytes(),
            blob: &self.blob,
            sha256: self.sha256,
        }
    }
}

/// Result of [`ClientHandshake::step`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// No progress possible without more input.
    NeedMore,
    /// Serialized bytes are waiting in [`ClientHandshake::take_output`].
    Send,
    /// The host signature verified; call [`ClientHandshake::provide_trust`]
    /// before anything else is sent.
    TrustDecisionRequired(HostIdentityOwned),
    /// The handshake has finished. Further calls return the same value.
    Finished(Box<HandshakeOutcome>),
}

/// A protocol violation that ends the handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolViolation {
    /// Identification phase failure (including an unsupported version).
    Ident(IdentError),
    /// Unprotected packet framing failure.
    Packet(PacketError),
    /// Protected packet framing failure other than a tag mismatch.
    Protected(OpenError),
    /// A packet had an empty payload.
    EmptyPayload,
    /// A recognised message failed to decode.
    Message {
        /// Message number.
        number: u8,
        /// Decoder error.
        error: MessageError,
    },
    /// `K_S` is malformed or of an unsupported algorithm.
    HostKey(KeyError),
    /// `Q_S` is malformed or produced an all-zero secret.
    Kex(KexError),
    /// `EXT_INFO` failed validation.
    ExtInfo(ExtInfoError),
    /// `SERVICE_ACCEPT` named a different service than requested.
    ServiceMismatch {
        /// What we asked for.
        requested: Vec<u8>,
        /// What the server accepted.
        accepted: Vec<u8>,
    },
    /// A packet could not be sealed.
    Seal(SealError),
    /// A `KEXINIT` payload could not be encoded (cannot happen with the
    /// fixed proposal; reported rather than panicked on).
    Encode(EncodeError),
}

impl fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolViolation::Ident(e) => write!(f, "identification: {e}"),
            ProtocolViolation::Packet(e) => write!(f, "packet framing: {e}"),
            ProtocolViolation::Protected(e) => write!(f, "protected packet: {e}"),
            ProtocolViolation::EmptyPayload => f.write_str("packet with empty payload"),
            ProtocolViolation::Message { number, error } => {
                write!(f, "malformed {}: {error}", MsgName(*number))
            }
            ProtocolViolation::HostKey(e) => write!(f, "host key: {e}"),
            ProtocolViolation::Kex(e) => write!(f, "key agreement: {e}"),
            ProtocolViolation::ExtInfo(e) => write!(f, "EXT_INFO: {e}"),
            ProtocolViolation::ServiceMismatch {
                requested,
                accepted,
            } => write!(
                f,
                "SERVICE_ACCEPT named {} byte(s) of service, not the requested {} byte(s)",
                accepted.len(),
                requested.len()
            ),
            ProtocolViolation::Seal(e) => write!(f, "sealing: {e}"),
            ProtocolViolation::Encode(e) => write!(f, "encoding: {e}"),
        }
    }
}

/// Which local budget was exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// More than [`HandshakeConfig::max_pre_kex_packets`] packets.
    PreKexPackets {
        /// The configured limit.
        limit: usize,
    },
    /// More than [`HandshakeConfig::max_pre_kex_bytes`] bytes.
    PreKexBytes {
        /// The configured limit.
        limit: usize,
    },
    /// More than [`HandshakeConfig::max_protected_packets`] packets.
    ProtectedPackets {
        /// The configured limit.
        limit: usize,
    },
}

impl fmt::Display for LimitKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LimitKind::PreKexPackets { limit } => {
                write!(f, "more than {limit} packets before NEWKEYS")
            }
            LimitKind::PreKexBytes { limit } => write!(f, "more than {limit} bytes before NEWKEYS"),
            LimitKind::ProtectedPackets { limit } => {
                write!(f, "more than {limit} protected packets")
            }
        }
    }
}

/// Terminal outcome of a handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeOutcome {
    /// Key exchange, host verification, `NEWKEYS` and `SERVICE_ACCEPT` all
    /// succeeded and our `DISCONNECT` was queued.
    Completed,
    /// The trust policy refused the host key. No `NEWKEYS` was sent.
    HostNotTrusted {
        /// The policy's reason.
        reason: UntrustedReason,
    },
    /// The host signature over the exchange hash did not verify (algorithm
    /// mismatch, malformed blob or invalid signature).
    SignatureInvalid,
    /// RFC 4253 §7.1 negotiation failed.
    NegotiationFailed(NegotiationError),
    /// A strict-KEX rule was broken.
    StrictKexViolation {
        /// What was seen.
        detail: String,
    },
    /// A protocol violation.
    ProtocolError(ProtocolViolation),
    /// The server sent `DISCONNECT`.
    ServerDisconnected {
        /// Reason code.
        reason_code: u32,
        /// Raw description. Untrusted.
        description: Vec<u8>,
    },
    /// The server requested a re-exchange, which this diagnostic does not
    /// support; a `DISCONNECT` was queued.
    RekeyNotSupported,
    /// A message that is not valid in the phase it arrived in.
    UnexpectedMessage {
        /// Message number.
        number: u8,
        /// Phase it arrived in.
        phase: Phase,
    },
    /// A protected packet failed authentication.
    TagMismatch,
    /// The adapter reported end of input.
    Eof {
        /// Phase at EOF.
        phase: Phase,
    },
    /// The caller offered more input than the buffer bound allows.
    InputOverflow(InputOverflow),
    /// A local budget was exhausted.
    Limit(LimitKind),
}

impl HandshakeOutcome {
    /// Stable, machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            HandshakeOutcome::Completed => "completed",
            HandshakeOutcome::HostNotTrusted { .. } => "host_not_trusted",
            HandshakeOutcome::SignatureInvalid => "signature_invalid",
            HandshakeOutcome::NegotiationFailed(_) => "negotiation_failed",
            HandshakeOutcome::StrictKexViolation { .. } => "strict_kex_violation",
            HandshakeOutcome::ProtocolError(_) => "protocol_error",
            HandshakeOutcome::ServerDisconnected { .. } => "server_disconnected",
            HandshakeOutcome::RekeyNotSupported => "rekey_not_supported",
            HandshakeOutcome::UnexpectedMessage { .. } => "unexpected_message",
            HandshakeOutcome::TagMismatch => "tag_mismatch",
            HandshakeOutcome::Eof { .. } => "eof",
            HandshakeOutcome::InputOverflow(_) => "input_overflow",
            HandshakeOutcome::Limit(_) => "limit",
        }
    }

    /// `true` only for [`HandshakeOutcome::Completed`].
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, HandshakeOutcome::Completed)
    }
}

impl fmt::Display for HandshakeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeOutcome::Completed => f.write_str("complete: service accepted"),
            HandshakeOutcome::HostNotTrusted { reason } => {
                write!(f, "host key not trusted: {reason:?}")
            }
            HandshakeOutcome::SignatureInvalid => {
                f.write_str("host signature over the exchange hash is invalid")
            }
            HandshakeOutcome::NegotiationFailed(e) => write!(f, "negotiation failed: {e}"),
            HandshakeOutcome::StrictKexViolation { detail } => {
                write!(f, "strict KEX violation: {detail}")
            }
            HandshakeOutcome::ProtocolError(e) => write!(f, "protocol error: {e}"),
            HandshakeOutcome::ServerDisconnected { reason_code, .. } => {
                match disconnect_reason::name(*reason_code) {
                    Some(name) => write!(f, "server disconnected: {name}"),
                    None => write!(f, "server disconnected: reason code {reason_code}"),
                }
            }
            HandshakeOutcome::RekeyNotSupported => {
                f.write_str("server requested a re-exchange; not supported")
            }
            HandshakeOutcome::UnexpectedMessage { number, phase } => {
                write!(f, "unexpected {} while {phase}", MsgName(*number))
            }
            HandshakeOutcome::TagMismatch => f.write_str("protected packet failed authentication"),
            HandshakeOutcome::Eof { phase } => write!(f, "connection closed by peer while {phase}"),
            HandshakeOutcome::InputOverflow(e) => write!(f, "{e}"),
            HandshakeOutcome::Limit(l) => write!(f, "limit exceeded: {l}"),
        }
    }
}

impl core::error::Error for HandshakeOutcome {}

impl From<ProtocolViolation> for HandshakeOutcome {
    fn from(v: ProtocolViolation) -> Self {
        HandshakeOutcome::ProtocolError(v)
    }
}

/// Failure of [`ClientHandshake::new`].
#[derive(Debug)]
pub enum HandshakeInitError {
    /// The configured software version cannot form a valid identification.
    Identification(InvalidLocalIdentification),
    /// The entropy source failed.
    Entropy(rand_core::Error),
    /// The proposal could not be encoded (cannot happen with the fixed
    /// lists; surfaced rather than panicked on).
    Encode(EncodeError),
}

impl fmt::Display for HandshakeInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeInitError::Identification(e) => write!(f, "{e}"),
            HandshakeInitError::Entropy(e) => write!(f, "entropy source failed: {e}"),
            HandshakeInitError::Encode(e) => write!(f, "cannot encode KEXINIT: {e}"),
        }
    }
}

impl core::error::Error for HandshakeInitError {}

/// The two initial proposals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertised {
    /// Ours, as sent.
    pub client: OwnedKexInit,
    /// The server's, if received.
    pub server: Option<OwnedKexInit>,
}

/// The presented host key, without the key itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKeySummary {
    /// Public-key algorithm.
    pub algorithm: String,
    /// SHA-256 of the complete blob (`ssh-keygen -l` form).
    pub fingerprint: Sha256Fingerprint,
    /// Length of the blob in bytes.
    pub blob_len: usize,
}

/// What the server's `EXT_INFO` said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtInfoSummary {
    /// An `EXT_INFO` was received as the first protected packet.
    pub received: bool,
    /// The `server-sig-algs` name-list, if present.
    pub server_sig_algs: Option<Vec<String>>,
    /// Every extension name, known or not, in wire order.
    pub extension_names: Vec<String>,
}

/// A server `DISCONNECT`, recorded even when it is not the outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerDisconnect {
    /// Reason code.
    pub reason_code: u32,
    /// Raw description. Untrusted.
    pub description: Vec<u8>,
}

/// Everything observed, with no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandshakeReport {
    /// Current phase.
    pub phase: Phase,
    /// Our identification without `CR LF` (`V_C`).
    pub client_identification: Vec<u8>,
    /// Server lines before its identification. Untrusted text.
    pub server_prelude_lines: Vec<Vec<u8>>,
    /// The server identification.
    pub server_identification: Option<OwnedIdentification>,
    /// Anomalies of the server identification.
    pub server_identification_anomalies: Vec<IdentAnomaly>,
    /// Both `KEXINIT`s.
    pub advertised: Advertised,
    /// The negotiation result.
    pub selected: Option<Negotiated>,
    /// Strict-KEX markers and decision (client side only until the server
    /// `KEXINIT` arrives).
    pub strict_kex: StrictKex,
    /// Whether the server `KEXINIT` was the first packet after its
    /// identification.
    pub kexinit_was_first_packet: Option<bool>,
    /// `IGNORE`/`DEBUG`/`UNIMPLEMENTED` messages accepted, in order.
    pub skipped_messages: Vec<SkippedMessage>,
    /// A wrongly guessed first key-exchange packet was discarded.
    pub server_guess_discarded: bool,
    /// The presented host key.
    pub host_key: Option<HostKeySummary>,
    /// Whether the host signature verified.
    pub signature_valid: Option<bool>,
    /// Why it did not, if it did not.
    pub signature_error: Option<String>,
    /// The trust policy's decision.
    pub trust: Option<TrustDecision>,
    /// Our `NEWKEYS` was queued.
    pub newkeys_sent: bool,
    /// The server `NEWKEYS` was received.
    pub newkeys_received: bool,
    /// Protected packets sealed.
    pub protected_packets_sent: u32,
    /// Protected packets opened.
    pub protected_packets_received: u32,
    /// Sequence number of the next packet we send.
    pub send_sequence: u32,
    /// Sequence number of the next packet we expect.
    pub receive_sequence: u32,
    /// `EXT_INFO` observations; `Some` once the protected phase began.
    pub ext_info: Option<ExtInfoSummary>,
    /// Service named in `SERVICE_ACCEPT`, if received and matching.
    pub service_accepted: Option<String>,
    /// A server `DISCONNECT`, if one was received.
    pub server_disconnect: Option<ServerDisconnect>,
    /// Terminal outcome, once finished.
    pub outcome: Option<HandshakeOutcome>,
    /// Always `false`: this diagnostic never authenticates.
    pub user_authenticated: bool,
}

/// Padding bytes for outgoing packets: SHA-256 in counter mode over a seed
/// drawn once from the injected entropy source. See the module notes. It
/// deliberately does not implement `CryptoRng`: it is an expander for
/// padding, never a source of key material.
struct PaddingSource {
    seed: Zeroizing<[u8; 32]>,
    counter: u64,
    block: Zeroizing<[u8; 32]>,
    used: usize,
}

impl PaddingSource {
    fn new(seed: [u8; 32]) -> Self {
        PaddingSource {
            seed: Zeroizing::new(seed),
            counter: 0,
            block: Zeroizing::new([0; 32]),
            used: 32,
        }
    }
}

impl RngCore for PaddingSource {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest {
            if self.used == 32 {
                *self.block = Sha256::new()
                    .chain_update(*self.seed)
                    .chain_update(self.counter.to_be_bytes())
                    .finalize()
                    .into();
                self.counter = self.counter.wrapping_add(1);
                self.used = 0;
            }
            *d = self.block[self.used];
            self.used += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Internal result of one processing attempt.
enum Flow {
    /// State changed; re-evaluate.
    Continue,
    /// Nothing more can be done with the buffered input.
    NeedMore,
}

/// The portable client handshake state machine.
pub struct ClientHandshake {
    config: HandshakeConfig,
    phase: Phase,
    client_line: Vec<u8>,
    ident_reader: IdentificationReader,
    buf: InputBuffer,
    out: Vec<u8>,
    /// Outcome to adopt once the queued output has been taken.
    pending_outcome: Option<HandshakeOutcome>,
    outcome: Option<HandshakeOutcome>,
    padding: PaddingSource,

    i_c: Vec<u8>,
    client_kexinit: OwnedKexInit,
    ephemeral: Option<EphemeralKeyPair>,
    q_c: [u8; X25519_LEN],

    prelude: Vec<Vec<u8>>,
    server_ident: Option<OwnedIdentification>,
    server_kexinit: Option<OwnedKexInit>,
    i_s: Option<Vec<u8>>,
    negotiated: Option<Negotiated>,
    strict: StrictKex,
    kexinit_was_first: Option<bool>,
    pre_kex_packets: usize,
    pre_kex_bytes: usize,
    skipped: Vec<SkippedMessage>,
    guess_discarded: bool,

    host_key: Option<HostKeySummary>,
    identity: Option<HostIdentityOwned>,
    signature_valid: Option<bool>,
    signature_error: Option<String>,
    trust: Option<TrustDecision>,
    session_id: Option<SessionId>,
    keys: Option<KeySet>,
    send_aead: Option<AeadDirection>,
    recv_aead: Option<AeadDirection>,
    newkeys_sent: bool,
    newkeys_received: bool,
    send_seq: u32,
    recv_seq: u32,
    protected_sent: u32,
    protected_received: u32,
    ext_info: Option<ExtInfoSummary>,
    service_accepted: Option<String>,
    server_disconnect: Option<ServerDisconnect>,
}

impl fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("phase", &self.phase)
            .field("pending_input", &self.buf.len())
            .field("pending_output", &self.out.len())
            .field("outcome", &self.outcome)
            .finish_non_exhaustive()
    }
}

impl ClientHandshake {
    /// Builds the state machine, draws the cookie, the ephemeral scalar and
    /// the padding seed from `rng`, and queues the client identification and
    /// `KEXINIT` as the first output.
    pub fn new(
        config: HandshakeConfig,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Self, HandshakeInitError> {
        let client_line = build_identification(&config.software_version)
            .map_err(HandshakeInitError::Identification)?;
        let mut cookie = [0u8; 16];
        rng.try_fill_bytes(&mut cookie)
            .map_err(HandshakeInitError::Entropy)?;
        let ephemeral = EphemeralKeyPair::generate(rng).map_err(HandshakeInitError::Entropy)?;
        let mut seed = [0u8; 32];
        rng.try_fill_bytes(&mut seed)
            .map_err(HandshakeInitError::Entropy)?;
        let padding = PaddingSource::new(seed);
        seed.zeroize();

        let proposal = ClientProposal {
            cookie,
            advertise_ext_info: config.advertise_ext_info,
            offer_strict_kex: config.offer_strict_kex,
        };
        let i_c = proposal.encode().map_err(HandshakeInitError::Encode)?;
        let client_kexinit = KexInit::decode(&i_c)
            .expect("proposal encoder produces a decodable KEXINIT")
            .to_owned();
        let strict = StrictKex::offered(&KexInit::decode(&i_c).expect("decodable"));
        let q_c = *ephemeral.public();

        let mut hs = ClientHandshake {
            ident_reader: IdentificationReader::new(config.ident),
            buf: InputBuffer::new(config.buffer_capacity()),
            config,
            phase: Phase::ServerIdentification,
            client_line,
            out: Vec::new(),
            pending_outcome: None,
            outcome: None,
            padding,
            i_c,
            client_kexinit,
            ephemeral: Some(ephemeral),
            q_c,
            prelude: Vec::new(),
            server_ident: None,
            server_kexinit: None,
            i_s: None,
            negotiated: None,
            strict,
            kexinit_was_first: None,
            pre_kex_packets: 0,
            pre_kex_bytes: 0,
            skipped: Vec::new(),
            guess_discarded: false,
            host_key: None,
            identity: None,
            signature_valid: None,
            signature_error: None,
            trust: None,
            session_id: None,
            keys: None,
            send_aead: None,
            recv_aead: None,
            newkeys_sent: false,
            newkeys_received: false,
            send_seq: 0,
            recv_seq: 0,
            protected_sent: 0,
            protected_received: 0,
            ext_info: None,
            service_accepted: None,
            server_disconnect: None,
        };
        // Identification first, then KEXINIT, in one output set.
        hs.out.extend_from_slice(&hs.client_line);
        let i_c = hs.i_c.clone();
        if let Err(outcome) = hs.send_unprotected(&i_c) {
            hs.finish(outcome);
        }
        Ok(hs)
    }

    /// Current phase.
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Our identification without `CR LF` (`V_C`).
    #[must_use]
    pub fn client_identification_line(&self) -> &[u8] {
        &self.client_line[..self.client_line.len() - 2]
    }

    /// The session identifier, once the exchange hash has been computed.
    #[must_use]
    pub const fn session_id(&self) -> Option<&SessionId> {
        self.session_id.as_ref()
    }

    /// Bytes fed but not yet consumed.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.buf.len()
    }

    /// Bytes that may still be fed without overflowing the buffer bound.
    #[must_use]
    pub fn room(&self) -> usize {
        self.buf.room()
    }

    /// Appends received bytes. Input exceeding [`ClientHandshake::room`] is
    /// rejected before copying and ends the handshake. Ignored once finished.
    pub fn feed(&mut self, data: &[u8]) {
        if self.outcome.is_some() {
            return;
        }
        if let Err(e) = self.buf.push(data) {
            self.finish(HandshakeOutcome::InputOverflow(e));
        }
    }

    /// Removes and returns every queued output byte, already serialized.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.out)
    }

    /// Signals end of input.
    pub fn input_ended(&mut self) -> HandshakeOutcome {
        if let Some(o) = &self.outcome {
            return o.clone();
        }
        let outcome = HandshakeOutcome::Eof { phase: self.phase };
        self.finish(outcome.clone());
        outcome
    }

    /// Answers [`Step::TrustDecisionRequired`]. Ignored in any other phase.
    pub fn provide_trust(&mut self, decision: TrustDecision) {
        if self.phase != Phase::TrustDecision {
            return;
        }
        self.trust = Some(decision);
        match decision {
            TrustDecision::Untrusted { reason } => {
                self.keys = None;
                self.finish(HandshakeOutcome::HostNotTrusted { reason });
            }
            TrustDecision::Trusted { .. } => {
                let mut payload = [0u8; NewKeys::LEN];
                let n = NewKeys.encode(&mut payload).expect("one byte fits");
                if let Err(outcome) = self.send_unprotected(&payload[..n]) {
                    self.finish(outcome);
                    return;
                }
                self.newkeys_sent = true;
                // Our sending direction is protected from now on; the
                // receiving direction switches only on the server NEWKEYS.
                let keys = self
                    .keys
                    .as_ref()
                    .expect("keys derived before trust decision");
                self.send_aead = Some(AeadDirection::new(&keys.client_to_server));
                if self.strict_active() {
                    self.send_seq = 0;
                }
                self.phase = Phase::ServerNewKeys;
            }
        }
    }

    /// Advances the state machine as far as the buffered input allows.
    pub fn step(&mut self) -> Step {
        loop {
            if let Some(o) = &self.outcome {
                return Step::Finished(Box::new(o.clone()));
            }
            if !self.out.is_empty() {
                return Step::Send;
            }
            if let Some(o) = self.pending_outcome.take() {
                self.finish(o);
                continue;
            }
            let flow = match self.phase {
                Phase::ServerIdentification => self.step_identification(),
                Phase::ServerKexInit | Phase::EcdhReply | Phase::ServerNewKeys => {
                    self.step_unprotected()
                }
                Phase::TrustDecision => {
                    let identity = self.identity.clone().expect("identity set with phase");
                    return Step::TrustDecisionRequired(identity);
                }
                Phase::Service => self.step_protected(),
                Phase::Finished => unreachable!("finished without an outcome"),
            };
            match flow {
                Flow::Continue => {}
                Flow::NeedMore => return Step::NeedMore,
            }
        }
    }

    /// A snapshot of everything observed so far.
    #[must_use]
    pub fn report(&self) -> HandshakeReport {
        HandshakeReport {
            phase: self.phase,
            client_identification: self.client_identification_line().to_vec(),
            server_prelude_lines: self.prelude.clone(),
            server_identification: self.server_ident.clone(),
            server_identification_anomalies: self
                .server_ident
                .as_ref()
                .map(|i| i.anomalies().collect())
                .unwrap_or_default(),
            advertised: Advertised {
                client: self.client_kexinit.clone(),
                server: self.server_kexinit.clone(),
            },
            selected: self.negotiated.clone(),
            strict_kex: self.strict,
            kexinit_was_first_packet: self.kexinit_was_first,
            skipped_messages: self.skipped.clone(),
            server_guess_discarded: self.guess_discarded,
            host_key: self.host_key.clone(),
            signature_valid: self.signature_valid,
            signature_error: self.signature_error.clone(),
            trust: self.trust,
            newkeys_sent: self.newkeys_sent,
            newkeys_received: self.newkeys_received,
            protected_packets_sent: self.protected_sent,
            protected_packets_received: self.protected_received,
            send_sequence: self.send_seq,
            receive_sequence: self.recv_seq,
            ext_info: self.ext_info.clone(),
            service_accepted: self.service_accepted.clone(),
            server_disconnect: self.server_disconnect.clone(),
            outcome: self.outcome.clone(),
            user_authenticated: false,
        }
    }

    // ----- internals -----------------------------------------------------

    fn strict_active(&self) -> bool {
        self.strict.negotiated
    }

    fn initial_kex_done(&self) -> bool {
        self.newkeys_sent && self.newkeys_received
    }

    fn finish(&mut self, outcome: HandshakeOutcome) {
        self.phase = Phase::Finished;
        self.pending_outcome = None;
        self.ephemeral = None;
        self.keys = None;
        self.outcome = Some(outcome);
    }

    fn fail(&mut self, outcome: HandshakeOutcome) -> Flow {
        self.finish(outcome);
        Flow::Continue
    }

    fn strict_violation(&mut self, detail: String) -> Flow {
        self.fail(HandshakeOutcome::StrictKexViolation { detail })
    }

    fn unexpected(&mut self, number: u8) -> Flow {
        let phase = self.phase;
        self.fail(HandshakeOutcome::UnexpectedMessage { number, phase })
    }

    /// Advances a sequence counter. Wrapping before the initial exchange
    /// completes is a strict-KEX violation; otherwise it wraps as RFC 4253
    /// §6.4 describes.
    fn bump_sequence(&mut self, send: bool) -> Result<(), HandshakeOutcome> {
        let seq = if send { self.send_seq } else { self.recv_seq };
        let next = match seq.checked_add(1) {
            Some(n) => n,
            None if self.strict_active() && !self.initial_kex_done() => {
                return Err(HandshakeOutcome::StrictKexViolation {
                    detail: String::from(
                        "packet sequence number wrapped before the initial key exchange completed",
                    ),
                });
            }
            None => 0,
        };
        if send {
            self.send_seq = next;
        } else {
            self.recv_seq = next;
        }
        Ok(())
    }

    fn send_unprotected(&mut self, payload: &[u8]) -> Result<(), HandshakeOutcome> {
        // Worst case: header, payload, and two blocks of padding.
        let mut framed = alloc::vec![0u8; HEADER_LEN + payload.len() + 16];
        let padding = &mut self.padding;
        let n = encode_initial_packet_with(payload, &mut framed, |pad| padding.fill_bytes(pad))
            .map_err(|_| {
                ProtocolViolation::Encode(EncodeError::LengthOverflow { len: payload.len() })
            })?;
        self.out.extend_from_slice(&framed[..n]);
        self.bump_sequence(true)
    }

    fn send_protected(&mut self, payload: &[u8]) -> Result<(), HandshakeOutcome> {
        let aead = self
            .send_aead
            .as_mut()
            .expect("protected send before NEWKEYS");
        aead.seal(payload, &mut self.padding, &mut self.out)
            .map_err(ProtocolViolation::Seal)?;
        self.protected_sent += 1;
        self.bump_sequence(true)
    }

    fn send_disconnect(&mut self, description: &[u8]) -> Result<(), HandshakeOutcome> {
        let mut buf = alloc::vec![0u8; 1 + 4 + 4 + description.len() + 4];
        let n = Disconnect {
            reason_code: disconnect_reason::BY_APPLICATION,
            description,
            language_tag: b"",
        }
        .encode(&mut buf)
        .map_err(ProtocolViolation::Encode)?;
        self.send_protected(&buf[..n])
    }

    fn step_identification(&mut self) -> Flow {
        match self.ident_reader.feed(self.buf.as_slice()) {
            Ok(IdentStep::NeedMore) => Flow::NeedMore,
            Ok(IdentStep::Prelude { line, consumed, .. }) => {
                let line = line.to_vec();
                self.prelude.push(line);
                self.buf.consume(consumed);
                Flow::Continue
            }
            Ok(IdentStep::Identification { ident, consumed }) => {
                self.server_ident = Some(OwnedIdentification::from(ident));
                self.buf.consume(consumed);
                self.phase = Phase::ServerKexInit;
                Flow::Continue
            }
            Err(e) => self.fail(ProtocolViolation::Ident(e).into()),
        }
    }

    fn step_unprotected(&mut self) -> Flow {
        let packet = match decode_initial_packet(self.buf.as_slice(), &self.config.packet) {
            Ok(PacketStep::NeedMore { .. }) => return Flow::NeedMore,
            Ok(PacketStep::Complete(p)) => p,
            Err(e) => return self.fail(ProtocolViolation::Packet(e).into()),
        };
        if self.pre_kex_packets >= self.config.max_pre_kex_packets {
            return self.fail(HandshakeOutcome::Limit(LimitKind::PreKexPackets {
                limit: self.config.max_pre_kex_packets,
            }));
        }
        let bytes = self.pre_kex_bytes.saturating_add(packet.total_len);
        if bytes > self.config.max_pre_kex_bytes {
            return self.fail(HandshakeOutcome::Limit(LimitKind::PreKexBytes {
                limit: self.config.max_pre_kex_bytes,
            }));
        }
        self.pre_kex_packets += 1;
        self.pre_kex_bytes = bytes;
        let payload = packet.payload.to_vec();
        self.buf.consume(packet.total_len);
        if let Err(o) = self.bump_sequence(false) {
            return self.fail(o);
        }
        self.handle_unprotected(&payload)
    }

    fn handle_unprotected(&mut self, payload: &[u8]) -> Flow {
        let Some(&number) = payload.first() else {
            return self.fail(ProtocolViolation::EmptyPayload.into());
        };
        match self.phase {
            Phase::ServerKexInit => match number {
                msg::KEXINIT => self.on_server_kexinit(payload),
                msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => self.skip(number, payload),
                msg::DISCONNECT => self.on_disconnect(payload, false),
                _ => self.unexpected(number),
            },
            Phase::EcdhReply | Phase::ServerNewKeys => self.handle_kex_message(number, payload),
            _ => unreachable!("unprotected packets are only read in the KEX phases"),
        }
    }

    /// Messages after the server `KEXINIT` and before its `NEWKEYS`.
    fn handle_kex_message(&mut self, number: u8, payload: &[u8]) -> Flow {
        let strict = self.strict_active();
        let awaiting_reply = self.phase == Phase::EcdhReply;
        let guess_wrong = self
            .negotiated
            .as_ref()
            .is_some_and(|n| n.server_guess_wrong);
        match number {
            n if msg::is_kex_method_specific(n)
                && awaiting_reply
                && guess_wrong
                && !self.guess_discarded =>
            {
                // RFC 4253 §7.1: the server's wrongly guessed first packet.
                self.guess_discarded = true;
                Flow::Continue
            }
            msg::KEX_ECDH_REPLY if awaiting_reply => self.on_ecdh_reply(payload),
            msg::NEWKEYS if !awaiting_reply => self.on_server_newkeys(payload),
            msg::KEXINIT if strict => self.strict_violation(String::from(
                "second KEXINIT during the initial key exchange",
            )),
            msg::KEX_ECDH_REPLY if strict => self.strict_violation(String::from(
                "second KEX_ECDH_REPLY during the initial key exchange",
            )),
            msg::NEWKEYS if strict => {
                self.strict_violation(String::from("NEWKEYS before KEX_ECDH_REPLY"))
            }
            n if msg::is_kex_method_specific(n) && strict => self.strict_violation(alloc::format!(
                "unexpected key-exchange message {n} during the initial key exchange"
            )),
            msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED if strict => self.strict_violation(
                alloc::format!("{} during the initial key exchange", MsgName(number)),
            ),
            msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED => self.skip(number, payload),
            msg::DISCONNECT => self.on_disconnect(payload, strict),
            _ => self.unexpected(number),
        }
    }

    fn skip(&mut self, number: u8, payload: &[u8]) -> Flow {
        let malformed = |error| ProtocolViolation::Message { number, error };
        let message = match number {
            msg::IGNORE => match Ignore::decode(payload) {
                Ok(i) => SkippedMessage::Ignored {
                    data_len: i.data.len(),
                },
                Err(e) => return self.fail(malformed(e).into()),
            },
            msg::DEBUG => match DebugMsg::decode(payload) {
                Ok(d) => SkippedMessage::Debug {
                    always_display: d.always_display,
                    message: d.message.to_vec(),
                    language_tag: d.language_tag.to_vec(),
                },
                Err(e) => return self.fail(malformed(e).into()),
            },
            msg::UNIMPLEMENTED => match Unimplemented::decode(payload) {
                Ok(u) => SkippedMessage::Unimplemented {
                    sequence_number: u.sequence_number,
                },
                Err(e) => return self.fail(malformed(e).into()),
            },
            _ => unreachable!("skip called for a non-skippable message"),
        };
        self.skipped.push(message);
        Flow::Continue
    }

    /// A server `DISCONNECT`. Under strict KEX before `NEWKEYS` it is still a
    /// disallowed message; the reason is recorded in the report either way.
    fn on_disconnect(&mut self, payload: &[u8], strict_violation: bool) -> Flow {
        let d = match Disconnect::decode(payload) {
            Ok(d) => d,
            Err(error) => {
                return self.fail(
                    ProtocolViolation::Message {
                        number: msg::DISCONNECT,
                        error,
                    }
                    .into(),
                );
            }
        };
        let reason_code = d.reason_code;
        let description = d.description.to_vec();
        self.server_disconnect = Some(ServerDisconnect {
            reason_code,
            description: description.clone(),
        });
        if strict_violation {
            return self.strict_violation(alloc::format!(
                "SSH_MSG_DISCONNECT (reason code {reason_code}) during the initial key exchange"
            ));
        }
        self.fail(HandshakeOutcome::ServerDisconnected {
            reason_code,
            description,
        })
    }

    fn on_server_kexinit(&mut self, payload: &[u8]) -> Flow {
        let was_first = self.pre_kex_packets == 1;
        self.kexinit_was_first = Some(was_first);
        let server = match KexInit::decode(payload) {
            Ok(k) => k,
            Err(error) => {
                return self.fail(
                    ProtocolViolation::Message {
                        number: msg::KEXINIT,
                        error,
                    }
                    .into(),
                );
            }
        };
        self.server_kexinit = Some(server.to_owned());
        self.i_s = Some(payload.to_vec());
        let client = KexInit::decode(&self.i_c).expect("our own KEXINIT decodes");
        let negotiated = match negotiate(&client, &server).and_then(|n| {
            n.check_profile()?;
            Ok(n)
        }) {
            Ok(n) => n,
            Err(e) => {
                // Record the markers even when negotiation fails.
                self.strict = StrictKex::evaluate(&client, &server);
                return self.fail(HandshakeOutcome::NegotiationFailed(e));
            }
        };
        self.strict = negotiated.strict_kex;
        self.negotiated = Some(negotiated);
        if self.strict_active() && !was_first {
            return self
                .strict_violation(String::from("KEXINIT was not the first packet received"));
        }
        let mut buf = [0u8; 1 + 4 + X25519_LEN];
        let n = KexEcdhInit {
            client_ephemeral: &self.q_c,
        }
        .encode(&mut buf)
        .expect("fixed-size buffer fits KEX_ECDH_INIT");
        if let Err(o) = self.send_unprotected(&buf[..n]) {
            return self.fail(o);
        }
        self.phase = Phase::EcdhReply;
        Flow::Continue
    }

    fn on_ecdh_reply(&mut self, payload: &[u8]) -> Flow {
        let reply = match KexEcdhReply::decode(payload) {
            Ok(r) => r,
            Err(error) => {
                return self.fail(
                    ProtocolViolation::Message {
                        number: msg::KEX_ECDH_REPLY,
                        error,
                    }
                    .into(),
                );
            }
        };
        let blob = match PublicKeyBlob::decode(reply.host_key_blob) {
            Ok(b) => b,
            Err(e) => return self.fail(ProtocolViolation::HostKey(KeyError::Blob(e)).into()),
        };
        let host_key = match HostKey::from_blob(&blob) {
            Ok(k) => k,
            Err(e) => return self.fail(ProtocolViolation::HostKey(e).into()),
        };
        let identity = HostIdentity::from_blob(&blob);
        self.host_key = Some(HostKeySummary {
            algorithm: String::from_utf8_lossy(identity.algorithm).into_owned(),
            fingerprint: identity.sha256,
            blob_len: identity.blob.len(),
        });
        let identity = HostIdentityOwned {
            algorithm: String::from_utf8_lossy(identity.algorithm).into_owned(),
            blob: identity.blob.to_vec(),
            sha256: identity.sha256,
        };

        let Some(ephemeral) = self.ephemeral.take() else {
            return self.unexpected(msg::KEX_ECDH_REPLY);
        };
        let k = match ephemeral.agree(reply.server_ephemeral) {
            Ok(k) => k,
            Err(e) => return self.fail(ProtocolViolation::Kex(e).into()),
        };
        let v_s = self
            .server_ident
            .as_ref()
            .expect("identification precedes KEX");
        let i_s = self
            .i_s
            .as_ref()
            .expect("server KEXINIT precedes the reply");
        let h = exchange_hash(
            &ExchangeHashInputs {
                v_c: self.client_identification_line(),
                v_s: &v_s.line,
                i_c: &self.i_c,
                i_s,
                k_s: reply.host_key_blob,
                q_c: &self.q_c,
                q_s: reply.server_ephemeral,
            },
            &k,
        );
        let session_id = SessionId::from_initial_exchange(h);

        let verified = SignatureBlob::decode(reply.signature_blob)
            .map_err(|e| alloc::format!("signature blob: {e}"))
            .and_then(|sig| {
                host_key
                    .verify_signature_blob(h.as_bytes(), &sig)
                    .map_err(|e| alloc::format!("{e}"))
            });
        if let Err(detail) = verified {
            self.signature_valid = Some(false);
            self.signature_error = Some(detail);
            return self.fail(HandshakeOutcome::SignatureInvalid);
        }
        self.signature_valid = Some(true);

        // Derive now so `K` can be dropped (zeroized) immediately.
        self.keys = Some(derive_aes128_gcm_keys(&k, &h, &session_id));
        drop(k);
        self.session_id = Some(session_id);
        self.identity = Some(identity);
        self.phase = Phase::TrustDecision;
        Flow::Continue
    }

    fn on_server_newkeys(&mut self, payload: &[u8]) -> Flow {
        if let Err(error) = NewKeys::decode(payload) {
            return self.fail(
                ProtocolViolation::Message {
                    number: msg::NEWKEYS,
                    error,
                }
                .into(),
            );
        }
        self.newkeys_received = true;
        let keys = self.keys.take().expect("keys derived before NEWKEYS");
        self.recv_aead = Some(AeadDirection::new(&keys.server_to_client));
        drop(keys);
        if self.strict_active() {
            self.recv_seq = 0;
        }
        self.phase = Phase::Service;
        self.ext_info = Some(ExtInfoSummary::default());
        let mut buf = alloc::vec![0u8; 1 + 4 + self.config.service.len()];
        let n = ServiceRequest {
            service_name: &self.config.service,
        }
        .encode(&mut buf)
        .expect("buffer sized for the service name");
        if let Err(o) = self.send_protected(&buf[..n]) {
            return self.fail(o);
        }
        Flow::Continue
    }

    fn step_protected(&mut self) -> Flow {
        let aead = self
            .recv_aead
            .as_mut()
            .expect("protected receive after NEWKEYS");
        let (payload, total_len) = match aead.open(self.buf.as_mut_slice(), &self.config.packet) {
            Ok(OpenStep::NeedMore { .. }) => return Flow::NeedMore,
            Ok(OpenStep::Packet(p)) => (p.payload.to_vec(), p.total_len),
            Err(OpenError::TagMismatch) => return self.fail(HandshakeOutcome::TagMismatch),
            Err(e) => return self.fail(ProtocolViolation::Protected(e).into()),
        };
        self.buf.consume(total_len);
        if usize::try_from(self.protected_received)
            .is_ok_and(|n| n >= self.config.max_protected_packets)
        {
            return self.fail(HandshakeOutcome::Limit(LimitKind::ProtectedPackets {
                limit: self.config.max_protected_packets,
            }));
        }
        self.protected_received += 1;
        if let Err(o) = self.bump_sequence(false) {
            return self.fail(o);
        }
        self.handle_protected(&payload)
    }

    fn handle_protected(&mut self, payload: &[u8]) -> Flow {
        let Some(&number) = payload.first() else {
            return self.fail(ProtocolViolation::EmptyPayload.into());
        };
        match number {
            // RFC 8308 §2.4: only as the first packet after NEWKEYS here.
            msg::EXT_INFO if self.protected_received == 1 => self.on_ext_info(payload),
            msg::IGNORE | msg::DEBUG => self.skip(number, payload),
            msg::SERVICE_ACCEPT => self.on_service_accept(payload),
            msg::DISCONNECT => self.on_disconnect(payload, false),
            msg::KEXINIT => {
                if let Err(o) = self.send_disconnect(REKEY_DESCRIPTION) {
                    return self.fail(o);
                }
                self.pending_outcome = Some(HandshakeOutcome::RekeyNotSupported);
                Flow::Continue
            }
            _ => self.unexpected(number),
        }
    }

    fn on_ext_info(&mut self, payload: &[u8]) -> Flow {
        let ext = match ExtInfo::decode(payload) {
            Ok(e) => e,
            Err(error) => {
                return self.fail(
                    ProtocolViolation::Message {
                        number: msg::EXT_INFO,
                        error,
                    }
                    .into(),
                );
            }
        };
        if let Err(e) = ext.validate(self.config.max_ext_info_extensions) {
            return self.fail(ProtocolViolation::ExtInfo(e).into());
        }
        let extension_names = ext
            .extensions()
            .filter_map(Result::ok)
            .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
            .collect();
        let server_sig_algs = match ext.server_sig_algs() {
            None => None,
            Some(Ok(list)) => Some(
                list.iter()
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .collect(),
            ),
            Some(Err(e)) => return self.fail(ProtocolViolation::ExtInfo(e).into()),
        };
        self.ext_info = Some(ExtInfoSummary {
            received: true,
            server_sig_algs,
            extension_names,
        });
        Flow::Continue
    }

    fn on_service_accept(&mut self, payload: &[u8]) -> Flow {
        let accept = match ServiceAccept::decode(payload) {
            Ok(a) => a,
            Err(error) => {
                return self.fail(
                    ProtocolViolation::Message {
                        number: msg::SERVICE_ACCEPT,
                        error,
                    }
                    .into(),
                );
            }
        };
        if accept.service_name != self.config.service.as_slice() {
            let violation = ProtocolViolation::ServiceMismatch {
                requested: self.config.service.clone(),
                accepted: accept.service_name.to_vec(),
            };
            return self.fail(violation.into());
        }
        self.service_accepted = Some(String::from_utf8_lossy(accept.service_name).into_owned());
        if let Err(o) = self.send_disconnect(COMPLETE_DESCRIPTION) {
            return self.fail(o);
        }
        self.pending_outcome = Some(HandshakeOutcome::Completed);
        Flow::Continue
    }
}

/// Shared scripted-server material for the state-machine and driver tests.
///
/// The server side is an *independent* minimal implementation: X25519 with
/// Bob's RFC 7748 secret through `x25519_dalek` directly, hashing with
/// `sha2` directly, sealing with `aes_gcm` directly, and the Ed25519
/// signatures over the deterministic exchange hashes precomputed with
/// python3 `cryptography` (RFC 8032 TEST 1 secret key). Nothing here calls
/// `transcript`, `gcm` or `negotiate`.
#[cfg(test)]
pub(crate) mod scripted {
    use alloc::vec::Vec;

    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::packet::encode_initial_packet;
    use crate::transcript::fixtures::*;
    use crate::transcript::testing::QueueRng;

    /// Padding seed the deterministic RNG hands the client.
    pub(crate) const PADDING_SEED: [u8; 32] = [0xAB; 32];

    /// The RNG the client draws from: cookie, X25519 scalar, padding seed.
    pub(crate) fn client_rng() -> QueueRng {
        QueueRng::new(&[&CLIENT_COOKIE, &ALICE_SECRET, &PADDING_SEED])
    }

    /// One scripted server: its KEXINIT payload and the Python-signed
    /// values for the exchange hash that results from it.
    pub(crate) struct Script {
        pub i_s: Vec<u8>,
        pub h: [u8; 32],
        pub signature: [u8; 64],
        pub key_c: [u8; 16],
        pub iv_a: [u8; 12],
        pub key_d: [u8; 16],
        pub iv_b: [u8; 12],
        /// Server sends EXT_INFO first (it offered ext-info-s).
        pub ext_info: bool,
    }

    fn kexinit(cookie: u8, kex: &[u8], first: bool) -> Vec<u8> {
        let mut out = alloc::vec![20u8];
        out.extend_from_slice(&[cookie; 16]);
        for list in [
            kex,
            &b"ssh-ed25519"[..],
            b"aes128-gcm@openssh.com",
            b"aes128-gcm@openssh.com",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ] {
            out.extend_from_slice(&(list.len() as u32).to_be_bytes());
            out.extend_from_slice(list);
        }
        out.push(u8::from(first));
        out.extend_from_slice(&[0, 0, 0, 0]);
        out
    }

    // Values below from target/fixtures/kex_fixtures2.py (python3 + hashlib
    // + cryptography 50): for each server KEXINIT, H = SHA256(...) over the
    // deterministic transcript, signature = Ed25519(TEST1 secret).sign(H),
    // keys per RFC 4253 §7.2 with session_id = H.

    /// Server offers `curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com`.
    pub(crate) fn strict() -> Script {
        Script {
            i_s: kexinit(
                0x53,
                b"curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
                false,
            ),
            h: H,
            signature: SIGNATURE,
            key_c: KEY_C[..16].try_into().unwrap(),
            iv_a: KEY_A[..12].try_into().unwrap(),
            key_d: KEY_D[..16].try_into().unwrap(),
            iv_b: KEY_B[..12].try_into().unwrap(),
            ext_info: true,
        }
    }

    /// Server prefers `diffie-hellman-group14-sha256`, sets
    /// `first_kex_packet_follows`, and is strict.
    pub(crate) fn guess() -> Script {
        Script {
            i_s: kexinit(
                0x47,
                b"diffie-hellman-group14-sha256,curve25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
                true,
            ),
            h: [
                0x21, 0x22, 0xd0, 0xff, 0xd6, 0x3e, 0xe2, 0x49, 0x48, 0x2e, 0x3c, 0x4c, 0x42, 0x1e,
                0x61, 0xcb, 0xbd, 0x15, 0xb3, 0xb5, 0x61, 0xfe, 0x05, 0x1c, 0xbe, 0x69, 0x5d, 0xe8,
                0xc1, 0x7d, 0x32, 0xb0,
            ],
            signature: [
                0x3d, 0x4b, 0x28, 0xbe, 0x38, 0x49, 0xbd, 0x00, 0xd9, 0x81, 0x85, 0xd0, 0x6b, 0x47,
                0x5f, 0x70, 0x77, 0x83, 0x1f, 0x47, 0x04, 0x44, 0x16, 0x3f, 0x11, 0x90, 0x4c, 0xdc,
                0x62, 0xc0, 0x38, 0x8b, 0x26, 0xdb, 0x31, 0x1d, 0xfe, 0xff, 0x43, 0x22, 0xb7, 0x3b,
                0xc2, 0xc5, 0x75, 0xff, 0x74, 0x1e, 0x8b, 0x34, 0x3c, 0x43, 0x36, 0xb0, 0x19, 0x60,
                0x51, 0x29, 0xaf, 0xe7, 0x9b, 0x3e, 0xe1, 0x09,
            ],
            key_c: [
                0xa7, 0xb1, 0x7e, 0x32, 0x38, 0xb7, 0xfc, 0x53, 0x7f, 0x4e, 0x9a, 0x16, 0xae, 0xdf,
                0x21, 0x7e,
            ],
            iv_a: [
                0x0a, 0xf4, 0xc0, 0xd4, 0xd4, 0xb9, 0x05, 0x8d, 0x01, 0xf7, 0xd3, 0xd0,
            ],
            key_d: [
                0xce, 0xb3, 0x6a, 0x97, 0x98, 0x63, 0x3c, 0xbe, 0xbe, 0x94, 0x38, 0x19, 0x60, 0x83,
                0x2d, 0x64,
            ],
            iv_b: [
                0x79, 0xfc, 0x83, 0x2a, 0xff, 0x0f, 0xec, 0x94, 0x01, 0x1d, 0xfa, 0x93,
            ],
            ext_info: true,
        }
    }

    /// Server offers only `curve25519-sha256`: no strict KEX, no EXT_INFO.
    pub(crate) fn plain() -> Script {
        Script {
            i_s: kexinit(0x50, b"curve25519-sha256", false),
            h: [
                0x11, 0xa4, 0x7a, 0x09, 0x43, 0x91, 0xae, 0xfc, 0x49, 0xa2, 0x4c, 0xa5, 0xd0, 0x38,
                0x5e, 0x48, 0xc9, 0xfe, 0xd5, 0xe2, 0xc7, 0xb9, 0x45, 0x8d, 0x23, 0xff, 0x6e, 0x71,
                0x85, 0x79, 0xde, 0x53,
            ],
            signature: [
                0xb8, 0xfe, 0x61, 0x94, 0x09, 0xae, 0x0e, 0x45, 0x54, 0xa5, 0xfd, 0x8d, 0x11, 0x84,
                0x9d, 0xd4, 0x9f, 0x12, 0xaf, 0xa4, 0x8d, 0x7a, 0x38, 0xa3, 0x4f, 0x4c, 0x82, 0xbd,
                0x30, 0x83, 0x53, 0xfe, 0x6c, 0x44, 0x9f, 0xba, 0xa1, 0xa7, 0xb6, 0xa2, 0xdc, 0x39,
                0x70, 0xbf, 0x40, 0x4e, 0xd3, 0x8b, 0x31, 0xaa, 0x96, 0x58, 0x78, 0xd0, 0x01, 0x65,
                0x0c, 0x61, 0xdc, 0x8c, 0xbf, 0xfb, 0x6f, 0x04,
            ],
            key_c: [
                0x23, 0xda, 0x10, 0xe8, 0xec, 0xef, 0x87, 0x3e, 0xcb, 0xa1, 0xba, 0xd0, 0xae, 0x0f,
                0x1b, 0xf3,
            ],
            iv_a: [
                0x60, 0x54, 0xac, 0x71, 0x51, 0x88, 0x08, 0xdd, 0x6f, 0x2a, 0xd6, 0x6f,
            ],
            key_d: [
                0x08, 0xc8, 0x1a, 0x37, 0x0a, 0x5e, 0xf6, 0x8a, 0xa2, 0x57, 0xc3, 0x6f, 0x3e, 0xbe,
                0xdd, 0xe9,
            ],
            iv_b: [
                0x67, 0xdc, 0x0c, 0x2e, 0xdd, 0xa4, 0xf8, 0x45, 0x91, 0x8e, 0xfd, 0x30,
            ],
            ext_info: false,
        }
    }

    pub(crate) fn string(b: &[u8]) -> Vec<u8> {
        let mut v = (b.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(b);
        v
    }

    /// Unprotected packet with fixed padding bytes.
    pub(crate) fn packet(payload: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; payload.len() + 32];
        let n = encode_initial_packet(payload, 0x5a, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// Independent check that the scripted transcript hashes to the Python
    /// `H`: `V_C`, `V_S`, `I_C`, `I_S`, `K_S`, `A`, `B`, mpint(K) with sha2
    /// directly.
    pub(crate) fn independent_h(i_s: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        for part in [
            V_C,
            V_S,
            &i_c()[..],
            i_s,
            &k_s()[..],
            &ALICE_PUBLIC,
            &BOB_PUBLIC,
        ] {
            hash.update((part.len() as u32).to_be_bytes());
            hash.update(part);
        }
        // K's first byte is 0x4a: no leading zero, no sign padding.
        hash.update(32u32.to_be_bytes());
        hash.update(SHARED_K);
        hash.finalize().into()
    }

    /// Bob's side of the exchange, straight from the provider.
    pub(crate) fn bob_shared_secret_with(q_c: &[u8; 32]) -> [u8; 32] {
        StaticSecret::from(BOB_SECRET)
            .diffie_hellman(&PublicKey::from(*q_c))
            .to_bytes()
    }

    /// `KEX_ECDH_REPLY` payload: `K_S`, `Q_S = B`, signature blob.
    pub(crate) fn ecdh_reply(signature: &[u8; 64]) -> Vec<u8> {
        let mut p = alloc::vec![31u8];
        p.extend(string(&k_s()));
        p.extend(string(&BOB_PUBLIC));
        let mut sig_blob = string(b"ssh-ed25519");
        sig_blob.extend(string(signature));
        p.extend(string(&sig_blob));
        p
    }

    pub(crate) fn ext_info_payload() -> Vec<u8> {
        let mut p = alloc::vec![7, 0, 0, 0, 1];
        p.extend(string(b"server-sig-algs"));
        p.extend(string(b"ssh-ed25519"));
        p
    }

    pub(crate) fn service_accept_payload(service: &[u8]) -> Vec<u8> {
        let mut p = alloc::vec![6u8];
        p.extend(string(service));
        p
    }

    /// Independent AES-GCM sealing (provider called directly) with the
    /// RFC 5647 layout and zero padding.
    pub(crate) struct Sealer {
        cipher: Aes128Gcm,
        nonce: [u8; 12],
    }

    impl Sealer {
        pub(crate) fn new(key: &[u8; 16], iv: &[u8; 12]) -> Self {
            Sealer {
                cipher: Aes128Gcm::new(GenericArray::from_slice(key)),
                nonce: *iv,
            }
        }

        pub(crate) fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
            let n = 1 + payload.len();
            let mut pad = 16 - (n % 16);
            if pad < 4 {
                pad += 16;
            }
            let length = ((n + pad) as u32).to_be_bytes();
            let mut body = alloc::vec![pad as u8];
            body.extend_from_slice(payload);
            body.resize(n + pad, 0);
            let tag = self
                .cipher
                .encrypt_in_place_detached(
                    GenericArray::from_slice(&self.nonce),
                    &length,
                    &mut body,
                )
                .unwrap();
            self.bump();
            let mut out = length.to_vec();
            out.extend(body);
            out.extend_from_slice(&tag);
            out
        }

        /// Decrypts one packet from the front of `buf`; returns the payload
        /// and the total length.
        pub(crate) fn open(&mut self, buf: &[u8]) -> (Vec<u8>, usize) {
            let packet_length = u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
            let total = 4 + packet_length + 16;
            let mut body = buf[4..4 + packet_length].to_vec();
            let tag = GenericArray::clone_from_slice(&buf[4 + packet_length..total]);
            self.cipher
                .decrypt_in_place_detached(
                    GenericArray::from_slice(&self.nonce),
                    &buf[..4],
                    &mut body,
                    &tag,
                )
                .expect("client packet authenticates");
            self.bump();
            let pad = body[0] as usize;
            assert!(pad >= 4);
            (body[1..packet_length - pad].to_vec(), total)
        }

        fn bump(&mut self) {
            let c = u64::from_be_bytes(self.nonce[4..].try_into().unwrap()) + 1;
            self.nonce[4..].copy_from_slice(&c.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::scripted::*;
    use super::*;
    use crate::transcript::fixtures::*;
    use crate::transcript::testing::QueueRng;
    use tatami_keys::trust::{HostTrustPolicy, PinnedSha256, TrustSource};

    fn config() -> HandshakeConfig {
        HandshakeConfig {
            software_version: String::from("tatami_0.1.0"),
            ..HandshakeConfig::default()
        }
    }

    fn handshake(config: HandshakeConfig) -> ClientHandshake {
        ClientHandshake::new(config, &mut client_rng()).unwrap()
    }

    fn pin() -> PinnedSha256 {
        PinnedSha256(Sha256Fingerprint::of_blob(&k_s()))
    }

    fn trusted() -> TrustDecision {
        TrustDecision::Trusted {
            source: TrustSource::PinnedFingerprint,
        }
    }

    /// Drives `hs` on the buffered input until it blocks, collecting output
    /// and answering trust with `decision`.
    fn drive(
        hs: &mut ClientHandshake,
        decision: TrustDecision,
    ) -> (Vec<u8>, Option<HandshakeOutcome>) {
        let mut written = Vec::new();
        loop {
            match hs.step() {
                Step::NeedMore => return (written, None),
                Step::Send => written.extend(hs.take_output()),
                Step::TrustDecisionRequired(id) => {
                    assert!(pin().decide(&id.as_identity()).is_trusted());
                    hs.provide_trust(decision);
                }
                Step::Finished(o) => return (written, Some(*o)),
            }
        }
    }

    /// Parses the client's unprotected packets from `written` after the
    /// identification line, returning payloads.
    fn client_payloads(written: &[u8]) -> Vec<Vec<u8>> {
        let mut rest = written;
        let ident_end = rest.iter().position(|&b| b == b'\n').unwrap() + 1;
        assert_eq!(&rest[..ident_end], b"SSH-2.0-tatami_0.1.0\r\n");
        rest = &rest[ident_end..];
        let mut payloads = Vec::new();
        while !rest.is_empty() {
            let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
            let pad = rest[4] as usize;
            payloads.push(rest[5..4 + len - pad].to_vec());
            rest = &rest[4 + len..];
        }
        payloads
    }

    /// Full server transcript up to and including NEWKEYS.
    fn server_to_newkeys(script: &Script) -> Vec<u8> {
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&script.i_s));
        wire.extend(packet(&ecdh_reply(&script.signature)));
        wire.extend(packet(&[21]));
        wire
    }

    fn server_protected(script: &Script, service: &[u8]) -> Vec<u8> {
        let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
        let mut wire = Vec::new();
        if script.ext_info {
            wire.extend(sealer.seal(&ext_info_payload()));
        }
        wire.extend(sealer.seal(&service_accept_payload(service)));
        wire
    }

    #[test]
    fn fixtures_are_self_consistent() {
        // The Python H equals an independent sha2 computation over the same
        // transcript, for every script.
        for s in [strict(), guess(), plain()] {
            assert_eq!(independent_h(&s.i_s), s.h);
        }
        // Bob's provider-side agreement with Alice's public value is K.
        assert_eq!(bob_shared_secret_with(&ALICE_PUBLIC), SHARED_K);
        // The Python signature verifies under the host key with tatami-keys.
        let k_s = k_s();
        let blob = PublicKeyBlob::decode(&k_s).unwrap();
        let key = HostKey::from_blob(&blob).unwrap();
        let mut sig_blob = string(b"ssh-ed25519");
        sig_blob.extend(string(&SIGNATURE));
        key.verify_signature_blob(&H, &SignatureBlob::decode(&sig_blob).unwrap())
            .unwrap();
        // The strict script's I_S equals the transcript fixture's I_S.
        assert_eq!(strict().i_s, i_s());
    }

    #[test]
    fn construction_queues_identification_and_kexinit_with_the_injected_cookie() {
        let mut hs = handshake(config());
        assert_eq!(hs.phase(), Phase::ServerIdentification);
        assert_eq!(hs.step(), Step::Send);
        let out = hs.take_output();
        let payloads = client_payloads(&out);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], i_c(), "I_C matches the hand-built fixture");
        assert_eq!(hs.step(), Step::NeedMore);
        let r = hs.report();
        assert_eq!(r.client_identification, V_C);
        assert_eq!(r.advertised.client.cookie, CLIENT_COOKIE);
        assert!(r.strict_kex.offered_pre_standard);
        assert!(r.strict_kex.offered_standard);
        assert!(!r.strict_kex.negotiated);
        assert_eq!(r.send_sequence, 1);
        assert!(!r.user_authenticated);
    }

    #[test]
    fn construction_failures_are_errors() {
        let bad = HandshakeConfig {
            software_version: String::from("has space"),
            ..config()
        };
        assert!(matches!(
            ClientHandshake::new(bad, &mut client_rng()),
            Err(HandshakeInitError::Identification(_))
        ));
        // 79 bytes: the padding seed draw fails.
        let mut short = QueueRng::new(&[&[0u8; 79]]);
        assert!(matches!(
            ClientHandshake::new(config(), &mut short),
            Err(HandshakeInitError::Entropy(_))
        ));
        let mut none = QueueRng::new(&[]);
        assert!(matches!(
            ClientHandshake::new(config(), &mut none),
            Err(HandshakeInitError::Entropy(_))
        ));
    }

    #[test]
    fn full_strict_handshake_completes() {
        let script = strict();
        let mut hs = handshake(config());
        hs.feed(&server_to_newkeys(&script));
        let (written, end) = drive(&mut hs, trusted());
        assert_eq!(end, None);
        assert_eq!(hs.phase(), Phase::Service);
        // Client sent: ident, KEXINIT, ECDH_INIT, NEWKEYS (unprotected), then
        // a protected SERVICE_REQUEST.
        let unprotected_len = written.len() - 52; // SERVICE_REQUEST: 4 + 32 + 16
        let payloads = client_payloads(&written[..unprotected_len]);
        assert_eq!(payloads.len(), 3);
        assert_eq!(payloads[0], i_c());
        let mut ecdh_init = alloc::vec![30u8];
        ecdh_init.extend(string(&ALICE_PUBLIC));
        assert_eq!(payloads[1], ecdh_init);
        assert_eq!(payloads[2], [21]);
        let mut opener = Sealer::new(&script.key_c, &script.iv_a);
        let (payload, total) = opener.open(&written[unprotected_len..]);
        assert_eq!(total, 52);
        let mut expected = alloc::vec![5u8];
        expected.extend(string(b"ssh-userauth"));
        assert_eq!(payload, expected);

        let r = hs.report();
        assert_eq!(r.kexinit_was_first_packet, Some(true));
        assert!(r.strict_kex.negotiated);
        assert!(r.newkeys_sent && r.newkeys_received);
        assert_eq!(r.signature_valid, Some(true));
        assert_eq!(r.trust, Some(trusted()));
        // Strict: both sequence numbers were reset at NEWKEYS.
        assert_eq!(
            r.send_sequence, 1,
            "SERVICE_REQUEST was packet 0 after reset"
        );
        assert_eq!(r.receive_sequence, 0);
        assert_eq!(r.protected_packets_sent, 1);
        assert_eq!(hs.session_id().unwrap().as_bytes(), &script.h);
        let selected = r.selected.unwrap();
        assert_eq!(selected.kex, "curve25519-sha256");
        assert_eq!(selected.host_key, "ssh-ed25519");
        assert_eq!(
            selected.encryption_client_to_server,
            "aes128-gcm@openssh.com"
        );
        assert_eq!(selected.mac_server_to_client.as_str(), "implicit (AEAD)");
        assert!(selected.ext_info);
        let hk = r.host_key.unwrap();
        assert_eq!(hk.algorithm, "ssh-ed25519");
        assert_eq!(hk.blob_len, 51);
        assert_eq!(hk.fingerprint, Sha256Fingerprint::of_blob(&k_s()));

        // Server protected: EXT_INFO then SERVICE_ACCEPT.
        hs.feed(&server_protected(&script, b"ssh-userauth"));
        let (written, end) = drive(&mut hs, trusted());
        assert_eq!(end, Some(HandshakeOutcome::Completed));
        let (payload, total) = opener.open(&written);
        assert_eq!(total, written.len());
        let mut expected = alloc::vec![1u8, 0, 0, 0, 11];
        expected.extend(string(COMPLETE_DESCRIPTION));
        expected.extend(string(b""));
        assert_eq!(payload, expected);
        let r = hs.report();
        assert_eq!(r.outcome, Some(HandshakeOutcome::Completed));
        assert_eq!(r.service_accepted.as_deref(), Some("ssh-userauth"));
        let ext = r.ext_info.unwrap();
        assert!(ext.received);
        assert_eq!(
            ext.server_sig_algs,
            Some(alloc::vec![String::from("ssh-ed25519")])
        );
        assert_eq!(ext.extension_names, ["server-sig-algs"]);
        assert_eq!(r.protected_packets_received, 2);
        assert_eq!(r.protected_packets_sent, 2);
        assert_eq!(r.receive_sequence, 2);
        assert_eq!(r.send_sequence, 2);
        assert!(r.outcome.unwrap().is_complete());
        assert!(matches!(hs.step(), Step::Finished(o) if *o == HandshakeOutcome::Completed));
        assert_eq!(hs.input_ended(), HandshakeOutcome::Completed);
    }

    #[test]
    fn byte_at_a_time_matches_all_at_once() {
        let script = strict();
        let mut wire = server_to_newkeys(&script);
        wire.extend(server_protected(&script, b"ssh-userauth"));
        let mut all = handshake(config());
        all.feed(&wire);
        let (written_all, end_all) = drive(&mut all, trusted());

        let mut one = handshake(config());
        let mut written_one = Vec::new();
        let mut end_one = None;
        for b in &wire {
            one.feed(&[*b]);
            let (w, e) = drive(&mut one, trusted());
            written_one.extend(w);
            if e.is_some() {
                end_one = e;
                break;
            }
        }
        assert_eq!(end_all, Some(HandshakeOutcome::Completed));
        assert_eq!(end_one, end_all);
        assert_eq!(written_one, written_all);
        assert_eq!(one.report(), all.report());
    }

    #[test]
    fn plain_server_without_strict_or_ext_info() {
        let script = plain();
        let mut hs = handshake(config());
        let mut wire = server_to_newkeys(&script);
        wire.extend(server_protected(&script, b"ssh-userauth"));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(end, Some(HandshakeOutcome::Completed));
        let r = hs.report();
        assert!(!r.strict_kex.negotiated);
        assert!(!r.strict_kex.server_pre_standard && !r.strict_kex.server_standard);
        assert!(!r.selected.as_ref().unwrap().ext_info);
        let ext = r.ext_info.unwrap();
        assert!(!ext.received);
        // No reset: KEXINIT 0, ECDH_INIT 1, NEWKEYS 2, SERVICE_REQUEST 3, DISCONNECT 4.
        assert_eq!(r.send_sequence, 5);
        assert_eq!(r.receive_sequence, 4);
        assert_eq!(r.protected_packets_received, 1);
    }

    #[test]
    fn server_guess_wrong_discards_one_kex_packet() {
        let script = guess();
        let mut hs = handshake(config());
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&script.i_s));
        // The server's guessed DH packet (number 31 under group14 = KEXDH_REPLY,
        // here with junk contents) must be ignored.
        wire.extend(packet(&[31, 0xde, 0xad]));
        wire.extend(packet(&ecdh_reply(&script.signature)));
        wire.extend(packet(&[21]));
        wire.extend(server_protected(&script, b"ssh-userauth"));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(end, Some(HandshakeOutcome::Completed));
        let r = hs.report();
        assert!(r.server_guess_discarded);
        assert!(r.selected.as_ref().unwrap().server_guess_wrong);
        assert!(r.strict_kex.negotiated);
        assert_eq!(hs.session_id().unwrap().as_bytes(), &script.h);
    }

    #[test]
    fn wrong_pin_stops_before_newkeys() {
        let script = strict();
        let mut hs = handshake(config());
        hs.feed(&server_to_newkeys(&script));
        let untrusted = TrustDecision::Untrusted {
            reason: UntrustedReason::FingerprintMismatch,
        };
        let (written, end) = drive(&mut hs, untrusted);
        assert_eq!(
            end,
            Some(HandshakeOutcome::HostNotTrusted {
                reason: UntrustedReason::FingerprintMismatch
            })
        );
        let payloads = client_payloads(&written);
        assert_eq!(payloads.len(), 2, "KEXINIT and ECDH_INIT only");
        assert!(payloads.iter().all(|p| p[0] != 21), "no NEWKEYS");
        let r = hs.report();
        assert!(!r.newkeys_sent);
        assert_eq!(r.signature_valid, Some(true));
        assert_eq!(r.trust, Some(untrusted));
        assert_eq!(r.outcome.as_ref().unwrap().code(), "host_not_trusted");
        // The server's NEWKEYS was buffered but never consumed.
        assert_eq!(hs.pending_bytes(), 16);
    }

    #[test]
    fn trust_decision_blocks_until_answered() {
        let script = strict();
        let mut hs = handshake(config());
        hs.feed(&server_to_newkeys(&script));
        loop {
            match hs.step() {
                Step::Send => {
                    hs.take_output();
                }
                Step::TrustDecisionRequired(id) => {
                    assert_eq!(id.algorithm, "ssh-ed25519");
                    assert_eq!(id.blob, k_s());
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(hs.phase(), Phase::TrustDecision);
        // Asked again, still waiting; nothing was sent; more input is held.
        assert!(matches!(hs.step(), Step::TrustDecisionRequired(_)));
        assert!(hs.take_output().is_empty());
        hs.feed(&server_protected(&script, b"ssh-userauth"));
        assert!(matches!(hs.step(), Step::TrustDecisionRequired(_)));
        assert!(!hs.report().newkeys_sent);
        hs.provide_trust(trusted());
        assert_eq!(hs.step(), Step::Send);
        // provide_trust outside the phase is ignored.
        hs.provide_trust(TrustDecision::Untrusted {
            reason: UntrustedReason::NoPolicy,
        });
        assert_eq!(hs.report().trust, Some(trusted()));
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(end, Some(HandshakeOutcome::Completed));
    }

    #[test]
    fn flipped_signature_byte_is_fatal() {
        let script = strict();
        for index in [0usize, 31, 63] {
            let mut hs = handshake(config());
            let mut sig = script.signature;
            sig[index] ^= 0x01;
            let mut wire = V_S.to_vec();
            wire.extend_from_slice(b"\r\n");
            wire.extend(packet(&script.i_s));
            wire.extend(packet(&ecdh_reply(&sig)));
            hs.feed(&wire);
            let (_, end) = drive(&mut hs, trusted());
            assert_eq!(
                end,
                Some(HandshakeOutcome::SignatureInvalid),
                "index {index}"
            );
            let r = hs.report();
            assert_eq!(r.signature_valid, Some(false));
            assert_eq!(
                r.signature_error.as_deref(),
                Some("signature does not verify")
            );
            assert_eq!(r.trust, None, "no trust decision was requested");
            assert!(!r.newkeys_sent);
        }
    }

    #[test]
    fn signature_algorithm_mismatch_and_malformed_blob_are_signature_invalid() {
        let script = strict();
        let reply_with_sig_blob = |sig_blob: &[u8]| {
            let mut p = alloc::vec![31u8];
            p.extend(string(&k_s()));
            p.extend(string(&BOB_PUBLIC));
            p.extend(string(sig_blob));
            p
        };
        let mut wrong_alg = string(b"rsa-sha2-256");
        wrong_alg.extend(string(&script.signature));
        let mut trailing = string(b"ssh-ed25519");
        trailing.extend(string(&script.signature));
        trailing.push(0);
        let mut short = string(b"ssh-ed25519");
        short.extend(string(&script.signature[..63]));
        for (blob, expect) in [
            (wrong_alg, "does not match key algorithm"),
            (trailing, "trailing byte"),
            (short, "expected 64"),
        ] {
            let mut hs = handshake(config());
            let mut wire = V_S.to_vec();
            wire.extend_from_slice(b"\r\n");
            wire.extend(packet(&script.i_s));
            wire.extend(packet(&reply_with_sig_blob(&blob)));
            hs.feed(&wire);
            let (_, end) = drive(&mut hs, trusted());
            assert_eq!(end, Some(HandshakeOutcome::SignatureInvalid));
            let err = hs.report().signature_error.unwrap();
            assert!(err.contains(expect), "{err}");
        }
    }

    #[test]
    fn host_key_problems_are_protocol_errors() {
        let script = strict();
        let reply_with_ks = |k_s: &[u8], q_s: &[u8]| {
            let mut p = alloc::vec![31u8];
            p.extend(string(k_s));
            p.extend(string(q_s));
            let mut sig_blob = string(b"ssh-ed25519");
            sig_blob.extend(string(&script.signature));
            p.extend(string(&sig_blob));
            p
        };
        let mut rsa = string(b"ssh-rsa");
        rsa.extend(string(&[1, 0, 1]));
        let run = |reply: Vec<u8>| {
            let mut hs = handshake(config());
            let mut wire = V_S.to_vec();
            wire.extend_from_slice(b"\r\n");
            wire.extend(packet(&script.i_s));
            wire.extend(packet(&reply));
            hs.feed(&wire);
            drive(&mut hs, trusted()).1.unwrap()
        };
        assert_eq!(
            run(reply_with_ks(&rsa, &BOB_PUBLIC)),
            HandshakeOutcome::ProtocolError(ProtocolViolation::HostKey(
                KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec())
            ))
        );
        assert!(matches!(
            run(reply_with_ks(&[0, 0, 0, 9, b'x'], &BOB_PUBLIC)),
            HandshakeOutcome::ProtocolError(ProtocolViolation::HostKey(KeyError::Blob(_)))
        ));
        assert_eq!(
            run(reply_with_ks(&k_s(), &BOB_PUBLIC[..31])),
            HandshakeOutcome::ProtocolError(ProtocolViolation::Kex(
                KexError::ServerEphemeralLength { found: 31 }
            ))
        );
        assert_eq!(
            run(reply_with_ks(&k_s(), &[0u8; 32])),
            HandshakeOutcome::ProtocolError(ProtocolViolation::Kex(KexError::AllZeroSharedSecret))
        );
        // A truncated reply names the field.
        assert!(matches!(
            run(alloc::vec![31, 0, 0, 0, 5, 1]),
            HandshakeOutcome::ProtocolError(ProtocolViolation::Message { number: 31, .. })
        ));
    }

    #[test]
    fn tampered_protected_byte_is_a_tag_mismatch() {
        let script = strict();
        let mut hs = handshake(config());
        hs.feed(&server_to_newkeys(&script));
        drive(&mut hs, trusted());
        let mut protected = server_protected(&script, b"ssh-userauth");
        protected[10] ^= 0x40;
        hs.feed(&protected);
        let (written, end) = drive(&mut hs, trusted());
        assert_eq!(end, Some(HandshakeOutcome::TagMismatch));
        assert!(written.is_empty(), "no DISCONNECT after a tag failure");
        assert_eq!(hs.report().protected_packets_received, 0);
    }

    #[test]
    fn strict_mode_rejects_ignore_before_kexinit_retroactively() {
        let script = strict();
        let mut hs = handshake(config());
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&[2, 0, 0, 0, 0])); // IGNORE
        wire.extend(packet(&script.i_s));
        hs.feed(&wire);
        let (written, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::StrictKexViolation {
                detail: String::from("KEXINIT was not the first packet received")
            })
        );
        assert_eq!(client_payloads(&written).len(), 1, "no ECDH_INIT sent");
        let r = hs.report();
        assert_eq!(r.kexinit_was_first_packet, Some(false));
        assert!(r.strict_kex.negotiated);
        assert_eq!(
            r.skipped_messages,
            [SkippedMessage::Ignored { data_len: 0 }]
        );
    }

    #[test]
    fn non_strict_mode_accepts_ignore_and_debug_before_kexinit_and_reply() {
        let script = plain();
        let mut hs = handshake(config());
        let mut wire = b"banner line\r\n".to_vec();
        wire.extend_from_slice(V_S);
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&[2, 0, 0, 0, 1, 9])); // IGNORE
        wire.extend(packet(&[4, 1, 0, 0, 0, 2, b'h', b'i', 0, 0, 0, 0])); // DEBUG
        wire.extend(packet(&script.i_s));
        wire.extend(packet(&[3, 0, 0, 0, 7])); // UNIMPLEMENTED
        wire.extend(packet(&ecdh_reply(&script.signature)));
        wire.extend(packet(&[2, 0, 0, 0, 0])); // IGNORE before NEWKEYS
        wire.extend(packet(&[21]));
        wire.extend(server_protected(&script, b"ssh-userauth"));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(end, Some(HandshakeOutcome::Completed));
        let r = hs.report();
        assert_eq!(r.kexinit_was_first_packet, Some(false));
        assert!(!r.strict_kex.negotiated);
        assert_eq!(r.server_prelude_lines, [b"banner line".to_vec()]);
        assert_eq!(r.skipped_messages.len(), 4);
        assert!(matches!(
            r.skipped_messages[1],
            SkippedMessage::Debug {
                always_display: true,
                ..
            }
        ));
        assert_eq!(
            r.skipped_messages[2],
            SkippedMessage::Unimplemented { sequence_number: 7 }
        );
    }

    #[test]
    fn strict_mode_rejects_transport_messages_during_kex() {
        let script = strict();
        for (payload, detail) in [
            (
                alloc::vec![2, 0, 0, 0, 0],
                "SSH_MSG_IGNORE (2) during the initial key exchange",
            ),
            (
                alloc::vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                "SSH_MSG_DEBUG (4) during the initial key exchange",
            ),
            (
                alloc::vec![3, 0, 0, 0, 1],
                "SSH_MSG_UNIMPLEMENTED (3) during the initial key exchange",
            ),
            (
                alloc::vec![1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0],
                "SSH_MSG_DISCONNECT (reason code 2) during the initial key exchange",
            ),
            (
                script.i_s.clone(),
                "second KEXINIT during the initial key exchange",
            ),
            (alloc::vec![21], "NEWKEYS before KEX_ECDH_REPLY"),
            (
                alloc::vec![32, 1],
                "unexpected key-exchange message 32 during the initial key exchange",
            ),
        ] {
            let mut hs = handshake(config());
            let mut wire = V_S.to_vec();
            wire.extend_from_slice(b"\r\n");
            wire.extend(packet(&script.i_s));
            wire.extend(packet(&payload));
            hs.feed(&wire);
            let (_, end) = drive(&mut hs, trusted());
            assert_eq!(
                end,
                Some(HandshakeOutcome::StrictKexViolation {
                    detail: String::from(detail)
                })
            );
        }
        // The disconnect reason is still recorded.
        let mut hs = handshake(config());
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&script.i_s));
        wire.extend(packet(&[
            1, 0, 0, 0, 3, 0, 0, 0, 3, b'b', b'y', b'e', 0, 0, 0, 0,
        ]));
        hs.feed(&wire);
        drive(&mut hs, trusted());
        assert_eq!(
            hs.report().server_disconnect,
            Some(ServerDisconnect {
                reason_code: 3,
                description: b"bye".to_vec()
            })
        );
    }

    #[test]
    fn second_ecdh_reply_is_fatal_in_strict_mode_and_unexpected_otherwise() {
        let strict_script = strict();
        let mut hs = handshake(config());
        let mut wire = server_to_newkeys(&strict_script);
        wire.truncate(wire.len() - 16); // drop NEWKEYS
        wire.extend(packet(&ecdh_reply(&strict_script.signature)));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::StrictKexViolation {
                detail: String::from("second KEX_ECDH_REPLY during the initial key exchange")
            })
        );

        let plain_script = plain();
        let mut hs = handshake(config());
        let mut wire = server_to_newkeys(&plain_script);
        wire.truncate(wire.len() - 16);
        wire.extend(packet(&ecdh_reply(&plain_script.signature)));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::UnexpectedMessage {
                number: 31,
                phase: Phase::ServerNewKeys
            })
        );
    }

    #[test]
    fn disconnect_before_kexinit_and_after_newkeys_is_reported() {
        let mut hs = handshake(config());
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&[
            1, 0, 0, 0, 2, 0, 0, 0, 3, b'b', b'y', b'e', 0, 0, 0, 0,
        ]));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::ServerDisconnected {
                reason_code: 2,
                description: b"bye".to_vec()
            })
        );

        let script = strict();
        let mut hs = handshake(config());
        hs.feed(&server_to_newkeys(&script));
        drive(&mut hs, trusted());
        let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
        let mut disconnect = alloc::vec![1u8, 0, 0, 0, 11];
        disconnect.extend(string(b"nope"));
        disconnect.extend(string(b""));
        hs.feed(&sealer.seal(&disconnect));
        let (written, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::ServerDisconnected {
                reason_code: 11,
                description: b"nope".to_vec()
            })
        );
        assert!(written.is_empty());
    }

    #[test]
    fn rekey_request_after_newkeys_sends_disconnect() {
        let script = strict();
        let mut hs = handshake(config());
        hs.feed(&server_to_newkeys(&script));
        let (mut written, _) = drive(&mut hs, trusted());
        let unprotected_len = written.len() - 52;
        let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
        hs.feed(&sealer.seal(&script.i_s));
        let (more, end) = drive(&mut hs, trusted());
        written.extend(more);
        assert_eq!(end, Some(HandshakeOutcome::RekeyNotSupported));
        let protected = &written[unprotected_len..];
        let mut opener = Sealer::new(&script.key_c, &script.iv_a);
        let (_, n) = opener.open(protected); // SERVICE_REQUEST
        let (payload, _) = opener.open(&protected[n..]);
        assert_eq!(payload[0], 1);
        assert_eq!(&payload[1..5], &[0, 0, 0, 11]);
        assert_eq!(&payload[9..9 + REKEY_DESCRIPTION.len()], REKEY_DESCRIPTION);
        assert_eq!(hs.report().protected_packets_sent, 2);
    }

    #[test]
    fn protected_phase_message_rules() {
        let script = strict();
        let run = |packets: &[Vec<u8>]| {
            let mut hs = handshake(config());
            hs.feed(&server_to_newkeys(&script));
            drive(&mut hs, trusted());
            let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
            for p in packets {
                hs.feed(&sealer.seal(p));
            }
            let (_, end) = drive(&mut hs, trusted());
            (end, hs.report())
        };
        // IGNORE and DEBUG are accepted and counted; EXT_INFO is only valid
        // first.
        let (end, r) = run(&[
            alloc::vec![2, 0, 0, 0, 0],
            alloc::vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            service_accept_payload(b"ssh-userauth"),
        ]);
        assert_eq!(end, Some(HandshakeOutcome::Completed));
        assert_eq!(r.skipped_messages.len(), 2);
        assert!(!r.ext_info.unwrap().received);
        let (end, _) = run(&[alloc::vec![2, 0, 0, 0, 0], ext_info_payload()]);
        assert_eq!(
            end,
            Some(HandshakeOutcome::UnexpectedMessage {
                number: 7,
                phase: Phase::Service
            })
        );
        let (end, _) = run(&[ext_info_payload(), ext_info_payload()]);
        assert_eq!(
            end,
            Some(HandshakeOutcome::UnexpectedMessage {
                number: 7,
                phase: Phase::Service
            })
        );
        // UNIMPLEMENTED and anything else are unexpected here.
        let (end, _) = run(&[alloc::vec![3, 0, 0, 0, 0]]);
        assert_eq!(
            end,
            Some(HandshakeOutcome::UnexpectedMessage {
                number: 3,
                phase: Phase::Service
            })
        );
        let (end, _) = run(&[alloc::vec![51, 0, 0, 0, 0, 0]]);
        assert!(matches!(
            end,
            Some(HandshakeOutcome::UnexpectedMessage { number: 51, .. })
        ));
        // Service mismatch.
        let (end, r) = run(&[service_accept_payload(b"ssh-connection")]);
        assert_eq!(
            end,
            Some(HandshakeOutcome::ProtocolError(
                ProtocolViolation::ServiceMismatch {
                    requested: b"ssh-userauth".to_vec(),
                    accepted: b"ssh-connection".to_vec(),
                }
            ))
        );
        assert_eq!(r.service_accepted, None);
        // Empty payload (padding_length consumes everything but one byte is
        // impossible; simulate with a sealed zero-length payload).
        let (end, _) = run(&[Vec::new()]);
        assert_eq!(
            end,
            Some(HandshakeOutcome::ProtocolError(
                ProtocolViolation::EmptyPayload
            ))
        );
        // Unknown extensions are preserved by name; server-sig-algs parsed.
        let mut ext = alloc::vec![7, 0, 0, 0, 3];
        ext.extend(string(b"publickey-hostbound@openssh.com"));
        ext.extend(string(b"0"));
        ext.extend(string(b"server-sig-algs"));
        ext.extend(string(b"ssh-ed25519,rsa-sha2-512"));
        ext.extend(string(b"ping@openssh.com"));
        ext.extend(string(b"\x00\x01"));
        let (end, r) = run(&[ext, service_accept_payload(b"ssh-userauth")]);
        assert_eq!(end, Some(HandshakeOutcome::Completed));
        let info = r.ext_info.unwrap();
        assert_eq!(
            info.extension_names,
            [
                "publickey-hostbound@openssh.com",
                "server-sig-algs",
                "ping@openssh.com"
            ]
        );
        assert_eq!(
            info.server_sig_algs.unwrap(),
            ["ssh-ed25519", "rsa-sha2-512"]
        );
        // Too many extensions.
        let mut cfg = config();
        cfg.max_ext_info_extensions = 2;
        let mut hs = ClientHandshake::new(cfg, &mut client_rng()).unwrap();
        hs.feed(&server_to_newkeys(&script));
        drive(&mut hs, trusted());
        let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
        let mut ext = alloc::vec![7, 0, 0, 0, 3];
        for _ in 0..3 {
            ext.extend(string(b"a"));
            ext.extend(string(b""));
        }
        hs.feed(&sealer.seal(&ext));
        let (_, end) = drive(&mut hs, trusted());
        assert!(matches!(
            end,
            Some(HandshakeOutcome::ProtocolError(ProtocolViolation::ExtInfo(
                ExtInfoError::TooManyExtensions { claimed: 3, max: 2 }
            )))
        ));
    }

    #[test]
    fn protected_packet_budget() {
        let script = strict();
        let mut cfg = config();
        cfg.max_protected_packets = 2;
        let mut hs = ClientHandshake::new(cfg, &mut client_rng()).unwrap();
        hs.feed(&server_to_newkeys(&script));
        drive(&mut hs, trusted());
        let mut sealer = Sealer::new(&script.key_d, &script.iv_b);
        for _ in 0..3 {
            hs.feed(&sealer.seal(&[2, 0, 0, 0, 0]));
        }
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::Limit(LimitKind::ProtectedPackets {
                limit: 2
            }))
        );
    }

    #[test]
    fn pre_kex_budgets_and_framing_errors() {
        let script = plain();
        let mut cfg = config();
        cfg.max_pre_kex_packets = 2;
        let mut hs = ClientHandshake::new(cfg, &mut client_rng()).unwrap();
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&[2, 0, 0, 0, 0]));
        wire.extend(packet(&[2, 0, 0, 0, 0]));
        wire.extend(packet(&script.i_s));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::Limit(LimitKind::PreKexPackets {
                limit: 2
            }))
        );

        let mut cfg = config();
        cfg.max_pre_kex_bytes = 20;
        let mut hs = ClientHandshake::new(cfg, &mut client_rng()).unwrap();
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        wire.extend(packet(&script.i_s));
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::Limit(LimitKind::PreKexBytes {
                limit: 20
            }))
        );

        // Oversized claim rejected from the header.
        let mut hs = handshake(config());
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n\xff\xff\xff\xff");
        hs.feed(&wire);
        let (_, end) = drive(&mut hs, trusted());
        assert!(matches!(
            end,
            Some(HandshakeOutcome::ProtocolError(ProtocolViolation::Packet(
                PacketError::TooLarge { .. }
            )))
        ));

        // Unsupported version.
        let mut hs = handshake(config());
        hs.feed(b"SSH-1.5-old\r\n");
        let (_, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::ProtocolError(ProtocolViolation::Ident(
                IdentError::UnsupportedVersion
            )))
        );

        // Negotiation failure.
        let mut hs = handshake(config());
        let mut wire = V_S.to_vec();
        wire.extend_from_slice(b"\r\n");
        // The plain server's KEXINIT with the c2s cipher replaced by
        // `aes256-ctr`.
        let mut i_s = script.i_s[..17].to_vec();
        for list in [
            &b"curve25519-sha256"[..],
            b"ssh-ed25519",
            b"aes256-ctr",
            b"aes128-gcm@openssh.com",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ] {
            i_s.extend(string(list));
        }
        i_s.extend_from_slice(&[0, 0, 0, 0, 0]);
        wire.extend(packet(&i_s));
        hs.feed(&wire);
        let (written, end) = drive(&mut hs, trusted());
        assert_eq!(
            end,
            Some(HandshakeOutcome::NegotiationFailed(
                NegotiationError::NoCommonCipher(crate::negotiate::Direction::ClientToServer)
            ))
        );
        assert_eq!(client_payloads(&written).len(), 1);
        assert!(hs.report().advertised.server.is_some());
    }

    #[test]
    fn eof_and_overflow() {
        let mut hs = handshake(config());
        hs.feed(b"SSH-2.0-x\r\n");
        drive(&mut hs, trusted());
        assert_eq!(
            hs.input_ended(),
            HandshakeOutcome::Eof {
                phase: Phase::ServerKexInit
            }
        );
        assert_eq!(hs.phase(), Phase::Finished);

        let mut hs = handshake(config());
        let room = hs.room();
        let too_much = alloc::vec![0u8; room + 1];
        hs.feed(&too_much);
        assert_eq!(hs.pending_bytes(), 0, "nothing copied on overflow");
        // The outcome is terminal immediately; the queued output is dropped.
        assert!(matches!(hs.step(), Step::Finished(o) if o.code() == "input_overflow"));
        assert_eq!(
            hs.input_ended(),
            HandshakeOutcome::InputOverflow(InputOverflow {
                capacity: room,
                pending: 0,
                offered: room + 1,
            })
        );
        // Exactly `room` bytes are accepted.
        let mut hs = handshake(config());
        let room = hs.room();
        hs.feed(&alloc::vec![b'x'; room]);
        assert_eq!(hs.room(), 0);
        assert_eq!(hs.pending_bytes(), room);
    }

    #[test]
    fn outcome_codes_are_stable() {
        let cases: [(HandshakeOutcome, &str); 13] = [
            (HandshakeOutcome::Completed, "completed"),
            (
                HandshakeOutcome::HostNotTrusted {
                    reason: UntrustedReason::NoPolicy,
                },
                "host_not_trusted",
            ),
            (HandshakeOutcome::SignatureInvalid, "signature_invalid"),
            (
                HandshakeOutcome::NegotiationFailed(NegotiationError::NoCommonKex),
                "negotiation_failed",
            ),
            (
                HandshakeOutcome::StrictKexViolation {
                    detail: String::new(),
                },
                "strict_kex_violation",
            ),
            (
                HandshakeOutcome::ProtocolError(ProtocolViolation::EmptyPayload),
                "protocol_error",
            ),
            (
                HandshakeOutcome::ServerDisconnected {
                    reason_code: 1,
                    description: Vec::new(),
                },
                "server_disconnected",
            ),
            (HandshakeOutcome::RekeyNotSupported, "rekey_not_supported"),
            (
                HandshakeOutcome::UnexpectedMessage {
                    number: 9,
                    phase: Phase::Service,
                },
                "unexpected_message",
            ),
            (HandshakeOutcome::TagMismatch, "tag_mismatch"),
            (
                HandshakeOutcome::Eof {
                    phase: Phase::ServerKexInit,
                },
                "eof",
            ),
            (
                HandshakeOutcome::InputOverflow(InputOverflow {
                    capacity: 1,
                    pending: 0,
                    offered: 2,
                }),
                "input_overflow",
            ),
            (
                HandshakeOutcome::Limit(LimitKind::PreKexPackets { limit: 1 }),
                "limit",
            ),
        ];
        for (outcome, code) in cases {
            assert_eq!(outcome.code(), code);
            let _ = alloc::format!("{outcome}");
        }
        assert_eq!(Phase::TrustDecision.code(), "trust_decision");
        assert_eq!(
            alloc::format!("{}", Phase::Service),
            "awaiting SERVICE_ACCEPT"
        );
    }

    #[test]
    fn padding_source_is_deterministic_and_not_constant() {
        let mut a = PaddingSource::new([1; 32]);
        let mut b = PaddingSource::new([1; 32]);
        let mut x = [0u8; 70];
        let mut y = [0u8; 70];
        a.fill_bytes(&mut x);
        b.fill_bytes(&mut y[..30]);
        b.fill_bytes(&mut y[30..]);
        assert_eq!(x, y);
        assert!(x.iter().any(|&v| v != x[0]));
        let mut c = PaddingSource::new([2; 32]);
        let mut z = [0u8; 70];
        c.fill_bytes(&mut z);
        assert_ne!(x, z);
    }

    #[test]
    fn debug_output_of_the_state_machine_has_no_secret() {
        let script = strict();
        let mut hs = handshake(config());
        hs.feed(&server_to_newkeys(&script));
        drive(&mut hs, trusted());
        let s = alloc::format!("{hs:?}");
        assert!(s.starts_with("ClientHandshake { phase: Service"), "{s}");
        let report = alloc::format!("{:?}", hs.report());
        for secret in [
            alloc::format!("{:02x?}", &SHARED_K[..4]),
            alloc::format!("{:02x?}", &script.key_c[..4]),
            alloc::format!("{:02x?}", &ALICE_SECRET[..4]),
        ] {
            assert!(!report.contains(&secret));
        }
    }
}
