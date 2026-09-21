#![no_main]
//! `tatami::client::handshake::Report::{to_json, write_text}` on reports
//! assembled from their public fields.
//!
//! # Input layout
//!
//! ```text
//! byte 0     completion selector (17 variants incl. host-side ends)
//! byte 1     bit 0: attach a `HandshakeReport`; bit 1: peer/local present;
//!            bit 2: elapsed present; bit 3: signal EOF to the state machine
//! u16        port
//! 32 bytes   pin digest
//! u8 + bytes host name (len mod 40, lossy text)
//! rest       server bytes fed to a `ClientHandshake` (no crypto is reached
//!            with random bytes; identification, prelude, KEXINIT decoding
//!            and negotiation failures are) whose `report()` is attached
//! ```
//!
//! # Oracles
//!
//! - `to_json().to_json()` parses with `serde_json` into an object whose
//!   keys, at every nesting level, come from the closed set documented in
//!   the module (no key material can appear under any name); the record has
//!   a fixed shape: every top-level key is present and an unknown datum is
//!   `null`, never absent and never guessed (`phase`/`advertised`/
//!   `strict_kex` non-null iff a handshake report is attached, `selected`
//!   iff negotiation succeeded, `host_trusted` iff a trust decision,
//!   `negotiation_error_code` iff `NegotiationFailed`, `elapsed_ms` iff
//!   elapsed, `peer`/`local` iff connected).
//! - `schema == 1`, `event == "tcp_handshake"`, `user_authenticated == false`,
//!   `rekey_supported == false`, `outcome_code == completion.code()` from
//!   the closed 17-string set, `negotiation_error_code` from the closed
//!   six-string set, `phase` from the closed seven-string set, `target`
//!   echoes host/port, `pinned_fingerprint_sha256` is `SHA256:` + 43
//!   unpadded base64 characters equal to `pin.to_string()`,
//!   `key_exchange_completed == newkeys_sent && newkeys_received`, counters
//!   echo the report, `host_key.fingerprint_sha256 == fingerprint_sha256`.
//! - `write_text` succeeds, contains `user_authenticated: false`,
//!   `Rekeying: not supported by this diagnostic` and `(code: <outcome_code>)`,
//!   and contains no raw control character other than `\n`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use serde_json::Value as J;
use tatami::client::handshake::{Completion, Report};
use tatami_fuzz_protocol::kex_support::base64;
use tatami_fuzz_protocol::kex_support::crypto::HarnessRng;
use tatami_fuzz_protocol::kex_support::negotiate_ref;
use tatami_fuzz_protocol::tcp_support::Cursor;
use tatami_keys::fingerprint::Sha256Fingerprint;
use tatami_keys::trust::UntrustedReason;
use tatami_tcp::handshake::{
    ClientHandshake, HandshakeConfig, HandshakeOutcome, HandshakeReport, LimitKind, Phase,
    ProtocolViolation, Step,
};
use tatami_tcp::initial::InputOverflow;
use tatami_tcp::io::ConnectError;
use tatami_tcp::negotiate::{Direction, NegotiationError};

const OUTCOME_CODES: [&str; 17] = [
    "completed",
    "host_not_trusted",
    "signature_invalid",
    "negotiation_failed",
    "strict_kex_violation",
    "protocol_error",
    "server_disconnected",
    "rekey_not_supported",
    "unexpected_message",
    "tag_mismatch",
    "eof",
    "input_overflow",
    "limit",
    "timed_out",
    "io_error",
    "connect_failed",
    "not_started",
];

const PHASE_CODES: [&str; 7] = [
    "server_identification",
    "server_kexinit",
    "kex_ecdh_reply",
    "trust_decision",
    "server_newkeys",
    "service",
    "finished",
];

/// Every object key the record may contain, at any level.
const ALLOWED_KEYS: &[&str] = &[
    // top level
    "schema",
    "event",
    "target",
    "peer",
    "local",
    "pinned_fingerprint_sha256",
    "phase",
    "client_identification",
    "server_prelude_lines",
    "server_identification",
    "skipped_messages",
    "advertised",
    "selected",
    "strict_kex",
    "kexinit_was_first_packet",
    "server_guess_discarded",
    "host_key",
    "fingerprint_sha256",
    "host_key_signature_valid",
    "signature_error",
    "trust_policy",
    "host_trusted",
    "trust_source",
    "untrusted_reason",
    "key_exchange_completed",
    "newkeys_sent",
    "newkeys_received",
    "protected_packets_sent",
    "protected_packets_received",
    "ext_info",
    "service_accepted",
    "server_disconnect",
    "outcome",
    "outcome_code",
    "negotiation_error_code",
    "user_authenticated",
    "rekey_supported",
    "elapsed_ms",
    // target
    "host",
    "port",
    // bytes records / identification
    "text",
    "hex",
    "line",
    "protocol_version",
    "software_version",
    "comments",
    "comments_hex",
    "anomalies",
    // skipped messages
    "type",
    "data_len",
    "always_display",
    "message",
    "message_hex",
    "language_tag",
    "sequence_number",
    // kexinit records
    "client",
    "server",
    "cookie_hex",
    "kex_algorithms",
    "kex_markers",
    "server_host_key_algorithms",
    "encryption_client_to_server",
    "encryption_server_to_client",
    "mac_client_to_server",
    "mac_server_to_client",
    "compression_client_to_server",
    "compression_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
    "first_kex_packet_follows",
    "reserved",
    // selected
    "kex",
    "server_guess_wrong",
    // strict_kex
    "offered_pre_standard",
    "offered_standard",
    "server_pre_standard",
    "server_standard",
    "negotiated",
    // host_key
    "algorithm",
    "blob_len",
    // ext_info
    "received",
    "server_sig_algs",
    "extension_names",
    // server_disconnect
    "reason_code",
    "reason_name",
    "description",
    "description_hex",
];

/// Keys that are `null` when the datum is unknown (the record is a fixed
/// shape).
const OPTIONAL_KEYS: [&str; 21] = [
    "peer",
    "local",
    "phase",
    "client_identification",
    "server_identification",
    "advertised",
    "selected",
    "strict_kex",
    "kexinit_was_first_packet",
    "host_key",
    "fingerprint_sha256",
    "host_key_signature_valid",
    "signature_error",
    "host_trusted",
    "trust_source",
    "untrusted_reason",
    "ext_info",
    "service_accepted",
    "server_disconnect",
    "negotiation_error_code",
    "elapsed_ms",
];

const ALWAYS_PRESENT: [&str; 17] = [
    "schema",
    "event",
    "target",
    "pinned_fingerprint_sha256",
    "server_prelude_lines",
    "skipped_messages",
    "server_guess_discarded",
    "trust_policy",
    "key_exchange_completed",
    "newkeys_sent",
    "newkeys_received",
    "protected_packets_sent",
    "protected_packets_received",
    "outcome",
    "outcome_code",
    "user_authenticated",
    "rekey_supported",
];

fn io_error(sel: u8) -> std::io::Error {
    let kind = match sel % 4 {
        0 => std::io::ErrorKind::ConnectionReset,
        1 => std::io::ErrorKind::TimedOut,
        2 => std::io::ErrorKind::BrokenPipe,
        _ => std::io::ErrorKind::Other,
    };
    // OS error text is not peer data and is printed as is; keep it plain.
    std::io::Error::new(kind, "harness error text")
}

fn completion(sel: u8, phase: Phase, addr: SocketAddr) -> Completion {
    match sel % 17 {
        0 => Completion::Complete,
        1 => Completion::HostNotTrusted {
            reason: if sel & 0x80 != 0 {
                UntrustedReason::FingerprintMismatch
            } else {
                UntrustedReason::NoPolicy
            },
        },
        2 => Completion::SignatureInvalid,
        3 => Completion::NegotiationFailed(match (sel >> 5) % 6 {
            0 => NegotiationError::NoCommonKex,
            1 => NegotiationError::NoCommonHostKey,
            2 => NegotiationError::NoCommonCipher(Direction::ClientToServer),
            3 => NegotiationError::NoMacImplemented(Direction::ServerToClient),
            4 => NegotiationError::NoCommonCompression(Direction::ClientToServer),
            _ => NegotiationError::UnsupportedSelection {
                field: "kex_algorithms",
                name: String::from("x\"y"),
            },
        }),
        4 => Completion::StrictKexViolation {
            detail: String::from("detail \"quoted\" \u{1}"),
        },
        5 => Completion::ProtocolError(ProtocolViolation::EmptyPayload),
        6 => Completion::ServerDisconnected {
            reason_code: u32::from(sel) % 20,
            description: b"bye \xff\x00\"".to_vec(),
        },
        7 => Completion::RekeyNotSupported,
        8 => Completion::UnexpectedMessage { number: sel, phase },
        9 => Completion::TagMismatch,
        10 => Completion::Eof { phase },
        11 => Completion::InputOverflow(InputOverflow {
            capacity: 10,
            pending: 3,
            offered: 8,
        }),
        12 => Completion::Limit(LimitKind::ProtectedPackets { limit: 64 }),
        13 => Completion::TimedOut {
            phase,
            pending_bytes: usize::from(sel),
        },
        14 => Completion::Io {
            phase,
            error: io_error(sel),
        },
        15 => Completion::ConnectFailed(match (sel >> 5) % 4 {
            0 => ConnectError::NoAddresses,
            1 => ConnectError::Resolve(io_error(sel)),
            2 => ConnectError::AllAttemptsFailed(vec![(addr, io_error(sel))]),
            _ => ConnectError::TimedOut(vec![(addr, io_error(sel)), (addr, io_error(sel >> 1))]),
        }),
        _ => Completion::NotStarted(io_error(sel)),
    }
}

/// Feeds fuzz bytes to a fresh handshake and returns its report.
fn handshake_report(server_bytes: &[u8], eof: bool) -> HandshakeReport {
    let config = HandshakeConfig {
        software_version: String::from("tatami_0.1.0"),
        ..HandshakeConfig::default()
    };
    let mut rng = HarnessRng::new(0x5eed);
    let mut hs = ClientHandshake::new(config, &mut rng).expect("valid config");
    let mut fed = 0;
    while fed < server_bytes.len() {
        let room = hs.room();
        if room == 0 {
            break;
        }
        let n = room.min(server_bytes.len() - fed).min(97);
        hs.feed(&server_bytes[fed..fed + n]);
        fed += n;
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 1024, "livelock");
            match hs.step() {
                Step::NeedMore => break,
                Step::Send => {
                    hs.take_output();
                }
                Step::TrustDecisionRequired(_) => {
                    unreachable!("random bytes cannot produce a verified signature")
                }
                Step::Finished(_) => break,
            }
        }
        if matches!(hs.step(), Step::Finished(_)) {
            break;
        }
    }
    if eof {
        hs.input_ended();
    }
    hs.report()
}

fn walk_keys(v: &J, path: &str) {
    match v {
        J::Object(map) => {
            for (k, child) in map {
                assert!(
                    ALLOWED_KEYS.contains(&k.as_str()),
                    "unexpected key {k:?} at {path}"
                );
                walk_keys(child, &format!("{path}/{k}"));
            }
        }
        J::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                walk_keys(child, &format!("{path}[{i}]"));
            }
        }
        _ => {}
    }
}

fn check_fingerprint_text(s: &str, pin: &Sha256Fingerprint) {
    assert_eq!(s, pin.to_string());
    let body = s.strip_prefix("SHA256:").expect("prefix");
    assert_eq!(body.len(), 43);
    assert_eq!(body, base64::encode_unpadded(pin.as_bytes()));
    assert!(!body.contains('='));
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let sel = cur.u8();
    let flags = cur.u8();
    let port = cur.u16();
    let digest: [u8; 32] = cur.take_filled(32, 11).try_into().expect("32");
    let pin = Sha256Fingerprint::from_bytes(digest);
    // The host is operator input (printed verbatim in the text form), so
    // it is kept to host-name characters; IPv6 literals exercise the
    // bracket rule.
    let host_len = usize::from(cur.u8()) % 40;
    let host: String = cur
        .take(host_len)
        .iter()
        .map(|&b| match b % 40 {
            0..=25 => (b'a' + b % 26) as char,
            26..=35 => (b'0' + b % 10) as char,
            36 => '.',
            37 => '-',
            38 => ':',
            _ => 'é',
        })
        .collect();
    let server_bytes = cur.rest();

    let handshake = if flags & 1 != 0 {
        Some(handshake_report(server_bytes, flags & 8 != 0))
    } else {
        None
    };
    let phase = handshake
        .as_ref()
        .map_or(Phase::ServerIdentification, |h| h.phase);
    let addr: SocketAddr = if sel & 1 == 0 {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, sel), port))
    } else {
        SocketAddr::from((Ipv6Addr::LOCALHOST, port))
    };
    let completion = completion(sel, phase, addr);
    let connected = flags & 2 != 0;
    let report = Report {
        host: host.clone(),
        port,
        pin,
        peer: connected.then_some(addr),
        local: connected.then_some(SocketAddr::from((
            Ipv4Addr::LOCALHOST,
            40000 + u16::from(sel),
        ))),
        handshake,
        completion,
        elapsed: (flags & 4 != 0).then_some(Duration::from_millis(u64::from(port) * 7)),
    };

    // JSON.
    let text = report.to_json().to_json();
    let json: J = serde_json::from_str(&text).expect("to_json output must parse");
    let obj = json.as_object().expect("a JSON object");
    walk_keys(&json, "");
    for k in ALWAYS_PRESENT {
        assert!(obj.contains_key(k), "missing always-present key {k}");
    }
    assert_eq!(json["schema"], J::from(1));
    assert_eq!(json["event"], "tcp_handshake");
    assert_eq!(json["target"]["host"], J::String(host.clone()));
    assert_eq!(json["target"]["port"], J::from(u64::from(port)));
    assert_eq!(json["user_authenticated"], J::Bool(false));
    assert_eq!(json["rekey_supported"], J::Bool(false));
    assert_eq!(json["trust_policy"], "pinned_fingerprint");
    let code = json["outcome_code"]
        .as_str()
        .expect("outcome_code is a string");
    assert_eq!(code, report.completion.code());
    assert!(OUTCOME_CODES.contains(&code), "unknown outcome code {code}");
    assert_eq!(report.is_complete(), code == "completed");
    assert_eq!(report.completion.is_complete(), report.is_complete());
    assert!(json["outcome"].as_str().is_some_and(|s| !s.is_empty()));
    check_fingerprint_text(
        json["pinned_fingerprint_sha256"].as_str().expect("string"),
        &pin,
    );
    // Optional data is `null`, never absent and never guessed.
    for k in OPTIONAL_KEYS {
        assert!(
            obj.contains_key(k),
            "optional key {k} must be present (null when unknown)"
        );
    }
    assert_eq!(json["peer"].is_null(), !connected);
    assert_eq!(json["local"].is_null(), !connected);
    if connected {
        assert_eq!(json["peer"], J::String(addr.to_string()));
    }
    assert_eq!(json["elapsed_ms"].is_null(), flags & 4 == 0);
    if flags & 4 != 0 {
        assert_eq!(json["elapsed_ms"], J::from(u64::from(port) * 7));
    }
    match &report.completion {
        Completion::NegotiationFailed(e) => {
            let c = json["negotiation_error_code"].as_str().expect("string");
            assert_eq!(c, e.code());
            assert!(negotiate_ref::ERROR_CODES.contains(&c));
        }
        _ => assert!(json["negotiation_error_code"].is_null()),
    }
    match &report.handshake {
        None => {
            for k in [
                "phase",
                "client_identification",
                "server_identification",
                "advertised",
                "selected",
                "strict_kex",
                "kexinit_was_first_packet",
                "host_key",
                "fingerprint_sha256",
                "host_key_signature_valid",
                "signature_error",
                "host_trusted",
                "trust_source",
                "untrusted_reason",
                "ext_info",
                "service_accepted",
                "server_disconnect",
            ] {
                assert!(
                    json[k].is_null(),
                    "{k} without a handshake report must be null"
                );
            }
            assert_eq!(json["server_prelude_lines"], J::Array(Vec::new()));
            assert_eq!(json["skipped_messages"], J::Array(Vec::new()));
            assert_eq!(json["key_exchange_completed"], J::Bool(false));
            assert_eq!(json["protected_packets_sent"], J::from(0));
        }
        Some(h) => {
            let phase = json["phase"].as_str().expect("phase string");
            assert!(PHASE_CODES.contains(&phase), "phase {phase}");
            assert_eq!(phase, h.phase.code());
            assert!(json["advertised"].is_object());
            assert!(json["advertised"]["client"].is_object());
            assert_eq!(
                json["advertised"]["server"].is_null(),
                h.advertised.server.is_none()
            );
            assert!(json["strict_kex"].is_object());
            assert_eq!(json["selected"].is_null(), h.selected.is_none());
            assert_eq!(json["host_trusted"].is_null(), h.trust.is_none());
            assert_eq!(json["host_key"].is_null(), h.host_key.is_none());
            assert_eq!(json["fingerprint_sha256"].is_null(), h.host_key.is_none());
            assert_eq!(
                json["server_identification"].is_null(),
                h.server_identification.is_none()
            );
            assert_eq!(json["ext_info"].is_null(), h.ext_info.is_none());
            assert_eq!(
                json["kexinit_was_first_packet"].is_null(),
                h.kexinit_was_first_packet.is_none()
            );
            assert_eq!(
                json["key_exchange_completed"],
                J::Bool(h.newkeys_sent && h.newkeys_received)
            );
            assert_eq!(json["newkeys_sent"], J::Bool(h.newkeys_sent));
            assert_eq!(json["newkeys_received"], J::Bool(h.newkeys_received));
            assert_eq!(
                json["protected_packets_sent"],
                J::from(u64::from(h.protected_packets_sent))
            );
            assert_eq!(
                json["protected_packets_received"],
                J::from(u64::from(h.protected_packets_received))
            );
            assert_eq!(
                json["server_prelude_lines"]
                    .as_array()
                    .expect("array")
                    .len(),
                h.server_prelude_lines.len()
            );
            assert_eq!(
                json["skipped_messages"].as_array().expect("array").len(),
                h.skipped_messages.len()
            );
            assert_eq!(
                json["server_guess_discarded"],
                J::Bool(h.server_guess_discarded)
            );
            assert!(!h.user_authenticated);
            if let Some(hk) = &h.host_key {
                assert_eq!(
                    json["host_key"]["fingerprint_sha256"],
                    json["fingerprint_sha256"]
                );
                assert_eq!(json["host_key"]["blob_len"], J::from(hk.blob_len as u64));
            }
            // Random server bytes never produce key material in the report.
            assert!(h.signature_valid.is_none() || h.signature_valid == Some(false));
            assert!(!h.newkeys_sent);
            if let Some(o) = &h.outcome {
                assert!(!matches!(o, HandshakeOutcome::Completed));
            }
        }
    }

    // Text.
    let mut out = String::new();
    report
        .write_text(&mut out)
        .expect("write_text into a String");
    assert!(out.contains("user_authenticated: false"));
    assert!(out.contains("Rekeying: not supported by this diagnostic"));
    assert!(
        out.contains(&format!("(code: {code})")),
        "text lacks the outcome code"
    );
    assert!(
        !out.chars().any(|c| c.is_control() && c != '\n'),
        "text output leaks a control character"
    );
    assert!(out.ends_with('\n'));
});
