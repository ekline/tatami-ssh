#![no_main]
//! `tatami::server::observe::Encoder` on constructed `ListenerEvent`s whose
//! untrusted fields are mutated, checked against `serde_json`, an
//! independent RFC 3339 formatter, closed code sets and a derived size bound
//! (`state_support::record_ref`).
//!
//! # Input layout
//!
//! ```text
//! byte 0   event: 0 Started, 1 Overload, 2 Stopped, otherwise Observation
//! byte 1   low nibble: max_record_bytes  0:0 1:1 2:64 3:256 4:1024 5:2048
//!            6:4096 7:65536 8:262144 9: explicit u32 mod 300001, else 262144
//!          high nibble: max_field_bytes  0:0 1:1 2:8 3:512 4: explicit u16
//!            mod 4097, else 512
//! then     the event's fields in declaration order, each read with:
//!   num    selector byte: 0:0 1:1 2:u32::MAX 3:u64::MAX 4:i64::MAX
//!            5: explicit u64 (8 bytes) else: the selector value itself
//!   dur    secs = num, nanos = u32 mod 1e9
//!   addr   selector byte (bit 0 IPv6, bit 1 IPv6 scope id from u32),
//!            port u16, then 4 or 16 address bytes
//!   bytes  len u16: bits 0-14 mod (max+1) give the length; bit 15 set:
//!            deterministic filler of that length (consumes no input),
//!            otherwise the next len input bytes (fewer at end of input)
//!   text   bytes -> String::from_utf8_lossy
//!
//! Started      addr
//! Overload     num dropped_since_last, num total_dropped
//! Stopped      addr, 4 x num counters, num workers, byte reason (mod 5),
//!              byte has_error (+ bytes<=256), dur elapsed
//! Observation  num id, addr local, addr peer, dur accepted, dur elapsed,
//!              num bytes_read, num bytes_written,
//!              server identification: byte 0 -> canonical, else bytes<=255,
//!              client identification: byte sel; sel%4: 0 none, 1 canonical,
//!                else mutated {line bytes<=2000, terminator sel&4,
//!                protocol_version text<=64, software_version text<=64,
//!                comments (sel&8) bytes<=2000, support sel&16},
//!              messages: byte n (mod 17) x [byte k: k%3 0 ignore{num},
//!                1 debug{k&4, message bytes<=2000, tag bytes<=2000},
//!                2 unimplemented{u32}],
//!              proposal: byte (0 -> none) else cookie 16 bytes, 10 name
//!                lists [byte n mod 9 x (byte sel: >= 0xC0 text<=64 else
//!                table[sel])], byte first_kex, u32 reserved, byte n_anom
//!                (mod 5) x [byte kind: odd -> NonzeroReserved(u32) else
//!                EmptyAlgorithmList(table)], u16 payload_len (mod 2001),
//!                num unexamined,
//!              byte stage (mod 3),
//!              byte end (mod 10): 0 banner_only, 1 proposal (a second
//!                generated proposal), 2/9 disconnected {u32 code (9: byte
//!                mod 16), description bytes<=2000, tag bytes<=2000},
//!                3 unexpected_input {sample bytes<=2000, byte truncated},
//!                4 eof {byte stage, num pending}, 5 error {byte variant
//!                (mod 17) + its numbers}, 6 timed_out, 7 shutdown,
//!                8 io {byte kind (mod 8), message bytes<=64}
//! ```
//!
//! # Oracles
//!
//! - `encode(..).to_json()` always parses with `serde_json` as an object;
//!   `schema == 1`; `event` names the variant; `time` has RFC 3339 shape;
//!   top-level keys appear in the documented order.
//! - Observations: `transport`, addresses, `id`, counters and `elapsed_ms`
//!   are exact; `accepted_at` equals an independent Fliegel–Van Flandern
//!   RFC 3339 formatter; `key_exchange_completed` and `peer_authenticated`
//!   are `false`; `stage`/`outcome`/`reason` come from closed sets and match
//!   the variant that was built (`reason` is `disconnect_<code>` for
//!   disconnects); `detail` is the documented text; `diagnostics` is the
//!   documented object with fields bounded by `max_field_bytes`.
//! - Client identification: `line` and `comments` are the lossy text of the
//!   full raw bytes, `line_hex` is lowercase hex of the first
//!   `max_field_bytes` bytes (decoded and compared), `line_hex_truncated` is
//!   present and `true` iff the raw line is longer; `*_truncated` flags of
//!   debug messages, disconnect descriptions and unexpected-input samples
//!   are `true` iff the raw field exceeded the bound.
//! - Proposal: every one of the ten name lists appears under its own key in
//!   order (directional lists differ when the inputs differ), markers are
//!   classified, anomalies use their codes.
//! - `record_truncated` is `true` iff the full record exceeds
//!   `max_record_bytes` (`observation_record(o, f, false)` length); then
//!   `messages` is `[]`, `proposal` is `null` and the record is strictly
//!   smaller than the full one (exactly one byte smaller when there was
//!   nothing to drop). Size policy: the truncated record never exceeds
//!   `record_ref::truncated_record_bound`, so budgets at or above it are
//!   always honoured; when a smaller budget is exceeded the record still
//!   parses and carries `record_truncated: true`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use serde_json::{Value as J, json};
use tatami::server::observe::{
    Encoder, SCHEMA_VERSION, observation_record, rfc3339, summary_record,
};
use tatami_fuzz_protocol::state_support::json_ref::{self, Node, decode_hex_lower};
use tatami_fuzz_protocol::state_support::record_ref::{
    self, FieldBounds, KEX_MARKERS, disconnect_name, looks_like_rfc3339, truncated_record_bound,
};
use tatami_fuzz_protocol::tcp_support::{Cursor, filler};
use tatami_tcp::ident::{
    IdentError, InvalidIdentification, LineTerminator, OwnedIdentification, VersionSupport,
};
use tatami_tcp::initial::{InitialError, InputOverflow, SkippedMessage};
use tatami_tcp::io::{ListenerEvent, Observation, ObservationEnd, StopReason, Summary};
use tatami_tcp::observer::{ObservationOutcome, ObserverStage};
use tatami_tcp::packet::PacketError;
use tatami_tcp::probe::{Proposal, ProposalAnomaly};
use tatami_wire::error::{DecodeError, InvalidEncoding, MessageError};
use tatami_wire::kexinit::OwnedKexInit;

const MAX_RAW_FIELD: usize = 2000;
const MAX_SHORT_FIELD: usize = 64;
/// Harness bound on the JSON-escaped `detail` string (checked at runtime).
const DETAIL_JSON_MAX: usize = 512;

const OBSERVATION_KEYS: [&str; 23] = [
    "schema",
    "event",
    "time",
    "id",
    "transport",
    "local_addr",
    "peer_addr",
    "accepted_at",
    "elapsed_ms",
    "bytes_read",
    "bytes_written",
    "server_identification",
    "client_identification",
    "messages",
    "proposal",
    "stage",
    "outcome",
    "reason",
    "detail",
    "diagnostics",
    "key_exchange_completed",
    "peer_authenticated",
    "record_truncated",
];

const SUMMARY_KEYS: [&str; 12] = [
    "schema",
    "event",
    "time",
    "bound",
    "reason",
    "accepted",
    "observed",
    "dropped_at_capacity",
    "records_dropped",
    "workers_abandoned",
    "elapsed_ms",
    "error",
];

const NAMES: [&str; 34] = [
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group-exchange-sha256",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768x25519-sha256",
    "ext-info-c",
    "ext-info-s",
    "kex-strict-c-v00@openssh.com",
    "kex-strict-s-v00@openssh.com",
    "ssh-ed25519",
    "rsa-sha2-512",
    "ecdsa-sha2-nistp256",
    "ssh-rsa",
    "aes128-ctr",
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-256-etm@openssh.com",
    "none",
    "zlib",
    "zlib@openssh.com",
    "en-US",
    "x-unknown-method",
    "",
    "a",
    "name,with,commas",
    "quote\"in\"name",
    "back\\slash",
    "ctrl\u{1}char\u{1f}",
    "über-\u{1F600}",
    "kex-strict-c",
    "kex-strict-s",
];

const LIST_NAMES: [&str; 8] = [
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
];

const FIELD_NAMES: [&str; 6] = [
    "cookie",
    "kex_algorithms",
    "compression_algorithms_client_to_server",
    "channel_type",
    "description",
    "x",
];

// ----- generators ------------------------------------------------------------

fn num(cur: &mut Cursor<'_>) -> u64 {
    match cur.u8() {
        0 => 0,
        1 => 1,
        2 => u64::from(u32::MAX),
        3 => u64::MAX,
        4 => i64::MAX as u64,
        5 => (u64::from(cur.u32()) << 32) | u64::from(cur.u32()),
        s => u64::from(s),
    }
}

fn usize_num(cur: &mut Cursor<'_>) -> usize {
    usize::try_from(num(cur)).unwrap_or(usize::MAX)
}

fn dur(cur: &mut Cursor<'_>) -> Duration {
    let secs = num(cur);
    let nanos = cur.u32() % 1_000_000_000;
    Duration::new(secs, nanos)
}

fn addr(cur: &mut Cursor<'_>) -> SocketAddr {
    let sel = cur.u8();
    let port = cur.u16();
    if sel & 1 == 0 {
        let mut o = [0u8; 4];
        o.copy_from_slice(&cur.take_filled(4, 1));
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(o)), port)
    } else {
        let mut o = [0u8; 16];
        o.copy_from_slice(&cur.take_filled(16, 2));
        let scope = if sel & 2 != 0 { cur.u32() } else { 0 };
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(o), port, 0, scope))
    }
}

fn bytes(cur: &mut Cursor<'_>, max: usize) -> Vec<u8> {
    let len = cur.u16();
    let n = usize::from(len & 0x7fff) % (max + 1);
    if len & 0x8000 != 0 {
        filler(n, u32::from(len))
    } else {
        cur.take(n).to_vec()
    }
}

fn text(cur: &mut Cursor<'_>, max: usize) -> String {
    String::from_utf8_lossy(&bytes(cur, max)).into_owned()
}

fn stage(sel: u8) -> (ObserverStage, &'static str, &'static str) {
    match sel % 3 {
        0 => (
            ObserverStage::ClientIdentification,
            "client_identification",
            "awaiting client identification",
        ),
        1 => (
            ObserverStage::InitialPackets,
            "initial_packets",
            "awaiting client KEXINIT",
        ),
        _ => (ObserverStage::Finished, "finished", "finished"),
    }
}

fn gen_ident(cur: &mut Cursor<'_>) -> Option<OwnedIdentification> {
    let sel = cur.u8();
    match sel % 4 {
        0 => None,
        1 => Some(OwnedIdentification {
            line: b"SSH-2.0-OpenSSH_9.9 Debian-1".to_vec(),
            terminator: LineTerminator::CrLf,
            protocol_version: String::from("2.0"),
            software_version: String::from("OpenSSH_9.9"),
            comments: Some(b"Debian-1".to_vec()),
            support: VersionSupport::Ssh2,
        }),
        _ => Some(OwnedIdentification {
            line: bytes(cur, MAX_RAW_FIELD),
            terminator: if sel & 4 != 0 {
                LineTerminator::Lf
            } else {
                LineTerminator::CrLf
            },
            protocol_version: text(cur, MAX_SHORT_FIELD),
            software_version: text(cur, MAX_SHORT_FIELD),
            comments: (sel & 8 != 0).then(|| bytes(cur, MAX_RAW_FIELD)),
            support: if sel & 16 != 0 {
                VersionSupport::Ssh2Compatibility
            } else {
                VersionSupport::Ssh2
            },
        }),
    }
}

fn gen_messages(cur: &mut Cursor<'_>) -> Vec<SkippedMessage> {
    let n = usize::from(cur.u8()) % 17;
    (0..n)
        .map(|_| {
            let k = cur.u8();
            match k % 3 {
                0 => SkippedMessage::Ignored {
                    data_len: usize_num(cur),
                },
                1 => SkippedMessage::Debug {
                    always_display: k & 4 != 0,
                    message: bytes(cur, MAX_RAW_FIELD),
                    language_tag: bytes(cur, MAX_RAW_FIELD),
                },
                _ => SkippedMessage::Unimplemented {
                    sequence_number: cur.u32(),
                },
            }
        })
        .collect()
}

fn gen_names(cur: &mut Cursor<'_>) -> Vec<String> {
    let n = usize::from(cur.u8()) % 9;
    (0..n)
        .map(|_| {
            let sel = cur.u8();
            if sel >= 0xC0 {
                text(cur, MAX_SHORT_FIELD)
            } else {
                String::from(NAMES[usize::from(sel) % NAMES.len()])
            }
        })
        .collect()
}

fn gen_proposal(cur: &mut Cursor<'_>) -> Proposal {
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(&cur.take_filled(16, 5));
    let mut lists: Vec<Vec<String>> = (0..10).map(|_| gen_names(cur)).collect();
    let mut next = || lists.remove(0);
    let kexinit = OwnedKexInit {
        cookie,
        kex_algorithms: next(),
        server_host_key_algorithms: next(),
        encryption_client_to_server: next(),
        encryption_server_to_client: next(),
        mac_client_to_server: next(),
        mac_server_to_client: next(),
        compression_client_to_server: next(),
        compression_server_to_client: next(),
        languages_client_to_server: next(),
        languages_server_to_client: next(),
        first_kex_packet_follows: cur.u8() & 1 == 1,
        reserved: cur.u32(),
    };
    let n_anom = usize::from(cur.u8()) % 5;
    let anomalies = (0..n_anom)
        .map(|_| {
            if cur.u8() & 1 == 1 {
                ProposalAnomaly::NonzeroReserved(cur.u32())
            } else {
                ProposalAnomaly::EmptyAlgorithmList(
                    LIST_NAMES[usize::from(cur.u8()) % LIST_NAMES.len()],
                )
            }
        })
        .collect();
    let payload_len = usize::from(cur.u16()) % (MAX_RAW_FIELD + 1);
    Proposal {
        kexinit,
        raw_payload: filler(payload_len, 9),
        anomalies,
        unexamined_bytes: usize_num(cur),
    }
}

fn gen_initial_error(cur: &mut Cursor<'_>) -> (InitialError, &'static str) {
    match cur.u8() % 17 {
        0 => (
            InitialError::Ident(IdentError::PreludeLineTooLong),
            "ident_prelude_line_too_long",
        ),
        1 => (
            InitialError::Ident(IdentError::TooManyPreludeLines),
            "ident_too_many_prelude_lines",
        ),
        2 => (
            InitialError::Ident(IdentError::PreludeBytesExceeded),
            "ident_prelude_too_large",
        ),
        3 => (
            InitialError::Ident(IdentError::IdentificationTooLong),
            "ident_too_long",
        ),
        4 => (
            InitialError::Ident(IdentError::InvalidIdentification(match cur.u8() % 4 {
                0 => InvalidIdentification::MissingSeparator,
                1 => InvalidIdentification::BadProtocolVersion,
                2 => InvalidIdentification::BadSoftwareVersion,
                _ => InvalidIdentification::ControlCharacter,
            })),
            "ident_invalid",
        ),
        5 => (
            InitialError::Ident(IdentError::UnsupportedVersion),
            "ident_unsupported_version",
        ),
        6 => (
            InitialError::Packet(PacketError::TooLarge {
                packet_length: cur.u32(),
                limit: cur.u32(),
            }),
            "packet_framing",
        ),
        7 => (
            InitialError::Packet(PacketError::TooSmall {
                packet_length: cur.u32(),
            }),
            "packet_framing",
        ),
        8 => (
            InitialError::Packet(PacketError::Misaligned {
                packet_length: cur.u32(),
            }),
            "packet_framing",
        ),
        9 => (
            InitialError::Packet(PacketError::BadPadding {
                packet_length: cur.u32(),
                padding_length: cur.u8(),
            }),
            "packet_framing",
        ),
        10 => (InitialError::EmptyPayload, "packet_empty_payload"),
        11 => {
            let number = cur.u8();
            let error = match cur.u8() % 4 {
                0 => MessageError::Empty,
                1 => MessageError::UnexpectedMessage {
                    expected: cur.u8(),
                    found: cur.u8(),
                },
                2 => MessageError::Field {
                    field: FIELD_NAMES[usize::from(cur.u8()) % FIELD_NAMES.len()],
                    offset: usize_num(cur),
                    error: match cur.u8() % 4 {
                        0 => DecodeError::Truncated {
                            needed: usize_num(cur),
                            available: usize_num(cur),
                        },
                        1 => DecodeError::LengthOverflow {
                            claimed: cur.u32(),
                            available: usize_num(cur),
                        },
                        2 => DecodeError::InvalidEncoding(InvalidEncoding::NameListNonAscii {
                            offset: usize_num(cur),
                        }),
                        _ => DecodeError::InvalidEncoding(InvalidEncoding::NameListEmptyName {
                            offset: usize_num(cur),
                        }),
                    },
                },
                _ => MessageError::TrailingBytes {
                    count: usize_num(cur),
                },
            };
            (InitialError::Message { number, error }, "message_malformed")
        }
        12 => (
            InitialError::UnexpectedMessage { number: cur.u8() },
            "message_unexpected",
        ),
        13 => (
            InitialError::UnsupportedTransition { number: cur.u8() },
            "unsupported_transition",
        ),
        14 => (
            InitialError::PacketBudgetExceeded {
                limit: usize_num(cur),
            },
            "packet_budget_exceeded",
        ),
        15 => (
            InitialError::ByteBudgetExceeded {
                limit: usize_num(cur),
            },
            "byte_budget_exceeded",
        ),
        _ => (
            InitialError::InputOverflow(InputOverflow {
                capacity: usize_num(cur),
                pending: usize_num(cur),
                offered: usize_num(cur),
            }),
            "input_overflow",
        ),
    }
}

/// What the harness knows about the end it built, independently of the
/// production `code()` functions.
struct EndExpect {
    outcome: &'static str,
    reason: Option<String>,
    detail: Detail,
}

enum Detail {
    Exact(String),
    Prefix(&'static str),
    Suffix(&'static str),
}

fn gen_end(cur: &mut Cursor<'_>) -> (ObservationEnd, EndExpect) {
    let sel = cur.u8() % 10;
    match sel {
        0 => (
            ObservationEnd::Observer(ObservationOutcome::BannerOnly),
            EndExpect {
                outcome: "banner_only",
                reason: None,
                detail: Detail::Exact(String::from(
                    "client identification received; banner-only mode",
                )),
            },
        ),
        1 => {
            let p = gen_proposal(cur);
            let (outcome, detail) = if p.anomalies.is_empty() {
                (
                    "proposal",
                    "client identification and initial KEXINIT received",
                )
            } else {
                (
                    "proposal_with_anomalies",
                    "KEXINIT decoded with anomalies; see proposal.anomalies",
                )
            };
            (
                ObservationEnd::Observer(ObservationOutcome::Proposal(Box::new(p))),
                EndExpect {
                    outcome,
                    reason: None,
                    detail: Detail::Exact(String::from(detail)),
                },
            )
        }
        2 | 9 => {
            let reason_code = if sel == 9 {
                u32::from(cur.u8() % 16)
            } else {
                cur.u32()
            };
            let detail = match disconnect_name(reason_code) {
                Some(n) => format!("client sent SSH_MSG_DISCONNECT ({n})"),
                None => String::from("client sent SSH_MSG_DISCONNECT"),
            };
            (
                ObservationEnd::Observer(ObservationOutcome::Disconnected {
                    reason_code,
                    description: bytes(cur, MAX_RAW_FIELD),
                    language_tag: bytes(cur, MAX_RAW_FIELD),
                }),
                EndExpect {
                    outcome: "disconnected",
                    reason: Some(format!("disconnect_{reason_code}")),
                    detail: Detail::Exact(detail),
                },
            )
        }
        3 => (
            ObservationEnd::Observer(ObservationOutcome::UnexpectedInput {
                sample: bytes(cur, MAX_RAW_FIELD),
                truncated: cur.u8() & 1 == 1,
            }),
            EndExpect {
                outcome: "unexpected_input",
                reason: Some(String::from("not_ssh_identification")),
                detail: Detail::Exact(String::from(
                    "first bytes did not begin an SSH identification",
                )),
            },
        ),
        4 => {
            let (st, _, display) = stage(cur.u8());
            let pending_bytes = usize_num(cur);
            (
                ObservationEnd::Observer(ObservationOutcome::Eof {
                    stage: st,
                    pending_bytes,
                }),
                EndExpect {
                    outcome: "eof",
                    reason: Some(String::from(if pending_bytes == 0 {
                        "eof_at_boundary"
                    } else {
                        "eof_truncated"
                    })),
                    detail: Detail::Exact(format!("peer closed while {display}")),
                },
            )
        }
        5 => {
            let (e, code) = gen_initial_error(cur);
            let detail = match &e {
                InitialError::Ident(_) => Detail::Prefix("identification: "),
                InitialError::Packet(_) => Detail::Prefix("packet framing: "),
                InitialError::EmptyPayload => {
                    Detail::Exact(String::from("packet with empty payload"))
                }
                InitialError::Message { .. } => Detail::Prefix("malformed "),
                InitialError::UnexpectedMessage { .. } => Detail::Suffix(" before KEXINIT"),
                InitialError::UnsupportedTransition { .. } => {
                    Detail::Suffix(" before KEXINIT; initial packet decoding cannot continue")
                }
                InitialError::PacketBudgetExceeded { limit } => {
                    Detail::Exact(format!("more than {limit} packets before KEXINIT"))
                }
                InitialError::ByteBudgetExceeded { limit } => {
                    Detail::Exact(format!("more than {limit} bytes before KEXINIT"))
                }
                InitialError::InputOverflow(o) => Detail::Exact(format!(
                    "input of {} bytes exceeds buffer capacity {} ({} pending)",
                    o.offered, o.capacity, o.pending
                )),
            };
            (
                ObservationEnd::Observer(ObservationOutcome::Error(e)),
                EndExpect {
                    outcome: "protocol_error",
                    reason: Some(String::from(code)),
                    detail,
                },
            )
        }
        6 => (
            ObservationEnd::TimedOut,
            EndExpect {
                outcome: "timeout",
                reason: Some(String::from("connection_deadline")),
                detail: Detail::Prefix("connection deadline passed"),
            },
        ),
        7 => (
            ObservationEnd::Shutdown,
            EndExpect {
                outcome: "shutdown",
                reason: Some(String::from("listener_stopping")),
                detail: Detail::Exact(String::from(
                    "listener stopped while the connection was active",
                )),
            },
        ),
        _ => {
            use std::io::ErrorKind;
            let (kind, code) = match cur.u8() % 8 {
                0 => (ErrorKind::ConnectionReset, "connection_reset"),
                1 => (ErrorKind::ConnectionAborted, "connection_aborted"),
                2 => (ErrorKind::BrokenPipe, "broken_pipe"),
                3 => (ErrorKind::TimedOut, "timed_out"),
                4 => (ErrorKind::Other, "io_other"),
                5 => (ErrorKind::UnexpectedEof, "io_other"),
                6 => (ErrorKind::WouldBlock, "io_other"),
                _ => (ErrorKind::Interrupted, "io_other"),
            };
            let message = text(cur, MAX_SHORT_FIELD);
            (
                ObservationEnd::Io(std::io::Error::new(kind, message.clone())),
                EndExpect {
                    outcome: "io_error",
                    reason: Some(String::from(code)),
                    detail: Detail::Exact(format!("socket error: {message}")),
                },
            )
        }
    }
}

// ----- expectations ----------------------------------------------------------

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    s
}

fn lossy_prefix(b: &[u8], max: usize) -> String {
    String::from_utf8_lossy(&b[..b.len().min(max)]).into_owned()
}

fn expected_millis(d: Duration) -> u64 {
    let ms = u128::from(d.as_secs()) * 1000 + u128::from(d.subsec_millis());
    u64::try_from(ms).unwrap_or(u64::MAX)
}

fn expected_identification(i: &OwnedIdentification, f: usize) -> J {
    let n = i.line.len().min(f);
    let mut anomalies: Vec<&str> = Vec::new();
    if i.terminator == LineTerminator::Lf {
        anomalies.push("lf_only_terminator");
    }
    if i.support == VersionSupport::Ssh2Compatibility {
        anomalies.push("compatibility_version_1_99");
    }
    let mut obj = json!({
        "line": String::from_utf8_lossy(&i.line),
        "line_hex": hex_lower(&i.line[..n]),
        "protocol_version": i.protocol_version,
        "software_version": i.software_version,
        "comments": i.comments.as_deref().map(|c| String::from_utf8_lossy(c).into_owned()),
        "terminator": match i.terminator {
            LineTerminator::CrLf => "crlf",
            LineTerminator::Lf => "lf",
        },
        "anomalies": anomalies,
    });
    if i.line.len() > f {
        obj["line_hex_truncated"] = J::Bool(true);
    }
    obj
}

fn expected_message(m: &SkippedMessage, f: usize) -> J {
    match m {
        SkippedMessage::Ignored { data_len } => json!({"type": "ignore", "data_len": data_len}),
        SkippedMessage::Debug {
            always_display,
            message,
            language_tag,
        } => json!({
            "type": "debug",
            "always_display": always_display,
            "message": lossy_prefix(message, f),
            "message_truncated": message.len() > f,
            "language_tag": lossy_prefix(language_tag, f),
        }),
        SkippedMessage::Unimplemented { sequence_number } => {
            json!({"type": "unimplemented", "sequence_number": sequence_number})
        }
    }
}

fn expected_proposal(p: &Proposal) -> J {
    let k = &p.kexinit;
    let markers: Vec<J> = k
        .kex_algorithms
        .iter()
        .filter_map(|n| {
            KEX_MARKERS
                .iter()
                .find(|(name, _)| name == n)
                .map(|(_, kind)| json!({"name": n, "kind": kind}))
        })
        .collect();
    let anomalies: Vec<&str> = p
        .anomalies
        .iter()
        .map(|a| match a {
            ProposalAnomaly::NonzeroReserved(_) => "kexinit_nonzero_reserved",
            ProposalAnomaly::EmptyAlgorithmList(_) => "kexinit_empty_algorithm_list",
        })
        .collect();
    json!({
        "role": "client",
        "cookie_hex": hex_lower(&k.cookie),
        "kex_algorithms": k.kex_algorithms,
        "kex_markers": markers,
        "server_host_key_algorithms": k.server_host_key_algorithms,
        "encryption_client_to_server": k.encryption_client_to_server,
        "encryption_server_to_client": k.encryption_server_to_client,
        "mac_client_to_server": k.mac_client_to_server,
        "mac_server_to_client": k.mac_server_to_client,
        "compression_client_to_server": k.compression_client_to_server,
        "compression_server_to_client": k.compression_server_to_client,
        "languages_client_to_server": k.languages_client_to_server,
        "languages_server_to_client": k.languages_server_to_client,
        "first_kex_packet_follows": k.first_kex_packet_follows,
        "reserved": k.reserved,
        "anomalies": anomalies,
        "payload_len": p.raw_payload.len(),
        "unexamined_bytes": p.unexamined_bytes,
    })
}

fn expected_diagnostics(end: &ObservationEnd, f: usize) -> J {
    match end {
        ObservationEnd::Observer(ObservationOutcome::Disconnected {
            reason_code,
            description,
            language_tag,
        }) => json!({
            "reason_code": reason_code,
            "reason_name": disconnect_name(*reason_code),
            "description": lossy_prefix(description, f),
            "description_truncated": description.len() > f,
            "language_tag": lossy_prefix(language_tag, f),
        }),
        ObservationEnd::Observer(ObservationOutcome::UnexpectedInput { sample, truncated }) => {
            json!({
                "sample": lossy_prefix(sample, f),
                "sample_hex": hex_lower(&sample[..sample.len().min(f)]),
                "sample_len": sample.len(),
                "sample_truncated": *truncated || sample.len() > f,
            })
        }
        ObservationEnd::Observer(ObservationOutcome::Eof { pending_bytes, .. }) => {
            json!({"pending_bytes": pending_bytes})
        }
        _ => J::Null,
    }
}

// ----- checks ----------------------------------------------------------------

fn parse(json: &str) -> J {
    let v: J = serde_json::from_str(json).unwrap_or_else(|e| panic!("invalid JSON: {e}\n{json}"));
    assert!(v.is_object(), "record must be an object");
    v
}

fn check_envelope(rec: &J, event: &str) {
    assert_eq!(rec["schema"], json!(SCHEMA_VERSION));
    assert_eq!(SCHEMA_VERSION, 1);
    assert_eq!(rec["event"], json!(event));
    assert!(record_ref::EVENT_NAMES.contains(&event));
    let time = rec["time"].as_str().expect("time is a string");
    assert!(looks_like_rfc3339(time), "time {time:?} is not RFC 3339");
}

/// Asserts that `keys` occur in this order at the top level of `json`.
/// A quoted key followed by a colon cannot occur inside a string value
/// (its quotes would be escaped) and none of these keys is nested.
fn check_key_order(json: &str, keys: &[&str]) {
    let mut pos = 0;
    for k in keys {
        let pat = format!("\"{k}\":");
        let i = json[pos..]
            .find(&pat)
            .unwrap_or_else(|| panic!("key {k} missing or out of order after {pos}: {json}"));
        pos += i + pat.len();
    }
}

fn detail_matches(detail: &str, expect: &Detail) -> bool {
    match expect {
        Detail::Exact(s) => detail == s,
        Detail::Prefix(p) => detail.starts_with(p),
        Detail::Suffix(s) => detail.ends_with(s),
    }
}

fn check_observation(event: &ListenerEvent, exp: &EndExpect, stage_code: &str, enc: Encoder) {
    let ListenerEvent::Observation(o) = event else {
        unreachable!()
    };
    let f = enc.max_field_bytes;
    let budget = enc.max_record_bytes;
    let out = enc.encode(event).to_json();
    let rec = parse(&out);
    check_envelope(&rec, "connection_observation");
    check_key_order(&out, &OBSERVATION_KEYS);
    assert_eq!(
        rec.as_object().map(serde_json::Map::len),
        Some(OBSERVATION_KEYS.len())
    );

    // Fixed fields.
    assert_eq!(rec["id"], json!(o.id));
    assert_eq!(rec["transport"], json!("tcp"));
    assert_eq!(rec["local_addr"], json!(o.local.to_string()));
    assert_eq!(rec["peer_addr"], json!(o.peer.to_string()));
    let accepted = record_ref::rfc3339(o.accepted_unix);
    assert_eq!(rec["accepted_at"], json!(accepted), "accepted_at");
    assert_eq!(rfc3339(o.accepted_unix), accepted, "public rfc3339");
    assert_eq!(rfc3339(o.elapsed), record_ref::rfc3339(o.elapsed));
    assert_eq!(rec["elapsed_ms"], json!(expected_millis(o.elapsed)));
    assert_eq!(rec["bytes_read"], json!(o.bytes_read));
    assert_eq!(rec["bytes_written"], json!(o.bytes_written));
    assert_eq!(
        rec["server_identification"],
        json!(String::from_utf8_lossy(&o.server_identification))
    );
    assert_eq!(rec["key_exchange_completed"], J::Bool(false));
    assert_eq!(rec["peer_authenticated"], J::Bool(false));

    // Client identification.
    match &o.client_identification {
        None => assert_eq!(rec["client_identification"], J::Null),
        Some(i) => {
            let ident = &rec["client_identification"];
            assert_eq!(
                *ident,
                expected_identification(i, f),
                "client_identification"
            );
            let line_hex = ident["line_hex"].as_str().expect("line_hex");
            assert!(line_hex.len() <= 2 * f);
            let n = i.line.len().min(f);
            assert_eq!(decode_hex_lower(line_hex), &i.line[..n], "line_hex prefix");
            assert_eq!(
                ident.get("line_hex_truncated"),
                (i.line.len() > f).then_some(&J::Bool(true))
            );
        }
    }

    // Stage / outcome / reason / detail / diagnostics.
    assert_eq!(rec["stage"], json!(stage_code));
    assert!(record_ref::STAGE_CODES.contains(&stage_code));
    assert_eq!(rec["outcome"], json!(exp.outcome));
    assert!(record_ref::OUTCOME_CODES.contains(&exp.outcome));
    assert_eq!(rec["reason"], json!(exp.reason), "reason");
    if let Some(r) = &exp.reason {
        assert!(
            record_ref::reason_is_known(r),
            "reason {r} outside the closed set"
        );
    }
    let detail = rec["detail"].as_str().expect("detail is a string");
    assert!(
        detail_matches(detail, &exp.detail),
        "detail {detail:?} does not match"
    );
    let detail_json_len = json_ref::serialize(&Node::Str(String::from(detail))).len();
    assert!(
        detail_json_len <= DETAIL_JSON_MAX,
        "harness bound on detail too small: {detail_json_len}"
    );
    assert_eq!(
        rec["diagnostics"],
        expected_diagnostics(&o.end, f),
        "diagnostics"
    );
    if let ObservationEnd::Observer(ObservationOutcome::UnexpectedInput { sample, .. }) = &o.end {
        let hex = rec["diagnostics"]["sample_hex"]
            .as_str()
            .expect("sample_hex");
        assert!(hex.len() <= 2 * f);
        assert_eq!(decode_hex_lower(hex), &sample[..sample.len().min(f)]);
    }

    // Truncation policy.
    let full_len = observation_record(o, f, false).to_json().len();
    let expect_truncated = full_len > budget;
    assert_eq!(
        rec["record_truncated"],
        J::Bool(expect_truncated),
        "record_truncated (full {full_len}, budget {budget})"
    );
    if expect_truncated {
        assert_eq!(rec["messages"], json!([]));
        assert_eq!(rec["proposal"], J::Null);
        if o.messages.is_empty() && o.proposal.is_none() {
            assert_eq!(out.len() + 1, full_len, "only false->true differs");
        } else {
            assert!(out.len() < full_len, "truncation must shrink the record");
        }
        let (line, pv, sv, comments) = match &o.client_identification {
            None => (0, 0, 0, 0),
            Some(i) => (
                i.line.len(),
                i.protocol_version.len(),
                i.software_version.len(),
                i.comments.as_ref().map_or(0, Vec::len),
            ),
        };
        let (diagnostic_text, diagnostic_hex) = match &o.end {
            ObservationEnd::Observer(ObservationOutcome::Disconnected {
                description,
                language_tag,
                ..
            }) => (description.len().min(f) + language_tag.len().min(f), 0),
            ObservationEnd::Observer(ObservationOutcome::UnexpectedInput { sample, .. }) => {
                (sample.len().min(f), sample.len().min(f))
            }
            _ => (0, 0),
        };
        let bound = truncated_record_bound(&FieldBounds {
            max_field: f,
            server_identification: o.server_identification.len(),
            line,
            protocol_version: pv,
            software_version: sv,
            comments,
            detail_json: DETAIL_JSON_MAX,
            diagnostic_text,
            diagnostic_hex,
        });
        assert!(
            out.len() <= bound,
            "truncated record is {} bytes, above the derived bound {bound}",
            out.len()
        );
        if budget >= bound {
            assert!(out.len() <= budget);
        }
    } else {
        assert_eq!(out.len(), full_len);
        assert!(out.len() <= budget);
        let msgs = rec["messages"].as_array().expect("messages array");
        assert_eq!(msgs.len(), o.messages.len());
        for (got, m) in msgs.iter().zip(&o.messages) {
            assert_eq!(*got, expected_message(m, f), "message record");
        }
        match &o.proposal {
            None => assert_eq!(rec["proposal"], J::Null),
            Some(p) => {
                let prop = &rec["proposal"];
                assert_eq!(*prop, expected_proposal(p), "proposal record");
                let k = &p.kexinit;
                if k.encryption_client_to_server != k.encryption_server_to_client {
                    assert_ne!(
                        prop["encryption_client_to_server"],
                        prop["encryption_server_to_client"]
                    );
                }
                if k.mac_client_to_server != k.mac_server_to_client {
                    assert_ne!(prop["mac_client_to_server"], prop["mac_server_to_client"]);
                }
                let cookie = prop["cookie_hex"].as_str().expect("cookie_hex");
                assert_eq!(decode_hex_lower(cookie), k.cookie);
            }
        }
    }
    if out.len() > budget {
        assert!(expect_truncated, "budget exceeded without truncation");
    }
}

fn strip_time(mut v: J) -> J {
    v.as_object_mut().expect("object").remove("time");
    v
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let kind = cur.u8();
    let b1 = cur.u8();
    let max_record_bytes = match b1 & 0x0f {
        0 => 0,
        1 => 1,
        2 => 64,
        3 => 256,
        4 => 1024,
        5 => 2048,
        6 => 4096,
        7 => 65536,
        8 => 262_144,
        9 => (cur.u32() % 300_001) as usize,
        _ => 262_144,
    };
    let max_field_bytes = match b1 >> 4 {
        0 => 0,
        1 => 1,
        2 => 8,
        3 => 512,
        4 => usize::from(cur.u16()) % 4097,
        _ => 512,
    };
    let enc = Encoder {
        max_record_bytes,
        max_field_bytes,
    };

    match kind {
        0 => {
            let bound = addr(&mut cur);
            let out = enc.encode(&ListenerEvent::Started { bound }).to_json();
            let rec = parse(&out);
            check_envelope(&rec, "listener_started");
            check_key_order(&out, &["schema", "event", "time", "bound"]);
            assert_eq!(rec["bound"], json!(bound.to_string()));
            assert_eq!(rec.as_object().map(serde_json::Map::len), Some(4));
        }
        1 => {
            let dropped_since_last = num(&mut cur);
            let total_dropped = num(&mut cur);
            let out = enc
                .encode(&ListenerEvent::Overload {
                    dropped_since_last,
                    total_dropped,
                })
                .to_json();
            let rec = parse(&out);
            check_envelope(&rec, "overload");
            check_key_order(
                &out,
                &[
                    "schema",
                    "event",
                    "time",
                    "dropped_since_last",
                    "total_dropped",
                ],
            );
            assert_eq!(rec["dropped_since_last"], json!(dropped_since_last));
            assert_eq!(rec["total_dropped"], json!(total_dropped));
            assert_eq!(rec.as_object().map(serde_json::Map::len), Some(5));
        }
        2 => {
            let bound = addr(&mut cur);
            let accepted = num(&mut cur);
            let observed = num(&mut cur);
            let dropped_at_capacity = num(&mut cur);
            let records_dropped = num(&mut cur);
            let workers_abandoned = usize_num(&mut cur);
            let (reason, code) = match cur.u8() % 5 {
                0 => (StopReason::RunDurationElapsed, "run_duration_elapsed"),
                1 => (
                    StopReason::ConnectionLimitReached,
                    "connection_limit_reached",
                ),
                2 => (StopReason::StopRequested, "stop_requested"),
                3 => (StopReason::SinkFailed, "sink_failed"),
                _ => (StopReason::AcceptFailed, "accept_failed"),
            };
            let error = (cur.u8() & 1 == 1).then(|| text(&mut cur, 256));
            let elapsed = dur(&mut cur);
            let summary = Summary {
                bound,
                accepted,
                observed,
                dropped_at_capacity,
                records_dropped,
                workers_abandoned,
                reason,
                error: error.clone(),
                elapsed,
            };
            let direct = summary_record(&summary);
            let out = enc.encode(&ListenerEvent::Stopped(summary)).to_json();
            let rec = parse(&out);
            check_envelope(&rec, "listener_stopped");
            check_key_order(&out, &SUMMARY_KEYS);
            assert_eq!(
                rec.as_object().map(serde_json::Map::len),
                Some(SUMMARY_KEYS.len())
            );
            assert_eq!(rec["bound"], json!(bound.to_string()));
            assert_eq!(rec["reason"], json!(code));
            assert!(record_ref::STOP_REASON_CODES.contains(&code));
            assert_eq!(rec["accepted"], json!(accepted));
            assert_eq!(rec["observed"], json!(observed));
            assert_eq!(rec["dropped_at_capacity"], json!(dropped_at_capacity));
            assert_eq!(rec["records_dropped"], json!(records_dropped));
            assert_eq!(rec["workers_abandoned"], json!(workers_abandoned));
            assert_eq!(rec["elapsed_ms"], json!(expected_millis(elapsed)));
            assert_eq!(rec["error"], json!(error));
            assert_eq!(
                strip_time(parse(&direct.to_json())),
                strip_time(rec),
                "summary_record and encode agree"
            );
        }
        _ => {
            let id = num(&mut cur);
            let local = addr(&mut cur);
            let peer = addr(&mut cur);
            let accepted_unix = dur(&mut cur);
            let elapsed = dur(&mut cur);
            let bytes_read = num(&mut cur);
            let bytes_written = num(&mut cur);
            let server_identification = if cur.u8() == 0 {
                b"SSH-2.0-tatami_observer_0.1.0".to_vec()
            } else {
                bytes(&mut cur, 255)
            };
            let client_identification = gen_ident(&mut cur);
            let messages = gen_messages(&mut cur);
            let proposal = if cur.u8() == 0 {
                None
            } else {
                Some(gen_proposal(&mut cur))
            };
            let (st, stage_code, _) = stage(cur.u8());
            let (end, exp) = gen_end(&mut cur);
            let event = ListenerEvent::Observation(Box::new(Observation {
                id,
                local,
                peer,
                accepted_unix,
                elapsed,
                bytes_read,
                bytes_written,
                server_identification,
                client_identification,
                messages,
                proposal,
                stage: st,
                end,
            }));
            check_observation(&event, &exp, stage_code, enc);
        }
    }
});
