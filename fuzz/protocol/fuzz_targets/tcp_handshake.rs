#![no_main]
//! `tatami_tcp::handshake::ClientHandshake` driven by a structured server
//! whose transcript the harness generates and signs itself.
//!
//! # Server side (all harness, providers called directly)
//!
//! The server has an X25519 key pair (`x25519_dalek`) and an Ed25519 host
//! key (`ed25519_dalek::SigningKey`), both from fuzz bytes. After the client
//! has sent `KEXINIT` and `KEX_ECDH_INIT`, the harness computes `K` from the
//! client's `Q_C`, the exchange hash `H` with `sha2` over the RFC 5656 §4 /
//! RFC 8731 §3 layout (its own `mpint` encoding), signs `H`, builds
//! `KEX_ECDH_REPLY` by hand, derives the RFC 4253 §7.2 keys itself and seals
//! the protected phase with `aes_gcm` in the RFC 5647 layout. Nothing here
//! calls `tatami_tcp::{transcript, gcm, negotiate}`.
//!
//! # Input layout (all via a forgiving cursor; see `gen_scenario`)
//!
//! rng seed 8, server X25519 secret 32, host seed 32, flags (bit 0
//! `ext-info-c`, bit 1 clear = offer strict KEX, bits 4-5 chunk schedule,
//! bit 6 no `curve25519-sha256` bias, bit 7 raw fuzz server lists; low
//! nibble `0x8` = pre-KEX budget of 3 packets, `0xC` = entropy-failure and
//! input-overflow checks only), identification kind + software index,
//! prelude count/indices, pre-`KEXINIT` messages, server `KEXINIT` lists
//! (`kex_support::lists::gen_lists`: real methods, all six markers, unknown
//! names, empty lists, `first_kex_packet_follows`), guess packet, messages
//! between `KEXINIT` and the reply, reply variant, messages before
//! `NEWKEYS`, protected messages, tamper location, trust decision, chunk
//! schedule. Interleaved messages include malformed bodies (exact
//! `MessageError` modelled), empty payloads and an unframeable length;
//! protected ones also a misaligned clear length.
//!
//! Set `TATAMI_FUZZ_TRACE=1` to print the outcome and client message
//! sequence of each input (triage aid; the oracles do not depend on it).
//!
//! # Oracles
//!
//! - The terminal `HandshakeOutcome` equals the harness's own model of the
//!   documented rules: `NegotiationFailed(e)` by the RFC 4253 §7.1 model;
//!   `StrictKexViolation` iff strict was negotiated (same-spelling pair) and
//!   a disallowed message (or a non-`KEXINIT` first packet) appears before
//!   `NEWKEYS`; wrong guess → exactly one key-exchange message discarded;
//!   `SignatureInvalid` iff the signature blob was corrupted (bit flip, wrong
//!   hash, `ssh-rsa`, trailing byte, 63 bytes); `ProtocolError(HostKey|Kex|
//!   Message)` for a bad `K_S`, all-zero/short `Q_S`, malformed reply;
//!   `HostNotTrusted` iff the decision was `Untrusted` — and then NO
//!   `NEWKEYS` in the client output; `Completed` iff everything was valid
//!   and `SERVICE_ACCEPT` named `ssh-userauth`; `ServiceMismatch`,
//!   `RekeyNotSupported` (server `KEXINIT` after `NEWKEYS`),
//!   `ServerDisconnected`, `UnexpectedMessage{number, phase}`,
//!   `TagMismatch` iff a protected byte was flipped, `Eof{phase}` when the
//!   stream ends. Exact equality except that `StrictKexViolation.detail` is
//!   checked by a distinguishing substring.
//! - Report: `user_authenticated` is always `false`; `kexinit_was_first_packet`,
//!   `strict_kex` (all five fields), `selected`, `signature_valid`, `trust`,
//!   `newkeys_sent/received`, `protected_packets_sent/received`,
//!   `send_sequence/receive_sequence` (reset under strict KEX),
//!   `skipped_messages`, `server_guess_discarded`, `host_key` fingerprint
//!   (= `sha2` over `K_S`), `ext_info`, `service_accepted`,
//!   `server_disconnect`, prelude and identification all equal the model;
//!   `session_id()` equals the harness `H` iff the signature verified.
//! - The client output is parsed (unprotected framing, then the harness
//!   opens the protected packets with its own client→server keys): the
//!   message numbers are exactly the modelled sequence from {KEXINIT,
//!   KEX_ECDH_INIT, NEWKEYS, SERVICE_REQUEST, DISCONNECT}; message 50
//!   (`USERAUTH_REQUEST`) never appears; `KEX_ECDH_INIT` carries a 32-byte
//!   `Q_C`; `SERVICE_REQUEST` names `ssh-userauth`; a `DISCONNECT` uses
//!   reason 11.
//! - Byte-at-a-time and fuzz-chunked delivery produce identical outcome,
//!   report and client bytes; `room()` is respected; a bounded step loop
//!   panics on livelock; the terminal outcome is stable and `input_ended`
//!   repeats it; `OwnedExtInfo` round-trips the generated `EXT_INFO`.
//! - An entropy source that fails is `HandshakeInitError::Entropy`.

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use tatami_fuzz_protocol::kex_support::crypto::{
    self, DirKeys, Gcm, HarnessRng, HashInputs, ed25519_key_blob, ed25519_sig_blob, string,
};
use tatami_fuzz_protocol::kex_support::lists::{Lists, gen_lists};
use tatami_fuzz_protocol::kex_support::negotiate_ref;
use tatami_fuzz_protocol::tcp_support::{ChunkMode, Cursor};
use tatami_keys::error::{BlobError, KeyError};
use tatami_keys::fingerprint::Sha256Fingerprint;
use tatami_keys::trust::{
    HostTrustPolicy, PinnedSha256, TrustDecision, TrustSource, UntrustedReason,
};
use tatami_tcp::gcm::OpenError;
use tatami_tcp::handshake::{
    ClientHandshake, HandshakeConfig, HandshakeInitError, HandshakeOutcome, HandshakeReport,
    LimitKind, Phase, ProtocolViolation, SkippedMessage, Step,
};
use tatami_tcp::ident::IdentError;
use tatami_tcp::negotiate::{Negotiated, NegotiationError, StrictKex};
use tatami_tcp::packet::PacketError;
use tatami_tcp::transcript::KexError;
use tatami_wire::ext_info::{ExtInfo, ExtInfoError, OwnedExtInfo};
use tatami_wire::{DecodeError, InvalidEncoding, MessageError};
use x25519_dalek::{PublicKey, StaticSecret};

const SOFTWARE: &str = "tatami_0.1.0";
const MAX_STEPS: usize = 4096;

// ---------------------------------------------------------------------------
// Scenario.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentKind {
    V20,
    V199,
    V20LfOnly,
    V15,
}

/// A message whose body does not decode (the exact `MessageError` is part
/// of the model).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mal {
    /// `2 00 00 00 05`: data length 5 with nothing after.
    Ignore,
    /// `4`: no `always_display` byte.
    Debug,
    /// `3 00`: one byte of the sequence number.
    Unimplemented,
    /// `1 00 00`: two bytes of the reason code.
    Disconnect,
    /// `21 00`: a trailing byte.
    NewKeys,
    /// `20 01 02 03 04`: four cookie bytes.
    KexInit,
    /// `7 00 00 00 01 00`: one extension claimed, one byte present.
    ExtInfo,
    /// `6 00 00 00 09`: service name length 9 with nothing after.
    ServiceAccept,
}

impl Mal {
    fn payload(self) -> Vec<u8> {
        match self {
            Mal::Ignore => vec![2, 0, 0, 0, 5],
            Mal::Debug => vec![4],
            Mal::Unimplemented => vec![3, 0],
            Mal::Disconnect => vec![1, 0, 0],
            Mal::NewKeys => vec![21, 0],
            Mal::KexInit => vec![20, 1, 2, 3, 4],
            Mal::ExtInfo => vec![7, 0, 0, 0, 1, 0],
            Mal::ServiceAccept => vec![6, 0, 0, 0, 9],
        }
    }

    fn number(self) -> u8 {
        self.payload()[0]
    }

    /// The decoder's verdict, from the RFC layouts.
    fn error(self) -> MessageError {
        let field = |field: &'static str, error: DecodeError| MessageError::Field {
            field,
            offset: 1,
            error,
        };
        match self {
            Mal::Ignore => field(
                "data",
                DecodeError::LengthOverflow {
                    claimed: 5,
                    available: 0,
                },
            ),
            Mal::Debug => field(
                "always_display",
                DecodeError::Truncated {
                    needed: 1,
                    available: 0,
                },
            ),
            Mal::Unimplemented => field(
                "sequence_number",
                DecodeError::Truncated {
                    needed: 4,
                    available: 1,
                },
            ),
            Mal::Disconnect => field(
                "reason_code",
                DecodeError::Truncated {
                    needed: 4,
                    available: 2,
                },
            ),
            Mal::NewKeys => MessageError::TrailingBytes { count: 1 },
            Mal::KexInit => field(
                "cookie",
                DecodeError::Truncated {
                    needed: 16,
                    available: 4,
                },
            ),
            Mal::ExtInfo => field(
                "nr-extensions",
                DecodeError::LengthOverflow {
                    claimed: 1,
                    available: 1,
                },
            ),
            Mal::ServiceAccept => field(
                "service_name",
                DecodeError::LengthOverflow {
                    claimed: 9,
                    available: 0,
                },
            ),
        }
    }

    fn outcome(self) -> HandshakeOutcome {
        HandshakeOutcome::ProtocolError(ProtocolViolation::Message {
            number: self.number(),
            error: self.error(),
        })
    }
}

/// An unprotected message the server may interleave.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Msg {
    Ignore(Vec<u8>),
    Debug {
        always_display: bool,
        message: Vec<u8>,
        language_tag: Vec<u8>,
    },
    Unimplemented(u32),
    Disconnect {
        reason_code: u32,
        description: Vec<u8>,
    },
    /// Any other message number with a short body.
    Other(u8),
    /// A second copy of the server KEXINIT.
    KexInitAgain,
    /// A NEWKEYS out of place.
    NewKeys,
    /// A junk KEX_ECDH_REPLY (`31 de ad`).
    ReplyAgain,
    /// A well-framed packet whose payload does not decode.
    Malformed(Mal),
    /// A well-framed packet with an empty payload.
    Empty,
    /// Four `0xff` bytes: an unframeable length; nothing after it is read.
    BadFrame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    Valid,
    WrongSig(u8),
    SigOverWrongHash,
    SigAlgRsa,
    SigTrailing,
    SigShort,
    KsAlgRsa,
    KsKey31,
    KsMalformed,
    QsZero,
    QsShort,
    Trailing,
    Truncated,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Prot {
    ExtInfo(Vec<(Vec<u8>, Vec<u8>)>),
    ExtInfoTooMany,
    ServiceAccept(Vec<u8>),
    Disconnect {
        reason_code: u32,
        description: Vec<u8>,
    },
    KexInit,
    Ignore(Vec<u8>),
    Debug {
        always_display: bool,
        message: Vec<u8>,
        language_tag: Vec<u8>,
    },
    Unimplemented(u32),
    Other(u8),
    Empty,
    Malformed(Mal),
    /// A sealed IGNORE whose clear length field is overwritten with 17:
    /// rejected by the alignment rule before any body is waited for.
    BadLength,
}

#[derive(Clone, Debug)]
struct Scenario {
    rng_seed: u64,
    server_secret: [u8; 32],
    host_seed: [u8; 32],
    advertise_ext_info: bool,
    offer_strict_kex: bool,
    entropy_fail: bool,
    /// `max_pre_kex_packets = 3`.
    tiny_budget: bool,
    prelude: Vec<Vec<u8>>,
    ident: IdentKind,
    software: &'static [u8],
    pre_kexinit: Vec<Msg>,
    server: Lists,
    /// Key-exchange-specific message number sent right after KEXINIT when
    /// `first_kex_packet_follows` is set (the server's "guess", junk body).
    guess: Option<u8>,
    before_reply: Vec<Msg>,
    reply: Reply,
    before_newkeys: Vec<Msg>,
    send_newkeys: bool,
    protected: Vec<Prot>,
    /// `(protected packet index, byte offset selector, xor)`; the offset is
    /// mapped into the body or tag, never the clear length.
    tamper: Option<(usize, usize, u8)>,
    trust: TrustDecision,
    chunk: ChunkMode,
}

const SOFTWARES: [&[u8]; 4] = [
    b"OpenSSH_9.6",
    b"tatami_0.1.0",
    b"x",
    b"Srv_1.0 comments here",
];
const PRELUDES: [&[u8]; 3] = [b"banner", b"Welcome to the diagnostic server", b"x"];
const DESCRIPTIONS: [&[u8]; 3] = [b"", b"bye", b"too many"];
const SERVICES: [&[u8]; 3] = [b"ssh-userauth", b"ssh-connection", b"ssh-userauth "];
const EXT_NAMES: [&[u8]; 4] = [
    b"server-sig-algs",
    b"publickey-hostbound@openssh.com",
    b"ping@openssh.com",
    b"elevation",
];
const SIG_ALGS: [&[u8]; 4] = [b"ssh-ed25519", b"ssh-ed25519,rsa-sha2-512", b"a,,b", b""];
/// Numbers that no phase handles (6 is excluded: SERVICE_ACCEPT decodes).
const OTHER_NUMBERS: [u8; 6] = [5, 50, 80, 22, 255, 60];

/// Up to seven fuzz bytes.
fn short(cur: &mut Cursor<'_>) -> Vec<u8> {
    let n = usize::from(cur.u8()) % 8;
    cur.take(n).to_vec()
}

const MALS: [Mal; 6] = [
    Mal::Ignore,
    Mal::Debug,
    Mal::Unimplemented,
    Mal::Disconnect,
    Mal::NewKeys,
    Mal::KexInit,
];

fn gen_msg(cur: &mut Cursor<'_>) -> Msg {
    match cur.u8() % 11 {
        8 => Msg::Malformed(MALS[usize::from(cur.u8()) % MALS.len()]),
        9 => Msg::Empty,
        10 => Msg::BadFrame,
        0 | 1 => Msg::Ignore(short(cur)),
        2 => Msg::Debug {
            always_display: cur.u8() & 1 == 1,
            message: short(cur),
            language_tag: Vec::new(),
        },
        3 => Msg::Unimplemented(cur.u32()),
        4 => Msg::Disconnect {
            reason_code: u32::from(cur.u8()) % 20,
            description: DESCRIPTIONS[usize::from(cur.u8()) % DESCRIPTIONS.len()].to_vec(),
        },
        5 => Msg::Other(OTHER_NUMBERS[usize::from(cur.u8()) % OTHER_NUMBERS.len()]),
        6 => Msg::KexInitAgain,
        _ => {
            if cur.u8() & 1 == 1 {
                Msg::NewKeys
            } else {
                Msg::ReplyAgain
            }
        }
    }
}

const PROT_MALS: [Mal; 5] = [
    Mal::Ignore,
    Mal::Debug,
    Mal::Disconnect,
    Mal::ExtInfo,
    Mal::ServiceAccept,
];

fn gen_prot(cur: &mut Cursor<'_>) -> Prot {
    match cur.u8() % 13 {
        12 => Prot::BadLength,
        11 => Prot::Malformed(PROT_MALS[usize::from(cur.u8()) % PROT_MALS.len()]),
        0 | 1 => {
            let n = usize::from(cur.u8()) % 4;
            let pairs = (0..n)
                .map(|_| {
                    let name = EXT_NAMES[usize::from(cur.u8()) % EXT_NAMES.len()].to_vec();
                    let value = if name == b"server-sig-algs" {
                        SIG_ALGS[usize::from(cur.u8()) % SIG_ALGS.len()].to_vec()
                    } else {
                        short(cur)
                    };
                    (name, value)
                })
                .collect();
            Prot::ExtInfo(pairs)
        }
        2 => Prot::ExtInfoTooMany,
        3..=5 => Prot::ServiceAccept(SERVICES[usize::from(cur.u8()) % SERVICES.len()].to_vec()),
        6 => Prot::Disconnect {
            reason_code: u32::from(cur.u8()) % 20,
            description: DESCRIPTIONS[usize::from(cur.u8()) % DESCRIPTIONS.len()].to_vec(),
        },
        7 => Prot::KexInit,
        8 => match cur.u8() % 3 {
            0 => Prot::Ignore(short(cur)),
            1 => Prot::Debug {
                always_display: true,
                message: b"hi".to_vec(),
                language_tag: b"en".to_vec(),
            },
            _ => Prot::Unimplemented(cur.u32()),
        },
        9 => Prot::Other(OTHER_NUMBERS[usize::from(cur.u8()) % OTHER_NUMBERS.len()]),
        _ => Prot::Empty,
    }
}

fn gen_scenario(data: &[u8]) -> Scenario {
    let mut cur = Cursor::new(data);
    let rng_seed = u64::from_le_bytes(cur.take_filled(8, 1).try_into().expect("8"));
    let server_secret: [u8; 32] = cur.take_filled(32, 2).try_into().expect("32");
    let host_seed: [u8; 32] = cur.take_filled(32, 3).try_into().expect("32");
    let flags = cur.u8();
    let ident = match cur.u8() % 8 {
        0..=4 => IdentKind::V20,
        5 => IdentKind::V199,
        6 => IdentKind::V20LfOnly,
        _ => IdentKind::V15,
    };
    let software = SOFTWARES[usize::from(cur.u8()) % SOFTWARES.len()];
    let prelude = (0..usize::from(cur.u8()) % 3)
        .map(|_| PRELUDES[usize::from(cur.u8()) % PRELUDES.len()].to_vec())
        .collect();
    let pre_kexinit: Vec<Msg> = (0..usize::from(cur.u8()) % 3)
        .map(|_| match gen_msg(&mut cur) {
            // A KEXINIT copy before the real one would *be* the KEXINIT.
            Msg::KexInitAgain => Msg::NewKeys,
            m => m,
        })
        .collect();
    let tiny_budget = flags & 0x0f == 0x08;
    let mut server = gen_lists(&mut cur);
    // Bias towards a negotiable server most of the time: the interesting
    // paths are behind a successful negotiation.
    if flags & 0x80 == 0 {
        let one = |n: &[u8]| vec![n.to_vec()];
        if flags & 0x40 == 0 {
            server.kex.insert(0, b"curve25519-sha256".to_vec());
        }
        server.host_key = one(b"ssh-ed25519");
        server.enc_c2s = one(b"aes128-gcm@openssh.com");
        server.enc_s2c = one(b"aes128-gcm@openssh.com");
        server.comp_c2s = one(b"none");
        server.comp_s2c = one(b"none");
        if server.mac_c2s.is_empty() {
            server.mac_c2s = one(b"hmac-sha2-256");
        }
        if server.mac_s2c.is_empty() {
            server.mac_s2c = one(b"hmac-sha2-256");
        }
    }
    let guess_byte = cur.u8();
    let guess = if server.first_kex_packet_follows && guess_byte & 1 == 1 {
        Some(30 + (guess_byte >> 1) % 20)
    } else {
        None
    };
    let before_reply = (0..usize::from(cur.u8()) % 3)
        .map(|_| gen_msg(&mut cur))
        .collect();
    let reply = match cur.u8() % 24 {
        0..=11 => Reply::Valid,
        12 => Reply::WrongSig(cur.u8()),
        13 => Reply::SigOverWrongHash,
        14 => Reply::SigAlgRsa,
        15 => Reply::SigTrailing,
        16 => Reply::SigShort,
        17 => Reply::KsAlgRsa,
        18 => Reply::KsKey31,
        19 => Reply::KsMalformed,
        20 => Reply::QsZero,
        21 => Reply::QsShort,
        22 => Reply::Trailing,
        _ => Reply::Truncated,
    };
    let mut before_newkeys: Vec<Msg> = (0..usize::from(cur.u8()) % 3)
        .map(|_| gen_msg(&mut cur))
        .collect();
    let mut send_newkeys = cur.u8() & 7 != 0;
    // At most one NEWKEYS after the reply: a NEWKEYS here *is* the server
    // NEWKEYS and everything after it would be read as protected.
    if let Some(pos) = before_newkeys.iter().position(|m| *m == Msg::NewKeys) {
        before_newkeys.truncate(pos);
        send_newkeys = true;
    }
    let protected: Vec<Prot> = (0..usize::from(cur.u8()) % 5)
        .map(|_| gen_prot(&mut cur))
        .collect();
    let tamper_byte = cur.u8();
    let tamper = if tamper_byte & 1 == 1 && !protected.is_empty() {
        Some((
            usize::from(cur.u8()) % protected.len(),
            usize::from(cur.u8()),
            cur.u8() | 1,
        ))
    } else {
        None
    };
    let trust = match cur.u8() % 6 {
        0 => TrustDecision::Untrusted {
            reason: UntrustedReason::FingerprintMismatch,
        },
        1 => TrustDecision::Untrusted {
            reason: UntrustedReason::NoPolicy,
        },
        _ => TrustDecision::Trusted {
            source: TrustSource::PinnedFingerprint,
        },
    };
    let n_sched = usize::from(cur.u8()) % 8;
    let sched = cur.take(n_sched).to_vec();
    let chunk = ChunkMode::from_selector(flags >> 4, &sched);
    Scenario {
        rng_seed,
        server_secret,
        host_seed,
        advertise_ext_info: flags & 1 != 0,
        offer_strict_kex: flags & 2 == 0,
        entropy_fail: flags & 0x0f == 0x0c,
        tiny_budget,
        prelude,
        ident,
        software,
        pre_kexinit,
        server,
        guess,
        before_reply,
        reply,
        before_newkeys,
        send_newkeys,
        protected,
        tamper,
        trust,
        chunk,
    }
}

// ---------------------------------------------------------------------------
// Wire assembly (server side, by hand).
// ---------------------------------------------------------------------------

/// Unprotected binary packet (RFC 4253 §6): `uint32 packet_length, byte
/// padding_length, payload, padding`, total a multiple of 8, padding ≥ 4.
fn frame(payload: &[u8]) -> Vec<u8> {
    let base = 5 + payload.len();
    let mut pad = 8 - (base % 8);
    if pad < 4 {
        pad += 8;
    }
    let mut out = ((1 + payload.len() + pad) as u32).to_be_bytes().to_vec();
    out.push(pad as u8);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0x5au8, pad));
    out
}

/// `(content without terminator, wire bytes)`.
fn ident_line(sc: &Scenario) -> (Vec<u8>, Vec<u8>) {
    let version: &[u8] = match sc.ident {
        IdentKind::V20 | IdentKind::V20LfOnly => b"2.0",
        IdentKind::V199 => b"1.99",
        IdentKind::V15 => b"1.5",
    };
    let mut content = b"SSH-".to_vec();
    content.extend_from_slice(version);
    content.push(b'-');
    content.extend_from_slice(sc.software);
    let mut wire = content.clone();
    wire.extend_from_slice(if sc.ident == IdentKind::V20LfOnly {
        b"\n"
    } else {
        b"\r\n"
    });
    (content, wire)
}

fn transport_payload(m: &Msg, i_s: &[u8]) -> Vec<u8> {
    match m {
        Msg::Ignore(data) => {
            let mut p = vec![2u8];
            p.extend(string(data));
            p
        }
        Msg::Debug {
            always_display,
            message,
            language_tag,
        } => {
            let mut p = vec![4u8, u8::from(*always_display)];
            p.extend(string(message));
            p.extend(string(language_tag));
            p
        }
        Msg::Unimplemented(seq) => {
            let mut p = vec![3u8];
            p.extend_from_slice(&seq.to_be_bytes());
            p
        }
        Msg::Disconnect {
            reason_code,
            description,
        } => {
            let mut p = vec![1u8];
            p.extend_from_slice(&reason_code.to_be_bytes());
            p.extend(string(description));
            p.extend(string(b""));
            p
        }
        Msg::Other(n) => vec![*n, 0, 0, 0, 0],
        Msg::KexInitAgain => i_s.to_vec(),
        Msg::NewKeys => vec![21],
        Msg::ReplyAgain => vec![31, 0xde, 0xad],
        Msg::Malformed(mal) => mal.payload(),
        Msg::Empty => Vec::new(),
        Msg::BadFrame => unreachable!("BadFrame has no payload; see wire_of"),
    }
}

/// Wire bytes of one unprotected server message.
fn wire_of(m: &Msg, i_s: &[u8]) -> Vec<u8> {
    match m {
        Msg::BadFrame => vec![0xff, 0xff, 0xff, 0xff],
        _ => frame(&transport_payload(m, i_s)),
    }
}

/// The frame-level verdict on `BadFrame`: the cap is checked from the
/// length alone, before anything is counted.
fn bad_frame_outcome() -> HandshakeOutcome {
    HandshakeOutcome::ProtocolError(ProtocolViolation::Packet(PacketError::TooLarge {
        packet_length: 0xffff_ffff,
        limit: 64 * 1024,
    }))
}

fn msg_number(m: &Msg) -> u8 {
    match m {
        Msg::Ignore(_) => 2,
        Msg::Debug { .. } => 4,
        Msg::Unimplemented(_) => 3,
        Msg::Disconnect { .. } => 1,
        Msg::Other(n) => *n,
        Msg::KexInitAgain => 20,
        Msg::NewKeys => 21,
        Msg::ReplyAgain => 31,
        Msg::Malformed(mal) => mal.number(),
        Msg::Empty | Msg::BadFrame => unreachable!("handled before the number is needed"),
    }
}

fn ext_info_payload(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut p = vec![7u8];
    p.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
    for (n, v) in pairs {
        p.extend(string(n));
        p.extend(string(v));
    }
    p
}

fn prot_payload(m: &Prot, i_s: &[u8]) -> Vec<u8> {
    match m {
        Prot::ExtInfo(pairs) => ext_info_payload(pairs),
        Prot::ExtInfoTooMany => {
            let pairs: Vec<(Vec<u8>, Vec<u8>)> =
                (0..65).map(|_| (b"a".to_vec(), Vec::new())).collect();
            ext_info_payload(&pairs)
        }
        Prot::ServiceAccept(name) => {
            let mut p = vec![6u8];
            p.extend(string(name));
            p
        }
        Prot::Disconnect {
            reason_code,
            description,
        } => transport_payload(
            &Msg::Disconnect {
                reason_code: *reason_code,
                description: description.clone(),
            },
            i_s,
        ),
        Prot::KexInit => i_s.to_vec(),
        Prot::Ignore(d) => transport_payload(&Msg::Ignore(d.clone()), i_s),
        Prot::Debug {
            always_display,
            message,
            language_tag,
        } => transport_payload(
            &Msg::Debug {
                always_display: *always_display,
                message: message.clone(),
                language_tag: language_tag.clone(),
            },
            i_s,
        ),
        Prot::Unimplemented(seq) => transport_payload(&Msg::Unimplemented(*seq), i_s),
        Prot::Other(n) => vec![*n, 0, 0, 0, 0],
        Prot::Empty => Vec::new(),
        Prot::Malformed(mal) => mal.payload(),
        Prot::BadLength => vec![2, 0, 0, 0, 0],
    }
}

// ---------------------------------------------------------------------------
// Model.
// ---------------------------------------------------------------------------

/// Expected terminal outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Expect {
    Exact(HandshakeOutcome),
    /// `StrictKexViolation` whose detail contains the substring.
    Strict(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExtInfoModel {
    received: bool,
    server_sig_algs: Option<Vec<String>>,
    extension_names: Vec<String>,
}

/// Everything the report must say at the end.
#[derive(Clone, Debug)]
struct Model {
    tiny_budget: bool,
    outcome: Option<Expect>,
    /// Phase when the stream ran out without a terminal outcome.
    phase_at_end: Phase,
    kexinit_was_first: Option<bool>,
    strict: StrictKex,
    strict_active: bool,
    selected: Option<Negotiated>,
    server_seen: bool,
    guess_discarded: bool,
    skipped: Vec<SkippedMessage>,
    host_key_seen: bool,
    signature_valid: Option<bool>,
    trust: Option<TrustDecision>,
    newkeys_sent: bool,
    newkeys_received: bool,
    protected_sent: u32,
    protected_received: u32,
    unprotected_received: u32,
    ext_info: Option<ExtInfoModel>,
    service_accepted: Option<String>,
    server_disconnect: Option<(u32, Vec<u8>)>,
    /// Message numbers the client must have sent, in order.
    client_messages: Vec<u8>,
}

/// RFC 4251 §5 name-list grammar with the production error vocabulary.
fn name_list(body: &[u8]) -> Result<Vec<String>, InvalidEncoding> {
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    let mut start = 0usize;
    for seg in body.split(|&b| b == b',') {
        if seg.is_empty() {
            return Err(InvalidEncoding::NameListEmptyName { offset: start });
        }
        if let Some(i) = seg.iter().position(|&b| !(0x21..=0x7e).contains(&b)) {
            return Err(InvalidEncoding::NameListNonAscii { offset: start + i });
        }
        names.push(String::from_utf8_lossy(seg).into_owned());
        start += seg.len() + 1;
    }
    Ok(names)
}

fn skipped_of(m: &Msg) -> SkippedMessage {
    match m {
        Msg::Ignore(d) => SkippedMessage::Ignored { data_len: d.len() },
        Msg::Debug {
            always_display,
            message,
            language_tag,
        } => SkippedMessage::Debug {
            always_display: *always_display,
            message: message.clone(),
            language_tag: language_tag.clone(),
        },
        Msg::Unimplemented(s) => SkippedMessage::Unimplemented {
            sequence_number: *s,
        },
        _ => unreachable!("not skippable"),
    }
}

fn is_skippable(m: &Msg) -> bool {
    matches!(
        m,
        Msg::Ignore(_) | Msg::Debug { .. } | Msg::Unimplemented(_)
    )
}

fn msg_name(n: u8) -> String {
    let name = match n {
        1 => "SSH_MSG_DISCONNECT",
        2 => "SSH_MSG_IGNORE",
        3 => "SSH_MSG_UNIMPLEMENTED",
        4 => "SSH_MSG_DEBUG",
        _ => return format!("message number {n}"),
    };
    format!("{name} ({n})")
}

/// `KEX_ECDH_REPLY::decode` of `31 de ad`: the K_S length prefix is short.
fn junk_reply_error() -> HandshakeOutcome {
    HandshakeOutcome::ProtocolError(ProtocolViolation::Message {
        number: 31,
        error: MessageError::Field {
            field: "K_S",
            offset: 1,
            error: DecodeError::Truncated {
                needed: 4,
                available: 2,
            },
        },
    })
}

/// Ordered server items after KEXINIT.
enum Item<'a> {
    Guess(u8),
    Msg(&'a Msg),
    Reply,
    NewKeys,
}

impl Model {
    fn exact(&mut self, o: HandshakeOutcome) {
        if self.outcome.is_none() {
            self.outcome = Some(Expect::Exact(o));
        }
    }

    fn strict(&mut self, keyword: impl Into<String>) {
        if self.outcome.is_none() {
            self.outcome = Some(Expect::Strict(keyword.into()));
        }
    }

    fn done(&self) -> bool {
        self.outcome.is_some()
    }

    /// Counts one framed unprotected packet against the pre-KEX budget;
    /// `false` when the budget refuses it (the packet is then neither
    /// counted nor handled).
    fn unprotected(&mut self) -> bool {
        if self.tiny_budget && self.unprotected_received >= 3 {
            self.exact(HandshakeOutcome::Limit(LimitKind::PreKexPackets {
                limit: 3,
            }));
            return false;
        }
        self.unprotected_received += 1;
        true
    }

    /// A malformed message in the key-exchange phases: the strict rule is
    /// applied before decoding for transport messages and out-of-place
    /// KEXINIT/NEWKEYS; DISCONNECT and an in-place NEWKEYS are decoded first.
    fn kex_phase_malformed(&mut self, mal: Mal, awaiting_reply: bool) {
        let strict = self.strict_active;
        match mal.number() {
            1 => self.exact(mal.outcome()),
            2..=4 if strict => self.kex_phase_rule(mal.number(), awaiting_reply),
            2..=4 => self.exact(mal.outcome()),
            21 if !awaiting_reply => self.exact(mal.outcome()),
            n => self.kex_phase_rule(n, awaiting_reply),
        }
    }

    /// A message with number `n` that is not the reply and not skipped,
    /// after the server KEXINIT and before its NEWKEYS.
    fn kex_phase_rule(&mut self, n: u8, awaiting_reply: bool) {
        let strict = self.strict_active;
        let phase = if awaiting_reply {
            Phase::EcdhReply
        } else {
            Phase::ServerNewKeys
        };
        match n {
            20 if strict => self.strict("second KEXINIT"),
            31 if strict => self.strict("second KEX_ECDH_REPLY"),
            21 if strict => self.strict("NEWKEYS before KEX_ECDH_REPLY"),
            30..=49 if strict => self.strict(format!("key-exchange message {n} during")),
            2..=4 if strict => {
                self.strict(format!("{} during the initial key exchange", msg_name(n)))
            }
            1 if strict => self.strict("SSH_MSG_DISCONNECT (reason code"),
            _ => self.exact(HandshakeOutcome::UnexpectedMessage { number: n, phase }),
        }
    }

    /// The real KEX_ECDH_REPLY. Returns `true` when the run continues to
    /// the NEWKEYS phase (trusted).
    fn reply(&mut self, sc: &Scenario) -> bool {
        match sc.reply {
            Reply::Truncated => {
                self.exact(junk_reply_error());
                return false;
            }
            Reply::Trailing => {
                self.exact(HandshakeOutcome::ProtocolError(
                    ProtocolViolation::Message {
                        number: 31,
                        error: MessageError::TrailingBytes { count: 1 },
                    },
                ));
                return false;
            }
            Reply::KsMalformed => {
                self.exact(HandshakeOutcome::ProtocolError(ProtocolViolation::HostKey(
                    KeyError::Blob(BlobError::Field {
                        field: "algorithm",
                        offset: 0,
                        error: DecodeError::LengthOverflow {
                            claimed: 9,
                            available: 1,
                        },
                    }),
                )));
                return false;
            }
            Reply::KsAlgRsa => {
                self.exact(HandshakeOutcome::ProtocolError(ProtocolViolation::HostKey(
                    KeyError::UnsupportedAlgorithm(b"ssh-rsa".to_vec()),
                )));
                return false;
            }
            Reply::KsKey31 => {
                self.exact(HandshakeOutcome::ProtocolError(ProtocolViolation::HostKey(
                    KeyError::WrongLength {
                        field: "key",
                        expected: 32,
                        found: 31,
                    },
                )));
                return false;
            }
            _ => {}
        }
        self.host_key_seen = true;
        match sc.reply {
            Reply::QsShort => {
                self.exact(HandshakeOutcome::ProtocolError(ProtocolViolation::Kex(
                    KexError::ServerEphemeralLength { found: 31 },
                )));
                return false;
            }
            Reply::QsZero => {
                self.exact(HandshakeOutcome::ProtocolError(ProtocolViolation::Kex(
                    KexError::AllZeroSharedSecret,
                )));
                return false;
            }
            Reply::WrongSig(_)
            | Reply::SigOverWrongHash
            | Reply::SigAlgRsa
            | Reply::SigTrailing
            | Reply::SigShort => {
                self.signature_valid = Some(false);
                self.exact(HandshakeOutcome::SignatureInvalid);
                return false;
            }
            Reply::Valid => {}
            _ => unreachable!("handled above"),
        }
        self.signature_valid = Some(true);
        self.trust = Some(sc.trust);
        match sc.trust {
            TrustDecision::Untrusted { reason } => {
                self.exact(HandshakeOutcome::HostNotTrusted { reason });
                false
            }
            TrustDecision::Trusted { .. } => {
                self.newkeys_sent = true;
                self.client_messages.push(21);
                self.phase_at_end = Phase::ServerNewKeys;
                true
            }
        }
    }

    fn protected_phase(&mut self, sc: &Scenario) {
        self.newkeys_received = true;
        self.phase_at_end = Phase::Service;
        self.protected_sent = 1;
        self.client_messages.push(5);
        self.ext_info = Some(ExtInfoModel {
            received: false,
            server_sig_algs: None,
            extension_names: Vec::new(),
        });
        for (idx, p) in sc.protected.iter().enumerate() {
            if *p == Prot::BadLength {
                // Rejected from the clear length field: never counted.
                self.exact(HandshakeOutcome::ProtocolError(
                    ProtocolViolation::Protected(OpenError::Misaligned { packet_length: 17 }),
                ));
                return;
            }
            if sc.tamper.is_some_and(|(t_idx, _, _)| t_idx == idx) {
                self.exact(HandshakeOutcome::TagMismatch);
                return;
            }
            self.protected_received += 1;
            let first = self.protected_received == 1;
            match p {
                Prot::Empty => {
                    self.exact(HandshakeOutcome::ProtocolError(
                        ProtocolViolation::EmptyPayload,
                    ));
                }
                Prot::Malformed(mal) => match mal.number() {
                    7 if !first => self.exact(HandshakeOutcome::UnexpectedMessage {
                        number: 7,
                        phase: Phase::Service,
                    }),
                    _ => self.exact(mal.outcome()),
                },
                Prot::BadLength => unreachable!("handled before counting"),
                Prot::ExtInfo(pairs) if first => {
                    let mut sig_algs = None;
                    for (name, value) in pairs {
                        if name == b"server-sig-algs" {
                            match name_list(value) {
                                Ok(list) => sig_algs = Some(list),
                                Err(e) => {
                                    self.exact(HandshakeOutcome::ProtocolError(
                                        ProtocolViolation::ExtInfo(
                                            ExtInfoError::InvalidServerSigAlgs(e),
                                        ),
                                    ));
                                    return;
                                }
                            }
                            break;
                        }
                    }
                    self.ext_info = Some(ExtInfoModel {
                        received: true,
                        server_sig_algs: sig_algs,
                        extension_names: pairs
                            .iter()
                            .map(|(n, _)| String::from_utf8_lossy(n).into_owned())
                            .collect(),
                    });
                }
                Prot::ExtInfoTooMany if first => {
                    self.exact(HandshakeOutcome::ProtocolError(ProtocolViolation::ExtInfo(
                        ExtInfoError::TooManyExtensions {
                            claimed: 65,
                            max: 64,
                        },
                    )));
                }
                Prot::ExtInfo(_) | Prot::ExtInfoTooMany => {
                    self.exact(HandshakeOutcome::UnexpectedMessage {
                        number: 7,
                        phase: Phase::Service,
                    });
                }
                Prot::ServiceAccept(name) => {
                    if name == b"ssh-userauth" {
                        self.service_accepted = Some(String::from("ssh-userauth"));
                        self.protected_sent += 1;
                        self.client_messages.push(1);
                        self.exact(HandshakeOutcome::Completed);
                    } else {
                        self.exact(HandshakeOutcome::ProtocolError(
                            ProtocolViolation::ServiceMismatch {
                                requested: b"ssh-userauth".to_vec(),
                                accepted: name.clone(),
                            },
                        ));
                    }
                }
                Prot::Disconnect {
                    reason_code,
                    description,
                } => {
                    self.server_disconnect = Some((*reason_code, description.clone()));
                    self.exact(HandshakeOutcome::ServerDisconnected {
                        reason_code: *reason_code,
                        description: description.clone(),
                    });
                }
                Prot::KexInit => {
                    self.protected_sent += 1;
                    self.client_messages.push(1);
                    self.exact(HandshakeOutcome::RekeyNotSupported);
                }
                Prot::Ignore(d) => self
                    .skipped
                    .push(SkippedMessage::Ignored { data_len: d.len() }),
                Prot::Debug {
                    always_display,
                    message,
                    language_tag,
                } => self.skipped.push(SkippedMessage::Debug {
                    always_display: *always_display,
                    message: message.clone(),
                    language_tag: language_tag.clone(),
                }),
                Prot::Unimplemented(_) => {
                    self.exact(HandshakeOutcome::UnexpectedMessage {
                        number: 3,
                        phase: Phase::Service,
                    });
                }
                Prot::Other(n) => {
                    self.exact(HandshakeOutcome::UnexpectedMessage {
                        number: *n,
                        phase: Phase::Service,
                    });
                }
            }
            if self.done() {
                return;
            }
        }
    }
}

fn model(
    sc: &Scenario,
    negotiated: Result<Negotiated, NegotiationError>,
    strict_eval: StrictKex,
) -> Model {
    let ours = Lists::tatami_client([0; 16], sc.advertise_ext_info, sc.offer_strict_kex);
    let mut m = Model {
        tiny_budget: sc.tiny_budget,
        outcome: None,
        phase_at_end: Phase::ServerIdentification,
        kexinit_was_first: None,
        strict: negotiate_ref::strict_offered(&ours),
        strict_active: false,
        selected: None,
        server_seen: false,
        guess_discarded: false,
        skipped: Vec::new(),
        host_key_seen: false,
        signature_valid: None,
        trust: None,
        newkeys_sent: false,
        newkeys_received: false,
        protected_sent: 0,
        protected_received: 0,
        unprotected_received: 0,
        ext_info: None,
        service_accepted: None,
        server_disconnect: None,
        client_messages: vec![20],
    };
    if sc.ident == IdentKind::V15 {
        m.exact(HandshakeOutcome::ProtocolError(ProtocolViolation::Ident(
            IdentError::UnsupportedVersion,
        )));
        return m;
    }
    m.phase_at_end = Phase::ServerKexInit;

    // Before KEXINIT: transport messages are accepted provisionally.
    for msg in &sc.pre_kexinit {
        if *msg == Msg::BadFrame {
            m.exact(bad_frame_outcome());
            return m;
        }
        if !m.unprotected() {
            return m;
        }
        match msg {
            Msg::Empty => {
                m.exact(HandshakeOutcome::ProtocolError(
                    ProtocolViolation::EmptyPayload,
                ));
                return m;
            }
            Msg::Malformed(mal) if mal.number() != 21 => {
                if mal.number() == 20 {
                    // Recorded from the message number, before decoding.
                    m.kexinit_was_first = Some(m.unprotected_received == 1);
                }
                m.exact(mal.outcome());
                return m;
            }
            _ if is_skippable(msg) => m.skipped.push(skipped_of(msg)),
            Msg::Disconnect {
                reason_code,
                description,
            } => {
                m.server_disconnect = Some((*reason_code, description.clone()));
                m.exact(HandshakeOutcome::ServerDisconnected {
                    reason_code: *reason_code,
                    description: description.clone(),
                });
                return m;
            }
            other => {
                m.exact(HandshakeOutcome::UnexpectedMessage {
                    number: msg_number(other),
                    phase: Phase::ServerKexInit,
                });
                return m;
            }
        }
    }

    // Server KEXINIT.
    if !m.unprotected() {
        return m;
    }
    m.server_seen = true;
    let was_first = sc.pre_kexinit.is_empty();
    m.kexinit_was_first = Some(was_first);
    let negotiated = match negotiated {
        Ok(n) => n,
        Err(e) => {
            m.strict = strict_eval;
            m.exact(HandshakeOutcome::NegotiationFailed(e));
            return m;
        }
    };
    m.strict = negotiated.strict_kex;
    m.strict_active = negotiated.strict_kex.negotiated;
    let guess_wrong = negotiated.server_guess_wrong;
    m.selected = Some(negotiated);
    if m.strict_active && !was_first {
        m.strict("not the first packet");
        return m;
    }
    m.client_messages.push(30);
    m.phase_at_end = Phase::EcdhReply;

    // Everything unprotected after KEXINIT, in wire order.
    let mut items: Vec<Item<'_>> = Vec::new();
    if let Some(g) = sc.guess {
        items.push(Item::Guess(g));
    }
    items.extend(sc.before_reply.iter().map(Item::Msg));
    items.push(Item::Reply);
    items.extend(sc.before_newkeys.iter().map(Item::Msg));
    if sc.send_newkeys {
        items.push(Item::NewKeys);
    }
    let mut awaiting_reply = true;
    for item in items {
        if matches!(item, Item::Msg(Msg::BadFrame)) {
            m.exact(bad_frame_outcome());
            return m;
        }
        if !m.unprotected() {
            return m;
        }
        if let Item::Msg(Msg::Empty) = item {
            m.exact(HandshakeOutcome::ProtocolError(
                ProtocolViolation::EmptyPayload,
            ));
            return m;
        }
        if let Item::Msg(Msg::Malformed(mal)) = item {
            m.kex_phase_malformed(*mal, awaiting_reply);
            return m;
        }
        let n = match &item {
            Item::Guess(g) => *g,
            Item::Msg(mm) => msg_number(mm),
            Item::Reply => 31,
            Item::NewKeys => 21,
        };
        if let Item::Msg(mm) = &item {
            if is_skippable(mm) && !m.strict_active {
                m.skipped.push(skipped_of(mm));
                continue;
            }
            if let Msg::Disconnect {
                reason_code,
                description,
            } = mm
            {
                m.server_disconnect = Some((*reason_code, description.clone()));
                if !m.strict_active {
                    m.exact(HandshakeOutcome::ServerDisconnected {
                        reason_code: *reason_code,
                        description: description.clone(),
                    });
                    return m;
                }
            }
        }
        if awaiting_reply {
            if (30..=49).contains(&n) && guess_wrong && !m.guess_discarded {
                // RFC 4253 §7.1: the wrongly guessed first packet, whatever
                // it is (even the real reply when the server sent no guess).
                m.guess_discarded = true;
                continue;
            }
            if n == 31 {
                if matches!(item, Item::Reply) {
                    if m.reply(sc) {
                        awaiting_reply = false;
                        continue;
                    }
                    return m;
                }
                m.exact(junk_reply_error());
                return m;
            }
            m.kex_phase_rule(n, true);
            return m;
        }
        if n == 21 {
            m.protected_phase(sc);
            return m;
        }
        m.kex_phase_rule(n, false);
        return m;
    }
    m
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

struct Run {
    outcome: Option<HandshakeOutcome>,
    report: HandshakeReport,
    output: Vec<u8>,
    session_id: Option<[u8; 32]>,
    /// The harness's H when the reply was valid.
    h: Option<[u8; 32]>,
    k_s: Vec<u8>,
    c2s: Option<DirKeys>,
}

struct Driver<'a> {
    hs: ClientHandshake,
    sc: &'a Scenario,
    output: Vec<u8>,
    outcome: Option<HandshakeOutcome>,
    k_s: Vec<u8>,
    trust_asked: bool,
}

impl Driver<'_> {
    /// Steps until the machine blocks, answering the trust decision.
    fn drain(&mut self) {
        for _ in 0..MAX_STEPS {
            if self.outcome.is_some() {
                return;
            }
            match self.hs.step() {
                Step::NeedMore => return,
                Step::Send => {
                    let out = self.hs.take_output();
                    assert!(!out.is_empty(), "Send with nothing queued");
                    self.output.extend(out);
                }
                Step::TrustDecisionRequired(id) => {
                    assert!(!self.trust_asked, "trust asked twice");
                    self.trust_asked = true;
                    assert_eq!(self.hs.phase(), Phase::TrustDecision);
                    assert_eq!(id.blob, self.k_s, "the identity is the presented K_S");
                    assert_eq!(id.algorithm, "ssh-ed25519");
                    let digest: [u8; 32] = Sha256::digest(&self.k_s).into();
                    assert_eq!(id.sha256, Sha256Fingerprint::from_bytes(digest));
                    let identity = id.as_identity();
                    assert!(PinnedSha256(id.sha256).decide(&identity).is_trusted());
                    let mut other = digest;
                    other[0] ^= 1;
                    assert!(
                        !PinnedSha256(Sha256Fingerprint::from_bytes(other))
                            .decide(&identity)
                            .is_trusted()
                    );
                    // Asking again without answering changes nothing.
                    assert!(matches!(self.hs.step(), Step::TrustDecisionRequired(_)));
                    assert!(self.hs.take_output().is_empty());
                    self.hs.provide_trust(self.sc.trust);
                }
                Step::Finished(o) => {
                    assert_eq!(self.hs.phase(), Phase::Finished);
                    self.outcome = Some(*o);
                    return;
                }
            }
        }
        panic!("{MAX_STEPS} steps without blocking: livelock");
    }

    /// Feeds `bytes` under the scenario's schedule, draining after each.
    fn feed(&mut self, bytes: &[u8]) {
        let mut off = 0;
        let mut desired = self.sc.chunk.desired();
        while off < bytes.len() && self.outcome.is_none() {
            let room = self.hs.room();
            assert!(room > 0, "buffer full without progress or failure");
            let n = desired
                .next()
                .unwrap_or(1)
                .max(1)
                .min(room)
                .min(bytes.len() - off);
            let before = self.hs.pending_bytes();
            self.hs.feed(&bytes[off..off + n]);
            assert_eq!(
                self.hs.pending_bytes(),
                before + n,
                "a feed within room() buffers everything"
            );
            off += n;
            self.drain();
        }
    }
}

/// Parses the client's unprotected packets (after the identification line)
/// up to and including NEWKEYS; returns the payloads and bytes consumed.
fn parse_unprotected(out: &[u8]) -> (Vec<Vec<u8>>, usize) {
    let mut payloads = Vec::new();
    let mut pos = 0;
    while out.len() - pos >= 5 {
        let len = u32::from_be_bytes(out[pos..pos + 4].try_into().expect("4")) as usize;
        let pad = usize::from(out[pos + 4]);
        assert!(pad >= 4, "client padding below 4");
        assert_eq!((4 + len) % 8, 0, "client unprotected packet not 8-aligned");
        assert!(pos + 4 + len <= out.len(), "truncated client packet");
        let payload = out[pos + 5..pos + 4 + len - pad].to_vec();
        pos += 4 + len;
        let stop = payload == [21];
        payloads.push(payload);
        if stop {
            break;
        }
    }
    (payloads, pos)
}

fn run(sc: &Scenario) -> Run {
    let config = HandshakeConfig {
        software_version: String::from(SOFTWARE),
        advertise_ext_info: sc.advertise_ext_info,
        offer_strict_kex: sc.offer_strict_kex,
        max_pre_kex_packets: if sc.tiny_budget {
            3
        } else {
            HandshakeConfig::default().max_pre_kex_packets
        },
        ..HandshakeConfig::default()
    };
    let mut rng = HarnessRng::new(sc.rng_seed);
    let mut hs = ClientHandshake::new(config.clone(), &mut rng).expect("valid config and entropy");
    assert_eq!(hs.phase(), Phase::ServerIdentification);
    // A trust decision outside the trust phase is ignored.
    hs.provide_trust(TrustDecision::Untrusted {
        reason: UntrustedReason::NoPolicy,
    });
    assert_eq!(hs.phase(), Phase::ServerIdentification);
    assert_eq!(hs.report().trust, None);
    assert_eq!(
        hs.client_identification_line(),
        format!("SSH-2.0-{SOFTWARE}").as_bytes()
    );
    assert_eq!(hs.pending_bytes(), 0);
    assert_eq!(hs.room(), config.buffer_capacity());
    assert!(hs.session_id().is_none());
    assert!(!format!("{hs:?}").contains("secret"));

    let host = SigningKey::from_bytes(&sc.host_seed);
    let host_pk: [u8; 32] = host.verifying_key().to_bytes();
    let k_s = ed25519_key_blob(&host_pk);
    let mut d = Driver {
        hs,
        sc,
        output: Vec::new(),
        outcome: None,
        k_s: k_s.clone(),
        trust_asked: false,
    };
    d.drain();
    assert!(
        d.outcome.is_none(),
        "finished before any input: {:?}",
        d.outcome
    );

    // Phase 1: identification, pre-KEXINIT messages, KEXINIT, the guess and
    // the messages that precede the reply (none depend on the client).
    let (v_s, ident_wire) = ident_line(sc);
    let mut wire = Vec::new();
    for line in &sc.prelude {
        wire.extend_from_slice(line);
        wire.extend_from_slice(b"\r\n");
    }
    wire.extend_from_slice(&ident_wire);
    let i_s = sc.server.payload();
    for m in &sc.pre_kexinit {
        wire.extend(wire_of(m, &i_s));
    }
    wire.extend(frame(&i_s));
    if let Some(g) = sc.guess {
        wire.extend(frame(&[g, 0xde, 0xad]));
    }
    for m in &sc.before_reply {
        wire.extend(wire_of(m, &i_s));
    }
    d.feed(&wire);

    let mut h_out = None;
    let mut c2s_keys = None;
    if d.outcome.is_none() {
        // The client must have sent its identification, KEXINIT and
        // KEX_ECDH_INIT by now.
        let line_end = d
            .output
            .iter()
            .position(|&b| b == b'\n')
            .expect("identification line")
            + 1;
        let (payloads, _) = parse_unprotected(&d.output[line_end..]);
        assert!(
            payloads.len() >= 2,
            "KEXINIT and KEX_ECDH_INIT expected, got {}",
            payloads.len()
        );
        let i_c = payloads[0].clone();
        assert_eq!(i_c[0], 20);
        let init = &payloads[1];
        assert_eq!(init[0], 30, "second client message is KEX_ECDH_INIT");
        assert_eq!(&init[1..5], &[0, 0, 0, 32], "Q_C is a 32-byte string");
        assert_eq!(init.len(), 37);
        let q_c: [u8; 32] = init[5..].try_into().expect("32");
        let v_c = format!("SSH-2.0-{SOFTWARE}").into_bytes();

        // Phase 2: the reply, built from the client's Q_C.
        let server_secret = StaticSecret::from(sc.server_secret);
        let q_s: [u8; 32] = PublicKey::from(&server_secret).to_bytes();
        let k: [u8; 32] = server_secret
            .diffie_hellman(&PublicKey::from(q_c))
            .to_bytes();
        let q_s_wire: Vec<u8> = match sc.reply {
            Reply::QsZero => vec![0u8; 32],
            Reply::QsShort => q_s[..31].to_vec(),
            _ => q_s.to_vec(),
        };
        let k_s_wire: Vec<u8> = match sc.reply {
            Reply::KsAlgRsa => {
                let mut b = string(b"ssh-rsa");
                b.extend(string(&host_pk));
                b
            }
            Reply::KsKey31 => {
                let mut b = string(b"ssh-ed25519");
                b.extend(string(&host_pk[..31]));
                b
            }
            Reply::KsMalformed => vec![0, 0, 0, 9, b'x'],
            _ => k_s.clone(),
        };
        let h = crypto::exchange_hash(&HashInputs {
            v_c: &v_c,
            v_s: &v_s,
            i_c: &i_c,
            i_s: &i_s,
            k_s: &k_s_wire,
            q_c: &q_c,
            q_s: &q_s_wire,
            k: &k,
        });
        let sig: [u8; 64] = host.sign(&h).to_bytes();
        let sig_blob: Vec<u8> = match sc.reply {
            Reply::WrongSig(flip) => {
                let mut s = sig;
                s[usize::from(flip) % 64] ^= 1 << (flip % 8);
                ed25519_sig_blob(&s)
            }
            Reply::SigOverWrongHash => {
                let mut wrong = h;
                wrong[0] ^= 0x80;
                ed25519_sig_blob(&host.sign(&wrong).to_bytes())
            }
            Reply::SigAlgRsa => {
                let mut b = string(b"ssh-rsa");
                b.extend(string(&sig));
                b
            }
            Reply::SigTrailing => {
                let mut b = ed25519_sig_blob(&sig);
                b.push(0);
                b
            }
            Reply::SigShort => {
                let mut b = string(b"ssh-ed25519");
                b.extend(string(&sig[..63]));
                b
            }
            _ => ed25519_sig_blob(&sig),
        };
        let mut reply = vec![31u8];
        reply.extend(string(&k_s_wire));
        reply.extend(string(&q_s_wire));
        reply.extend(string(&sig_blob));
        let reply = match sc.reply {
            Reply::Truncated => vec![31, 0xde, 0xad],
            Reply::Trailing => {
                reply.push(0);
                reply
            }
            _ => reply,
        };
        if sc.reply == Reply::Valid {
            h_out = Some(h);
        }
        let mut wire = frame(&reply);
        for m in &sc.before_newkeys {
            wire.extend(wire_of(m, &i_s));
        }
        if sc.send_newkeys {
            wire.extend(frame(&[21]));
        }
        d.feed(&wire);

        // Phase 3: protected messages under the harness's derived keys.
        if d.outcome.is_none() && d.hs.phase() == Phase::Service {
            let (c2s, s2c) = crypto::derive_gcm(&k, &h, &h);
            c2s_keys = Some(c2s);
            let mut sealer = Gcm::new(&s2c.key, &s2c.iv);
            let mut wire = Vec::new();
            for (idx, p) in sc.protected.iter().enumerate() {
                let payload = prot_payload(p, &i_s);
                if let Prot::ExtInfo(pairs) = p {
                    // OwnedExtInfo round trip on the generated message.
                    let ext = ExtInfo::decode(&payload).expect("hand-built EXT_INFO decodes");
                    let owned = OwnedExtInfo {
                        extensions: pairs.clone(),
                    };
                    assert_eq!(ext.to_owned(64), Ok(owned.clone()));
                    let mut out = vec![0u8; payload.len()];
                    assert_eq!(owned.encode(&mut out), Ok(payload.len()));
                    assert_eq!(out, payload, "OwnedExtInfo::encode reproduces the payload");
                }
                let mut packet = sealer.seal(&payload);
                if *p == Prot::BadLength {
                    packet[..4].copy_from_slice(&[0, 0, 0, 17]);
                } else if let Some((t_idx, off, xor)) = sc.tamper
                    && t_idx == idx
                {
                    // Body or tag, never the clear length field.
                    let i = 4 + off % (packet.len() - 4);
                    packet[i] ^= xor;
                }
                wire.extend(packet);
            }
            d.feed(&wire);
        }
    }

    // End of stream.
    let report_before_eof = d.hs.report();
    let outcome = match d.outcome.clone() {
        Some(o) => {
            assert_eq!(d.hs.input_ended(), o, "input_ended repeats the outcome");
            assert!(
                matches!(d.hs.step(), Step::Finished(b) if *b == o),
                "terminal not stable"
            );
            let pending = d.hs.pending_bytes();
            d.hs.feed(b"ignored after finish");
            assert_eq!(
                d.hs.pending_bytes(),
                pending,
                "feed after finish is ignored"
            );
            assert_eq!(d.hs.report().outcome, Some(o.clone()));
            Some(o)
        }
        None => {
            assert_eq!(report_before_eof.outcome, None);
            let eof = d.hs.input_ended();
            assert_eq!(
                eof,
                HandshakeOutcome::Eof {
                    phase: report_before_eof.phase
                }
            );
            assert_eq!(d.hs.phase(), Phase::Finished);
            assert!(matches!(d.hs.step(), Step::Finished(b) if *b == eof));
            None
        }
    };
    d.output.extend(d.hs.take_output());
    let report = d.hs.report();
    Run {
        outcome,
        session_id: d.hs.session_id().map(|s| *s.as_bytes()),
        report,
        output: d.output,
        h: h_out,
        k_s,
        c2s: c2s_keys,
    }
}

// ---------------------------------------------------------------------------
// Checks.
// ---------------------------------------------------------------------------

fn check_outcome(got: &Option<HandshakeOutcome>, m: &Model) {
    match (&m.outcome, got) {
        (None, None) => {}
        (Some(Expect::Exact(want)), Some(got)) => assert_eq!(got, want, "outcome"),
        (Some(Expect::Strict(keyword)), Some(HandshakeOutcome::StrictKexViolation { detail })) => {
            assert!(
                detail.contains(keyword.as_str()),
                "strict detail {detail:?} lacks {keyword:?}"
            );
        }
        (want, got) => panic!("outcome disagreement:\n library {got:?}\n model {want:?}"),
    }
}

fn check_report(r: &HandshakeReport, m: &Model, sc: &Scenario, run: &Run) {
    assert!(
        !r.user_authenticated,
        "user_authenticated must always be false"
    );
    assert_eq!(
        r.client_identification,
        format!("SSH-2.0-{SOFTWARE}").into_bytes()
    );
    assert_eq!(
        r.phase,
        Phase::Finished,
        "after the run the phase is Finished"
    );
    match &run.outcome {
        Some(o) => {
            assert_eq!(r.outcome.as_ref(), Some(o));
            assert_eq!(o.is_complete(), *o == HandshakeOutcome::Completed);
            assert!(!o.code().is_empty());
        }
        None => assert_eq!(
            r.outcome,
            Some(HandshakeOutcome::Eof {
                phase: m.phase_at_end
            })
        ),
    }
    if sc.ident != IdentKind::V15 {
        assert_eq!(r.server_prelude_lines, sc.prelude);
        let ident = r
            .server_identification
            .as_ref()
            .expect("identification parsed");
        assert_eq!(ident.line, ident_line(sc).0);
    }
    assert_eq!(
        r.kexinit_was_first_packet, m.kexinit_was_first,
        "kexinit_was_first_packet"
    );
    assert_eq!(r.strict_kex, m.strict, "strict_kex");
    assert_eq!(r.selected, m.selected, "selected");
    assert_eq!(r.advertised.server.is_some(), m.server_seen);
    assert_eq!(
        r.server_guess_discarded, m.guess_discarded,
        "server_guess_discarded"
    );
    assert_eq!(r.skipped_messages, m.skipped, "skipped_messages");
    assert_eq!(r.signature_valid, m.signature_valid, "signature_valid");
    assert_eq!(
        r.signature_error.is_some(),
        m.signature_valid == Some(false)
    );
    if let Some(err) = &r.signature_error {
        let want = match sc.reply {
            Reply::SigAlgRsa => "does not match key algorithm",
            Reply::SigTrailing => "trailing byte",
            Reply::SigShort => "expected 64",
            _ => "does not verify",
        };
        assert!(err.contains(want), "signature_error {err:?} lacks {want:?}");
    }
    assert_eq!(r.trust, m.trust, "trust");
    assert_eq!(r.newkeys_sent, m.newkeys_sent, "newkeys_sent");
    assert_eq!(r.newkeys_received, m.newkeys_received, "newkeys_received");
    assert_eq!(
        r.protected_packets_sent, m.protected_sent,
        "protected_packets_sent"
    );
    assert_eq!(
        r.protected_packets_received, m.protected_received,
        "protected_packets_received"
    );
    // Sequence numbers: reset at NEWKEYS under strict KEX, else cumulative.
    let unprotected_sent = m
        .client_messages
        .iter()
        .filter(|&&n| matches!(n, 20 | 30 | 21))
        .count() as u32;
    let (want_send, want_recv) = if m.strict_active {
        (
            if m.newkeys_sent {
                m.protected_sent
            } else {
                unprotected_sent
            },
            if m.newkeys_received {
                m.protected_received
            } else {
                m.unprotected_received
            },
        )
    } else {
        (
            unprotected_sent + m.protected_sent,
            m.unprotected_received + m.protected_received,
        )
    };
    assert_eq!(r.send_sequence, want_send, "send_sequence");
    assert_eq!(r.receive_sequence, want_recv, "receive_sequence");
    match &r.host_key {
        Some(hk) => {
            assert!(m.host_key_seen);
            assert_eq!(hk.algorithm, "ssh-ed25519");
            assert_eq!(hk.blob_len, 51);
            let digest: [u8; 32] = Sha256::digest(&run.k_s).into();
            assert_eq!(
                hk.fingerprint,
                Sha256Fingerprint::from_bytes(digest),
                "fingerprint is sha2 over K_S"
            );
        }
        None => assert!(!m.host_key_seen, "host key should have been recorded"),
    }
    let ext = r.ext_info.as_ref().map(|e| ExtInfoModel {
        received: e.received,
        server_sig_algs: e.server_sig_algs.clone(),
        extension_names: e.extension_names.clone(),
    });
    assert_eq!(ext, m.ext_info, "ext_info");
    assert_eq!(r.service_accepted, m.service_accepted, "service_accepted");
    assert_eq!(
        r.server_disconnect
            .as_ref()
            .map(|d| (d.reason_code, d.description.clone())),
        m.server_disconnect,
        "server_disconnect"
    );
    // Session id iff the signature verified, and then the harness's H.
    assert_eq!(
        run.session_id.is_some(),
        m.signature_valid == Some(true),
        "session_id presence"
    );
    if let (Some(sid), Some(h)) = (run.session_id, run.h) {
        assert_eq!(sid, h, "session_id equals the harness exchange hash");
    }
}

/// Parses the client output: identification line, unprotected packets,
/// then protected packets opened with the harness's client→server keys.
fn check_client_output(run: &Run, m: &Model) {
    let out = &run.output;
    let line_end = out
        .iter()
        .position(|&b| b == b'\n')
        .expect("identification line")
        + 1;
    assert_eq!(
        &out[..line_end],
        format!("SSH-2.0-{SOFTWARE}\r\n").as_bytes()
    );
    let (unprotected, consumed) = parse_unprotected(&out[line_end..]);
    let mut numbers: Vec<u8> = Vec::new();
    for p in &unprotected {
        assert!(!p.is_empty(), "client sent an empty payload");
        numbers.push(p[0]);
        match p[0] {
            20 => assert!(p.len() > 17),
            30 => assert_eq!(p.len(), 37),
            21 => assert_eq!(p.len(), 1),
            n => panic!("unexpected unprotected client message {n}"),
        }
    }
    let mut rest = &out[line_end + consumed..];
    if let Some(keys) = run.c2s {
        let mut opener = Gcm::new(&keys.key, &keys.iv);
        while !rest.is_empty() {
            let (payload, total) = opener
                .open(rest)
                .expect("client protected packet authenticates under the harness keys");
            assert!(!payload.is_empty());
            numbers.push(payload[0]);
            match payload[0] {
                5 => {
                    let mut want = vec![5u8];
                    want.extend(string(b"ssh-userauth"));
                    assert_eq!(payload, want, "SERVICE_REQUEST names ssh-userauth");
                }
                1 => {
                    assert_eq!(
                        &payload[1..5],
                        &[0, 0, 0, 11],
                        "DISCONNECT reason BY_APPLICATION"
                    );
                }
                n => panic!("unexpected protected client message {n}"),
            }
            rest = &rest[total..];
        }
    } else {
        assert!(
            rest.is_empty(),
            "protected client bytes without keys: {} bytes",
            rest.len()
        );
    }
    assert!(
        !numbers.contains(&50),
        "the client must never send USERAUTH_REQUEST"
    );
    for n in &numbers {
        assert!(
            matches!(n, 20 | 30 | 21 | 5 | 1),
            "message {n} outside the allowed set"
        );
    }
    assert_eq!(numbers, m.client_messages, "client message sequence");
    if m.trust.is_some_and(|t| !t.is_trusted()) {
        assert!(
            !numbers.contains(&21),
            "no NEWKEYS after an untrusted decision"
        );
    }
}

fn check_entropy_failure(sc: &Scenario) {
    let config = HandshakeConfig {
        software_version: String::from(SOFTWARE),
        ..HandshakeConfig::default()
    };
    let mut rng = HarnessRng::failing_after(sc.rng_seed, usize::from(sc.host_seed[0]) % 80);
    match ClientHandshake::new(config.clone(), &mut rng) {
        Err(HandshakeInitError::Entropy(_)) => {}
        other => panic!("short entropy must fail construction: {other:?}"),
    }
    // A single feed beyond `room()` is rejected before copying and ends the
    // handshake; exactly `room()` bytes are accepted.
    let mut hs =
        ClientHandshake::new(config.clone(), &mut HarnessRng::new(sc.rng_seed)).expect("valid");
    let room = hs.room();
    let extra = usize::from(sc.host_seed[1]) % 3 + 1;
    hs.feed(&vec![0x55u8; room + extra]);
    assert_eq!(hs.pending_bytes(), 0, "nothing copied on overflow");
    let want = HandshakeOutcome::InputOverflow(tatami_tcp::initial::InputOverflow {
        capacity: room,
        pending: 0,
        offered: room + extra,
    });
    assert!(matches!(hs.step(), Step::Finished(o) if *o == want));
    assert_eq!(hs.input_ended(), want);
    let mut hs = ClientHandshake::new(config, &mut HarnessRng::new(sc.rng_seed)).expect("valid");
    hs.feed(&vec![0x55u8; room]);
    assert_eq!(hs.pending_bytes(), room);
    assert_eq!(hs.room(), 0);
}

fuzz_target!(|data: &[u8]| {
    let sc = gen_scenario(data);
    if sc.entropy_fail {
        check_entropy_failure(&sc);
        return;
    }
    let ours = Lists::tatami_client([0; 16], sc.advertise_ext_info, sc.offer_strict_kex);
    let negotiated = negotiate_ref::negotiate(&ours, &sc.server);
    let strict_eval = negotiate_ref::strict(&ours, &sc.server);
    let m = model(&sc, negotiated, strict_eval);

    let a = run(&sc);
    if std::env::var_os("TATAMI_FUZZ_TRACE").is_some() {
        eprintln!(
            "TRACE outcome={:?} client={:?}",
            a.outcome, m.client_messages
        );
    }
    check_outcome(&a.outcome, &m);
    check_report(&a.report, &m, &sc, &a);
    check_client_output(&a, &m);

    // Same scenario, byte-at-a-time: identical bytes, outcome and report.
    let one = Scenario {
        chunk: ChunkMode::ByteAtATime,
        ..sc.clone()
    };
    let b = run(&one);
    assert_eq!(b.outcome, a.outcome, "chunking changed the outcome");
    assert_eq!(b.report, a.report, "chunking changed the report");
    assert_eq!(b.output, a.output, "chunking changed the client bytes");
    assert_eq!(b.session_id, a.session_id);
});
