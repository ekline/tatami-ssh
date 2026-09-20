#![no_main]
//! `tatami_tcp::probe::Probe` (client side) under three delivery schedules,
//! bounded configurations, EOF, and deliberately oversized feeds.
//!
//! # Input layout
//!
//! ```text
//! byte 0   bits 0-2: configuration (see `probe_config`)
//!            0 default; 1 max_packets 1; 2 max_packets 2 + max_bytes 64;
//!            3 max_packets 3 + identification line 512; 4 packet cap 64;
//!            5 tiny ident limits (1 line / 40 bytes / line 20 / ident 32);
//!            6 max_bytes 20; 7 packet cap 16 + prelude forbidden + max_packets 1
//!          bit 3:    a fuzz software version follows (len u8, bytes)
//!          bits 4-5: chunk schedule selector (`ChunkMode::from_selector`)
//!          bit 6:    signal EOF after the stream
//!          bit 7:    structured stream (else the rest is the raw stream)
//! byte     n_sched (mod 16), then n_sched chunk sizes (0 counts as 1)
//! u16      k: stream bytes fed before the deliberately oversized feed
//! rest     `stream_gen::generate` description (server role) | raw stream bytes
//! ```
//!
//! The structured description yields prelude lines, an identification with
//! fuzz fields (2.0 / 1.99 / 1.5 / LF-only / invalid syntax), pre-KEX
//! messages framed with `encode_initial_packet` (IGNORE up to the packet cap,
//! DEBUG, UNIMPLEMENTED, DISCONNECT, NEWKEYS, method-specific, unexpected
//! numbers, empty payload, oversized claim), an optional KEXINIT with distinct
//! directional lists, server markers, nonzero reserved, empty required lists
//! or truncation, trailing bytes, and optional raw mutation.
//!
//! # Oracles
//!
//! - `client_identification()` is `SSH-2.0-<software>\r\n`, at most 255
//!   bytes; `Probe::new` accepts exactly the software versions the reference
//!   token/length rule accepts.
//! - Byte-at-a-time, fuzz-chunked and (when the stream fits `room()`)
//!   all-at-once delivery agree on the event sequence and the terminal
//!   outcome, except `Proposal::unexamined_bytes` (byte-at-a-time is 0 and
//!   chunked is at most all-at-once) which is chunk-dependent by design.
//! - Every driver respects `room()`; a full buffer must have produced
//!   progress or an error; each `Event` consumes bytes or advances the
//!   stage; stages are monotonic; a drain is bounded (panic on livelock).
//! - After `Finished`, `step()` twice returns the identical value,
//!   `feed` is ignored, and `input_ended()` repeats the end.
//! - Unmutated structured streams match a sequential model over the
//!   description: prelude lines, identification fields and anomalies,
//!   skipped messages, budgets (`PacketBudgetExceeded`,
//!   `ByteBudgetExceeded`, `TooLarge`), and the decoded proposal equals the
//!   generated lists/cookie/flags with nonzero-reserved / empty-list
//!   anomalies.
//! - A single feed of `room() + 1` bytes ends the probe with
//!   `InputOverflow { capacity, pending, offered }` and copies nothing.

use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::tcp_support::drive::{
    End, MAX_STEPS, assert_ident_phase, assert_same_run, drive,
};
use tatami_fuzz_protocol::tcp_support::stream_gen::{self, ModelLimits, Role};
use tatami_fuzz_protocol::tcp_support::{ChunkMode, Cursor, ident_ref, msg_ref};
use tatami_tcp::ident::IdentLimits;
use tatami_tcp::initial::InputOverflow;
use tatami_tcp::packet::{HEADER_LEN, PacketLimits};
use tatami_tcp::probe::{Probe, ProbeConfig, ProbeEnd, ProbeError, Stage, Step};
use tatami_wire::kexinit::classify_kex_name;

fn probe_config(sel: u8) -> ProbeConfig {
    let base = ProbeConfig::default();
    match sel & 7 {
        0 => base,
        1 => ProbeConfig {
            max_packets_before_kexinit: 1,
            ..base
        },
        2 => ProbeConfig {
            max_packets_before_kexinit: 2,
            max_bytes_before_kexinit: 64,
            ..base
        },
        3 => ProbeConfig {
            max_packets_before_kexinit: 3,
            ident: IdentLimits {
                max_identification_line: 512,
                ..IdentLimits::default()
            },
            ..base
        },
        4 => ProbeConfig {
            packet: PacketLimits {
                max_packet_length: 64,
            },
            ..base
        },
        5 => ProbeConfig {
            ident: IdentLimits {
                max_prelude_lines: 1,
                max_prelude_bytes: 40,
                max_prelude_line: 20,
                max_identification_line: 32,
            },
            ..base
        },
        6 => ProbeConfig {
            max_bytes_before_kexinit: 20,
            ..base
        },
        _ => ProbeConfig {
            packet: PacketLimits {
                max_packet_length: 16,
            },
            ident: IdentLimits {
                max_prelude_lines: 0,
                max_prelude_bytes: 0,
                ..IdentLimits::default()
            },
            max_packets_before_kexinit: 1,
            ..base
        },
    }
}

fn model_limits(c: &ProbeConfig) -> ModelLimits {
    ModelLimits {
        ident: c.ident,
        cap: c.packet.max_packet_length,
        max_packets: c.max_packets_before_kexinit,
        max_bytes: c.max_bytes_before_kexinit,
        banner_only: false,
    }
}

fn check_proposal_names(end: &Option<End>) {
    if let Some(End::Proposal(p)) = end {
        for name in &p.kexinit.kex_algorithms {
            let class = classify_kex_name(name.as_bytes());
            assert_eq!(
                class,
                msg_ref::kex_name(name.as_bytes()),
                "marker table for {name}"
            );
            assert_eq!(
                class.is_marker(),
                class != tatami_wire::kexinit::KexName::Method
            );
        }
        assert!(
            p.raw_payload.first() == Some(&20),
            "raw payload is the KEXINIT"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let b0 = cur.u8();
    let mut config = probe_config(b0 & 7);
    if b0 & 8 != 0 {
        let n = usize::from(cur.u8());
        let sw = String::from_utf8_lossy(cur.take(n)).into_owned();
        let valid = ident_ref::local_software_version_ok(sw.as_bytes());
        let candidate = ProbeConfig {
            software_version: sw.clone(),
            ..config.clone()
        };
        match Probe::new(candidate) {
            Ok(p) => {
                assert!(
                    valid,
                    "Probe::new accepted an invalid software version {sw:?}"
                );
                assert_eq!(
                    p.client_identification(),
                    format!("SSH-2.0-{sw}\r\n").as_bytes()
                );
                config.software_version = sw;
            }
            Err(e) => assert!(
                !valid,
                "Probe::new rejected a valid software version {sw:?}: {e}"
            ),
        }
    }
    let chunk_sel = (b0 >> 4) & 3;
    let eof = b0 & 0x40 != 0;
    let structured = b0 & 0x80 != 0;
    let n_sched = usize::from(cur.u8()) % 16;
    let sched = cur.take(n_sched).to_vec();
    let mode = ChunkMode::from_selector(chunk_sel, &sched);
    let overflow_prefix = usize::from(cur.u16());
    let cap = config.packet.max_packet_length;
    let generated = structured.then(|| stream_gen::generate(&mut cur, Role::Server, cap));
    let stream: Vec<u8> = match &generated {
        Some(g) => g.bytes.clone(),
        None => cur.rest().to_vec(),
    };

    let make = || Probe::new(config.clone()).expect("configuration table entries are valid");
    let probe = make();
    let line = probe.client_identification();
    assert_eq!(
        line,
        format!("SSH-2.0-{}\r\n", config.software_version).as_bytes()
    );
    assert!(line.len() <= 255);
    assert_eq!(probe.client_identification_line(), &line[..line.len() - 2]);
    let capacity = probe.room();
    assert_eq!(capacity, config.buffer_capacity());
    assert!(capacity >= cap as usize + HEADER_LEN + config.ident.max_identification_line);
    assert_eq!(probe.stage(), Stage::Identification);
    assert_eq!(probe.pending_bytes(), 0);

    let mut by_byte = make();
    let byte_run = drive(&mut by_byte, &stream, &ChunkMode::ByteAtATime, eof);
    let mut by_chunk = make();
    let chunk_run = drive(&mut by_chunk, &stream, &mode, eof);
    assert_same_run(&byte_run, &chunk_run, "byte-at-a-time vs chunked");

    check_proposal_names(&byte_run.end);
    // The identification phase (prelude lines, identification or error)
    // must match the reference reader under the probe's limits.
    assert_ident_phase(&byte_run, &stream, config.ident, eof);

    if let Some(End::Proposal(p)) = &byte_run.end {
        assert_eq!(
            p.unexamined_bytes, 0,
            "byte-at-a-time completes the KEXINIT on its last byte"
        );
    }
    if stream.len() <= capacity {
        let mut all = make();
        let all_run = drive(&mut all, &stream, &ChunkMode::All, eof);
        assert_same_run(&all_run, &byte_run, "all-at-once vs byte-at-a-time");
        if let (Some(End::Proposal(a)), Some(End::Proposal(c))) = (&all_run.end, &chunk_run.end) {
            assert!(
                c.unexamined_bytes <= a.unexamined_bytes,
                "chunked cannot leave more unexamined than all-at-once"
            );
            assert!(a.unexamined_bytes < stream.len());
        }
    }

    if let Some(g) = &generated
        && !g.mutated
    {
        let exp = stream_gen::expect(g, &model_limits(&config));
        stream_gen::check_expectation(g, &byte_run, &exp, eof);
    }

    // Oversized single feed: rejected before copying, nothing pending changes.
    let mut p = make();
    let k = overflow_prefix.min(stream.len()).min(p.room());
    p.feed(&stream[..k]);
    let mut settled = None;
    for _ in 0..MAX_STEPS {
        match p.step() {
            Step::NeedMore => {
                settled = Some(false);
                break;
            }
            Step::Event(_) => {}
            Step::Finished(_) => {
                settled = Some(true);
                break;
            }
        }
    }
    let finished = settled.expect("probe livelocked while draining the overflow prefix");
    if !finished {
        let room = p.room();
        let pending = p.pending_bytes();
        let offered = room + 1;
        // Content is irrelevant: the probe must refuse before reading it.
        let too_much = vec![0u8; offered];
        p.feed(&too_much);
        assert_eq!(
            p.pending_bytes(),
            pending,
            "oversized feed must copy nothing"
        );
        assert_eq!(p.stage(), Stage::Finished);
        let expected = ProbeEnd::Error(ProbeError::InputOverflow(InputOverflow {
            capacity,
            pending,
            offered,
        }));
        assert_eq!(p.step(), Step::Finished(expected.clone()));
        assert_eq!(p.input_ended(), expected);
    }
});
