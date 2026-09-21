#![no_main]
//! `tatami_tcp::observer::Observer` (server side) under three delivery
//! schedules, bounded configurations, banner-only mode, unexpected client
//! input, EOF, and deliberately oversized feeds.
//!
//! # Input layout
//!
//! ```text
//! byte 0   bits 0-2: configuration (see `observer_config`)
//!            0 default; 1 banner_only; 2 max_packets 1; 3 max_packets 2 +
//!            max_bytes 64; 4 packet cap 64; 5 identification line 32 +
//!            unexpected_sample 4; 6 unexpected_sample 0 + max_bytes 20;
//!            7 packet cap 16 + identification line 512 + max_packets 1
//!          bit 3:    a fuzz software version follows (len u8, bytes)
//!          bits 4-5: chunk schedule selector (`ChunkMode::from_selector`)
//!          bit 6:    signal EOF after the stream
//!          bit 7:    structured stream (else the rest is the raw stream)
//! byte     n_sched (mod 16), then n_sched chunk sizes (0 counts as 1)
//! u16      k: stream bytes fed before the deliberately oversized feed
//! rest     `stream_gen::generate` description (client role) | raw stream bytes
//! ```
//!
//! The client-role description has no prelude; instead an optional run of
//! junk bytes (never starting with `SSH-`) precedes the identification to
//! exercise the unexpected-input policy. KEXINITs carry client markers
//! (`ext-info-c`, `kex-strict-c-v00@openssh.com`, and the standard
//! `kex-strict-c`) when requested.
//!
//! # Oracles
//!
//! - Everything `tcp_probe` checks (driver agreement, `room()` respected,
//!   progress, monotonic stage, bounded drains, stable terminal, model of
//!   the structured description, oversized feed), for the observer.
//! - Role policy: input not starting with `SSH-` ends the observation with
//!   `UnexpectedInput` whose `sample` is the first
//!   `min(fed, unexpected_sample)` bytes of the stream at the moment of the
//!   decision and `truncated` says whether more had been buffered; the
//!   buffer is then empty. Across drivers only "all yield UnexpectedInput
//!   and each sample is a stream prefix" is compared.
//! - `banner_only`: `BannerOnly` right after the identification event; no
//!   packet is ever decoded (no `Skipped`, never a `Proposal`).
//! - `1.99` and LF-only are anomalies on the identification while the
//!   observation continues; `SSH-1.5-` is `Error(Ident(UnsupportedVersion))`.
//! - `classify_kex_name` on every advertised kex name matches the reference
//!   marker table; `ObservationOutcome::code()` is one of the seven
//!   documented strings and consistent with its variant; the outcome set is
//!   closed (exhaustive match: nothing negotiated or authenticated).
//! - `server_identification()` is `SSH-2.0-<software>\r\n`, ≤ 255 bytes.

use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::tcp_support::drive::{
    End, Ev, MAX_STEPS, OUTCOME_CODES, Run, assert_ident_phase, assert_same_run, drive,
    expected_outcome_code,
};
use tatami_fuzz_protocol::tcp_support::stream_gen::{self, ModelLimits, Role};
use tatami_fuzz_protocol::tcp_support::{ChunkMode, Cursor, ident_ref, msg_ref};
use tatami_tcp::ident::{IdentLimits, LineTerminator, VersionSupport};
use tatami_tcp::initial::{InitialError, InitialLimits, InputOverflow};
use tatami_tcp::observer::{
    ObservationOutcome, Observer, ObserverConfig, ObserverStage, ObserverStep,
};
use tatami_tcp::packet::{HEADER_LEN, PacketLimits};
use tatami_wire::kexinit::{KexName, classify_kex_name};

fn observer_config(sel: u8) -> ObserverConfig {
    let base = ObserverConfig::default();
    let initial = InitialLimits::default();
    match sel & 7 {
        0 => base,
        1 => ObserverConfig {
            banner_only: true,
            ..base
        },
        2 => ObserverConfig {
            initial: InitialLimits {
                max_packets: 1,
                ..initial
            },
            ..base
        },
        3 => ObserverConfig {
            initial: InitialLimits {
                max_packets: 2,
                max_bytes: 64,
                ..initial
            },
            ..base
        },
        4 => ObserverConfig {
            initial: InitialLimits {
                packet: PacketLimits {
                    max_packet_length: 64,
                },
                ..initial
            },
            ..base
        },
        5 => ObserverConfig {
            max_identification_line: 32,
            unexpected_sample: 4,
            ..base
        },
        6 => ObserverConfig {
            unexpected_sample: 0,
            initial: InitialLimits {
                max_bytes: 20,
                ..initial
            },
            ..base
        },
        _ => ObserverConfig {
            initial: InitialLimits {
                packet: PacketLimits {
                    max_packet_length: 16,
                },
                max_packets: 1,
                ..initial
            },
            max_identification_line: 512,
            ..base
        },
    }
}

fn model_limits(c: &ObserverConfig) -> ModelLimits {
    ModelLimits {
        ident: IdentLimits {
            max_prelude_lines: 0,
            max_prelude_bytes: 0,
            max_prelude_line: c.max_identification_line,
            max_identification_line: c.max_identification_line,
        },
        cap: c.initial.packet.max_packet_length,
        max_packets: c.initial.max_packets,
        max_bytes: c.initial.max_bytes,
        banner_only: c.banner_only,
    }
}

/// Role-policy checks on one finished run.
fn check_role_policy(run: &Run, stream: &[u8], config: &ObserverConfig) {
    assert!(
        !run.events.iter().any(|e| matches!(e, Ev::Prelude { .. })),
        "a server observer never reports prelude lines"
    );
    let ident = run.events.iter().find_map(|e| match e {
        Ev::Ident(i) => Some(i),
        _ => None,
    });
    if let Some(i) = ident {
        assert!(i.line.starts_with(b"SSH-"));
        let lf = i.terminator == LineTerminator::Lf;
        let compat = i.support == VersionSupport::Ssh2Compatibility;
        assert_eq!(compat, i.protocol_version == "1.99");
        assert_eq!(i.anomalies().count(), usize::from(lf) + usize::from(compat));
        assert!(
            !matches!(run.end, Some(End::Error(InitialError::Ident(_)))),
            "identification accepted and then rejected"
        );
    } else {
        assert!(
            !matches!(
                run.end,
                Some(End::Proposal(_) | End::BannerOnly | End::Disconnected { .. })
            ),
            "packet-phase outcome without an identification"
        );
    }
    if config.banner_only {
        assert!(
            !matches!(run.end, Some(End::Proposal(_))),
            "banner-only decoded a proposal"
        );
        assert!(
            !run.events.iter().any(|e| matches!(e, Ev::Skipped(_))),
            "banner-only decoded a packet"
        );
        if ident.is_some() {
            assert_eq!(run.end, Some(End::BannerOnly));
            assert_eq!(
                run.events.len(),
                1,
                "banner-only stops right after the identification"
            );
        }
    }
    match &run.end {
        Some(End::UnexpectedInput { sample, truncated }) => {
            let fed = run
                .decision_pending
                .expect("driver records pending bytes at the decision");
            let n = fed.min(config.unexpected_sample);
            assert_eq!(sample, &stream[..n], "sample is the fed prefix, bounded");
            assert_eq!(*truncated, fed > n, "truncated flag");
            assert!(sample.len() <= config.unexpected_sample);
            assert!(stream.starts_with(sample));
            assert!(
                ident_ref::starts_ident(&stream[..fed]) == Some(false),
                "unexpected input decided while the prefix could still be SSH-"
            );
            assert!(ident.is_none() && run.events.is_empty());
        }
        Some(End::Proposal(p)) => {
            for name in &p.kexinit.kex_algorithms {
                let class = classify_kex_name(name.as_bytes());
                assert_eq!(
                    class,
                    msg_ref::kex_name(name.as_bytes()),
                    "marker table for {name}"
                );
                assert_eq!(class.is_marker(), class != KexName::Method);
            }
            assert_eq!(p.raw_payload.first(), Some(&20));
        }
        _ => {}
    }
    if stream.len() >= 4 && !stream.starts_with(b"SSH-") {
        assert!(
            matches!(run.end, Some(End::UnexpectedInput { .. })),
            "client input not starting with SSH- must be unexpected input: {:?}",
            run.end
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let b0 = cur.u8();
    let mut config = observer_config(b0 & 7);
    if b0 & 8 != 0 {
        let n = usize::from(cur.u8());
        let sw = String::from_utf8_lossy(cur.take(n)).into_owned();
        let valid = ident_ref::local_software_version_ok(sw.as_bytes());
        let candidate = ObserverConfig {
            software_version: sw.clone(),
            ..config.clone()
        };
        match Observer::new(&candidate) {
            Ok(o) => {
                assert!(
                    valid,
                    "Observer::new accepted an invalid software version {sw:?}"
                );
                assert_eq!(
                    o.server_identification(),
                    format!("SSH-2.0-{sw}\r\n").as_bytes()
                );
                config.software_version = sw;
            }
            Err(e) => assert!(
                !valid,
                "Observer::new rejected a valid software version {sw:?}: {e}"
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
    let cap = config.initial.packet.max_packet_length;
    let generated = structured.then(|| stream_gen::generate(&mut cur, Role::Client, cap));
    let stream: Vec<u8> = match &generated {
        Some(g) => g.bytes.clone(),
        None => cur.rest().to_vec(),
    };

    let make = || Observer::new(&config).expect("configuration table entries are valid");
    let observer = make();
    let line = observer.server_identification();
    assert_eq!(
        line,
        format!("SSH-2.0-{}\r\n", config.software_version).as_bytes()
    );
    assert!(line.len() <= 255);
    assert_eq!(
        observer.server_identification_line(),
        &line[..line.len() - 2]
    );
    let capacity = observer.room();
    assert_eq!(capacity, config.buffer_capacity());
    assert!(capacity >= cap as usize + HEADER_LEN + config.max_identification_line);
    assert_eq!(observer.stage(), ObserverStage::ClientIdentification);
    assert_eq!(OUTCOME_CODES.len(), 7);

    let mut by_byte = make();
    let byte_run = drive(&mut by_byte, &stream, &ChunkMode::ByteAtATime, eof);
    let mut by_chunk = make();
    let chunk_run = drive(&mut by_chunk, &stream, &mode, eof);
    assert_same_run(&byte_run, &chunk_run, "byte-at-a-time vs chunked");
    check_role_policy(&byte_run, &stream, &config);
    check_role_policy(&chunk_run, &stream, &config);
    // Where the observer does not intercept (the stream starts with `SSH-`
    // or is still a prefix of it), the identification phase must match the
    // reference reader under the observer's own limits (prelude forbidden).
    if ident_ref::starts_ident(&stream) != Some(false) {
        assert_ident_phase(&byte_run, &stream, model_limits(&config).ident, eof);
    }
    if let Some(End::Proposal(p)) = &byte_run.end {
        assert_eq!(p.unexamined_bytes, 0);
    }
    if stream.len() <= capacity {
        let mut all = make();
        let all_run = drive(&mut all, &stream, &ChunkMode::All, eof);
        assert_same_run(&all_run, &byte_run, "all-at-once vs byte-at-a-time");
        check_role_policy(&all_run, &stream, &config);
        if let (Some(End::Proposal(a)), Some(End::Proposal(c))) = (&all_run.end, &chunk_run.end) {
            assert!(c.unexamined_bytes <= a.unexamined_bytes);
        }
        if let Some(End::UnexpectedInput { sample, truncated }) = &all_run.end {
            // All at once: the whole stream was buffered at the decision.
            let n = stream.len().min(config.unexpected_sample);
            assert_eq!(sample, &stream[..n]);
            assert_eq!(*truncated, stream.len() > n);
        }
    }

    if let Some(g) = &generated
        && !g.mutated
    {
        let exp = stream_gen::expect(g, &model_limits(&config));
        stream_gen::check_expectation(g, &byte_run, &exp, eof);
    }

    // Oversized single feed: rejected before copying.
    let mut o = make();
    let k = overflow_prefix.min(stream.len()).min(o.room());
    o.feed(&stream[..k]);
    let mut settled = None;
    for _ in 0..MAX_STEPS {
        match o.step() {
            ObserverStep::NeedMore => {
                settled = Some(false);
                break;
            }
            ObserverStep::Event(_) => {}
            ObserverStep::Finished(_) => {
                settled = Some(true);
                break;
            }
        }
    }
    let finished = settled.expect("observer livelocked while draining the overflow prefix");
    if !finished {
        let room = o.room();
        let pending = o.pending_bytes();
        let offered = room + 1;
        // Content is irrelevant: the observer must refuse before reading it.
        o.feed(&vec![0u8; offered]);
        assert_eq!(
            o.pending_bytes(),
            pending,
            "oversized feed must copy nothing"
        );
        assert_eq!(o.stage(), ObserverStage::Finished);
        let expected = ObservationOutcome::Error(InitialError::InputOverflow(InputOverflow {
            capacity,
            pending,
            offered,
        }));
        assert_eq!(expected.code(), "protocol_error");
        assert_eq!(expected_outcome_code(&expected), "protocol_error");
        assert_eq!(o.step(), ObserverStep::Finished(expected.clone()));
        assert_eq!(o.input_ended(), expected);
    }
});
