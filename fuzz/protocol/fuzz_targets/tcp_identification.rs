#![no_main]
//! `tatami_tcp::ident::IdentificationReader` against an independent line
//! reader, under two limit configurations and three delivery schedules.
//!
//! # Input layout
//!
//! ```text
//! byte 0   bits 0-1: second limit configuration
//!            0 fuzz-chosen small limits (4 values follow)
//!            1 observer-style: prelude forbidden (0 lines / 0 bytes), lines 255
//!            2 tiny: 1 prelude line, 40 prelude bytes, line 20, identification 32
//!            3 generous: 1000 lines, 65535 bytes, line 4096, identification 4096
//!          bits 2-3: fuzz chunk schedule selector (`ChunkMode::from_selector`)
//!          bits 4-5: terminator transform applied to the raw stream
//!            0 none; 1 bare LF -> CR LF; 2 CR LF -> LF; 3 append CR LF unless
//!            the stream already ends with LF
//! [cfg 0]  prelude_lines u8 (mod 5), prelude_bytes u16 (mod 300),
//!          prelude_line u8 -> 4 + (v mod 60), identification u16 -> 4 + (v mod 600)
//! byte     n_sched (mod 16), then n_sched chunk sizes (0 counts as 1)
//! rest     the byte stream: prelude lines, identification, packet suffix
//! ```
//!
//! Both the default `IdentLimits` and the selected configuration are run.
//! Fuzz-chosen line limits start at four: with fewer than four bytes the
//! reader cannot classify the line, so a smaller limit rejects everything
//! and only the *kind* of error would depend on delivery (a degenerate
//! policy, not a network-reachable distinction).
//!
//! # Oracles
//!
//! - Step sequence (prelude lines with exact bytes and terminator, then the
//!   identification fields or an error, or NeedMore at end of stream) equals
//!   the reference reader in `tcp_support::ident_ref`, which implements line
//!   splitting, the `SSH-` classification, the 255-byte-with-terminator rule,
//!   the prelude budgets and the RFC 4253 §4.2 grammar itself.
//! - All-at-once, byte-at-a-time and fuzz-chunked delivery produce identical
//!   sequences and final results (NeedMore interleaving aside).
//! - `consumed` values sum to the reference offset just past the
//!   identification terminator; the suffix after it is untouched and every
//!   borrowed field is a sub-slice of the caller's buffer.
//! - `Identification::line` is the exact content, comments are raw bytes,
//!   and `OwnedIdentification` preserves all of them losslessly.

use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::tcp_support::ident_ref::{self, RefIdent, RefOutcome};
use tatami_fuzz_protocol::tcp_support::{ChunkMode, Cursor};
use tatami_tcp::ident::{
    IdentError, IdentLimits, IdentStep, Identification, IdentificationReader, LineTerminator,
    OwnedIdentification, VersionSupport, starts_identification,
};

/// Owned copy of an identification for cross-run comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
struct IdentRec {
    line: Vec<u8>,
    terminator: LineTerminator,
    protocol_version: Vec<u8>,
    software_version: Vec<u8>,
    comments: Option<Vec<u8>>,
    support: VersionSupport,
}

impl IdentRec {
    fn from_lib(i: &Identification<'_>) -> Self {
        IdentRec {
            line: i.line.to_vec(),
            terminator: i.terminator,
            protocol_version: i.protocol_version.to_vec(),
            software_version: i.software_version.to_vec(),
            comments: i.comments.map(<[u8]>::to_vec),
            support: i.support,
        }
    }

    fn from_ref(i: &RefIdent<'_>) -> Self {
        IdentRec {
            line: i.line.to_vec(),
            terminator: i.terminator,
            protocol_version: i.protocol_version.to_vec(),
            software_version: i.software_version.to_vec(),
            comments: i.comments.map(<[u8]>::to_vec),
            support: i.support,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Outcome {
    Identification {
        ident: IdentRec,
        consumed_total: usize,
    },
    Error(IdentError),
    Incomplete,
}

type Prelude = Vec<(Vec<u8>, LineTerminator)>;

fn is_subslice(outer: &[u8], inner: &[u8]) -> bool {
    let o = outer.as_ptr_range();
    let i = inner.as_ptr_range();
    i.start >= o.start && i.end <= o.end
}

/// Checks the borrowing and owned-conversion contracts of one identification
/// borrowed from `buf`.
fn check_ident_borrows(buf: &[u8], ident: &Identification<'_>, consumed: usize) {
    assert!(
        is_subslice(buf, ident.line),
        "line must borrow from the buffer"
    );
    assert!(is_subslice(buf, ident.protocol_version));
    assert!(is_subslice(buf, ident.software_version));
    if let Some(c) = ident.comments {
        assert!(is_subslice(buf, c));
    }
    assert_eq!(
        consumed,
        ident.line.len() + ident.terminator.byte_len(),
        "consumed must be content plus the observed terminator"
    );
    assert_eq!(
        ident.line,
        &buf[..ident.line.len()],
        "line must be the exact content bytes"
    );
    assert!(ident.line.starts_with(b"SSH-"));
    let owned = OwnedIdentification::from(*ident);
    assert_eq!(owned.line, ident.line);
    assert_eq!(owned.terminator, ident.terminator);
    assert_eq!(owned.protocol_version.as_bytes(), ident.protocol_version);
    assert_eq!(owned.software_version.as_bytes(), ident.software_version);
    assert_eq!(
        owned.comments.as_deref(),
        ident.comments,
        "comments must stay raw"
    );
    assert_eq!(owned.support, ident.support);
    assert!(
        owned.anomalies().eq(ident.anomalies()),
        "owned and borrowed anomalies differ"
    );
    let lf = ident.terminator == LineTerminator::Lf;
    let compat = ident.support == VersionSupport::Ssh2Compatibility;
    assert_eq!(
        ident.anomalies().count(),
        usize::from(lf) + usize::from(compat)
    );
}

/// Feeds the whole stream, dropping `consumed` bytes after every step.
fn run_all_at_once(stream: &[u8], limits: IdentLimits) -> (Prelude, Outcome) {
    let mut reader = IdentificationReader::new(limits);
    let mut prelude = Vec::new();
    let mut off = 0;
    loop {
        let buf = &stream[off..];
        match reader.feed(buf) {
            Ok(IdentStep::NeedMore) => return (prelude, Outcome::Incomplete),
            Ok(IdentStep::Prelude {
                line,
                terminator,
                consumed,
            }) => {
                assert!(is_subslice(buf, line));
                assert_eq!(consumed, line.len() + terminator.byte_len());
                assert!(consumed >= 1 && consumed <= buf.len());
                assert_ne!(
                    starts_identification(buf),
                    Some(true),
                    "prelude cannot start with SSH-"
                );
                prelude.push((line.to_vec(), terminator));
                assert_eq!(reader.prelude_lines(), prelude.len());
                off += consumed;
            }
            Ok(IdentStep::Identification { ident, consumed }) => {
                check_ident_borrows(buf, &ident, consumed);
                return (
                    prelude,
                    Outcome::Identification {
                        ident: IdentRec::from_lib(&ident),
                        consumed_total: off + consumed,
                    },
                );
            }
            Err(e) => return (prelude, Outcome::Error(e)),
        }
    }
}

/// Accumulates chunks into a buffer, feeding the whole buffer each time and
/// dropping consumed bytes, as the API requires.
fn run_chunked(stream: &[u8], limits: IdentLimits, mode: &ChunkMode) -> (Prelude, Outcome) {
    let mut reader = IdentificationReader::new(limits);
    let mut prelude = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut off = 0;
    let mut desired = mode.desired();
    while off < stream.len() {
        let n = desired.next().unwrap_or(1).max(1).min(stream.len() - off);
        pending.extend_from_slice(&stream[off..off + n]);
        off += n;
        loop {
            match reader.feed(&pending) {
                Ok(IdentStep::NeedMore) => break,
                Ok(IdentStep::Prelude {
                    line,
                    terminator,
                    consumed,
                }) => {
                    assert_eq!(consumed, line.len() + terminator.byte_len());
                    assert!(consumed >= 1 && consumed <= pending.len());
                    prelude.push((line.to_vec(), terminator));
                    pending.drain(..consumed);
                }
                Ok(IdentStep::Identification { ident, consumed }) => {
                    check_ident_borrows(&pending, &ident, consumed);
                    let rec = IdentRec::from_lib(&ident);
                    let consumed_total = off - (pending.len() - consumed);
                    return (
                        prelude,
                        Outcome::Identification {
                            ident: rec,
                            consumed_total,
                        },
                    );
                }
                Err(e) => return (prelude, Outcome::Error(e)),
            }
        }
    }
    (prelude, Outcome::Incomplete)
}

fn check_configuration(stream: &[u8], limits: IdentLimits, mode: &ChunkMode) {
    let (ref_prelude, ref_outcome) = ident_ref::run(stream, limits);
    let expected_prelude: Prelude = ref_prelude.iter().map(|(l, t)| (l.to_vec(), *t)).collect();
    let expected = match ref_outcome {
        RefOutcome::Identification {
            ident,
            consumed_total,
        } => Outcome::Identification {
            ident: IdentRec::from_ref(&ident),
            consumed_total,
        },
        RefOutcome::Error(e) => Outcome::Error(e),
        RefOutcome::Incomplete => Outcome::Incomplete,
    };

    let (prelude, outcome) = run_all_at_once(stream, limits);
    assert_eq!(
        prelude, expected_prelude,
        "prelude lines (all at once) {limits:?}"
    );
    assert_eq!(outcome, expected, "outcome (all at once) {limits:?}");

    if let Outcome::Identification {
        ident,
        consumed_total,
    } = &outcome
    {
        // Consumed accounting: prelude bytes, then the exact line, then the
        // observed terminator; everything after that offset is the packet
        // suffix the reader never looked at.
        let term_len = ident.terminator.byte_len();
        assert_eq!(
            &stream[consumed_total - term_len..*consumed_total],
            match ident.terminator {
                LineTerminator::CrLf => b"\r\n".as_slice(),
                LineTerminator::Lf => b"\n",
            }
        );
        let prelude_len: usize = prelude.iter().map(|(l, t)| l.len() + t.byte_len()).sum();
        assert_eq!(*consumed_total, prelude_len + ident.line.len() + term_len);
        assert_eq!(
            &stream[prelude_len..consumed_total - term_len],
            &ident.line[..]
        );
        assert!(*consumed_total <= stream.len());
        assert!(ident.line.len() + term_len <= limits.max_identification_line);
        assert!(!ident.line.contains(&b'\n') && !ident.line.contains(&b'\r'));
        assert!(prelude.len() <= limits.max_prelude_lines);
        assert!(prelude_len <= limits.max_prelude_bytes);
    }

    for chunk_mode in [&ChunkMode::ByteAtATime, mode] {
        let (p, o) = run_chunked(stream, limits, chunk_mode);
        assert_eq!(
            p, prelude,
            "prelude lines depend on chunking {chunk_mode:?} {limits:?}"
        );
        assert_eq!(
            o, outcome,
            "outcome depends on chunking {chunk_mode:?} {limits:?}"
        );
    }
}

fn transform_terminators(stream: &[u8], kind: u8) -> Vec<u8> {
    match kind {
        1 => {
            let mut out = Vec::with_capacity(stream.len() + 16);
            for (i, &b) in stream.iter().enumerate() {
                if b == b'\n' && (i == 0 || stream[i - 1] != b'\r') {
                    out.push(b'\r');
                }
                out.push(b);
            }
            out
        }
        2 => {
            let mut out = Vec::with_capacity(stream.len());
            for (i, &b) in stream.iter().enumerate() {
                if b == b'\r' && stream.get(i + 1) == Some(&b'\n') {
                    continue;
                }
                out.push(b);
            }
            out
        }
        3 => {
            let mut out = stream.to_vec();
            if out.last() != Some(&b'\n') {
                out.extend_from_slice(b"\r\n");
            }
            out
        }
        _ => stream.to_vec(),
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cur = Cursor::new(data);
    let b0 = cur.u8();
    let second = match b0 & 3 {
        0 => {
            let max_prelude_lines = usize::from(cur.u8()) % 5;
            let max_prelude_bytes = usize::from(cur.u16()) % 300;
            let max_prelude_line = 4 + usize::from(cur.u8()) % 60;
            let max_identification_line = 4 + usize::from(cur.u16()) % 600;
            IdentLimits {
                max_prelude_lines,
                max_prelude_bytes,
                max_prelude_line,
                max_identification_line,
            }
        }
        1 => IdentLimits {
            max_prelude_lines: 0,
            max_prelude_bytes: 0,
            max_prelude_line: 255,
            max_identification_line: 255,
        },
        2 => IdentLimits {
            max_prelude_lines: 1,
            max_prelude_bytes: 40,
            max_prelude_line: 20,
            max_identification_line: 32,
        },
        _ => IdentLimits {
            max_prelude_lines: 1000,
            max_prelude_bytes: 65535,
            max_prelude_line: 4096,
            max_identification_line: 4096,
        },
    };
    let chunk_sel = (b0 >> 2) & 3;
    let transform = (b0 >> 4) & 3;
    let n_sched = usize::from(cur.u8()) % 16;
    let sched = cur.take(n_sched).to_vec();
    let mode = ChunkMode::from_selector(chunk_sel, &sched);
    let stream = transform_terminators(cur.rest(), transform);

    // Reference and library must agree on the prefix classification too.
    for k in 0..=stream.len().min(8) {
        assert_eq!(
            starts_identification(&stream[..k]),
            ident_ref::starts_ident(&stream[..k]),
            "starts_identification on {:?}",
            &stream[..k]
        );
    }

    check_configuration(&stream, IdentLimits::default(), &mode);
    check_configuration(&stream, second, &mode);
});
