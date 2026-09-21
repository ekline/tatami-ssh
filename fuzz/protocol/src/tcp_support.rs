//! Helpers for the TCP stream/probe/observer targets.
//!
//! Harness-only code; never a dependency of a production package.
//!
//! - [`Cursor`]: a forgiving big-endian byte cursor for the self-describing
//!   seed layouts documented at the top of each target. Exhausted reads yield
//!   zero / empty so that short, hand-written seeds are still meaningful.
//! - [`ChunkMode`]: chunk schedules for fragmented delivery.
//! - [`ident_ref`]: an independent RFC 4253 §4.2 line reader (terminator
//!   scanning, prelude budgets, 255-byte rule counted with the observed
//!   terminator, content grammar, `2.0`/`1.99` policy). Oracle for
//!   `tatami_tcp::ident`.
//! - [`packet_ref`]: independent initial-packet header rules and slicing.
//!   Oracle for `tatami_tcp::packet` and `tatami_tcp::initial`.
//! - [`msg_ref`]: independent pre-`KEXINIT` message classification with
//!   small reference decoders, plus a checked driver for `InitialPackets`.
//! - [`stream_gen`]: a structured server/client stream generator with an
//!   expectation model for the probe and observer targets.
//! - [`drive`]: a common driver for the probe/observer state machines that
//!   enforces the progress, buffer-bound and stable-terminal contracts.

use std::iter;

/// Deterministic filler bytes (a small LCG) for content whose value is
/// irrelevant to the property under test.
#[must_use]
pub fn filler(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect()
}

/// Appends an SSH `string` (`uint32` length + bytes).
pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Forgiving big-endian byte cursor over the fuzz input.
#[derive(Clone, Debug)]
pub struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Cursor at the start of `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }

    /// Bytes not yet read.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// `true` once every byte has been read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Up to `n` bytes (fewer if the input is exhausted).
    pub fn take(&mut self, n: usize) -> &'a [u8] {
        let n = n.min(self.remaining());
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        out
    }

    /// Everything that is left.
    pub fn rest(&mut self) -> &'a [u8] {
        self.take(self.remaining())
    }

    /// One byte, or 0 when exhausted.
    pub fn u8(&mut self) -> u8 {
        self.take(1).first().copied().unwrap_or(0)
    }

    /// Big-endian `u16`, zero-padded when exhausted.
    pub fn u16(&mut self) -> u16 {
        let mut v = [0u8; 2];
        let b = self.take(2);
        v[..b.len()].copy_from_slice(b);
        u16::from_be_bytes(v)
    }

    /// Big-endian `u32`, zero-padded when exhausted.
    pub fn u32(&mut self) -> u32 {
        let mut v = [0u8; 4];
        let b = self.take(4);
        v[..b.len()].copy_from_slice(b);
        u32::from_be_bytes(v)
    }

    /// Exactly `n` bytes: what the input still has, padded with [`filler`].
    pub fn take_filled(&mut self, n: usize, seed: u32) -> Vec<u8> {
        let mut out = self.take(n).to_vec();
        if out.len() < n {
            out.extend(filler(n - out.len(), seed));
        }
        out
    }
}

/// How a byte stream is split into feeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkMode {
    /// Everything in one feed (drivers still clip to the machine's room).
    All,
    /// One byte per feed.
    ByteAtATime,
    /// Fixed-size feeds.
    Fixed(usize),
    /// Cycle through a fuzz-provided list of sizes.
    List(Vec<usize>),
}

impl ChunkMode {
    /// Selector 0: the fuzz-provided `list` (each byte one chunk size, 0
    /// counts as 1; an empty list falls back to `Fixed(3)`); 1: `Fixed(3)`;
    /// 2: `Fixed(64)`; 3: `Fixed(7)`.
    #[must_use]
    pub fn from_selector(sel: u8, list: &[u8]) -> ChunkMode {
        match sel & 3 {
            0 if !list.is_empty() => {
                ChunkMode::List(list.iter().map(|&b| usize::from(b).max(1)).collect())
            }
            0 | 1 => ChunkMode::Fixed(3),
            2 => ChunkMode::Fixed(64),
            _ => ChunkMode::Fixed(7),
        }
    }

    /// Infinite sequence of desired chunk sizes (each ≥ 1). Drivers clip
    /// every size to what remains of the stream (and to the machine's room)
    /// and stop when the stream is exhausted.
    #[must_use]
    pub fn desired(&self) -> Box<dyn Iterator<Item = usize> + '_> {
        match self {
            ChunkMode::All => Box::new(iter::repeat(usize::MAX)),
            ChunkMode::ByteAtATime => Box::new(iter::repeat(1)),
            ChunkMode::Fixed(n) => Box::new(iter::repeat((*n).max(1))),
            ChunkMode::List(l) if l.is_empty() => Box::new(iter::repeat(1)),
            ChunkMode::List(l) => Box::new(l.iter().map(|&n| n.max(1)).cycle()),
        }
    }
}

/// Independent reference for the TCP identification exchange.
pub mod ident_ref {
    use tatami_tcp::ident::{
        IdentError, IdentLimits, InvalidIdentification, LineTerminator, VersionSupport,
    };

    /// Mandatory prefix of an identification line.
    pub const PREFIX: &[u8] = b"SSH-";

    /// Fields of a valid identification, all borrowed from the line.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefIdent<'a> {
        pub line: &'a [u8],
        pub terminator: LineTerminator,
        pub protocol_version: &'a [u8],
        pub software_version: &'a [u8],
        pub comments: Option<&'a [u8]>,
        pub support: VersionSupport,
    }

    /// One reference step, mirroring the shape of the library's step.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RefStep<'a> {
        NeedMore,
        Prelude {
            line: &'a [u8],
            terminator: LineTerminator,
            consumed: usize,
        },
        Identification {
            ident: RefIdent<'a>,
            consumed: usize,
        },
    }

    /// RFC 4253 §4.2: printable US-ASCII, no whitespace, no `-`.
    #[must_use]
    pub fn is_token_byte(b: u8) -> bool {
        (0x21..=0x7e).contains(&b) && b != b'-'
    }

    /// Non-empty run of token bytes.
    #[must_use]
    pub fn is_token(t: &[u8]) -> bool {
        !t.is_empty() && t.iter().all(|&b| is_token_byte(b))
    }

    /// Bytes that may not appear anywhere in identification content.
    #[must_use]
    pub fn is_forbidden(b: u8) -> bool {
        matches!(b, b'\r' | b'\n' | 0)
    }

    /// Our own `SSH-2.0-<sw>\r\n` is buildable iff `sw` is a token and the
    /// whole line fits in 255 bytes.
    #[must_use]
    pub fn local_software_version_ok(sw: &[u8]) -> bool {
        is_token(sw) && PREFIX.len() + 3 + 1 + sw.len() + 2 <= 255
    }

    /// First line terminator: `(content_len, terminator)`. A LF preceded by
    /// CR is CR LF; any other LF is a bare LF.
    #[must_use]
    pub fn split_line(buf: &[u8]) -> Option<(usize, LineTerminator)> {
        let lf = buf.iter().position(|&b| b == b'\n')?;
        if lf >= 1 && buf[lf - 1] == b'\r' {
            Some((lf - 1, LineTerminator::CrLf))
        } else {
            Some((lf, LineTerminator::Lf))
        }
    }

    /// `Some(true)` if `buf` starts with `SSH-`, `Some(false)` if it cannot,
    /// `None` if it is a proper prefix of `SSH-` (undecided).
    #[must_use]
    pub fn starts_ident(buf: &[u8]) -> Option<bool> {
        if buf.len() >= PREFIX.len() {
            Some(&buf[..PREFIX.len()] == PREFIX)
        } else if PREFIX.starts_with(buf) {
            None
        } else {
            Some(false)
        }
    }

    /// Grammar `SSH-protoversion-softwareversion [SP comments]` plus the TCP
    /// binding's version policy. `line` must start with `SSH-`.
    ///
    /// Error precedence (documented, not derived): control characters,
    /// then missing separator, then the protocol token, then the software
    /// token, then the version policy.
    pub fn parse_content(
        line: &[u8],
        terminator: LineTerminator,
    ) -> Result<RefIdent<'_>, IdentError> {
        assert!(line.starts_with(PREFIX), "caller classifies the prefix");
        if line.iter().any(|&b| is_forbidden(b)) {
            return Err(IdentError::InvalidIdentification(
                InvalidIdentification::ControlCharacter,
            ));
        }
        let rest = &line[PREFIX.len()..];
        let Some(dash) = rest.iter().position(|&b| b == b'-') else {
            return Err(IdentError::InvalidIdentification(
                InvalidIdentification::MissingSeparator,
            ));
        };
        let protocol_version = &rest[..dash];
        if !is_token(protocol_version) {
            return Err(IdentError::InvalidIdentification(
                InvalidIdentification::BadProtocolVersion,
            ));
        }
        let after = &rest[dash + 1..];
        let (software_version, comments) = match after.iter().position(|&b| b == b' ') {
            Some(sp) => (&after[..sp], Some(&after[sp + 1..])),
            None => (after, None),
        };
        if !is_token(software_version) {
            return Err(IdentError::InvalidIdentification(
                InvalidIdentification::BadSoftwareVersion,
            ));
        }
        let support = match protocol_version {
            b"2.0" => VersionSupport::Ssh2,
            b"1.99" => VersionSupport::Ssh2Compatibility,
            _ => return Err(IdentError::UnsupportedVersion),
        };
        Ok(RefIdent {
            line,
            terminator,
            protocol_version,
            software_version,
            comments,
            support,
        })
    }

    /// Reference incremental reader.
    #[derive(Clone, Debug)]
    pub struct RefReader {
        limits: IdentLimits,
        lines: usize,
        bytes: usize,
    }

    impl RefReader {
        #[must_use]
        pub fn new(limits: IdentLimits) -> Self {
            RefReader {
                limits,
                lines: 0,
                bytes: 0,
            }
        }

        /// Prelude lines accepted so far.
        #[must_use]
        pub fn lines(&self) -> usize {
            self.lines
        }

        /// Examines all unconsumed bytes for the next complete line.
        pub fn feed<'a>(&mut self, buf: &'a [u8]) -> Result<RefStep<'a>, IdentError> {
            let kind = starts_ident(buf);
            let limit = match kind {
                Some(true) => self.limits.max_identification_line,
                Some(false) => self.limits.max_prelude_line,
                // Undecided: only reject if the line cannot fit either bound.
                None => self
                    .limits
                    .max_prelude_line
                    .max(self.limits.max_identification_line),
            };
            let Some((content_len, terminator)) = split_line(buf) else {
                // Without a terminator the line will be at least len + 1
                // bytes, so `len >= limit` already violates the limit.
                if buf.len() >= limit {
                    return Err(if kind == Some(true) {
                        IdentError::IdentificationTooLong
                    } else {
                        IdentError::PreludeLineTooLong
                    });
                }
                return Ok(RefStep::NeedMore);
            };
            let consumed = content_len + terminator.byte_len();
            let line = &buf[..content_len];
            if kind == Some(true) {
                if consumed > self.limits.max_identification_line {
                    return Err(IdentError::IdentificationTooLong);
                }
                let ident = parse_content(line, terminator)?;
                return Ok(RefStep::Identification { ident, consumed });
            }
            // A complete line shorter than four bytes can never be a prefix
            // of `SSH-` (it contains LF), so `kind` is `Some(false)` here.
            assert_eq!(kind, Some(false));
            if consumed > self.limits.max_prelude_line {
                return Err(IdentError::PreludeLineTooLong);
            }
            if self.lines >= self.limits.max_prelude_lines {
                return Err(IdentError::TooManyPreludeLines);
            }
            let total = self.bytes + consumed;
            if total > self.limits.max_prelude_bytes {
                return Err(IdentError::PreludeBytesExceeded);
            }
            self.lines += 1;
            self.bytes = total;
            Ok(RefStep::Prelude {
                line,
                terminator,
                consumed,
            })
        }
    }

    /// Final state of a whole-stream reference run.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RefOutcome<'a> {
        Identification {
            ident: RefIdent<'a>,
            /// Offset just past the identification terminator.
            consumed_total: usize,
        },
        Error(IdentError),
        Incomplete,
    }

    /// Runs the reference reader over a complete stream.
    pub fn run(
        stream: &[u8],
        limits: IdentLimits,
    ) -> (Vec<(&[u8], LineTerminator)>, RefOutcome<'_>) {
        let mut reader = RefReader::new(limits);
        let mut prelude = Vec::new();
        let mut off = 0;
        loop {
            match reader.feed(&stream[off..]) {
                Ok(RefStep::NeedMore) => return (prelude, RefOutcome::Incomplete),
                Ok(RefStep::Prelude {
                    line,
                    terminator,
                    consumed,
                }) => {
                    prelude.push((line, terminator));
                    off += consumed;
                }
                Ok(RefStep::Identification { ident, consumed }) => {
                    return (
                        prelude,
                        RefOutcome::Identification {
                            ident,
                            consumed_total: off + consumed,
                        },
                    );
                }
                Err(e) => return (prelude, RefOutcome::Error(e)),
            }
        }
    }
}

/// Independent reference for initial (unprotected) packet framing.
pub mod packet_ref {
    use std::ops::Range;

    use tatami_tcp::packet::PacketError;

    /// Reference decode result; slices are expressed as ranges into the
    /// input so the caller can compare against the library's borrows.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RefStep {
        NeedMore {
            total_len: Option<usize>,
        },
        Complete {
            payload: Range<usize>,
            padding: Range<usize>,
            total_len: usize,
        },
    }

    /// Rules that need only the four-byte length field, in the documented
    /// precedence: cap, minimum size, alignment. Returns the total length.
    pub fn header(len_bytes: [u8; 4], cap: u32) -> Result<usize, PacketError> {
        let packet_length = u32::from_be_bytes(len_bytes);
        if packet_length > cap {
            return Err(PacketError::TooLarge {
                packet_length,
                limit: cap,
            });
        }
        let total = u64::from(packet_length) + 4;
        if total < 16 {
            return Err(PacketError::TooSmall { packet_length });
        }
        if total % 8 != 0 {
            return Err(PacketError::Misaligned { packet_length });
        }
        Ok(usize::try_from(total).expect("fits on 64-bit hosts"))
    }

    /// Full reference decoder.
    pub fn decode(buf: &[u8], cap: u32) -> Result<RefStep, PacketError> {
        if buf.len() < 4 {
            return Ok(RefStep::NeedMore { total_len: None });
        }
        let total_len = header([buf[0], buf[1], buf[2], buf[3]], cap)?;
        if buf.len() < 5 {
            return Ok(RefStep::NeedMore {
                total_len: Some(total_len),
            });
        }
        let packet_length = total_len - 4;
        let padding_length = usize::from(buf[4]);
        // payload_len = packet_length - padding_length - 1 must not go
        // negative and padding must be at least four bytes.
        if padding_length < 4 || packet_length < padding_length + 1 {
            return Err(PacketError::BadPadding {
                packet_length: packet_length as u32,
                padding_length: buf[4],
            });
        }
        let payload_len = packet_length - padding_length - 1;
        if buf.len() < total_len {
            return Ok(RefStep::NeedMore {
                total_len: Some(total_len),
            });
        }
        Ok(RefStep::Complete {
            payload: 5..5 + payload_len,
            padding: 5 + payload_len..total_len,
            total_len,
        })
    }

    /// Smallest padding `p >= 4` with `(5 + payload_len + p) % 8 == 0`,
    /// found by search rather than arithmetic.
    #[must_use]
    pub fn minimal_padding(payload_len: usize) -> usize {
        (4..12)
            .find(|p| (5 + payload_len + p).is_multiple_of(8))
            .expect("some padding in 4..12 aligns")
    }

    /// Total framed size of a payload with minimal padding.
    #[must_use]
    pub fn framed_len(payload_len: usize) -> usize {
        5 + payload_len + minimal_padding(payload_len)
    }

    /// Largest `packet_length` accepted under `cap` that also satisfies
    /// the size and alignment rules, if any.
    #[must_use]
    pub fn max_packet_length(cap: u32) -> Option<u32> {
        let misalignment = ((u64::from(cap) + 4) % 8) as u32;
        cap.checked_sub(misalignment).filter(|&pl| pl >= 12)
    }
}

/// Independent reference for pre-`KEXINIT` message handling.
pub mod msg_ref {
    use tatami_tcp::initial::{
        InitialError, InitialLimits, InitialPackets, InitialStep, SkippedMessage,
    };
    use tatami_tcp::probe::ProposalAnomaly;
    use tatami_wire::kexinit::{KexName, OwnedKexInit};

    use super::{ChunkMode, packet_ref};

    /// The eight lists RFC 4253 requires to be non-empty, in wire order.
    pub const ALGORITHM_LISTS: [&str; 8] = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
    ];

    /// Reference-decoded KEXINIT.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RefKexInit {
        pub cookie: [u8; 16],
        /// Ten name lists in wire order.
        pub lists: Vec<Vec<Vec<u8>>>,
        pub first_kex_packet_follows: bool,
        pub reserved: u32,
    }

    impl RefKexInit {
        /// The owned form the library is expected to produce.
        #[must_use]
        pub fn to_owned_kexinit(&self) -> OwnedKexInit {
            let s = |l: &Vec<Vec<u8>>| -> Vec<String> {
                l.iter()
                    .map(|n| String::from_utf8(n.clone()).expect("names are validated ASCII"))
                    .collect()
            };
            OwnedKexInit {
                cookie: self.cookie,
                kex_algorithms: s(&self.lists[0]),
                server_host_key_algorithms: s(&self.lists[1]),
                encryption_client_to_server: s(&self.lists[2]),
                encryption_server_to_client: s(&self.lists[3]),
                mac_client_to_server: s(&self.lists[4]),
                mac_server_to_client: s(&self.lists[5]),
                compression_client_to_server: s(&self.lists[6]),
                compression_server_to_client: s(&self.lists[7]),
                languages_client_to_server: s(&self.lists[8]),
                languages_server_to_client: s(&self.lists[9]),
                first_kex_packet_follows: self.first_kex_packet_follows,
                reserved: self.reserved,
            }
        }

        /// Anomalies a proposal report must carry: nonzero reserved first,
        /// then every empty required list in wire order.
        #[must_use]
        pub fn anomalies(&self) -> Vec<ProposalAnomaly> {
            let mut out = Vec::new();
            if self.reserved != 0 {
                out.push(ProposalAnomaly::NonzeroReserved(self.reserved));
            }
            for (i, name) in ALGORITHM_LISTS.iter().enumerate() {
                if self.lists[i].is_empty() {
                    out.push(ProposalAnomaly::EmptyAlgorithmList(name));
                }
            }
            out
        }
    }

    /// Reference classification of one complete payload.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RefMessage {
        Skipped(SkippedMessage),
        Disconnect {
            reason_code: u32,
            description: Vec<u8>,
            language_tag: Vec<u8>,
        },
        KexInit(Box<RefKexInit>),
        /// A recognised message number whose body does not decode.
        Malformed(u8),
        Empty,
        UnsupportedTransition(u8),
        Unexpected(u8),
    }

    struct R<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> R<'a> {
        fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.buf.len() - self.pos < n {
                return None;
            }
            let out = &self.buf[self.pos..self.pos + n];
            self.pos += n;
            Some(out)
        }
        fn u8(&mut self) -> Option<u8> {
            self.bytes(1).map(|b| b[0])
        }
        fn u32(&mut self) -> Option<u32> {
            self.bytes(4)
                .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
        }
        fn string(&mut self) -> Option<&'a [u8]> {
            let len = usize::try_from(self.u32()?).ok()?;
            self.bytes(len)
        }
        fn done(&self) -> bool {
            self.pos == self.buf.len()
        }
    }

    /// `name-list` body: empty, or comma-separated non-empty names of
    /// printable US-ASCII.
    fn name_list(body: &[u8]) -> Option<Vec<Vec<u8>>> {
        if body.is_empty() {
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        for name in body.split(|&b| b == b',') {
            if name.is_empty() || !name.iter().all(|&b| (0x21..=0x7e).contains(&b)) {
                return None;
            }
            out.push(name.to_vec());
        }
        Some(out)
    }

    fn decode_kexinit(payload: &[u8]) -> Option<RefKexInit> {
        let mut r = R {
            buf: payload,
            pos: 0,
        };
        if r.u8()? != 20 {
            return None;
        }
        let cookie: [u8; 16] = r.bytes(16)?.try_into().ok()?;
        let mut lists = Vec::with_capacity(10);
        for _ in 0..10 {
            lists.push(name_list(r.string()?)?);
        }
        let first_kex_packet_follows = r.u8()? != 0;
        let reserved = r.u32()?;
        r.done().then_some(RefKexInit {
            cookie,
            lists,
            first_kex_packet_follows,
            reserved,
        })
    }

    /// Classifies a payload exactly as the pre-`KEXINIT` phase must.
    #[must_use]
    pub fn classify(payload: &[u8]) -> RefMessage {
        let Some(&number) = payload.first() else {
            return RefMessage::Empty;
        };
        let mut r = R {
            buf: payload,
            pos: 1,
        };
        let decoded = match number {
            1 => (|| {
                let reason_code = r.u32()?;
                let description = r.string()?.to_vec();
                let language_tag = r.string()?.to_vec();
                r.done().then_some(RefMessage::Disconnect {
                    reason_code,
                    description,
                    language_tag,
                })
            })(),
            2 => (|| {
                let data = r.string()?;
                r.done()
                    .then_some(RefMessage::Skipped(SkippedMessage::Ignored {
                        data_len: data.len(),
                    }))
            })(),
            3 => (|| {
                let sequence_number = r.u32()?;
                r.done()
                    .then_some(RefMessage::Skipped(SkippedMessage::Unimplemented {
                        sequence_number,
                    }))
            })(),
            4 => (|| {
                let always_display = r.u8()? != 0;
                let message = r.string()?.to_vec();
                let language_tag = r.string()?.to_vec();
                r.done()
                    .then_some(RefMessage::Skipped(SkippedMessage::Debug {
                        always_display,
                        message,
                        language_tag,
                    }))
            })(),
            20 => decode_kexinit(payload).map(|k| RefMessage::KexInit(Box::new(k))),
            21 | 30..=49 => return RefMessage::UnsupportedTransition(number),
            _ => return RefMessage::Unexpected(number),
        };
        decoded.unwrap_or(RefMessage::Malformed(number))
    }

    /// Reference table for `kex_algorithms` entries that are markers, not
    /// methods (RFC 8308 §2.1; draft-ietf-sshm-strict-kex-02 §3.1 in both
    /// the standard and the pre-standard OpenSSH `-v00@openssh.com`
    /// spellings).
    #[must_use]
    pub fn kex_name(name: &[u8]) -> KexName {
        match name {
            b"ext-info-c" => KexName::ExtInfoClient,
            b"ext-info-s" => KexName::ExtInfoServer,
            b"kex-strict-c-v00@openssh.com" | b"kex-strict-c" => KexName::StrictKexClient,
            b"kex-strict-s-v00@openssh.com" | b"kex-strict-s" => KexName::StrictKexServer,
            _ => KexName::Method,
        }
    }

    /// What a step of `InitialPackets` produced, in owned form.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Observed {
        Skipped {
            message: SkippedMessage,
            consumed: usize,
        },
        KexInit {
            kexinit: Box<OwnedKexInit>,
            payload: Vec<u8>,
            consumed: usize,
        },
        Disconnect {
            reason_code: u32,
            description: Vec<u8>,
            language_tag: Vec<u8>,
            consumed: usize,
        },
        Error(InitialError),
    }

    impl Observed {
        fn consumed(&self) -> Option<usize> {
            match self {
                Observed::Skipped { consumed, .. } => Some(*consumed),
                _ => None,
            }
        }
    }

    fn observe(step: InitialStep<'_>) -> Option<Observed> {
        Some(match step {
            InitialStep::NeedMore => return None,
            InitialStep::Skipped { message, consumed } => Observed::Skipped { message, consumed },
            InitialStep::KexInit {
                kexinit,
                payload,
                consumed,
            } => Observed::KexInit {
                kexinit: Box::new(kexinit.to_owned()),
                payload: payload.to_vec(),
                consumed,
            },
            InitialStep::Disconnect {
                disconnect,
                consumed,
            } => Observed::Disconnect {
                reason_code: disconnect.reason_code,
                description: disconnect.description.to_vec(),
                language_tag: disconnect.language_tag.to_vec(),
                consumed,
            },
            InitialStep::Error(e) => Observed::Error(e),
        })
    }

    #[derive(Default)]
    struct Model {
        packets: usize,
        bytes: usize,
    }

    enum ModelStep {
        NeedMore,
        Observed(Observed),
        /// Library must report `Error(Message { number, .. })`; the decoder
        /// detail is fuzzed by the wire-core targets.
        Malformed(u8),
    }

    fn model_step(model: &mut Model, rest: &[u8], limits: &InitialLimits) -> ModelStep {
        let (payload, total_len) = match packet_ref::decode(rest, limits.packet.max_packet_length) {
            Ok(packet_ref::RefStep::NeedMore { .. }) => return ModelStep::NeedMore,
            Err(e) => return ModelStep::Observed(Observed::Error(InitialError::Packet(e))),
            Ok(packet_ref::RefStep::Complete {
                payload, total_len, ..
            }) => (&rest[payload], total_len),
        };
        if model.packets >= limits.max_packets {
            return ModelStep::Observed(Observed::Error(InitialError::PacketBudgetExceeded {
                limit: limits.max_packets,
            }));
        }
        if model.bytes + total_len > limits.max_bytes {
            return ModelStep::Observed(Observed::Error(InitialError::ByteBudgetExceeded {
                limit: limits.max_bytes,
            }));
        }
        model.packets += 1;
        model.bytes += total_len;
        ModelStep::Observed(match classify(payload) {
            RefMessage::Skipped(message) => Observed::Skipped {
                message,
                consumed: total_len,
            },
            RefMessage::Disconnect {
                reason_code,
                description,
                language_tag,
            } => Observed::Disconnect {
                reason_code,
                description,
                language_tag,
                consumed: total_len,
            },
            RefMessage::KexInit(k) => Observed::KexInit {
                kexinit: Box::new(k.to_owned_kexinit()),
                payload: payload.to_vec(),
                consumed: total_len,
            },
            RefMessage::Malformed(n) => return ModelStep::Malformed(n),
            RefMessage::Empty => Observed::Error(InitialError::EmptyPayload),
            RefMessage::UnsupportedTransition(number) => {
                Observed::Error(InitialError::UnsupportedTransition { number })
            }
            RefMessage::Unexpected(number) => {
                Observed::Error(InitialError::UnexpectedMessage { number })
            }
        })
    }

    fn check_step(actual: Option<&Observed>, expected: &ModelStep, index: usize) {
        match (actual, expected) {
            (None, ModelStep::NeedMore) => {}
            (
                Some(Observed::Error(InitialError::Message { number, .. })),
                ModelStep::Malformed(n),
            ) => assert_eq!(number, n, "malformed message number at packet {index}"),
            (Some(a), ModelStep::Observed(e)) => {
                assert_eq!(
                    a, e,
                    "InitialPackets step {index} disagrees with the reference"
                );
            }
            (a, ModelStep::NeedMore) => panic!("packet {index}: library {a:?}, reference NeedMore"),
            (a, ModelStep::Malformed(n)) => {
                panic!("packet {index}: library {a:?}, reference Malformed({n})")
            }
            (a, ModelStep::Observed(e)) => panic!("packet {index}: library {a:?}, reference {e:?}"),
        }
    }

    /// Drives `InitialPackets` over `stream` all at once (checked step by
    /// step against the reference model, including budget counters) and
    /// again with `mode` chunking, asserting both produce the same sequence.
    /// Returns the all-at-once sequence.
    pub fn check_initial_packets(
        stream: &[u8],
        limits: &InitialLimits,
        mode: &ChunkMode,
    ) -> Vec<Observed> {
        let mut ip = InitialPackets::new(*limits);
        let mut model = Model::default();
        let mut off = 0;
        let mut seq = Vec::new();
        loop {
            let rest = &stream[off..];
            let expected = model_step(&mut model, rest, limits);
            let actual = observe(ip.step(rest));
            check_step(actual.as_ref(), &expected, seq.len());
            assert_eq!(ip.packets(), model.packets, "packet counter");
            assert_eq!(ip.bytes(), model.bytes, "byte counter");
            let Some(observed) = actual else { break };
            let consumed = observed.consumed();
            seq.push(observed);
            match consumed {
                Some(c) => {
                    assert!(
                        c >= 16 && off + c <= stream.len(),
                        "consumed {c} out of range"
                    );
                    off += c;
                }
                None => break,
            }
        }

        let mut ip = InitialPackets::new(*limits);
        let mut acc: Vec<u8> = Vec::new();
        let mut off = 0;
        let mut seq2 = Vec::new();
        let mut desired = mode.desired();
        let mut terminal = false;
        while !terminal && off < stream.len() {
            let n = desired.next().unwrap_or(1).max(1).min(stream.len() - off);
            acc.extend_from_slice(&stream[off..off + n]);
            off += n;
            while let Some(observed) = observe(ip.step(&acc)) {
                let consumed = observed.consumed();
                seq2.push(observed);
                match consumed {
                    Some(c) => acc.drain(..c),
                    None => {
                        terminal = true;
                        break;
                    }
                };
            }
        }
        assert_eq!(seq, seq2, "InitialPackets outcome depends on chunking");
        seq
    }
}

/// Common driver for the probe and observer state machines.
pub mod drive {
    use tatami_tcp::ident::{IdentLimits, LineTerminator, OwnedIdentification};
    use tatami_tcp::initial::{InitialError, SkippedMessage};
    use tatami_tcp::observer::{
        ObservationOutcome, Observer, ObserverEvent, ObserverStage, ObserverStep,
    };
    use tatami_tcp::probe::{Probe, ProbeEnd, ProbeEvent, ProposalAnomaly, Stage, Step};
    use tatami_wire::kexinit::OwnedKexInit;

    use super::ChunkMode;
    use super::ident_ref::{self, RefOutcome};

    /// Stage ordinal: identification.
    pub const STAGE_IDENT: u8 = 0;
    /// Stage ordinal: initial packets.
    pub const STAGE_PACKETS: u8 = 1;
    /// Stage ordinal: finished.
    pub const STAGE_FINISHED: u8 = 2;

    /// Role-independent event.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Ev {
        Prelude {
            line: Vec<u8>,
            terminator: LineTerminator,
        },
        Ident(OwnedIdentification),
        Skipped(SkippedMessage),
    }

    /// Proposal fields; `unexamined_bytes` is chunk-dependent by design.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EndProposal {
        pub kexinit: OwnedKexInit,
        pub raw_payload: Vec<u8>,
        pub anomalies: Vec<ProposalAnomaly>,
        pub unexamined_bytes: usize,
    }

    /// Role-independent terminal outcome.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum End {
        Proposal(Box<EndProposal>),
        Disconnected {
            reason_code: u32,
            description: Vec<u8>,
            language_tag: Vec<u8>,
        },
        Eof {
            stage: u8,
            pending_bytes: usize,
        },
        Error(InitialError),
        BannerOnly,
        UnexpectedInput {
            sample: Vec<u8>,
            truncated: bool,
        },
    }

    /// Role-independent step.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum MStep {
        NeedMore,
        Event(Ev),
        Finished(End),
    }

    /// The state-machine surface both roles share.
    pub trait Machine {
        fn feed(&mut self, data: &[u8]);
        fn step(&mut self) -> MStep;
        fn input_ended(&mut self) -> End;
        fn pending(&self) -> usize;
        fn room(&self) -> usize;
        fn stage(&self) -> u8;
    }

    fn probe_end(end: ProbeEnd) -> End {
        match end {
            ProbeEnd::Proposal(p) => End::Proposal(Box::new(EndProposal {
                kexinit: p.kexinit,
                raw_payload: p.raw_payload,
                anomalies: p.anomalies,
                unexamined_bytes: p.unexamined_bytes,
            })),
            ProbeEnd::Disconnected {
                reason_code,
                description,
                language_tag,
            } => End::Disconnected {
                reason_code,
                description,
                language_tag,
            },
            ProbeEnd::Eof {
                stage,
                pending_bytes,
            } => End::Eof {
                stage: probe_stage(stage),
                pending_bytes,
            },
            ProbeEnd::Error(e) => End::Error(e),
        }
    }

    fn probe_stage(stage: Stage) -> u8 {
        match stage {
            Stage::Identification => STAGE_IDENT,
            Stage::InitialPackets => STAGE_PACKETS,
            Stage::Finished => STAGE_FINISHED,
        }
    }

    impl Machine for Probe {
        fn feed(&mut self, data: &[u8]) {
            Probe::feed(self, data);
        }
        fn step(&mut self) -> MStep {
            match Probe::step(self) {
                Step::NeedMore => MStep::NeedMore,
                Step::Event(e) => MStep::Event(match e {
                    ProbeEvent::PreludeLine { line, terminator } => {
                        Ev::Prelude { line, terminator }
                    }
                    ProbeEvent::ServerIdentification(i) => Ev::Ident(i),
                    ProbeEvent::Ignored { data_len } => {
                        Ev::Skipped(SkippedMessage::Ignored { data_len })
                    }
                    ProbeEvent::Debug {
                        always_display,
                        message,
                        language_tag,
                    } => Ev::Skipped(SkippedMessage::Debug {
                        always_display,
                        message,
                        language_tag,
                    }),
                    ProbeEvent::Unimplemented { sequence_number } => {
                        Ev::Skipped(SkippedMessage::Unimplemented { sequence_number })
                    }
                }),
                Step::Finished(end) => MStep::Finished(probe_end(end)),
            }
        }
        fn input_ended(&mut self) -> End {
            probe_end(Probe::input_ended(self))
        }
        fn pending(&self) -> usize {
            self.pending_bytes()
        }
        fn room(&self) -> usize {
            Probe::room(self)
        }
        fn stage(&self) -> u8 {
            probe_stage(Probe::stage(self))
        }
    }

    /// Documented outcome codes.
    pub const OUTCOME_CODES: [&str; 7] = [
        "banner_only",
        "proposal",
        "proposal_with_anomalies",
        "disconnected",
        "unexpected_input",
        "eof",
        "protocol_error",
    ];

    /// The code each variant must report (independent table). The match is
    /// exhaustive on purpose: the outcome set is closed and contains no
    /// negotiated or authenticated state.
    #[must_use]
    pub fn expected_outcome_code(o: &ObservationOutcome) -> &'static str {
        match o {
            ObservationOutcome::BannerOnly => "banner_only",
            ObservationOutcome::Proposal(p) if p.anomalies.is_empty() => "proposal",
            ObservationOutcome::Proposal(_) => "proposal_with_anomalies",
            ObservationOutcome::Disconnected { .. } => "disconnected",
            ObservationOutcome::UnexpectedInput { .. } => "unexpected_input",
            ObservationOutcome::Eof { .. } => "eof",
            ObservationOutcome::Error(_) => "protocol_error",
        }
    }

    fn observer_stage(stage: ObserverStage) -> u8 {
        let code = stage.code();
        assert!(
            ["client_identification", "initial_packets", "finished"].contains(&code),
            "undocumented stage code {code}"
        );
        match stage {
            ObserverStage::ClientIdentification => STAGE_IDENT,
            ObserverStage::InitialPackets => STAGE_PACKETS,
            ObserverStage::Finished => STAGE_FINISHED,
        }
    }

    fn observer_end(end: ObservationOutcome) -> End {
        let code = end.code();
        assert!(OUTCOME_CODES.contains(&code), "undocumented code {code}");
        assert_eq!(code, expected_outcome_code(&end), "code/variant mismatch");
        match end {
            ObservationOutcome::BannerOnly => End::BannerOnly,
            ObservationOutcome::Proposal(p) => End::Proposal(Box::new(EndProposal {
                kexinit: p.kexinit,
                raw_payload: p.raw_payload,
                anomalies: p.anomalies,
                unexamined_bytes: p.unexamined_bytes,
            })),
            ObservationOutcome::Disconnected {
                reason_code,
                description,
                language_tag,
            } => End::Disconnected {
                reason_code,
                description,
                language_tag,
            },
            ObservationOutcome::UnexpectedInput { sample, truncated } => {
                End::UnexpectedInput { sample, truncated }
            }
            ObservationOutcome::Eof {
                stage,
                pending_bytes,
            } => End::Eof {
                stage: observer_stage(stage),
                pending_bytes,
            },
            ObservationOutcome::Error(e) => End::Error(e),
        }
    }

    impl Machine for Observer {
        fn feed(&mut self, data: &[u8]) {
            Observer::feed(self, data);
        }
        fn step(&mut self) -> MStep {
            match Observer::step(self) {
                ObserverStep::NeedMore => MStep::NeedMore,
                ObserverStep::Event(ObserverEvent::ClientIdentification(i)) => {
                    MStep::Event(Ev::Ident(i))
                }
                ObserverStep::Event(ObserverEvent::Skipped(m)) => MStep::Event(Ev::Skipped(m)),
                ObserverStep::Finished(end) => MStep::Finished(observer_end(end)),
            }
        }
        fn input_ended(&mut self) -> End {
            observer_end(Observer::input_ended(self))
        }
        fn pending(&self) -> usize {
            self.pending_bytes()
        }
        fn room(&self) -> usize {
            Observer::room(self)
        }
        fn stage(&self) -> u8 {
            observer_stage(Observer::stage(self))
        }
    }

    /// Result of one driver run.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Run {
        pub events: Vec<Ev>,
        /// `None` when the stream ended with the machine still waiting.
        pub end: Option<End>,
        /// Bytes fed when the run stopped feeding.
        pub fed: usize,
        /// Pending bytes when the run stopped.
        pub pending_at_end: usize,
        /// For `UnexpectedInput`: pending bytes just before the deciding
        /// step (equals the bytes fed so far, nothing having been consumed).
        pub decision_pending: Option<usize>,
    }

    /// Maximum steps per drain before the harness declares a livelock.
    pub const MAX_STEPS: usize = 4096;

    fn drain<M: Machine>(m: &mut M, run: &mut Run, stage: &mut u8) -> Option<End> {
        for _ in 0..MAX_STEPS {
            let pending_before = m.pending();
            let stage_before = *stage;
            let step = m.step();
            let stage_after = m.stage();
            assert!(
                stage_after >= stage_before,
                "stage went backwards: {stage_before} -> {stage_after}"
            );
            *stage = stage_after;
            match step {
                MStep::NeedMore => {
                    assert_eq!(m.pending(), pending_before, "NeedMore must not consume");
                    assert!(stage_after < STAGE_FINISHED, "NeedMore after finishing");
                    return None;
                }
                MStep::Event(ev) => {
                    assert!(
                        m.pending() < pending_before || stage_after > stage_before,
                        "event without progress: {ev:?}"
                    );
                    run.events.push(ev);
                }
                MStep::Finished(end) => {
                    assert_eq!(stage_after, STAGE_FINISHED, "finished but stage is not");
                    if matches!(end, End::UnexpectedInput { .. }) {
                        run.decision_pending = Some(pending_before);
                        assert_eq!(m.pending(), 0, "unexpected input must clear the buffer");
                    }
                    return Some(end);
                }
            }
        }
        panic!("state machine produced {MAX_STEPS} steps without asking for input");
    }

    /// Feeds `stream` according to `mode`, never exceeding `room()`, draining
    /// after every feed; signals EOF afterwards when `eof` is set and the
    /// machine has not finished. Checks the stable-terminal contract twice
    /// (never in a loop) and that feeding after the end is ignored.
    pub fn drive<M: Machine>(m: &mut M, stream: &[u8], mode: &ChunkMode, eof: bool) -> Run {
        let capacity = m.room();
        assert_eq!(m.pending(), 0, "fresh machine must be empty");
        let mut run = Run {
            events: Vec::new(),
            end: None,
            fed: 0,
            pending_at_end: 0,
            decision_pending: None,
        };
        let mut stage = m.stage();
        run.end = drain(m, &mut run, &mut stage);
        let mut off = 0;
        let mut desired = mode.desired();
        while run.end.is_none() && off < stream.len() {
            let room = m.room();
            assert!(
                room > 0,
                "buffer full (capacity {capacity}) yet the machine neither progressed nor failed"
            );
            let want = desired.next().unwrap_or(1).max(1);
            let n = want.min(room).min(stream.len() - off);
            let before = m.pending();
            m.feed(&stream[off..off + n]);
            assert_eq!(
                m.pending(),
                before + n,
                "a feed within room() must buffer everything"
            );
            off += n;
            run.fed = off;
            run.end = drain(m, &mut run, &mut stage);
        }
        if run.end.is_none() && eof {
            let end = m.input_ended();
            assert_eq!(m.stage(), STAGE_FINISHED);
            run.end = Some(end);
        }
        match &run.end {
            Some(end) => {
                assert_eq!(m.stage(), STAGE_FINISHED);
                assert_eq!(
                    m.step(),
                    MStep::Finished(end.clone()),
                    "terminal not stable (1)"
                );
                assert_eq!(
                    m.step(),
                    MStep::Finished(end.clone()),
                    "terminal not stable (2)"
                );
                let pending = m.pending();
                m.feed(b"ignored after finish");
                assert_eq!(m.pending(), pending, "feed after finish must be ignored");
                assert_eq!(
                    &m.input_ended(),
                    end,
                    "input_ended after finish must repeat the end"
                );
            }
            None => assert!(m.stage() < STAGE_FINISHED, "not finished but stage says so"),
        }
        run.pending_at_end = m.pending();
        run
    }

    /// Semantic equality of two terminal outcomes from different chunkings:
    /// everything must match except `Proposal::unexamined_bytes` and the
    /// content of an `UnexpectedInput` sample (both chunk-dependent).
    pub fn assert_same_end(a: &End, b: &End, what: &str) {
        match (a, b) {
            (End::Proposal(x), End::Proposal(y)) => {
                assert_eq!(x.kexinit, y.kexinit, "{what}: kexinit");
                assert_eq!(x.raw_payload, y.raw_payload, "{what}: raw_payload");
                assert_eq!(x.anomalies, y.anomalies, "{what}: anomalies");
            }
            (End::UnexpectedInput { .. }, End::UnexpectedInput { .. }) => {}
            _ => assert_eq!(a, b, "{what}"),
        }
    }

    /// Compares two full runs (events and, when both finished, ends).
    pub fn assert_same_run(a: &Run, b: &Run, what: &str) {
        assert_eq!(a.events, b.events, "{what}: event sequences differ");
        match (&a.end, &b.end) {
            (Some(x), Some(y)) => assert_same_end(x, y, what),
            (None, None) => {}
            (x, y) => panic!("{what}: one run finished and the other did not: {x:?} vs {y:?}"),
        }
    }

    /// The identification phase of a run must match the reference line
    /// reader run over the same stream with the machine's limits: the same
    /// prelude lines, then the same identification fields, or the same
    /// error, or (when the stream ends mid-line) no identification and, on
    /// EOF, `Eof` in the identification stage with the unconsumed remainder
    /// pending. Callers must not use this where the machine intercepts input
    /// before the reader (the observer's non-`SSH-` policy).
    pub fn assert_ident_phase(run: &Run, stream: &[u8], limits: IdentLimits, eof: bool) {
        let (ref_prelude, outcome) = ident_ref::run(stream, limits);
        let n = ref_prelude.len();
        assert!(
            run.events.len() >= n,
            "fewer prelude events ({}) than the reference ({n})",
            run.events.len()
        );
        for (i, (line, terminator)) in ref_prelude.iter().enumerate() {
            assert_eq!(
                run.events[i],
                Ev::Prelude {
                    line: line.to_vec(),
                    terminator: *terminator,
                },
                "prelude line {i}"
            );
        }
        match outcome {
            RefOutcome::Identification { ident, .. } => {
                let Some(Ev::Ident(owned)) = run.events.get(n) else {
                    panic!(
                        "reference parsed an identification, machine reported {:?} / {:?}",
                        run.events.get(n),
                        run.end
                    );
                };
                assert_eq!(owned.line, ident.line, "identification line bytes");
                assert_eq!(owned.terminator, ident.terminator);
                assert_eq!(owned.protocol_version.as_bytes(), ident.protocol_version);
                assert_eq!(owned.software_version.as_bytes(), ident.software_version);
                assert_eq!(owned.comments.as_deref(), ident.comments, "raw comments");
                assert_eq!(owned.support, ident.support);
            }
            RefOutcome::Error(e) => {
                assert_eq!(run.events.len(), n, "events after an identification error");
                assert_eq!(
                    run.end,
                    Some(End::Error(InitialError::Ident(e))),
                    "identification error differs from the reference"
                );
            }
            RefOutcome::Incomplete => {
                assert_eq!(run.events.len(), n, "events without a complete line");
                let consumed: usize = ref_prelude
                    .iter()
                    .map(|(l, t)| l.len() + t.byte_len())
                    .sum();
                if eof {
                    assert_eq!(
                        run.end,
                        Some(End::Eof {
                            stage: STAGE_IDENT,
                            pending_bytes: stream.len() - consumed,
                        }),
                        "EOF while awaiting the identification"
                    );
                } else {
                    assert_eq!(run.end, None, "terminal outcome without a complete line");
                }
            }
        }
    }
}

/// Structured stream generation with an expectation model.
pub mod stream_gen {
    use tatami_tcp::ident::{
        IdentError, IdentLimits, InvalidIdentification, LineTerminator, OwnedIdentification,
        VersionSupport,
    };
    use tatami_tcp::initial::{InitialError, SkippedMessage};
    use tatami_tcp::packet::{PacketError, encode_initial_packet};
    use tatami_tcp::probe::ProposalAnomaly;
    use tatami_wire::Writer;
    use tatami_wire::kexinit::OwnedKexInit;

    use super::drive::{End, Ev, Run, STAGE_PACKETS};
    use super::{Cursor, filler, ident_ref, msg_ref, packet_ref, put_string};

    /// Known algorithm names and markers (unknown names are also generated).
    pub const NAMES: &[&[u8]] = &[
        b"curve25519-sha256",
        b"curve25519-sha256@libssh.org",
        b"ecdh-sha2-nistp256",
        b"diffie-hellman-group14-sha256",
        b"diffie-hellman-group-exchange-sha256",
        b"sntrup761x25519-sha512@openssh.com",
        b"mlkem768x25519-sha256",
        b"ext-info-c",
        b"ext-info-s",
        b"kex-strict-c-v00@openssh.com",
        b"kex-strict-s-v00@openssh.com",
        b"ssh-ed25519",
        b"rsa-sha2-256",
        b"rsa-sha2-512",
        b"ecdsa-sha2-nistp256",
        b"aes128-ctr",
        b"aes256-ctr",
        b"aes256-gcm@openssh.com",
        b"chacha20-poly1305@openssh.com",
        b"hmac-sha2-256",
        b"hmac-sha2-512",
        b"hmac-sha2-256-etm@openssh.com",
        b"umac-64@openssh.com",
        b"none",
        b"zlib",
        b"zlib@openssh.com",
        b"en-US",
        b"en",
        b"made-up-name",
        b"kex-strict-c",
        b"kex-strict-s",
    ];

    /// Message numbers that are not valid before `KEXINIT`.
    pub const OTHER_NUMBERS: &[u8] = &[5, 6, 7, 21, 30, 31, 49, 50, 0, 60, 80, 90, 255, 22, 29];

    /// Which side produced the stream.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Role {
        /// Server bytes, consumed by the client probe.
        Server,
        /// Client bytes, consumed by the server observer.
        Client,
    }

    /// Byte to a valid token byte.
    #[must_use]
    pub fn sanitize_token(b: u8) -> u8 {
        if ident_ref::is_token_byte(b) {
            b
        } else {
            b'a' + b % 26
        }
    }

    /// Byte to a valid name byte.
    #[must_use]
    pub fn sanitize_name(b: u8) -> u8 {
        if (0x21..=0x7e).contains(&b) && b != b',' {
            b
        } else {
            b'a' + b % 26
        }
    }

    fn term_bytes(t: LineTerminator) -> &'static [u8] {
        match t {
            LineTerminator::CrLf => b"\r\n",
            LineTerminator::Lf => b"\n",
        }
    }

    /// A generated identification line.
    #[derive(Clone, Debug)]
    pub struct GenIdent {
        /// Content without terminator.
        pub content: Vec<u8>,
        pub terminator: LineTerminator,
        /// What the reader must report (before length limits).
        pub expect: Result<OwnedIdentification, IdentError>,
    }

    /// Layout: flags u8 (bit0 LF-only; bit1 `1.99`; bit2 comments present;
    /// bit3 `1.5`; bit4 invalid syntax, kind in bits 5-6), sw_len u8 (mod
    /// 65) + bytes, c_len u8 (mod 201) + bytes.
    pub fn gen_ident(cur: &mut Cursor<'_>) -> GenIdent {
        let flags = cur.u8();
        let sw_len = usize::from(cur.u8()) % 65;
        let mut sw: Vec<u8> = cur
            .take(sw_len)
            .iter()
            .map(|&b| sanitize_token(b))
            .collect();
        if sw.is_empty() {
            sw = b"x".to_vec();
        }
        let c_len = usize::from(cur.u8()) % 201;
        let comments: Vec<u8> = cur
            .take(c_len)
            .iter()
            .map(|&b| if ident_ref::is_forbidden(b) { b'.' } else { b })
            .collect();
        let terminator = if flags & 1 != 0 {
            LineTerminator::Lf
        } else {
            LineTerminator::CrLf
        };
        let proto: &[u8] = if flags & 8 != 0 {
            b"1.5"
        } else if flags & 2 != 0 {
            b"1.99"
        } else {
            b"2.0"
        };
        let has_comments = flags & 4 != 0;
        let mut content = Vec::new();
        content.extend_from_slice(b"SSH-");
        content.extend_from_slice(proto);
        content.push(b'-');
        content.extend_from_slice(&sw);
        if has_comments {
            content.push(b' ');
            content.extend_from_slice(&comments);
        }
        let mut expect = if proto == b"1.5" {
            Err(IdentError::UnsupportedVersion)
        } else {
            Ok(OwnedIdentification {
                line: content.clone(),
                terminator,
                protocol_version: String::from_utf8(proto.to_vec()).expect("ascii"),
                software_version: String::from_utf8(sw.clone()).expect("ascii"),
                comments: has_comments.then(|| comments.clone()),
                support: if proto == b"1.99" {
                    VersionSupport::Ssh2Compatibility
                } else {
                    VersionSupport::Ssh2
                },
            })
        };
        if flags & 0x10 != 0 {
            let (bytes, err): (Vec<u8>, InvalidIdentification) = match (flags >> 5) & 3 {
                0 => (
                    [b"SSH-2.0".as_slice(), &sw].concat(),
                    InvalidIdentification::MissingSeparator,
                ),
                1 => (
                    [b"SSH--".as_slice(), &sw].concat(),
                    InvalidIdentification::BadProtocolVersion,
                ),
                2 => (
                    [b"SSH-2.0- ".as_slice(), &comments].concat(),
                    InvalidIdentification::BadSoftwareVersion,
                ),
                _ => (
                    [b"SSH-2.0-".as_slice(), &sw, b"\rx"].concat(),
                    InvalidIdentification::ControlCharacter,
                ),
            };
            content = bytes;
            expect = Err(IdentError::InvalidIdentification(err));
        }
        GenIdent {
            content,
            terminator,
            expect,
        }
    }

    /// Layout: flags u8 (bit0 LF-only; bit1 long line of 1024 + len filler
    /// bytes, consuming no further input), len u8, then len bytes unless
    /// long. Never starts with `SSH-`, never contains LF, never ends with CR
    /// (so the terminator is unambiguous).
    pub fn gen_prelude_line(cur: &mut Cursor<'_>) -> (Vec<u8>, LineTerminator) {
        let flags = cur.u8();
        let len = usize::from(cur.u8());
        // Long lines are pure filler so a short description still describes
        // everything after them.
        let mut line = if flags & 2 != 0 {
            filler(1024 + len, 5)
        } else {
            cur.take(len).to_vec()
        };
        for b in &mut line {
            if *b == b'\n' {
                *b = b'.';
            }
        }
        if line.starts_with(b"SSH-") {
            line[0] = b'#';
        }
        if line.last() == Some(&b'\r') {
            let last = line.len() - 1;
            line[last] = b'.';
        }
        let terminator = if flags & 1 != 0 {
            LineTerminator::Lf
        } else {
            LineTerminator::CrLf
        };
        (line, terminator)
    }

    /// Layout: idx u8: a table entry, or (idx ≥ table) a fuzz name of
    /// `1 + (idx - table) % 16` sanitized bytes.
    pub fn gen_name(cur: &mut Cursor<'_>) -> Vec<u8> {
        let idx = usize::from(cur.u8());
        if idx < NAMES.len() {
            NAMES[idx].to_vec()
        } else {
            let len = 1 + (idx - NAMES.len()) % 16;
            cur.take_filled(len, 13)
                .into_iter()
                .map(sanitize_name)
                .collect()
        }
    }

    /// A generated `KEXINIT`.
    #[derive(Clone, Debug)]
    pub struct GenKexInit {
        pub cookie: [u8; 16],
        pub lists: Vec<Vec<Vec<u8>>>,
        /// Raw boolean byte as sent (non-canonical values allowed).
        pub first_kex_packet_follows: u8,
        pub reserved: u32,
        /// Trailing bytes cut from the payload (nonzero → malformed).
        pub truncate: usize,
        /// The payload as framed.
        pub payload: Vec<u8>,
    }

    impl GenKexInit {
        /// The owned decode the library must produce (untruncated only).
        #[must_use]
        pub fn expected(&self) -> msg_ref::RefKexInit {
            msg_ref::RefKexInit {
                cookie: self.cookie,
                lists: self.lists.clone(),
                first_kex_packet_follows: self.first_kex_packet_follows != 0,
                reserved: self.reserved,
            }
        }
    }

    /// Layout: flags u8 (bit0 add role markers (`ext-info-*` and the
    /// pre-standard `kex-strict-*-v00@openssh.com`) to kex_algorithms; bit1
    /// empty a required list (index u8 mod 8); bit2 raw
    /// first_kex_packet_follows byte follows; bit3 reserved u32 follows;
    /// bit4 truncate 1 + u8 mod 7 bytes; bit5 add the standard role marker
    /// `kex-strict-c` / `kex-strict-s`), cookie 16 bytes, then ten lists:
    /// count u8 mod 4, names.
    pub fn gen_kexinit(cur: &mut Cursor<'_>, role: Role) -> GenKexInit {
        let flags = cur.u8();
        let cookie: [u8; 16] = cur.take_filled(16, 7).try_into().expect("exactly 16 bytes");
        let mut lists: Vec<Vec<Vec<u8>>> = Vec::with_capacity(10);
        for _ in 0..10 {
            let count = usize::from(cur.u8()) % 4;
            lists.push((0..count).map(|_| gen_name(cur)).collect());
        }
        if flags & 1 != 0 {
            let markers: [&[u8]; 2] = match role {
                Role::Server => [b"ext-info-s", b"kex-strict-s-v00@openssh.com"],
                Role::Client => [b"ext-info-c", b"kex-strict-c-v00@openssh.com"],
            };
            lists[0].extend(markers.iter().map(|m| m.to_vec()));
        }
        if flags & 32 != 0 {
            let standard: &[u8] = match role {
                Role::Server => b"kex-strict-s",
                Role::Client => b"kex-strict-c",
            };
            lists[0].push(standard.to_vec());
        }
        if flags & 2 != 0 {
            let idx = usize::from(cur.u8()) % 8;
            lists[idx].clear();
        }
        let first_kex_packet_follows = if flags & 4 != 0 { cur.u8() } else { 0 };
        let reserved = if flags & 8 != 0 { cur.u32() } else { 0 };
        let truncate = if flags & 16 != 0 {
            1 + usize::from(cur.u8()) % 7
        } else {
            0
        };
        let mut buf = vec![0u8; 8192];
        let mut w = Writer::new(&mut buf);
        w.write_u8(20).expect("capacity");
        w.write_bytes(&cookie).expect("capacity");
        for list in &lists {
            w.write_name_list(list.iter())
                .expect("sanitized names encode");
        }
        w.write_u8(first_kex_packet_follows).expect("capacity");
        w.write_u32(reserved).expect("capacity");
        let n = w.position();
        let mut payload = buf[..n].to_vec();
        payload.truncate(n - truncate);
        GenKexInit {
            cookie,
            lists,
            first_kex_packet_follows,
            reserved,
            truncate,
            payload,
        }
    }

    /// A generated pre-`KEXINIT` element.
    #[derive(Clone, Debug)]
    pub enum GenMsg {
        Ignore {
            data_len: usize,
        },
        Debug {
            always_display: u8,
            message: Vec<u8>,
            language_tag: Vec<u8>,
        },
        Unimplemented {
            sequence_number: u32,
        },
        Disconnect {
            reason_code: u32,
            description: Vec<u8>,
            language_tag: Vec<u8>,
        },
        /// `NEWKEYS`, a method-specific number, or an unexpected number.
        Raw {
            payload: Vec<u8>,
        },
        /// Hand-built 16-byte frame whose payload is empty.
        EmptyPayload,
        /// Five-byte header claiming more than the cap allows.
        OversizedClaim,
        KexInit(GenKexInit),
    }

    /// Layout: kind u8 mod 9: 0 IGNORE (data_len u16 mod 4097); 1 DEBUG
    /// (byte, msg u8 mod 64, lang u8 mod 8); 2 UNIMPLEMENTED (u32);
    /// 3 DISCONNECT (u32, desc u8 mod 64, lang u8 mod 8); 4 other number
    /// (idx u8, body u8 mod 16 bytes); 5 empty payload; 6 oversized claim;
    /// 7 boundary-sized IGNORE (u8 mod 4: exactly the largest packet the
    /// cap admits, eight bytes under it, 4097 or 8192 data bytes);
    /// 8 KEXINIT.
    pub fn gen_msg(cur: &mut Cursor<'_>, role: Role, cap: u32) -> GenMsg {
        match cur.u8() % 9 {
            0 => GenMsg::Ignore {
                data_len: usize::from(cur.u16()) % 4097,
            },
            1 => {
                let always_display = cur.u8();
                let m = usize::from(cur.u8()) % 64;
                let message = cur.take(m).to_vec();
                let l = usize::from(cur.u8()) % 8;
                let language_tag = cur.take(l).to_vec();
                GenMsg::Debug {
                    always_display,
                    message,
                    language_tag,
                }
            }
            2 => GenMsg::Unimplemented {
                sequence_number: cur.u32(),
            },
            3 => {
                let reason_code = cur.u32();
                let d = usize::from(cur.u8()) % 64;
                let description = cur.take(d).to_vec();
                let l = usize::from(cur.u8()) % 8;
                let language_tag = cur.take(l).to_vec();
                GenMsg::Disconnect {
                    reason_code,
                    description,
                    language_tag,
                }
            }
            4 => {
                let number = OTHER_NUMBERS[usize::from(cur.u8()) % OTHER_NUMBERS.len()];
                let body = usize::from(cur.u8()) % 16;
                let mut payload = vec![number];
                payload.extend_from_slice(cur.take(body));
                GenMsg::Raw { payload }
            }
            5 => GenMsg::EmptyPayload,
            6 => GenMsg::OversizedClaim,
            7 => {
                // Boundary sizes relative to the cap. For the first,
                // packet_length = 1 + (1 + 4 + data_len) + 4 = data_len + 10,
                // i.e. exactly the largest packet the cap admits.
                let cap = cap.min(65536) as usize;
                let at_cap =
                    packet_ref::max_packet_length(cap as u32).map_or(0, |pl| pl as usize - 10);
                let data_len = match cur.u8() % 4 {
                    0 => at_cap,
                    1 => at_cap.saturating_sub(8),
                    2 => 4097,
                    _ => 8192,
                };
                GenMsg::Ignore { data_len }
            }
            _ => GenMsg::KexInit(gen_kexinit(cur, role)),
        }
    }

    /// Frames one element as it appears on the wire.
    #[must_use]
    pub fn frame(msg: &GenMsg, pad_byte: u8, cap: u32) -> Vec<u8> {
        let payload: Vec<u8> = match msg {
            GenMsg::Ignore { data_len } => {
                let mut p = vec![2u8];
                put_string(&mut p, &filler(*data_len, 3));
                p
            }
            GenMsg::Debug {
                always_display,
                message,
                language_tag,
            } => {
                let mut p = vec![4u8, *always_display];
                put_string(&mut p, message);
                put_string(&mut p, language_tag);
                p
            }
            GenMsg::Unimplemented { sequence_number } => {
                let mut p = vec![3u8];
                p.extend_from_slice(&sequence_number.to_be_bytes());
                p
            }
            GenMsg::Disconnect {
                reason_code,
                description,
                language_tag,
            } => {
                let mut p = vec![1u8];
                p.extend_from_slice(&reason_code.to_be_bytes());
                put_string(&mut p, description);
                put_string(&mut p, language_tag);
                p
            }
            GenMsg::Raw { payload } => payload.clone(),
            GenMsg::EmptyPayload => {
                // packet_length 12, padding 11, payload_len 0.
                return vec![0, 0, 0, 12, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            }
            GenMsg::OversizedClaim => {
                let pl = packet_ref::max_packet_length(cap)
                    .unwrap_or(cap)
                    .saturating_add(8);
                assert!(pl > cap, "oversized claim needs headroom below u32::MAX");
                let mut f = pl.to_be_bytes().to_vec();
                f.push(4);
                return f;
            }
            GenMsg::KexInit(k) => k.payload.clone(),
        };
        let mut out = vec![0u8; payload.len() + 5 + 12];
        let n =
            encode_initial_packet(&payload, pad_byte, &mut out).expect("bounded payload frames");
        out.truncate(n);
        out
    }

    /// A generated stream and its description.
    #[derive(Clone, Debug)]
    pub struct GenStream {
        pub role: Role,
        /// Client role only: bytes before the identification that do not
        /// start with `SSH-`.
        pub junk_first: Vec<u8>,
        /// Server role only.
        pub prelude: Vec<(Vec<u8>, LineTerminator)>,
        pub ident: GenIdent,
        /// Elements with their framed bytes.
        pub msgs: Vec<(GenMsg, Vec<u8>)>,
        pub trailing: Vec<u8>,
        /// The wire bytes (after mutation, if any).
        pub bytes: Vec<u8>,
        pub mutated: bool,
    }

    /// Layout (after the role-specific head): server: n_prelude u8 mod 9 and
    /// the lines; client: junk_len u8 mod 33 and the bytes. Then the
    /// identification, n_msgs u8 mod 9 with (pad_byte u8, element) each,
    /// trailing len u16 mod 4097 + bytes, mutation flags u8 (bit0 mutate;
    /// count 1 + (flags >> 1) mod 16 of (pos u16, xor u8)).
    pub fn generate(cur: &mut Cursor<'_>, role: Role, cap: u32) -> GenStream {
        let mut bytes = Vec::new();
        let mut junk_first = Vec::new();
        let mut prelude = Vec::new();
        match role {
            Role::Server => {
                let n = usize::from(cur.u8()) % 9;
                for _ in 0..n {
                    let line = gen_prelude_line(cur);
                    bytes.extend_from_slice(&line.0);
                    bytes.extend_from_slice(term_bytes(line.1));
                    prelude.push(line);
                }
            }
            Role::Client => {
                let n = usize::from(cur.u8()) % 33;
                if n > 0 {
                    let mut junk = cur.take_filled(n, 11);
                    if junk.starts_with(b"SSH-") {
                        junk[0] = b'X';
                    }
                    bytes.extend_from_slice(&junk);
                    junk_first = junk;
                }
            }
        }
        let ident = gen_ident(cur);
        bytes.extend_from_slice(&ident.content);
        bytes.extend_from_slice(term_bytes(ident.terminator));
        let n_msgs = usize::from(cur.u8()) % 9;
        let mut msgs = Vec::with_capacity(n_msgs);
        let mut max_size_used = false;
        for _ in 0..n_msgs {
            let pad_byte = cur.u8();
            let mut msg = gen_msg(cur, role, cap);
            if let GenMsg::Ignore { data_len } = &msg
                && *data_len > 4096
            {
                if max_size_used {
                    msg = GenMsg::Ignore { data_len: 0 };
                }
                max_size_used = true;
            }
            let framed = frame(&msg, pad_byte, cap);
            bytes.extend_from_slice(&framed);
            msgs.push((msg, framed));
        }
        let trailing_len = usize::from(cur.u16()) % 4097;
        let trailing = cur.take(trailing_len).to_vec();
        bytes.extend_from_slice(&trailing);
        let mut_flags = cur.u8();
        let mut mutated = false;
        if mut_flags & 1 != 0 && !bytes.is_empty() {
            mutated = true;
            let count = 1 + usize::from(mut_flags >> 1) % 16;
            for _ in 0..count {
                let pos = usize::from(cur.u16()) % bytes.len();
                let val = cur.u8();
                bytes[pos] ^= if val == 0 { 0x80 } else { val };
            }
        }
        GenStream {
            role,
            junk_first,
            prelude,
            ident,
            msgs,
            trailing,
            bytes,
            mutated,
        }
    }

    /// Limits the model applies (mirrors the machine's configuration).
    #[derive(Clone, Debug)]
    pub struct ModelLimits {
        pub ident: IdentLimits,
        pub cap: u32,
        pub max_packets: usize,
        pub max_bytes: usize,
        pub banner_only: bool,
    }

    /// Expected terminal outcome.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ExpEnd {
        Proposal {
            kexinit: Box<OwnedKexInit>,
            raw_payload: Vec<u8>,
            anomalies: Vec<ProposalAnomaly>,
        },
        /// `Error(Message { number: 20, .. })` with any decoder detail.
        MalformedKexInit,
        Disconnected {
            reason_code: u32,
            description: Vec<u8>,
            language_tag: Vec<u8>,
        },
        Error(InitialError),
        BannerOnly,
        UnexpectedInput,
        /// The generated elements produce no terminal outcome; trailing
        /// bytes and the EOF flag decide.
        Incomplete,
    }

    /// Expected events and end.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Expectation {
        pub events: Vec<Ev>,
        pub end: ExpEnd,
        /// Stage after the last generated element (for `Eof`).
        pub stage: u8,
    }

    /// Sequential model over the generated description (not over bytes).
    #[must_use]
    pub fn expect(g: &GenStream, lim: &ModelLimits) -> Expectation {
        let mut events = Vec::new();
        let done = |events: Vec<Ev>, end: ExpEnd, stage: u8| Expectation { events, end, stage };
        let ident_err = |e: IdentError| ExpEnd::Error(InitialError::Ident(e));

        if g.role == Role::Client && !g.junk_first.is_empty() {
            return done(events, ExpEnd::UnexpectedInput, 0);
        }
        let (mut lines, mut bytes) = (0usize, 0usize);
        for (line, terminator) in &g.prelude {
            let consumed = line.len() + terminator.byte_len();
            if consumed > lim.ident.max_prelude_line {
                return done(events, ident_err(IdentError::PreludeLineTooLong), 0);
            }
            if lines >= lim.ident.max_prelude_lines {
                return done(events, ident_err(IdentError::TooManyPreludeLines), 0);
            }
            if bytes + consumed > lim.ident.max_prelude_bytes {
                return done(events, ident_err(IdentError::PreludeBytesExceeded), 0);
            }
            lines += 1;
            bytes += consumed;
            events.push(Ev::Prelude {
                line: line.clone(),
                terminator: *terminator,
            });
        }
        let consumed = g.ident.content.len() + g.ident.terminator.byte_len();
        if consumed > lim.ident.max_identification_line {
            return done(events, ident_err(IdentError::IdentificationTooLong), 0);
        }
        match &g.ident.expect {
            Err(e) => return done(events, ident_err(*e), 0),
            Ok(owned) => events.push(Ev::Ident(owned.clone())),
        }
        if lim.banner_only {
            return done(events, ExpEnd::BannerOnly, STAGE_PACKETS);
        }

        let (mut packets, mut total_bytes) = (0usize, 0usize);
        for (msg, framed) in &g.msgs {
            let packet_length = u32::from_be_bytes([framed[0], framed[1], framed[2], framed[3]]);
            if packet_length > lim.cap {
                return done(
                    events,
                    ExpEnd::Error(InitialError::Packet(PacketError::TooLarge {
                        packet_length,
                        limit: lim.cap,
                    })),
                    STAGE_PACKETS,
                );
            }
            // Every other generated frame satisfies the header rules.
            let total = framed.len();
            if packets >= lim.max_packets {
                return done(
                    events,
                    ExpEnd::Error(InitialError::PacketBudgetExceeded {
                        limit: lim.max_packets,
                    }),
                    STAGE_PACKETS,
                );
            }
            if total_bytes + total > lim.max_bytes {
                return done(
                    events,
                    ExpEnd::Error(InitialError::ByteBudgetExceeded {
                        limit: lim.max_bytes,
                    }),
                    STAGE_PACKETS,
                );
            }
            packets += 1;
            total_bytes += total;
            let end = match msg {
                GenMsg::Ignore { data_len } => {
                    events.push(Ev::Skipped(SkippedMessage::Ignored {
                        data_len: *data_len,
                    }));
                    continue;
                }
                GenMsg::Debug {
                    always_display,
                    message,
                    language_tag,
                } => {
                    events.push(Ev::Skipped(SkippedMessage::Debug {
                        always_display: *always_display != 0,
                        message: message.clone(),
                        language_tag: language_tag.clone(),
                    }));
                    continue;
                }
                GenMsg::Unimplemented { sequence_number } => {
                    events.push(Ev::Skipped(SkippedMessage::Unimplemented {
                        sequence_number: *sequence_number,
                    }));
                    continue;
                }
                GenMsg::Disconnect {
                    reason_code,
                    description,
                    language_tag,
                } => ExpEnd::Disconnected {
                    reason_code: *reason_code,
                    description: description.clone(),
                    language_tag: language_tag.clone(),
                },
                GenMsg::Raw { payload } => {
                    let number = payload[0];
                    ExpEnd::Error(match number {
                        21 | 30..=49 => InitialError::UnsupportedTransition { number },
                        _ => InitialError::UnexpectedMessage { number },
                    })
                }
                GenMsg::EmptyPayload => ExpEnd::Error(InitialError::EmptyPayload),
                GenMsg::OversizedClaim => unreachable!("rejected by the cap check above"),
                GenMsg::KexInit(k) if k.truncate > 0 => ExpEnd::MalformedKexInit,
                GenMsg::KexInit(k) => {
                    let expected = k.expected();
                    ExpEnd::Proposal {
                        kexinit: Box::new(expected.to_owned_kexinit()),
                        raw_payload: k.payload.clone(),
                        anomalies: expected.anomalies(),
                    }
                }
            };
            return done(events, end, STAGE_PACKETS);
        }
        done(events, ExpEnd::Incomplete, STAGE_PACKETS)
    }

    /// Checks a driver run against the model. `eof` is the harness EOF flag.
    pub fn check_expectation(g: &GenStream, run: &Run, exp: &Expectation, eof: bool) {
        assert!(!g.mutated, "the model only applies to unmutated streams");
        assert_eq!(
            run.events, exp.events,
            "events differ from the generated description"
        );
        match &exp.end {
            ExpEnd::Incomplete => {
                // Trailing bytes are parsed as packets; only the drivers'
                // mutual agreement is checked for them.
                if g.trailing.is_empty() {
                    if eof {
                        assert_eq!(
                            run.end,
                            Some(End::Eof {
                                stage: exp.stage,
                                pending_bytes: 0
                            }),
                            "EOF after a fully consumed stream"
                        );
                    } else {
                        assert_eq!(run.end, None, "no terminal outcome expected");
                    }
                }
            }
            ExpEnd::Proposal {
                kexinit,
                raw_payload,
                anomalies,
            } => match &run.end {
                Some(End::Proposal(p)) => {
                    assert_eq!(&p.kexinit, kexinit.as_ref(), "proposal fields");
                    assert_eq!(&p.raw_payload, raw_payload, "raw payload");
                    assert_eq!(&p.anomalies, anomalies, "anomalies");
                }
                other => panic!("expected a proposal, got {other:?}"),
            },
            ExpEnd::MalformedKexInit => assert!(
                matches!(
                    run.end,
                    Some(End::Error(InitialError::Message { number: 20, .. }))
                ),
                "expected malformed KEXINIT, got {:?}",
                run.end
            ),
            ExpEnd::Disconnected {
                reason_code,
                description,
                language_tag,
            } => assert_eq!(
                run.end,
                Some(End::Disconnected {
                    reason_code: *reason_code,
                    description: description.clone(),
                    language_tag: language_tag.clone(),
                })
            ),
            ExpEnd::Error(e) => assert_eq!(run.end, Some(End::Error(e.clone()))),
            ExpEnd::BannerOnly => assert_eq!(run.end, Some(End::BannerOnly)),
            ExpEnd::UnexpectedInput => assert!(
                matches!(run.end, Some(End::UnexpectedInput { .. })),
                "expected unexpected input, got {:?}",
                run.end
            ),
        }
    }
}
