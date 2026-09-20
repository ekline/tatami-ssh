//! Shared helpers for the wire-core fuzz targets. Harness-only code; never a
//! dependency of a production package.
//!
//! Everything here is an *oracle*: an independent restatement of the RFC
//! grammar or wire layout that the targets use to judge `tatami-wire`. The
//! reference code is deliberately written in a different shape from the
//! production code (maximal-munch token runs, segment splitting, explicit
//! shifts) so that a shared misunderstanding is less likely to cancel out.

pub mod ident_ref {
    //! RFC 4253 §4.2 identification grammar:
    //! `SSH-protoversion-softwareversion [SP comments]`.

    /// Reference view of accepted identification content.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefIdent<'a> {
        pub protocol_version: &'a [u8],
        pub software_version: &'a [u8],
        pub comments: Option<&'a [u8]>,
    }

    /// Printable US-ASCII excluding whitespace and the minus sign.
    pub fn is_token_byte(b: u8) -> bool {
        (0x21..=0x7e).contains(&b) && b != b'-'
    }

    /// CR, LF and NUL may never appear anywhere in the content.
    pub fn is_forbidden_byte(b: u8) -> bool {
        b == b'\r' || b == b'\n' || b == 0
    }

    /// Non-empty run of token bytes.
    pub fn is_version_token(t: &[u8]) -> bool {
        !t.is_empty() && t.iter().all(|&b| is_token_byte(b))
    }

    /// Length of the maximal leading run of token bytes.
    fn token_run(s: &[u8]) -> usize {
        s.iter().take_while(|&&b| is_token_byte(b)).count()
    }

    /// Accepts iff `data` matches the grammar; returns the field slices.
    pub fn parse(data: &[u8]) -> Option<RefIdent<'_>> {
        if data.iter().any(|&b| is_forbidden_byte(b)) {
            return None;
        }
        if data.len() < 4
            || data[0] != b'S'
            || data[1] != b'S'
            || data[2] != b'H'
            || data[3] != b'-'
        {
            return None;
        }
        let rest = &data[4..];
        let p = token_run(rest);
        if p == 0 || rest.get(p) != Some(&b'-') {
            return None;
        }
        let protocol_version = &rest[..p];
        let after = &rest[p + 1..];
        let s = token_run(after);
        if s == 0 {
            return None;
        }
        let software_version = &after[..s];
        let comments = match after.get(s) {
            None => None,
            Some(&b' ') => Some(&after[s + 1..]),
            Some(_) => return None,
        };
        Some(RefIdent {
            protocol_version,
            software_version,
            comments,
        })
    }

    /// Bytes `encode` must produce for valid fields.
    pub fn assemble(proto: &[u8], software: &[u8], comments: Option<&[u8]>) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + proto.len() + 1 + software.len() + 64);
        out.extend_from_slice(b"SSH-");
        out.extend_from_slice(proto);
        out.push(b'-');
        out.extend_from_slice(software);
        if let Some(c) = comments {
            out.push(b' ');
            out.extend_from_slice(c);
        }
        out
    }

    /// Maps arbitrary bytes onto the token alphabet (in place).
    pub fn sanitize_token(bytes: &mut [u8]) {
        for b in bytes {
            let c = 0x21 + (*b % 94);
            *b = if c == b'-' { b'_' } else { c };
        }
    }
}

pub mod namelist_ref {
    //! RFC 4251 §5 `name-list` grammar: comma-separated, non-empty names of
    //! printable US-ASCII (no commas); the list as a whole may be empty.

    use tatami_wire::InvalidEncoding;

    /// Printable US-ASCII.
    pub fn is_printable(b: u8) -> bool {
        (0x21..=0x7e).contains(&b)
    }

    /// A single valid name: non-empty, printable, comma-free.
    pub fn is_valid_name(name: &[u8]) -> bool {
        !name.is_empty() && name.iter().all(|&b| is_printable(b) && b != b',')
    }

    /// Splits `body` into names, or reports the first offending segment in
    /// offset order using the production error vocabulary.
    pub fn parse(body: &[u8]) -> Result<Vec<&[u8]>, InvalidEncoding> {
        if body.is_empty() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        let mut start = 0usize;
        for seg in body.split(|&b| b == b',') {
            if seg.is_empty() {
                return Err(InvalidEncoding::NameListEmptyName { offset: start });
            }
            if let Some(i) = seg.iter().position(|&b| !is_printable(b)) {
                return Err(InvalidEncoding::NameListNonAscii { offset: start + i });
            }
            names.push(seg);
            start += seg.len() + 1;
        }
        Ok(names)
    }

    /// Comma-joined body for a list of names.
    pub fn join<S: AsRef<[u8]>>(names: &[S]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, n) in names.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(n.as_ref());
        }
        out
    }

    /// Maps arbitrary bytes onto the name alphabet (in place).
    pub fn sanitize_name(bytes: &mut [u8]) {
        for b in bytes {
            let c = 0x21 + (*b % 94);
            *b = if c == b',' { b'-' } else { c };
        }
    }
}

pub mod bytes {
    //! Hand assembly of SSH primitives (RFC 4251 §5), written with explicit
    //! shifts rather than the standard-library helpers the codec uses.

    pub fn put_u8(out: &mut Vec<u8>, v: u8) {
        out.push(v);
    }

    pub fn put_bool(out: &mut Vec<u8>, v: bool) {
        out.push(if v { 1 } else { 0 });
    }

    pub fn put_u32(out: &mut Vec<u8>, v: u32) {
        out.push((v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }

    pub fn put_u64(out: &mut Vec<u8>, v: u64) {
        put_u32(out, (v >> 32) as u32);
        put_u32(out, v as u32);
    }

    pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        put_u32(
            out,
            u32::try_from(s.len()).expect("harness strings are small"),
        );
        out.extend_from_slice(s);
    }

    pub fn put_name_list<S: AsRef<[u8]>>(out: &mut Vec<u8>, names: &[S]) {
        let body = crate::namelist_ref::join(names);
        put_string(out, &body);
    }

    pub fn be_u32(b: &[u8]) -> u32 {
        (u32::from(b[0]) << 24) | (u32::from(b[1]) << 16) | (u32::from(b[2]) << 8) | u32::from(b[3])
    }

    pub fn be_u64(b: &[u8]) -> u64 {
        (u64::from(be_u32(&b[..4])) << 32) | u64::from(be_u32(&b[4..8]))
    }
}

pub mod cursor {
    //! Reference decoder cursor. Computes the exact outcome (value or error
    //! variant with `needed`/`available`/`claimed`) that the documented
    //! `Reader` contract requires, without touching the production cursor.

    use tatami_wire::DecodeError;

    use crate::bytes::{be_u32, be_u64};
    use crate::namelist_ref;

    #[derive(Clone, Copy, Debug)]
    pub struct RefCursor<'a> {
        pub data: &'a [u8],
        pub pos: usize,
    }

    impl<'a> RefCursor<'a> {
        pub fn new(data: &'a [u8]) -> Self {
            RefCursor { data, pos: 0 }
        }

        pub fn remaining(&self) -> usize {
            self.data.len() - self.pos
        }

        pub fn rest(&self) -> &'a [u8] {
            &self.data[self.pos..]
        }

        pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
            let available = self.remaining();
            if n > available {
                return Err(DecodeError::Truncated {
                    needed: n,
                    available,
                });
            }
            let out = &self.data[self.pos..self.pos + n];
            self.pos += n;
            Ok(out)
        }

        pub fn u8(&mut self) -> Result<u8, DecodeError> {
            self.take(1).map(|b| b[0])
        }

        pub fn boolean(&mut self) -> Result<bool, DecodeError> {
            self.u8().map(|b| b != 0)
        }

        pub fn u32(&mut self) -> Result<u32, DecodeError> {
            self.take(4).map(be_u32)
        }

        pub fn u64(&mut self) -> Result<u64, DecodeError> {
            self.take(8).map(be_u64)
        }

        /// `uint32` length then that many bytes; the cursor does not move on
        /// failure, even when the prefix itself was readable.
        pub fn string(&mut self) -> Result<&'a [u8], DecodeError> {
            let available = self.remaining();
            if available < 4 {
                return Err(DecodeError::Truncated {
                    needed: 4,
                    available,
                });
            }
            let claimed = be_u32(&self.data[self.pos..self.pos + 4]);
            let after_prefix = available - 4;
            if claimed as usize > after_prefix {
                return Err(DecodeError::LengthOverflow {
                    claimed,
                    available: after_prefix,
                });
            }
            let start = self.pos + 4;
            let end = start + claimed as usize;
            self.pos = end;
            Ok(&self.data[start..end])
        }

        /// A string whose body must satisfy the name-list grammar. Returns
        /// the body and its names.
        #[allow(clippy::type_complexity)]
        pub fn name_list(&mut self) -> Result<(&'a [u8], Vec<&'a [u8]>), DecodeError> {
            let save = self.pos;
            let body = self.string()?;
            match namelist_ref::parse(body) {
                Ok(names) => Ok((body, names)),
                Err(e) => {
                    self.pos = save;
                    Err(DecodeError::InvalidEncoding(e))
                }
            }
        }

        /// `Ok` iff exhausted, else the number of unread bytes.
        pub fn finish(&self) -> Result<(), usize> {
            if self.remaining() == 0 {
                Ok(())
            } else {
                Err(self.remaining())
            }
        }
    }
}

pub mod messages_ref {
    //! Reference layouts for the message payloads `tatami-wire` decodes.
    //! Field names follow the RFC definitions and must match the names the
    //! production decoders report in `MessageError::Field`.

    use tatami_wire::{DecodeError, MessageError};

    use crate::cursor::RefCursor;

    // Message numbers from the IANA registry, restated independently.
    pub const DISCONNECT: u8 = 1;
    pub const IGNORE: u8 = 2;
    pub const UNIMPLEMENTED: u8 = 3;
    pub const DEBUG: u8 = 4;
    pub const KEXINIT: u8 = 20;
    pub const CHANNEL_OPEN: u8 = 90;
    pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
    pub const CHANNEL_OPEN_FAILURE: u8 = 92;

    /// Cookie length (RFC 4253 §7.1).
    pub const COOKIE_LEN: usize = 16;

    /// The ten KEXINIT name-list fields in wire order (RFC 4253 §7.1).
    pub const KEXINIT_LIST_FIELDS: [&str; 10] = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ];

    /// Number of leading lists in [`KEXINIT_LIST_FIELDS`] that RFC 4253
    /// requires to be non-empty (the language lists may be empty).
    pub const REQUIRED_LIST_COUNT: usize = 8;

    /// Registered `SSH_MSG_DISCONNECT` reason codes (RFC 4253 §11.1).
    pub const DISCONNECT_REASONS: [(u32, &str); 15] = [
        (1, "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT"),
        (2, "SSH_DISCONNECT_PROTOCOL_ERROR"),
        (3, "SSH_DISCONNECT_KEY_EXCHANGE_FAILED"),
        (4, "SSH_DISCONNECT_RESERVED"),
        (5, "SSH_DISCONNECT_MAC_ERROR"),
        (6, "SSH_DISCONNECT_COMPRESSION_ERROR"),
        (7, "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE"),
        (8, "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED"),
        (9, "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE"),
        (10, "SSH_DISCONNECT_CONNECTION_LOST"),
        (11, "SSH_DISCONNECT_BY_APPLICATION"),
        (12, "SSH_DISCONNECT_TOO_MANY_CONNECTIONS"),
        (13, "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER"),
        (14, "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE"),
        (15, "SSH_DISCONNECT_ILLEGAL_USER_NAME"),
    ];

    /// Registered `CHANNEL_OPEN_FAILURE` reason codes (RFC 4254 §5.1).
    pub const OPEN_FAILURE_REASONS: [(u32, &str); 4] = [
        (1, "SSH_OPEN_ADMINISTRATIVELY_PROHIBITED"),
        (2, "SSH_OPEN_CONNECT_FAILED"),
        (3, "SSH_OPEN_UNKNOWN_CHANNEL_TYPE"),
        (4, "SSH_OPEN_RESOURCE_SHORTAGE"),
    ];

    /// The four `kex_algorithms` entries that are markers, not methods.
    pub const KEX_MARKERS: [&[u8]; 4] = [
        b"ext-info-c",
        b"ext-info-s",
        b"kex-strict-c-v00@openssh.com",
        b"kex-strict-s-v00@openssh.com",
    ];

    fn expect_number(c: &mut RefCursor<'_>, expected: u8) -> Result<(), MessageError> {
        match c.u8() {
            Err(_) => Err(MessageError::Empty),
            Ok(found) if found == expected => Ok(()),
            Ok(found) => Err(MessageError::UnexpectedMessage { expected, found }),
        }
    }

    fn field<'a, T>(
        c: &mut RefCursor<'a>,
        name: &'static str,
        read: impl FnOnce(&mut RefCursor<'a>) -> Result<T, DecodeError>,
    ) -> Result<T, MessageError> {
        let offset = c.pos;
        read(c).map_err(|error| MessageError::Field {
            field: name,
            offset,
            error,
        })
    }

    fn finish(c: &RefCursor<'_>) -> Result<(), MessageError> {
        c.finish()
            .map_err(|count| MessageError::TrailingBytes { count })
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RefKexInit<'a> {
        pub cookie: &'a [u8],
        /// Raw bodies of the ten lists, wire order.
        pub lists: [&'a [u8]; 10],
        /// Names of the ten lists, wire order.
        pub names: Vec<Vec<&'a [u8]>>,
        /// Raw boolean byte as sent.
        pub first_kex_packet_follows_byte: u8,
        /// Payload offset of that byte.
        pub first_kex_packet_follows_offset: usize,
        pub reserved: u32,
    }

    pub fn kexinit(payload: &[u8]) -> Result<RefKexInit<'_>, MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, KEXINIT)?;
        let cookie = field(&mut c, "cookie", |c| c.take(COOKIE_LEN))?;
        let mut lists: [&[u8]; 10] = [&[]; 10];
        let mut names = Vec::with_capacity(10);
        for (i, name) in KEXINIT_LIST_FIELDS.into_iter().enumerate() {
            let (body, list_names) = field(&mut c, name, RefCursor::name_list)?;
            lists[i] = body;
            names.push(list_names);
        }
        let first_kex_packet_follows_offset = c.pos;
        let first_kex_packet_follows_byte =
            field(&mut c, "first_kex_packet_follows", RefCursor::u8)?;
        let reserved = field(&mut c, "reserved", RefCursor::u32)?;
        finish(&c)?;
        Ok(RefKexInit {
            cookie,
            lists,
            names,
            first_kex_packet_follows_byte,
            first_kex_packet_follows_offset,
            reserved,
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefDisconnect<'a> {
        pub reason_code: u32,
        pub description: &'a [u8],
        pub language_tag: &'a [u8],
    }

    pub fn disconnect(payload: &[u8]) -> Result<RefDisconnect<'_>, MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, DISCONNECT)?;
        let reason_code = field(&mut c, "reason_code", RefCursor::u32)?;
        let description = field(&mut c, "description", RefCursor::string)?;
        let language_tag = field(&mut c, "language_tag", RefCursor::string)?;
        finish(&c)?;
        Ok(RefDisconnect {
            reason_code,
            description,
            language_tag,
        })
    }

    pub fn ignore(payload: &[u8]) -> Result<&[u8], MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, IGNORE)?;
        let data = field(&mut c, "data", RefCursor::string)?;
        finish(&c)?;
        Ok(data)
    }

    pub fn unimplemented(payload: &[u8]) -> Result<u32, MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, UNIMPLEMENTED)?;
        let sequence_number = field(&mut c, "sequence_number", RefCursor::u32)?;
        finish(&c)?;
        Ok(sequence_number)
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefDebug<'a> {
        pub always_display_byte: u8,
        pub message: &'a [u8],
        pub language_tag: &'a [u8],
    }

    pub fn debug(payload: &[u8]) -> Result<RefDebug<'_>, MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, DEBUG)?;
        let always_display_byte = field(&mut c, "always_display", RefCursor::u8)?;
        let message = field(&mut c, "message", RefCursor::string)?;
        let language_tag = field(&mut c, "language_tag", RefCursor::string)?;
        finish(&c)?;
        Ok(RefDebug {
            always_display_byte,
            message,
            language_tag,
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefChannelOpen<'a> {
        pub channel_type: &'a [u8],
        pub sender_channel: u32,
        pub initial_window_size: u32,
        pub maximum_packet_size: u32,
        pub type_specific: &'a [u8],
    }

    pub fn channel_open(payload: &[u8]) -> Result<RefChannelOpen<'_>, MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, CHANNEL_OPEN)?;
        let channel_type = field(&mut c, "channel_type", RefCursor::string)?;
        let sender_channel = field(&mut c, "sender_channel", RefCursor::u32)?;
        let initial_window_size = field(&mut c, "initial_window_size", RefCursor::u32)?;
        let maximum_packet_size = field(&mut c, "maximum_packet_size", RefCursor::u32)?;
        // No finish: the remainder is the bounded type-specific tail.
        Ok(RefChannelOpen {
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            type_specific: c.rest(),
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefChannelOpenConfirmation<'a> {
        pub recipient_channel: u32,
        pub sender_channel: u32,
        pub initial_window_size: u32,
        pub maximum_packet_size: u32,
        pub type_specific: &'a [u8],
    }

    pub fn channel_open_confirmation(
        payload: &[u8],
    ) -> Result<RefChannelOpenConfirmation<'_>, MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, CHANNEL_OPEN_CONFIRMATION)?;
        let recipient_channel = field(&mut c, "recipient_channel", RefCursor::u32)?;
        let sender_channel = field(&mut c, "sender_channel", RefCursor::u32)?;
        let initial_window_size = field(&mut c, "initial_window_size", RefCursor::u32)?;
        let maximum_packet_size = field(&mut c, "maximum_packet_size", RefCursor::u32)?;
        Ok(RefChannelOpenConfirmation {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            type_specific: c.rest(),
        })
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct RefChannelOpenFailure<'a> {
        pub recipient_channel: u32,
        pub reason_code: u32,
        pub description: &'a [u8],
        pub language_tag: &'a [u8],
    }

    pub fn channel_open_failure(payload: &[u8]) -> Result<RefChannelOpenFailure<'_>, MessageError> {
        let mut c = RefCursor::new(payload);
        expect_number(&mut c, CHANNEL_OPEN_FAILURE)?;
        let recipient_channel = field(&mut c, "recipient_channel", RefCursor::u32)?;
        let reason_code = field(&mut c, "reason_code", RefCursor::u32)?;
        let description = field(&mut c, "description", RefCursor::string)?;
        let language_tag = field(&mut c, "language_tag", RefCursor::string)?;
        finish(&c)?;
        Ok(RefChannelOpenFailure {
            recipient_channel,
            reason_code,
            description,
            language_tag,
        })
    }
}

pub mod generate {
    //! Bounded generation helpers over `arbitrary::Unstructured`. These never
    //! fail: when the input is exhausted they yield short or empty values.

    use arbitrary::Unstructured;

    /// Reads a length in `0..=max` (from the front, big-endian, modulo) and
    /// then that many raw bytes, clamped to what is left.
    pub fn bounded_bytes(u: &mut Unstructured<'_>, max: usize) -> Vec<u8> {
        let max = u16::try_from(max).expect("harness bound fits u16");
        let n = u.int_in_range(0..=max).unwrap_or(0) as usize;
        let n = n.min(u.len());
        u.bytes(n).map(<[u8]>::to_vec).unwrap_or_default()
    }

    /// Integer in `0..=max`.
    pub fn small(u: &mut Unstructured<'_>, max: u16) -> usize {
        u.int_in_range(0..=max).unwrap_or(0) as usize
    }

    pub fn byte(u: &mut Unstructured<'_>) -> u8 {
        u.arbitrary().unwrap_or(0)
    }

    pub fn word(u: &mut Unstructured<'_>) -> u32 {
        u.arbitrary().unwrap_or(0)
    }

    pub fn qword(u: &mut Unstructured<'_>) -> u64 {
        u.arbitrary().unwrap_or(0)
    }

    /// A valid SSH name of length `1..=max` from the name alphabet.
    pub fn valid_name(u: &mut Unstructured<'_>, max: usize) -> Vec<u8> {
        let mut name = bounded_bytes(u, max);
        if name.is_empty() {
            name.push(b'a');
        }
        crate::namelist_ref::sanitize_name(&mut name);
        name
    }
}
