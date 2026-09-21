//! Helpers for the key-exchange targets (`key_blobs`, `tcp_negotiation`,
//! `tcp_gcm_packets`, `tcp_handshake`, `handshake_report_json`).
//!
//! Harness-only code; never a dependency of a production package.
//!
//! - [`base64`]: a tiny standard-alphabet, unpadded base64 encoder and a
//!   strict decoder, written from RFC 4648 §4, as the oracle for the
//!   `SHA256:` fingerprint text.
//! - [`lists`]: the ten `KEXINIT` name lists as owned values, hand-assembled
//!   into a payload with explicit big-endian lengths, plus the name pools.
//! - [`negotiate_ref`]: an independent model of RFC 4253 §7.1 negotiation as
//!   the crate documents it (markers excluded, MAC skipped for an AEAD,
//!   strict pairing by identical spelling, server guess correctness).
//! - [`crypto`]: the harness's own server side, calling the providers
//!   directly: X25519 with `x25519_dalek`, the RFC 5656 §4 / RFC 8731 §3
//!   exchange hash and RFC 4253 §7.2 key expansion with `sha2`, `mpint`
//!   encoding by hand, AES-128-GCM sealing/opening in the RFC 5647 layout
//!   with `aes_gcm`, and a deterministic `CryptoRngCore` for the client.
//!   Nothing here calls `tatami_tcp::{transcript, gcm, negotiate}`.

/// RFC 4648 §4 alphabet, unpadded, with a strict decoder.
pub mod base64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Unpadded encoding: every 3 bytes become 4 characters; a 2-byte tail
    /// becomes 3 characters, a 1-byte tail 2.
    #[must_use]
    pub fn encode_unpadded(bytes: &[u8]) -> String {
        let mut out = String::new();
        let (chunks, remainder) = bytes.as_chunks::<3>();
        for c in chunks {
            let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
            for shift in [18, 12, 6, 0] {
                out.push(ALPHABET[((n >> shift) & 63) as usize] as char);
            }
        }
        match remainder {
            [] => {}
            [a] => {
                let n = u32::from(*a) << 16;
                out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
                out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            }
            [a, b] => {
                let n = (u32::from(*a) << 16) | (u32::from(*b) << 8);
                out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
                out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
                out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
            }
            _ => unreachable!("remainder of chunks_exact(3) has fewer than 3 items"),
        }
        out
    }

    fn value(c: u8) -> Option<u32> {
        ALPHABET.iter().position(|&a| a == c).map(|p| p as u32)
    }

    /// Strict unpadded decoding of exactly 43 characters into 32 bytes:
    /// every character in the alphabet and the two unused trailing bits
    /// zero (a canonical encoding). `None` otherwise.
    #[must_use]
    pub fn decode_43_strict(text: &[u8]) -> Option<[u8; 32]> {
        if text.len() != 43 {
            return None;
        }
        let mut vals = [0u32; 43];
        for (i, &c) in text.iter().enumerate() {
            vals[i] = value(c)?;
        }
        let mut out = [0u8; 32];
        // 10 full groups of 4 chars -> 30 bytes.
        for g in 0..10 {
            let n = (vals[4 * g] << 18)
                | (vals[4 * g + 1] << 12)
                | (vals[4 * g + 2] << 6)
                | vals[4 * g + 3];
            out[3 * g] = (n >> 16) as u8;
            out[3 * g + 1] = (n >> 8) as u8;
            out[3 * g + 2] = n as u8;
        }
        // Tail: 3 chars -> 2 bytes, 18 bits of which 16 are used.
        let n = (vals[40] << 12) | (vals[41] << 6) | vals[42];
        if n & 0b11 != 0 {
            return None;
        }
        out[30] = (n >> 10) as u8;
        out[31] = (n >> 2) as u8;
        Some(out)
    }
}

/// The ten `KEXINIT` name lists and their hand assembly.
pub mod lists {
    use super::Cursor;

    /// Real key-exchange method names (none of them a marker).
    pub const KEX_METHODS: &[&[u8]] = &[
        b"curve25519-sha256",
        b"curve25519-sha256@libssh.org",
        b"ecdh-sha2-nistp256",
        b"diffie-hellman-group14-sha256",
        b"sntrup761x25519-sha512@openssh.com",
        b"x-unknown-kex",
    ];

    /// The six marker names (RFC 8308 §2.1; draft-ietf-sshm-strict-kex-02
    /// §3.1 standard and pre-standard spellings).
    pub const MARKERS: &[&[u8]] = &[
        b"ext-info-c",
        b"ext-info-s",
        b"kex-strict-c-v00@openssh.com",
        b"kex-strict-s-v00@openssh.com",
        b"kex-strict-c",
        b"kex-strict-s",
    ];

    pub const HOST_KEYS: &[&[u8]] = &[
        b"ssh-ed25519",
        b"rsa-sha2-512",
        b"rsa-sha2-256",
        b"ssh-rsa",
        b"ecdsa-sha2-nistp256",
        b"sk-ssh-ed25519@openssh.com",
    ];

    pub const CIPHERS: &[&[u8]] = &[
        b"aes128-gcm@openssh.com",
        b"aes256-gcm@openssh.com",
        b"aes128-ctr",
        b"aes256-ctr",
        b"chacha20-poly1305@openssh.com",
        b"none",
    ];

    pub const MACS: &[&[u8]] = &[
        b"hmac-sha2-256",
        b"hmac-sha2-512",
        b"hmac-sha2-256-etm@openssh.com",
        b"umac-64@openssh.com",
        b"none",
        b"x-unknown-mac",
    ];

    pub const COMPRESSIONS: &[&[u8]] = &[b"none", b"zlib", b"zlib@openssh.com", b"x-unknown-comp"];

    pub const LANGUAGES: &[&[u8]] = &[b"en-US", b"en", b"de"];

    /// Owned lists in wire order (RFC 4253 §7.1).
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Lists {
        pub cookie: [u8; 16],
        pub kex: Vec<Vec<u8>>,
        pub host_key: Vec<Vec<u8>>,
        pub enc_c2s: Vec<Vec<u8>>,
        pub enc_s2c: Vec<Vec<u8>>,
        pub mac_c2s: Vec<Vec<u8>>,
        pub mac_s2c: Vec<Vec<u8>>,
        pub comp_c2s: Vec<Vec<u8>>,
        pub comp_s2c: Vec<Vec<u8>>,
        pub lang_c2s: Vec<Vec<u8>>,
        pub lang_s2c: Vec<Vec<u8>>,
        pub first_kex_packet_follows: bool,
        pub reserved: u32,
    }

    fn put_u32(out: &mut Vec<u8>, v: u32) {
        out.push((v >> 24) as u8);
        out.push((v >> 16) as u8);
        out.push((v >> 8) as u8);
        out.push(v as u8);
    }

    fn put_name_list(out: &mut Vec<u8>, names: &[Vec<u8>]) {
        let mut body = Vec::new();
        for (i, n) in names.iter().enumerate() {
            if i > 0 {
                body.push(b',');
            }
            body.extend_from_slice(n);
        }
        put_u32(out, body.len() as u32);
        out.extend_from_slice(&body);
    }

    impl Lists {
        /// The ten lists in wire order.
        #[must_use]
        pub fn slots(&self) -> [&Vec<Vec<u8>>; 10] {
            [
                &self.kex,
                &self.host_key,
                &self.enc_c2s,
                &self.enc_s2c,
                &self.mac_c2s,
                &self.mac_s2c,
                &self.comp_c2s,
                &self.comp_s2c,
                &self.lang_c2s,
                &self.lang_s2c,
            ]
        }

        /// Hand-assembled `KEXINIT` payload (message number included).
        #[must_use]
        pub fn payload(&self) -> Vec<u8> {
            let mut out = vec![20u8];
            out.extend_from_slice(&self.cookie);
            for list in self.slots() {
                put_name_list(&mut out, list);
            }
            out.push(u8::from(self.first_kex_packet_follows));
            put_u32(&mut out, self.reserved);
            out
        }

        /// The lists Tatami's `ClientProposal` sends, restated from the
        /// negotiate module documentation.
        #[must_use]
        pub fn tatami_client(cookie: [u8; 16], ext_info: bool, strict: bool) -> Lists {
            let mut kex: Vec<Vec<u8>> = vec![b"curve25519-sha256".to_vec()];
            if ext_info {
                kex.push(b"ext-info-c".to_vec());
            }
            if strict {
                kex.push(b"kex-strict-c-v00@openssh.com".to_vec());
                kex.push(b"kex-strict-c".to_vec());
            }
            let one = |n: &[u8]| vec![n.to_vec()];
            Lists {
                cookie,
                kex,
                host_key: one(b"ssh-ed25519"),
                enc_c2s: one(b"aes128-gcm@openssh.com"),
                enc_s2c: one(b"aes128-gcm@openssh.com"),
                mac_c2s: one(b"hmac-sha2-256"),
                mac_s2c: one(b"hmac-sha2-256"),
                comp_c2s: one(b"none"),
                comp_s2c: one(b"none"),
                lang_c2s: Vec::new(),
                lang_s2c: Vec::new(),
                first_kex_packet_follows: false,
                reserved: 0,
            }
        }
    }

    /// Byte to a valid name byte.
    fn sanitize_name(b: u8) -> u8 {
        if (0x21..=0x7e).contains(&b) && b != b',' {
            b
        } else {
            b'a' + b % 26
        }
    }

    /// One name from `pool` (index byte below the pool length plus the
    /// marker table), or a short fuzz name of sanitized bytes.
    pub fn gen_name(cur: &mut Cursor<'_>, pool: &[&[u8]], with_markers: bool) -> Vec<u8> {
        let idx = usize::from(cur.u8());
        let table_len = pool.len() + if with_markers { MARKERS.len() } else { 0 };
        if idx < pool.len() {
            pool[idx].to_vec()
        } else if idx < table_len {
            MARKERS[idx - pool.len()].to_vec()
        } else {
            let len = 1 + (idx - table_len) % 12;
            cur.take_filled(len, 17)
                .into_iter()
                .map(sanitize_name)
                .collect()
        }
    }

    /// A list of `count u8 mod 5` names from `pool`.
    pub fn gen_list(cur: &mut Cursor<'_>, pool: &[&[u8]], with_markers: bool) -> Vec<Vec<u8>> {
        let count = usize::from(cur.u8()) % 5;
        (0..count)
            .map(|_| gen_name(cur, pool, with_markers))
            .collect()
    }

    /// Layout: cookie 16, then for each of the ten lists `count u8 mod 5`
    /// and per name an index byte (fuzz names consume more), then a flags
    /// byte (bit0 first_kex_packet_follows, bit1 reserved u32 follows).
    pub fn gen_lists(cur: &mut Cursor<'_>) -> Lists {
        let cookie: [u8; 16] = cur.take_filled(16, 23).try_into().expect("16 bytes");
        let kex = gen_list(cur, KEX_METHODS, true);
        let host_key = gen_list(cur, HOST_KEYS, false);
        let enc_c2s = gen_list(cur, CIPHERS, false);
        let enc_s2c = gen_list(cur, CIPHERS, false);
        let mac_c2s = gen_list(cur, MACS, false);
        let mac_s2c = gen_list(cur, MACS, false);
        let comp_c2s = gen_list(cur, COMPRESSIONS, false);
        let comp_s2c = gen_list(cur, COMPRESSIONS, false);
        let lang_c2s = gen_list(cur, LANGUAGES, false);
        let lang_s2c = gen_list(cur, LANGUAGES, false);
        let flags = cur.u8();
        let reserved = if flags & 2 != 0 { cur.u32() } else { 0 };
        Lists {
            cookie,
            kex,
            host_key,
            enc_c2s,
            enc_s2c,
            mac_c2s,
            mac_s2c,
            comp_c2s,
            comp_s2c,
            lang_c2s,
            lang_s2c,
            first_kex_packet_follows: flags & 1 != 0,
            reserved,
        }
    }
}

/// Independent RFC 4253 §7.1 negotiation model for the first profile.
pub mod negotiate_ref {
    use tatami_tcp::negotiate::{Direction, Mac, Negotiated, NegotiationError, StrictKex};

    use super::lists::{Lists, MARKERS};

    /// A `kex_algorithms` entry that is a marker, never a method.
    #[must_use]
    pub fn is_marker(name: &[u8]) -> bool {
        MARKERS.contains(&name)
    }

    fn contains(list: &[Vec<u8>], name: &[u8]) -> bool {
        list.iter().any(|n| n == name)
    }

    /// First client entry the server also lists.
    fn first_common<'a>(client: &'a [Vec<u8>], server: &[Vec<u8>]) -> Option<&'a [u8]> {
        client
            .iter()
            .map(Vec::as_slice)
            .find(|c| contains(server, c))
    }

    /// First real method (markers skipped).
    fn first_method(list: &[Vec<u8>]) -> Option<&[u8]> {
        list.iter().map(Vec::as_slice).find(|n| !is_marker(n))
    }

    fn text(name: &[u8]) -> String {
        String::from_utf8_lossy(name).into_owned()
    }

    /// Marker evaluation: each side offered which spelling; strict is in
    /// effect iff a client-role and a server-role marker of the *same*
    /// spelling were both offered.
    #[must_use]
    pub fn strict(client: &Lists, server: &Lists) -> StrictKex {
        let offered_pre_standard = contains(&client.kex, b"kex-strict-c-v00@openssh.com");
        let offered_standard = contains(&client.kex, b"kex-strict-c");
        let server_pre_standard = contains(&server.kex, b"kex-strict-s-v00@openssh.com");
        let server_standard = contains(&server.kex, b"kex-strict-s");
        StrictKex {
            offered_pre_standard,
            offered_standard,
            server_pre_standard,
            server_standard,
            negotiated: (offered_pre_standard && server_pre_standard)
                || (offered_standard && server_standard),
        }
    }

    /// The client-side half of [`strict`] before the server is known.
    #[must_use]
    pub fn strict_offered(client: &Lists) -> StrictKex {
        StrictKex {
            offered_pre_standard: contains(&client.kex, b"kex-strict-c-v00@openssh.com"),
            offered_standard: contains(&client.kex, b"kex-strict-c"),
            server_pre_standard: false,
            server_standard: false,
            negotiated: false,
        }
    }

    /// The model. Failure order: kex, host key, cipher c2s, cipher s2c, MAC
    /// c2s, MAC s2c, compression c2s, compression s2c.
    pub fn negotiate(client: &Lists, server: &Lists) -> Result<Negotiated, NegotiationError> {
        let kex = client
            .kex
            .iter()
            .map(Vec::as_slice)
            .filter(|c| !is_marker(c))
            .find(|c| contains(&server.kex, c))
            .ok_or(NegotiationError::NoCommonKex)?;
        let host_key = first_common(&client.host_key, &server.host_key)
            .ok_or(NegotiationError::NoCommonHostKey)?;
        let enc_c2s = first_common(&client.enc_c2s, &server.enc_c2s)
            .ok_or(NegotiationError::NoCommonCipher(Direction::ClientToServer))?;
        let enc_s2c = first_common(&client.enc_s2c, &server.enc_s2c)
            .ok_or(NegotiationError::NoCommonCipher(Direction::ServerToClient))?;
        let aead = |c: &[u8]| c == b"aes128-gcm@openssh.com";
        if !aead(enc_c2s) {
            return Err(NegotiationError::NoMacImplemented(
                Direction::ClientToServer,
            ));
        }
        if !aead(enc_s2c) {
            return Err(NegotiationError::NoMacImplemented(
                Direction::ServerToClient,
            ));
        }
        let comp_c2s = first_common(&client.comp_c2s, &server.comp_c2s).ok_or(
            NegotiationError::NoCommonCompression(Direction::ClientToServer),
        )?;
        let comp_s2c = first_common(&client.comp_s2c, &server.comp_s2c).ok_or(
            NegotiationError::NoCommonCompression(Direction::ServerToClient),
        )?;
        let server_guess_wrong = server.first_kex_packet_follows
            && !(first_method(&client.kex) == first_method(&server.kex)
                && client.host_key.first() == server.host_key.first());
        Ok(Negotiated {
            kex: text(kex),
            host_key: text(host_key),
            encryption_client_to_server: text(enc_c2s),
            encryption_server_to_client: text(enc_s2c),
            mac_client_to_server: Mac::ImplicitAead,
            mac_server_to_client: Mac::ImplicitAead,
            compression_client_to_server: text(comp_c2s),
            compression_server_to_client: text(comp_s2c),
            strict_kex: strict(client, server),
            ext_info: contains(&server.kex, b"ext-info-s"),
            server_guess_wrong,
        })
    }

    /// The profile check: only the first-profile selection is implemented.
    pub fn check_profile(n: &Negotiated) -> Result<(), NegotiationError> {
        let bad = |field: &'static str, name: &str| {
            Err(NegotiationError::UnsupportedSelection {
                field,
                name: String::from(name),
            })
        };
        if n.kex != "curve25519-sha256" {
            return bad("kex_algorithms", &n.kex);
        }
        if n.host_key != "ssh-ed25519" {
            return bad("server_host_key_algorithms", &n.host_key);
        }
        if n.encryption_client_to_server != "aes128-gcm@openssh.com" {
            return bad(
                "encryption_algorithms_client_to_server",
                &n.encryption_client_to_server,
            );
        }
        if n.encryption_server_to_client != "aes128-gcm@openssh.com" {
            return bad(
                "encryption_algorithms_server_to_client",
                &n.encryption_server_to_client,
            );
        }
        if n.compression_client_to_server != "none" {
            return bad(
                "compression_algorithms_client_to_server",
                &n.compression_client_to_server,
            );
        }
        if n.compression_server_to_client != "none" {
            return bad(
                "compression_algorithms_server_to_client",
                &n.compression_server_to_client,
            );
        }
        Ok(())
    }

    /// The closed set of `NegotiationError::code()` values.
    pub const ERROR_CODES: [&str; 6] = [
        "no_common_kex",
        "no_common_host_key",
        "no_common_cipher",
        "no_mac_implemented",
        "no_common_compression",
        "unsupported_selection",
    ];
}

/// The harness's own server-side cryptography, providers called directly.
pub mod crypto {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit};
    use rand_core::{CryptoRng, RngCore};
    use sha2::{Digest, Sha256};

    /// SSH `string`.
    pub fn put_string(out: &mut Vec<u8>, b: &[u8]) {
        out.extend_from_slice(&(b.len() as u32).to_be_bytes());
        out.extend_from_slice(b);
    }

    /// SSH `string` as a fresh vector.
    #[must_use]
    pub fn string(b: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + b.len());
        put_string(&mut v, b);
        v
    }

    /// Positive `mpint` (RFC 4251 §5) of an unsigned magnitude: leading
    /// zeros stripped, `0x00` prepended when the top bit is set, with the
    /// length prefix.
    #[must_use]
    pub fn mpint(magnitude: &[u8]) -> Vec<u8> {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        let m = &magnitude[start..];
        let mut body = Vec::with_capacity(m.len() + 1);
        if m.first().is_some_and(|&b| b & 0x80 != 0) {
            body.push(0);
        }
        body.extend_from_slice(m);
        string(&body)
    }

    /// `ssh-ed25519` public-key blob (RFC 8709 §4) by hand.
    #[must_use]
    pub fn ed25519_key_blob(pk: &[u8; 32]) -> Vec<u8> {
        let mut b = string(b"ssh-ed25519");
        b.extend(string(pk));
        b
    }

    /// `ssh-ed25519` signature blob (RFC 8709 §6) by hand.
    #[must_use]
    pub fn ed25519_sig_blob(sig: &[u8; 64]) -> Vec<u8> {
        let mut b = string(b"ssh-ed25519");
        b.extend(string(sig));
        b
    }

    /// The exchange-hash inputs as they appeared on the wire.
    pub struct HashInputs<'a> {
        pub v_c: &'a [u8],
        pub v_s: &'a [u8],
        pub i_c: &'a [u8],
        pub i_s: &'a [u8],
        pub k_s: &'a [u8],
        pub q_c: &'a [u8],
        pub q_s: &'a [u8],
        pub k: &'a [u8; 32],
    }

    /// `H = SHA256(string V_C || string V_S || string I_C || string I_S ||
    /// string K_S || string Q_C || string Q_S || mpint K)` (RFC 5656 §4 with
    /// RFC 8731 §3's `mpint K`).
    #[must_use]
    pub fn exchange_hash(i: &HashInputs<'_>) -> [u8; 32] {
        let mut h = Sha256::new();
        for part in [i.v_c, i.v_s, i.i_c, i.i_s, i.k_s, i.q_c, i.q_s] {
            h.update((part.len() as u32).to_be_bytes());
            h.update(part);
        }
        h.update(mpint(i.k));
        h.finalize().into()
    }

    /// RFC 4253 §7.2: `K1 = HASH(K || H || X || session_id)`,
    /// `K2 = HASH(K || H || K1)`, ... concatenated and truncated to `n`.
    #[must_use]
    pub fn derive(
        k: &[u8; 32],
        h: &[u8; 32],
        letter: u8,
        session_id: &[u8; 32],
        n: usize,
    ) -> Vec<u8> {
        let k_mpint = mpint(k);
        let mut out: Vec<u8> = Sha256::new()
            .chain_update(&k_mpint)
            .chain_update(h)
            .chain_update([letter])
            .chain_update(session_id)
            .finalize()
            .to_vec();
        while out.len() < n {
            let next: [u8; 32] = Sha256::new()
                .chain_update(&k_mpint)
                .chain_update(h)
                .chain_update(&out)
                .finalize()
                .into();
            out.extend_from_slice(&next);
        }
        out.truncate(n);
        out
    }

    /// Key and initial nonce for one direction of `aes128-gcm@openssh.com`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DirKeys {
        pub key: [u8; 16],
        pub iv: [u8; 12],
    }

    /// Both directions: `A`/`C` client to server, `B`/`D` server to client.
    #[must_use]
    pub fn derive_gcm(k: &[u8; 32], h: &[u8; 32], session_id: &[u8; 32]) -> (DirKeys, DirKeys) {
        let take16 = |v: Vec<u8>| -> [u8; 16] { v.try_into().expect("16") };
        let take12 = |v: Vec<u8>| -> [u8; 12] { v.try_into().expect("12") };
        let c2s = DirKeys {
            iv: take12(derive(k, h, b'A', session_id, 12)),
            key: take16(derive(k, h, b'C', session_id, 16)),
        };
        let s2c = DirKeys {
            iv: take12(derive(k, h, b'B', session_id, 12)),
            key: take16(derive(k, h, b'D', session_id, 16)),
        };
        (c2s, s2c)
    }

    /// Protected-packet padding rule (RFC 5647 §7.2 / RFC 4253 §6 with a
    /// 16-byte block): `1 + payload + padding` is a multiple of 16 with at
    /// least 4 bytes of padding.
    #[must_use]
    pub fn padding_len(payload_len: usize) -> usize {
        let n = 1 + payload_len;
        let mut pad = 16 - (n % 16);
        if pad < 4 {
            pad += 16;
        }
        pad
    }

    /// One AES-128-GCM direction in the RFC 5647 layout: the nonce is a
    /// 4-byte fixed field and an 8-byte big-endian counter incremented
    /// after every packet.
    pub struct Gcm {
        cipher: Aes128Gcm,
        fixed: [u8; 4],
        counter: u64,
    }

    impl Gcm {
        #[must_use]
        pub fn new(key: &[u8; 16], iv: &[u8; 12]) -> Self {
            Gcm {
                cipher: Aes128Gcm::new(GenericArray::from_slice(key)),
                fixed: iv[..4].try_into().expect("4"),
                counter: u64::from_be_bytes(iv[4..].try_into().expect("8")),
            }
        }

        /// The nonce the next packet uses.
        #[must_use]
        pub fn nonce(&self) -> [u8; 12] {
            let mut n = [0u8; 12];
            n[..4].copy_from_slice(&self.fixed);
            n[4..].copy_from_slice(&self.counter.to_be_bytes());
            n
        }

        /// Packets sealed or opened so far relative to the initial nonce.
        #[must_use]
        pub fn counter(&self) -> u64 {
            self.counter
        }

        /// Seals `payload` with the given padding bytes (`padding.len()`
        /// must equal [`padding_len`]) into a complete packet.
        #[must_use]
        pub fn seal_with_padding(&mut self, payload: &[u8], padding: &[u8]) -> Vec<u8> {
            assert_eq!(padding.len(), padding_len(payload.len()));
            let packet_length = (1 + payload.len() + padding.len()) as u32;
            let aad = packet_length.to_be_bytes();
            let mut body = vec![padding.len() as u8];
            body.extend_from_slice(payload);
            body.extend_from_slice(padding);
            let tag = self
                .cipher
                .encrypt_in_place_detached(GenericArray::from_slice(&self.nonce()), &aad, &mut body)
                .expect("small buffers");
            self.counter = self.counter.wrapping_add(1);
            let mut out = aad.to_vec();
            out.extend(body);
            out.extend_from_slice(&tag);
            out
        }

        /// Seals with zero padding.
        #[must_use]
        pub fn seal(&mut self, payload: &[u8]) -> Vec<u8> {
            let pad = vec![0u8; padding_len(payload.len())];
            self.seal_with_padding(payload, &pad)
        }

        /// Opens one packet from the front of `buf`: `Some((payload,
        /// total_len))` when the tag verifies, `None` otherwise (the counter
        /// then does not advance).
        pub fn open(&mut self, buf: &[u8]) -> Option<(Vec<u8>, usize)> {
            if buf.len() < 4 {
                return None;
            }
            let packet_length = u32::from_be_bytes(buf[..4].try_into().expect("4")) as usize;
            let total = 4 + packet_length + 16;
            if buf.len() < total {
                return None;
            }
            let mut body = buf[4..4 + packet_length].to_vec();
            let tag = GenericArray::clone_from_slice(&buf[4 + packet_length..total]);
            self.cipher
                .decrypt_in_place_detached(
                    GenericArray::from_slice(&self.nonce()),
                    &buf[..4],
                    &mut body,
                    &tag,
                )
                .ok()?;
            self.counter = self.counter.wrapping_add(1);
            let pad = usize::from(*body.first()?);
            if pad < 4 || pad + 1 > packet_length {
                return None;
            }
            Some((body[1..packet_length - pad].to_vec(), total))
        }
    }

    /// Deterministic byte stream (xorshift64*) usable both as the client's
    /// entropy source and as a reproducible padding source. `CryptoRng` is
    /// asserted only so the harness can hand it to `CryptoRngCore` APIs;
    /// it is not cryptographic and lives only in the harness.
    #[derive(Clone, Debug)]
    pub struct HarnessRng {
        state: u64,
        fail_after: Option<usize>,
        drawn: usize,
    }

    impl HarnessRng {
        /// A stream seeded from up to eight fuzz bytes (never the all-zero
        /// state).
        #[must_use]
        pub fn new(seed: u64) -> Self {
            HarnessRng {
                state: seed | 1,
                fail_after: None,
                drawn: 0,
            }
        }

        /// A stream whose `try_fill_bytes` fails once `limit` bytes were
        /// drawn.
        #[must_use]
        pub fn failing_after(seed: u64, limit: usize) -> Self {
            HarnessRng {
                fail_after: Some(limit),
                ..Self::new(seed)
            }
        }

        fn next(&mut self) -> u64 {
            let mut x = self.state;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.state = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    impl RngCore for HarnessRng {
        fn next_u32(&mut self) -> u32 {
            (self.next() >> 32) as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.next()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            self.drawn += dest.len();
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            if let Some(limit) = self.fail_after
                && self.drawn + dest.len() > limit
            {
                // Custom code without `rand_core/std`.
                return Err(rand_core::Error::from(
                    core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START + 1)
                        .expect("nonzero"),
                ));
            }
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for HarnessRng {}
}

pub use crate::tcp_support::Cursor;
