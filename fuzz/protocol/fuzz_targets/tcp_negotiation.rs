#![no_main]
//! `tatami_ssh_tcp::negotiate`: RFC 4253 §7.1 algorithm negotiation for the
//! first profile, strict-KEX marker pairing, `first_kex_packet_follows`
//! evaluation, the profile check and the client's own proposal.
//!
//! # Input layout
//!
//! ```text
//! byte 0   bit 0: client is Tatami's `ClientProposal` (else fuzz lists)
//!          bit 1: proposal advertises ext-info-c
//!          bit 2: proposal offers strict KEX (both spellings)
//!          bit 3: also feed the raw remainder to `KexInit::decode` as a
//!                 server payload
//!          bit 4: (proposal only) host-key algorithms from fuzz, else
//!                 `HostKeyAlgorithms::ED25519_ONLY`: `count u8` (mod 6),
//!                 `count` scheme indices (mod 4, duplicates allowed) and a
//!                 `preferred` mask byte, all right after the cookie
//! rest     client lists (unless bit 0), then server lists, each per
//!          `kex_support::lists::gen_lists`: cookie 16, ten lists of
//!          `count u8 mod 5` names chosen from small pools (real methods,
//!          all six markers, unknown names, fuzz names, empty lists), flags
//! ```
//!
//! # Oracles
//!
//! - `negotiate(client, server)` equals an INDEPENDENT model of RFC 4253
//!   §7.1 as documented by the crate: first client name present in the
//!   server list, markers excluded on both sides for `kex_algorithms`, MAC
//!   skipped (`ImplicitAead`) iff the selected cipher is
//!   `aes128-gcm@openssh.com` else `NoMacImplemented`, compression by the
//!   same rule, failure order kex → host key → cipher c2s → cipher s2c →
//!   MAC c2s → MAC s2c → compression c2s → s2c; exact `Result` equality
//!   including error variants, `Direction`s, and every `StrictKex` field.
//! - Strict pairing: enabled iff a client-role and a server-role marker of
//!   the SAME spelling were offered; never across spellings.
//!   `StrictKex::evaluate` and `StrictKex::offered` equal the model.
//! - `ext_info` iff the server offered `ext-info-s`; `server_guess_wrong`
//!   iff the server set the flag and either the first real method or the
//!   first host-key algorithm differs.
//! - `check_profile` equals the model (`UnsupportedSelection{field,name}`
//!   for the first field outside the profile).
//! - `ClientProposal::encode` equals a hand-assembled `KEXINIT` (with the
//!   configured host-key list as `server_host_key_algorithms`),
//!   `kex_algorithms()` lists the method then the markers in order, decode
//!   returns the lists, and `negotiate(ours, server)` equals the model.
//! - Host-key algorithms: `HostKeyAlgorithms::new` refuses exactly an empty
//!   list (`Empty`) or the first repeated scheme (`Duplicate`), else keeps
//!   the order; `preferred(pred)` is `PREFERENCE` filtered by `pred` (`None`
//!   if empty); `Default` is `ED25519_ONLY`. The encoded client list never
//!   contains `ssh-rsa` or `ssh-dss`. With our proposal, success selects the
//!   first client-listed scheme the server also offers, `host_key_scheme()`
//!   is that scheme (never `ssh-rsa`), and `check_profile` passes; a server
//!   offering none of our schemes gives `NoCommonHostKey`.
//! - `check_profile` (both paths) accepts exactly the four scheme names
//!   for the host key, and `host_key_scheme()` is `Some` exactly for them.
//! - `NegotiationError::code()` is from the closed six-string set and
//!   `Display` is non-empty for every error and direction.

use libfuzzer_sys::fuzz_target;
use tatami_ssh_fuzz_protocol::kex_support::lists::{Lists, gen_lists};
use tatami_ssh_fuzz_protocol::kex_support::negotiate_ref;
use tatami_ssh_fuzz_protocol::tcp_support::Cursor;
use tatami_ssh_keys::algorithm::SignatureScheme;
use tatami_ssh_tcp::negotiate::{
    ClientProposal, Direction, HostKeyAlgorithms, HostKeyAlgorithmsError, Mac, NegotiationError,
    StrictKex, is_aead, negotiate,
};
use tatami_ssh_wire::kexinit::{KexInit, KexName, classify_kex_name};

fn check_pair(client: &Lists, server: &Lists) {
    let i_c = client.payload();
    let i_s = server.payload();
    let c = KexInit::decode(&i_c).expect("hand-assembled client KEXINIT decodes");
    let s = KexInit::decode(&i_s).expect("hand-assembled server KEXINIT decodes");
    assert_eq!(c.first_kex_packet_follows, client.first_kex_packet_follows);
    assert_eq!(s.first_kex_packet_follows, server.first_kex_packet_follows);
    assert_eq!(s.reserved, server.reserved);

    // Marker classification agrees with the model's table on every name.
    for name in c.kex_algorithms.iter().chain(s.kex_algorithms.iter()) {
        assert_eq!(
            classify_kex_name(name).is_marker(),
            negotiate_ref::is_marker(name),
            "marker table for {name:?}"
        );
        assert_eq!(
            classify_kex_name(name) == KexName::Method,
            !negotiate_ref::is_marker(name)
        );
    }

    let got = negotiate(&c, &s);
    let want = negotiate_ref::negotiate(client, server);
    assert_eq!(
        got, want,
        "negotiate for\n client {client:?}\n server {server:?}"
    );

    let strict = StrictKex::evaluate(&c, &s);
    assert_eq!(
        strict,
        negotiate_ref::strict(client, server),
        "StrictKex::evaluate"
    );
    assert_eq!(
        StrictKex::offered(&c),
        negotiate_ref::strict_offered(client),
        "StrictKex::offered"
    );
    // Mixed spellings never enable strict KEX.
    if strict.negotiated {
        assert!(
            (strict.offered_pre_standard && strict.server_pre_standard)
                || (strict.offered_standard && strict.server_standard),
            "strict without a same-spelling pair: {strict:?}"
        );
    }

    match &got {
        Ok(n) => {
            assert_eq!(n.strict_kex, strict);
            assert!(
                !negotiate_ref::is_marker(n.kex.as_bytes()),
                "a marker was selected as the method: {}",
                n.kex
            );
            assert!(is_aead(n.encryption_client_to_server.as_bytes()));
            assert!(is_aead(n.encryption_server_to_client.as_bytes()));
            assert_eq!(n.mac_client_to_server, Mac::ImplicitAead);
            assert_eq!(n.mac_server_to_client.as_str(), "implicit (AEAD)");
            assert_eq!(n.mac_server_to_client.to_string(), "implicit (AEAD)");
            if !server.first_kex_packet_follows {
                assert!(!n.server_guess_wrong);
            }
            let known = negotiate_ref::HOST_KEY_SCHEMES.contains(&n.host_key.as_str());
            assert_eq!(n.host_key_scheme().is_some(), known, "{}", n.host_key);
            if let Some(s) = n.host_key_scheme() {
                assert_eq!(s.name(), n.host_key.as_bytes());
                assert_ne!(n.host_key, "ssh-rsa");
            }
            assert_eq!(
                n.check_profile(),
                negotiate_ref::check_profile(n),
                "check_profile"
            );
            if let Err(e) = n.check_profile() {
                assert_eq!(e.code(), "unsupported_selection");
                assert!(matches!(e, NegotiationError::UnsupportedSelection { .. }));
            }
        }
        Err(e) => {
            assert!(
                negotiate_ref::ERROR_CODES.contains(&e.code()),
                "code {}",
                e.code()
            );
            assert!(!e.to_string().is_empty());
            // A NoCommonKex from marker-only lists: markers never match.
            let real_common = client
                .kex
                .iter()
                .any(|k| !negotiate_ref::is_marker(k) && server.kex.contains(k));
            assert_eq!(*e == NegotiationError::NoCommonKex, !real_common);
        }
    }
}

const SCHEMES: [SignatureScheme; 4] = SignatureScheme::PREFERENCE;

/// A fuzz-described host-key list: `count u8 % 6`, indices, `preferred`
/// mask. Checks the constructors against their documented rules and returns
/// the list to offer.
fn gen_host_key_algorithms(cur: &mut Cursor<'_>) -> HostKeyAlgorithms {
    let count = usize::from(cur.u8()) % 6;
    let raw: Vec<SignatureScheme> = (0..count)
        .map(|_| SCHEMES[usize::from(cur.u8()) % 4])
        .collect();
    let mask = cur.u8();
    let mut want: Result<Vec<SignatureScheme>, HostKeyAlgorithmsError> = Ok(Vec::new());
    if raw.is_empty() {
        want = Err(HostKeyAlgorithmsError::Empty);
    }
    for (i, s) in raw.iter().enumerate() {
        if raw[..i].contains(s) {
            want = Err(HostKeyAlgorithmsError::Duplicate(*s));
            break;
        }
    }
    let got = HostKeyAlgorithms::new(&raw);
    assert_eq!(
        got.map(|h| h.as_slice().to_vec()),
        want.map(|_| raw.clone()),
        "HostKeyAlgorithms::new({raw:?})"
    );
    let filtered: Vec<SignatureScheme> = SCHEMES
        .iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, s)| *s)
        .collect();
    let preferred = HostKeyAlgorithms::preferred(|s| {
        mask & (1 << SCHEMES.iter().position(|&x| x == s).expect("known")) != 0
    });
    assert_eq!(
        preferred.map(|h| h.as_slice().to_vec()),
        (!filtered.is_empty()).then(|| filtered.clone())
    );
    assert_eq!(
        HostKeyAlgorithms::default(),
        HostKeyAlgorithms::ED25519_ONLY
    );
    assert_eq!(
        HostKeyAlgorithms::ED25519_ONLY.as_slice(),
        &[SignatureScheme::Ed25519]
    );
    match (got, preferred) {
        (Ok(h), _) => h,
        (Err(_), Some(p)) if mask & 0x80 != 0 => p,
        _ => HostKeyAlgorithms::ED25519_ONLY,
    }
}

fn check_proposal(
    cookie: [u8; 16],
    ext_info: bool,
    strict: bool,
    host_keys: HostKeyAlgorithms,
    server: &Lists,
) {
    let p = ClientProposal {
        cookie,
        advertise_ext_info: ext_info,
        offer_strict_kex: strict,
        host_key_algorithms: host_keys,
    };
    let names: Vec<&[u8]> = host_keys.as_slice().iter().map(|s| s.name()).collect();
    let ours = Lists::tatami_client_with_host_keys(cookie, ext_info, strict, &names);
    let encoded = p.encode().expect("fixed proposal encodes");
    assert_eq!(
        encoded,
        ours.payload(),
        "ClientProposal::encode differs from hand assembly"
    );
    let kex: Vec<&[u8]> = ours.kex.iter().map(Vec::as_slice).collect();
    assert_eq!(
        p.kex_algorithms(),
        kex,
        "kex_algorithms() order: method, ext-info-c, both strict spellings"
    );
    let k = KexInit::decode(&encoded).expect("proposal decodes");
    assert_eq!(k.cookie, &cookie);
    for (slot, want) in k.name_lists().iter().zip(ours.slots()) {
        let got: Vec<&[u8]> = slot.iter().collect();
        let want: Vec<&[u8]> = want.iter().map(Vec::as_slice).collect();
        assert_eq!(got, want);
    }
    assert!(!k.first_kex_packet_follows);
    assert_eq!(k.reserved, 0);
    let offered: Vec<&[u8]> = k.server_host_key_algorithms.iter().collect();
    assert_eq!(
        offered, names,
        "server_host_key_algorithms in configured order"
    );
    for legacy in [&b"ssh-rsa"[..], b"ssh-dss"] {
        assert!(
            !k.server_host_key_algorithms.contains(legacy),
            "{legacy:?} offered"
        );
    }
    assert_eq!(
        k.empty_algorithm_lists().count(),
        0,
        "the proposal has no empty required list"
    );
    let offered = StrictKex::offered(&k);
    assert_eq!(offered.offered_pre_standard, strict);
    assert_eq!(offered.offered_standard, strict);
    assert!(!offered.server_pre_standard && !offered.server_standard && !offered.negotiated);
    check_pair(&ours, server);

    // With our proposal, success implies the first profile exactly.
    let i_s = server.payload();
    let s = KexInit::decode(&i_s).expect("decodes");
    let first_shared = host_keys
        .as_slice()
        .iter()
        .copied()
        .find(|sch| server.host_key.iter().any(|h| h == sch.name()));
    match negotiate(&k, &s) {
        Ok(n) => {
            assert_eq!(
                n.check_profile(),
                Ok(()),
                "our proposal can only select the profile"
            );
            assert_eq!(n.kex, "curve25519-sha256");
            let want = first_shared.expect("a host key was selected");
            assert_eq!(n.host_key.as_bytes(), want.name(), "first shared scheme");
            assert_eq!(n.host_key_scheme(), Some(want));
            assert_eq!(n.ext_info, server.kex.contains(&b"ext-info-s".to_vec()));
        }
        Err(NegotiationError::NoCommonKex) => {}
        Err(e) => {
            if first_shared.is_none() {
                assert_eq!(e, NegotiationError::NoCommonHostKey);
            }
        }
    }
}

fn check_error_table() {
    let all = [
        NegotiationError::NoCommonKex,
        NegotiationError::NoCommonHostKey,
        NegotiationError::NoCommonCipher(Direction::ClientToServer),
        NegotiationError::NoMacImplemented(Direction::ServerToClient),
        NegotiationError::NoCommonCompression(Direction::ClientToServer),
        NegotiationError::UnsupportedSelection {
            field: "kex_algorithms",
            name: String::from("x"),
        },
    ];
    for (e, code) in all.iter().zip(negotiate_ref::ERROR_CODES) {
        assert_eq!(e.code(), code);
    }
    assert_eq!(Direction::ClientToServer.to_string(), "client-to-server");
    assert_eq!(Direction::ServerToClient.to_string(), "server-to-client");
}

fuzz_target!(|data: &[u8]| {
    check_error_table();
    let mut cur = Cursor::new(data);
    let flags = cur.u8();
    if flags & 1 != 0 {
        let cookie: [u8; 16] = cur.take_filled(16, 29).try_into().expect("16");
        let host_keys = if flags & 0x10 != 0 {
            gen_host_key_algorithms(&mut cur)
        } else {
            HostKeyAlgorithms::ED25519_ONLY
        };
        let server = gen_lists(&mut cur);
        check_proposal(cookie, flags & 2 != 0, flags & 4 != 0, host_keys, &server);
    } else {
        let client = gen_lists(&mut cur);
        let server = gen_lists(&mut cur);
        check_pair(&client, &server);
        // Symmetric call: the model is defined for any pair.
        check_pair(&server, &client);
    }
    if flags & 8 != 0 {
        // Whatever is left is a raw server payload; a decodable one is
        // negotiated against the default proposal without panicking, and
        // the result again equals the model over the decoded lists.
        let rest = cur.rest();
        if let Ok(s) = KexInit::decode(rest) {
            let server = Lists {
                cookie: *s.cookie,
                kex: s.kex_algorithms.iter().map(<[u8]>::to_vec).collect(),
                host_key: s
                    .server_host_key_algorithms
                    .iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
                enc_c2s: s
                    .encryption_client_to_server
                    .iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
                enc_s2c: s
                    .encryption_server_to_client
                    .iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
                mac_c2s: s.mac_client_to_server.iter().map(<[u8]>::to_vec).collect(),
                mac_s2c: s.mac_server_to_client.iter().map(<[u8]>::to_vec).collect(),
                comp_c2s: s
                    .compression_client_to_server
                    .iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
                comp_s2c: s
                    .compression_server_to_client
                    .iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
                lang_c2s: s
                    .languages_client_to_server
                    .iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
                lang_s2c: s
                    .languages_server_to_client
                    .iter()
                    .map(<[u8]>::to_vec)
                    .collect(),
                first_kex_packet_follows: s.first_kex_packet_follows,
                reserved: s.reserved,
            };
            check_proposal(
                [0x5a; 16],
                true,
                true,
                HostKeyAlgorithms::ED25519_ONLY,
                &server,
            );
            if let Some(all) = HostKeyAlgorithms::preferred(|_| true) {
                check_proposal([0x5a; 16], false, true, all, &server);
            }
        }
    }
});
