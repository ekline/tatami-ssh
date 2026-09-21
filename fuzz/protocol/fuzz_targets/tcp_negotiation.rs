#![no_main]
//! `tatami_tcp::negotiate`: RFC 4253 §7.1 algorithm negotiation for the
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
//! - `ClientProposal::encode` equals a hand-assembled `KEXINIT`,
//!   `kex_algorithms()` lists the method then the markers in order, decode
//!   returns the lists, and `negotiate(ours, server)` equals the model.
//! - `NegotiationError::code()` is from the closed six-string set and
//!   `Display` is non-empty for every error and direction.

use libfuzzer_sys::fuzz_target;
use tatami_fuzz_protocol::kex_support::lists::{Lists, gen_lists};
use tatami_fuzz_protocol::kex_support::negotiate_ref;
use tatami_fuzz_protocol::tcp_support::Cursor;
use tatami_tcp::negotiate::{
    ClientProposal, Direction, Mac, NegotiationError, StrictKex, is_aead, negotiate,
};
use tatami_wire::kexinit::{KexInit, KexName, classify_kex_name};

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

fn check_proposal(cookie: [u8; 16], ext_info: bool, strict: bool, server: &Lists) {
    let p = ClientProposal {
        cookie,
        advertise_ext_info: ext_info,
        offer_strict_kex: strict,
    };
    let ours = Lists::tatami_client(cookie, ext_info, strict);
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
    if let Ok(n) = negotiate(&k, &s) {
        assert_eq!(
            n.check_profile(),
            Ok(()),
            "our proposal can only select the profile"
        );
        assert_eq!(n.kex, "curve25519-sha256");
        assert_eq!(n.host_key, "ssh-ed25519");
        assert_eq!(n.ext_info, server.kex.contains(&b"ext-info-s".to_vec()));
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
        let server = gen_lists(&mut cur);
        check_proposal(cookie, flags & 2 != 0, flags & 4 != 0, &server);
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
            check_proposal([0x5a; 16], true, true, &server);
        }
    }
});
