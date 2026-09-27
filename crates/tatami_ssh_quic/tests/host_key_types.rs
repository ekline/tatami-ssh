//! RSA and ECDSA P-256 SSH host keys presented over QUIC as RFC 7250 raw
//! public keys and judged by the same `HostTrustPolicy` as TCP.
//!
//! In memory, no sockets. Fixture keys were generated with OpenSSH_10.2p1
//! (`ssh-keygen -t rsa -b 2048` / `-t ecdsa -b 256`, test use only) and
//! converted by OpenSSL (`ssh-keygen -p -m PEM`) into the PKCS#1 / SEC1
//! forms `tatami_ssh_keys::openssh_key` produces. Covers: pin and
//! `known_hosts` success with the OpenSSH fingerprint; wrong key, revoked
//! key and a host listed only with another key type; public/private and
//! type mismatches at load; keys the provider cannot sign with; and live
//! proof of possession (a trusted key advertised while `CertificateVerify`
//! is made by another key, of the same or another type, fails).

#![cfg(all(feature = "quinn-backend", feature = "rsa", feature = "ecdsa-p256"))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64ct::{Base64, Encoding as _};
use tatami_ssh_keys::KeyType;
use tatami_ssh_keys::known_hosts::{KnownHosts, Limits};
use tatami_ssh_keys::trust::{PinnedSha256, SharedHostTrustPolicy, TrustDecision, UntrustedReason};
use tatami_ssh_quic::diag::client::{DiagClientConfig, HandshakeResult};
use tatami_ssh_quic::diag::identity::{
    HostKeyIdentity, IdentityError, PresentedIdentity, PrivateKeyEncoding, ServerIdentity,
};
use tatami_ssh_quic::diag::inmem::{Pair, raw_handshake};
use tatami_ssh_quic::diag::quinn_proto::crypto::rustls::QuicServerConfig;
use tatami_ssh_quic::diag::rustls;
use tatami_ssh_quic::diag::server::{DiagServerConfig, HandshakeOutcome};
use tatami_ssh_quic::diag::tls::{
    ClientTrust, SshHostTrust, SshIdentityCheck, client_crypto_recording, identity_slot, provider,
    scheme_matches_key,
};
use tatami_ssh_quic::keys::Sha256Fingerprint;

const ALPN: &[u8] = b"tatami-diag/0";

struct Fixture {
    encoding: PrivateKeyEncoding,
    der: &'static str,
    public: &'static str,
    fingerprint: &'static str,
    key_type: KeyType,
}

const RSA_A: Fixture = Fixture {
    encoding: PrivateKeyEncoding::Pkcs1,
    der: "MIIEogIBAAKCAQEAv6VEqSv26Q53FO+bmICfsULcbqiEx803fSFMxYDTZadWrbDIBvqZSoIAPd4zGj7knPzyq59EoSEnKNVFmWoynjV8jto3XLFrcIkVy0ES1hYE99PKcrp6TJnsEtN8SYO5wYZ3lkj2y4769z8QC7A2UqZU0wpdeSMrsL3KKteCafqDyduyc+97EUWKnMF6MqzKn4Djm+ZE3kvhBttOnX9c38FZCzZs04fjd3OZK3XOPXkI4NyShrM0I6SKLX8iUjsLQ0x63sRXK2CYFzT42srYDtzieVJwL17kApdmHg7t6cCVLopeaxhXyzZaGuaZkg9Gt+HP/CMVJey2VQm0lhhrXQIDAQABAoIBAAhlDial6x0m2c8ENundeoFKhzrerWBOLDfSOVlubPQnOhwGIiDyIbxaiPWs0cq8xgldaCjd42T2fY9jljaj6P82oxPj2ah5ChaGHrsGSPOxR7ruX1AavIg19toVQvy6ZSzlvb/KxurAQtyJOeP1Lk/9Arqy2cjYYk3N5njtc0Q+llahz8HF2kkRmJsEF+y+WI+e8GaO5QETcTnPbEE7J6FWFVhSuwDd5n9MWio5eUQUa9DzhjIHXAs7lNpcWVnN9uypDW1HcKmGANq+Uak8gH6/GlCV7mlF1Mgk3OjqtOEvxifyJqO4bD51rMtDWov3iUK1TKxnaAn6byUYwq3Gk4ECgYEA4HxmN818pH0dSdioNyqFZz/kQT4Q3xfECOeKSW4Ow2XtVeL675K5hDI9KB7yHN0yDwVHlPys1pV6xqFNVf2KGOkb7kO8COUMZEYID1kjacKHD6eYhQwmijp/zRzSqrhnvwAfndkEiypjjE+xWK18Xg0E81ZiqvZBsC2ACoUZf90CgYEA2oymBcz8Hk4TdajFYB4W0an76ogqYEWFYyV6horrYkyqBFMkKcEMfq/bgiQzTVx4ekJe6i7zHpEpYJF1zDpbOpK6lbdsohpOX1AIvN6JsUqQt+TPY0LEPVY/OzZIyZbna3Dvy04v5ImlJVMqNnP7jt5PwKaMDTsyRQrmDDNZoYECgYA9gHd0xFxoqEp05+G2M3UXA38ijMGMjXNMyTquwXNT/0HVrPj41+bxm937dvb4B3XmfZjN7afgplVbw+dvLqY+Cud3EKGcgjwx4KnmopI8MGpWVKFJmjmY10waQtJIqXrq7jq7QTCoe/WIBHFfDTCsh76aeElR82Otw9l3iF2jFQKBgAynxllhpFvQ45mVm1BUjbe4YykSl3mZrP6vxeeSlczMaa/0bIyqbCHN5yUjGYFqUGOsAjkHXPaxKzc3VR3tZyj+JCXVSEoewdkNFmRxcoG8sqKjckrqK9jtbJ3uJ8rcnSwAjzIzpdxTCCggJ7qdfryoLPAX9NYzTlbnKakdNByBAoGAaKSruN1CEJTTaZ86nMrTMvQmon7qj4BgJT/S+lhLdvZv0R7gy8QNyV7mxfryDMLbYLNMk2EGStN3hkCGMKNHDXhutCG7HqP9jEEubMZUad77O6bAndA3b6ycttA5qJ/y5EQg60/Dzd6+wI1sc9RHu+g+Wr+KaQ2PLOFDvUGIa2k=",
    public: "AAAAB3NzaC1yc2EAAAADAQABAAABAQC/pUSpK/bpDncU75uYgJ+xQtxuqITHzTd9IUzFgNNlp1atsMgG+plKggA93jMaPuSc/PKrn0ShISco1UWZajKeNXyO2jdcsWtwiRXLQRLWFgT308pyunpMmewS03xJg7nBhneWSPbLjvr3PxALsDZSplTTCl15Iyuwvcoq14Jp+oPJ27Jz73sRRYqcwXoyrMqfgOOb5kTeS+EG206df1zfwVkLNmzTh+N3c5krdc49eQjg3JKGszQjpIotfyJSOwtDTHrexFcrYJgXNPjaytgO3OJ5UnAvXuQCl2YeDu3pwJUuil5rGFfLNloa5pmSD0a34c/8IxUl7LZVCbSWGGtd",
    fingerprint: "SHA256:xo85+YH/IOJ/kQz2hVqUbirzalxWNzzNn3z5MbwJkWA",
    key_type: KeyType::Rsa,
};
const RSA_B: Fixture = Fixture {
    encoding: PrivateKeyEncoding::Pkcs1,
    der: "MIIEpAIBAAKCAQEAy1A5biID9DaLRFAQpmGKgUmsGu91SR5GIr00WilWY8bWwQlOXZPsfj6g7f6PfkA3CcCbX6ODkRQKE0U/cIF0cE1/wrtN17qyslvdWMQ50f6TloBqus3n8lix70bmsf6eES8/STUAhwNUvrx7RuPKm+R1iiBwtNA0UhPIKz8WfcBb6PIIURg9P2MNcG5Q51sqHjg6s9rdSSVhuieF+2nFUOOjx8y4ZvKoW6BStnoswGDTTSB6S0kbOMOZqXz5hADVP67k4eLLzEeLAuvqA/zuQiDRLc2MflRsMs1g8NHKxldyzaVamQ4PD4UiAgYM0dY9PfTD4BvDzSWrV05Y0VRgLQIDAQABAoIBAA8vg8qdEcyI0mgcztGOkYjMluVAI3N9pmFr3mApnEFBlcK/TjIhHVXkmaKNE+yrITFCSJihHu+UHpiH4JAnqynEMBm8YbkOQdCeme7KYUM1D5L7Ln2baYqpY0jq88oxqV7BN6nhIpPzBL5mV5LY6sYwDzNs7t4ievXyck4AnU5xEI1bMw//HVdugZVqFitFAuG4mhRSN6ZAdyKyIdRIte0N4lu/snfgHG0J4nCpgcE/OrtkJ2gU9g0hc2KdPQnkAOx+jytvnddwUL9U+C/X/+iAmfp9SlxSCyEw9fWmQP8kpj2sfCQ3oZJWFEoxz/bAKf5chLJN2sW9oZXLFKZ2NoUCgYEA741o3fDYZbnQmhUWSaVnSwJr2k0BM2r9DShOtr34u0V3PyjisTXV41Dk7Z0b6Wxb+9FOsjOIpm4WGU9N2tlE+SGsUy3qZuNpNdNgtxiKcwssifz5K+w7oTqIkQ5tLWgR/PWoS2Tr/b61jBidPZ/9LoYsSCk28HZ7OZXzPsEkpKsCgYEA2UXYUr1vhSz8nYNr7Gj1K8q183fvrsJhk6ILnbEY2ncq8kN+cHA0wkMlRhwkjmOayC4cNm4GUdoG9Ov1gVjVIS1cRzsD/WiSmFrp76yFytay4U8YomHbUaAkOOtt8TvgqVcxNd4dRGmruoGXjkNccbDnwS0BvhMF5aBEv0wgnocCgYEAx9peJuuMXjILysDU+1Q3POkkOdgMrG0R+Swrn2IWZYaq2dKubdHQQ/l1RJfSdYelpg0Vbq53zwIBBdSXy4GAfaiOMEcaTARl/jX/dkHPH/OukOCwsOhBR12iGgLDKyKr/zKj2WK1T9kPdXYDmSok+++MeheIck0muQBVE4HnpEkCgYAzRiJY1E+/E/DBk0Qi1FoXbY0m2cT8bu7sEi+/lQ2ScND3vynViwVIWuQu+XE/EQ5z8z3BMpHXOyatIgob7kTNwZCnVqwIX2dJARt37jTcu3IXbb0YhRNm3e3uaNDXPxQzoloAplwtyuo152NGtWrZgbAPjHl+y6p2mC3hHywLfQKBgQDKbSO9lSkb4ZttUhcvO6eiWnBb4Ku72X1Wm93lPTWQU+KgiiSGNYwUggSjiyYoj1rCfiMfs6oPufRrSI6BsIy+5O5zcR3ckHVEg7kBP+v0wPBBmdMoo6tww/kBwLVU79o7KqlcL6c2gNKBsKr+YHHnK1tsVXd6UHzg8hQiypQuHA==",
    public: "AAAAB3NzaC1yc2EAAAADAQABAAABAQDLUDluIgP0NotEUBCmYYqBSawa73VJHkYivTRaKVZjxtbBCU5dk+x+PqDt/o9+QDcJwJtfo4ORFAoTRT9wgXRwTX/Cu03XurKyW91YxDnR/pOWgGq6zefyWLHvRuax/p4RLz9JNQCHA1S+vHtG48qb5HWKIHC00DRSE8grPxZ9wFvo8ghRGD0/Yw1wblDnWyoeODqz2t1JJWG6J4X7acVQ46PHzLhm8qhboFK2eizAYNNNIHpLSRs4w5mpfPmEANU/ruTh4svMR4sC6+oD/O5CINEtzYx+VGwyzWDw0crGV3LNpVqZDg8PhSICBgzR1j099MPgG8PNJatXTljRVGAt",
    fingerprint: "SHA256:dAzEiMkYfOgdNZHMtkmVfffOnTXFxIAq/42ljNMxFM8",
    key_type: KeyType::Rsa,
};
const P256_A: Fixture = Fixture {
    encoding: PrivateKeyEncoding::Sec1,
    der: "MHcCAQEEILYUyJJ3H2634hSVlQKFu2gLJEWfBiDyCpd43t+LnLJOoAoGCCqGSM49AwEHoUQDQgAE95+pxfTjOLA3JK8xd4sR8N7wXRdILyDTTc07KZTA3S9vlSlnechc0klBp9PjXFDM9cf0MlFvLw0sS1EuBLbQ2g==",
    public: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPefqcX04ziwNySvMXeLEfDe8F0XSC8g003NOymUwN0vb5UpZ3nIXNJJQafT41xQzPXH9DJRby8NLEtRLgS20No=",
    fingerprint: "SHA256:SsEpc4vJWMyCyhf6jvzGGY6gWGY4opN5/12I08W43B4",
    key_type: KeyType::EcdsaP256,
};
const P256_B: Fixture = Fixture {
    encoding: PrivateKeyEncoding::Sec1,
    der: "MHcCAQEEIN9zfrKO3T/bfMPjWMGm7UMTwwd/hZuoZm4LLdefsKsSoAoGCCqGSM49AwEHoUQDQgAEPF1tins7ENHf38Czljlcy1EcsscydqCHFzmb331rzs4FB2XryMryUkuIOJxP9EgUXIOLLVVZqawqwHtZIepVdw==",
    public: "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDxdbYp7OxDR39/As5Y5XMtRHLLHMnaghxc5m999a87OBQdl68jK8lJLiDicT/RIFFyDiy1VWamsKsB7WSHqVXc=",
    fingerprint: "SHA256:a8axUiW/oqHpCM4d6xdbN3VeKK1dnRU5P0zAU79d2vw",
    key_type: KeyType::EcdsaP256,
};
/// 1024-bit RSA: parses, but the provider (and Tatami's policy) refuse it.
const RSA_1024_DER: &str = "MIICXgIBAAKBgQDaHk8Oo0PJIFbw0drZloysH85GmOfyoDgcqK0Hpn95IWPYh2QVc1O43DwNQ0+ZoCQnTC7IxjTpDv/flXnjf0gHBsLojhDOvBTpdKE5Y/fwRM/XiKpOMFpqS+UHwKN5v8HuCK37uPNdhJ24cn2kZSLLvZ8rheglnS7lDbS88aAxTwIDAQABAoGBALLh8IxcsZcdgq/2K7oPkkcHvrB/bpq5c8ttOprvndPF4pEOWLKO5rbRSB7IeVvQzlW8URIwG+yXdJn1iQVeub4lVTOBlcueWEDwJsbwnv6I5Kf7177HneBR7LyQ5b5PXAIckwcTx0X250ayi7lJ0MzpvgMMEUYIwANl6d8sQU4BAkEA+S78pNwYYw3quVDezjKmidu+iT8gH3H/oGFVXH9+Um6h3mJOsig4YbkwNwWdpU0+dfIMyax0J/Z2jOt8Gr9ajwJBAOAVxmwzS/YhMd1v6HeaMlqrULjaEYKk+S3OHuJAwRXAfu+IwgIiOQ3fYWo6y2Ba9YnsuwIExpOn08YNfe24HUECQQDyLg+P7vWot+rsZ0PUpfekPrUFURvYVAR9DHxZJPRSC4I4z9TqZBrAJ6tLnqKj+Nn+6dwx2fEesfRwa6I3oMjTAkEAmtexIvdXWB6b/G3l7y+H+AtFXlahnussnDBAOwuP4N4BWLfhh+PqFOH0yJkUC+MOpF4G42A1b7aaqdKM4AVHgQJAdMVMJJsrwP7uMILYgXldP1A1DbSnwBVxbDun8YAZJAhBoFKoqKQ+DMUQb0fYpxZ+4j1r1okHBQC50hkd6xBHwg==";
const RSA_1024_PUB: &str = "AAAAB3NzaC1yc2EAAAADAQABAAAAgQDaHk8Oo0PJIFbw0drZloysH85GmOfyoDgcqK0Hpn95IWPYh2QVc1O43DwNQ0+ZoCQnTC7IxjTpDv/flXnjf0gHBsLojhDOvBTpdKE5Y/fwRM/XiKpOMFpqS+UHwKN5v8HuCK37uPNdhJ24cn2kZSLLvZ8rheglnS7lDbS88aAxTw==";

fn b64(s: &str) -> Vec<u8> {
    Base64::decode_vec(s).unwrap()
}

fn host(f: &Fixture) -> HostKeyIdentity {
    HostKeyIdentity::from_private_key_der(f.encoding, &b64(f.der), &b64(f.public)).unwrap()
}

fn server_addr() -> SocketAddr {
    "127.0.0.1:4433".parse().unwrap()
}

fn ssh_trust(policy: impl SharedHostTrustPolicy + 'static, source: &'static str) -> ClientTrust {
    ClientTrust::SshHostKey(SshHostTrust {
        policy: Arc::new(policy),
        source,
        lookup_name: None,
    })
}

fn pin(f: &Fixture) -> ClientTrust {
    ssh_trust(
        PinnedSha256(Sha256Fingerprint::of_blob(&b64(f.public))),
        "pinned_fingerprint",
    )
}

fn known_hosts(text: &str) -> ClientTrust {
    let kh = KnownHosts::parse(text.as_bytes(), &Limits::default()).unwrap();
    ssh_trust(kh.policy_for("localhost", 4433).unwrap(), "known_hosts")
}

fn entry(hosts: &str, f: &Fixture) -> String {
    let kind = match f.key_type {
        KeyType::Rsa => "ssh-rsa",
        KeyType::EcdsaP256 => "ecdsa-sha2-nistp256",
        KeyType::Ed25519 => "ssh-ed25519",
    };
    format!("{hosts} {kind} {}\n", f.public)
}

fn run(
    identity: HostKeyIdentity,
    trust: ClientTrust,
) -> (
    tatami_ssh_quic::diag::client::ClientOutcome,
    HandshakeOutcome,
) {
    let mut sc = DiagServerConfig::new(identity, vec![ALPN.to_vec()]);
    sc.bind = server_addr();
    let mut cc = DiagClientConfig::new(server_addr(), "localhost", vec![ALPN.to_vec()], trust);
    cc.handshake_timeout = Duration::from_secs(5);
    let mut pair = Pair::new(&sc, &cc, "127.0.0.1:50004".parse().unwrap()).unwrap();
    assert!(pair.run(10_000), "client did not finish");
    let (client, observations, _) = pair.finish_client();
    assert_eq!(observations.len(), 1, "{observations:?}");
    (client, observations[0].outcome.clone())
}

fn judged(check: &Option<SshIdentityCheck>) -> (String, Sha256Fingerprint, TrustDecision) {
    match check {
        Some(SshIdentityCheck::Judged {
            algorithm,
            fingerprint,
            decision,
            ..
        }) => (algorithm.clone(), *fingerprint, *decision),
        other => panic!("expected a judged identity, got {other:?}"),
    }
}

#[test]
fn rsa_and_p256_identities_complete_with_pins_and_known_hosts() {
    for f in [&RSA_A, &P256_A] {
        let id = host(f);
        assert_eq!(id.key_type(), f.key_type);
        assert_eq!(id.ssh_fingerprint().to_string(), f.fingerprint);
        assert_eq!(
            ServerIdentity::from(id.clone()).presented(),
            PresentedIdentity::SshHostKey {
                key_type: f.key_type,
                fingerprint: id.ssh_fingerprint(),
            }
        );
        for trust in [
            pin(f),
            known_hosts(&format!(
                "{}{}",
                entry("[localhost]:4433", &RSA_B),
                entry("[localhost]:4433", f)
            )),
        ] {
            let (client, server) = run(host(f), trust);
            assert_eq!(client.handshake, HandshakeResult::Completed, "{client:?}");
            assert_eq!(server, HandshakeOutcome::Completed);
            let (algorithm, fp, decision) = judged(&client.ssh_identity);
            assert_eq!(algorithm, f.key_type.to_string());
            assert_eq!(fp.to_string(), f.fingerprint);
            assert!(decision.is_trusted());
        }
    }
}

fn refused(identity: HostKeyIdentity, trust: ClientTrust) -> UntrustedReason {
    let (client, server) = run(identity, trust);
    let HandshakeResult::Failed { reason } = &client.handshake else {
        panic!("expected failure, got {client:?}");
    };
    assert!(reason.contains("SSH host key not trusted"), "{reason}");
    assert_ne!(server, HandshakeOutcome::Completed);
    match judged(&client.ssh_identity).2 {
        TrustDecision::Untrusted { reason } => reason,
        t => panic!("expected untrusted, got {t:?}"),
    }
}

#[test]
fn wrong_revoked_and_other_type_keys_fail() {
    assert_eq!(
        refused(host(&RSA_A), pin(&RSA_B)),
        UntrustedReason::FingerprintMismatch
    );
    assert_eq!(
        refused(
            host(&P256_A),
            known_hosts(&entry("[localhost]:4433", &P256_B))
        ),
        UntrustedReason::KeyChanged { line: 1 }
    );
    for f in [&RSA_A, &P256_A] {
        // Revocation before and after the matching entry.
        let plain = entry("[localhost]:4433", f);
        let revoked = format!("@revoked {}", entry("*", f));
        for (text, line) in [
            (format!("{plain}{revoked}"), 2),
            (format!("{revoked}{plain}"), 1),
        ] {
            assert_eq!(
                refused(host(f), known_hosts(&text)),
                UntrustedReason::Revoked { line }
            );
        }
    }
    // Only another key type is listed for the host.
    assert_eq!(
        refused(
            host(&P256_A),
            known_hosts(&entry("[localhost]:4433", &RSA_A))
        ),
        UntrustedReason::NoKeyForAlgorithm
    );
}

#[test]
fn mismatched_and_unusable_keys_are_refused_at_load() {
    // Private key of A, public blob of B (same type and across types).
    for (f, other) in [(&RSA_A, &RSA_B), (&P256_A, &P256_B), (&RSA_A, &P256_A)] {
        assert!(matches!(
            HostKeyIdentity::from_private_key_der(f.encoding, &b64(f.der), &b64(other.public)),
            Err(IdentityError::HostKeyMismatch)
        ));
    }
    // Container and content disagree.
    assert!(
        HostKeyIdentity::from_private_key_der(
            PrivateKeyEncoding::Sec1,
            &b64(RSA_A.der),
            &b64(RSA_A.public)
        )
        .is_err()
    );
    // Below the provider's (and Tatami's) RSA size.
    assert!(matches!(
        HostKeyIdentity::from_private_key_der(
            PrivateKeyEncoding::Pkcs1,
            &b64(RSA_1024_DER),
            &b64(RSA_1024_PUB)
        ),
        Err(IdentityError::KeyRejected(_))
    ));
    // An inconsistent CRT exponent (dP): `ring` accepts the components (it
    // checks p, q, qInv and sizes, and never uses d), but no valid signature
    // comes out; the load-time proof of possession catches it.
    let mut der = b64(RSA_A.der);
    let dp = der_integers(&der)[6];
    der[dp.0 + dp.1 / 2] ^= 0x01;
    assert!(matches!(
        HostKeyIdentity::from_private_key_der(PrivateKeyEncoding::Pkcs1, &der, &b64(RSA_A.public)),
        Err(IdentityError::KeyRejected(_))
    ));
}

/// (content offset, content length) of each INTEGER directly inside the
/// outer SEQUENCE of a DER `RSAPrivateKey`.
fn der_integers(der: &[u8]) -> Vec<(usize, usize)> {
    fn len_at(der: &[u8], i: usize) -> (usize, usize) {
        match der[i] {
            n @ 0..=0x7f => (usize::from(n), 1),
            0x81 => (usize::from(der[i + 1]), 2),
            0x82 => ((usize::from(der[i + 1]) << 8) | usize::from(der[i + 2]), 3),
            other => panic!("length form {other:#x}"),
        }
    }
    assert_eq!(der[0], 0x30);
    let (_, hdr) = len_at(der, 1);
    let mut i = 1 + hdr;
    let mut out = Vec::new();
    while i < der.len() {
        assert_eq!(der[i], 0x02);
        let (len, n) = len_at(der, i + 1);
        out.push((i + 1 + n, len));
        i += 1 + n + len;
    }
    assert_eq!(out.len(), 9);
    out
}

fn foreign_signature(advertised: &Fixture, signer: &Fixture) {
    let certified = Arc::new(rustls::sign::CertifiedKey::new(
        vec![rustls::pki_types::CertificateDer::from(
            host(advertised).subject_public_key_info_der().to_vec(),
        )],
        host(signer).signing_key(),
    ));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(certified),
        ));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let server_crypto = Arc::new(QuicServerConfig::try_from(tls).unwrap());
    let slot = identity_slot();
    let client_crypto =
        client_crypto_recording(&pin(advertised), &[ALPN.to_vec()], slot.clone()).unwrap();
    let hs = raw_handshake(
        client_crypto,
        server_crypto,
        "localhost",
        Duration::from_secs(5),
        1_000,
    )
    .unwrap();
    assert!(
        hs.client_result.is_err(),
        "client completed with {} advertised and {} signing",
        advertised.fingerprint,
        signer.fingerprint
    );
    let check = slot.lock().unwrap().clone();
    let (_, fp, decision) = judged(&check);
    assert_eq!(fp.to_string(), advertised.fingerprint);
    assert!(
        decision.is_trusted(),
        "the advertised key itself matched the pin"
    );
}

#[test]
fn trusted_key_with_a_foreign_signature_fails() {
    foreign_signature(&RSA_B, &RSA_A);
    foreign_signature(&P256_B, &P256_A);
    // Across types: the scheme no longer belongs to the key.
    foreign_signature(&P256_A, &RSA_A);
    foreign_signature(&RSA_A, &P256_A);
}

#[test]
fn tls13_schemes_per_key_type() {
    use rustls::SignatureScheme as S;
    assert!(scheme_matches_key(S::ED25519, KeyType::Ed25519));
    for s in [S::RSA_PSS_SHA256, S::RSA_PSS_SHA384, S::RSA_PSS_SHA512] {
        assert!(scheme_matches_key(s, KeyType::Rsa), "{s:?}");
    }
    assert!(scheme_matches_key(
        S::ECDSA_NISTP256_SHA256,
        KeyType::EcdsaP256
    ));
    for (s, k) in [
        (S::RSA_PKCS1_SHA256, KeyType::Rsa),
        (S::RSA_PKCS1_SHA1, KeyType::Rsa),
        (S::ECDSA_NISTP384_SHA384, KeyType::EcdsaP256),
        (S::ECDSA_SHA1_Legacy, KeyType::EcdsaP256),
        (S::ED25519, KeyType::Rsa),
        (S::RSA_PSS_SHA256, KeyType::EcdsaP256),
    ] {
        assert!(!scheme_matches_key(s, k), "{s:?} {k:?}");
    }
}
