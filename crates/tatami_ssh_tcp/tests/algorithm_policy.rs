//! Enabled-algorithm configuration: no SHA-1 operation in what the TCP
//! client advertises, and SHA-256 only for fingerprints, pins and SSHFP.
//!
//! This is the *configuration* half of the SHA-1 boundary. The dependency
//! half (`scripts/check-sha1-boundary.py`) proves where SHA-1 code may be
//! linked; this proves that no protocol list offers, and so no peer can
//! select, a SHA-1 signature, key exchange or MAC. `ssh-rsa` is checked only
//! in the host-key/signature list: as a public-key *blob* type it names RSA
//! keys that are used with `rsa-sha2-*` signatures and stays legal.

#![cfg(feature = "kex")]

use tatami_ssh_keys::blob::encode_ed25519_blob;
use tatami_ssh_keys::fingerprint::Sha256Fingerprint;
use tatami_ssh_keys::sshfp::{Sshfp, TYPE_SHA256};
use tatami_ssh_keys::trust::{HostIdentity, HostTrustPolicy, PinnedSha256};
use tatami_ssh_tcp::negotiate::{ClientProposal, HostKeyAlgorithms};
use tatami_ssh_wire::kexinit::KexInit;

/// SHA-1 host-key / signature algorithms (RFC 4253 `ssh-rsa` signatures,
/// DSA) and their certificate forms.
const FORBIDDEN_HOST_KEY: &[&str] = &[
    "ssh-rsa",
    "ssh-dss",
    "ssh-rsa-cert-v01@openssh.com",
    "ssh-dss-cert-v01@openssh.com",
];
const FORBIDDEN_KEX: &[&str] = &[
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
];
const FORBIDDEN_MAC: &[&str] = &[
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha1-96-etm@openssh.com",
];

/// OpenSSH_10.2p1 fixture: the key of the `.pub` line
/// `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBUtYrV+0vHQidVi7Z+g6dLICWIXPgHvi2hkEv+kUcPg`,
/// its `ssh-keygen -lf` fingerprint and its `ssh-keygen -r` records (which
/// include a SHA-1 `4 1` record that Tatami must never produce or accept).
const KEY: [u8; 32] = [
    0x15, 0x2d, 0x62, 0xb5, 0x7e, 0xd2, 0xf1, 0xd0, 0x89, 0xd5, 0x62, 0xed, 0x9f, 0xa0, 0xe9, 0xd2,
    0xc8, 0x09, 0x62, 0x17, 0x3e, 0x01, 0xef, 0x8b, 0x68, 0x64, 0x12, 0xff, 0xa4, 0x51, 0xc3, 0xe0,
];
const KEYGEN_LF: &str = "SHA256:aCw4D+swMrV7HEVZQKMEkLpI5HWOuB071Q2qcU1bCRo";
const KEYGEN_R_SHA1: &str = "4 1 24d24f1929181cf710d7233e5cc3e5fd4473b5b8";
const KEYGEN_R_SHA256: &str =
    "4 2 682c380feb3032b57b1c455940a30490ba48e4758eb81d3bd50daa714d5b091a";

fn proposals() -> Vec<ClientProposal> {
    let mut out = Vec::new();
    // Ed25519 only (no provider) and every scheme Tatami can offer.
    let lists = [
        HostKeyAlgorithms::ED25519_ONLY,
        HostKeyAlgorithms::preferred(|_| true).unwrap(),
    ];
    for advertise_ext_info in [false, true] {
        for offer_strict_kex in [false, true] {
            for host_key_algorithms in lists {
                out.push(ClientProposal {
                    cookie: [0x5a; 16],
                    advertise_ext_info,
                    offer_strict_kex,
                    host_key_algorithms,
                });
            }
        }
    }
    out
}

fn names(list: &tatami_ssh_wire::namelist::NameList<'_>) -> Vec<String> {
    list.iter()
        .map(|n| String::from_utf8(n.to_vec()).unwrap())
        .collect()
}

#[test]
fn advertised_lists_contain_no_sha1_algorithm() {
    for proposal in proposals() {
        let payload = proposal.encode().unwrap();
        let kexinit = KexInit::decode(&payload).unwrap();
        let host_key = names(&kexinit.server_host_key_algorithms);
        let kex = names(&kexinit.kex_algorithms);
        let macs: Vec<String> = names(&kexinit.mac_client_to_server)
            .into_iter()
            .chain(names(&kexinit.mac_server_to_client))
            .collect();
        let all: Vec<String> = [
            &kexinit.kex_algorithms,
            &kexinit.server_host_key_algorithms,
            &kexinit.encryption_client_to_server,
            &kexinit.encryption_server_to_client,
            &kexinit.mac_client_to_server,
            &kexinit.mac_server_to_client,
            &kexinit.compression_client_to_server,
            &kexinit.compression_server_to_client,
            &kexinit.languages_client_to_server,
            &kexinit.languages_server_to_client,
        ]
        .into_iter()
        .flat_map(names)
        .collect();

        assert!(!host_key.is_empty());
        for bad in FORBIDDEN_HOST_KEY {
            assert!(!host_key.iter().any(|n| n == bad), "{bad} in {host_key:?}");
        }
        for bad in FORBIDDEN_KEX {
            assert!(!kex.iter().any(|n| n == bad), "{bad} in {kex:?}");
        }
        for bad in FORBIDDEN_MAC {
            assert!(!macs.iter().any(|n| n == bad), "{bad} in {macs:?}");
        }
        // Catch-all over every list: no SHA-1 or DSA name at all, and the
        // SHA-1 names above appear in no list, not only in their own.
        for name in &all {
            assert!(!name.contains("sha1"), "SHA-1 algorithm {name} advertised");
            assert!(!name.contains("dss"), "DSA algorithm {name} advertised");
            for bad in FORBIDDEN_KEX.iter().chain(FORBIDDEN_MAC) {
                assert_ne!(name, bad);
            }
        }
    }
}

#[test]
fn ssh_rsa_blob_type_is_not_banned() {
    // The blob codec still names RSA keys `ssh-rsa`; only the SHA-1
    // signature scheme of the same name is excluded above.
    let mut blob = Vec::new();
    for part in [&b"ssh-rsa"[..], &[1, 0, 1], &[0x00, 0xc3]] {
        blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
        blob.extend_from_slice(part);
    }
    let parsed = tatami_ssh_keys::PublicKeyBlob::decode(&blob).unwrap();
    assert_eq!(parsed.algorithm, b"ssh-rsa");
}

#[test]
fn fingerprints_pins_and_sshfp_are_sha256_only() {
    let mut blob = [0u8; 51];
    assert_eq!(encode_ed25519_blob(&KEY, &mut blob).unwrap(), 51);
    let fp = Sha256Fingerprint::of_blob(&blob);
    assert_eq!(fp.as_bytes().len(), 32);
    assert_eq!(fp.to_string(), KEYGEN_LF);
    assert_eq!(Sha256Fingerprint::parse(KEYGEN_LF).unwrap(), fp);
    // A SHA-1 or MD5 fingerprint text is not a pin.
    assert!(Sha256Fingerprint::parse("SHA1:JNJPGSkYHPcQ1yM+XMPl/URztbg").is_err());
    assert!(
        Sha256Fingerprint::parse("MD5:a6:39:e1:c2:ea:f6:20:0a:43:82:31:17:f7:10:ce:6a").is_err()
    );

    // Pins compare the SHA-256 of the blob.
    let identity = HostIdentity {
        algorithm: b"ssh-ed25519",
        blob: &blob,
        sha256: fp,
    };
    assert!(PinnedSha256(fp).decide(&identity).is_trusted());

    // SSHFP: fingerprint type 2 (SHA-256) only, never 1 (SHA-1).
    let sshfp = Sshfp::sha256_of_blob(&blob).unwrap();
    assert_eq!(TYPE_SHA256, 2);
    assert_eq!(sshfp.fingerprint_type, 2);
    assert_eq!(sshfp.to_string(), KEYGEN_R_SHA256);
    assert_eq!(&sshfp.digest, fp.as_bytes());
    assert_eq!(Sshfp::parse_rdata(KEYGEN_R_SHA1), None);
}
