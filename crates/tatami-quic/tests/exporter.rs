//! TLS exporter experiment (RFC 8446 §7.5 through `quinn-proto`'s
//! `crypto::Session::export_keying_material`).
//!
//! Two raw `quinn_proto::Endpoint`s exchange datagrams through `Vec`
//! queues (`inmem::raw_handshake`); no sockets, no real time. After the
//! handshake both ends export with the same label/context and the outputs
//! must be equal; a different label, a different context, a different
//! length or a fresh connection must give different output; exporting
//! before completion must fail. Only equality, inequality and availability
//! are asserted. No exporter bytes are printed or persisted, and the label
//! is explicitly experimental: it is not the session-binding construction
//! (P-04 is open).

#![cfg(feature = "quinn-backend")]

use std::sync::Arc;
use std::time::Duration;

use tatami_quic::diag::identity::TestIdentity;
use tatami_quic::diag::inmem::{RawHandshake, raw_handshake};
use tatami_quic::diag::quinn_proto::Connection;
use tatami_quic::diag::quinn_proto::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use tatami_quic::diag::tls::{
    ClientTrust, ServerIdentityMode, client_crypto, hello_slot, server_crypto,
};

const ALPN: &[u8] = b"tatami-diag/0";
const LABEL: &[u8] = b"EXPERIMENTAL-tatami-ssh-binding-v0";
const CONTEXT: &[u8] = b"tatami-test-context";

fn cryptos(identity: &TestIdentity) -> (Arc<QuicClientConfig>, Arc<QuicServerConfig>) {
    let client = client_crypto(
        &ClientTrust::PinnedCertificateSha256(identity.certificate_sha256_fingerprint()),
        &[ALPN.to_vec()],
    )
    .unwrap();
    let server = server_crypto(
        identity,
        &[ALPN.to_vec()],
        hello_slot(),
        ServerIdentityMode::Certificate,
    )
    .unwrap();
    (client, server)
}

fn handshake(identity: &TestIdentity) -> RawHandshake {
    let (c, s) = cryptos(identity);
    let h = raw_handshake(c, s, "localhost", Duration::from_secs(5), 1_000).unwrap();
    assert!(
        h.completed(),
        "client: {:?}, server: {:?}",
        h.client_result,
        h.server_result
    );
    assert!(
        h.datagrams >= 3,
        "a 1-RTT handshake needs at least three datagrams"
    );
    h
}

fn export(conn: &Connection, out: &mut [u8], label: &[u8], context: &[u8]) -> bool {
    conn.crypto_session()
        .export_keying_material(out, label, context)
        .is_ok()
}

#[test]
fn exporter_is_unavailable_before_the_handshake_completes() {
    let identity = TestIdentity::generate_ed25519(&["localhost".to_string()]).unwrap();
    let (c, s) = cryptos(&identity);
    // Zero steps: the client has only produced its Initial.
    let h = raw_handshake(c, s, "localhost", Duration::from_secs(5), 0).unwrap();
    assert!(h.client_result.is_err());
    assert!(h.server.is_none());
    let mut out = [0u8; 32];
    assert!(
        !export(&h.client, &mut out, LABEL, CONTEXT),
        "export before the handshake must fail"
    );
    assert_eq!(out, [0u8; 32], "buffer untouched on failure");
}

#[test]
fn exporter_matches_across_ends_and_separates_labels_contexts_lengths_and_connections() {
    let identity = TestIdentity::generate_ed25519(&["localhost".to_string()]).unwrap();
    let h = handshake(&identity);
    let server = h.server.as_ref().expect("server connection");

    let mut client_out = [0u8; 32];
    let mut server_out = [0u8; 32];
    assert!(export(&h.client, &mut client_out, LABEL, CONTEXT));
    assert!(export(server, &mut server_out, LABEL, CONTEXT));
    assert_eq!(client_out, server_out, "same label/context must agree");
    assert_ne!(client_out, [0u8; 32]);

    let mut other_label = [0u8; 32];
    assert!(export(
        &h.client,
        &mut other_label,
        b"EXPERIMENTAL-tatami-other-label",
        CONTEXT
    ));
    assert_ne!(other_label, client_out, "label must separate outputs");

    let mut other_context = [0u8; 32];
    assert!(export(
        &h.client,
        &mut other_context,
        LABEL,
        b"other-context"
    ));
    assert_ne!(other_context, client_out, "context must separate outputs");

    let mut empty_context = [0u8; 32];
    assert!(export(&h.client, &mut empty_context, LABEL, b""));
    assert_ne!(empty_context, client_out);

    let mut longer = [0u8; 64];
    assert!(export(&h.client, &mut longer, LABEL, CONTEXT));
    assert_ne!(
        &longer[..32],
        &client_out[..],
        "HKDF-Expand output depends on the requested length"
    );

    // Second, fresh connection between the same identities.
    let h2 = handshake(&identity);
    let mut second = [0u8; 32];
    let mut second_server = [0u8; 32];
    assert!(export(&h2.client, &mut second, LABEL, CONTEXT));
    assert!(export(
        h2.server.as_ref().unwrap(),
        &mut second_server,
        LABEL,
        CONTEXT
    ));
    assert_eq!(second, second_server);
    assert_ne!(
        second, client_out,
        "a new connection must have new exporter output"
    );
    let _ = (h.endpoints(), h2.endpoints());
}
