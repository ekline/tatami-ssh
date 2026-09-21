# QUIC observer readiness: status and corrections

Status: round 4, 2026-09-20. Observer **(a)** below — the TLS/QUIC handshake
observer — is **implemented** as `tatami-quic::diag` behind the
`quinn-backend` feature (W-31), with the `tatami-quic-server observe` and
`tatami-quic-client handshake` binaries behind the facade feature
`quic-diag`. Observer **(b)** — the SSH-over-QUIC observer — is **not
started**; every mapping question it depends on remains open (P-03–P-05,
AQ-015, AQ-018–AQ-023, AQ-026). Sections 1 and 2 are kept as written in
round 3 because they still hold; §3 records the decision, §4 the corrections
learned by compiling and testing against the backend, §5 what (b) requires.

## 0. What was built (evidence)

| Claim | Evidence |
|---|---|
| Backend: `quinn-proto` 0.11.18 (`rustls-ring`, `ring`), `rustls` 0.23.45 (`ring`, `std`, `tls12`), `rcgen` 0.13.2 for test identities; MSRV stays 1.85 | `crates/tatami-quic/Cargo.toml`, `crypto-provider-audit.md`, `cargo tree -p tatami-quic --features quinn-backend` |
| Sans-I/O cores (`ServerCore`, `ClientCore`) driven by a blocking UDP loop; no async runtime | `crates/tatami-quic/src/diag/{server,client,udp}.rs` |
| Full handshake completes on both ends; offered vs negotiated ALPN and SNI consistent; exporter available after completion | `tests/inmem_handshake.rs::matching_identity_and_alpn_completes_on_both_sides`, `tests/loopback.rs::matching_handshake_over_loopback`, `tatami/tests/quic_cli.rs::end_to_end_handshake_with_pin_and_exporter_probe` |
| Wrong certificate pin fails at the client with `certificate_unknown` (alert 46 via rustls `CertificateError::Other`); the server records `Failed`, `ConnectionLost`, still with the offered ClientHello and the negotiated ALPN | `tests/inmem_handshake.rs::wrong_pin_fails_with_certificate_error_on_both_sides`, `tests/loopback.rs::wrong_identity_over_loopback` |
| ALPN mismatch fails with `no_application_protocol` (alert 120, "peer doesn't support any known protocol") | `tests/inmem_handshake.rs::alpn_mismatch_fails_with_no_application_protocol`, `tests/loopback.rs::wrong_alpn_over_loopback` |
| No listener → `TimedOut` at the client deadline, `datagrams_received == 0` | `tests/loopback.rs::no_listener_times_out_within_the_deadline`, `tests/inmem_handshake.rs::client_into_blackhole_times_out_at_its_deadline` |
| `require_validation` → one Retry, two `Incoming`, accepted connection reports `peer_address_validated: true`, `validation_method: retry_token` | `tests/loopback.rs::require_validation_sends_retry_and_reports_validated_peer`, `tatami/tests/quic_cli.rs::require_validation_is_visible_in_records` |
| Exporter: fails before completion (buffer untouched), equal at both ends, differs by label, context, length and connection | `tests/exporter.rs` |
| RFC 7250 raw public keys work end to end; `peer_identity()` is the 44-byte SPKI DER; wrong SPKI pin fails; no silent downgrade in either direction; three fingerprints of one Ed25519 key differ | `tests/rpk.rs` |
| No SSH byte on the wire: every captured datagram checked for `SSH-` | `tests/inmem_handshake.rs::assert_no_ssh_bytes` |
| 0-RTT never attempted (`zero_rtt_attempted: false` both ends) | `tests/inmem_handshake.rs` |

All of the above passed on the development machine on 2026-09-20
(`cargo test -p tatami-quic --features quinn-backend`; `cargo test -p tatami
--features quic-diag --test quic_cli`). This is a loopback experiment with
Tatami on both ends; **no interoperability with any other QUIC or TLS
implementation is claimed**, and the ALPN value is unregistered.

## 1. What comes before any SSH byte over QUIC

A QUIC server sees, in order: a long-header **Initial** packet carrying a
version field and (possibly) triggering **Version Negotiation**; the TLS 1.3
**ClientHello** inside CRYPTO frames, including SNI and the *offered* ALPN
list; then the handshake outcome. Only after the handshake does application
data exist ([RFC 9000 §5, §6, §17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2),
[RFC 9001 §4, §8.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1)).

Consequences that are fixed regardless of backend:

- A plain UDP listener that answers datagrams with `SSH-2.0-…` is **not a QUIC
  implementation** and must not be built. It would violate the
  3× anti-amplification limit and address validation in RFC 9000 §8.1 the
  moment it replied with more bytes than it received from an unvalidated
  address, and it would not be observing QUIC at all.
- Anti-amplification, Retry/token handling and path validation stay inside
  the real QUIC implementation. Tatami code never emits a datagram of its own
  construction in response to an Initial.
- No 0-RTT work: 0-RTT is irrelevant to observation and introduces replay
  considerations the project has not analysed
  ([RFC 9001 §9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2)).
- An Initial packet's source address is **not** a validated peer. Until the
  backend reports address validation (Retry token or a later
  PATH_CHALLENGE/RESPONSE), any report must label it "unvalidated source
  address" ([RFC 9000 §8.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1)).

## 2. Two different observers

| | (a) TLS/QUIC handshake observer | (b) SSH-over-QUIC observer |
|---|---|---|
| Purpose | Learn what a real QUIC client sends: version, ClientHello SNI, offered vs negotiated ALPN, handshake success/failure, validation/Retry status, migration events. | Observe the *Tatami mapping's* first SSH artefacts on a QUIC connection. |
| SSH content | None. No identification string, no `KEXINIT`. | Identification placement and the control-stream bootstrap as decided under AQ-015, AQ-020–AQ-023, AQ-026. Not decided yet. |
| Identity | A locally generated certificate or raw public key sufficient to complete a TLS handshake; trust decisions are out of scope. | Real identity configuration (P-06: raw public keys are the candidate) and the exporter-derived binding (P-04) — still open. |
| Application protocol | An experimental, configurable ALPN value; no IANA registration is claimed (AQ-019 / P-08). Observing which values clients *offer* is the point. | Same value, but now it must be *agreed* (RFC 9001 §8.1 requires authenticated negotiation). |
| Must not | Reply on UDP outside the backend; treat Initial source as peer. | Inherit TCP packet framing (`tatami-tcp::packet` is the TCP envelope, W-12), or manufacture an SSH KEX / session ID. The QUIC record rule is AQ-018 and is unwritten. |
| Prerequisite | A backend that compiles under an explicit `std`-enabling feature. | (a) plus the mapping decisions above. |

Observer (a) is implemented (§0). Observer (b) is blocked on design work,
not on code (§5).

## 3. Backend audit and decision

**Decision (W-31):** `quinn-proto` + `rustls` on `ring`, selected after
compiling and testing the exact releases in §0. The reasons in §3.1 held;
the "unverified" items for that column are now verified and, where the
round-3 expectation was wrong, corrected in §4. The other columns were not
re-audited and remain as read on 2026-09-20 from the linked sources
("Unverified" means the source was not fetched, not that the feature is
absent). Project MSRV is 1.85 (W-07); `quinn-proto` 0.11.18 declares 1.85 and
is pinned by `Cargo.lock`, so the MSRV-drift blocker is contained, not gone.

| Property | quinn / quinn-proto (+ rustls) | quiche (Cloudflare) | s2n-quic (AWS) | neqo (Mozilla) | msquic (Microsoft) |
|---|---|---|---|---|---|
| Latest release; `rust-version` | quinn-proto 0.11.18, `rust_version` **1.85**, edition 2021 ([crates.io](https://crates.io/api/v1/crates/quinn-proto)). Unreleased `main` (0.12.0) sets `rust-version = "1.88.0"`, edition 2024 ([workspace Cargo.toml](https://raw.githubusercontent.com/quinn-rs/quinn/main/Cargo.toml)). rustls 0.23.45 `rust_version` 1.71 ([crates.io](https://crates.io/api/v1/crates/rustls/0.23.45)). | 0.30.0, `rust_version` **1.88**, BSD-2-Clause ([crates.io](https://crates.io/api/v1/crates/quiche)). | 1.88.0, `rust_version` **1.92**, Apache-2.0 ([crates.io](https://crates.io/api/v1/crates/s2n-quic)). | Not on crates.io (`neqo-transport` returns 404). Git workspace 0.31.1, `rust-version = "1.90.0"`, edition 2024 ([Cargo.toml](https://raw.githubusercontent.com/mozilla/neqo/main/Cargo.toml)). | 2.5.1-beta, `rust_version` null (undeclared), MIT ([crates.io](https://crates.io/api/v1/crates/msquic/2.5.1-beta)). |
| std / runtime | `quinn-proto` is sans-IO ("performs no I/O whatsoever"; caller drives `handle`, `poll_transmit`, `poll_timeout`) — [Endpoint docs](https://docs.rs/quinn-proto/latest/quinn_proto/struct.Endpoint.html). Requires `std` (uses `SocketAddr`, `Instant`). The `quinn` crate always depends on `tokio` (for `sync`) and defaults to `runtime-tokio`, with `runtime-smol` optional ([quinn/Cargo.toml](https://raw.githubusercontent.com/quinn-rs/quinn/main/quinn/Cargo.toml)). | Sans-IO (`recv`/`send`/`timeout`/`on_timeout`; application owns sockets and timers) — [crate docs](https://docs.rs/quiche/latest/quiche/index.html). Requires `std`. TLS is BoringSSL via the `boring` crate (C/C++ build) — default feature `boringssl-boring-crate`. | `tokio ^1` is a non-optional dependency ([docs.rs deps](https://docs.rs/s2n-quic/latest/s2n_quic/connection/struct.Connection.html)); async API. TLS provider is s2n-tls (C) or rustls via features. | TLS via NSS through a git dependency (`nss-rs`); README says build uses a system NSS or a separate NSS/NSPR checkout ([README](https://raw.githubusercontent.com/mozilla/neqo/main/README.md)). Sans-IO core is the design intent; not re-verified here. | C library built by `cmake` (default feature `src`) or located with `find`; TLS `quictls`/`schannel` features ([sparse index](https://index.crates.io/ms/qu/msquic)). FFI callback API; requires `std`. |
| Offered vs negotiated ALPN | Negotiated: `HandshakeData { protocol, server_name }` after `Event::HandshakeDataReady` ([docs](https://docs.rs/quinn-proto/latest/quinn_proto/crypto/rustls/struct.HandshakeData.html)). Offered: rustls `server::ClientHello::alpn()` (plus `server_name()`, `cipher_suites()`, `signature_schemes()`, `named_groups()`, `server_cert_types()`) inside a custom `ResolvesServerCert` ([docs](https://docs.rs/rustls/latest/rustls/server/struct.ClientHello.html)); wiring it through quinn-proto's `ServerConfig` is an inference, not verified in this pass. | Negotiated: `Connection::application_proto()`, `server_name()` ([docs](https://docs.rs/quiche/latest/quiche/struct.Connection.html)). Offered list: unverified. | Events `on_tls_client_hello`, `on_application_protocol_information`, `on_server_name_information` ([Subscriber](https://docs.rs/s2n-quic/latest/s2n_quic/provider/event/trait.Subscriber.html)); whether the ClientHello event exposes the offered ALPN list is unverified. | Unverified. | Unverified. |
| Handshake outcome | `Event::Connected` / `Event::ConnectionLost { reason }`; `Connection::is_handshaking()` ([docs](https://docs.rs/quinn-proto/latest/quinn_proto/enum.Event.html)). | `is_established()`, `peer_error()`, `local_error()`, `is_timed_out()`. | `on_handshake_status_updated`, `on_tls_handshake_failed`, `on_connection_closed`. | Unverified. | Unverified. |
| Address validation / Retry | `Incoming::remote_address_validated()`, `may_retry()`, `orig_dst_cid()`; `Endpoint::retry`, `accept`, `refuse`, `ignore` ([Incoming](https://docs.rs/quinn-proto/latest/quinn_proto/struct.Incoming.html), [Endpoint](https://docs.rs/quinn-proto/latest/quinn_proto/struct.Endpoint.html)). | Free functions `retry`, `negotiate_version`, `version_is_supported`, `accept_with_retry`; `is_path_validated(from, to)`. | Default `provider-address-token-default`; `on_path_challenge_updated`, `on_handshake_remote_address_change_observed`. Retry-decision telemetry unverified. | Unverified. | Unverified. |
| Migration events | No dedicated event in 0.11; `remote_address()` is "the latest" address, plus `path_changed()`/`local_address_changed()` hooks ([Connection](https://docs.rs/quinn-proto/latest/quinn_proto/struct.Connection.html)). | `path_event_next()` → `PathEvent`; `probe_path`, `migrate`. | `on_active_path_updated`, `on_path_created`, `on_connection_migration_denied`. | Unverified. | Unverified. |
| Certificates and raw public keys (RFC 7250) | rustls: `requires_raw_public_keys()` on `ClientCertVerifier`/`ServerCertVerifier`; `peer_certificates()` returns the raw public key as the single element when RPK is in use ([ClientCertVerifier](https://docs.rs/rustls/latest/rustls/server/danger/trait.ClientCertVerifier.html), [ConnectionCommon](https://docs.rs/rustls/latest/rustls/struct.ConnectionCommon.html)). Through quinn-proto: `Session::peer_identity()` as `Box<dyn Any>`. | `peer_cert()`, `peer_cert_chain()` (DER). RPK: unverified (BoringSSL). | `take_tls_context()`; RPK support unverified. | NSS; unverified. | Unverified. |
| TLS exporter (RFC 5705 / RFC 8446 §7.5) | `Session::export_keying_material(output, label, context)` ([trait](https://docs.rs/quinn-proto/latest/quinn_proto/crypto/trait.Session.html)); rustls `ConnectionCommon::export_keying_material` "does not use the early exporter" and fails before handshake completion. | Not on `Connection`; `AsMut<SslRef>` (feature `boringssl-boring-crate`) may reach BoringSSL's exporter — unverified. | `on_tls_exporter_ready` event exists; the accessor it provides is unverified. | Unverified. | Unverified. |
| Feature isolation | Yes: `quinn-proto` with `default-features = false`, `rustls-ring` or `rustls-aws-lc-rs` chosen explicitly ([quinn-proto/Cargo.toml](https://raw.githubusercontent.com/quinn-rs/quinn/main/quinn-proto/Cargo.toml)); can sit behind `tatami-quic` feature `backend-quinn = ["std", …]`. | Yes in principle, but the BoringSSL build (cmake, C++ toolchain) is heavy and MSRV 1.88 already exceeds the project's. | Feature-gated, but tokio is unconditional and MSRV 1.92 exceeds the project's. | Git-only dependency plus NSS build; hard to isolate reproducibly (W-08 lockfile). | FFI + cmake; isolatable but pulls a C toolchain and vendor TLS. |

### 3.1 Why this backend (confirmed)

1. Its current release matches MSRV 1.85 and its core is sans-I/O, so no
   async runtime is committed (W-14) and the blocking, deadline-driven
   adapter style of `tatami-tcp::io` is reused. The `quinn` convenience
   crate is not used; it drags in tokio.
2. Address validation is first-class: an `Incoming` exists *before* any
   handshake state; `remote_address_validated()` and `may_retry()` are
   recorded, then `Endpoint::retry`/`accept`/`refuse`. Every datagram on the
   wire is a `Transmit` produced by the library, so anti-amplification (3×,
   RFC 9000 §8.1) and Retry-token integrity stay inside quinn-proto.
3. rustls exposes the offered ClientHello through `ResolvesServerCert`, the
   negotiated result through `HandshakeData`, supports RFC 7250 raw public
   keys, and provides the RFC 8446 §7.5 exporter.

## 4. Corrections learned in implementation

Each row replaces a round-3 expectation. "Handled" says what the code does
about it.

| # | Round-3 expectation | What the backend actually does | Handled |
|---|---|---|---|
| 1 | ALPN mismatch would surface as a failed `Connection` with `HandshakeData.protocol == None`. | rustls rejects the ClientHello while `Endpoint::accept` is processing it; `accept` returns `AcceptError { cause, response }` and **no `Connection` ever exists**. The `ResolvesServerCert` hook has already run, so the *offered* list is still captured. Error text: `error 120` / "peer doesn't support any known protocol". | Distinct outcome `HandshakeOutcome::AcceptFailed { reason }` carrying the offered ClientHello; the library's optional `response` transmit is sent unchanged; `stats.observed` is not incremented. |
| 2 | Version Negotiation might be reported to the caller; "verify during the spike". | It is not. `quinn-proto` 0.11 answers an unsupported version itself and exposes neither a VN event nor the negotiated version. | Endpoint is v1-only (`EndpointConfig::supported_versions([1])`); `quic_version = 1` is reported *by construction*; VN responses are counted by classifying our **own** outgoing endpoint datagrams (long header, version `0x00000000`) as `EndpointResponse::VersionNegotiation`. |
| 3 | "Validated" could be treated as one boolean. | Three different facts: `remote_address_validated()` (address), `may_retry()`/Retry sent (mechanism), and TLS identity. quinn-proto also validates via NEW_TOKEN tokens, but only when its `bloom` feature is on (default `ValidationTokenConfig::sent` is 2 with `bloom`, **0 without**); this workspace enables only `ring,rustls-ring`, so **no NEW_TOKEN frame is ever sent** and, without Retry, the peer is never validated before the handshake. | `validation_method` ∈ {`none`, `retry_token`, `validation_token`} derived from `(validated, may_retry)`; `validation_token` would indicate a token from elsewhere. Reports label the source "unvalidated" until Retry. Validation says nothing about identity; identity is the pin. |
| 4 | "No 0-RTT work" was assumed to mean nothing to do. | quinn-proto's convenience constructors enable early data: `ServerConfig::with_single_cert` sets `max_early_data_size = u32::MAX` and `QuicClientConfig::new` / `with_platform_verifier` set `enable_early_data = true` (`crypto/rustls.rs`). Only the `TryFrom<rustls::*Config>` conversions keep what the caller set; rustls clients also resume by default. | Both rustls configs are built directly and converted with `TryFrom`: server `max_early_data_size = 0`, `send_tls13_tickets = 0`; client `enable_early_data = false`, `Resumption::disabled()`; nothing calls `into_0rtt`/`accept_0rtt`; `zero_rtt_attempted` reported and asserted `false`. |
| 5 | `HandshakeData` is read at `Event::Connected`. | On the **server** it is available from `Event::HandshakeDataReady` (after the ClientHello is processed) and therefore also for handshakes that later fail, e.g. wrong pin: the server still reports the negotiated ALPN. On the **client**, ALPN arrives in EncryptedExtensions *before* the server is authenticated. | Server reads at `HandshakeDataReady` and again at `Connected`; client reads only at `Connected` so unauthenticated values are never reported as negotiated. |
| 6 | Client timeout is just a deadline. | Two paths: the local deadline (idle timeout equals the handshake deadline) and `ConnectionError::TimedOut` from the library. Any other `ConnectionLost` reason is a failure, not a timeout. | Both map to `HandshakeResult::TimedOut`; `close_reason` distinguishes `local_close_handshake_deadline` from the library's reason text. |
| 7 | Initial DCIDs are "8 bytes or so". | quinn-proto clients use `RandomConnectionIdGenerator::new(MAX_CID_SIZE)` — **20-byte** initial destination CIDs by default (RFC 9000 §7.2 requires ≥ 8). | `orig_dst_cid` is reported as hex and tested for 8–20 bytes; it identifies the *attempt*, not the peer. |
| 8 | A pin mismatch would render as a readable rustls error. | rustls maps `CertificateError::Other` to the `certificate_unknown` alert (46) and renders the inner error with `Debug`, not `Display`. | `PinMismatch` implements `Debug` by delegating to `Display`, so both ends see "presented certificate/raw public key does not match the configured SHA-256 pin"; the server sees the crypto error code (`0x100 + alert`) with the client's reason phrase. |

Also confirmed: the offered ClientHello values (SNI, ALPN list, cipher
suites, signature schemes, named groups, certificate types) are recorded
through the recording resolver with exact per-connection correlation
(single-threaded core, slot drained after every call into quinn-proto);
they are **untrusted peer metadata**. Path change remains observable only
coarsely (no migration event in 0.11) and is not exercised.

### Telemetry observer (a) reports today

| Field | Source | Caveat |
|---|---|---|
| Source address, local address | `Endpoint::handle(now, remote, …)` | "Unvalidated" until Retry. |
| `orig_dst_cid` | `Incoming::orig_dst_cid()` | Attempt identifier, up to 20 bytes. |
| `peer_address_validated`, `may_retry`, `retry_sent`, `validation_method` | `Incoming` accessors, `Endpoint::retry` | Reachability, not identity (§4 row 3). |
| `quic_version` | By construction (v1 only) | VN counted from our own datagrams (§4 row 2). |
| `offered {server_name, alpn, cipher_suites, signature_schemes, named_groups, server_cert_types, hellos_seen}` | rustls `ClientHello` via `RecordingResolver` | Peer-supplied; bounded to 32 entries; rendered escaped. |
| `negotiated_alpn`, `sni` | `HandshakeData` at `HandshakeDataReady` (server) / `Connected` (client) | §4 row 5. |
| `outcome`: `completed` / `failed {reason}` / `timed_out` / `accept_failed {reason}` / `shutdown` | `Event::Connected`, `Event::ConnectionLost`, `AcceptError`, deadline | `ConnectionError` text recorded verbatim, peer phrases escaped. |
| `exporter {available, len}` (client, `--exporter-probe`) | `Session::export_keying_material` after `Connected` | Output discarded; experimental label; **not** a session binding (P-04). |
| `zero_rtt_attempted`, `unexpected_streams`, `unexpected_datagrams` | Events counted and ignored | Always 0 in tests. |
| Certificate SHA-256 (server start), pin outcome (client) | `TestIdentity`, `PinnedCertificateVerifier` | Certificate fingerprint, not an SSH host-key fingerprint. |

Not observed by design: stream data, SSH identification, `KEXINIT`,
migration.

## 5. Observer (b): not started, and what it requires

| Requirement | Reference | State |
|---|---|---|
| Where the client and server identification strings go (control stream? first bytes? both directions?) and their canonical encoding for any binding | P-05, AQ-020–AQ-023 | open |
| Control-stream bootstrap: initiator, direction, recognition, first record | P-03, AQ-015 | open |
| Bounded enclosing record rule on QUIC streams (TCP's binary packet is **not** inherited, W-12) | P-02, AQ-018 | open |
| Session-binding construction from the exporter (label, context, length, transcript inputs, identification strings) and its proof of authentication | P-04, AQ-003, AQ-024 | exporter *availability* shown; construction open |
| Host identity: SPKI ↔ SSH key mapping and the fingerprint an operator pins | P-06 | RPK handshake shown; mapping open (three fingerprints differ) |
| Channel-opening placement and stream association | AQ-026, AQ-001, AQ-004 | open |
| ALPN value | AQ-019, P-08 | experimental `tatami-diag/0`; unregistered |
| Interoperability partner other than Tatami itself | — | none |

Until these have recorded proposals in the checkpoint, no SSH byte is sent
over QUIC and no `--quic` option exists on `tatami-client`/`tatami-server`.
The `tatami-quic-*` binaries state in their usage text that they are not SSH
clients or servers (W-16 spirit: a stub must never look like a running
service).

## 6. Remaining blockers

| Blocker | Status |
|---|---|
| `std` in `tatami-quic` | Resolved as designed: `quinn-backend` enables `std`; `check-workspace.sh` verifies the backend is absent without the feature and that portable builds still pass. |
| MSRV drift | Contained: `quinn-proto` pinned to 0.11.18 by `Cargo.lock`; 0.12 requires 1.88. Raising MSRV is a W-07 change. |
| Crypto provider | `ring` selected for the experiment (W-31); the SSH side uses the pure-Rust set (W-29). Not unified, deliberately. |
| Identity | rcgen test identities only; P-06 open. |
| Second-opinion backend | Not done; quiche when MSRV 1.88 is acceptable. |
| Observer (b) | Blocked on §5. |
