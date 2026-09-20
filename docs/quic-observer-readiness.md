# QUIC observer readiness

Status: proposal for a later backend milestone, 2026-09-20. Nothing here is
implemented, no dependency is added, and every QUIC/TLS choice below is a
*candidate* until the checkpoint ledger records it (P-03–P-08, AQ-015,
AQ-018–AQ-023, AQ-026). `tatami-quic` remains documentation-only.

Delivered this round: the **TCP** server-side observer (sends
`SSH-2.0-tatami_observer_0.1.0`, records the client identification and the
client `KEXINIT`, sends no server `KEXINIT`). **There is no `--quic` option;
none appears to work, and none should be added until a backend milestone
exists.**

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

Observer (a) is the proposed next QUIC slice. Observer (b) is blocked on
design work, not on code.

## 3. Backend audit

Facts below were read on 2026-09-20 from the linked primary sources.
"Unverified" means the source was not fetched in this pass, not that the
feature is absent. Project MSRV is 1.85 (W-07).

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

## 4. Recommendation (proposed, not decided)

Try **`quinn-proto` + rustls** first for observer (a), for these reasons:

1. It is the only candidate whose current release matches MSRV 1.85 and
   whose core is sans-IO. That matches W-14 (no async runtime commitment) and
   lets the observer reuse the blocking, per-phase-deadline adapter style of
   `tatami-tcp::io`. Note the `quinn` convenience crate is *not* proposed; it
   drags in tokio.
2. Address validation is first-class: the observer receives an `Incoming`
   *before* any handshake state exists and can record
   `remote_address_validated()` and `may_retry()`, then call
   `Endpoint::retry` (if `may_retry()`), `accept`, `refuse` or `ignore`. All
   datagrams come from `Transmit` values produced by the library, so
   anti-amplification and Retry token integrity stay inside quinn-proto.
3. rustls exposes both the offered ClientHello (`server::ClientHello`) and
   the negotiated result, supports RFC 7250 raw public keys (P-06 candidate),
   and provides the RFC 8446 §7.5 exporter needed later by P-04.

### Telemetry the candidate exposes (observer (a) report fields)

| Field | Source | Caveat |
|---|---|---|
| Datagram source address | `Endpoint::handle(now, remote, …)` | Report as "source address (unvalidated)" until validated. |
| Original destination CID | `Incoming::orig_dst_cid()` | Identifies the attempt, not the peer. |
| Address validated? / Retry permitted? / Retry sent? | `Incoming::remote_address_validated()`, `may_retry()`, result of `Endpoint::retry` | Validation via Retry means the client proved it can receive at that address, nothing more (RFC 9000 §8.1). |
| Version handling | quinn-proto answers unsupported versions itself; the observer sees only the resulting `DatagramEvent` | Version Negotiation packets are not surfaced as an event; count them as "no `Incoming` produced" — verify during implementation. |
| Offered ALPN list, SNI, cipher suites, signature schemes, named groups, certificate types | rustls `ClientHello` in a custom `ResolvesServerCert` | Wiring path through quinn-proto unverified; fallback is negotiated-only data. |
| Negotiated ALPN, SNI | `HandshakeData` after `Event::HandshakeDataReady` | `protocol` is `None` if no ALPN matched; RFC 9001 §8.1 makes that a handshake failure in practice. |
| Handshake outcome | `Event::Connected` or `Event::ConnectionLost { reason }` | Record the `ConnectionError` verbatim. |
| Peer identity | `Session::peer_identity()` (rustls: certificate chain or raw public key) | Observer records; it does not decide trust (contract §2.2 item 7). |
| Exporter available | `Session::export_keying_material` succeeds only after handshake | Observer (a) may confirm availability with a throwaway label; it must not persist output or call it a session binding (P-04 open). |
| Path change | `Connection::remote_address()` changes between polls | No event in 0.11; migration is C-04 priority but only observable coarsely here. |

Not observed by design: 0-RTT, stream data, SSH identification, `KEXINIT`.

## 5. Unresolved blockers

| Blocker | Why it matters | Owner / reference |
|---|---|---|
| `std` in `tatami-quic` | quinn-proto needs `std`; the backend must live behind an explicit feature that enables `std`, never in shared protocol code (`architecture.md` portability). Confirm the `thumbv7em-none-eabi` check still passes with the feature off. | W-02, W-09 |
| MSRV drift | quinn `main` already requires 1.88; the next quinn-proto minor will exceed 1.85. Either pin `0.11.x` or raise the workspace MSRV deliberately (W-07 change). | W-07 |
| Crypto provider choice | `rustls-ring` vs `rustls-aws-lc-rs` is a provider decision the project has not made; it also interacts with the later SSH algorithm audit (`specification-inventory.md` §5). | C-07, provider audit |
| Offered-ALPN wiring | `ResolvesServerCert`/`ClientHello` inside quinn-proto's `ServerConfig` is unverified. | implementation spike |
| Identity for the handshake | Even observer (a) must present something; a generated RPK or self-signed certificate is test material, not P-06. | P-06 |
| ALPN value | Experimental, configurable; no registration. Absence is not a valid deployment (checkpoint §4.1). | AQ-019 / P-08 |
| Version Negotiation visibility | Whether quinn-proto reports VN to the caller needs checking during the spike. | implementation spike |
| Observer (b) design | Identification placement, control-stream association, record rule. Cannot start until AQ-015, AQ-018, AQ-020–AQ-023, AQ-026 have proposals. | checkpoint §1.3 |
| Second-opinion backend | quiche is the natural comparison (sans-IO, Cloudflare interop history) once MSRV 1.88 is acceptable; s2n-quic's event model is richer but tokio-bound and MSRV 1.92. | later milestone |

## 6. Staged delivery

| Stage | Content | State |
|---|---|---|
| This round | TCP observer: identification exchange and client `KEXINIT` capture over TCP. | implemented (see `architecture.md`) |
| Next QUIC slice (proposed) | Observer (a) behind `tatami-quic` feature `backend-quinn`, reporting the §4 fields; loopback test with a real QUIC client library; no SSH bytes. | designed here; not scheduled |
| Later | Observer (b) once the mapping questions are answered; then bootstrap, exporter binding and userauth over QUIC (checkpoint §5 items 3–4). | blocked on design |

No `--quic` flag, feature or module exists today. Adding one before stage
two would advertise capability the workspace does not have (W-16 spirit: a
stub must never look like a running server).
