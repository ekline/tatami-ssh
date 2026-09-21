# Workspace architecture

Status: round 4, 2026-09-20. Package boundaries are an implementation
starting point; unresolved protocol choices remain unresolved and are tracked
in `tatami-ssh-design-state-checkpoint.md`.

All libraries are `no_std`. All seven proposed package boundaries exist so
that the layout, dependency direction and feature policy can be checked
mechanically. `tatami-wire`, `tatami-keys`, `tatami-tcp`, `tatami-connection`,
`tatami-quic` (diagnostic backend only) and the `tatami` facade contain
working code (see "Implemented" below); `tatami-auth` remains
documentation-only.

## Portability layers

| Layer | Packages | Policy |
|---|---|---|
| No allocation required | `tatami-wire` | Borrowed/caller-buffer codecs by default; owned helpers may use the optional `alloc` feature. |
| Allocation permitted, no OS | `tatami-keys`, `tatami-auth`, `tatami-connection` | Always `no_std` with `alloc`; no `std` feature. `tatami-keys/ed25519` adds pure-Rust verification and fingerprints, still `no_std`. |
| Portable binding state with optional host integration | `tatami-tcp`, `tatami-quic` | Always `no_std` with `alloc`; `std` exposes `io` modules. `tatami-tcp/kex` is **portable `no_std` crypto** (pure Rust, entropy injected via `rand_core`; `getrandom` only under `std`). |
| Host-only backend | `tatami-quic/quinn-backend` | Enables `std`; pulls `quinn-proto`, `rustls`, `ring` (C/assembly), `rcgen`. Never present in default, `tcp`-only or portable builds (`check-workspace.sh` verifies both directions). |
| Application composition | `tatami` | Portable `client`/`server` modules; `std` exposes `host::{environment,process,pty}`; `kex` = `tcp` + portable crypto; `quic-diag` = `std` + `quic` + backend, enabling the `tatami-quic-*` binaries. |

`alloc` provides owned collections without requiring `std`. A final application
that uses them needs an allocator; the libraries do not install one. Passing a
library compile check does not establish an allocator, panic handler, executable
entry point, or firmware integration. [Rust alloc documentation](https://doc.rust-lang.org/alloc/).

Keep public pure APIs expressed in terms of core/alloc values. Providers supply
entropy, signing operations, time and policy as appropriate. Socket access need
not inherently require `std` on every platform, but the planned host networking,
process and PTY adapters are explicitly isolated. Embedded integration remains
possible without pretending that an OS-backed implementation is portable.

Providers were selected in round 4 after the audit in
`crypto-provider-audit.md` (W-29, W-31): a pure-Rust `no_std` set for SSH
(`x25519-dalek`, `ed25519-dalek`, `sha2`, `aes-gcm`, `zeroize`, `subtle`,
`base64ct`, `rand_core`; `getrandom` host-only) and a host-only QUIC/TLS
backend (`quinn-proto` 0.11.18, `rustls` 0.23.45 on `ring`). The backend
needs `std` beyond socket handling and therefore sits behind
`quinn-backend`, which enables `std`; it is never imported into shared
protocol code. No async runtime is used anywhere (W-14). The TLS exporter's
*availability* is demonstrated through that backend; the SSH session-binding
*construction* remains unselected (P-04).

## Dependencies

Each dependency below is a Cargo path dependency declared once in
`[workspace.dependencies]` with defaults disabled.

| Package | Depends on |
|---|---|
| `tatami-wire` | No project packages |
| `tatami-keys` | `wire` |
| `tatami-auth` | `wire`, `keys` |
| `tatami-connection` | `wire` |
| `tatami-tcp` | `wire`, `keys`, `auth`, `connection` |
| `tatami-quic` | `wire`, `keys`, `auth`, `connection` |
| `tatami` | `keys`, `auth`, `connection`; optional `tcp` and `quic` |

Names in the dependency column omit the `tatami-` prefix. Bindings own their
distinct transport drivers and compose shared engines; neither shared engines
nor either binding depend on the facade. No common `Transport`/KEX interface is
introduced. Client and server remain library modules of the facade, avoiding
extra empty role-specific packages.

## Feature behavior

All package defaults are empty. In the four shared protocol packages the only
opt-in features are `tatami-wire/alloc` and `tatami-keys/ed25519` (a
provider, not a portability change). The three shared packages other than
`tatami-wire` permit allocation unconditionally (and enable
`tatami-wire/alloc` themselves); `--no-default-features` is not a
no-allocation mode for them.

| Facade features | Binding dependencies | Host modules |
|---|---|---|
| none | None | None |
| `std` | None | Facade host modules |
| `tcp` | TCP | None |
| `quic` | QUIC | None |
| `tcp,quic` | TCP and QUIC | None |
| `std,tcp` | TCP with `std` | Facade and TCP; `tatami-client probe`, `tatami-server observe` |
| `std,quic` | QUIC with `std` | Facade and QUIC (no backend) |
| `std,tcp,quic` | Both with `std` | Facade and both bindings |
| `kex` (implies `tcp`) | TCP + `tatami-tcp/kex` + `tatami-keys/ed25519` | None; portable — `check-workspace.sh` checks it on `thumbv7em-none-eabi` (CI gate; first run not yet observed) |
| `std,tcp,kex` | as above with `std` | `tatami-client handshake` |
| `quic-diag` (implies `std,quic`) | QUIC + `tatami-quic/quinn-backend` | `tatami::quic_diag`, `tatami-quic-server`, `tatami-quic-client` |

Weak dependency feature forwarding (`tatami-tcp?/std`, `tatami-quic?/std`) ensures
that `std` does not itself select a transport. Cargo features are additive and
can be unified by other dependents, so inspect the resolved graph
(`cargo tree -e features`) when adding providers.
[Cargo feature documentation](https://doc.rust-lang.org/cargo/reference/features.html).

Libraries always use `#![no_std]`, with a gated `extern crate std` in the three
packages that permit host integration. This keeps the implicit `std` prelude
out of portable modules even in host builds. Core/alloc checks use
`thumbv7em-none-eabi`, which has no standard library, to catch accidental
transitive `std` use that a host-only check can miss. `scripts/check-workspace.sh`
skips that step with a notice when the target's `rust-std` is not installed
locally; CI installs it and requires the step.

## Locations and next implementation slice

| Location | Contents |
|---|---|
| `crates/*/src/lib.rs` | Package documentation and portability gates |
| `crates/tatami-wire/src/{primitives,namelist}.rs` | Checked `Reader`/`Writer` and borrowed name lists; no `alloc` |
| `crates/tatami-wire/src/ident.rs` | Shared identification *content* syntax: borrowed parser, content encoder, version classification; `OwnedIdentification` behind `alloc` |
| `crates/tatami-wire/src/{kexinit,transport,channel}.rs` | `KEXINIT`, `DISCONNECT`/`IGNORE`/`DEBUG`/`UNIMPLEMENTED`/`SERVICE_REQUEST`/`SERVICE_ACCEPT`, and channel-opening payload codecs |
| `crates/tatami-wire/src/primitives.rs` (`Mpint`) | RFC 4251 §5 `mpint`: borrowed two's-complement read, minimal-encoding check, positive-magnitude write; tested against the RFC's five examples (round 4) |
| `crates/tatami-wire/src/kex.rs` | `KEX_ECDH_INIT` / `KEX_ECDH_REPLY` (RFC 5656 §4 structure) and `NEWKEYS` codecs; syntactic only (round 4) |
| `crates/tatami-wire/src/ext_info.rs` | `EXT_INFO` lazy decoder/encoder, known extension names (RFC 8308) (round 4) |
| `crates/tatami-wire/src/algorithms.rs` | Name constants for the first interoperability profile and markers (round 4) |
| `crates/tatami-keys/src/{blob,fingerprint,trust}.rs` | `PublicKeyBlob`/`SignatureBlob` codecs; `Sha256Fingerprint` (`SHA256:` base64, OpenSSH presentation); `HostTrustPolicy`, `TrustDecision`, `PinnedSha256`, `NoTrustPolicy` (round 4) |
| `crates/tatami-keys/src/ed25519.rs` (`ed25519`) | `Ed25519PublicKey`/`Ed25519Signature`/`HostKey`; verification via `ed25519-dalek` `verify_strict`; RFC 8032 §7.1 vectors (round 4) |
| `crates/tatami-tcp/src/{ident,packet}.rs` | Identification *exchange* (terminators, prelude, 255-byte rule, version policy) over the shared syntax; initial unprotected packet framing |
| `crates/tatami-tcp/src/negotiate.rs` (`kex`) | Client proposal; RFC 4253 §7.1 negotiation; strict-KEX spelling pairing; `first_kex_packet_follows`; AEAD-implies-no-MAC rule (W-30) (round 4) |
| `crates/tatami-tcp/src/transcript.rs` (`kex`) | X25519 agreement (RFC 7748 §6.1 vectors, all-zero abort), exchange hash `H`, session id, RFC 4253 §7.2 key derivation (round 4) |
| `crates/tatami-tcp/src/gcm.rs` (`kex`) | `aes128-gcm@openssh.com` seal/open (RFC 5647: length as AAD, 64-bit invocation counter, never reset) (round 4) |
| `crates/tatami-tcp/src/handshake.rs` (`kex`) | Portable `ClientHandshake` state machine and `HandshakeReport`; scripted fixture server for tests (round 4) |
| `crates/tatami-tcp/src/io/handshake.rs` (`std`+`kex`) | Blocking driver with connect + overall deadlines and OS entropy (round 4) |
| `crates/tatami-tcp/tests/openssh_handshake.rs` | Interop against a locally spawned OpenSSH `sshd` (skips if absent) (round 4) |
| `crates/tatami-quic/src/diag/{mod,identity,tls,server,client,inmem,udp}.rs` (`quinn-backend`) | QUIC/TLS diagnostic handshake observer: sans-I/O `ServerCore`/`ClientCore`, recording `ResolvesServerCert`, pinned certificate and RFC 7250 raw-public-key verifiers, rcgen test identities, in-memory pair for tests, UDP adapter (round 4) |
| `crates/tatami-quic/tests/{inmem_handshake,loopback,exporter,rpk}.rs` | Evidence for the QUIC experiment (see `quic-observer-readiness.md`) (round 4) |
| `crates/tatami/src/quic_diag/` (`quic-diag`) | Options, JSON Lines encoder and text reports for the `tatami-quic-*` binaries (round 4) |
| `crates/tatami/src/bin/tatami-quic-{server,client}.rs` | `observe` and `handshake` executables (`quic-diag`) (round 4) |
| `scripts/openssh-fixture.sh` | Reproducible loopback `sshd` with an ephemeral Ed25519 key; prints the pin and the exact handshake command (round 4) |
| `docs/crypto-provider-audit.md` | Provider versions, features, MSRV, `no_std` evidence, MAC-list policy, QUIC backend constraints (round 4) |
| `crates/tatami-tcp/src/io/seam.rs` | Internal `Conn`/`Clock` seam with a scripted connection and virtual clock for deterministic adapter tests (`std`, `pub(crate)`) |
| `crates/tatami-tcp/src/initial.rs` | Bounded `InputBuffer`; shared pre-`KEXINIT` packet handling and error codes |
| `crates/tatami-tcp/src/probe.rs` | Portable client-side initial-offer probe |
| `crates/tatami-tcp/src/observer.rs` | Portable server-side observer (no server `KEXINIT`) |
| `crates/tatami-tcp/src/io.rs` | Blocking TCP connect/read adapter with phase deadlines (`std`) |
| `crates/tatami-tcp/src/io/listener.rs` | Bounded diagnostic listener: accept loop, worker pool, record channel (`std`) |
| `crates/tatami-tcp/tests/` | Loopback fixture-peer tests for the probe adapter and the listener |
| `crates/tatami-quic/src/io.rs` | Future optional socket/runtime adapters |
| `crates/tatami-connection/src/opening.rs` | Channel-opening lifecycle engine |
| `crates/tatami/src/client.rs` | `client::probe` (`std,tcp`) and `client::handshake` (`std,tcp,kex`): options, structured reports, text and JSON rendering |
| `crates/tatami/src/server.rs` | `server::observe`: listener options, JSON Lines encoder, RFC 3339 time (`std,tcp`) |
| `crates/tatami/src/json.rs` | Small RFC 8259 serializer used for JSON Lines |
| `crates/tatami/src/text.rs` | Escaping of untrusted bytes for terminal display (not JSON) |
| `crates/tatami/src/bin/` | `tatami-client` (`probe`; `handshake` with `kex`) and `tatami-server` executables (`std,tcp`) |
| `crates/tatami/tests/` | End-to-end binary tests; JSON validated with `serde_json` (dev-dependency only) |
| `docs/specification-inventory.md` | Which specifications touch which layer, and their status |
| `docs/quic-observer-readiness.md` | QUIC handshake observer: backend decision, implementation corrections, what remains for an SSH-over-QUIC observer |
| `crates/tatami/src/host/` | Future environment, process and PTY adapters |
| `docs/` | Architecture, decisions, protocol checkpoint and existing Draft 00 |
| `scripts/check-workspace.sh` | Local and CI build/feature verification |
| `.github/workflows/ci.yml` | Minimum-version and stable checks |
| `fuzz/wire-core/`, `fuzz/protocol/` | Isolated libFuzzer workspaces (18 targets, committed seeds); see `docs/fuzzing.md` |
| `fuzz/toolchain.env`, `scripts/fuzz.sh`, `.github/workflows/fuzz.yml` | Pinned fuzz toolchain, wrapper and bounded CI campaigns |

### Implemented

**Wire.** `Reader`/`Writer` over borrowed slices with an atomic cursor
contract (a failed call leaves the cursor unchanged). Primitives: byte,
boolean (any nonzero decodes true, encodes 0/1), `uint32`, `uint64`, `string`
(arbitrary bytes), `name-list` (validated, iterated without allocation; empty
list valid at this layer) and, since round 4, `mpint` (borrowed
two's-complement value, minimal-encoding check, positive-magnitude writer;
negative values readable but not writable). Message decoders consume a
delimited payload, name the failing field, reject trailing bytes where the
message has no tail, and preserve unknown names and codes. `KEXINIT` parsing
is syntactic; `classify_kex_name` separately annotates `ext-info-c/s` and
both strict-KEX spellings (`kex-strict-*-v00@openssh.com`, `kex-strict-*`) as
non-methods, and `classify_strict_kex_name` yields role and spelling. Round 4
added `kex` (`KEX_ECDH_INIT`/`REPLY`, `NEWKEYS`), `ext_info` (lazy, bounded)
and the `SERVICE_REQUEST`/`SERVICE_ACCEPT` codecs; all remain syntactic
(the 32-byte X25519 length rule lives in `tatami-tcp::transcript`).

**Identification (round 3 split).** `tatami_wire::ident::Identification::parse`
validates complete content without a terminator: the `SSH-` prefix, both
separators, RFC 4253 token characters, and no CR/LF/NUL anywhere; fields are
borrowed slices, absent and empty comments stay distinct, nothing is trimmed
or lossily decoded, and any syntactically valid version parses.
`tatami_wire::ident::encode` writes content only and never partially fills
the buffer. `tatami_tcp::ident` wraps that with everything TCP-specific and
applies the `2.0`/`1.99` policy (W-12 revised).

**TCP.** Identification parsing survives any read boundary, bounds prelude
lines/bytes separately from the 255-byte identification limit (measured with
the observed terminator: 254 content + LF fits, 254 + CRLF does not), accepts
LF-only terminators (reported), treats `1.99` as SSH-2 compatibility and
rejects SSH-1. Initial packet framing validates alignment, minimum size,
padding and a configurable cap (default 64 KiB, above the RFC 4253 §6.1
baseline) from the header alone, before buffering the body. The probe state
machine sends only a client identification (`SSH-2.0-tatami_0.1.0`), handles
`IGNORE`/`DEBUG`/`UNIMPLEMENTED`/`DISCONNECT`, stops at the first `KEXINIT`,
and ends with an explicit unsupported-state result on `NEWKEYS` or a
method-specific message. Deadlines are per phase (connect, read) and live
only in `io`. Name resolution is synchronous `ToSocketAddrs` and is not
covered by the deadlines; that is documented, not solved.

**Connection.** `opening::OpeningEngine` keeps local numbers, peer numbers
and generation-checked application handles distinct. Opens become channels
only on a decoded confirmation or an explicit `accept`. Local numbers are
allocated monotonically and never reused in this version; cancelled numbers
are tombstoned (bounded) so late replies are classified rather than treated
as violations. Incoming opens beyond the pending limit are refused with
`SSH_OPEN_RESOURCE_SHORTAGE`. Transport loss is a distinct event from peer
refusal and local cancellation. Window/max-packet fields are retained
verbatim with no accounting.

**TCP observer (round 2).** `initial.rs` factors the role-neutral parts out
of the probe: an `InputBuffer` that rejects over-capacity input before
copying, and `InitialPackets`, which applies the packet/byte budgets and
classifies pre-`KEXINIT` messages identically for both roles. `observer.rs`
is the server-side state machine: it emits `SSH-2.0-tatami_observer_0.1.0`
(validated for token characters and the 255-byte line limit via
`ident::build_identification`, now shared with the probe), treats any
non-`SSH-` client input as `unexpected_input` with a bounded sample, reports
`1.99` and LF-only as anomalies, and stops at the client's first `KEXINIT`
or after the identification in banner-only mode. `io/listener.rs` is the
host side: non-blocking accept polled at 25 ms, capacity acquired before a
detached worker thread is spawned, excess connections closed without a
banner and counted, one deadline per connection covering banner and reads
with the remaining time recomputed per operation, a bounded record channel
to a single sink thread with `try_send` drop accounting, and a stop policy
that lets in-flight observations finish within the grace period before
cancelling them. `StopHandle` and finite-run limits stop the loop without
another client connecting.

**Facade.** `client::probe::run` returns a `Report`; `write_text` renders it
with every peer string escaped, lists in advertised order and both directions
printed separately. `server::observe::prepare` binds and returns the actual
address; `run_jsonl` writes schema-1 JSON Lines through `tatami::json`, with
raw bytes as lossy text plus bounded hex and oversized records re-emitted
truncated. Exit statuses per W-16.

**Fuzzing (round 3).** libFuzzer targets in two isolated workspaces cover
every implemented parser, encoder and state machine with independent
oracles; committed seeds reach the deep states; `scripts/fuzz.sh` wraps
build/replay/run/reproduce/minimize/coverage; CI runs bounded campaigns.
Details, execution evidence and findings are in `fuzzing.md`.

**TCP handshake (round 4).** `tatami-tcp/kex` implements exactly the first
interoperability profile (W-29): `negotiate` builds the client `KEXINIT`
(one method, one host-key algorithm, one AEAD cipher, `none` compression,
`hmac-sha2-256` listed only to satisfy the non-empty name-list syntax, W-30)
and applies RFC 4253 §7.1 selection with markers excluded on both sides,
strict-KEX markers matched only within the same spelling, and
`first_kex_packet_follows` evaluated on the first real method. `transcript`
performs X25519, rejects an all-zero shared secret, computes `H` over
`V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K` with the received `KEXINIT` bytes
verbatim (EID 4533), sets `session_id = H`, and derives the four GCM
keys/IVs (§7.2). `gcm` seals and opens `aes128-gcm@openssh.com` packets with
the 4-byte length as AAD and a 64-bit invocation counter that is never reset
or reused. `handshake::ClientHandshake` is a sans-I/O validator: it stops at
`Step::TrustDecisionRequired` after the Ed25519 signature over `H` verifies,
and only a `Trusted` answer (from `tatami_keys::trust::HostTrustPolicy`;
the CLI uses `PinnedSha256`, W-32) lets `NEWKEYS` be sent. Under strict KEX
the server `KEXINIT` must be the first packet, only KEX messages are accepted
before the initial exchange completes, and sequence numbers reset per
direction at each `NEWKEYS`. After `NEWKEYS` it sends
`SERVICE_REQUEST("ssh-userauth")`, accepts `EXT_INFO` only as the first
protected packet (`server-sig-algs` recorded; nothing is enabled), and on
`SERVICE_ACCEPT` sends a protected `DISCONNECT` and finishes `Completed`. A
server `KEXINIT` after `NEWKEYS` yields `RekeyNotSupported`; a
`USERAUTH_REQUEST` is never sent (W-33). Pre-KEX packets/bytes and protected
packets are budgeted; reports never contain key material. `io::handshake`
drives it over a blocking socket with connect and overall deadlines and OS
entropy. Verified against a locally spawned `OpenSSH_10.2p1` in
`tatami-tcp/tests/openssh_handshake.rs` and `tatami/tests/handshake_cli.rs`
(default sshd completes; wrong pin stops before `NEWKEYS`; profile-restricted
sshd completes; `Ciphers=aes256-ctr` fails negotiation cleanly).

**Keys (round 4).** `tatami-keys` owns the algorithm-agnostic public-key
and signature blob codecs (key-format name and signature-algorithm name are
separate fields, as RFC 8332 requires; `HostKey::from_blob` and
`verify_signature_blob` check both for `ssh-ed25519`),
`Ed25519PublicKey::from_bytes` (invalid points rejected at construction) and
`verify_strict`, the `SHA256:` fingerprint of the complete blob (equal to
`ssh-keygen -lf`), and the trust contract:
`HostTrustPolicy::decide(&HostIdentity) -> TrustDecision`. Signature
validity and trust are separate facts. Unknown algorithms are reported with
their name; RSA/ECDSA/certificates, signing, `known_hosts` and SPKI
conversion are not implemented here (the SPKI helpers used by the QUIC
experiment live in `tatami-quic::diag::identity`).

**Connection (round 4 fix).** `OpeningEngine::handle_open_confirmation`
now rejects a peer `sender_channel` already in use by a pending or
established channel with `Violation::DuplicatePeerNumber` before any state
change; a late confirmation for a cancelled open with such a number is
rejected and its tombstone kept. Regression tests and a strengthened
independent fuzz model cover both paths.

**QUIC diagnostic backend (round 4).** `tatami-quic::diag` (feature
`quinn-backend`, W-31) is observer (a) of `quic-observer-readiness.md`: a
QUIC v1-only `quinn-proto` endpoint with `rustls` 0.23 on `ring`, driven
sans-I/O by `ServerCore`/`ClientCore` and, for hosts, a blocking UDP loop.
It completes TLS 1.3 handshakes with an rcgen-generated Ed25519 *test*
identity, records the offered ClientHello (through a recording
`ResolvesServerCert`) and the negotiated ALPN/SNI, the source address and
its validation state (`--require-validation` answers with Retry), the
outcome, and whether the exporter is available after completion. 0-RTT and
resumption are disabled explicitly; streams and datagrams are refused at the
transport-parameter level; every datagram on the wire is a `quinn-proto`
`Transmit`. The RFC 7250 raw-public-key experiment succeeded
(`tests/rpk.rs`): server `AlwaysResolvesServerRawPublicKeys`, client
verifier pinning the SPKI SHA-256 with rustls verifying the
`CertificateVerify` signature; `peer_identity()` then holds the 44-byte
SPKI DER. The same Ed25519 key has three distinct SHA-256 fingerprints
(certificate DER, SPKI DER, `ssh-ed25519` blob). No SSH byte is sent; the
tests assert this over every captured datagram. The facade adds
`tatami::quic_diag` (JSON Lines schema 1, transport `quic`) and two
binaries. Nothing here defines the SSH-over-QUIC mapping.

### Next implementation slices

1. **TCP:** rekeying (both initiators, key rollover under strict KEX, the
   `EXT_INFO`-before-`USERAUTH_SUCCESS` opportunity), then `publickey`
   userauth in `tatami-auth` consuming `session_id` (contract §2.2 item 6),
   then a `session` channel with `exec`, data, window accounting (EID 3878),
   `EOF`/`CLOSE` and number release; then `direct-tcpip`, `tcpip-forward` /
   `forwarded-tcpip` and a SOCKS front end in the facade. Second cipher and
   `hmac-sha2-256` only with a specified negotiation path (W-30 gap).
2. **QUIC:** bootstrap (identification placement, control stream), the
   exporter-derived binding construction and its userauth input, and the
   channel/stream association — each defined against the TCP behaviour above
   and recorded in the checkpoint before code. Observer (b) starts only then.
3. **Later:** PTY/`shell`, SFTP v3 (W-25).

The workspace still deliberately does not define QUIC record framing, window
mapping, stream association, session-binding construction or a crypto
abstraction. Interoperability evidence is the OpenSSH tests above (one
implementation, client role only); the loopback fixtures in
`tatami-tcp/tests`, `tatami-quic/tests` and `tatami/tests` are not SSH
servers.

## Toolchain and publishing

The initial MSRV is Rust 1.85, with edition 2024 and resolver 3. CI checks both
1.85.0 and stable. No toolchain override file forces contributors to change their
default compiler. [Rust 2024 documentation](https://doc.rust-lang.org/edition-guide/rust-2024/index.html).

The workspace inherits the repository's Apache-2.0 license and disables package
publishing. It commits `Cargo.lock` so later application/CI dependency resolution
is reproducible. This does not commit the project to its current API surface.
