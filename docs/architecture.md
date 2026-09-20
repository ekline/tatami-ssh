# Workspace architecture

Status: scaffold plus first implementation slice, 2026-09-20. Package
boundaries are an implementation starting point; unresolved protocol choices
remain unresolved and are tracked in `tatami-ssh-design-state-checkpoint.md`.

All libraries are `no_std`. All seven proposed package boundaries exist so
that the layout, dependency direction and feature policy can be checked
mechanically. `tatami-wire`, `tatami-tcp`, `tatami-connection` and the
`tatami` facade now contain the first working code (see "Implemented" below);
`tatami-keys`, `tatami-auth` and `tatami-quic` remain documentation-only.

## Portability layers

| Layer | Packages | Policy |
|---|---|---|
| No allocation required | `tatami-wire` | Borrowed/caller-buffer codecs by default; owned helpers may use the optional `alloc` feature. |
| Allocation permitted, no OS | `tatami-keys`, `tatami-auth`, `tatami-connection` | Always `no_std` with `alloc`; no `std` feature. |
| Portable binding state with optional host integration | `tatami-tcp`, `tatami-quic` | Always `no_std` with `alloc`; `std` exposes `io` modules. |
| Application composition | `tatami` | Portable `client`/`server` modules; `std` exposes `host::{environment,process,pty}`. |

`alloc` provides owned collections without requiring `std`. A final application
that uses them needs an allocator; the libraries do not install one. Passing a
library compile check does not establish an allocator, panic handler, executable
entry point, or firmware integration. [Rust alloc documentation](https://doc.rust-lang.org/alloc/).

Keep public pure APIs expressed in terms of core/alloc values. Providers supply
entropy, signing operations, time and policy as appropriate. Socket access need
not inherently require `std` on every platform, but the planned host networking,
process and PTY adapters are explicitly isolated. Embedded integration remains
possible without pretending that an OS-backed implementation is portable.

Future QUIC/TLS and crypto providers require an actual feature/capability audit.
Some will require `std` beyond socket handling. Put such dependencies behind
explicit backend features that enable `std`, or narrow the crate boundary if
needed; do not silently import them into shared protocol code. No provider,
runtime, entropy source, or TLS exporter implementation has been selected.

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

All package defaults are empty. `tatami-wire/alloc` is the sole opt-in feature
in the four shared protocol packages. The other three shared packages permit
allocation unconditionally (and enable `tatami-wire/alloc` themselves);
`--no-default-features` is not a no-allocation mode for them.

| Facade features | Binding dependencies | Host modules |
|---|---|---|
| none | None | None |
| `std` | None | Facade host modules |
| `tcp` | TCP | None |
| `quic` | QUIC | None |
| `tcp,quic` | TCP and QUIC | None |
| `std,tcp` | TCP with `std` | Facade and TCP |
| `std,quic` | QUIC with `std` | Facade and QUIC |
| `std,tcp,quic` | Both with `std` | Facade and both bindings |

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
| `crates/tatami-wire/src/{kexinit,transport,channel}.rs` | `KEXINIT`, `DISCONNECT`/`IGNORE`/`DEBUG`/`UNIMPLEMENTED`, and channel-opening payload codecs |
| `crates/tatami-tcp/src/{ident,packet}.rs` | Identification exchange and initial unprotected packet framing |
| `crates/tatami-tcp/src/initial.rs` | Bounded `InputBuffer`; shared pre-`KEXINIT` packet handling and error codes |
| `crates/tatami-tcp/src/probe.rs` | Portable client-side initial-offer probe |
| `crates/tatami-tcp/src/observer.rs` | Portable server-side observer (no server `KEXINIT`) |
| `crates/tatami-tcp/src/io.rs` | Blocking TCP connect/read adapter with phase deadlines (`std`) |
| `crates/tatami-tcp/src/io/listener.rs` | Bounded diagnostic listener: accept loop, worker pool, record channel (`std`) |
| `crates/tatami-tcp/tests/` | Loopback fixture-peer tests for the probe adapter and the listener |
| `crates/tatami-quic/src/io.rs` | Future optional socket/runtime adapters |
| `crates/tatami-connection/src/opening.rs` | Channel-opening lifecycle engine |
| `crates/tatami/src/client.rs` | `client::probe`: options, structured report, text rendering (`std,tcp`) |
| `crates/tatami/src/server.rs` | `server::observe`: listener options, JSON Lines encoder, RFC 3339 time (`std,tcp`) |
| `crates/tatami/src/json.rs` | Small RFC 8259 serializer used for JSON Lines |
| `crates/tatami/src/text.rs` | Escaping of untrusted bytes for terminal display (not JSON) |
| `crates/tatami/src/bin/` | `tatami-client` and `tatami-server` executables (`std,tcp`) |
| `crates/tatami/tests/` | End-to-end binary tests; JSON validated with `serde_json` (dev-dependency only) |
| `docs/specification-inventory.md` | Which specifications touch which layer, and their status |
| `docs/quic-observer-readiness.md` | Proposed QUIC handshake-observer slice and backend audit |
| `crates/tatami/src/host/` | Future environment, process and PTY adapters |
| `docs/` | Architecture, decisions, protocol checkpoint and existing Draft 00 |
| `scripts/check-workspace.sh` | Local and CI build/feature verification |
| `.github/workflows/ci.yml` | Minimum-version and stable checks |

### Implemented

**Wire.** `Reader`/`Writer` over borrowed slices with an atomic cursor
contract (a failed call leaves the cursor unchanged). Primitives: byte,
boolean (any nonzero decodes true, encodes 0/1), `uint32`, `uint64`, `string`
(arbitrary bytes), `name-list` (validated, iterated without allocation; empty
list valid at this layer). `mpint` is absent until something needs it.
Message decoders consume a delimited payload, name the failing field, reject
trailing bytes where the message has no tail, and preserve unknown names and
codes. `KEXINIT` parsing is syntactic; `classify_kex_name` separately
annotates `ext-info-c/s` and OpenSSH `kex-strict-*` markers as non-methods.

**TCP.** Identification parsing survives any read boundary, bounds prelude
lines/bytes separately from the 255-byte identification limit, accepts
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

### Next implementation slices

Two tracks, neither started here:

1. **TCP:** a real selected key-exchange method, host-key signature
   verification and trust validation, then protected packets and service
   negotiation. Requires algorithm and provider selection with a capability
   audit (`specification-inventory.md` §4). On the connection side, the
   channel close lifecycle must define when a local number may be released.
2. **QUIC:** a TLS/QUIC handshake observer after the backend audit in
   `quic-observer-readiness.md`; an SSH-over-QUIC observer only once ALPN,
   identity, control-stream association and identification placement are
   settled in the mapping. No `--quic` option exists.

The workspace still deliberately does not define QUIC record framing, window
mapping, stream association, session-binding construction or a crypto
abstraction. Interoperability tests belong to a Cargo package; the loopback
fixtures in `tatami-tcp/tests` and `tatami/tests` are not SSH servers and do
not substitute for the recorded OpenSSH smoke test in the README.

## Toolchain and publishing

The initial MSRV is Rust 1.85, with edition 2024 and resolver 3. CI checks both
1.85.0 and stable. No toolchain override file forces contributors to change their
default compiler. [Rust 2024 documentation](https://doc.rust-lang.org/edition-guide/rust-2024/index.html).

The workspace inherits the repository's Apache-2.0 license and disables package
publishing. It commits `Cargo.lock` so later application/CI dependency resolution
is reproducible. This does not commit the project to its current API surface.
