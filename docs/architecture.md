# Workspace architecture

Status: initial scaffold, 2026-09-20. Package boundaries are an implementation
starting point; unresolved protocol choices remain unresolved and are tracked
in `tatami-ssh-design-state-checkpoint.md`.

All libraries are `no_std`. All seven proposed package boundaries are
represented now as documentation-only scaffolds so that the layout, dependency
direction and feature policy can be checked mechanically before functionality
lands. They are not working protocol implementations.

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
| `crates/tatami-{tcp,quic}/src/io.rs` | Future optional socket/runtime adapters |
| `crates/tatami/src/{client,server}.rs` | Future reusable application composition |
| `crates/tatami/src/host/` | Future environment, process and PTY adapters |
| `docs/` | Architecture, decisions, protocol checkpoint and existing Draft 00 |
| `scripts/check-workspace.sh` | Local and CI build/feature verification |
| `.github/workflows/ci.yml` | Minimum-version and stable checks |

Implement bounded SSH primitives and opening-message codecs in `wire`, then the
pending/accepted/refused channel lifecycle in `connection`. Keep local/peer SSH
numbers distinct from QUIC stream IDs. The connection engine must not equate
stream readiness with channel acceptance. Allocation-free wire helpers should
accept caller-provided buffers or borrowed inputs.

The scaffold deliberately does not define QUIC record framing, window mapping,
stream association, session-binding construction or a crypto abstraction. Add
protocol tests for actual behavior as it arrives. Future interoperability tests
must belong to a Cargo package; a virtual workspace root is not a test package.

## Toolchain and publishing

The initial MSRV is Rust 1.85, with edition 2024 and resolver 3. CI checks both
1.85.0 and stable. No toolchain override file forces contributors to change their
default compiler. [Rust 2024 documentation](https://doc.rust-lang.org/edition-guide/rust-2024/index.html).

The workspace inherits the repository's Apache-2.0 license and disables package
publishing. It commits `Cargo.lock` so later application/CI dependency resolution
is reproducible. This does not commit the project to its current API surface.
