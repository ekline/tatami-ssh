# Workspace decisions

Protocol and architecture decisions (C-xx, P-xx, AQ-xx, D-xxx) are recorded in
`tatami-ssh-design-state-checkpoint.md` §1 and are not duplicated here. This
file records decisions about the Cargo workspace itself. Dates are the date the
decision was recorded.

| ID | Date | Decision | Rationale / consequence |
|---|---|---|---|
| W-01 | 2026-09-20 | All seven package boundaries exist from the start as documentation-only scaffolds. | Supersedes the checkpoint §2 suggestion to create packages lazily. Lets dependency direction and feature policy be verified mechanically before code lands. Each package still gains functionality only when its first real slice is implemented. |
| W-02 | 2026-09-20 | Every library is `#![no_std]`; `std` is a feature only on `tatami-tcp`, `tatami-quic` and `tatami`. | Keeps the `std` prelude out of portable modules even in host builds. See `architecture.md` portability layers. |
| W-03 | 2026-09-20 | `tatami-wire/alloc` is the only opt-in feature among the shared protocol packages; `keys`, `auth` and `connection` require `alloc` unconditionally. | Bounded, allocation-free codecs are a real embedded need; allocation-free state machines are not a current requirement and would complicate the API. |
| W-04 | 2026-09-20 | The facade's `std` forwards to bindings via weak features (`tatami-tcp?/std`) and never selects a transport. | `std` alone compiles only the facade host modules. Transport selection is always explicit. |
| W-05 | 2026-09-20 | Client and server are modules of `tatami`, not separate crates. | Library reuse is met by public modules; a split is deferred until dependency weight or release cadence justifies it. |
| W-06 | 2026-09-20 | No common `Transport` trait, KEX abstraction, or `tatami-crypto` crate. | Matches C-07 and checkpoint §2.1. Sharing engine-driving code between bindings is a later, evidence-based refactor. |
| W-07 | 2026-09-20 | MSRV 1.85, edition 2024, resolver 3; CI checks 1.85.0 and stable; no `rust-toolchain` file. | Edition 2024 is the first available on 1.85. Contributors keep their default compiler. |
| W-08 | 2026-09-20 | `Cargo.lock` is committed; `publish = false` on every package. | Reproducible CI and application builds without committing to an API surface. |
| W-09 | 2026-09-20 | Core/alloc-only verification uses `thumbv7em-none-eabi`; it is required in CI and optional locally. | A host check cannot detect transitive `std` use because `std` is always present on the host. |
| W-10 | 2026-09-20 | Tests and future interoperability harnesses live inside Cargo packages. | A virtual workspace root is not a test package; root-level test directories would create apparent coverage with no executable harness. |
| W-11 | 2026-09-20 | The first diagnostic client is an *initial-offer probe* that sends only a client identification and never a client `KEXINIT`. | Tatami has no implemented algorithm set; advertising copied, empty or placeholder lists would be a false claim on the wire. Servers that wait for the client's proposal yield a documented partial result at the deadline. |
| W-12 | 2026-09-20 | Identification and initial packet framing live in `tatami-tcp`, not `tatami-wire`. | They are the TCP binding's envelope. Moving them to `wire` would imply a QUIC envelope shares them, which has not been decided. |
| W-13 | 2026-09-20 | `tatami-wire` message decoders are syntactic; recognition of `KEXINIT` marker names (`ext-info-*`, `kex-strict-*`) is a separate annotation function. | Keeps unknown names intact and prevents a report helper from becoming an accidental negotiation policy. |
| W-14 | 2026-09-20 | The probe adapter is blocking `std::net` with per-phase deadlines; no async runtime is chosen. | A runtime commitment is not needed for the probe and would leak into `io` before a provider audit. Synchronous name resolution is outside the deadlines and documented as such. |
| W-15 | 2026-09-20 | `OpeningEngine` never reuses a local channel number; cancelled numbers are tombstoned (bounded) to classify late replies. | RFC 4254 cannot withdraw an `OPEN`. Reuse must wait for a close lifecycle that defines when the peer can no longer reference a number; deferring reuse avoids ambiguity without inventing a wire extension. |
| W-16 | 2026-09-20 | CLI exit statuses: 0 complete observation, 1 incomplete or network/protocol failure, 2 usage or unsupported command. `tatami-server` exits 1 for any non-help invocation. | Stable statuses for scripting; the server stub must never look like a running server. |
| W-17 | 2026-09-20 | Packet-length cap defaults to 64 KiB (configurable), above the RFC 4253 §6.1 35 000-byte mandatory baseline. | The baseline is a floor implementations must accept, not a maximum. The cap is local policy and is enforced from the header before the body is buffered. |
