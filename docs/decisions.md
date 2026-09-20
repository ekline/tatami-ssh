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
