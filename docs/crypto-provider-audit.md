# Cryptographic provider and QUIC backend audit

Status: round 4, 2026-09-20. This audit precedes and governs the provider
features added in this round. It selects a deliberately small first
interoperability profile; it is not a claim that SSH's full algorithm
requirements (RFC 9142 MUSTs, RFC 8332, etc.) are met — those gaps remain in
`specification-inventory.md`.

## Method

Every claim below was checked against the crate's own manifest and source in
the local registry (`~/.cargo/registry/src/*/<crate>-<version>/Cargo.toml`)
and against the resolved graph of this workspace:

```sh
cargo tree -p tatami-tcp  --features kex           -e features -f '{p} {f}'
cargo tree -p tatami-keys --features ed25519       -e features -f '{p} {f}'
cargo tree -p tatami-quic --features quinn-backend -e features -f '{p} {f}'
grep -m1 rust-version ~/.cargo/registry/src/*/<crate>-<version>/Cargo.toml
```

The portable set was additionally resolved in an isolated `#![no_std]`
scratch crate (`target/audit-crypto`, not committed) to confirm that no
`std` feature, `getrandom`, `libc` or C build appears in its normal
dependency graph. Bare-metal compilation on `thumbv7em-none-eabi` runs in
CI (`scripts/check-workspace.sh`); it could not be run on the development
machine (no `rust-std` for that target) and is therefore a **pending CI
gate**, not a local claim. Advisory review used the RustSec database as
known to the author at the audit date; no automated `cargo audit` run was
possible offline and none is claimed.

## First interoperability profile

| Function | Algorithm | Specification | Provider |
|---|---|---|---|
| Key exchange | `curve25519-sha256` | [RFC 8731](https://www.rfc-editor.org/rfc/rfc8731.html), [RFC 5656 §4](https://www.rfc-editor.org/rfc/rfc5656.html#section-4) | `x25519-dalek` + `sha2` |
| Host-key signature | `ssh-ed25519` | [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709.html) | `ed25519-dalek` |
| Packet protection (both directions) | `aes128-gcm@openssh.com` | [RFC 5647](https://www.rfc-editor.org/rfc/rfc5647.html) construction; negotiation per [draft-miller-sshm-aes-gcm-01 §2](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm-01) and [OpenSSH PROTOCOL §1.6](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL) | `aes-gcm` |
| Compression | `none` | RFC 4253 §6.2 | — |
| Strict KEX | `kex-strict-c-v00@openssh.com` marker | [draft-ietf-sshm-strict-kex-02](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-strict-kex-02) | — |
| Extension negotiation | `ext-info-c` marker, `EXT_INFO` receive only | [RFC 8308 §2](https://www.rfc-editor.org/rfc/rfc8308.html#section-2) | — |
| Host fingerprint | `SHA256:` base64 (no padding) of the complete key blob | OpenSSH `ssh-keygen -l` convention | `sha2` + `base64ct` |

### Specification revisions pinned

- **draft-ietf-sshm-strict-kex-02** (published 22 July 2026, active). Rules
  used: markers only in the initial `KEXINIT`; enable when client offers
  `kex-strict-c[-v00@openssh.com]` and server offers the *matching*
  `kex-strict-s[-v00@openssh.com]` name (standard with standard, pre-standard
  with pre-standard — never mixed); `KEXINIT` must be the first packet
  received; only KEX-specific messages, `KEXINIT` and `NEWKEYS` before the
  initial KEX completes; each permitted message accepted the expected number
  of times; sequence numbers reset to zero after `NEWKEYS` is sent and after
  it is received, per direction; no wrap before initial KEX completes. Tatami
  offers **both** names, as §3.1 recommends.
- **draft-miller-sshm-aes-gcm-01** (published 10 November 2025, expired 14 May
  2026, no `draft-ietf-sshm-aes-gcm` successor existed at the audit date).
  Rules used: AEAD names appear only in `encryption_algorithms`; when the
  selected cipher is an AEAD, MAC negotiation is skipped and the MAC lists are
  ignored; `aes128-gcm@openssh.com` is the deployed vendor name for §2.1.
  OpenSSH PROTOCOL §1.6 points to this draft as its authority.
- **RFC 5647 §§6–7** for the construction: the 4-byte `packet_length` is
  additional authenticated data and is transmitted in clear; the 12-byte
  nonce is a 4-byte fixed field followed by an 8-byte invocation counter that
  is incremented as a 64-bit integer after every packet (both fields come
  from the derived IV); the 16-byte tag follows the ciphertext; padding is
  computed over `padding_length + payload + padding` to a multiple of the
  16-byte block; minimum padding 4.

### MAC-list policy under the AEAD rule

Tatami advertises only `aes128-gcm@openssh.com` as a cipher, so the peer can
never select a non-AEAD cipher from our proposal and MAC negotiation is
always skipped by the rule above. The `mac_algorithms` lists are still
required to be non-empty name-lists by RFC 4253 §7.1. Tatami sends
`hmac-sha2-256` in both directions purely to satisfy that syntax; it does
not implement an HMAC and the handshake state machine refuses to proceed
(`NoMacImplemented`) in the impossible case that a negotiated cipher is not
an AEAD. This is recorded as W-30 and as a compatibility gap in the
inventory rather than hidden.

## Selected crates (portable set)

All are pure Rust, `no_std`-capable, allocation only where noted, with no
C/assembly, OS or runtime dependency in the normal graph. The only `std`
edge in `cargo tree -e features` is `semver` inside `rustc_version`, which
is a **build-script** dependency of `curve25519-dalek` (compiler version
probing) and never part of the compiled library.

| Crate | Version | Features enabled | MSRV (`rust-version`) | Transitive notes | Entropy / secrets | Why it fits |
|---|---|---|---|---|---|---|
| `x25519-dalek` | 2.0.1 | `zeroize`, `static_secrets` (defaults off) | 1.60 | `curve25519-dalek` 4.1.3 (MSRV 1.60.0; `digest`, `zeroize`), `curve25519-dalek-derive` (proc-macro), `rand_core` 0.6.4 | Ephemeral secret built from 32 caller-supplied random bytes via `StaticSecret::from`; `zeroize` on drop; `Debug` on secrets is not derived | Maintained dalek-cryptography implementation of RFC 7748 X25519 with constant-time field arithmetic; `static_secrets` is needed only because the ephemeral secret is constructed from injected bytes rather than an RNG |
| `ed25519-dalek` | 2.2.0 | `zeroize` (defaults off) | **1.81** | `ed25519` 2.2.3, `signature` 2.2.0, `sha2` | Verification only; no signing keys are created | RFC 8032 verification with the strict validation the SSH ecosystem expects; same maintained family as above |
| `sha2` | 0.10.9 | none (defaults off) | unset in manifest; RustCrypto documents 1.41 for 0.10 | `digest` 0.10.7, `block-buffer`, `crypto-common`, `cpufeatures` (no-op on `thumbv7em`) | none | SHA-256 for the exchange hash, key derivation and fingerprints |
| `aes-gcm` | 0.10.3 | `aes` (defaults off; no `alloc`, no `getrandom`) | 1.56 | `aes` 0.8.4 (1.56), `ghash` 0.5.1 (1.56), `polyval`, `ctr`, `aead` 0.5.2, `universal-hash`, `subtle` | Keys and nonces are supplied by the caller; the in-place detached API is used so no plaintext copy is made by the provider | RFC 5116/5647 AES-128-GCM with constant-time GHASH; RustCrypto AEAD API allows detached tags and in-place operation, which the SSH packet layout needs |
| `rand_core` | 0.6.4 | none | unset (crate documents 1.56 for 0.6) | none | Defines the `RngCore`/`CryptoRng` contract that portable code accepts by injection | Version the dalek 2.x crates expect; the host adapter supplies an implementation |
| `getrandom` | 0.2.17 | none; **only in `tatami-tcp/std`** | unset (crate documents 1.36) | OS syscalls | Host entropy for the `std` adapter only | Never present in portable builds; fallible API is surfaced rather than panicking |
| `zeroize` | 1.9.0 | `zeroize_derive` (defaults off) | **1.85** (equals the workspace MSRV) | proc-macro | Wipes shared secrets, derived keys and ephemeral scalars on drop | Standard secret-hygiene crate |
| `subtle` | 2.6.1 | none | unset (documents 1.60) | none | Constant-time equality for fingerprint/pin and tag comparison | Avoids early-exit comparison on secret-adjacent values |
| `base64ct` | 1.8.3 | `alloc` | **1.85** | none | none | Constant-time base64 for `SHA256:` fingerprints; no `std` |

MSRV consequence: the highest `rust-version` in the portable set is 1.85
(`zeroize`, `base64ct`), equal to the workspace MSRV, so nothing is raised.
`Cargo.lock` pins these exact versions; `cargo update` would move `zeroize`
and `base64ct` only within 1.85-compatible releases (Cargo resolver 3
honours `rust-version`).

Not selected: `ring`/`aws-lc-rs` for the SSH side (C/assembly, `std`), RSA
or ECDSA crates (out of profile), `chacha20poly1305` (the profile picks one
AEAD; ChaCha20-Poly1305 is a natural second and is *not* Terrapin-safe
without strict KEX, which is one more reason to land strict KEX first),
`hmac` (no non-AEAD cipher to pair it with).

## QUIC/TLS diagnostic backend (host-only)

Selected after compiling against the exact releases below (the readiness
document's `quinn-proto + rustls` candidate is now the decision, W-31):

| Crate | Version | Features enabled | MSRV | Notes |
|---|---|---|---|---|
| `quinn-proto` | 0.11.18 | `rustls-ring`, `ring` (defaults off) | **1.85** | Sans-I/O QUIC state machine; no runtime. `Connection::crypto_session().export_keying_material(out, label, context)` exposes the TLS exporter (`src/crypto.rs` trait, `src/crypto/rustls.rs` impl over `rustls::quic::Connection::export_keying_material`); `Incoming::remote_address_validated()` and `may_retry()` expose address-validation state (`src/endpoint.rs`); `HandshakeData { protocol, server_name }` exposes the **negotiated** ALPN and SNI. The **offered** ALPN list is not exposed by quinn-proto; it is observable only through a rustls `ResolvesServerCert::resolve(ClientHello)` hook on the server. Version Negotiation is handled inside the endpoint and is not surfaced as an event. |
| `rustls` | 0.23.45 | `ring`, `std`, `tls12` (defaults off) | 1.71 | `std` is required by the QUIC API surface; this is why the backend feature enables `std`. `CertificateType::RawPublicKey` and `AlwaysResolvesServerRawPublicKeys` / `AlwaysResolvesClientRawPublicKeys` exist (`src/server/handy.rs`, `src/client/handy.rs`), so RFC 7250 raw public keys are an API possibility to be proven by the experiment in this round, not assumed. |
| `rustls-pki-types` | 1.15.1 | `std` | 1.60 | Certificate/key DER types |
| `rcgen` | 0.13.2 | `ring`, `pem` (defaults off) | unset | Generates the ephemeral **test** identity; never used for production identity. Pulls `time` 0.3.45 (the newest `time` requires 1.88; the lockfile pins the 1.85-compatible release). |
| `ring` | 0.17.14 | none | 1.66.0 | C and assembly; needs a C compiler at build time. Confined to the `quinn-backend` feature. |

Constraints recorded: the whole backend requires `std`; it never appears in
default, `tcp`-only or portable builds (`cargo tree -p tatami-quic` without
the feature shows no crypto crates); it exists for the diagnostic handshake
experiment only and settles no SSH-over-QUIC wire question.

## Secret handling rules applied

- Entropy is injected into portable code through `rand_core::CryptoRngCore`
  (fallible `try_fill_bytes`); the OS adapter uses `getrandom`. Deterministic
  RNGs exist only under `cfg(test)`.
- Ephemeral X25519 scalars, the shared secret `K`, the exchange hash inputs
  that contain `K`, and all derived keys/IVs live in `Zeroizing` wrappers or
  types with `Drop` zeroization; they are copied at most once into the
  provider's key schedule.
- No secret implements `Debug` output: reports carry only the host-key
  fingerprint, algorithm names, sizes and outcomes. Fuzz artifacts and JSON
  records never include key material.
- Signature verification uses `ed25519_dalek::VerifyingKey::verify_strict`.

## Open items

- Bare-metal (`thumbv7em-none-eabi`) build of `tatami-tcp --features kex` and
  `tatami-keys --features ed25519` is pending its first CI run.
- `cargo audit` has not been executed (offline); run it before any release.
- `ed25519-dalek` 3.x and `x25519-dalek` 3.x exist; they were not adopted
  because they move to `rand_core` 0.9 and newer MSRVs and offer nothing the
  profile needs.
