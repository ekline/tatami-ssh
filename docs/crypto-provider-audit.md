# Cryptographic provider and QUIC backend audit

Status: round 4, 2026-09-20; round 5 (host identity) added 2026-09-26 in
[Host-identity crates](#host-identity-crates-round-5). This audit precedes
and governs the provider features added in those rounds. It selects a deliberately small first
interoperability profile; it is not a claim that SSH's full algorithm
requirements (RFC 9142 MUSTs, RFC 8332, etc.) are met — those gaps remain in
`specification-inventory.md`.

## Method

Every claim below was checked against the crate's own manifest and source in
the local registry (`~/.cargo/registry/src/*/<crate>-<version>/Cargo.toml`)
and against the resolved graph of this workspace:

```sh
cargo tree -p tatami_ssh_tcp  --features kex           -e features -f '{p} {f}'
cargo tree -p tatami_ssh_keys --features ed25519       -e features -f '{p} {f}'
cargo tree -p tatami_ssh_quic --features quinn-backend -e features -f '{p} {f}'
cargo tree -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key -e normal -f '{p} {f}'
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
| `ed25519-dalek` | 2.2.0 | `zeroize` (defaults off) | **1.81** | `ed25519` 2.2.3, `signature` 2.2.0, `sha2` | Verification only; no signing keys are created (round 5: `SigningKey::from_bytes` derives the public key of a loaded host seed for a consistency check; Tatami never signs with it) | RFC 8032 verification with the strict validation the SSH ecosystem expects; same maintained family as above |
| `sha2` | 0.10.9 | none (defaults off) | unset in manifest; RustCrypto documents 1.41 for 0.10 | `digest` 0.10.7, `block-buffer`, `crypto-common`, `cpufeatures` (no-op on `thumbv7em`) | none | SHA-256 for the exchange hash, key derivation and fingerprints |
| `aes-gcm` | 0.10.3 | `aes` (defaults off; no `alloc`, no `getrandom`) | 1.56 | `aes` 0.8.4 (1.56), `ghash` 0.5.1 (1.56), `polyval`, `ctr`, `aead` 0.5.2, `universal-hash`, `subtle` | Keys and nonces are supplied by the caller; the in-place detached API is used so no plaintext copy is made by the provider | RFC 5116/5647 AES-128-GCM with constant-time GHASH; RustCrypto AEAD API allows detached tags and in-place operation, which the SSH packet layout needs |
| `rand_core` | 0.6.4 | none | unset (crate documents 1.56 for 0.6) | none | Defines the `RngCore`/`CryptoRng` contract that portable code accepts by injection | Version the dalek 2.x crates expect; the host adapter supplies an implementation |
| `getrandom` | 0.2.17 | none; **only in `tatami_ssh_tcp/std`** | unset (crate documents 1.36) | OS syscalls | Host entropy for the `std` adapter only | Never present in portable builds; fallible API is surfaced rather than panicking |
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
`hmac` for SSH packets (no non-AEAD cipher to pair it with; `hmac` is used
only for hashed `known_hosts` names, inside `tatami_ssh_openssh_compat`,
see the SHA-1 boundary below).

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
default, `tcp`-only or portable builds (`cargo tree -p tatami_ssh_quic` without
the feature shows no crypto crates); it exists for the diagnostic handshake
experiment only and settles no SSH-over-QUIC wire question.

Round 5 signs with an SSH host key through this backend: the in-memory
PKCS#8 is passed borrowed to `rustls::crypto::ring::sign::any_eddsa_type`;
whatever copy `ring` keeps inside its key object is outside Tatami's control.
Peer raw public keys are converted by `tatami_ssh_keys::spki` (pure Rust), and
`CertificateVerify` is verified by rustls with the provider's algorithms.

## Host-identity crates (round 5)

Added behind `tatami_ssh_keys/openssh-key` (host private-key container)
and, since round 6, `tatami_ssh_openssh_compat` (hashed hostnames; reached
only through `tatami_ssh_keys/openssh-hashed-hosts`), all portable
`no_std`, all off by default. Checked against the registry manifests and
sources and the resolved graph above (W-37, W-39, W-42):

| Crate | Version | Features enabled | MSRV (`rust-version`) | Transitive notes | Entropy / secrets | Why it fits |
|---|---|---|---|---|---|---|
| `ssh-key` | 0.6.7 | `alloc` only (defaults `ecdsa`, `rand_core`, `std` off) | 1.65 (edition 2021) | `ssh-encoding` 0.2.0 (1.60), `ssh-cipher` 0.2.0 (1.60; pulls the `cipher` 0.4 traits but no cipher implementation), `pem-rfc7468` 0.7.0 (1.60), plus the already-audited `sha2`, `signature`, `subtle`, `zeroize`, `base64ct` | Decodes the private section; its Ed25519 private key type zeroizes on drop. No RNG: `rand_core` is not enabled | Maintained RustCrypto parser for `openssh-key-v1`; decode-from-bytes API keeps file access in the host layer |
| `hmac` | 0.12.1 | none (defaults off) | unset (edition 2018) | `digest` 0.10.7 (`mac`) | none (salts are public) | HMAC-SHA1 for `\|1\|salt\|hash` hostnames only (`verify_slice`, constant time); dependency of `tatami_ssh_openssh_compat` only |
| `sha1` | 0.10.7 | none (defaults off) | unset (edition 2018) | `digest`, `cpufeatures` 0.2.17 (already present via `sha2`) | none | Hash for the legacy hashed-hostname format only; dependency of `tatami_ssh_openssh_compat` only |

`ssh-key` features deliberately **not** enabled: `ed25519` (would pull
`rand_core` and its own seed→public derivation check, which Tatami performs
with `ed25519-dalek` instead), `encryption` (would pull `bcrypt-pbkdf` and
AES/ChaCha implementations; `grep bcrypt Cargo.lock` finds nothing, so no
KDF can run), `std`, `ecdsa`, `rsa`, `dsa`. `getrandom` is not in the graph of
`tatami_ssh_keys --features known-hosts,openssh-key`; `check-workspace.sh`
enforces that together with the absence of `rustls`/`ring`/`quinn`, of any
`std` feature, of `hmac`/`sha1`/`ssh-key` without their features, and of
`ssh-key`/`rustls`/`ring` in the portable `kex` facade. MSRV stays 1.85.

## SHA-1 boundary (round 6)

SHA-1 appears in Tatami for exactly one purpose: matching OpenSSH hashed
host names (`|1|salt|HMAC-SHA1(salt, name)`, written by `ssh-keygen -H` /
`HashKnownHosts`) in operator `known_hosts` files. No SSH signature
(`ssh-rsa` RSA/SHA-1, `ssh-dss`), key exchange (`diffie-hellman-group*-sha1`),
MAC (`hmac-sha1*`), fingerprint, pin, SSHFP digest (type 1) or TLS
exporter/signature operation uses it.

- **Code.** `tatami_ssh_openssh_compat` (portable, `no_std`, no `alloc`,
  `forbid(unsafe_code)`) depends on `hmac` 0.12.1, `sha1` 0.10.7 and
  `base64ct` 1.x (defaults off). Its public API is only
  `matches_hashed_hostname(stored_field, lookup_name) -> Result<bool,
  HashedHostnameError>` and the error enum: it validates the whole
  `|1|salt|hash` field (canonical padded base64, 20-byte salt and digest,
  field ≤ 128 bytes, name ≤ 1024 bytes) and compares with `verify_slice`.
  No writer, digest/HMAC function, hash state or re-export.
- **Feature.** `tatami_ssh_keys/openssh-hashed-hosts` (forwarded by the
  facade's `openssh-hashed-hosts`); off by default and not part of `kex`
  or `quic-diag`. Without it, any hashed entry, including `@revoked` and
  `@cert-authority` lines, is `KnownHostsError::Unsupported` and the
  facade reports `unsupported_configuration` before connecting. Plaintext
  `known_hosts`, SHA-256 fingerprints/pins, SSHFP and all handshakes work
  without it.
- **Dependency enforcement** (`scripts/check-sha1-boundary.py`, run by
  `check-workspace.sh`, with a `--self-test` of every rule): the resolved
  facade graphs (`cargo tree -e normal --target all`) for
  `std,tcp,kex,quic-diag,openssh-hashed-hosts` and `kex,openssh-hashed-hosts`
  reach `sha1`/`sha-1`/`sha1_smol`/`sha1-asm`/`sha1-checked` only through
  the compat crate, which only `tatami_ssh_keys` reaches; for
  `std,tcp,kex,quic-diag`, `std,tcp,kex`, `kex`, `std,tcp`, `quic-diag` and
  no features, neither the compat crate nor any SHA-1 package is reachable.
  From `cargo metadata` (resolved package ids and declared package names,
  so renames do not hide edges): only `tatami_ssh_keys` depends on the
  compat crate, and no other workspace package depends directly on `hmac`
  or a SHA-1 package. Sources: the compat crate's public items are exactly
  the two above; within `tatami_ssh_keys` only `src/known_hosts.rs` names
  the compat crate (or a manifest rename of it).
- **Algorithm configuration** (tests, separate from the graph):
  `tatami_ssh_tcp/tests/algorithm_policy.rs` checks that no advertised
  KEXINIT list contains a SHA-1 or DSA name (`ssh-rsa` is refused in the
  host-key/signature list only; as a public-key blob type it stays legal
  for RSA/SHA-2), that fingerprints and pins are SHA-256 (`ssh-keygen -lf`
  fixture) and that SSHFP uses fingerprint type 2 only (a `4 1` record is
  refused). `tatami_ssh_quic/tests/tls_algorithm_policy.rs` checks that the
  provider's and every verifier's signature schemes exclude
  `RSA_PKCS1_SHA1`/`ECDSA_SHA1_Legacy`, that no `_SHA` cipher suite exists,
  and that rustls's QUIC mode refuses a configuration without TLS 1.3 (the
  diagnostic configs enable TLS 1.3 only).
- **Limit of the claim.** The bundled TLS backend (`ring`, under
  `quic-diag`) contains SHA-1 code internally (for example for legacy
  signature verification it never offers here). Dependency checks cannot
  prove the physical absence of every SHA-1 instruction in a binary; the
  enforceable boundary is the dependency graph above plus the enabled
  algorithm configuration.

Validation split, confirmed in `ssh-key-0.6.7/src/private.rs` and
`src/private/ed25519.rs`:

| Check | Performed by |
|---|---|
| Magic `openssh-key-v1\0`; `nkeys == 1`; KDF must be `none` when unencrypted; `checkint1 == checkint2`; outer public key equals the private section's public key (`Error::PublicKey`); the embedded `seed \|\| public` repeats that public key; padding `1, 2, 3, …`; no trailing data | `ssh-key` |
| Encrypted containers (cipher ≠ `none`) are returned opaque, undecrypted | `ssh-key`; Tatami maps them to `PrivateKeyError::Encrypted` |
| Public key is the one derived from the seed (skipped by `ssh-key` without its `ed25519` feature) | Tatami (`ed25519-dalek` `SigningKey::from_bytes`) |
| `-----BEGIN OPENSSH PRIVATE KEY-----` armor present; input ≤ 16 KiB before decoding; only `ssh-ed25519` | Tatami |
| Regular file, size bound on the opened handle; on Unix no group/other permission bits | Tatami facade (`host::files`) |

Check integers alone do not establish key consistency; the derivation check
does. The PKCS#8 form (RFC 8410 §7 prefix plus seed) is built in
`Zeroizing` memory and never written.

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
- Host private keys (round 5): read into a zeroizing buffer reserved past
  the size bound so it never reallocates; the seed and the PKCS#8 form live
  in `Zeroizing`; `Ed25519HostPrivateKey` and `HostKeyIdentity` print only
  the public fingerprint in `Debug`; `PrivateKeyError` carries no key bytes.
  Transient copies inside `ssh-key` and `ring` are outside Tatami's control.

## Open items

- Bare-metal (`thumbv7em-none-eabi`) build of `tatami_ssh_tcp --features kex`,
  `tatami_ssh_keys --features ed25519` and (round 5) `tatami_ssh_keys --features
  known-hosts,openssh-key` is pending its first observed CI run; the target
  is not installed on the development machine, where the step was skipped.
- Round 5 code has been built and tested locally on stable (rustc 1.98.1)
  only; the Rust 1.85 CI run is pending.
- `cargo audit` has not been executed (offline); run it before any release.
- Round 6 (SHA-1 boundary): the new crate adds no registry package; its
  `hmac`/`sha1`/`base64ct` versions are the ones already locked.
- `ed25519-dalek` 3.x and `x25519-dalek` 3.x exist; they were not adopted
  because they move to `rand_core` 0.9 and newer MSRVs and offer nothing the
  profile needs.
