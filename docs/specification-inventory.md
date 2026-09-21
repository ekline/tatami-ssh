# Specification inventory

Status: inventory as of 2026-09-20 (round 4). This file records which
specifications touch which package, what the workspace actually does with
each today, and the next consequence. Algorithm and provider selection for
the **first interoperability profile** is recorded in
`crypto-provider-audit.md` (W-29–W-31); this file states what that profile
covers and, explicitly, what it does not. QUIC wire choices remain open in
`tatami-ssh-design-state-checkpoint.md` (P-04, P-06, AQ-002, AQ-006–AQ-008,
AQ-018–AQ-023).

Status meanings: **implemented** — code exists and is tested;
**implemented (profile-limited)** — code exists and is tested for exactly the
scope stated, and the specification's other requirements are not met;
**recognized** — the workspace parses or annotates the artefact without
acting on it; **deferred** — nothing in the workspace depends on it yet.

## 1. Core SSH and extension specifications

| Specification | Layer / package affected | Status | Next consequence |
|---|---|---|---|
| [RFC 4250](https://www.rfc-editor.org/rfc/rfc4250.html) Assigned Numbers | `tatami-wire` (`msg` constants) | recognized: only the message numbers the codecs use (1–4, 20, 90–92) plus the 30–49 method-specific range noted by the probe | Add numbers as codecs land; keep unknown numbers reportable rather than fatal. |
| [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html) Architecture (§5 data types, §9.2 diagnostics) | `tatami-wire::{primitives,namelist}`; `tatami::text` | implemented: byte, boolean, uint32, uint64, string, name-list, and (round 4) `mpint` — borrowed two's-complement read, minimal-encoding check, positive write; the RFC's five examples are test fixtures; negative values readable, not writable | Escaping policy stays in the facade (checkpoint §3.3). `mpint` is currently used only for `K` in the exchange hash. |
| [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252.html) Userauth | `tatami-auth` (documentation-only) | **deferred** — the handshake requests and receives `ssh-userauth` (§10 of RFC 4253) and then disconnects; **no `USERAUTH_REQUEST` is ever sent**, not even `none` (W-33) | `session_id` now exists on TCP (`transcript::SessionId`); `publickey` in `tatami-auth` is the next consumer (contract §2.2 item 6). QUIC still needs the exporter binding (P-04). |
| [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html) Transport §4.2 identification, §6 unprotected framing, §7.1 `KEXINIT`, §11 `IGNORE`/`DEBUG`/`UNIMPLEMENTED` | `tatami-wire::ident`, `tatami-tcp::{ident,packet,probe,observer,initial}`, `tatami-wire::{kexinit,transport}` | implemented (probe, observer and handshake all use them) | Server-side KEX path for `tatami-server` is not implemented. |
| RFC 4253 §§7–8 algorithm negotiation, key exchange, exchange hash, `NEWKEYS`, §7.2 key derivation, §6.2–6.4 protected packets | `tatami-tcp::{negotiate,transcript,gcm,handshake}` (`kex`), `tatami-wire::kex` | **implemented (profile-limited)**, round 4: client role only; §7.1 selection (first client choice the server lists; markers excluded), `first_kex_packet_follows` guess evaluation and one discarded packet; `H` computed with `I_C`/`I_S` verbatim (EID 4533), `session_id = H`, §7.2 derivation (all six letters tested against a Python oracle; the AEAD consumes A–D, E/F are not derived); `NEWKEYS` both directions; protected packets with `aes128-gcm@openssh.com` only; padding ≥ 4 to the 16-byte block. **Not** implemented: server role, re-exchange (§9: a server `KEXINIT` after `NEWKEYS` ends the run as `RekeyNotSupported`), compression other than `none`, any non-AEAD cipher/MAC, `diffie-hellman-group*` methods. Verified against OpenSSH_10.2p1 (`tatami-tcp/tests/openssh_handshake.rs`). | Rekeying is the first item of the next TCP slice; until then sessions cannot exceed the initial keys. |
| RFC 4253 §10 service request, §11.1 `DISCONNECT` | `tatami-wire::transport::{ServiceRequest,ServiceAccept,Disconnect}`, `tatami-tcp::handshake` | **implemented (profile-limited)**: protected `SERVICE_REQUEST("ssh-userauth")`, `SERVICE_ACCEPT` name checked against the request (`ServiceMismatch`), protected `DISCONNECT` (reason 11 `BY_APPLICATION`, description `tatami diagnostic complete`) sent on completion and on rekey refusal; server `DISCONNECT` decoded and reported in every phase | `ssh-connection` is never requested. |
| RFC 4253 §6.6 public-key/signature blob encodings | `tatami-keys::blob` | implemented (algorithm-agnostic; `ssh-ed25519` bodies in `tatami-keys::ed25519`) | RSA/ECDSA bodies deferred (below). |
| [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254.html) Connection: §5.1 opening | `tatami-wire::channel`, `tatami-connection::opening` | implemented for `CHANNEL_OPEN` / `OPEN_CONFIRMATION` / `OPEN_FAILURE` codecs and the opening lifecycle; no data, window accounting, EOF or close | Continue the matrix (checkpoint §5 item 2): `WINDOW_ADJUST`, `DATA`, `EXTENDED_DATA`, `EOF`/`CLOSE`, requests; erratum 3878 governs window debit (§4). |
| [RFC 4256](https://www.rfc-editor.org/rfc/rfc4256.html) keyboard-interactive (optional) | `tatami-auth` | deferred | Optional method; only after `publickey` and userauth framing exist. |
| [RFC 8308](https://www.rfc-editor.org/rfc/rfc8308.html) Extension negotiation | `tatami-wire::{kexinit,ext_info}`, `tatami-tcp::{negotiate,handshake}` | **implemented (profile-limited)**, round 4: `ext-info-c` offered (configurable); `EXT_INFO` decoded when it is the first protected packet after the server's `NEWKEYS` (§2.4 first opportunity), accepted whether or not the marker was offered (as OpenSSH does); `server-sig-algs` parsed and recorded; other extensions counted by name; **nothing is enabled**. Receive-only: no `EXT_INFO` is sent. The second server opportunity (before `USERAUTH_SUCCESS`) is unreachable because userauth is not implemented. | See §2. `server-sig-algs` becomes an input to `tatami-auth` client policy. |
| [RFC 6668](https://www.rfc-editor.org/rfc/rfc6668.html) SHA-2 MACs | `tatami-tcp::negotiate` | **deferred / policy gap (W-30)**: the profile's MAC lists carry `hmac-sha2-256` only to satisfy RFC 4253 §7.1's non-empty name-list syntax; no HMAC is implemented; negotiation fails closed (`NoMacImplemented`) if a non-AEAD cipher were ever selected, which the single-cipher proposal prevents | A peer reading the MAC list literally would over-estimate support. Implement `hmac-sha2-256` (with `-etm@openssh.com` considered) before a second, non-AEAD cipher is offered. |
| [RFC 8268](https://www.rfc-editor.org/rfc/rfc8268.html) MODP groups with SHA-2; corrects RFC 4253 §8 DH public-value bounds to `1 < e,f < p-1` | `tatami-tcp` KEX; `tatami-keys` | deferred | The bounds check is mandatory for any FFC DH method if one is ever selected. |
| [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332.html) RSA with SHA-2 | `tatami-keys`, `tatami-auth` | deferred; `tatami-keys::blob` already models key-format name and signature-algorithm name as separate fields, and `HostKey::verify_signature_blob` reports an `AlgorithmMismatch` before touching signature bytes | RSA verification, `ssh-rsa` blob bodies and the `rsa-sha2-*` names remain unimplemented; `UnsupportedAlgorithm` preserves the peer's name. |
| [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709.html) Ed25519 / Ed448 host and user keys | `tatami-keys::{blob,ed25519}` (`ed25519`) | **implemented (profile-limited)**, round 4: `ssh-ed25519` public-key blob (§4) and signature blob (§6) decode with exact lengths; verification via `ed25519-dalek` `verify_strict`; RFC 8032 §7.1 TEST 1–3 vectors; invalid points rejected at construction. **Not** implemented: Ed448 (`ssh-ed448`), signing, user keys in userauth. | Host-key verification only; user-key use arrives with `tatami-auth`. |
| [RFC 8758](https://www.rfc-editor.org/rfc/rfc8758.html) Deprecating RC4 (`arcfour*`) | `tatami-tcp::negotiate` | satisfied trivially: the cipher list contains only `aes128-gcm@openssh.com` | Record as MUST NOT when the list grows. |
| [RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html) KEX method updates | `tatami-tcp::negotiate` | **partially met; MUST not implemented**: `curve25519-sha256` (SHOULD) implemented; `ext-info-c` (SHOULD) offered; **`diffie-hellman-group14-sha256` (MUST, §4) is NOT implemented**; `ecdh-sha2-nistp*` (SHOULD) not implemented; `diffie-hellman-group1-sha1` / `rsa1024-sha1` not offered | The profile does not claim RFC 9142 conformance (W-29). Adding group14-sha256 needs an FFC provider and the RFC 8268 bounds check. |
| [RFC 5656](https://www.rfc-editor.org/rfc/rfc5656.html) §4 ECDH message structure (`KEX_ECDH_INIT` 30 / `KEX_ECDH_REPLY` 31, `K_S`, `Q_C`/`Q_S`, signature); §6 ECDSA | `tatami-wire::kex`, `tatami-tcp::transcript` | **§4 implemented (profile-limited)** as the message and exchange-hash structure used by RFC 8731 (round 4); **§6 ECDSA and `ecdh-sha2-nistp*` deferred** | ECDSA keys also matter for the RFC 7250 raw-key conversion question (checkpoint §4). |
| [RFC 8731](https://www.rfc-editor.org/rfc/rfc8731.html) `curve25519-sha256`, `curve448-sha512` | `tatami-tcp::transcript` (`kex`) via `x25519-dalek` | **`curve25519-sha256` implemented (profile-limited)**, round 4: 32-byte `Q_C`/`Q_S` (`ServerEphemeralLength` otherwise), all-zero shared secret aborts (§3, RFC 7748 §6.1), `K` encoded as `mpint`, SHA-256 hash; RFC 7748 §6.1 Alice/Bob vectors as fixtures. `curve448-sha512` not implemented. | Second method only after the RFC 9142 MUST is addressed. |
| [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) X25519 | `x25519-dalek` behind `tatami-tcp::transcript` | implemented by provider; §6.1 test vectors used | Provider rules in `crypto-provider-audit.md`. |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) Ed25519 | `ed25519-dalek` behind `tatami-keys::ed25519` | implemented by provider (verification only); §7.1 vectors used | Same. |
| [RFC 5647](https://www.rfc-editor.org/rfc/rfc5647.html) AES-GCM for SSH (construction §§6–7) with negotiation per [draft-miller-sshm-aes-gcm-01 §2](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm-01) (expired 2026-05-14; no `draft-ietf-sshm-aes-gcm` successor existed at the audit date) and [OpenSSH `PROTOCOL` §1.6](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL) | `tatami-tcp::{gcm,negotiate}` | **implemented (profile-limited)**, round 4: `aes128-gcm@openssh.com` only; `packet_length` as AAD in clear; 12-byte nonce = 4-byte fixed + 64-bit invocation counter incremented per packet, never reset or reused under one key; 16-byte tag; AEAD name in the cipher lists only, MAC lists ignored when an AEAD is selected. RFC 5647's own names `AEAD_AES_128_GCM` / `AEAD_AES_256_GCM` and `aes256-gcm@openssh.com` are **not** offered. | Cite the draft as expired work-in-progress, not a standard. |
| SFTP v3 = [draft-ietf-secsh-filexfer-02](https://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt) — an expired Internet-Draft, **not** an RFC | none (would be an application on a `session` channel) | deferred | No SFTP code exists. OpenSSH implements revision 3 of this draft with its own extensions ([OpenSSH `PROTOCOL` §4](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL)). |
| Strict KEX: [draft-ietf-sshm-strict-kex-02](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-strict-kex-02) (`kex-strict-c` / `kex-strict-s`) and the deployed pre-standard names `kex-strict-c-v00@openssh.com` / `kex-strict-s-v00@openssh.com` ([OpenSSH `PROTOCOL` §1.9](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL)) | `tatami-wire::kexinit::{classify_kex_name,classify_strict_kex_name}`, `tatami-tcp::{negotiate,handshake}` | **implemented (profile-limited)**, round 4: both client spellings offered (§3.1 recommendation; `--no-strict-kex` disables); enabled only when the server offers the *same* spelling's server marker, never mixed; `KEXINIT` must be the first packet (a non-`KEXINIT` first packet is provisionally accepted and becomes fatal once strictness is known); only `KEXINIT`, `NEWKEYS` and 30–49 accepted before the initial exchange completes, each once; sequence numbers reset to zero per direction after `NEWKEYS` sent/received; wrap before completion fatal. Negotiated with OpenSSH 10.2 under the pre-standard name. | Server role and rekey interaction (§3.3 applies to every `NEWKEYS`) untested until those exist. |
| `ext-info-c` / `ext-info-s` markers | `tatami-wire::kexinit`, `tatami-tcp::negotiate` | implemented: never selectable as a method (RFC 8308 §2.2); excluded before comparison on both sides | A client that sends `ext-info-c` MUST accept `EXT_INFO` at both server opportunities; the second is unreachable today. |

Note on section numbering: the task brief cited strict KEX as OpenSSH
`PROTOCOL` §1.10. In the `PROTOCOL` revision fetched for this inventory
(`$OpenBSD: PROTOCOL,v 1.60 2026/02/09`), strict KEX is §1.9 and §1.10 is
"`SSH2_MSG_EXT_INFO` during user authentication" (`ext-info-in-auth@openssh.com`).
The code comments in `kexinit.rs` say §1.10; a later doc pass should
reconcile them to the file's current numbering.

## 1a. TLS/QUIC specifications touched by the diagnostic experiment (round 4)

All rows below concern `tatami-quic::diag` (feature `quinn-backend`, W-31),
which completes QUIC/TLS handshakes and **sends no SSH byte**. None of them
settles an SSH-over-QUIC wire question.

| Specification | Layer / package affected | Status | Next consequence |
|---|---|---|---|
| [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) QUIC transport, [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) TLS for QUIC | `quinn-proto` 0.11.18 behind `tatami-quic::diag` | **diagnostic handshake only**: v1 only; Initial/Retry/address validation (§8.1) and anti-amplification inside the library; streams and DATAGRAM refused by transport parameters; ALPN mandatory (§8.1 of RFC 9001) and validated non-empty before any I/O; 0-RTT disabled | Record framing, streams, migration handling and the SSH bootstrap are unimplemented (AQ-015, AQ-018, AQ-020–AQ-023). |
| [RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5) / [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705.html) exporter | `quinn-proto` `crypto::Session::export_keying_material` | **availability shown** (`tatami-quic/tests/exporter.rs`): fails before completion, equal at both ends, differs by label, context, length and connection; the label used is explicitly experimental and output is discarded. **The SSH session-binding construction is NOT defined** (P-04, AQ-003). | Define label, context, length, transcript inputs and their relation to identification strings before any userauth over QUIC. RFC 9266's registered `tls-exporter` binding is a different fixed construction (checkpoint §4.1). |
| [RFC 7250](https://www.rfc-editor.org/rfc/rfc7250.html) raw public keys in TLS | `rustls` 0.23 `AlwaysResolvesServerRawPublicKeys`, `PinnedRawPublicKeyVerifier` in `tatami-quic::diag::tls` | **experiment succeeded** (`tatami-quic/tests/rpk.rs`): RPK handshake completes over QUIC; `peer_identity()` holds exactly the SPKI DER; wrong SPKI pin fails; X.509-only client vs RPK server and RPK client vs X.509 server both fail (no silent downgrade); `server_certificate_type` offer recorded. Not exposed on the CLI (certificate pinning only). | P-06 mapping of SSH host identity onto SPKI remains open: SPKI, SSH blob and certificate fingerprints of one key all differ (below). |
| [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html) Ed25519 in SPKI | `tatami-quic::diag::identity` (`ED25519_SPKI_PREFIX`, `raw_ed25519_to_spki`, `spki_ed25519_to_raw`) | implemented for Ed25519 only: 44-byte DER = 12-byte prefix + 32-byte key; typed conversion both ways; other algorithms rejected | Any SSH↔SPKI identity mapping must validate algorithm and parameters, not hash arbitrary TLS bytes (checkpoint §4). |
| [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html) ALPN | `tatami-quic::diag::validate_alpn`; rustls | implemented for the experiment: configurable list, 1–255 bytes per entry, no default; `tatami-diag/0` used in tests; offered list recorded via `ResolvesServerCert`, negotiated via `HandshakeData` | Experimental and **unregistered**; AQ-019 / P-08 open. |

## 2. RFC 8308 extensions, individually

Each extension has a distinct effect. Only `EXT_INFO` receipt and
`server-sig-algs` recording exist; no extension is *enabled*. The workspace
must not treat "RFC 8308 support" as a single switch.

| Extension | Defined effect (RFC 8308) | Status | Consequence for Tatami |
|---|---|---|---|
| `SSH_MSG_EXT_INFO` (7) and ordering rules (§2.3–2.5) | Client: only as the next packet after its first `NEWKEYS`. Server: next packet after its first `NEWKEYS` and/or immediately before `USERAUTH_SUCCESS`; a second message replaces the first. Unknown names MUST be ignored; values may contain any bytes. | **receive-only, first opportunity** (round 4): `tatami-wire::ext_info` lazy codec (bounded entry count); `tatami-tcp::handshake` accepts it only as the first protected packet and reports `ExtInfoSummary { received, server_sig_algs, extension_names }`; unknown names ignored by count; no `EXT_INFO` sent | Second opportunity and client-side sending arrive with userauth. Under QUIC (P-03) the "next packet" rule has no equivalent and must be mapped explicitly (AQ-002). |
| `server-sig-algs` (§3.1) | Server lists public-key algorithms accepted for `publickey` userauth. Client MAY still try others. | **recorded** (OpenSSH 10.2 lists `ssh-ed25519` among others in the interop test); not acted on | Consumed by `tatami-auth` client policy; motivates the RSA name distinction above. |
| `delay-compression` (§3.2) | Both sides send two name-lists; takes effect after `USERAUTH_SUCCESS` (server) / `SSH_MSG_NEWCOMPRESS` (8) (client). Constrains when re-exchange may start (§3.2.1). | deferred | Compression is not planned; if ever added, the re-exchange constraint touches the transport state machine. |
| `no-flow-control` (§3.3) | Both send it, at least one with `p`; then `initial_window_size` fields are meaningless and `WINDOW_ADJUST` is ignored. **Implementations MUST refuse to open more than one simultaneous channel** while in effect. | deferred — must NOT be enabled on the observer, and must NOT be adopted unchanged as the QUIC flow-control design | The observer sends no `EXT_INFO`, so it cannot enable this. P-01 (one channel per QUIC stream, many streams) is multichannel by construction, so this extension cannot stand in for the SSH-credit-vs-QUIC-credit decision (AQ-016, contract §2.2 item 5). |
| `elevation` (§3.4) | Client requests Windows session elevation `y`/`n`/`d`; server may reply with an `elevation` global request. | deferred | Out of scope for current host adapters; keep the name in any future extension registry so it is ignored, not rejected. |

## 3. How the documents relate

| Relationship | Documents | Note |
|---|---|---|
| **Updates** RFC 4253 | RFC 6668, 8268, 8308, 8332, 8709, 8758, 9142 | List taken from the RFC 4253 errata page header ("Updated by"). |
| **Updates** RFC 4252 | RFC 8308, 8332 | From the RFC 4252 errata page header. |
| **Updates** RFC 4254 | RFC 8308 | From the RFC 4254 errata page header. |
| **Updates** RFC 4251 | RFC 8308 | From RFC 8308's own header; the RFC 4251 errata page shows no errata. |
| **Updates** RFC 4250 | RFC 8268, 9142 | From those RFCs' headers; 9142 also updates 4432 and 4462. |
| **Standalone** (no "Updates" header) | RFC 4256, 5656, 8731 | Register new names; do not change base-RFC text. |
| **Standalone** (TLS/QUIC side) | RFC 5705, 7250, 7301, 7748, 8032, 8410, 8446, 9000, 9001 | Touched only by the QUIC diagnostic experiment and the SSH crypto providers; see §1a. |
| **Non-RFC references** | OpenSSH `PROTOCOL` (AES-GCM §1.6, strict KEX §1.9, ext-info-in-auth §1.10), draft-ietf-sshm-strict-kex-02 (active I-D, not an RFC), draft-miller-sshm-aes-gcm-01 (expired I-D, no WG successor at the audit date), draft-ietf-secsh-filexfer-02 (expired I-D) | Cite as work in progress / vendor documentation, never as standards. |
| **Errata** | See §4 | Corrections to published text; verified errata are the only ones treated as authoritative here. |

## 4. Errata

Fetched from rfc-editor.org on 2026-09-20 for RFC 4250, 4251, 4252, 4253,
4254, 8308 and 8332. Not fetched in this pass: RFC 4256, 5656, 6668, 8268,
8709, 8731, 8758, 9142 — their errata status is **not verified** here.

### Verified (status "Verified" on rfc-editor.org)

| Erratum | RFC / section | Effect | Relevance |
|---|---|---|---|
| [EID 4533](https://www.rfc-editor.org/errata/eid4533) (Technical) | 4253 §7.1 `KEXINIT` reserved field | Unaware implementations MUST send 0, MUST NOT act on the received value, and MUST hash the actual received value. | Matches `KexInit::decode`: the field is exposed, not rejected. Any future KEX hash must use the received bytes verbatim. |
| [EID 1486](https://www.rfc-editor.org/errata/eid1486) (Editorial) | 4253 §12 | Adds `SSH_MSG_KEXDH_INIT` = 30, `SSH_MSG_KEXDH_REPLY` = 31 to the summary table. | Confirms the 30–49 range the probe treats as method-specific. |
| [EID 4721](https://www.rfc-editor.org/errata/eid4721) (Editorial) | 4253 §5.3 | Corrects overhead arithmetic (33→60 bytes; ≤14 bytes on Ethernet). | Informational only. |
| [EID 5563](https://www.rfc-editor.org/errata/eid5563) (Technical) | 4252 §8 | `SSH_MSG_USERAUTH_CHANGEREQ` → `SSH_MSG_USERAUTH_PASSWD_CHANGEREQ`. | Name to use if password auth is ever implemented. |
| [EID 6850](https://www.rfc-editor.org/errata/eid6850) (Technical) | 4254 §5.1 | Reason codes belong to `CHANNEL_OPEN_FAILURE`, not `CHANNEL_OPEN`. | Already reflected in `tatami-connection` (checkpoint §3.4). |
| [EID 8764](https://www.rfc-editor.org/errata/eid8764) (Technical, verified 2026-05-07) | 4254 §4 | If `want reply` is false the recipient MUST NOT send any response, even for unrecognised requests. | Binding rule for the future global-request engine; reply ordering depends on it. |
| [EID 3878](https://www.rfc-editor.org/errata/eid3878) (Editorial) | 4254 §5.2 | Window is decremented by the data length **including the string length field**; notes ambiguity about `EXTENDED_DATA`. | Governs the pending window-accounting audit (checkpoint §3.4, AQ-016). |

No errata are recorded for RFC 4250, 4251, 8308 or 8332.

### Not verified / held / rejected (kept separate)

| Item | Status on rfc-editor.org | Note |
|---|---|---|
| [EID 3877](https://www.rfc-editor.org/errata/eid3877) 4254 §6.10 | Held for Document Update | Clarifies that the server closes after `exit-status`. Not normative. |
| [EID 3268](https://www.rfc-editor.org/errata/eid3268) 4252 §5.1 | Held for Document Update | Wording of "aborted by a subsequent request". |
| EID 152, EID 1408 (4253 §12) | Rejected | Superseded by EID 1486. |

### Observed implementation differences (not errata)

| Observation | Source | Consequence |
|---|---|---|
| OpenSSH ≤ 7.5 disconnects on `EXT_INFO` values containing NUL bytes. | RFC 8308 §3.2.3 | Only matters if `delay-compression` is ever sent. |
| OpenSSH `sftp-server` reverses `SSH_FXP_SYMLINK` arguments relative to the draft. | OpenSSH `PROTOCOL` §4.1 | SFTP is deferred; record for later. |
| OpenSSH sends `EXT_INFO` during userauth (`ext-info-in-auth@openssh.com`), earlier than RFC 8308 §2.4 permits. | OpenSSH `PROTOCOL` §1.10 | A future client must tolerate it if it advertises that key. |
| Strict KEX is deployed under the pre-standard `-v00@openssh.com` names; the I-D forbids mixing standard and pre-standard names across the two sides. | draft-ietf-sshm-strict-kex-02 §3.1; observed: OpenSSH 10.2 offers only `kex-strict-s-v00@openssh.com` | Implemented as pairs (round 4); Tatami offers both client spellings and the server's pre-standard marker is what gets matched today. |
| OpenSSH sends `EXT_INFO` immediately after its `NEWKEYS`, before `SERVICE_ACCEPT`. | Observed in `tatami-tcp/tests/openssh_handshake.rs` (`protected_packets_received >= 2`) | The handshake accepts `EXT_INFO` as the first protected packet even when `--no-ext-info` withheld the marker, matching OpenSSH's own tolerance. |
| OpenSSH compares raw first `kex_algorithms` tokens for the `first_kex_packet_follows` guess; Tatami skips markers to find the first *method*. | `negotiate.rs` module notes | Agrees whenever markers follow the real methods, which is how OpenSSH lists them. |

## 5. Crypto profile status

The first interoperability profile (`curve25519-sha256`, `ssh-ed25519`,
`aes128-gcm@openssh.com`, `none`, strict KEX, `ext-info-c`) is selected and
implemented; providers, versions, MSRV and `no_std` evidence are in
`crypto-provider-audit.md`. What it does **not** cover, in one place: the
RFC 9142 MUST (`diffie-hellman-group14-sha256`), `ecdh-sha2-nistp*`, RSA
(RFC 8332) and ECDSA (RFC 5656 §6) host keys, OpenSSH certificates, any
HMAC (RFC 6668; W-30 gap), any second cipher, compression, rekeying, the
server role, and user authentication. Recognising a name in a `KEXINIT` is
still not support for it: the probe and observer display advertisements;
only `negotiate` selects, and only from the profile.
