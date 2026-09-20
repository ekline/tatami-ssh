# Specification inventory

Status: inventory as of 2026-09-20. This file records which specifications
touch which package, what the workspace actually does with each today, and
the next consequence. It selects no algorithm, provider or QUIC wire choice;
those remain open in `tatami-ssh-design-state-checkpoint.md` (C-07, P-04,
P-06, AQ-002, AQ-006–AQ-008).

Status meanings: **implemented** — code exists and is tested;
**recognized** — the workspace parses or annotates the artefact without
acting on it; **deferred** — nothing in the workspace depends on it yet.

## 1. Core SSH and extension specifications

| Specification | Layer / package affected | Status | Next consequence |
|---|---|---|---|
| [RFC 4250](https://www.rfc-editor.org/rfc/rfc4250.html) Assigned Numbers | `tatami-wire` (`msg` constants) | recognized: only the message numbers the codecs use (1–4, 20, 90–92) plus the 30–49 method-specific range noted by the probe | Add numbers as codecs land; keep unknown numbers reportable rather than fatal. |
| [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html) Architecture (§5 data types, §9.2 diagnostics) | `tatami-wire::{primitives,namelist}`; `tatami::text` | implemented: byte, boolean, uint32, uint64, string, name-list; `mpint` absent; peer text escaped before display | `mpint` arrives with the first KEX method. Escaping policy stays in the facade (checkpoint §3.3). |
| [RFC 4252](https://www.rfc-editor.org/rfc/rfc4252.html) Userauth | `tatami-auth` (documentation-only) | deferred | Needs a session identifier from a real KEX (TCP) or a defined exporter binding (QUIC, P-04); contract §2.2 item 6. |
| [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html) Transport: §4.2 identification, §6 unprotected packet framing, §7.1 `KEXINIT`, §11 `DISCONNECT`/`IGNORE`/`DEBUG`/`UNIMPLEMENTED` | `tatami-wire::ident` (§4.2 content syntax, shared), `tatami-tcp::{ident,packet,probe,observer}`, `tatami-wire::{kexinit,transport}` | implemented for the pre-KEX phase only: client initial-offer probe (W-11) and, this round, a server-side observer that sends `SSH-2.0-tatami_observer_0.1.0`, records the client identification and client `KEXINIT`, and sends no server `KEXINIT` | KEX (§7–8), `NEWKEYS`, protected packets (§6.2–6.4), service negotiation (§10) and rekeying are the next milestone and need the provider audit in §4 below. |
| [RFC 4254](https://www.rfc-editor.org/rfc/rfc4254.html) Connection: §5.1 opening | `tatami-wire::channel`, `tatami-connection::opening` | implemented for `CHANNEL_OPEN` / `OPEN_CONFIRMATION` / `OPEN_FAILURE` codecs and the opening lifecycle; no data, window accounting, EOF or close | Continue the matrix (checkpoint §5 item 2): `WINDOW_ADJUST`, `DATA`, `EXTENDED_DATA`, `EOF`/`CLOSE`, requests; erratum 3878 governs window debit (§4). |
| [RFC 4256](https://www.rfc-editor.org/rfc/rfc4256.html) keyboard-interactive (optional) | `tatami-auth` | deferred | Optional method; only after `publickey` and userauth framing exist. |
| [RFC 8308](https://www.rfc-editor.org/rfc/rfc8308.html) Extension negotiation | `tatami-wire::kexinit::classify_kex_name` | recognized: `ext-info-c` / `ext-info-s` annotated as non-methods (W-13); no `EXT_INFO` codec | See §2. The observer sends no `KEXINIT`, so it neither offers nor receives `EXT_INFO`. |
| [RFC 6668](https://www.rfc-editor.org/rfc/rfc6668.html) SHA-2 MACs | `tatami-tcp` (future MAC negotiation) | deferred | Provider audit input (§4). |
| [RFC 8268](https://www.rfc-editor.org/rfc/rfc8268.html) MODP groups with SHA-2; corrects RFC 4253 §8 DH public-value bounds to `1 < e,f < p-1` | `tatami-tcp` KEX; `tatami-keys` | deferred | Provider audit input; the bounds check is mandatory for any FFC DH method if one is ever selected. |
| [RFC 8332](https://www.rfc-editor.org/rfc/rfc8332.html) RSA with SHA-2 | `tatami-keys`, `tatami-auth` | deferred | Keep the key-blob format identifier `ssh-rsa` distinguishable from the signature/public-key algorithm names `rsa-sha2-256` / `rsa-sha2-512`: the same key blob is used under different algorithm names. `tatami-keys` must model key format and signature algorithm as separate fields. |
| [RFC 8709](https://www.rfc-editor.org/rfc/rfc8709.html) Ed25519 / Ed448 host and user keys | `tatami-keys` | deferred | Provider audit input; likely first host-key candidate, but not selected here. |
| [RFC 8758](https://www.rfc-editor.org/rfc/rfc8758.html) Deprecating RC4 (`arcfour*`) | `tatami-tcp` cipher negotiation | deferred | Nothing to remove; record as MUST NOT when a cipher list is first written. |
| [RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html) KEX method updates | `tatami-tcp` KEX negotiation | deferred | Provider audit input: `diffie-hellman-group14-sha256` MUST, `curve25519-sha256` / `ecdh-sha2-nistp*` SHOULD, `ext-info-c/s` SHOULD, `diffie-hellman-group1-sha1` SHOULD NOT, `rsa1024-sha1` MUST NOT (RFC 9142 §4). |
| [RFC 5656](https://www.rfc-editor.org/rfc/rfc5656.html) ECDH / ECDSA | `tatami-tcp` KEX; `tatami-keys` | deferred | Provider audit input; ECDSA keys also matter for the RFC 7250 raw-key conversion question (checkpoint §4). |
| [RFC 8731](https://www.rfc-editor.org/rfc/rfc8731.html) `curve25519-sha256`, `curve448-sha512` | `tatami-tcp` KEX | deferred | Provider audit input; the probe already reports the name when a server advertises it. |
| SFTP v3 = [draft-ietf-secsh-filexfer-02](https://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt) — an expired Internet-Draft, **not** an RFC | none (would be an application on a `session` channel) | deferred | No SFTP code exists. OpenSSH implements revision 3 of this draft with its own extensions ([OpenSSH `PROTOCOL` §4](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL)). |
| OpenSSH strict KEX: `kex-strict-c-v00@openssh.com` / `kex-strict-s-v00@openssh.com` — [OpenSSH `PROTOCOL` §1.9](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL), now [draft-ietf-sshm-strict-kex](https://datatracker.ietf.org/doc/draft-ietf-sshm-strict-kex/) | `tatami-wire::kexinit::classify_kex_name` | recognized: annotated as non-methods | Real KEX must implement §3.2 (only KEX messages during initial KEX, `KEXINIT` first) and §3.3 (sequence-number reset after each `NEWKEYS`) when both sides signal. The draft also defines standard names `kex-strict-c` / `kex-strict-s`, which the classifier does not yet recognise. |
| `ext-info-c` / `ext-info-s` markers | `tatami-wire::kexinit` | recognized | Must never be selected as a method (RFC 8308 §2.2); a client that sends `ext-info-c` MUST accept `EXT_INFO` at both server opportunities. |

Note on section numbering: the task brief cited strict KEX as OpenSSH
`PROTOCOL` §1.10. In the `PROTOCOL` revision fetched for this inventory
(`$OpenBSD: PROTOCOL,v 1.60 2026/02/09`), strict KEX is §1.9 and §1.10 is
"`SSH2_MSG_EXT_INFO` during user authentication" (`ext-info-in-auth@openssh.com`).
The code comments in `kexinit.rs` say §1.10; a later doc pass should
reconcile them to the file's current numbering.

## 2. RFC 8308 extensions, individually

Each extension has a distinct effect; none is implemented. The workspace
must not treat "RFC 8308 support" as a single switch.

| Extension | Defined effect (RFC 8308) | Status | Consequence for Tatami |
|---|---|---|---|
| `SSH_MSG_EXT_INFO` (7) and ordering rules (§2.3–2.5) | Client: only as the next packet after its first `NEWKEYS`. Server: next packet after its first `NEWKEYS` and/or immediately before `USERAUTH_SUCCESS`; a second message replaces the first. Unknown names MUST be ignored; values may contain any bytes. | deferred | Codec belongs in `tatami-wire`; placement rules belong in the TCP transport driver. Under QUIC (P-03) the "next packet" rule has no equivalent and must be mapped explicitly (AQ-002). |
| `server-sig-algs` (§3.1) | Server lists public-key algorithms accepted for `publickey` userauth. Client MAY still try others. | deferred | Consumed by `tatami-auth` client policy; motivates the RSA name distinction above. |
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
| **Non-RFC references** | OpenSSH `PROTOCOL` (strict KEX §1.9, ext-info-in-auth §1.10), draft-ietf-sshm-strict-kex-02 (active I-D, not an RFC), draft-ietf-secsh-filexfer-02 (expired I-D) | Cite as work in progress / vendor documentation, never as standards. |
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
| Strict KEX is deployed under the pre-standard `-v00@openssh.com` names; the I-D forbids mixing standard and pre-standard names across the two sides. | draft-ietf-sshm-strict-kex-02 §3.1 | Future KEX must offer/match names as pairs. |

## 5. Crypto-related RFCs inform a later audit

RFC 5656, 6668, 8268, 8332, 8709, 8731, 8758 and 9142 are listed so that the
algorithm/provider audit required before the next milestone
(`architecture.md` "Next implementation slice", README "Next milestone") has
its reading list. **Nothing in this round selects an algorithm, a
cryptographic provider, an entropy source or a key format.** The probe and
the observer only display what a peer advertises; recognising a name in a
`KEXINIT` is not support for it.
