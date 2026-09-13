# Tatami SSH / QUIC Design Continuity Notes

**Purpose:** This file is a state-of-work snapshot for resuming the Tatami SSH project design discussion if conversation state is lost. Re-upload this file and ask to resume from it.

**Date:** 2026-09-10

---

## Project

**Tatami-rs** is a Rust SSH implementation exploring QUIC as an alternate transport for SSH.

The original working document was `tatami-ssh.md`, a poorly formatted architecture/implementation outline. The goal is to iteratively turn it into a coherent implementation specification, then use implementation experience to inform an Internet-Draft describing how QUIC can replace TCP as the transport for SSH.

### Core compatibility goal

The intended architecture is **genuine SSH compatibility over TCP**:

- TCP mode should remain ordinary SSH.
- An unmodified conventional TCP SSH client/server should ultimately interoperate with Tatami.
- QUIC is an alternate transport binding for SSH, not a new SSH-like protocol.
- The eventual standards work should preserve SSH semantics wherever practical and introduce only the minimum QUIC-specific binding necessary.

### Design philosophy

> **Prefer existing standardized cryptographic mechanisms and SSH extension mechanisms over introducing a parallel cryptographic protocol.**

In particular, the design should be standards-aligned, minimize new crypto/protocol invention, and preserve familiar SSH trust/authentication UX.

---

## Existing crate/workspace concept

Initial target crates:

- `tatami-core` — shared types, framing, OpenSSH key parsers
- `tatami-transport` — transport abstraction, Quinn QUIC, TCP framing
- `tatami-client`
- `tatami-server`
- `tatami-cli`

Initial architectural ideas included:

- QUIC + TLS 1.3
- raw public keys (RFC 7250), avoiding X.509
- `known_hosts` for server trust / TOFU
- `authorized_keys` for SSH user authentication
- unified async `TatamiTransport` trait
- experimental mapping of SSH channels to QUIC bidirectional streams
- custom framed TCP multiplexing fallback was initially considered
- QUIC-first discovery/probe was initially proposed (250 ms), but remains experimental and should not be treated as settled protocol design

---

## Intended trust/authentication model

The desired user-visible model is:

```text
QUIC connection establishment
    │
    ├── TLS 1.3
    │     └── server raw public key
    │             └── known_hosts
    │
    ▼
secure QUIC connection
    │
    ▼
SSH protocol binding
    │
    ├── SSH user authentication
    │       └── authorized_keys
    │
    └── SSH connection protocol
```

Important distinction:

- `known_hosts` represents **server identity/trust**.
- `authorized_keys` represents **later SSH user authentication**.

The motivation for raw public keys was partly to preserve the familiar SSH public-key/hash trust paradigm rather than introducing a certificate/PKI UX.

---

## Major architectural hypothesis

One of the central experimental questions is whether SSH channels can map naturally to QUIC streams:

```text
SSH channel  <──>  QUIC bidirectional stream
```

This is attractive because QUIC gives independent reliable ordered streams and avoids TCP head-of-line blocking between channels.

However, SSH itself has connection-level transport/KEX semantics and a single SSH packet stream. Therefore, the exact binding between SSH's existing Connection Protocol and QUIC streams must be carefully specified.

This is **not yet a settled design decision**.

Earlier discussion clarified that two seemingly different proposals — direct channel-to-QUIC-stream mapping and an adapter layer — are not necessarily distinct architectures. An adapter can be an implementation-layer separation while the wire-level binding remains channel ↔ QUIC stream.

---

# SSH Transport/KEX analysis

Relevant SSH specifications:

- RFC 4253 — SSH Transport Layer Protocol
- RFC 4252 — SSH Authentication Protocol

RFC 4253 transport key exchange provides:

1. server host authentication
2. shared secret `K`
3. exchange hash `H`
4. the SSH session identifier (the `H` from the first KEX)
5. transition via `SSH_MSG_NEWKEYS`
6. rekeying

For the classic Diffie-Hellman exchange, `H` is computed from:

```text
V_C || V_S || I_C || I_S || K_S || e || f || K
```

where these represent the client/server identification strings, KEXINIT payloads, server host key, DH exchange values, and shared secret.

RFC 4252 user authentication receives the SSH session identifier. Public-key authentication signs data beginning with:

```text
session identifier
|| SSH_MSG_USERAUTH_REQUEST
|| username
|| service
|| "publickey"
|| TRUE
|| public-key algorithm
|| public key
```

Thus `authorized_keys` authentication is logically downstream of the SSH transport KEX and its session identifier.

SSH rekeying creates new encryption contexts but does not replace the original session identifier.

---

# QUIC/TLS implications

QUIC + TLS 1.3 already provides:

- authenticated TLS server identity
- encrypted transport
- key establishment
- transport packet protection
- key updates

Therefore, the design question is whether QUIC/TLS can replace the cryptographic functions of SSH transport KEX while preserving the SSH userauth and connection semantics.

Important caveat:

It is **not** sufficient to say that TLS server authentication simply "replaces SSH host-key authentication," because classic SSH `H` includes the SSH server host key and is also the session identifier.

If SSH KEX is removed/replaced, the QUIC binding needs a new, well-defined connection/session binding for the role previously played by the SSH session identifier.

---

## TLS session resumption is NOT directly suitable as SSH `H`

TLS 1.3 resumption state such as the `resumption_master_secret` is secret keying material. SSH's session identifier is a non-secret value used as a binding input to later authentication signatures.

Therefore, TLS resumption state should not simply be substituted for SSH `H`.

The TLS 1.3 transcript hash is conceptually closer, but it is not semantically equivalent to SSH `H`, because the transcript contents and protocol semantics differ.

---

# TLS exporter proposal

A more promising approach is to use the standardized TLS exporter mechanism to construct a QUIC/SSH connection binding.

RFC 9266 standardizes `tls-exporter` as a TLS 1.3 channel-binding mechanism. The exported value is bound to the TLS connection and is suitable as non-secret channel-binding material.

Candidate architecture:

```text
QUIC/TLS 1.3
    │
    ├── server identity / RPK
    ├── transport crypto
    └── TLS exporter
            │
      SSH-specific context
            │
      SSH/QUIC session binding
            │
      SSH userauth → authorized_keys
            │
      SSH connection
```

The precise construction is still open.

Important wording/design point:

Do **not** describe this as the TLS exporter "taking the extra parts of SSH H" or directly recreating `H`. Instead, define a **new SSH/QUIC session-binding construction** based on the TLS exporter plus an SSH-specific context.

Potentially, the context should bind the value to the SSH-over-QUIC protocol/version and relevant negotiated parameters. The exact context is an open design question.

This proposal is attractive because it uses an existing standardized cryptographic primitive rather than inventing a new KDF or parallel key exchange.

---

# Bider SSH-over-QUIC draft

A previous standards effort is:

`draft-bider-ssh-quic`

The latest known version discussed here was:

- `draft-bider-ssh-quic-09`
- updated 2020-12-02
- published 2021-06-05
- archived/expired
- no RFC status

Bider's approach is materially different from the Tatami direction.

### Bider architectural idea

In broad terms:

```text
SSH KEX
   │
   ├── K
   └── H
       │
       ▼
derive QUIC secrets
       │
       ▼
QUIC
```

The Bider work uses SSH-derived key exchange material to bootstrap QUIC rather than simply using normal QUIC/TLS semantics.

Later versions also explored moving SSH KEX over UDP/QUIC and adapting SSH Connection Protocol behavior to QUIC streams.

### Tatami candidate approach

```text
QUIC + TLS 1.3
   │
   ├── normal QUIC/TLS security
   ├── TLS server identity
   └── TLS exporter
          │
          ▼
SSH-specific session binding
          │
          ▼
SSH userauth / connection semantics
```

This is a fundamental architectural distinction.

Tatami's design goal is to let QUIC/TLS do what QUIC/TLS is standardized to do, and then define the smallest SSH-specific binding necessary to preserve SSH semantics.

---

# Eventual Internet-Draft comparison appendix

The eventual Internet-Draft should contain an appendix along the lines of:

**Appendix A — Comparison with `draft-bider-ssh-quic`**

The appendix should compare at least:

| Topic | Bider approach | Tatami candidate |
|---|---|---|
| QUIC TLS | Replaced/repurposed using SSH KEX-derived material | Normal QUIC + TLS 1.3 |
| SSH KEX | Central to deriving QUIC secrets | Candidate for replacement by QUIC/TLS |
| Server identity | SSH host-key/KEX based | TLS server authentication using SSH-compatible raw public key trust |
| Session identifier | SSH `H` | New SSH/QUIC binding, potentially TLS exporter based |
| User authentication | SSH userauth | Preserve SSH userauth / `authorized_keys` |
| `known_hosts` | Needs comparison with proposal | Preserve familiar server trust model |
| Connection protocol | QUIC stream adaptations | Investigate channel ↔ QUIC stream binding |
| Crypto invention | SSH-derived QUIC key schedule | Prefer existing TLS exporter / QUIC mechanisms |
| TCP compatibility | Compare transition/compatibility model | TCP remains ordinary SSH |

The appendix should be factual and technically respectful. It should not claim a reason for Bider's lack of progress unless the historical record supports that claim.

The motivation can be framed positively:

> Tatami deliberately revisits SSH-over-QUIC using a standards-aligned architecture that minimizes changes to established SSH semantics and reuses standardized QUIC/TLS mechanisms wherever possible.

The fact that the Bider draft expired/was archived is relevant historical context, but "it failed to get consensus" should not be asserted as an independently verified fact unless later research establishes that.

---

# Current design ledger

## DECIDED / STRONG INTENT

### D-001 — TCP compatibility
TCP mode must remain genuine SSH, with eventual interoperability with unmodified conventional SSH implementations.

### D-002 — QUIC is an alternate transport binding
Tatami should not become a new SSH-like protocol.

### D-003 — Preserve SSH authentication UX
Retain the conceptual distinction between:

- server trust / identity → `known_hosts`
- user authentication → `authorized_keys`

### D-004 — Standards-first cryptography
Prefer existing standardized QUIC/TLS mechanisms and SSH extension mechanisms over new cryptographic protocols.

### D-005 — Eventual Bider comparison
The Internet-Draft should include an appendix comparing the Tatami architecture with `draft-bider-ssh-quic`.

### D-006 — TLS exporter is worth serious investigation
A TLS exporter plus SSH-specific context is currently the leading candidate for the SSH/QUIC session binding, subject to further analysis and implementation/testing.

---

# OPEN ARCHITECTURAL QUESTIONS

### AQ-001 — SSH channels ↔ QUIC streams
Can one SSH channel map cleanly and interoperably to one QUIC bidirectional stream?

Questions include:

- how channel IDs relate to QUIC stream IDs
- how channel open/close semantics map
- how SSH flow control interacts with QUIC flow control
- whether SSH's connection-level packet framing must remain
- how global requests behave
- how channel-local requests behave
- whether a QUIC stream can be associated with an SSH channel before/after SSH channel-open negotiation

### AQ-002 — Which SSH transport semantics remain?
Precisely identify which RFC 4253 mechanisms remain in a QUIC binding and which are supplied by QUIC/TLS.

Especially:

- identification/version exchange
- KEXINIT algorithm negotiation
- KEX
- host authentication
- `NEWKEYS`
- rekeying
- packet framing
- compression
- service negotiation
- disconnect/error semantics

### AQ-003 — QUIC/TLS versus SSH KEX

Subquestions:

- **AQ-003.1:** Is TLS server authentication the complete replacement for SSH server identity authentication?
- **AQ-003.2:** What exactly replaces SSH `K` and the SSH transport encryption?
- **AQ-003.2a:** Can a TLS exporter provide the needed SSH/QUIC session binding?
- **AQ-003.2b:** What SSH-specific exporter label/context is appropriate?
- **AQ-003.2c:** What protocol/version/negotiation data must be bound into the context?
- **AQ-003.2d:** How does the construction interact with SSH userauth signature formats?
- **AQ-003.2e:** What does comparison with Bider teach us?

### AQ-004 — SSH channel IDs versus QUIC stream IDs
Determine whether to:

- use SSH channel IDs independently of QUIC stream IDs,
- derive/map one from the other,
- or define a constrained one-to-one relationship.

### AQ-005 — OpenSSH authentication compatibility
Determine how closely QUIC mode can preserve existing OpenSSH userauth behavior and configuration.

The desired end state is that `authorized_keys` remains meaningful without inventing a separate QUIC-specific user authentication system.

### AQ-006 — `SSH_MSG_NEWKEYS`
If QUIC/TLS already supplies encryption, determine whether:

- `NEWKEYS` is retained as an SSH state transition for compatibility,
- it becomes a no-op/semantic marker,
- it is replaced by a QUIC/TLS handshake-completion condition,
- or a QUIC-specific SSH transport binding defines another mechanism.

### AQ-007 — Rekeying
Determine whether QUIC key updates can serve the security/lifecycle role of SSH rekeying, and what SSH-visible semantics, if any, must remain.

### AQ-008 — SSH algorithm negotiation
Determine which SSH KEX, cipher, MAC, and host-key algorithm negotiation fields remain meaningful when QUIC/TLS supplies transport cryptography.

The goal should be to avoid pretending to negotiate algorithms that are no longer used.

### AQ-009 — Discovery / fallback
The original document proposed QUIC-first probing with a 250 ms probe followed by TCP fallback. This is **not settled**.

Need to distinguish:

- implementation convenience
- command-line/user experience
- deployment discovery
- protocol-standard behavior
- interaction with existing SSH clients

### AQ-010 — Extension/negotiation mechanism
Determine the cleanest way to signal/identify the SSH-over-QUIC binding without creating an incompatible parallel SSH protocol.

---

# Suggested next work sequence

1. **Pin down the wire model.**
   Decide exactly what an SSH-over-QUIC connection looks like from SSH's perspective.

2. **Inventory RFC 4253 semantics.**
   Make a table of every transport-layer mechanism and classify it:
   - retained unchanged
   - supplied by QUIC/TLS
   - replaced by binding
   - unnecessary
   - still unknown

3. **Work through userauth.**
   Start from RFC 4252's exact signature/session-ID requirements and design the exporter-based session binding around them.

4. **Prototype the exporter construction.**
   Determine what exporter label/context and inputs produce a stable, collision-resistant connection binding with the right security properties.

5. **Study channel mapping experimentally.**
   Implement channel ↔ QUIC stream mapping and identify where SSH assumptions break.

6. **Keep TCP implementation conventional.**
   Avoid contaminating the ordinary SSH/TCP path with QUIC-specific semantics unless an SSH extension mechanism genuinely requires it.

7. **Use implementation experience to drive the draft.**
   The Internet-Draft should describe what was actually learned, not merely a theoretical protocol.

8. **Write the Bider comparison last.**
   Once the Tatami architecture is stable, make the comparison precise and evidence-based.

---

# Useful RFC/research references already identified

- **RFC 4253** — SSH Transport Layer Protocol
- **RFC 4252** — SSH Authentication Protocol
- **RFC 7250** — Using Raw Public Keys in Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)
- **RFC 8446** — TLS 1.3
- **RFC 9001** — Using TLS to Secure QUIC
- **RFC 9266** — Exported Authenticators? / TLS exporter channel binding context discussed during research; verify exact title/details before citing in the eventual draft
- **draft-bider-ssh-quic-09** — archived SSH over QUIC Internet-Draft

**Important:** Re-verify exact RFC titles, sections, and current standards status before incorporating references into a formal Internet-Draft.

---


---

# Checkpoint update — 2026-09-10

The following decisions were added after the previous checkpoint.

## QUIC connection migration is a primary objective

Tatami's QUIC transport should explicitly explore **true QUIC connection migration**.

Desired behavior:

```text
SSH session
    │
    │ QUIC connection
    ▼
Wi-Fi A
    │
    │ client changes network / IP address
    ▼
Wi-Fi B
    │
    ▼
same QUIC connection
    │
    ▼
same SSH session
```

The SSH layer should not need to reconnect or reauthenticate merely because the client's network path changes.

Initial migration experiments should consider:

- Wi-Fi → Wi-Fi
- Wi-Fi → cellular
- NAT rebinding
- IPv4 → IPv4
- IPv6 → IPv6
- IPv4 ↔ IPv6 where practical
- temporary loss of the old path
- migration during an interactive shell
- migration while data is flowing
- migration while the connection is mostly idle

The repository/API design must not accidentally reduce QUIC to "an encrypted TCP-like byte stream" in a way that prevents connection migration from being exercised.

## Migration and resumption are distinct

These must remain separate concepts:

### Connection migration

The existing QUIC connection survives a change of network path.

```text
old UDP path ──┐
               ├── same QUIC connection ── same SSH session
new UDP path ──┘
```

No new SSH authentication or session recovery mechanism is needed.

### QUIC/TLS session resumption

A new QUIC connection is established using TLS resumption state:

```text
QUIC connection A
       │
       X
       │
QUIC connection B (resumed)
```

This is a new transport connection and must not automatically be treated as continuation of the old SSH session.

## D-009 — Migration before resumption

The initial QUIC implementation will prioritize:

1. basic SSH-over-QUIC functionality,
2. QUIC connection migration,
3. NAT rebinding,
4. migration failure/timeout behavior,

before attempting SSH-level recovery after connection loss.

## D-010 — QUIC/TLS resumption is initially observational/experimental

Tatami should investigate QUIC/TLS session resumption, but initial work should not imply SSH-session resumption.

A resumed QUIC connection is a new transport connection. TLS resumption state should not automatically become an SSH session identifier or an authorization to recover prior server-side SSH state.

The interaction between TLS resumption and the proposed TLS-exporter-based SSH/QUIC session binding remains an interesting later research question.

## D-011 — SSH session recovery after connection loss is deferred

Tatami should initially **not** define a mechanism whereby a newly established QUIC connection reattaches to an old SSH connection, PTY, or channel state.

Questions such as:

- how long to retain a PTY,
- how to authenticate a reconnecting client,
- how to handle buffered output,
- how to handle outstanding requests,
- how to handle duplicate reconnects,
- how to handle server restart,

are deliberately deferred.

## D-012 — Do not duplicate terminal-session persistence

Existing terminal/session tools such as `tmux` and `screen` already provide long-lived server-side terminal sessions.

Tatami should distinguish:

- **transport mobility** — QUIC connection migration
- **application/session persistence** — tools such as `tmux`/`screen`

The intended division of responsibility is therefore:

```text
Network path changes while QUIC remains alive
    → QUIC migration
    → same SSH connection
    → same PTY

Transport connection actually dies
    → SSH connection ends normally
    → tmux/screen may preserve the workload
    → user can establish a new SSH connection and reattach
```

This means Tatami does not initially need to solve arbitrary SSH server-state resurrection.

### Important consequence

"SSH survives changing networks" and "SSH survives losing its transport connection" are deliberately different claims.

The first is a core QUIC experiment.

The second is not initially a Tatami protocol feature and may ultimately remain outside the protocol's scope entirely.

## Migration testing goal

A particularly valuable integration test/demo should eventually:

1. establish an interactive SSH session over QUIC,
2. start/use a PTY,
3. change the client's network path/address,
4. allow QUIC path validation/migration to occur,
5. verify that:
   - the SSH connection remains alive,
   - the PTY remains alive,
   - the SSH channel remains alive,
   - authentication is not repeated,
   - the SSH session identifier does not change,
   - stdin/stdout continue normally.

A complementary negative test should allow the QUIC connection to actually die and verify that Tatami does **not** silently invent SSH session recovery.

## Repository implications

The eventual test layout should reserve room for:

```text
tests/
├── tcp/
│   └── interoperability.rs
│
└── quic/
    ├── basic_connection.rs
    ├── authentication.rs
    ├── migration.rs
    ├── nat_rebinding.rs
    └── resumption.rs
```

The QUIC implementation may eventually have internal modules such as:

```text
crates/tatami-transport/src/quic/
├── mod.rs
├── endpoint.rs
├── connection.rs
├── config.rs
├── migration.rs
└── resumption.rs
```

These names are implementation suggestions, not yet API commitments.

---

# Current priority order

The current design priority is:

```text
1. Conventional SSH/TCP compatibility
2. SSH-over-QUIC basic transport
3. SSH authentication / authorized_keys compatibility
4. SSH channel semantics
5. QUIC connection migration
6. NAT rebinding
7. TLS-exporter-based SSH/QUIC session binding refinement
8. QUIC/TLS session resumption experiments
9. Any possible SSH-session recovery after connection loss
```

Items 8–9 should not block the initial repository or basic QUIC implementation.

---

# Key conceptual principle

> **QUIC migration handles mobility; terminal multiplexers handle disconnection.**

This should guide both implementation scope and the eventual Internet-Draft.

The I-D can therefore make a strong, bounded claim: Tatami explores preserving an SSH connection across network-path changes using QUIC connection migration, while leaving application-level persistence after actual connection loss to existing mechanisms such as `tmux`/`screen`.


# Resume instruction

If this file is re-uploaded after conversation state is lost, start by treating it as the current design ledger.

Do **not** restart the project from scratch.

The immediate technical task should be to continue from the open architectural questions, with particular attention to:

1. the RFC 4253 transport-semantics inventory,
2. the TLS-exporter-based SSH/QUIC session binding,
3. SSH userauth compatibility,
4. SSH-channel ↔ QUIC-stream mapping,
5. and the eventual standards-oriented comparison with Bider.

Maintain the distinction between:

- **decided**
- **strong candidate**
- **experimental hypothesis**
- **open question**

Avoid silently turning an experimental proposal into a protocol requirement.
