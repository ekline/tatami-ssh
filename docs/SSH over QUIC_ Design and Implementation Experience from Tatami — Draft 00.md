# SSH over QUIC: Design and Implementation Experience from Tatami

## 1. Abstract

The Secure Shell (SSH) protocols defined in [RFC4251], [RFC4252], [RFC4253], and [RFC4254] were designed around a reliable, ordered byte-stream transport, conventionally TCP. QUIC [RFC9000] provides a secure, multiplexed transport with independent streams, connection migration, and other properties that are potentially useful for long-lived interactive SSH sessions.

This document describes Tatami, an implementation and architectural exploration of binding SSH to QUIC. The goal is to investigate how the externally meaningful semantics of SSH can be retained while replacing transport mechanisms that are naturally supplied by QUIC. Particular attention is given to SSH authentication, server identity, SSH channel semantics, QUIC stream multiplexing, connection migration, and the relationship between SSH and QUIC security mechanisms.

Tatami is intended to provide genuine SSH interoperability over conventional TCP while exploring QUIC as an alternative transport binding. The work is implementation-driven: protocol choices are evaluated through implementation and interoperability experience rather than assuming that an existing SSH-over-QUIC design is necessarily the appropriate architecture.

This document is informational. It describes the Tatami approach, implementation experience, design rationale, and lessons learned. It does not propose HTTP/3 as an SSH transport and does not require HTTP/3.

## 2. Introduction

SSH is widely used for interactive login, remote command execution, forwarding, file transfer, and other secure remote-access applications. The SSH architecture separates the application-level Connection Protocol from the underlying transport and authentication mechanisms, but the standardized transport protocol defined by [RFC4253] assumes a reliable, ordered byte stream.

QUIC [RFC9000] provides a different transport model. In addition to reliable delivery, QUIC provides independently flow-controlled streams, connection-level flow control, connection identifiers, path validation, connection migration, and integration with TLS 1.3 [RFC9001]. These properties are potentially valuable for SSH, particularly for multiplexed connections and long-lived interactive sessions that move between network paths.

Tatami-rs is an implementation project intended to explore this design space.

The central design question is not whether SSH packets can simply be placed inside QUIC. Rather, it is:

> How can the semantics of SSH be preserved while making appropriate use of the transport mechanisms that QUIC already provides?

This distinction is important. Some mechanisms in the SSH transport protocol exist because SSH was originally designed to operate over a TCP byte stream. QUIC provides mechanisms with different properties and semantics, and duplicating those mechanisms merely to preserve the historical SSH wire representation may unnecessarily discard the benefits of QUIC.

Tatami therefore investigates a QUIC-native binding in which SSH semantics remain visible at the application protocol boundary while suitable transport functions are provided directly by QUIC.

The project also maintains a conventional SSH-over-TCP implementation. TCP mode is intended to remain ordinary SSH rather than becoming a compatibility layer for the QUIC design. In particular, a long-term goal is interoperability between Tatami's TCP implementation and unmodified conventional SSH implementations.

The work is deliberately implementation-driven. Some aspects of the binding are straightforward mappings of existing SSH semantics onto QUIC. Other aspects require new protocol definitions or careful analysis because SSH and QUIC have different notions of connection establishment, cryptographic state, flow control, stream termination, and channel multiplexing.

This document records the design as it develops and the experience obtained from implementing and testing it. Where the design remains unresolved, that fact is stated explicitly rather than presenting a provisional implementation choice as a settled protocol requirement.

### 2.1. Scope

The primary scope of this work is:

* SSH over QUIC using QUIC and TLS 1.3 as the underlying secure transport;
* preservation of SSH user authentication semantics, including the use of existing SSH public-key authentication where practical;
* preservation of SSH Connection Protocol semantics where they remain meaningful;
* use of QUIC's native multiplexing and flow-control mechanisms where appropriate;
* investigation of QUIC connection migration and NAT rebinding for long-lived SSH sessions;
* interoperability and implementation experience;
* comparison with previous SSH-over-QUIC work.

The work also considers how SSH transport-layer concepts such as the exchange hash, session identifier, key exchange, rekeying, and `SSH_MSG_NEWKEYS` relate to a QUIC/TLS transport.

### 2.2. Non-Goals

The following are not goals of the Tatami project:

* replacing SSH with a new SSH-like remote-access protocol;
* defining SSH over HTTP/3;
* requiring HTTP/3 or an HTTP intermediary;
* introducing a new user authentication system unrelated to SSH;
* defining application-level session resurrection after a QUIC connection has actually terminated;
* reproducing every TCP-era SSH transport mechanism inside QUIC solely for byte-for-byte compatibility;
* asserting that the Tatami wire protocol is necessarily the protocol that should ultimately be standardized by the IETF.

The last point is particularly important. The purpose of this document is to record an implementation and architectural exploration and to make its results available to future protocol work.

## 3. Goals and Design Principles

Tatami follows several principles throughout the design.

### 3.1. SSH remains SSH

QUIC is treated as an alternate transport binding for SSH rather than as the foundation of a new remote-access protocol.

The SSH concepts that remain externally meaningful should therefore retain their semantics. In particular, the design seeks to preserve the distinction between:

* server identity and trust; and
* user authentication.

Existing SSH mechanisms such as `known_hosts` and `authorized_keys` are important reference points for this goal.

### 3.2. Use QUIC where QUIC provides the appropriate mechanism

The binding should make use of QUIC's native properties rather than treating QUIC as merely an encrypted replacement for TCP.

In particular, the design investigates:

* QUIC native streams for SSH channel multiplexing;
* QUIC stream and connection flow control;
* QUIC connection identifiers and connection migration;
* TLS 1.3 as the cryptographic foundation of QUIC;
* TLS exporter mechanisms where an SSH-specific cryptographic binding is required.

The guiding principle is:

> Preserve SSH's externally meaningful semantics; replace underlying transport mechanisms with native QUIC mechanisms where QUIC provides an appropriate equivalent.

This principle is inspired in part by the architectural transition from HTTP/2 to HTTP/3, but Tatami does not depend upon or attempt to reproduce HTTP/3.

### 3.3. Minimize new cryptographic mechanisms

The design prefers established mechanisms defined by SSH, TLS, and QUIC specifications over a parallel cryptographic protocol.

QUIC already uses TLS 1.3 [RFC9001]. Consequently, the design investigates which functions traditionally performed by SSH key exchange and packet protection can be supplied by QUIC/TLS, and what SSH-specific binding is still necessary.

### 3.4. Preserve conventional SSH/TCP interoperability

TCP remains a first-class transport for Tatami.

The QUIC binding should not impose QUIC-specific semantics on the ordinary TCP implementation unless an SSH extension or other standards-defined mechanism requires them.

This permits Tatami to be used as an ordinary SSH implementation even when QUIC is unavailable.

### 3.5. Treat mobility and session persistence separately

A primary motivation for QUIC is its ability to maintain a connection while the network path changes.

Tatami therefore distinguishes:

* **transport mobility:** maintaining the same QUIC connection across network-path changes; and
* **application/session persistence:** preserving an application workload after the transport connection has actually terminated.

The first is a primary Tatami objective. The second is deliberately outside the initial protocol scope. Existing mechanisms such as terminal multiplexers can provide application persistence independently of SSH transport.

Thus:

> QUIC migration handles mobility; terminal multiplexers handle disconnection.

### 3.6. Implementation experience is part of the result

The Tatami design is expected to evolve as implementation and interoperability testing expose constraints or ambiguities.

A protocol choice documented in this document may therefore be:

* a settled design decision;
* a strong candidate;
* an experimental hypothesis; or
* an open question.

These categories should not be conflated.

## 4. Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **NOT RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in BCP 14 when, and only when, they appear in all capitals.

The following terminology is used in this document.

**SSH connection**

An SSH protocol connection as defined by the SSH architecture and Connection Protocol. In the conventional SSH transport, an SSH connection is carried over a single reliable byte-stream transport connection.

**SSH channel**

A logical SSH channel as defined by [RFC4254], such as a session channel, forwarding channel, or other channel type.

**QUIC connection**

A QUIC connection as defined by [RFC9000]. A QUIC connection may survive changes to its network path through QUIC connection migration.

**QUIC stream**

A QUIC bidirectional or unidirectional stream belonging to a QUIC connection.

**SSH-over-QUIC binding**

The protocol binding defined or explored by Tatami that carries SSH semantics using a QUIC connection.

**SSH control stream**

A QUIC stream dedicated to SSH connection-level protocol state in the Tatami architecture. The precise stream type and bootstrap rules are specified later in this document.

**SSH channel stream**

A QUIC stream associated with an SSH channel in the QUIC-native channel-multiplexing design explored by Tatami.

**Session binding**

The cryptographic or protocol association that identifies the SSH session established over a particular QUIC/TLS connection and provides the context required by SSH operations such as user authentication.

**Connection migration**

Continuation of the same QUIC connection after a change in the client's or server's network path, as defined by [RFC9000].

**NAT rebinding**

A change in the network-layer address and/or UDP source port observed for a QUIC endpoint while the underlying QUIC connection remains established.

**Resumption**

Establishment of a new QUIC connection using TLS resumption state. Resumption is distinct from QUIC connection migration and does not, by itself, imply continuation of an existing SSH connection.

## 5. Relationship to SSH and QUIC

Tatami is based on the observation that SSH and QUIC provide overlapping but non-identical protocol functions.

The conventional SSH stack can be represented approximately as:

```text
SSH Connection Protocol
        │
SSH Authentication Protocol
        │
SSH Transport Protocol
        │
TCP
```

The Tatami QUIC architecture instead investigates:

```text
SSH Connection Protocol
        │
SSH Authentication Protocol
        │
SSH/QUIC binding
        │
QUIC
        │
TLS 1.3
        │
UDP/IP
```

The important difference is that the SSH transport layer is not assumed to retain every mechanism defined for the TCP binding.

[RFC4253] combines several functions in one protocol layer, including:

* identification exchange;
* algorithm negotiation;
* key exchange;
* server host-key authentication;
* derivation of transport encryption and integrity keys;
* packet framing;
* rekeying; and
* transport-level error handling.

QUIC and TLS already provide mechanisms corresponding to some of these functions. The Tatami design therefore analyzes each SSH transport function separately rather than assuming that the entire RFC 4253 transport protocol should simply be encapsulated within QUIC.

This produces three broad categories.

### 5.1. SSH semantics retained

Some SSH semantics remain useful regardless of the underlying transport. Examples include:

* SSH user authentication;
* SSH services;
* SSH channels;
* channel requests;
* global requests; and
* SSH disconnect semantics, to the extent appropriate to the binding.

### 5.2. Functions supplied by QUIC/TLS

Some transport functions are naturally supplied by QUIC and TLS. Examples include:

* authenticated cryptographic transport;
* packet protection;
* reliable delivery;
* stream multiplexing;
* transport flow control;
* connection identifiers;
* path validation; and
* connection migration.

The precise correspondence between these functions and SSH mechanisms is analyzed later rather than assumed to be exact.

### 5.3. Functions requiring an SSH/QUIC binding

Other functions require an explicit protocol binding because SSH semantics depend on information that is not represented in QUIC alone.

A particularly important example is the SSH session identifier.

In conventional SSH, the session identifier is derived from the initial SSH key exchange and is based on the SSH exchange hash. SSH user authentication signatures incorporate this session identifier.

A QUIC connection does not perform the RFC 4253 key exchange and therefore does not naturally produce the same SSH exchange hash.

Tatami consequently investigates an SSH/QUIC-specific session-binding construction based on the established TLS/QUIC security context. A TLS exporter with an SSH-specific context is a leading candidate, but the exact construction remains subject to protocol analysis and implementation testing.

The binding must also explicitly account for the SSH identification exchange. The fact that the RFC 4253 exchange hash includes the client and server identification strings means that simply discarding those strings would change an important part of the SSH security model.

The resulting architecture is therefore:

```text
                 QUIC connection
                       │
              ┌────────┴────────┐
              │                 │
       TLS 1.3 security    SSH/QUIC binding
              │                 │
              │          SSH session identity
              │                 │
              └────────┬────────┘
                       │
                SSH authentication
                       │
                 SSH connection
                       │
              ┌────────┴────────┐
              │                 │
          SSH channel       SSH channel
              │                 │
        QUIC stream       QUIC stream
```

This diagram represents the architectural direction under investigation; later sections define which elements are normative and which remain experimental.

## 6. Architectural Model

### 6.1. Overview

The Tatami QUIC architecture consists of an SSH protocol binding operating over a single QUIC connection.

The current architectural model uses QUIC's native stream multiplexing rather than representing the entire SSH connection as one QUIC byte stream.

A strong working hypothesis is:

```text
                     QUIC connection
                           │
          ┌────────────────┼────────────────┐
          │                │                │
   SSH control stream   SSH channel      SSH channel
                        stream 1         stream 2
          │                │                │
   identification         data             data
   + connection-
   level semantics
```

This architecture is analogous in spirit to the use of dedicated control and application streams in HTTP/3, but it is not intended to reproduce HTTP/3's protocol or wire format.

### 6.2. SSH control stream

A dedicated QUIC stream is being investigated as the home for SSH connection-level protocol state.

Candidate contents include:

* the SSH client and server identification exchange;
* SSH/QUIC negotiation or capability information;
* connection-level SSH messages;
* global requests and their responses; and
* other SSH state that cannot naturally be associated with an individual channel.

The exact stream direction, stream type, creation rules, and bootstrap procedure remain to be specified.

In particular, the design must answer whether the control stream is:

* a conventional bidirectional QUIC stream;
* a specially typed QUIC stream;
* created by a fixed endpoint;
* negotiated explicitly; or
* established using some other deterministic rule.

These questions are deferred to the wire-protocol section.

### 6.3. SSH channel streams

The primary channel-multiplexing hypothesis is that an SSH channel corresponds to a QUIC bidirectional stream.

This provides an attractive mapping because QUIC streams have independent reliability and flow control. A blocked or delayed channel therefore need not necessarily block unrelated SSH channels at the transport layer.

The mapping must nevertheless preserve SSH channel semantics, including:

* channel opening;
* channel numbering;
* initial channel parameters;
* channel data;
* extended data;
* channel requests;
* end-of-file;
* channel close; and
* channel-specific flow-control behavior.

It is not yet assumed that the SSH channel wire representation can simply be copied onto a QUIC stream. The later channel-mapping section will determine which SSH fields remain necessary and which transport functions can instead be represented by QUIC.

### 6.4. Connection-level SSH semantics

Not every SSH message belongs to a particular channel.

The binding therefore needs a separate representation for connection-level SSH semantics, including global requests and their responses.

The control-stream model provides a natural candidate for this purpose.

This separation is important because a QUIC stream associated with one SSH channel should not have to carry unrelated connection-level protocol messages merely because conventional SSH represents all channels on one transport packet stream.

### 6.5. Flow control

SSH [RFC4254] provides per-channel flow control using channel windows and `SSH_MSG_CHANNEL_WINDOW_ADJUST`. QUIC independently provides stream-level and connection-level flow control.

The Tatami architecture therefore investigates whether SSH channel flow control can be mapped onto QUIC stream flow control rather than reproducing SSH's window-adjustment mechanism.

The guiding principle is to preserve observable SSH behavior while avoiding redundant transport machinery.

This does not imply that SSH channel-window parameters can simply be discarded. Parameters such as maximum packet size and initial channel configuration may retain protocol significance even when QUIC supplies the underlying flow control.

The exact mapping is therefore deferred to the flow-control section.

### 6.6. Stream termination

SSH defines distinct concepts for channel EOF and channel close. QUIC provides FIN, RESET_STREAM, and STOP_SENDING, which have related but not identical meanings.

Tatami therefore does not assume that:

```text
SSH EOF   == QUIC FIN
SSH CLOSE == QUIC RESET
```

A later section will define the mapping based on the observable semantics of both protocols.

### 6.7. Network-path changes

One of the principal motivations for using QUIC is connection migration.

A Tatami SSH connection should be able to remain an SSH connection when the underlying QUIC path changes, subject to the normal requirements and limitations of QUIC connection migration.

Conceptually:

```text
             same SSH connection
                      │
                same QUIC CID
                      │
             ┌────────┴────────┐
             │                 │
          network A         network B
             │                 │
             └──── migration ─┘
```

Migration should not require SSH user reauthentication or creation of a new SSH channel.

This is distinct from connection loss. If the QUIC connection terminates, Tatami does not initially define a mechanism for a newly established connection to resurrect the previous SSH connection or PTY.

### 6.8. Resumption

TLS/QUIC resumption is also distinct from migration.

A resumed connection is a new QUIC connection. It therefore does not automatically represent continuation of an earlier SSH connection.

Tatami may investigate the performance and security implications of QUIC/TLS resumption, but SSH-session recovery following connection loss is outside the initial scope.

### 6.9. TCP architecture

The TCP implementation follows the conventional SSH architecture independently of the QUIC binding:

```text
SSH
 │
SSH Transport
 │
TCP
```

The TCP implementation should not require QUIC stream concepts, QUIC connection identifiers, or QUIC migration semantics.

This separation is intentional. It permits interoperability testing against conventional SSH implementations and prevents experimental QUIC-specific design decisions from becoming accidental requirements on the ordinary SSH/TCP protocol.

## Appendix A. Implementation Status and Evidence (2026-09-20)

This appendix records what the Tatami implementation has actually done as of round 4, so that later sections of this document can cite implementation experience rather than intent. It is a status report inside an Informational draft intended for the Independent Submission Stream; nothing here has been adopted, reviewed or accepted by any IETF working group, and no interoperability with any implementation other than OpenSSH (TCP transport handshake, client role only) is claimed. Terms: **decided** refers to a workspace decision (`W-nn`) or checkpoint entry (`P-nn`, `AQ-nnn`) in the project's ledgers; **open** means no wire behaviour has been selected.

### A.1. Mechanism matrix

| Mechanism | TCP behaviour ([RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html) unless noted) | Proposed QUIC mapping | Decision / open ID | Implementation state | Test evidence |
|---|---|---|---|---|---|
| Identification exchange | `SSH-2.0-…` lines both ways; server prelude lines; 255-byte limit; `1.99` compatibility (§4.2) | Retain strings; placement (control stream vs first bytes) and canonical encoding for the binding **open** | P-05, AQ-020–AQ-023; W-12 | TCP: implemented (probe, observer, handshake). QUIC: not started; the diagnostic handshake sends none. | `tatami-tcp/tests/ident_characterization.rs`; `tatami-quic/tests/inmem_handshake.rs::assert_no_ssh_bytes` |
| Algorithm negotiation | `KEXINIT` name-lists, first client choice the server lists (§7.1); markers never selected ([RFC 8308 §2.2](https://www.rfc-editor.org/rfc/rfc8308.html#section-2.2)) | Supplied by TLS 1.3 for keys and protection; SSH-level negotiation of what remains (services, extensions) **open** | AQ-002, AQ-006–AQ-008 | TCP: implemented for one profile (`curve25519-sha256`, `ssh-ed25519`, `aes128-gcm@openssh.com`, `none`); RFC 9142 MUST (`diffie-hellman-group14-sha256`) not implemented. | `tatami-tcp/src/negotiate.rs` tests; `openssh_handshake.rs::sshd_outside_the_profile_fails_negotiation_cleanly` |
| KEX, exchange hash, session id | `KEX_ECDH_INIT`/`REPLY` ([RFC 5656 §4](https://www.rfc-editor.org/rfc/rfc5656.html#section-4), [RFC 8731](https://www.rfc-editor.org/rfc/rfc8731.html)); `H` over `V_C,V_S,I_C,I_S,K_S,Q_C,Q_S,K`; `session_id = H` (§7.2, §8) | Not performed over QUIC; replaced by TLS key establishment plus an exporter-derived identifier (§5.3 of this document) | P-04, AQ-003 | TCP: implemented (client). QUIC: no KEX by design; see "Session binding". | `tatami-tcp/src/transcript.rs` (RFC 7748 §6.1 vectors, Python oracle); `openssh_handshake.rs::default_sshd_completes_the_profile_handshake` |
| Host identity and trust | Host-key blob `K_S` signed over `H`; trust policy external (`known_hosts`) | TLS server identity; raw public keys ([RFC 7250](https://www.rfc-editor.org/rfc/rfc7250.html)) preferred candidate; SSH↔SPKI mapping **open** | P-06, C-03; W-32 | TCP: `ssh-ed25519` verification + operator pin (`PinnedSha256`); no `known_hosts`. QUIC: RPK handshake demonstrated with SPKI pinning; the SPKI, SSH-blob and certificate fingerprints of one key differ. | `tatami-keys` tests; `openssh_handshake.rs::wrong_pin_stops_before_newkeys_against_sshd`; `tatami-quic/tests/rpk.rs` |
| Packet protection | Binary packet, AEAD with length as AAD ([RFC 5647](https://www.rfc-editor.org/rfc/rfc5647.html)); per-direction keys (§6.2–6.4, §7.2) | Supplied by QUIC packet protection ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)); SSH records on streams need only framing, **record rule open** | P-02, AQ-018 | TCP: `aes128-gcm@openssh.com` both directions, 64-bit invocation counter never reset. QUIC: nothing SSH-specific. | `tatami-tcp/src/gcm.rs` tests (Python `cryptography` oracle); interop tests above |
| Strict KEX | [draft-ietf-sshm-strict-kex-02](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-strict-kex-02): markers in initial `KEXINIT`, `KEXINIT` first, sequence reset at `NEWKEYS` | Not applicable as such: there is no SSH KEX over QUIC. Whether QUIC's handshake and record protection give an equivalent guarantee against handshake-prefix manipulation is part of the C-02 equivalence argument, not asserted here | C-02 | TCP: implemented, both client spellings offered; negotiated with OpenSSH 10.2 under `kex-strict-s-v00@openssh.com`. | `handshake.rs::strict_mode_*` tests; interop tests |
| `EXT_INFO` | Next packet after `NEWKEYS` and/or before `USERAUTH_SUCCESS` ([RFC 8308 §2.3–2.5](https://www.rfc-editor.org/rfc/rfc8308.html#section-2.3)) | "Next packet" has no QUIC equivalent; placement on the control stream **open** | AQ-002 | TCP: receive-only at the first opportunity; `server-sig-algs` recorded; nothing enabled. | `handshake.rs::protected_phase_message_rules`; interop test asserts `server-sig-algs` |
| Service negotiation | `SERVICE_REQUEST`/`SERVICE_ACCEPT` (§10) | Retained semantics (§5.1); carrier **open** (control stream candidate) | P-03 | TCP: `ssh-userauth` requested and accepted, protected. `ssh-connection` never requested. | interop tests (`service_accepted == "ssh-userauth"`) |
| Disconnect | `DISCONNECT` reason/description (§11.1) | Retained "to the extent appropriate" (§5.1); relation to CONNECTION_CLOSE **open** | AQ-017 (adjacent) | TCP: protected `DISCONNECT` sent on completion and on rekey refusal; server `DISCONNECT` decoded. QUIC: application CONNECTION_CLOSE only, no SSH content. | `handshake.rs::disconnect_*`; sshd log `Received disconnect … tatami diagnostic complete` |
| Rekeying | `KEXINIT` after `NEWKEYS` (§9) | Supplied by QUIC key update ([RFC 9001 §6](https://www.rfc-editor.org/rfc/rfc9001.html#section-6)); SSH-visible effect **open** | AQ-008 | TCP: **not implemented**; a server re-exchange request ends the diagnostic (`RekeyNotSupported`). | `handshake.rs::rekey_request_after_newkeys_sends_disconnect` |
| Channel opening | `CHANNEL_OPEN`/`CONFIRMATION`/`FAILURE` ([RFC 4254 §5.1](https://www.rfc-editor.org/rfc/rfc4254.html#section-5.1)) | One channel per bidirectional stream (**provisional**); placement of the opening exchange and association **open** | P-01, AQ-026, AQ-001, AQ-004 | Codecs and a transport-independent opening engine implemented (distinct local/peer numbers, tombstoned cancellations, duplicate peer numbers rejected). Not wired to either transport. | `tatami-connection/src/opening.rs` tests; fuzz target `channel_opening` |
| Data and window | `DATA`/`EXTENDED_DATA`/`WINDOW_ADJUST`; debit includes the string length field ([EID 3878](https://www.rfc-editor.org/errata/eid3878)) | SSH credit vs QUIC stream/connection credit **open**; separate credit domains required | P-07, AQ-016, AQ-029 | **Not implemented** on either transport; fields retained verbatim in the opening codecs. | — |
| EOF and close | `EOF`, `CLOSE` (§5.3) | Not assumed equal to FIN/RESET_STREAM/STOP_SENDING (§6.6 of this document) | AQ-017, AQ-028 | **Not implemented.** | — |
| Control stream and bootstrap | — (single ordered byte stream) | Dedicated bidirectional stream candidate (§6.2 of this document) | P-03, AQ-015 | **Not started.** | — |
| Session binding / exporter | `session_id = H` from the initial KEX | [RFC 8446 §7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5) exporter with SSH-specific label/context; not the fixed [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html) `tls-exporter` binding | P-04, AQ-003, AQ-024 | **Availability shown** through quinn-proto/rustls (fails before completion; equal both ends; separated by label, context, length, connection). **Construction not defined.** | `tatami-quic/tests/exporter.rs` |
| ALPN and versioning | — | ALPN required by [RFC 9001 §8.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1); value configurable, **experimental, unregistered** | P-08, AQ-019 | Diagnostic handshake requires an explicit ALPN (`tatami-diag/0` in tests); offered and negotiated values reported separately. | `tatami-quic/tests/loopback.rs::wrong_alpn_over_loopback` (alert 120) |
| Address validation | — | Retry/token inside the QUIC implementation; validation ≠ identity | — | Diagnostic server can require Retry; accepted connections report `peer_address_validated`, `validation_method`. | `loopback.rs::require_validation_sends_retry_and_reports_validated_peer` |
| Connection loss vs migration | TCP loss ends the SSH connection | Migration keeps the SSH connection (§6.7); loss ends it, no resurrection (C-04) | AQ-028 (streams), C-04 | **Open**; migration not exercised (quinn-proto 0.11 has no migration event; only coarse address change). | — |

### A.2. Implementation experience

Concrete findings from round 4 that bear on the design text:

- **AEAD ciphers and the MAC lists.** With `aes128-gcm@openssh.com`, MAC negotiation is skipped and the MAC name-lists are ignored ([draft-miller-sshm-aes-gcm-01 §2](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm-01), an expired individual draft that [OpenSSH `PROTOCOL` §1.6](https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL) names as its authority). The lists must still be non-empty (RFC 4253 §7.1), so an implementation that offers only AEADs advertises a MAC it may not implement. Tatami records this as a gap rather than hiding it (W-30). A QUIC binding has no such list and no such gap.
- **Strict-KEX spellings.** The standard names `kex-strict-c`/`kex-strict-s` and the deployed `-v00@openssh.com` names must be matched within one spelling, never across. OpenSSH 10.2 offers only the pre-standard server name; a client should offer both (draft §3.1). Under QUIC this whole mechanism is absent, which is itself a data point for §5.2.
- **Exporter behaviour.** Through quinn-proto's `crypto::Session::export_keying_material`, exporting before the handshake completes fails without touching the buffer; after completion both ends agree and any change of label, context or requested length, or a fresh connection, changes the output. This confirms the *mechanism* P-04 needs; it says nothing about which label, context or transcript inputs the SSH binding should use.
- **Raw public keys.** rustls 0.23 completes an RFC 7250 handshake over QUIC with the server presenting only the SPKI and the client pinning its SHA-256 while still verifying `CertificateVerify`. The SPKI DER (44 bytes for Ed25519, [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html) prefix), the `ssh-ed25519` blob (51 bytes) and an X.509 certificate of the same key have three different SHA-256 fingerprints although all render as `SHA256:…`. "Familiar host-key trust" therefore requires a defined, algorithm-validated conversion, not a hash of whatever TLS presents (checkpoint §4).
- **Offered vs negotiated ALPN.** quinn-proto exposes only the negotiated ALPN and SNI (`HandshakeData`). The offered list is visible only through a rustls `ResolvesServerCert` hook, and an ALPN mismatch fails inside `Endpoint::accept` before a connection exists — so a server that wants to learn what clients *offer* must capture it at that hook, and its records must allow "failed before a connection existed".
- **0-RTT is on by default in convenience paths.** quinn-proto's `ServerConfig::with_single_cert` sets `max_early_data_size = u32::MAX` and its client constructors set `enable_early_data = true`. A binding that has not analysed replay must build its TLS configuration explicitly (Tatami: early data 0, no tickets, resumption disabled). This is a requirement to state in the eventual bootstrap section, not an implementation detail.
- **Validation is three facts.** QUIC address validation (Retry token or NEW_TOKEN), the Retry mechanism itself, and TLS peer identity are independent; a report or a policy that collapses them is wrong. quinn-proto sends NEW_TOKEN frames only with its optional `bloom` feature.

### A.3. Constraints from the next use cases (directions, not support)

None of the following is implemented. They are recorded so that the channel, flow-control and stream sections are written against concrete workloads.

| Use case | SSH mechanism ([RFC 4254](https://www.rfc-editor.org/rfc/rfc4254.html)) | Constraint on the QUIC binding |
|---|---|---|
| Local TCP forwarding; SOCKS5 `CONNECT` front end | One `direct-tcpip` channel per forwarded connection (§7.2) | One channel → one bidirectional QUIC stream, eventually; SOCKS resolution and the originator address remain opening parameters, never the QUIC peer address (checkpoint §3.3). |
| Remote forwarding | `tcpip-forward` / `cancel-tcpip-forward` global requests (§7.1) authorise a listener; each accepted connection is a `forwarded-tcpip` open | Listener lifetime and connection lifetime are distinct objects. Cancellation ordering against in-flight opens is the AQ-027 counterexample; a fence or generation rule is required if opens travel on independent streams. |
| UDP forwarding (future) | No standard SSH mechanism | Investigate QUIC DATAGRAM ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)) with an explicit association rule; **not** one stream per UDP flow. |
| SFTP | SFTP v3 per [draft-ietf-secsh-filexfer-02](https://www.openssh.com/txt/draft-ietf-secsh-filexfer-02.txt) on a `session` channel `subsystem` request; no legacy SCP protocol (W-25) | Experiment: one transfer per channel per stream inside one authenticated connection; parent directories confirmed before their files; final directory metadata after descendants; cross-stream ordering expressed as explicit dependencies; bounded per-file concurrency, memory and handles; handle and session ownership explicit and never shared across sessions. Performance gain is a hypothesis to measure. |

Two cautions carry over unchanged. First, one channel per bidirectional stream remains **provisional** (P-01): the stream provides ordered delivery per direction only, and messages on different streams have no order relative to each other, so any dependency between a channel and connection-level state (authentication completion, forwarding authorisation, X11 permission) needs an explicit ordering rule (AQ-027). Second, the RFC 8308 `no-flow-control` extension is not a template for QUIC flow control: it applies only while a **single** channel exists ([RFC 8308 §3.3](https://www.rfc-editor.org/rfc/rfc8308.html#section-3.3)) and cannot describe a multichannel binding, which must decide separately whether SSH window credit is enforced alongside QUIC credit (AQ-016).