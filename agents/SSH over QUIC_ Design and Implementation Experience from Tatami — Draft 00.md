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