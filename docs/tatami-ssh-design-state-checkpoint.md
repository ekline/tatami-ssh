# Tatami-SSH checkpoint — 2026-09-20

This is the current design and implementation handoff. The historical checkpoint follows at the end, unchanged. Read this section first when older statements disagree with it.

**Scope completed:** reconstructed decision ledger; proposed Cargo package responsibilities and dependencies; first RFC 4254 audit covering channel opening; conflicts and implementation gates. No Cargo workspace or substantial Rust implementation has been created in this step.

**Inputs:** the complete `tatami-ssh-design-state-checkpoint.md` through its 2026-09-13 channel-framing update, and the user's newer `Pasted markdown(1).md` handoff. The handoff controls current intent. Protocol claims below were checked against primary RFC text; recommendations are our analysis, not requirements imposed by those RFCs.

## 0. Implementation status (added 2026-09-20, after the sections below were written)

The Cargo workspace now exists with all seven packages (see `architecture.md`, decision W-01 supersedes the "create lazily" advice in §2). The first implementation slice is done and tested:

| Area | State | Where |
|---|---|---|
| Bounded SSH primitives, name lists | Implemented, allocation-free | `tatami-wire::{primitives,namelist}` |
| `KEXINIT`, `DISCONNECT`/`IGNORE`/`DEBUG`/`UNIMPLEMENTED` codecs | Implemented; syntactic only | `tatami-wire::{kexinit,transport}` |
| `CHANNEL_OPEN` / `OPEN_CONFIRMATION` / `OPEN_FAILURE` codecs | Implemented; tails bounded and opaque (contract §2.2 item 1) | `tatami-wire::channel` |
| Identification exchange, initial packet framing | Implemented for the TCP binding only (§4 first row: TCP keeps its own envelope) | `tatami-tcp::{ident,packet}` |
| TCP initial-offer probe and `tatami-client probe` | Implemented; sends no client `KEXINIT`; verified against OpenSSH_10.2p1 | `tatami-tcp::{probe,io}`, `tatami::client::probe` |
| Opening lifecycle engine (§2.2 items 2, 3, 4, 7 for opening only) | Implemented; no data, window accounting, EOF or close | `tatami-connection::opening` |
| `tatami-server` | Entry-point stub only | `crates/tatami/src/bin/tatami-server.rs` |
| Key exchange, host-key verification, packet protection, userauth | Not started; next milestone | — |
| QUIC record framing, association, session binding (AQ-018, AQ-026, P-04) | Not started; no wire choice made | — |

Item 1 of "Next concrete work" in §5 is complete. Validation rows "Message codecs" and "Opening state" in §5 now have executable evidence in package tests; "Interoperability" has one recorded manual smoke test (README), not a claim of interoperability.

## 1. Reconstructed decision ledger

Status meanings: **accepted** means established project intent; **provisional** means the current hypothesis; **proposed** means a recommendation from this checkpoint; **open** means no wire behavior has been selected. A recommendation does not become accepted merely by being saved here.

### 1.1 Accepted constraints and scope

| ID / prior reference | Current position |
|---|---|
| C-01 / D-001 | TCP mode is genuine SSH, targeting interoperability with unmodified clients and servers. |
| C-02 / D-002, D-004, D-014 | QUIC is an alternate SSH transport binding. Preserve externally meaningful SSH semantics and use standardized cryptographic mechanisms. A claimed QUIC replacement needs an explicit equivalence argument. |
| C-03 / D-003 | Preserve familiar server-trust and user-authentication behavior. `known_hosts` and `authorized_keys` remain separate policies. |
| C-04 / D-009–D-012 | Prioritize migration of the same QUIC connection and NAT rebinding. Actual transport loss ends the SSH connection; session resurrection is deferred. TLS resumption creates a new connection. |
| C-05 / current handoff | Target an eventual Independent Stream Informational document informed by implementation experience. Draft design text early enough to guide implementation. |
| C-06 / current handoff | Keep client and server usable as libraries; keep CLI entry points thin. TCP and QUIC bindings must remain separable. |
| C-07 / current handoff | Do not require a common byte-stream `Transport` trait or a common KEX abstraction that makes TLS behave like SSH KEX. |
| C-08 / current handoff | Explicitly classify retained mechanisms as unchanged, mapped, advisory, or retained with no independent effect. No undocumented “ignore it” behavior. |
| C-09 / D-005, later appendix status | Plan a factual comparison with Bider after the design is clearer; the appendix remains optional. Do not infer why the earlier draft stalled. |
| C-10 / continuity requirement | Checkpoint substantial progress, preserve unresolved issues, and record implementation feedback in the ledger and draft. |

Historical D-007/D-008 and AQ-011–AQ-014 are not defined in the checkpoint supplied here. Their contents are not reconstructed by guessing.

### 1.2 Provisional architecture

| ID / prior reference | Hypothesis | What is still unsettled |
|---|---|---|
| P-01 / D-013, AQ-001 | One SSH connection per QUIC connection; one SSH channel per bidirectional QUIC stream. | Opening, association, lifetime and failure rules. Pending/refused streams need not become established channels. |
| P-02 / AQ-018, latest historical update | Preserve SSH channel message types and fields on the channel's stream, including normal and extended data. | Exact enclosing QUIC record format and extension behavior. This does not yet prescribe full RFC 4253 transport packets. |
| P-03 / AQ-015, AQ-022 | A dedicated control stream carries connection-level state. A bidirectional stream is a candidate. | Initiator, identification, stream recognition, lifecycle, and placement of the opening handshake. |
| P-04 / D-006, AQ-003 | TLS 1.3/QUIC supplies key establishment and protection; an exporter-derived SSH/QUIC binding supplies the identifier needed by userauth. | Label, context, output length, transcript inputs, availability and authentication proof. |
| P-05 / D-015, AQ-020–AQ-024 | Retain SSH identification strings and account for them explicitly in the binding. | Exact bootstrap syntax, optional pre-identification lines and canonical input encoding. D-015 records intent, not a finished wire specification. |
| P-06 / trust model | TLS raw public keys are the preferred candidate for familiar host-key trust. | Supported key encodings, algorithms, policy conversions and selected TLS/QUIC implementation capabilities. |
| P-07 / AQ-016 | Conservatively retain transport-related channel fields/messages while auditing their semantics. | Retained bytes do not settle whether SSH credit remains independently enforced. Earlier window-elision wording is not a decision. |
| P-08 / AQ-019 | ALPN value is configurable during experiments; no standardized Tatami identifier is asserted. | An ALPN-free deployment requires a defined authenticated alternative, not merely a known port. |

The channel ordering claim is directional: messages encoded in one sending direction retain their order. A bidirectional stream does not create a total order across both directions. Interleaving preserved by the binding is the order already chosen by the SSH sender, not necessarily the original timing of writes to separate process stdout/stderr pipes. PTY configurations can merge output before SSH frames it.

### 1.3 Open-question register

| References | Unresolved work | Blocks |
|---|---|---|
| AQ-001, AQ-004 | Channel/stream association, endpoint roles, pending-open states, ID allocation and reuse. | QUIC channel lifecycle. |
| AQ-002, AQ-006–AQ-008 | Full RFC 4253 inventory: packet framing, service negotiation, disconnect, compression, algorithm negotiation, NEWKEYS and rekeying. | Complete transport bindings; common semantic code can proceed. |
| AQ-003 and subquestions, AQ-005, AQ-024 | Exporter construction, identity validation and exact userauth signature integration. | Authenticated SSH/QUIC operation. |
| AQ-009, AQ-010, AQ-019, AQ-025 | Discovery, fallback, protocol identification and mismatch diagnostics. No 250 ms fallback rule is accepted. | Deployment policy and bootstrap. |
| AQ-015, AQ-020–AQ-023 | Control-stream bootstrap and identification exchange. | QUIC control protocol. |
| AQ-016 | SSH credit versus QUIC credit, data accounting, limit negotiation and credit-release policy. | Final QUIC flow-control profile. |
| AQ-017 | EOF/CLOSE versus FIN/RESET_STREAM/STOP_SENDING, including resets during opening. | QUIC teardown semantics. |
| AQ-018 | Bounded enclosing records, message decoding, opaque extension payloads and receive limits. | Interoperable QUIC wire encoding. |
| AQ-026 — new | Where does the channel-opening handshake run, and how is it associated with exactly one stream? | Initial QUIC channel protocol. |
| AQ-027 — new | Which control/channel dependencies need explicit ordering, notably auth completion and forwarding authorization/cancellation? | Correct concurrent stream processing. |
| AQ-028 — new | How are pending/refused streams bounded and reclaimed without confusing transport abort with SSH refusal? | Resource behavior and errors. |
| AQ-029 — new | What is the precise maximum-packet-size accounting unit under each binding? | Chunking and maximum-record validation. |
| AQ-030 — new | Which client/server, key-format and extension features define the first meaningful OpenSSH interoperability target? | Scope of interoperability claims. |

### 1.4 Rejected or deferred alternatives

| Alternative | Disposition and rationale |
|---|---|
| Custom framed TCP fallback | Rejected by genuine SSH/TCP compatibility goal. |
| Separate stdout and stderr QUIC streams by default | Rejected for the current hypothesis: loses existing channel-direction ordering without extra machinery. |
| One generic stream API for both transports | Rejected as a prerequisite: would obscure QUIC stream admission, association and migration. |
| TLS pretending to implement conventional SSH KEX | Rejected; share downstream security facts, not fictitious handshake steps. |
| Direct use of TLS resumption secrets as SSH identifier | Rejected; secret resumption material is not the proposed application binding. |
| Treat a resumed transport as the old SSH connection | Rejected for initial scope; no implicit PTY reattachment. |
| Window elision or no-op fields without a binding rule | Rejected as an implementation shortcut. A specified alternative can still be investigated. |
| SSH over HTTP/3 | Outside scope; HTTP/3 supplies architectural precedent only. |
| Immediate publication or a claimed IANA ALPN allocation | Outside this task. No value or registration has been invented. |

## 2. Proposed Cargo architecture

**Recommendation:** use small protocol engines and separate transport-binding packages. Plan seven substantive packages, creating each only when its first real functionality is implemented. The first workspace can contain `tatami-wire` and `tatami-connection`; there is no reason to create seven empty crates now.

### 2.1 Responsibilities and dependency direction

Arrows in the dependency column mean “depends on.” Third-party libraries are intentionally unspecified until implementation selection and capability checks.

| Package | Owns | Internal dependencies | Does not own |
|---|---|---|---|
| `tatami-wire` | SSH primitive encodings, raw message fields, context-appropriate payload codecs, checked lengths, bounded opaque extension tails. | None. | Sockets, TCP/QUIC records, state transitions, TLS, trust policy. |
| `tatami-keys` | SSH key/signature representations, format validation, supported SPKI-to-SSH conversions, wrappers around cryptographic providers, key-policy contracts. | `wire` | SSH KEX orchestration, TLS handshakes, userauth policy decisions or home-grown cryptographic primitives. |
| `tatami-auth` | Client/server userauth state machines, method-specific decoding context, signature-input construction, method/authorization callbacks, session security context consumed by userauth. | `wire`, `keys` | Session-identifier derivation, socket I/O, PTY/channel management. |
| `tatami-connection` | Connection/channel state machines, local and peer channel numbers, pending-open context, requests and replies, SSH window accounting, application events and admission decisions. | `wire` | QUIC stream IDs, socket operations, TLS, physical stream admission or external process execution. |
| `tatami-tcp` | Ordinary SSH transport: identification, packet protection, KEX, services and rekey; TCP runtime driver that composes the shared auth/connection engines. | `wire`, `keys`, `auth`, `connection` | QUIC bootstrap, exporters, stream mapping or QUIC-specific policy. |
| `tatami-quic` | QUIC/TLS integration, SSH/QUIC bootstrap and binding derivation, outer records, channel/stream association, QUIC stream scheduling, migration exposure; its own engine driver. | `wire`, `keys`, `auth`, `connection` | Conventional SSH KEX, a fabricated common transport handshake, process/PTY persistence after connection death. |
| `tatami` | Reusable `client` and `server` modules, application configuration, filesystem/policy integrations and thin CLI binaries. | `keys`, `auth`, `connection`, independently optional `tcp` and `quic`; re-exports as needed. | Protocol state machines duplicated from lower packages. |

Here `wire`, `keys`, etc. abbreviate the corresponding `tatami-*` package names. Neither transport binding depends on the other. The shared engines never depend on a binding or the public facade. The two transport packages intentionally include distinct engine-driving code; sharing that code is a later evidence-based refactoring, not an initial interface requirement.

Do not start with a broad `tatami-crypto` crate: key operations are reusable, but SSH KEX orchestration and TLS key establishment belong in different bindings. Split provider wrappers further only if a real backend or feature boundary warrants it. Separate `tatami-client` and `tatami-server` crates are also unnecessary initially: public library modules meet the reuse requirement. A later split is reasonable if dependency weight or independent release needs justify it. CLI dependencies should be feature-gated and required only by the binaries.

### 2.2 API contracts worth establishing early

These are design contracts, not committed Rust signatures.

1. **Bounded decoding.** A wire decoder consumes an already delimited payload. Decode common OPEN fields and keep any remaining type-specific bytes bounded by that payload. Do not require a parser to understand an unknown channel type merely to locate the next record. Check lengths before allocating.
2. **Distinct identities.** Keep local and peer SSH channel numbers distinct from a connection-local logical handle. Use a generation or equivalent stale-reference defense internally when IDs are recycled. Stream IDs and association state live solely in the QUIC binding. The common wire type need not encode runtime role information.
3. **Opening is a protocol lifecycle.** Expose pending local opens, incoming requests, application acceptance/refusal, and peer confirmation/refusal. A ready socket/stream is not an accepted channel. Retain the requested channel type until its reply has been decoded, since confirmation does not repeat that type.
4. **Engine outputs are intents/events.** Shared engines request message transmission and application actions; bindings carry them over their own topology. Sending, being queued, transport acknowledgment, peer acceptance and application consumption are distinct events. Use bounded queues and preserve per-direction protocol ordering.
5. **Separate credit domains.** Implement ordinary SSH window accounting as an identifiable module in `connection`. QUIC byte availability and stream-count availability remain in `quic`. Do not add an `ignore_windows` switch; an alternative binding profile needs specified behavior and an explicit integration boundary.
6. **Security facts, not shared KEX.** `auth` consumes a session identifier/binding plus established protection and identity context. TCP obtains its identifier from the initial SSH KEX; QUIC derives its separate binding after the required bootstrap. Only normalize these downstream facts at the driver/auth boundary. Preserve binding provenance/version in diagnostics. Do not replace this with a fixed 32-byte generic “H”.
7. **Policy remains external to mechanism.** A server-side admission callback may refuse a requested channel independently of transport resources. Host trust, signature validity and user authorization are separate decisions. Filesystem reads, interactive trust prompts, launching processes, PTY allocation and outbound forwarding sockets belong in facade/application adapters.
8. **Transport-specific controls stay accessible.** Callers can configure and inspect TCP and QUIC separately. QUIC path/migration events do not trigger auth again or replace the logical SSH session. Connection loss is distinct from stream failure and SSH channel refusal.

RFC 4252 supplies the basis for sharing the downstream authentication engine: it receives a lower-layer identifier, and public-key authentication includes that value as an SSH string in the signed input. This supports a common consumer; it does not establish the security of the proposed QUIC construction. [RFC 4252 §§1, 7](https://www.rfc-editor.org/rfc/rfc4252.html#section-7).

### 2.3 Repository layout and staged creation

Use `doc/design.md`, `doc/decisions.md`, `doc/channel-matrix.md` and `doc/draft/` when creating the actual repository. Port the current ledger and audit into them; do not let copied historical hypotheses become normative requirements. `AGENTS.md` should instruct implementation agents to stop at unresolved wire decisions, record conflicts, and keep shared engines independent of networking.

| Stage | Create or implement | Completion evidence |
|---|---|---|
| A | Workspace metadata, documentation and instructions; `wire` + `connection`. Start with primitives and the opening lifecycle. | Reviewed golden message fixtures, bounded malformed-input cases, asymmetric channel IDs, simultaneous opens and acceptance/refusal state tests. |
| B | `keys`, then `auth` as real key and authentication work begins. | Exact signature-input fixtures; distinct host-trust and user-authorization behavior. |
| C | `tcp` and public `tatami` client/server modules and binaries. | Explicit OpenSSH feature/algorithm subset, then actual client/server interoperability in both directions. |
| D | `quic`, once its bootstrap/binding/record/opening profile is documented. Small isolated capability probes can precede a complete binding. | Basic authentication/channels followed by ordering, flow-control, reset and migration tests. |

The root of a virtual Cargo workspace does not itself supply an integration-test package. Put executable interoperability tests under a package such as `crates/tatami/tests/`, with helper modules/subdirectories, or later add a real test-only package. A root `tests/` directory can hold fixtures and scripts, but merely placing `.rs` files there will not create a test harness.

No license, MSRV, async runtime, TLS/QUIC backend or cryptographic algorithm set has been selected in this checkpoint. These are routine repository choices to resolve when scaffolding; backend selection must verify exporter, raw-key verification and migration capabilities against the then-current implementation. Do not represent dependency support as already proven.

## 3. RFC 4254 opening audit

### 3.1 Classification matrix

Classes are **1** unchanged semantics, **2** mapped to a QUIC mechanism, **3** advisory under the binding, and **4** retained with no independent effect. `P1`/`P2` below mean *proposed* classes, not accepted decisions; `U` means unresolved and is a status rather than a fifth semantic class. Retaining a field in the codec does not select its runtime treatment. No opening field currently has a defensible class-3 or class-4 recommendation.

The baseline fields and message numbers come from [RFC 4254 §§5.1, 9](https://www.rfc-editor.org/rfc/rfc4254.html#section-5.1). QUIC comparisons and recommendations are the design analysis of this checkpoint.

| Message / field | SSH purpose | QUIC analogy and equivalence | Proposed treatment and implications |
|---|---|---|---|
| `CHANNEL_OPEN` / byte 90 | Request admission. | Stream creation offers transport resources, not application acceptance. | **P1:** keep the request; do not emit an accepted-channel event on stream creation. |
| `OPEN.channel_type` / string | Select channel semantics. | No equivalent. | **P1:** retain extensible type name; keep unknown names available for refusal. |
| `OPEN.sender_channel` / uint32 | Opener's local ID. | QUIC stream ID has different scope and lifecycle. | **P1:** retain; associate separately with the stream. |
| `OPEN.initial_window_size` / uint32 | Opener's receive credit. | QUIC byte credit is not automatically equivalent. | **U:** retain in codecs; evaluate classes 1–4 during the flow-control audit. |
| `OPEN.maximum_packet_size` / uint32 | Opener's packetization bound. | QUIC has no corresponding application-message bound. | **P1**, exact accounting **U**: preserve the directional limit separately from record caps. |
| `OPEN.type_specific_data` / tail | Opening parameters. | No equivalent. | **P1:** preserve a bounded tail; avoid baking all channel types into the generic parser. |
| `CHANNEL_OPEN_CONFIRMATION` / byte 91 | Accept admission. | A QUIC ACK/readiness event cannot express this decision. | **P1:** retain explicit acceptance before opener use. |
| `CONFIRMATION.recipient_channel` / uint32 | Correlate pending request. | A stream locates an attempted association, not all SSH state. | **P1:** validate against the pending local ID. |
| `CONFIRMATION.sender_channel` / uint32 | Acceptor's local ID. | No equivalent endpoint-local namespace. | **P1:** record the peer ID independently. |
| `CONFIRMATION.initial_window_size` / uint32 | Acceptor's receive credit. | Same non-equivalence as OPEN. | **U:** resolve consistently with OPEN under AQ-016. |
| `CONFIRMATION.maximum_packet_size` / uint32 | Acceptor's packetization bound. | No equivalent application-message bound. | **P1**, exact accounting **U**: do not merge opposite-direction limits. |
| `CONFIRMATION.type_specific_data` / tail | Acceptance parameters. | No equivalent. | **P1:** interpret using saved pending-open type; confirmation does not repeat it. |
| `CHANNEL_OPEN_FAILURE` / byte 92 | Refuse admission. | Stream interruption is not an SSH refusal. | **P1:** preserve refusal as a distinct outcome. |
| `FAILURE.recipient_channel` / uint32 | Correlate refused request. | Not replaced by a stream reset. | **P1:** match and retire the pending attempt. |
| `FAILURE.reason_code` / uint32 | Machine-readable category. | QUIC error numbers have different semantics. | **P1:** retain known and extension values. |
| `FAILURE.description` / string | UTF-8 diagnostic. | No equivalent. | **P1:** preserve; display policy is separate from protocol classification. |
| `FAILURE.language_tag` / string | Diagnostic language. | No equivalent. | **P1:** retain; no justification for a new no-op rule. |
| Channel transport multiplexing | Route channel traffic. | QUIC streams supply an appropriate transport mechanism. | **P2:** associate channels with streams; this does not require removing SSH IDs. |

For example, after A opens with sender ID 7 and B confirms with recipient 7/sender 12, A addresses later messages to 12 and B to 7. That pair associates with one full QUIC stream ID. A simultaneous B-originated open can independently use local number 7. Avoid keys that treat a peer number as part of the same namespace as a local number.

The refusal constants are 1 = administratively prohibited, 2 = connect failed, 3 = unknown channel type, and 4 = resource shortage. Preserve the numeric extension space. Local inability to obtain QUIC stream credit must not be reported as if the peer sent reason 4. [RFC 4254 §5.1](https://www.rfc-editor.org/rfc/rfc4254.html#section-5.1).

### 3.2 Opening placement remains a real design fork

Neither option below is selected. In both, application admission remains explicit. A stream-type/bootstrap rule must distinguish channel streams from control or future extension streams.

| Concern | Handshake on channel stream | Handshake on control stream |
|---|---|---|
| Opening sequence | First SSH record is OPEN; first responder SSH record is CONFIRMATION or FAILURE. | Opening messages carried in bounded control records; bind them explicitly to a full stream ID or defined token. |
| Association | Physical stream provides an association anchor; validate the SSH IDs. | Requires a binding declaration/preface and an association state machine. |
| Responder data ordering | Queue confirmation before channel data on the same sending direction. | Data may arrive before confirmation; withhold application delivery until acceptance is known. |
| Connection-level dependencies | Must explicitly synchronize relevant global-control state. | Preserves order for relevant messages sharing the same control-stream direction. |
| Independent progress | Channel attempts can progress independently. | All opening records share control-stream ordering and loss delays. |
| Stream visibility | Transmitting OPEN makes the stream visible. | Writing a stream ID inside control data does not itself open the QUIC stream. |
| Refusal and teardown | Preserve delivery of the failure record before graceful retirement. | Define failure/termination precedence if they arrive in opposite order. |

Do not rely on “the next observed stream” as an association rule. QUIC stream IDs encode initiator/direction, have a wider range than SSH channel numbers, are not reused, and higher streams can imply lower streams have opened. A lower inferred stream must not create an accepted SSH channel. [RFC 9000 §§2.1–2.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1).

For control-stream opening, a bounded binding preface is one possible way to make a newly referenced stream observable and correlate it. It is not yet a chosen wire encoding. Do not assume a library permits writing to a peer-initiated stream before that stream has been observed. Check direction, initiator, duplicate declarations, late declarations, refused attempts, and ID reuse.

For channel-stream opening, the proposed rule is that the opener waits for confirmation before ordinary channel use. The responder can queue confirmation followed by data; no extra acceptance acknowledgement is automatically required. Define what to do with unexpected early channel records rather than allowing unbounded buffering.

**Concrete ordering counterexample:** remote-forwarding cancellation permits incoming channel opens until its reply arrives. If OPEN moves to an independent stream, an earlier open can arrive after that reply. A fence, generation rule, or explicitly changed semantics is needed; retaining message bytes alone does not preserve the relationship. Control-stream opening helps when OPEN and the cancellation reply share a sending direction, but it does not solve every dependency. X11 permission originates on an existing channel, so new X11 channels can still have a cross-stream authorization dependency. [RFC 4254 §§6.3, 7.1](https://www.rfc-editor.org/rfc/rfc4254.html#section-7.1).

### 3.3 Framing, identity, limits and refusal

**Bounded messages:** keep common opening fields and their bounded opaque tail in `wire`. SSH primitive string lengths do not make every extension tail universally self-delimiting. TCP gets message boundaries from its binary packet envelope; QUIC still needs a record rule. Receiving a QUIC STREAM frame is not receiving an application record. This is an inference about the proposed binding from the existing encodings and stream interface. [RFC 4251 §5](https://www.rfc-editor.org/rfc/rfc4251.html#section-5), [RFC 4253 §6](https://www.rfc-editor.org/rfc/rfc4253.html#section-6), [RFC 9000 §2](https://www.rfc-editor.org/rfc/rfc9000.html#section-2).

**Parameter identity:** forwarding destination/originator addresses and ports remain application opening parameters. Do not substitute the current QUIC peer address for them: forwarding provenance and a migrating transport endpoint are different information. Keep unknown channel names and supported extension payloads available to the admission handler.

**Limits:** both peers advertise receive-side parameters. If SSH windows remain enforced, a sender must satisfy SSH credit and the independently enforced QUIC limits. Stream credit counts encoded stream bytes; connection credit and stream-count limits add distinct restrictions. Neither an initial window nor a maximum-packet field can simply be copied into an arbitrary QUIC limit. [RFC 9000 §§4.1, 4.6](https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1).

A proposed resource design must let opening/control records progress even with zero SSH data credit. It also needs enough QUIC connection credit and bounded application consumption to keep the dedicated control stream usable when channel traffic is stalled. A separate control stream does not reserve connection credit automatically. Record-size caps, per-channel packetization limits, aggregate memory and pending-open limits should remain distinct configuration concepts.

**Refusal:** distinguish application refusal, local cancellation, stream transport failure and whole-connection failure. Normal refusal should preserve OPEN_FAILURE before retiring stream resources under a defined procedure. Resetting the sending direction can interrupt pending data delivery, so “write the failure and immediately reset” is not a reliable refusal protocol. By contrast, FIN queued after the complete failure record preserves the ordered delivery of preceding bytes; no application acknowledgement is needed merely to queue FIN. Graceful and abortive retirement need separate rules. [RFC 9000 §3.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-3.2).

Preserve received diagnostic bytes; perform terminal-safe rendering if displayed. Do not equate optional display with class-3 semantics. [RFC 4251 §9.2](https://www.rfc-editor.org/rfc/rfc4251.html#section-9.2).

### 3.4 Errata to carry into the next audit

The primary errata check found a material follow-up issue: **verified EID 3878** changes §5.2 window debit to include the SSH string length field. Its explanatory notes also discuss extended-data behavior in a way that needs careful reconciliation with the published shared-window text. Do not implement a casual “data bytes only” rule from memory. In the next audit, distinguish corrected RFC text, deployed implementation behavior, and the eventual QUIC binding rule. [RFC 4254 erratum 3878](https://www.rfc-editor.org/errata/eid3878).

**Verified EID 6850** corrects the reason-code allocation paragraph to refer to CHANNEL_OPEN_FAILURE. This supports treating refusal codes as their own extensible field rather than QUIC stream errors. [RFC 4254 erratum 6850](https://www.rfc-editor.org/errata/eid6850).

The precise interpretation of maximum-packet-size remains AQ-029. It is a separate issue from the window-debit correction; this checkpoint does not claim the erratum resolves packetization or establishes QUIC credit equivalence.

## 4. Architecture conflicts and their resolution boundaries

| Potential conflict | Consequence | Proposed boundary / remaining decision |
|---|---|---|
| Preserved channel messages treated as complete framing | Unknown type-specific tails cannot always be delimited on a byte stream. | `wire` accepts bounded payloads; `quic` specifies records under AQ-018. TCP retains its genuine transport packet envelope. |
| A generic `open_stream()` returns a usable SSH channel | Skips application permission, type negotiation and peer refusal. | `connection` owns pending-open states; binding stream admission is separate. |
| SSH IDs aliased to QUIC stream IDs | Conflates two endpoint-local namespaces with one transport stream and constrains lifetime/reuse. | Keep distinct identifiers and an explicit association registry in `quic`. |
| Every connection event processed in global arrival order | QUIC supplies no such order across independent streams. | AQ-027 defines dependencies and synchronization; the driver must not infer causality from callback arrival order. |
| Finalizing where OPEN is sent before analyzing globals | Can introduce races with forwarding authorization and cancellation. | Keep both channel-first and control-first layouts as candidates; see audit. |
| Common flow-control counter | Equates application data credit with all stream bytes, and misses connection/stream-count limits. | Keep SSH window state and QUIC credit separate; mapping is AQ-016, not an API convenience. |
| Resetting the sending direction carrying an SSH refusal | Can discard the intended refusal record or conflate application and transport errors. | Keep graceful FIN after the complete record distinct from reset; define cleanup under AQ-017/AQ-028. |
| Shared security type named `ExchangeHash` | Forces the exporter construction to impersonate SSH KEX. | Share identifier bytes plus security facts only at userauth input; preserve derivation ownership. |
| Treating raw TLS key bytes as an SSH key blob | Breaks familiar key comparison even when the underlying public key is the same. | `keys` performs validated algorithm-specific conversions; peer trust policy uses the intended identity encoding. |
| “ALPN optional” implemented as unrestricted absence | Violates QUIC's authenticated negotiation requirement unless an alternative is defined. | Keep configuration but require authenticated protocol agreement; AQ-019 remains open. |
| Session-binding work placed after usable QUIC userauth | Risks authenticating with a placeholder identifier. | A defined, reviewed experimental construction gates authenticated QUIC operation; later refinement is separate. |
| Root test directories mistaken for runnable Cargo tests | Creates apparent coverage with no executable harness. | Place tests in a package or explicit test-only workspace member. |

The raw-key concern follows from TLS raw keys using DER `SubjectPublicKeyInfo`; it is an encoding conversion problem as well as a trust-policy problem. Preserving the familiar SSH key identity requires validating the underlying algorithm and public-key parameters, not hashing arbitrary TLS bytes and assuming the result matches SSH. [RFC 7250 §3](https://www.rfc-editor.org/rfc/rfc7250.html#section-3).

### 4.1 Corrections to older research notes

**ALPN:** RFC 9001 requires authenticated protocol negotiation in the cryptographic handshake. ALPN is required unless another mechanism supplies it. A configured UDP port alone does not establish that property. Keep the configurable deployment intent; do not assume omission is automatically valid. No ALPN wire value is selected here. [RFC 9001 §8.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-8.1).

**Exporter terminology:** RFC 9266 is titled *Channel Bindings for TLS 1.3*. Its named `tls-exporter` binding has fixed inputs: label `EXPORTER-Channel-Binding`, empty context and 32 output bytes. A Tatami-specific label/context would use the TLS exporter mechanism but would not be that exact registered binding. The choice remains open. [RFC 9266 §§2, 4](https://www.rfc-editor.org/rfc/rfc9266.html#section-2).

**Transcript precision:** the regular TLS 1.3 exporter secret is bound through the server Finished, rather than indiscriminately to every later TLS/application message. ALPN is already within the relevant handshake transcript. SSH identification data sent afterwards needs explicit treatment. Do not substitute an early exporter or resumption secret, and do not put those secrets into a public session-context object. [RFC 8446 §§7.1, 7.5](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5).

## 5. Draft progress, validation and next handoff

The historical checkpoint reports that Draft 00 Sections 1–6 were established conceptually. Their actual prose is not present as a complete separate draft in the inputs read for this task; this checkpoint does not claim to have revised unseen text. Section 7 bootstrap remains design work. This audit supplies material for Sections 9–11, with session-binding and userauth dependencies in Sections 8 and 12. No new normative wire specification or submitted Internet-Draft is claimed.

### Proposed design prose for the future channel-opening section

> In the architecture being investigated, a QUIC stream carries the SSH messages associated with a channel. Allocation of the stream does not itself establish that channel. The opening exchange continues to express the requested channel type and the receiving endpoint's acceptance or refusal. The binding must specify how this exchange is associated with the stream and how its dependencies on connection-level state are ordered. This draft has not yet selected that association procedure or the treatment of SSH channel credit.

This paragraph is editorial scaffolding, not a normative definition. Keep the open issues adjacent when incorporating it into a draft.

### Next concrete work

1. **Implement the first transport-independent slice:** create the documented workspace with `wire` and `connection`, encode/decode the three opening messages against bounded payloads, and implement pending/accepted/refused state with distinct local/peer IDs. Keep optional channel-type tails intact. Do not choose a QUIC record format implicitly.
2. **Continue the protocol matrix:** audit WINDOW_ADJUST, DATA and EXTENDED_DATA, including extended-data accounting and maximum-packet-size interpretation; then EOF/CLOSE and REQUEST/SUCCESS/FAILURE. Use the four classifications, leaving unresolved items explicitly unclassified.
3. **Resolve channel opening and cross-stream ordering together:** evaluate AQ-026 against forwarding and authentication traces under AQ-027. Only then select an experimental wire profile and write its association, error and resource rules.
4. **Before authenticated QUIC operation:** specify bootstrap, application protocol agreement, regular-exporter construction, trust mapping and bounded records. A placeholder binding or a test-only bypass must never be presented as working authentication.
5. **Maintain both workstreams:** codec/state-machine implementation can proceed while protocol analysis continues. Record any new binding assumptions before they become implementation defaults.

### Validation planned for implementation, not claimed as executed

| Concern | Meaningful evidence |
|---|---|
| Message codecs | Hand-derived wire fixtures; unknown type tails; malformed/truncated lengths and configured record limits. |
| Opening state | Both endpoints opening concurrently; distinct sender numbers; correct confirmation/failure correlation; duplicate/late responses and stale handles. |
| Limits | Directionally different windows and maximum-packet values; zero credit; refused opens; bounded pending queues. |
| QUIC association | Stream appears before/after control declaration; duplicate association; wrong direction or ID; stream admission blocked; reset while pending. |
| Ordering | Confirmation before responder data; auth/forwarding dependencies under artificial cross-stream reordering; stdout/extended-data ordering without assuming PTY separation. |
| Interoperability | Tatami client ↔ OpenSSH sshd; OpenSSH ssh ↔ Tatami server; Tatami ↔ Tatami over TCP and over QUIC, with explicit supported feature sets. |
| Migration | Same QUIC connection, SSH identifier, channel and PTY across path changes; negative test for actual connection death without automatic resurrection. |

This task performed document and source review only. It did not run Rust tests, demonstrate interoperability, or prove the provisional QUIC mapping. The useful result is a concrete architecture that allows implementation to start while keeping the unresolved protocol choices visible.

---

# Historical checkpoint (preserved)

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

---

# New architectural direction: HTTP/3-inspired QUIC mapping

The HTTP/2 -> HTTP/3 transition provides a useful architectural precedent. Tatami should not be framed as simply tunneling RFC 4254 SSH packets through QUIC. Instead, preserve the externally meaningful SSH semantics while replacing TCP-era transport mechanisms with native QUIC mechanisms where the mapping is sound.

A strong working model is:

```text
                         QUIC connection
                               │
              ┌────────────────┼────────────────┐
              │                │                 │
       SSH control stream   SSH channel       SSH channel
              │              stream 1          stream 2
              │                │                 │
       identification          │                 │
       exchange +              data              data
       connection-level
       SSH semantics
```

This is analogous in spirit to HTTP/3's use of a dedicated control stream plus independent request streams and other specialized QUIC streams. It is a design precedent, not a requirement to copy HTTP/3's exact wire format.

## Identification exchange and session binding

The SSH `SSH-2.0-...` identification exchange needs explicit treatment. In conventional SSH, the client and server identification strings are outside the binary packet protocol and are inputs to the RFC 4253 exchange hash `H`.

For SSH-over-QUIC, the working direction is to retain the familiar SSH identification exchange on the SSH control stream, but not attempt to reconstruct the RFC 4253 DH-based `H`. Instead, the TLS exporter/session-binding construction should explicitly bind the SSH/QUIC session to the identification exchange and other explicitly defined SSH/QUIC context.

Conceptually:

```text
SSH identification exchange
        │
SSH/QUIC negotiation/context
        │
        ├── client identification
        ├── server identification
        └── other explicitly defined context
                  │
                  ▼
          TLS exporter
                  │
                  ▼
       SSH/QUIC session binding
```

The exact exporter label, context, output length, and userauth-signature implications remain open design questions.

## SSH flow control versus QUIC flow control

SSH RFC 4254 channel windows are a major example of TCP-era/application transport machinery that may be redundant when SSH is bound directly to QUIC. SSH has per-channel windows and `SSH_MSG_CHANNEL_WINDOW_ADJUST`; QUIC already provides stream-level and connection-level flow control.

The preferred direction is therefore to investigate a semantic mapping rather than blindly carrying SSH window messages inside channel streams:

```text
SSH channel
     │
     │ conceptual flow-control semantics
     ▼
QUIC stream flow control
```

This follows the architectural lesson of HTTP/3, where HTTP/2 flow-control mechanisms that duplicate QUIC capabilities are not simply tunneled through QUIC.

However, this is not yet a protocol decision. RFC 4254 also carries channel parameters such as initial window size and maximum packet size, and SSH's observable channel semantics must be preserved. The SSH/QUIC binding must determine exactly which parameters remain meaningful and how they map to QUIC.

Important candidate mappings to investigate:

| SSH concept | Possible SSH/QUIC treatment |
|---|---|
| SSH channel | QUIC bidirectional stream |
| channel window | QUIC stream flow control |
| connection-wide resource limit | QUIC connection flow control |
| `SSH_MSG_CHANNEL_WINDOW_ADJUST` | potentially eliminated/translated rather than transmitted |
| `SSH_MSG_CHANNEL_DATA` | channel-stream data |
| `SSH_MSG_CHANNEL_EXTENDED_DATA` | channel-stream data with SSH-level type semantics, exact encoding TBD |
| `SSH_MSG_CHANNEL_EOF` | potentially related to QUIC FIN, but semantic equivalence must be demonstrated |
| `SSH_MSG_CHANNEL_CLOSE` | SSH-level close semantics; relationship to QUIC stream termination TBD |
| maximum SSH packet size | likely remains relevant to SSH framing; exact role TBD |

Do not assume a one-to-one mapping between SSH EOF/CLOSE and QUIC FIN/RESET/STOP_SENDING. These have related but not necessarily identical semantics.

## Control-stream hypothesis

The current strong candidate is that SSH-over-QUIC has a dedicated QUIC stream for SSH connection-level protocol state. It should be investigated as the home for:

- the SSH identification exchange;
- SSH/QUIC negotiation or capability information, if required;
- connection-level SSH protocol messages such as global requests and their responses;
- any other SSH state that cannot naturally be associated with an individual channel.

The exact stream direction, stream type, bootstrap rules, and whether additional unidirectional streams are needed remain open.

## Architectural principle

Add the following principle to the design plan:

> **Preserve SSH's externally meaningful semantics; replace underlying transport mechanisms with native QUIC mechanisms where QUIC provides an appropriate equivalent. Do not tunnel TCP-era SSH transport machinery through QUIC merely for the sake of byte-for-byte similarity.**

This makes the Tatami design philosophy closer to the HTTP/3 transition: an application protocol is mapped onto QUIC rather than merely encapsulated inside it.

## New design ledger entries

- **D-013 — QUIC-native SSH stream multiplexing.** SSH-over-QUIC uses QUIC native stream multiplexing as a primary design hypothesis. A dedicated SSH control stream is paired with independent QUIC streams associated with SSH channels. The binding should preserve SSH semantics while using QUIC transport primitives where appropriate.
- **D-014 — HTTP/3-inspired transport mapping principle.** Preserve externally meaningful SSH semantics, but replace SSH/TCP transport mechanisms with native QUIC mechanisms where an appropriate semantic mapping exists. Do not tunnel redundant transport machinery solely for compatibility with the old wire encoding.
- **D-015 — SSH identification remains explicit.** The SSH `SSH-2.0-...` identification exchange remains part of the SSH-over-QUIC protocol bootstrap and must be explicitly bound into the replacement session-binding construction; the design should not attempt to reproduce RFC 4253's DH-based `H`.

New open questions:

- **AQ-015 — SSH/QUIC control-stream design.** Determine which SSH protocol elements belong on a dedicated control stream, including the identification exchange and connection-level SSH messages.
- **AQ-016 — SSH/QUIC flow-control mapping.** Determine whether RFC 4254 channel windows and `SSH_MSG_CHANNEL_WINDOW_ADJUST` should be carried over QUIC, translated into QUIC stream flow control, or otherwise represented, while preserving observable SSH channel semantics.
- **AQ-017 — SSH/QUIC stream termination mapping.** Determine the relationship between SSH EOF/CLOSE semantics and QUIC FIN/RESET/STOP_SENDING.
- **AQ-018 — SSH channel-stream framing.** Determine whether channel streams carry ordinary SSH channel messages, a reduced SSH representation, or another precisely specified mapping, including `CHANNEL_DATA`, `CHANNEL_EXTENDED_DATA`, channel requests, and channel-open parameters.

---

# Internet-Draft-first versus implementation-first strategy

The project should explicitly consider writing a **design-level Internet-Draft before substantial implementation**, rather than treating the I-D as documentation written after the code.

The motivation is strong: the eventual goal is an Internet-Draft describing a standards-oriented way to bind SSH to QUIC. A draft written first can serve as an explicit protocol contract for the implementation and can substantially reduce accidental protocol drift between the implementation and the eventual specification.

However, the draft should not be treated as immutable. Implementation experience is expected to challenge the design. The recommended process is therefore:

```text
protocol research / design
          │
          ▼
   draft I-D (v0.x)
          │
          ▼
 implementation + tests
          │
          ├── confirms design
          │
          └── exposes problems / missing semantics
                    │
                    ▼
             revise I-D + ledger
                    │
                    ▼
             implementation
```

The initial I-D should specify the architecture and wire semantics sufficiently for an independent implementation, but should clearly mark experimentally motivated or provisional sections where the design is not yet validated.

The coding agent should receive the draft together with the design ledger. It should treat the draft as the current protocol specification, but must **not silently invent protocol behavior** where the draft is intentionally unresolved. Instead it should isolate unresolved questions behind interfaces, experimental features, tests, or explicit TODOs and report where implementation experience conflicts with the draft.

This approach is preferable to either extreme:

- **Code-first with no protocol specification:** risks implementation decisions becoming de facto protocol requirements and makes later I-D cleanup difficult.
- **Specification-first with no implementation feedback:** risks spending substantial effort specifying a protocol whose practical stream, flow-control, interoperability, or library constraints have not been tested.

The recommended compromise is a **design-first experimental I-D**, followed by implementation-driven revision.

## Proposed I-D development stages

1. **Architecture draft:** define the protocol model, security model, stream model, and relationship to RFC 4252/4253/4254 and QUIC.
2. **Wire-format draft:** specify control stream, channel stream association, bootstrap/identification exchange, session binding, and mappings for channel lifecycle and flow control to the degree needed for implementation.
3. **Reference implementation:** implement against that draft and create interoperability tests.
4. **Design revision:** record deviations, failed hypotheses, and necessary changes in the ledger and update the draft.
5. **Candidate I-D:** consolidate the experimentally validated protocol and include comparison with `draft-bider-ssh-quic`.

The first draft should deliberately distinguish **normative protocol requirements** from **implementation experiments** and **known open questions**.

---
# Checkpoint — 2026-09-13 — Before Section 7 design

## Working method / continuity requirement

The user explicitly requested frequent checkpoints so the design discussion can be resumed if conversation state is lost. Treat this file as the persistent continuity record. After each substantial design step, update the checkpoint with:

- decisions that have become firm;
- strong candidates that remain provisional;
- rejected alternatives and why, where useful;
- newly discovered open questions;
- the current I-D section/status;
- important RFC/web research findings;
- the next concrete task.

Do not silently promote a hypothesis into a protocol requirement.

## I-D progress checkpoint

Draft 00 has Sections 1–6 established conceptually:

1. Abstract
2. Introduction / scope
3. Goals and design principles
4. Terminology
5. Relationship to SSH and QUIC
6. Architectural model

The next section is **§7 Connection Bootstrap and SSH Identification**.

The immediate design work is to establish the bootstrap wire model before drafting detailed normative prose.

## Section 7 research checkpoint

RFC 4253 §4 says SSH works over an 8-bit-clean, binary-transparent transport and requires both endpoints to send an SSH identification string after the connection is established. The SSHv2 identification form is:

`SSH-protoversion-softwareversion SP comments CR LF`

The maximum length is 255 characters including CR LF. The portion before CR LF is used in the classic Diffie-Hellman exchange hash. After the identification string, conventional SSH begins the binary packet protocol. RFC 4253 also permits the server to send pre-identification lines that do not begin with `SSH-`.

For Tatami/QUIC, these facts create a deliberate design fork:

1. Preserve the SSH identification exchange as an explicit SSH-over-QUIC bootstrap element; or
2. replace it with a QUIC/TLS-native negotiation mechanism.

Current working direction remains (1): retain explicit SSH identification semantics, while binding the identifiers into the new SSH/QUIC session-binding construction rather than reconstructing the RFC 4253 DH exchange hash.

QUIC provides authenticated application-protocol negotiation through TLS/ALPN unless another authenticated mechanism is used. RFC 9001 §8.1 therefore makes ALPN a likely candidate for identifying the SSH-over-QUIC application protocol at the QUIC/TLS layer. This does **not** by itself answer whether the SSH `SSH-2.0-...` identification exchange should remain; those are separate protocol-layer questions.

QUIC stream IDs encode initiator and directionality. Client-initiated bidirectional streams are even; server-initiated bidirectional streams are odd; unidirectional streams use the other two ID forms. This is relevant to the eventual control-stream and channel-stream bootstrap rules.

## Section 7 provisional model

Strong candidate, not yet final:

```text
UDP / QUIC
    │
    ├── TLS 1.3 + authenticated ALPN
    │       └── identifies SSH-over-QUIC application protocol
    │
    ▼
QUIC connection established
    │
    ▼
SSH-over-QUIC control stream
    │
    ├── SSH identification exchange
    │       ├── client SSH-2.0-...
    │       └── server SSH-2.0-...
    │
    └── SSH/QUIC binding / connection-level negotiation
            │
            ▼
       SSH authentication + channels
```

Important: this is a **layering hypothesis**, not yet a final wire specification.

## New/open questions for §7

- AQ-019 — What exact ALPN identifier should identify SSH-over-QUIC? Is registration required or can an experimental/private-use identifier be used during implementation?
- AQ-020 — Is the SSH identification exchange mandatory in QUIC mode, and if so, must it be byte-for-byte RFC 4253 compliant apart from transport context?
- AQ-021 — How should RFC 4253's optional pre-identification server lines map to QUIC, if at all? They may be unnecessary because QUIC already has authenticated application negotiation.
- AQ-022 — Which endpoint opens the SSH control stream, and is its stream type/directionality fixed?
- AQ-023 — What event marks the transition from QUIC/TLS handshake completion to the SSH identification exchange? Must the application wait for handshake completion before opening the control stream?
- AQ-024 — Which bootstrap values must be included in the eventual SSH/QUIC session-binding context: ALPN, QUIC version, SSH identifiers, implementation-independent protocol version, negotiated capabilities, or other values?
- AQ-025 — How does the bootstrap model permit clean failure reporting when the peer speaks ordinary SSH over TCP/another protocol rather than SSH-over-QUIC?

## Current I-D section/status table

| Section | Subject | Status |
|---|---|---|
| 1 | Abstract | Draft 00 |
| 2 | Introduction / scope | Draft 00 |
| 3 | Goals / non-goals | Draft 00 |
| 4 | Terminology | Draft 00 |
| 5 | Relationship to SSH and QUIC | Draft 00 |
| 6 | Architectural model | Draft 00 |
| 7 | Connection bootstrap & identification | **Research / design in progress** |
| 8 | SSH/QUIC session binding | Major research question |
| 9 | QUIC stream architecture | Major design question |
| 10 | SSH channel mapping | Major design question |
| 11 | Flow control | Major design question |
| 12 | SSH authentication | Depends partly on §8 |
| 13 | Rekeying / key updates | Open |
| 14 | Migration / NAT rebinding | Strong objective |
| 15 | Resumption | Experimental/later |
| 16 | TCP compatibility | Important interoperability section |
| 17 | Implementation experience | Later |
| 18 | Interoperability testing | Later |
| 19 | Security considerations | Develop alongside protocol |
| 20 | Lessons learned | Later |
| 21 | Future standardization considerations | Later |
| 22 | IANA considerations | Determine during design |
| 23 | References | Maintain continuously |
| A | Comparison with `draft-bider-ssh-quic` | Appendix; optional |

## Next checkpoint trigger

Before making a firm decision about ALPN, control-stream direction, or exact identification/bootstrap encoding, research the relevant QUIC/TLS/SSH requirements and record the rationale here. Then draft §7 only after the wire behavior is sufficiently clear to avoid accidental protocol decisions.
---

# Checkpoint — 2026-09-13: SSH channel ↔ QUIC stream and preserved channel framing

The discussion following review of RFC 4254 identified an important semantic constraint on QUIC stream mapping.

## Key observation

SSH stdout and stderr are not separate SSH channels. For an interactive/session channel, normal output is carried by `SSH_MSG_CHANNEL_DATA`, while stderr is carried by `SSH_MSG_CHANNEL_EXTENDED_DATA` with the SSH extended-data type code for stderr. Both are messages belonging to the same SSH channel and therefore share the channel's message ordering and channel flow-control semantics.

Consequently, mapping stdout and stderr to independent QUIC streams would not automatically preserve their relative ordering. A sequence such as:

    CHANNEL_DATA           stdout "A"
    CHANNEL_EXTENDED_DATA  stderr "B"
    CHANNEL_DATA           stdout "C"
    CHANNEL_EXTENDED_DATA  stderr "D"

has an ordering relationship within the SSH channel that separate QUIC streams would not intrinsically preserve.

## Candidate architecture now favored provisionally

A more defensible architecture is:

    One SSH connection <-> one QUIC connection

    One SSH channel <-> one QUIC bidirectional stream

    SSH channel message framing is preserved within that QUIC stream.

In other words, the QUIC stream is the transport substrate for an SSH channel, rather than being declared semantically identical to the SSH channel byte/message protocol.

A dedicated QUIC bidirectional control stream remains a separate candidate/architectural component for SSH connection-level messages.

Conceptually:

    QUIC connection
    |
    +-- SSH control stream
    |      +-- connection-level SSH messages
    |
    +-- QUIC stream <-> SSH channel 0
    |      +-- CHANNEL_DATA
    |      +-- CHANNEL_EXTENDED_DATA
    |      +-- CHANNEL_REQUEST
    |      +-- CHANNEL_SUCCESS/FAILURE
    |      +-- CHANNEL_EOF
    |      +-- CHANNEL_CLOSE
    |
    +-- QUIC stream <-> SSH channel 1
    |      +-- same SSH channel message protocol
    |
    +-- ...

## Architectural rationale

This preserves the distinction between two layers of multiplexing:

- QUIC performs connection-level multiplexing and supplies independent ordered/reliable streams.
- SSH channel messages retain SSH application semantics within each channel stream.

This avoids inventing new mechanisms for stdout/stderr ordering and retains the SSH channel state machine, including channel data versus extended data, requests and replies, directional EOF, close, and channel-specific flow-control semantics.

The useful design statement is:

> QUIC streams provide transport concurrency; SSH channel messages provide application semantics.

Another useful formulation is:

> Each SSH channel is mapped to one QUIC bidirectional stream, while the SSH channel's message framing and semantics are preserved within that stream.

This is deliberately more precise than saying that a QUIC stream is semantically equivalent to an SSH channel.

## Burden of proof

The project should not reject more QUIC-native decompositions categorically, but the burden of proof should be on any transformation that removes or redistributes SSH channel message semantics. In particular, a design using multiple QUIC streams for stdout/stderr or other portions of one SSH channel would need to demonstrate preservation of all externally meaningful SSH behavior, including ordering, flow control, requests/replies, EOF, and close semantics.

## Control-plane observation

Retaining a dedicated control stream remains compatible with the one-channel/one-stream mapping. Connection-level SSH messages can remain on the control stream while channel-specific messages remain on the stream corresponding to their SSH channel. This gives QUIC native multiplexing between SSH channels without collapsing the SSH channel protocol itself.

## Important remaining design question

This is a strong provisional architectural direction, but it is not yet a final numbered design decision. The next research/design pass must examine the interaction among SSH channel flow control, QUIC stream flow control, SSH EOF/close semantics, channel request ordering, stream creation/termination, and the control-stream design. The goal is to establish whether the proposed mapping can be specified cleanly without either redundant transport machinery or changed SSH-observable semantics.

## Impact on prior decisions/open questions

- Prior D-013 (QUIC-native SSH stream multiplexing) should be revisited and refined rather than treated as final.
- Prior D-014 (replace SSH/TCP transport mechanisms with QUIC-native mechanisms where an appropriate semantic mapping exists) remains useful, but now has a stronger semantic-preservation test.
- The candidate mapping is compatible with the project's core goal: preserve externally meaningful SSH semantics while using QUIC for connection/stream transport concurrency.
- I-D sections 9 (QUIC stream architecture), 10 (SSH channel mapping), and 11 (flow control) remain design work, with this checkpoint providing their current architectural hypothesis.

## Suggested empirical validation

Interoperability/behavior tests should include deliberately interleaved stdout/stderr output, both with and without a PTY where meaningful, to establish the observable behavior of conventional SSH implementations and to ensure the QUIC binding does not inadvertently alter it.
