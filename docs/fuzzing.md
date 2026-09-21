# Fuzzing

Status: rounds 3–4, 2026-09-20. Coverage-guided libFuzzer harnesses exist for
every implemented protocol surface, including (round 4) the KEX/service/
EXT_INFO codecs, key and signature blobs, algorithm negotiation, AES-GCM
packet protection and the complete client handshake state machine. Nothing
here fuzzes the upstream TLS/QUIC stack, authentication or SFTP (see
[Future targets](#future-targets)); the QUIC diagnostic adapter is covered by
deterministic in-memory tests rather than a libFuzzer target (see
[QUIC](#quic-diagnostic-adapter)).

## Architecture

Two isolated Cargo workspaces under `fuzz/`, excluded from the production
workspace (`Cargo.toml` `exclude`), each with its own manifest, `[workspace]`,
lockfile, `fuzz_targets/`, committed `seeds/` and ignored `corpus/`,
`artifacts/`, `coverage/` and `target/` directories:

| Workspace | Crate under test | Features | Why separate |
|---|---|---|---|
| `fuzz/wire-core` | `tatami-wire` | defaults off, **no `alloc`** | Proves the allocation-free configuration; the harness is `std` but the library is not. `cargo tree -e features` in that directory shows `tatami-wire` with no features. |
| `fuzz/protocol` | `tatami-tcp` (`std,kex`), `tatami-keys` (`ed25519`), `tatami-connection`, `tatami` (`std,tcp,kex`), `tatami-wire` (`alloc`) | explicit | State machines, reports and owned helpers. `serde_json` and the harness-side crypto (`ed25519-dalek` with signing, `x25519-dalek`, `aes-gcm`, `sha2`, `rand_core`) are present only here, as independent oracles and as the fuzz "server". |

Harness dependencies (`libfuzzer-sys`, `arbitrary`, `serde_json`, the
harness-side crypto crates) never appear in any production `Cargo.toml`
beyond the versions the production lockfile already pins. Fuzz-support code (reference grammars,
models, byte assembly) lives in `fuzz/*/src/` and `fuzz_targets/`, not in the
libraries; no production type derives `Arbitrary`; no `cfg(fuzzing)` path
exists in `crates/`.

Both workspaces build release with `debug = 1`, `overflow-checks = true` and
`debug-assertions = true`, so integer overflow and internal assertions are
findings, not silent wraps.

## Tooling

One configuration source, `fuzz/toolchain.env`, is read by `scripts/fuzz.sh`
and `.github/workflows/fuzz.yml`:

| Key | Value | Meaning |
|---|---|---|
| `FUZZ_NIGHTLY` | `nightly-2026-09-01` | Dated nightly for CI builds with AddressSanitizer |
| `CARGO_FUZZ_VERSION` | `0.13.1` | cargo-fuzz release pinned in CI |
| `FUZZ_HOST_TRIPLE` | `x86_64-unknown-linux-gnu` | The only supported fuzzing host |
| `FUZZ_TIMEOUT_SECS` / `FUZZ_RSS_LIMIT_MB` | `2` / `1024` | libFuzzer per-input timeout and process RSS cap |
| `FUZZ_PR_SECONDS` / `FUZZ_SCHEDULED_SECONDS` | `20` / `300` | Campaign length per target |

The production MSRV (1.85) and stable CI are untouched. There is no root
`rust-toolchain` file and no script changes the global default toolchain.

### One-time setup

With rustup (the CI path):

```sh
. fuzz/toolchain.env
rustup toolchain install "$FUZZ_NIGHTLY" --profile minimal --component rustfmt,clippy,llvm-tools-preview
rustup run "$FUZZ_NIGHTLY" cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked
```

A C++ compiler (`clang++` or `g++`) is needed to build libFuzzer.

Without rustup (a distribution toolchain, as on the development machine):

```sh
cargo install cargo-fuzz --version 0.13.1 --root target/tools
export FUZZ_CARGO_FUZZ=$PWD/target/tools/bin/cargo-fuzz
```

`scripts/fuzz.sh` then uses the stable compiler with `RUSTC_BOOTSTRAP=1` and
`-s none`, because distribution toolchains ship no sanitizer runtimes. That
configuration still provides coverage guidance, overflow checks and debug
assertions, but **not** AddressSanitizer; the wrapper prints the effective
configuration on every command. Coverage reports work with the system
`llvm-profdata`/`llvm-cov` on `PATH` (or `LLVM_PROFDATA`/`LLVM_COV`).

## Commands

```sh
scripts/fuzz.sh list                       # targets, workspaces, seed counts
scripts/fuzz.sh lint                       # fmt --check and clippy -D warnings for fuzz code
scripts/fuzz.sh build                      # build both workspaces
scripts/fuzz.sh replay [TARGET...]         # run every committed seed once (-runs=0)
scripts/fuzz.sh smoke [SECONDS]            # build, replay, then a short run per target
scripts/fuzz.sh run tcp_observer -- -max_total_time=300 -max_len=131072 -timeout=2 -rss_limit_mb=1024
scripts/fuzz.sh reproduce tcp_observer fuzz/protocol/artifacts/tcp_observer/crash-…
scripts/fuzz.sh minimize tcp_observer fuzz/protocol/artifacts/tcp_observer/crash-…
scripts/fuzz.sh coverage tcp_observer      # instrumented run over seeds+corpus, llvm-cov report
```

Arguments after `--` are passed to libFuzzer verbatim (no `eval`). `run`
prepends `-timeout`, `-rss_limit_mb` and a per-target `-max_len` (4 KiB for
byte-oriented wire targets, 64 KiB for structured state targets, 512 KiB for
the TCP stream targets so the 64 KiB packet cap and aggregate budgets are
reachable); user arguments override them.

**Replay semantics, verified:** libFuzzer with `-runs=0` and a corpus
directory loads every file, executes each exactly once (`INFO: seed corpus:
files: N`, `Done N+1 runs` including the empty input), performs no mutation,
writes nothing into the seeds directory, and exits nonzero on any crash,
timeout or RSS violation. `replay` refuses to run a target with no committed
seeds.

## Targets, inputs and oracles

An oracle is a rule that detects wrong behaviour; "did not panic" is the
floor, not the oracle. Every target below has an independent reference
written from the specification or the documented contract, not a copy of the
library's code structure.

| Target | Workspace | Input | Oracles |
|---|---|---|---|
| `identification_content` | wire-core | raw bytes | Maximal-munch RFC 4253 §4.2 reference grammar: accept iff reference accepts; field slices equal reference slices (absent vs empty comments distinct); `as_bytes()` is the input; slices are sub-slices of the input; `classify_protocol_version`; each `IdentSyntaxError` implies its claimed property; `encode(parse(x)) == x` |
| `identification_encode` | wire-core | structured fields ≤ 300 B, capacity ≤ 600 | `encoded_len` = `4+p+1+s(+1+c)` iff valid; error variant in field order with exact `needed/available`; output buffer byte-identical to its pre-fill on any error; success bytes equal hand concatenation; parse-back yields the fields; fixed vectors (`SSH-2.0-tatami_0.1.0`) |
| `wire_primitives` | wire-core | op script ≤ 64 over a Reader on fuzz bytes and a Writer over a ≤ 1 KiB buffer | Per-read expected value/error computed from raw bytes (`Truncated{needed,available}`, `LengthOverflow{claimed,available}`); cursor moves exactly on success and not at all on error; `Vec` model of the writer after every op; `write_bool(true)` is `1`; `write_name_list` rejects the first invalid index; name-list iteration re-joins to the body, `len`/`contains` agree with linear scans |
| `wire_messages` | wire-core | first byte selects raw payload → all 8 decoders, or structured generation → hand assembly | Raw: exact `MessageError` agreement with an independent layout decoder, tail rules (OPEN/CONFIRMATION keep the remainder; the rest reject trailing bytes), re-encode reproduces payload with canonical booleans. Structured: library `encode` equals hand-assembled bytes (a little-endian sabotage of the assembler was confirmed to fail replay), decode returns the generated fields, then truncate/flip/append mutations with layout-derived expectations. KEXINIT: 16-byte cookie, ten distinct lists in slot order, `reserved` preserved, `empty_algorithm_lists` exact, markers only for the four exact names |
| `tcp_identification` | protocol | content + terminator + chunk schedule + limits | Independent line reader (LF/CRLF, `SSH-` classification, 255-with-terminator rule, prelude budgets, grammar, `2.0`/`1.99` policy) agrees on the step sequence under default and fuzz-chosen limits; all-at-once = byte-at-a-time = fuzz-chunked; `consumed` sums to the terminator offset; suffix bytes untouched; borrowed fields are sub-slices; `OwnedIdentification` lossless |
| `tcp_initial_packets` | protocol | raw stream with incremental delivery under caps {16, 64, 1024, 35000, 65536, 65532, 0, fuzz} + structured packets incl. the 65536-byte maximum | Every prefix: `decode_initial_packet` equals the reference (`NeedMore{total_len}`, exact error, slices); a 4-byte oversized claim is `TooLarge`, never `NeedMore`; proper prefixes never `Complete`; encoder alignment/min-padding/pad byte and no partial write on a 1-byte-short buffer; `InitialPackets` budgets hit at the reference index with equal counters |
| `tcp_probe` | protocol | generated server stream (prelude, identification, pre-KEX messages, KEXINIT with distinct lists and markers, junk) ± byte mutation, 8 configs incl. tiny budgets/caps, chunk schedule, EOF flag | Three drivers (all-at-once when it fits `room()`, byte-at-a-time, fuzz chunks) agree on events and terminal result except the chunk-dependent `unexamined_bytes` (must be 0 byte-at-a-time, ≤ all-at-once when chunked); `room()` respected; progress or error on a full buffer; monotonic stage; a 4096-step driver bound panics; terminal result stable across two extra `step()` calls; unmutated structured streams equal the sequential model including decoded proposal and anomalies; oversized single feed → exact `InputOverflow`, nothing copied |
| `tcp_observer` | protocol | as `tcp_probe`, client-side, plus banner-only, unexpected first bytes, client markers, `1.99`/LF-only, `SSH-1.5-` | Same driver equivalence; `UnexpectedInput.sample` is the fed prefix bounded by `unexpected_sample`, `truncated` exact, buffer cleared; banner-only ends right after the identification and never decodes a proposal; anomalies present and observation continues; `code()` from the closed seven-string set with an exhaustive match (no "authenticated"/"negotiated" state can exist) |
| `input_buffer` | protocol | op script ≤ 256 over `InputBuffer::new(cap ≤ 8192)` | `Vec` model after every op (`as_slice/len/is_empty/room/capacity`); push fails iff `len+n > cap` with exact `InputOverflow` and no partial append; boundary pushes room/room+1/0/cap+1; `consume(n)` only for `n ≤ len` (documented precondition); allocator capacity never asserted |
| `channel_opening` | protocol | ≤ 200 actions over `OpeningEngine` with small fuzz limits (tombstones 0–3) | Model keyed by local/peer numbers with opaque handle tokens (no slot/generation mirroring): counts and `phase(h)` for every handle ever issued after every action; each result/event/violation predicted; handles and wire local numbers never reissued; `LateReply` consumes the tombstone and changes nothing else; eviction → `UnknownRecipient`; `DuplicateReply`, `ReplyToIncoming`, `DuplicatePeerNumber`; `IncomingRefusedByLimit` with a queued `OpenFailure{4}`; `transport_lost` = one event per live channel, then empty with no outgoing; credits/tails verbatim including 0 and `u32::MAX`; every `Outgoing` round-trips through the wire codecs with exact length and fails with `InsufficientCapacity` at `n-1` |
| `json_values` | protocol | `Value` tree ≤ 64 nodes / depth 6, strings via `lossy_text`, `hex`, class-generated UTF-8 | `to_json()` byte-exact with an independent serializer; `serde_json` parses and equals an independent semantic conversion; tokenizer verifies key order and rejects raw bytes < 0x20, non-RFC escapes (incl. `\x`) and lone surrogates; `lossy_text == from_utf8_lossy`; `hex` lowercase, 2×len, decodes; `escape_bytes`/`quoted` printable ASCII and invertible |
| `observation_records` | protocol | all four `ListenerEvent`s with mutated untrusted fields ≤ 2000 B; budgets {0, 1, 64, 256, 1024, 2048, 4096, 65536, 262144, fuzz}; field bounds {0, 1, 8, 512, fuzz ≤ 4096} | Always a valid JSON object; `schema`, `event`, RFC 3339 `time`; `accepted_at` equals an independent civil-from-days formatter; both auth flags `false`; `stage`/`outcome`/`reason` from closed sets; `client_identification`/`messages`/`proposal`/`diagnostics` compared as expected values (`line_hex` decodes to the bounded prefix, `*_truncated` iff exceeded, directional lists distinct); `record_truncated` iff full > budget, then `messages: []`, `proposal: null`, strictly smaller; size bound below |
| `wire_kex_codecs` (round 4) | wire-core | first byte selects mpint read/write, `KEX_ECDH_INIT`/`REPLY`, `NEWKEYS`, `SERVICE_REQUEST`/`ACCEPT`, `EXT_INFO`; raw and structured paths | Reference decoders with exact `MessageError` incl. field names; RFC 4251 §5 canonical rule ("drop first byte ⇒ value changes") for `is_canonical`; `write_mpint_positive` equals the reference encoding, atomic on capacity failure, round-trips iff canonical; EXT_INFO count must fail before iteration when `count > remaining/8` (huge count in 12 bytes), `validate(max)` for max ∈ {0,1,8,64}, `server_sig_algs` name-list validity, count+1 mismatch, trailing bytes; all five RFC 4251 examples and both RFC 8731 mpint edge cases seeded |
| `key_blobs` (round 4) | protocol | raw bytes into the blob decoders, `HostKey::from_blob`, `Sha256Fingerprint::parse`; structured path from a fuzz-seeded Ed25519 signing key | Independent blob layouts; hand-built `ssh-ed25519` blob accepted; `of_blob` equals `sha2` over the hand blob and `Display` equals a harness base64 encoder (own strict 43-char decoder for the inverse); `verify_signature_blob` succeeds on the harness signature and fails exactly for signature/message bit flips, another key, `ssh-rsa` in either blob, a trailing byte, key length 31/33, signature length 63/65; `PinnedSha256` trusts iff fingerprints are equal; `NoTrustPolicy` never trusts |
| `tcp_negotiation` (round 4) | protocol | client and server KEXINIT lists from pools of real methods, unknown names, all six markers and empty lists; `ClientProposal::encode` round trip | Independent RFC 4253 §7.1 model: first client name in the server list with markers excluded; MAC skipped when the selected cipher is an AEAD; `none` compression; strict-KEX pairing only for the same spelling (mixed spellings never enable); `ext_info` iff the server offered `ext-info-s`; guess correctness = first real method and first host-key algorithm equal; exact `Result` incl. `Direction` and every `StrictKex` field; `ClientProposal::encode` equals hand assembly; `check_profile` |
| `tcp_gcm_packets` (round 4) | protocol | key/nonce from fuzz; sealed streams delivered under three chunk schedules; byte flips; truncation; huge/misaligned length claims; counters near `u64::MAX`; a 65 536-byte cap packet | Independent `Aes128Gcm` sealer in the harness (length prefix as AAD, padding to 16 with minimum 4, big-endian u64 nonce increment) agrees with `seal`; `open` round-trips payloads and counters; the four clear length bytes alone decide `TooLarge`/`TooSmall`/`Misaligned` (never `NeedMore`); any flipped byte → `TagMismatch`; truncated → `NeedMore`, never `Complete`; the buffer is byte-identical and no counter is spent on any failure; `CounterExhausted` exactly at the boundary. Characterised: a `BadPadding` rejection after a verified tag does spend one counter and is terminal |
| `tcp_handshake` (round 4) | protocol | a harness *server* (its own X25519, exchange hash, mpint conversion, Ed25519 signing, RFC 4253 §7.2 derivation and AES-GCM) generates one transcript per input: identification ± prelude, KEXINIT from pools with markers/strict spellings and sometimes a wrong guess, optional IGNORE/DEBUG/UNIMPLEMENTED at chosen points, correct or corrupted `KEX_ECDH_REPLY` (bad signature, wrong `K_S` algorithm, all-zero `Q_S`, trailing bytes), `NEWKEYS`, then protected `EXT_INFO`/`SERVICE_ACCEPT` (right or wrong service)/`DISCONNECT`/`KEXINIT` (rekey), optional protected byte flip, EOF; fuzz-chosen trust decision; deterministic client RNG | The harness predicts the `HandshakeOutcome` code for every scenario (strict violation iff strict negotiated and a disallowed message precedes NEWKEYS; `SignatureInvalid` iff corrupted; `HostNotTrusted` iff `Untrusted`, and then no NEWKEYS bytes in the client output; `NegotiationFailed` per the negotiation model; `Completed` iff all valid and the accepted service is `ssh-userauth`; `RekeyNotSupported` iff server KEXINIT after NEWKEYS; `TagMismatch` iff a protected byte flipped); `user_authenticated` always false; protected packet counts vs the model; `session_id` equals the harness hash; the client's protected output is decrypted with the harness keys and its message numbers checked against the modelled sequence — message 50 (`USERAUTH_REQUEST`) never appears; byte-at-a-time ≡ chunked; `room()` respected; bounded driver panics on livelock |
| `handshake_report_json` (round 4) | protocol | `tatami::client::handshake::Report` built from its public fields with mutated peer text and every `Completion` variant | `to_json` parses with `serde_json`; closed key set at every level with a fixed shape (`null`, never absent); closed `outcome_code`/phase/error-code sets; `user_authenticated` and `rekey_supported` false; fingerprint text form; `write_text` invariants (escaped peer text, fixed trailing lines) |

Entry points covered by these targets or by deterministic tests:

| Entry point | Where exercised |
|---|---|
| `tatami_wire::ident::{Identification::parse, encode, encoded_len, classify_protocol_version, OwnedIdentification}` | `identification_content`, `identification_encode`; owned helper in `tcp_identification` and unit tests |
| `tatami_wire::primitives::{Reader, Writer}`, `namelist::NameList` | `wire_primitives` |
| `tatami_wire::{kexinit, transport, channel}::*::{decode, encode}`, `classify_kex_name`, reason-code tables | `wire_messages` |
| `tatami_tcp::ident::{IdentificationReader, build_identification, starts_identification}` | `tcp_identification`, `tcp_probe`, `tcp_observer`, `tests/ident_characterization.rs` |
| `tatami_tcp::packet::{decode_initial_packet, encode_initial_packet}`, `initial::{InputBuffer, InitialPackets}` | `tcp_initial_packets`, `input_buffer` |
| `tatami_tcp::probe::Probe`, `observer::Observer` | `tcp_probe`, `tcp_observer` |
| `tatami_wire::primitives::{read_mpint, write_mpint_positive}`, `kex::*`, `transport::{ServiceRequest, ServiceAccept}`, `ext_info::*` | `wire_kex_codecs` |
| `tatami_keys::{blob, ed25519::HostKey, fingerprint, trust::PinnedSha256}` | `key_blobs`, unit tests with RFC 8032 vectors |
| `tatami_tcp::negotiate::{negotiate, ClientProposal}` | `tcp_negotiation` |
| `tatami_tcp::gcm::AeadDirection::{seal, open}` | `tcp_gcm_packets` |
| `tatami_tcp::transcript::*`, `handshake::ClientHandshake` | `tcp_handshake` (plus deterministic scripted-I/O tests and the OpenSSH interoperability tests in `tatami-tcp/tests/openssh_handshake.rs`) |
| `tatami_tcp::io::handshake::run_handshake` | scripted `Conn`/`Clock` tests; OpenSSH fixture; CLI tests (`tatami/tests/handshake_cli.rs`) |
| `tatami::client::handshake::Report::{to_json, write_text}` | `handshake_report_json` |
| `tatami_quic::diag::*`, `tatami::quic_diag::*` | deterministic in-memory endpoint pairs and loopback UDP tests (`tatami-quic/tests/*.rs`, `tatami/tests/quic_*.rs`); not a libFuzzer target (see below) |
| `tatami_connection::opening::OpeningEngine`, `Outgoing::encode` | `channel_opening` |
| `tatami::json::Value`, `tatami::text::{escape_bytes, quoted}` | `json_values` |
| `tatami::server::observe::{Encoder, observation_record, summary_record, rfc3339}` | `observation_records` |
| `tatami_tcp::io` drivers (probe and listener) | deterministic scripted I/O tests (below), loopback tests, CLI tests |
| `tatami::client::probe::{run, Report::write_text}`, `server::observe::{prepare, run_jsonl}`, CLI parsing | `crates/tatami/tests/{cli,observe_cli}.rs` only (socket/process bound; not fuzzed) |

### Record-size policy (characterised, not assumed)

`server::observe::Encoder` re-emits an observation without `messages` and
`proposal` when the full record exceeds `max_record_bytes`. Only `line_hex`
and diagnostics text are bounded by `max_field_bytes`; the identification
line, comments, version tokens and `server_identification` are emitted in
full. The `observation_records` target derives and checks the bound

```text
len ≤ 1100 + 6·(server_ident + line + proto + soft + comments) + 2·min(line, F) + 12·F + detail
```

Constructed worst cases (F = `max_field_bytes`, a 253-byte identification
line is the default TCP maximum):

| F | raw line | truncated record bytes |
|---|---|---|
| 512 (default) | 253 | 12 185 |
| 512 | 2000 | 33 693 |
| 4096 | 253 | 55 193 |
| 0 | 253 | 5 561 |

So the truncated form always fits when `max_record_bytes ≥ 12 432` under the
default field bound and TCP line limit; the default budget of 256 KiB has
21× headroom. Budgets of 4096 and below can be exceeded by the truncated
form (seed `observation_prodlike_exceeds_4096`); in that case the record is
still valid JSON with `record_truncated: true`. This is documented behaviour,
not a hard cap; an operator choosing a tiny budget gets honest output rather
than truncated JSON.

## Seeds, corpora and artifacts

`fuzz/<ws>/seeds/<target>/` holds small, individually named regression and
deep-state fixtures (432 files across 18 targets, ~2 MB, including one 65 536-byte maximum
packet). Provenance: hand-constructed from RFC layouts by the harness authors;
the wire-core set is regenerable with `fuzz/wire-core/seeds/generate_seeds.py`.
No traffic captures, keys or credentials. Seeds named `regression_*` come from
minimized findings (see below). Evolved corpora (`corpus/`), crash artifacts
(`artifacts/`) and coverage data are ignored by Git; CI preserves corpora in a
bounded cache for trusted runs only and minimizes them with `cargo fuzz cmin`.

## Failure triage

On a crash, timeout or oracle failure libFuzzer writes an artifact under
`fuzz/<ws>/artifacts/<target>/`. Then:

1. `scripts/fuzz.sh reproduce TARGET ARTIFACT` (no mutation) and record: Git
   revision, `scripts/fuzz.sh` printed toolchain/cargo-fuzz/sanitizer line,
   lockfile, limits, target, failure category.
2. `scripts/fuzz.sh minimize TARGET ARTIFACT`.
3. Classify: harness bug (reference/model wrong) vs production bug.
4. For a production bug: fix, add an ordinary `#[test]` in the package that
   runs on stable/MSRV, copy the minimized input to
   `seeds/<target>/regression_<name>`, replay, resume.
5. Never catch panics, disable assertions, skip inputs or shrink coverage to
   get green.

### Findings this round

| Finding | Category | Resolution |
|---|---|---|
| `OpeningEngine::cancel` with `max_tombstones == 0` kept one tombstone (evict-before-push), so a late reply to the last cancelled number was `LateReply` instead of `UnknownRecipient` | production | Fixed (push then trim); regression test `zero_tombstones_forgets_cancelled_numbers_immediately`; seed `channel_opening/regression_zero_tombstones_late_reply` |
| `packet_ref::max_packet_length` underflowed for cap 0 in the `tcp_initial_packets` reference | harness | Fixed with `checked_sub` |
| Probe driver reported a write-phase deadline as `RunEnd::Io` while the listener reported the same case as `TimedOut` | production (adapter) | Unified to `RunEnd::TimedOut`; the write path now recomputes its timeout between partial writes; scripted I/O tests cover both |
| `handle_open_confirmation` did not reject a peer `sender_channel` already in use by another live channel | production (round-3 observation, fixed round 4) | `locate_reply`/`consume_reply` split; `DuplicatePeerNumber` rejected before any state change for live and late confirmations (tombstone kept); four regressions; the fuzz model now derives peer-number liveness from its own sets (`peer_number_live`) and asserts the invariant independently; seed `regression_duplicate_peer_number_on_confirmation` |
| Round-4 harness bugs (all fixed, none production): `wire_kex_codecs` expected the lazy EXT_INFO iterator to stop before yielding its terminal error; `tcp_gcm_packets` seeded a counter at `u64::MAX` in the general path; `tcp_handshake` model omitted that `kexinit_was_first_packet` is recorded before the KEXINIT body decodes (minimized input kept as `seeds/tcp_handshake/regression_malformed_kexinit_first_recorded`); `handshake_report_json` assumed optional keys are absent rather than `null` | harness | Fixed; oracle sabotage checks (little-endian assembler, mpint sign-byte rule, mixed strict spellings) each made replay fail as intended |

## Deterministic host I/O tests

High-throughput targets are in-process and free of sockets, clocks, sleeps
and subprocesses. The blocking adapters are exercised deterministically
through a narrow internal seam (`tatami_tcp::io::seam`: `Conn` and `Clock`
traits implemented by `TcpStream`/`SystemClock` and, under `cfg(test)`, by a
`ScriptedConn`/`VirtualClock` pair that consumes exactly the timeout the
driver requested and panics after 10 000 calls). Unit tests in `io.rs` and
`io/listener.rs` cover short writes, `Interrupted` retries without deadline
reset, trickling reads that cannot extend the deadline, EOF at a boundary vs
mid-line/mid-packet, `WriteZero`, deadline already passed before the first
write, deadline exhaustion inside a packet body, reads never exceeding
`min(chunk, room())`, stop requested mid-observation, and silent peers that
are waited for rather than spun on. Sink failure, capacity saturation and
requested stop at the listener level remain in `tests/observer_loopback.rs`
with real sockets and threads; libFuzzer does not explore thread schedules,
and none of this validates constant-time behaviour (there is no
cryptography yet). No `adapter_events` fuzz target was added: the scripted
seam is exercised by enumerated scenarios whose oracles are exact expected
timelines, which a mutation engine adds little to.

## QUIC diagnostic adapter

The QUIC/TLS handshake experiment (`tatami-quic` `diag`, behind
`quinn-backend`) is exercised by deterministic in-memory endpoint pairs
(`inmem::Pair`: two sans-I/O cores exchanging datagrams through `Vec` queues
under a virtual clock) and by loopback UDP tests: matching handshake,
wrong pin, ALPN mismatch, no listener (timeout), Retry/validation, the
exporter equality/inequality matrix and the raw-public-key path. No
libFuzzer target wraps it: the state that Tatami owns is a thin driver over
quinn-proto, and a mutation campaign over TLS records would be fuzzing the
upstream stack, which this project does not claim to do. Tatami's own
adapter states, deadlines and limits are covered by the enumerated tests.

## CI policy

`.github/workflows/fuzz.yml` (read-only `contents` permission):

- **push/PR:** install the pinned nightly and cargo-fuzz, `lint`, `build`
  (ASan), `replay` all seeds, then run every target for `FUZZ_PR_SECONDS`
  with `-seed=<run id>` and `-print_final_stats=1`; failure artifacts are
  uploaded; nothing uses `continue-on-error`; PR runs never read or write the
  corpus cache.
- **scheduled (03:17 UTC) / manual:** the same with `FUZZ_SCHEDULED_SECONDS`
  (or the dispatch input), evolved corpora restored from cache, minimized and
  saved.
- Job timeout 150 minutes; build cache keyed by nightly, cargo-fuzz version
  and lockfiles, separate from the corpus cache.

Ordinary `cargo test` never depends on nightly, cargo-fuzz or the corpora;
`scripts/check-workspace.sh` is unchanged apart from the identification
refactor's tests.

## What the evidence means

Four different kinds of evidence, none substituting for another:

- **Line/region coverage** (`scripts/fuzz.sh coverage`) says which code ran
  under the corpus. It says nothing about whether the results were right.
- **State coverage** is provided by seeds that reach deep states (proposals
  with markers, budget exhaustion, cancellation then late reply, truncated
  records) and by the model-based targets that visit state combinations.
- **Oracle strength** comes from the independent references and models
  above; each was sanity-checked by breaking it deliberately at least once
  during development (e.g. little-endian sabotage of the hand assembler).
- **Sanitizer checks** (ASan in CI) detect memory errors that safe Rust
  should exclude; locally, without a sanitizer runtime, overflow checks and
  debug assertions are the only extra instrumentation.

## Execution evidence (development machine)

Host: Fedora, `rustc 1.98.1` via `RUSTC_BOOTSTRAP=1`, cargo-fuzz 0.13.1,
sanitizer `none`, `-seed=1`. Round 3: `scripts/fuzz.sh smoke 20` after
building and replaying all 268 seeds:

| Target | 20 s execs | exec/s | cov | ft | corpus | crashes |
|---|---|---|---|---|---|---|
| identification_content | 5 884 399 | 280 209 | 161 | 413 | 112 | 0 |
| identification_encode | 2 011 006 | 95 762 | 224 | 471 | 121 | 0 |
| wire_messages | 477 455 | 22 735 | 984 | 2535 | 338 | 0 |
| wire_primitives | 890 778 | 42 418 | 506 | 3337 | 460 | 0 |
| channel_opening | 119 651 | 5 697 | 1155 | 7072 | 1176 | 0 |
| input_buffer | 3 483 169 | 165 865 | 94 | 496 | 93 | 0 |
| json_values | 260 895 | 11 343 | 936 | 5808 | 811 | 0 |
| observation_records | 62 701 | 2 985 | 1791 | 4895 | 654 | 0 |
| tcp_identification | 151 095 | 7 195 | 378 | 1198 | 228 | 0 |
| tcp_initial_packets | 254 075 | 12 098 | 773 | 2585 | 360 | 0 |
| tcp_observer | 34 431 | 1 639 | 1471 | 3866 | 564 | 0 |
| tcp_probe | 20 986 | 999 | 1533 | 4702 | 637 | 0 |

Round 4, same host and configuration, 60 s per new target from the seeds
(432 seeds across 18 targets now replay clean):

| Target | 60 s execs | exec/s | cov | ft | corpus | crashes |
|---|---|---|---|---|---|---|
| wire_kex_codecs | 3 232 554 | 52 992 | 902 | 2418 | 384 | 0 |
| key_blobs | 138 238 | 2 266 | 622 | 1198 | 195 | 0 |
| tcp_negotiation | 1 787 993 | 29 311 | 696 | 2206 | 439 | 0 |
| tcp_gcm_packets | 110 689 | 1 814 | 563 | 1584 | 183 | 0 |
| tcp_handshake | 79 731 | 1 307 | 2742 | 5175 | 534 | 0 |
| handshake_report_json | 190 479 | 3 122 | 1777 | 3743 | 542 | 0 |

`tcp_handshake` additionally ran 120 s (`-seed=2`) and 150 s (`-seed=3`),
379 k further executions, no findings. `channel_opening` ran 90 s after the
duplicate-peer-number model change, clean.

Each round-3 target was additionally run for 60 s (and the five TCP targets
for a further 150 s with `-seed=2`) by the harness authors during development
with the same result: one production finding and one harness finding, both
fixed above. Probe/observer throughput is bounded by libFuzzer comparison tracing
across three drivers plus the model, not by production code.

Coverage was generated with `scripts/fuzz.sh coverage` over seeds plus the
smoke corpora and inspected with `llvm-cov show`:

- `identification_content`: `tatami_wire::ident` parse paths 100 %; misses are
  `Display` impls and the encoder (owned by `identification_encode`).
- `tcp_probe`: `probe.rs` 89 % of regions; every miss is a `Display`/`code`
  helper or an `unreachable!`. Proposal completion, both budgets, `TooLarge`,
  `EmptyPayload`, EOF in both stages and the 65 536-byte packet are hit.
- `channel_opening`: `LateReply` (686 tombstone hits), `DuplicateReply`
  (1.4 k), `IncomingRefusedByLimit` (2.9 k) and `TransportLost` (17.5 k)
  branches are hit. The only unreached production branch is number
  exhaustion inside `accept` (needs 2³² opens); the unit test
  `numbers_exhaust_without_wrapping` covers it by setting the counter
  directly.
- `observation_records`: the truncation branch was taken 605 of 1 780 times.
- `tcp_handshake` (round 4, 897 inputs): `handshake.rs` 84.4 % lines /
  81.5 % regions. `on_service_accept` 60 hits, `Completed` constructed 46
  times, `ServiceMismatch` 6, NEWKEYS received 314, `HostNotTrusted` 302,
  rekey `DISCONNECT` 32, wrong-guess discard 64, strict "KEXINIT not first"
  16, `SignatureInvalid` 34. Misses are `Display`/`code()` helpers (covered
  by `handshake_report_json`), padding-source trait methods production never
  calls, the 2³² sequence-number wrap, and `expect`-guarded impossibilities.
- `tcp_negotiation`: `negotiate.rs` 94 % of regions.

`scripts/fuzz.sh coverage` now copies seeds and corpus into one input
directory before the instrumented run: cargo-fuzz runs each directory as a
separate process writing the same `default-<target>.profraw`, so a second
directory used to overwrite the first profile.

ASan runs and the pinned nightly were not executed locally (no rustup on the
development machine); they run in CI. No coverage percentage is a goal in
itself.

## Future targets

Recorded so the next slices arrive with harnesses, not claimed as fuzzed:

| Future surface | Target requirements |
|---|---|
| `known_hosts`/`authorized_keys` policy, RSA/ECDSA/certificate blobs | Policy engine model with distinct host-trust vs user-authorization decisions; further blob layouts; never a private key in a corpus (Ed25519 blobs, signatures, fingerprints and the pinned policy are covered by `key_blobs`) |
| Rekeying and general sessions | Rekey state model (second exchange hash distinct from the session id), sequence-number and counter behaviour across re-keys, key-usage limits; the diagnostic currently refuses rekey and is fuzzed only for that refusal |
| Userauth (`tatami-auth`) | Method state machines with a model of allowed transitions; signature-input construction against hand-assembled bytes; session-identifier provenance preserved |
| QUIC stream association and flow control | Association registry model (stream IDs vs SSH numbers), pending/refused stream reclamation, SSH-window vs QUIC-credit separation; only after the record format (AQ-018) exists |
| SFTP | Path canonicalisation, handle lifetime per session, directory-dependency ordering across streams; only after the transport exists |
