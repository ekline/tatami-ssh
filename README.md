<p align="center">
  <img src="assets/branding/tatami-guardian-512.png" width="256" height="256" alt="Tatami: a friendly green folding-armour guardian whose head preserves the complete 田 cross in 畳.">
</p>

# tatami-ssh
Rust-based SSH experiment

Cargo packages and Rust imports use the `tatami_ssh` prefix: the facade is
`tatami_ssh`, with libraries such as `tatami_ssh_wire` and `tatami_ssh_keys`.
The executables are `tatami-client` and `tatami-server`.

Genuine SSH over TCP, with QUIC explored as an alternate transport binding.
All libraries are `no_std`; see `docs/architecture.md` for the package layout,
portability layers and feature policy, and `docs/decisions.md` for workspace
decisions. Protocol design state lives in
`docs/tatami-ssh-design-state-checkpoint.md`.

## Status

Early. What runs today (round 5, 2026-09-26):

- **`tatami-client probe`** — connects to an SSH server, sends a client
  identification, and reports the server's identification and its initial
  `KEXINIT` proposal. It does **not** send a client `KEXINIT`, perform key
  exchange, obtain a host key, or authenticate. The output describes what the
  server *advertised*, not what was negotiated.
- **`tatami-server observe`** — a TCP diagnostic listener. It sends
  `SSH-2.0-tatami_observer_0.1.0`, records each connecting client's
  identification and initial `KEXINIT` proposal as JSON Lines, and closes.
  It sends **no** server `KEXINIT`, has no host key, and authenticates nobody.
  It observes early peer offers; it is **not an SSH service**.
- **`tatami-client handshake`** (feature `kex`) — a genuine SSH transport
  handshake against a real server: `curve25519-sha256` key exchange,
  `ssh-ed25519` host-key signature verification, host trust from an
  operator-supplied fingerprint pin or an explicitly named `known_hosts`
  file, `aes128-gcm@openssh.com` protected packets in both
  directions, strict KEX, `EXT_INFO` receive, `SERVICE_REQUEST` /
  `SERVICE_ACCEPT` for `ssh-userauth`, then a protected `DISCONNECT`. It
  never authenticates a user and never rekeys. Verified against a local
  `OpenSSH_10.2p1` sshd (see below).
- **`tatami-server observe --transport quic` / `tatami-client handshake
  --transport quic`** (feature `quic-diag`) — a QUIC v1 + TLS 1.3
  **handshake observer experiment** on `quinn-proto` + `rustls`, built into
  the same two binaries. It completes and reports handshakes; it carries
  **no SSH bytes** and is not SSH over QUIC. Since round 5 the server can
  present an OpenSSH Ed25519 host key as an RFC 7250 raw public key, which
  the client judges with the same pin or `known_hosts` entry as on TCP
  ([below](#one-host-identity-across-tcp-and-quic)).

Library pieces behind that: bounded SSH primitive codecs (including `mpint`)
and `KEXINIT` / `KEX_ECDH_*` / `NEWKEYS` / `EXT_INFO` / service / transport /
channel-opening codecs (`tatami_ssh_wire`); key and signature blobs, Ed25519
verification, `SHA256:` fingerprints, the trust policies (pin and read-only
`known_hosts`), strict Ed25519 SPKI conversion, SSHFP values and unencrypted
OpenSSH Ed25519 private-key decoding (`tatami_ssh_keys`); identification and
packet framing, negotiation, exchange hash and key derivation, AES-GCM packet
protection, the probe/observer and handshake state machines, and blocking
host adapters (`tatami_ssh_tcp`); a pure
channel-opening engine (`tatami_ssh_connection`); the QUIC diagnostic backend
(`tatami_ssh_quic`, feature `quinn-backend`); and reporting, bounded file reads
and trust selection (`tatami_ssh`).

Not implemented: user authentication, rekeying, a TCP SSH server handshake,
writing or enrolling `known_hosts` (or reading `~/.ssh` implicitly),
`@cert-authority` and host certificates, encrypted host keys, RSA/ECDSA host
keys, compression, any cipher other than `aes128-gcm@openssh.com`, channels
and data flow, PTY/exec/forwarding/SFTP,
and SSH over QUIC (the ALPN value is experimental and unregistered; record
framing, control stream and session binding are open).

## Running the probe

```sh
cargo run -p tatami_ssh --features std,tcp --bin tatami-client -- \
  probe ssh.example.net --port 22

cargo run -p tatami_ssh --features std,tcp --bin tatami-client -- \
  probe 2001:db8::10 --port 2222 --connect-timeout 5s --read-timeout 5s

cargo run -p tatami_ssh --features std,tcp --bin tatami-client -- --help
```

Host and port are separate so IPv6 literals need no brackets. Exit status is
`0` for a complete observation (identification plus a clean `KEXINIT`), `1`
for a partial observation or any network/protocol failure, `2` for usage
errors. The report goes to stdout; progress and errors go to stderr. All
peer-supplied text is escaped before printing.

Because no client `KEXINIT` is sent, a server that waits for the client's
proposal before sending its own will produce a partial result at the read
deadline: the identification is still reported. OpenSSH sends its `KEXINIT`
immediately after identification, so the probe completes against it. The
server's log will show the connection closing before authentication; that is
the expected consequence of this diagnostic mode.

Observed against a real server during development (OpenSSH_10.2p1, started
locally with `sshd -D -f /dev/null -p 2299 -o ListenAddress=127.0.0.1 -h
<ephemeral-ed25519-key>`): exit 0, twelve KEX names including the
`ext-info-s` and `kex-strict-s-v00@openssh.com` markers annotated as
non-methods, `[preauth]` close in sshd's log.

## Running the observer

```sh
# Local diagnostic, finite duration and connection count.
cargo run -p tatami_ssh --features std,tcp --bin tatami-server -- \
  observe --listen 127.0.0.1:2222 --timeout 5s \
  --max-concurrent 32 --max-connections 100 --run-for 10m --format jsonl

# IPv6 banner-only observation.
cargo run -p tatami_ssh --features std,tcp --bin tatami-server -- \
  observe --listen '[::1]:2222' --banner-only --run-for 1m --format jsonl

# Explicit public bind, for you to run on the intended host.
cargo run -p tatami_ssh --features std,tcp --bin tatami-server -- \
  observe --listen 0.0.0.0:2222 --format jsonl > observations.jsonl
```

`observe` without `--listen` binds `127.0.0.1:2222`. Without `--run-for` or
`--max-connections` it runs until interrupted. One address per process: run
separate instances for IPv4 and IPv6 rather than relying on dual-stack
wildcard behaviour. Binding port 22 needs OS privileges and must not displace
an existing SSH service; the program never edits firewall or service settings.

Defaults (all local policy, all configurable): 32 concurrent observations;
5 s per connection from acceptance, covering the banner write and all reads;
64 KiB packet-length cap; 16 packets and 256 KiB through the first `KEXINIT`;
256-byte sample of unexpected input; 128 pending records; records over 256 KiB
truncated; 5 s shutdown grace. Excess connections beyond the concurrency limit
are accepted, closed without a banner, counted as `dropped_at_capacity`, and
count toward `--max-connections`.

Output is JSON Lines on stdout (schema 1: `listener_started`,
`connection_observation`, `overload`, `listener_stopped`); diagnostics go to
stderr. Each observation carries the peer socket address, timestamps, byte
counts, the sent server identification, the parsed client identification and
anomalies, the client proposal with directional lists and marker annotations,
the last stage, a stable `outcome`/`reason`, and explicit
`key_exchange_completed: false` / `peer_authenticated: false`. Peer addresses
and banners describe where packets came from and what was sent; they do not
identify an operator or establish intent. For long runs redirect stdout to a
file and rotate it externally; nothing is kept in memory.

Exit status: 0 clean finite/requested stop; 1 listener/output/runtime failure;
2 usage error. A malformed peer is a record, not a failed process.

Because no server `KEXINIT` is sent, a client that waits for it will end with
`outcome: timeout` after the connection deadline, with its identification
recorded. `tatami-client probe` against the observer produces exactly that
partial exchange on both sides (tested). OpenSSH sends its `KEXINIT` right
after its identification, so it is fully observed.

Observed with a real client during development (`OpenSSH_10.2p1`, command
`ssh -F /dev/null -vv -p 2299 -o BatchMode=yes -o ConnectTimeout=5
-o ConnectionAttempts=1 -o IdentityAgent=none -o IdentitiesOnly=yes localhost`):
the client logged `remote software version tatami_observer_0.1.0`,
`SSH2_MSG_KEXINIT sent`, then `Connection closed by 127.0.0.1 port 2299` and
exited 255 (expected). The observer recorded `outcome: proposal` with the
client identification `SSH-2.0-OpenSSH_10.2`, 16 KEX names including
`ext-info-c` and `kex-strict-c-v00@openssh.com` annotated as markers, 16
server-host-key algorithm names, and 1646 bytes read.

## Running the TCP handshake

```sh
# On the SERVER, independently of any connection: obtain the pin.
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
#   256 SHA256:<43 base64 characters> comment (ED25519)

# On the client, with the SHA256: value printed above.
cargo run -p tatami_ssh --features std,tcp,kex --bin tatami-client -- \
  handshake ssh.example.net --port 22 \
  --host-key-sha256 'SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8'

# Options: [--connect-timeout 10s] [--timeout 10s] [--no-ext-info]
#          [--no-strict-kex] [--json]
```

Exactly one trust source is **required**: the pin, or `--known-hosts FILE`
(read-only; see
[One host identity across TCP and QUIC](#one-host-identity-across-tcp-and-quic)).
Take the pin or entry from the server's own public key file (or another
out-of-band source); never from a scan, a previous `probe` run, or the
connection being checked. A valid signature proves the peer holds the key;
the trust source decides whether that key is the expected one. Both are
reported separately (`host_key_signature_valid`, `host_trusted`, with
`trust_source`/`trust_line` or `untrusted_reason`) and both gate `NEWKEYS`.
`untrusted_reason` lists every structured trust failure in one field: a
policy reason (`fingerprint_mismatch`, `unknown_host`, `key_changed`,
`revoked`, ...) once a key was judged, or the configuration code (`io_error`,
`malformed_configuration`, `unsupported_configuration`, `invalid_lookup_name`,
also in `trust_error`) when no decision was made; the message is in `outcome`.
`~/.ssh/known_hosts` is never read implicitly; there is no prompt and no
enrollment (`docs/decisions.md` W-32, W-37).

What it does: identification exchange, `KEXINIT` (offering exactly
`curve25519-sha256`, `ssh-ed25519`, `aes128-gcm@openssh.com`, `none`, plus the
`ext-info-c`, `kex-strict-c-v00@openssh.com` and `kex-strict-c` markers),
`KEX_ECDH_INIT`/`REPLY`, exchange hash and Ed25519 signature verification, the
pin check, `NEWKEYS` both ways with sequence-number reset under strict KEX,
protected `SERVICE_REQUEST("ssh-userauth")`, `EXT_INFO` receive
(`server-sig-algs` recorded, nothing enabled), `SERVICE_ACCEPT`, protected
`DISCONNECT` (`tatami diagnostic complete`). What it does **not** do: send
`USERAUTH_REQUEST` (not even `none`; `user_authenticated` is always `false`),
rekey (a server `KEXINIT` after `NEWKEYS` ends the run as
`RekeyNotSupported` after a `DISCONNECT`), open channels, or negotiate any
other algorithm (`docs/decisions.md` W-29, W-33).

Exit status: `0` only for `Completed`; `1` for any other outcome (untrusted
host key, mismatched pin, unusable `known_hosts` file, negotiation failure,
protocol error, timeout, connection refused); `2` usage error. The text
report or `--json` object goes to stdout, progress to stderr; no key
material appears in either.

A reproducible local fixture starts an ephemeral-key OpenSSH sshd on loopback
and prints the exact pin and command:

```sh
scripts/openssh-fixture.sh start [--port PORT] [--profile default|matching|mismatch]
scripts/openssh-fixture.sh pin      # SHA256:… from ssh-keygen -lf on the fixture key
scripts/openssh-fixture.sh status
scripts/openssh-fixture.sh stop     # kills sshd, deletes the key
```

Observed against `OpenSSH_10.2p1` during development
(`crates/tatami_ssh_tcp/tests/openssh_handshake.rs`,
`crates/tatami_ssh/tests/handshake_cli.rs`; the tests skip when
`/usr/sbin/sshd` is absent, unless `TATAMI_REQUIRE_OPENSSH=1` makes that a
failure, as CI sets it): default sshd — `Completed`, strict KEX
negotiated under `kex-strict-s-v00@openssh.com`, `EXT_INFO` with
`server-sig-algs` received, sshd log `Received disconnect …: tatami
diagnostic complete [preauth]`; wrong pin — `HostNotTrusted`, no `NEWKEYS`
sent, sshd log `Connection closed … [preauth]`; sshd restricted to exactly
the profile — `Completed`; sshd with `Ciphers=aes256-ctr` —
`NegotiationFailed(NoCommonCipher)` on our side, `no matching cipher found`
on sshd's. No authentication attempt appears in any log.

## QUIC handshake experiment

```sh
# Server: generates a self-signed Ed25519 test identity into DIR on first run
# and prints its certificate SHA-256 to stderr.
cargo run -p tatami_ssh --features std,tcp,quic-diag --bin tatami-server -- \
  observe --transport quic --listen 127.0.0.1:4433 --alpn tatami-diag/0 \
  --identity-dir target/quic-identity --generate-identity \
  [--require-validation] [--timeout 5s] [--max-connections N] [--run-for 10m]

# Client: pins that certificate fingerprint (not an SSH host-key fingerprint).
cargo run -p tatami_ssh --features std,tcp,quic-diag --bin tatami-client -- \
  handshake 127.0.0.1 --transport quic --port 4433 --server-name localhost \
  --alpn tatami-diag/0 --cert-sha256 'SHA256:…' --exporter-probe [--json]
```

QUIC is a mode of the ordinary `tatami-client` and `tatami-server`
binaries, not a separate program. `--transport` defaults to `tcp`, so
existing TCP command lines are unchanged. Each transport accepts only its
own options (for example `--alpn` is rejected without `--transport quic`,
`--banner-only` with it) and keeps its own defaults (QUIC: UDP port 4433,
5 s handshake deadline). A build without `quic-diag` reports
`--transport quic` as a usage error (exit 2), just as a build without `kex`
does for the TCP handshake. Build with `--features std,tcp,kex,quic-diag`
to get every command in one pair of binaries.

This is **experimental**: `quinn-proto` 0.11.18 + `rustls` 0.23.45 on `ring`,
host-only, behind `tatami_ssh_quic/quinn-backend` (`docs/decisions.md` W-31). The
ALPN value has no default, is unregistered, and interoperates with nothing
else. No stream is opened, no DATAGRAM is sent, 0-RTT and resumption are
disabled, and **no SSH byte is ever sent** — tests inspect every datagram. It
reports the source address and its validation state (`--require-validation`
answers with Retry), offered vs negotiated ALPN, SNI, outcome and whether the
TLS exporter is available after completion (output discarded; not a session
binding). Records are JSON Lines (`quic_listener_started`,
`quic_handshake_observation`, `overload`, `quic_listener_stopped`). Exit
status follows the TCP tools: 0 clean/complete, 1 failure or timeout, 2
usage. What it settled and did not settle is in
`docs/quic-observer-readiness.md`. Instead of the test certificate the
server can present an SSH host key (`--host-key`, next section).

## One host identity across TCP and QUIC

The same OpenSSH Ed25519 host key can serve an OpenSSH `sshd` on TCP and the
QUIC diagnostic on UDP, and the client accepts both with one `known_hosts`
entry (round 5). Build with `--features std,tcp,kex,quic-diag`:

```sh
# QUIC: the key sshd uses on TCP, presented as an RFC 7250 raw public key.
cargo run -p tatami_ssh --features std,tcp,kex,quic-diag --bin tatami-server -- \
  observe --transport quic --listen 127.0.0.1:2222 \
  --alpn tatami-diag/0 --host-key /path/to/ssh_host_ed25519_key

# TCP (sshd on 127.0.0.1:2222) and QUIC (UDP 2222) under the same entry.
cargo run -p tatami_ssh --features std,tcp,kex,quic-diag --bin tatami-client -- \
  handshake 127.0.0.1 --transport tcp --port 2222 \
  --known-hosts /path/to/fixture_known_hosts

cargo run -p tatami_ssh --features std,tcp,kex,quic-diag --bin tatami-client -- \
  handshake 127.0.0.1 --transport quic --port 2222 \
  --alpn tatami-diag/0 --known-hosts /path/to/fixture_known_hosts
```

- **Identity.** The complete SSH public-key blob, on both transports. The
  QUIC client converts the server's raw public key strictly to that blob and
  applies the same policy object as TCP; TLS `CertificateVerify` (QUIC) and
  the signature over the exchange hash (TCP) are still verified. On QUIC,
  `--host-key-sha256` is the SSH fingerprint `ssh-keygen -lf` prints, not a
  certificate or SPKI hash; the SSH modes require a raw public key and refuse
  a certificate, and `--cert-sha256`/`--root-cert` are unchanged. Reports
  show the SSH fingerprint and the SSHFP value (`4 2 <hex>`, as `ssh-keygen
  -r` prints) as fingerprint equivalence only: no DNS lookup or DNSSEC
  validation takes place (W-36, W-40).
- **Key types (round 6).** With `--features rsa,ecdsa-p256` the same works
  for RSA (`rsa-sha2-512` / `rsa-sha2-256`; 2048–4096-bit keys as QUIC
  identities, up to 8192 bits on TCP) and ECDSA P-256 host keys, with SSHFP
  algorithms 1 and 3. `tatami-client handshake --host-key-algorithms LIST`
  forces the TCP host-key algorithm list; `ssh-rsa` (RSA/SHA-1) is never
  offered or accepted. RSA and P-256 signatures are checked by `ring`, the
  provider rustls already uses; the portable crates stay free of C/asm
  (W-43).
- **Lookup name.** The host as typed, lowercased; `[host]:port` unless the
  port is 22 (OpenSSH's rule), bound before connecting. TCP and UDP on the
  same port number share an entry; different ports do not. The resolved
  address, `--server-name` and QUIC path changes never replace it. The
  intended convention is TCP 22 plus UDP 22; UDP 4433 is only the
  experiment's default (W-38).
- **`known_hosts` subset.** Read-only, explicit file only. Comments,
  comma-separated patterns with `*`/`?`, `!` negation, `[host]:port` and
  `@revoked`. Hashed `|1|` names (`ssh-keygen -H`) need the opt-in
  `openssh-hashed-hosts` feature (for example
  `--features std,tcp,kex,quic-diag,openssh-hashed-hosts`); without it a
  file containing any hashed entry, including a hashed `@revoked` line, is
  refused before connecting (`unsupported_configuration`). That feature is
  the only thing in Tatami that links SHA-1 (HMAC-SHA1, in
  `tatami_ssh_openssh_compat`; W-42). An applicable revocation wins regardless of
  line order; several keys per host (rotation) are allowed; unknown hosts
  fail. Any malformed line or unknown marker (including in `@revoked`)
  rejects the whole file before connecting (`trust_configuration_error`,
  with the line number). `@cert-authority` and other-algorithm lines never
  confer trust. Limits: 1 MiB, 16 KiB per line, 10 000 entries, 256 patterns
  per line. Stricter than OpenSSH by design (W-37, W-41).
- **Host key.** Unencrypted Ed25519 `openssh-key-v1` only, at most 16 KiB.
  Encrypted keys are refused with a specific error and there is no
  passphrase input. On Unix the file must not be group/other-accessible
  (checked on the opened file); other platforms get no permission check.
  The key is converted in memory; no certificate or copy is written.
  `--host-key` excludes `--identity-dir`/`--generate-identity` (W-39).

This demonstrates **identity continuity**, not SSH over QUIC: a trusted host
key over QUIC/TLS is not an SSH session. No SSH byte crosses QUIC, no user is
authenticated, and the QUIC report says `ssh_session: false`. Tatami has no
TCP SSH server; OpenSSH is the TCP side.

Observed during development (`crates/tatami_ssh/tests/host_identity.rs`, real
`sshd` and `tatami-server --host-key` on the same TCP/UDP port number, one
entry; skips when `/usr/sbin/sshd` or `ssh-keygen` is absent, fails instead
with `TATAMI_REQUIRE_OPENSSH=1`) against
`OpenSSH_10.2p1`: both transports report the fingerprint `ssh-keygen -lf`
prints and the SSHFP value `ssh-keygen -r` prints; changed key, unknown host,
wrong port, a port-22 entry for another port, negation, revocation before and
after the positive line, a malformed file (no connection made) and replaced
server keys fail; rotation works; `ssh-keygen -H` hashed entries (and a
hashed revocation) work with `openssh-hashed-hosts` and are an explicit
`unsupported_configuration` on both transports without it; a
certificate server is refused; bad host-key files (permissions, encrypted,
a public key) and conflicting identity options are refused at startup; the
file is never modified; matching agrees with `ssh-keygen -F` on 16 plain
(and, with the feature, hashed) queries.

## Checks

```sh
scripts/check-workspace.sh
```

Runs formatting, Clippy, the feature matrix (including `kex`, `std,tcp,kex`,
`quic-diag`, `tatami_ssh_keys` `known-hosts`/`openssh-key`), dependency-graph
checks (no `std`, TLS, resolver or `getrandom` crates in the portable key
graphs; no private-key or TLS crates in the portable `kex` facade), the
self-tested SHA-1 boundary check (`scripts/check-sha1-boundary.py`: SHA-1
reachable only through `tatami_ssh_openssh_compat` with
`openssh-hashed-hosts`, unreachable without it), tests with and without
`openssh-hashed-hosts`, docs and (when the `thumbv7em-none-eabi` target is installed) core/alloc-only
builds, including `tatami_ssh_tcp --features kex` and `tatami_ssh_keys --features
known-hosts,openssh-key` with no standard library. CI runs it on Rust 1.85.0
and stable, with OpenSSH installed and `TATAMI_REQUIRE_OPENSSH=1` so the
OpenSSH interoperability tests fail rather than skip. Round 5 ran it locally
on stable only (rustc 1.98.1, 529 tests, none skipped; bare-metal step
skipped, target not installed); the 1.85, bare-metal and CI OpenSSH runs
(non-root `sshd` on the runner included) are gates not yet observed
(`docs/crypto-provider-audit.md`).

## Fuzzing

Twenty-one coverage-guided libFuzzer targets live in isolated workspaces under
`fuzz/` and cover the implemented parsers, encoders and state machines
(including negotiation, GCM packets, key blobs, the handshake, SPKI
conversion, `known_hosts` and the private-key loader) with independent
oracles. See `docs/fuzzing.md` for setup, commands, oracles,
seeds, findings and CI policy. Quick start with rustup (`cargo-fuzz` is
installed with **stable** and run under the pinned nightly, W-34):

```sh
. fuzz/toolchain.env
rustup toolchain install "$FUZZ_NIGHTLY" --profile minimal --component rustfmt,clippy,llvm-tools-preview
rustup run stable cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked
scripts/fuzz.sh smoke 20
scripts/fuzz.sh run tcp_observer -- -max_total_time=300
```

Ordinary `cargo test` never depends on nightly, cargo-fuzz or the corpora.

## Next milestones

1. **Reusable TCP transport and rekeying:** both initiators, strict-KEX key
   rollover, byte/time limits, preservation of the first session identifier,
   and an interface userauth can use instead of the diagnostic's exit.
2. **QUIC mapping proposal, then implementation:** identification placement,
   control-stream bootstrap, bounded record framing, exporter binding and
   userauth inputs, channel/stream association (one channel per
   bidirectional stream, in-stream data framing), ordering and errors —
   security-sensitive binding decisions written down and reviewed first. No
   SSH-over-QUIC option exists.
3. **Hostname resolution review:** an explicit shared resolver interface
   instead of `ToSocketAddrs` (TCP) and first-address (QUIC); deadlines,
   A/AAAA racing, caching, search domains, split DNS; explicit DNSSEC and
   SSHFP policy. The logical trust name stays separate (W-38).
4. **First authenticated command:** `publickey` userauth, channel data and
   windows, stdout/stderr, `EOF`/`CLOSE` and exit status against OpenSSH,
   then over QUIC; server privilege/process boundaries specified first. Git,
   PTY, forwarding/SOCKS and SFTP v3 (W-25) follow.

Also deferred: encrypted host keys, signing agents/HSMs, `@cert-authority`
and host certificates, implicit `~/.ssh` files and enrollment, and SSHFP/DNSSEC
verification.

Pending gates: the remote fuzz CI run with ASan (including the round-5
targets), Rust 1.85 on the round-5 code, the first CI bare-metal build of
the `kex`/`ed25519`/`known-hosts`/`openssh-key` features, and the first CI run
of the OpenSSH tests with `TATAMI_REQUIRE_OPENSSH=1` (non-root `sshd` on the
runner is unverified).
