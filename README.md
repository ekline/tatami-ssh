<p align="center">
  <img src="assets/branding/tatami-guardian-512.png" width="256" height="256" alt="Tatami: a friendly green folding-armour guardian whose head preserves the complete 田 cross in 畳.">
</p>

# tatami-ssh
Rust-based SSH experiment

Genuine SSH over TCP, with QUIC explored as an alternate transport binding.
All libraries are `no_std`; see `docs/architecture.md` for the package layout,
portability layers and feature policy, and `docs/decisions.md` for workspace
decisions. Protocol design state lives in
`docs/tatami-ssh-design-state-checkpoint.md`.

## Status

Early. What runs today (round 4, 2026-09-20):

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
  `ssh-ed25519` host-key signature verification, an operator-supplied
  fingerprint pin, `aes128-gcm@openssh.com` protected packets in both
  directions, strict KEX, `EXT_INFO` receive, `SERVICE_REQUEST` /
  `SERVICE_ACCEPT` for `ssh-userauth`, then a protected `DISCONNECT`. It
  never authenticates a user and never rekeys. Verified against a local
  `OpenSSH_10.2p1` sshd (see below).
- **`tatami-quic-server observe` / `tatami-quic-client handshake`** (feature
  `quic-diag`) — a QUIC v1 + TLS 1.3 **handshake observer experiment** on
  `quinn-proto` + `rustls`. It completes and reports handshakes; it carries
  **no SSH bytes** and is not SSH over QUIC.

Library pieces behind that: bounded SSH primitive codecs (including `mpint`)
and `KEXINIT` / `KEX_ECDH_*` / `NEWKEYS` / `EXT_INFO` / service / transport /
channel-opening codecs (`tatami-wire`); key and signature blobs, Ed25519
verification, `SHA256:` fingerprints and the pinned trust policy
(`tatami-keys`); identification and packet framing, negotiation, exchange
hash and key derivation, AES-GCM packet protection, the probe/observer and
handshake state machines, and blocking host adapters (`tatami-tcp`); a pure
channel-opening engine (`tatami-connection`); the QUIC diagnostic backend
(`tatami-quic`, feature `quinn-backend`); and reporting (`tatami`).

Not implemented: user authentication, rekeying, `known_hosts`, RSA/ECDSA or
certificate host keys, compression, any cipher other than
`aes128-gcm@openssh.com`, channels and data flow, PTY/exec/forwarding/SFTP,
and SSH over QUIC (the ALPN value is experimental and unregistered; record
framing, control stream and session binding are open).

## Running the probe

```sh
cargo run -p tatami --features std,tcp --bin tatami-client -- \
  probe ssh.example.net --port 22

cargo run -p tatami --features std,tcp --bin tatami-client -- \
  probe 2001:db8::10 --port 2222 --connect-timeout 5s --read-timeout 5s

cargo run -p tatami --features std,tcp --bin tatami-client -- --help
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
cargo run -p tatami --features std,tcp --bin tatami-server -- \
  observe --listen 127.0.0.1:2222 --timeout 5s \
  --max-concurrent 32 --max-connections 100 --run-for 10m --format jsonl

# IPv6 banner-only observation.
cargo run -p tatami --features std,tcp --bin tatami-server -- \
  observe --listen '[::1]:2222' --banner-only --run-for 1m --format jsonl

# Explicit public bind, for you to run on the intended host.
cargo run -p tatami --features std,tcp --bin tatami-server -- \
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
cargo run -p tatami --features std,tcp,kex --bin tatami-client -- \
  handshake ssh.example.net --port 22 \
  --host-key-sha256 'SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8'

# Options: [--connect-timeout 10s] [--timeout 10s] [--no-ext-info]
#          [--no-strict-kex] [--json]
```

The pin is **required** and is the only trust decision. Take it from the
server's own public key file (or another out-of-band source); never from a
scan, a previous `probe` run, or the connection being pinned. A valid
signature proves the peer holds the key; the pin decides whether that key is
the expected one. Both are reported separately (`host_key_signature_valid`,
`host_trusted`) and both gate `NEWKEYS`. There is no `known_hosts` reading,
no prompt and no enrollment (`docs/decisions.md` W-32).

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
host key, mismatched pin, negotiation failure, protocol error, timeout,
connection refused); `2` usage error. The text report or `--json` object goes
to stdout, progress to stderr; no key material appears in either.

A reproducible local fixture starts an ephemeral-key OpenSSH sshd on loopback
and prints the exact pin and command:

```sh
scripts/openssh-fixture.sh start [--port PORT] [--profile default|matching|mismatch]
scripts/openssh-fixture.sh pin      # SHA256:… from ssh-keygen -lf on the fixture key
scripts/openssh-fixture.sh status
scripts/openssh-fixture.sh stop     # kills sshd, deletes the key
```

Observed against `OpenSSH_10.2p1` during development
(`crates/tatami-tcp/tests/openssh_handshake.rs`,
`crates/tatami/tests/handshake_cli.rs`; the tests skip when
`/usr/sbin/sshd` is absent): default sshd — `Completed`, strict KEX
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
cargo run -p tatami --features quic-diag --bin tatami-quic-server -- \
  observe --listen 127.0.0.1:4433 --alpn tatami-diag/0 \
  --identity-dir target/quic-identity --generate-identity \
  [--require-validation] [--timeout 5s] [--max-connections N] [--run-for 10m]

# Client: pins that certificate fingerprint (not an SSH host-key fingerprint).
cargo run -p tatami --features quic-diag --bin tatami-quic-client -- \
  handshake 127.0.0.1 --port 4433 --server-name localhost --alpn tatami-diag/0 \
  --cert-sha256 'SHA256:…' --exporter-probe [--json]
```

This is **experimental**: `quinn-proto` 0.11.18 + `rustls` 0.23.45 on `ring`,
host-only, behind `tatami-quic/quinn-backend` (`docs/decisions.md` W-31). The
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
`docs/quic-observer-readiness.md`.

## Checks

```sh
scripts/check-workspace.sh
```

Runs formatting, Clippy, the feature matrix (including `kex`, `std,tcp,kex`,
`quic-diag`), tests, docs and (when the `thumbv7em-none-eabi` target is
installed) core/alloc-only builds, including `tatami-tcp --features kex` and
`tatami-keys --features ed25519` with no standard library. CI runs it on Rust
1.85.0 and stable; the bare-metal build of the crypto features is a CI gate
whose first run had not been observed at this writing
(`docs/crypto-provider-audit.md`).

## Fuzzing

Eighteen coverage-guided libFuzzer targets live in isolated workspaces under
`fuzz/` and cover the implemented parsers, encoders and state machines
(including negotiation, GCM packets, key blobs and the handshake) with
independent oracles. See `docs/fuzzing.md` for setup, commands, oracles,
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

1. **TCP:** full rekeying (client- and server-initiated, key rollover under
   strict KEX) and `publickey` user authentication; then a `session` channel
   with `exec`, data, window accounting, `EOF`/`CLOSE`; then local, remote
   and SOCKS forwarding (`direct-tcpip`, `tcpip-forward`/`forwarded-tcpip`).
2. **QUIC:** bootstrap (identification placement, control stream), the
   exporter-derived session binding and its userauth integration, and the
   channel-to-stream mapping — each measured against the TCP behaviour above,
   not designed in isolation. No SSH-over-QUIC option exists.
3. **After that:** PTY sessions and SFTP v3 (`docs/decisions.md` W-25).

Pending gates: the remote fuzz CI run with ASan after the W-34 install fix,
and the first CI bare-metal build of the `kex`/`ed25519` features.
