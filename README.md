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

Early. What runs today:

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

Library pieces behind that: bounded SSH primitive codecs and `KEXINIT` /
channel-opening / transport-message codecs (`tatami-wire`), identification and
initial packet parsing, shared bounded pre-`KEXINIT` handling, portable probe
and observer state machines and a bounded blocking listener (`tatami-tcp`), a
pure channel-opening engine (`tatami-connection`), and JSON Lines reporting
(`tatami`).

Two runtime tracks remain ahead and are **not** started by this code: real TCP
key exchange with host-key trust and protected packets, and a QUIC handshake
observer after the backend audit in `docs/quic-observer-readiness.md`.

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

## Checks

```sh
scripts/check-workspace.sh
```

Runs formatting, Clippy, the feature matrix, tests, docs and (when the
`thumbv7em-none-eabi` target is installed) a core/alloc-only build. CI runs it
on Rust 1.85.0 and stable.

## Fuzzing

Twelve coverage-guided libFuzzer targets live in isolated workspaces under
`fuzz/` and cover every implemented parser, encoder and state machine with
independent oracles. See `docs/fuzzing.md` for setup, commands, oracles,
seeds, findings and CI policy. Quick start with rustup:

```sh
. fuzz/toolchain.env
rustup toolchain install "$FUZZ_NIGHTLY" --profile minimal --component rustfmt,clippy,llvm-tools-preview
rustup run "$FUZZ_NIGHTLY" cargo install cargo-fuzz --version "$CARGO_FUZZ_VERSION" --locked
scripts/fuzz.sh smoke 20
scripts/fuzz.sh run tcp_observer -- -max_total_time=300
```

Ordinary `cargo test` never depends on nightly, cargo-fuzz or the corpora.

## Next milestones

Two separate tracks, neither begun by the probe or the observer:

1. **TCP:** a real key-exchange method with host-key signature verification
   and trust policy, then protected packets and service negotiation. Needs the
   algorithm/provider audit outlined in `docs/specification-inventory.md`.
2. **QUIC:** a TLS/QUIC handshake observer after the backend audit in
   `docs/quic-observer-readiness.md`, and only later an SSH-over-QUIC observer
   once the mapping's open questions are settled. No `--quic` option exists.

File transfer direction (SFTP v3 baseline, one transfer per stream experiment)
is recorded in `docs/decisions.md` W-25 and is not implemented.
