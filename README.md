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
- **`tatami-server`** — an entry-point stub. `--help`/`--version` only; it
  does not listen.

Library pieces behind that: bounded SSH primitive codecs and `KEXINIT` /
channel-opening / transport-message codecs (`tatami-wire`), identification and
initial packet parsing plus a portable probe state machine (`tatami-tcp`), and
a pure channel-opening engine (`tatami-connection`).

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

## Checks

```sh
scripts/check-workspace.sh
```

Runs formatting, Clippy, the feature matrix, tests, docs and (when the
`thumbv7em-none-eabi` target is installed) a core/alloc-only build. CI runs it
on Rust 1.85.0 and stable.

## Next milestone

A real key-exchange method with host-key signature verification and trust
policy, then protected packets and service negotiation. That needs separate
algorithm and cryptographic-provider review; displaying `KEXINIT` does not
begin it.
