# TCP rekey: scope and acceptance criteria

**Status:** design for the next TCP slice, not a supported command. The client now has a connection-scoped key schedule with a two-exchange test. The live diagnostic still disconnects on a peer `KEXINIT` after `NEWKEYS`; no rekey has been demonstrated on the wire.

## Keep the connection, replace the traffic keys

[RFC 4253 §§7–9](https://www.rfc-editor.org/rfc/rfc4253.html#section-9) distinguishes three lifetimes:

| Lifetime | What Tatami must retain or replace |
|---|---|
| Connection | Retain the original identification strings, logical trust name/policy, first exchange hash as the session ID, initial strict-KEX decision, service and (eventually) authenticated user and open channels. Do not exchange banners or request the service a second time. |
| Key exchange | Either endpoint sends `KEXINIT`. If proposals cross, finish **one** exchange, not two. Use fresh entropy for the cookie and X25519 ephemeral; verify the signature on the new exchange hash using the negotiated scheme. Derive fresh keys and IVs from the new shared secret and hash **and the original session ID**. Compression stays `none` (W-44). |
| Packet direction | Send `NEWKEYS` under the old sending key; only later packets use the new sending key. Authenticate and consume the peer's `NEWKEYS` under the old receiving key before switching that direction. With strict KEX, reset that direction's SSH sequence number after each `NEWKEYS`; otherwise continue it. The AES-GCM invocation counter starts from the newly derived IV, not the SSH sequence number. |

RFC 4253 permits the server to change host keys at re-exchange; it does not give an unknown key any trust. **Proposed first profile:** require the same SSH public-key blob as the initial exchange as well as a valid new signature. A second key listed for rotation may be used on a new connection. This is a deliberately narrower local policy, not a requirement on other SSH implementations.

## Implementation order

1. **Separate the diagnostic's exit from the transport.** Let the caller take over after `SERVICE_ACCEPT` with the same socket, buffered input, packet ciphers, counters and session ID. Keep `tatami-client handshake` as a short-lived diagnostic. Today `ClientHandshake::on_service_accept` queues `DISCONNECT` and `run_handshake` closes the socket: returning just the report would lose live state.
2. **Drive a second exchange through the protected packet path.** Reuse the KEX codecs, negotiation, signature provider and trust checks; do not construct another `ClientHandshake` (it sends a banner and starts unprotected). Inject fresh entropy per exchange, not the padding generator. Omit initial-only extension markers; do not renegotiate strictness or reopen the first `EXT_INFO` opportunity. Pause new service sends during KEX. Process messages already in flight in order as required by RFC 4253 §7.1; bound any buffering. Fail closed on a bad signature, key mismatch, malformed/out-of-phase packet, or timeout.
3. **Schedule and bound rekey.** Track bytes and packets per direction under each key and elapsed monotonic time in the driver. Start with the RFC 4253 §9 recommendation (1 GB or 1 hour), with test-injectable limits. Trigger early enough to finish KEX under the old keys; never cross the cipher's hard usage limit or wrap a nonce. Suppress duplicate local triggers while KEX is pending and retain a deadline for completion. Do not turn an SSH sequence reset into a GCM nonce reset under an old key.

## Evidence before calling rekey supported

- Use the existing deterministic peer for client initiation, server initiation and crossed proposals. Send a protected service payload on either side of the change. Check a fragmented old-key `NEWKEYS` followed in the **same read** by a new-key packet; check both directions independently and with strict KEX off. Never accept an old-key packet after that direction switches. See [strict KEX §§3.1–3.3](https://www.ietf.org/archive/id/draft-ietf-sshm-strict-kex-03.html#section-3.3) (Internet-Draft).
- Test unchanged session ID, fresh traffic keys, failed trust/signature, in-flight service messages, byte/time triggers and timeout without progress. Local limits must be testable without moving a gigabyte or waiting an hour. Extend the existing handshake fuzz model when wire behavior changes; there is no need for a new target for the KDF.
- **OpenSSH interop belongs after login.** OpenSSH portable 10.2p1's [`ssh_packet_need_rekeying`](https://github.com/openssh/openssh-portable/blob/V_10_2_P1/packet.c) skips automatic rekey before authentication. A tiny `RekeyLimit` on today's pre-auth fixture is not a valid server-initiated rekey test. Once `publickey` and `exec` exist, force each initiator separately, confirm a second KEX in the server log and verify command output and exit status across the boundary. Report fixture evidence separately from OpenSSH interop.

## What this unlocks for QUIC and services

The reusable result for `tatami_ssh_auth` is an authenticated **server** identity and a stable, transport-specific session binding, not a shared rekey state machine. SSH over QUIC should use QUIC's 1-RTT key update ([RFC 9001 §6](https://www.rfc-editor.org/rfc/rfc9001.html#section-6)); it should neither replay SSH KEX on a stream nor treat a key phase change as a new login. Unlike a fresh SSH Diffie–Hellman exchange, a QUIC key update derives the next traffic secret from the current one. Do not claim identical recovery properties.

The QUIC draft can specify that distinction now. The control stream, record boundaries, exporter binding and channel/stream association still need a reviewed wire proposal before implementation. The first service test should be one non-interactive `exec` with separate stdout/stderr and an exit status against OpenSSH on TCP, then Tatami on QUIC. An interactive shell needs PTY and channel lifecycle support; modern `scp` normally uses the SFTP subsystem, so it follows SFTP v3, not a legacy SCP wire protocol (W-25).
