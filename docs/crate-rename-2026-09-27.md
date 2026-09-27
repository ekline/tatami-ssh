# Crate rename: tatami_ssh

Prepared against `b89cb47` after round five and the Node 24 Actions update.

## Names

| Previous package | New package / Rust import |
|---|---|
| `tatami` | `tatami_ssh` |
| `tatami-wire` | `tatami_ssh_wire` |
| `tatami-keys` | `tatami_ssh_keys` |
| `tatami-auth` | `tatami_ssh_auth` |
| `tatami-connection` | `tatami_ssh_connection` |
| `tatami-tcp` | `tatami_ssh_tcp` |
| `tatami-quic` | `tatami_ssh_quic` |
| `tatami-fuzz-wire-core` | `tatami_ssh_fuzz_wire_core` |
| `tatami-fuzz-protocol` | `tatami_ssh_fuzz_protocol` |

Production directories now match the package names under `crates/`.
The fuzz workspace directories remain `fuzz/wire-core` and `fuzz/protocol`.
Manifests, lockfiles, feature forwarding, imports, scripts, examples and
current crate documentation use the new names. Existing historical draft
sketches of superseded, unimplemented packages remain historical sketches.

`tatami-client` and `tatami-server` executable names are unchanged, as are
protocol banners, ALPN values, exporter labels, branding and repository URL.
All packages remain unpublished (`publish = false`). No third-party package
version, source or checksum changed in any of the three lockfiles.
The crates.io API returned 404 for all nine new names during this review;
this is an availability check, not a reservation or publication.

Example:

```sh
cargo run -p tatami_ssh --features std,tcp,kex --bin tatami-client -- --help
```

## Separate MSRV correction

Round five passed a `dyn SharedHostTrustPolicy` directly where a
`dyn HostTrustPolicy` was expected. Rust 1.85 rejects that trait upcast.
The follow-up commit uses the existing forwarding implementation of
`HostTrustPolicy` for references instead. It changes no trust decision and
keeps the declared MSRV. The incompatibility was present before the rename.

## Verification

Passed locally:

- Stable all-target/all-feature production checks, workspace Clippy in both
  no-default and all-feature configurations, and the existing feature matrix.
- Rust 1.85 all-target/all-feature production checks after the MSRV fix.
- Stable and Rust 1.85 bare-metal no-default workspace builds; portable
  key/trust features on both, and portable facade KEX on stable.
- All workspace library tests and doctests, QUIC crate tests, and facade
  `cli`, `quic_cli` and `observe_cli` tests.
- Rustdoc with `-D warnings` and formatting checks.
- Both isolated fuzz workspaces' all-target checks with `--locked`, and
  `scripts/fuzz.sh lint` (formatting, Clippy and harness library tests).
- All three lockfiles retain identical third-party dependency records.

The full workspace script reached OpenSSH interoperability tests, but this
container denies `sshd`'s required `chroot("/run/sshd")` with `Operation not
permitted`. These cases therefore did not pass locally; the tests and their
security settings were not weakened. Run the existing CI gates after applying.
No mutation campaign was run for this package/import rename.

Apply the accompanying two-commit patch series using:

```sh
git am tatami-ssh-crate-rename.patch
```

The first commit is the rename; the second fixes the pre-existing MSRV
error and includes this validation record. Neither has been pushed from
this workspace.
