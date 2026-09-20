# tatami-ssh
Rust-based SSH experiment

Genuine SSH over TCP, with QUIC explored as an alternate transport binding.
All libraries are `no_std`; see `docs/architecture.md` for the package layout,
portability layers and feature policy, and `docs/decisions.md` for workspace
decisions. Protocol design state lives in
`docs/tatami-ssh-design-state-checkpoint.md`.

Run `scripts/check-workspace.sh` to reproduce the CI checks locally.
