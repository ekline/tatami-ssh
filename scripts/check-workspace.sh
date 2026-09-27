#!/bin/sh
# Local and CI build/feature verification for the Tatami workspace.
#
# Usage: scripts/check-workspace.sh [--no-embedded]
#
# Runs formatting, clippy, the facade feature matrix, tests, docs, and a
# core/alloc-only check against a target with no standard library. The
# embedded check is skipped with a notice if that target's `rust-std` is not
# installed (install it with `rustup target add thumbv7em-none-eabi`); pass
# --no-embedded to skip it silently. Set CHECK_EMBEDDED_REQUIRED=1 to make a
# missing target a hard failure, which CI does.

set -eu

cd "$(dirname "$0")/.."

EMBEDDED_TARGET=thumbv7em-none-eabi
run_embedded=1
for arg in "$@"; do
    case "$arg" in
        --no-embedded) run_embedded=0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

step() {
    printf '\n==> %s\n' "$*"
    "$@"
}

# The fuzz harnesses must stay out of the production workspace; a stray
# member would drag nightly-only build flags and harness deps into it.
printf '\n==> verify fuzz workspaces are not production members\n'
if cargo metadata --no-deps --format-version 1 | grep -q 'tatami_ssh_fuzz_'; then
    echo "error: a fuzz harness package is a member of the production workspace" >&2
    exit 1
fi

step cargo fmt --all -- --check
step cargo clippy --workspace --all-targets --no-default-features -- -D warnings
step cargo clippy --workspace --all-targets --all-features -- -D warnings
# `--all-features` enables openssh-hashed-hosts; lint the code paths of the
# ordinary build (hashed entries unsupported) too.
step cargo clippy -p tatami_ssh_keys --all-targets --no-default-features --features known-hosts,openssh-key -- -D warnings
step cargo clippy -p tatami_ssh --all-targets --no-default-features --features std,tcp,kex,quic-diag -- -D warnings

# tatami_ssh_wire is the only shared package with a feature; check both states.
# The allocation-free path is checked in isolation: when other workspace
# members are selected they enable `tatami_ssh_wire/alloc`, which would mask an
# accidental alloc dependency. Verify the resolved feature set is empty.
step cargo check -p tatami_ssh_wire --no-default-features
step cargo test -p tatami_ssh_wire --no-default-features
printf '\n==> verify tatami_ssh_wire resolves with no features when checked alone\n'
wire_features=$(cargo tree -p tatami_ssh_wire --no-default-features -e features --depth 0 -f '{f}')
if [ -n "$wire_features" ]; then
    echo "error: tatami_ssh_wire unexpectedly has features enabled: $wire_features" >&2
    exit 1
fi
step cargo check -p tatami_ssh_wire --no-default-features --features alloc

# Bindings: portable state with and without host io modules.
for crate in tatami_ssh_tcp tatami_ssh_quic; do
    step cargo check -p "$crate" --no-default-features
    step cargo check -p "$crate" --no-default-features --features std
done

# Portable crypto profile (round 4): must not pull std. The graph check
# tolerates only the `semver` edge, which is curve25519-dalek's build script.
step cargo check -p tatami_ssh_keys --no-default-features --features ed25519
step cargo check -p tatami_ssh_tcp --no-default-features --features kex
step cargo check -p tatami_ssh_tcp --no-default-features --features std,kex
printf '\n==> verify the kex feature graph enables no std feature\n'
if cargo tree -p tatami_ssh_tcp --no-default-features --features kex -e features -f '{p} {f}' \
    | grep -E 'feature "std"' | grep -v semver; then
    echo "error: a std feature is enabled in the portable kex graph" >&2
    exit 1
fi

# Portable host-identity features (round 5): known_hosts policy and OpenSSH
# private-key decoding. Neither may pull std, a TLS stack, a resolver or
# file I/O; the facade's host layer does the file reads.
step cargo check -p tatami_ssh_keys --no-default-features --features known-hosts
step cargo check -p tatami_ssh_keys --no-default-features --features openssh-key
step cargo check -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key
# Legacy hashed known_hosts names (round 6): the only SHA-1 user is the
# portable tatami_ssh_openssh_compat crate, behind openssh-hashed-hosts.
step cargo check -p tatami_ssh_openssh_compat
step cargo check -p tatami_ssh_keys --no-default-features --features openssh-hashed-hosts
step cargo check -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key,openssh-hashed-hosts
printf '\n==> verify the host-identity feature graph enables no std feature\n'
if cargo tree -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key,openssh-hashed-hosts \
    -e normal,build -e features -f '{p} {f}' | grep -E 'feature "std"' | grep -v semver; then
    echo "error: a std feature is enabled in the portable host-identity graph" >&2
    exit 1
fi
printf '\n==> verify portable key/trust builds pull no TLS, resolver or key-file crates\n'
if cargo tree -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key,openssh-hashed-hosts -e normal \
    | grep -qE 'rustls|ring|quinn|getrandom|hickory|trust-dns'; then
    echo "error: host-only crates in the portable host-identity graph" >&2
    exit 1
fi
if cargo tree -p tatami_ssh_keys --no-default-features -e normal | grep -qE 'hmac|sha1|ssh-key|tatami_ssh_openssh_compat'; then
    echo "error: known_hosts/openssh-key crates present without their features" >&2
    exit 1
fi
if cargo tree -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key -e normal \
    | grep -qE 'hmac|sha1|tatami_ssh_openssh_compat'; then
    echo "error: HMAC/SHA-1 present in known-hosts without openssh-hashed-hosts" >&2
    exit 1
fi

# SHA-1 boundary (round 6): resolved facade graphs with compatibility on and
# off, allowed dependents and call sites, the compat crate's public API; the
# self-test proves each rule reports a representative violation. See the
# rule list at the top of the script and docs/crypto-provider-audit.md.
step python3 scripts/check-sha1-boundary.py --self-test
step python3 scripts/check-sha1-boundary.py
if cargo tree -p tatami_ssh --no-default-features --features kex -e normal | grep -qE 'ssh-key|rustls|ring'; then
    echo "error: private-key or TLS crates present in the portable kex facade" >&2
    exit 1
fi

# Host-only QUIC diagnostic backend (needs a C compiler for ring).
step cargo check -p tatami_ssh_quic --no-default-features --features quinn-backend
printf '\n==> verify the QUIC backend is absent without its feature\n'
if cargo tree -p tatami_ssh_quic --no-default-features --features std -e normal | grep -qE 'quinn|rustls|ring'; then
    echo "error: QUIC backend crates present without quinn-backend" >&2
    exit 1
fi

# Facade feature matrix from docs/architecture.md.
for features in "" std tcp quic tcp,quic std,tcp std,quic std,tcp,quic kex std,tcp,kex quic-diag quic-diag,tcp std,tcp,kex,quic-diag \
    openssh-hashed-hosts kex,openssh-hashed-hosts std,tcp,kex,quic-diag,openssh-hashed-hosts; do
    if [ -z "$features" ]; then
        step cargo check -p tatami_ssh --no-default-features
    else
        step cargo check -p tatami_ssh --no-default-features --features "$features"
    fi
done

# Binaries exist only with std,tcp; cargo skips them otherwise. Build them
# explicitly so a broken bin cannot hide behind required-features.
step cargo build -p tatami_ssh --no-default-features --features std,tcp --bins
step cargo build -p tatami_ssh --no-default-features --features std,tcp,kex --bins
step cargo build -p tatami_ssh --no-default-features --features std,tcp,quic-diag --bins
step cargo build -p tatami_ssh --no-default-features --features std,tcp,kex,quic-diag --bins

step cargo test --workspace --all-features
# `--all-features` enables openssh-hashed-hosts; also test the ordinary
# configuration where a hashed known_hosts entry is an unsupported-format
# error (unit tests, facade trust and the OpenSSH identity tests).
step cargo test -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key
step cargo test -p tatami_ssh --no-default-features --features std,tcp,kex,quic-diag
step env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# Core/alloc-only check: catches accidental transitive std use that a host
# target check cannot see, because std is always present on the host.
if [ "$run_embedded" -eq 1 ]; then
    if rustc --print sysroot >/dev/null 2>&1 \
        && [ -d "$(rustc --print sysroot)/lib/rustlib/$EMBEDDED_TARGET" ]; then
        step cargo check --workspace --no-default-features --target "$EMBEDDED_TARGET"
        # Isolated allocation-free check: the workspace build above unifies
        # `alloc` into tatami_ssh_wire through its dependents.
        step cargo check -p tatami_ssh_wire --no-default-features --target "$EMBEDDED_TARGET"
        step cargo check -p tatami_ssh_wire --no-default-features --features alloc --target "$EMBEDDED_TARGET"
        step cargo check -p tatami_ssh --no-default-features --features tcp,quic --target "$EMBEDDED_TARGET"
        # Portable crypto profile on a target with no std at all.
        step cargo check -p tatami_ssh_keys --no-default-features --features ed25519 --target "$EMBEDDED_TARGET"
        step cargo check -p tatami_ssh_tcp --no-default-features --features kex --target "$EMBEDDED_TARGET"
        step cargo check -p tatami_ssh --no-default-features --features kex --target "$EMBEDDED_TARGET"
        # Portable host-identity features (round 5) with no std at all.
        step cargo check -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key --target "$EMBEDDED_TARGET"
        # Legacy hashed-hostname compatibility (round 6) with no std at all.
        step cargo check -p tatami_ssh_openssh_compat --target "$EMBEDDED_TARGET"
        step cargo check -p tatami_ssh_keys --no-default-features --features known-hosts,openssh-key,openssh-hashed-hosts --target "$EMBEDDED_TARGET"
        step cargo check -p tatami_ssh --no-default-features --features kex,openssh-hashed-hosts --target "$EMBEDDED_TARGET"
    elif [ "${CHECK_EMBEDDED_REQUIRED:-0}" = 1 ]; then
        echo "error: target $EMBEDDED_TARGET is not installed" >&2
        exit 1
    else
        echo "notice: skipping $EMBEDDED_TARGET check; target not installed" >&2
    fi
fi

printf '\nworkspace checks passed\n'
