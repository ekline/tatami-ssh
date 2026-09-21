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
if cargo metadata --no-deps --format-version 1 | grep -q 'tatami-fuzz-'; then
    echo "error: a fuzz harness package is a member of the production workspace" >&2
    exit 1
fi

step cargo fmt --all -- --check
step cargo clippy --workspace --all-targets --no-default-features -- -D warnings
step cargo clippy --workspace --all-targets --all-features -- -D warnings

# tatami-wire is the only shared package with a feature; check both states.
# The allocation-free path is checked in isolation: when other workspace
# members are selected they enable `tatami-wire/alloc`, which would mask an
# accidental alloc dependency. Verify the resolved feature set is empty.
step cargo check -p tatami-wire --no-default-features
step cargo test -p tatami-wire --no-default-features
printf '\n==> verify tatami-wire resolves with no features when checked alone\n'
wire_features=$(cargo tree -p tatami-wire --no-default-features -e features --depth 0 -f '{f}')
if [ -n "$wire_features" ]; then
    echo "error: tatami-wire unexpectedly has features enabled: $wire_features" >&2
    exit 1
fi
step cargo check -p tatami-wire --no-default-features --features alloc

# Bindings: portable state with and without host io modules.
for crate in tatami-tcp tatami-quic; do
    step cargo check -p "$crate" --no-default-features
    step cargo check -p "$crate" --no-default-features --features std
done

# Portable crypto profile (round 4): must not pull std. The graph check
# tolerates only the `semver` edge, which is curve25519-dalek's build script.
step cargo check -p tatami-keys --no-default-features --features ed25519
step cargo check -p tatami-tcp --no-default-features --features kex
step cargo check -p tatami-tcp --no-default-features --features std,kex
printf '\n==> verify the kex feature graph enables no std feature\n'
if cargo tree -p tatami-tcp --no-default-features --features kex -e features -f '{p} {f}' \
    | grep -E 'feature "std"' | grep -v semver; then
    echo "error: a std feature is enabled in the portable kex graph" >&2
    exit 1
fi

# Host-only QUIC diagnostic backend (needs a C compiler for ring).
step cargo check -p tatami-quic --no-default-features --features quinn-backend
printf '\n==> verify the QUIC backend is absent without its feature\n'
if cargo tree -p tatami-quic --no-default-features --features std -e normal | grep -qE 'quinn|rustls|ring'; then
    echo "error: QUIC backend crates present without quinn-backend" >&2
    exit 1
fi

# Facade feature matrix from docs/architecture.md.
for features in "" std tcp quic tcp,quic std,tcp std,quic std,tcp,quic kex std,tcp,kex quic-diag quic-diag,tcp std,tcp,kex,quic-diag; do
    if [ -z "$features" ]; then
        step cargo check -p tatami --no-default-features
    else
        step cargo check -p tatami --no-default-features --features "$features"
    fi
done

# Binaries exist only with std,tcp; cargo skips them otherwise. Build them
# explicitly so a broken bin cannot hide behind required-features.
step cargo build -p tatami --no-default-features --features std,tcp --bins
step cargo build -p tatami --no-default-features --features std,tcp,kex --bins
step cargo build -p tatami --no-default-features --features quic-diag --bins

step cargo test --workspace --all-features
step env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# Core/alloc-only check: catches accidental transitive std use that a host
# target check cannot see, because std is always present on the host.
if [ "$run_embedded" -eq 1 ]; then
    if rustc --print sysroot >/dev/null 2>&1 \
        && [ -d "$(rustc --print sysroot)/lib/rustlib/$EMBEDDED_TARGET" ]; then
        step cargo check --workspace --no-default-features --target "$EMBEDDED_TARGET"
        # Isolated allocation-free check: the workspace build above unifies
        # `alloc` into tatami-wire through its dependents.
        step cargo check -p tatami-wire --no-default-features --target "$EMBEDDED_TARGET"
        step cargo check -p tatami-wire --no-default-features --features alloc --target "$EMBEDDED_TARGET"
        step cargo check -p tatami --no-default-features --features tcp,quic --target "$EMBEDDED_TARGET"
        # Portable crypto profile on a target with no std at all.
        step cargo check -p tatami-keys --no-default-features --features ed25519 --target "$EMBEDDED_TARGET"
        step cargo check -p tatami-tcp --no-default-features --features kex --target "$EMBEDDED_TARGET"
        step cargo check -p tatami --no-default-features --features kex --target "$EMBEDDED_TARGET"
    elif [ "${CHECK_EMBEDDED_REQUIRED:-0}" = 1 ]; then
        echo "error: target $EMBEDDED_TARGET is not installed" >&2
        exit 1
    else
        echo "notice: skipping $EMBEDDED_TARGET check; target not installed" >&2
    fi
fi

printf '\nworkspace checks passed\n'
