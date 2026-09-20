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

step cargo fmt --all -- --check
step cargo clippy --workspace --all-targets --no-default-features -- -D warnings
step cargo clippy --workspace --all-targets --all-features -- -D warnings

# tatami-wire is the only shared package with a feature; check both states.
step cargo check -p tatami-wire --no-default-features
step cargo check -p tatami-wire --no-default-features --features alloc

# Bindings: portable state with and without host io modules.
for crate in tatami-tcp tatami-quic; do
    step cargo check -p "$crate" --no-default-features
    step cargo check -p "$crate" --no-default-features --features std
done

# Facade feature matrix from docs/architecture.md.
for features in "" std tcp quic tcp,quic std,tcp std,quic std,tcp,quic; do
    if [ -z "$features" ]; then
        step cargo check -p tatami --no-default-features
    else
        step cargo check -p tatami --no-default-features --features "$features"
    fi
done

step cargo test --workspace --all-features
step env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps

# Core/alloc-only check: catches accidental transitive std use that a host
# target check cannot see, because std is always present on the host.
if [ "$run_embedded" -eq 1 ]; then
    if rustc --print sysroot >/dev/null 2>&1 \
        && [ -d "$(rustc --print sysroot)/lib/rustlib/$EMBEDDED_TARGET" ]; then
        step cargo check --workspace --no-default-features --target "$EMBEDDED_TARGET"
        step cargo check -p tatami-wire --no-default-features --features alloc --target "$EMBEDDED_TARGET"
        step cargo check -p tatami --no-default-features --features tcp,quic --target "$EMBEDDED_TARGET"
    elif [ "${CHECK_EMBEDDED_REQUIRED:-0}" = 1 ]; then
        echo "error: target $EMBEDDED_TARGET is not installed" >&2
        exit 1
    else
        echo "notice: skipping $EMBEDDED_TARGET check; target not installed" >&2
    fi
fi

printf '\nworkspace checks passed\n'
