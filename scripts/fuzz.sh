#!/bin/sh
# Fuzzing wrapper for the isolated harness workspaces under fuzz/.
#
# Usage:
#   scripts/fuzz.sh list
#   scripts/fuzz.sh build
#   scripts/fuzz.sh lint
#   scripts/fuzz.sh replay [TARGET...]
#   scripts/fuzz.sh smoke [SECONDS]
#   scripts/fuzz.sh run TARGET [-- LIBFUZZER_ARGS...]
#   scripts/fuzz.sh reproduce TARGET ARTIFACT
#   scripts/fuzz.sh minimize TARGET ARTIFACT
#   scripts/fuzz.sh coverage TARGET
#
# Targets live in fuzz/<workspace>/fuzz_targets/<target>.rs; the wrapper
# resolves each target to its workspace. Committed seeds are in
# fuzz/<workspace>/seeds/<target>/; evolved corpora go to
# fuzz/<workspace>/corpus/<target>/ (ignored by Git).
#
# Toolchain selection (see fuzz/toolchain.env):
#   * With rustup: `cargo +$FUZZ_NIGHTLY fuzz` and AddressSanitizer.
#   * Without rustup (FUZZ_CARGO_FUZZ set to a cargo-fuzz binary): the
#     current stable cargo with RUSTC_BOOTSTRAP=1 and FUZZ_SANITIZER (default
#     `none`, because distribution toolchains ship no sanitizer runtimes).
#     This still gives coverage-guided fuzzing with overflow checks and debug
#     assertions, but not ASan; the effective configuration is printed.
# Nothing here installs software or changes a global toolchain.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
. ./fuzz/toolchain.env

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

die() {
    echo "fuzz.sh: $*" >&2
    exit 1
}

# ---- toolchain -------------------------------------------------------------
# Resolved lazily: `list` and `lint` need only a stable cargo.

toolchain_ready=0
need_toolchain() {
    [ "$toolchain_ready" -eq 1 ] && return 0
    if [ -n "${FUZZ_CARGO_FUZZ:-}" ]; then
        cargo_fuzz_bin=$FUZZ_CARGO_FUZZ
        [ -x "$cargo_fuzz_bin" ] || die "FUZZ_CARGO_FUZZ=$cargo_fuzz_bin is not executable"
        sanitizer=${FUZZ_SANITIZER:-none}
        toolchain_desc="$(rustc --version) via RUSTC_BOOTSTRAP=1 (no rustup)"
        export RUSTC_BOOTSTRAP=1
        run_cargo_fuzz() { "$cargo_fuzz_bin" fuzz "$@"; }
    elif command -v rustup >/dev/null 2>&1; then
        rustup run "$FUZZ_NIGHTLY" cargo fuzz --version >/dev/null 2>&1 \
            || die "cargo-fuzz not available on $FUZZ_NIGHTLY; see docs/fuzzing.md for one-time setup"
        sanitizer=${FUZZ_SANITIZER:-address}
        toolchain_desc="$FUZZ_NIGHTLY via rustup"
        run_cargo_fuzz() { rustup run "$FUZZ_NIGHTLY" cargo fuzz "$@"; }
    else
        die "neither rustup nor FUZZ_CARGO_FUZZ is available; see docs/fuzzing.md"
    fi
    toolchain_ready=1
}

# ---- target resolution -----------------------------------------------------

workspaces="wire-core protocol"

all_targets() {
    for ws in $workspaces; do
        for f in fuzz/"$ws"/fuzz_targets/*.rs; do
            [ -e "$f" ] || continue
            printf '%s %s\n' "$ws" "$(basename "$f" .rs)"
        done
    done
}

workspace_of() {
    for ws in $workspaces; do
        if [ -e "fuzz/$ws/fuzz_targets/$1.rs" ]; then
            echo "$ws"
            return 0
        fi
    done
    die "unknown target '$1' (try: scripts/fuzz.sh list)"
}

fuzz_dir_args() {
    echo "--fuzz-dir fuzz/$1 -s $sanitizer"
}

print_config() {
    need_toolchain
    echo "fuzz.sh: toolchain: $toolchain_desc"
    echo "fuzz.sh: cargo-fuzz: $(run_cargo_fuzz --version 2>/dev/null || echo unknown)"
    echo "fuzz.sh: sanitizer: $sanitizer; overflow-checks and debug-assertions on (see fuzz/*/Cargo.toml)"
}

# ---- commands --------------------------------------------------------------

cmd_list() {
    all_targets | while read -r ws t; do
        seeds=$(find "fuzz/$ws/seeds/$t" -type f 2>/dev/null | wc -l | tr -d ' ')
        printf '%-24s %-10s seeds=%s\n' "$t" "$ws" "$seeds"
    done
}

cmd_build() {
    print_config
    for ws in $workspaces; do
        echo "==> build fuzz/$ws"
        # shellcheck disable=SC2046
        run_cargo_fuzz build $(fuzz_dir_args "$ws")
    done
}

cmd_lint() {
    for ws in $workspaces; do
        echo "==> fmt fuzz/$ws"
        (cd "fuzz/$ws" && cargo fmt --all -- --check)
        echo "==> clippy fuzz/$ws"
        # Harness crates need the fuzzing cfg only when built by cargo-fuzz;
        # plain clippy on the manifest is enough for lint purposes.
        (cd "fuzz/$ws" && cargo clippy --all-targets -- -D warnings)
    done
}

# Replay: execute every committed seed once through the target and exit.
# libFuzzer semantics verified: with `-runs=0` it loads the given corpus
# directories, runs each input exactly once ("INFO: seed corpus: files: N"
# and "Executed N inputs"), performs no mutation, and returns nonzero on any
# crash/timeout/OOM. The seeds directory is passed as the only corpus so
# nothing is written into it.
cmd_replay() {
    print_config
    if [ $# -eq 0 ]; then
        set -- $(all_targets | awk '{print $2}')
    fi
    for t in "$@"; do
        ws=$(workspace_of "$t")
        seeds="fuzz/$ws/seeds/$t"
        if [ ! -d "$seeds" ] || [ -z "$(ls -A "$seeds")" ]; then
            die "target $t has no committed seeds in $seeds"
        fi
        echo "==> replay $t ($(find "$seeds" -type f | wc -l | tr -d ' ') seeds)"
        # shellcheck disable=SC2046
        run_cargo_fuzz run $(fuzz_dir_args "$ws") "$t" "$seeds" -- \
            -runs=0 -timeout="$FUZZ_TIMEOUT_SECS" -rss_limit_mb="$FUZZ_RSS_LIMIT_MB"
    done
}

# Smoke: build, replay, then a short bounded mutation run per target.
cmd_smoke() {
    secs=${1:-5}
    cmd_build
    cmd_replay
    all_targets | while read -r ws t; do
        echo "==> smoke $t for ${secs}s"
        cmd_run "$t" -- -max_total_time="$secs" -seed=1
    done
}

target_max_len() {
    case "$1" in
        tcp_initial_packets|tcp_probe|tcp_observer|observation_records) echo 524288 ;;
        wire_messages|input_buffer|channel_opening|json_values) echo 65536 ;;
        *) echo 4096 ;;
    esac
}

cmd_run() {
    need_toolchain
    [ $# -ge 1 ] || usage
    t=$1
    shift
    [ "${1:-}" = "--" ] && shift
    ws=$(workspace_of "$t")
    seeds="fuzz/$ws/seeds/$t"
    corpus="fuzz/$ws/corpus/$t"
    mkdir -p "$corpus"
    # The evolved corpus is first (new inputs are written there); seeds are
    # read-only inputs. Defaults come first so user args override them.
    # shellcheck disable=SC2046
    run_cargo_fuzz run $(fuzz_dir_args "$ws") "$t" "$corpus" "$seeds" -- \
        -timeout="$FUZZ_TIMEOUT_SECS" -rss_limit_mb="$FUZZ_RSS_LIMIT_MB" \
        -max_len="$(target_max_len "$t")" "$@"
}

cmd_reproduce() {
    [ $# -eq 2 ] || usage
    ws=$(workspace_of "$1")
    print_config
    # shellcheck disable=SC2046
    run_cargo_fuzz run $(fuzz_dir_args "$ws") "$1" "$2" -- -runs=0
}

cmd_minimize() {
    need_toolchain
    [ $# -eq 2 ] || usage
    ws=$(workspace_of "$1")
    # shellcheck disable=SC2046
    run_cargo_fuzz tmin $(fuzz_dir_args "$ws") "$1" "$2"
}

cmd_coverage() {
    need_toolchain
    [ $# -eq 1 ] || usage
    t=$1
    ws=$(workspace_of "$t")
    seeds="fuzz/$ws/seeds/$t"
    corpus="fuzz/$ws/corpus/$t"
    covdir="fuzz/$ws/coverage/$t"
    rm -rf "$covdir"
    profdata="$covdir/coverage.profdata"
    # cargo-fuzz runs each corpus directory as a separate process and every
    # process writes the same default-<target>.profraw, so a second directory
    # would overwrite the first. Copy seeds and evolved corpus into one
    # scratch directory and run that once.
    inputs="$covdir/inputs"
    mkdir -p "$inputs"
    find "$seeds" -type f ! -name '*.py' -exec cp -t "$inputs" {} +
    [ -d "$corpus" ] && find "$corpus" -type f -exec cp -t "$inputs" {} + 2>/dev/null
    echo "==> coverage $t over $(find "$inputs" -type f | wc -l | tr -d ' ') inputs (seeds + corpus)"
    # cargo-fuzz builds an instrumented binary, runs every input once and
    # merges the .profraw files with llvm-profdata (from the toolchain's
    # llvm-tools, or LLVM_PROFDATA / PATH for a distribution toolchain).
    # shellcheck disable=SC2046
    if ! run_cargo_fuzz coverage $(fuzz_dir_args "$ws") "$t" "$inputs"; then
        # cargo-fuzz only looks in the rustc sysroot for llvm-profdata. With a
        # distribution toolchain the raw profiles exist but the merge fails;
        # merge them with the llvm-profdata on PATH (or LLVM_PROFDATA).
        llvm_profdata=${LLVM_PROFDATA:-llvm-profdata}
        [ -d "$covdir/raw" ] || die "coverage run failed before writing raw profiles"
        command -v "$llvm_profdata" >/dev/null 2>&1 \
            || die "cargo-fuzz could not merge profiles and $llvm_profdata is not on PATH"
        echo "fuzz.sh: merging raw profiles with $llvm_profdata"
        "$llvm_profdata" merge -sparse "$covdir/raw" -o "$profdata"
    fi
    # cargo-fuzz writes the instrumented binary under the *current directory's*
    # target/<triple>/coverage/ (separate from the fuzzing binaries).
    bin="target/$FUZZ_HOST_TRIPLE/coverage/$FUZZ_HOST_TRIPLE/release/$t"
    [ -f "$profdata" ] || die "no profdata at $profdata"
    [ -f "$bin" ] || die "no coverage binary at $bin"
    llvm_cov=${LLVM_COV:-llvm-cov}
    command -v "$llvm_cov" >/dev/null 2>&1 || die "$llvm_cov not found; set LLVM_COV"
    "$llvm_cov" report "$bin" -instr-profile="$profdata" \
        -ignore-filename-regex='(/\.cargo/|/rustc/|fuzz_targets/|fuzz/[a-z-]+/src/)'
    echo "fuzz.sh: for line detail: $llvm_cov show $bin -instr-profile=$profdata -format=text <source-file>"
}

[ $# -ge 1 ] || usage
cmd=$1
shift
case "$cmd" in
    list) cmd_list "$@" ;;
    build) cmd_build "$@" ;;
    lint) cmd_lint "$@" ;;
    replay) cmd_replay "$@" ;;
    smoke) cmd_smoke "$@" ;;
    run) cmd_run "$@" ;;
    reproduce) cmd_reproduce "$@" ;;
    minimize) cmd_minimize "$@" ;;
    coverage) cmd_coverage "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown subcommand '$cmd'" ;;
esac
