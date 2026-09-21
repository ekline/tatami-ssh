#!/bin/sh
# Reproducible local OpenSSH sshd fixture for `tatami-client handshake`.
#
# Usage:
#   scripts/openssh-fixture.sh start  [--port PORT] [--profile default|matching|mismatch]
#   scripts/openssh-fixture.sh run    [--port PORT] [--profile default|matching|mismatch]
#   scripts/openssh-fixture.sh pin
#   scripts/openssh-fixture.sh status
#   scripts/openssh-fixture.sh stop
#
# `start` generates an ephemeral Ed25519 host key under target/openssh-fixture/,
# starts `sshd -D -e -f /dev/null` on a loopback port (PORT, or a free high
# port chosen here), waits for its "Server listening" line, and prints the
# operator command that yields the pin (`ssh-keygen -lf .../hostkey.pub`) and
# the exact `cargo run ... handshake` command to run against it. `run` does
# the same in the foreground and cleans up on Ctrl-C or SIGTERM. `pin` prints
# only the SHA256: fingerprint. `stop` kills sshd and removes the key
# directory.
#
# Profiles add sshd options:
#   default   no restriction (sshd's defaults; the profile is negotiated)
#   matching  KexAlgorithms=curve25519-sha256 HostKeyAlgorithms=ssh-ed25519
#             Ciphers=aes128-gcm@openssh.com  (exactly the Tatami profile)
#   mismatch  Ciphers=aes256-ctr  (negotiation must fail: no common cipher)
#
# The fixture is a diagnostic aid for a loopback handshake only: no user can
# log in (UsePAM=no, no authorized keys), and the key is deleted on `stop`.

set -eu

SSHD=/usr/sbin/sshd
SSH_KEYGEN=/usr/bin/ssh-keygen
NAME=openssh-fixture

cd "$(dirname "$0")/.."
ROOT=$PWD
DIR=$ROOT/target/openssh-fixture
KEY=$DIR/hostkey
LOG=$DIR/sshd.log
PIDFILE=$DIR/sshd.pid
PORTFILE=$DIR/port
PROFILEFILE=$DIR/profile

say() { printf '%s: %s\n' "$NAME" "$*"; }
die() { printf '%s: %s\n' "$NAME" "$*" >&2; exit 1; }
usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
}

require_openssh() {
    [ -x "$SSHD" ] || die "$SSHD is not executable; install OpenSSH server"
    [ -x "$SSH_KEYGEN" ] || die "$SSH_KEYGEN is not executable; install OpenSSH"
}

running_pid() {
    # Prints the pid when sshd from a previous `start` is alive; else nothing.
    [ -f "$PIDFILE" ] || return 0
    pid=$(cat "$PIDFILE")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        printf '%s\n' "$pid"
    fi
}

fingerprint() {
    # The operator's independent source for the pin: ssh-keygen -l on the
    # public key file, never anything read from the connection.
    "$SSH_KEYGEN" -lf "$KEY.pub" | tr ' ' '\n' | grep '^SHA256:' | head -n 1
}

print_commands() {
    port=$1
    pin=$(fingerprint)
    say "host key fingerprint, obtained with: $SSH_KEYGEN -lf $KEY.pub"
    printf '  %s\n' "$pin"
    say "run the handshake with:"
    printf "  cargo run -p tatami --features std,tcp,kex --bin tatami-client -- handshake 127.0.0.1 --port %s --host-key-sha256 '%s'\n" "$port" "$pin"
    say "JSON form: append --json; wrong-pin check: change one character of the pin (exit status 1)"
}

# Starts sshd on $1 (a port, or 0 for an automatically chosen free port)
# with profile $2. Sets $port. Returns non-zero if sshd does not come up.
launch() {
    want=$1
    profile=$2
    attempt=0
    while :; do
        attempt=$((attempt + 1))
        if [ "$want" = 0 ]; then
            # Deterministic-enough high port from the pid and attempt; a
            # collision is detected from sshd's log and retried.
            port=$((20000 + ($$ + attempt * 977) % 30000))
        else
            port=$want
        fi
        : >"$LOG"
        set -- -D -e -f /dev/null -p "$port" \
            -o ListenAddress=127.0.0.1 -h "$KEY" \
            -o UsePAM=no -o PidFile=none -o LogLevel=VERBOSE \
            -o MaxStartups=10 -o PerSourcePenalties=no
        case "$profile" in
            default) ;;
            matching)
                set -- "$@" -o KexAlgorithms=curve25519-sha256 \
                    -o HostKeyAlgorithms=ssh-ed25519 \
                    -o Ciphers=aes128-gcm@openssh.com
                ;;
            mismatch) set -- "$@" -o Ciphers=aes256-ctr ;;
            *) die "unknown profile '$profile' (default, matching or mismatch)" ;;
        esac
        say "starting: $SSHD $*"
        "$SSHD" "$@" >>"$LOG" 2>&1 &
        pid=$!
        printf '%s\n' "$pid" >"$PIDFILE"

        # Bounded wait for readiness; sshd -e logs to stderr (captured).
        i=0
        while [ "$i" -lt 100 ]; do
            if grep -q 'Server listening on' "$LOG" 2>/dev/null; then
                printf '%s\n' "$port" >"$PORTFILE"
                printf '%s\n' "$profile" >"$PROFILEFILE"
                return 0
            fi
            if ! kill -0 "$pid" 2>/dev/null; then
                break
            fi
            i=$((i + 1))
            sleep 0.1
        done
        kill "$pid" 2>/dev/null || true
        rm -f "$PIDFILE"
        if [ "$want" = 0 ] && [ "$attempt" -lt 5 ] && grep -q 'Address already in use' "$LOG"; then
            say "port $port is busy; trying another"
            continue
        fi
        say "sshd did not start; log follows" >&2
        cat "$LOG" >&2
        return 1
    done
}

cmd_start() {
    want=0
    profile=default
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --port)
                [ "$#" -ge 2 ] || die "--port requires a value"
                want=$2
                shift 2
                ;;
            --profile)
                [ "$#" -ge 2 ] || die "--profile requires a value"
                profile=$2
                shift 2
                ;;
            -h|--help) usage ;;
            *) die "unknown argument '$1'" ;;
        esac
    done
    case "$want" in
        ''|*[!0-9]*) die "--port must be a number" ;;
    esac
    require_openssh
    if [ -n "$(running_pid)" ]; then
        die "already running (pid $(running_pid), port $(cat "$PORTFILE")); run '$0 stop' first"
    fi
    rm -rf "$DIR"
    mkdir -p "$DIR"
    "$SSH_KEYGEN" -q -t ed25519 -N '' -f "$KEY"
    launch "$want" "$profile"
    version=$("$SSHD" -V 2>&1 || true)
    say "sshd ($version) listening on 127.0.0.1:$port, profile $profile, pid $(cat "$PIDFILE")"
    say "state directory: $DIR (log: $LOG)"
    print_commands "$port"
}

cmd_status() {
    pid=$(running_pid)
    if [ -z "$pid" ]; then
        say "not running"
        return 1
    fi
    say "running: pid $pid, 127.0.0.1:$(cat "$PORTFILE"), profile $(cat "$PROFILEFILE")"
    print_commands "$(cat "$PORTFILE")"
    say "last log lines:"
    tail -n 5 "$LOG" | sed 's/^/  /'
}

cmd_pin() {
    [ -f "$KEY.pub" ] || die "no host key; run '$0 start' first"
    require_openssh
    fingerprint
}

cmd_stop() {
    pid=$(running_pid)
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || true
        i=0
        while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 50 ]; do
            i=$((i + 1))
            sleep 0.1
        done
        say "stopped sshd (pid $pid)"
    else
        say "sshd was not running"
    fi
    rm -rf "$DIR"
    say "removed $DIR"
}

cmd_run() {
    cmd_start "$@"
    pid=$(cat "$PIDFILE")
    say "press Ctrl-C to stop"
    trap 'cmd_stop; exit 0' INT TERM
    # sshd is our child, so this returns when it exits or when a trap fires.
    wait "$pid" || true
    cmd_stop
}

[ "$#" -ge 1 ] || usage
command=$1
shift
case "$command" in
    start) cmd_start "$@" ;;
    run) cmd_run "$@" ;;
    pin) cmd_pin "$@" ;;
    status) cmd_status "$@" ;;
    stop) cmd_stop "$@" ;;
    -h|--help|help) usage ;;
    *) die "unknown command '$command' (start, run, pin, status, stop)" ;;
esac
