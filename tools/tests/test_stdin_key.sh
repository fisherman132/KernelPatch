#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLS_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/kptools-stdin-key.XXXXXX")
BIN="$TMP_DIR/kptools-stdin-test"
STDOUT="$TMP_DIR/stdout"
STDERR="$TMP_DIR/stderr"

cleanup()
{
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

cc -std=c11 -Wall -Wextra -Werror \
    -I"$TOOLS_DIR" -iquote "$TOOLS_DIR/../kernel/include" \
    "$TOOLS_DIR/kptools.c" "$TOOLS_DIR/key_input.c" \
    "$SCRIPT_DIR/kptools_stdin_stub.c" -o "$BIN"

fail()
{
    printf '[FAIL] kptools stdin key regression: %s\n' "$1" >&2
    exit 1
}

assert_no_key_output()
{
    for marker in stdin-root stdin-plain stdin-reset literal-normal-key literal-root-key embedded-nul second-line; do
        if grep -F "$marker" "$STDOUT" "$STDERR" >/dev/null 2>&1; then
            fail "key material appeared in command output"
        fi
    done
}

run_valid_stdin()
{
    fixture=$1
    option=$2
    format=$3

    : >"$STDOUT"
    : >"$STDERR"
    if ! printf "$format" | "$BIN" -p -i "$fixture" -k fixture-kpimg \
        "$option" - -o fixture-out >"$STDOUT" 2>"$STDERR"; then
        fail "valid $fixture input was rejected"
    fi
    assert_no_key_output
}

run_rejected_stdin()
{
    fixture=$1

    : >"$STDOUT"
    : >"$STDERR"
    if case "$fixture" in
        empty) printf '\n' ;;
        empty-eof) : ;;
        too-long) printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n' ;;
        embedded-nul) printf 'embedded-nul\000suffix\n' ;;
        extra-line) printf 'first-line\nsecond-line\n' ;;
        bare-cr) printf 'bare-carriage-return\r' ;;
        *) exit 125 ;;
    esac | "$BIN" -p -i rejected -k fixture-kpimg -S - -o fixture-out \
        >"$STDOUT" 2>"$STDERR"; then
        fail "invalid $fixture input was accepted"
    fi
    assert_no_key_output
}

run_valid_stdin root-lf -S 'stdin-root-lf\n'
run_valid_stdin root-crlf -S 'stdin-root-crlf\r\n'
run_valid_stdin plain-lf -s 'stdin-plain-lf\n'
run_valid_stdin plain-crlf -s 'stdin-plain-crlf\r\n'
run_valid_stdin max-lf -S 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n'

: >"$STDOUT"
: >"$STDERR"
if ! printf 'stdin-root-extra\n' | "$BIN" -p -i extra-name -k fixture-kpimg \
    -S - -o fixture-out -M fixture-extra.kpm -T kpm \
    -N device-profile -V pre-kernel-init >"$STDOUT" 2>"$STDERR"; then
    fail "-N extra name overwrote the -M extra path"
fi
assert_no_key_output

: >"$STDOUT"
: >"$STDERR"
"$BIN" -p -i literal-plain -k fixture-kpimg -s literal-normal-key \
    -o fixture-out </dev/null >"$STDOUT" 2>"$STDERR" || \
    fail "literal -s key compatibility failed"
assert_no_key_output

: >"$STDOUT"
: >"$STDERR"
"$BIN" -p -i literal-root -k fixture-kpimg -S literal-root-key \
    -o fixture-out </dev/null >"$STDOUT" 2>"$STDERR" || \
    fail "literal -S key compatibility failed"
assert_no_key_output

: >"$STDOUT"
: >"$STDERR"
if ! printf 'stdin-reset-lf\n' | "$BIN" -r -i reset-stdin -s - -o fixture-out \
    >"$STDOUT" 2>"$STDERR"; then
    fail "reset did not accept a valid stdin key"
fi
assert_no_key_output

: >"$STDOUT"
: >"$STDERR"
if "$BIN" -r -i reset-stdin -S - -o fixture-out </dev/null \
    >"$STDOUT" 2>"$STDERR"; then
    fail "reset accepted unsupported root-key mode"
fi
assert_no_key_output

run_rejected_stdin empty
run_rejected_stdin empty-eof
run_rejected_stdin too-long
run_rejected_stdin embedded-nul
run_rejected_stdin extra-line
run_rejected_stdin bare-cr

: >"$STDOUT"
: >"$STDERR"
if "$BIN" -r -i fixture-input -o fixture-out </dev/null \
    >"$STDOUT" 2>"$STDERR"; then
    fail "reset without a key did not fail safely"
fi
grep -F 'reset superkey requires -s KEY or -s -' "$STDERR" >/dev/null || \
    fail "reset without a key bypassed the parser guard"

# Key-like options on commands that do not consume a key must not read stdin.
: >"$STDOUT"
: >"$STDERR"
"$BIN" -h -S - </dev/null >"$STDOUT" 2>"$STDERR" || \
    fail "help command attempted to consume stdin key input"
"$BIN" -l -S - </dev/null >"$STDOUT" 2>"$STDERR" || \
    fail "list command attempted to consume stdin key input"

printf '[PASS] kptools stdin key regression tests\n'
