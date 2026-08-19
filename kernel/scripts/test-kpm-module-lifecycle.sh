#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

set -eu
export LC_ALL=C

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
KERNEL_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TEST_SOURCE="$KERNEL_DIR/tests/kpm_module_lifecycle_test.c"
MODULE_SOURCE="$KERNEL_DIR/patch/module/module.c"
MODULE_HEADER="$KERNEL_DIR/patch/include/module.h"
RCU_HEADER="$KERNEL_DIR/linux/include/linux/rcupdate.h"
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/kpm-module-lifecycle.XXXXXX")

cleanup()
{
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT HUP INT TERM

fail()
{
    printf '[FAIL] KPM module lifecycle regression: %s\n' "$1" >&2
    exit 1
}

require_file()
{
    [ -r "$1" ] || fail "unreadable source: $1"
}

require_file "$TEST_SOURCE"
require_file "$MODULE_SOURCE"
require_file "$MODULE_HEADER"
require_file "$RCU_HEADER"

python3 - "$MODULE_SOURCE" "$MODULE_HEADER" "$RCU_HEADER" <<'PY' || exit $?
import re
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
source = source_path.read_text(encoding="utf-8")
module_header = Path(sys.argv[2]).read_text(encoding="utf-8")
rcu_header = Path(sys.argv[3]).read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"[FAIL] KPM module lifecycle regression: {message}", file=sys.stderr)
    raise SystemExit(1)


def strip_noncode(text: str) -> str:
    output = []
    state = "code"
    index = 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and following == "*":
                output.extend((" ", " "))
                state = "block_comment"
                index += 2
                continue
            if char == "/" and following == "/":
                output.extend((" ", " "))
                state = "line_comment"
                index += 2
                continue
            if char == '"':
                output.append(" ")
                state = "string"
            elif char == "'":
                output.append(" ")
                state = "character"
            else:
                output.append(char)
        elif state == "block_comment":
            if char == "*" and following == "/":
                output.extend((" ", " "))
                state = "code"
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
        elif state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        else:
            if char == "\\" and following:
                output.extend((" ", " ") if following != "\n" else (" ", "\n"))
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
            if (state == "string" and char == '"') or (state == "character" and char == "'"):
                state = "code"
        index += 1
    return "".join(output)


code_source = strip_noncode(source)
module_header_code = strip_noncode(module_header)
rcu_header_code = strip_noncode(rcu_header)


def function_body(name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", code_source, re.S)
    if not match:
        fail(f"cannot locate production function {name}")
    start = code_source.find("{", match.start())
    depth = 0
    index = start
    while index < len(code_source):
        char = code_source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return code_source[start + 1 : index]
        index += 1
    fail(f"unterminated production function {name}")
    return ""


def transitive_body(name: str, seen=None) -> str:
    if seen is None:
        seen = set()
    if name in seen:
        return ""
    seen.add(name)
    body = function_body(name)
    pieces = [body]
    for helper in ("module_get_live", "module_try_get_live", "module_put_live"):
        if helper not in seen and re.search(rf"\b{helper}\s*\(", body):
            pieces.append(transitive_body(helper, seen))
    return "\n".join(pieces)


def require(body: str, pattern: str, description: str) -> None:
    if not re.search(pattern, body, re.S):
        fail(f"production invariant missing: {description}")


for state in ("MODULE_LIVE", "MODULE_EXITING", "MODULE_INIT_FAILED"):
    require(module_header_code, rf"\b{state}\b", f"{state} declaration")
    require(code_source, rf"\b{state}\b", f"{state} used by the loader")
require(module_header_code, r"atomic_t\s+active_calls\s*;", "active callback counter")
require(code_source, r"spin_lock[^;]*module_lock", "module registry lock acquisition")
require(code_source, r"spin_unlock[^;]*module_lock", "module registry lock release")
require(rcu_header_code, r"kfunc_call_void\s*\(\s*synchronize_rcu\s*\)",
        "synchronize_rcu wrapper dispatches the matching kernel function")
if re.search(r"\blist_add_tail\s*\(\s*&mod->list", code_source):
    fail("unsafe production pattern remains: non-RCU module publication")
if re.search(r"\blist_del\s*\(\s*&mod->list", code_source):
    fail("unsafe production pattern remains: non-RCU module retirement")


load = function_body("load_module")
unload = function_body("unload_module")
control0 = function_body("module_control0")
control1 = function_body("module_control1")
events = function_body("notify_modules_event")
control0_lifecycle = transitive_body("module_control0")
control1_lifecycle = transitive_body("module_control1")
event_lifecycle = transitive_body("notify_modules_event")

require(load, r"MODULE_LOADING", "load reserves a LOADING entry before init")
require(load, r"MODULE_LIVE", "successful init transitions to LIVE")
require(load, r"MODULE_INIT_FAILED", "failed init transitions to INIT_FAILED")
require(load, r"active_calls", "load initializes active callback accounting")
require(load, r"list_add_tail_rcu\s*\(", "load publishes with list_add_tail_rcu")
require(load, r"EEXIST", "same-name load is rejected")
loading_store = re.search(r"module_state_store\s*\(\s*mod\s*,\s*MODULE_LOADING\s*\)", load)
publication = re.search(r"list_add_tail_rcu\s*\(", load)
init_call = re.search(r"(?:mod->init_rc|rc)\s*=\s*\(\*mod->init\)\s*\(", load)
live_store = re.search(r"module_state_store\s*\(\s*mod\s*,\s*MODULE_LIVE\s*\)", load)
if not all((loading_store, publication, init_call, live_store)):
    fail("cannot locate ordered load lifecycle operations")
if not (loading_store.start() < publication.start() < init_call.start() < live_store.start()):
    fail("load lifecycle is not LOADING -> publish -> init -> LIVE")

require(unload, r"MODULE_EXITING", "unload marks EXITING")
require(unload, r"active_calls", "unload gates active callbacks")
require(unload, r"list_del_rcu\s*\(", "successful unload retires with list_del_rcu")
require(unload, r"synchronize_rcu\s*\(", "unload waits for an RCU grace period")
require(unload, r"previous_state", "unload retains the state restored after a veto")

exit_call = re.search(r"(?P<lhs>(?:\b[a-zA-Z_][a-zA-Z0-9_]*->exit_rc\s*=\s*)?)\(\*(?P<obj>[a-zA-Z_][a-zA-Z0-9_]*)->exit\)\s*\(", unload)
if not exit_call:
    fail("cannot locate unload exit callback")
if not exit_call.group("lhs") and not re.search(r"\brc\s*=\s*\(\*[^)]*->exit\)\s*\(", unload):
    fail("unload does not retain the exit callback result")

delete_positions = [match.start() for match in re.finditer(r"list_del_rcu\s*\(", unload)]
free_positions = [match.start() for match in re.finditer(r"(?:kp_free_exec|kvfree|free_module)\s*\(", unload)]
if delete_positions and delete_positions[0] < exit_call.start():
    fail("unload removes the list entry before exit can veto")
if free_positions and free_positions[0] < exit_call.start():
    fail("unload frees module resources before observing exit result")
veto_branch = re.search(r"if\s*\(\s*(?:rc|mod->exit_rc)\s*\)\s*\{(?P<body>.*?)\}",
                        unload[exit_call.end():], re.S)
if not veto_branch:
    fail("unload does not branch on a nonzero exit result")
require(veto_branch.group("body"), r"module_state_store\s*\([^,]+,\s*previous_state\s*\)",
        "exit veto restores the previous list-visible state")
if re.search(r"(?:list_del_rcu|kp_free_exec|free_module|kvfree)\s*\(", veto_branch.group("body")):
    fail("exit veto path retires or frees the module")
unload_delete = re.search(r"list_del_rcu\s*\(", unload)
unload_sync = re.search(r"synchronize_rcu\s*\(", unload)
unload_free = re.search(r"free_module\s*\(\s*mod\s*\)", unload)
if not all((unload_delete, unload_sync, unload_free)):
    fail("successful unload is missing retirement, grace period, or release")
if not (exit_call.start() < unload_delete.start() < unload_sync.start() < unload_free.start()):
    fail("successful unload is not exit -> list_del_rcu -> synchronize_rcu -> free_module")

init_exit_call = re.search(r"(?:mod->exit_rc|rc)\s*=\s*\(\*mod->exit\)\s*\(", load)
if not init_exit_call:
    fail("cannot locate failed-init cleanup callback")
init_failed_stores = list(re.finditer(
    r"module_state_store\s*\(\s*mod\s*,\s*MODULE_INIT_FAILED\s*\)", load))
if not any(store.start() > init_exit_call.start() for store in init_failed_stores):
    fail("failed init is not retained as INIT_FAILED after cleanup veto")
load_delete = re.search(r"list_del_rcu\s*\(", load)
load_syncs = list(re.finditer(r"synchronize_rcu\s*\(", load))
load_sync = min((sync for sync in load_syncs
                 if load_delete and sync.start() > load_delete.start()),
                key=lambda match: match.start(), default=None)
load_exec_free = re.search(r"kp_free_exec\s*\(\s*mod->start\s*\)", load)
load_module_free = re.search(r"kvfree\s*\(\s*mod\s*\)", load)
if not load_delete or not load_sync:
    fail("successful failed-init cleanup does not retire before the RCU grace period")
if not all((load_exec_free, load_module_free)) or not (
        load_sync.start() < load_exec_free.start() < load_module_free.start()):
    fail("successful failed-init cleanup does not free executable and module state after RCU")

callback_gate = r"MODULE_LIVE"
active_acquire = r"(?:atomic_(?:inc|inc_return|cmpxchg)|__atomic_add_fetch|active_calls\s*\+\+)"
active_release = r"(?:atomic_(?:dec|dec_and_test)|__atomic_sub_fetch|active_calls\s*--)"
for name, body in (("module_control0", control0_lifecycle),
                   ("module_control1", control1_lifecycle),
                   ("notify_modules_event", event_lifecycle)):
    require(body, callback_gate, f"{name} only dispatches LIVE modules")
    require(body, active_acquire, f"{name} acquires an active callback reference")
    require(body, active_release, f"{name} releases its active callback reference")

for name, body, lifecycle_body, callback_pattern in (
    ("module_control0", control0, control0_lifecycle, r"\(\*mod->ctl0\)\s*\("),
    ("module_control1", control1, control1_lifecycle, r"\(\*mod->ctl1\)\s*\("),
    ("notify_modules_event", events, event_lifecycle, r"\(\*cursor->event\)\s*\("),
):
    callback = re.search(callback_pattern, body)
    if not callback:
        fail(f"cannot locate {name} callback")
    require(lifecycle_body, r"(?:module_get_live|module_try_get_live)\s*\(",
            f"{name} acquires a live reference")
    require(lifecycle_body, r"module_put_live\s*\(",
            f"{name} releases its live reference")

for name, body, callback_pattern in (
    ("module_control0", control0, r"\(\*mod->ctl0\)\s*\("),
    ("module_control1", control1, r"\(\*mod->ctl1\)\s*\("),
):
    acquire = re.search(r"module_get_live\s*\(", body)
    callback = re.search(callback_pattern, body)
    puts = list(re.finditer(r"module_put_live\s*\(", body))
    release = min((put for put in puts if callback and put.start() > callback.start()),
                  key=lambda match: match.start(), default=None)
    if not all((acquire, callback, release)) or acquire.start() > callback.start():
        fail(f"{name} does not order live acquire -> callback -> live release")

require(control0, r"__atomic_compare_exchange_n\s*\(\s*&mod->ctl_active\.counter",
        "module_control0 serializes ctl0 dispatch with ctl_active CAS")
control_allocate = re.search(r"new_args\s*=\s*(?:vmalloc|kmalloc|kstrdup|memdup)\s*\(", control0)
control_copy = re.search(r"(?:strcpy|memcpy)\s*\(\s*new_args\s*,", control0)
control_old = re.search(r"old_args\s*=\s*mod->ctl_args", control0)
control_publish = re.search(r"mod->ctl_args\s*=\s*new_args", control0)
control_callback = re.search(r"\(\*mod->ctl0\)\s*\(\s*mod->ctl_args\s*,", control0)
control_unlocks = list(re.finditer(
    r"__atomic_store_n\s*\(\s*&mod->ctl_active\.counter\s*,\s*0", control0))
control_unlock = min((match for match in control_unlocks
                      if control_callback and match.start() > control_callback.start()),
                     key=lambda match: match.start(), default=None)
control_puts = list(re.finditer(r"module_put_live\s*\(", control0))
if not all((control_allocate, control_copy, control_old, control_publish, control_callback, control_unlock)):
    fail("module_control0 serialized argument replacement is incomplete")
if not (control_allocate.start() < control_copy.start() < control_old.start() <
        control_publish.start() < control_callback.start() < control_unlock.start()):
    fail("module_control0 argument lifecycle ordering is unsafe")
if not any(put.start() > control_unlock.start() for put in control_puts):
    fail("module_control0 drops the live reference before releasing ctl_active")

event_callback = re.search(r"\(\*cursor->event\)\s*\(", events)
event_lock = re.search(r"rcu_read_lock\s*\(", events)
event_unlocks = list(re.finditer(r"rcu_read_unlock\s*\(", events))
event_acquire = re.search(r"module_try_get_live\s*\(\s*candidate\s*\)", events)
event_put = re.search(r"module_put_live\s*\(\s*cursor\s*\)", events)
event_assign = re.search(r"cursor\s*=\s*selected", events)
if not all((event_callback, event_lock, event_acquire, event_put, event_assign)):
    fail("event traversal does not pin current and next modules")
event_unlock = max((match for match in event_unlocks if match.start() < event_callback.start()),
                   key=lambda match: match.start(), default=None)
if not event_unlock or not (event_lock.start() < event_acquire.start() < event_unlock.start() <
                            event_callback.start()):
    fail("event callback is not dispatched outside its short RCU acquisition window")
if not (event_put.start() < event_assign.start() < event_callback.start()):
    fail("event traversal does not release old cursor then bind pinned selected module")
early_put = re.search(r"module_put_live\s*\(\s*cursor\s*\)",
                      events[event_assign.end():event_callback.start()])
if early_put:
    fail("event traversal releases selected cursor before its callback")

print("[PASS] KPM module lifecycle production invariants")
PY

compiler_kind()
{
    "$1" -dM -E -x c /dev/null 2>/dev/null
}

run_host_test()
{
    compiler=$1
    label=$2
    binary="$TMP_DIR/kpm-module-lifecycle-$label"

    command -v "$compiler" >/dev/null 2>&1 || fail "$label compiler not found: $compiler"
    "$compiler" -std=c11 -Wall -Wextra -Werror -O1 -g \
        -fno-omit-frame-pointer -fsanitize=address,undefined \
        "$TEST_SOURCE" -o "$binary" || fail "$label sanitizer build failed"

    leak_option=detect_leaks=1
    case $(uname -s) in
        Darwin) leak_option=detect_leaks=0 ;;
    esac
    ASAN_OPTIONS="$leak_option:halt_on_error=1:abort_on_error=1" \
    UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
        "$binary" || fail "$label lifecycle or sanitizer checks failed"
    printf '[PASS] KPM module lifecycle %s strict ASan/UBSan build\n' "$label"
}

CLANG=${CLANG:-clang}
if [ "${GCC+x}" = x ]; then
    GCC_EXPLICIT=1
else
    GCC_EXPLICIT=0
    GCC=
    for candidate in gcc-16 gcc-15 gcc-14 gcc-13 gcc-12 gcc-11 gcc; do
        if command -v "$candidate" >/dev/null 2>&1; then
            candidate_macros=$(compiler_kind "$candidate") || continue
            if printf '%s\n' "$candidate_macros" | grep -q '^#define __GNUC__ ' &&
               ! printf '%s\n' "$candidate_macros" | grep -q '^#define __clang__ '; then
                GCC=$candidate
                break
            fi
        fi
    done
fi

clang_macros=$(compiler_kind "$CLANG") || fail "cannot identify Clang compiler: $CLANG"
printf '%s\n' "$clang_macros" | grep -q '^#define __clang__ ' ||
    fail "CLANG is not a Clang-family compiler: $CLANG"
run_host_test "$CLANG" clang

if [ -n "$GCC" ]; then
    gcc_macros=$(compiler_kind "$GCC") || fail "cannot identify GCC compiler: $GCC"
    printf '%s\n' "$gcc_macros" | grep -q '^#define __GNUC__ ' ||
        fail "GCC does not define __GNUC__: $GCC"
    if printf '%s\n' "$gcc_macros" | grep -q '^#define __clang__ '; then
        if [ "$GCC_EXPLICIT" -eq 1 ]; then
            fail "GCC resolves to Clang; set GCC to a GNU GCC executable"
        fi
        GCC=
    fi
fi

if [ -n "$GCC" ]; then
    run_host_test "$GCC" gcc
else
    printf '[SKIP] KPM module lifecycle GNU GCC build (GNU GCC unavailable)\n'
fi

printf '[PASS] KPM module lifecycle regression tests\n'
