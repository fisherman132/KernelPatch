#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Link-time invariants for the relocatable arm64 KernelPatch image.  Use the
# target toolchain's ELF tools: the build host does not need to understand
# AArch64 instructions itself.

set -eu
export LC_ALL=C

if [ "$#" -ne 4 ]; then
    echo "usage: $0 KPIMG_ELF TARGET_NM TARGET_OBJDUMP TARGET_READELF" >&2
    exit 2
fi

elf=$1
nm=$2
objdump=$3
readelf=$4

if [ ! -r "$elf" ]; then
    echo "arm64 check: unreadable ELF: $elf" >&2
    exit 2
fi
if ! command -v "$nm" >/dev/null 2>&1; then
    echo "arm64 check: target nm not found: $nm" >&2
    exit 2
fi
if ! command -v "$objdump" >/dev/null 2>&1; then
    echo "arm64 check: target objdump not found: $objdump" >&2
    exit 2
fi
if ! command -v "$readelf" >/dev/null 2>&1; then
    echo "arm64 check: target readelf not found: $readelf" >&2
    exit 2
fi

map_start=$(
    "$nm" -n --defined-only "$elf" |
        awk '$NF == "_map_start" { if (++count == 1) print $1 }
             END { if (count != 1) exit 1 }'
) || {
    echo "arm64 check: expected exactly one _map_start" >&2
    exit 1
}
map_end=$(
    "$nm" -n --defined-only "$elf" |
        awk '$NF == "_map_end" { if (++count == 1) print $1 }
             END { if (count != 1) exit 1 }'
) || {
    echo "arm64 check: expected exactly one _map_end" >&2
    exit 1
}

case "$map_start:$map_end" in
    *[!0-9A-Fa-f:]* | :* | *:)
        echo "arm64 check: malformed map bounds: $map_start..$map_end" >&2
        exit 1
        ;;
esac

if ! bl_report=$(
    "$objdump" -d --section=.setup.map.text --no-show-raw-insn "$elf" |
        awk -v start_hex="$map_start" -v end_hex="$map_end" '
            function hex_value(s,    i, digit, value) {
                sub(/^0[xX]/, "", s)
                s = tolower(s)
                value = 0
                for (i = 1; i <= length(s); i++) {
                    digit = index("0123456789abcdef", substr(s, i, 1)) - 1
                    if (digit < 0) return -1
                    value = value * 16 + digit
                }
                return value
            }
            BEGIN {
                start = hex_value(start_hex)
                end = hex_value(end_hex)
                if (start < 0 || end <= start) {
                    print "arm64 check: invalid .setup.map bounds" > "/dev/stderr"
                    exit 2
                }
            }
            $2 == "bl" {
                target = hex_value($3)
                count++
                if (target < start || target >= end) {
                    printf "arm64 check: .setup.map direct BL escapes map: %s\n", $0 > "/dev/stderr"
                    bad = 1
                }
            }
            END {
                if (count == 0) {
                    print "arm64 check: no direct BL decoded in .setup.map" > "/dev/stderr"
                    exit 2
                }
                if (bad) exit 1
                printf "[PASS] .setup.map direct BL targets: %d within 0x%s..0x%s\n", count, start_hex, end_hex
            }
        '
); then
    exit 1
fi
printf '%s\n' "$bl_report"

if ! map_layout_report=$(
    "$nm" -n -S --defined-only "$elf" |
        awk '
            function hex_value(s,    i, digit, value) {
                sub(/^0[xX]/, "", s)
                s = tolower(s)
                value = 0
                for (i = 1; i <= length(s); i++) {
                    digit = index("0123456789abcdef", substr(s, i, 1)) - 1
                    if (digit < 0) return -1
                    value = value * 16 + digit
                }
                return value
            }
            $NF == "_map_start" { start = hex_value($1); starts++ }
            $NF == "map_data" { data = hex_value($1); size = hex_value($2); data_count++ }
            $NF == "get_myva" { anchor = hex_value($1); anchors++ }
            END {
                if (starts != 1 || data_count != 1 || anchors != 1 ||
                    start < 0 || data < 0 || size <= 0 || anchor < 0) {
                    print "arm64 check: malformed map anchor symbols" > "/dev/stderr"
                    exit 2
                }
                if (data != start || anchor != data + size) {
                    printf "arm64 check: map_data/get_myva layout mismatch: start=0x%x data=0x%x size=0x%x anchor=0x%x\n",
                           start, data, size, anchor > "/dev/stderr"
                    exit 1
                }
                printf "[PASS] map anchor layout: map_data size 0x%x immediately precedes get_myva\n", size
            }
        '
); then
    exit 1
fi
printf '%s\n' "$map_layout_report"

program_headers=$("$readelf" -W -l "$elf") || {
    echo "arm64 check: failed to read ELF program headers" >&2
    exit 1
}
if printf '%s\n' "$program_headers" |
    grep -Eq '^[[:space:]]*LOAD.*[[:space:]]RWE[[:space:]]'; then
    echo "arm64 check: writable/executable LOAD segment detected" >&2
    exit 1
fi
printf '%s\n' "[PASS] flat-image ELF ranges have no directly RWX LOAD descriptor"

# The two allowed x18 references are the assembly save/restore surrounding the
# early setup path.  Any additional reference means compiler-generated code or
# new assembly may clobber Android's shadow-call-stack pointer and needs review.
if ! x18_report=$(
    "$objdump" -d --no-show-raw-insn "$elf" |
        awk '
            /^[[:space:]]*[[:xdigit:]]+:/ && /(^|[^[:alnum:]_])[wx]18([^[:alnum:]_]|$)/ {
                line = $0
                sub(/^[[:space:]]*[[:xdigit:]]+:[[:space:]]*/, "", line)
                if (line ~ /^stp[[:space:]]+x8,[[:space:]]*x18,[[:space:]]*\[sp,[[:space:]]*#-(0x10|16)\]!/) {
                    saves++
                } else if (line ~ /^ldp[[:space:]]+x8,[[:space:]]*x18,[[:space:]]*\[sp\],[[:space:]]*#(0x10|16)/) {
                    restores++
                } else {
                    printf "arm64 check: unexpected x18 use: %s\n", $0 > "/dev/stderr"
                    bad = 1
                }
            }
            END {
                if (saves != 1 || restores != 1) {
                    printf "arm64 check: expected one x18 save/restore, found %d/%d\n", saves, restores > "/dev/stderr"
                    exit 1
                }
                if (bad) exit 1
                print "[PASS] x18 reserved: only the reviewed setup save/restore pair is present"
            }
        '
); then
    exit 1
fi
printf '%s\n' "$x18_report"
