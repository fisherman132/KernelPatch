#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later

set -eu
export LC_ALL=C

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)

python3 - "$REPO_DIR" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
patched = (root / "kernel/patch/common/supercall.c").read_text(encoding="utf-8")
lkm_entry = (root / "lkm/supercall/supercall.c").read_text(encoding="utf-8")
lkm_dispatch = (root / "lkm/supercall/dispatch.c").read_text(encoding="utf-8")
lkm_sucompat = (root / "lkm/supercall/sucompat.c").read_text(encoding="utf-8")
lkm_manager = (root / "lkm/manager/manager.c").read_text(encoding="utf-8")
lkm_sign = (root / "lkm/manager/apk_sign.c").read_text(encoding="utf-8")
lkm_readme = (root / "lkm/README.md").read_text(encoding="utf-8")
workflow = (root / ".github/workflows/build.yml").read_text(encoding="utf-8")
lkm_workflow = (root / ".github/workflows/build-lkm.yml").read_text(encoding="utf-8")
map_source = (root / "kernel/base/map.c").read_text(encoding="utf-8")
symbol_source = (root / "tools/symbol.c").read_text(encoding="utf-8")
sucompat_source = (root / "kernel/patch/common/sucompat.c").read_text(encoding="utf-8")


def fail(message):
    print(f"[FAIL] merged security boundary: {message}", file=sys.stderr)
    raise SystemExit(1)


restricted = re.search(
    r"#ifdef KP_RESTRICTED_PROFILE_BUILD(?P<body>.*?)#endif\s*\n\s*switch \(cmd\)",
    patched, re.S)
if not restricted:
    fail("cannot locate restricted patched-kernel dispatch")
feature_case = re.search(
    r"case\s+SUPERCALL_CONTROL_FEATURE\s*:(?P<body>.*?)"
    r"(?=case\s+SUPERCALL_|#endif)",
    restricted.group("body"), re.S)
if not feature_case or "kp_control_feature_sc" not in feature_case.group("body") or \
        "current_uid() == 0" not in feature_case.group("body") or \
        "is_trusted_manager_uid(current_uid())" not in feature_case.group("body"):
    fail("root-managed sucompat feature lacks a root/manager gate")
if '"sucompat_extra"' not in sucompat_source or '"path_probe"' not in sucompat_source or \
        "return -ENOENT" not in sucompat_source:
    fail("root-managed feature control is not limited to fixed sucompat names")
sucompat_init = re.search(
    r"void\s+sucompat_init\s*\([^)]*\)\s*\{(?P<body>.*?)\n\}",
    sucompat_source, re.S)
if not sucompat_init or "filp_open(sucompat_file" not in sucompat_init.group("body") or \
        "su_register_path_probe_hooks()" not in sucompat_init.group("body"):
    fail("root-managed sucompat is not gated by the APatch runtime marker")
if not re.search(
        r"#ifdef\s+KP_RESTRICTED_PROFILE_BUILD\s*"
        r"if\s*\(uid\s*!=\s*0\s*&&\s*!is_trusted_manager_uid\(uid\)\)\s*return\s*;",
        sucompat_source, re.S):
    fail("root-managed exec redirect lacks the root or trusted-manager gate")

for command in (
    "SUPERCALL_SU_TASK", "SUPERCALL_SU_GRANT_UID",
    "SUPERCALL_SU_REVOKE_UID", "SUPERCALL_KPM_LOAD",
    "SUPERCALL_KPM_UNLOAD", "SUPERCALL_KPM_CONTROL",
    "SUPERCALL_CONTROL_FEATURE",
):
    match = re.search(
        rf"case\s+{command}\s*:(?P<body>.*?)(?=case\s+SUPERCALL_|default:)",
        lkm_dispatch, re.S)
    if not match or "privileged ?" not in match.group("body"):
        fail(f"LKM command lacks root/manager gate: {command}")

if "bool privileged = uid == 0 || manager;" not in lkm_entry or \
        "if (!privileged && !allowed)" not in lkm_entry:
    fail("LKM entry does not distinguish root/manager from an ordinary allowlisted uid")
if re.search(r"kp_su_add_allow_uid\(\s*2000", lkm_sucompat):
    fail("LKM grants shell UID 2000 by default")
if "return uid == appid;" not in lkm_manager:
    fail("LKM manager trust is not bound to the exact verified uid")
if "com.example.apatch" in lkm_sign:
    fail("example manager identity remains trusted")
if "KP_RESTRICTED_MANAGER_PACKAGE" not in lkm_sign or \
        "KP_RESTRICTED_MANAGER_CERT_SHA256" not in lkm_sign:
    fail("LKM manager package/certificate are not build-configurable")
if "research-only" not in lkm_readme.lower():
    fail("LKM is not documented as research-only")
if re.search(r"^  Release-lkm:", workflow, re.M):
    fail("research LKM remains attached to production releases")
if re.search(r"^  (?:push|pull_request):", lkm_workflow, re.M):
    fail("research LKM workflow still runs automatically")

if "memblock_alloc_try_nid_f" not in map_source or \
        "size, align, NUMA_NO_NODE" not in map_source:
    fail("legacy three-argument memblock allocator ABI is missing")
if "legacy_memblock_alloc" not in symbol_source or \
        "kallsym->version.minor <= 19" not in symbol_source:
    fail("memblock fallback is not limited to Linux 4.19 and older")
if map_source.count("if (!pxd_pa) __builtin_trap();") != 1 or \
        map_source.count("if (!start_pa) __builtin_trap();") != 1:
    fail("PA-zero allocation guards are missing")

print("[PASS] merged KernelPatch security and ABI boundaries")
PY
