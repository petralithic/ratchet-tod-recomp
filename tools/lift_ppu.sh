#!/usr/bin/env bash
# POSIX twin of tools/lift_ppu.ps1: lifts a decrypted EBOOT.ELF to C++ with ps3recomp's
# ppu_loader.py + ppu_lifter.py. The release is recognised by the ELF's SHA-256 so the two
# native Lua hooks (luaD_rawrunprotected, longjmp; src/stubs/lua_eh.cpp) get that release's
# addresses. See docs/macos-port-plan.md for the NA (BCUS98127) address map.
#
#   tools/lift_ppu.sh [ELF] [OUT_DIR] [RECOMP_DIR]
#     defaults: elf/EBOOT.ELF out/v100 recompiled
#   JOBS=<n> limits the lifter's worker count.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ELF="${1:-elf/EBOOT.ELF}"
OUT="${2:-out/v100}"
RECOMP="${3:-recompiled}"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || { echo "no .venv: python3 -m venv .venv && .venv/bin/pip install -r ps3recomp/requirements.txt" >&2; exit 1; }
[ -f "$ELF" ] || { echo "missing $ELF (decrypt EBOOT.BIN with tools/self2elf.py)" >&2; exit 1; }

SHA="$(shasum -a 256 "$ELF" | cut -d' ' -f1)"
case "$SHA" in
  cd2c37351e840fb31810f1be5fe9d7d03860d2c1d9b621f8ee55cdf67a8889ba)
    RELEASE="BCES00052 1.00"; HOOKS=(0x671A28 0x8268B4) ;;
  0ee9a8414c8fc182bc19fa2a523e6d050d0be76138b3733ae515798d77d2468c)
    RELEASE="BCUS98127 1.00 (disc 02.00)"; HOOKS=(0x671CA8 0x826B34) ;;
  *)
    echo "unknown EBOOT.ELF (sha256 $SHA): not a supported release" >&2; exit 1 ;;
esac
CODE_END="$("$PY" -I tools/elf_code_end.py "$ELF" | tr -d '[:space:]')"
echo "release:   $RELEASE"
echo "code-end:  $CODE_END"
echo "lua hooks: ${HOOKS[*]}"

STEM="$(basename "$ELF" .ELF)"
mkdir -p "$OUT" "$RECOMP"
"$PY" -I ps3recomp/tools/ppu_loader.py "$ELF" -o "$OUT/"
ARGS=(ps3recomp/tools/ppu_lifter.py "$ELF"
      --functions "$OUT/$STEM.functions.json"
      --hle-stubs "$OUT/$STEM.imports.json"
      --code-end "$CODE_END"
      --nonvolatile-locals)
for h in "${HOOKS[@]}"; do ARGS+=(--hook "$h"); done
ARGS+=(-o "$RECOMP/")
[ -n "${JOBS:-}" ] && ARGS+=(--jobs "$JOBS")
echo "lifting -> $RECOMP (minutes, hundreds of MB)"
"$PY" -I "${ARGS[@]}"
echo "done"
