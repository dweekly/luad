#!/usr/bin/env bash
# Build the outside-trial inputs from the vendored LuCI sources, never executing them.
# Usage: scripts/trials/build_inputs.sh OUT_DIR LUAC51 LNUM32_LUAC
#   LUAC51       official Lua 5.1.5 luac (stock layout of the host)
#   LNUM32_LUAC  OpenWrt LNUM32 luac from scripts/build_lua51_openwrt_lnum32.sh
set -euo pipefail
out="$1"; stock="$2"; lnum32="$3"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
[ -e "$out" ] && { echo "refusing to reuse $out" >&2; exit 1; }
"$stock" -v 2>&1 | grep -q '^Lua 5.1.5 ' || { echo "need official Lua 5.1.5 luac" >&2; exit 1; }
"$lnum32" -v 2>&1 | grep -q 'int32' || { echo "need the OpenWrt LNUM32 luac" >&2; exit 1; }
mkdir -p "$out/firmware" "$out/releases"
# A stripped LNUM32 tree, shaped like an extracted OpenWrt image.
while IFS= read -r src; do
  rel="${src#"$root"/tests/corpus/luci-23.05/}"
  dest="$out/firmware/usr/lib/lua/luci/${rel##*/luasrc/}"
  mkdir -p "$(dirname "$dest")"
  "$lnum32" -s -o "${dest%.lua}.lua" "$src"   # compiled chunks keep the .lua name, as on devices
done < <(find "$root/tests/corpus/luci-23.05" -name '*.lua' | sort)
# Two releases of luci.util, stripped, stock layout.
"$stock" -s -o "$out/releases/util-22.03.luac" "$root/tests/corpus/luci-22.03/libs/luci-lib-base/luasrc/util.lua"
"$stock" -s -o "$out/releases/util-23.05.luac" "$root/tests/corpus/luci-23.05/libs/luci-lib-base/luasrc/util.lua"
(cd "$out" && find . -type f | sort | xargs shasum -a 256 > SHA256SUMS)
echo "trial inputs in $out"
