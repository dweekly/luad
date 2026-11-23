#!/usr/bin/env bash
# Verify the public trial handoff with the same two compilers as build_inputs.sh.
set -euo pipefail
export LC_ALL=C
scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
"$scripts_dir/build_inputs.sh" "$work/inputs" "$1" "$2"
mkdir "$work/received"
tar -C "$work/inputs" -cf - . | tar -C "$work/received" -xf -
cd "$work/received"
test -s LICENSE
test -s UPSTREAM-NOTICE
test "$(find firmware -type f -name '*.lua' | wc -l)" -eq 13
test "$(find releases -type f -name '*.luac' | wc -l)" -eq 2
find . -type f ! -name SHA256SUMS | sort > "$work/inventory"
cut -c 67- SHA256SUMS > "$work/listed"
diff -u "$work/inventory" "$work/listed"
shasum -a 256 -c SHA256SUMS
printf '\001' >> firmware/usr/lib/lua/luci/sys.lua
if shasum -a 256 -c SHA256SUMS > "$work/corrupted.log" 2>&1; then
  echo "checksum verification accepted a corrupted sys.lua" >&2
  exit 1
fi
grep -Fqx './firmware/usr/lib/lua/luci/sys.lua: FAILED' "$work/corrupted.log"
