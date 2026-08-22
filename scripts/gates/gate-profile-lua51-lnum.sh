#!/usr/bin/env bash
set -euo pipefail

# Gate L1: Lua 5.1 LNUM profile tests

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate L1 (LNUM): Lua 5.1 LNUM profile tests"
cargo test -p luad-oracle --test test_layout_lua51 test_profile_lua51_lnum_accepts_tag_9 -- --nocapture

echo "==> Gate L1 (LNUM) passed successfully"
