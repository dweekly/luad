#!/usr/bin/env bash
set -euo pipefail

# Gate L1: Lua 5.1 ChunkLayout and Stock profile

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate L1 (Stock): Lua 5.1 ChunkLayout validation and stock profile tests"
cargo test -p luad-oracle --test test_layout_lua51 -- --nocapture

echo "==> Gate L1 (Stock) passed successfully"
