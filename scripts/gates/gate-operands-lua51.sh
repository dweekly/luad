#!/usr/bin/env bash
set -euo pipefail

# Gate L3: Lua 5.1 resolved constant-bearing operands

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate L3: Lua 5.1 resolved constant-bearing operands tests"
cargo test -p luad-oracle --test test_operands_lua51 -- --nocapture

echo "==> Gate L3 passed successfully"
