#!/usr/bin/env bash
set -euo pipefail

# Gate L2: Lua 5.1 closure-binding and capture facts

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate L2: Lua 5.1 closure-binding and capture facts tests"
cargo test -p luad-oracle --test test_closures_lua51 -- --nocapture

echo "==> Gate L2 passed successfully"
