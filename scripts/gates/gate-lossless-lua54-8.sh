#!/usr/bin/env bash
set -euo pipefail

# Gate P4: Real losslessness and byte accounting for Lua 5.4.8

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate P4: Lua 5.4.8 Lossless binary roundtrip and byte ledger tests"
cargo test -p luad-oracle --test test_lossless_lua54 -- --nocapture

echo "==> Gate P4 passed successfully"
