#!/usr/bin/env bash
set -euo pipefail

# Gate P2: Sound Lua 5.4.8 instruction and constant oracle

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate P2: Sound Lua 5.4.8 differential oracle and negative controls"
cargo test -p luad-oracle --test test_differential_oracle -- test_canonical_differential_oracle_lua54 --nocapture
cargo test -p luad-oracle --test test_oracle_negative_controls -- --nocapture

echo "==> Gate P2 passed successfully"
