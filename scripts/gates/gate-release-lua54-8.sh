#!/usr/bin/env bash
set -euo pipefail

# Gate P5: Promote only the proven Lua 5.4.8 scope

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running full proof spine for Lua 5.4.8: P1 -> P2 -> P3 -> P4 -> P5"
bash scripts/gates/gate-proof-harness.sh
bash scripts/gates/gate-facts-lua54-8.sh
bash scripts/gates/gate-analysis-cfg.sh
bash scripts/gates/gate-lossless-lua54-8.sh

echo "==> Running Gate P5: Promotion and release verification tests"
cargo test -p luad-oracle --test test_release_lua54 -- --nocapture
cargo test -p luad-oracle --test test_cli_e2e -- --nocapture

echo "==> Gate P5 passed successfully: Lua 5.4.8 promoted with validated evidence"
