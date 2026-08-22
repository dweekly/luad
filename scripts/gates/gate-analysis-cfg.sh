#!/usr/bin/env bash
set -euo pipefail

# Gate P3: Correct CFG, dominators, and analysis preconditions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate P3: CFG, Dominators, and Analysis preconditions tests"
cargo test -p luad-oracle --test test_analysis -- --nocapture

echo "==> Gate P3 passed successfully"
