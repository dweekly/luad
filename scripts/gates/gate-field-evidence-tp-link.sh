#!/usr/bin/env bash
set -euo pipefail

# Gate F4: Lua 5.1 field corpus and reproducible evidence

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate F4: Lua 5.1 reproducible field evidence and regression tests"
cargo test -p luad-oracle --test test_corpus_lua51 -- --nocapture

echo "==> Gate F4 passed successfully"
