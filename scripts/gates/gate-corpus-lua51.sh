#!/usr/bin/env bash
set -euo pipefail

# Gate L4: Field-corpus regression evidence for Lua 5.1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${ROOT_DIR}"

echo "==> Running Gate L4: Lua 5.1 field-corpus regression and differential oracle tests"
cargo test -p luad-oracle --test test_corpus_lua51 -- --nocapture
cargo test -p luad-oracle --test test_differential_oracle test_canonical_differential_oracle_lua51 -- --nocapture

echo "==> Gate L4 passed successfully"
