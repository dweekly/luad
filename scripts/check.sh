#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

echo "==> formatting"
cargo fmt --all -- --check

echo "==> agent wrapper configuration"
bash -n scripts/agents/agy-gemini.sh scripts/agents/claude-opus.sh
actual_agy_config=$(scripts/agents/agy-gemini.sh config)
expected_agy_config=$'model=gemini-3.7-flash-high\nreasoning=high-model-variant'
if [[ "$actual_agy_config" != "$expected_agy_config" ]]; then
  echo "unexpected Antigravity model or reasoning configuration" >&2
  exit 1
fi

echo "==> clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> tests"
cargo build -p luad-cli --bin luad
cargo test --workspace

echo "==> rustdoc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "==> fuzz targets"
cargo check --manifest-path fuzz/Cargo.toml

echo "==> all checks passed"
