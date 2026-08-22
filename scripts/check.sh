#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"

echo "==> formatting"
cargo fmt --all -- --check

echo "==> clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> tests"
cargo test --workspace

echo "==> rustdoc"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

echo "==> fuzz targets"
cargo check --manifest-path fuzz/Cargo.toml

echo "==> all checks passed"
