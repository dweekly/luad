#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_dir}"
report="${1:-${repo_dir}/artifacts/coverage/lcov.info}"
mkdir -p "$(dirname "${report}")"

# Apply instrumentation to both the test executables and the CLI they spawn.
coverage_env="$(cargo llvm-cov show-env --sh)"
eval "${coverage_env}"
cargo llvm-cov clean --workspace
cargo build --locked -p luad-cli --bin luad
target_dir="$(cargo metadata --locked --no-deps --format-version 1 | jq -r .target_directory)"
export CARGO_BIN_EXE_luad="${target_dir}/debug/luad"
cargo test --locked --workspace
cargo llvm-cov report --lcov \
    --ignore-filename-regex '(^|/)crates/luad-oracle/' --output-path "${report}"

test -s "${report}"
grep -Eq '^SF:.*crates/luad-cli/src/' "${report}"
grep -Eq '^SF:.*crates/luad-core/src/' "${report}"
grep -Eq '^LH:[1-9][0-9]*$' "${report}"
