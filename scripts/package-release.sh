#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository="$(cd "${script_dir}/.." && pwd)"
output_dir="${1:-${repository}/artifacts/release}"

case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    platform="linux-x86_64"
    ;;
  Darwin:arm64)
    platform="macos-aarch64"
    ;;
  *)
    echo "package-release: unsupported host $(uname -s):$(uname -m)" >&2
    exit 1
    ;;
esac

exec cargo run --quiet --manifest-path "${repository}/Cargo.toml" \
  -p luad-oracle --bin luad-release -- \
  package \
  --repository "${repository}" \
  --platform "${platform}" \
  --output-dir "${output_dir}"
