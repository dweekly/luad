#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository="$(cd "${script_dir}/.." && pwd)"
output_dir="${1:-${repository}/artifacts/release-sbom}"
cargo_cyclonedx="${CARGO_CYCLONEDX:-$(command -v cargo-cyclonedx || true)}"

if [[ -z "${cargo_cyclonedx}" ]]; then
  echo "generate-release-sbom: cargo-cyclonedx 0.5.9 is required" >&2
  exit 1
fi

exec cargo run --quiet --manifest-path "${repository}/Cargo.toml" \
  -p luad-oracle --bin luad-release -- \
  sbom \
  --repository "${repository}" \
  --cargo-cyclonedx "${cargo_cyclonedx}" \
  --output-dir "${output_dir}"
