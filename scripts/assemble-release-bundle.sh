#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "usage: $0 ARCHIVE_DIR SBOM_FILE PREREQUISITES_FILE OUTPUT_DIR" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository="$(cd "${script_dir}/.." && pwd)"
archive_dir="$1"
sbom_file="$2"
prerequisites_file="$3"
output_dir="$4"

exec cargo run --quiet --manifest-path "${repository}/Cargo.toml" \
  -p luad-oracle --bin luad-release -- \
  bundle \
  --repository "${repository}" \
  --archive-dir "${archive_dir}" \
  --sbom "${sbom_file}" \
  --prerequisites "${prerequisites_file}" \
  --output-dir "${output_dir}"
