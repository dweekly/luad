#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

readonly pinned_rust_toolchain="nightly-2026-08-25"
readonly pinned_cargo_fuzz_version="0.13.2"
readonly runs_per_target=1000
readonly max_input_bytes=4096
readonly input_timeout_seconds=5
readonly outer_timeout_seconds=300
readonly mutation_seed=1
readonly sanitizer="address"
readonly rss_limit_mb=512
readonly malloc_limit_mb=128
readonly canonical_targets=(
  fuzz_detect
  fuzz_lua51
  fuzz_lua52
  fuzz_lua53
  fuzz_lua54
  fuzz_lua55
  fuzz_lua51_analysis
  fuzz_lua54_analysis
)

usage() {
  cat <<'EOF'
Usage: scripts/fuzz_smoke.sh [OUTPUT_DIR] [--out-dir DIR] [--dry-run]

Runs the canonical bounded hostile-input campaign under a pinned resource-detection envelope and writes
logs, derived seed corpora, and fuzz-smoke-evidence.json beneath OUTPUT_DIR. The default output is
artifacts/fuzz-smoke. --dry-run is a contract-test seam and never reports an executed
campaign or successful fuzz evidence.
EOF
}

out_dir=""
dry_run=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      [[ $# -ge 2 ]] || { echo "missing value for --out-dir" >&2; exit 2; }
      out_dir="$2"
      shift 2
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      if [[ -z "${out_dir}" ]]; then
        out_dir="$1"
        shift
      else
        echo "unexpected argument: $1" >&2
        exit 2
      fi
      ;;
  esac
done

if [[ -z "${out_dir}" ]]; then
  out_dir="${repo_root}/artifacts/fuzz-smoke"
fi
mkdir -p "${out_dir}"
out_dir="$(cd "${out_dir}" && pwd -P)"
case "${out_dir}" in
  /tmp|/tmp/*|/private/tmp|/private/tmp/*|/var/tmp|/var/tmp/*|/private/var/folders/*)
    if [[ "${LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT:-0}" != "1" ]]; then
      echo "output directory is temporary storage: ${out_dir}" >&2
      echo "choose a persistent artifact directory" >&2
      exit 1
    fi
    ;;
esac

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{print $1}'
  else
    echo "neither sha256sum nor shasum is available" >&2
    return 1
  fi
}

if [[ "${dry_run}" == true ]]; then
  rust_toolchain_id="${LUAD_FUZZ_TEST_RUST_TOOLCHAIN:-${pinned_rust_toolchain}}"
  rustc_version="${LUAD_FUZZ_TEST_RUSTC_VERSION:-rustc dry-run}"
  cargo_fuzz_version="${LUAD_FUZZ_TEST_CARGO_FUZZ_VERSION:-cargo-fuzz ${pinned_cargo_fuzz_version}}"
  timeout_command="dry-run"
  pinned_toolchain_bin="dry-run"
else
  command -v rustup >/dev/null 2>&1 || { echo "rustup is required" >&2; exit 1; }
  command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
  if command -v timeout >/dev/null 2>&1; then
    timeout_command="timeout"
  elif command -v gtimeout >/dev/null 2>&1; then
    timeout_command="gtimeout"
  else
    echo "GNU timeout is required (install coreutils on macOS)" >&2
    exit 1
  fi
  rust_toolchain_id="${pinned_rust_toolchain}"
  if ! rustc_version="$(rustup run "${pinned_rust_toolchain}" rustc --version --verbose 2>&1)"; then
    echo "pinned Rust toolchain is unavailable: ${pinned_rust_toolchain}" >&2
    echo "${rustc_version}" >&2
    exit 1
  fi
  pinned_toolchain_bin="$(dirname "$(rustup which --toolchain "${pinned_rust_toolchain}" cargo)")"
  if ! cargo_fuzz_version="$(cargo fuzz --version 2>&1)"; then
    echo "cargo-fuzz is unavailable; install version ${pinned_cargo_fuzz_version} with --locked" >&2
    exit 1
  fi
fi

if [[ "${rust_toolchain_id}" != "${pinned_rust_toolchain}" ]]; then
  echo "Rust toolchain mismatch: expected ${pinned_rust_toolchain}, got ${rust_toolchain_id}" >&2
  exit 1
fi
if [[ "${cargo_fuzz_version}" != "cargo-fuzz ${pinned_cargo_fuzz_version}" ]]; then
  echo "cargo-fuzz version mismatch: expected cargo-fuzz ${pinned_cargo_fuzz_version}, got ${cargo_fuzz_version}" >&2
  exit 1
fi

targets=("${canonical_targets[@]}")
if [[ -n "${LUAD_FUZZ_TEST_TARGETS:-}" ]]; then
  IFS=',' read -r -a targets <<< "${LUAD_FUZZ_TEST_TARGETS}"
fi
if [[ "${#targets[@]}" -ne "${#canonical_targets[@]}" ]]; then
  echo "canonical target list mismatch: expected ${#canonical_targets[@]} targets" >&2
  exit 1
fi
for index in "${!canonical_targets[@]}"; do
  if [[ "${targets[$index]}" != "${canonical_targets[$index]}" ]]; then
    echo "canonical target list mismatch at index ${index}: expected ${canonical_targets[$index]}" >&2
    exit 1
  fi
done

seed_corpus() {
  local target="$1"
  local target_dir="${out_dir}/corpus/${target}"
  local dialect=""
  mkdir -p "${target_dir}"
  find "${target_dir}" -type f -delete

  case "${target}" in
    fuzz_detect)
      for dialect in lua51 lua52 lua53 lua54 lua55; do
        local fixture="${repo_root}/tests/fixtures/precompiled/${dialect}/hello.luac"
        [[ -f "${fixture}" ]] || { echo "missing seed fixture: ${fixture}" >&2; return 1; }
        cp "${fixture}" "${target_dir}/${dialect}-hello.luac"
      done
      return 0
      ;;
    fuzz_lua51|fuzz_lua51_analysis) dialect=lua51 ;;
    fuzz_lua52) dialect=lua52 ;;
    fuzz_lua53) dialect=lua53 ;;
    fuzz_lua54|fuzz_lua54_analysis) dialect=lua54 ;;
    fuzz_lua55) dialect=lua55 ;;
    *) echo "no seed authority for target ${target}" >&2; return 1 ;;
  esac

  if [[ -n "${dialect}" ]]; then
    local fixture_dir="${repo_root}/tests/fixtures/precompiled/${dialect}"
    local fixtures=()
    while IFS= read -r fixture; do fixtures+=("${fixture}"); done < <(find "${fixture_dir}" -maxdepth 1 -type f -name '*.luac' | sort)
    [[ "${#fixtures[@]}" -gt 0 ]] || { echo "no seed fixtures found in ${fixture_dir}" >&2; return 1; }
    for fixture in "${fixtures[@]}"; do
      cp "${fixture}" "${target_dir}/$(basename "${fixture}")"
    done
  fi
}

for target in "${targets[@]}"; do
  [[ -f "${repo_root}/fuzz/fuzz_targets/${target}.rs" ]] || { echo "missing fuzz target source: ${target}" >&2; exit 1; }
  grep -Fq "name = \"${target}\"" "${repo_root}/fuzz/Cargo.toml" || { echo "fuzz target is not registered: ${target}" >&2; exit 1; }
  seed_corpus "${target}"
done

echo "Hostile-input fuzz smoke"
echo "Rust toolchain: ${pinned_rust_toolchain}"
echo "cargo-fuzz: cargo-fuzz ${pinned_cargo_fuzz_version}"
echo "Targets: ${#targets[@]}"
echo "Budget: ${runs_per_target} runs, ${max_input_bytes} bytes, ${outer_timeout_seconds}s outer timeout"
echo "Detector: ${sanitizer} sanitizer, ${rss_limit_mb}MB RSS, ${malloc_limit_mb}MB malloc"

target_results=()
for target in "${targets[@]}"; do
  corpus_dir="${out_dir}/corpus/${target}"
  target_log="${out_dir}/${target}.log"
  seed_files=()
  while IFS= read -r path; do
    seed_files+=("{\"name\":\"$(basename "${path}")\",\"size\":$(wc -c < "${path}" | tr -d ' '),\"sha256\":\"$(sha256_file "${path}")\"}")
  done < <(find "${corpus_dir}" -maxdepth 1 -type f | sort)
  [[ "${#seed_files[@]}" -gt 0 ]] || { echo "empty seed corpus: ${target}" >&2; exit 1; }
  seed_json="$(IFS=,; echo "${seed_files[*]}")"
  started="$(date +%s)"
  executions=0
  status=0
  executed=true

  if [[ "${dry_run}" == true ]]; then
    executed=false
    executions="${LUAD_FUZZ_TEST_EXECUTIONS:-${runs_per_target}}"
    status="${LUAD_FUZZ_TEST_EXIT_CODE:-0}"
    if [[ "${LUAD_FUZZ_TEST_MISSING_LOG_TARGET:-}" != "${target}" ]]; then
      printf 'stat::number_of_executed_units: %s\n' "${executions}" > "${target_log}"
    else
      rm -f "${target_log}"
    fi
  else
    set +e
    "${timeout_command}" --signal=TERM --kill-after=10s "${outer_timeout_seconds}s" \
      env PATH="${pinned_toolchain_bin}:${PATH}" cargo fuzz run \
      --sanitizer "${sanitizer}" "${target}" "${corpus_dir}" -- \
        -runs="${runs_per_target}" \
        -max_len="${max_input_bytes}" \
        -timeout="${input_timeout_seconds}" \
        -seed="${mutation_seed}" \
        -rss_limit_mb="${rss_limit_mb}" \
        -malloc_limit_mb="${malloc_limit_mb}" \
        -print_final_stats=1 \
        > "${target_log}" 2>&1
    status=$?
    set -e
    if [[ -f "${target_log}" ]]; then
      executions="$(awk '/stat::number_of_executed_units:/ { value=$2 } END { print value+0 }' "${target_log}")"
      if [[ "${executions}" -eq 0 ]]; then
        executions="$(grep -oE '#[0-9]+' "${target_log}" | tail -n 1 | tr -d '#' || true)"
        executions="${executions:-0}"
      fi
    fi
  fi

  [[ -f "${target_log}" ]] || { echo "missing target output: ${target}" >&2; exit 1; }
  [[ "${status}" -eq 0 ]] || { echo "target failed (${status}): ${target}" >&2; tail -n 30 "${target_log}" >&2; exit 1; }
  [[ "${executions}" =~ ^[0-9]+$ && "${executions}" -gt 0 ]] || { echo "zero executions: ${target}" >&2; exit 1; }

  finished="$(date +%s)"
  target_results+=("{\"target\":\"${target}\",\"executed\":${executed},\"exit_code\":${status},\"executions\":${executions},\"duration_seconds\":$((finished - started)),\"seed_corpus_count\":${#seed_files[@]},\"seed_corpus_files\":[${seed_json}],\"log_file\":\"${target}.log\"}")
  echo "${target}: ${executions} executions"
done

if [[ "${dry_run}" == true ]]; then
  mode="dry-run"
  campaign_executed=false
  success=false
else
  mode="executed"
  campaign_executed=true
  success=true
fi
results_json="$(IFS=,; echo "${target_results[*]}")"
evidence_file="${out_dir}/fuzz-smoke-evidence.json"
cat > "${evidence_file}" <<EOF
{
  "schema_version": 1,
  "mode": "${mode}",
  "campaign_executed": ${campaign_executed},
  "success": ${success},
  "generated_at": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "toolchain": {
    "rust_toolchain": "${pinned_rust_toolchain}",
    "rustc": "$(printf '%s' "${rustc_version}" | head -n 1)",
    "cargo_fuzz": "${cargo_fuzz_version}",
    "outer_timeout_command": "${timeout_command}"
  },
  "budget": {
    "runs_per_target": ${runs_per_target},
    "max_input_bytes": ${max_input_bytes},
    "input_timeout_seconds": ${input_timeout_seconds},
    "outer_timeout_seconds": ${outer_timeout_seconds},
    "mutation_seed": ${mutation_seed}
  },
  "detection_envelope": {
    "sanitizer": "${sanitizer}",
    "rss_limit_mb": ${rss_limit_mb},
    "malloc_limit_mb": ${malloc_limit_mb}
  },
  "target_count": ${#targets[@]},
  "targets": [${results_json}]
}
EOF

[[ -s "${evidence_file}" ]] || { echo "missing evidence output" >&2; exit 1; }
if [[ "${dry_run}" == true ]]; then
  echo "Fuzz smoke contract dry-run passed; no campaign success is claimed."
else
  echo "Hostile-input fuzz smoke passed."
fi
echo "Evidence: ${evidence_file}"
