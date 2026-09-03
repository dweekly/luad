#!/usr/bin/env bash
# Repository bring-up: report or install every tool the developer-machine section of
# docs/BRINGUP.md requires, at the exact pinned version.
#
# Every version compared here is read from the one place that owns it: scripts/pins.env
# for the cargo-installed tools and the compiler directory, rust-toolchain.toml for the
# contributor toolchain, Cargo.toml for the MSRV, scripts/fuzz_smoke.sh for the fuzz
# nightly and cargo-fuzz, and scripts/install_ci_compilers.sh for the official Lua
# releases. Nothing is restated, so a pin can never drift from what CI installs.
#
# Portability: bash 3.2 (macOS system bash). No associative arrays, no mapfile.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

# shellcheck source=scripts/pins.env
. "${script_dir}/pins.env"

usage() {
  cat <<'EOF'
Usage: scripts/bringup.sh [--doctor|--install] [--scope developer|ci-test]

  --doctor   Report every required tool as OK, MISSING, or WRONG (default).
             Exits non-zero if any row is not OK.
  --install  Install whatever the doctor reports as MISSING or WRONG, then re-run
             the doctor. Never uses sudo and never installs Python packages; a step
             that needs root is printed for the operator instead of being run.

  --scope developer  Everything docs/BRINGUP.md section 1 requires (default).
  --scope ci-test    Only what the CI "Test" jobs provide: the pinned toolchain and
                     the official Lua compilers. The remaining tools belong to the
                     dependency-audit, release-SBOM, and fuzz-smoke jobs and are
                     absent from a Test runner.
EOF
}

mode="doctor"
scope="developer"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --doctor) mode="doctor"; shift ;;
    --install) mode="install"; shift ;;
    --scope)
      [ "$#" -ge 2 ] || { echo "missing value for --scope" >&2; exit 2; }
      scope="$2"
      shift 2
      ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unexpected argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "${scope}" in
  developer|ci-test) ;;
  *) echo "unknown scope: ${scope}" >&2; exit 2 ;;
esac

# --------------------------------------------------------------------------------
# Pins read from the manifests that own them.
# --------------------------------------------------------------------------------

require_pin() {
  # A pin that silently reads as empty turns every comparison below into a check that
  # cannot fail, so an unreadable manifest is a hard error.
  if [ -z "$2" ]; then
    echo "bringup: could not read $1" >&2
    exit 2
  fi
}

pinned_channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' rust-toolchain.toml | head -n 1)"
require_pin "the toolchain channel from rust-toolchain.toml" "${pinned_channel}"

msrv="$(sed -n 's/^rust-version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1)"
require_pin "rust-version from Cargo.toml" "${msrv}"
# Cargo's rust-version may omit the patch component; rustup names toolchains with all
# three, and the MSRV CI job installs the .0 patch of the declared minor.
case "${msrv}" in
  *.*.*) msrv_toolchain="${msrv}" ;;
  *)     msrv_toolchain="${msrv}.0" ;;
esac

pinned_nightly="$(sed -n 's/^readonly pinned_rust_toolchain="\(.*\)"$/\1/p' scripts/fuzz_smoke.sh | head -n 1)"
require_pin "pinned_rust_toolchain from scripts/fuzz_smoke.sh" "${pinned_nightly}"

pinned_cargo_fuzz="$(sed -n 's/^readonly pinned_cargo_fuzz_version="\(.*\)"$/\1/p' scripts/fuzz_smoke.sh | head -n 1)"
require_pin "pinned_cargo_fuzz_version from scripts/fuzz_smoke.sh" "${pinned_cargo_fuzz}"

lua_versions="$(sed -n 's/^build_lua "\([0-9][0-9.]*\)".*/\1/p' scripts/install_ci_compilers.sh)"
require_pin "the official Lua releases from scripts/install_ci_compilers.sh" "${lua_versions}"

compiler_dir="${LUAD_COMPILER_DIR:-${LUAD_COMPILER_DIR_DEFAULT}}"
cargo_bin_dir="${CARGO_HOME:-${HOME}/.cargo}/bin"
lnum32_authority_root="${LUAD_LNUM32_GATE_ROOT}/authority"
# scripts/build_lua51_openwrt_lnum32.sh builds a static host compiler from the patched
# Lua 5.1.5 tree it unpacks; scripts/gates/gate-authority-lua51-openwrt-lnum32.sh reads
# it back from exactly this path.
lnum32_compiler="${lnum32_authority_root}/lua-5.1.5/src/luac-host"

# --------------------------------------------------------------------------------
# Row accumulation. Parallel arrays keep this bash 3.2 compatible.
# --------------------------------------------------------------------------------

row_tool=()
row_expected=()
row_found=()
row_status=()
hint_text=()

add_row() {
  row_tool[${#row_tool[@]}]="$1"
  row_expected[${#row_expected[@]}]="$2"
  row_found[${#row_found[@]}]="$3"
  row_status[${#row_status[@]}]="$4"
  if [ "$4" != "OK" ] && [ -n "${5:-}" ]; then
    hint_text[${#hint_text[@]}]="$1: $5"
  fi
}

# Named statuses for --install, which only acts on what the doctor rejected.
st_rustup=""
st_channel=""
st_msrv=""
st_nightly=""
st_components=""
st_llvm_tools=""
st_timeout=""
st_cargo_fuzz=""
st_cargo_deny=""
st_cyclonedx=""
st_compilers=""
st_lnum32=""

# --------------------------------------------------------------------------------
# Probes.
# --------------------------------------------------------------------------------

# Directories crates/luad-oracle/src/lib.rs find_compiler_binary consults, in order:
# an explicit override, the persistent directory, then the legacy one. The caller adds
# the PATH entry that holds the bare binary name, which is the oracle's last resort.
luac_search_dirs() {
  if [ -n "${LUAD_ORACLE_BIN_DIR:-}" ]; then
    printf '%s\n' "${LUAD_ORACLE_BIN_DIR}"
  fi
  printf '%s\n' "${compiler_dir}"
  printf '%s\n' "${LUAD_LEGACY_COMPILER_DIR}"
}

check_rustup() {
  # From a neutral directory: `rustup --version` inside the repository resolves the
  # toolchain rust-toolchain.toml names and installs its declared components, which
  # would repair the very state check_pinned_components exists to report.
  found="$(cd / && rustup --version 2>/dev/null | head -n 1 || true)"
  if [ -z "${found}" ]; then
    st_rustup="MISSING"
    add_row "rustup" "installed" "absent" "MISSING" \
      "install rustup from https://rustup.rs (curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh)"
    return
  fi
  st_rustup="OK"
  add_row "rustup" "installed" "${found}" "OK"
}

check_channel() {
  if [ "${st_rustup}" != "OK" ]; then
    st_channel="MISSING"
    add_row "cargo (rust-toolchain.toml)" "${pinned_channel}" "no rustup" "MISSING" \
      "install rustup first"
    return
  fi

  cargo_path="$(command -v cargo 2>/dev/null || true)"
  # Run from the repository root so rust-toolchain.toml applies.
  cargo_version="$(cargo --version 2>/dev/null | awk '{print $2}' || true)"

  shim_note=""
  if [ -n "${cargo_path}" ] && [ "${cargo_path}" != "${cargo_bin_dir}/cargo" ]; then
    # Only the rustup shim honors rust-toolchain.toml. A package-manager cargo earlier
    # in PATH is a fixed compiler that ignores the pin.
    shim_note=" from ${cargo_path} (not the rustup shim at ${cargo_bin_dir}/cargo)"
  fi

  if [ "${cargo_version}" = "${pinned_channel}" ]; then
    st_channel="OK"
    add_row "cargo (rust-toolchain.toml)" "${pinned_channel}" \
      "${cargo_version}${shim_note}" "OK"
    return
  fi

  st_channel="WRONG"
  if [ -n "${shim_note}" ]; then
    add_row "cargo (rust-toolchain.toml)" "${pinned_channel}" \
      "${cargo_version:-unknown}${shim_note}" "WRONG" \
      "put the rustup shim first: export PATH=\"${cargo_bin_dir}:\$PATH\""
  else
    add_row "cargo (rust-toolchain.toml)" "${pinned_channel}" "${cargo_version:-absent}" "WRONG" \
      "rustup toolchain install ${pinned_channel} --profile minimal --component clippy --component rustfmt"
  fi
}

# scripts/check.sh runs `cargo fmt --all -- --check` and `cargo clippy` under the
# toolchain rust-toolchain.toml selects, so both components must be present for that
# toolchain. A `--profile minimal` install satisfies the cargo version check without
# them, which is why this is a separate row.
# `cargo doc`, also in check.sh, needs no extra component: rustdoc ships inside rustc.
#
# Two properties hold this honest. `rustup component list` and `rustup run` both read
# the stored toolchain and install nothing, so the probe cannot repair what it measures.
# And it runs before check_channel, whose bare `cargo` call does reconcile the
# `components` list in rust-toolchain.toml and downloads what is missing.
#
# That reconciliation means a networked machine repairs this itself on the next cargo
# command. The row still matters where the download cannot happen: an offline or
# network-restricted host fails at check.sh's first step instead, with no warning.
check_pinned_components() {
  st_components="OK"
  if [ "${st_rustup}" != "OK" ]; then
    st_components="MISSING"
    add_row "rustfmt (${pinned_channel})" "available" "no rustup" "MISSING" "install rustup first"
    add_row "clippy (${pinned_channel})" "available" "no rustup" "MISSING" "install rustup first"
    return
  fi

  hint="rustup component add rustfmt clippy --toolchain ${pinned_channel}"
  installed="$(rustup component list --toolchain "${pinned_channel}" --installed 2>/dev/null || true)"
  for component in rustfmt clippy; do
    case "${component}" in
      rustfmt) subcommand="fmt" ;;
      *) subcommand="clippy" ;;
    esac
    label="${component} (${pinned_channel})"

    # rustup names an installed component after the host target, so match the prefix.
    if ! printf '%s\n' "${installed}" | grep -q "^${component}"; then
      st_components="MISSING"
      add_row "${label}" "available for ${pinned_channel}" "not installed for ${pinned_channel}" \
        "MISSING" "${hint}"
      continue
    fi

    found="$(rustup run "${pinned_channel}" cargo "${subcommand}" --version 2>/dev/null | head -n 1 || true)"
    if [ -z "${found}" ]; then
      st_components="WRONG"
      add_row "${label}" "available for ${pinned_channel}" "listed but does not run" "WRONG" "${hint}"
    else
      add_row "${label}" "available for ${pinned_channel}" "${found}" "OK"
    fi
  done
}

# .github/workflows/ci.yml installs the fuzz nightly with llvm-tools-preview. rustup
# names the installed component after the host target, so the check is on the prefix.
check_nightly_llvm_tools() {
  label="llvm-tools (${pinned_nightly})"
  hint="rustup component add llvm-tools-preview --toolchain ${pinned_nightly}"
  if [ "${st_nightly}" != "OK" ]; then
    st_llvm_tools="MISSING"
    add_row "${label}" "installed" "no ${pinned_nightly}" "MISSING" "install ${pinned_nightly} first"
    return
  fi
  found="$(rustup component list --toolchain "${pinned_nightly}" --installed 2>/dev/null | grep -m1 '^llvm-tools' || true)"
  if [ -z "${found}" ]; then
    st_llvm_tools="MISSING"
    add_row "${label}" "installed" "absent" "MISSING" "${hint}"
  else
    st_llvm_tools="OK"
    add_row "${label}" "installed" "${found}" "OK"
  fi
}

# scripts/fuzz_smoke.sh resolves `timeout`, then `gtimeout`, and invokes it with
# --signal and --kill-after, which are GNU coreutils options. Presence alone would
# accept a non-GNU timeout that the campaign cannot use, so the probe runs the flags.
check_gnu_timeout() {
  label="GNU timeout (fuzz smoke)"
  expected="accepts --signal and --kill-after"
  case "$(uname -s)" in
    Darwin) hint="brew install coreutils" ;;
    *) hint="install the coreutils package with your distribution's package manager" ;;
  esac

  timeout_command=""
  if command -v timeout >/dev/null 2>&1; then
    timeout_command="timeout"
  elif command -v gtimeout >/dev/null 2>&1; then
    timeout_command="gtimeout"
  fi

  if [ -z "${timeout_command}" ]; then
    st_timeout="MISSING"
    add_row "${label}" "${expected}" "neither timeout nor gtimeout on PATH" "MISSING" "${hint}"
    return
  fi

  timeout_path="$(command -v "${timeout_command}")"
  if "${timeout_command}" --signal=TERM --kill-after=10s 1s true >/dev/null 2>&1; then
    st_timeout="OK"
    add_row "${label}" "${expected}" "${timeout_path}" "OK"
  else
    st_timeout="WRONG"
    add_row "${label}" "${expected}" "${timeout_path} rejected the flags" "WRONG" "${hint}"
  fi
}

# Reports the MSRV toolchain by the rustc version it actually runs, not by its presence
# in `rustup toolchain list`: a toolchain directory can exist without a working rustc.
check_msrv() {
  label="rustup toolchain ${msrv_toolchain} (MSRV)"
  expected="rustc ${msrv_toolchain}"
  install_hint="rustup toolchain install ${msrv_toolchain} --profile minimal"

  if [ "${st_rustup}" != "OK" ]; then
    st_msrv="MISSING"
    add_row "${label}" "${expected}" "no rustup" "MISSING" "install rustup first"
    return
  fi

  found="$(rustup run "${msrv_toolchain}" rustc --version 2>/dev/null | head -n 1 || true)"
  if [ -z "${found}" ]; then
    st_msrv="MISSING"
    add_row "${label}" "${expected}" "absent" "MISSING" "${install_hint}"
    return
  fi

  case "${found}" in
    "${expected}"*)
      st_msrv="OK"
      add_row "${label}" "${expected}" "${found}" "OK"
      ;;
    *)
      st_msrv="WRONG"
      add_row "${label}" "${expected}" "${found}" "WRONG" "${install_hint}"
      ;;
  esac
}

# The nightly pin is a dated channel name, so the name in `rustup toolchain list` is the
# version. Both halves are required: the exact dated channel must be installed, and its
# rustc must run and report a nightly build.
check_nightly() {
  label="rustup toolchain ${pinned_nightly} (fuzz)"
  expected="${pinned_nightly}, rustc -nightly"
  install_hint="rustup toolchain install ${pinned_nightly} --profile minimal --component llvm-tools-preview"

  if [ "${st_rustup}" != "OK" ]; then
    st_nightly="MISSING"
    add_row "${label}" "${expected}" "no rustup" "MISSING" "install rustup first"
    return
  fi

  listed="$(rustup toolchain list 2>/dev/null | grep -c "^${pinned_nightly}-" || true)"
  found="$(rustup run "${pinned_nightly}" rustc --version 2>/dev/null | head -n 1 || true)"

  if [ "${listed}" -eq 0 ] || [ -z "${found}" ]; then
    st_nightly="MISSING"
    add_row "${label}" "${expected}" "absent" "MISSING" "${install_hint}"
    return
  fi

  case "${found}" in
    *-nightly*)
      st_nightly="OK"
      add_row "${label}" "${expected}" "${pinned_nightly}, ${found}" "OK"
      ;;
    *)
      st_nightly="WRONG"
      add_row "${label}" "${expected}" "${pinned_nightly}, ${found}" "WRONG" "${install_hint}"
      ;;
  esac
}

check_cargo_fuzz() {
  if [ "${st_nightly}" != "OK" ]; then
    st_cargo_fuzz="MISSING"
    add_row "cargo-fuzz" "cargo-fuzz ${pinned_cargo_fuzz}" "no ${pinned_nightly}" "MISSING" \
      "install ${pinned_nightly} first"
    return
  fi

  # scripts/fuzz_smoke.sh runs cargo-fuzz with the pinned nightly's bin directory
  # prepended, so the doctor must read the same binary that the campaign will use.
  nightly_bin="$(dirname "$(rustup which --toolchain "${pinned_nightly}" cargo 2>/dev/null || echo /nonexistent/cargo)")"
  found="$(env PATH="${nightly_bin}:${PATH}" cargo fuzz --version 2>/dev/null | grep -m1 '^cargo-fuzz ' || true)"

  if [ -z "${found}" ]; then
    st_cargo_fuzz="MISSING"
    add_row "cargo-fuzz" "cargo-fuzz ${pinned_cargo_fuzz}" "absent" "MISSING" \
      "cargo +${pinned_nightly} install cargo-fuzz --version ${pinned_cargo_fuzz} --locked"
    return
  fi

  if [ "${found}" = "cargo-fuzz ${pinned_cargo_fuzz}" ]; then
    st_cargo_fuzz="OK"
    add_row "cargo-fuzz" "cargo-fuzz ${pinned_cargo_fuzz}" "${found}" "OK"
  else
    st_cargo_fuzz="WRONG"
    add_row "cargo-fuzz" "cargo-fuzz ${pinned_cargo_fuzz}" "${found}" "WRONG" \
      "cargo +${pinned_nightly} install cargo-fuzz --version ${pinned_cargo_fuzz} --locked --force"
  fi
}

check_cargo_deny() {
  expected="cargo-deny ${LUAD_CARGO_DENY_VERSION}"
  found="$(cargo deny --version 2>/dev/null | head -n 1 || true)"
  if [ -z "${found}" ]; then
    st_cargo_deny="MISSING"
    add_row "cargo-deny" "${expected}" "absent" "MISSING" \
      "cargo install cargo-deny --version ${LUAD_CARGO_DENY_VERSION} --locked"
    return
  fi
  if [ "${found}" = "${expected}" ]; then
    st_cargo_deny="OK"
    add_row "cargo-deny" "${expected}" "${found}" "OK"
  else
    st_cargo_deny="WRONG"
    add_row "cargo-deny" "${expected}" "${found}" "WRONG" \
      "cargo install cargo-deny --version ${LUAD_CARGO_DENY_VERSION} --locked --force"
  fi
}

check_cyclonedx() {
  expected="cargo-cyclonedx-cyclonedx ${LUAD_CARGO_CYCLONEDX_VERSION}"
  # scripts/generate-release-sbom.sh resolves the generator the same way.
  binary="${CARGO_CYCLONEDX:-$(command -v cargo-cyclonedx 2>/dev/null || true)}"
  if [ -z "${binary}" ]; then
    st_cyclonedx="MISSING"
    add_row "cargo-cyclonedx" "${expected}" "absent" "MISSING" \
      "cargo install cargo-cyclonedx --version ${LUAD_CARGO_CYCLONEDX_VERSION} --locked"
    return
  fi
  found="$("${binary}" cyclonedx --version 2>/dev/null | head -n 1 || true)"
  if [ "${found}" = "${expected}" ]; then
    st_cyclonedx="OK"
    add_row "cargo-cyclonedx" "${expected}" "${found}" "OK"
  else
    st_cyclonedx="WRONG"
    add_row "cargo-cyclonedx" "${expected}" "${found:-unreadable}" "WRONG" \
      "cargo install cargo-cyclonedx --version ${LUAD_CARGO_CYCLONEDX_VERSION} --locked --force"
  fi
}

check_compilers() {
  st_compilers="OK"
  for version in ${lua_versions}; do
    series="${version%.*}"
    bin_name="luac${series}"
    expected="Lua ${version}"
    matched=""
    matched_banner=""
    rejected_path=""
    rejected_banner=""

    # Like the oracle, a candidate is accepted only if its banner names the pinned
    # release; a wrong-version binary in an earlier directory does not mask a correct
    # one later in the order. The first rejected candidate is kept for the report.
    while IFS= read -r dir; do
      [ -n "${dir}" ] || continue
      candidate="${dir}/${bin_name}"
      [ -x "${candidate}" ] || continue
      banner="$("${candidate}" -v 2>&1 | head -n 1 || true)"
      case "${banner}" in
        *"${expected}"*)
          matched="${candidate}"
          matched_banner="${banner}"
          break
          ;;
      esac
      if [ -z "${rejected_path}" ]; then
        rejected_path="${candidate}"
        rejected_banner="${banner}"
      fi
    done <<EOT
$(luac_search_dirs)
$(command -v "${bin_name}" 2>/dev/null | sed 's|/[^/]*$||')
EOT

    if [ -n "${matched}" ]; then
      add_row "${bin_name}" "${expected}" "${matched_banner%%  *} (${matched})" "OK"
    elif [ -n "${rejected_path}" ]; then
      st_compilers="WRONG"
      add_row "${bin_name}" "${expected}" "${rejected_banner:-unreadable} (${rejected_path})" "WRONG" \
        "bash scripts/install_ci_compilers.sh replaces a wrong-version binary in ${compiler_dir}; delete ${rejected_path} if it is elsewhere"
    else
      st_compilers="MISSING"
      add_row "${bin_name}" "${expected}" "absent" "MISSING" \
        "bash scripts/install_ci_compilers.sh"
    fi
  done
}

lnum32_prerequisites_missing() {
  # Mirrors the host-tool list scripts/build_lua51_openwrt_lnum32.sh enforces.
  missing=""
  for tool in curl tar patch make cmp od; do
    command -v "${tool}" >/dev/null 2>&1 || missing="${missing} ${tool}"
  done
  printf '%s' "${missing# }"
}

check_lnum32() {
  # The banner the build script itself demands from the patched compiler.
  expected="Lua 5.1.5 (double int32)"
  if [ ! -x "${lnum32_compiler}" ]; then
    st_lnum32="MISSING"
    add_row "luac-host (OpenWrt LNUM32)" "${expected}" "absent" "MISSING" \
      "bash scripts/build_lua51_openwrt_lnum32.sh ${lnum32_authority_root}"
    return
  fi
  banner="$("${lnum32_compiler}" -v 2>&1 | head -n 1 || true)"
  case "${banner}" in
    *"Lua 5.1.5"*"(double int32)"*)
      st_lnum32="OK"
      add_row "luac-host (OpenWrt LNUM32)" "${expected}" "${banner}" "OK"
      ;;
    *)
      st_lnum32="WRONG"
      add_row "luac-host (OpenWrt LNUM32)" "${expected}" "${banner:-unreadable}" "WRONG" \
        "rm -rf ${lnum32_authority_root} && bash scripts/build_lua51_openwrt_lnum32.sh ${lnum32_authority_root}"
      ;;
  esac
}

run_checks() {
  row_tool=()
  row_expected=()
  row_found=()
  row_status=()
  hint_text=()

  check_rustup
  # Before check_channel: its bare `cargo` call reconciles rust-toolchain.toml's
  # declared components. Both scopes, because the CI Test jobs run scripts/check.sh.
  check_pinned_components
  check_channel

  if [ "${scope}" = "developer" ]; then
    check_msrv
    check_nightly
    check_nightly_llvm_tools
    check_cargo_fuzz
    check_gnu_timeout
    check_cargo_deny
    check_cyclonedx
  fi

  check_compilers

  if [ "${scope}" = "developer" ]; then
    check_lnum32
  fi
}

print_table() {
  w_tool=4   # len("tool")
  w_expected=8
  w_found=5
  index=0
  while [ "${index}" -lt "${#row_tool[@]}" ]; do
    [ "${#row_tool[$index]}" -gt "${w_tool}" ] && w_tool="${#row_tool[$index]}"
    [ "${#row_expected[$index]}" -gt "${w_expected}" ] && w_expected="${#row_expected[$index]}"
    [ "${#row_found[$index]}" -gt "${w_found}" ] && w_found="${#row_found[$index]}"
    index=$((index + 1))
  done

  printf "%-${w_tool}s | %-${w_expected}s | %-${w_found}s | %s\n" \
    "tool" "expected" "found" "status"
  printf "%-${w_tool}s-+-%-${w_expected}s-+-%-${w_found}s-+-%s\n" \
    "$(dashes "${w_tool}")" "$(dashes "${w_expected}")" "$(dashes "${w_found}")" "------"

  index=0
  while [ "${index}" -lt "${#row_tool[@]}" ]; do
    printf "%-${w_tool}s | %-${w_expected}s | %-${w_found}s | %s\n" \
      "${row_tool[$index]}" "${row_expected[$index]}" "${row_found[$index]}" "${row_status[$index]}"
    index=$((index + 1))
  done
}

dashes() {
  count="$1"
  out=""
  index=0
  while [ "${index}" -lt "${count}" ]; do
    out="${out}-"
    index=$((index + 1))
  done
  printf '%s' "${out}"
}

failing_rows() {
  count=0
  index=0
  while [ "${index}" -lt "${#row_status[@]}" ]; do
    [ "${row_status[$index]}" != "OK" ] && count=$((count + 1))
    index=$((index + 1))
  done
  printf '%s' "${count}"
}

report() {
  echo "luad bring-up doctor (scope: ${scope}, host: $(uname -s) $(uname -m))"
  echo
  print_table
  echo

  failures="$(failing_rows)"
  if [ "${failures}" -eq 0 ]; then
    echo "All ${#row_tool[@]} checks OK."
    return 0
  fi

  echo "${failures} of ${#row_tool[@]} checks need attention:"
  index=0
  while [ "${index}" -lt "${#hint_text[@]}" ]; do
    echo "  - ${hint_text[$index]}"
    index=$((index + 1))
  done
  echo
  echo "Run 'bash scripts/bringup.sh --install' to apply these, or see docs/BRINGUP.md."
  return 1
}

# --------------------------------------------------------------------------------
# Install.
# --------------------------------------------------------------------------------

install_missing() {
  if [ "${st_rustup}" != "OK" ]; then
    cat >&2 <<EOF
bringup: rustup is required and cannot be installed by this script.
Run this in a terminal, then rerun 'bash scripts/bringup.sh --install':

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  export PATH="${cargo_bin_dir}:\$PATH"
EOF
    exit 1
  fi

  cargo_path="$(command -v cargo 2>/dev/null || true)"
  if [ "${st_channel}" != "OK" ] && [ -n "${cargo_path}" ] &&
    [ "${cargo_path}" != "${cargo_bin_dir}/cargo" ]; then
    cat >&2 <<EOF
bringup: '${cargo_path}' shadows the rustup shim at '${cargo_bin_dir}/cargo'.
That cargo ignores rust-toolchain.toml, so installing under it would pin the wrong
compiler. Fix the search order first, then rerun 'bash scripts/bringup.sh --install':

  export PATH="${cargo_bin_dir}:\$PATH"
EOF
    exit 1
  fi

  if [ "${st_channel}" != "OK" ]; then
    echo "==> rustup toolchain install ${pinned_channel}"
    rustup toolchain install "${pinned_channel}" --profile minimal \
      --component clippy --component rustfmt
  fi

  if [ "${st_components}" != "OK" ]; then
    echo "==> rustup component add rustfmt clippy --toolchain ${pinned_channel}"
    rustup component add rustfmt clippy --toolchain "${pinned_channel}"
  fi

  if [ "${st_msrv}" != "OK" ]; then
    echo "==> rustup toolchain install ${msrv_toolchain} (MSRV)"
    rustup toolchain install "${msrv_toolchain}" --profile minimal
  fi

  if [ "${st_nightly}" != "OK" ]; then
    echo "==> rustup toolchain install ${pinned_nightly} (fuzz)"
    rustup toolchain install "${pinned_nightly}" --profile minimal \
      --component llvm-tools-preview
  fi

  if [ "${st_llvm_tools}" != "OK" ]; then
    echo "==> rustup component add llvm-tools-preview --toolchain ${pinned_nightly}"
    rustup component add llvm-tools-preview --toolchain "${pinned_nightly}"
  fi

  if [ "${st_timeout}" != "OK" ]; then
    # GNU timeout is a system package. Homebrew installs it without elevation; every
    # other package manager needs root, which this script never takes.
    if [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
      echo "==> brew install coreutils (GNU timeout for the fuzz smoke runner)"
      brew install coreutils
    else
      echo "==> skipping GNU timeout: it needs a system package manager"
      echo "    run this yourself, then rerun 'bash scripts/bringup.sh --install':"
      case "$(uname -s)" in
        Darwin) echo "      brew install coreutils" ;;
        *) echo "      sudo <your package manager> install coreutils" ;;
      esac
    fi
  fi

  if [ "${st_cargo_fuzz}" != "OK" ]; then
    echo "==> cargo-fuzz ${pinned_cargo_fuzz}"
    cargo "+${pinned_nightly}" install cargo-fuzz \
      --version "${pinned_cargo_fuzz}" --locked --force
  fi

  if [ "${st_cargo_deny}" != "OK" ]; then
    echo "==> cargo-deny ${LUAD_CARGO_DENY_VERSION}"
    cargo install cargo-deny --version "${LUAD_CARGO_DENY_VERSION}" --locked --force
  fi

  if [ "${st_cyclonedx}" != "OK" ]; then
    # CI downloads the pinned Linux release asset for this version; a developer
    # machine builds the same version from source, which also covers macOS arm64.
    echo "==> cargo-cyclonedx ${LUAD_CARGO_CYCLONEDX_VERSION}"
    cargo install cargo-cyclonedx \
      --version "${LUAD_CARGO_CYCLONEDX_VERSION}" --locked --force
  fi

  if [ "${st_compilers}" != "OK" ]; then
    echo "==> official Lua compilers into ${compiler_dir}"
    LUAD_COMPILER_DIR="${compiler_dir}" bash scripts/install_ci_compilers.sh
  fi

  if [ "${st_lnum32}" != "OK" ]; then
    missing_tools="$(lnum32_prerequisites_missing)"
    if [ -n "${missing_tools}" ]; then
      echo "==> skipping the OpenWrt LNUM32 authority compiler"
      echo "    missing host tools:${missing_tools:+ }${missing_tools}"
      echo "    install them, then run:"
      echo "      bash scripts/build_lua51_openwrt_lnum32.sh ${lnum32_authority_root}"
    else
      echo "==> OpenWrt Lua 5.1 LNUM32 authority compiler into ${lnum32_authority_root}"
      if ! bash scripts/build_lua51_openwrt_lnum32.sh "${lnum32_authority_root}"; then
        echo "    build failed; run it directly to see the full output:" >&2
        echo "      bash scripts/build_lua51_openwrt_lnum32.sh ${lnum32_authority_root}" >&2
      fi
    fi
  fi
}

# --------------------------------------------------------------------------------

run_checks
if [ "${mode}" = "install" ]; then
  install_missing
  echo
  run_checks
fi
report
