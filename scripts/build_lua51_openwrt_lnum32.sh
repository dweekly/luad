#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 OUTPUT_ROOT [--reproduce]" >&2
  exit 1
fi

OUTPUT_ROOT="$1"
REPRODUCE=false

if [[ $# -eq 2 ]]; then
  if [[ "$2" != "--reproduce" ]]; then
    echo "Error: invalid option '$2' (expected --reproduce)" >&2
    exit 1
  fi
  REPRODUCE=true
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

case "${OUTPUT_ROOT}" in
  /tmp/* | /private/tmp/*) ;;
  *)
    echo "Error: OUTPUT_ROOT must be a dedicated directory below /tmp or /private/tmp" >&2
    exit 1
    ;;
esac

# Verify required host tools
for tool in curl tar patch make cmp od; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Error: required tool '$tool' not found" >&2
    exit 1
  fi
done

# Verify host is little-endian
endian_val="$(printf '\1\0\0\0' | od -An -vtu4 | tr -d '[:space:]')"
if [[ "${endian_val}" != "1" ]]; then
  echo "Error: little-endian host required (got ${endian_val})" >&2
  exit 1
fi

sha256_file() {
  local target="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$target" | awk '{print $1}'
  else
    echo "Error: neither sha256sum nor shasum is available" >&2
    exit 1
  fi
}

fetch_and_verify() {
  local url="$1"
  local expected_sha="$2"
  local dest="$3"
  local tmp="${dest}.tmp.$$"

  if [[ -f "${dest}" ]]; then
    local current_sha
    current_sha="$(sha256_file "${dest}")"
    if [[ "${current_sha}" == "${expected_sha}" ]]; then
      return 0
    fi
    rm -f "${dest}"
  fi

  rm -f "${tmp}"
  curl -sSfL "${url}" -o "${tmp}"
  local downloaded_sha
  downloaded_sha="$(sha256_file "${tmp}")"
  if [[ "${downloaded_sha}" != "${expected_sha}" ]]; then
    echo "Error: SHA256 mismatch for ${url}" >&2
    echo "  Expected: ${expected_sha}" >&2
    echo "  Got:      ${downloaded_sha}" >&2
    rm -f "${tmp}"
    exit 1
  fi
  mv "${tmp}" "${dest}"
}

DOWNLOADS_DIR="${OUTPUT_ROOT}/downloads"
FIXTURES_DIR="${OUTPUT_ROOT}/fixtures"
BUILD_SRC_DIR="${OUTPUT_ROOT}/lua-5.1.5"

mkdir -p "${DOWNLOADS_DIR}" "${FIXTURES_DIR}"

LUA_URL="https://www.lua.org/ftp/lua-5.1.5.tar.gz"
LUA_SHA="2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333"
LUA_TAR="${DOWNLOADS_DIR}/lua-5.1.5.tar.gz"

OPENWRT_RAW_BASE="https://raw.githubusercontent.com/openwrt/openwrt/1da2e82c1182a3fd681da5760be96821213afadd"
MAKEFILE_URL="${OPENWRT_RAW_BASE}/package/utils/lua/Makefile"
MAKEFILE_SHA="01bf9f41cb70ce42ce094d12d5b8866521ec4d63c443d0058ffa8fc7df6d2607"
MAKEFILE_DEST="${DOWNLOADS_DIR}/Makefile"

fetch_and_verify "${LUA_URL}" "${LUA_SHA}" "${LUA_TAR}"
fetch_and_verify "${MAKEFILE_URL}" "${MAKEFILE_SHA}" "${MAKEFILE_DEST}"

PATCHES=(
  "010-lua-5.1.3-lnum-full-260308.patch:af9193b55e9cdc1b9b204726c906e22fcd463bce8ac3e2fdec1b969fa8399052"
  "011-lnum-use-double.patch:4284e1d30796b3d91878603b3e22ecb6c7232ba6ba7c7bca9eeb9d7263a4aec9"
  "012-lnum-fix-ltle-relational-operators.patch:44c4cb48b73cfdbb33f216ac2f5f2f40726a97c91394b90080cbb68932ff1256"
  "015-lnum-ppc-compat.patch:134db797bade3c114e94c14ef331b454a49aba33b9a5fcb20bc155d4de2fef28"
  "020-shared_liblua.patch:9c0c5191e84df74f35de7ce1c840e31c1a309857ef08c6f820746d2cc47c0b76"
  "030-archindependent-bytecode.patch:a4c0f33770e6d004e495d093b66ab6641596fe546fd608473e1f59916a07b37d"
  "040-use-symbolic-functions.patch:4224d931ba5d24fb33403f11ba6adbd30031fec3eb36380f1e632ec8b4b58f48"
  "050-honor-cflags.patch:e7bdccac83984a190308f9e5d02f201c72cb8703039033daa6c7bd6af716bdab"
  "100-no_readline.patch:cea568c36adc5d0605f8a6f503365e7441cbcb31b9f11a57d6530247b87c44d0"
  "200-lua-path.patch:6b15f745550372a3841b252563ebb76868008ec0750131918f9381f20707a634"
  "300-opcode_performance.patch:953527850509aa9970a4a58ece9c46747bf0e6733c61715e523e6e744b910729"
)

for entry in "${PATCHES[@]}"; do
  patch_name="${entry%%:*}"
  patch_sha="${entry##*:}"
  patch_url="${OPENWRT_RAW_BASE}/package/utils/lua/patches/${patch_name}"
  patch_dest="${DOWNLOADS_DIR}/${patch_name}"
  fetch_and_verify "${patch_url}" "${patch_sha}" "${patch_dest}"
done

# Cleanly extract source archive
rm -rf "${BUILD_SRC_DIR}"
tar -xzf "${LUA_TAR}" -C "${OUTPUT_ROOT}"

# Apply patches in manifest order
for entry in "${PATCHES[@]}"; do
  patch_name="${entry%%:*}"
  patch_dest="${DOWNLOADS_DIR}/${patch_name}"
  (cd "${BUILD_SRC_DIR}" && patch --batch --forward -p1 < "${patch_dest}")
done

# Build static native compiler
(
  cd "${BUILD_SRC_DIR}"
  unset CFLAGS CPPFLAGS LDFLAGS MYCFLAGS MYLDFLAGS
  make -C src clean
  make -C src a
  make -C src luac-host
)

LUAC_HOST="${BUILD_SRC_DIR}/src/luac-host"
if [[ ! -x "${LUAC_HOST}" ]]; then
  echo "Error: luac-host binary not built or not executable at ${LUAC_HOST}" >&2
  exit 1
fi

# Verify compiler version banner
COMPILER_VER="$("${LUAC_HOST}" -v 2>&1)"
if [[ "${COMPILER_VER}" != *"Lua 5.1.5"* || "${COMPILER_VER}" != *"(double int32)"* ]]; then
  echo "Error: unexpected compiler version banner: ${COMPILER_VER}" >&2
  exit 1
fi

REL_SOURCE="tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32.lua"
SOURCE_FILE="${ROOT_DIR}/${REL_SOURCE}"
EXPECTED_SRC_SHA="84862a976e997c6cbab296de0c02b096814ebe34978b55e0b42469f3a026133c"

if [[ ! -f "${SOURCE_FILE}" ]]; then
  echo "Error: source fixture not found: ${SOURCE_FILE}" >&2
  exit 1
fi

actual_src_sha="$(sha256_file "${SOURCE_FILE}")"
if [[ "${actual_src_sha}" != "${EXPECTED_SRC_SHA}" ]]; then
  echo "Error: source fixture SHA mismatch: ${actual_src_sha}" >&2
  exit 1
fi

GEN_DEBUG="${FIXTURES_DIR}/authority_lnum32.luac"
GEN_STRIPPED="${FIXTURES_DIR}/authority_lnum32_stripped.luac"
EXPECTED_DEBUG_SHA="21b751768c37a930607c8a04e803206554887ef9b8a6f9c415a8cba6a8be4a3c"
EXPECTED_STRIPPED_SHA="3ad36ac1e1b7d94fbfa6f4171c8c1257b80e1813780e258ca139b0b1601e223d"

# Regenerate fixtures from repository root for deterministic embedded debug paths
(cd "${ROOT_DIR}" && "${LUAC_HOST}" -o "${GEN_DEBUG}" "${REL_SOURCE}")
(cd "${ROOT_DIR}" && "${LUAC_HOST}" -s -o "${GEN_STRIPPED}" "${REL_SOURCE}")

# Verify 12-byte header
EXPECTED_HEADER="1b4c75615100010404040804"
for chunk in "${GEN_DEBUG}" "${GEN_STRIPPED}"; do
  header="$(od -An -v -N12 -tx1 "${chunk}" | tr -d '[:space:]')"
  if [[ "${header}" != "${EXPECTED_HEADER}" ]]; then
    echo "Error: invalid 12-byte header in ${chunk}: ${header}" >&2
    exit 1
  fi
done

# Verify observable tag-9 integer constant sequence in debug chunk
debug_hex="$(od -An -v -tx1 "${GEN_DEBUG}" | tr -s '[:space:]' ' ')"
if [[ "${debug_hex}" != *" 09 00 00 00 00 "* ]]; then
  echo "Error: observable tag-9 integer constant sequence not found in ${GEN_DEBUG}" >&2
  exit 1
fi

# Authenticate generated fixture hashes
actual_debug_sha="$(sha256_file "${GEN_DEBUG}")"
if [[ "${actual_debug_sha}" != "${EXPECTED_DEBUG_SHA}" ]]; then
  echo "Error: generated debug fixture SHA mismatch: ${actual_debug_sha}" >&2
  exit 1
fi

actual_stripped_sha="$(sha256_file "${GEN_STRIPPED}")"
if [[ "${actual_stripped_sha}" != "${EXPECTED_STRIPPED_SHA}" ]]; then
  echo "Error: generated stripped fixture SHA mismatch: ${actual_stripped_sha}" >&2
  exit 1
fi

# Reproduce mode: byte-for-byte comparison against frozen fixtures
if [[ "${REPRODUCE}" == true ]]; then
  FROZEN_DEBUG="${ROOT_DIR}/tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32.luac"
  FROZEN_STRIPPED="${ROOT_DIR}/tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32_stripped.luac"

  if ! cmp -s "${GEN_DEBUG}" "${FROZEN_DEBUG}"; then
    echo "Error: generated debug fixture does not match frozen fixture byte-for-byte" >&2
    exit 1
  fi
  if ! cmp -s "${GEN_STRIPPED}" "${FROZEN_STRIPPED}"; then
    echo "Error: generated stripped fixture does not match frozen fixture byte-for-byte" >&2
    exit 1
  fi
fi
