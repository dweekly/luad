#!/usr/bin/env bash
set -euo pipefail

# Build exact official Lua compiler releases with verified SHA-256 checksums used by the differential oracle.

DEST_DIR="${LUAD_COMPILER_DIR:-/tmp/lua-tools/bin}"
mkdir -p "${DEST_DIR}"
BUILD_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

echo "=== Installing official Lua compilers with SHA-256 validation to ${DEST_DIR} ==="

case "$(uname -s)" in
    Darwin) LUA_MAKE_PLATFORM="macosx" ;;
    Linux) LUA_MAKE_PLATFORM="linux" ;;
    *) LUA_MAKE_PLATFORM="generic" ;;
esac

build_lua() {
    local version="$1"
    local tarball="$2"
    local url="$3"
    local expected_sha="$4"
    local bin_name="$5"

    if [ -f "${DEST_DIR}/${bin_name}" ]; then
        echo "[INFO] ${bin_name} already installed, skipping."
        return 0
    fi

    echo "[DOWNLOAD] Fetching Lua ${version} from ${url}..."
    cd "${BUILD_DIR}"
    curl -sSfL "${url}" -o "${tarball}"

    echo "[VERIFY] Verifying SHA-256 for ${tarball}..."
    local actual_sha
    if command -v shasum >/dev/null 2>&1; then
        actual_sha=$(shasum -a 256 "${tarball}" | awk '{print $1}')
    else
        actual_sha=$(sha256sum "${tarball}" | awk '{print $1}')
    fi

    if [ "${actual_sha}" != "${expected_sha}" ]; then
        echo "[ERROR] Checksum mismatch for ${tarball}!" >&2
        echo "  Expected: ${expected_sha}" >&2
        echo "  Actual:   ${actual_sha}" >&2
        return 1
    fi
    echo "[OK] Checksum verified: ${actual_sha}"

    echo "[BUILD] Building Lua ${version} -> ${bin_name}..."
    tar -xzf "${tarball}"
    cd "lua-${version}"

    # Lua's top-level makefiles select platform-specific compiler and linker
    # settings through an explicit target. In Lua 5.1, `all` only prints the
    # target-selection instructions and exits successfully.
    make "${LUA_MAKE_PLATFORM}" -j4

    test -x "src/luac"
    cp "src/luac" "${DEST_DIR}/${bin_name}"
    chmod +x "${DEST_DIR}/${bin_name}"

    local detected_version
    detected_version=$("${DEST_DIR}/${bin_name}" -v 2>&1)
    case "${detected_version}" in
        *"Lua ${version}"*) ;;
        *)
            echo "[ERROR] ${bin_name} reported unexpected version: ${detected_version}" >&2
            return 1
            ;;
    esac

    echo "[OK] Installed ${DEST_DIR}/${bin_name}: ${detected_version}"
}

# Lua 5.1.5
build_lua "5.1.5" "lua-5.1.5.tar.gz" "https://www.lua.org/ftp/lua-5.1.5.tar.gz" \
    "2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333" "luac5.1"

# Lua 5.2.4
build_lua "5.2.4" "lua-5.2.4.tar.gz" "https://www.lua.org/ftp/lua-5.2.4.tar.gz" \
    "b9e2e4aad6789b3b63a056d442f7b39f0ecfca3ae0f1fc0ae4e9614401b69f4b" "luac5.2"

# Lua 5.3.6
build_lua "5.3.6" "lua-5.3.6.tar.gz" "https://www.lua.org/ftp/lua-5.3.6.tar.gz" \
    "fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60" "luac5.3"

# Lua 5.4.8
build_lua "5.4.8" "lua-5.4.8.tar.gz" "https://www.lua.org/ftp/lua-5.4.8.tar.gz" \
    "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae" "luac5.4"

# Lua 5.5.1
build_lua "5.5.1" "lua-5.5.1.tar.gz" "https://www.lua.org/ftp/lua-5.5.1.tar.gz" \
    "1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce" "luac5.5"

echo "=== Completed official Lua compilers setup ==="
ls -la "${DEST_DIR}"
