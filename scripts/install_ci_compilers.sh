#!/usr/bin/env bash
set -euo pipefail

# Build exact official Lua compiler releases used by the differential oracle.

DEST_DIR="/tmp/lua-tools/bin"
mkdir -p "${DEST_DIR}"
BUILD_DIR="$(mktemp -d)"

cleanup() {
    rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

echo "=== Installing official Lua compilers to ${DEST_DIR} ==="

build_lua() {
    local version="$1"
    local tarball="$2"
    local url="$3"
    local bin_name="$4"

    if [ -f "${DEST_DIR}/${bin_name}" ]; then
        echo "[INFO] ${bin_name} already installed, skipping."
        return 0
    fi

    echo "[BUILD] Building Lua ${version} -> ${bin_name}..."
    cd "${BUILD_DIR}"
    curl -sSfL "${url}" -o "${tarball}"
    tar -xzf "${tarball}"
    cd "lua-${version}"

    if ! make all -j4; then
        make generic -j4
    fi

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
build_lua "5.1.5" "lua-5.1.5.tar.gz" "https://www.lua.org/ftp/lua-5.1.5.tar.gz" "luac5.1"

# Lua 5.2.4
build_lua "5.2.4" "lua-5.2.4.tar.gz" "https://www.lua.org/ftp/lua-5.2.4.tar.gz" "luac5.2"

# Lua 5.3.6
build_lua "5.3.6" "lua-5.3.6.tar.gz" "https://www.lua.org/ftp/lua-5.3.6.tar.gz" "luac5.3"

# Lua 5.4.8
build_lua "5.4.8" "lua-5.4.8.tar.gz" "https://www.lua.org/ftp/lua-5.4.8.tar.gz" "luac5.4"

# Lua 5.5.1
build_lua "5.5.1" "lua-5.5.1.tar.gz" "https://www.lua.org/ftp/lua-5.5.1.tar.gz" "luac5.5"

echo "=== Completed official Lua compilers setup ==="
ls -la "${DEST_DIR}"
