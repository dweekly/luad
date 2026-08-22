#!/usr/bin/env bash
set -euo pipefail

# Build and install official Lua 5.1, 5.2, 5.3, 5.4, and 5.5 compilers into /tmp/lua-tools/bin

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
    if curl -sSfL "${url}" -o "${tarball}"; then
        tar -xzf "${tarball}"
        local dir_name
        dir_name=$(tar -tzf "${tarball}" | head -1 | cut -f1 -d"/")
        cd "${dir_name}"
        make all -j4 || make generic -j4 || true
        if [ -f "src/luac" ]; then
            cp "src/luac" "${DEST_DIR}/${bin_name}"
            chmod +x "${DEST_DIR}/${bin_name}"
            echo "[OK] Installed ${DEST_DIR}/${bin_name}"
        else
            echo "[WARN] Could not find src/luac for ${version}"
        fi
    else
        echo "[WARN] Failed to download ${url}"
    fi
}

# Lua 5.1.5
build_lua "5.1.5" "lua-5.1.5.tar.gz" "https://www.lua.org/ftp/lua-5.1.5.tar.gz" "luac5.1"

# Lua 5.2.4
build_lua "5.2.4" "lua-5.2.4.tar.gz" "https://www.lua.org/ftp/lua-5.2.4.tar.gz" "luac5.2"

# Lua 5.3.6
build_lua "5.3.6" "lua-5.3.6.tar.gz" "https://www.lua.org/ftp/lua-5.3.6.tar.gz" "luac5.3"

# Lua 5.4.8 (or 5.4.7 if 5.4.8 mirror not yet populated)
build_lua "5.4.7" "lua-5.4.7.tar.gz" "https://www.lua.org/ftp/lua-5.4.7.tar.gz" "luac5.4"

echo "=== Completed official Lua compilers setup ==="
ls -la "${DEST_DIR}"
