#!/usr/bin/env python3
"""Generate canonical provenance manifest for all precompiled fixtures."""

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
PRECOMPILED_DIR = FIXTURES_DIR / "precompiled"
MANIFEST_PATH = PRECOMPILED_DIR / "MANIFEST.json"

PINS_PATH = Path(__file__).resolve().parent / "pins.env"


def load_pins() -> dict:
    """Read scripts/pins.env, the single source for the compiler directory pins."""
    pins = {}
    for raw in PINS_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        pins[key.strip()] = os.path.expandvars(value.strip().strip('"'))
    return pins


PINS = load_pins()

# Search order for the official compilers, matching find_compiler_binary in
# crates/luad-oracle/src/lib.rs: an explicit override, then the persistent directory
# under the user's home, then the legacy directory. /tmp is last because macOS clears
# it on reboot.
COMPILER_DIRS = [
    d
    for d in (
        os.environ.get("LUAD_COMPILER_DIR"),
        PINS["LUAD_COMPILER_DIR_DEFAULT"],
        PINS["LUAD_LEGACY_COMPILER_DIR"],
    )
    if d
]


def find_compiler(bin_name: str) -> str:
    """Absolute path of an official compiler, or the preferred path if none exists."""
    for directory in COMPILER_DIRS:
        candidate = Path(directory) / bin_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return str(Path(COMPILER_DIRS[0]) / bin_name)


DIALECTS = {
    "lua51": {"bin": find_compiler("luac5.1"), "version": "Lua 5.1.5"},
    "lua52": {"bin": find_compiler("luac5.2"), "version": "Lua 5.2.4"},
    "lua53": {"bin": find_compiler("luac5.3"), "version": "Lua 5.3.6"},
    "lua54": {"bin": find_compiler("luac5.4"), "version": "Lua 5.4.8"},
    "lua55": {"bin": find_compiler("luac5.5"), "version": "Lua 5.5.1"},
}

FIXTURE_NAMES = ["hello", "control_flow", "closures", "tables", "numerics"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def main():
    fixtures_entries = []

    for dialect_dir_name, info in DIALECTS.items():
        dialect_dir = PRECOMPILED_DIR / dialect_dir_name
        if not dialect_dir.exists():
            continue

        for fixture_name in FIXTURE_NAMES:
            source_file = FIXTURES_DIR / f"{fixture_name}.lua"
            if not source_file.exists():
                continue

            source_sha = sha256_file(source_file)

            # Debug binary
            bin_debug = dialect_dir / f"{fixture_name}.luac"
            if bin_debug.exists():
                bin_sha = sha256_file(bin_debug)
                fixtures_entries.append({
                    "dialect": dialect_dir_name,
                    "fixture_name": fixture_name,
                    "source_path": f"tests/fixtures/{fixture_name}.lua",
                    "source_sha256": source_sha,
                    "binary_path": f"tests/fixtures/precompiled/{dialect_dir_name}/{fixture_name}.luac",
                    "binary_sha256": bin_sha,
                    "is_stripped": False,
                    "compiler_version": info["version"],
                    "compiler_flags": "-o <out> <src>",
                })

            # Stripped binary
            bin_stripped = dialect_dir / f"{fixture_name}_stripped.luac"
            if bin_stripped.exists():
                bin_sha = sha256_file(bin_stripped)
                fixtures_entries.append({
                    "dialect": dialect_dir_name,
                    "fixture_name": fixture_name,
                    "source_path": f"tests/fixtures/{fixture_name}.lua",
                    "source_sha256": source_sha,
                    "binary_path": f"tests/fixtures/precompiled/{dialect_dir_name}/{fixture_name}_stripped.luac",
                    "binary_sha256": bin_sha,
                    "is_stripped": True,
                    "compiler_version": info["version"],
                    "compiler_flags": "-s -o <out> <src>",
                })

    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host_system": platform.system(),
        "host_machine": platform.machine(),
        "fixtures_count": len(fixtures_entries),
        "fixtures": fixtures_entries,
    }

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print(f"[OK] Generated {MANIFEST_PATH} with {len(fixtures_entries)} fixtures.")


if __name__ == "__main__":
    main()
