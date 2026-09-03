//! Oracle compiler harness and differential testing utilities.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tempfile::NamedTempFile;

pub mod candidate;
pub mod differential_disasm;
pub mod gate_runner;
pub mod independent_lua51_oracle;
pub mod independent_lua54_oracle;
pub mod listing_parser;
pub mod release_bundle;
pub mod release_package;
pub mod release_sbom;

pub use candidate::{
    decompress_gzip, parse_tar, resolve_test_binary, verify_platform_attestation,
    BinaryResolutionDoc, BinaryResolutionError, CandidateSpec, EvidenceIndex, MemberLedger,
    MemberLedgerEntry, PlatformArtifactEntry, PlatformAttestation, TranscriptDoc,
    WorkflowTranscript,
};
pub use differential_disasm::{
    compare_chunk_tree_three_way, compare_chunk_tree_three_way_lua51, compare_proto_three_way,
    compare_proto_three_way_lua51, DisasmComparisonError, LuacProtoDumpList,
};
pub use independent_lua51_oracle::{
    IndependentInstruction51, IndependentOpMode51, IndependentOpcode51,
};

pub use gate_runner::{
    assemble_release_manifest, execute_gate_spec, verify_gate_result, verify_release_manifest,
    GateResult, GateRunnerError, GateSpec, ReleaseManifest,
};

pub use listing_parser::{
    assert_chunk_matches_luac, compare_chunk_with_luac, decode_instruction_mnemonic,
    decode_instruction_operands, parse_luac_dump, LuacConstDump, LuacDump, LuacInstDump,
    LuacLocVarDump, LuacProtoDump, LuacUpvalDump, OracleMismatch, OracleParseError,
};
pub use release_bundle::{
    assemble_release_bundle, verify_release_bundle, BundleArchive, BundleMember,
    BundleMemberLedger, BundlePlatform, BundleSbom, EvidenceConclusion, PrerequisiteDocument,
    PrerequisiteResult, ReleaseBundleResult, ReleaseEvidenceIndex,
};
pub use release_package::{
    clean_source_revision, extract_verified_release, pack_release, package_clean_workspace,
    smoke_release_binary, verify_release, InstallationTranscript, PackageCommandResult,
    ReleaseArtifactPaths, ReleaseIdentity, ReleaseInputs, VerifiedRelease,
};
pub use release_sbom::{
    generate_release_sbom, verify_release_sbom, ReleaseSbomResult, VerifiedReleaseSbom,
};

use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::Lua54Dialect;

/// Locate repository root directory in a CWD-independent manner.
#[must_use]
pub fn find_workspace_root() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());

    let mut current = manifest_dir;
    loop {
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return current;
                }
            }
        }
        if !current.pop() {
            break;
        }
    }
    PathBuf::from(".")
}

/// Load a test fixture Lua source string in a CWD-independent manner.
pub fn load_source_fixture(fixture_name: &str) -> Result<String, String> {
    let root = find_workspace_root();
    let path = root
        .join("tests")
        .join("fixtures")
        .join(format!("{fixture_name}.lua"));
    fs::read_to_string(&path).map_err(|e| format!("Failed to read fixture '{path:?}': {e}"))
}

/// Load a precompiled bytecode fixture binary in a CWD-independent manner.
pub fn load_precompiled_fixture(
    dialect: &str,
    fixture_name: &str,
    strip: bool,
) -> Result<Vec<u8>, String> {
    let root = find_workspace_root();
    let filename = if strip {
        format!("{fixture_name}_stripped.luac")
    } else {
        format!("{fixture_name}.luac")
    };
    let path = root
        .join("tests")
        .join("fixtures")
        .join("precompiled")
        .join(dialect)
        .join(filename);
    fs::read(&path).map_err(|e| format!("Failed to read precompiled fixture '{path:?}': {e}"))
}

/// Obtain bytecode for a fixture: compiles dynamically if host compiler is available, or falls back to bundled precompiled bytecode.
pub fn get_fixture_bytes(
    dialect: &str,
    fixture_name: &str,
    strip: bool,
) -> Result<Vec<u8>, String> {
    let live_result = match dialect {
        "lua5.5" => load_source_fixture(fixture_name).and_then(|s| compile_source_lua55(&s, strip)),
        "lua5.4" => load_source_fixture(fixture_name).and_then(|s| compile_source_lua54(&s, strip)),
        "lua5.3" => load_source_fixture(fixture_name).and_then(|s| compile_source_lua53(&s, strip)),
        "lua5.2" => load_source_fixture(fixture_name).and_then(|s| compile_source_lua52(&s, strip)),
        "lua5.1" => load_source_fixture(fixture_name).and_then(|s| compile_source_lua51(&s, strip)),
        _ => Err(format!("Unknown dialect {dialect}")),
    };

    match live_result {
        Ok(bytes) => Ok(bytes),
        Err(_) => load_precompiled_fixture(
            match dialect {
                "lua5.5" => "lua55",
                "lua5.4" => "lua54",
                "lua5.3" => "lua53",
                "lua5.2" => "lua52",
                "lua5.1" => "lua51",
                other => other,
            },
            fixture_name,
            strip,
        ),
    }
}

/// The exact official Lua releases the differential oracle is pinned to, ascending.
///
/// `scripts/install_ci_compilers.sh` owns these values: it builds each release against a
/// recorded SHA-256 and refuses a binary whose banner names a different one. Its
/// `build_lua` arguments are the definition; `scripts/bringup.sh` reads them directly,
/// and `crates/luad-oracle/tests/test_bringup_pins.rs` fails if this array disagrees.
///
/// Every search below matches a whole release. A series prefix such as `5.4` accepts any
/// 5.4.x a host happens to carry, and a differential result is evidence only about the
/// release that produced it.
pub const LUA_RELEASES: [&str; 5] = ["5.1.5", "5.2.4", "5.3.6", "5.4.8", "5.5.1"];

/// Pinned Lua 5.1 release.
pub const LUA51_RELEASE: &str = LUA_RELEASES[0];
/// Pinned Lua 5.2 release.
pub const LUA52_RELEASE: &str = LUA_RELEASES[1];
/// Pinned Lua 5.3 release.
pub const LUA53_RELEASE: &str = LUA_RELEASES[2];
/// Pinned Lua 5.4 release.
pub const LUA54_RELEASE: &str = LUA_RELEASES[3];
/// Pinned Lua 5.5 release.
pub const LUA55_RELEASE: &str = LUA_RELEASES[4];

/// Directory beneath the user's home where `scripts/install_ci_compilers.sh` installs the
/// official Lua compilers, and the first location every compiler search consults after an
/// explicit `LUAD_ORACLE_BIN_DIR` override.
///
/// The compilers live under `$HOME` rather than `/tmp` because macOS clears `/tmp` on
/// reboot; the `/tmp/lua-tools/bin` entries that remain in the candidate lists keep an
/// existing installation usable without a reinstall.
///
/// Cross-checked against `LUAD_COMPILER_DIR_DEFAULT` in `scripts/pins.env` by
/// `crates/luad-oracle/tests/test_bringup_pins.rs`.
pub const PERSISTENT_COMPILER_SUBDIR: &str = ".cache/luad/lua-tools/bin";

/// Absolute persistent compiler directory for the current user, when `HOME` is set.
#[must_use]
pub fn persistent_compiler_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(PERSISTENT_COMPILER_SUBDIR))
}

/// Directory `scripts/install_ci_compilers.sh` installs into, for operator messages.
fn install_compiler_dir() -> String {
    if let Some(dir) = std::env::var_os("LUAD_COMPILER_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).display().to_string();
        }
    }
    persistent_compiler_dir().map_or_else(
        || format!("$HOME/{PERSISTENT_COMPILER_SUBDIR}"),
        |p| p.display().to_string(),
    )
}

/// Cargo's target directory for this workspace.
///
/// Honors `CARGO_TARGET_DIR` and `CARGO_BUILD_TARGET_DIR`; a relative value is resolved
/// against the workspace root, which is where Cargo is invoked for the repository's own
/// checks. Tests that spawn a built binary must go through this rather than assuming
/// `<workspace>/target`, or they break whenever the target directory is relocated.
#[must_use]
pub fn cargo_target_dir() -> PathBuf {
    let root = find_workspace_root();
    for key in ["CARGO_TARGET_DIR", "CARGO_BUILD_TARGET_DIR"] {
        if let Some(value) = std::env::var_os(key) {
            if value.is_empty() {
                continue;
            }
            let path = PathBuf::from(value);
            return if path.is_absolute() {
                path
            } else {
                root.join(path)
            };
        }
    }
    root.join("target")
}

/// Serializes the on-demand `luad` build so parallel test threads issue at most one.
static LUAD_BUILD_LOCK: Mutex<()> = Mutex::new(());

/// Absolute path of the public `luad` binary for integration tests, built if absent.
///
/// `env!("CARGO_BIN_EXE_luad")` is not available here: Cargo defines `CARGO_BIN_EXE_<name>`
/// only for binaries declared by the package under test, and `luad` belongs to `luad-cli`.
/// `scripts/check.sh` exports the variable at runtime. Otherwise the binary is resolved
/// inside whatever target directory Cargo is using, and built there when it is not
/// present: `cargo test -p luad-oracle` builds only `luad-oracle`, so a fresh target
/// directory never contains `luad` until something asks for it.
///
/// Absence is never reported as success; a failed build returns the command's output.
pub fn try_luad_binary_path() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("CARGO_BIN_EXE_luad") {
        if !value.is_empty() {
            let path = PathBuf::from(value);
            if path.exists() {
                return Ok(path);
            }
        }
    }

    let target_dir = cargo_target_dir();
    let path = target_dir.join("debug").join("luad");
    if path.exists() {
        return Ok(path);
    }

    let guard = LUAD_BUILD_LOCK.lock();
    // A poisoned lock means another thread panicked mid-build; the build itself is
    // idempotent, so recover the guard and rebuild rather than propagating the panic.
    let _guard = match guard {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    if path.exists() {
        return Ok(path);
    }

    // Cargo exports CARGO for processes it launches; falling back to the name on PATH
    // keeps this working when a test binary is run directly.
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let root = find_workspace_root();
    let output = Command::new(cargo)
        .args(["build", "-p", "luad-cli", "--bin", "luad", "--target-dir"])
        .arg(&target_dir)
        .current_dir(&root)
        .output()
        .map_err(|error| format!("failed to spawn cargo build -p luad-cli: {error}"))?;

    if !output.status.success() {
        return Err(format!(
            "cargo build -p luad-cli --bin luad --target-dir {} failed with status {:?}\nstderr:\n{}",
            target_dir.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !path.exists() {
        return Err(format!(
            "cargo build reported success but {} does not exist",
            path.display()
        ));
    }
    Ok(path)
}

/// Absolute path of the public `luad` binary, panicking when it cannot be produced.
#[must_use]
pub fn luad_binary_path() -> PathBuf {
    try_luad_binary_path().unwrap_or_else(|error| panic!("{error}"))
}

/// Accept `path` only when its `-v` banner names `expected_version`.
fn compiler_matches_version(path: &Path, expected_version: &str) -> bool {
    let Ok(output) = Command::new(path).arg("-v").output() else {
        return false;
    };
    let banner = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let actual = banner.trim();
    actual.starts_with(expected_version) || actual.contains(expected_version)
}

/// Locate compiler binary checking LUAD_ORACLE_BIN_DIR first, then the persistent
/// compiler directory, then explicit absolute paths, verifying version output.
pub fn find_compiler_binary(
    bin_name: &str,
    candidates: &[&str],
    expected_version: &str,
) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("LUAD_ORACLE_BIN_DIR") {
        let p = Path::new(&dir).join(bin_name);
        if p.exists() && compiler_matches_version(&p, expected_version) {
            return Some(p);
        }
    }

    // Ahead of the candidate list so a persistent installation always wins over a
    // stale copy left in /tmp by an earlier session.
    if let Some(p) = persistent_compiler_dir().map(|dir| dir.join(bin_name)) {
        if p.exists() && compiler_matches_version(&p, expected_version) {
            return Some(p);
        }
    }

    for candidate in candidates {
        let path = Path::new(candidate);
        let target_path = if path.is_absolute() {
            if path.exists() {
                Some(path.to_path_buf())
            } else {
                None
            }
        } else {
            // Search in PATH directories
            std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|p| p.join(candidate))
                    .find(|p| p.is_file())
            })
        };

        if let Some(p) = target_path {
            if let Ok(output) = Command::new(&p).arg("-v").output() {
                let v = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let actual = v.trim();
                if actual.starts_with(expected_version) || actual.contains(expected_version) {
                    return Some(p);
                }
            }
        }
    }

    None
}

/// Locate Lua 5.4 compiler binary on host system.
#[must_use]
pub fn find_luac54() -> Option<PathBuf> {
    find_compiler_binary(
        "luac5.4",
        &[
            "/tmp/lua-tools/bin/luac5.4",
            "/opt/homebrew/opt/lua@5.4/bin/luac",
            "/usr/local/opt/lua@5.4/bin/luac",
            "luac5.4",
            "luac-5.4",
        ],
        LUA54_RELEASE,
    )
}

/// Compile Lua 5.4 source code to binary chunk using host `luac`.
pub fn compile_source_lua54(source: &str, strip: bool) -> Result<Vec<u8>, String> {
    let luac_path = find_luac54().ok_or("Lua 5.4 compiler ('luac') not found on system")?;

    let src_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    let out_file = NamedTempFile::new().map_err(|e| e.to_string())?;

    fs::write(src_file.path(), source).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(luac_path);
    cmd.arg("-o").arg(out_file.path());
    if strip {
        cmd.arg("-s");
    }
    cmd.arg(src_file.path());

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("luac compilation failed: {err}"));
    }

    fs::read(out_file.path()).map_err(|e| e.to_string())
}

/// Compile Lua source and parse with `luad_dialect_lua54`.
pub fn compile_and_parse_lua54(source: &str, strip: bool) -> Result<Chunk, String> {
    let bytes = compile_source_lua54(source, strip)?;
    let dialect = Lua54Dialect;
    let mut reader =
        SafeReader::with_options(&bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    dialect.decode_chunk(&mut reader).map_err(|d| d.message)
}

/// Locate Lua 5.5 compiler binary on host system.
#[must_use]
pub fn find_luac55() -> Option<PathBuf> {
    find_compiler_binary(
        "luac5.5",
        &[
            "/tmp/lua-tools/bin/luac5.5",
            "/opt/homebrew/bin/luac",
            "/opt/homebrew/Cellar/lua/5.5.1/bin/luac",
            "/usr/local/bin/luac",
            "luac5.5",
            "luac-5.5",
        ],
        LUA55_RELEASE,
    )
}

/// Compile Lua 5.5 source code to binary chunk using host `luac`.
pub fn compile_source_lua55(source: &str, strip: bool) -> Result<Vec<u8>, String> {
    let luac_path = find_luac55().ok_or("Lua 5.5 compiler ('luac') not found on system")?;

    let src_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    let out_file = NamedTempFile::new().map_err(|e| e.to_string())?;

    fs::write(src_file.path(), source).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(luac_path);
    cmd.arg("-o").arg(out_file.path());
    if strip {
        cmd.arg("-s");
    }
    cmd.arg(src_file.path());

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("luac 5.5 compilation failed: {err}"));
    }

    fs::read(out_file.path()).map_err(|e| e.to_string())
}

/// Disassemble Lua source using `luac -l -l`.
pub fn dump_source_luac(compiler_path: &Path, source: &str) -> Result<String, String> {
    let src_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    fs::write(src_file.path(), source).map_err(|e| e.to_string())?;

    let output = Command::new(compiler_path)
        .args(["-l", "-l", "-p"])
        .arg(src_file.path())
        .output()
        .map_err(|e| e.to_string())?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("luac dump failed: {err}"));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Locate Lua 5.3 compiler binary on host system.
#[must_use]
pub fn find_luac53() -> Option<PathBuf> {
    find_compiler_binary(
        "luac5.3",
        &[
            "/tmp/lua-tools/bin/luac5.3",
            "/opt/homebrew/bin/luac5.3",
            "luac5.3",
            "luac-5.3",
        ],
        LUA53_RELEASE,
    )
}

/// Compile Lua 5.3 source code to binary chunk using host `luac`.
pub fn compile_source_lua53(source: &str, strip: bool) -> Result<Vec<u8>, String> {
    let luac_path = find_luac53().ok_or("Lua 5.3 compiler ('luac') not found on system")?;
    let src_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    let out_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    fs::write(src_file.path(), source).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(luac_path);
    cmd.arg("-o").arg(out_file.path());
    if strip {
        cmd.arg("-s");
    }
    cmd.arg(src_file.path());

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("luac 5.3 compilation failed: {err}"));
    }
    fs::read(out_file.path()).map_err(|e| e.to_string())
}

/// Compile Lua source and parse with `luad_dialect_lua53`.
pub fn compile_and_parse_lua53(source: &str, strip: bool) -> Result<Chunk, String> {
    let bytes = compile_source_lua53(source, strip)?;
    let dialect = luad_dialect_lua53::Lua53Dialect;
    let mut reader =
        SafeReader::with_options(&bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    dialect.decode_chunk(&mut reader).map_err(|d| d.message)
}

/// Locate Lua 5.2 compiler binary on host system.
#[must_use]
pub fn find_luac52() -> Option<PathBuf> {
    find_compiler_binary(
        "luac5.2",
        &[
            "/tmp/lua-tools/bin/luac5.2",
            "/opt/homebrew/bin/luac5.2",
            "luac5.2",
            "luac-5.2",
        ],
        LUA52_RELEASE,
    )
}

/// Compile Lua 5.2 source code to binary chunk using host `luac`.
pub fn compile_source_lua52(source: &str, strip: bool) -> Result<Vec<u8>, String> {
    let luac_path = find_luac52().ok_or("Lua 5.2 compiler ('luac') not found on system")?;
    let src_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    let out_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    fs::write(src_file.path(), source).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(luac_path);
    cmd.arg("-o").arg(out_file.path());
    if strip {
        cmd.arg("-s");
    }
    cmd.arg(src_file.path());

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("luac 5.2 compilation failed: {err}"));
    }
    fs::read(out_file.path()).map_err(|e| e.to_string())
}

/// Compile Lua source and parse with `luad_dialect_lua52`.
pub fn compile_and_parse_lua52(source: &str, strip: bool) -> Result<Chunk, String> {
    let bytes = compile_source_lua52(source, strip)?;
    let dialect = luad_dialect_lua52::Lua52Dialect;
    let mut reader =
        SafeReader::with_options(&bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    dialect.decode_chunk(&mut reader).map_err(|d| d.message)
}

/// Locate Lua 5.1 compiler binary on host system.
#[must_use]
pub fn find_luac51() -> Option<PathBuf> {
    find_compiler_binary(
        "luac5.1",
        &[
            "/tmp/lua-tools/bin/luac5.1",
            "/opt/homebrew/opt/lua@5.1/bin/luac",
            "/opt/homebrew/bin/luac5.1",
            "/usr/local/bin/luac5.1",
            "luac5.1",
            "luac-5.1",
        ],
        LUA51_RELEASE,
    )
}

/// Compile Lua 5.1 source code to binary chunk using host `luac`.
pub fn compile_source_lua51(source: &str, strip: bool) -> Result<Vec<u8>, String> {
    let luac_path = find_luac51().ok_or("Lua 5.1 compiler ('luac') not found on system")?;
    let src_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    let out_file = NamedTempFile::new().map_err(|e| e.to_string())?;
    fs::write(src_file.path(), source).map_err(|e| e.to_string())?;

    let mut cmd = Command::new(luac_path);
    cmd.arg("-o").arg(out_file.path());
    if strip {
        cmd.arg("-s");
    }
    cmd.arg(src_file.path());

    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("luac 5.1 compilation failed: {err}"));
    }
    fs::read(out_file.path()).map_err(|e| e.to_string())
}

/// Compile Lua source and parse with `luad_dialect_lua51`.
pub fn compile_and_parse_lua51(source: &str, strip: bool) -> Result<Chunk, String> {
    let bytes = compile_source_lua51(source, strip)?;
    let dialect = luad_dialect_lua51::Lua51Dialect::default();
    let mut reader =
        SafeReader::with_options(&bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    dialect.decode_chunk(&mut reader).map_err(|d| d.message)
}

/// Verify that 100% of bytes in a valid chunk are accounted for.
pub fn verify_byte_accounting(chunk: &Chunk, raw_bytes: &[u8]) {
    assert_eq!(chunk.byte_length, raw_bytes.len());
    assert_eq!(chunk.header.source.byte_length, 31);
    assert_eq!(chunk.header.source.byte_offset, 0);

    let main_proto = &chunk.main_proto;
    assert_eq!(main_proto.source.byte_offset, 32);
    // 31 (header) + 1 (main closure sizeupvalues) + main_proto length
    let total_accounted = chunk.header.source.byte_length + 1 + main_proto.source.byte_length;
    assert_eq!(
        total_accounted,
        raw_bytes.len(),
        "Byte accounting mismatch: expected {} bytes accounted, found {}",
        raw_bytes.len(),
        total_accounted
    );
}

/// Verify that truncating valid chunk at every byte offset 0..N terminates gracefully without panic.
pub fn verify_truncation_safety(raw_bytes: &[u8]) {
    let dialect = Lua54Dialect;
    verify_truncation_safety_for_dialect(raw_bytes, &dialect);
}

/// Locate Lua 5.1 compiler binary on host system, failing closed if missing.
#[must_use]
pub fn require_luac51() -> PathBuf {
    find_luac51().unwrap_or_else(|| {
        panic!(
            "Required official Lua 5.1 compiler not found.\n\
            Run 'bash scripts/install_ci_compilers.sh' to install all official compilers into {}.",
            install_compiler_dir()
        )
    })
}

/// Locate Lua 5.2 compiler binary on host system, failing closed if missing.
#[must_use]
pub fn require_luac52() -> PathBuf {
    find_luac52().unwrap_or_else(|| {
        panic!(
            "Required official Lua 5.2 compiler not found.\n\
            Run 'bash scripts/install_ci_compilers.sh' to install all official compilers into {}.",
            install_compiler_dir()
        )
    })
}

/// Locate Lua 5.3 compiler binary on host system, failing closed if missing.
#[must_use]
pub fn require_luac53() -> PathBuf {
    find_luac53().unwrap_or_else(|| {
        panic!(
            "Required official Lua 5.3 compiler not found.\n\
            Run 'bash scripts/install_ci_compilers.sh' to install all official compilers into {}.",
            install_compiler_dir()
        )
    })
}

/// Locate Lua 5.4 compiler binary on host system, failing closed if missing.
#[must_use]
pub fn require_luac54() -> PathBuf {
    find_luac54().unwrap_or_else(|| {
        panic!(
            "Required official Lua 5.4 compiler not found.\n\
            Run 'bash scripts/install_ci_compilers.sh' to install all official compilers into {}.",
            install_compiler_dir()
        )
    })
}

/// Locate Lua 5.5 compiler binary on host system, failing closed if missing.
#[must_use]
pub fn require_luac55() -> PathBuf {
    find_luac55().unwrap_or_else(|| {
        panic!(
            "Required official Lua 5.5 compiler not found.\n\
            Run 'bash scripts/install_ci_compilers.sh' to install all official compilers into {}.",
            install_compiler_dir()
        )
    })
}

/// Verify that truncating valid chunk at every byte offset 0..N terminates gracefully without panic for a given dialect.
pub fn verify_truncation_safety_for_dialect(raw_bytes: &[u8], dialect: &dyn Dialect) {
    for len in 0..raw_bytes.len() {
        let truncated = &raw_bytes[..len];
        let mut reader =
            SafeReader::with_options(truncated, 0, ResourceLimits::default(), ParseMode::Strict);
        let _ = dialect.decode_chunk(&mut reader);

        // Also test permissive mode
        let mut perm_reader = SafeReader::with_options(
            truncated,
            0,
            ResourceLimits::default(),
            ParseMode::Permissive,
        );
        let _ = dialect.decode_chunk(&mut perm_reader);
    }
}
