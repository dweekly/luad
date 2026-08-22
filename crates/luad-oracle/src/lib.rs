//! Oracle compiler harness and differential testing utilities.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;

pub mod listing_parser;

pub use listing_parser::{assert_chunk_matches_luac, parse_luac_dump, LuacDump, LuacProtoDump};
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

/// Locate Lua 5.4 compiler binary on host system.
#[must_use]
pub fn find_luac54() -> Option<PathBuf> {
    let candidate_paths = [
        "/tmp/lua-tools/bin/luac5.4",
        "/opt/homebrew/opt/lua@5.4/bin/luac",
        "/usr/local/opt/lua@5.4/bin/luac",
        "luac5.4",
        "luac-5.4",
        "luac",
    ];

    for candidate in candidate_paths {
        let path = Path::new(candidate);
        if path.exists() {
            // Verify version output
            if let Ok(output) = Command::new(path).arg("-v").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stdout.contains("5.4") || stderr.contains("5.4") {
                    return Some(path.to_path_buf());
                }
            }
        } else if let Ok(output) = Command::new(candidate).arg("-v").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stdout.contains("5.4") || stderr.contains("5.4") {
                return Some(PathBuf::from(candidate));
            }
        }
    }

    None
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
    let candidate_paths = [
        "/tmp/lua-tools/bin/luac5.5",
        "/opt/homebrew/bin/luac",
        "/opt/homebrew/Cellar/lua/5.5.1/bin/luac",
        "/usr/local/bin/luac",
        "luac5.5",
        "luac-5.5",
        "luac",
    ];

    for candidate in candidate_paths {
        let path = Path::new(candidate);
        if path.exists() {
            if let Ok(output) = Command::new(path).arg("-v").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stdout.contains("5.5") || stderr.contains("5.5") {
                    return Some(path.to_path_buf());
                }
            }
        }
    }

    None
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
    let candidate_paths = [
        "/tmp/lua-tools/bin/luac5.3",
        "/opt/homebrew/bin/luac5.3",
        "luac5.3",
        "luac-5.3",
    ];

    for candidate in candidate_paths {
        let path = Path::new(candidate);
        if path.exists() {
            if let Ok(output) = Command::new(path).arg("-v").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stdout.contains("5.3") || stderr.contains("5.3") {
                    return Some(path.to_path_buf());
                }
            }
        }
    }
    None
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
    let candidate_paths = [
        "/tmp/lua-tools/bin/luac5.2",
        "/opt/homebrew/bin/luac5.2",
        "luac5.2",
        "luac-5.2",
    ];

    for candidate in candidate_paths {
        let path = Path::new(candidate);
        if path.exists() {
            if let Ok(output) = Command::new(path).arg("-v").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stdout.contains("5.2") || stderr.contains("5.2") {
                    return Some(path.to_path_buf());
                }
            }
        }
    }
    None
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
    let candidate_paths = [
        "/tmp/lua-tools/bin/luac5.1",
        "/opt/homebrew/bin/luac5.1",
        "luac5.1",
        "luac-5.1",
    ];

    for candidate in candidate_paths {
        let path = Path::new(candidate);
        if path.exists() {
            if let Ok(output) = Command::new(path).arg("-v").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                if stdout.contains("5.1") || stderr.contains("5.1") {
                    return Some(path.to_path_buf());
                }
            }
        }
    }
    None
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
    let dialect = luad_dialect_lua51::Lua51Dialect;
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
