//! Oracle compiler harness and differential testing utilities.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;

use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::Lua54Dialect;

/// Locate Lua 5.4 compiler binary on host system.
#[must_use]
pub fn find_luac54() -> Option<PathBuf> {
    let candidate_paths = [
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
    let mut reader = SafeReader::with_options(
        &bytes,
        0,
        ResourceLimits::default(),
        ParseMode::Strict,
    );
    dialect.decode_chunk(&mut reader).map_err(|d| d.message)
}

/// Locate Lua 5.5 compiler binary on host system.
#[must_use]
pub fn find_luac55() -> Option<PathBuf> {
    let candidate_paths = [
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

/// Compile Lua source and parse with `luad_dialect_lua55`.
pub fn compile_and_parse_lua55(source: &str, strip: bool) -> Result<Chunk, String> {
    let bytes = compile_source_lua55(source, strip)?;
    let dialect = luad_dialect_lua55::Lua55Dialect;
    let mut reader = SafeReader::with_options(
        &bytes,
        0,
        ResourceLimits::default(),
        ParseMode::Strict,
    );
    dialect.decode_chunk(&mut reader).map_err(|d| d.message)
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
    let mut reader = SafeReader::with_options(
        &bytes,
        0,
        ResourceLimits::default(),
        ParseMode::Strict,
    );
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
    let mut reader = SafeReader::with_options(
        &bytes,
        0,
        ResourceLimits::default(),
        ParseMode::Strict,
    );
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
    let mut reader = SafeReader::with_options(
        &bytes,
        0,
        ResourceLimits::default(),
        ParseMode::Strict,
    );
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
        let mut reader = SafeReader::with_options(
            truncated,
            0,
            ResourceLimits::default(),
            ParseMode::Strict,
        );
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

