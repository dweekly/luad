//! Failure provenance and exit categories test suite (Roadmap Stage 4 / Package E).
//!
//! Verifies:
//! 1. Offending field locations attached to diagnostics across dialects.
//! 2. Elimination of invented offset-zero fallbacks.
//! 3. Syntactically valid count of 1,000,001 instructions reports count field offset and exits 5 (LimitExceeded).
//! 4. Nonzero reader base offsets honored in reported locations.
//! 5. Process boundary exit codes (1=InvalidInput, 2=UsageError, 3=IoError, 4=UnsupportedFormat, 5=LimitExceeded).
//! 6. Batch export preserves actual failure provenance while upholding mixed aggregation policy.

use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::Lua54Dialect;

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

/// Helper to build a minimal valid Lua 5.4 bytecode header (31 bytes).
fn make_lua54_header() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"\x1bLua\x54\x00"); // signature, version, format
    h.extend_from_slice(b"\x19\x93\r\n\x1a\n"); // luac_data
    h.push(4); // sizeof(Instruction)
    h.push(8); // sizeof(lua_Integer)
    h.push(8); // sizeof(lua_Number)
    h.extend_from_slice(&0x5678_i64.to_le_bytes()); // LUAC_INT
    h.extend_from_slice(&370.5_f64.to_le_bytes()); // LUAC_NUM
    assert_eq!(h.len(), 31);
    h
}

#[test]
fn test_instruction_count_ceiling_1000001_reports_offset_and_exits_5() {
    let luad = get_luad_bin();

    // Construct a Lua 5.4 chunk where the instruction count is exactly 1,000,001.
    // In Lua 5.4 varint: MSB bit 7 set terminates.
    // 1,000,001 in Lua 5.4 varint: [0x3d, 0x04, 0xc1].
    let mut bytes = make_lua54_header();
    bytes.push(0); // sizeupvalues = 0 (offset 31)
                   // Proto fields:
    bytes.push(0x80); // source name NULL (offset 32)
    bytes.push(0x80); // line_defined = 0 (offset 33)
    bytes.push(0x80); // last_line_defined = 0 (offset 34)
    bytes.push(0); // numparams = 0 (offset 35)
    bytes.push(0); // is_vararg = 0 (offset 36)
    bytes.push(2); // maxstacksize = 2 (offset 37)

    // Code size varint: starts at offset 38
    let count_offset = bytes.len();
    assert_eq!(count_offset, 38);
    bytes.extend_from_slice(&[0x3d, 0x04, 0xc1]); // 1,000,001

    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), &bytes).unwrap();

    let output = Command::new(&luad)
        .args(["inspect", temp_file.path().to_str().unwrap()])
        .output()
        .expect("luad inspect must run");

    // Must exit with code 5 (LimitExceeded), NOT code 1 (InvalidInput)
    assert_eq!(
        output.status.code(),
        Some(5),
        "Instruction count limit exceeded must exit code 5 (LimitExceeded)"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Must report the exact count field offset (38)
    assert!(
        stderr.contains(&format!("offset {count_offset}")),
        "stderr must report count field offset {count_offset}, got: {stderr}"
    );
    // Must not invent offset 0
    assert!(
        !stderr.contains("offset 0"),
        "stderr must not report invented offset 0, got: {stderr}"
    );
    // Must explain the instruction count limit
    assert!(
        stderr.contains("Instruction count 1000001 exceeds safety limit"),
        "stderr must explain instruction count ceiling, got: {stderr}"
    );
}

#[test]
fn test_constant_count_ceiling_reports_offset_and_exits_5() {
    let luad = get_luad_bin();

    let mut bytes = make_lua54_header();
    bytes.push(0); // sizeupvalues = 0 (offset 31)
    bytes.push(0x80); // source name NULL (offset 32)
    bytes.push(0x80); // line_defined = 0 (offset 33)
    bytes.push(0x80); // last_line_defined = 0 (offset 34)
    bytes.push(0); // numparams = 0 (offset 35)
    bytes.push(0); // is_vararg = 0 (offset 36)
    bytes.push(2); // maxstacksize = 2 (offset 37)
    bytes.push(0x80); // sizecode = 0 (offset 38)

    // Constant count varint starts at offset 39
    let const_count_offset = bytes.len();
    assert_eq!(const_count_offset, 39);
    bytes.extend_from_slice(&[0x3d, 0x04, 0xc1]); // 1,000,001

    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), &bytes).unwrap();

    let output = Command::new(&luad)
        .args(["inspect", temp_file.path().to_str().unwrap()])
        .output()
        .expect("luad inspect must run");

    assert_eq!(
        output.status.code(),
        Some(5),
        "Constant count limit exceeded must exit code 5"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("offset {const_count_offset}")),
        "stderr must report constant count offset {const_count_offset}, got: {stderr}"
    );
    assert!(
        !stderr.contains("offset 0"),
        "stderr must not report invented offset 0"
    );
}

#[test]
fn test_malformed_constant_tag_reports_exact_offset_and_exits_1() {
    let luad = get_luad_bin();

    let mut bytes = make_lua54_header();
    bytes.push(0); // sizeupvalues = 0 (offset 31)
    bytes.push(0x80); // source name NULL (offset 32)
    bytes.push(0x80); // line_defined (offset 33)
    bytes.push(0x80); // last_line_defined (offset 34)
    bytes.push(0); // numparams (offset 35)
    bytes.push(0); // is_vararg (offset 36)
    bytes.push(2); // maxstacksize (offset 37)
    bytes.push(0x80); // sizecode = 0 (offset 38)
    bytes.push(0x81); // sizek = 1 (offset 39)

    let tag_offset = bytes.len();
    assert_eq!(tag_offset, 40);
    bytes.push(0xee); // Corrupt constant tag (not a valid Lua 5.4 tag)

    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), &bytes).unwrap();

    let output = Command::new(&luad)
        .args(["inspect", temp_file.path().to_str().unwrap()])
        .output()
        .expect("luad inspect must run");

    // Malformed recognized input must exit 1 (InvalidInput)
    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("offset {tag_offset}")),
        "stderr must report corrupt tag offset {tag_offset}, got: {stderr}"
    );
}

#[test]
fn test_nested_truncation_reports_exact_offset_and_exits_1() {
    let luad = get_luad_bin();

    let mut bytes = make_lua54_header();
    bytes.push(0); // sizeupvalues
    bytes.push(0x80); // source name NULL
    bytes.push(0x80); // line_defined
    bytes.push(0x80); // last_line_defined
    bytes.push(0); // numparams
    bytes.push(0); // is_vararg
    bytes.push(2); // maxstacksize
    bytes.push(0x82); // sizecode = 2 instructions (8 bytes required)
    let inst_offset = bytes.len();
    assert_eq!(inst_offset, 39);
    bytes.extend_from_slice(&[0x01, 0x02]); // only 2 bytes provided -> truncated

    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), &bytes).unwrap();

    let output = Command::new(&luad)
        .args(["inspect", temp_file.path().to_str().unwrap()])
        .output()
        .expect("luad inspect must run");

    assert_eq!(output.status.code(), Some(1));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("offset {inst_offset}")),
        "stderr must report truncated instruction offset {inst_offset}, got: {stderr}"
    );
}

#[test]
fn test_nonzero_reader_base_offset_shifts_all_reported_locations() {
    let base_offset: usize = 0x1000; // 4096 base offset

    let mut bytes = make_lua54_header();
    bytes.push(0); // sizeupvalues (offset 31)
    bytes.push(0x80); // source name NULL (offset 32)
    bytes.push(0x80); // line_defined (offset 33)
    bytes.push(0x80); // last_line_defined (offset 34)
    bytes.push(0); // numparams (offset 35)
    bytes.push(0); // is_vararg (offset 36)
    bytes.push(2); // maxstacksize (offset 37)
                   // 1,000,001 instructions at offset 38
    bytes.extend_from_slice(&[0x3d, 0x04, 0xc1]);

    let limits = ResourceLimits::default();
    let mut reader =
        SafeReader::with_options(&bytes, base_offset, limits.clone(), ParseMode::Strict);

    let dialect = Lua54Dialect;
    let result = dialect.decode_chunk(&mut reader);
    assert!(result.is_err());
    let diag = result.unwrap_err();

    let source = diag.source.expect("diagnostic must have source location");
    assert_eq!(
        source.byte_offset,
        base_offset + 38,
        "SourceLocation must incorporate nonzero reader base offset"
    );
    assert_eq!(source.byte_length, 3);
    assert_eq!(source.raw_hex, "3d04c1");

    // Also verify truncation with base offset:
    let trunc_bytes = vec![0x1b, 0x4c, 0x75, 0x61]; // 4 bytes only
    let mut trunc_reader =
        SafeReader::with_options(&trunc_bytes, base_offset, limits, ParseMode::Strict);
    let trunc_res = dialect.decode_chunk(&mut trunc_reader);
    assert!(trunc_res.is_err());
    let trunc_diag = trunc_res.unwrap_err();
    let trunc_source = trunc_diag.source.expect("truncation must have location");
    assert_eq!(
        trunc_source.byte_offset,
        base_offset + 4,
        "Truncation location must incorporate base offset"
    );
}

#[test]
fn test_missing_source_location_diagnostic_prints_without_offset_zero() {
    let luad = get_luad_bin();

    // Create a diagnostic without a source location and verify formatting behavior.
    // Also test CLI directly on unknown dialect:
    let output = Command::new(&luad)
        .args(["inspect", "Cargo.toml"]) // Not a lua bytecode file
        .output()
        .expect("luad inspect must run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Unknown format fails without invented offset 0
    assert!(
        !stderr.contains("offset 0"),
        "stderr must not report invented offset 0 on unknown format"
    );
}

#[test]
fn test_exit_code_matrix_strict_separation() {
    let luad = get_luad_bin();

    // 1. Exit code 1: InvalidInput (malformed recognized chunk)
    {
        let mut bytes = make_lua54_header();
        bytes.push(0); // sizeupvalues
        bytes.push(0); // source name
        bytes.push(0); // line_defined
        bytes.push(0); // last_line_defined
        bytes.push(0); // numparams
        bytes.push(0); // is_vararg
        bytes.push(2); // maxstacksize
        bytes.push(1); // 1 instruction
        bytes.extend_from_slice(&[0x00, 0x00]); // truncated instruction body
        let temp = NamedTempFile::new().unwrap();
        fs::write(temp.path(), &bytes).unwrap();
        let out = Command::new(&luad)
            .args(["inspect", temp.path().to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "Malformed body must exit 1");
    }

    // 2. Exit code 2: UsageError (invalid selector / arguments)
    {
        let fixture = luad_oracle::get_fixture_bytes("lua5.4", "hello", false).unwrap();
        let temp = NamedTempFile::new().unwrap();
        fs::write(temp.path(), &fixture).unwrap();
        let out = Command::new(&luad)
            .args([
                "disasm",
                "--proto",
                "proto:0:child:9999",
                temp.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "Bad selector must exit 2");
    }

    // 3. Exit code 3: IoError (missing input file)
    {
        let out = Command::new(&luad)
            .args(["inspect", "nonexistent_file_xyz_123.luac"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "Missing file must exit 3");
    }

    // 4. Exit code 4: UnsupportedFormat (unknown bytecode / non-Lua)
    {
        let temp = NamedTempFile::new().unwrap();
        fs::write(temp.path(), b"NOT_LUA_BYTES").unwrap();
        let out = Command::new(&luad)
            .args(["inspect", temp.path().to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(4), "Unknown format must exit 4");
    }

    // 5. Exit code 5: LimitExceeded (instruction count > 1,000,000)
    {
        let mut bytes = make_lua54_header();
        bytes.push(0); // sizeupvalues (offset 31)
        bytes.push(0x80); // source name (offset 32)
        bytes.push(0x80); // line_defined (offset 33)
        bytes.push(0x80); // last_line_defined (offset 34)
        bytes.push(0); // numparams (offset 35)
        bytes.push(0); // is_vararg (offset 36)
        bytes.push(2); // maxstacksize (offset 37)
        bytes.extend_from_slice(&[0x3d, 0x04, 0xc1]); // 1,000,001 at offset 38
        let temp = NamedTempFile::new().unwrap();
        fs::write(temp.path(), &bytes).unwrap();
        let out = Command::new(&luad)
            .args(["inspect", temp.path().to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(5), "Limit exceeded must exit 5");
    }
}

#[test]
fn test_batch_export_retains_provenance_and_preserves_aggregation() {
    let luad = get_luad_bin();

    // 1. Valid file
    let valid_bytes = luad_oracle::get_fixture_bytes("lua5.4", "hello", false).unwrap();
    let valid_temp = NamedTempFile::new().unwrap();
    fs::write(valid_temp.path(), &valid_bytes).unwrap();

    // 2. Limit-exceeded file (instruction count 1,000,001)
    let mut limit_bytes = make_lua54_header();
    limit_bytes.push(0); // sizeupvalues (offset 31)
    limit_bytes.push(0x80); // source name (offset 32)
    limit_bytes.push(0x80); // line_defined (offset 33)
    limit_bytes.push(0x80); // last_line_defined (offset 34)
    limit_bytes.push(0); // numparams (offset 35)
    limit_bytes.push(0); // is_vararg (offset 36)
    limit_bytes.push(2); // maxstacksize (offset 37)
    limit_bytes.extend_from_slice(&[0x3d, 0x04, 0xc1]); // offset 38
    let limit_temp = NamedTempFile::new().unwrap();
    fs::write(limit_temp.path(), &limit_bytes).unwrap();

    // 3. Malformed tag file
    let mut malformed_bytes = make_lua54_header();
    malformed_bytes.push(0); // sizeupvalues (offset 31)
    malformed_bytes.push(0x80); // source name (offset 32)
    malformed_bytes.push(0x80); // line_defined (offset 33)
    malformed_bytes.push(0x80); // last_line_defined (offset 34)
    malformed_bytes.push(0); // numparams (offset 35)
    malformed_bytes.push(0); // is_vararg (offset 36)
    malformed_bytes.push(2); // maxstacksize (offset 37)
    malformed_bytes.push(0x80); // sizecode = 0 (offset 38)
    malformed_bytes.push(0x81); // sizek = 1 (offset 39)
    malformed_bytes.push(0xee); // corrupt tag (offset 40)
    let malformed_temp = NamedTempFile::new().unwrap();
    fs::write(malformed_temp.path(), &malformed_bytes).unwrap();

    // 4. Missing file
    let missing_path = "nonexistent_batch_file_abc.luac";

    let output = Command::new(&luad)
        .args([
            "export",
            valid_temp.path().to_str().unwrap(),
            limit_temp.path().to_str().unwrap(),
            malformed_temp.path().to_str().unwrap(),
            missing_path,
            "--format",
            "jsonl",
        ])
        .output()
        .expect("luad export must run");

    // Exit code 0 because at least 1 file succeeded
    assert_eq!(output.status.code(), Some(0));

    let stdout = String::from_utf8(output.stdout).expect("valid utf8");
    let records: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    let export_end = records.last().expect("must have export_end");
    assert_eq!(export_end["record_type"], "export_end");
    assert_eq!(export_end["files_processed"], 4);
    assert_eq!(export_end["files_succeeded"], 1);
    assert_eq!(export_end["files_skipped"], 2); // limit and malformed parse failures are skipped
    assert_eq!(export_end["files_failed"], 1); // missing file read error is failed

    // Verify diagnostic records preserve source location
    let diag_records: Vec<_> = records
        .iter()
        .filter(|r| r["record_type"] == "diagnostic")
        .collect();

    // Find diagnostic for limit file
    let limit_diag = diag_records
        .iter()
        .find(|r| {
            r["context"]["input_identity"]["path"]
                .as_str()
                .unwrap_or("")
                == limit_temp.path().to_str().unwrap()
        })
        .expect("must have diagnostic for limit file");

    assert_eq!(limit_diag["data"]["code"], "PARSE-001");
    let limit_source = &limit_diag["data"]["source"];
    assert!(
        limit_source.is_object(),
        "limit diagnostic must carry source location"
    );
    assert_eq!(
        limit_source["byte_offset"], 38,
        "limit diagnostic must point to count offset 38"
    );
    assert!(
        limit_diag["data"]["evidence"]
            .as_str()
            .unwrap()
            .contains("L54-CODE-001"),
        "diagnostic evidence must record underlying code L54-CODE-001"
    );

    // Find diagnostic for malformed file
    let malformed_diag = diag_records
        .iter()
        .find(|r| {
            r["context"]["input_identity"]["path"]
                .as_str()
                .unwrap_or("")
                == malformed_temp.path().to_str().unwrap()
        })
        .expect("must have diagnostic for malformed file");

    assert_eq!(malformed_diag["data"]["code"], "PARSE-001");
    let malformed_source = &malformed_diag["data"]["source"];
    assert!(
        malformed_source.is_object(),
        "malformed diagnostic must carry source location"
    );
    assert_eq!(
        malformed_source["byte_offset"], 40,
        "malformed diagnostic must point to tag offset 40"
    );

    // Verify file_end records carry specific failure error
    let file_ends: Vec<_> = records
        .iter()
        .filter(|r| r["record_type"] == "file_end")
        .collect();
    assert_eq!(file_ends.len(), 4);

    let limit_end = file_ends
        .iter()
        .find(|r| r["path"] == limit_temp.path().to_str().unwrap())
        .unwrap();
    assert_eq!(limit_end["status"], "skipped");
    assert!(
        limit_end["error"]
            .as_str()
            .unwrap()
            .contains("Instruction count 1000001 exceeds safety limit"),
        "file_end error must preserve specific limit message"
    );
}
