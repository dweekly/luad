//! Analysis qualification and eligibility tests (Package A).

use std::process::Command;

use luad_analysis::{lift_proto_for_dialect, validate_for_analysis};
use luad_core::reader::SafeReader;
use luad_oracle::{get_fixture_bytes, luad_binary_path};

#[test]
fn test_analysis_eligibility_positive_for_qualified_dialects() {
    // Lua 5.1 is qualified
    let raw_51 = get_fixture_bytes("lua5.1", "hello", false).expect("5.1 fixture");
    let mut reader_51 = SafeReader::new(&raw_51);
    let chunk_51 = luad_dialect_lua51::decode_chunk_lua51(&mut reader_51).expect("clean decode");
    let res_51 = validate_for_analysis(&chunk_51);
    assert!(
        res_51.is_ok(),
        "Lua 5.1 must qualify for analysis: {res_51:?}"
    );

    // Lua 5.4 is qualified
    let raw_54 = get_fixture_bytes("lua5.4", "hello", false).expect("5.4 fixture");
    let mut reader_54 = SafeReader::new(&raw_54);
    let chunk_54 = luad_dialect_lua54::decode_chunk_lua54(&mut reader_54).expect("clean decode");
    let res_54 = validate_for_analysis(&chunk_54);
    assert!(
        res_54.is_ok(),
        "Lua 5.4 must qualify for analysis: {res_54:?}"
    );
}

#[test]
fn test_analysis_eligibility_negative_for_unqualified_dialects() {
    // Lua 5.2
    let raw_52 = get_fixture_bytes("lua5.2", "hello", false).expect("5.2 fixture");
    let mut reader_52 = SafeReader::new(&raw_52);
    let chunk_52 = luad_dialect_lua52::decode_chunk_lua52(&mut reader_52).expect("clean decode");
    let res_52 = validate_for_analysis(&chunk_52);
    assert!(
        res_52.is_err(),
        "Lua 5.2 must refuse analysis preconditions"
    );
    let diags_52 = res_52.unwrap_err();
    assert!(diags_52.iter().any(|d| d.code == "ANA-PRECOND-001"));

    // Lua 5.3
    let raw_53 = get_fixture_bytes("lua5.3", "hello", false).expect("5.3 fixture");
    let mut reader_53 = SafeReader::new(&raw_53);
    let chunk_53 = luad_dialect_lua53::decode_chunk_lua53(&mut reader_53).expect("clean decode");
    let res_53 = validate_for_analysis(&chunk_53);
    assert!(
        res_53.is_err(),
        "Lua 5.3 must refuse analysis preconditions"
    );
    let diags_53 = res_53.unwrap_err();
    assert!(diags_53.iter().any(|d| d.code == "ANA-PRECOND-001"));

    // Lua 5.5
    let raw_55 = get_fixture_bytes("lua5.5", "hello", false).expect("5.5 fixture");
    let mut reader_55 = SafeReader::new(&raw_55);
    let chunk_55 = luad_dialect_lua55::decode_chunk_lua55(&mut reader_55).expect("clean decode");
    let res_55 = validate_for_analysis(&chunk_55);
    assert!(
        res_55.is_err(),
        "Lua 5.5 must refuse analysis preconditions"
    );
    let diags_55 = res_55.unwrap_err();
    assert!(diags_55.iter().any(|d| d.code == "ANA-PRECOND-001"));

    // Unknown dialect
    let mut chunk_unknown = chunk_55;
    chunk_unknown.dialect = "lua-custom-unknown".to_string();
    let res_unk = validate_for_analysis(&chunk_unknown);
    assert!(res_unk.is_err());
    let diags_unk = res_unk.unwrap_err();
    assert!(diags_unk.iter().any(|d| d.code == "ANA-PRECOND-001"));
}

#[test]
fn test_lifter_dispatch_unknown_dialect_fails_safe() {
    let raw_54 = get_fixture_bytes("lua5.4", "hello", false).expect("5.4 fixture");
    let mut reader_54 = SafeReader::new(&raw_54);
    let chunk_54 = luad_dialect_lua54::decode_chunk_lua54(&mut reader_54).expect("clean decode");

    let lifted = lift_proto_for_dialect("unknown-dialect", &chunk_54.main_proto);
    assert!(
        lifted.is_empty(),
        "Unknown dialect lifter dispatch must return empty, not fall back to Lua 5.4"
    );
}

#[test]
fn test_cli_raw_inspection_succeeds_on_unqualified_dialects() {
    let bin = luad_binary_path();
    let root = luad_oracle::find_workspace_root();

    for (dialect, rel_path) in [
        ("lua5.2", "tests/fixtures/precompiled/lua52/hello.luac"),
        ("lua5.3", "tests/fixtures/precompiled/lua53/hello.luac"),
        ("lua5.5", "tests/fixtures/precompiled/lua55/hello.luac"),
    ] {
        let fixture = root.join(rel_path);

        // disasm succeeds with exit code 0
        let disasm_out = Command::new(&bin)
            .args(["disasm", fixture.to_str().unwrap()])
            .output()
            .unwrap_or_else(|e| panic!("Failed to run disasm on {dialect}: {e}"));
        assert!(
            disasm_out.status.success(),
            "disasm on {dialect} must succeed (exit 0): stderr={}",
            String::from_utf8_lossy(&disasm_out.stderr)
        );

        // inspect succeeds with exit code 0
        let inspect_out = Command::new(&bin)
            .args(["inspect", fixture.to_str().unwrap()])
            .output()
            .unwrap_or_else(|e| panic!("Failed to run inspect on {dialect}: {e}"));
        assert!(
            inspect_out.status.success(),
            "inspect on {dialect} must succeed (exit 0): stderr={}",
            String::from_utf8_lossy(&inspect_out.stderr)
        );
    }
}

#[test]
fn test_cli_analysis_refused_with_exit_code_4_on_unqualified_dialects() {
    let bin = luad_binary_path();
    let root = luad_oracle::find_workspace_root();

    // CFG command on Lua 5.2
    let fixture_52 = root.join("tests/fixtures/precompiled/lua52/hello.luac");
    let cfg_52 = Command::new(&bin)
        .args(["cfg", fixture_52.to_str().unwrap(), "--proto", "proto:0"])
        .output()
        .expect("run cfg");
    assert_eq!(
        cfg_52.status.code(),
        Some(4),
        "cfg on Lua 5.2 must exit with code 4"
    );
    let stderr_52 = String::from_utf8_lossy(&cfg_52.stderr);
    assert!(
        stderr_52.contains("ANA-PRECOND-001"),
        "stderr must contain ANA-PRECOND-001: {stderr_52}"
    );

    // Query command on Lua 5.3
    let fixture_53 = root.join("tests/fixtures/precompiled/lua53/hello.luac");
    let query_53 = Command::new(&bin)
        .args(["query", fixture_53.to_str().unwrap()])
        .output()
        .expect("run query");
    assert_eq!(
        query_53.status.code(),
        Some(4),
        "query on Lua 5.3 must exit with code 4"
    );
    let stderr_53 = String::from_utf8_lossy(&query_53.stderr);
    assert!(
        stderr_53.contains("ANA-PRECOND-001"),
        "stderr must contain ANA-PRECOND-001: {stderr_53}"
    );

    // Xrefs command on Lua 5.5
    let fixture_55 = root.join("tests/fixtures/precompiled/lua55/hello.luac");
    let xrefs_55 = Command::new(&bin)
        .args(["xrefs", fixture_55.to_str().unwrap()])
        .output()
        .expect("run xrefs");
    assert_eq!(
        xrefs_55.status.code(),
        Some(4),
        "xrefs on Lua 5.5 must exit with code 4"
    );
    let stderr_55 = String::from_utf8_lossy(&xrefs_55.stderr);
    assert!(
        stderr_55.contains("ANA-PRECOND-001"),
        "stderr must contain ANA-PRECOND-001: {stderr_55}"
    );
}

#[test]
fn test_cli_analysis_invalid_input_exits_code_1_not_code_4() {
    let bin = luad_binary_path();
    let root = luad_oracle::find_workspace_root();
    let fixture_54 = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let mut corrupted = std::fs::read(&fixture_54).expect("read fixture");

    // Corrupt an instruction opcode in Lua 5.4 so it fails structural validation
    // Instruction words in Lua 5.4 start at byte 64 in hello.luac
    corrupted[64] = 0x7E; // invalid opcode number 126

    let temp_dir = std::env::temp_dir();
    let temp_file = temp_dir.join("corrupted_lua54.luac");
    std::fs::write(&temp_file, &corrupted).expect("write temp corrupted chunk");

    let cfg_out = Command::new(&bin)
        .args(["cfg", temp_file.to_str().unwrap(), "--proto", "proto:0"])
        .output()
        .expect("run cfg on corrupt input");

    let _ = std::fs::remove_file(&temp_file);

    assert_eq!(
        cfg_out.status.code(),
        Some(1),
        "Corrupt input must exit with code 1 (InvalidInput), not code 4"
    );
    let stderr = String::from_utf8_lossy(&cfg_out.stderr);
    assert!(
        !stderr.contains("ANA-PRECOND-001"),
        "Corrupt input failure must not be attributed to ANA-PRECOND-001"
    );
}
