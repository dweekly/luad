//! End-to-end CLI command and exit code verification test suite.

use std::process::Command;
use luad_oracle::{compile_source_lua54, find_luac54};

fn get_luad_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut path = std::path::PathBuf::from(manifest_dir);
    path.pop(); // up from crates/luad-oracle
    path.pop(); // up to repo root
    path.push("target");
    path.push("debug");
    path.push("luad");
    path.to_str().unwrap().to_string()
}


#[test]
fn test_cli_capabilities() {
    let luad = get_luad_bin();
    let output = Command::new(&luad)
        .arg("capabilities")
        .output()
        .expect("luad capabilities must run");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("lua5.5"));
    assert!(stdout.contains("lua5.4"));
    assert!(stdout.contains("lua5.3"));
    assert!(stdout.contains("lua5.2"));
    assert!(stdout.contains("lua5.1"));
}

#[test]
fn test_cli_schema_export() {
    let luad = get_luad_bin();
    for schema_name in &["chunk", "diagnostic", "instruction", "cfg", "xrefs", "query", "diff"] {
        let output = Command::new(&luad)
            .args(["schema", schema_name, "--schema-version", "1"])
            .output()
            .expect("luad schema must run");

        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: serde_json::Value = serde_json::from_str(&stdout)
            .expect("Schema output must be valid JSON");
        assert!(parsed.get("$schema").is_some() || parsed.get("title").is_some());
    }

    // Invalid schema version -> Exit code 2 (UsageError)
    let bad_version = Command::new(&luad)
        .args(["schema", "chunk", "--schema-version", "99"])
        .output()
        .expect("luad schema must run");
    assert_eq!(bad_version.status.code(), Some(2));
}

#[test]
fn test_cli_completions() {
    let luad = get_luad_bin();
    for shell in &["bash", "zsh", "fish"] {
        let output = Command::new(&luad)
            .args(["completions", shell])
            .output()
            .expect("luad completions must run");

        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.is_empty());
        assert!(stdout.contains("luad"));
    }
}

#[test]
fn test_cli_exit_codes_contract() {
    let luad = get_luad_bin();

    // 1. Missing file -> Exit code 3 (IoError)
    let missing = Command::new(&luad)
        .args(["inspect", "non_existent_file_12345.luac"])
        .output()
        .expect("luad inspect must run");
    assert_eq!(missing.status.code(), Some(3));

    // 2. Corrupt / invalid non-Lua file -> Exit code 4 (UnsupportedFormat)
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), b"NOT_A_LUA_CHUNK").unwrap();
    let unsupported = Command::new(&luad)
        .args(["inspect", temp_file.path().to_str().unwrap()])
        .output()
        .expect("luad inspect must run");
    assert_eq!(unsupported.status.code(), Some(4));
}

#[test]
fn test_cli_inspect_and_disasm() {
    if find_luac54().is_none() {
        return;
    }

    let luad = get_luad_bin();
    let bytes = compile_source_lua54("local x = 10; return x * 2", false).unwrap();
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &bytes).unwrap();
    let path = temp_file.path().to_str().unwrap();

    // Inspect JSON
    let inspect_out = Command::new(&luad)
        .args(["inspect", "--format", "json", path])
        .output()
        .unwrap();
    assert_eq!(inspect_out.status.code(), Some(0));
    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert_eq!(inspect_json["dialect"], "lua5.4");
    assert_eq!(inspect_json["verdict"], "valid-for-parser");

    // Disasm Text
    let disasm_out = Command::new(&luad)
        .args(["disasm", "--effects", path])
        .output()
        .unwrap();
    assert_eq!(disasm_out.status.code(), Some(0));
    let disasm_text = String::from_utf8_lossy(&disasm_out.stdout);
    assert!(disasm_text.contains("LOADI") || disasm_text.contains("MOVE"));

    // Explain
    let explain_out = Command::new(&luad)
        .args(["explain", path, "proto:0:pc:0"])
        .output()
        .unwrap();
    assert_eq!(explain_out.status.code(), Some(0));
    let explain_text = String::from_utf8_lossy(&explain_out.stdout);
    assert!(explain_text.contains("Instruction Explanation"));

    // CFG DOT
    let cfg_out = Command::new(&luad)
        .args(["cfg", "--proto", "proto:0", "--format", "dot", path])
        .output()
        .unwrap();
    assert_eq!(cfg_out.status.code(), Some(0));
    let dot_text = String::from_utf8_lossy(&cfg_out.stdout);
    assert!(dot_text.starts_with("digraph"));

    // Query
    let query_out = Command::new(&luad)
        .args(["query", "--format", "json", path])
        .output()
        .unwrap();
    assert_eq!(query_out.status.code(), Some(0));
    let query_json: serde_json::Value = serde_json::from_slice(&query_out.stdout).unwrap();
    assert!(query_json["count"].as_u64().unwrap() > 0);
}
