//! Table-driven CLI conformance test suite over selection, query, xrefs, and exit codes (Gate Q1).

use std::process::Command;

fn get_luad_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut path = std::path::PathBuf::from(manifest_dir);
    path.pop(); // up from crates/luad-oracle
    path.pop(); // up to repo root
    let root = path.clone();
    path.push("target");
    path.push("debug");
    path.push("luad");

    let _ = Command::new("cargo")
        .args(["build", "-p", "luad-cli", "--bin", "luad"])
        .current_dir(&root)
        .output();

    path.to_str().unwrap().to_string()
}

struct CliTestCase {
    name: &'static str,
    args: Vec<String>,
    expected_exit_code: i32,
    stderr_substring: &'static str,
}

#[test]
fn test_table_driven_cli_selection_conformance() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let f = fixture.to_str().unwrap().to_string();

    let test_cases = vec![
        // 1. Query syntax errors -> Exit 2
        CliTestCase {
            name: "query_missing_value_after_contains",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "constant contains".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Missing query value",
        },
        CliTestCase {
            name: "query_missing_value_after_equals",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "opcode ==".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Missing query value",
        },
        CliTestCase {
            name: "query_unknown_field",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "nonexistent_field == \"val\"".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Unknown query field",
        },
        CliTestCase {
            name: "query_invalid_operator_for_field",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "opcode contains \"CALL\"".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Unsupported operator",
        },
        CliTestCase {
            name: "query_unbalanced_parentheses",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "(mnemonic == \"CALL\"".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Unbalanced parentheses",
        },
        CliTestCase {
            name: "query_trailing_tokens",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "mnemonic == \"CALL\" extra_tokens".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Unexpected trailing tokens",
        },
        CliTestCase {
            name: "query_cursor_past_total_matches",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "mnemonic == \"CALL\"".into(),
                "--cursor".into(),
                "9999".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Invalid cursor",
        },
        CliTestCase {
            name: "query_invalid_non_integer_cursor",
            args: vec![
                "query".into(),
                f.clone(),
                "--cursor".into(),
                "not_a_number".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Invalid cursor",
        },
        // 2. Xrefs nonexistent and malformed targets -> Exit 2
        CliTestCase {
            name: "xrefs_nonexistent_to_constant",
            args: vec![
                "xrefs".into(),
                f.clone(),
                "--to".into(),
                "proto:0:k:9999".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "does not exist in chunk",
        },
        CliTestCase {
            name: "xrefs_nonexistent_from_pc",
            args: vec![
                "xrefs".into(),
                f.clone(),
                "--from".into(),
                "proto:0:pc:9999".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "does not exist in chunk",
        },
        CliTestCase {
            name: "xrefs_malformed_stable_id",
            args: vec![
                "xrefs".into(),
                f.clone(),
                "--to".into(),
                "invalid_id_format".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Invalid target ID",
        },
        // 3. Explain nonexistent targets -> Exit 2
        CliTestCase {
            name: "explain_nonexistent_proto",
            args: vec!["explain".into(), f.clone(), "proto:99/99:pc:0".into()],
            expected_exit_code: 2,
            stderr_substring: "not found",
        },
        CliTestCase {
            name: "explain_nonexistent_pc",
            args: vec!["explain".into(), f.clone(), "proto:0:pc:9999".into()],
            expected_exit_code: 2,
            stderr_substring: "not found",
        },
        // 4. CFG nonexistent prototype -> Exit 2
        CliTestCase {
            name: "cfg_nonexistent_proto",
            args: vec![
                "cfg".into(),
                f.clone(),
                "--proto".into(),
                "proto:99/99".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "not found",
        },
        CliTestCase {
            name: "query_foreign_cursor_signature_rejected",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "mnemonic == \"CALL\"".into(),
                "--cursor".into(),
                "cur_00000000_1".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "Invalid cursor",
        },
        CliTestCase {
            name: "xrefs_nonexistent_local_target",
            args: vec![
                "xrefs".into(),
                f.clone(),
                "--to".into(),
                "proto:0:local:9999".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "does not exist in chunk",
        },
        CliTestCase {
            name: "xrefs_nonexistent_upval_target",
            args: vec![
                "xrefs".into(),
                f.clone(),
                "--to".into(),
                "proto:0:upvalue:9999".into(),
            ],
            expected_exit_code: 2,
            stderr_substring: "does not exist in chunk",
        },
        CliTestCase {
            name: "xrefs_valid_chunk_target",
            args: vec!["xrefs".into(), f.clone(), "--to".into(), "chunk".into()],
            expected_exit_code: 0,
            stderr_substring: "",
        },
        CliTestCase {
            name: "xrefs_valid_proto_target",
            args: vec!["xrefs".into(), f.clone(), "--to".into(), "proto:0".into()],
            expected_exit_code: 0,
            stderr_substring: "",
        },
        // 5. Positive cases -> Exit 0
        CliTestCase {
            name: "query_valid_exact_match_success",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "string contains \"Hello\"".into(),
                "--format".into(),
                "json".into(),
            ],
            expected_exit_code: 0,
            stderr_substring: "",
        },
        CliTestCase {
            name: "query_valid_integer_cursor_zero_accepted",
            args: vec![
                "query".into(),
                f.clone(),
                "--where".into(),
                "mnemonic == \"CALL\"".into(),
                "--cursor".into(),
                "0".into(),
                "--format".into(),
                "json".into(),
            ],
            expected_exit_code: 0,
            stderr_substring: "",
        },
    ];

    for tc in &test_cases {
        let output = Command::new(&luad)
            .args(&tc.args)
            .output()
            .unwrap_or_else(|e| panic!("Failed to run test case '{}': {e}", tc.name));

        assert_eq!(
            output.status.code(),
            Some(tc.expected_exit_code),
            "Test case '{}' expected exit code {}, got {:?}. Stderr:\n{}",
            tc.name,
            tc.expected_exit_code,
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );

        if !tc.stderr_substring.is_empty() {
            let stderr_str = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr_str.contains(tc.stderr_substring),
                "Test case '{}' expected stderr to contain '{}', got:\n{}",
                tc.name,
                tc.stderr_substring,
                stderr_str
            );
        }
    }
}

#[test]
fn test_cli_selection_stock_and_lnum32_automatic_and_explicit() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();

    let stock_fixture = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let stock32_fixture = root.join("tests/fixtures/precompiled/lua51_32bit/hello.luac");
    let lnum_fixture = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");

    // 1. Stock 64-bit size_t auto-detection
    let out = Command::new(&luad)
        .args([
            "inspect",
            stock_fixture.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect stock fixture");
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["interpretation"]["base_dialect"], "lua5.1");
    assert_eq!(doc["interpretation"]["profile"], "lua5.1");
    let layout = doc["interpretation"]["validated_layout"].as_str().unwrap();
    assert!(
        layout.contains("sizet=8"),
        "Stock layout must have sizet=8: {layout}"
    );

    // 2. Stock 32-bit size_t auto-detection
    let out = Command::new(&luad)
        .args([
            "inspect",
            stock32_fixture.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect stock 32-bit fixture");
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["interpretation"]["base_dialect"], "lua5.1");
    let layout = doc["interpretation"]["validated_layout"].as_str().unwrap();
    assert!(
        layout.contains("sizet=4"),
        "Stock 32-bit layout must have sizet=4: {layout}"
    );

    // 3. LNUM32 auto-detection
    let out = Command::new(&luad)
        .args([
            "inspect",
            lnum_fixture.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect lnum32 fixture");
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["interpretation"]["base_dialect"], "lua5.1");
    assert_eq!(doc["interpretation"]["profile"], "lua5.1-lnum32");
    let layout = doc["interpretation"]["validated_layout"].as_str().unwrap();
    assert!(
        layout.contains("integral_flag=4"),
        "LNUM32 layout must have integral_flag=4: {layout}"
    );

    // 4. Explicit dialect selection (-d lua5.1-lnum32)
    let out = Command::new(&luad)
        .args([
            "inspect",
            lnum_fixture.to_str().unwrap(),
            "-d",
            "lua5.1-lnum32",
            "--format",
            "json",
        ])
        .output()
        .expect("inspect lnum32 explicit");
    assert_eq!(out.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["interpretation"]["profile"], "lua5.1-lnum32");

    // 5. Dialect mismatch rejection: forcing -d lua5.1 on LNUM32 fixture fails with error exit
    let out = Command::new(&luad)
        .args([
            "inspect",
            lnum_fixture.to_str().unwrap(),
            "-d",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .expect("inspect mismatch");
    assert_ne!(out.status.code(), Some(0));
}

#[test]
fn test_cli_query_cursor_offset_tampering_and_integer_contract() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let f = fixture.to_str().unwrap();

    // Query full results to get exact total_matches count
    let full_out = Command::new(&luad)
        .args(["query", f, "--format", "json"])
        .output()
        .expect("full query failed");
    assert_eq!(full_out.status.code(), Some(0));
    let full_doc: serde_json::Value = serde_json::from_slice(&full_out.stdout).unwrap();
    let total_matches = full_doc["data"]["count"].as_u64().unwrap() as usize;

    // 1. Get initial page with limit 1
    let page1_output = Command::new(&luad)
        .args(["query", f, "--limit", "1", "--format", "json"])
        .output()
        .expect("page1 query failed");
    assert_eq!(page1_output.status.code(), Some(0));
    let doc: serde_json::Value = serde_json::from_slice(&page1_output.stdout).unwrap();
    let next_cursor = doc["data"]["next_cursor"]
        .as_str()
        .expect("next_cursor must be present");

    // 2. Fetch page 2 using valid continuation cursor
    let page2_output = Command::new(&luad)
        .args([
            "query",
            f,
            "--limit",
            "1",
            "--cursor",
            next_cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("page2 query failed");
    assert_eq!(page2_output.status.code(), Some(0));

    // 3. Tamper with the cursor offset (e.g. replace offset with 99) -> must fail closed (Exit 2)
    let parts: Vec<&str> = next_cursor.split('_').collect();
    assert_eq!(parts.len(), 3, "Cursor format cur_<sig>_<offset>");
    let tampered_cursor = format!("{}_{}_{}", parts[0], parts[1], 99);
    let tampered_output = Command::new(&luad)
        .args([
            "query",
            f,
            "--limit",
            "1",
            "--cursor",
            &tampered_cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("tampered cursor query");
    assert_eq!(tampered_output.status.code(), Some(2));

    // 4. Exact end cursor must return empty page (Exit 0, count: 0, is_truncated: false)
    let end_cursor = format!("{total_matches}");
    let end_output = Command::new(&luad)
        .args([
            "query",
            f,
            "--limit",
            "5",
            "--cursor",
            &end_cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("end cursor query");
    assert_eq!(end_output.status.code(), Some(0));
    let end_doc: serde_json::Value = serde_json::from_slice(&end_output.stdout).unwrap();
    assert_eq!(end_doc["data"]["count"], 0);
    assert_eq!(end_doc["data"]["is_truncated"], false);
    assert_eq!(end_doc["data"]["next_cursor"], serde_json::Value::Null);

    // 5. Cursor past total matches fails (Exit 2)
    let oob_cursor = format!("{}", total_matches + 1);
    let oob_output = Command::new(&luad)
        .args([
            "query",
            f,
            "--limit",
            "5",
            "--cursor",
            &oob_cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("oob cursor query");
    assert_eq!(oob_output.status.code(), Some(2));
}
