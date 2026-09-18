//! Integration tests for corpus-wide `query --input-list` (R-4).

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

fn fixture_dir() -> std::path::PathBuf {
    luad_oracle::find_workspace_root().join("tests/fixtures/firmware_tree")
}

fn parse_jsonl(output: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(output.to_vec())
        .expect("query stdout is UTF-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("query line is JSON"))
        .collect()
}

#[test]
fn test_batch_query_file_list_preserves_order_and_duplicates() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let file1 = fdir.join("system_service.luac");
    let file2 = fdir.join("dispatcher.lua");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("inputs.txt");
    let list_content = format!(
        "{}\n{}\n{}\n",
        file1.display(),
        file2.display(),
        file1.display()
    );
    fs::write(&list_path, list_content).expect("write input list");

    let output = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--where",
            "opcode == \"OP_MOVE\"",
        ])
        .output()
        .expect("run batch query");

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let records = parse_jsonl(&output.stdout);
    assert!(!records.is_empty(), "records must not be empty");

    // First record: query_start
    let start = &records[0];
    assert_eq!(start["record_type"], "query_start");
    assert_eq!(start["schema_version"], 2);
    assert_eq!(start["total_files"], 3);
    assert_eq!(start["where"], "opcode == \"OP_MOVE\"");

    // Last record: query_end
    let end = records.last().unwrap();
    assert_eq!(end["record_type"], "query_end");
    assert_eq!(end["files_processed"], 3);
    assert_eq!(end["files_succeeded"], 3);
    assert_eq!(end["files_skipped"], 0);
    assert_eq!(end["files_failed"], 0);

    // Verify file_start order matches input list exactly (including duplicate)
    let file_starts: Vec<&str> = records
        .iter()
        .filter(|r| r["record_type"] == "file_start")
        .map(|r| r["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        file_starts,
        vec![
            file1.to_str().unwrap(),
            file2.to_str().unwrap(),
            file1.to_str().unwrap()
        ]
    );

    // Verify file_end order and status
    let file_ends: Vec<(&str, &str)> = records
        .iter()
        .filter(|r| r["record_type"] == "file_end")
        .map(|r| (r["path"].as_str().unwrap(), r["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        file_ends,
        vec![
            (file1.to_str().unwrap(), "succeeded"),
            (file2.to_str().unwrap(), "succeeded"),
            (file1.to_str().unwrap(), "succeeded"),
        ]
    );

    // Stderr summary check
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr_str.contains("3 queried, 0 skipped, 0 failed"),
        "stderr summary: {stderr_str}"
    );
}

#[test]
fn test_batch_query_stdin_input_list() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let file1 = fdir.join("system_service.luac");

    let mut child = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            "-",
            "--where",
            "opcode == \"OP_LOADK\"",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn luad");

    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        writeln!(stdin, "{}", file1.display()).expect("write stdin");
    }

    let output = child.wait_with_output().expect("wait for output");
    assert_eq!(output.status.code(), Some(0));

    let records = parse_jsonl(&output.stdout);
    assert_eq!(records[0]["record_type"], "query_start");
    assert_eq!(records[0]["total_files"], 1);
    assert_eq!(records.last().unwrap()["record_type"], "query_end");
    assert_eq!(records.last().unwrap()["files_succeeded"], 1);
}

#[test]
fn test_batch_query_mixed_outcomes_no_false_zero_matches() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let succeeded_file = fdir.join("system_service.luac");
    let source_file = fdir.join("network_setup.lua");
    let corrupt_file = fdir.join("corrupted_module.luac");
    let missing_file = fdir.join("nonexistent_path.luac");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("mixed_inputs.txt");
    let list_content = format!(
        "{}\n{}\n{}\n{}\n",
        succeeded_file.display(),
        source_file.display(),
        corrupt_file.display(),
        missing_file.display()
    );
    fs::write(&list_path, list_content).expect("write mixed list");

    let output = Command::new(&luad)
        .args(["query", "--input-list", list_path.to_str().unwrap()])
        .output()
        .expect("run mixed batch query");

    // In default mode, at least one success -> exit code 0
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let records = parse_jsonl(&output.stdout);

    // End record verifies aggregate numbers
    let end_rec = records.last().expect("query_end record");
    assert_eq!(end_rec["record_type"], "query_end");
    assert_eq!(end_rec["files_processed"], 4);
    assert_eq!(end_rec["files_succeeded"], 1);
    assert_eq!(end_rec["files_skipped"], 2);
    assert_eq!(end_rec["files_failed"], 1);

    // Find file_end for each file
    let file_ends: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["record_type"] == "file_end")
        .collect();
    assert_eq!(file_ends.len(), 4);

    let succeeded_end = file_ends
        .iter()
        .find(|r| r["path"] == succeeded_file.to_str().unwrap())
        .unwrap();
    assert_eq!(succeeded_end["status"], "succeeded");
    assert!(succeeded_end["error"].is_null());

    let source_end = file_ends
        .iter()
        .find(|r| r["path"] == source_file.to_str().unwrap())
        .unwrap();
    assert_eq!(source_end["status"], "skipped");
    assert!(source_end["error"]
        .as_str()
        .unwrap()
        .contains("source text is unsupported"));

    let corrupt_end = file_ends
        .iter()
        .find(|r| r["path"] == corrupt_file.to_str().unwrap())
        .unwrap();
    assert_eq!(corrupt_end["status"], "skipped");
    assert!(corrupt_end["error"].is_string());

    let missing_end = file_ends
        .iter()
        .find(|r| r["path"] == missing_file.to_str().unwrap())
        .unwrap();
    assert_eq!(missing_end["status"], "failed");
    assert!(missing_end["error"]
        .as_str()
        .unwrap()
        .contains("Failed to read input file"));

    // Verify diagnostics were emitted for skipped and failed files
    let diags: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["record_type"] == "diagnostic")
        .collect();
    assert!(
        diags
            .iter()
            .any(|d| d["data"]["code"] == "PARSE-SOURCE-001"),
        "must emit PARSE-SOURCE-001 for source text"
    );
    assert!(
        diags.iter().any(|d| d["data"]["code"] == "PARSE-001"),
        "must emit PARSE-001 for corrupted bytecode"
    );
    assert!(
        diags.iter().any(|d| d["data"]["code"] == "IO-001"),
        "must emit IO-001 for missing file"
    );

    // Verify stderr summary
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr_str.contains("1 queried, 2 skipped, 1 failed"),
        "stderr summary mismatch: {stderr_str}"
    );
}

#[test]
fn test_batch_query_strict_mode() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let succeeded_file = fdir.join("system_service.luac");
    let corrupt_file = fdir.join("corrupted_module.luac");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("strict_inputs.txt");
    fs::write(
        &list_path,
        format!("{}\n{}\n", succeeded_file.display(), corrupt_file.display()),
    )
    .expect("write strict list");

    // With --strict, any skipped/failed file yields exit code 1
    let output = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--strict",
        ])
        .output()
        .expect("run strict query");

    assert_eq!(output.status.code(), Some(1));
    let records = parse_jsonl(&output.stdout);
    assert_eq!(records.last().unwrap()["record_type"], "query_end");
    assert_eq!(records.last().unwrap()["files_succeeded"], 1);
    assert_eq!(records.last().unwrap()["files_skipped"], 1);
}

#[test]
fn test_batch_query_all_failures_returns_error_even_without_strict() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let corrupt_file = fdir.join("corrupted_module.luac");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("all_fail.txt");
    fs::write(&list_path, format!("{}\n", corrupt_file.display())).expect("write list");

    let output = Command::new(&luad)
        .args(["query", "--input-list", list_path.to_str().unwrap()])
        .output()
        .expect("run query");

    // 0 succeeded -> exit code 1
    assert_eq!(output.status.code(), Some(1));
    let records = parse_jsonl(&output.stdout);
    assert_eq!(records.last().unwrap()["files_succeeded"], 0);
    assert_eq!(records.last().unwrap()["files_skipped"], 1);
}

#[test]
fn test_batch_query_limit_truncation() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let file = fdir.join("system_service.luac");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("limit_input.txt");
    fs::write(&list_path, format!("{}\n", file.display())).expect("write list");

    let output = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--where",
            "mnemonic != \"\"",
            "--limit",
            "1",
        ])
        .output()
        .expect("run limit query");

    assert_eq!(output.status.code(), Some(0));
    let records = parse_jsonl(&output.stdout);

    let matches: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["record_type"] == "query_match")
        .collect();
    assert_eq!(matches.len(), 1, "exactly 1 match must be emitted");

    let file_end = records
        .iter()
        .find(|r| r["record_type"] == "file_end")
        .unwrap();
    assert_eq!(file_end["is_truncated"], true);
    assert_eq!(file_end["emitted_fact_count"], 1);
    assert!(
        file_end["available_fact_count"].as_u64().unwrap() > 1,
        "available facts must exceed 1"
    );
}

#[test]
fn test_batch_query_malformed_predicate_fails_closed() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let file = fdir.join("system_service.luac");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("malformed_predicate.txt");
    fs::write(&list_path, format!("{}\n", file.display())).expect("write list");

    let output = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--where",
            "invalid === syntax == error",
        ])
        .output()
        .expect("run bad predicate query");

    assert_eq!(
        output.status.code(),
        Some(2),
        "must fail with ExitCode::UsageError"
    );
    assert!(output.stdout.is_empty(), "stdout must be completely empty");
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr_str.contains("Query error"),
        "stderr must report query syntax error"
    );
}

#[test]
fn test_batch_query_argument_validation() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let file = fdir.join("system_service.luac");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("validation.txt");
    fs::write(&list_path, format!("{}\n", file.display())).expect("write list");

    // Both file and --input-list
    let output = Command::new(&luad)
        .args([
            "query",
            file.to_str().unwrap(),
            "--input-list",
            list_path.to_str().unwrap(),
        ])
        .output()
        .expect("run query");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    // Neither file nor --input-list
    let output = Command::new(&luad)
        .args(["query"])
        .output()
        .expect("run query");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    // --cursor with --input-list
    let output = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--cursor",
            "cur_test_0",
        ])
        .output()
        .expect("run query");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    // --format text with --input-list
    let output = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--format",
            "text",
        ])
        .output()
        .expect("run query");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());

    // --format json with --input-list
    let output = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("run query");
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn test_batch_query_equivalence_with_export() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let file = fdir.join("system_service.luac");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let list_path = temp_dir.path().join("equiv.txt");
    fs::write(&list_path, format!("{}\n", file.display())).expect("write list");

    // 1. Run query for OP_MOVE
    let query_out = Command::new(&luad)
        .args([
            "query",
            "--input-list",
            list_path.to_str().unwrap(),
            "--where",
            "opcode == \"OP_MOVE\"",
        ])
        .output()
        .expect("run query");
    assert_eq!(query_out.status.code(), Some(0));
    let query_records = parse_jsonl(&query_out.stdout);
    let query_moves: Vec<&str> = query_records
        .iter()
        .filter(|r| r["record_type"] == "query_match" && r["data"]["kind"] == "instruction")
        .map(|r| r["data"]["id"].as_str().unwrap())
        .collect();

    // 2. Run export for instructions
    let export_out = Command::new(&luad)
        .args([
            "export",
            file.to_str().unwrap(),
            "--format",
            "jsonl",
            "--facts",
            "instruction",
        ])
        .output()
        .expect("run export");
    assert_eq!(export_out.status.code(), Some(0));
    let export_records = parse_jsonl(&export_out.stdout);
    let export_moves: Vec<&str> = export_records
        .iter()
        .filter(|r| r["record_type"] == "instruction" && r["data"]["mnemonic"] == "MOVE")
        .map(|r| r["data"]["id"].as_str().unwrap())
        .collect();

    assert!(
        !query_moves.is_empty(),
        "fixture system_service.luac must have OP_MOVE instructions"
    );
    assert_eq!(
        query_moves, export_moves,
        "query matches for OP_MOVE must match export instruction facts 1-to-1"
    );
}
