//! Deterministic firmware-scale batch export tests (Gate W1 / gate-batch-export).

use sha2::{Digest, Sha256};
use std::process::Command;

use luad_core::envelope::{JsonlDataRecord, JSONL_SCHEMA_VERSION};

fn get_luad_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut path = std::path::PathBuf::from(manifest_dir);
    path.pop();
    path.pop();
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

#[test]
fn test_batch_export_deterministic_hash_on_mixed_fixtures() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();

    let files = [
        root.join("tests/fixtures/precompiled/lua54/hello.luac"),
        root.join("tests/fixtures/precompiled/lua51/hello.luac"),
        root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac"),
        root.join("tests/fixtures/precompiled/lua54/closures_stripped.luac"),
    ];

    let mut cmd_args = vec![
        "export".to_string(),
        "--format".to_string(),
        "jsonl".to_string(),
    ];
    for f in &files {
        cmd_args.push(f.to_str().unwrap().to_string());
    }

    let run1 = Command::new(&luad)
        .args(&cmd_args)
        .output()
        .expect("luad export run 1 failed");
    assert_eq!(run1.status.code(), Some(0));

    let run2 = Command::new(&luad)
        .args(&cmd_args)
        .output()
        .expect("luad export run 2 failed");
    assert_eq!(run2.status.code(), Some(0));

    let hash1 = hex::encode(Sha256::digest(&run1.stdout));
    let hash2 = hex::encode(Sha256::digest(&run2.stdout));

    assert_eq!(
        hash1, hash2,
        "Repeated batch export over identical inputs must be byte-for-byte deterministic"
    );
    assert_eq!(run1.stdout, run2.stdout);
}

#[test]
fn test_batch_export_jsonl_record_structure_and_discriminators() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let file = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["export", file.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("luad export failed");

    assert_eq!(output.status.code(), Some(0));
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    assert!(
        lines.len() >= 4,
        "Export stream must have start, file_start, facts, file_end, export_end"
    );

    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["record_type"], "export_start");
    assert_eq!(first["schema_version"], JSONL_SCHEMA_VERSION);

    let second: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(second["record_type"], "file_start");
    assert!(second.get("sha256").is_some());
    assert!(second.get("interpretation").is_some());

    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["record_type"], "export_end");
    assert_eq!(last["files_processed"], 1);
    assert_eq!(last["files_succeeded"], 1);

    for (i, line) in lines.iter().enumerate() {
        let val: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("Line {i} is invalid JSON: {e}"));
        assert!(
            val.get("record_type").is_some(),
            "Line {i} missing record_type discriminator: '{line}'"
        );
    }
}

#[test]
fn test_batch_export_mixed_valid_and_failing_files() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();

    let valid_file = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let non_existent = root.join("non_existent_file_path_12345.luac");

    let output = Command::new(&luad)
        .args([
            "export",
            valid_file.to_str().unwrap(),
            non_existent.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("luad export failed");

    // Aggregate exit must be nonzero when any file fails
    assert_ne!(
        output.status.code(),
        Some(0),
        "Batch export must exit nonzero when at least one input fails"
    );

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    // Check that we got an export_end record with files_failed = 1 and files_succeeded = 1
    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["record_type"], "export_end");
    assert_eq!(last["files_processed"], 2);
    assert_eq!(last["files_succeeded"], 1);
    assert_eq!(last["files_failed"], 1);
}

#[test]
fn test_batch_export_input_list_file_and_stdin() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();

    let f1 = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let f2 = root.join("tests/fixtures/precompiled/lua51/hello.luac");

    let temp_dir = tempfile::tempdir().unwrap();
    let list_file = temp_dir.path().join("inputs.txt");
    let list_content = format!("{}\n{}\n", f1.display(), f2.display());
    std::fs::write(&list_file, &list_content).unwrap();

    // 1. Test --input-list FILE
    let out_file = Command::new(&luad)
        .args([
            "export",
            "--input-list",
            list_file.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("export --input-list FILE");
    assert_eq!(out_file.status.code(), Some(0));

    // 2. Test --input-list - (stdin)
    use std::io::Write;
    let mut child = Command::new(&luad)
        .args(["export", "--input-list", "-", "--format", "jsonl"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn export with stdin");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(list_content.as_bytes())
        .unwrap();
    let out_stdin = child.wait_with_output().unwrap();
    assert_eq!(out_stdin.status.code(), Some(0));

    assert_eq!(
        out_file.stdout, out_stdin.stdout,
        "--input-list FILE and --input-list - must produce identical outputs"
    );
}

#[test]
fn test_batch_export_duplicate_inputs_processed_deterministically() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let f1 = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let out = Command::new(&luad)
        .args([
            "export",
            f1.to_str().unwrap(),
            f1.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("export duplicates");
    assert_eq!(out.status.code(), Some(0));

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["record_type"], "export_end");
    assert_eq!(last["files_processed"], 2);
    assert_eq!(last["files_succeeded"], 2);
}

#[test]
fn test_batch_export_plain_lua_source_produces_explicit_unsupported_diagnostic() {
    let luad = get_luad_bin();
    let temp_dir = tempfile::tempdir().unwrap();
    let source_file = temp_dir.path().join("script.lua");
    std::fs::write(&source_file, "-- plain lua script\nprint('hello')\n").unwrap();

    let out = Command::new(&luad)
        .args(["export", source_file.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("export source file");

    assert_ne!(out.status.code(), Some(0));
    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    let has_source_diag = lines.iter().any(|l| {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(l) {
            v["record_type"] == "diagnostic"
                && v["data"]["code"].as_str() == Some("PARSE-SOURCE-001")
        } else {
            false
        }
    });
    assert!(
        has_source_diag,
        "Export of plain Lua source must emit PARSE-SOURCE-001 diagnostic record"
    );
}

#[test]
fn test_batch_export_emits_recursive_facts_and_xrefs_for_closures() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let file = root.join("tests/fixtures/precompiled/lua51/closures.luac");

    let out = Command::new(&luad)
        .args(["export", file.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("export closures");
    assert_eq!(out.status.code(), Some(0));

    let stdout_str = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();

    let mut protos = 0;
    let mut instructions = 0;
    let mut upvalues = 0;
    let mut xrefs = 0;

    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        match v["record_type"].as_str() {
            Some("prototype") => protos += 1,
            Some("instruction") => instructions += 1,
            Some("upvalue") => upvalues += 1,
            Some("xref") => xrefs += 1,
            _ => {}
        }
    }

    assert!(protos >= 4, "closures.luac has 4 prototypes, got {protos}");
    assert!(instructions > 0, "must emit instructions");
    assert!(upvalues > 0, "must emit upvalues");
    assert!(xrefs > 0, "must emit xrefs");
}

#[test]
fn test_batch_export_facts_remain_attributable_after_control_records_are_removed() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let stock = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let lnum = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");
    let output = Command::new(&luad)
        .args([
            "export",
            stock.to_str().unwrap(),
            lnum.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("mixed-profile export");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let facts: Vec<JsonlDataRecord<serde_json::Value>> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| {
            matches!(
                record["record_type"].as_str(),
                Some("prototype" | "instruction" | "constant" | "upvalue" | "xref" | "diagnostic")
            )
        })
        .map(|record| serde_json::from_value(record).expect("export fact context"))
        .collect();
    assert!(!facts.is_empty());

    let mut saw_stock = false;
    let mut saw_lnum = false;
    for fact in facts {
        let identity = fact
            .context
            .input_identity
            .expect("successful fact identity");
        let interpretation = fact
            .context
            .interpretation
            .expect("successful interpretation");
        assert_eq!(
            identity.byte_length,
            std::fs::metadata(&identity.path).unwrap().len() as usize
        );
        assert_eq!(
            identity.sha256,
            hex::encode(Sha256::digest(std::fs::read(&identity.path).unwrap()))
        );
        match identity.path.as_str() {
            path if path == stock.to_str().unwrap() => {
                saw_stock = true;
                assert_eq!(interpretation.profile, "lua5.1");
            }
            path if path == lnum.to_str().unwrap() => {
                saw_lnum = true;
                assert_eq!(interpretation.profile, "lua5.1-lnum32");
            }
            path => panic!("unexpected fact input: {path}"),
        }
    }
    assert!(saw_stock && saw_lnum);
}

#[test]
fn test_batch_export_failure_diagnostics_report_only_available_context() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let unreadable = root.join("missing-stream-context-fixture.luac");
    let temp_dir = tempfile::tempdir().unwrap();
    let source = temp_dir.path().join("source.lua");
    std::fs::write(&source, "print('source')\n").unwrap();

    let output = Command::new(&luad)
        .args([
            "export",
            source.to_str().unwrap(),
            unreadable.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("failure export");
    assert_ne!(output.status.code(), Some(0));

    let diagnostics: Vec<JsonlDataRecord<serde_json::Value>> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .filter(|record| record["record_type"] == "diagnostic")
        .map(|record| serde_json::from_value(record).expect("diagnostic context"))
        .collect();
    assert_eq!(diagnostics.len(), 2);

    let parse = diagnostics
        .iter()
        .find(|record| record.data["code"] == "PARSE-SOURCE-001")
        .unwrap();
    let parse_identity = parse
        .context
        .input_identity
        .as_ref()
        .expect("read bytes identity");
    assert_eq!(parse_identity.path, source.to_str().unwrap());
    assert_eq!(
        parse_identity.byte_length,
        std::fs::read(&source).unwrap().len()
    );
    assert!(parse.context.interpretation.is_none());

    let read = diagnostics
        .iter()
        .find(|record| record.data["code"] == "IO-001")
        .unwrap();
    assert!(read.context.input_identity.is_none());
    assert!(read.context.interpretation.is_none());
}
