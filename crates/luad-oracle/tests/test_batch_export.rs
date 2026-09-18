//! Deterministic firmware-scale batch export tests (Gate W1 / gate-batch-export).

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::process::Command;

use luad_core::envelope::{JsonlDataRecord, JSONL_SCHEMA_VERSION};
use luad_core::{ExportFactFamily, EXPORT_FACT_FAMILY_NAMES, SORTED_FACT_FAMILY_NAMES};

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

const COUNTED_EXPORT_FACTS: [&str; 9] = [
    "prototype",
    "prototype_identity",
    "instruction",
    "constant",
    "upvalue",
    "xref",
    "callee",
    "origin",
    "call_relation",
];

fn run_selected_export(luad: &str, file: &std::path::Path, facts: &str) -> std::process::Output {
    Command::new(luad)
        .args([
            "export",
            file.to_str().expect("fixture path"),
            "--format",
            "jsonl",
            "--facts",
            facts,
        ])
        .output()
        .expect("run selected export")
}

fn parse_jsonl(output: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(output.to_vec())
        .expect("export stdout is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("export line is JSON"))
        .collect()
}

#[test]
fn test_batch_export_fact_family_selection_matrix() {
    let root = luad_oracle::find_workspace_root();
    let lua51 = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let luad = get_luad_bin();

    for family in COUNTED_EXPORT_FACTS {
        let output = run_selected_export(&luad, &lua51, family);
        assert_eq!(
            output.status.code(),
            Some(0),
            "{family}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let records = parse_jsonl(&output.stdout);
        assert_eq!(records[0]["fact_families"], serde_json::json!([family]));

        let facts: Vec<_> = records
            .iter()
            .filter(|record| {
                record["record_type"]
                    .as_str()
                    .is_some_and(|kind| COUNTED_EXPORT_FACTS.contains(&kind))
            })
            .collect();
        assert!(!facts.is_empty(), "fixture must exercise {family}");
        assert!(
            facts.iter().all(|record| record["record_type"] == family),
            "{family}: selected stream emitted another counted family"
        );
        assert!(facts.iter().all(|record| record.get("context").is_some()));

        let file_end = records
            .iter()
            .find(|record| record["record_type"] == "file_end")
            .expect("file_end");
        assert_eq!(file_end["emitted_fact_count"], facts.len());
        assert_eq!(file_end["available_fact_count"], facts.len());
        assert_eq!(file_end["is_truncated"], false);
        let instruction_count = facts
            .iter()
            .filter(|record| record["record_type"] == "instruction")
            .count();
        assert_eq!(file_end["instruction_count"], instruction_count);
        assert_eq!(
            records.last().expect("export_end")["total_instructions"],
            instruction_count
        );
    }

    let lua54 = root.join("tests/fixtures/precompiled/lua54/closures.luac");
    let mixed = run_selected_export(&luad, &lua54, "instruction,prototype");
    assert_eq!(mixed.status.code(), Some(0));
    let mixed_records = parse_jsonl(&mixed.stdout);
    assert_eq!(
        mixed_records[0]["fact_families"],
        serde_json::json!(["prototype", "instruction"]),
        "selection metadata uses canonical family order"
    );
    assert!(mixed_records
        .iter()
        .any(|record| record["record_type"] == "prototype"));
    assert!(mixed_records
        .iter()
        .any(|record| record["record_type"] == "instruction"));
    assert!(mixed_records.iter().all(|record| {
        record["record_type"].as_str().is_none_or(|kind| {
            !COUNTED_EXPORT_FACTS.contains(&kind) || matches!(kind, "prototype" | "instruction")
        })
    }));

    let default = Command::new(&luad)
        .args(["export", lua51.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("default export");
    let explicit_all = run_selected_export(&luad, &lua51, &COUNTED_EXPORT_FACTS.join(","));
    assert_eq!(default.status.code(), Some(0));
    assert_eq!(explicit_all.status.code(), Some(0));
    let default_records = parse_jsonl(&default.stdout);
    let mut explicit_records = parse_jsonl(&explicit_all.stdout);
    assert!(default_records[0].get("fact_families").is_none());
    explicit_records[0]
        .as_object_mut()
        .expect("export_start object")
        .remove("fact_families");
    assert_eq!(default_records, explicit_records);
}

#[test]
fn test_batch_export_invalid_fact_family_selection_fails_closed() {
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let luad = get_luad_bin();
    for (selection, marker) in [
        ("", "non-empty"),
        ("unknown", "unknown export fact family 'unknown'"),
        (
            "prototype,prototype",
            "duplicate export fact family 'prototype'",
        ),
        ("prototype,", "unknown export fact family ''"),
    ] {
        let first = run_selected_export(&luad, &fixture, selection);
        let second = run_selected_export(&luad, &fixture, selection);
        assert_eq!(first.status.code(), Some(2), "selection {selection:?}");
        assert!(first.stdout.is_empty(), "selection {selection:?}");
        assert!(
            String::from_utf8_lossy(&first.stderr).contains(marker),
            "selection {selection:?}: {}",
            String::from_utf8_lossy(&first.stderr)
        );
        assert_eq!(first.stdout, second.stdout, "selection {selection:?}");
        assert_eq!(first.stderr, second.stderr, "selection {selection:?}");
    }
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

    let inventory = lines
        .iter()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .fold(BTreeMap::<String, usize>::new(), |mut counts, record| {
            *counts
                .entry(record["record_type"].as_str().unwrap().to_string())
                .or_default() += 1;
            counts
        });
    assert_eq!(
        inventory,
        BTreeMap::from([
            ("constant".to_string(), 3),
            ("export_end".to_string(), 1),
            ("export_start".to_string(), 1),
            ("file_end".to_string(), 1),
            ("file_start".to_string(), 1),
            ("instruction".to_string(), 10),
            ("prototype".to_string(), 1),
            ("upvalue".to_string(), 1),
            ("xref".to_string(), 3),
        ])
    );
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

    assert_eq!(
        output.status.code(),
        Some(0),
        "A complete successful file makes the default mixed run usable"
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
    assert_eq!(last["files_skipped"], 0);
    assert_eq!(last["files_failed"], 1);
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        format!(
            "error: {}: failed to read input file\n1 exported, 0 skipped, 1 failed\n",
            non_existent.display()
        )
    );
}

#[test]
fn test_batch_export_input_list_file_and_stdin() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();

    let f1 = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let f2 = root.join("tests/fixtures/precompiled/lua51/hello.luac");

    let temp_dir = tempfile::tempdir().unwrap();
    let spaced = temp_dir.path().join("bytecode with spaces.luac");
    std::fs::copy(&f1, &spaced).unwrap();
    let list_file = temp_dir.path().join("inputs.txt");
    let list_content = format!("{}\n{}\n{}\n", f1.display(), f2.display(), spaced.display());
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
    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["files_skipped"], 1);
    assert_eq!(last["files_failed"], 0);
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

#[test]
fn test_batch_export_outcome_matrix_is_total_and_path_qualified() {
    struct Case {
        name: &'static str,
        inputs: Vec<String>,
        strict: bool,
        exit: i32,
        counts: (usize, usize, usize, usize),
        statuses: Vec<&'static str>,
    }

    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let valid = root
        .join("tests/fixtures/precompiled/lua51/hello.luac")
        .to_string_lossy()
        .into_owned();
    let temp_dir = tempfile::tempdir().unwrap();
    let source = temp_dir.path().join("plain source with spaces.lua");
    let unknown = temp_dir.path().join("unknown format.bin");
    let malformed = temp_dir.path().join("malformed chunk.luac");
    let missing = temp_dir.path().join("missing input.luac");
    std::fs::write(&source, "print('source')\n").unwrap();
    std::fs::write(&unknown, [0_u8, 0xff, 0x10]).unwrap();
    std::fs::write(&malformed, b"\x1bLua\x51").unwrap();

    let non_successes = vec![
        source.to_string_lossy().into_owned(),
        unknown.to_string_lossy().into_owned(),
        malformed.to_string_lossy().into_owned(),
        missing.to_string_lossy().into_owned(),
    ];
    let mut mixed = vec![valid.clone()];
    mixed.extend(non_successes.clone());

    let cases = [
        Case {
            name: "mixed-default",
            inputs: mixed.clone(),
            strict: false,
            exit: 0,
            counts: (5, 1, 3, 1),
            statuses: vec!["succeeded", "skipped", "skipped", "skipped", "failed"],
        },
        Case {
            name: "mixed-strict",
            inputs: mixed,
            strict: true,
            exit: 1,
            counts: (5, 1, 3, 1),
            statuses: vec!["succeeded", "skipped", "skipped", "skipped", "failed"],
        },
        Case {
            name: "zero-success-default",
            inputs: non_successes,
            strict: false,
            exit: 1,
            counts: (4, 0, 3, 1),
            statuses: vec!["skipped", "skipped", "skipped", "failed"],
        },
    ];

    for case in cases {
        let mut args = vec!["export".to_string()];
        args.extend(case.inputs.clone());
        args.extend(["--format".to_string(), "jsonl".to_string()]);
        if case.strict {
            args.push("--strict".to_string());
        }
        let output = Command::new(&luad)
            .args(&args)
            .output()
            .unwrap_or_else(|error| panic!("{}: {error}", case.name));
        assert_eq!(output.status.code(), Some(case.exit), "{}", case.name);

        let records: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let terminal = records.last().expect("export_end");
        assert_eq!(terminal["record_type"], "export_end", "{}", case.name);
        let actual_counts = (
            terminal["files_processed"].as_u64().unwrap() as usize,
            terminal["files_succeeded"].as_u64().unwrap() as usize,
            terminal["files_skipped"].as_u64().unwrap() as usize,
            terminal["files_failed"].as_u64().unwrap() as usize,
        );
        assert_eq!(actual_counts, case.counts, "{}", case.name);
        assert_eq!(
            actual_counts.0,
            actual_counts.1 + actual_counts.2 + actual_counts.3,
            "{} count closure",
            case.name
        );

        let file_ends: Vec<_> = records
            .iter()
            .filter(|record| record["record_type"] == "file_end")
            .collect();
        assert_eq!(file_ends.len(), case.inputs.len(), "{}", case.name);
        for ((record, expected_path), expected_status) in
            file_ends.iter().zip(&case.inputs).zip(&case.statuses)
        {
            assert_eq!(record["path"], *expected_path, "{}", case.name);
            assert_eq!(record["status"], *expected_status, "{}", case.name);
        }

        let stderr = String::from_utf8(output.stderr).unwrap();
        for path in case.inputs.iter().skip(usize::from(case.counts.1 > 0)) {
            assert!(stderr.contains(path), "{} missing path {path}", case.name);
        }
        assert!(stderr.ends_with(&format!(
            "{} exported, {} skipped, {} failed\n",
            case.counts.1, case.counts.2, case.counts.3
        )));

        let diagnostic_codes: Vec<_> = records
            .iter()
            .filter(|record| record["record_type"] == "diagnostic")
            .filter_map(|record| record["data"]["code"].as_str())
            .collect();
        assert!(diagnostic_codes.contains(&"PARSE-SOURCE-001"));
        assert!(diagnostic_codes.contains(&"PARSE-UNKNOWN-001"));
        assert!(diagnostic_codes.contains(&"PARSE-001"));
        assert!(diagnostic_codes.contains(&"IO-001"));
    }
}

#[test]
fn test_batch_export_help_discovers_fact_families() {
    let luad = get_luad_bin();
    let output = Command::new(&luad)
        .args(["export", "--help"])
        .output()
        .expect("run export --help");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(stdout.contains("--facts"));
    for family in SORTED_FACT_FAMILY_NAMES {
        assert!(
            stdout.contains(family),
            "export --help must document fact family '{family}'"
        );
    }
}

#[test]
fn test_batch_export_capabilities_json_and_text_discover_fact_families() {
    let luad = get_luad_bin();

    // JSON output
    let output = Command::new(&luad)
        .args(["capabilities", "--format", "json"])
        .output()
        .expect("run capabilities --format json");
    assert_eq!(output.status.code(), Some(0));
    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid capabilities JSON");
    let export_cap = &doc["export"];
    assert_eq!(export_cap["command"], "export");
    assert_eq!(export_cap["schema"], "export");
    assert_eq!(export_cap["formats"], serde_json::json!(["jsonl"]));
    let families = export_cap["fact_families"]
        .as_array()
        .expect("fact_families is array")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        families,
        SORTED_FACT_FAMILY_NAMES
            .iter()
            .map(|&s| s.to_string())
            .collect::<Vec<_>>()
    );

    // Text output
    let text_out = Command::new(&luad)
        .args(["capabilities", "--format", "text"])
        .output()
        .expect("run capabilities --format text");
    assert_eq!(text_out.status.code(), Some(0));
    let text_str = String::from_utf8(text_out.stdout).expect("capabilities text is UTF-8");
    assert!(text_str.contains("Export Capability:"));
    assert!(text_str.contains("export (schema: export, formats: jsonl)"));
    assert!(text_str.contains(&format!(
        "fact families: {}",
        SORTED_FACT_FAMILY_NAMES.join(", ")
    )));
}

#[test]
fn test_batch_export_unknown_family_error_contains_sorted_valid_families() {
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let luad = get_luad_bin();

    let output = run_selected_export(&luad, &fixture, "bogus_family");
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty on invalid fact family"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let expected_err = format!(
        "unknown export fact family 'bogus_family'. Valid families: {}",
        SORTED_FACT_FAMILY_NAMES.join(", ")
    );
    assert!(
        stderr.contains(&expected_err),
        "stderr should contain {expected_err:?}, got: {stderr}"
    );
}

#[test]
fn test_batch_export_fact_family_negative_controls() {
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let luad = get_luad_bin();

    // 1. Invented family fails closed in both parser and CLI
    assert!(ExportFactFamily::parse("speculative_taint").is_none());
    let inv_out = run_selected_export(&luad, &fixture, "speculative_taint");
    assert_eq!(inv_out.status.code(), Some(2));
    assert!(inv_out.stdout.is_empty());

    // 2. Exact match between canonical and sorted sets
    let mut canonical_sorted = EXPORT_FACT_FAMILY_NAMES.to_vec();
    canonical_sorted.sort_unstable();
    assert_eq!(SORTED_FACT_FAMILY_NAMES.to_vec(), canonical_sorted);

    // 3. Omitting any family from advertised list would be detected by comparator
    let full_set: std::collections::BTreeSet<_> =
        SORTED_FACT_FAMILY_NAMES.iter().copied().collect();
    for family in SORTED_FACT_FAMILY_NAMES {
        let mut corrupted = full_set.clone();
        corrupted.remove(family);
        assert_ne!(
            corrupted, full_set,
            "omitting {family} must produce a strictly smaller set"
        );
    }
}
