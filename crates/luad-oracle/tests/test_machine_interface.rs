//! Machine interface schema, JSON/JSONL determinism, envelope validation, and golden schema tests (Gate M1).

use std::process::Command;

use luad_analysis::{ChunkDiff, ControlFlowGraph, QueryResponse, XrefResponse};
use luad_core::capabilities::CapabilityManifest;
use luad_core::envelope::{
    ExportEndRecord, ExportStartRecord, FileEndRecord, FileStartRecord, JsonlDataRecord,
    JsonlMetadataRecord, MachineDocument, ValidationResponse, JSONL_SCHEMA_VERSION,
};
use luad_core::model::Chunk;
use luad_core::DisassembledPrototype;

fn load_schema(root: &std::path::Path, schema_file: &str) -> serde_json::Value {
    let path = root.join("tests/schemas").join(schema_file);
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("Failed to read schema '{}': {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("Schema '{}' is not JSON: {error}", path.display()))
}

fn assert_schema_valid(schema: &serde_json::Value, instance: &serde_json::Value, context: &str) {
    let validator = jsonschema::validator_for(schema)
        .unwrap_or_else(|error| panic!("Failed to compile schema for {context}: {error}"));
    if let Err(error) = validator.validate(instance) {
        panic!("Schema rejected {context}: {error}");
    }
}

fn assert_output_matches_schema(
    root: &std::path::Path,
    schema_file: &str,
    output: &[u8],
    context: &str,
) {
    let schema = load_schema(root, schema_file);
    let instance: serde_json::Value = serde_json::from_slice(output)
        .unwrap_or_else(|error| panic!("{context} is not JSON: {error}"));
    assert_schema_valid(&schema, &instance, context);
}

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

#[test]
fn test_all_schema_exports_return_valid_json_schema() {
    let luad = get_luad_bin();
    let schema_types = [
        "chunk",
        "diagnostic",
        "instruction",
        "disasm",
        "validate",
        "cfg",
        "callees",
        "xrefs",
        "query",
        "analysis",
        "diff",
        "capabilities",
        "manifest",
        "export",
    ];

    for st in schema_types {
        let output = Command::new(&luad)
            .args(["schema", st])
            .output()
            .unwrap_or_else(|e| panic!("Failed to run luad schema {st}: {e}"));

        assert_eq!(
            output.status.code(),
            Some(0),
            "Schema export for '{st}' failed with code {:?}",
            output.status.code()
        );

        let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("Schema output for '{st}' is not valid JSON: {e}"));

        assert!(
            json_val.get("$schema").is_some()
                || json_val.get("type").is_some()
                || json_val.get("title").is_some(),
            "Schema for '{st}' must have standard schema metadata"
        );
    }
}

#[test]
fn test_schema_goldens_consistency() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let schemas_dir = root.join("tests/schemas");

    let goldens = [
        ("chunk", "chunk.schema.json"),
        ("disasm", "disasm.schema.json"),
        ("validate", "validate.schema.json"),
        ("query", "query.schema.json"),
        ("capabilities", "capabilities.schema.json"),
        ("cfg", "cfg.schema.json"),
        ("callees", "callees.schema.json"),
        ("xrefs", "xrefs.schema.json"),
        ("diff", "diff.schema.json"),
        ("diagnostic", "diagnostic.schema.json"),
        ("export", "export.schema.json"),
    ];

    for (st, filename) in goldens {
        let golden_path = schemas_dir.join(filename);
        assert!(
            golden_path.exists(),
            "Golden schema {filename} must exist in tests/schemas/"
        );

        let output = Command::new(&luad)
            .args(["schema", st])
            .output()
            .unwrap_or_else(|e| panic!("Failed to run luad schema {st}: {e}"));

        let current_json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("Invalid JSON from luad schema {st}: {e}"));

        let golden_content = std::fs::read_to_string(&golden_path)
            .unwrap_or_else(|e| panic!("Failed to read {filename}: {e}"));
        let golden_json: serde_json::Value = serde_json::from_str(&golden_content)
            .unwrap_or_else(|e| panic!("Golden schema {filename} is not valid JSON: {e}"));

        assert_eq!(
            current_json, golden_json,
            "Live schema output for '{st}' differs from checked-in golden '{filename}'"
        );
    }
}

#[test]
fn test_live_inspect_json_envelope_and_schema_validation() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["inspect", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad inspect --format json failed");

    assert_eq!(output.status.code(), Some(0));
    assert_output_matches_schema(&root, "chunk.schema.json", &output.stdout, "live inspect");
    let doc: MachineDocument<Chunk> = serde_json::from_slice(&output.stdout)
        .expect("Failed to deserialize inspect JSON document");

    assert_eq!(doc.schema_version, 1);
    assert_eq!(doc.input_identity.path, fixture.to_str().unwrap());
    assert!(!doc.input_identity.sha256.is_empty());
    assert!(doc.input_identity.byte_length > 0);
    assert_eq!(doc.interpretation.base_dialect, "lua5.4");
}

#[test]
fn test_live_disasm_json_envelope_and_schema_validation() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["disasm", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad disasm --format json failed");

    assert_eq!(output.status.code(), Some(0));
    assert_output_matches_schema(&root, "disasm.schema.json", &output.stdout, "live disasm");
    let doc: MachineDocument<DisassembledPrototype> =
        serde_json::from_slice(&output.stdout).expect("Failed to deserialize disasm JSON document");

    assert_eq!(doc.schema_version, 1);
    assert_eq!(doc.input_identity.path, fixture.to_str().unwrap());
    assert!(!doc.data.instructions.is_empty());
}

#[test]
fn test_live_validate_json_envelope_and_schema_validation() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["validate", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad validate --format json failed");

    assert_eq!(output.status.code(), Some(0));
    assert_output_matches_schema(
        &root,
        "validate.schema.json",
        &output.stdout,
        "live validate",
    );
    let doc: MachineDocument<ValidationResponse> = serde_json::from_slice(&output.stdout)
        .expect("Failed to deserialize validate JSON document");

    assert_eq!(doc.schema_version, 1);
    assert!(matches!(
        doc.data.verdict,
        luad_core::Verdict::ValidForParser | luad_core::Verdict::ValidForAnalysis
    ));
}

#[test]
fn test_live_cfg_json_envelope_and_schema_validation() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["cfg", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad cfg --format json failed");

    assert_eq!(output.status.code(), Some(0));
    assert_output_matches_schema(&root, "cfg.schema.json", &output.stdout, "live cfg");
    let doc: MachineDocument<ControlFlowGraph> =
        serde_json::from_slice(&output.stdout).expect("Failed to deserialize cfg JSON document");

    assert_eq!(doc.schema_version, 1);
    assert!(!doc.data.blocks.is_empty());
}

#[test]
fn test_live_xrefs_json_envelope_and_schema_validation() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["xrefs", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad xrefs --format json failed");

    assert_eq!(output.status.code(), Some(0));
    assert_output_matches_schema(&root, "xrefs.schema.json", &output.stdout, "live xrefs");
    let doc: MachineDocument<XrefResponse> =
        serde_json::from_slice(&output.stdout).expect("Failed to deserialize xrefs JSON document");

    assert_eq!(doc.schema_version, 1);
    assert!(doc.data.total_count > 0);
}

#[test]
fn test_live_query_json_envelope_and_schema_validation() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args([
            "query",
            fixture.to_str().unwrap(),
            "--where",
            "mnemonic == 'VARARGPREP'",
            "--format",
            "json",
        ])
        .output()
        .expect("luad query --format json failed");

    assert_eq!(output.status.code(), Some(0));
    assert_output_matches_schema(&root, "query.schema.json", &output.stdout, "live query");
    let doc: MachineDocument<QueryResponse> =
        serde_json::from_slice(&output.stdout).expect("Failed to deserialize query JSON document");

    assert_eq!(doc.schema_version, 1);
    assert_eq!(doc.data.count, 1);
}

#[test]
fn test_live_diff_json_envelope_and_schema_validation() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let old_fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let new_fixture = root.join("tests/fixtures/precompiled/lua54/hello_stripped.luac");

    let output = Command::new(&luad)
        .args([
            "diff",
            old_fixture.to_str().unwrap(),
            new_fixture.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("luad diff --format json failed");

    assert_eq!(output.status.code(), Some(0));
    assert_output_matches_schema(&root, "diff.schema.json", &output.stdout, "live diff");
    let doc: MachineDocument<ChunkDiff> =
        serde_json::from_slice(&output.stdout).expect("Failed to deserialize diff JSON document");

    assert_eq!(doc.schema_version, 1);
    assert!(!doc.data.is_identical);
}

#[test]
fn test_live_capabilities_json_and_schema_validation() {
    let luad = get_luad_bin();

    let output = Command::new(&luad)
        .args(["capabilities", "--format", "json"])
        .output()
        .expect("luad capabilities --format json failed");

    assert_eq!(output.status.code(), Some(0));
    let root = luad_oracle::find_workspace_root();
    assert_output_matches_schema(
        &root,
        "capabilities.schema.json",
        &output.stdout,
        "live capabilities",
    );
    let manifest: CapabilityManifest = serde_json::from_slice(&output.stdout)
        .expect("Failed to deserialize capabilities JSON document");

    assert_eq!(manifest.schema_version, 2);
    assert_eq!(manifest.diagnostic_catalog.command, "diagnostics");
    assert_eq!(manifest.diagnostic_catalog.schema, "diagnostics");
    assert_eq!(
        manifest.diagnostic_catalog.formats,
        ["json".to_string(), "text".to_string()]
    );
    assert!(!manifest.dialects.is_empty());
}

#[test]
fn test_jsonl_streaming_disasm_format_integrity() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["disasm", fixture.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("luad disasm --format jsonl failed");

    assert_eq!(output.status.code(), Some(0));
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert!(lines.len() >= 2);

    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["record_type"], "metadata");
    assert_eq!(first["schema_version"], JSONL_SCHEMA_VERSION);

    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["record_type"], "summary");
    assert!(last.get("total_records").is_some());
}

#[test]
fn test_jsonl_streaming_cfg_format_integrity() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["cfg", fixture.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("luad cfg --format jsonl failed");

    assert_eq!(output.status.code(), Some(0));
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert!(lines.len() >= 2);

    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["record_type"], "metadata");

    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["record_type"], "summary");
}

#[test]
fn test_jsonl_streaming_diff_format_integrity() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let old_fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let new_fixture = root.join("tests/fixtures/precompiled/lua54/hello_stripped.luac");

    let output = Command::new(&luad)
        .args([
            "diff",
            old_fixture.to_str().unwrap(),
            new_fixture.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("luad diff --format jsonl failed");

    assert_eq!(output.status.code(), Some(0));
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert!(lines.len() >= 2);

    let first: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["record_type"], "metadata");

    let last: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
    assert_eq!(last["record_type"], "summary");
}

#[test]
fn test_every_single_input_jsonl_fact_is_self_identifying() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let hello = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let stripped = root.join("tests/fixtures/precompiled/lua54/hello_stripped.luac");
    let lua51 = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let commands = vec![
        vec!["inspect".to_string(), hello.display().to_string()],
        vec!["disasm".to_string(), hello.display().to_string()],
        vec!["cfg".to_string(), hello.display().to_string()],
        vec!["callees".to_string(), lua51.display().to_string()],
        vec!["xrefs".to_string(), hello.display().to_string()],
        vec![
            "query".to_string(),
            hello.display().to_string(),
            "--where".to_string(),
            "mnemonic == 'VARARGPREP'".to_string(),
        ],
        vec![
            "diff".to_string(),
            hello.display().to_string(),
            stripped.display().to_string(),
        ],
    ];

    for mut args in commands {
        let command = args[0].clone();
        args.extend(["--format".to_string(), "jsonl".to_string()]);
        let output = Command::new(&luad)
            .args(&args)
            .output()
            .unwrap_or_else(|error| panic!("{command} JSONL failed: {error}"));
        assert_eq!(
            output.status.code(),
            Some(0),
            "{command} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let records: Vec<serde_json::Value> = String::from_utf8(output.stdout)
            .expect("JSONL is UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSONL record"))
            .collect();
        let metadata: JsonlMetadataRecord = serde_json::from_value(records[0].clone())
            .unwrap_or_else(|error| panic!("{command} metadata: {error}"));
        assert_eq!(metadata.schema_version, JSONL_SCHEMA_VERSION);

        let facts: Vec<_> = records
            .iter()
            .filter(|record| {
                !matches!(record["record_type"].as_str(), Some("metadata" | "summary"))
            })
            .collect();
        assert!(!facts.is_empty(), "{command} emitted no facts");
        for fact in facts {
            let typed: JsonlDataRecord<serde_json::Value> = serde_json::from_value(fact.clone())
                .unwrap_or_else(|error| panic!("{command} fact lacks required context: {error}"));
            assert_eq!(
                typed.context.input_identity.as_ref(),
                Some(&metadata.input_identity)
            );
            assert_eq!(
                typed.context.interpretation.as_ref(),
                Some(&metadata.interpretation)
            );
        }
    }
}

#[test]
fn test_jsonl_context_killer_mutations_are_rejected() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let output = Command::new(&luad)
        .args(["disasm", fixture.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("disasm JSONL");
    assert_eq!(output.status.code(), Some(0));
    let records: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let metadata: JsonlMetadataRecord = serde_json::from_value(records[0].clone()).unwrap();
    let fact = records
        .iter()
        .find(|record| record["record_type"] == "instruction")
        .unwrap();

    let mut missing = fact.clone();
    missing.as_object_mut().unwrap().remove("context");
    assert!(serde_json::from_value::<JsonlDataRecord<serde_json::Value>>(missing).is_err());

    for field in ["sha256", "path"] {
        let mut mutated = fact.clone();
        mutated["context"]["input_identity"][field] = serde_json::json!("tampered");
        let typed: JsonlDataRecord<serde_json::Value> = serde_json::from_value(mutated).unwrap();
        assert_ne!(
            typed.context.input_identity.as_ref(),
            Some(&metadata.input_identity)
        );
    }

    let mut swapped = fact.clone();
    swapped["context"]["interpretation"]["profile"] = serde_json::json!("lnum32");
    let typed: JsonlDataRecord<serde_json::Value> = serde_json::from_value(swapped).unwrap();
    assert_ne!(
        typed.context.interpretation.as_ref(),
        Some(&metadata.interpretation)
    );
}

#[test]
fn test_jsonl_streaming_batch_export_deterministic_and_recursive() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let f1 = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let f2 = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args([
            "export",
            f1.to_str().unwrap(),
            f2.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("luad export --format jsonl failed");

    assert_eq!(output.status.code(), Some(0));
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout_str
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    let export_schema = load_schema(&root, "export.schema.json");

    for (line_index, line) in lines.iter().enumerate() {
        let record: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("export line {} is not JSON: {error}", line_index + 1));
        assert_schema_valid(
            &export_schema,
            &record,
            &format!("live export line {}", line_index + 1),
        );
    }

    // First line must be export_start
    let start: ExportStartRecord = serde_json::from_str(lines[0]).expect("export_start record");
    assert_eq!(start.record_type, "export_start");
    assert_eq!(start.total_files, 2);

    // Last line must be export_end
    let end: ExportEndRecord =
        serde_json::from_str(lines.last().unwrap()).expect("export_end record");
    assert_eq!(end.record_type, "export_end");
    assert_eq!(end.files_processed, 2);
    assert_eq!(end.files_succeeded, 2);
    assert_eq!(end.files_failed, 0);
    assert!(end.total_instructions > 0);

    let mut found_file_start = 0;
    let mut found_file_end = 0;
    let mut found_protos = 0;

    for line in &lines {
        let val: serde_json::Value = serde_json::from_str(line).unwrap();
        match val["record_type"].as_str() {
            Some("file_start") => {
                let _rec: FileStartRecord = serde_json::from_str(line).unwrap();
                found_file_start += 1;
            }
            Some("file_end") => {
                let _rec: FileEndRecord = serde_json::from_str(line).unwrap();
                found_file_end += 1;
            }
            Some("prototype") => found_protos += 1,
            _ => {}
        }
    }

    assert_eq!(found_file_start, 2);
    assert_eq!(found_file_end, 2);
    // Closures fixture has 4 prototypes (root + 3 nested), hello has 1 prototype -> 5 total prototypes
    assert!(
        found_protos >= 5,
        "Export must recursively emit prototype records across proto trees: found {found_protos}"
    );
}

#[test]
fn test_negative_control_missing_provenance_field_rejected() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["inspect", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad inspect --format json failed");

    let mut doc_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Tamper with envelope: delete input_identity.sha256
    doc_json
        .get_mut("input_identity")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("sha256");

    let parse_res: Result<MachineDocument<Chunk>, _> = serde_json::from_value(doc_json);
    assert!(
        parse_res.is_err(),
        "Strict envelope deserializer MUST reject documents missing input_identity.sha256"
    );
}

#[test]
fn test_negative_control_envelope_field_mutations_rejected() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args(["inspect", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad inspect --format json failed");

    let base_json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    // 1. Remove interpretation
    let mut bad_interp = base_json.clone();
    bad_interp.as_object_mut().unwrap().remove("interpretation");
    let res: Result<MachineDocument<Chunk>, _> = serde_json::from_value(bad_interp);
    assert!(res.is_err(), "Missing interpretation must be rejected");

    // 2. Remove analysis_configuration
    let mut bad_config = base_json.clone();
    bad_config
        .as_object_mut()
        .unwrap()
        .remove("analysis_configuration");
    let res: Result<MachineDocument<Chunk>, _> = serde_json::from_value(bad_config);
    assert!(
        res.is_err(),
        "Missing analysis_configuration must be rejected"
    );

    // 3. Remove tool_version
    let mut bad_ver = base_json.clone();
    bad_ver.as_object_mut().unwrap().remove("tool_version");
    let res: Result<MachineDocument<Chunk>, _> = serde_json::from_value(bad_ver);
    assert!(res.is_err(), "Missing tool_version must be rejected");

    let schema = load_schema(&root, "chunk.schema.json");
    let mut wrong_nested_type = base_json;
    wrong_nested_type["input_identity"]["byte_length"] = serde_json::json!("not-a-number");
    let validator = jsonschema::validator_for(&schema).expect("compile chunk schema");
    assert!(
        !validator.is_valid(&wrong_nested_type),
        "Schema must reject a nested field with the wrong type"
    );
}

#[test]
fn test_cross_dialect_diff_without_semantic_flag_rejected() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let old_fixture = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let new_fixture = root.join("tests/fixtures/precompiled/lua54/hello.luac");

    let output = Command::new(&luad)
        .args([
            "diff",
            old_fixture.to_str().unwrap(),
            new_fixture.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("diff command failed");

    // Cross-dialect positional diff without --semantic must fail closed
    assert_ne!(
        output.status.code(),
        Some(0),
        "Positional diff across mismatched dialects without --semantic must fail"
    );
}

#[test]
fn test_validate_all_generated_examples_against_schemas() {
    let root = luad_oracle::find_workspace_root();
    let examples_dir = root.join("docs/examples");
    let schemas_dir = root.join("tests/schemas");

    let examples = [
        ("inspect.json", "chunk.schema.json"),
        ("disasm.json", "disasm.schema.json"),
        ("validate.json", "validate.schema.json"),
        ("cfg.json", "cfg.schema.json"),
        ("callees.json", "callees.schema.json"),
        ("xrefs.json", "xrefs.schema.json"),
        ("query.json", "query.schema.json"),
        ("diff.json", "diff.schema.json"),
        ("capabilities.json", "capabilities.schema.json"),
    ];

    for (ex_file, schema_file) in examples {
        let ex_path = examples_dir.join(ex_file);
        let schema_path = schemas_dir.join(schema_file);

        assert!(ex_path.exists(), "Example file must exist: {ex_path:?}");
        assert!(
            schema_path.exists(),
            "Schema file must exist: {schema_path:?}"
        );

        let ex_bytes = std::fs::read(&ex_path).unwrap();
        let schema_bytes = std::fs::read(&schema_path).unwrap();
        let ex_val: serde_json::Value = serde_json::from_slice(&ex_bytes).unwrap();
        let schema_val: serde_json::Value = serde_json::from_slice(&schema_bytes).unwrap();
        assert_schema_valid(&schema_val, &ex_val, ex_file);
    }

    let export_schema = load_schema(&root, "export.schema.json");
    let export_path = examples_dir.join("export.jsonl");
    let export_text = std::fs::read_to_string(&export_path).unwrap();
    for (line_index, line) in export_text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!("export.jsonl line {} is not JSON: {error}", line_index + 1)
        });
        assert_schema_valid(
            &export_schema,
            &record,
            &format!("export.jsonl line {}", line_index + 1),
        );
    }

    let mut wrong_discriminator: serde_json::Value =
        serde_json::from_str(export_text.lines().next().unwrap()).unwrap();
    wrong_discriminator["record_type"] = serde_json::json!("file_end");
    let validator = jsonschema::validator_for(&export_schema).expect("compile export schema");
    assert!(
        !validator.is_valid(&wrong_discriminator),
        "Export schema must reject a record whose discriminator does not match its fields"
    );
}

#[test]
fn test_negative_control_trailing_garbage_fails_json_parser() {
    let valid_json = "{\"valid\": true}";
    let corrupted = format!("{valid_json} GARBAGE_TRAILING_TEXT");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&corrupted);
    assert!(
        parsed.is_err(),
        "Trailing garbage MUST fail strict JSON decoding"
    );
}
