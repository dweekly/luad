//! Required compiler controls for explicit public fact availability and completion.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

type Compile = fn(&str, bool) -> Result<Vec<u8>, String>;
type Case = (&'static str, &'static str, Compile, fn() -> PathBuf);
const CASES: [Case; 5] = [
    (
        "lua5.1",
        "5.1.5",
        luad_oracle::compile_source_lua51,
        luad_oracle::require_luac51,
    ),
    (
        "lua5.2",
        "5.2.4",
        luad_oracle::compile_source_lua52,
        luad_oracle::require_luac52,
    ),
    (
        "lua5.3",
        "5.3.6",
        luad_oracle::compile_source_lua53,
        luad_oracle::require_luac53,
    ),
    (
        "lua5.4",
        "5.4.8",
        luad_oracle::compile_source_lua54,
        luad_oracle::require_luac54,
    ),
    (
        "lua5.5",
        "5.5.1",
        luad_oracle::compile_source_lua55,
        luad_oracle::require_luac55,
    ),
];
const FAMILIES: [&str; 9] = [
    "prototype",
    "constant",
    "upvalue",
    "instruction",
    "xref",
    "callee",
    "origin",
    "call_relation",
    "prototype_identity",
];
const SOURCE: &str = r#"
local salt = "fixed"
local function live(p)
  local function leaf(q) return q.name .. salt, "\255\000" end
  return leaf(p)
end
local function decoy(p) return p.other end
return live, decoy
"#;

fn run(luad: &str, args: &[&str]) -> Output {
    Command::new(luad)
        .args(args)
        .output()
        .expect("public luad command must run")
}
fn records(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).expect("framed export JSON"))
        .collect()
}
fn identity(path: &Path, bytes: &[u8]) -> Value {
    json!({"path": path.to_str().unwrap(), "sha256": hex::encode(Sha256::digest(bytes)), "byte_length": bytes.len()})
}
fn expected_ids() -> BTreeSet<String> {
    ["proto:0", "proto:0/0", "proto:0/0/0", "proto:0/1"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}
fn structural_matches(rows: &[Value], input: &Value, bytes: &[u8]) -> bool {
    let ids: BTreeSet<_> = rows
        .iter()
        .filter(|r| r["record_type"] == "prototype")
        .filter_map(|r| r["data"]["id"].as_str().map(str::to_owned))
        .collect();
    if ids != expected_ids() {
        return false;
    }
    let Some(start) = rows.iter().find(|r| r["record_type"] == "file_start") else {
        return false;
    };
    if start["path"] != input["path"]
        || start["sha256"] != input["sha256"]
        || start["byte_length"] != input["byte_length"]
    {
        return false;
    }
    let context = json!({"input_identity": input, "interpretation": start["interpretation"]});
    let mut raw_string = false;
    for row in rows.iter().filter(|r| r.get("context").is_some()) {
        if row["context"] != context {
            return false;
        }
        if row["record_type"] == "constant" {
            let source = &row["data"]["source"];
            let Some(offset) = source["byte_offset"].as_u64() else {
                return false;
            };
            let Some(length) = source["byte_length"].as_u64() else {
                return false;
            };
            let Some(raw) = bytes.get(offset as usize..(offset + length) as usize) else {
                return false;
            };
            if source["raw_hex"] != hex::encode(raw) {
                return false;
            }
            if row["data"]["value"]["type"] == "short-string"
                && row["data"]["value"]["value"]["raw_bytes"] == json!([255, 0])
            {
                raw_string = true;
            }
        }
    }
    raw_string
}
fn assert_refusal(output: &Output, profile: &str) {
    assert_eq!(
        output.status.code(),
        Some(4),
        "{profile}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "unavailable disassembly must not publish data"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("ANA-PRECOND-001")
            && stderr.contains(profile)
            && stderr.contains("inspect")
    );
    let mut damaged = output.clone();
    damaged.stdout = b"{\"opcode_num\":0}\n".to_vec();
    assert!(
        !is_refusal(&damaged),
        "a refusal cannot carry fabricated success facts"
    );
}
fn is_refusal(output: &Output) -> bool {
    output.status.code() == Some(4) && output.stdout.is_empty()
}
fn assert_file_failure(
    rows: &[Value],
    input: &Value,
    bytes: &[u8],
    profile: &str,
    parsed: &[Value],
) {
    assert_eq!(
        rows.len(),
        5 + parsed.len(),
        "retain diagnostics, one availability error, no facts"
    );
    assert_eq!(rows[0]["record_type"], "export_start");
    assert_eq!(rows[1]["record_type"], "file_start");
    assert_eq!(rows[1]["path"], input["path"]);
    assert_eq!(rows[1]["sha256"], input["sha256"]);
    assert_eq!(rows[1]["byte_length"], input["byte_length"]);
    assert_eq!(rows[1]["interpretation"]["profile"], profile);
    let diagnostics: Vec<_> = rows
        .iter()
        .filter(|r| r["record_type"] == "diagnostic")
        .collect();
    assert_eq!(diagnostics.len(), parsed.len() + 1);
    for (actual, expected) in diagnostics.iter().zip(parsed) {
        assert_eq!(&actual["data"], expected);
    }
    let context = json!({"input_identity":input, "interpretation":rows[1]["interpretation"]});
    for diagnostic in &diagnostics {
        assert_eq!(diagnostic["context"], context);
    }
    let unavailable = diagnostics.last().unwrap();
    assert_eq!(unavailable["data"]["code"], "ANA-PRECOND-001");
    let source = &unavailable["data"]["source"];
    let offset = source["byte_offset"].as_u64().unwrap() as usize;
    let length = source["byte_length"].as_u64().unwrap() as usize;
    assert!(length > 0);
    assert_eq!(
        source["raw_hex"],
        hex::encode(&bytes[offset..offset + length])
    );
    let end = &rows[rows.len() - 2];
    assert_eq!(end["record_type"], "file_end");
    assert_eq!(end["path"], input["path"]);
    assert_eq!(end["status"], "failed");
    for field in [
        "instruction_count",
        "emitted_fact_count",
        "available_fact_count",
    ] {
        assert_eq!(end[field], 0);
    }
    assert_eq!(end["diagnostic_count"], diagnostics.len());
    assert_eq!(end["is_truncated"], false);
    let end = rows.last().unwrap();
    assert_eq!(end["record_type"], "export_end");
    assert_eq!(end["files_processed"], 1);
    assert_eq!(end["files_failed"], 1);
    assert_eq!(end["files_succeeded"], 0);
    assert_eq!(end["files_skipped"], 0);
    assert_eq!(end["total_instructions"], 0);
}

fn parsed_diagnostics(luad: &str, path: &Path) -> Vec<Value> {
    let output = run(
        luad,
        &["inspect", path.to_str().unwrap(), "--format", "json"],
    );
    assert!(output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    document["diagnostics"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

fn assert_diagnostic_retention(luad: &str, directory: &Path) {
    for (compiler, version) in [
        (luad_oracle::require_luac52(), "5.2.4"),
        (luad_oracle::require_luac51(), "5.1.5"),
    ] {
        let output = Command::new(compiler).arg("-v").output().unwrap();
        let banner = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(luad_oracle::banner_names_release(&banner, version));
    }
    let mut bytes = luad_oracle::compile_source_lua52(
        &format!("local x=0; {} return x", "x=x+1;".repeat(10_020)),
        true,
    )
    .unwrap();
    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua52::decode_chunk_lua52(&mut reader).unwrap();
    assert!(chunk
        .interpretation
        .as_ref()
        .unwrap()
        .validated_layout
        .as_ref()
        .unwrap()
        .contains("endian=1"));
    assert!(chunk.main_proto.instructions.len() > 10_000);
    // Declared little-endian physical words with unknown opcodes; never execute them.
    for word in &chunk.main_proto.instructions {
        assert_eq!(word.source.byte_length, 4);
        let offset = word.source.byte_offset;
        bytes[offset..offset + 4].copy_from_slice(&0x3fu32.to_le_bytes());
    }
    let limited = directory.join("diagnostic-limit.luac");
    std::fs::write(&limited, &bytes).unwrap();
    let parsed = parsed_diagnostics(luad, &limited);
    assert!(
        parsed.iter().any(|d| d["code"] == "CORE-LIMIT-003"),
        "control must reach an actual diagnostic limit"
    );
    let output = run(luad, &["export", limited.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(5),
        "an unavailable view cannot hide a cutoff"
    );
    assert_file_failure(
        &records(&output),
        &identity(&limited, &bytes),
        &bytes,
        "lua5.2",
        &parsed,
    );
    let positive = directory.join("qualified-positive.luac");
    std::fs::write(
        &positive,
        luad_oracle::compile_source_lua51(SOURCE, true).unwrap(),
    )
    .unwrap();
    let output = run(
        luad,
        &[
            "export",
            positive.to_str().unwrap(),
            limited.to_str().unwrap(),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "a successful sibling cannot hide a cutoff"
    );
    let rows = records(&output);
    assert_eq!(rows.last().unwrap()["files_succeeded"], 1);
    assert_eq!(rows.last().unwrap()["files_failed"], 1);
    assert!(rows
        .iter()
        .any(|r| r["record_type"] == "diagnostic" && r["data"]["code"] == "CORE-LIMIT-003"));

    let mut warning = luad_oracle::compile_source_lua52(SOURCE, false).unwrap();
    warning.push(0xab);
    let path = directory.join("trailing-warning.luac");
    std::fs::write(&path, &warning).unwrap();
    let parsed = parsed_diagnostics(luad, &path);
    assert!(parsed.iter().any(|d| d["code"] == "L52-CHUNK-001"));
    let output = run(
        luad,
        &["export", path.to_str().unwrap(), "--facts", "instruction"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_file_failure(
        &records(&output),
        &identity(&path, &warning),
        &warning,
        "lua5.2",
        &parsed,
    );
}

fn available(profile: &str, family: &str) -> bool {
    match family {
        "prototype" | "constant" | "upvalue" => true,
        "instruction" | "xref" => matches!(profile, "lua5.1" | "lua5.4"),
        "callee" | "origin" | "call_relation" | "prototype_identity" => profile == "lua5.1",
        _ => panic!("unknown test family"),
    }
}

pub fn assert_public_availability(luad: &str) {
    let directory = tempfile::tempdir().unwrap();
    assert_diagnostic_retention(luad, directory.path());
    let mut debug_paths = Vec::new();
    for (profile, version, compile, require) in CASES {
        let compiler = require();
        let banner = Command::new(compiler).arg("-v").output().unwrap();
        let banner = format!(
            "{}{}",
            String::from_utf8_lossy(&banner.stdout),
            String::from_utf8_lossy(&banner.stderr)
        );
        assert!(luad_oracle::banner_names_release(&banner, version));
        for stripped in [false, true] {
            let bytes = compile(SOURCE, stripped).expect("required official compiler");
            let path = directory.path().join(format!("{profile}-{stripped}.luac"));
            std::fs::write(&path, &bytes).unwrap();
            let name = path.to_str().unwrap();
            let input = identity(&path, &bytes);
            let parsed = parsed_diagnostics(luad, &path);
            if !stripped {
                debug_paths.push(path.clone());
            }
            let output = run(
                luad,
                &["export", name, "--facts", "prototype,constant,upvalue"],
            );
            assert!(output.status.success(), "structural export {profile}");
            let rows = records(&output);
            assert!(
                structural_matches(&rows, &input, &bytes),
                "exact child/raw structural facts {profile}"
            );
            let mut missing_child = rows.clone();
            let index = missing_child
                .iter()
                .position(|r| r["record_type"] == "prototype" && r["data"]["id"] == "proto:0/0/0")
                .unwrap();
            missing_child.remove(index);
            for row in &mut missing_child {
                if row["record_type"] == "file_end" {
                    for field in ["emitted_fact_count", "available_fact_count"] {
                        row[field] = json!(row[field].as_u64().unwrap() - 1);
                    }
                }
            }
            assert!(
                !structural_matches(&missing_child, &input, &bytes),
                "omitted child despite internally consistent counters must be detected"
            );
            for command in ["disasm", "explain"] {
                for format in ["text", "json", "jsonl"] {
                    let mut args = vec![command, name];
                    if command == "explain" {
                        args.push("proto:0:pc:0");
                    }
                    args.extend(["--format", format]);
                    let output = run(luad, &args);
                    if matches!(profile, "lua5.1" | "lua5.4")
                        || (command == "disasm" && format == "text")
                    {
                        assert!(
                            output.status.success(),
                            "available {command} {profile}: {}",
                            String::from_utf8_lossy(&output.stderr)
                        );
                        assert!(!output.stdout.is_empty());
                        assert!(!is_refusal(&output));
                        if !matches!(profile, "lua5.1" | "lua5.4") {
                            assert!(String::from_utf8_lossy(&output.stdout).contains("unverified"));
                            let effects =
                                run(luad, &["disasm", name, "--format", "text", "--effects"]);
                            assert_refusal(&effects, profile);
                        }
                    } else {
                        assert_refusal(&output, profile);
                    }
                }
            }
            // Every non-instruction StableId kind, plus an absent prototype.
            for selector in [
                "chunk",
                "proto:0",
                "proto:0:block:0",
                "proto:0:k:0",
                "proto:0:upvalue:0",
                "proto:0:local:0",
                "diagnostic:L54-JUMP-003:proto:0:pc:0",
                "proto:9:pc:0",
            ] {
                for format in ["text", "json", "jsonl", "dot"] {
                    let output = run(luad, &["explain", name, selector, "--format", format]);
                    if matches!(profile, "lua5.1" | "lua5.4") {
                        assert_eq!(output.status.code(), Some(2));
                        assert!(output.stdout.is_empty());
                    } else {
                        assert_refusal(&output, profile);
                    }
                }
            }
            for family in FAMILIES {
                let output = run(luad, &["export", name, "--facts", family]);
                let rows = records(&output);
                if available(profile, family) {
                    assert!(
                        output.status.success(),
                        "available family {profile}/{family}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    assert_eq!(rows.last().unwrap()["files_succeeded"], 1);
                    assert_eq!(rows.last().unwrap()["files_failed"], 0);
                    assert_eq!(
                        rows.iter()
                            .find(|r| r["record_type"] == "file_end")
                            .unwrap()["is_truncated"],
                        false
                    );
                } else {
                    assert_eq!(
                        output.status.code(),
                        Some(1),
                        "unavailable family {profile}/{family}"
                    );
                    assert_file_failure(&rows, &input, &bytes, profile, &parsed);
                }
            }
            for cap in ["0", "2"] {
                let output = run(luad, &["export", name, "--max-facts-per-file", cap]);
                let rows = records(&output);
                if matches!(profile, "lua5.1" | "lua5.4") {
                    assert!(output.status.success());
                    let end = rows
                        .iter()
                        .find(|r| r["record_type"] == "file_end")
                        .unwrap();
                    assert_eq!(end["status"], "succeeded");
                    assert_eq!(end["is_truncated"], true);
                    assert_eq!(
                        end["emitted_fact_count"].as_u64().unwrap(),
                        cap.parse::<u64>().unwrap()
                    );
                } else {
                    assert_eq!(output.status.code(), Some(1));
                    assert_file_failure(&rows, &input, &bytes, profile, &parsed);
                }
            }
            let output = run(luad, &["export", name, "--facts", "prototype,instruction"]);
            if !matches!(profile, "lua5.1" | "lua5.4") {
                assert_eq!(output.status.code(), Some(1));
                assert_file_failure(&records(&output), &input, &bytes, profile, &parsed);
            }
        }
    }
    for strict in [false, true] {
        let mut args = vec!["export"];
        for path in &debug_paths {
            args.push(path.to_str().unwrap());
        }
        if strict {
            args.push("--strict");
        }
        let output = run(luad, &args);
        assert_eq!(output.status.code(), Some(if strict { 1 } else { 0 }));
        let rows = records(&output);
        let end = rows.last().unwrap();
        assert_eq!(end["record_type"], "export_end");
        assert_eq!(end["files_processed"], 5);
        assert_eq!(end["files_succeeded"], 2);
        assert_eq!(end["files_failed"], 3);
        assert_eq!(end["files_skipped"], 0);
        assert_eq!(
            rows.iter()
                .filter(|r| r["record_type"] == "file_start")
                .count(),
            5
        );
        assert_eq!(
            rows.iter()
                .filter(|r| r["record_type"] == "file_end")
                .count(),
            5
        );
    }
    let output = run(luad, &["capabilities", "--format", "json"]);
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    for dialect in document["dialects"].as_array().unwrap() {
        let profile = dialect["id"].as_str().unwrap();
        let advertises = dialect["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "disasm");
        assert_eq!(advertises, matches!(profile, "lua5.1" | "lua5.4"));
        let text_only = dialect["features"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "disasm-text-unverified");
        assert_eq!(text_only, matches!(profile, "lua5.2" | "lua5.3" | "lua5.5"));
    }
}
