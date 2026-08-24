//! Independent public regression for Lua 5.1 numeric-for register spans.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

type Json = serde_json::Value;

const FIXTURE: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/control_flow.luac",
    "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
);

struct Case {
    pc: usize,
    byte_offset: usize,
    mnemonic: &'static str,
}

const CASES: [Case; 2] = [
    Case {
        pc: 10,
        byte_offset: 109,
        mnemonic: "FORPREP",
    },
    Case {
        pc: 12,
        byte_offset: 117,
        mnemonic: "FORLOOP",
    },
];

fn luad_bin() -> PathBuf {
    static LUAD: OnceLock<PathBuf> = OnceLock::new();
    LUAD.get_or_init(|| {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
            return path.into();
        }
        let workspace = luad_oracle::find_workspace_root();
        let out = Command::new("cargo")
            .args(["build", "-p", "luad-cli", "--bin", "luad"])
            .current_dir(&workspace)
            .output()
            .expect("build luad CLI");
        assert!(out.status.success());
        workspace.join("target/debug/luad")
    })
    .clone()
}

fn schema_validator(command: &str) -> &'static jsonschema::Validator {
    static VALIDATE: OnceLock<jsonschema::Validator> = OnceLock::new();
    static DISASM: OnceLock<jsonschema::Validator> = OnceLock::new();
    let cell = match command {
        "validate" => &VALIDATE,
        "disasm" => &DISASM,
        other => panic!("no schema for {other}"),
    };
    cell.get_or_init(|| {
        let out = Command::new(luad_bin())
            .args(["schema", command])
            .output()
            .expect("schema CLI");
        let schema: Json = serde_json::from_slice(&out.stdout).unwrap();
        jsonschema::validator_for(&schema).unwrap()
    })
}

fn run_luad(command: &str, extra_args: &[&str], bytes: &[u8]) -> Json {
    let file = NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let mut args = vec![
        command,
        file.path().to_str().unwrap(),
        "--dialect",
        "lua5.1",
        "--format",
        "json",
    ];
    args.extend_from_slice(extra_args);

    let output = Command::new(luad_bin()).args(&args).output().unwrap();
    let doc: Json = serde_json::from_slice(&output.stdout).expect("valid JSON stdout");
    if command == "validate" || command == "disasm" {
        let errors: Vec<_> = schema_validator(command)
            .iter_errors(&doc)
            .map(|e| e.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "live schema validation failed for {command}: {errors:?}"
        );
    }
    doc
}

fn find_inst<'a>(doc: &'a Json, target_id: &str) -> &'a Json {
    fn walk<'a>(v: &'a Json, id: &str) -> Option<&'a Json> {
        if v.get("id").and_then(Json::as_str) == Some(id)
            && v.get("mnemonic").and_then(Json::as_str).is_some()
        {
            return Some(v);
        }
        match v {
            Json::Object(map) => map.values().find_map(|child| walk(child, id)),
            Json::Array(arr) => arr.iter().find_map(|child| walk(child, id)),
            _ => None,
        }
    }
    walk(doc, target_id).unwrap_or_else(|| panic!("instruction {target_id} not found"))
}

#[test]
fn test_validator_numeric_for_span_lua51() {
    let base_path = luad_oracle::find_workspace_root().join(FIXTURE.0);
    let base = std::fs::read(&base_path).expect("read fixture");
    let mut hasher = Sha256::new();
    hasher.update(&base);
    assert_eq!(hex::encode(hasher.finalize()), FIXTURE.1);

    let inspect_doc = run_luad("inspect", &[], &base);
    let maxstacksize = inspect_doc["data"]["main_proto"]["maxstacksize"]
        .as_u64()
        .expect("maxstacksize");
    assert_eq!(maxstacksize, 6);

    let clean_val = run_luad("validate", &[], &base);
    let clean_diags = clean_val["data"]["diagnostics"].as_array().unwrap();
    assert!(
        !clean_diags
            .iter()
            .any(|d| d["code"].as_str() == Some("L51-REG-SPAN-001")),
        "original fixture has no L51-REG-SPAN-001"
    );

    let clean_disasm = run_luad("disasm", &["--proto", "proto:0"], &base);

    for case in &CASES {
        let target_id = format!("proto:0:pc:{}", case.pc);
        let orig_inst = find_inst(&clean_disasm, &target_id);
        assert_eq!(orig_inst["mnemonic"].as_str(), Some(case.mnemonic));
        assert_eq!(orig_inst["encoded_operands"]["a"].as_u64(), Some(2));
        let orig_sbx = orig_inst["encoded_operands"]["sbx"].as_i64().unwrap();
        let orig_target = orig_inst["jump_target"].as_u64().unwrap();

        // Mutate only encoded field A from 2 to 3, preserving opcode and sBx.
        let mut mutated = base.clone();
        let orig_word = u32::from_le_bytes(
            base[case.byte_offset..case.byte_offset + 4]
                .try_into()
                .unwrap(),
        );
        let mutated_word = (orig_word & !0x3fc0) | (3 << 6);
        assert_eq!(orig_word ^ mutated_word, 1 << 6);
        mutated[case.byte_offset..case.byte_offset + 4]
            .copy_from_slice(&mutated_word.to_le_bytes());

        let val_doc = run_luad("validate", &[], &mutated);
        let diags: Vec<_> = val_doc["data"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["code"].as_str() == Some("L51-REG-SPAN-001"))
            .collect();
        assert_eq!(
            diags.len(),
            1,
            "expected exactly one L51-REG-SPAN-001 for {target_id}"
        );

        let d = diags[0];
        assert_eq!(d["target"].as_str(), Some(target_id.as_str()));
        let src = &d["source"];
        assert_eq!(src["byte_offset"].as_u64(), Some(case.byte_offset as u64));
        assert_eq!(src["byte_length"].as_u64(), Some(4));
        assert_eq!(
            src["raw_hex"].as_str(),
            Some(hex::encode(mutated_word.to_le_bytes()).as_str())
        );
        let expected_msg = format!(
            "{} register window R(3)..R(6) exceeds maxstacksize ({maxstacksize}) at PC {}",
            case.mnemonic, case.pc
        );
        assert_eq!(d["message"].as_str(), Some(expected_msg.as_str()));

        let disasm_doc = run_luad("disasm", &["--proto", "proto:0"], &mutated);
        let inst = find_inst(&disasm_doc, &target_id);
        assert_eq!(inst["mnemonic"].as_str(), Some(case.mnemonic));
        assert_eq!(inst["raw_word"].as_u64(), Some(mutated_word as u64));
        assert_eq!(
            inst["encoded_operands"]["sbx"].as_i64(),
            Some(orig_sbx),
            "signed jump must remain unchanged"
        );
        assert_eq!(
            inst["jump_target"].as_u64(),
            Some(orig_target),
            "jump target must remain unchanged"
        );

        let operands = inst["operands"].as_array().unwrap();
        let op_a = operands
            .iter()
            .find(|o| o["name"].as_str() == Some("A"))
            .expect("operand A");
        assert_eq!(op_a["kind"]["kind"].as_str(), Some("register"));
        assert_eq!(op_a["kind"]["index"].as_u64(), Some(3));
        assert_eq!(op_a["display"].as_str(), Some("R(3)"));

        let op_sbx = operands
            .iter()
            .find(|o| o["name"].as_str() == Some("sBx"))
            .expect("operand sBx");
        assert_eq!(op_sbx["kind"]["value"].as_i64(), Some(orig_sbx));
        assert_eq!(op_sbx["resolved"]["target_pc"].as_u64(), Some(orig_target));
    }
}
