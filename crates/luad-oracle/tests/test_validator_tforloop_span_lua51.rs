//! Independent public regression for Lua 5.1 TFORLOOP register span.

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

fn luad_bin() -> PathBuf {
    luad_oracle::luad_binary_path()
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

fn check_operands(inst: &Json, a: u64, c: u64) {
    let operands = inst["operands"].as_array().unwrap();
    assert_eq!(operands.len(), 2);
    let op_a = operands
        .iter()
        .find(|o| o["name"].as_str() == Some("A"))
        .unwrap();
    assert_eq!(op_a["kind"]["kind"].as_str(), Some("register"));
    assert_eq!(op_a["kind"]["index"].as_u64(), Some(a));
    assert_eq!(op_a["display"].as_str(), Some(format!("R({a})").as_str()));

    let op_c = operands
        .iter()
        .find(|o| o["name"].as_str() == Some("C"))
        .unwrap();
    assert_eq!(op_c["kind"]["kind"].as_str(), Some("immediate-unsigned"));
    assert_eq!(op_c["kind"]["value"].as_u64(), Some(c));
    assert_eq!(op_c["display"].as_str(), Some(format!("{c}").as_str()));
    assert_ne!(op_c["kind"]["kind"].as_str(), Some("register"));

    assert!(
        !operands.iter().any(|o| o["name"].as_str() == Some("B")),
        "B must remain only an encoded physical field"
    );
}

#[test]
fn test_validator_tforloop_span_lua51() {
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

    const PC: usize = 0;
    const OFFSET: usize = 69;
    const TARGET_ID: &str = "proto:0:pc:0";

    let encode_tforloop = |a: u32, b: u32, c: u32| 33u32 | (a << 6) | (c << 14) | (b << 23);
    let valid_word = encode_tforloop(0, 0, 3);
    let invalid_word = encode_tforloop(0, 0, 4);
    assert_eq!(valid_word ^ invalid_word, (4 ^ 3) << 14);

    let assert_disasm_inst = |bytes: &[u8], word: u32, a: u64, c: u64| {
        let disasm_doc = run_luad("disasm", &["--proto", "proto:0"], bytes);
        let inst = find_inst(&disasm_doc, TARGET_ID);
        assert_eq!(inst["id"].as_str(), Some(TARGET_ID));
        assert_eq!(inst["mnemonic"].as_str(), Some("TFORLOOP"));
        assert_eq!(inst["raw_word"].as_u64(), Some(word as u64));
        assert_eq!(
            inst["raw_hex"].as_str(),
            Some(format!("0x{word:08x}").as_str())
        );
        assert_eq!(inst["source"]["byte_offset"].as_u64(), Some(OFFSET as u64));
        assert_eq!(inst["source"]["byte_length"].as_u64(), Some(4));
        assert_eq!(inst["encoded_operands"]["a"].as_u64(), Some(a));
        assert_eq!(inst["encoded_operands"]["b"].as_u64(), Some(0));
        assert_eq!(inst["encoded_operands"]["c"].as_u64(), Some(c));
        check_operands(inst, a, c);
    };

    let mut valid_bytes = base.clone();
    valid_bytes[OFFSET..OFFSET + 4].copy_from_slice(&valid_word.to_le_bytes());
    let valid_val = run_luad("validate", &[], &valid_bytes);
    let valid_diags = valid_val["data"]["diagnostics"].as_array().unwrap();
    assert!(
        !valid_diags
            .iter()
            .any(|d| d["code"].as_str() == Some("L51-REG-SPAN-001")),
        "valid TFORLOOP R(0)..R(5) produces no L51-REG-SPAN-001"
    );
    assert!(
        !valid_diags
            .iter()
            .any(|d| d["code"].as_str() == Some("L51-REG-003")),
        "valid TFORLOOP produces no L51-REG-003"
    );
    assert_disasm_inst(&valid_bytes, valid_word, 0, 3);

    let mut invalid_bytes = base.clone();
    invalid_bytes[OFFSET..OFFSET + 4].copy_from_slice(&invalid_word.to_le_bytes());
    let invalid_val = run_luad("validate", &[], &invalid_bytes);
    let invalid_diags = invalid_val["data"]["diagnostics"].as_array().unwrap();
    let diags: Vec<_> = invalid_diags
        .iter()
        .filter(|d| d["code"].as_str() == Some("L51-REG-SPAN-001"))
        .collect();
    assert_eq!(diags.len(), 1, "expected exactly one L51-REG-SPAN-001");
    assert!(
        !invalid_diags
            .iter()
            .any(|d| d["code"].as_str() == Some("L51-REG-003")),
        "invalid TFORLOOP produces no L51-REG-003"
    );

    let d = diags[0];
    assert_eq!(d["target"].as_str(), Some(TARGET_ID));
    assert_eq!(d["source"]["byte_offset"].as_u64(), Some(OFFSET as u64));
    assert_eq!(d["source"]["byte_length"].as_u64(), Some(4));
    assert_eq!(
        d["source"]["raw_hex"].as_str(),
        Some(hex::encode(invalid_word.to_le_bytes()).as_str())
    );
    let expected_msg = format!(
        "TFORLOOP register window R(0)..R(6) exceeds maxstacksize ({maxstacksize}) at PC {PC}"
    );
    assert_eq!(d["message"].as_str(), Some(expected_msg.as_str()));
    assert_disasm_inst(&invalid_bytes, invalid_word, 0, 4);
}
