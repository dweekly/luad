//! Independent public regression for Lua 5.1 closure-capture source bounds.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

type Json = serde_json::Value;

const FIXTURE: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/closures.luac",
    "62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e",
);

const fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    (op as u32) | ((a as u32) << 6) | ((c as u32) << 14) | ((b as u32) << 23)
}

struct Probe {
    proto_id: &'static str,
    pc: u64,
    target_id: &'static str,
    byte_offset: usize,
    word: u32,
    diag_code: &'static str,
    mnemonic: &'static str,
    companion_pc: u64,
    source_kind: &'static str,
    source_value_field: &'static str,
    source_display: &'static str,
    source_raw: u64,
}

const PROBES: [Probe; 2] = [
    Probe {
        proto_id: "proto:0/0/0",
        pc: 7,
        target_id: "proto:0/0/0:pc:7",
        byte_offset: 260,
        word: iabc(4, 0, 1, 0),
        diag_code: "L51-UPVAL-001",
        mnemonic: "GETUPVAL (binding descriptor)",
        companion_pc: 6,
        source_kind: "immediate-unsigned",
        source_value_field: "value",
        source_display: "parent upvalue[1]",
        source_raw: 1,
    },
    Probe {
        proto_id: "proto:0/0",
        pc: 4,
        target_id: "proto:0/0:pc:4",
        byte_offset: 179,
        word: iabc(0, 0, 3, 0),
        diag_code: "L51-REG-002",
        mnemonic: "MOVE (binding descriptor)",
        companion_pc: 3,
        source_kind: "register",
        source_value_field: "index",
        source_display: "parent R(3)",
        source_raw: 3,
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

fn run_luad(command: &str, extra_args: &[&str], bytes: &[u8]) -> Vec<u8> {
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
    output.stdout
}

fn derive(base: &[u8], offset: usize, word: u32) -> Vec<u8> {
    let mut bytes = base.to_vec();
    bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    bytes
}

fn find_json_node<'a>(v: &'a Json, key: &str, val: &str) -> Option<&'a Json> {
    if v.get(key).and_then(Json::as_str) == Some(val) {
        return Some(v);
    }
    match v {
        Json::Object(map) => map
            .values()
            .find_map(|child| find_json_node(child, key, val)),
        Json::Array(arr) => arr.iter().find_map(|child| find_json_node(child, key, val)),
        _ => None,
    }
}

#[test]
fn test_validator_closure_capture_bounds_lua51() {
    let base_path = luad_oracle::find_workspace_root().join(FIXTURE.0);
    let base = std::fs::read(&base_path).expect("read fixture");
    let mut hasher = Sha256::new();
    hasher.update(&base);
    assert_eq!(hex::encode(hasher.finalize()), FIXTURE.1);

    let inspect_raw = run_luad("inspect", &[], &base);
    let inspect_doc: Json = serde_json::from_slice(&inspect_raw).unwrap();
    let p_parent = find_json_node(&inspect_doc, "id", "proto:0/0").expect("proto:0/0");
    let p_child = find_json_node(&inspect_doc, "id", "proto:0/0/0").expect("proto:0/0/0");
    assert_eq!(p_parent["maxstacksize"].as_u64(), Some(3));
    assert_eq!(p_child["maxstacksize"].as_u64(), Some(4));
    assert_eq!(p_child["upvalues"].as_array().map(Vec::len), Some(1));
    let p_grandchild = find_json_node(&inspect_doc, "id", "proto:0/0/0/0").expect("proto:0/0/0/0");
    assert_eq!(p_grandchild["upvalues"].as_array().map(Vec::len), Some(1));

    for probe in &PROBES {
        let mutated = derive(&base, probe.byte_offset, probe.word);
        let val_raw = run_luad("validate", &[], &mutated);
        let val_doc: Json = serde_json::from_slice(&val_raw).unwrap();
        let diags = val_doc["data"]["diagnostics"]
            .as_array()
            .expect("diagnostics array");
        assert_eq!(
            diags.len(),
            1,
            "{} expected exactly one diagnostic",
            probe.target_id
        );
        let d = &diags[0];
        assert_eq!(d["code"].as_str(), Some(probe.diag_code));
        assert_eq!(d["target"].as_str(), Some(probe.target_id));
        let src = &d["source"];
        assert_eq!(src["byte_offset"].as_u64(), Some(probe.byte_offset as u64));
        assert_eq!(src["byte_length"].as_u64(), Some(4));
        assert_eq!(
            src["raw_hex"].as_str(),
            Some(hex::encode(probe.word.to_le_bytes()).as_str())
        );

        let disasm_raw = run_luad("disasm", &["--proto", probe.proto_id], &mutated);
        let disasm_doc: Json = serde_json::from_slice(&disasm_raw).unwrap();
        let inst =
            find_json_node(&disasm_doc, "id", probe.target_id).expect("descriptor instruction");
        assert_eq!(inst["pc"].as_u64(), Some(probe.pc));
        assert_eq!(inst["role"].as_str(), Some("closure_binding"));
        assert_eq!(inst["mnemonic"].as_str(), Some(probe.mnemonic));
        assert_eq!(inst["companion_pc"].as_u64(), Some(probe.companion_pc));

        let ops = inst["operands"].as_array().expect("operands array");
        let dst = ops
            .iter()
            .find(|o| o["name"].as_str() == Some("upvalue_index"))
            .expect("destination operand");
        assert_eq!(dst["display"].as_str(), Some("upvalue[0]"));
        assert_eq!(dst["kind"]["value"].as_u64(), Some(0));

        let src_op = ops
            .iter()
            .find(|o| o["name"].as_str() == Some("source"))
            .expect("source operand");
        assert_eq!(src_op["kind"]["kind"].as_str(), Some(probe.source_kind));
        assert_eq!(
            src_op["kind"][probe.source_value_field].as_u64(),
            Some(probe.source_raw)
        );
        assert_eq!(src_op["display"].as_str(), Some(probe.source_display));
        assert!(src_op.get("resolved").is_none() || src_op["resolved"].is_null());
    }
}
