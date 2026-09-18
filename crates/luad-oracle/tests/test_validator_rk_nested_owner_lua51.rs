//! Independent public regression for Lua 5.1 nested RK operand owner isolation.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use luad_core::envelope::{MachineDocument, ValidationResponse};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

type Json = serde_json::Value;

const FIXTURE: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/closures.luac",
    "62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e",
);
const TARGET_OFFSET: usize = 163;
const TARGET_ID: &str = "proto:0/0:pc:0";
const BITRK_51: u16 = 256;
const OP_ADD: u8 = 12;

const fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    (op as u32) | ((a as u32) << 6) | ((c as u32) << 14) | ((b as u32) << 23)
}

type RkCase = (
    &'static str,
    u32,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    u64,
);

const CASES: [RkCase; 4] = [
    (
        "clear_bit_b_reg3",
        iabc(OP_ADD, 0, 3, 0),
        "L51-REG-002",
        "B",
        "R(3)",
        "register",
        3,
    ),
    (
        "clear_bit_c_reg3",
        iabc(OP_ADD, 0, 0, 3),
        "L51-REG-003",
        "C",
        "R(3)",
        "register",
        3,
    ),
    (
        "selected_b_const1",
        iabc(OP_ADD, 0, BITRK_51 | 1, 0),
        "L51-CONST-004",
        "B",
        "K(1)",
        "immediate-unsigned",
        257,
    ),
    (
        "selected_c_const1",
        iabc(OP_ADD, 0, 0, BITRK_51 | 1),
        "L51-CONST-005",
        "C",
        "K(1)",
        "immediate-unsigned",
        257,
    ),
];

fn root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

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

fn find_inst(v: &Json, pc: u64) -> &Json {
    let insts = v
        .get("data")
        .and_then(|d| d.get("instructions"))
        .or_else(|| v.get("instructions"))
        .and_then(Json::as_array)
        .expect("instructions array");
    insts
        .iter()
        .find(|i| i.get("pc").and_then(Json::as_u64) == Some(pc))
        .expect("inst at pc")
}

fn find_operand<'a>(inst: &'a Json, name: &str) -> &'a Json {
    inst["operands"]
        .as_array()
        .expect("operands array")
        .iter()
        .find(|op| op["name"].as_str() == Some(name))
        .expect("operand")
}

fn proto_bounds(doc: &Json, target_id: &str) -> (u64, usize) {
    fn find_proto<'a>(v: &'a Json, id: &str) -> Option<&'a Json> {
        if v.get("id").and_then(Json::as_str) == Some(id) {
            return Some(v);
        }
        match v {
            Json::Object(m) => m.values().find_map(|n| find_proto(n, id)),
            Json::Array(a) => a.iter().find_map(|n| find_proto(n, id)),
            _ => None,
        }
    }
    let p = find_proto(doc, target_id).expect("prototype in inspect JSON");
    let maxstack = p["maxstacksize"].as_u64().expect("maxstacksize");
    let consts = p["constants"].as_array().expect("constants").len();
    (maxstack, consts)
}

#[test]
fn test_validator_rk_nested_owner_lua51() {
    let fixture_bytes = std::fs::read(root().join(FIXTURE.0)).expect("read fixture");
    let actual_hash = hex::encode(Sha256::digest(&fixture_bytes));
    assert_eq!(actual_hash, FIXTURE.1, "pinned fixture hash mismatch");

    let inspect_out = run_luad("inspect", &[], &fixture_bytes);
    let inspect_doc: Json = serde_json::from_slice(&inspect_out).expect("inspect json");

    let (root_maxstack, root_consts) = proto_bounds(&inspect_doc, "proto:0");
    assert_eq!(root_maxstack, 6, "root maxstack must be 6");
    assert_eq!(root_consts, 2, "root constants count must be 2");

    let (child_maxstack, child_consts) = proto_bounds(&inspect_doc, "proto:0/0");
    assert_eq!(child_maxstack, 3, "child maxstack must be 3");
    assert_eq!(child_consts, 1, "child constants count must be 1");

    for &(name, word, code, operand_name, display, kind, value) in &CASES {
        let mutated = derive(&fixture_bytes, TARGET_OFFSET, word);
        let val_out = run_luad("validate", &[], &mutated);
        let val_doc: MachineDocument<ValidationResponse> =
            serde_json::from_slice(&val_out).unwrap();

        assert_eq!(val_doc.data.diagnostics.len(), 1, "{name}");
        let diag = &val_doc.data.diagnostics[0];
        assert_eq!(diag.code, code, "{name}");
        assert_eq!(diag.target.to_string(), TARGET_ID, "{name}");

        let src = diag
            .source
            .as_ref()
            .expect("diagnostic source location present");
        assert_eq!(src.byte_offset, TARGET_OFFSET, "{name}");
        assert_eq!(src.byte_length, 4, "{name}");
        assert_eq!(
            src.raw_hex,
            hex::encode(&mutated[TARGET_OFFSET..TARGET_OFFSET + 4]),
            "{name}"
        );

        let disasm_out = run_luad("disasm", &["--proto", "proto:0/0"], &mutated);
        let disasm_doc: Json = serde_json::from_slice(&disasm_out).expect("disasm json");

        let inst = find_inst(&disasm_doc, 0);
        assert_eq!(inst["mnemonic"].as_str(), Some("ADD"), "{name}");

        let op = find_operand(inst, operand_name);
        assert_eq!(op["display"].as_str(), Some(display), "{name}");
        assert_eq!(op["kind"]["kind"].as_str(), Some(kind), "{name}");
        let raw_value = if kind == "register" {
            op["kind"]["index"].as_u64()
        } else {
            op["kind"]["value"].as_u64()
        };
        assert_eq!(raw_value, Some(value), "{name}");
        assert!(op.get("resolved").is_none(), "{name}");

        let other_name = if operand_name == "B" { "C" } else { "B" };
        let other_op = find_operand(inst, other_name);
        assert_eq!(other_op["display"].as_str(), Some("R(0)"), "{name}");
    }
}
