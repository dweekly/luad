//! Independent public acceptance for Lua 5.1 conditional RK operand `B`.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use luad_core::diagnostic::{Diagnostic, Verdict};
use luad_core::envelope::{MachineDocument, ValidationResponse};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

type Json = serde_json::Value;

const CONTROL_FLOW: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/control_flow.luac",
    "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40",
);

const BITRK_51: u16 = 256;
const REG_B_CODE: &str = "L51-REG-002";
const CONST_B_CODE: &str = "L51-CONST-004";

/// Ten stock Lua 5.1 opcodes whose B field is conditional RK.
const RK_B_OPS: [(u8, &str); 10] = [
    (9, "SETTABLE"),
    (12, "ADD"),
    (13, "SUB"),
    (14, "MUL"),
    (15, "DIV"),
    (16, "MOD"),
    (17, "POW"),
    (23, "EQ"),
    (24, "LT"),
    (25, "LE"),
];

struct RootProto {
    maxstacksize: u8,
    pc: usize,
    byte_offset: usize,
    constant_count: usize,
}

fn read_root_proto(bytes: &[u8]) -> RootProto {
    assert_eq!(&bytes[0..4], b"\x1bLua", "Lua 5.1 signature");
    let sizeof_int = bytes[7] as usize;
    let sizeof_sizet = bytes[8] as usize;
    let uint = |pos: usize, width: usize| -> usize {
        let mut val = 0_u64;
        for i in 0..width {
            val |= u64::from(bytes[pos + i]) << (i * 8);
        }
        val as usize
    };
    let mut pos = 12;
    let source_len = uint(pos, sizeof_sizet);
    pos += sizeof_sizet + source_len + 2 * sizeof_int + 3;
    let maxstacksize = bytes[pos];
    pos += 1;
    let inst_count = uint(pos, sizeof_int);
    pos += sizeof_int;
    let code_offset = pos;
    pos += 4 * inst_count;
    let constant_count = uint(pos, sizeof_int);

    RootProto {
        maxstacksize,
        pc: 0,
        byte_offset: code_offset,
        constant_count,
    }
}

fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (u32::from(c) << 14) | (u32::from(b) << 23)
}

fn root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
        let output = Command::new(luad_bin())
            .args(["schema", command])
            .output()
            .expect("schema CLI");
        let schema: Json = serde_json::from_slice(&output.stdout).unwrap();
        jsonschema::validator_for(&schema).unwrap()
    })
}

fn run_luad(command: &str, bytes: &[u8]) -> Vec<u8> {
    let file = NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    let output = Command::new(luad_bin())
        .args([
            command,
            file.path().to_str().unwrap(),
            "--dialect",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let doc: Json = serde_json::from_slice(&output.stdout).expect("valid JSON stdout");
    let errors: Vec<_> = schema_validator(command)
        .iter_errors(&doc)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "live schema validation failed: {errors:?}"
    );
    output.stdout
}

fn validate_bytes(bytes: &[u8]) -> MachineDocument<ValidationResponse> {
    serde_json::from_slice(&run_luad("validate", bytes)).unwrap()
}

fn disasm_bytes(bytes: &[u8]) -> Json {
    serde_json::from_slice(&run_luad("disasm", bytes)).unwrap()
}

fn derive(base: &[u8], offset: usize, word: u32) -> Vec<u8> {
    let mut bytes = base.to_vec();
    bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    bytes
}

fn zero_constant_chunk(word: u32, maxstacksize: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00");
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);
    bytes.push(maxstacksize);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&word.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

fn find_inst(v: &Json, pc: u64) -> &Json {
    fn walk(v: &Json, pc: u64) -> Option<&Json> {
        if v.get("opcode_num").is_some() && v.get("pc").and_then(Json::as_u64) == Some(pc) {
            return Some(v);
        }
        match v {
            Json::Object(m) => m.values().find_map(|n| walk(n, pc)),
            Json::Array(a) => a.iter().find_map(|n| walk(n, pc)),
            _ => None,
        }
    }
    walk(v, pc).expect("instruction at PC")
}

fn operand_b(inst: &Json) -> &Json {
    inst["operands"]
        .as_array()
        .expect("operands array")
        .iter()
        .find(|op| op["name"].as_str() == Some("B"))
        .expect("operand B")
}

fn findings<'a>(doc: &'a MachineDocument<ValidationResponse>, code: &str) -> Vec<&'a Diagnostic> {
    doc.data
        .diagnostics
        .iter()
        .filter(|d| d.code == code)
        .collect()
}

fn pinned_base() -> (Vec<u8>, RootProto) {
    let base = std::fs::read(root().join(CONTROL_FLOW.0)).expect("pinned base fixture");
    assert_eq!(sha256(&base), CONTROL_FLOW.1);
    let proto = read_root_proto(&base);
    (base, proto)
}

#[test]
fn test_rk_b_four_boundaries_and_domain_selection() {
    let (base, proto) = pinned_base();
    let maxstack = proto.maxstacksize;
    let k_count = proto.constant_count;
    assert!(maxstack >= 2);
    assert!(k_count >= 1);

    for (op, name) in RK_B_OPS {
        // Boundary 1: B = maxstacksize - 1 (typed register, clean)
        let b1 = u16::from(maxstack - 1);
        let chunk1 = derive(&base, proto.byte_offset, iabc(op, 0, b1, 0));
        let doc1 = validate_bytes(&chunk1);
        assert_eq!(
            doc1.data.verdict,
            Verdict::ValidForParser,
            "{name} B={b1} must be ValidForParser: {:?}",
            doc1.data.diagnostics
        );
        assert!(
            findings(&doc1, REG_B_CODE).is_empty(),
            "{name} B={b1} must produce no {REG_B_CODE}"
        );
        let dis1 = disasm_bytes(&chunk1);
        let inst1 = find_inst(&dis1, proto.pc as u64);
        assert_eq!(inst1["mnemonic"].as_str(), Some(name));
        let op_b1 = operand_b(inst1);
        assert_eq!(op_b1["kind"]["kind"].as_str(), Some("register"));
        assert_eq!(op_b1["kind"]["index"].as_u64(), Some(u64::from(b1)));

        // Boundary 2: B = maxstacksize (typed register, exactly one L51-REG-002)
        let b2 = u16::from(maxstack);
        let chunk2 = derive(&base, proto.byte_offset, iabc(op, 0, b2, 0));
        let doc2 = validate_bytes(&chunk2);
        assert_eq!(doc2.data.verdict, Verdict::Invalid);
        let reg_diags2 = findings(&doc2, REG_B_CODE);
        assert_eq!(
            reg_diags2.len(),
            1,
            "{name} B={b2} must report exactly one {REG_B_CODE}: {:?}",
            doc2.data.diagnostics
        );
        assert_eq!(
            reg_diags2[0].message,
            format!(
                "Register B ({b2}) exceeds maxstacksize ({maxstack}) at PC {}",
                proto.pc
            )
        );
        assert!(findings(&doc2, CONST_B_CODE).is_empty());
        let dis2 = disasm_bytes(&chunk2);
        let inst2 = find_inst(&dis2, proto.pc as u64);
        assert_eq!(inst2["mnemonic"].as_str(), Some(name));
        let op_b2 = operand_b(inst2);
        assert_eq!(op_b2["kind"]["kind"].as_str(), Some("register"));
        assert_eq!(op_b2["kind"]["index"].as_u64(), Some(u64::from(b2)));

        // Boundary 3: B = BITRK | (constants.len() - 1) (typed resolved constant, clean)
        let k_idx3 = (k_count - 1) as u16;
        let b3 = BITRK_51 | k_idx3;
        let chunk3 = derive(&base, proto.byte_offset, iabc(op, 0, b3, 0));
        let doc3 = validate_bytes(&chunk3);
        assert_eq!(
            doc3.data.verdict,
            Verdict::ValidForParser,
            "{name} B={b3} must be ValidForParser: {:?}",
            doc3.data.diagnostics
        );
        assert!(
            findings(&doc3, CONST_B_CODE).is_empty(),
            "{name} B={b3} must produce no {CONST_B_CODE}"
        );
        assert!(findings(&doc3, REG_B_CODE).is_empty());
        let dis3 = disasm_bytes(&chunk3);
        let inst3 = find_inst(&dis3, proto.pc as u64);
        assert_eq!(inst3["mnemonic"].as_str(), Some(name));
        let op_b3 = operand_b(inst3);
        assert_eq!(op_b3["kind"]["kind"].as_str(), Some("immediate-unsigned"));
        assert_eq!(op_b3["kind"]["value"].as_u64(), Some(u64::from(b3)));
        assert_eq!(op_b3["resolved"]["type"].as_str(), Some("constant"));
        assert_eq!(op_b3["resolved"]["index"].as_u64(), Some(u64::from(k_idx3)));

        // Boundary 4: B = BITRK | constants.len() (typed selected constant, exactly one L51-CONST-004)
        let k_idx4 = k_count as u16;
        let b4 = BITRK_51 | k_idx4;
        let chunk4 = derive(&base, proto.byte_offset, iabc(op, 0, b4, 0));
        let doc4 = validate_bytes(&chunk4);
        assert_eq!(doc4.data.verdict, Verdict::Invalid);
        let const_diags4 = findings(&doc4, CONST_B_CODE);
        assert_eq!(
            const_diags4.len(),
            1,
            "{name} B={b4} must report exactly one {CONST_B_CODE}: {:?}",
            doc4.data.diagnostics
        );
        assert_eq!(
            const_diags4[0].message,
            format!(
                "RK operand B constant index {k_idx4} out of bounds (total constants: {k_count})"
            )
        );
        assert!(findings(&doc4, REG_B_CODE).is_empty());
        let dis4 = disasm_bytes(&chunk4);
        let inst4 = find_inst(&dis4, proto.pc as u64);
        assert_eq!(inst4["mnemonic"].as_str(), Some(name));
        let op_b4 = operand_b(inst4);
        assert_eq!(op_b4["kind"]["kind"].as_str(), Some("immediate-unsigned"));
        assert_eq!(op_b4["kind"]["value"].as_u64(), Some(u64::from(b4)));
        assert!(op_b4["resolved"].is_null());
    }
}

#[test]
fn test_rk_b_zero_constant_owner() {
    for (op, name) in RK_B_OPS {
        let b = BITRK_51; // B = BITRK | 0 against 0 constants
        let chunk = zero_constant_chunk(iabc(op, 0, b, 0), 2);
        let doc = validate_bytes(&chunk);
        assert_eq!(doc.data.verdict, Verdict::Invalid);
        let const_diags = findings(&doc, CONST_B_CODE);
        assert_eq!(
            const_diags.len(),
            1,
            "{name} in 0-constant proto must report exactly one {CONST_B_CODE}"
        );
        assert_eq!(
            const_diags[0].message,
            "RK operand B constant index 0 out of bounds (total constants: 0)"
        );
        assert!(
            findings(&doc, REG_B_CODE).is_empty(),
            "{name} in 0-constant proto must produce no {REG_B_CODE}"
        );
    }
}

#[test]
fn test_high_bit_scalar_control_does_not_enter_constant_domain() {
    // NEWTABLE.B is a scalar size hint with no register-window meaning.
    let newtable = validate_bytes(&zero_constant_chunk(iabc(10, 0, 256, 0), 2));
    assert_eq!(newtable.data.verdict, Verdict::ValidForParser);
    assert!(findings(&newtable, CONST_B_CODE).is_empty());
    assert!(findings(&newtable, REG_B_CODE).is_empty());

    // CALL.B is a scalar count whose semantic window can exceed the register file.
    let call = validate_bytes(&zero_constant_chunk(iabc(28, 0, 256, 0), 2));
    assert_eq!(call.data.verdict, Verdict::Invalid);
    assert!(findings(&call, CONST_B_CODE).is_empty());
    assert!(findings(&call, REG_B_CODE).is_empty());
    let spans: Vec<_> = call
        .data
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "L51-REG-SPAN-001")
        .collect();
    assert_eq!(spans.len(), 1);
    assert_eq!(
        spans[0].message,
        "CALL register window R(0)..R(255) exceeds maxstacksize (2) at PC 0"
    );

    // MOVE (op 0): fixed register -> reports L51-REG-002, never L51-CONST-004
    let chunk_move = zero_constant_chunk(iabc(0, 0, 256, 0), 2);
    let doc_move = validate_bytes(&chunk_move);
    assert_eq!(doc_move.data.verdict, Verdict::Invalid);
    let reg_move = findings(&doc_move, REG_B_CODE);
    assert_eq!(reg_move.len(), 1, "MOVE B=256 must report L51-REG-002");
    assert_eq!(
        reg_move[0].message,
        "Register B (256) exceeds maxstacksize (2) at PC 0"
    );
    assert!(findings(&doc_move, CONST_B_CODE).is_empty());
}
