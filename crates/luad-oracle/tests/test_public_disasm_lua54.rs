//! Differential conformance test suite for Gate R6 (Public Lua 5.4.8 Disassembly Conformance).
//!
//! Asserts 3-way differential agreement across all 10 maintained Lua 5.4.8 fixtures between:
//! 1. Official PUC-Rio `luac -l -l` oracle dump (`LuacInstDump`).
//! 2. Independent reference decoder (`IndependentInstruction54`).
//! 3. Production public disassembly record (`DisassembledPrototype` and live `luad disasm` CLI JSON/text).

use luad_core::disasm::{DisassembledPrototype, OperandKind, ResolvedFact};
use luad_core::model::{Chunk, Constant, ConstantValue, InstructionWord, Prototype};
use luad_core::provenance::SourceLocation;
use luad_core::SafeReader;
use luad_dialect_lua54::disassemble_proto_lua54;
use luad_oracle::differential_disasm::{
    compare_chunk_tree_three_way, compare_proto_three_way, DisasmComparisonError, LuacProtoDumpList,
};
use luad_oracle::independent_lua54_oracle::IndependentInstruction54;
use luad_oracle::listing_parser::{parse_luac_dump, LuacDump};
use luad_oracle::{find_workspace_root, require_luac54};
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

const LUA54_FIXTURES: [&str; 10] = [
    "tests/fixtures/precompiled/lua54/hello.luac",
    "tests/fixtures/precompiled/lua54/hello_stripped.luac",
    "tests/fixtures/precompiled/lua54/control_flow.luac",
    "tests/fixtures/precompiled/lua54/control_flow_stripped.luac",
    "tests/fixtures/precompiled/lua54/closures.luac",
    "tests/fixtures/precompiled/lua54/closures_stripped.luac",
    "tests/fixtures/precompiled/lua54/tables.luac",
    "tests/fixtures/precompiled/lua54/tables_stripped.luac",
    "tests/fixtures/precompiled/lua54/numerics.luac",
    "tests/fixtures/precompiled/lua54/numerics_stripped.luac",
];

const PINNED_DISASM_SCHEMA_SHA256: &str =
    "e8166b9c69b8b2c37b9f6d13d9a1bac8dee52291325cfcc46ae8ecf820f28c29";

fn load_fixture(rel_path: &str) -> (Vec<u8>, Chunk, LuacDump) {
    let root = find_workspace_root();
    let abs_path = root.join(rel_path);
    assert!(
        abs_path.exists(),
        "Fixture {} must exist at {:?}",
        rel_path,
        abs_path
    );

    let raw_bytes = fs::read(&abs_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {:?}: {e}", abs_path));
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader)
        .unwrap_or_else(|e| panic!("Failed to parse fixture {:?}: {:?}", abs_path, e));

    let luac54 = require_luac54();
    let output = Command::new(&luac54)
        .args(["-l", "-l", "-p", abs_path.to_str().unwrap()])
        .output()
        .unwrap_or_else(|e| panic!("Failed to run luac -l -l on {:?}: {e}", abs_path));

    let dump_str = String::from_utf8_lossy(&output.stdout);
    let luac_dump = parse_luac_dump(&dump_str)
        .unwrap_or_else(|e| panic!("Failed to parse luac dump for {:?}: {:?}", abs_path, e));

    assert!(
        !root.join("crates/luad-oracle/luac.out").exists()
            && !std::path::Path::new("luac.out").exists(),
        "luac must not drop luac.out into cwd"
    );

    (raw_bytes, chunk, luac_dump)
}

fn get_cli_json_disasm(fixture_rel_path: &str) -> DisassembledPrototype {
    let root = find_workspace_root();
    let luad = luad_oracle::luad_binary_path();
    let abs_path = root.join(fixture_rel_path);

    let output = Command::new(&luad)
        .args(["disasm", abs_path.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap_or_else(|e| panic!("Failed to run luad disasm --format json on {abs_path:?}: {e}"));

    assert!(
        output.status.success(),
        "luad disasm --format json failed on {fixture_rel_path}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc: luad_core::MachineDocument<DisassembledPrototype> =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
            panic!("Failed to deserialize CLI JSON for {fixture_rel_path}: {e}")
        });
    doc.data
}

fn decode_indep_proto(proto: &Prototype) -> Vec<IndependentInstruction54> {
    proto
        .instructions
        .iter()
        .map(|i| IndependentInstruction54::decode(i.raw_word))
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum GoldenMismatchError {
    LineCountMismatch {
        expected: usize,
        actual: usize,
    },
    LineMismatch {
        line_num: usize,
        expected: String,
        actual: String,
    },
}

pub fn compare_disasm_text_to_golden(
    actual: &str,
    golden: &str,
) -> Result<(), GoldenMismatchError> {
    let act_lines: Vec<&str> = actual.lines().collect();
    let exp_lines: Vec<&str> = golden.lines().collect();

    if act_lines.len() != exp_lines.len() {
        return Err(GoldenMismatchError::LineCountMismatch {
            expected: exp_lines.len(),
            actual: act_lines.len(),
        });
    }

    for (idx, (a, e)) in act_lines.iter().zip(exp_lines.iter()).enumerate() {
        if a != e {
            return Err(GoldenMismatchError::LineMismatch {
                line_num: idx + 1,
                expected: (*e).to_string(),
                actual: (*a).to_string(),
            });
        }
    }

    Ok(())
}

#[test]
fn test_three_way_agreement_on_all_10_fixtures() {
    for fixture in LUA54_FIXTURES {
        let (_raw_bytes, chunk, luac_dump) = load_fixture(fixture);
        let cli_json_proto = get_cli_json_disasm(fixture);

        assert!(
            !luac_dump.functions.is_empty(),
            "Fixture {fixture} must have at least main proto in luac dump"
        );

        // Recursively walk and verify every prototype in the entire hierarchy
        compare_chunk_tree_three_way(
            &chunk.main_proto,
            &LuacProtoDumpList {
                functions: &luac_dump.functions,
            },
            &cli_json_proto,
        )
        .unwrap_or_else(|e| {
            panic!(
                "Fixture {fixture} failed recursive 3-way differential agreement with CLI JSON: {:?}",
                e
            )
        });
    }
}

#[test]
fn test_exact_signed_immediate_and_control_flow_goldens() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);
    let cli_json = get_cli_json_disasm("tests/fixtures/precompiled/lua54/control_flow.luac");

    compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        Some(&cli_json),
    )
    .expect("control_flow.luac must satisfy three-way agreement");

    // Directly assert exact instructions at PCs 17-21 in control_flow.luac:
    // PC 17: GTI 1 0 0
    let pc17 = &prod.instructions[17];
    assert_eq!(pc17.mnemonic, "GTI");
    assert_eq!(pc17.encoded_operands.a, 1);
    assert_eq!(pc17.encoded_operands.sb, 0);
    assert_eq!(pc17.encoded_operands.k, 0);
    assert_eq!(
        pc17.operands[1].kind,
        OperandKind::ImmediateSigned { value: 0 }
    );

    // PC 18: JMP 5 ; to 25
    let pc18 = &prod.instructions[18];
    assert_eq!(pc18.mnemonic, "JMP");
    assert_eq!(pc18.encoded_operands.sj, 5);
    assert_eq!(pc18.jump_target, Some(24));
    assert_eq!(pc18.comment.as_deref(), Some("to 25"));

    // PC 19: ADDI 1 1 -5
    let pc19 = &prod.instructions[19];
    assert_eq!(pc19.mnemonic, "ADDI");
    assert_eq!(pc19.encoded_operands.a, 1);
    assert_eq!(pc19.encoded_operands.b, 1);
    assert_eq!(pc19.encoded_operands.sc, -5);
    assert_eq!(
        pc19.operands[2].kind,
        OperandKind::ImmediateSigned { value: -5 }
    );
    assert_eq!(pc19.operands[2].display, "-5");

    // PC 20: MMBINI 1 5 7 0 ; __sub
    let pc20 = &prod.instructions[20];
    assert_eq!(pc20.mnemonic, "MMBINI");
    assert_eq!(pc20.role, "companion");
    assert_eq!(pc20.companion_pc, Some(19));
    assert_eq!(pc20.encoded_operands.a, 1);
    assert_eq!(pc20.encoded_operands.sb, 5);
    assert_eq!(pc20.encoded_operands.c, 7);
    assert_eq!(pc20.metamethod.as_deref(), Some("__sub"));
    assert_eq!(pc20.comment.as_deref(), Some("__sub"));

    // PC 21: EQI 1 15 1
    let pc21 = &prod.instructions[21];
    assert_eq!(pc21.mnemonic, "EQI");
    assert_eq!(pc21.encoded_operands.a, 1);
    assert_eq!(pc21.encoded_operands.sb, 15);
    assert_eq!(pc21.encoded_operands.k, 1);
    assert_eq!(
        pc21.operands[1].kind,
        OperandKind::ImmediateSigned { value: 15 }
    );
}

#[test]
fn test_killer_probe_signed_operand_mutation_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Mutate signed immediate sC at PC 19 (ADDI 1 1 -5 -> ADDI 1 1 5)
    prod.instructions[19].encoded_operands.sc = 5;

    let res = compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        None,
    );
    match res {
        Err(DisasmComparisonError::PhysicalFieldMismatch {
            pc,
            field_name,
            independent_val,
            production_val,
        }) => {
            assert_eq!(pc, 19);
            assert_eq!(field_name, "sC");
            assert_eq!(independent_val, -5);
            assert_eq!(production_val, 5);
        }
        other => panic!("Expected PhysicalFieldMismatch on mutated sC, got: {other:?}"),
    }
}

#[test]
fn test_killer_probe_independent_decoder_mutation_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let prod = disassemble_proto_lua54(&chunk.main_proto);
    let mut indep = decode_indep_proto(&chunk.main_proto);

    // Mutate independent decoder sB field at PC 17 (GTI)
    indep[17].sb = 99;

    let res = compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        None,
    );
    match res {
        Err(DisasmComparisonError::PhysicalFieldMismatch {
            pc,
            field_name,
            independent_val,
            production_val,
        }) => {
            assert_eq!(pc, 17);
            assert_eq!(field_name, "sB");
            assert_eq!(independent_val, 99);
            assert_eq!(production_val, 0);
        }
        other => panic!(
            "Expected PhysicalFieldMismatch on mutated independent decoder sB, got: {other:?}"
        ),
    }
}

#[test]
fn test_killer_probe_missing_jump_target_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Strip resolved jump target from PC 18 (JMP)
    prod.instructions[18].jump_target = None;

    let res = compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        None,
    );
    match res {
        Err(DisasmComparisonError::MissingJumpTarget {
            pc,
            expected_target,
        }) => {
            assert_eq!(pc, 18);
            assert_eq!(expected_target, 24);
        }
        other => panic!("Expected MissingJumpTarget on stripped JMP target, got: {other:?}"),
    }
}

#[test]
fn test_killer_probe_missing_source_line_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Strip line information from PC 0 in unstripped binary
    prod.instructions[0].line = None;

    let res = compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        None,
    );
    match res {
        Err(DisasmComparisonError::MissingSourceLine { pc, expected_line }) => {
            assert_eq!(pc, 0);
            assert_eq!(expected_line, 1);
        }
        other => panic!("Expected MissingSourceLine on stripped line, got: {other:?}"),
    }
}

#[test]
fn test_killer_probe_missing_k_flag_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Clear k flag at PC 21 (EQI 1 15 1 -> k=0)
    prod.instructions[21].encoded_operands.k = 0;

    let res = compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        None,
    );
    match res {
        Err(DisasmComparisonError::PhysicalFieldMismatch {
            pc,
            field_name,
            independent_val,
            production_val,
        }) => {
            assert_eq!(pc, 21);
            assert_eq!(field_name, "k");
            assert_eq!(independent_val, 1);
            assert_eq!(production_val, 0);
        }
        other => panic!("Expected PhysicalFieldMismatch on cleared k flag, got: {other:?}"),
    }
}

#[test]
fn test_killer_probe_missing_resolved_constant_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Strip resolved constant fact from PC 1 (GETTABUP 0 0 0 ; _ENV "print")
    prod.instructions[1].operands[2].resolved = None;

    let res = compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        None,
    );
    match res {
        Err(DisasmComparisonError::MissingResolvedFact {
            pc,
            operand_name,
            fact_type,
        }) => {
            assert_eq!(pc, 1);
            assert_eq!(operand_name, "C");
            assert_eq!(fact_type, "Constant");
        }
        other => {
            panic!("Expected MissingResolvedFact on stripped constant resolution, got: {other:?}")
        }
    }
}

#[test]
fn test_killer_probe_json_mutation_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    let prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    let mut cli_json = get_cli_json_disasm("tests/fixtures/precompiled/lua54/hello.luac");
    // Mutate CLI JSON mnemonic
    cli_json.instructions[0].mnemonic = "MUTATED_GETTABUP".to_string();

    let res = compare_proto_three_way(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep,
        &prod,
        Some(&cli_json),
    );
    match res {
        Err(DisasmComparisonError::JsonMismatch { pc, detail }) => {
            assert_eq!(pc, 0);
            assert!(detail.contains("did not match production"));
        }
        other => panic!("Expected JsonMismatch on mutated CLI JSON, got: {other:?}"),
    }
}

#[test]
fn test_killer_probe_text_renderer_mutation_rejected_by_golden() {
    let root = find_workspace_root();
    let golden_path = root
        .join("tests")
        .join("goldens")
        .join("lua54")
        .join("control_flow.disasm.golden");

    let golden_text = fs::read_to_string(&golden_path)
        .unwrap_or_else(|e| panic!("Failed to read golden {:?}: {e}", golden_path));

    // Mutate golden text
    let mutated_text = golden_text.replace("ADDI         1 1 -5", "ADDI         1 1 5");

    let res = compare_disasm_text_to_golden(&mutated_text, &golden_text);
    match res {
        Err(GoldenMismatchError::LineMismatch {
            line_num,
            expected,
            actual,
        }) => {
            assert!(expected.contains("ADDI         1 1 -5"));
            assert!(actual.contains("ADDI         1 1 5"));
            assert_eq!(line_num, 29);
        }
        other => panic!("Expected LineMismatch on mutated text golden, got: {other:?}"),
    }
}

#[test]
fn test_killer_probe_unknown_opcode_produces_structured_diagnostic() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    let invalid_word: u32 = 83; // Opcode 83 is out of range for Lua 5.4 (0..=82)
    let d_inst =
        luad_dialect_lua54::disassemble_instruction_lua54(&chunk.main_proto, 0, invalid_word);

    assert_eq!(d_inst.mnemonic, "UNKNOWN_0x53");
    assert_eq!(
        d_inst.diagnostics.len(),
        1,
        "Unknown opcode must emit structured diagnostic"
    );
    let diag = &d_inst.diagnostics[0];
    assert_eq!(diag.code, "L54-INVALID-OPCODE");
    assert_eq!(diag.severity, luad_core::diagnostic::Severity::Error);
    assert_eq!(
        diag.category,
        luad_core::diagnostic::DiagnosticCategory::Instruction
    );
}

#[test]
fn test_killer_probe_oob_constant_reference_emits_diagnostic() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    // Formulate a GETTABUP instruction referencing constant index 250 (out of bounds)
    // Opcode Gettabup = 11 (0x0B), A = 0, B = 0, C = 250 (0xFA), k = 0
    let oob_word: u32 = 0x0B | (250 << 24);
    let d_inst = luad_dialect_lua54::disassemble_instruction_lua54(&chunk.main_proto, 0, oob_word);

    assert_eq!(d_inst.mnemonic, "GETTABUP");
    assert_eq!(
        d_inst.diagnostics.len(),
        1,
        "Out of bounds constant must emit structured diagnostic"
    );
    let diag = &d_inst.diagnostics[0];
    assert_eq!(diag.code, "L54-OOB-CONSTANT");
    assert_eq!(diag.severity, luad_core::diagnostic::Severity::Error);
    assert_eq!(
        diag.category,
        luad_core::diagnostic::DiagnosticCategory::Instruction
    );
}

#[test]
fn test_loadkx_extraarg_companion_and_constant_resolution() {
    let path = luad_core::id::ProtoPath::root();
    // Formulate synthetic prototype with LOADKX 0 and EXTRAARG 1
    let dummy_proto = Prototype {
        id: luad_core::id::StableId::proto(path.clone()),
        path: path.clone(),
        source_name: None,
        line_defined: 0,
        last_line_defined: 0,
        numparams: 0,
        is_vararg: 0,
        maxstacksize: 2,
        instructions: vec![
            // PC 0: LOADKX A=0 (opcode 4)
            InstructionWord {
                id: luad_core::id::StableId::instruction(path.clone(), 0),
                pc: 0,
                raw_word: 4,
                raw_hex: "0x00000004".to_string(),
                source: SourceLocation::new(0, &[4, 0, 0, 0]),
            },
            // PC 1: EXTRAARG Ax=1 (opcode 82 = 0x52, Ax=1 << 7)
            InstructionWord {
                id: luad_core::id::StableId::instruction(path.clone(), 1),
                pc: 1,
                raw_word: 0x52 | (1 << 7),
                raw_hex: "0x000000d2".to_string(),
                source: SourceLocation::new(4, &[0xd2, 0, 0, 0]),
            },
        ],
        constants: vec![
            Constant {
                index: 0,
                id: luad_core::id::StableId::constant(path.clone(), 0),
                value: ConstantValue::Integer {
                    val: 100,
                    raw_hex: "0x64".to_string(),
                },
                source: SourceLocation::new(8, &[0]),
            },
            Constant {
                index: 1,
                id: luad_core::id::StableId::constant(path, 1),
                value: ConstantValue::ShortString(luad_core::model::LuaString {
                    display: "extraarg_resolved".to_string(),
                    raw_bytes: b"extraarg_resolved".to_vec(),
                    is_utf8: true,
                }),
                source: SourceLocation::new(12, &[0]),
            },
        ],
        upvalues: vec![],
        protos: vec![],
        line_info: vec![],
        abs_line_info: vec![],
        loc_vars: vec![],
        upvalue_names: vec![],
        source: SourceLocation::new(0, &[]),
    };

    let disasm = disassemble_proto_lua54(&dummy_proto);
    assert_eq!(disasm.instructions.len(), 2);

    // PC 0: LOADKX
    let loadkx = &disasm.instructions[0];
    assert_eq!(loadkx.mnemonic, "LOADKX");
    assert_eq!(loadkx.companion_pc, Some(1));
    assert_eq!(loadkx.operands.len(), 2);
    assert_eq!(loadkx.operands[1].name, "Ax");
    match &loadkx.operands[1].resolved {
        Some(ResolvedFact::Constant {
            index,
            formatted_preview,
            ..
        }) => {
            assert_eq!(*index, 1);
            assert_eq!(formatted_preview, "\"extraarg_resolved\"");
        }
        other => panic!("Expected resolved constant for LOADKX Ax, got: {other:?}"),
    }

    // PC 1: EXTRAARG
    let extraarg = &disasm.instructions[1];
    assert_eq!(extraarg.mnemonic, "EXTRAARG");
    assert_eq!(extraarg.role, "extra_argument");
    assert_eq!(extraarg.companion_pc, Some(0));
}

#[test]
fn test_public_disasm_schema_major_and_hash_pinned() {
    let luad = luad_oracle::luad_binary_path();

    let output = Command::new(&luad)
        .args(["schema", "disasm"])
        .output()
        .expect("luad schema disasm must execute");

    assert!(
        output.status.success(),
        "luad schema disasm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let schema_str = String::from_utf8_lossy(&output.stdout);
    let parsed_schema: serde_json::Value =
        serde_json::from_str(&schema_str).expect("Valid JSON schema");

    // Validate major schema version
    assert_eq!(
        parsed_schema["title"].as_str(),
        Some("MachineDocument_for_DisassembledPrototype"),
        "Schema title must be MachineDocument_for_DisassembledPrototype"
    );

    // Validate pinned SHA-256 schema hash
    let mut hasher = Sha256::new();
    hasher.update(&output.stdout);
    let computed_hash = hex::encode(hasher.finalize());

    assert_eq!(
        computed_hash, PINNED_DISASM_SCHEMA_SHA256,
        "Public disassembly schema hash must match pinned canonical hash"
    );
}

#[test]
fn test_cli_disasm_json_and_text_goldens() {
    let root = find_workspace_root();
    let luad = luad_oracle::luad_binary_path();

    // 1. Full normalized golden check for hello.luac
    let hello_path = root
        .join("tests")
        .join("fixtures")
        .join("precompiled")
        .join("lua54")
        .join("hello.luac");
    let hello_golden_path = root
        .join("tests")
        .join("goldens")
        .join("lua54")
        .join("hello.disasm.golden");
    let expected_hello_golden = fs::read_to_string(&hello_golden_path)
        .unwrap_or_else(|e| panic!("Failed to read golden {:?}: {e}", hello_golden_path));

    let hello_text_output = Command::new(&luad)
        .args(["disasm", hello_path.to_str().unwrap(), "--format", "text"])
        .output()
        .expect("luad disasm --format text execution");
    assert!(hello_text_output.status.success());
    let hello_text = String::from_utf8_lossy(&hello_text_output.stdout);

    compare_disasm_text_to_golden(&hello_text, &expected_hello_golden)
        .expect("hello.luac CLI text disasm must match complete exact golden");

    // 2. Full normalized golden check for control_flow.luac
    let cf_path = root
        .join("tests")
        .join("fixtures")
        .join("precompiled")
        .join("lua54")
        .join("control_flow.luac");
    let cf_golden_path = root
        .join("tests")
        .join("goldens")
        .join("lua54")
        .join("control_flow.disasm.golden");
    let expected_cf_golden = fs::read_to_string(&cf_golden_path)
        .unwrap_or_else(|e| panic!("Failed to read golden {:?}: {e}", cf_golden_path));

    let cf_text_output = Command::new(&luad)
        .args(["disasm", cf_path.to_str().unwrap(), "--format", "text"])
        .output()
        .expect("luad disasm --format text execution");
    assert!(cf_text_output.status.success());
    let cf_text = String::from_utf8_lossy(&cf_text_output.stdout);

    compare_disasm_text_to_golden(&cf_text, &expected_cf_golden)
        .expect("control_flow.luac CLI text disasm must match complete exact golden");
}

#[test]
fn test_cli_explain_never_reports_static_effects_as_fact() {
    let root = find_workspace_root();
    let luad = luad_oracle::luad_binary_path();
    let fixtures = [
        "tests/fixtures/precompiled/lua54/hello.luac",
        "tests/fixtures/precompiled/lua54/control_flow.luac",
    ];

    for fixture in fixtures {
        let abs_path = root.join(fixture);
        let (_bytes, chunk, _dump) = load_fixture(fixture);

        for pc in 0..chunk.main_proto.instructions.len() {
            let output = Command::new(&luad)
                .args([
                    "explain",
                    abs_path.to_str().unwrap(),
                    &format!("proto:0:pc:{pc}"),
                    "--format",
                    "json",
                ])
                .output()
                .expect("luad explain --format json must run");

            assert!(
                output.status.success(),
                "luad explain failed at PC {pc} for {fixture}: {}",
                String::from_utf8_lossy(&output.stderr)
            );

            let json_val: serde_json::Value = serde_json::from_slice(&output.stdout)
                .expect("Valid SemanticInstruction JSON output");

            let confidence = json_val["confidence"]
                .as_str()
                .expect("confidence field must be string");

            assert_ne!(
                confidence.to_lowercase(),
                "fact",
                "luad explain at PC {pc} for {fixture} must NEVER report static effect as fact: got {confidence}"
            );
            assert_eq!(
                confidence.to_lowercase(),
                "reviewed",
                "luad explain at PC {pc} for {fixture} must report reviewed confidence: got {confidence}"
            );
        }
    }
}
