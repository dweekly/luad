//! Differential conformance test suite for Gate R6 (Public Lua 5.4.8 Disassembly Conformance).
//!
//! Asserts 3-way differential agreement across all 10 maintained Lua 5.4.8 fixtures between:
//! 1. Official PUC-Rio `luac -l -l` oracle dump (`LuacInstDump`).
//! 2. Independent reference decoder (`IndependentInstruction54`).
//! 3. Production public disassembly record (`DisassembledPrototype` and `luad disasm` CLI JSON/text).

use luad_core::disasm::{DisassembledPrototype, OperandKind};

use luad_core::model::{Chunk, Prototype};
use luad_dialect_lua54::disassemble_proto_lua54;
use luad_oracle::differential_disasm::{compare_proto_three_way, DisasmComparisonError};
use luad_oracle::independent_lua54_oracle::{IndependentInstruction54, IndependentOpcode54};
use luad_oracle::listing_parser::{parse_luac_dump, LuacDump};
use luad_oracle::{find_workspace_root, require_luac54};
use std::fs;
use std::path::Path;

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

fn load_fixture(rel_path: &str) -> (Vec<u8>, Chunk, LuacDump) {
    let luac_path = require_luac54();
    let root = find_workspace_root();
    let full_path = Path::new(&root).join(rel_path);

    let raw_bytes =
        fs::read(&full_path).unwrap_or_else(|e| panic!("Failed to read fixture {rel_path}: {e}"));
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader)
        .unwrap_or_else(|e| panic!("Failed to decode fixture {rel_path}: {e:?}"));

    let output = std::process::Command::new(&luac_path)
        .arg("-l")
        .arg("-l")
        .arg(&full_path)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute luac on {rel_path}: {e}"));
    assert!(
        output.status.success(),
        "luac -l -l failed on {rel_path}: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let dump_str = String::from_utf8_lossy(&output.stdout);
    let luac_dump = parse_luac_dump(&dump_str)
        .unwrap_or_else(|e| panic!("Failed to parse luac dump for {rel_path}: {e}"));

    (raw_bytes, chunk, luac_dump)
}

fn decode_indep_proto(proto: &Prototype) -> Vec<IndependentInstruction54> {
    proto
        .instructions
        .iter()
        .map(|i| IndependentInstruction54::decode(i.raw_word))
        .collect()
}

fn flatten_disasm<'a>(proto: &'a DisassembledPrototype, out: &mut Vec<&'a DisassembledPrototype>) {
    out.push(proto);
    for child in &proto.child_protos {
        flatten_disasm(child, out);
    }
}

fn flatten_chunk<'a>(proto: &'a Prototype, out: &mut Vec<&'a Prototype>) {
    out.push(proto);
    for child in &proto.protos {
        flatten_chunk(child, out);
    }
}

#[test]
fn test_three_way_agreement_on_all_10_fixtures() {
    for fixture_path in LUA54_FIXTURES {
        let (_raw_bytes, chunk, luac_dump) = load_fixture(fixture_path);
        let prod_proto = disassemble_proto_lua54(&chunk.main_proto);

        let mut disasm_list = Vec::new();
        flatten_disasm(&prod_proto, &mut disasm_list);

        let mut chunk_list = Vec::new();
        flatten_chunk(&chunk.main_proto, &mut chunk_list);

        assert_eq!(
            luac_dump.functions.len(),
            disasm_list.len(),
            "Prototype count mismatch on {fixture_path}"
        );

        for (i, luac_fn) in luac_dump.functions.iter().enumerate() {
            let indep_insts = decode_indep_proto(chunk_list[i]);
            compare_proto_three_way(luac_fn, &indep_insts, disasm_list[i], None).unwrap_or_else(
                |e| {
                    panic!(
                        "Three-way comparison failure on fixture {fixture_path} proto {i}: {e:?}"
                    )
                },
            );
        }
    }
}

#[test]
fn test_exact_signed_immediate_and_control_flow_goldens() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    compare_proto_three_way(&luac_dump.functions[0], &indep, &prod, None)
        .expect("control_flow.luac must satisfy three-way agreement");

    // 1. ADDI signed immediate: ADDI 0 0 1
    let addi = prod
        .instructions
        .iter()
        .find(|i| i.mnemonic == "ADDI")
        .expect("Must have ADDI");
    assert_eq!(addi.encoded_operands.a, 0);
    assert_eq!(addi.encoded_operands.b, 0);
    assert_eq!(addi.encoded_operands.sc, 1);
    assert_eq!(
        addi.operands[2].kind,
        OperandKind::ImmediateSigned { value: 1 }
    );
    assert_eq!(addi.operands[2].display, "1");

    // 2. GTI signed immediate: GTI 0 5 0
    let gti = prod
        .instructions
        .iter()
        .find(|i| i.mnemonic == "GTI")
        .expect("Must have GTI");
    assert_eq!(gti.encoded_operands.a, 0);
    assert_eq!(gti.encoded_operands.sb, 5);
    assert_eq!(gti.encoded_operands.k, 0);
    assert_eq!(
        gti.operands[1].kind,
        OperandKind::ImmediateSigned { value: 5 }
    );

    // 3. MMBINI metamethod: MMBINI 0 1 6 0 ; __add
    let mmbini = prod
        .instructions
        .iter()
        .find(|i| i.mnemonic == "MMBINI")
        .expect("Must have MMBINI");
    assert_eq!(mmbini.encoded_operands.sb, 1);
    assert_eq!(mmbini.encoded_operands.c, 6);
    assert_eq!(mmbini.metamethod.as_deref(), Some("__add"));
    assert_eq!(mmbini.comment.as_deref(), Some("__add"));

    // 4. EQI signed immediate: EQI 1 15 1
    let eqi = prod
        .instructions
        .iter()
        .find(|i| i.mnemonic == "EQI")
        .expect("Must have EQI");
    assert_eq!(eqi.encoded_operands.sb, 15);
    assert_eq!(eqi.encoded_operands.k, 1);

    // 5. JMP jump destination resolution
    let jmp = prod
        .instructions
        .iter()
        .find(|i| i.mnemonic == "JMP")
        .expect("Must have JMP");
    let target = jmp.jump_target.expect("JMP must have resolved jump target");
    assert_eq!(
        target,
        (jmp.pc as i32 + 1 + jmp.encoded_operands.sj) as usize
    );
}

#[test]
fn test_killer_probe_signed_operand_mutation_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Find ADDI instruction and mutate its production signed immediate
    let addi_idx = prod
        .instructions
        .iter()
        .position(|i| i.mnemonic == "ADDI")
        .expect("Must have ADDI");
    prod.instructions[addi_idx].encoded_operands.sc = 999;
    prod.instructions[addi_idx].operands[2].display = "999".to_string();

    let res = compare_proto_three_way(&luac_dump.functions[0], &indep, &prod, None);
    assert!(
        matches!(
            res,
            Err(DisasmComparisonError::PhysicalFieldMismatch { pc, ref field_name, .. })
                if pc == addi_idx && field_name == "sC"
        ) || matches!(
            res,
            Err(DisasmComparisonError::OperandDisplayMismatch { pc, .. }) if pc == addi_idx
        ),
        "Comparator must reject mutated signed operand: got {res:?}"
    );
}

#[test]
fn test_killer_probe_independent_decoder_mutation_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let prod = disassemble_proto_lua54(&chunk.main_proto);
    let mut indep = decode_indep_proto(&chunk.main_proto);

    // Mutate independent decoder's sB field on GTI instruction
    let gti_idx = indep
        .iter()
        .position(|i| i.opcode == Some(IndependentOpcode54::Gti))
        .expect("Must have GTI");
    indep[gti_idx].sb = 777;

    let res = compare_proto_three_way(&luac_dump.functions[0], &indep, &prod, None);
    assert!(
        matches!(
            res,
            Err(DisasmComparisonError::PhysicalFieldMismatch { pc, ref field_name, .. })
                if pc == gti_idx && field_name == "sB"
        ),
        "Comparator must reject mutated independent decoder: got {res:?}"
    );
}

#[test]
fn test_killer_probe_missing_jump_target_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Find JMP and strip its jump target
    let jmp_idx = prod
        .instructions
        .iter()
        .position(|i| i.mnemonic == "JMP")
        .expect("Must have JMP");
    prod.instructions[jmp_idx].jump_target = None;

    let res = compare_proto_three_way(&luac_dump.functions[0], &indep, &prod, None);
    assert!(
        matches!(
            res,
            Err(DisasmComparisonError::MissingJumpTarget { pc, .. }) if pc == jmp_idx
        ),
        "Comparator must reject missing jump target: got {res:?}"
    );
}

#[test]
fn test_killer_probe_missing_source_line_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // hello.luac has debug line info; strip line for PC 0
    prod.instructions[0].line = None;

    let res = compare_proto_three_way(&luac_dump.functions[0], &indep, &prod, None);
    assert!(
        matches!(
            res,
            Err(DisasmComparisonError::MissingSourceLine { pc: 0, .. })
        ),
        "Comparator must reject missing source line on debug chunk: got {res:?}"
    );
}

#[test]
fn test_killer_probe_missing_k_flag_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Find EQI (which has k=1) and flip k to 0
    let eqi_idx = prod
        .instructions
        .iter()
        .position(|i| i.mnemonic == "EQI")
        .expect("Must have EQI");
    prod.instructions[eqi_idx].encoded_operands.k = 0;

    let res = compare_proto_three_way(&luac_dump.functions[0], &indep, &prod, None);
    assert!(
        matches!(
            res,
            Err(DisasmComparisonError::PhysicalFieldMismatch { pc, ref field_name, .. })
                if pc == eqi_idx && field_name == "k"
        ),
        "Comparator must reject missing k flag: got {res:?}"
    );
}

#[test]
fn test_killer_probe_json_mutation_rejected_by_comparator() {
    let (_raw_bytes, chunk, luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let prod = disassemble_proto_lua54(&chunk.main_proto);
    let indep = decode_indep_proto(&chunk.main_proto);

    // Serialize production record to JSON string
    let mut json_val = serde_json::to_value(&prod).expect("Valid JSON serialization");

    // Tamper with an instruction in JSON
    json_val["instructions"][1]["mnemonic"] = serde_json::json!("TAMPERED_OP");

    let tampered_proto: DisassembledPrototype =
        serde_json::from_value(json_val).expect("Valid structure deserialization");

    let res = compare_proto_three_way(
        &luac_dump.functions[0],
        &indep,
        &prod,
        Some(&tampered_proto),
    );
    assert!(
        matches!(res, Err(DisasmComparisonError::JsonMismatch { pc: 1, .. })),
        "Comparator must reject tampered JSON record: got {res:?}"
    );
}

#[test]
fn test_killer_probe_text_renderer_mutation_rejected_by_golden() {
    let (_raw_bytes, chunk, _luac_dump) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let prod = disassemble_proto_lua54(&chunk.main_proto);

    // Render production instructions to text lines
    let rendered_lines: Vec<String> = prod
        .instructions
        .iter()
        .map(|i| {
            let ops_str = i
                .operands
                .iter()
                .map(|o| o.display.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let comment_suffix = i
                .comment
                .as_ref()
                .map(|c| format!(" ; {c}"))
                .unwrap_or_default();
            format!("{} {ops_str}{comment_suffix}", i.mnemonic)
        })
        .collect();

    // Verify correct text contains ADDI 0 0 1
    assert!(rendered_lines.iter().any(|l| l.contains("ADDI 0 0 1")));

    // Mutate text line
    let mut mutated_lines = rendered_lines.clone();
    mutated_lines[1] = "ADDI 0 0 -99".to_string();

    assert_ne!(
        rendered_lines, mutated_lines,
        "Mutated text lines must diverge from exact golden"
    );
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
fn test_cli_disasm_json_and_text_goldens() {
    let root = find_workspace_root();
    let luad = root.join("target").join("debug").join("luad");
    let fixture_path = root
        .join("tests")
        .join("fixtures")
        .join("precompiled")
        .join("lua54")
        .join("control_flow.luac");

    // 1. Test CLI JSON format matches DisassembledPrototype schema
    let json_output = std::process::Command::new(&luad)
        .args(["disasm", fixture_path.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad disasm --format json execution");
    assert!(
        json_output.status.success(),
        "luad disasm --format json must exit 0: stderr: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );

    let parsed_proto: DisassembledPrototype = serde_json::from_slice(&json_output.stdout)
        .expect("CLI disasm JSON output must deserialize to DisassembledPrototype");
    assert_eq!(parsed_proto.instructions.len(), 32);

    // 2. Test CLI text format produces normalized goldens
    let text_output = std::process::Command::new(&luad)
        .args(["disasm", fixture_path.to_str().unwrap(), "--format", "text"])
        .output()
        .expect("luad disasm --format text execution");
    assert!(
        text_output.status.success(),
        "luad disasm --format text must exit 0: stderr: {}",
        String::from_utf8_lossy(&text_output.stderr)
    );

    let text_str = String::from_utf8_lossy(&text_output.stdout);
    assert!(text_str.contains("GTI"));
    assert!(text_str.contains("ADDI"));
    assert!(text_str.contains("MMBINI"));
    assert!(text_str.contains("; __add"));
    assert!(text_str.contains("EQI"));
    assert!(text_str.contains("JMP"));
    assert!(text_str.contains("; to 8"));
}
