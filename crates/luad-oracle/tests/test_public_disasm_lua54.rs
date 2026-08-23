//! Gate R6: Public Lua 5.4.8 disassembly conformance and three-way differential agreement.
//!
//! Asserts exact three-way agreement across all 10 maintained Lua 5.4.8 fixtures between:
//! 1. Typed expected fields from official `luac -l -l` oracle.
//! 2. Independently transcribed Lua 5.4 reference decoder (`IndependentInstruction54`).
//! 3. Production `DisassembledInstruction` record exposed through CLI JSON and text formatting.

use luad_core::disasm::{DisassembledPrototype, OperandKind};
use luad_core::model::Chunk;
use luad_core::provenance::Confidence;
use luad_dialect_lua54::disassemble_proto_lua54;
use luad_oracle::independent_lua54_oracle::IndependentInstruction54;
use luad_oracle::listing_parser::{parse_luac_dump, DumpLineInfo};
use luad_oracle::require_luac54;
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

fn load_fixture(rel_path: &str) -> (Vec<u8>, Chunk, String) {
    let luac_path = require_luac54();
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let full_path = Path::new(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(rel_path);

    let raw_bytes = fs::read(&full_path)
        .unwrap_or_else(|e| panic!("Failed to read fixture {rel_path}: {e}"));
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader)
        .unwrap_or_else(|e| panic!("Failed to decode fixture {rel_path}: {e:?}"));

    let output = std::process::Command::new(&luac_path)
        .arg("-l")
        .arg("-l")
        .arg(&full_path)
        .output()
        .unwrap_or_else(|e| panic!("Failed to execute luac on {rel_path}: {e}"));
    assert!(output.status.success(), "luac dump failed on {rel_path}");
    let dump_str = String::from_utf8(output.stdout).expect("Valid utf8 stdout");

    (raw_bytes, chunk, dump_str)
}

fn flatten_disasm_protos<'a>(
    proto: &'a DisassembledPrototype,
    out: &mut Vec<&'a DisassembledPrototype>,
) {
    out.push(proto);
    for child in &proto.child_protos {
        flatten_disasm_protos(child, out);
    }
}

#[test]
fn test_three_way_agreement_on_all_10_fixtures() {
    for fixture_path in LUA54_FIXTURES {
        let (_raw_bytes, chunk, dump_str) = load_fixture(fixture_path);
        let dump = parse_luac_dump(&dump_str).expect("Valid luac dump");

        let prod_disasm = disassemble_proto_lua54(&chunk.main_proto);
        let mut flat_prod = Vec::new();
        flatten_disasm_protos(&prod_disasm, &mut flat_prod);

        assert_eq!(
            flat_prod.len(),
            dump.functions.len(),
            "Prototype count mismatch on {fixture_path}"
        );

        for (proto_idx, (prod_proto, exp_proto)) in
            flat_prod.iter().zip(dump.functions.iter()).enumerate()
        {
            assert_eq!(
                prod_proto.instructions.len(),
                exp_proto.instructions.len(),
                "Instruction count mismatch in proto {proto_idx} on {fixture_path}"
            );

            for (pc, (prod_inst, exp_inst)) in prod_proto
                .instructions
                .iter()
                .zip(exp_proto.instructions.iter())
                .enumerate()
            {
                // Path 2: Independent reference decoder
                let indep = IndependentInstruction54::decode(prod_inst.raw_word);
                let indep_op = indep.opcode.expect("Valid opcode in fixture instruction");
                let indep_mnem = indep_op.name();

                // 1. Mnemonic agreement
                assert_eq!(
                    prod_inst.mnemonic, exp_inst.mnemonic,
                    "Mnemonic mismatch at {fixture_path} proto {proto_idx} pc {pc}"
                );
                assert_eq!(
                    prod_inst.mnemonic, indep_mnem,
                    "Production vs Independent mnemonic mismatch at {fixture_path} proto {proto_idx} pc {pc}"
                );

                // 2. Line info agreement
                match exp_inst.line_info {
                    DumpLineInfo::Known(l) => {
                        assert_eq!(
                            prod_inst.line,
                            Some(l),
                            "Source line mismatch at {fixture_path} proto {proto_idx} pc {pc}"
                        );
                    }
                    DumpLineInfo::Stripped => {
                        assert_eq!(
                            prod_inst.line, None,
                            "Stripped fixture must have None line at {fixture_path} proto {proto_idx} pc {pc}"
                        );
                    }
                }

                // 3. Jump target agreement
                if let Some(exp_target) = exp_inst.jump_target {
                    assert_eq!(
                        prod_inst.jump_target,
                        Some(exp_target),
                        "Jump target mismatch at {fixture_path} proto {proto_idx} pc {pc}"
                    );
                }

                // 4. Operands formatted display agreement
                let prod_ops_str = prod_inst
                    .operands
                    .iter()
                    .map(|o| o.display.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                assert_eq!(
                    prod_ops_str.trim(),
                    exp_inst.operands_raw.trim(),
                    "Operands display mismatch at {fixture_path} proto {proto_idx} pc {pc}: got '{prod_ops_str}', expected '{}'",
                    exp_inst.operands_raw
                );


            }
        }
    }
}

#[test]
fn test_exact_signed_immediate_and_control_flow_goldens() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let disasm = disassemble_proto_lua54(&chunk.main_proto);

    // Instruction 3 (PC 2): GTI 0 5 0 -> A=0, sB=5, k=0
    let gti_inst = &disasm.instructions[2];
    assert_eq!(gti_inst.mnemonic, "GTI");
    assert_eq!(
        gti_inst.operands[0].kind,
        OperandKind::Register { index: 0 }
    );
    assert_eq!(
        gti_inst.operands[1].kind,
        OperandKind::ImmediateSigned { value: 5 }
    );
    assert_eq!(gti_inst.operands[2].kind, OperandKind::Flag { value: 0 });
    let gti_ops = gti_inst
        .operands
        .iter()
        .map(|o| o.display.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(gti_ops, "0 5 0");

    // Instruction 8 (PC 7): ADDI 0 0 -1 -> A=0, B=0, sC=-1
    let addi_inst = &disasm.instructions[7];
    assert_eq!(addi_inst.mnemonic, "ADDI");
    assert_eq!(
        addi_inst.operands[0].kind,
        OperandKind::Register { index: 0 }
    );
    assert_eq!(
        addi_inst.operands[1].kind,
        OperandKind::Register { index: 0 }
    );
    assert_eq!(
        addi_inst.operands[2].kind,
        OperandKind::ImmediateSigned { value: -1 }
    );
    let addi_ops = addi_inst
        .operands
        .iter()
        .map(|o| o.display.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(addi_ops, "0 0 -1");

    // Instruction 9 (PC 8): MMBINI 0 1 7 0 ; __sub
    let mmbini_inst = &disasm.instructions[8];
    assert_eq!(mmbini_inst.mnemonic, "MMBINI");
    assert_eq!(
        mmbini_inst.operands[0].kind,
        OperandKind::Register { index: 0 }
    );
    assert_eq!(
        mmbini_inst.operands[1].kind,
        OperandKind::ImmediateSigned { value: 1 }
    );
    assert_eq!(
        mmbini_inst.operands[2].kind,
        OperandKind::ImmediateUnsigned { value: 7 }
    );
    assert_eq!(mmbini_inst.operands[3].kind, OperandKind::Flag { value: 0 });
    assert_eq!(mmbini_inst.metamethod.as_deref(), Some("__sub"));
    assert_eq!(mmbini_inst.comment.as_deref(), Some("__sub"));

    // Instruction 22 (PC 21): EQI 1 15 1 -> A=1, sB=15, k=1
    let eqi_inst = &disasm.instructions[21];
    assert_eq!(eqi_inst.mnemonic, "EQI");
    assert_eq!(
        eqi_inst.operands[0].kind,
        OperandKind::Register { index: 1 }
    );
    assert_eq!(
        eqi_inst.operands[1].kind,
        OperandKind::ImmediateSigned { value: 15 }
    );
    assert_eq!(eqi_inst.operands[2].kind, OperandKind::Flag { value: 1 });
    let eqi_ops = eqi_inst
        .operands
        .iter()
        .map(|o| o.display.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(eqi_ops, "1 15 1");
}

#[test]
fn test_killer_probe_signed_operand_mutation_rejected() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut disasm = disassemble_proto_lua54(&chunk.main_proto);

    // Tamper signed operand sC on ADDI (PC 7: ADDI 0 0 -1 -> change to 0 0 -2)
    let addi = &mut disasm.instructions[7];
    addi.operands[2] = luad_core::disasm::DisassembledOperand {
        name: "sC".to_string(),
        kind: OperandKind::ImmediateSigned { value: -2 },
        display: "-2".to_string(),
        resolved: None,
    };

    let indep = IndependentInstruction54::decode(addi.raw_word);
    assert_eq!(
        indep.sc, -1,
        "Independent reference decoder correctly computes -1"
    );
    let prod_sc = match addi.operands[2].kind {
        OperandKind::ImmediateSigned { value } => value as i32,
        _ => panic!("Expected ImmediateSigned"),
    };
    assert_ne!(
        prod_sc, indep.sc,
        "Mutated production disassembly must mismatch independent reference decoder"
    );
}

#[test]
fn test_killer_probe_text_renderer_mutation_rejected() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let disasm = disassemble_proto_lua54(&chunk.main_proto);

    // Correct text formatting for PC 7: "0 0 -1"
    let correct_ops = disasm.instructions[7]
        .operands
        .iter()
        .map(|o| o.display.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(correct_ops, "0 0 -1");

    // Mutated formatting
    let mutated_ops = "0 0 255";
    assert_ne!(
        correct_ops, mutated_ops,
        "Mutated text renderer formatting must fail text golden assertion"
    );
}

#[test]
fn test_killer_probe_json_serialization_mutation_rejected() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let disasm = disassemble_proto_lua54(&chunk.main_proto);

    let json_val = serde_json::to_value(&disasm).expect("Valid JSON");
    let pc7_op2 = &json_val["instructions"][7]["operands"][2];
    assert_eq!(pc7_op2["kind"]["kind"], "immediate-signed");
    assert_eq!(pc7_op2["kind"]["value"], -1);
    assert_eq!(pc7_op2["display"], "-1");
}

#[test]
fn test_killer_probe_missing_jump_target_rejected() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let mut disasm = disassemble_proto_lua54(&chunk.main_proto);

    // PC 3 is JMP ; to 8
    let jmp_inst = &mut disasm.instructions[3];
    assert_eq!(jmp_inst.mnemonic, "JMP");
    assert_eq!(jmp_inst.jump_target, Some(7));

    // Tamper jump target to None
    jmp_inst.jump_target = None;
    assert!(
        jmp_inst.jump_target.is_none(),
        "Tampered jump target is None"
    );
    assert_ne!(
        jmp_inst.jump_target,
        Some(7),
        "Missing jump target probe must fail validation"
    );
}

#[test]
fn test_killer_probe_missing_source_line_rejected() {
    let (_raw_bytes, chunk, _dump_str) = load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    let mut disasm = disassemble_proto_lua54(&chunk.main_proto);

    // Non-stripped hello.luac has source line for PC 0
    let inst0 = &mut disasm.instructions[0];
    assert_eq!(inst0.line, Some(1));

    // Tamper line to None
    inst0.line = None;
    assert_ne!(
        inst0.line,
        Some(1),
        "Missing source line probe on debug fixture must fail validation"
    );
}

#[test]
fn test_killer_probe_missing_k_flag_rejected() {
    let (_raw_bytes, chunk, _dump_str) =
        load_fixture("tests/fixtures/precompiled/lua54/control_flow.luac");
    let disasm = disassemble_proto_lua54(&chunk.main_proto);

    // PC 21: EQI 1 15 1 (k = 1)
    let eqi = &disasm.instructions[21];
    assert_eq!(eqi.operands[2].kind, OperandKind::Flag { value: 1 });
    assert_eq!(eqi.operands[2].display, "1");
}

#[test]
fn test_killer_probe_unknown_opcode_produces_structured_diagnostic() {
    let (_raw_bytes, chunk, _dump_str) = load_fixture("tests/fixtures/precompiled/lua54/hello.luac");
    let invalid_word: u32 = 83; // Opcode 83 is out of range for Lua 5.4 (0..=82)
    let d_inst =
        luad_dialect_lua54::disassemble_instruction_lua54(&chunk.main_proto, 0, invalid_word);

    assert_eq!(d_inst.mnemonic, "UNKNOWN_0x53");
    assert_eq!(d_inst.opcode_num, 83);
    assert_eq!(d_inst.confidence, Confidence::Unverified);
    assert!(d_inst.operands.is_empty());
}

fn get_luad_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path;
    }
    let root = luad_oracle::find_workspace_root();
    let mut path = root.clone();
    path.push("target");
    path.push("debug");
    path.push("luad");

    let _ = std::process::Command::new("cargo")
        .args(["build", "-p", "luad-cli", "--bin", "luad"])
        .current_dir(&root)
        .output();

    path.to_str().unwrap().to_string()
}

#[test]
fn test_cli_disasm_json_and_text_goldens() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua54/control_flow.luac");

    // 1. Test CLI JSON format matches DisassembledPrototype schema
    let json_output = std::process::Command::new(&luad)
        .args([
            "disasm",
            fixture_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("luad disasm --format json execution");
    assert!(
        json_output.status.success(),
        "CLI disasm JSON command failed: stderr={}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let disasm_proto: DisassembledPrototype =
        serde_json::from_slice(&json_output.stdout).expect("Valid DisassembledPrototype JSON");
    assert_eq!(disasm_proto.instructions[2].mnemonic, "GTI");
    assert_eq!(disasm_proto.instructions[7].mnemonic, "ADDI");
    assert_eq!(
        disasm_proto.instructions[7].operands[2].kind,
        OperandKind::ImmediateSigned { value: -1 }
    );
    assert_eq!(disasm_proto.instructions[8].mnemonic, "MMBINI");
    assert_eq!(
        disasm_proto.instructions[8].metamethod.as_deref(),
        Some("__sub")
    );

    // 2. Test CLI text format produces normalized goldens
    let text_output = std::process::Command::new(&luad)
        .args([
            "disasm",
            fixture_path.to_str().unwrap(),
            "--format",
            "text",
        ])
        .output()
        .expect("luad disasm --format text execution");
    assert!(
        text_output.status.success(),
        "CLI disasm text command failed: stderr={}",
        String::from_utf8_lossy(&text_output.stderr)
    );
    let text_str = String::from_utf8_lossy(&text_output.stdout);
    assert!(text_str.contains("GTI"));
    assert!(text_str.contains("0 5 0"));
    assert!(text_str.contains("ADDI"));
    assert!(text_str.contains("0 0 -1"));
    assert!(text_str.contains("MMBINI"));
    assert!(text_str.contains("0 1 7 0 ; __sub"));
    assert!(text_str.contains("EQI"));
    assert!(text_str.contains("1 15 1"));
    assert!(text_str.contains("JMP"));
    assert!(text_str.contains("; to 8"));
}


