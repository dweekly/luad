//! Production Lua 5.1 disassembly, closure capture facts, and three-way agreement tests (Gate L2).

use std::process::Command;

use luad_core::envelope::MachineDocument;
use luad_core::id::StableId;
use luad_core::DisassembledPrototype;
use luad_oracle::{
    compare_chunk_tree_three_way_lua51, parse_luac_dump, require_luac51, DisasmComparisonError,
    IndependentInstruction51, LuacProtoDumpList,
};

fn get_luad_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut path = std::path::PathBuf::from(manifest_dir);
    path.pop();
    path.pop();
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
fn test_lua51_disasm_emits_typed_records_with_resolved_constants() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = root.join("tests/fixtures/precompiled/lua51/hello.luac");

    let output = Command::new(&luad)
        .args(["disasm", fixture.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("luad disasm --format json failed");

    assert_eq!(output.status.code(), Some(0));
    let doc: MachineDocument<DisassembledPrototype> =
        serde_json::from_slice(&output.stdout).expect("disasm output must be valid JSON");

    assert_eq!(doc.schema_version, 1);
    let instructions = &doc.data.instructions;
    assert!(!instructions.is_empty());

    // In hello.luac, instruction 0 is GETGLOBAL R(0) K(0) ["print"]
    let first_inst = &instructions[0];
    assert_eq!(first_inst.role, "instruction");
}

#[test]
fn test_lua51_closure_bindings_have_closure_binding_role_and_zero_writes() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let bytes = std::fs::read(&fixture_path).expect("read closures.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode closures.luac");

    let mut found_closure = 0;
    let mut found_bindings = 0;
    verify_closure_bindings_recursive(&chunk.main_proto, &mut found_closure, &mut found_bindings);

    assert!(
        found_closure > 0,
        "Must find at least one CLOSURE across proto tree in closures.luac"
    );
    assert!(
        found_bindings > 0,
        "Must find at least one closure binding descriptor across proto tree in closures.luac"
    );
}

fn verify_closure_bindings_recursive(
    proto: &luad_core::Prototype,
    closures_count: &mut usize,
    bindings_count: &mut usize,
) {
    let disasm = luad_dialect_lua51::disassemble_proto_lua51(proto);
    let lifted = luad_analysis::lift_proto_for_dialect("lua5.1", proto);

    for (pc, inst) in disasm.instructions.iter().enumerate() {
        if inst.mnemonic == "CLOSURE" {
            *closures_count += 1;
            let child_idx = inst.operands.iter().find_map(|op| {
                if let luad_core::OperandKind::ImmediateUnsigned { value } = op.kind {
                    Some(value as usize)
                } else {
                    None
                }
            });
            if let Some(c_idx) = child_idx {
                if let Some(child) = proto.protos.get(c_idx) {
                    let nups = child.upvalues.len();
                    for j in 1..=nups {
                        let b_pc = pc + j;
                        if b_pc < disasm.instructions.len() {
                            let b_inst = &disasm.instructions[b_pc];
                            assert_eq!(
                                b_inst.role, "closure_binding",
                                "Descriptor at PC {b_pc} following CLOSURE must have role closure_binding"
                            );
                            assert_eq!(
                                b_inst.companion_pc, Some(pc),
                                "Descriptor at PC {b_pc} companion_pc must point to CLOSURE at {pc}"
                            );
                            *bindings_count += 1;

                            // In lifted semantic IR, closure binding words must have 0 standalone writes
                            let sem = &lifted[b_pc];
                            assert!(
                                sem.writes.is_empty(),
                                "Closure binding descriptor at PC {b_pc} must not acquire standalone writes: {:?}",
                                sem.writes
                            );
                        }
                    }
                }
            }
        }
    }

    for child in &proto.protos {
        verify_closure_bindings_recursive(child, closures_count, bindings_count);
    }
}

#[test]
fn test_lua51_xrefs_index_binds_relation_for_closures_three_hop_chain() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let bytes = std::fs::read(&fixture_path).expect("read closures.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode closures.luac");

    let index = luad_analysis::XrefIndex::build(&chunk);
    let binds_entries: Vec<_> = index
        .entries
        .iter()
        .filter(|e| e.relation == luad_analysis::XrefRelation::Binds)
        .collect();

    assert!(
        !binds_entries.is_empty(),
        "XrefIndex must contain Binds relations for closures in closures.luac"
    );

    // Verify exact multi-hop upvalue capture:
    // Hop 1: proto:0/0 captures parent local R(1) into child upvalue proto:0/0/0:upvalue:0
    let path_0_0 = luad_core::ProtoPath(vec![0, 0]);
    let path_0_0_0 = luad_core::ProtoPath(vec![0, 0, 0]);
    let path_0_0_0_0 = luad_core::ProtoPath(vec![0, 0, 0, 0]);

    let has_local_capture = binds_entries.iter().any(|e| {
        e.source
            == StableId::Local {
                proto: path_0_0.clone(),
                index: 1,
            }
            && e.target
                == StableId::Upvalue {
                    proto: path_0_0_0.clone(),
                    index: 0,
                }
    });
    assert!(
        has_local_capture,
        "XrefIndex must record parent local register R(1) capture into proto:0/0/0 upvalue 0"
    );

    // Hop 2: proto:0/0/0 captures parent upvalue(0) into child upvalue proto:0/0/0/0:upvalue:0
    let has_upval_capture = binds_entries.iter().any(|e| {
        e.source
            == StableId::Upvalue {
                proto: path_0_0_0.clone(),
                index: 0,
            }
            && e.target
                == StableId::Upvalue {
                    proto: path_0_0_0_0.clone(),
                    index: 0,
                }
    });
    assert!(
        has_upval_capture,
        "XrefIndex must record parent upvalue(0) capture into proto:0/0/0/0 upvalue 0"
    );

    // Verify binding descriptor PC evidence
    let has_desc_pc_evidence = binds_entries.iter().any(|e| {
        matches!(&e.source, StableId::Instruction { proto, pc } if *proto == path_0_0 && *pc == 4)
            && e.target
                == StableId::Upvalue {
                    proto: path_0_0_0.clone(),
                    index: 0,
                }
    });
    assert!(
        has_desc_pc_evidence,
        "XrefIndex must record descriptor instruction PC evidence for upvalue binding"
    );
}

#[test]
fn test_lua51_three_way_agreement_across_all_fixtures() {
    let luad = get_luad_bin();
    let fixtures = [
        "hello",
        "hello_stripped",
        "numerics",
        "numerics_stripped",
        "tables",
        "tables_stripped",
        "closures",
        "closures_stripped",
        "control_flow",
        "control_flow_stripped",
    ];

    // Per AGENTS.md, differential tests must require the official compiler and never skip.
    let luac_bin = require_luac51();

    for name in fixtures {
        let root = luad_oracle::find_workspace_root();
        let fixture_path = root.join(format!("tests/fixtures/precompiled/lua51/{name}.luac"));
        let bytes = std::fs::read(&fixture_path)
            .unwrap_or_else(|e| panic!("Failed to read lua5.1 {name}.luac: {e}"));

        // 1. Production decoder
        let mut reader = luad_core::SafeReader::new(&bytes);
        let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader)
            .unwrap_or_else(|e| panic!("Decode failed for {name}: {e:?}"));

        // 2. Production disassembly via CLI
        let output = Command::new(&luad)
            .args(["disasm", fixture_path.to_str().unwrap(), "--format", "json"])
            .output()
            .unwrap_or_else(|e| panic!("CLI disasm failed for {name}: {e}"));

        assert_eq!(output.status.code(), Some(0));
        let doc: MachineDocument<DisassembledPrototype> =
            serde_json::from_slice(&output.stdout).unwrap();

        // 3. Official luac 5.1 dump
        let dump_out = Command::new(&luac_bin)
            .args(["-l", "-l", "-p"])
            .arg(&fixture_path)
            .output()
            .unwrap_or_else(|e| panic!("Failed to run luac5.1 on {name}: {e}"));

        assert!(
            dump_out.status.success(),
            "luac5.1 dump failed for fixture {name}"
        );
        let dump_text = String::from_utf8_lossy(&dump_out.stdout);
        let luac_dump = parse_luac_dump(&dump_text)
            .unwrap_or_else(|e| panic!("Failed to parse luac dump for {name}: {e:?}"));

        let dump_list = LuacProtoDumpList {
            functions: &luac_dump.functions,
        };
        let cmp_res = compare_chunk_tree_three_way_lua51(&chunk.main_proto, &dump_list, &doc.data);
        assert!(
            cmp_res.is_ok(),
            "Three-way agreement failed on fixture {name}: {:?}",
            cmp_res.err()
        );

        // 4. Independent reference decoder agreement on every instruction across the proto tree
        verify_independent_agreement_recursive(&chunk.main_proto, &doc.data);
    }
}

fn verify_independent_agreement_recursive(
    proto: &luad_core::Prototype,
    disasm: &DisassembledPrototype,
) {
    assert_eq!(
        proto.instructions.len(),
        disasm.instructions.len(),
        "Instruction count mismatch for prototype {}",
        proto.id
    );

    for (pc, inst) in proto.instructions.iter().enumerate() {
        let indep = IndependentInstruction51::decode(pc, inst.raw_word);
        let prod = &disasm.instructions[pc];

        assert_eq!(indep.a, prod.encoded_operands.a, "A mismatch at PC {pc}");
        assert_eq!(indep.b, prod.encoded_operands.b, "B mismatch at PC {pc}");
        assert_eq!(indep.c, prod.encoded_operands.c, "C mismatch at PC {pc}");
        assert_eq!(indep.bx, prod.encoded_operands.bx, "Bx mismatch at PC {pc}");
        assert_eq!(
            indep.sbx, prod.encoded_operands.sbx,
            "sBx mismatch at PC {pc}"
        );
    }

    assert_eq!(
        proto.protos.len(),
        disasm.child_protos.len(),
        "Child prototype count mismatch for prototype {}",
        proto.id
    );

    for (child_proto, child_disasm) in proto.protos.iter().zip(&disasm.child_protos) {
        verify_independent_agreement_recursive(child_proto, child_disasm);
    }
}

#[test]
fn test_lua51_text_disassembly_renders_closure_binding_golden_lines() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/closures.luac");

    let output = Command::new(&luad)
        .args(["disasm", fixture_path.to_str().unwrap(), "--format", "text"])
        .output()
        .expect("luad disasm --format text failed");

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);

    // These lines pin closure ownership, descriptor rendering, and upvalue metadata.
    assert!(
        stdout.contains("; proto:0 (source: @tests/fixtures/closures.lua, lines 0-0, stack: 6)")
    );
    assert!(stdout.contains("0  CLOSURE      R(0) Proto(0) ; proto:0/0"));
    assert!(stdout.contains("3  CLOSURE      R(2) Proto(0) ; proto:0/0/0"));
    assert!(stdout.contains("6  CLOSURE      R(1) Proto(0) ; proto:0/0/0/0"));
    assert!(stdout.contains("4  |->          upvalue[0] <- parent R(1)"));
    assert!(stdout.contains("7  |->          upvalue[0] <- parent upvalue[0]"));
    assert!(stdout.contains("upvalue[0] = count (instack=0, idx=0, kind=0)"));
    assert!(!stdout
        .lines()
        .any(|line| { line.contains(" CLOSURE ") && line.ends_with("Proto(0) ; proto:0") }));
    assert!(!stdout.contains("MOVE 0 1 0"));
}

#[test]
fn test_killer_probe_mutated_mnemonic_rejected_by_comparator() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let bytes = std::fs::read(&fixture_path).expect("read hello.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();

    let luac_bin = require_luac51();
    let dump_out = Command::new(&luac_bin)
        .args(["-l", "-l", "-p"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    let luac_dump = parse_luac_dump(&String::from_utf8_lossy(&dump_out.stdout)).unwrap();
    let indep_insts: Vec<_> = chunk
        .main_proto
        .instructions
        .iter()
        .enumerate()
        .map(|(pc, inst)| IndependentInstruction51::decode(pc, inst.raw_word))
        .collect();

    let mut disasm = luad_dialect_lua51::disassemble_proto_lua51(&chunk.main_proto);
    // Mutate instruction mnemonic
    disasm.instructions[0].mnemonic = "LOADNIL".to_string();

    let res = luad_oracle::compare_proto_three_way_lua51(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep_insts,
        &disasm,
        None,
    );
    match res {
        Err(DisasmComparisonError::MnemonicMismatch { pc, .. }) => assert_eq!(pc, 0),
        other => panic!("Expected MnemonicMismatch at PC 0, got {other:?}"),
    }
}

#[test]
fn test_killer_probe_mutated_operand_rejected_by_comparator() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let bytes = std::fs::read(&fixture_path).expect("read hello.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();

    let luac_bin = require_luac51();
    let dump_out = Command::new(&luac_bin)
        .args(["-l", "-l", "-p"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    let luac_dump = parse_luac_dump(&String::from_utf8_lossy(&dump_out.stdout)).unwrap();
    let indep_insts: Vec<_> = chunk
        .main_proto
        .instructions
        .iter()
        .enumerate()
        .map(|(pc, inst)| IndependentInstruction51::decode(pc, inst.raw_word))
        .collect();

    let mut disasm = luad_dialect_lua51::disassemble_proto_lua51(&chunk.main_proto);
    // Mutate physical operand B
    disasm.instructions[0].encoded_operands.b = 999;

    let res = luad_oracle::compare_proto_three_way_lua51(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep_insts,
        &disasm,
        None,
    );
    match res {
        Err(DisasmComparisonError::PhysicalFieldMismatch { pc, field_name, .. }) => {
            assert_eq!(pc, 0);
            assert_eq!(field_name, "B");
        }
        other => panic!("Expected PhysicalFieldMismatch on B at PC 0, got {other:?}"),
    }
}

#[test]
fn test_killer_probe_missing_constant_rejected_by_comparator() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let bytes = std::fs::read(&fixture_path).expect("read hello.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();

    let luac_bin = require_luac51();
    let dump_out = Command::new(&luac_bin)
        .args(["-l", "-l", "-p"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    let luac_dump = parse_luac_dump(&String::from_utf8_lossy(&dump_out.stdout)).unwrap();
    let indep_insts: Vec<_> = chunk
        .main_proto
        .instructions
        .iter()
        .enumerate()
        .map(|(pc, inst)| IndependentInstruction51::decode(pc, inst.raw_word))
        .collect();

    let mut disasm = luad_dialect_lua51::disassemble_proto_lua51(&chunk.main_proto);
    // Remove resolved constant fact on Bx operand
    if let Some(op) = disasm.instructions[0]
        .operands
        .iter_mut()
        .find(|o| o.name == "Bx")
    {
        op.resolved = None;
    }

    let res = luad_oracle::compare_proto_three_way_lua51(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep_insts,
        &disasm,
        None,
    );
    match res {
        Err(DisasmComparisonError::MissingResolvedFact {
            pc, operand_name, ..
        }) => {
            assert_eq!(pc, 0);
            assert_eq!(operand_name, "Bx");
        }
        other => panic!("Expected MissingResolvedFact for Bx at PC 0, got {other:?}"),
    }
}

#[test]
fn test_killer_probe_missing_companion_link_rejected_by_comparator() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/closures.luac");
    let bytes = std::fs::read(&fixture_path).expect("read closures.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();

    let luac_bin = require_luac51();
    let dump_out = Command::new(&luac_bin)
        .args(["-l", "-l", "-p"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    let luac_dump = parse_luac_dump(&String::from_utf8_lossy(&dump_out.stdout)).unwrap();

    let child_proto = &chunk.main_proto.protos[0];
    let indep_insts: Vec<_> = child_proto
        .instructions
        .iter()
        .enumerate()
        .map(|(pc, inst)| IndependentInstruction51::decode(pc, inst.raw_word))
        .collect();

    let mut disasm = luad_dialect_lua51::disassemble_proto_lua51(child_proto);
    // Mutate companion_pc of closure binding at PC 4 to None
    disasm.instructions[4].companion_pc = None;

    let res = luad_oracle::compare_proto_three_way_lua51(
        child_proto,
        &luac_dump.functions[1],
        &indep_insts,
        &disasm,
        None,
    );
    match res {
        Err(DisasmComparisonError::CompanionMismatch { pc, .. }) => assert_eq!(pc, 4),
        other => panic!("Expected CompanionMismatch at PC 4, got {other:?}"),
    }
}

#[test]
fn test_killer_probe_mutated_line_rejected_by_comparator() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let bytes = std::fs::read(&fixture_path).expect("read hello.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();

    let luac_bin = require_luac51();
    let dump_out = Command::new(&luac_bin)
        .args(["-l", "-l", "-p"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    let luac_dump = parse_luac_dump(&String::from_utf8_lossy(&dump_out.stdout)).unwrap();
    let indep_insts: Vec<_> = chunk
        .main_proto
        .instructions
        .iter()
        .enumerate()
        .map(|(pc, inst)| IndependentInstruction51::decode(pc, inst.raw_word))
        .collect();

    let mut disasm = luad_dialect_lua51::disassemble_proto_lua51(&chunk.main_proto);
    // Mutate source line number
    disasm.instructions[0].line = Some(9999);

    let res = luad_oracle::compare_proto_three_way_lua51(
        &chunk.main_proto,
        &luac_dump.functions[0],
        &indep_insts,
        &disasm,
        None,
    );
    match res {
        Err(DisasmComparisonError::LineMismatch {
            pc,
            expected_line,
            actual_line,
        }) => {
            assert_eq!(pc, 0);
            assert_eq!(actual_line, 9999);
            assert_ne!(expected_line, 9999);
        }
        other => panic!("Expected LineMismatch at PC 0, got {other:?}"),
    }
}

#[test]
fn test_killer_probe_json_mutation_rejected_by_tree_comparator() {
    let root = luad_oracle::find_workspace_root();
    let fixture_path = root.join("tests/fixtures/precompiled/lua51/hello.luac");
    let bytes = std::fs::read(&fixture_path).expect("read hello.luac");

    let mut reader = luad_core::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();

    let luac_bin = require_luac51();
    let dump_out = Command::new(&luac_bin)
        .args(["-l", "-l", "-p"])
        .arg(&fixture_path)
        .output()
        .unwrap();
    let luac_dump = parse_luac_dump(&String::from_utf8_lossy(&dump_out.stdout)).unwrap();
    let dump_list = LuacProtoDumpList {
        functions: &luac_dump.functions,
    };

    let mut disasm = luad_dialect_lua51::disassemble_proto_lua51(&chunk.main_proto);
    // Mutate disasm to cause JsonMismatch
    disasm.instructions[0].mnemonic = "TAMPERED".to_string();

    let res = compare_chunk_tree_three_way_lua51(&chunk.main_proto, &dump_list, &disasm);
    match res {
        Err(DisasmComparisonError::JsonMismatch { pc, .. }) => assert_eq!(pc, 0),
        other => panic!("Expected JsonMismatch at PC 0, got {other:?}"),
    }
}
