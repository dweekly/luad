//! Negative control test suite for the canonical differential oracle.
//!
//! Asserts that deliberate corruptions to mnemonics, operands, constants, local debug info,
//! line info, prototype counts, and field consumption are detected and produce exact expected `OracleMismatch` variants.

use luad_core::model::{Chunk, ConstantValue};
use luad_oracle::{
    compare_chunk_with_luac, compile_source_lua54, dump_source_luac, require_luac54, OracleMismatch,
};

fn get_base_test_pair() -> (Chunk, String) {
    let luac_path = require_luac54();
    let source = "local a = \"hello_constant\"\nlocal b = \"world_constant\"\nreturn a .. b";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes clean chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");
    (chunk, dump)
}

#[test]
fn test_all_10_fixtures_lua54_against_differential_oracle() {
    let luac_path = require_luac54();
    let fixtures = [
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

    for fixture_path in fixtures {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let full_path = std::path::Path::new(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(fixture_path);
        let raw_bytes = std::fs::read(&full_path)
            .unwrap_or_else(|e| panic!("Failed to read {fixture_path}: {e}"));
        let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
        let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode {fixture_path}: {e:?}"));

        let output = std::process::Command::new(&luac_path)
            .arg("-l")
            .arg("-l")
            .arg(&full_path)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute luac on {fixture_path}: {e}"));
        assert!(
            output.status.success(),
            "luac -l -l failed on {fixture_path}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let luac_dump = String::from_utf8(output.stdout).expect("Valid utf8 stdout");

        luad_oracle::assert_chunk_matches_luac(&chunk, &luac_dump);
    }
}

#[test]
fn test_negative_control_clean_passes() {
    let (chunk, dump) = get_base_test_pair();
    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        mismatches.is_empty(),
        "Clean comparison must produce 0 mismatches, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_mnemonic_mutation() {
    let (mut chunk, dump) = get_base_test_pair();

    // Perturb instruction 0 opcode (change to LOADI, opcode 1)
    let original_word = chunk.main_proto.instructions[0].raw_word;
    let corrupted_word = (original_word & !0x7F) | 1; // force LOADI (opcode 1)
    chunk.main_proto.instructions[0].raw_word = corrupted_word;

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Corrupted mnemonic must produce mismatches"
    );

    let has_mnemonic_mismatch = mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::Mnemonic { pc: 0, .. }));
    assert!(
        has_mnemonic_mismatch,
        "Expected OracleMismatch::Mnemonic at PC 0, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_operand_mutation() {
    let (mut chunk, dump) = get_base_test_pair();

    // Mutate operand A of instruction 1 (e.g. change register index from 0 to 42)
    let original_word = chunk.main_proto.instructions[1].raw_word;
    let corrupted_word = (original_word & !(0xFF << 7)) | (42 << 7);
    chunk.main_proto.instructions[1].raw_word = corrupted_word;

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Corrupted operand must produce mismatches"
    );

    let has_operand_mismatch = mismatches.iter().any(|m| {
        matches!(
            m,
            OracleMismatch::Operand { pc: 1, .. } | OracleMismatch::OperandField { pc: 1, .. }
        )
    });
    assert!(
        has_operand_mismatch,
        "Expected OracleMismatch::Operand or OperandField at PC 1, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_all_10_operand_fields_mutated_independently() {
    // Tests that mutations to each of the 10 fields (A, B, C, k, sB, sC, Bx, sBx, Ax, sJ)
    // independently trigger exact, field-specific OracleMismatch::OperandField.
    let luac_path = require_luac54();

    // 1. Field A (in VARARGPREP 0)
    {
        let source = "local a = 1; return a";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        chunk.main_proto.instructions[0].raw_word ^= 5 << 7; // mutate A
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "A")));
    }

    // 2. Field B (in MOVE 1 0)
    {
        let source = "local a = 1; local b = a; return b";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let move_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 0)
            .unwrap();
        chunk.main_proto.instructions[move_pc].raw_word ^= 3 << 16; // mutate B
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "B")));
    }

    // 3. Field C (in ADD 2 0 1)
    {
        let source = "local a = 1; local b = 2; return a + b";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let add_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 34)
            .unwrap();
        chunk.main_proto.instructions[add_pc].raw_word ^= 3 << 24; // mutate C
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "C")));
    }

    // 4. Field k (in TEST 0 0)
    {
        let source = "local a = true; if not a then return 1 else return 2 end";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let test_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 66)
            .unwrap();
        chunk.main_proto.instructions[test_pc].raw_word ^= 1 << 15; // mutate k
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "k")));
    }

    // 5. Field sB (in EQI 0 5 0)
    {
        let source = "local a = 10; if a == 5 then return 1 end";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let eqi_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 61)
            .unwrap();
        chunk.main_proto.instructions[eqi_pc].raw_word ^= 2 << 16; // mutate sB
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "sB")));
    }

    // 6. Field sC (in ADDI 0 0 5)
    {
        let source = "local a = 10; return a + 5";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let addi_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 21)
            .unwrap();
        chunk.main_proto.instructions[addi_pc].raw_word ^= 2 << 24; // mutate sC
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "sC")));
    }

    // 7. Field Bx (in LOADK 0 0)
    {
        let source = "local a = \"str_const\"; return a";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let loadk_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 3)
            .unwrap();
        chunk.main_proto.instructions[loadk_pc].raw_word ^= 1 << 17; // mutate Bx
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "Bx")));
    }

    // 8. Field sBx (in LOADI 0 100)
    {
        let source = "local a = 100; return a";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let loadi_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 1)
            .unwrap();
        chunk.main_proto.instructions[loadi_pc].raw_word ^= 5 << 15; // mutate sBx
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "sBx")));
    }

    // 9. Field Ax (in EXTRAARG 100)
    {
        let (mut chunk, dump) = get_base_test_pair();
        let raw_word = 82 | (100 << 7); // EXTRAARG opcode 82 with Ax = 100
        let indep =
            luad_oracle::independent_lua54_oracle::IndependentInstruction54::decode(raw_word);
        assert_eq!(indep.ax, 100);
        chunk.main_proto.instructions[0].raw_word = raw_word;
        // In dump, replace instruction 1 with EXTRAARG 200
        let tampered_dump = dump.replace("VARARGPREP\t0", "EXTRAARG\t200");
        assert_ne!(tampered_dump, dump);
        let m = compare_chunk_with_luac(&chunk, &tampered_dump);
        assert!(m
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "Ax")));
    }

    // 10. Field sJ (in JMP 5)
    {
        let source = "local x = 1\nwhile x < 10 do\n  x = x + 1\nend\nreturn x";
        let raw = compile_source_lua54(source, false).unwrap();
        let mut chunk =
            luad_dialect_lua54::decode_chunk_lua54(&mut luad_core::reader::SafeReader::new(&raw))
                .unwrap();
        let dump = dump_source_luac(&luac_path, source).unwrap();
        let jmp_pc = chunk
            .main_proto
            .instructions
            .iter()
            .position(|i| (i.raw_word & 0x7F) == 56)
            .expect("JMP instruction exists");
        chunk.main_proto.instructions[jmp_pc].raw_word ^= 2 << 10; // mutate sJ
        let mismatches = compare_chunk_with_luac(&chunk, &dump);
        assert!(mismatches
            .iter()
            .any(|m| matches!(m, OracleMismatch::OperandField { field, .. } if field == "sJ")));
    }
}

#[test]
fn test_negative_control_bit15_b_decoder_bug() {
    let luac_path = require_luac54();
    let source = "local a = 10\nlocal b = 20\nreturn a + b";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let mut chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");

    // Mutate the instruction word to simulate offset B/sBx bitfield bug
    let inst_word = chunk.main_proto.instructions[1].raw_word;
    chunk.main_proto.instructions[1].raw_word = inst_word ^ (1 << 16);

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Buggy bitfield decoding must produce mismatches"
    );
    let has_operand_mismatch = mismatches.iter().any(|m| {
        matches!(
            m,
            OracleMismatch::Operand { pc: 1, .. } | OracleMismatch::OperandField { pc: 1, .. }
        )
    });
    assert!(
        has_operand_mismatch,
        "Expected OracleMismatch::Operand on bitfield corruption, got: {mismatches:?}"
    );
}

#[test]
fn test_unpatched_pre_gate2_decoder_fails_oracle_on_all_fixtures() {
    let luac_path = require_luac54();
    let fixtures = [
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

    use luad_oracle::independent_lua54_oracle::IndependentOpcode54;

    for fixture_path in &fixtures {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let full_path = std::path::Path::new(manifest_dir)
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(fixture_path);
        let raw_bytes = std::fs::read(&full_path)
            .unwrap_or_else(|e| panic!("Failed to read {fixture_path}: {e}"));

        let output = std::process::Command::new(&luac_path)
            .arg("-l")
            .arg("-l")
            .arg(&full_path)
            .output()
            .unwrap_or_else(|e| panic!("Failed to execute luac on {fixture_path}: {e}"));
        assert!(
            output.status.success(),
            "luac -l -l failed on {fixture_path}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let luac_dump = String::from_utf8(output.stdout).expect("Valid utf8 stdout");
        let dump_parsed = luad_oracle::parse_luac_dump(&luac_dump).expect("Parses dump");

        assert!(!dump_parsed.functions.is_empty());

        let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
        let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode fixture {fixture_path}: {e:?}"));

        let mut pre_gate2_mismatches = Vec::new();
        for (pc, inst) in chunk.main_proto.instructions.iter().enumerate() {
            let raw = inst.raw_word;
            let op = (raw & 0x7F) as u8;
            let a = ((raw >> 7) & 0xff) as u8;
            let buggy_b = ((raw >> 15) & 0xff) as u8;
            let buggy_c = ((raw >> 23) & 0xff) as u8;
            let buggy_sc = (buggy_c as i32) - 128;

            if let Some(exp_inst) = dump_parsed.functions[0].instructions.get(pc) {
                if let Some(opcode) = IndependentOpcode54::from_u8(op) {
                    let buggy_ops = match opcode {
                        IndependentOpcode54::Move => format!("{a} {buggy_b}"),
                        IndependentOpcode54::Addi => format!("{a} {buggy_b} {buggy_sc}"),
                        IndependentOpcode54::Add => format!("{a} {buggy_b} {buggy_c}"),
                        IndependentOpcode54::Call => format!("{a} {buggy_b} {buggy_c}"),
                        _ => continue,
                    };
                    if buggy_ops.trim() != exp_inst.operands_raw.trim() {
                        pre_gate2_mismatches.push((pc, buggy_ops, exp_inst.operands_raw.clone()));
                    }
                }
            }
        }

        assert!(
            !pre_gate2_mismatches.is_empty(),
            "Pre-Gate 2 buggy decoder MUST fail the oracle on maintained fixture '{fixture_path}'"
        );
    }
}

#[test]
fn test_golden_word_pins_and_unpatched_decoder_failure() {
    let golden_cases = [
        (0x050100a2_u32, "ADD", "1 1 5"),
        (0x00010180_u32, "MOVE", "3 1"),
        (0x01030146_u32, "RETURN", "2 3 1"),
    ];

    for (word, exp_mnem, exp_ops) in golden_cases {
        let mnem =
            luad_oracle::decode_instruction_mnemonic("lua5.4", word).expect("Mnemonic must decode");
        assert_eq!(mnem, exp_mnem, "Mnemonic mismatch on word 0x{word:08x}");
        let ops =
            luad_oracle::decode_instruction_operands("lua5.4", word).expect("Operands must decode");
        assert_eq!(
            ops.trim(),
            exp_ops,
            "Operands mismatch on word 0x{word:08x}"
        );

        let a = ((word >> 7) & 0xff) as u8;
        let buggy_b = ((word >> 15) & 0xff) as u8;
        let buggy_c = ((word >> 23) & 0xff) as u8;
        let buggy_ops = match exp_mnem {
            "MOVE" => format!("{a} {buggy_b}"),
            "ADD" => format!("{a} {buggy_b} {buggy_c}"),
            "RETURN" => format!("{a} {buggy_b} {buggy_c}"),
            _ => panic!("Unexpected golden mnemonic"),
        };
        assert_ne!(
            buggy_ops.trim(),
            exp_ops,
            "Pre-Gate 2 unpatched decoder must FAIL on golden word 0x{word:08x}"
        );
    }
}

#[test]
fn test_negative_control_constant_mutation() {
    let (mut chunk, dump) = get_base_test_pair();

    assert!(
        !chunk.main_proto.constants.is_empty(),
        "Test fixture must contain constants"
    );

    // Corrupt constant 0 value
    chunk.main_proto.constants[0].value = ConstantValue::Integer {
        val: 999999,
        raw_hex: "corrupted".to_string(),
    };

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Corrupted constant must produce mismatches"
    );

    let has_const_mismatch = mismatches.iter().any(|m| {
        matches!(
            m,
            OracleMismatch::Constant { index: 0, .. }
                | OracleMismatch::ConstantTagMismatch { index: 0, .. }
        )
    });
    assert!(
        has_const_mismatch,
        "Expected OracleMismatch::Constant or ConstantTagMismatch at index 0, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_local_var_mutation() {
    let (mut chunk, dump) = get_base_test_pair();

    assert!(
        !chunk.main_proto.loc_vars.is_empty(),
        "Test fixture must contain local variables"
    );

    // Corrupt local var name
    chunk.main_proto.loc_vars[0].name = luad_core::model::LuaString::from_bytes(b"corrupted_var");

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Corrupted local variable must produce mismatches"
    );

    let has_local_mismatch = mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::Local { index: 0, .. }));
    assert!(
        has_local_mismatch,
        "Expected OracleMismatch::Local at index 0, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_metadata_mutation() {
    let (mut chunk, dump) = get_base_test_pair();

    // Corrupt numparams
    chunk.main_proto.numparams += 5;

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Corrupted numparams must produce mismatches"
    );

    let has_meta_mismatch = mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::Metadata { field, .. } if field == "numparams"));
    assert!(
        has_meta_mismatch,
        "Expected OracleMismatch::Metadata for numparams, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_instruction_count_mutation() {
    let (mut chunk, dump) = get_base_test_pair();

    // Drop one instruction
    chunk.main_proto.instructions.pop();

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Missing instruction must produce mismatches"
    );

    let has_count_mismatch = mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::InstructionCount { .. }));
    assert!(
        has_count_mismatch,
        "Expected OracleMismatch::InstructionCount, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_signed_immediate_offset_sb() {
    let luac_path = require_luac54();
    let source = "local x = 5\nreturn x + 1";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");

    let clean_mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(clean_mismatches.is_empty());

    let addi_pc = chunk
        .main_proto
        .instructions
        .iter()
        .position(|i| {
            luad_oracle::decode_instruction_mnemonic("lua5.4", i.raw_word) == Some("ADDI")
        })
        .expect("ADDI instruction present in chunk");

    let addi_inst = &chunk.main_proto.instructions[addi_pc];
    let dump_parsed = luad_oracle::parse_luac_dump(&dump).expect("Parses dump");
    let exp_addi_inst = &dump_parsed.functions[0].instructions[addi_pc];

    let raw = addi_inst.raw_word;
    let a = ((raw >> 7) & 0xff) as u8;
    let b = ((raw >> 16) & 0xff) as u8;
    let c = ((raw >> 24) & 0xff) as u8;
    let buggy_sc = (c as i32) - 128;
    let correct_sc = (c as i32) - 127;

    assert_ne!(
        buggy_sc, correct_sc,
        "Buggy bias 128 must differ from correct bias 127"
    );
    let buggy_rendered = format!("{a} {b} {buggy_sc}");
    assert_ne!(
        buggy_rendered.trim(),
        exp_addi_inst.operands_raw.trim(),
        "Buggy OFFSET_SB = 128 rendering must FAIL against luac dump"
    );
}

#[test]
fn test_negative_control_comparison_opcode_modes() {
    use luad_dialect_lua54::{OpMode54, Opcode54};

    let comparison_opcodes = [
        Opcode54::Eq,
        Opcode54::Lt,
        Opcode54::Le,
        Opcode54::Eqk,
        Opcode54::Eqi,
        Opcode54::Mmbini,
        Opcode54::Mmbink,
    ];

    for op in comparison_opcodes {
        assert_eq!(
            op.mode(),
            OpMode54::IABC,
            "Opcode {:?} must be iABC mode",
            op
        );
    }
}

#[test]
fn test_negative_control_constant_type_mismatch() {
    let (mut chunk, dump) = get_base_test_pair();

    // Replace string constant with float approximation
    chunk.main_proto.constants[0].value = ConstantValue::Float {
        val: 123.456,
        raw_hex: "405edd2f1a9fbe77".to_string(),
        is_inf: false,
        is_nan: false,
    };

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Float constant substitution for string MUST produce mismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::Constant { index: 0, .. }
            | OracleMismatch::ConstantTagMismatch { index: 0, .. }
    )));
}

#[test]
#[should_panic(expected = "Canonical differential oracle detected")]
fn test_assert_chunk_matches_luac_panics_on_mismatch() {
    let (mut chunk, dump) = get_base_test_pair();

    // Corrupt mnemonic
    chunk.main_proto.instructions[0].raw_word ^= 0x7F;
    luad_oracle::assert_chunk_matches_luac(&chunk, &dump);
}

#[test]
fn test_negative_control_unknown_actual_opcode() {
    let (mut chunk, dump) = get_base_test_pair();
    // Opcode 120 is invalid in Lua 5.4 (valid are 0..82)
    chunk.main_proto.instructions[0].raw_word =
        (chunk.main_proto.instructions[0].raw_word & !0x7F) | 120;
    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Unknown opcode must produce mismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::UnknownActualOpcode {
            pc: 0,
            opcode: 120,
            ..
        }
    )));
}

#[test]
fn test_negative_control_unknown_expected_mnemonic() {
    let (chunk, dump) = get_base_test_pair();
    assert!(dump.contains("VARARGPREP"));
    let tampered_dump = dump.replace("VARARGPREP", "UNKNOWN_OP");
    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(!mismatches.is_empty());
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::UnknownExpectedMnemonic { mnemonic, .. } if mnemonic == "UNKNOWN_OP"
    )));
}

#[test]
fn test_negative_control_float_token_character_mutation_preserving_value() {
    let luac_path = require_luac54();
    let source = "local f = 1e-05\nreturn f";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");

    // Clean check
    assert!(compare_chunk_with_luac(&chunk, &dump).is_empty());

    // In luac dump, change "1e-05" to "1e-5" (same IEEE-754 float 0.00001, but string token altered by 1 char)
    assert!(
        dump.contains("1e-05"),
        "Luac dump must contain canonical float token 1e-05"
    );
    let tampered_dump = dump.replace("1e-05", "1e-5");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Altering one character in oracle float token while preserving IEEE-754 value MUST fail oracle"
    );
    assert!(mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::ConstantFloatTokenMismatch { .. })));
}

#[test]
fn test_negative_control_signed_zero_float_exact() {
    // 1. Test +0.0 mutated to -0.0
    let (mut chunk_pos, dump_pos) = get_base_test_pair();
    assert!(!chunk_pos.main_proto.constants.is_empty());
    chunk_pos.main_proto.constants[0].value = ConstantValue::Float {
        val: 0.0,
        raw_hex: "0000000000000000".to_string(),
        is_inf: false,
        is_nan: false,
    };
    let dump_pos_tampered = dump_pos.replace("0\tS\t\"hello_constant\"", "0\tF\t0");
    assert_ne!(dump_pos_tampered, dump_pos);

    // Clean check for +0.0
    assert!(compare_chunk_with_luac(&chunk_pos, &dump_pos_tampered).is_empty());

    // Mutate +0.0 to -0.0
    chunk_pos.main_proto.constants[0].value = ConstantValue::Float {
        val: -0.0,
        raw_hex: "8000000000000000".to_string(),
        is_inf: false,
        is_nan: false,
    };
    let mismatches_pos = compare_chunk_with_luac(&chunk_pos, &dump_pos_tampered);
    assert!(
        !mismatches_pos.is_empty(),
        "+0.0 mutated to -0.0 must mismatch"
    );
    assert!(mismatches_pos.iter().any(|m| matches!(
        m,
        OracleMismatch::ConstantFloatTokenMismatch { actual_token, expected_token, .. }
            if actual_token == "-0" && expected_token == "0"
    )));

    // 2. Test -0.0 mutated to +0.0
    let (mut chunk_neg, dump_neg) = get_base_test_pair();
    chunk_neg.main_proto.constants[0].value = ConstantValue::Float {
        val: -0.0,
        raw_hex: "8000000000000000".to_string(),
        is_inf: false,
        is_nan: false,
    };
    let dump_neg_tampered = dump_neg.replace("0\tS\t\"hello_constant\"", "0\tF\t-0");
    assert_ne!(dump_neg_tampered, dump_neg);

    // Clean check for -0.0
    assert!(compare_chunk_with_luac(&chunk_neg, &dump_neg_tampered).is_empty());

    // Mutate -0.0 to +0.0
    chunk_neg.main_proto.constants[0].value = ConstantValue::Float {
        val: 0.0,
        raw_hex: "0000000000000000".to_string(),
        is_inf: false,
        is_nan: false,
    };
    let mismatches_neg = compare_chunk_with_luac(&chunk_neg, &dump_neg_tampered);
    assert!(
        !mismatches_neg.is_empty(),
        "-0.0 mutated to +0.0 must mismatch"
    );
    assert!(mismatches_neg.iter().any(|m| matches!(
        m,
        OracleMismatch::ConstantFloatTokenMismatch { actual_token, expected_token, .. }
            if actual_token == "0" && expected_token == "-0"
    )));
}

#[test]
fn test_negative_control_integer_vs_float_constant_tag() {
    let luac_path = require_luac54();
    let source = "local s = \"str\"\nlocal i = 9223372036854775807\nreturn s, i";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let mut chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");

    assert!(compare_chunk_with_luac(&chunk, &dump).is_empty());

    // Replace integer constant with float constant with same value
    chunk.main_proto.constants[1].value = ConstantValue::Float {
        val: 9223372036854775807.0,
        raw_hex: "43e0000000000000".to_string(),
        is_inf: false,
        is_nan: false,
    };

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Integer vs Float tag mismatch must produce mismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::ConstantTagMismatch { index: 1, .. }
            | OracleMismatch::Constant { index: 1, .. }
    )));
}

#[test]
fn test_negative_control_nil_constant_wrong_tag_paired_with_nil_value() {
    let (mut chunk, dump) = get_base_test_pair();
    assert!(!chunk.main_proto.constants.is_empty());

    // Set actual constant 0 to Nil
    chunk.main_proto.constants[0].value = ConstantValue::Nil;

    // Tamper constant 0 in dump to tag 'I' with value "nil"
    let tampered_dump = dump.replace("0\tS\t\"hello_constant\"", "0\tI\tnil");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Wrong tag 'I' paired with value 'nil' MUST be rejected by ConstantTagMismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::ConstantTagMismatch { actual_tag, expected_tag, .. }
            if actual_tag == "N" && expected_tag == "I"
    )));
}

#[test]
fn test_negative_control_extra_operand_detected() {
    let (chunk, dump) = get_base_test_pair();
    let tampered_dump = dump.replace("VARARGPREP\t0", "VARARGPREP\t0 999 888");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Extra operands in listing MUST fail the oracle"
    );
    assert!(mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::ExtraOperand { .. })));
}

#[test]
fn test_negative_control_missing_operand() {
    let (chunk, dump) = get_base_test_pair();
    let tampered_dump = dump.replace("0 0\t;", "0\t;");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Missing operand in listing must produce mismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::MissingOperand { .. } | OracleMismatch::Operand { .. }
    )));
}

#[test]
fn test_negative_control_unconsumed_field() {
    let (chunk, dump) = get_base_test_pair();

    // 1. Extra unconsumed instruction operand tokens
    assert!(dump.contains("VARARGPREP\t0"));
    let tampered_dump_ops = dump.replace("VARARGPREP\t0", "VARARGPREP\t0 999 888");
    let m_ops = compare_chunk_with_luac(&chunk, &tampered_dump_ops);
    assert!(!m_ops.is_empty());
    assert!(m_ops
        .iter()
        .any(|m| matches!(m, OracleMismatch::UnconsumedField { .. })));

    // 2. Unconsumed / mismatched instruction PC in ledger
    assert!(dump.contains("\t1\t[1]\t"));
    let tampered_dump_pc = dump.replace("\t1\t[1]\t", "\t99\t[1]\t");
    let m_pc = compare_chunk_with_luac(&chunk, &tampered_dump_pc);
    assert!(!m_pc.is_empty());
    assert!(m_pc.iter().any(|m| matches!(
        m,
        OracleMismatch::UnconsumedField { field, .. } if field.contains("instruction PC")
    )));

    // 3. Unconsumed / mismatched constant index in ledger
    assert!(dump.contains("0\tS\t"));
    let tampered_dump_c = dump.replace("0\tS\t", "5\tS\t");
    let m_c = compare_chunk_with_luac(&chunk, &tampered_dump_c);
    assert!(!m_c.is_empty());
    assert!(m_c.iter().any(|m| matches!(
        m,
        OracleMismatch::UnconsumedField { field, .. } if field.contains("constant index")
    )));

    // 4. Unconsumed / mismatched local index in ledger
    assert!(dump.contains("0\ta\t"));
    let tampered_dump_loc = dump.replace("0\ta\t", "7\ta\t");
    let m_loc = compare_chunk_with_luac(&chunk, &tampered_dump_loc);
    assert!(!m_loc.is_empty());
    assert!(m_loc.iter().any(|m| matches!(
        m,
        OracleMismatch::UnconsumedField { field, .. } if field.contains("local index")
    )));
}

#[test]
fn test_negative_control_prototype_is_main_mismatch() {
    let (chunk, dump) = get_base_test_pair();
    assert!(dump.contains("main <"));
    let tampered_dump = dump.replacen("main <", "function <", 1);
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Mismatched is_main flag MUST produce Metadata mismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::Metadata { field, .. } if field == "is_main"
    )));
}

#[test]
fn test_negative_control_missing_constant_tag_rejected() {
    let (chunk, dump) = get_base_test_pair();
    assert!(dump.contains("0\tS\t"));
    // Tamper dump by removing the tag column entirely for constant 0
    let tampered_dump = dump.replace("0\tS\t\"hello_constant\"", "0\t\"hello_constant\"");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Missing constant tag in Lua 5.4 MUST produce ConstantTagMismatch"
    );
    assert!(mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::ConstantTagMismatch { .. })));
}

#[test]
fn test_negative_control_string_constant_exact_formatting_required() {
    let (chunk, dump) = get_base_test_pair();
    assert!(dump.contains("\"hello_constant\""));
    // Tamper dump by removing quotes (unquoted string token)
    let tampered_dump = dump.replace("\"hello_constant\"", "hello_constant");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Unquoted string constant in oracle dump MUST be rejected"
    );
    assert!(mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::Constant { index: 0, .. })));
}

#[test]
fn test_negative_control_jump_target_mismatch() {
    let luac_path = require_luac54();
    let source = "local x = 1\nwhile x < 10 do\n  x = x + 1\nend\nreturn x";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let mut chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");

    assert!(compare_chunk_with_luac(&chunk, &dump).is_empty());

    let pos = chunk
        .main_proto
        .instructions
        .iter()
        .position(|i| (i.raw_word & 0x7F) == 56)
        .expect("JMP instruction (opcode 56) must exist in compiled fixture");

    chunk.main_proto.instructions[pos].raw_word ^= 1 << 15;
    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Mutated jump target must produce mismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::OperandField { field, .. } if field == "sJ"
    ) || matches!(m, OracleMismatch::JumpTargetMismatch { .. })));
}

#[test]
fn test_negative_control_line_erasure_detected() {
    let (chunk, dump) = get_base_test_pair();
    // Non-stripped chunk has line 1 for instruction 1: [1]
    assert!(dump.contains("\t1\t[1]\t"));
    // Tamper line info by erasing it to stripped marker [-]
    let tampered_dump = dump.replace("\t1\t[1]\t", "\t1\t[-]\t");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Erasing line info [1] to [-] in non-stripped chunk MUST produce Line mismatch"
    );
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::Line {
            pc: 0,
            actual: 1,
            expected: 0,
            ..
        }
    )));
}

#[test]
fn test_negative_control_missing_upvalue_columns_rejected() {
    let (chunk, dump) = get_base_test_pair();
    // Upvalue section has "\t0\t_ENV\t1\t0" (4 columns)
    assert!(dump.contains("0\t_ENV\t1\t0"));
    // Tamper dump by removing instack and idx columns
    let tampered_dump = dump.replace("0\t_ENV\t1\t0", "0\t_ENV");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Missing mandatory instack/idx columns in Lua 5.4 upvalues MUST produce UnconsumedField"
    );
    assert!(mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::UnconsumedField { .. })));
}

#[test]
fn test_negative_control_recognized_unconsumed_field_sweep() {
    let (_chunk, dump) = get_base_test_pair();
    let parsed_dump = luad_oracle::listing_parser::parse_luac_dump(&dump).expect("Parses dump");
    let mut ledger = luad_oracle::listing_parser::RecordConsumptionLedger::from_dump(&parsed_dump);

    // Mark all clean fields as consumed
    for v in ledger.proto_fields.values_mut() {
        *v = true;
    }
    for v in ledger.inst_fields.values_mut() {
        *v = true;
    }
    for v in ledger.const_fields.values_mut() {
        *v = true;
    }
    for v in ledger.loc_fields.values_mut() {
        *v = true;
    }
    for v in ledger.upval_fields.values_mut() {
        *v = true;
    }

    let mut clean_mismatches = Vec::new();
    ledger.sweep_unconsumed(&mut clean_mismatches);
    assert!(
        clean_mismatches.is_empty(),
        "Fully consumed ledger must produce 0 unconsumed field mismatches"
    );

    // Deliberately register extra recognized fields in the ledger that are not marked consumed
    ledger
        .proto_fields
        .insert((0, "extra_unconsumed_proto_field"), false);
    ledger
        .inst_fields
        .insert((0, 0, "extra_unconsumed_inst_field"), false);

    let mut mismatches = Vec::new();
    ledger.sweep_unconsumed(&mut mismatches);

    assert_eq!(mismatches.len(), 2);
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::UnconsumedField { field, .. } if field.contains("extra_unconsumed_proto_field")
    )));
    assert!(mismatches.iter().any(|m| matches!(
        m,
        OracleMismatch::UnconsumedField { field, .. } if field.contains("extra_unconsumed_inst_field")
    )));
}

#[test]
fn test_negative_control_malformed_zero_valued_field_rejected() {
    let (chunk, dump) = get_base_test_pair();

    // 1. Malformed instruction line token
    let malformed_inst_dump = dump.replace("\t1\t[1]\t", "\tbad_pc\t[1]\t");
    let parse_res1 = luad_oracle::listing_parser::parse_luac_dump(&malformed_inst_dump);
    assert!(
        parse_res1.is_err(),
        "Non-numeric instruction index MUST be rejected"
    );
    let mismatches1 = compare_chunk_with_luac(&chunk, &malformed_inst_dump);
    assert!(!mismatches1.is_empty());

    // 2. Malformed line token (e.g. [-0] or [bad])
    let malformed_line_dump = dump.replace("\t1\t[1]\t", "\t1\t[bad]\t");
    let parse_res2 = luad_oracle::listing_parser::parse_luac_dump(&malformed_line_dump);
    assert!(parse_res2.is_err(), "Malformed line token MUST be rejected");
    let mismatches2 = compare_chunk_with_luac(&chunk, &malformed_line_dump);
    assert!(!mismatches2.is_empty());

    // 3. Malformed header line number
    assert!(dump.contains(":0,0>"));
    let malformed_header_dump = dump.replace(":0,0>", ":0,invalid>");
    let parse_res3 = luad_oracle::listing_parser::parse_luac_dump(&malformed_header_dump);
    assert!(
        parse_res3.is_err(),
        "Malformed header line number MUST be rejected"
    );
}

#[test]
fn test_negative_control_jmp_comment_changed_to_arbitrary_text_rejected() {
    let luac_path = require_luac54();
    let source = "local x = 1\nwhile x < 10 do\n  x = x + 1\nend\nreturn x";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");

    assert!(dump.contains("; to "));
    // Change "; to 4" (or whatever destination) to arbitrary non-semantic comment text
    let tampered_dump = dump.replace("; to ", "; arbitrary_comment_text ");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Changing JMP destination comment to arbitrary text MUST fail with JumpTargetMismatch"
    );
    assert!(mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::JumpTargetMismatch { .. })));
}

#[test]
fn test_negative_control_jmp_comment_changed_to_wrong_target_rejected() {
    let luac_path = require_luac54();
    let source = "local x = 1\nwhile x < 10 do\n  x = x + 1\nend\nreturn x";
    let raw_bytes = compile_source_lua54(source, false).expect("Compiles with luac 5.4");
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("Decodes chunk");
    let dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");

    assert!(dump.contains("; to "));
    let tampered_dump = dump.replace("; to ", "; to 99");
    assert_ne!(tampered_dump, dump);

    let mismatches = compare_chunk_with_luac(&chunk, &tampered_dump);
    assert!(
        !mismatches.is_empty(),
        "Changing JMP destination comment to wrong target MUST fail with JumpTargetMismatch"
    );
    assert!(mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::JumpTargetMismatch { .. })));
}
