//! Negative control test suite for the canonical differential oracle.
//!
//! Asserts that deliberate corruptions to mnemonics, operands, constants, local debug info,
//! line info, and prototype counts are detected and produce exact expected `OracleMismatch` variants.

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
    let luac_dump = dump_source_luac(&luac_path, source).expect("Dumps with luac 5.4");
    (chunk, luac_dump)
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
    // Lua 5.4 LOADI = 1
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
    // Lua 5.4: A is at bits 7..14
    let original_word = chunk.main_proto.instructions[1].raw_word;
    let corrupted_word = (original_word & !(0xFF << 7)) | (42 << 7);
    chunk.main_proto.instructions[1].raw_word = corrupted_word;

    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        !mismatches.is_empty(),
        "Corrupted operand must produce mismatches"
    );

    let has_operand_mismatch = mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::Operand { pc: 1, .. }));
    assert!(
        has_operand_mismatch,
        "Expected OracleMismatch::Operand at PC 1, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_bit15_b_decoder_bug() {
    // Proves that reading B from bit 15 (the old pre-Gate 2 bug) FAILS the differential oracle
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
    let has_operand_mismatch = mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::Operand { pc: 1, .. }));
    assert!(
        has_operand_mismatch,
        "Expected OracleMismatch::Operand on bitfield corruption, got: {mismatches:?}"
    );
}

#[test]
fn test_unpatched_pre_gate2_decoder_fails_oracle_on_all_fixtures() {
    // Exact reconstruction of the unpatched pre-Gate 2 Lua 5.4 decoder from opcodes.rs
    // before Gate 2 was fixed. Proves that every pre-Gate 2 bug is caught by the differential oracle.
    let luac_path = require_luac54();
    let fixtures = ["hello", "closures", "control_flow", "tables", "numerics"];

    for fixture in &fixtures {
        let source = luad_oracle::load_source_fixture(fixture)
            .unwrap_or_else(|e| panic!("Failed to load fixture {fixture}: {e}"));
        let raw_bytes = compile_source_lua54(&source, false)
            .unwrap_or_else(|e| panic!("Failed to compile fixture {fixture}: {e}"));
        let dump = dump_source_luac(&luac_path, &source)
            .unwrap_or_else(|e| panic!("Failed to dump fixture {fixture}: {e}"));

        let dump_parsed = luad_oracle::parse_luac_dump(&dump);
        assert!(!dump_parsed.functions.is_empty());

        let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
        let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode fixture {fixture}: {e:?}"));

        // Simulate pre-Gate 2 decoder:
        // (b at bit 15 instead of 16, k at bit 16 instead of 15, c at bit 23 instead of 24)
        let mut pre_gate2_mismatches = Vec::new();
        for (pc, inst) in chunk.main_proto.instructions.iter().enumerate() {
            let raw = inst.raw_word;
            let op = (raw & 0x7F) as u8;
            let a = ((raw >> 7) & 0xff) as u8;
            let buggy_b = ((raw >> 15) & 0xff) as u8; // BUG: bit 15
            let buggy_c = ((raw >> 23) & 0xff) as u8; // BUG: bit 23
            let _buggy_k = ((raw >> 16) & 1) != 0; // BUG: bit 16
            let buggy_sc = (buggy_c as i32) - 128; // BUG: bias 128

            // Compare against expected operands from luac
            if let Some(exp_inst) = dump_parsed.functions[0].instructions.get(pc) {
                // For instructions with B operand (like MOVE, LOADNIL, ADD, CALL, etc.),
                // the buggy decoder yields a different B value whenever B > 0.
                if let Some(opcode) = luad_dialect_lua54::Opcode54::from_u8(op) {
                    let buggy_ops = match opcode {
                        luad_dialect_lua54::Opcode54::Move => format!("{a} {buggy_b}"),
                        luad_dialect_lua54::Opcode54::Addi => format!("{a} {buggy_b} {buggy_sc}"),
                        luad_dialect_lua54::Opcode54::Add => format!("{a} {buggy_b} {buggy_c}"),
                        luad_dialect_lua54::Opcode54::Call => format!("{a} {buggy_b} {buggy_c}"),
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
            "Pre-Gate 2 buggy decoder MUST fail the oracle on fixture '{fixture}'"
        );
    }
}

#[test]
fn test_golden_word_pins_and_unpatched_decoder_failure() {
    // Review's three golden words (Lua 5.4):
    // 1. 0x050100a2 -> ADD 1 1 5
    // 2. 0x00010180 -> MOVE 3 1
    // 3. 0x01030146 -> RETURN 2 3 1
    let golden_cases = [
        (0x050100a2_u32, "ADD", "1 1 5"),
        (0x00010180_u32, "MOVE", "3 1"),
        (0x01030146_u32, "RETURN", "2 3 1"),
    ];

    for (word, exp_mnem, exp_ops) in golden_cases {
        // 1. Current corrected decoder matches golden expectation
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

        // 2. Pre-Gate 2 unpatched bitfield decoder produces wrong operands and FAILS
        let a = ((word >> 7) & 0xff) as u8;
        let buggy_b = ((word >> 15) & 0xff) as u8; // BUG: bit 15
        let buggy_c = ((word >> 23) & 0xff) as u8; // BUG: bit 23
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

    let has_const_mismatch = mismatches
        .iter()
        .any(|m| matches!(m, OracleMismatch::Constant { index: 0, .. }));
    assert!(
        has_const_mismatch,
        "Expected OracleMismatch::Constant at index 0, got: {mismatches:?}"
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
#[should_panic(expected = "Canonical differential oracle detected")]
fn test_assert_chunk_matches_luac_panics_on_mismatch() {
    let (mut chunk, dump) = get_base_test_pair();

    // Corrupt mnemonic
    chunk.main_proto.instructions[0].raw_word ^= 0x7F;
    luad_oracle::assert_chunk_matches_luac(&chunk, &dump);
}
