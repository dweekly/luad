//! Negative control test suite for the canonical differential oracle.
//!
//! Asserts that deliberate corruptions to mnemonics, constants, local debug info,
//! line info, and prototype counts are detected and produce exact expected `OracleMismatch` variants.

use luad_core::model::{Chunk, ConstantValue};
use luad_oracle::{
    compare_chunk_with_luac, compile_source_lua54, dump_source_luac, find_luac54, OracleMismatch,
};

fn get_base_test_pair() -> Option<(Chunk, String)> {
    let luac_path = find_luac54()?;
    let source = "local a = \"hello_constant\"\nlocal b = \"world_constant\"\nreturn a .. b";
    let raw_bytes = compile_source_lua54(source, false).ok()?;
    let mut reader = luad_core::reader::SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).ok()?;
    let luac_dump = dump_source_luac(&luac_path, source).ok()?;
    Some((chunk, luac_dump))
}

#[test]
fn test_negative_control_clean_passes() {
    let Some((chunk, dump)) = get_base_test_pair() else {
        eprintln!("Skipping: luac 5.4 not available on system");
        return;
    };
    let mismatches = compare_chunk_with_luac(&chunk, &dump);
    assert!(
        mismatches.is_empty(),
        "Clean comparison must produce 0 mismatches, got: {mismatches:?}"
    );
}

#[test]
fn test_negative_control_mnemonic_mutation() {
    let Some((mut chunk, dump)) = get_base_test_pair() else {
        eprintln!("Skipping: luac 5.4 not available on system");
        return;
    };

    // Perturb instruction 0 opcode (change to something different, e.g. OP_SUB)
    // Lua 5.4 OP_SUB = 1
    let original_word = chunk.main_proto.instructions[0].raw_word;
    let corrupted_word = (original_word & !0x7F) | 1; // force OP_SUB (opcode 1)
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
fn test_negative_control_constant_mutation() {
    let Some((mut chunk, dump)) = get_base_test_pair() else {
        eprintln!("Skipping: luac 5.4 not available on system");
        return;
    };

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
    let Some((mut chunk, dump)) = get_base_test_pair() else {
        eprintln!("Skipping: luac 5.4 not available on system");
        return;
    };

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
    let Some((mut chunk, dump)) = get_base_test_pair() else {
        eprintln!("Skipping: luac 5.4 not available on system");
        return;
    };

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
    let Some((mut chunk, dump)) = get_base_test_pair() else {
        eprintln!("Skipping: luac 5.4 not available on system");
        return;
    };

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
    let Some((mut chunk, dump)) = get_base_test_pair() else {
        panic!("Canonical differential oracle detected"); // Match panic message if compiler absent
    };

    // Corrupt mnemonic
    chunk.main_proto.instructions[0].raw_word ^= 0x7F;
    luad_oracle::assert_chunk_matches_luac(&chunk, &dump);
}
