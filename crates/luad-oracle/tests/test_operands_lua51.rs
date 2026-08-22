//! Gate L3: Lua 5.1 resolved constant-bearing operands tests.

use luad_core::ir::TypedOperand;
use luad_core::model::ConstantValue;
use luad_core::reader::SafeReader;
use luad_dialect_lua51::{
    decode_chunk_lua51, lift_proto_lua51, validate_chunk_lua51, Opcode51, RawInstruction51,
    BITRK_51,
};
use luad_oracle::get_fixture_bytes;

#[test]
fn test_lua51_operand_resolution_getglobal() {
    let raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    let lifted = lift_proto_lua51(&chunk.main_proto);

    let getglobal = lifted
        .iter()
        .find(|i| i.mnemonic == "GETGLOBAL")
        .expect("GETGLOBAL present in hello fixture");

    // Second operand must be resolved TypedOperand::Constant
    assert_eq!(getglobal.operands.len(), 2);
    match &getglobal.operands[1] {
        TypedOperand::Constant { index, value } => {
            assert_eq!(*index, 0); // "print" is constant 0
            match value {
                ConstantValue::ShortString(s) => assert_eq!(s.as_str(), "print"),
                _ => panic!("Expected ShortString constant for GETGLOBAL"),
            }
        }
        other => panic!("Expected TypedOperand::Constant, found {:?}", other),
    }
}

#[test]
fn test_lua51_operand_resolution_rk_operands() {
    let raw_bytes = get_fixture_bytes("lua5.1", "numerics", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    let lifted = lift_proto_lua51(&chunk.main_proto);

    let has_rk_const = lifted.iter().any(|i| {
        i.operands
            .iter()
            .any(|op| matches!(op, TypedOperand::Constant { .. }))
    });
    assert!(
        has_rk_const,
        "Numerics fixture must contain resolved constant operands"
    );
}

#[test]
fn test_negative_control_getglobal_oob_rejected() {
    let raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let mut chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    // Replace first instruction (GETGLOBAL) with Bx = 5000 (out of bounds)
    let bad_inst = RawInstruction51::encode_iabx(Opcode51::GetGlobal, 0, 5000);
    chunk.main_proto.instructions[0].raw_word = bad_inst;

    let (verdict, diags) = validate_chunk_lua51(&chunk);
    assert_eq!(
        verdict,
        luad_core::diagnostic::Verdict::Invalid,
        "Out of bounds GETGLOBAL must fail validation"
    );
    assert!(
        diags.iter().any(|d| d.code == "L51-CONST-003"),
        "Expected L51-CONST-003 diagnostic, found: {:?}",
        diags
    );
}

#[test]
fn test_negative_control_rk_constant_oob_rejected() {
    let raw_bytes = get_fixture_bytes("lua5.1", "numerics", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let mut chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    // Encode ADD R(0), R(1), K(500)
    let bad_add = RawInstruction51::encode_iabc(
        Opcode51::Add,
        0,
        1,
        (BITRK_51 as u16) | 500, // C is constant index 500 (OOB)
    );
    chunk.main_proto.instructions[0].raw_word = bad_add;

    let (verdict, diags) = validate_chunk_lua51(&chunk);
    assert_eq!(
        verdict,
        luad_core::diagnostic::Verdict::Invalid,
        "Out of bounds RK constant must fail validation"
    );
    assert!(
        diags.iter().any(|d| d.code == "L51-CONST-005"),
        "Expected L51-CONST-005 diagnostic, found: {:?}",
        diags
    );
}
