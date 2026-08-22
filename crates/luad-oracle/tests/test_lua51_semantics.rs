//! Lua 5.1 instruction semantics, golden vectors, and effect verification.

use luad_core::model::InstructionWord;
use luad_core::SourceLocation;
use luad_dialect_lua51::{lift_proto_lua51, OpMode51, Opcode51, RawInstruction51};

#[test]
fn test_lua51_golden_word_vectors() {
    // 1. MOVE 0 1 (A=0, B=1, C=0)
    let word_move = RawInstruction51::encode_iabc(Opcode51::Move, 0, 1, 0);
    let raw_move = RawInstruction51::decode(word_move);
    assert_eq!(raw_move.opcode, Some(Opcode51::Move));
    assert_eq!(raw_move.a, 0);
    assert_eq!(raw_move.b, 1);
    assert_eq!(raw_move.c, 0);
    assert_eq!(raw_move.encode(), Some(word_move));

    // 2. LOADK 0 42 (A=0, Bx=42)
    let word_loadk = RawInstruction51::encode_iabx(Opcode51::LoadK, 0, 42);
    let raw_loadk = RawInstruction51::decode(word_loadk);
    assert_eq!(raw_loadk.opcode, Some(Opcode51::LoadK));
    assert_eq!(raw_loadk.a, 0);
    assert_eq!(raw_loadk.bx, 42);
    assert_eq!(raw_loadk.encode(), Some(word_loadk));

    // 3. JMP 0 -100 (A=0, sBx=-100)
    let word_jmp = RawInstruction51::encode_iasbx(Opcode51::Jmp, 0, -100);
    let raw_jmp = RawInstruction51::decode(word_jmp);
    assert_eq!(raw_jmp.opcode, Some(Opcode51::Jmp));
    assert_eq!(raw_jmp.sbx, -100);
    assert_eq!(raw_jmp.encode(), Some(word_jmp));
}

#[test]
fn test_lua51_all_38_opcodes_round_trip() {
    for op_idx in 0..=37 {
        let op = Opcode51::from_u8(op_idx).expect("Valid opcode");
        let word = match op.mode() {
            OpMode51::IABC => RawInstruction51::encode_iabc(op, 10, 20, 30),
            OpMode51::IABx => RawInstruction51::encode_iabx(op, 10, 5000),
            OpMode51::IAsBx => RawInstruction51::encode_iasbx(op, 10, -500),
        };

        let decoded = RawInstruction51::decode(word);
        assert_eq!(decoded.opcode, Some(op), "Opcode mismatch for #{op_idx}");
        assert_eq!(
            decoded.encode(),
            Some(word),
            "Round-trip encode mismatch for #{op_idx} ({})",
            op.name()
        );
    }
}

#[test]
fn test_lua51_lifting_and_effects() {
    let word_add = RawInstruction51::encode_iabc(Opcode51::Add, 0, 1, 2);
    let word_ret = RawInstruction51::encode_iabc(Opcode51::Return, 0, 2, 0);

    let proto = luad_core::model::Prototype {
        id: "proto:0".parse().unwrap(),
        path: luad_core::ProtoPath::root(),
        source_name: None,
        line_defined: 1,
        last_line_defined: 2,
        numparams: 0,
        is_vararg: 0,
        maxstacksize: 10,
        instructions: vec![
            InstructionWord {
                id: "proto:0:pc:0".parse().unwrap(),
                pc: 0,
                raw_word: word_add,
                raw_hex: hex::encode(word_add.to_le_bytes()),
                source: SourceLocation::new(0, &word_add.to_le_bytes()),
            },
            InstructionWord {
                id: "proto:0:pc:1".parse().unwrap(),
                pc: 1,
                raw_word: word_ret,
                raw_hex: hex::encode(word_ret.to_le_bytes()),
                source: SourceLocation::new(4, &word_ret.to_le_bytes()),
            },
        ],
        constants: vec![],
        upvalues: vec![],
        protos: vec![],
        line_info: vec![],
        abs_line_info: vec![],
        loc_vars: vec![],
        upvalue_names: vec![],
        source: SourceLocation::new(0, &[]),
    };

    let lifted = lift_proto_lua51(&proto);
    assert_eq!(lifted.len(), 2);
    assert_eq!(lifted[0].mnemonic, "ADD");
    assert_eq!(lifted[1].mnemonic, "RETURN");
}
