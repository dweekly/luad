//! Lua 5.5 instruction semantics, golden vectors, and effect verification.

use luad_core::ir::ImplicitEffect;
use luad_core::model::InstructionWord;
use luad_core::SourceLocation;
use luad_dialect_lua55::{lift_proto_lua55, OpMode55, Opcode55, RawInstruction55};

#[test]
fn test_lua55_golden_word_vectors() {
    // 1. MOVE 0 1 (A=0, B=1, C=0, k=0) -> 0x00010000
    let word_move = 0x00010000;
    let raw_move = RawInstruction55::decode(word_move);
    assert_eq!(raw_move.opcode, Some(Opcode55::Move));
    assert_eq!(raw_move.a, 0);
    assert_eq!(raw_move.b, 1);
    assert_eq!(raw_move.c, 0);
    assert_eq!(raw_move.k, 0);
    assert_eq!(raw_move.encode(), Some(word_move));

    // 2. LOADI 0 42 (A=0, sBx=42, Bx = 42 + 65535 = 65577)
    let word_loadi = RawInstruction55::encode_iasbx(Opcode55::Loadi, 0, 42);
    let raw_loadi = RawInstruction55::decode(word_loadi);
    assert_eq!(raw_loadi.opcode, Some(Opcode55::Loadi));
    assert_eq!(raw_loadi.a, 0);
    assert_eq!(raw_loadi.sbx, 42);
    assert_eq!(raw_loadi.encode(), Some(word_loadi));

    // 3. ADDI 0 1 -5 (A=0, B=1, sC=-5 -> C=122, k=0)
    let word_addi = RawInstruction55::encode_iabc(Opcode55::Addi, 0, 1, (-5 + 127) as u8, 0);
    let raw_addi = RawInstruction55::decode(word_addi);
    assert_eq!(raw_addi.opcode, Some(Opcode55::Addi));
    assert_eq!(raw_addi.a, 0);
    assert_eq!(raw_addi.b, 1);
    assert_eq!(raw_addi.sc, -5);
    assert_eq!(raw_addi.encode(), Some(word_addi));

    // 4. SETLIST 2 10 500 (A=2, vB=10, vC=500, k=0)
    let word_setlist = RawInstruction55::encode_ivabc(Opcode55::Setlist, 2, 10, 500, 0);
    let raw_setlist = RawInstruction55::decode(word_setlist);
    assert_eq!(raw_setlist.opcode, Some(Opcode55::Setlist));
    assert_eq!(raw_setlist.a, 2);
    assert_eq!(raw_setlist.vb, 10);
    assert_eq!(raw_setlist.vc, 500);
    assert_eq!(raw_setlist.encode(), Some(word_setlist));

    // 5. JMP -100
    let word_jmp = RawInstruction55::encode_isj(Opcode55::Jmp, -100);
    let raw_jmp = RawInstruction55::decode(word_jmp);
    assert_eq!(raw_jmp.opcode, Some(Opcode55::Jmp));
    assert_eq!(raw_jmp.sj, -100);
    assert_eq!(raw_jmp.encode(), Some(word_jmp));
}

#[test]
fn test_lua55_all_85_opcodes_round_trip() {
    for op_idx in 0..=84 {
        let op = Opcode55::from_u8(op_idx).expect("Valid opcode");
        let word = match op.mode() {
            OpMode55::IABC => RawInstruction55::encode_iabc(op, 10, 20, 30, 1),
            OpMode55::IvABC => RawInstruction55::encode_ivabc(op, 10, 25, 600, 0),
            OpMode55::IABx => RawInstruction55::encode_iabx(op, 10, 5000),
            OpMode55::IAsBx => RawInstruction55::encode_iasbx(op, 10, -500),
            OpMode55::IAx => RawInstruction55::encode_iax(op, 123456),
            OpMode55::IsJ => RawInstruction55::encode_isj(op, -1000),
        };

        let decoded = RawInstruction55::decode(word);
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
fn test_lua55_metamethod_dispatch_companions() {
    let word_add = RawInstruction55::encode_iabc(Opcode55::Add, 0, 1, 2, 0);
    let word_mmbin = RawInstruction55::encode_iabc(Opcode55::Mmbin, 0, 1, 0, 0); // TM_ADD = 0

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
                raw_word: word_mmbin,
                raw_hex: hex::encode(word_mmbin.to_le_bytes()),
                source: SourceLocation::new(4, &word_mmbin.to_le_bytes()),
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

    let lifted = lift_proto_lua55(&proto);
    assert_eq!(lifted.len(), 2);
    let mmbin_inst = &lifted[1];
    assert_eq!(mmbin_inst.mnemonic, "MMBIN");
    assert_eq!(mmbin_inst.companion_pc, Some(0));
    assert!(mmbin_inst
        .metamethod_fallbacks
        .contains(&"__add".to_string()));
    assert!(mmbin_inst.implicit_effects.iter().any(|e| matches!(
        e,
        ImplicitEffect::CompanionPair {
            companion_pc: 0,
            ..
        }
    )));
}
