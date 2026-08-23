//! Comprehensive opcode table coverage, operand decoding, semantic effects, and control-flow verification across all 5 Lua dialects.

use luad_core::id::ProtoPath;
use luad_core::ir::{EffectTarget, TypedOperand};
use luad_core::model::{InstructionWord, Prototype};
use luad_core::provenance::SourceLocation;

#[test]
fn test_lua51_comprehensive_opcodes_operands_and_effects() {
    let num_opcodes = 38;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua51::Opcode51::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.1 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        // Construct synthetic instruction with realistic non-zero operands:
        // A=3, B=5, C=7, Bx=250, sBx=-10
        // Lua 5.1 layout: Op: 0..5, A: 6..13, C: 14..22, B: 23..31
        let a = 3u32;
        let c = 7u32;
        let b = 5u32;
        let raw_word = (op_num as u32 & 0x3f) | (a << 6) | (c << 14) | (b << 23);

        let dummy_proto = create_dummy_proto("lua5.1");
        let inst = InstructionWord {
            id: luad_core::id::StableId::instruction(dummy_proto.path.clone(), 0),
            pc: 0,
            raw_word,
            raw_hex: hex::encode(raw_word.to_le_bytes()),
            source: SourceLocation::new(0, &raw_word.to_le_bytes()),
        };
        let lifted = luad_dialect_lua51::lift_proto_lua51(&Prototype {
            instructions: vec![inst],
            ..dummy_proto.clone()
        });
        let sem = &lifted[0];
        assert_eq!(sem.mnemonic, op.name());
        assert!(
            !sem.source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
        for cite in &sem.source_citations {
            assert!(
                cite.starts_with("lua-5.1.5:src/"),
                "Citation for {} must be pinned to lua-5.1.5:src/: got '{cite}'",
                op.name()
            );
        }

        // Verify operand decoding
        assert!(
            !sem.operands.is_empty() || sem.mnemonic == "VARARG",
            "Opcode {} missing operands",
            op.name()
        );

        // Verify specific semantic classes
        match op.name() {
            "MOVE" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 3, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Register { index: 5, .. })));
            }
            "LOADK" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 3, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Constant { .. })));
            }
            "LOADBOOL" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 3, .. })));
            }
            "LOADNIL" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::RegisterRange { start: 3, .. })));
            }
            "GETUPVAL" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 3, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Upvalue { index: 5, .. })));
            }
            "SETUPVAL" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Upvalue { index: 5, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Register { index: 3, .. })));
            }
            "ADD" | "SUB" | "MUL" | "DIV" | "MOD" | "POW" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 3, .. })));
                assert!(!sem.metamethod_fallbacks.is_empty());
            }
            "CALL" | "TAILCALL" => {
                assert!(sem.metamethod_fallbacks.contains(&"__call".to_string()));
            }
            "JMP" => {
                assert!(sem.jump_target.is_some());
            }
            _ => {}
        }
    }
    assert!(luad_dialect_lua51::Opcode51::from_u8(38).is_none());
}

#[test]
fn test_lua52_comprehensive_opcodes_operands_and_effects() {
    let num_opcodes = 40;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua52::Opcode52::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.2 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        let a = 2u32;
        let c = 4u32;
        let b = 6u32;
        let raw_word = (op_num as u32 & 0x3f) | (a << 6) | (c << 14) | (b << 23);

        let dummy_proto = create_dummy_proto("lua5.2");
        let inst = InstructionWord {
            id: luad_core::id::StableId::instruction(dummy_proto.path.clone(), 0),
            pc: 0,
            raw_word,
            raw_hex: hex::encode(raw_word.to_le_bytes()),
            source: SourceLocation::new(0, &raw_word.to_le_bytes()),
        };
        let lifted = luad_dialect_lua52::lift_proto_lua52(&Prototype {
            instructions: vec![inst],
            ..dummy_proto.clone()
        });
        let sem = &lifted[0];
        assert_eq!(sem.mnemonic, op.name());
        assert!(
            !sem.source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
        for cite in &sem.source_citations {
            assert!(
                cite.starts_with("lua-5.2.4:src/"),
                "Citation for {} must be pinned to lua-5.2.4:src/: got '{cite}'",
                op.name()
            );
        }

        match op.name() {
            "MOVE" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 2, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Register { index: 6, .. })));
            }
            "ADD" | "SUB" | "MUL" | "DIV" | "MOD" | "POW" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 2, .. })));
                assert!(!sem.metamethod_fallbacks.is_empty());
            }
            "JMP" => {
                assert!(sem.jump_target.is_some());
            }
            "CALL" => {
                assert!(sem.metamethod_fallbacks.contains(&"__call".to_string()));
            }
            _ => {}
        }
    }
    assert!(luad_dialect_lua52::Opcode52::from_u8(40).is_none());
}

#[test]
fn test_lua53_comprehensive_opcodes_operands_and_effects() {
    let num_opcodes = 47;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua53::Opcode53::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.3 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        let a = 2u32;
        let c = 4u32;
        let b = 6u32;
        let raw_word = (op_num as u32 & 0x3f) | (a << 6) | (c << 14) | (b << 23);

        let dummy_proto = create_dummy_proto("lua5.3");
        let inst = InstructionWord {
            id: luad_core::id::StableId::instruction(dummy_proto.path.clone(), 0),
            pc: 0,
            raw_word,
            raw_hex: hex::encode(raw_word.to_le_bytes()),
            source: SourceLocation::new(0, &raw_word.to_le_bytes()),
        };
        let lifted = luad_dialect_lua53::lift_proto_lua53(&Prototype {
            instructions: vec![inst],
            ..dummy_proto.clone()
        });
        let sem = &lifted[0];
        assert_eq!(sem.mnemonic, op.name());
        assert!(
            !sem.source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
        for cite in &sem.source_citations {
            assert!(
                cite.starts_with("lua-5.3.6:src/"),
                "Citation for {} must be pinned to lua-5.3.6:src/: got '{cite}'",
                op.name()
            );
        }

        match op.name() {
            "MOVE" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 2, .. })));
            }
            "IDIV" | "BAND" | "BOR" | "BXOR" | "SHL" | "SHR" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 2, .. })));
                assert!(!sem.metamethod_fallbacks.is_empty());
            }
            "JMP" => {
                assert!(sem.jump_target.is_some());
            }
            _ => {}
        }
    }
    assert!(luad_dialect_lua53::Opcode53::from_u8(47).is_none());
}

#[test]
fn test_lua54_comprehensive_opcodes_operands_and_effects() {
    let num_opcodes = 83;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua54::Opcode54::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.4 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        let a = 1u8;
        let b = 2u8;
        let c = 3u8;
        let raw_word = luad_dialect_lua54::RawInstruction54::encode_iabc(op, a, b, c, 0);

        let dummy_proto = create_dummy_proto("lua5.4");
        let inst = InstructionWord {
            id: luad_core::id::StableId::instruction(dummy_proto.path.clone(), 0),
            pc: 0,
            raw_word,
            raw_hex: hex::encode(raw_word.to_le_bytes()),
            source: SourceLocation::new(0, &raw_word.to_le_bytes()),
        };
        let lifted = luad_dialect_lua54::lift_proto_lua54(&Prototype {
            instructions: vec![inst],
            ..dummy_proto.clone()
        });
        let sem = &lifted[0];
        assert_eq!(sem.mnemonic, op.name());
        assert!(
            !sem.source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
        for cite in &sem.source_citations {
            assert!(
                cite.starts_with("lua-5.4.8:src/"),
                "Citation for {} must be pinned to lua-5.4.8:src/: got '{cite}'",
                op.name()
            );
        }

        match op.name() {
            "MOVE" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 1, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Register { index: 2, .. })));
            }
            "LOADI" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 1, .. })));
                assert!(sem
                    .operands
                    .iter()
                    .any(|op| matches!(op, TypedOperand::ImmediateInt { .. })));
            }
            "ADDI" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 1, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Register { index: 2, .. })));
            }
            "JMP" => {
                assert!(sem.jump_target.is_some());
            }
            "MMBIN" | "MMBINI" | "MMBINK" => {
                assert!(!sem.metamethod_fallbacks.is_empty());
            }
            _ => {}
        }
    }
    assert!(luad_dialect_lua54::Opcode54::from_u8(83).is_none());
}

#[test]
fn test_lua55_comprehensive_opcodes_operands_and_effects() {
    let num_opcodes = 85;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua55::Opcode55::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.5 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        let a = 1u32;
        let b = 2u32;
        let c = 3u32;
        let raw_word = (op_num as u32 & 0x7f) | (a << 7) | (b << 16) | (c << 24);

        let dummy_proto = create_dummy_proto("lua5.5");
        let inst = InstructionWord {
            id: luad_core::id::StableId::instruction(dummy_proto.path.clone(), 0),
            pc: 0,
            raw_word,
            raw_hex: hex::encode(raw_word.to_le_bytes()),
            source: SourceLocation::new(0, &raw_word.to_le_bytes()),
        };
        let lifted = luad_dialect_lua55::lift_proto_lua55(&Prototype {
            instructions: vec![inst],
            ..dummy_proto.clone()
        });
        let sem = &lifted[0];
        assert_eq!(sem.mnemonic, op.name());
        assert!(
            !sem.source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
        for cite in &sem.source_citations {
            assert!(
                cite.starts_with("lua-5.5.1:src/"),
                "Citation for {} must be pinned to lua-5.5.1:src/: got '{cite}'",
                op.name()
            );
        }

        match op.name() {
            "MOVE" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 1, .. })));
                assert!(sem
                    .reads
                    .iter()
                    .any(|r| matches!(r, EffectTarget::Register { index: 2, .. })));
            }
            "LOADI" => {
                assert!(sem
                    .writes
                    .iter()
                    .any(|w| matches!(w, EffectTarget::Register { index: 1, .. })));
                assert!(sem
                    .operands
                    .iter()
                    .any(|op| matches!(op, TypedOperand::ImmediateInt { .. })));
            }
            "JMP" => {
                assert!(sem.jump_target.is_some());
            }
            "MMBIN" | "MMBINI" | "MMBINK" => {
                assert!(!sem.metamethod_fallbacks.is_empty());
            }
            _ => {}
        }
    }
    assert!(luad_dialect_lua55::Opcode55::from_u8(85).is_none());
}

fn create_dummy_proto(_dialect: &str) -> Prototype {
    Prototype {
        id: luad_core::id::StableId::proto(ProtoPath::root()),
        path: ProtoPath::root(),
        source_name: None,
        line_defined: 1,
        last_line_defined: 10,
        numparams: 0,
        is_vararg: 0,
        maxstacksize: 10,
        instructions: vec![],
        constants: vec![],
        upvalues: vec![],
        protos: vec![],
        line_info: vec![],
        abs_line_info: vec![],
        loc_vars: vec![],
        upvalue_names: vec![],
        source: SourceLocation::new(0, &[]),
    }
}
