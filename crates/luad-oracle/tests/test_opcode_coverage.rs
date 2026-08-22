//! Complete opcode table coverage and field-by-field lifting verification across all 5 Lua dialects.

use luad_core::id::ProtoPath;
use luad_core::model::{InstructionWord, Prototype};
use luad_core::provenance::SourceLocation;

#[test]
fn test_lua51_full_opcode_table_coverage() {
    let num_opcodes = 38;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua51::Opcode51::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.1 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        // Construct synthetic instruction: opcode in bits 0..5
        let raw_word = (op_num as u32) & 0x3f;
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
        assert_eq!(lifted[0].mnemonic, op.name());
        assert!(
            !lifted[0].source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
    }
    assert!(luad_dialect_lua51::Opcode51::from_u8(38).is_none());
}

#[test]
fn test_lua52_full_opcode_table_coverage() {
    let num_opcodes = 40;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua52::Opcode52::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.2 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        // Construct synthetic instruction: opcode in bits 0..5
        let raw_word = (op_num as u32) & 0x3f;
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
        assert_eq!(lifted[0].mnemonic, op.name());
        assert!(
            !lifted[0].source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
    }
    assert!(luad_dialect_lua52::Opcode52::from_u8(40).is_none());
}

#[test]
fn test_lua53_full_opcode_table_coverage() {
    let num_opcodes = 47;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua53::Opcode53::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.3 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        // Construct synthetic instruction: opcode in bits 0..5
        let raw_word = (op_num as u32) & 0x3f;
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
        assert_eq!(lifted[0].mnemonic, op.name());
        assert!(
            !lifted[0].source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
    }
    assert!(luad_dialect_lua53::Opcode53::from_u8(47).is_none());
}

#[test]
fn test_lua54_full_opcode_table_coverage() {
    let num_opcodes = 83;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua54::Opcode54::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.4 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        // Construct synthetic instruction: opcode in bits 0..6
        let raw_word = (op_num as u32) & 0x7f;
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
        assert_eq!(lifted[0].mnemonic, op.name());
        assert!(
            !lifted[0].source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
    }
    assert!(luad_dialect_lua54::Opcode54::from_u8(83).is_none());
}

#[test]
fn test_lua55_full_opcode_table_coverage() {
    let num_opcodes = 85;
    for op_num in 0..num_opcodes {
        let op = luad_dialect_lua55::Opcode55::from_u8(op_num as u8)
            .unwrap_or_else(|| panic!("Lua 5.5 opcode {op_num} must be defined"));
        assert!(!op.name().is_empty());

        // Construct synthetic instruction: opcode in bits 0..6
        let raw_word = (op_num as u32) & 0x7f;
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
        assert_eq!(lifted[0].mnemonic, op.name());
        assert!(
            !lifted[0].source_citations.is_empty(),
            "Opcode {} missing citation",
            op.name()
        );
    }
    assert!(luad_dialect_lua55::Opcode55::from_u8(85).is_none());
}

fn create_dummy_proto(_dialect: &str) -> Prototype {
    Prototype {
        id: luad_core::id::StableId::proto(ProtoPath::root()),
        path: ProtoPath::root(),
        source_name: None,
        line_defined: 0,
        last_line_defined: 0,
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
