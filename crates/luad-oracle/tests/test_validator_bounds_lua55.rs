//! Validator bounds and operand validation tests for Lua 5.5.

use luad_core::diagnostic::{Severity, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::InstructionWord;
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;
use luad_dialect_lua55::{validate_chunk_lua55, Opcode55, RawInstruction55};
use luad_oracle::get_fixture_bytes;

fn create_valid_chunk_55() -> luad_core::model::Chunk {
    let raw_bytes = get_fixture_bytes("lua5.5", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    luad_dialect_lua55::decode_chunk_lua55(&mut reader).expect("clean decode")
}

fn make_inst(pc: usize, raw_word: u32) -> InstructionWord {
    InstructionWord {
        id: StableId::instruction(ProtoPath::root(), pc),
        pc,
        raw_word,
        raw_hex: hex::encode(raw_word.to_le_bytes()),
        source: SourceLocation::new(pc * 4, &raw_word.to_le_bytes()),
    }
}

#[test]
fn test_lua55_clean_fixture_validates_as_valid_for_parser() {
    let chunk = create_valid_chunk_55();
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::ValidForParser);
    assert!(
        !diags.iter().any(|d| d.severity == Severity::Error),
        "Clean Lua 5.5 fixture must have no error diagnostics: {diags:?}"
    );
}

#[test]
fn test_lua55_stack_bounds_warning() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 255;
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::ValidForParser);
    assert!(diags.iter().any(|d| d.code == "L55-STACK-001"));
}

#[test]
fn test_lua55_invalid_opcode() {
    let mut chunk = create_valid_chunk_55();
    let bad_word = 85; // opcode 85 exceeds 84
    chunk.main_proto.instructions = vec![make_inst(0, bad_word)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-OP-001"));
}

#[test]
fn test_lua55_companion_pairing() {
    // 1. LOADKX without EXTRAARG
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 10;
    let loadkx = RawInstruction55::encode_iabx(Opcode55::Loadkx, 0, 0);
    let ret = RawInstruction55::encode_iabc(Opcode55::Return0, 0, 0, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, loadkx), make_inst(1, ret)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-COMPANION-001"));

    // 2. Standalone EXTRAARG without LOADKX
    let mut chunk2 = create_valid_chunk_55();
    chunk2.main_proto.maxstacksize = 10;
    let extra = RawInstruction55::encode_iax(Opcode55::Extraarg, 0);
    chunk2.main_proto.instructions = vec![make_inst(0, extra), make_inst(1, ret)];
    let (verdict2, diags2) = validate_chunk_lua55(&chunk2);
    assert_eq!(verdict2, Verdict::Invalid);
    assert!(diags2.iter().any(|d| d.code == "L55-COMPANION-001"));
}

#[test]
fn test_lua55_register_a_bounds() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 5;
    // MOVE R(5), R(0) exceeds maxstacksize 5
    let move_inst = RawInstruction55::encode_iabc(Opcode55::Move, 5, 0, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, move_inst)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-REG-001"));
}

#[test]
fn test_lua55_register_b_bounds() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 5;
    // MOVE R(0), R(5) exceeds maxstacksize 5
    let move_inst = RawInstruction55::encode_iabc(Opcode55::Move, 0, 5, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, move_inst)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-REG-002"));
}

#[test]
fn test_lua55_register_c_bounds() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 5;
    // ADD R(0), R(1), R(5) exceeds maxstacksize 5
    let add_inst = RawInstruction55::encode_iabc(Opcode55::Add, 0, 1, 5, 0);
    chunk.main_proto.instructions = vec![make_inst(0, add_inst)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-REG-003"));
}

#[test]
fn test_lua55_constant_bounds() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 10;
    chunk.main_proto.constants = vec![]; // 0 constants
                                         // LOADK R(0), K(0) when table size is 0
    let loadk = RawInstruction55::encode_iabx(Opcode55::Loadk, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, loadk)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-CONST-002"));

    // ADDK with C constant index 5
    let mut chunk2 = create_valid_chunk_55();
    chunk2.main_proto.maxstacksize = 10;
    chunk2.main_proto.constants = vec![];
    let addk = RawInstruction55::encode_iabc(Opcode55::Addk, 0, 0, 5, 0);
    chunk2.main_proto.instructions = vec![make_inst(0, addk)];
    let (verdict2, diags2) = validate_chunk_lua55(&chunk2);
    assert_eq!(verdict2, Verdict::Invalid);
    assert!(diags2.iter().any(|d| d.code == "L55-CONST-002"));
}

#[test]
fn test_lua55_upvalue_bounds() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 10;
    chunk.main_proto.upvalues = vec![]; // 0 upvalues
    let getupval = RawInstruction55::encode_iabc(Opcode55::Getupval, 0, 0, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, getupval)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-UPVAL-002"));

    // SETTABUP with A=0 (upvalue 0) when upvalues is empty
    let settabup = RawInstruction55::encode_iabc(Opcode55::Settabup, 0, 0, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, settabup)];
    let (verdict2, diags2) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict2, Verdict::Invalid);
    assert!(diags2.iter().any(|d| d.code == "L55-UPVAL-002"));
}

#[test]
fn test_lua55_proto_bounds() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 10;
    chunk.main_proto.protos = vec![]; // 0 protos
    let closure = RawInstruction55::encode_iabx(Opcode55::Closure, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, closure)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-PROTO-002"));
}

#[test]
fn test_lua55_jump_bounds() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 10;
    // JMP with offset +10 when total instructions is 1
    let jmp = RawInstruction55::encode_isj(Opcode55::Jmp, 10);
    chunk.main_proto.instructions = vec![make_inst(0, jmp)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-JMP-001"));
}

#[test]
fn test_lua55_register_spans() {
    let mut chunk = create_valid_chunk_55();
    chunk.main_proto.maxstacksize = 5;
    // LOADNIL A=3, B=2 -> sets R(3)..R(5), exceeds maxstacksize 5
    let loadnil = RawInstruction55::encode_iabc(Opcode55::Loadnil, 3, 2, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, loadnil)];
    let (verdict, diags) = validate_chunk_lua55(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L55-REG-SPAN-001"));

    // FORLOOP with A=3 (span R(3)..R(6)) exceeds maxstacksize 5
    let mut chunk2 = create_valid_chunk_55();
    chunk2.main_proto.maxstacksize = 5;
    let forloop = RawInstruction55::encode_iabx(Opcode55::Forloop, 3, 0);
    chunk2.main_proto.instructions = vec![make_inst(0, forloop)];
    let (verdict2, diags2) = validate_chunk_lua55(&chunk2);
    assert_eq!(verdict2, Verdict::Invalid);
    assert!(diags2.iter().any(|d| d.code == "L55-REG-SPAN-001"));
}
