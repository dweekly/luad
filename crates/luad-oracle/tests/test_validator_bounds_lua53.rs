//! Validator bounds and operand validation tests for Lua 5.3.

use luad_core::diagnostic::{Severity, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::InstructionWord;
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;
use luad_dialect_lua53::{validate_chunk_lua53, Opcode53, RawInstruction53};
use luad_oracle::get_fixture_bytes;

fn create_valid_chunk_53() -> luad_core::model::Chunk {
    let raw_bytes = get_fixture_bytes("lua5.3", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    luad_dialect_lua53::decode_chunk_lua53(&mut reader).expect("clean decode")
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
fn test_lua53_clean_fixture_validates_as_valid_for_parser() {
    let chunk = create_valid_chunk_53();
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::ValidForParser);
    assert!(
        !diags.iter().any(|d| d.severity == Severity::Error),
        "Clean Lua 5.3 fixture must have no error diagnostics: {diags:?}"
    );
}

#[test]
fn test_lua53_stack_bounds_warning() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 255;
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::ValidForParser);
    assert!(diags.iter().any(|d| d.code == "L53-STACK-001"));
}

#[test]
fn test_lua53_invalid_opcode() {
    let mut chunk = create_valid_chunk_53();
    let bad_word = 0x3F; // opcode 63 exceeds 46
    chunk.main_proto.instructions = vec![make_inst(0, bad_word)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-OP-001"));
}

#[test]
fn test_lua53_companion_pairing() {
    // 1. LOADKX without EXTRAARG
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 10;
    let loadkx = RawInstruction53::encode_iabx(Opcode53::LoadKx, 0, 0);
    let ret = RawInstruction53::encode_iabc(Opcode53::Return, 0, 1, 0);
    chunk.main_proto.instructions = vec![make_inst(0, loadkx), make_inst(1, ret)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-COMPANION-001"));

    // 2. Standalone EXTRAARG without LOADKX or SETLIST
    let mut chunk2 = create_valid_chunk_53();
    chunk2.main_proto.maxstacksize = 10;
    let extra = RawInstruction53::encode_iax(Opcode53::ExtraArg, 0);
    chunk2.main_proto.instructions = vec![make_inst(0, extra), make_inst(1, ret)];
    let (verdict2, diags2) = validate_chunk_lua53(&chunk2);
    assert_eq!(verdict2, Verdict::Invalid);
    assert!(diags2.iter().any(|d| d.code == "L53-COMPANION-001"));
}

#[test]
fn test_lua53_register_a_bounds() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 5;
    // MOVE R(5), R(0) exceeds maxstacksize 5
    let move_inst = RawInstruction53::encode_iabc(Opcode53::Move, 5, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, move_inst)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-REG-001"));
}

#[test]
fn test_lua53_register_b_bounds() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 5;
    // MOVE R(0), R(5) exceeds maxstacksize 5
    let move_inst = RawInstruction53::encode_iabc(Opcode53::Move, 0, 5, 0);
    chunk.main_proto.instructions = vec![make_inst(0, move_inst)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-REG-002"));
}

#[test]
fn test_lua53_register_c_bounds() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 5;
    // EQ 0 R(0) R(5) (C is register, not constant)
    let eq_inst = RawInstruction53::encode_iabc(Opcode53::Eq, 0, 0, 5);
    chunk.main_proto.instructions = vec![make_inst(0, eq_inst)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-REG-003"));
}

#[test]
fn test_lua53_constant_bounds() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 10;
    chunk.main_proto.constants = vec![]; // 0 constants
                                         // LOADK R(0), K(0) when table size is 0
    let loadk = RawInstruction53::encode_iabx(Opcode53::LoadK, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, loadk)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-CONST-003"));

    // GETTABUP with RK(C) as constant index 0
    let mut chunk2 = create_valid_chunk_53();
    chunk2.main_proto.maxstacksize = 10;
    chunk2.main_proto.constants = vec![];
    let gettabup = RawInstruction53::encode_iabc(Opcode53::GetTabUp, 0, 0, 256); // 256 is constant 0
    chunk2.main_proto.instructions = vec![make_inst(0, gettabup)];
    let (verdict2, diags2) = validate_chunk_lua53(&chunk2);
    assert_eq!(verdict2, Verdict::Invalid);
    assert!(diags2.iter().any(|d| d.code == "L53-CONST-003"));
}

#[test]
fn test_lua53_upvalue_bounds() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 10;
    chunk.main_proto.upvalues = vec![]; // 0 upvalues
    let getupval = RawInstruction53::encode_iabc(Opcode53::GetUpval, 0, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, getupval)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-UPVAL-002"));
}

#[test]
fn test_lua53_proto_bounds() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 10;
    chunk.main_proto.protos = vec![]; // 0 protos
    let closure = RawInstruction53::encode_iabx(Opcode53::Closure, 0, 0);
    chunk.main_proto.instructions = vec![make_inst(0, closure)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-PROTO-002"));
}

#[test]
fn test_lua53_jump_bounds() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 10;
    // JMP with offset +10 when total instructions is 1
    let jmp = RawInstruction53::encode_iasbx(Opcode53::Jmp, 0, 10);
    chunk.main_proto.instructions = vec![make_inst(0, jmp)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-JMP-001"));
}

#[test]
fn test_lua53_register_spans() {
    let mut chunk = create_valid_chunk_53();
    chunk.main_proto.maxstacksize = 5;
    // LOADNIL A=3, B=2 -> sets R(3)..R(5), exceeds maxstacksize 5
    let loadnil = RawInstruction53::encode_iabc(Opcode53::LoadNil, 3, 2, 0);
    chunk.main_proto.instructions = vec![make_inst(0, loadnil)];
    let (verdict, diags) = validate_chunk_lua53(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L53-REG-SPAN-001"));

    // CONCAT with B > C (invalid range)
    let mut chunk2 = create_valid_chunk_53();
    chunk2.main_proto.maxstacksize = 10;
    let concat = RawInstruction53::encode_iabc(Opcode53::Concat, 0, 3, 1);
    chunk2.main_proto.instructions = vec![make_inst(0, concat)];
    let (verdict2, diags2) = validate_chunk_lua53(&chunk2);
    assert_eq!(verdict2, Verdict::Invalid);
    assert!(diags2.iter().any(|d| d.code == "L53-REG-SPAN-001"));
}
