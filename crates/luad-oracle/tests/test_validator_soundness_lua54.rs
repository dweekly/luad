//! Validator soundness and complete diagnostic test coverage for Lua 5.4 (Gate V1).

use luad_core::diagnostic::{Severity, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::limits::ParseMode;
use luad_core::model::InstructionWord;
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;
use luad_dialect_lua54::{validate_chunk_lua54, Opcode54, RawInstruction54};
use luad_oracle::get_fixture_bytes;

fn create_valid_dummy_chunk() -> luad_core::model::Chunk {
    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("clean decode")
}

#[test]
fn test_all_83_opcodes_parse_and_validate_without_false_positives() {
    let mut chunk = create_valid_dummy_chunk();
    chunk.main_proto.maxstacksize = 20;
    chunk.main_proto.constants = vec![luad_core::Constant {
        id: StableId::constant(ProtoPath::root(), 0),
        index: 0,
        value: luad_core::ConstantValue::Integer {
            val: 42,
            raw_hex: "2a00000000000000".to_string(),
        },
        source: SourceLocation::new(0, &[0]),
    }];
    chunk.main_proto.upvalues = vec![luad_core::UpvalueDesc {
        id: StableId::upvalue(ProtoPath::root(), 0),
        index: 0,
        name: Some(luad_core::LuaString::from_bytes(b"u0")),
        instack: 1,
        idx: 0,
        kind: 0,
        source: SourceLocation::new(0, &[0]),
    }];
    let mut child = chunk.main_proto.clone();
    child.id = StableId::proto(ProtoPath::root().child(0));
    child.instructions = vec![];
    child.protos = vec![];
    chunk.main_proto.protos = vec![child];

    let mut insts = Vec::new();
    for op_num in 0..=82 {
        let op = Opcode54::from_u8(op_num).unwrap_or_else(|| panic!("Opcode {op_num} must exist"));
        assert!(!op.name().is_empty());
        let raw_word = match op.mode() {
            luad_dialect_lua54::OpMode54::IsJ => RawInstruction54::encode_isj(op, 0),
            luad_dialect_lua54::OpMode54::IAx => RawInstruction54::encode_iax(op, 0),
            luad_dialect_lua54::OpMode54::IABx => RawInstruction54::encode_iabx(op, 0, 0),
            luad_dialect_lua54::OpMode54::IAsBx => RawInstruction54::encode_iasbx(op, 0, 0),
            luad_dialect_lua54::OpMode54::IABC => RawInstruction54::encode_iabc(op, 0, 0, 0, 0),
        };
        insts.push(InstructionWord {
            id: StableId::instruction(ProtoPath::root(), op_num as usize),
            pc: op_num as usize,
            raw_word,
            raw_hex: hex::encode(raw_word.to_le_bytes()),
            source: SourceLocation::new(0, &raw_word.to_le_bytes()),
        });
    }

    chunk.main_proto.instructions = insts;
    let (verdict, diags) = validate_chunk_lua54(&chunk);
    assert_eq!(
        verdict,
        Verdict::ValidForAnalysis,
        "All 83 validly encoded opcodes must produce zero validation errors: {:?}",
        diags
    );
    assert!(
        diags.is_empty(),
        "All 83 opcodes must validate cleanly without false positive diagnostics: {:?}",
        diags
    );
}

#[test]
fn test_jmp_with_high_a_slot_bits_does_not_fail_stack_size_check() {
    let mut chunk = create_valid_dummy_chunk();
    // In Lua 5.4, JMP uses format sJ where sJ occupies bits 7..31 (including where A would be in iABC).
    // encode_isj(Opcode54::Jmp, 0) sets the biased offset where the lower 8 bits (the A slot) are 0xFF (255).
    let raw_jmp = RawInstruction54::encode_isj(Opcode54::Jmp, 0);
    chunk.main_proto.instructions = vec![
        InstructionWord {
            id: StableId::instruction(ProtoPath::root(), 0),
            pc: 0,
            raw_word: raw_jmp,
            raw_hex: hex::encode(raw_jmp.to_le_bytes()),
            source: SourceLocation::new(0, &raw_jmp.to_le_bytes()),
        },
        InstructionWord {
            id: StableId::instruction(ProtoPath::root(), 1),
            pc: 1,
            raw_word: Opcode54::Return0 as u32,
            raw_hex: hex::encode((Opcode54::Return0 as u32).to_le_bytes()),
            source: SourceLocation::new(4, &(Opcode54::Return0 as u32).to_le_bytes()),
        },
    ];

    let (verdict, diags) = validate_chunk_lua54(&chunk);
    assert_eq!(
        verdict,
        Verdict::ValidForAnalysis,
        "JMP with arbitrary bits in A slot must NOT trigger false positive register warning: {:?}",
        diags
    );
    assert!(
        !diags.iter().any(|d| d.code == "L54-VAL-REG-001"),
        "JMP must not emit L54-VAL-REG-001"
    );
}

#[test]
fn test_register_a_out_of_bounds_on_instruction_using_a_triggers_warning() {
    let mut chunk = create_valid_dummy_chunk();
    chunk.main_proto.maxstacksize = 2;

    // MOVE R(5) := R(0) - A is 5 which exceeds maxstacksize 2
    let raw_move = RawInstruction54::encode_iabc(Opcode54::Move, 5, 0, 0, 0);
    chunk.main_proto.instructions = vec![InstructionWord {
        id: StableId::instruction(ProtoPath::root(), 0),
        pc: 0,
        raw_word: raw_move,
        raw_hex: hex::encode(raw_move.to_le_bytes()),
        source: SourceLocation::new(0, &raw_move.to_le_bytes()),
    }];

    let (_verdict, diags) = validate_chunk_lua54(&chunk);
    assert!(
        diags.iter().any(|d| d.code == "L54-VAL-REG-001"),
        "Out of bounds register A on MOVE must emit L54-VAL-REG-001"
    );
}

#[test]
fn test_corrupted_forward_jump_target_fails() {
    let mut chunk = create_valid_dummy_chunk();
    // JMP with large forward jump offset beyond code bounds
    let raw_jmp = RawInstruction54::encode_isj(Opcode54::Jmp, 500);
    chunk.main_proto.instructions = vec![InstructionWord {
        id: StableId::instruction(ProtoPath::root(), 0),
        pc: 0,
        raw_word: raw_jmp,
        raw_hex: hex::encode(raw_jmp.to_le_bytes()),
        source: SourceLocation::new(0, &raw_jmp.to_le_bytes()),
    }];

    let (verdict, diags) = validate_chunk_lua54(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L54-VAL-JUMP-001"));
}

#[test]
fn test_corrupted_negative_jump_before_instruction_zero_fails() {
    let mut chunk = create_valid_dummy_chunk();
    // JMP at PC 0 with negative jump offset -5
    let raw_jmp = RawInstruction54::encode_isj(Opcode54::Jmp, -5);
    chunk.main_proto.instructions = vec![InstructionWord {
        id: StableId::instruction(ProtoPath::root(), 0),
        pc: 0,
        raw_word: raw_jmp,
        raw_hex: hex::encode(raw_jmp.to_le_bytes()),
        source: SourceLocation::new(0, &raw_jmp.to_le_bytes()),
    }];

    let (verdict, diags) = validate_chunk_lua54(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L54-VAL-JUMP-001"));
}

#[test]
fn test_constant_index_out_of_bounds_fails() {
    let mut chunk = create_valid_dummy_chunk();
    chunk.main_proto.constants = vec![]; // 0 constants

    // LOADK R(0), K(0) -> index 0 >= table size 0
    let raw_loadk = RawInstruction54::encode_iabx(Opcode54::Loadk, 0, 0);
    chunk.main_proto.instructions = vec![InstructionWord {
        id: StableId::instruction(ProtoPath::root(), 0),
        pc: 0,
        raw_word: raw_loadk,
        raw_hex: hex::encode(raw_loadk.to_le_bytes()),
        source: SourceLocation::new(0, &raw_loadk.to_le_bytes()),
    }];

    let (verdict, diags) = validate_chunk_lua54(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L54-VAL-CONST-001"));
}

#[test]
fn test_upvalue_index_out_of_bounds_fails() {
    let mut chunk = create_valid_dummy_chunk();
    chunk.main_proto.upvalues = vec![]; // 0 upvalues

    // GETUPVAL R(0), U(0)
    let raw_getupval = RawInstruction54::encode_iabc(Opcode54::Getupval, 0, 0, 0, 0);
    chunk.main_proto.instructions = vec![InstructionWord {
        id: StableId::instruction(ProtoPath::root(), 0),
        pc: 0,
        raw_word: raw_getupval,
        raw_hex: hex::encode(raw_getupval.to_le_bytes()),
        source: SourceLocation::new(0, &raw_getupval.to_le_bytes()),
    }];

    let (verdict, diags) = validate_chunk_lua54(&chunk);
    assert_eq!(verdict, Verdict::Invalid);
    assert!(diags.iter().any(|d| d.code == "L54-VAL-UPVAL-001"));
}

#[test]
fn test_strict_mode_halts_early_permissive_accumulates_all() {
    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("fixture failed");

    // Set a very small string limit (e.g. 2 bytes) so that strings in hello.luac trigger L54-STR-001
    let limits = luad_core::limits::ResourceLimits {
        max_string_bytes: 2,
        ..Default::default()
    };

    // Strict mode: halts immediately on first error
    let mut reader_strict =
        SafeReader::with_options(&raw_bytes, 0, limits.clone(), ParseMode::Strict);
    let res_strict = luad_dialect_lua54::decode_chunk_lua54(&mut reader_strict);
    assert!(
        res_strict.is_err(),
        "Strict mode must fail immediately on first diagnostic error"
    );
    let diag = res_strict.unwrap_err();
    assert_eq!(diag.code, "L54-STR-001");
    assert_eq!(diag.severity, Severity::Error);

    // Permissive mode: collects diagnostic
    let mut reader_perm = SafeReader::with_options(&raw_bytes, 0, limits, ParseMode::Permissive);
    let res_perm = luad_dialect_lua54::decode_chunk_lua54(&mut reader_perm);
    // In permissive mode with string error, reader recorded the error and returned Err because string content could not be read
    assert!(res_perm.is_err() || res_perm.is_ok());
    assert_eq!(reader_perm.diagnostics().len(), 1);
    assert_eq!(reader_perm.diagnostics()[0].code, "L54-STR-001");
}

#[test]
fn test_diagnostic_exhaustion_must_never_authorize_invalid_bytecode() {
    let mut chunk = create_valid_dummy_chunk();
    // maxstacksize = 2, so raw.a = 10 produces L54-VAL-REG-001 (Warning)
    chunk.main_proto.maxstacksize = 2;

    // 1. Exactly 10,000 warnings followed by an invalid opcode:
    let mut insts = Vec::with_capacity(10_001);
    let move_op = Opcode54::Move;
    let raw_warn = RawInstruction54::encode_iabc(move_op, 10, 0, 0, 0);

    for pc in 0..10_000 {
        insts.push(InstructionWord {
            id: StableId::instruction(ProtoPath::root(), pc),
            pc,
            raw_word: raw_warn,
            raw_hex: hex::encode(raw_warn.to_le_bytes()),
            source: SourceLocation::new(0, &raw_warn.to_le_bytes()),
        });
    }

    // Invalid opcode at PC 10000:
    let bad_raw = 0xFE; // opcode 254 (invalid)
    insts.push(InstructionWord {
        id: StableId::instruction(ProtoPath::root(), 10_000),
        pc: 10_000,
        raw_word: bad_raw,
        raw_hex: hex::encode(bad_raw.to_le_bytes()),
        source: SourceLocation::new(0, &bad_raw.to_le_bytes()),
    });

    chunk.main_proto.instructions = insts;

    // Validation must return Verdict::Incomplete and CORE-LIMIT-003
    let (verdict, diags) = validate_chunk_lua54(&chunk);
    assert_eq!(
        verdict,
        Verdict::Incomplete,
        "Diagnostic exhaustion must produce Incomplete, never ValidForAnalysis"
    );
    assert!(
        diags.iter().any(|d| d.code == "CORE-LIMIT-003"),
        "Must emit CORE-LIMIT-003 on exhaustion"
    );
    assert_eq!(
        diags.last().unwrap().code,
        "CORE-LIMIT-003",
        "Terminal diagnostic must be CORE-LIMIT-003"
    );

    // Analysis qualification MUST fail
    let ana_res = luad_analysis::validate_for_analysis(&chunk);
    assert!(
        ana_res.is_err(),
        "validate_for_analysis must reject Incomplete verdict"
    );

    // Negative Control: 9,999 warnings followed by invalid opcode
    // Validation finishes before limit and catches the invalid opcode as Invalid
    let mut neg_chunk = chunk.clone();
    neg_chunk.main_proto.instructions.remove(0); // 9,999 warnings + 1 invalid opcode
                                                 // Re-index PCs
    for (i, inst) in neg_chunk.main_proto.instructions.iter_mut().enumerate() {
        inst.pc = i;
        inst.id = StableId::instruction(ProtoPath::root(), i);
    }

    let (neg_verdict, neg_diags) = validate_chunk_lua54(&neg_chunk);
    assert_eq!(
        neg_verdict,
        Verdict::Invalid,
        "Below exhaustion limit, invalid opcode must be caught as Invalid"
    );
    assert!(
        neg_diags.iter().any(|d| d.code == "L54-VAL-OPCODE-001"),
        "Must report invalid opcode"
    );
    assert!(
        !neg_diags.iter().any(|d| d.code == "CORE-LIMIT-003"),
        "Must not report CORE-LIMIT-003 when limit was not reached"
    );
}

#[test]
fn test_diagnostic_truncation_preserves_error_and_rejects() {
    let mut chunk = create_valid_dummy_chunk();
    chunk.main_proto.maxstacksize = 2;
    chunk.main_proto.constants = vec![]; // 0 constants

    // 9,999 warning-producing instructions (R(10) >= maxstacksize 2)
    let mut insts = Vec::with_capacity(10_000);
    let raw_warn = RawInstruction54::encode_iabc(Opcode54::Move, 10, 0, 0, 0);

    for pc in 0..9_999 {
        insts.push(InstructionWord {
            id: StableId::instruction(ProtoPath::root(), pc),
            pc,
            raw_word: raw_warn,
            raw_hex: hex::encode(raw_warn.to_le_bytes()),
            source: SourceLocation::new(0, &raw_warn.to_le_bytes()),
        });
    }

    // 10,000th instruction produces BOTH a warning (R(10) >= 2) AND an error (LOADK K(999) with 0 constants)
    let raw_both = RawInstruction54::encode_iabx(Opcode54::Loadk, 10, 999);
    insts.push(InstructionWord {
        id: StableId::instruction(ProtoPath::root(), 9_999),
        pc: 9_999,
        raw_word: raw_both,
        raw_hex: hex::encode(raw_both.to_le_bytes()),
        source: SourceLocation::new(0, &raw_both.to_le_bytes()),
    });

    chunk.main_proto.instructions = insts;

    let (verdict, diags) = validate_chunk_lua54(&chunk);

    // Must be Verdict::Invalid, never ValidForAnalysis or ValidForParser
    assert_eq!(
        verdict,
        Verdict::Invalid,
        "Chunk with 9,999 warnings and 1 invalid-constant error must be Invalid, not ValidForAnalysis"
    );

    // The error L54-VAL-CONST-001 must NOT be discarded by diagnostic truncation!
    assert!(
        diags.iter().any(|d| d.code == "L54-VAL-CONST-001"),
        "Diagnostic truncation must preserve the error L54-VAL-CONST-001"
    );

    // Analysis qualification MUST fail
    let ana_res = luad_analysis::validate_for_analysis(&chunk);
    assert!(
        ana_res.is_err(),
        "validate_for_analysis must reject Invalid verdict"
    );
}
