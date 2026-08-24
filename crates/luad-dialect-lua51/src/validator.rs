//! Structural and VM invariant validator for Lua 5.1 bytecode chunks.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::model::{Chunk, Prototype};

use crate::opcodes::{OpMode51, RawInstruction51};

/// Validate Lua 5.1 chunk invariants.
pub fn validate_chunk_lua51(chunk: &Chunk) -> (Verdict, Vec<Diagnostic>) {
    let mut diagnostics = chunk.diagnostics.clone();
    validate_proto(&chunk.main_proto, &mut diagnostics);

    let mut deduped = Vec::with_capacity(diagnostics.len());
    for diag in diagnostics {
        if !deduped.contains(&diag) {
            deduped.push(diag);
        }
    }
    let diagnostics = deduped;

    let verdict = if diagnostics.iter().any(|d| d.severity == Severity::Error) {
        Verdict::Invalid
    } else {
        Verdict::ValidForParser
    };

    (verdict, diagnostics)
}

fn validate_proto(proto: &Prototype, diags: &mut Vec<Diagnostic>) {
    let num_insts = proto.instructions.len();

    // 1. Stack bounds check
    if proto.maxstacksize > 250 {
        let diag = Diagnostic::warning(
            "L51-STACK-001",
            DiagnosticCategory::Structure,
            proto.id.clone(),
            format!("Unusually large maxstacksize: {}", proto.maxstacksize),
        )
        .with_source(proto.source.clone());
        diags.push(diag);
    }

    // 2. Validate instructions
    for (pc, inst) in proto.instructions.iter().enumerate() {
        let raw = RawInstruction51::decode(inst.raw_word);

        let Some(op) = raw.opcode else {
            let diag = Diagnostic::error(
                "L51-OP-001",
                DiagnosticCategory::Instruction,
                inst.id.clone(),
                format!("Invalid opcode 0x{:02x} at PC {pc}", raw.opcode_num),
            )
            .with_source(inst.source.clone())
            .with_suggested_action("Check dialect version or decompilation flags");
            diags.push(diag);
            continue;
        };

        // Jump target bounds check
        if op.mode() == OpMode51::IAsBx {
            let dest_pc = (pc as i32 + 1 + raw.sbx) as usize;
            if dest_pc >= num_insts {
                let diag = Diagnostic::error(
                    "L51-JMP-001",
                    DiagnosticCategory::ControlFlow,
                    inst.id.clone(),
                    format!("Jump destination PC {dest_pc} out of bounds (total instructions: {num_insts})"),
                )
                .with_source(inst.source.clone());
                diags.push(diag);
            }
        }

        // Constant bounds validation
        if op == crate::opcodes::Opcode51::LoadK
            || op == crate::opcodes::Opcode51::GetGlobal
            || op == crate::opcodes::Opcode51::SetGlobal
        {
            let k_idx = raw.bx as usize;
            if k_idx >= proto.constants.len() {
                let diag = Diagnostic::error(
                    "L51-CONST-003",
                    DiagnosticCategory::Instruction,
                    inst.id.clone(),
                    format!(
                        "Constant index {k_idx} out of bounds (total constants: {})",
                        proto.constants.len()
                    ),
                )
                .with_source(inst.source.clone());
                diags.push(diag);
            }
        }

        // Upvalue bounds validation
        if (op == crate::opcodes::Opcode51::GetUpval || op == crate::opcodes::Opcode51::SetUpval)
            && raw.b as usize >= proto.upvalues.len()
        {
            let diag = Diagnostic::error(
                "L51-UPVAL-001",
                DiagnosticCategory::Instruction,
                inst.id.clone(),
                format!(
                    "{} field B upvalue index {} out of bounds (declared upvalues: {}) at PC {pc}",
                    op.name(),
                    raw.b,
                    proto.upvalues.len()
                ),
            )
            .with_source(inst.source.clone());
            diags.push(diag);
        }

        // Comparison boolean domain validation
        if (op == crate::opcodes::Opcode51::Eq
            || op == crate::opcodes::Opcode51::Lt
            || op == crate::opcodes::Opcode51::Le)
            && raw.a > 1
        {
            let diag = Diagnostic::error(
                "L51-BOOL-001",
                DiagnosticCategory::Instruction,
                inst.id.clone(),
                format!(
                    "{} field A comparison flag {} outside legal boolean domain 0..=1 at PC {pc}",
                    op.name(),
                    raw.a
                ),
            )
            .with_source(inst.source.clone());
            diags.push(diag);
        }

        // Register bounds validation (field A)
        let max_reg = proto.maxstacksize as usize;
        if raw.a as usize >= max_reg
            && op != crate::opcodes::Opcode51::Close
            && op != crate::opcodes::Opcode51::Eq
            && op != crate::opcodes::Opcode51::Lt
            && op != crate::opcodes::Opcode51::Le
        {
            let diag = Diagnostic::error(
                "L51-REG-001",
                DiagnosticCategory::Instruction,
                inst.id.clone(),
                format!(
                    "Register A ({}) exceeds maxstacksize ({}) at PC {pc}",
                    raw.a, max_reg
                ),
            )
            .with_source(inst.source.clone());
            diags.push(diag);
        }

        // RK operand and register bounds validation
        if op.mode() == OpMode51::IABC {
            if !raw.is_b_k()
                && raw.b as usize >= max_reg
                && op != crate::opcodes::Opcode51::VarArg
                && op != crate::opcodes::Opcode51::Test
                && op != crate::opcodes::Opcode51::LoadBool
                && op != crate::opcodes::Opcode51::Call
                && op != crate::opcodes::Opcode51::TailCall
                && op != crate::opcodes::Opcode51::Return
                && op != crate::opcodes::Opcode51::GetUpval
                && op != crate::opcodes::Opcode51::SetUpval
            {
                let diag = Diagnostic::error(
                    "L51-REG-002",
                    DiagnosticCategory::Instruction,
                    inst.id.clone(),
                    format!(
                        "Register B ({}) exceeds maxstacksize ({}) at PC {pc}",
                        raw.b, max_reg
                    ),
                )
                .with_source(inst.source.clone());
                diags.push(diag);
            }
            if !raw.is_c_k()
                && raw.c as usize >= max_reg
                && op != crate::opcodes::Opcode51::SetList
                && op != crate::opcodes::Opcode51::Test
                && op != crate::opcodes::Opcode51::TestSet
                && op != crate::opcodes::Opcode51::LoadBool
                && op != crate::opcodes::Opcode51::Call
                && op != crate::opcodes::Opcode51::Return
            {
                let diag = Diagnostic::error(
                    "L51-REG-003",
                    DiagnosticCategory::Instruction,
                    inst.id.clone(),
                    format!(
                        "Register C ({}) exceeds maxstacksize ({}) at PC {pc}",
                        raw.c, max_reg
                    ),
                )
                .with_source(inst.source.clone());
                diags.push(diag);
            }
            if raw.is_b_k()
                && op != crate::opcodes::Opcode51::GetUpval
                && op != crate::opcodes::Opcode51::SetUpval
            {
                let k_idx = raw.b_index_k();
                if k_idx >= proto.constants.len() {
                    let diag = Diagnostic::error(
                        "L51-CONST-004",
                        DiagnosticCategory::Instruction,
                        inst.id.clone(),
                        format!("RK operand B constant index {k_idx} out of bounds (total constants: {})", proto.constants.len()),
                    )
                    .with_source(inst.source.clone());
                    diags.push(diag);
                }
            }
            if raw.is_c_k() {
                let k_idx = raw.c_index_k();
                if k_idx >= proto.constants.len() {
                    let diag = Diagnostic::error(
                        "L51-CONST-005",
                        DiagnosticCategory::Instruction,
                        inst.id.clone(),
                        format!("RK operand C constant index {k_idx} out of bounds (total constants: {})", proto.constants.len()),
                    )
                    .with_source(inst.source.clone());
                    diags.push(diag);
                }
            }
        }

        // Closure binding descriptor and prototype index validation
        if op == crate::opcodes::Opcode51::Closure {
            let child_idx = raw.bx as usize;
            if child_idx >= proto.protos.len() {
                let diag = Diagnostic::error(
                    "L51-PROTO-002",
                    DiagnosticCategory::Instruction,
                    inst.id.clone(),
                    format!(
                        "CLOSURE field Bx child prototype index {child_idx} out of bounds (child prototypes: {}) at PC {pc}",
                        proto.protos.len()
                    ),
                )
                .with_source(inst.source.clone());
                diags.push(diag);
            } else if let Some(child) = proto.protos.get(child_idx) {
                let nups = child.upvalues.len();
                for j in 1..=nups {
                    let desc_pc = pc + j;
                    if desc_pc >= num_insts {
                        let diag = Diagnostic::error(
                            "L51-CLOSURE-001",
                            DiagnosticCategory::Instruction,
                            inst.id.clone(),
                            format!("Missing closure binding descriptor at PC {desc_pc} for closure at PC {pc}"),
                        )
                        .with_source(inst.source.clone());
                        diags.push(diag);
                    } else {
                        let desc_word = proto.instructions[desc_pc].raw_word;
                        let desc_raw = RawInstruction51::decode(desc_word);
                        if desc_raw.opcode != Some(crate::opcodes::Opcode51::Move)
                            && desc_raw.opcode != Some(crate::opcodes::Opcode51::GetUpval)
                        {
                            let diag = Diagnostic::error(
                                "L51-CLOSURE-002",
                                DiagnosticCategory::Instruction,
                                proto.instructions[desc_pc].id.clone(),
                                format!(
                                    "Invalid closure binding opcode at PC {desc_pc}: expected MOVE or GETUPVAL, found {:?}",
                                    desc_raw.opcode
                                ),
                            )
                            .with_source(proto.instructions[desc_pc].source.clone());
                            diags.push(diag);
                        }
                    }
                }
            }
        }
    }

    for child in &proto.protos {
        validate_proto(child, diags);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::opcodes::Opcode51;
    use luad_core::id::{ProtoPath, StableId};
    use luad_core::model::{Header, InstructionWord};
    use luad_core::provenance::SourceLocation;

    fn make_test_proto(instructions: Vec<u32>, nups: usize, num_protos: usize) -> Prototype {
        let path = ProtoPath::root();
        let inst_words = instructions
            .into_iter()
            .enumerate()
            .map(|(pc, raw_word)| InstructionWord {
                id: StableId::instruction(path.clone(), pc),
                pc,
                raw_word,
                raw_hex: hex::encode(raw_word.to_le_bytes()),
                source: SourceLocation::new(pc * 4, &raw_word.to_le_bytes()),
            })
            .collect();

        let upvalues = (0..nups)
            .map(|idx| luad_core::model::UpvalueDesc {
                id: StableId::upvalue(path.clone(), idx),
                index: idx,
                instack: 0,
                idx: 0,
                kind: 0,
                name: None,
                source: SourceLocation::new(0, &[]),
            })
            .collect();

        let protos = (0..num_protos)
            .map(|_idx| make_test_proto(vec![], 0, 0))
            .collect();

        Prototype {
            id: StableId::proto(path.clone()),
            path,
            source_name: None,
            line_defined: 0,
            last_line_defined: 0,
            numparams: 0,
            is_vararg: 0,
            maxstacksize: 2,
            instructions: inst_words,
            constants: vec![],
            upvalues,
            protos,
            line_info: vec![],
            abs_line_info: vec![],
            loc_vars: vec![],
            upvalue_names: vec![],
            source: SourceLocation::new(0, &[]),
        }
    }

    fn make_test_chunk(proto: Prototype) -> Chunk {
        Chunk {
            sha256: "0".repeat(64),
            byte_length: 0,
            dialect: "lua5.1".to_string(),
            interpretation: None,
            verdict: Verdict::ValidForParser,
            header: Header {
                signature: "\x1bLua".to_string(),
                version: 0x51,
                format: 0,
                luac_data: String::new(),
                instruction_size: 4,
                lua_integer_size: 4,
                sizeof_sizet: 8,
                lua_number_size: 8,
                luac_int: 0,
                luac_num: 0.0,
                source: SourceLocation::new(0, &[]),
            },
            main_proto: proto,
            diagnostics: vec![],
            trailing_bytes: None,
        }
    }

    #[test]
    fn test_validator_upvalue_bounds_and_no_false_reg() {
        // GETUPVAL R(0), Upvalue(3) with nups=4 and maxstacksize=2
        // Should be valid (3 < 4) and NOT fail maxstacksize (3 >= 2)
        let getupval_valid = RawInstruction51::encode_iabc(Opcode51::GetUpval, 0, 3, 0);
        let proto = make_test_proto(vec![getupval_valid], 4, 0);
        let chunk = make_test_chunk(proto);
        let (verdict, diags) = validate_chunk_lua51(&chunk);
        assert_eq!(verdict, Verdict::ValidForParser);
        assert!(diags.is_empty(), "unexpected diags: {diags:?}");

        // GETUPVAL R(0), Upvalue(4) with nups=4 -> out of bounds
        let getupval_invalid = RawInstruction51::encode_iabc(Opcode51::GetUpval, 0, 4, 0);
        let proto = make_test_proto(vec![getupval_invalid], 4, 0);
        let chunk = make_test_chunk(proto);
        let (verdict, diags) = validate_chunk_lua51(&chunk);
        assert_eq!(verdict, Verdict::Invalid);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "L51-UPVAL-001");
        assert_eq!(
            diags[0].message,
            "GETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 4) at PC 0"
        );

        // SETUPVAL R(0), Upvalue(4) with nups=4 -> out of bounds
        let setupval_invalid = RawInstruction51::encode_iabc(Opcode51::SetUpval, 0, 4, 0);
        let proto = make_test_proto(vec![setupval_invalid], 4, 0);
        let chunk = make_test_chunk(proto);
        let (verdict, diags) = validate_chunk_lua51(&chunk);
        assert_eq!(verdict, Verdict::Invalid);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "L51-UPVAL-001");
        assert_eq!(
            diags[0].message,
            "SETUPVAL field B upvalue index 4 out of bounds (declared upvalues: 4) at PC 0"
        );
    }

    #[test]
    fn test_validator_closure_child_proto_bounds() {
        // CLOSURE R(0), Proto(1) with 1 child proto -> out of bounds
        let closure_invalid = RawInstruction51::encode_iabx(Opcode51::Closure, 0, 1);
        let proto = make_test_proto(vec![closure_invalid], 0, 1);
        let chunk = make_test_chunk(proto);
        let (verdict, diags) = validate_chunk_lua51(&chunk);
        assert_eq!(verdict, Verdict::Invalid);
        assert_eq!(diags.len(), 1);
        assert_eq!(diags[0].code, "L51-PROTO-002");
        assert_eq!(
            diags[0].message,
            "CLOSURE field Bx child prototype index 1 out of bounds (child prototypes: 1) at PC 0"
        );
    }

    #[test]
    fn test_validator_comparison_boolean_flags_and_no_false_reg() {
        for op in [Opcode51::Eq, Opcode51::Lt, Opcode51::Le] {
            // A=0 and A=1 valid regardless of maxstacksize (maxstacksize=1)
            for flag in [0, 1] {
                let inst = RawInstruction51::encode_iabc(op, flag, 0, 0);
                let mut proto = make_test_proto(vec![inst], 0, 0);
                proto.maxstacksize = 1;
                let chunk = make_test_chunk(proto);
                let (verdict, diags) = validate_chunk_lua51(&chunk);
                assert_eq!(verdict, Verdict::ValidForParser);
                assert!(diags.is_empty());
            }

            // A=2 invalid
            let inst = RawInstruction51::encode_iabc(op, 2, 0, 0);
            let mut proto = make_test_proto(vec![inst], 0, 0);
            proto.maxstacksize = 1;
            let chunk = make_test_chunk(proto);
            let (verdict, diags) = validate_chunk_lua51(&chunk);
            assert_eq!(verdict, Verdict::Invalid);
            assert_eq!(diags.len(), 1);
            assert_eq!(diags[0].code, "L51-BOOL-001");
            assert_eq!(
                diags[0].message,
                format!(
                    "{} field A comparison flag 2 outside legal boolean domain 0..=1 at PC 0",
                    op.name()
                )
            );
        }
    }

    #[test]
    fn test_validator_idempotent() {
        let getupval_invalid = RawInstruction51::encode_iabc(Opcode51::GetUpval, 0, 4, 0);
        let proto = make_test_proto(vec![getupval_invalid], 4, 0);
        let mut chunk = make_test_chunk(proto);

        let (v1, d1) = validate_chunk_lua51(&chunk);
        chunk.verdict = v1;
        chunk.diagnostics = d1.clone();

        let (v2, d2) = validate_chunk_lua51(&chunk);
        assert_eq!(v1, v2);
        assert_eq!(d1, d2);
        assert_eq!(d2.len(), 1);
    }
}
