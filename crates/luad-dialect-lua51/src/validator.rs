//! Structural and VM invariant validator for Lua 5.1 bytecode chunks.

use std::collections::BTreeSet;

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::model::{Chunk, Prototype};

use crate::opcodes::{OpMode51, Opcode51, RawInstruction51};

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

    // Map closure binding descriptor PCs
    let mut binding_descriptors = BTreeSet::new();
    for (pc, inst) in proto.instructions.iter().enumerate() {
        let raw = RawInstruction51::decode(inst.raw_word);
        if raw.opcode == Some(Opcode51::Closure) {
            let child_bx = raw.bx as usize;
            let nups = proto
                .protos
                .get(child_bx)
                .map(|p| p.upvalues.len())
                .unwrap_or(0);
            for b_pc in (pc + 1)..=(pc + nups) {
                if b_pc < num_insts {
                    binding_descriptors.insert(b_pc);
                }
            }
        }
    }

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
        let is_binding_descriptor = binding_descriptors.contains(&pc);
        if !is_binding_descriptor && op.a_is_register() && raw.a as usize >= max_reg {
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

        // Register bounds validation (field B)
        if !is_binding_descriptor && op.b_is_fixed_register() && raw.b as usize >= max_reg {
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

        // Register bounds validation (field C)
        let is_reg_c = op.c_is_fixed_register() || (op.c_is_rk() && !raw.is_c_k());
        if !is_binding_descriptor && is_reg_c && raw.c as usize >= max_reg {
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

        // RK operand constant bounds validation
        if op.mode() == OpMode51::IABC {
            if raw.is_b_k()
                && !op.b_is_fixed_register()
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
            if raw.is_c_k() && op.c_is_rk() {
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
    use luad_core::model::{Constant, ConstantValue, Header, InstructionWord};
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

    #[test]
    fn test_validator_register_a_close_and_jmp_authority() {
        // CLOSE with A = maxstacksize (invalid)
        let close_invalid = RawInstruction51::encode_iabc(Opcode51::Close, 2, 0, 0);
        let proto = make_test_proto(vec![close_invalid], 0, 0); // maxstacksize = 2
        let chunk = make_test_chunk(proto);
        let (verdict, diags) = validate_chunk_lua51(&chunk);
        assert_eq!(verdict, Verdict::Invalid);
        let reg_diags: Vec<_> = diags.iter().filter(|d| d.code == "L51-REG-001").collect();
        assert_eq!(reg_diags.len(), 1);
        assert_eq!(
            reg_diags[0].message,
            "Register A (2) exceeds maxstacksize (2) at PC 0"
        );

        // CLOSE with A = maxstacksize - 1 (valid)
        let close_valid = RawInstruction51::encode_iabc(Opcode51::Close, 1, 0, 0);
        let proto = make_test_proto(vec![close_valid], 0, 0);
        let chunk = make_test_chunk(proto);
        let (verdict, diags) = validate_chunk_lua51(&chunk);
        assert_eq!(verdict, Verdict::ValidForParser);
        assert!(diags.is_empty());

        // JMP with A >= maxstacksize (A ignored in 5.1, must not report L51-REG-001)
        let jmp_inst = RawInstruction51::encode_iasbx(Opcode51::Jmp, 255, -1);
        let proto = make_test_proto(vec![jmp_inst], 0, 0);
        let chunk = make_test_chunk(proto);
        let (_, diags) = validate_chunk_lua51(&chunk);
        assert!(!diags.iter().any(|d| d.code == "L51-REG-001"));
    }

    #[test]
    fn test_validator_closure_binding_descriptor_a_ignored() {
        // Prototype with 1 child proto having 2 upvalues
        let closure = RawInstruction51::encode_iabx(Opcode51::Closure, 0, 0);
        let desc_move = RawInstruction51::encode_iabc(Opcode51::Move, 255, 0, 0);
        let desc_getupval = RawInstruction51::encode_iabc(Opcode51::GetUpval, 255, 0, 0);
        let mut proto = make_test_proto(vec![closure, desc_move, desc_getupval], 1, 0);
        proto.protos = vec![make_test_proto(vec![], 2, 0)]; // child has 2 upvalues
        proto.maxstacksize = 2;

        let chunk = make_test_chunk(proto);
        let (verdict, diags) = validate_chunk_lua51(&chunk);
        assert_eq!(verdict, Verdict::ValidForParser);
        assert!(
            !diags.iter().any(|d| d.code == "L51-REG-001"),
            "binding descriptors must not report L51-REG-001: {diags:?}"
        );
        assert!(
            !diags.iter().any(|d| d.code == "L51-REG-002"),
            "binding descriptors must not report L51-REG-002: {diags:?}"
        );
    }

    #[test]
    fn test_validator_register_b_fixed_and_deferred_rk() {
        let fixed_b_ops = [
            Opcode51::Move,
            Opcode51::LoadNil,
            Opcode51::GetTable,
            Opcode51::SelfOp,
            Opcode51::Unm,
            Opcode51::Not,
            Opcode51::Len,
            Opcode51::Concat,
            Opcode51::TestSet,
        ];

        // maxstacksize = 2: B=1 is valid, B=2 is invalid (L51-REG-002), B=256 reports L51-REG-002 and no L51-CONST-004
        for op in fixed_b_ops {
            let inst_valid = RawInstruction51::encode_iabc(op, 0, 1, 0);
            let proto_valid = make_test_proto(vec![inst_valid], 0, 0);
            let chunk_valid = make_test_chunk(proto_valid);
            let (v_valid, d_valid) = validate_chunk_lua51(&chunk_valid);
            assert_eq!(
                v_valid,
                Verdict::ValidForParser,
                "{:?} with B=1 must be ValidForParser",
                op
            );
            assert!(
                d_valid.is_empty(),
                "{:?} with B=1 must produce no diagnostics, got: {:?}",
                op,
                d_valid
            );

            let inst_invalid = RawInstruction51::encode_iabc(op, 0, 2, 0);
            let proto_invalid = make_test_proto(vec![inst_invalid], 0, 0);
            let chunk_invalid = make_test_chunk(proto_invalid);
            let (v_invalid, d_invalid) = validate_chunk_lua51(&chunk_invalid);
            assert_eq!(v_invalid, Verdict::Invalid);
            let reg_b_invalid: Vec<_> = d_invalid
                .iter()
                .filter(|d| d.code == "L51-REG-002")
                .collect();
            assert_eq!(
                reg_b_invalid.len(),
                1,
                "{:?} with B=2 must report L51-REG-002",
                op
            );
            assert_eq!(
                reg_b_invalid[0].message,
                "Register B (2) exceeds maxstacksize (2) at PC 0"
            );

            let inst_bit8 = RawInstruction51::encode_iabc(op, 0, 256, 0);
            let proto_bit8 = make_test_proto(vec![inst_bit8], 0, 0);
            let chunk_bit8 = make_test_chunk(proto_bit8);
            let (v_bit8, d_bit8) = validate_chunk_lua51(&chunk_bit8);
            assert_eq!(v_bit8, Verdict::Invalid);
            let reg_b_bit8: Vec<_> = d_bit8.iter().filter(|d| d.code == "L51-REG-002").collect();
            assert_eq!(
                reg_b_bit8.len(),
                1,
                "{:?} with B=256 must report exactly one L51-REG-002",
                op
            );
            assert_eq!(
                reg_b_bit8[0].message,
                "Register B (256) exceeds maxstacksize (2) at PC 0"
            );
            assert!(
                !d_bit8.iter().any(|d| d.code == "L51-CONST-004"),
                "{:?} with B=256 must not report L51-CONST-004",
                op
            );
            assert_eq!(
                d_bit8.len(),
                1,
                "{:?} with B=256 must produce only L51-REG-002",
                op
            );
        }

        // NEWTABLE with high legal B (array size hint = 255) must not report L51-REG-002
        let newtable = RawInstruction51::encode_iabc(Opcode51::NewTable, 0, 255, 0);
        let proto_nt = make_test_proto(vec![newtable], 0, 0);
        let chunk_nt = make_test_chunk(proto_nt);
        let (_, d_nt) = validate_chunk_lua51(&chunk_nt);
        assert!(
            !d_nt.iter().any(|d| d.code == "L51-REG-002"),
            "NEWTABLE.B must not report L51-REG-002"
        );

        // Deferred RK opcodes (e.g. ADD, SETTABLE, EQ) with B=2 (no RK bit) must not report L51-REG-002
        for op in [Opcode51::Add, Opcode51::SetTable, Opcode51::Eq] {
            let inst_rk = RawInstruction51::encode_iabc(op, 0, 2, 0);
            let proto_rk = make_test_proto(vec![inst_rk], 0, 0);
            let chunk_rk = make_test_chunk(proto_rk);
            let (_, d_rk) = validate_chunk_lua51(&chunk_rk);
            assert!(
                !d_rk.iter().any(|d| d.code == "L51-REG-002"),
                "Deferred RK opcode {:?} must not report L51-REG-002",
                op
            );
        }
    }

    #[test]
    fn test_validator_register_c_fixed_and_rk() {
        // maxstacksize = 2: C=1 is valid, C=2 is invalid (L51-REG-003), C=256 reports L51-REG-003 and no L51-CONST-005
        let inst_valid = RawInstruction51::encode_iabc(Opcode51::Concat, 0, 0, 1);
        let proto_valid = make_test_proto(vec![inst_valid], 0, 0);
        let chunk_valid = make_test_chunk(proto_valid);
        let (v_valid, d_valid) = validate_chunk_lua51(&chunk_valid);
        assert_eq!(v_valid, Verdict::ValidForParser);
        assert!(
            d_valid.is_empty(),
            "CONCAT with C=1 must produce no diagnostics, got: {:?}",
            d_valid
        );

        let inst_invalid = RawInstruction51::encode_iabc(Opcode51::Concat, 0, 0, 2);
        let proto_invalid = make_test_proto(vec![inst_invalid], 0, 0);
        let chunk_invalid = make_test_chunk(proto_invalid);
        let (v_invalid, d_invalid) = validate_chunk_lua51(&chunk_invalid);
        assert_eq!(v_invalid, Verdict::Invalid);
        let reg_c_invalid: Vec<_> = d_invalid
            .iter()
            .filter(|d| d.code == "L51-REG-003")
            .collect();
        assert_eq!(
            reg_c_invalid.len(),
            1,
            "CONCAT with C=2 must report L51-REG-003"
        );
        assert_eq!(
            reg_c_invalid[0].message,
            "Register C (2) exceeds maxstacksize (2) at PC 0"
        );

        let inst_bit8 = RawInstruction51::encode_iabc(Opcode51::Concat, 0, 0, 256);
        let proto_bit8 = make_test_proto(vec![inst_bit8], 0, 0);
        let chunk_bit8 = make_test_chunk(proto_bit8);
        let (v_bit8, d_bit8) = validate_chunk_lua51(&chunk_bit8);
        assert_eq!(v_bit8, Verdict::Invalid);
        let reg_c_bit8: Vec<_> = d_bit8.iter().filter(|d| d.code == "L51-REG-003").collect();
        assert_eq!(
            reg_c_bit8.len(),
            1,
            "CONCAT with C=256 must report exactly one L51-REG-003"
        );
        assert_eq!(
            reg_c_bit8[0].message,
            "Register C (256) exceeds maxstacksize (2) at PC 0"
        );
        assert!(
            !d_bit8.iter().any(|d| d.code == "L51-CONST-005"),
            "CONCAT with C=256 must not report L51-CONST-005"
        );
        assert_eq!(
            d_bit8.len(),
            1,
            "CONCAT with C=256 must produce only L51-REG-003"
        );

        // High non-register C fields (NEWTABLE, SETLIST, CALL, LOADBOOL, TEST, TESTSET, TAILCALL) must not report L51-REG-003
        for op in [
            Opcode51::NewTable,
            Opcode51::SetList,
            Opcode51::Call,
            Opcode51::LoadBool,
            Opcode51::Test,
            Opcode51::TestSet,
            Opcode51::TailCall,
        ] {
            let inst_non_reg = RawInstruction51::encode_iabc(op, 0, 0, 255);
            let proto_non_reg = make_test_proto(vec![inst_non_reg], 0, 0);
            let chunk_non_reg = make_test_chunk(proto_non_reg);
            let (_, d_non_reg) = validate_chunk_lua51(&chunk_non_reg);
            assert!(
                !d_non_reg.iter().any(|d| d.code == "L51-REG-003"),
                "{:?}.C must not report L51-REG-003",
                op
            );
        }

        // Active RK opcodes (ADD, SETTABLE, EQ) at maxstacksize 2
        for op in [Opcode51::Add, Opcode51::SetTable, Opcode51::Eq] {
            // C=1 (bit 8 clear, inside frame) -> valid
            let inst_valid = RawInstruction51::encode_iabc(op, 0, 0, 1);
            let proto_valid = make_test_proto(vec![inst_valid], 0, 0);
            let chunk_valid = make_test_chunk(proto_valid);
            let (v_valid, d_valid) = validate_chunk_lua51(&chunk_valid);
            assert_eq!(
                v_valid,
                Verdict::ValidForParser,
                "{:?} with C=1 must be ValidForParser",
                op
            );
            assert!(
                d_valid.is_empty(),
                "{:?} with C=1 must produce no diagnostics, got: {:?}",
                op,
                d_valid
            );

            // C=2 (bit 8 clear, >= maxstacksize) -> invalid (L51-REG-003)
            let inst_invalid = RawInstruction51::encode_iabc(op, 0, 0, 2);
            let proto_invalid = make_test_proto(vec![inst_invalid], 0, 0);
            let chunk_invalid = make_test_chunk(proto_invalid);
            let (v_invalid, d_invalid) = validate_chunk_lua51(&chunk_invalid);
            assert_eq!(v_invalid, Verdict::Invalid);
            let reg_c_invalid: Vec<_> = d_invalid
                .iter()
                .filter(|d| d.code == "L51-REG-003")
                .collect();
            assert_eq!(
                reg_c_invalid.len(),
                1,
                "{:?} with C=2 must report L51-REG-003",
                op
            );
            assert_eq!(
                reg_c_invalid[0].message,
                "Register C (2) exceeds maxstacksize (2) at PC 0"
            );

            // C=256 (bit 8 set, selects K(0) from a one-constant owner) -> produces no L51-REG-003
            let inst_k = RawInstruction51::encode_iabc(op, 0, 0, 256);
            let mut proto_k = make_test_proto(vec![inst_k], 0, 0);
            proto_k.constants = vec![Constant {
                id: StableId::constant(proto_k.path.clone(), 0),
                index: 0,
                value: ConstantValue::Nil,
                source: SourceLocation::new(0, &[]),
            }];
            let chunk_k = make_test_chunk(proto_k);
            let (v_k, d_k) = validate_chunk_lua51(&chunk_k);
            assert_eq!(
                v_k,
                Verdict::ValidForParser,
                "{:?} with C=256 and 1 constant must be ValidForParser",
                op
            );
            assert!(
                !d_k.iter().any(|d| d.code == "L51-REG-003"),
                "{:?} with C=256 must not report L51-REG-003",
                op
            );
        }
    }
}
