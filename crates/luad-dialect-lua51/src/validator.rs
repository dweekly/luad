//! Structural and VM invariant validator for Lua 5.1 bytecode chunks.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::model::{Chunk, Prototype};

use crate::opcodes::{OpMode51, RawInstruction51};

/// Validate Lua 5.1 chunk invariants.
pub fn validate_chunk_lua51(chunk: &Chunk) -> (Verdict, Vec<Diagnostic>) {
    let mut diagnostics = chunk.diagnostics.clone();
    validate_proto(&chunk.main_proto, &mut diagnostics);

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

        // RK operand bounds validation
        if op.mode() == OpMode51::IABC {
            if raw.is_b_k() {
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

        // Closure binding descriptor validation
        if op == crate::opcodes::Opcode51::Closure {
            let child_idx = raw.bx as usize;
            if let Some(child) = proto.protos.get(child_idx) {
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
