//! Structural and VM invariant validator for Lua 5.3 bytecode chunks.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::model::{Chunk, Prototype};

use crate::opcodes::{Opcode53, RawInstruction53};

const MAX_DIAGNOSTICS: usize = 10_000;

/// Validate Lua 5.3 chunk invariants.
pub fn validate_chunk_lua53(chunk: &Chunk) -> (Verdict, Vec<Diagnostic>) {
    let mut diagnostics = chunk.diagnostics.clone();
    validate_proto(&chunk.main_proto, &mut diagnostics);

    let mut deduped = Vec::with_capacity(diagnostics.len().min(MAX_DIAGNOSTICS));
    let mut seen = std::collections::HashSet::new();
    for diag in diagnostics {
        if deduped.len() >= MAX_DIAGNOSTICS {
            break;
        }
        if seen.insert(diag.clone()) {
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

fn uses_register_a(op: Opcode53) -> bool {
    !matches!(
        op,
        Opcode53::ExtraArg
            | Opcode53::Jmp
            | Opcode53::SetTabUp
            | Opcode53::Eq
            | Opcode53::Lt
            | Opcode53::Le
    )
}

fn validate_proto(proto: &Prototype, diags: &mut Vec<Diagnostic>) {
    if diags.len() >= MAX_DIAGNOSTICS {
        return;
    }
    let num_insts = proto.instructions.len();
    let num_constants = proto.constants.len();
    let num_upvalues = proto.upvalues.len();
    let num_protos = proto.protos.len();

    // 1. Stack bounds check
    if proto.maxstacksize > 250 {
        let diag = Diagnostic::warning(
            "L53-STACK-001",
            DiagnosticCategory::Structure,
            proto.id.clone(),
            format!("Unusually large maxstacksize: {}", proto.maxstacksize),
        )
        .with_source(proto.source.clone());
        diags.push(diag);
    }

    // 2. Validate instructions
    for (pc, inst) in proto.instructions.iter().enumerate() {
        if diags.len() >= MAX_DIAGNOSTICS {
            return;
        }
        let raw = RawInstruction53::decode(inst.raw_word);
        let inst_id = inst.id.clone();

        let Some(op) = raw.opcode else {
            let diag = Diagnostic::error(
                "L53-OP-001",
                DiagnosticCategory::Instruction,
                inst_id.clone(),
                format!("Invalid opcode 0x{:02x} at PC {pc}", raw.opcode_num),
            )
            .with_source(inst.source.clone())
            .with_suggested_action("Check dialect version or decompilation flags");
            diags.push(diag);
            continue;
        };

        // Companion pairing validation
        match op {
            Opcode53::LoadKx => {
                let has_extra = if pc + 1 < num_insts {
                    let next_raw = RawInstruction53::decode(proto.instructions[pc + 1].raw_word);
                    next_raw.opcode == Some(Opcode53::ExtraArg)
                } else {
                    false
                };
                if !has_extra {
                    diags.push(
                        Diagnostic::error(
                            "L53-COMPANION-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!("LOADKX at PC {pc} must be followed immediately by EXTRAARG"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::ExtraArg => {
                let preceded_by_kx = if pc > 0 {
                    let prev_raw = RawInstruction53::decode(proto.instructions[pc - 1].raw_word);
                    prev_raw.opcode == Some(Opcode53::LoadKx)
                        || (prev_raw.opcode == Some(Opcode53::SetList) && prev_raw.c == 0)
                } else {
                    false
                };
                if !preceded_by_kx {
                    diags.push(
                        Diagnostic::error(
                            "L53-COMPANION-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!("EXTRAARG at PC {pc} must be preceded by LOADKX or SETLIST with C=0"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            _ => {}
        }

        // Jump target bounds check
        match op {
            Opcode53::Jmp => {
                let dest_pc = (pc as i32 + 1) + raw.sbx;
                if dest_pc < 0 || dest_pc as usize >= num_insts {
                    diags.push(
                        Diagnostic::error(
                            "L53-JMP-001",
                            DiagnosticCategory::ControlFlow,
                            inst_id.clone(),
                            format!("Jump destination PC {dest_pc} out of bounds (total instructions: {num_insts})"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
                if raw.a != 0 && (raw.a - 1) >= proto.maxstacksize {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "JMP close register R({}) at PC {pc} exceeds maxstacksize {}",
                                raw.a - 1,
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::ForLoop | Opcode53::ForPrep | Opcode53::TForLoop => {
                let dest_pc = (pc as i32 + 1) + raw.sbx;
                if dest_pc < 0 || dest_pc as usize >= num_insts {
                    diags.push(
                        Diagnostic::error(
                            "L53-JMP-001",
                            DiagnosticCategory::ControlFlow,
                            inst_id.clone(),
                            format!("Loop destination PC {dest_pc} out of bounds (total instructions: {num_insts})"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            _ => {}
        }

        // Register A bounds
        if uses_register_a(op) && raw.a >= proto.maxstacksize {
            diags.push(
                Diagnostic::error(
                    "L53-REG-001",
                    DiagnosticCategory::Instruction,
                    inst_id.clone(),
                    format!(
                        "Register R({}) at PC {pc} exceeds maxstacksize {}",
                        raw.a, proto.maxstacksize
                    ),
                )
                .with_source(inst.source.clone()),
            );
        }

        // Register B and Constant bounds
        match op {
            Opcode53::Move
            | Opcode53::SetUpval
            | Opcode53::Unm
            | Opcode53::BNot
            | Opcode53::Not
            | Opcode53::Len
            | Opcode53::TestSet => {
                if (raw.b as u8) >= proto.maxstacksize {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Source register R({}) at PC {pc} exceeds maxstacksize {}",
                                raw.b, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::GetTable | Opcode53::SelfOp => {
                if (raw.b as u8) >= proto.maxstacksize {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Table register R({}) at PC {pc} exceeds maxstacksize {}",
                                raw.b, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::Concat => {
                if (raw.b as u8) >= proto.maxstacksize {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Concat start register R({}) at PC {pc} exceeds maxstacksize {}",
                                raw.b, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
                if (raw.c as u8) >= proto.maxstacksize {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-003",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Concat end register R({}) at PC {pc} exceeds maxstacksize {}",
                                raw.c, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
                if raw.b > raw.c {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Concat range invalid (R({}) > R({})) at PC {pc}",
                                raw.b, raw.c
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::SetTabUp
            | Opcode53::SetTable
            | Opcode53::Add
            | Opcode53::Sub
            | Opcode53::Mul
            | Opcode53::Mod
            | Opcode53::Pow
            | Opcode53::Div
            | Opcode53::IDiv
            | Opcode53::BAnd
            | Opcode53::BOr
            | Opcode53::BXor
            | Opcode53::Shl
            | Opcode53::Shr
            | Opcode53::Eq
            | Opcode53::Lt
            | Opcode53::Le => {
                if raw.is_b_k() {
                    let k_idx = raw.b_index_k();
                    if k_idx >= num_constants {
                        diags.push(
                            Diagnostic::error(
                                "L53-CONST-003",
                                DiagnosticCategory::Instruction,
                                inst_id.clone(),
                                format!("RK(B) constant index {k_idx} exceeds table size {num_constants} at PC {pc}"),
                            )
                            .with_source(inst.source.clone()),
                        );
                    }
                } else if (raw.b as u8) >= proto.maxstacksize {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "RK(B) register R({}) at PC {pc} exceeds maxstacksize {}",
                                raw.b, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::LoadK => {
                if raw.bx as usize >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L53-CONST-003",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Constant index {} exceeds table size {num_constants} at PC {pc}",
                                raw.bx
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::ExtraArg if pc > 0 => {
                let prev_raw = RawInstruction53::decode(proto.instructions[pc - 1].raw_word);
                if prev_raw.opcode == Some(Opcode53::LoadKx) && raw.ax as usize >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L53-CONST-003",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "EXTRAARG constant index {} exceeds table size {num_constants} at PC {pc}",
                                raw.ax
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            _ => {}
        }

        // Register C and RK(C) bounds
        match op {
            Opcode53::GetTabUp
            | Opcode53::GetTable
            | Opcode53::SetTabUp
            | Opcode53::SetTable
            | Opcode53::SelfOp
            | Opcode53::Add
            | Opcode53::Sub
            | Opcode53::Mul
            | Opcode53::Mod
            | Opcode53::Pow
            | Opcode53::Div
            | Opcode53::IDiv
            | Opcode53::BAnd
            | Opcode53::BOr
            | Opcode53::BXor
            | Opcode53::Shl
            | Opcode53::Shr
            | Opcode53::Eq
            | Opcode53::Lt
            | Opcode53::Le => {
                if raw.is_c_k() {
                    let k_idx = raw.c_index_k();
                    if k_idx >= num_constants {
                        diags.push(
                            Diagnostic::error(
                                "L53-CONST-003",
                                DiagnosticCategory::Instruction,
                                inst_id.clone(),
                                format!("RK(C) constant index {k_idx} exceeds table size {num_constants} at PC {pc}"),
                            )
                            .with_source(inst.source.clone()),
                        );
                    }
                } else if (raw.c as u8) >= proto.maxstacksize {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-003",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "RK(C) register R({}) at PC {pc} exceeds maxstacksize {}",
                                raw.c, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            _ => {}
        }

        // Upvalue operand bounds
        match op {
            Opcode53::GetUpval | Opcode53::SetUpval | Opcode53::GetTabUp => {
                if raw.b as usize >= num_upvalues {
                    diags.push(
                        Diagnostic::error(
                            "L53-UPVAL-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!("Upvalue index {} exceeds declared upvalues count {num_upvalues} at PC {pc}", raw.b),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::SetTabUp if raw.a as usize >= num_upvalues => {
                diags.push(
                    Diagnostic::error(
                        "L53-UPVAL-002",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!("Table upvalue index {} exceeds declared upvalues count {num_upvalues} at PC {pc}", raw.a),
                    )
                    .with_source(inst.source.clone()),
                );
            }
            _ => {}
        }

        // Prototype operand bounds
        if op == Opcode53::Closure && raw.bx as usize >= num_protos {
            diags.push(
                Diagnostic::error(
                    "L53-PROTO-002",
                    DiagnosticCategory::Instruction,
                    inst_id.clone(),
                    format!("CLOSURE prototype index {} exceeds sub-prototypes count {num_protos} at PC {pc}", raw.bx),
                )
                .with_source(inst.source.clone()),
            );
        }

        // Fixed register span checks
        match op {
            Opcode53::LoadNil => {
                if raw.a as u16 + raw.b >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "LOADNIL register span R({})..R({}) exceeds maxstacksize {}",
                                raw.a,
                                raw.a + raw.b as u8,
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::SelfOp => {
                if raw.a as u16 + 1 >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "SELF target register window R({})..R({}) exceeds maxstacksize {}",
                                raw.a,
                                raw.a + 1,
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::Call => {
                if raw.b > 1 && (raw.a as u16 + raw.b - 1) > proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "CALL argument register window exceeds maxstacksize {} at PC {pc}",
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
                if raw.c > 1 && (raw.a as u16 + raw.c - 2) >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "CALL return register window exceeds maxstacksize {} at PC {pc}",
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::TailCall => {
                if raw.b > 1 && (raw.a as u16 + raw.b - 1) > proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!("TAILCALL argument register window exceeds maxstacksize {} at PC {pc}", proto.maxstacksize),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::Return => {
                if raw.b > 1 && (raw.a as u16 + raw.b - 2) >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "RETURN register window exceeds maxstacksize {} at PC {pc}",
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::ForLoop => {
                if raw.a as u16 + 3 >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "FORLOOP internal registers R({})..R({}) exceed maxstacksize {}",
                                raw.a,
                                raw.a + 3,
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::ForPrep => {
                if raw.a as u16 + 2 >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "FORPREP internal registers R({})..R({}) exceed maxstacksize {}",
                                raw.a,
                                raw.a + 2,
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::TForCall => {
                if (raw.a as u16 + 2 + raw.c) > proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "TFORCALL return window exceeds maxstacksize {} at PC {pc}",
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::TForLoop => {
                if raw.a as u16 + 1 >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "TFORLOOP state registers exceed maxstacksize {} at PC {pc}",
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::SetList => {
                if raw.b > 0 && (raw.a as u16 + raw.b) > proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L53-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "SETLIST values window exceeds maxstacksize {} at PC {pc}",
                                proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode53::VarArg
                if raw.b > 1 && (raw.a as u16 + raw.b - 2) >= proto.maxstacksize as u16 =>
            {
                diags.push(
                    Diagnostic::error(
                        "L53-REG-SPAN-001",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "VARARG destination register window exceeds maxstacksize {} at PC {pc}",
                            proto.maxstacksize
                        ),
                    )
                    .with_source(inst.source.clone()),
                );
            }
            _ => {}
        }
    }

    for child in &proto.protos {
        if diags.len() >= MAX_DIAGNOSTICS {
            return;
        }
        validate_proto(child, diags);
    }
}
