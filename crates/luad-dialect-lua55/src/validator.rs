//! Structural and VM invariant validator for Lua 5.5 bytecode chunks.

use luad_core::diagnostic::{
    truncate_and_dedup_diagnostics, Diagnostic, DiagnosticCategory, Severity, Verdict,
};
use luad_core::model::{Chunk, Prototype};

use crate::opcodes::{Opcode55, RawInstruction55};

const MAX_DIAGNOSTICS: usize = 10_000;

/// Validate Lua 5.5 chunk invariants.
pub fn validate_chunk_lua55(chunk: &Chunk) -> (Verdict, Vec<Diagnostic>) {
    let mut diagnostics = chunk.diagnostics.clone();
    let mut limit_reached = diagnostics.len() >= MAX_DIAGNOSTICS;
    if !limit_reached {
        validate_proto(&chunk.main_proto, &mut diagnostics, &mut limit_reached);
    }
    limit_reached = limit_reached || diagnostics.len() > MAX_DIAGNOSTICS;

    // Determine failure and completeness BEFORE truncating diagnostics
    let has_errors = diagnostics.iter().any(|d| d.severity == Severity::Error);
    let verdict = if has_errors {
        Verdict::Invalid
    } else if limit_reached {
        Verdict::Incomplete
    } else {
        Verdict::ValidForParser
    };

    if limit_reached {
        diagnostics.push(Diagnostic::error(
            "CORE-LIMIT-003",
            DiagnosticCategory::Parse,
            chunk.main_proto.id.clone(),
            format!("Diagnostic collection limit ({MAX_DIAGNOSTICS}) exceeded; validation terminated early and is incomplete"),
        ));
    }

    let diagnostics = truncate_and_dedup_diagnostics(diagnostics, MAX_DIAGNOSTICS);

    (verdict, diagnostics)
}

fn uses_register_a(op: Opcode55) -> bool {
    !matches!(
        op,
        Opcode55::Jmp
            | Opcode55::Extraarg
            | Opcode55::Settabup
            | Opcode55::Return0
            | Opcode55::Varargprep
    )
}

fn validate_proto(proto: &Prototype, diags: &mut Vec<Diagnostic>, limit_reached: &mut bool) {
    if *limit_reached || diags.len() >= MAX_DIAGNOSTICS {
        *limit_reached = true;
        return;
    }
    let num_insts = proto.instructions.len();
    let num_constants = proto.constants.len();
    let num_upvalues = proto.upvalues.len();
    let num_protos = proto.protos.len();

    // 1. Stack bounds check
    if proto.maxstacksize > 250 {
        let diag = Diagnostic::warning(
            "L55-STACK-001",
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
            *limit_reached = true;
            return;
        }
        let raw = RawInstruction55::decode(inst.raw_word);
        let inst_id = inst.id.clone();

        let Some(op) = raw.opcode else {
            let diag = Diagnostic::error(
                "L55-OP-001",
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
            Opcode55::Loadkx => {
                let has_extra = if pc + 1 < num_insts {
                    let next_raw = RawInstruction55::decode(proto.instructions[pc + 1].raw_word);
                    next_raw.opcode == Some(Opcode55::Extraarg)
                } else {
                    false
                };
                if !has_extra {
                    diags.push(
                        Diagnostic::error(
                            "L55-COMPANION-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!("LOADKX at PC {pc} must be followed immediately by EXTRAARG"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Extraarg => {
                let preceded_by_companion = if pc > 0 {
                    let prev_raw = RawInstruction55::decode(proto.instructions[pc - 1].raw_word);
                    matches!(
                        prev_raw.opcode,
                        Some(Opcode55::Loadkx | Opcode55::Newtable | Opcode55::Setlist)
                    )
                } else {
                    false
                };
                if !preceded_by_companion {
                    diags.push(
                        Diagnostic::error(
                            "L55-COMPANION-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!("EXTRAARG at PC {pc} must be preceded by LOADKX, NEWTABLE, or SETLIST"),
                        )
                        .with_source(inst.source.clone()),
                    );
                } else if pc > 0 {
                    let prev_raw = RawInstruction55::decode(proto.instructions[pc - 1].raw_word);
                    if prev_raw.opcode == Some(Opcode55::Loadkx)
                        && (raw.ax as usize) >= num_constants
                    {
                        diags.push(
                            Diagnostic::error(
                                "L55-CONST-002",
                                DiagnosticCategory::Instruction,
                                inst_id.clone(),
                                format!(
                                    "EXTRAARG constant index {} exceeds constant count {} at PC {pc}",
                                    raw.ax, num_constants
                                ),
                            )
                            .with_source(inst.source.clone()),
                        );
                    }
                }
            }
            _ => {}
        }

        // Jump target bounds check
        match op {
            Opcode55::Jmp => {
                let dest_pc = (pc as i32 + 1) + raw.sj;
                if dest_pc < 0 || dest_pc as usize >= num_insts {
                    diags.push(
                        Diagnostic::error(
                            "L55-JMP-001",
                            DiagnosticCategory::ControlFlow,
                            inst_id.clone(),
                            format!("Jump destination PC {dest_pc} out of bounds (total instructions: {num_insts})"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Forprep | Opcode55::Tforprep => {
                let dest_pc = pc + 1 + raw.bx as usize;
                if dest_pc >= num_insts {
                    diags.push(
                        Diagnostic::error(
                            "L55-JMP-001",
                            DiagnosticCategory::ControlFlow,
                            inst_id.clone(),
                            format!("Loop destination PC {dest_pc} out of bounds (total instructions: {num_insts})"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Forloop | Opcode55::Tforloop => {
                let dest_pc = (pc as i32 + 1) - (raw.bx as i32);
                if dest_pc < 0 || dest_pc as usize >= num_insts {
                    diags.push(
                        Diagnostic::error(
                            "L55-JMP-001",
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
                    "L55-REG-001",
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

        // Register B bounds
        match op {
            Opcode55::Move
            | Opcode55::Gettable
            | Opcode55::Geti
            | Opcode55::Getfield
            | Opcode55::Settable
            | Opcode55::SelfOp
            | Opcode55::Addi
            | Opcode55::Shli
            | Opcode55::Shri
            | Opcode55::Addk
            | Opcode55::Subk
            | Opcode55::Mulk
            | Opcode55::Modk
            | Opcode55::Powk
            | Opcode55::Divk
            | Opcode55::Idivk
            | Opcode55::Bandk
            | Opcode55::Bork
            | Opcode55::Bxork
            | Opcode55::Add
            | Opcode55::Sub
            | Opcode55::Mul
            | Opcode55::Mod
            | Opcode55::Pow
            | Opcode55::Div
            | Opcode55::Idiv
            | Opcode55::Band
            | Opcode55::Bor
            | Opcode55::Bxor
            | Opcode55::Shl
            | Opcode55::Shr
            | Opcode55::Mmbin
            | Opcode55::Unm
            | Opcode55::Bnot
            | Opcode55::Not
            | Opcode55::Len
            | Opcode55::Eq
            | Opcode55::Lt
            | Opcode55::Le
            | Opcode55::Testset
            | Opcode55::Getvarg
                if raw.b >= proto.maxstacksize =>
            {
                diags.push(
                    Diagnostic::error(
                        "L55-REG-002",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Register R({}) at PC {pc} exceeds maxstacksize {}",
                            raw.b, proto.maxstacksize
                        ),
                    )
                    .with_source(inst.source.clone()),
                );
            }
            _ => {}
        }

        // Register C bounds
        match op {
            Opcode55::Gettable
            | Opcode55::Add
            | Opcode55::Sub
            | Opcode55::Mul
            | Opcode55::Mod
            | Opcode55::Pow
            | Opcode55::Div
            | Opcode55::Idiv
            | Opcode55::Band
            | Opcode55::Bor
            | Opcode55::Bxor
            | Opcode55::Shl
            | Opcode55::Shr
            | Opcode55::Getvarg
                if raw.c >= proto.maxstacksize =>
            {
                diags.push(
                    Diagnostic::error(
                        "L55-REG-003",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Register R({}) at PC {pc} exceeds maxstacksize {}",
                            raw.c, proto.maxstacksize
                        ),
                    )
                    .with_source(inst.source.clone()),
                );
            }
            Opcode55::Settabup | Opcode55::Settable | Opcode55::Seti | Opcode55::Setfield
                if raw.k == 0 && raw.c >= proto.maxstacksize =>
            {
                diags.push(
                    Diagnostic::error(
                        "L55-REG-003",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Register R({}) at PC {pc} exceeds maxstacksize {}",
                            raw.c, proto.maxstacksize
                        ),
                    )
                    .with_source(inst.source.clone()),
                );
            }
            _ => {}
        }

        // Constant bounds
        match op {
            Opcode55::Loadk => {
                if (raw.bx as usize) >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L55-CONST-002",
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
            Opcode55::Getfield | Opcode55::Gettabup => {
                if (raw.c as usize) >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L55-CONST-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Constant index {} exceeds table size {num_constants} at PC {pc}",
                                raw.c
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Setfield | Opcode55::Settabup | Opcode55::Mmbink | Opcode55::Eqk => {
                if (raw.b as usize) >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L55-CONST-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Constant index {} exceeds table size {num_constants} at PC {pc}",
                                raw.b
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Addk
            | Opcode55::Subk
            | Opcode55::Mulk
            | Opcode55::Modk
            | Opcode55::Powk
            | Opcode55::Divk
            | Opcode55::Idivk
            | Opcode55::Bandk
            | Opcode55::Bork
            | Opcode55::Bxork => {
                if (raw.c as usize) >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L55-CONST-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Constant index {} exceeds table size {num_constants} at PC {pc}",
                                raw.c
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Settable | Opcode55::Seti => {
                if raw.k != 0 && (raw.c as usize) >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L55-CONST-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Constant index {} exceeds table size {num_constants} at PC {pc}",
                                raw.c
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Errnnil if raw.bx > 0 => {
                let k_idx = (raw.bx - 1) as usize;
                if k_idx >= num_constants {
                    diags.push(
                        Diagnostic::error(
                            "L55-CONST-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!("Constant index {k_idx} exceeds table size {num_constants} at PC {pc}"),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            _ => {}
        }

        // Upvalue bounds
        match op {
            Opcode55::Getupval | Opcode55::Setupval | Opcode55::Gettabup => {
                if (raw.b as usize) >= num_upvalues {
                    diags.push(
                        Diagnostic::error(
                            "L55-UPVAL-002",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "Upvalue index {} exceeds count {num_upvalues} at PC {pc}",
                                raw.b
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Settabup if (raw.a as usize) >= num_upvalues => {
                diags.push(
                    Diagnostic::error(
                        "L55-UPVAL-002",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Upvalue index {} exceeds count {num_upvalues} at PC {pc}",
                            raw.a
                        ),
                    )
                    .with_source(inst.source.clone()),
                );
            }
            _ => {}
        }

        // Prototype bounds
        if op == Opcode55::Closure && (raw.bx as usize) >= num_protos {
            diags.push(
                Diagnostic::error(
                    "L55-PROTO-002",
                    DiagnosticCategory::Instruction,
                    inst_id.clone(),
                    format!(
                        "Child prototype index {} exceeds count {num_protos} at PC {pc}",
                        raw.bx
                    ),
                )
                .with_source(inst.source.clone()),
            );
        }

        // Fixed register span checks
        match op {
            Opcode55::Loadnil => {
                let end_reg = raw.a as u16 + raw.b as u16;
                if end_reg >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L55-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "LOADNIL register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                raw.a, end_reg, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Concat => {
                if raw.b > 0 {
                    let end_reg = raw.a as u16 + raw.b as u16 - 1;
                    if end_reg >= proto.maxstacksize as u16 {
                        diags.push(
                            Diagnostic::error(
                                "L55-REG-SPAN-001",
                                DiagnosticCategory::Instruction,
                                inst_id.clone(),
                                format!(
                                    "CONCAT register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                    raw.a, end_reg, proto.maxstacksize
                                ),
                            )
                            .with_source(inst.source.clone()),
                        );
                    }
                }
            }
            Opcode55::SelfOp => {
                if (raw.a as u16 + 1) >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L55-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "SELF target register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                raw.a, raw.a + 1, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Call | Opcode55::Tailcall => {
                if raw.b > 1 {
                    let arg_end = raw.a as u16 + raw.b as u16 - 1;
                    if arg_end >= proto.maxstacksize as u16 {
                        diags.push(
                            Diagnostic::error(
                                "L55-REG-SPAN-001",
                                DiagnosticCategory::Instruction,
                                inst_id.clone(),
                                format!(
                                    "CALL argument register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                    raw.a + 1, arg_end, proto.maxstacksize
                                ),
                            )
                            .with_source(inst.source.clone()),
                        );
                    }
                }
                if op == Opcode55::Call && raw.c > 1 {
                    let ret_end = raw.a as u16 + raw.c as u16 - 2;
                    if ret_end >= proto.maxstacksize as u16 {
                        diags.push(
                            Diagnostic::error(
                                "L55-REG-SPAN-001",
                                DiagnosticCategory::Instruction,
                                inst_id.clone(),
                                format!(
                                    "CALL return register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                    raw.a, ret_end, proto.maxstacksize
                                ),
                            )
                            .with_source(inst.source.clone()),
                        );
                    }
                }
            }
            Opcode55::Return => {
                if raw.b > 1 {
                    let ret_end = raw.a as u16 + raw.b as u16 - 2;
                    if ret_end >= proto.maxstacksize as u16 {
                        diags.push(
                            Diagnostic::error(
                                "L55-REG-SPAN-001",
                                DiagnosticCategory::Instruction,
                                inst_id.clone(),
                                format!(
                                    "RETURN register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                    raw.a, ret_end, proto.maxstacksize
                                ),
                            )
                            .with_source(inst.source.clone()),
                        );
                    }
                }
            }
            Opcode55::Forloop | Opcode55::Forprep => {
                if (raw.a as u16 + 2) >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L55-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "FOR loop register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                raw.a, raw.a + 2, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Tforcall => {
                let span_end = raw.a as u16 + 3 + raw.c as u16;
                if span_end >= proto.maxstacksize as u16 {
                    diags.push(
                        Diagnostic::error(
                            "L55-REG-SPAN-001",
                            DiagnosticCategory::Instruction,
                            inst_id.clone(),
                            format!(
                                "TFORCALL register span R({})..R({}) exceeds maxstacksize {} at PC {pc}",
                                raw.a, span_end, proto.maxstacksize
                            ),
                        )
                        .with_source(inst.source.clone()),
                    );
                }
            }
            Opcode55::Tforloop if (raw.a as u16 + 2) >= proto.maxstacksize as u16 => {
                diags.push(
                    Diagnostic::error(
                        "L55-REG-SPAN-001",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "TFORLOOP register span R({})..R({}) exceeds maxstacksize {}",
                            raw.a,
                            raw.a + 2,
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
        if *limit_reached || diags.len() >= MAX_DIAGNOSTICS {
            *limit_reached = true;
            return;
        }
        validate_proto(child, diags, limit_reached);
    }
}
