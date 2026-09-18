//! Structural and VM invariant validator for Lua 5.4 chunks.

use crate::opcodes::{Opcode54, RawInstruction54};
use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::id::StableId;
use luad_core::model::{Chunk, Prototype};

const MAX_DIAGNOSTICS: usize = 10_000;

/// Validate all structural and VM invariants of a parsed Lua 5.4 chunk.
pub fn validate_chunk_lua54(chunk: &Chunk) -> (Verdict, Vec<Diagnostic>) {
    let mut diagnostics = chunk.diagnostics.clone();

    // 1. Header validation checks
    if chunk.header.instruction_size != 4 {
        diagnostics.push(Diagnostic::error(
            "L54-VAL-HEADER-001",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            "Instruction size must be 4 bytes",
        ));
    }

    if chunk.header.lua_integer_size != 8 {
        diagnostics.push(Diagnostic::error(
            "L54-VAL-HEADER-002",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            "lua_Integer size must be 8 bytes",
        ));
    }

    if chunk.header.lua_number_size != 8 {
        diagnostics.push(Diagnostic::error(
            "L54-VAL-HEADER-003",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            "lua_Number size must be 8 bytes",
        ));
    }

    // 2. Prototype validation
    validate_proto_lua54(&chunk.main_proto, &mut diagnostics);

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

    let has_errors = diagnostics.iter().any(|d| d.severity == Severity::Error);
    let verdict = if has_errors {
        Verdict::Invalid
    } else {
        Verdict::ValidForAnalysis
    };

    (verdict, diagnostics)
}

fn uses_register_a(op: Opcode54) -> bool {
    !matches!(
        op,
        Opcode54::Jmp
            | Opcode54::Extraarg
            | Opcode54::Settabup
            | Opcode54::Return0
            | Opcode54::Varargprep
    )
}

fn validate_proto_lua54(proto: &Prototype, diagnostics: &mut Vec<Diagnostic>) {
    if diagnostics.len() >= MAX_DIAGNOSTICS {
        return;
    }
    let _proto_id = proto.id.clone();
    let num_instructions = proto.instructions.len();
    let num_constants = proto.constants.len();
    let num_upvalues = proto.upvalues.len();
    let num_protos = proto.protos.len();

    // Validate instructions
    for inst in &proto.instructions {
        if diagnostics.len() >= MAX_DIAGNOSTICS {
            return;
        }
        let raw = RawInstruction54::decode(inst.raw_word);
        let inst_id = inst.id.clone();

        let Some(op) = raw.opcode else {
            diagnostics.push(
                Diagnostic::error(
                    "L54-VAL-OPCODE-001",
                    DiagnosticCategory::Instruction,
                    inst_id.clone(),
                    format!("Invalid opcode number {} at PC {}", raw.opcode_num, inst.pc),
                )
                .with_source(inst.source.clone()),
            );
            continue;
        };

        // Stack size validation: check destination register A
        if uses_register_a(op) && raw.a >= proto.maxstacksize {
            diagnostics.push(
                Diagnostic::warning(
                    "L54-VAL-REG-001",
                    DiagnosticCategory::Instruction,
                    inst_id.clone(),
                    format!(
                        "Register R({}) at PC {} exceeds maxstacksize {}",
                        raw.a, inst.pc, proto.maxstacksize
                    ),
                )
                .with_source(inst.source.clone()),
            );
        }

        // Opcode-specific operand bounds checks
        match op {
            Opcode54::Loadk => {
                if (raw.bx as usize) >= num_constants {
                    diagnostics.push(Diagnostic::error(
                        "L54-VAL-CONST-001",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Constant index {} exceeds table size {} at PC {}",
                            raw.bx, num_constants, inst.pc
                        ),
                    ));
                }
            }
            Opcode54::Getupval | Opcode54::Setupval => {
                if (raw.b as usize) >= num_upvalues {
                    diagnostics.push(Diagnostic::error(
                        "L54-VAL-UPVAL-001",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Upvalue index {} exceeds upvalue count {} at PC {}",
                            raw.b, num_upvalues, inst.pc
                        ),
                    ));
                }
            }
            Opcode54::Gettabup | Opcode54::Settabup => {
                let upval_idx = if op == Opcode54::Gettabup {
                    raw.b
                } else {
                    raw.a
                };
                if (upval_idx as usize) >= num_upvalues {
                    diagnostics.push(Diagnostic::error(
                        "L54-VAL-UPVAL-002",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Table upvalue index {upval_idx} exceeds upvalue count {num_upvalues} at PC {}",
                            inst.pc
                        ),
                    ));
                }
            }
            Opcode54::Closure => {
                if (raw.bx as usize) >= num_protos {
                    diagnostics.push(Diagnostic::error(
                        "L54-VAL-PROTO-001",
                        DiagnosticCategory::Instruction,
                        inst_id.clone(),
                        format!(
                            "Prototype index {} exceeds sub-prototypes count {} at PC {}",
                            raw.bx, num_protos, inst.pc
                        ),
                    ));
                }
            }
            Opcode54::Jmp => {
                let target_pc = (inst.pc as i32) + 1 + raw.sj;
                if target_pc < 0 || (target_pc as usize) >= num_instructions {
                    diagnostics.push(Diagnostic::error(
                        "L54-VAL-JUMP-001",
                        DiagnosticCategory::ControlFlow,
                        inst_id.clone(),
                        format!(
                            "Jump destination PC {target_pc} is out of code bounds (0..{num_instructions}) at PC {}",
                            inst.pc
                        ),
                    ));
                }
            }
            _ => {}
        }
    }

    // Recursively validate child prototypes
    for child in &proto.protos {
        if diagnostics.len() >= MAX_DIAGNOSTICS {
            return;
        }
        validate_proto_lua54(child, diagnostics);
    }
}
