//! Production disassembly emitter for Lua 5.1 bytecode.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory};
use luad_core::disasm::{
    DisassembledInstruction, DisassembledOperand, DisassembledPrototype, EncodedOperands,
    OperandKind, ResolvedFact,
};
use luad_core::id::StableId;
use luad_core::model::{ConstantValue, Prototype};
use luad_core::provenance::{Confidence, SourceLocation};
use luad_core::scalar::render_constant;

use crate::opcodes::{Opcode51, RawInstruction51};
use crate::roles::{discover_roles_lua51, Lua51PhysicalRole};

/// Produce structured, typed disassembly for a Lua 5.1 prototype and all child prototypes.
#[must_use]
pub fn disassemble_proto_lua51(proto: &Prototype) -> DisassembledPrototype {
    let source_name = proto.source_name.as_ref().map(|s| s.display.clone());
    let mut instructions = Vec::with_capacity(proto.instructions.len());
    let mut proto_diagnostics = Vec::new();

    let role_map = discover_roles_lua51(proto);

    for (pc, inst) in proto.instructions.iter().enumerate() {
        let role = role_map.get(pc);
        let d_inst = disassemble_instruction_lua51(proto, pc, inst.raw_word, role);
        proto_diagnostics.extend(d_inst.diagnostics.clone());
        instructions.push(d_inst);
    }

    let mut child_protos = Vec::with_capacity(proto.protos.len());
    for child in &proto.protos {
        let child_disasm = disassemble_proto_lua51(child);
        proto_diagnostics.extend(child_disasm.diagnostics.clone());
        child_protos.push(child_disasm);
    }

    DisassembledPrototype {
        id: proto.id.clone(),
        source_name,
        line_defined: proto.line_defined,
        last_line_defined: proto.last_line_defined,
        numparams: proto.numparams,
        is_vararg: proto.is_vararg != 0,
        maxstacksize: proto.maxstacksize,
        instructions,
        diagnostics: proto_diagnostics,
        child_protos,
    }
}

/// Produce structured, typed disassembly according to the v1 scheme where only closure bindings are companions.
#[must_use]
pub fn disassemble_proto_lua51_v1(proto: &Prototype) -> DisassembledPrototype {
    let source_name = proto.source_name.as_ref().map(|s| s.display.clone());
    let mut instructions = Vec::with_capacity(proto.instructions.len());
    let mut proto_diagnostics = Vec::new();

    let mut binding_descriptors: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    for (pc, inst) in proto.instructions.iter().enumerate() {
        let raw = RawInstruction51::decode(inst.raw_word);
        if raw.opcode == Some(Opcode51::Closure) {
            let child_bx = raw.bx as usize;
            let nups = proto
                .protos
                .get(child_bx)
                .map(|p| p.upvalues.len())
                .unwrap_or(0);
            for (j, b_pc) in (0..nups).zip(pc + 1..) {
                if b_pc < proto.instructions.len() {
                    binding_descriptors.insert(b_pc, (pc, j));
                }
            }
        }
    }

    for (pc, inst) in proto.instructions.iter().enumerate() {
        let role = if let Some(&(owner_pc, upvalue_index)) = binding_descriptors.get(&pc) {
            Lua51PhysicalRole::ClosureBinding {
                owner_pc,
                upvalue_index,
            }
        } else {
            Lua51PhysicalRole::Instruction
        };
        let d_inst = disassemble_instruction_lua51(proto, pc, inst.raw_word, role);
        proto_diagnostics.extend(d_inst.diagnostics.clone());
        instructions.push(d_inst);
    }

    let mut child_protos = Vec::with_capacity(proto.protos.len());
    for child in &proto.protos {
        let child_disasm = disassemble_proto_lua51_v1(child);
        proto_diagnostics.extend(child_disasm.diagnostics.clone());
        child_protos.push(child_disasm);
    }

    DisassembledPrototype {
        id: proto.id.clone(),
        source_name,
        line_defined: proto.line_defined,
        last_line_defined: proto.last_line_defined,
        numparams: proto.numparams,
        is_vararg: proto.is_vararg != 0,
        maxstacksize: proto.maxstacksize,
        instructions,
        diagnostics: proto_diagnostics,
        child_protos,
    }
}

/// Disassemble a single Lua 5.1 instruction word within its owning prototype context.
#[must_use]
pub fn disassemble_instruction_lua51(
    proto: &Prototype,
    pc: usize,
    raw_word: u32,
    role: Lua51PhysicalRole,
) -> DisassembledInstruction {
    let raw = RawInstruction51::decode(raw_word);
    let raw_hex = format!("0x{:08x}", raw_word);
    let inst_id = match &proto.id {
        StableId::Proto(path) => StableId::Instruction {
            proto: path.clone(),
            pc,
        },
        other => other.clone(),
    };

    let source = proto
        .instructions
        .get(pc)
        .map(|i| i.source.clone())
        .unwrap_or_else(|| SourceLocation::new(0, &raw_word.to_le_bytes()));

    let line = {
        let l = proto.get_line_for_pc(pc);
        if l > 0 {
            Some(l)
        } else {
            None
        }
    };

    let encoded_operands = EncodedOperands {
        a: raw.a,
        b: raw.b as u32,
        c: raw.c as u32,
        k: 0,
        bx: raw.bx,
        sbx: raw.sbx,
        ax: 0,
        sb: 0,
        sc: 0,
        sj: 0,
    };

    if let Lua51PhysicalRole::SetlistExtra { owner_pc } = role {
        let operands = vec![DisassembledOperand {
            name: "value".to_string(),
            kind: OperandKind::Raw {
                value: raw_word as u64,
            },
            display: format!("{raw_word} (0x{raw_word:08x})"),
            resolved: None,
        }];

        return DisassembledInstruction {
            id: inst_id,
            pc,
            raw_word,
            raw_hex,
            mnemonic: "setlist_extra".to_string(),
            opcode_num: raw.opcode_num,
            role: "setlist_extra".to_string(),
            encoded_operands,
            line,
            operands,
            jump_target: None,
            companion_pc: Some(owner_pc),
            metamethod: None,
            comment: Some(format!("setlist_extra {raw_word} (0x{raw_word:08x})")),
            confidence: Confidence::Fact,
            source,
            diagnostics: vec![],
        };
    }

    if let Lua51PhysicalRole::ClosureBinding {
        owner_pc,
        upvalue_index,
    } = role
    {
        let is_move = raw.opcode == Some(Opcode51::Move);
        let role_str = "closure_binding".to_string();
        let mnemonic = match raw.opcode {
            Some(op) => format!("{} (binding descriptor)", op.name()),
            None => format!("OP_UNKNOWN_0x{:02x} (binding descriptor)", raw.opcode_num),
        };
        let parent_desc = if is_move {
            format!("parent R({})", raw.b)
        } else {
            format!("parent upvalue[{}]", raw.b)
        };

        let mut operands = Vec::new();
        operands.push(DisassembledOperand {
            name: "upvalue_index".to_string(),
            kind: OperandKind::ImmediateUnsigned {
                value: upvalue_index as u64,
            },
            display: format!("upvalue[{upvalue_index}]"),
            resolved: None,
        });
        operands.push(DisassembledOperand {
            name: "source".to_string(),
            kind: if is_move {
                OperandKind::Register { index: raw.b as u8 }
            } else {
                OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                }
            },
            display: parent_desc.clone(),
            resolved: None,
        });

        let comment = Some(format!("upvalue[{upvalue_index}] <- {parent_desc}"));

        return DisassembledInstruction {
            id: inst_id,
            pc,
            raw_word,
            raw_hex,
            mnemonic,
            opcode_num: raw.opcode_num,
            role: role_str,
            encoded_operands,
            line,
            operands,
            jump_target: None,
            companion_pc: Some(owner_pc),
            metamethod: None,
            comment,
            confidence: Confidence::Fact,
            source,
            diagnostics: vec![],
        };
    }

    let Some(op) = raw.opcode else {
        return DisassembledInstruction {
            id: inst_id.clone(),
            pc,
            raw_word,
            raw_hex,
            mnemonic: format!("OP_UNKNOWN_0x{:02x}", raw.opcode_num),
            opcode_num: raw.opcode_num,
            role: "instruction".to_string(),
            encoded_operands,
            line,
            operands: vec![],
            jump_target: None,
            companion_pc: None,
            metamethod: None,
            comment: None,
            confidence: Confidence::Unverified,
            source,
            diagnostics: vec![Diagnostic::error(
                "L51-DISASM-001",
                DiagnosticCategory::Instruction,
                inst_id,
                format!("Unknown opcode number 0x{:02x}", raw.opcode_num),
            )],
        };
    };

    let mut operands = Vec::new();
    let mut diagnostics = Vec::new();
    let mut jump_target = None;
    let mut companion_pc = None;
    let mut comment = None;

    let format_k = |k_idx: usize| -> (Option<ConstantValue>, String) {
        if let Some(k) = proto.constants.get(k_idx) {
            let preview = render_constant(&k.value);
            (Some(k.value.clone()), preview)
        } else {
            (None, format!("<invalid constant index {k_idx}>"))
        }
    };

    let resolve_rk = |raw_val: u16,
                      name: &'static str,
                      ops: &mut Vec<DisassembledOperand>,
                      diags: &mut Vec<Diagnostic>| {
        let is_k = (raw_val & 0x100) != 0;
        let idx = (raw_val & 0xFF) as usize;
        if is_k {
            let (val_opt, preview) = format_k(idx);
            let resolved = val_opt.map(|v| ResolvedFact::Constant {
                index: idx,
                id: StableId::constant(proto.path.clone(), idx),
                value: v,
                formatted_preview: preview.clone(),
            });
            if resolved.is_none() {
                diags.push(Diagnostic::error(
                    "L51-DISASM-002",
                    DiagnosticCategory::Instruction,
                    inst_id.clone(),
                    format!("RK operand {name} constant index {idx} out of bounds"),
                ));
            }
            ops.push(DisassembledOperand {
                name: name.to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw_val as u64,
                },
                display: format!("K({idx})"),
                resolved,
            });
        } else {
            ops.push(DisassembledOperand {
                name: name.to_string(),
                kind: OperandKind::Register { index: idx as u8 },
                display: format!("R({idx})"),
                resolved: None,
            });
        }
    };

    match op {
        Opcode51::Move => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::Register { index: raw.b as u8 },
                display: format!("R({})", raw.b),
                resolved: None,
            });
        }
        Opcode51::LoadK => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            let k_idx = raw.bx as usize;
            let (val_opt, preview) = format_k(k_idx);
            let resolved = val_opt.map(|v| ResolvedFact::Constant {
                index: k_idx,
                id: StableId::constant(proto.path.clone(), k_idx),
                value: v,
                formatted_preview: preview.clone(),
            });
            if resolved.is_none() {
                diagnostics.push(Diagnostic::error(
                    "L51-DISASM-002",
                    DiagnosticCategory::Instruction,
                    inst_id.clone(),
                    format!("Constant index {k_idx} out of bounds"),
                ));
            }
            comment = Some(preview);
            operands.push(DisassembledOperand {
                name: "Bx".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.bx as u64,
                },
                display: format!("K({k_idx})"),
                resolved,
            });
        }
        Opcode51::LoadBool => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                },
                display: (raw.b != 0).to_string(),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.c as u64,
                },
                display: raw.c.to_string(),
                resolved: None,
            });
        }
        Opcode51::LoadNil => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::Register { index: raw.b as u8 },
                display: format!("R({})", raw.b),
                resolved: None,
            });
        }
        Opcode51::GetUpval | Opcode51::SetUpval => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            let u_idx = raw.b as u8;
            let u_name = proto
                .upvalues
                .get(raw.b as usize)
                .and_then(|u| u.name.as_ref().map(|s| s.display.clone()));
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                },
                display: format!("Upvalue({u_idx})"),
                resolved: Some(ResolvedFact::Upvalue {
                    index: u_idx,
                    id: StableId::upvalue(proto.path.clone(), u_idx as usize),
                    name: u_name.clone(),
                }),
            });
            if let Some(n) = u_name {
                comment = Some(format!("; {n}"));
            }
        }
        Opcode51::GetGlobal | Opcode51::SetGlobal => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            let k_idx = raw.bx as usize;
            let (val_opt, preview) = format_k(k_idx);
            let resolved = val_opt.map(|v| ResolvedFact::Constant {
                index: k_idx,
                id: StableId::constant(proto.path.clone(), k_idx),
                value: v,
                formatted_preview: preview.clone(),
            });
            comment = Some(preview);
            operands.push(DisassembledOperand {
                name: "Bx".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.bx as u64,
                },
                display: format!("K({k_idx})"),
                resolved,
            });
        }
        Opcode51::GetTable => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::Register { index: raw.b as u8 },
                display: format!("R({})", raw.b),
                resolved: None,
            });
            resolve_rk(raw.c, "C", &mut operands, &mut diagnostics);
        }
        Opcode51::SetTable => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            resolve_rk(raw.b, "B", &mut operands, &mut diagnostics);
            resolve_rk(raw.c, "C", &mut operands, &mut diagnostics);
        }
        Opcode51::NewTable => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                },
                display: raw.b.to_string(),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.c as u64,
                },
                display: raw.c.to_string(),
                resolved: None,
            });
        }
        Opcode51::SelfOp => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::Register { index: raw.b as u8 },
                display: format!("R({})", raw.b),
                resolved: None,
            });
            resolve_rk(raw.c, "C", &mut operands, &mut diagnostics);
        }
        Opcode51::Add
        | Opcode51::Sub
        | Opcode51::Mul
        | Opcode51::Div
        | Opcode51::Mod
        | Opcode51::Pow => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            resolve_rk(raw.b, "B", &mut operands, &mut diagnostics);
            resolve_rk(raw.c, "C", &mut operands, &mut diagnostics);
        }
        Opcode51::Unm | Opcode51::Not | Opcode51::Len => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::Register { index: raw.b as u8 },
                display: format!("R({})", raw.b),
                resolved: None,
            });
        }
        Opcode51::Concat => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::Register { index: raw.b as u8 },
                display: format!("R({})", raw.b),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::Register { index: raw.c as u8 },
                display: format!("R({})", raw.c),
                resolved: None,
            });
        }
        Opcode51::Jmp => {
            let target_pc = (pc as i32 + 1 + raw.sbx) as usize;
            jump_target = Some(target_pc);
            comment = Some(format!("to {target_pc}"));
            operands.push(DisassembledOperand {
                name: "sBx".to_string(),
                kind: OperandKind::ImmediateSigned {
                    value: raw.sbx as i64,
                },
                display: raw.sbx.to_string(),
                resolved: Some(ResolvedFact::JumpTarget {
                    target_pc,
                    id: StableId::instruction(proto.path.clone(), target_pc),
                }),
            });
        }
        Opcode51::Eq | Opcode51::Lt | Opcode51::Le => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.a as u64,
                },
                display: raw.a.to_string(),
                resolved: None,
            });
            resolve_rk(raw.b, "B", &mut operands, &mut diagnostics);
            resolve_rk(raw.c, "C", &mut operands, &mut diagnostics);
        }
        Opcode51::Test => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.c as u64,
                },
                display: raw.c.to_string(),
                resolved: None,
            });
        }
        Opcode51::TestSet => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::Register { index: raw.b as u8 },
                display: format!("R({})", raw.b),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.c as u64,
                },
                display: raw.c.to_string(),
                resolved: None,
            });
        }
        Opcode51::Call | Opcode51::TailCall => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                },
                display: raw.b.to_string(),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.c as u64,
                },
                display: raw.c.to_string(),
                resolved: None,
            });
        }
        Opcode51::Return => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                },
                display: raw.b.to_string(),
                resolved: None,
            });
        }
        Opcode51::ForLoop | Opcode51::ForPrep => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            let target_pc = (pc as i32 + 1 + raw.sbx) as usize;
            jump_target = Some(target_pc);
            comment = Some(format!("to {target_pc}"));
            operands.push(DisassembledOperand {
                name: "sBx".to_string(),
                kind: OperandKind::ImmediateSigned {
                    value: raw.sbx as i64,
                },
                display: raw.sbx.to_string(),
                resolved: Some(ResolvedFact::JumpTarget {
                    target_pc,
                    id: StableId::instruction(proto.path.clone(), target_pc),
                }),
            });
        }
        Opcode51::TForLoop => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.c as u64,
                },
                display: raw.c.to_string(),
                resolved: None,
            });
        }
        Opcode51::SetList => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                },
                display: raw.b.to_string(),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "C".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.c as u64,
                },
                display: raw.c.to_string(),
                resolved: None,
            });
            if raw.c == 0 && pc + 1 < proto.instructions.len() {
                companion_pc = Some(pc + 1);
            }
        }
        Opcode51::Close => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
        }
        Opcode51::Closure => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            let child_idx = raw.bx as usize;
            let child_path = proto.path.child(child_idx);
            let child_id = StableId::proto(child_path);
            comment = Some(child_id.to_string());
            let resolved = Some(ResolvedFact::Prototype {
                index: child_idx,
                id: child_id,
            });
            operands.push(DisassembledOperand {
                name: "Bx".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.bx as u64,
                },
                display: format!("Proto({child_idx})"),
                resolved,
            });
        }
        Opcode51::VarArg => {
            operands.push(DisassembledOperand {
                name: "A".to_string(),
                kind: OperandKind::Register { index: raw.a },
                display: format!("R({})", raw.a),
                resolved: None,
            });
            operands.push(DisassembledOperand {
                name: "B".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.b as u64,
                },
                display: raw.b.to_string(),
                resolved: None,
            });
        }
    }

    DisassembledInstruction {
        id: inst_id,
        pc,
        raw_word,
        raw_hex,
        mnemonic: op.name().to_string(),
        opcode_num: raw.opcode_num,
        role: "instruction".to_string(),
        encoded_operands,
        line,
        operands,
        jump_target,
        companion_pc,
        metamethod: None,
        comment,
        confidence: Confidence::Fact,
        source,
        diagnostics,
    }
}
