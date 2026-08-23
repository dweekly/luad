//! Production disassembly emitter for Lua 5.4 bytecode.

#![forbid(unsafe_code)]

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity};
use luad_core::disasm::{
    DisassembledInstruction, DisassembledOperand, DisassembledPrototype, EncodedOperands,
    OperandKind, ResolvedFact,
};
use luad_core::id::StableId;
use luad_core::model::{ConstantValue, Prototype};
use luad_core::provenance::{Confidence, SourceLocation};

use crate::opcodes::{Opcode54, RawInstruction54};

/// Produce structured, typed disassembly for a Lua 5.4 prototype and all child prototypes.
#[must_use]
pub fn disassemble_proto_lua54(proto: &Prototype) -> DisassembledPrototype {
    let source_name = proto.source_name.as_ref().map(|s| s.display.clone());
    let mut instructions = Vec::with_capacity(proto.instructions.len());
    let mut proto_diagnostics = Vec::new();

    for (pc, inst) in proto.instructions.iter().enumerate() {
        let d_inst = disassemble_instruction_lua54(proto, pc, inst.raw_word);
        proto_diagnostics.extend(d_inst.diagnostics.clone());
        instructions.push(d_inst);
    }

    // Link forward companion pointers (e.g. instruction preceding MMBIN or EXTRAARG)
    for pc in 0..instructions.len() {
        if pc + 1 < instructions.len() {
            let next_role = &instructions[pc + 1].role;
            if next_role == "companion" || next_role == "extra_argument" {
                instructions[pc].companion_pc = Some(pc + 1);
            }
        }
    }

    let mut child_protos = Vec::with_capacity(proto.protos.len());
    for child in &proto.protos {
        let child_disasm = disassemble_proto_lua54(child);
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

/// Disassemble a single Lua 5.4 instruction word within its owning prototype context.
#[must_use]
pub fn disassemble_instruction_lua54(
    proto: &Prototype,
    pc: usize,
    raw_word: u32,
) -> DisassembledInstruction {
    let raw = RawInstruction54::decode(raw_word);
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
        k: raw.k,
        bx: raw.bx,
        sbx: raw.sbx,
        ax: raw.ax,
        sb: raw.sb,
        sc: raw.sc,
        sj: raw.sj,
    };

    let mut diagnostics = Vec::new();

    let Some(op) = raw.opcode else {
        let diag = Diagnostic {
            code: "L54-INVALID-OPCODE".to_string(),
            category: DiagnosticCategory::Instruction,
            severity: Severity::Error,
            target: inst_id.clone(),
            message: format!("Unrecognized Lua 5.4 opcode byte 0x{:02x}", raw.opcode_num),
            source: Some(source.clone()),
            evidence: None,
            suggested_action: None,
            help_topic: None,
        };
        diagnostics.push(diag);

        return DisassembledInstruction {
            id: inst_id,
            pc,
            raw_word,
            raw_hex,
            mnemonic: format!("UNKNOWN_0x{:02x}", raw.opcode_num),
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
            diagnostics,
        };
    };

    let mnemonic = op.name().to_string();
    let opcode_num = raw.opcode_num;
    let mut operands = Vec::new();
    let mut jump_target = None;
    let mut companion_pc = None;
    let mut metamethod = None;
    let mut comment = None;
    let mut role = "instruction".to_string();

    match op {
        Opcode54::Move
        | Opcode54::Loadnil
        | Opcode54::Getupval
        | Opcode54::Setupval
        | Opcode54::Unm
        | Opcode54::Bnot
        | Opcode54::Not
        | Opcode54::Len
        | Opcode54::Concat => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
        }

        Opcode54::Loadi | Opcode54::Loadf => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_signed("sBx", raw.sbx as i64));
        }

        Opcode54::Loadk => {
            operands.push(op_reg("A", raw.a));
            let bx = raw.bx as usize;
            let res = resolve_const(proto, bx, &inst_id, &source, &mut diagnostics);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("Bx", raw.bx as u64, res));
            comment = prev;
        }

        Opcode54::Loadkx => {
            operands.push(op_reg("A", raw.a));
            if pc + 1 < proto.instructions.len() {
                companion_pc = Some(pc + 1);
                let next_raw = RawInstruction54::decode(proto.instructions[pc + 1].raw_word);
                if next_raw.opcode == Some(Opcode54::Extraarg) {
                    let ax = next_raw.ax as usize;
                    let res = resolve_const(proto, ax, &inst_id, &source, &mut diagnostics);
                    let prev = res.as_ref().map(|c| c.preview.clone());
                    operands.push(op_const("Ax", next_raw.ax as u64, res));
                    comment = prev;
                }
            }
        }

        Opcode54::Loadfalse => {
            if raw.k != 0 {
                operands.push(op_reg_tagged("A", raw.a, true));
            } else {
                operands.push(op_reg("A", raw.a));
            }
        }

        Opcode54::Lfalseskip | Opcode54::Loadtrue => {
            operands.push(op_reg("A", raw.a));
        }

        Opcode54::Gettabup => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_upval("B", raw.b, proto));
            let c_idx = raw.c as usize;
            let res = resolve_const(proto, c_idx, &inst_id, &source, &mut diagnostics);
            let upval_name = proto
                .upvalues
                .get(raw.b as usize)
                .and_then(|u| u.name.as_ref().map(|s| s.display.clone()))
                .unwrap_or_else(|| "_ENV".to_string());
            let prev = res
                .as_ref()
                .map(|c| format!("{} {}", upval_name, c.preview));
            operands.push(op_const("C", raw.c as u64, res));
            comment = prev;
        }

        Opcode54::Gettable => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_reg("C", raw.c));
        }

        Opcode54::Geti => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_unsigned("C", raw.c as u64));
        }

        Opcode54::Getfield => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            let c_idx = raw.c as usize;
            let res = resolve_const(proto, c_idx, &inst_id, &source, &mut diagnostics);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("C", raw.c as u64, res));
            comment = prev;
        }

        Opcode54::Settabup => {
            operands.push(op_upval("A", raw.a, proto));
            let b_idx = raw.b as usize;
            let res_b = resolve_const(proto, b_idx, &inst_id, &source, &mut diagnostics);
            operands.push(op_const("B", raw.b as u64, res_b));
            let (op_c, prev_c) = if raw.k != 0 {
                let c_idx = raw.c as usize;
                let res_c =
                    resolve_const_tagged(proto, c_idx, true, &inst_id, &source, &mut diagnostics);
                let prev = res_c.as_ref().map(|c| format!("{}k", c.preview));
                (op_const("C", raw.c as u64, res_c), prev)
            } else {
                (op_reg("C", raw.c), None)
            };
            operands.push(op_c);
            let prev_b =
                resolve_const(proto, b_idx, &inst_id, &source, &mut diagnostics).map(|c| c.preview);
            if let (Some(pb), Some(pc)) = (prev_b, prev_c) {
                comment = Some(format!("{pb} {pc}"));
            } else if let Some(pb) =
                resolve_const(proto, b_idx, &inst_id, &source, &mut diagnostics).map(|c| c.preview)
            {
                comment = Some(pb);
            }
        }

        Opcode54::Settable => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            if raw.k != 0 {
                let c_idx = raw.c as usize;
                let res_c =
                    resolve_const_tagged(proto, c_idx, true, &inst_id, &source, &mut diagnostics);
                operands.push(op_const("C", raw.c as u64, res_c));
            } else {
                operands.push(op_reg("C", raw.c));
            }
        }

        Opcode54::Seti => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("B", raw.b as u64));
            if raw.k != 0 {
                let c_idx = raw.c as usize;
                let res_c =
                    resolve_const_tagged(proto, c_idx, true, &inst_id, &source, &mut diagnostics);
                let prev = res_c.as_ref().map(|c| c.preview.clone());
                operands.push(op_const("C", raw.c as u64, res_c));
                comment = prev;
            } else {
                operands.push(op_reg("C", raw.c));
            }
        }

        Opcode54::Setfield => {
            operands.push(op_reg("A", raw.a));
            let b_idx = raw.b as usize;
            let res_b = resolve_const(proto, b_idx, &inst_id, &source, &mut diagnostics);
            let prev_b = res_b.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("B", raw.b as u64, res_b));
            let (op_c, prev_c) = if raw.k != 0 {
                let c_idx = raw.c as usize;
                let res_c =
                    resolve_const_tagged(proto, c_idx, true, &inst_id, &source, &mut diagnostics);
                let prev = res_c.as_ref().map(|c| c.preview.clone());
                (op_const("C", raw.c as u64, res_c), prev)
            } else {
                (op_reg("C", raw.c), None)
            };
            operands.push(op_c);
            if let (Some(pb), Some(pc)) = (prev_b, prev_c) {
                comment = Some(format!("{pb} {pc}"));
            } else if let Some(pb) =
                resolve_const(proto, b_idx, &inst_id, &source, &mut diagnostics).map(|c| c.preview)
            {
                comment = Some(pb);
            }
        }

        Opcode54::Newtable => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("B", raw.b as u64));
            operands.push(op_unsigned("C", raw.c as u64));
            let v = if raw.c > 0 { 1 << (raw.c - 1) } else { 0 };
            comment = Some(format!("{v}"));
        }

        Opcode54::SelfOp => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            let c_idx = raw.c as usize;
            let res = resolve_const(proto, c_idx, &inst_id, &source, &mut diagnostics);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("C", raw.c as u64, res));
            comment = prev;
        }

        Opcode54::Addi | Opcode54::Shri | Opcode54::Shli => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_signed("sC", raw.sc as i64));
        }

        Opcode54::Addk
        | Opcode54::Subk
        | Opcode54::Mulk
        | Opcode54::Modk
        | Opcode54::Powk
        | Opcode54::Divk
        | Opcode54::Idivk
        | Opcode54::Bandk
        | Opcode54::Bork
        | Opcode54::Bxork => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            let c_idx = raw.c as usize;
            let res = resolve_const(proto, c_idx, &inst_id, &source, &mut diagnostics);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("C", raw.c as u64, res));
            comment = prev;
        }

        Opcode54::Add
        | Opcode54::Sub
        | Opcode54::Mul
        | Opcode54::Mod
        | Opcode54::Pow
        | Opcode54::Div
        | Opcode54::Idiv
        | Opcode54::Band
        | Opcode54::Bor
        | Opcode54::Bxor
        | Opcode54::Shl
        | Opcode54::Shr => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_reg("C", raw.c));
        }

        Opcode54::Mmbin => {
            role = "companion".to_string();
            if pc > 0 {
                companion_pc = Some(pc - 1);
            }
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_unsigned("C", raw.c as u64));
            let tm = tm_name(raw.c);
            metamethod = Some(tm.to_string());
            comment = Some(tm.to_string());
        }

        Opcode54::Mmbini => {
            role = "companion".to_string();
            if pc > 0 {
                companion_pc = Some(pc - 1);
            }
            operands.push(op_reg("A", raw.a));
            operands.push(op_signed("sB", raw.sb as i64));
            operands.push(op_unsigned("C", raw.c as u64));
            operands.push(op_flag("k", raw.k));
            let tm = tm_name(raw.c);
            metamethod = Some(tm.to_string());
            comment = Some(tm.to_string());
        }

        Opcode54::Mmbink => {
            role = "companion".to_string();
            if pc > 0 {
                companion_pc = Some(pc - 1);
            }
            operands.push(op_reg("A", raw.a));
            let b_idx = raw.b as usize;
            let res = resolve_const(proto, b_idx, &inst_id, &source, &mut diagnostics);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("B", raw.b as u64, res));
            operands.push(op_unsigned("C", raw.c as u64));
            operands.push(op_flag("k", raw.k));
            let tm = tm_name(raw.c);
            metamethod = Some(tm.to_string());
            if let Some(p) = prev {
                comment = Some(format!("{tm} {p}"));
            } else {
                comment = Some(tm.to_string());
            }
        }

        Opcode54::Close | Opcode54::Tbc => {
            operands.push(op_reg("A", raw.a));
        }

        Opcode54::Jmp => {
            operands.push(op_signed("sJ", raw.sj as i64));
            let target = (pc as i32 + 1 + raw.sj) as usize;
            jump_target = Some(target);
            comment = Some(format!("to {}", target + 1));
        }

        Opcode54::Eq | Opcode54::Lt | Opcode54::Le => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_flag("k", raw.k));
        }

        Opcode54::Eqk => {
            operands.push(op_reg("A", raw.a));
            let b_idx = raw.b as usize;
            let res = resolve_const(proto, b_idx, &inst_id, &source, &mut diagnostics);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("B", raw.b as u64, res));
            operands.push(op_flag("k", raw.k));
            comment = prev;
        }

        Opcode54::Eqi | Opcode54::Lti | Opcode54::Lei | Opcode54::Gti | Opcode54::Gei => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_signed("sB", raw.sb as i64));
            operands.push(op_flag("k", raw.k));
        }

        Opcode54::Test => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_flag("k", raw.k));
        }

        Opcode54::Testset => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_flag("k", raw.k));
        }

        Opcode54::Call | Opcode54::Tailcall => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("B", raw.b as u64));
            operands.push(op_unsigned("C", raw.c as u64));
            if raw.b > 0 && raw.c > 0 {
                comment = Some(format!("{} in {} out", raw.b - 1, raw.c - 1));
            }
        }

        Opcode54::Return => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("B", raw.b as u64));
            if raw.k != 0 {
                operands.push(op_unsigned_tagged("C", raw.c as u64, true));
            } else {
                operands.push(op_unsigned("C", raw.c as u64));
            }
            if raw.b > 0 {
                comment = Some(format!("{} out", raw.b - 1));
            }
        }

        Opcode54::Return0 => {}

        Opcode54::Return1 => {
            operands.push(op_reg("A", raw.a));
        }

        Opcode54::Forloop => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("Bx", raw.bx as u64));
            let target = (pc as i32 + 1 - raw.bx as i32) as usize;
            jump_target = Some(target);
            comment = Some(format!("to {}", target + 1));
        }

        Opcode54::Forprep | Opcode54::Tforprep => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("Bx", raw.bx as u64));
            let target = (pc as i32 + 1 + raw.bx as i32 + 1) as usize;
            jump_target = Some(target);
            comment = Some(format!("exit to {}", target + 1));
        }

        Opcode54::Tforcall => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("C", raw.c as u64));
        }

        Opcode54::Tforloop => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("Bx", raw.bx as u64));
            let target = (pc as i32 + 1 - raw.bx as i32) as usize;
            jump_target = Some(target);
            comment = Some(format!("to {}", target + 1));
        }

        Opcode54::Setlist => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_unsigned("B", raw.b as u64));
            if raw.k != 0 {
                operands.push(op_unsigned_tagged("C", raw.c as u64, true));
            } else {
                operands.push(op_unsigned("C", raw.c as u64));
            }
        }

        Opcode54::Closure => {
            operands.push(op_reg("A", raw.a));
            let bx = raw.bx as usize;
            let res_proto = if let Some(child) = proto.protos.get(bx) {
                Some(ResolvedFact::Prototype {
                    index: bx,
                    id: child.id.clone(),
                })
            } else {
                diagnostics.push(Diagnostic {
                    code: "L54-OOB-PROTO".to_string(),
                    category: DiagnosticCategory::Instruction,
                    severity: Severity::Error,
                    target: inst_id.clone(),
                    message: format!(
                        "Prototype index {bx} out of bounds (child proto table length {})",
                        proto.protos.len()
                    ),
                    source: Some(source.clone()),
                    evidence: None,
                    suggested_action: None,
                    help_topic: None,
                });
                None
            };
            operands.push(DisassembledOperand {
                name: "Bx".to_string(),
                kind: OperandKind::ImmediateUnsigned {
                    value: raw.bx as u64,
                },
                display: format!("{}", raw.bx),
                resolved: res_proto,
            });
        }

        Opcode54::Vararg => {
            operands.push(op_reg("A", raw.a));
            if raw.k != 0 {
                operands.push(op_unsigned_tagged("C", raw.c as u64, true));
            } else {
                operands.push(op_unsigned("C", raw.c as u64));
            }
        }

        Opcode54::Varargprep => {
            operands.push(op_reg("A", raw.a));
        }

        Opcode54::Extraarg => {
            role = "extra_argument".to_string();
            if pc > 0 {
                companion_pc = Some(pc - 1);
            }
            operands.push(op_unsigned("Ax", raw.ax as u64));
        }
    }

    DisassembledInstruction {
        id: inst_id,
        pc,
        raw_word,
        raw_hex,
        mnemonic,
        opcode_num,
        role,
        encoded_operands,
        line,
        operands,
        jump_target,
        companion_pc,
        metamethod,
        comment,
        confidence: Confidence::Fact,
        source,
        diagnostics,
    }
}

fn op_reg(name: &str, reg: u8) -> DisassembledOperand {
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::Register { index: reg },
        display: format!("{reg}"),
        resolved: None,
    }
}

fn op_reg_tagged(name: &str, reg: u8, is_k: bool) -> DisassembledOperand {
    let display = if is_k {
        format!("{reg}k")
    } else {
        format!("{reg}")
    };
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::Register { index: reg },
        display,
        resolved: None,
    }
}

fn op_unsigned(name: &str, val: u64) -> DisassembledOperand {
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::ImmediateUnsigned { value: val },
        display: format!("{val}"),
        resolved: None,
    }
}

fn op_unsigned_tagged(name: &str, val: u64, is_k: bool) -> DisassembledOperand {
    let display = if is_k {
        format!("{val}k")
    } else {
        format!("{val}")
    };
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::ImmediateUnsigned { value: val },
        display,
        resolved: None,
    }
}

fn op_signed(name: &str, val: i64) -> DisassembledOperand {
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::ImmediateSigned { value: val },
        display: format!("{val}"),
        resolved: None,
    }
}

fn op_flag(name: &str, val: u8) -> DisassembledOperand {
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::Flag { value: val },
        display: format!("{val}"),
        resolved: None,
    }
}

fn op_upval(name: &str, idx: u8, proto: &Prototype) -> DisassembledOperand {
    let upval_id = match &proto.id {
        StableId::Proto(path) => StableId::Upvalue {
            proto: path.clone(),
            index: idx as usize,
        },
        other => other.clone(),
    };
    let upval_name = proto
        .upvalues
        .get(idx as usize)
        .and_then(|u| u.name.as_ref().map(|s| s.display.clone()));
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::Register { index: idx },
        display: format!("{idx}"),
        resolved: Some(ResolvedFact::Upvalue {
            index: idx,
            id: upval_id,
            name: upval_name,
        }),
    }
}

fn op_const(name: &str, idx: u64, res: Option<ResolvedConstInfo>) -> DisassembledOperand {
    let is_k_tagged = res.as_ref().map(|r| r.is_k).unwrap_or(false);
    let display = if is_k_tagged {
        format!("{idx}k")
    } else {
        format!("{idx}")
    };
    DisassembledOperand {
        name: name.to_string(),
        kind: OperandKind::ImmediateUnsigned { value: idx },
        display,
        resolved: res.map(|r| ResolvedFact::Constant {
            index: idx as usize,
            id: r.id,
            value: r.value,
            formatted_preview: r.preview,
        }),
    }
}

struct ResolvedConstInfo {
    id: StableId,
    value: ConstantValue,
    preview: String,
    is_k: bool,
}

fn resolve_const(
    proto: &Prototype,
    idx: usize,
    inst_id: &StableId,
    source: &SourceLocation,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<ResolvedConstInfo> {
    resolve_const_tagged(proto, idx, false, inst_id, source, diagnostics)
}

fn resolve_const_tagged(
    proto: &Prototype,
    idx: usize,
    is_k: bool,
    inst_id: &StableId,
    source: &SourceLocation,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<ResolvedConstInfo> {
    let Some(c) = proto.constants.get(idx) else {
        diagnostics.push(Diagnostic {
            code: "L54-OOB-CONSTANT".to_string(),
            category: DiagnosticCategory::Instruction,
            severity: Severity::Error,
            target: inst_id.clone(),
            message: format!(
                "Constant index {idx} out of bounds (constant table length {})",
                proto.constants.len()
            ),
            source: Some(source.clone()),
            evidence: None,
            suggested_action: None,
            help_topic: None,
        });
        return None;
    };

    let const_id = match &proto.id {
        StableId::Proto(path) => StableId::Constant {
            proto: path.clone(),
            index: idx,
        },
        other => other.clone(),
    };

    let preview = match &c.value {
        ConstantValue::Nil => "nil".to_string(),
        ConstantValue::Boolean(b) => b.to_string(),
        ConstantValue::Integer { val, .. } => format!("{val}"),
        ConstantValue::Float { val, .. } => format_float(*val),
        ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
            format_string_preview(&s.display)
        }
    };
    Some(ResolvedConstInfo {
        id: const_id,
        value: c.value.clone(),
        preview,
        is_k,
    })
}

fn format_string_preview(s: &str) -> String {
    let max_len = 64;
    if s.len() > max_len {
        let truncated: String = s.chars().take(max_len).collect();
        format!("\"{truncated}...\"")
    } else {
        format!("\"{s}\"")
    }
}

fn format_float(val: f64) -> String {
    if val.is_nan() {
        "nan".to_string()
    } else if val.is_infinite() {
        if val > 0.0 {
            "inf".to_string()
        } else {
            "-inf".to_string()
        }
    } else if val == 0.0 && val.is_sign_negative() {
        "-0.0".to_string()
    } else {
        let s = format!("{val:?}");
        if !s.contains('.') && !s.contains('e') && !s.contains('E') {
            format!("{s}.0")
        } else {
            s
        }
    }
}

fn tm_name(event: u8) -> &'static str {
    match event {
        0 => "__index",
        1 => "__newindex",
        2 => "__gc",
        3 => "__mode",
        4 => "__len",
        5 => "__eq",
        6 => "__add",
        7 => "__sub",
        8 => "__mul",
        9 => "__mod",
        10 => "__pow",
        11 => "__div",
        12 => "__idiv",
        13 => "__band",
        14 => "__bor",
        15 => "__bxor",
        16 => "__shl",
        17 => "__shr",
        18 => "__unm",
        19 => "__bnot",
        20 => "__lt",
        21 => "__le",
        22 => "__concat",
        23 => "__call",
        24 => "__close",
        _ => "__unknown",
    }
}
