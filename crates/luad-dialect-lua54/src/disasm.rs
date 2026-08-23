//! Production disassembly emitter for Lua 5.4 bytecode.

#![forbid(unsafe_code)]

use luad_core::disasm::{
    DisassembledInstruction, DisassembledOperand, DisassembledPrototype, OperandKind, ResolvedFact,
};
use luad_core::model::{ConstantValue, Prototype};
use luad_core::provenance::Confidence;

use crate::opcodes::{Opcode54, RawInstruction54};

/// Produce structured, typed disassembly for a Lua 5.4 prototype and all child prototypes.
#[must_use]
pub fn disassemble_proto_lua54(proto: &Prototype) -> DisassembledPrototype {
    let source_name = proto.source_name.as_ref().map(|s| s.display.clone());
    let mut instructions = Vec::with_capacity(proto.instructions.len());

    for (pc, inst) in proto.instructions.iter().enumerate() {
        instructions.push(disassemble_instruction_lua54(proto, pc, inst.raw_word));
    }

    let mut child_protos = Vec::with_capacity(proto.protos.len());
    for child in &proto.protos {
        child_protos.push(disassemble_proto_lua54(child));
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
    let line = {
        let l = proto.get_line_for_pc(pc);
        if l > 0 {
            Some(l)
        } else {
            None
        }
    };

    let Some(op) = raw.opcode else {
        return DisassembledInstruction {
            pc,
            raw_word,
            raw_hex,
            mnemonic: format!("UNKNOWN_0x{:02x}", raw.opcode_num),
            opcode_num: raw.opcode_num,
            line,
            operands: vec![],
            jump_target: None,
            metamethod: None,
            comment: None,
            confidence: Confidence::Unverified,
        };
    };

    let mnemonic = op.name().to_string();
    let opcode_num = raw.opcode_num;
    let mut operands = Vec::new();
    let mut jump_target = None;
    let mut metamethod = None;
    let mut comment = None;

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
            let res = resolve_const(proto, bx);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("Bx", raw.bx as u64, res));
            comment = prev;
        }

        Opcode54::Loadkx => {
            operands.push(op_reg("A", raw.a));
        }

        Opcode54::Loadfalse | Opcode54::Lfalseskip | Opcode54::Loadtrue => {
            operands.push(op_reg("A", raw.a));
        }

        Opcode54::Gettabup => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_upval("B", raw.b, proto));
            let c_idx = raw.c as usize;
            let res = resolve_const(proto, c_idx);
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
            let res = resolve_const(proto, c_idx);
            let prev = res.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("C", raw.c as u64, res));
            comment = prev;
        }

        Opcode54::Settabup => {
            operands.push(op_upval("A", raw.a, proto));
            let b_idx = raw.b as usize;
            let res_b = resolve_const(proto, b_idx);
            operands.push(op_const("B", raw.b as u64, res_b));
            let (op_c, prev_c) = if raw.k != 0 {
                let c_idx = raw.c as usize;
                let res_c = resolve_const_tagged(proto, c_idx, true);
                let prev = res_c.as_ref().map(|c| format!("{}k", c.preview));
                (op_const("C", raw.c as u64, res_c), prev)
            } else {
                (op_reg("C", raw.c), None)
            };
            operands.push(op_c);
            let prev_b = resolve_const(proto, b_idx).map(|c| c.preview);
            if let (Some(pb), Some(pc)) = (prev_b, prev_c) {
                comment = Some(format!("{pb} {pc}"));
            } else if let Some(pb) = resolve_const(proto, b_idx).map(|c| c.preview) {
                comment = Some(pb);
            }
        }

        Opcode54::Settable => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            if raw.k != 0 {
                let c_idx = raw.c as usize;
                let res_c = resolve_const_tagged(proto, c_idx, true);
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
                let res_c = resolve_const_tagged(proto, c_idx, true);
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
            let res_b = resolve_const(proto, b_idx);
            let prev_b = res_b.as_ref().map(|c| c.preview.clone());
            operands.push(op_const("B", raw.b as u64, res_b));
            let (op_c, prev_c) = if raw.k != 0 {
                let c_idx = raw.c as usize;
                let res_c = resolve_const_tagged(proto, c_idx, true);
                let prev = res_c.as_ref().map(|c| c.preview.clone());
                (op_const("C", raw.c as u64, res_c), prev)
            } else {
                (op_reg("C", raw.c), None)
            };
            operands.push(op_c);
            if let (Some(pb), Some(pc)) = (prev_b, prev_c) {
                comment = Some(format!("{pb} {pc}"));
            } else if let Some(pb) = resolve_const(proto, b_idx).map(|c| c.preview) {
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
            let res = resolve_const(proto, c_idx);
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
            let res = resolve_const(proto, c_idx);
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
            operands.push(op_reg("A", raw.a));
            operands.push(op_reg("B", raw.b));
            operands.push(op_unsigned("C", raw.c as u64));
            let tm = tm_name(raw.c);
            metamethod = Some(tm.to_string());
            comment = Some(tm.to_string());
        }

        Opcode54::Mmbini => {
            operands.push(op_reg("A", raw.a));
            operands.push(op_signed("sB", raw.sb as i64));
            operands.push(op_unsigned("C", raw.c as u64));
            operands.push(op_flag("k", raw.k));
            let tm = tm_name(raw.c);
            metamethod = Some(tm.to_string());
            comment = Some(tm.to_string());
        }

        Opcode54::Mmbink => {
            operands.push(op_reg("A", raw.a));
            let b_idx = raw.b as usize;
            let res = resolve_const(proto, b_idx);
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
            let res = resolve_const(proto, b_idx);
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
            operands.push(op_unsigned("Bx", raw.bx as u64));
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
            operands.push(op_unsigned("Ax", raw.ax as u64));
        }
    }

    DisassembledInstruction {
        pc,
        raw_word,
        raw_hex,
        mnemonic,
        opcode_num,
        line,
        operands,
        jump_target,
        metamethod,
        comment,
        confidence: Confidence::Fact,
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
            value: r.value,
            formatted_preview: r.preview,
        }),
    }
}

struct ResolvedConstInfo {
    value: ConstantValue,
    preview: String,
    is_k: bool,
}

fn resolve_const(proto: &Prototype, idx: usize) -> Option<ResolvedConstInfo> {
    resolve_const_tagged(proto, idx, false)
}

fn resolve_const_tagged(proto: &Prototype, idx: usize, is_k: bool) -> Option<ResolvedConstInfo> {
    let c = proto.constants.get(idx)?;
    let preview = match &c.value {
        ConstantValue::Nil => "nil".to_string(),
        ConstantValue::Boolean(b) => b.to_string(),
        ConstantValue::Integer { val, .. } => format!("{val}"),
        ConstantValue::Float { val, .. } => format_float(*val),
        ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
            format!("\"{}\"", s.display)
        }
    };
    Some(ResolvedConstInfo {
        value: c.value.clone(),
        preview,
        is_k,
    })
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
