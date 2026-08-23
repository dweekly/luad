//! Semantic lifter for Lua 5.2 bytecode.

use luad_core::id::StableId;
use luad_core::ir::{EffectTarget, ImplicitEffect, SemanticInstruction, TypedOperand};
use luad_core::model::{ConstantValue, Prototype};
use luad_core::provenance::Confidence;

use crate::opcodes::{Opcode52, RawInstruction52};

/// Lift an entire prototype's instructions into normalized semantic IR.
#[must_use]
pub fn lift_proto_lua52(proto: &Prototype) -> Vec<SemanticInstruction> {
    let mut lifted = Vec::with_capacity(proto.instructions.len());

    for (pc, inst) in proto.instructions.iter().enumerate() {
        let raw = RawInstruction52::decode(inst.raw_word);
        let next_word = proto
            .instructions
            .get(pc + 1)
            .map(|i| RawInstruction52::decode(i.raw_word));
        let prev_word = if pc > 0 {
            proto
                .instructions
                .get(pc - 1)
                .map(|i| RawInstruction52::decode(i.raw_word))
        } else {
            None
        };

        let semantic = lift_instruction_52(proto, pc, inst, raw, next_word, prev_word);
        lifted.push(semantic);
    }

    lifted
}

fn lift_instruction_52(
    proto: &Prototype,
    pc: usize,
    inst: &luad_core::model::InstructionWord,
    raw: RawInstruction52,
    _next: Option<RawInstruction52>,
    _prev: Option<RawInstruction52>,
) -> SemanticInstruction {
    let id = StableId::instruction(proto.path.clone(), pc);
    let raw_word = inst.raw_word;
    let raw_hex = inst.raw_hex.clone();
    let source = inst.source.clone();

    let Some(op) = raw.opcode else {
        return SemanticInstruction {
            id,
            pc,
            raw_word,
            raw_hex,
            mnemonic: format!("UNKNOWN_0x{:02x}", raw.opcode_num),
            operands: vec![],
            reads: vec![],
            writes: vec![],
            implicit_effects: vec![],
            metamethod_fallbacks: vec![],
            jump_target: None,
            companion_pc: None,
            confidence: Confidence::Unverified,
            source_citations: vec![],

            explanation: format!("Unrecognized opcode index {}", raw.opcode_num),
            source,
        };
    };

    let mut reads = Vec::new();
    let mut writes = Vec::new();
    let mut metamethods = Vec::new();
    let mut implicit_effects = Vec::new();
    let mut operands = Vec::new();
    let mut citations = Vec::new();
    let mut jump_target = None;
    let explanation;

    let get_k_val = |idx: usize| -> ConstantValue {
        proto
            .constants
            .get(idx)
            .map(|c| c.value.clone())
            .unwrap_or(ConstantValue::Nil)
    };

    let parse_rk =
        |is_k: bool, idx: usize, reads: &mut Vec<EffectTarget>, ops: &mut Vec<TypedOperand>| {
            if is_k {
                reads.push(EffectTarget::Constant { index: idx });
                ops.push(TypedOperand::Constant {
                    index: idx,
                    value: get_k_val(idx),
                });
            } else {
                reads.push(EffectTarget::Register { index: idx as u8 });
                ops.push(TypedOperand::Register { index: idx as u8 });
            }
        };

    match op {
        Opcode52::Move => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Copy R({}) := R({})", raw.a, raw.b);
            citations.push("lvm.c:1130".to_string());
        }
        Opcode52::LoadK => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: raw.bx as usize,
                value: get_k_val(raw.bx as usize),
            });
            reads.push(EffectTarget::Constant {
                index: raw.bx as usize,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load constant K[{}] into R({})", raw.bx, raw.a);
            citations.push("lvm.c:1135".to_string());
        }
        Opcode52::LoadKx => {
            operands.push(TypedOperand::Register { index: raw.a });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load extra-arg constant into R({})", raw.a);
            citations.push("lvm.c:1140".to_string());
        }
        Opcode52::LoadBool => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: raw.b != 0 });
            operands.push(TypedOperand::Flag { value: raw.c != 0 });
            writes.push(EffectTarget::Register { index: raw.a });
            let val = raw.b != 0;
            explanation = if raw.c != 0 {
                format!(
                    "Load boolean {} into R({}) and skip next instruction",
                    val, raw.a
                )
            } else {
                format!("Load boolean {} into R({})", val, raw.a)
            };
            citations.push("lvm.c:1145".to_string());
        }
        Opcode52::LoadNil => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: false,
            });
            writes.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: raw.a + raw.b as u8,
            });
            explanation = format!("Set nil into R({}..{})", raw.a, raw.a + raw.b as u8);
            citations.push("lvm.c:1150".to_string());
        }
        Opcode52::GetUpval => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b as u8,
                name: proto
                    .upvalues
                    .get(raw.b as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            reads.push(EffectTarget::Upvalue {
                index: raw.b as u8,
                name: proto
                    .upvalues
                    .get(raw.b as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load Upvalue[{}] into R({})", raw.b, raw.a);
            citations.push("lvm.c:1155".to_string());
        }
        Opcode52::GetTabUp => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b as u8,
                name: proto
                    .upvalues
                    .get(raw.b as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            reads.push(EffectTarget::Upvalue {
                index: raw.b as u8,
                name: proto
                    .upvalues
                    .get(raw.b as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            writes.push(EffectTarget::Register { index: raw.a });
            metamethods.push("__index".to_string());
            explanation = format!("Load table field Upvalue[{}][C] into R({})", raw.b, raw.a);
            citations.push("lvm.c:1160".to_string());
        }
        Opcode52::GetTable => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            writes.push(EffectTarget::Register { index: raw.a });
            metamethods.push("__index".to_string());
            explanation = format!("Load table field R({})[C] into R({})", raw.b, raw.a);
            citations.push("lvm.c:1170".to_string());
        }
        Opcode52::SetTabUp => {
            operands.push(TypedOperand::Upvalue {
                index: raw.a,
                name: proto
                    .upvalues
                    .get(raw.a as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            reads.push(EffectTarget::Upvalue {
                index: raw.a,
                name: proto
                    .upvalues
                    .get(raw.a as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            parse_rk(raw.is_b_k(), raw.b_index_k(), &mut reads, &mut operands);
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            metamethods.push("__newindex".to_string());
            explanation = format!("Store into Upvalue[{}][B] := C", raw.a);
            citations.push("lvm.c:1180".to_string());
        }
        Opcode52::SetUpval => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b as u8,
                name: proto
                    .upvalues
                    .get(raw.b as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            reads.push(EffectTarget::Register { index: raw.a });
            writes.push(EffectTarget::Upvalue {
                index: raw.b as u8,
                name: proto
                    .upvalues
                    .get(raw.b as usize)
                    .and_then(|u| u.name.as_ref().map(|s| s.display.clone())),
            });
            explanation = format!("Store R({}) into Upvalue[{}]", raw.a, raw.b);
            citations.push("lvm.c:1190".to_string());
        }
        Opcode52::SetTable => {
            operands.push(TypedOperand::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.a });
            parse_rk(raw.is_b_k(), raw.b_index_k(), &mut reads, &mut operands);
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            metamethods.push("__newindex".to_string());
            explanation = format!("Store into table R({})[B] := C", raw.a);
            citations.push("lvm.c:1200".to_string());
        }
        Opcode52::NewTable => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: false,
            });
            operands.push(TypedOperand::Count {
                value: raw.c as usize,
                is_variable: false,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Create new table in R({})", raw.a);
            citations.push("lvm.c:1210".to_string());
        }
        Opcode52::SelfOp => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            writes.push(EffectTarget::Register { index: raw.a + 1 });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethods.push("__index".to_string());
            explanation = format!(
                "Method lookup: R({}+1) := R({}), R({}) := R({})[C]",
                raw.a, raw.b, raw.a, raw.b
            );
            citations.push("lvm.c:1220".to_string());
        }
        Opcode52::Add
        | Opcode52::Sub
        | Opcode52::Mul
        | Opcode52::Div
        | Opcode52::Mod
        | Opcode52::Pow => {
            operands.push(TypedOperand::Register { index: raw.a });
            parse_rk(raw.is_b_k(), raw.b_index_k(), &mut reads, &mut operands);
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            writes.push(EffectTarget::Register { index: raw.a });
            let mm = match op {
                Opcode52::Add => "__add",
                Opcode52::Sub => "__sub",
                Opcode52::Mul => "__mul",
                Opcode52::Div => "__div",
                Opcode52::Mod => "__mod",
                Opcode52::Pow => "__pow",
                _ => "__add",
            };
            metamethods.push(mm.to_string());
            explanation = format!("Binary op {}: R({}) := B op C", op.name(), raw.a);
            citations.push("lvm.c:1230".to_string());
        }
        Opcode52::Unm | Opcode52::Not | Opcode52::Len => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Unary op {}: R({}) := op R({})", op.name(), raw.a, raw.b);
            citations.push("lvm.c:1260".to_string());
        }
        Opcode52::Concat => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            operands.push(TypedOperand::Register { index: raw.c as u8 });
            reads.push(EffectTarget::RegisterRange {
                start: raw.b as u8,
                end: raw.c as u8,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethods.push("__concat".to_string());
            explanation = format!("Concatenate R({}..{}) into R({})", raw.b, raw.c, raw.a);
            citations.push("lvm.c:1270".to_string());
        }
        Opcode52::Jmp => {
            let target = (pc as i32 + 1 + raw.sbx) as usize;
            operands.push(TypedOperand::Jump {
                offset: raw.sbx,
                target_pc: target,
                target_id: StableId::instruction(proto.path.clone(), target),
            });
            jump_target = Some(target);
            if raw.a != 0 {
                implicit_effects.push(ImplicitEffect::CloseUpvalues {
                    min_register: raw.a - 1,
                });
            }
            explanation = format!("Jump to PC {target}");
            citations.push("lvm.c:1280".to_string());
        }
        Opcode52::Eq | Opcode52::Lt | Opcode52::Le => {
            operands.push(TypedOperand::Flag { value: raw.a != 0 });
            parse_rk(raw.is_b_k(), raw.b_index_k(), &mut reads, &mut operands);
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            let skip_pc = pc + 2;
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            explanation = format!(
                "Comparison {}: if (B op C) != {} skip next instruction",
                op.name(),
                raw.a
            );
            citations.push("lvm.c:1290".to_string());
        }
        Opcode52::Test => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: raw.c != 0 });
            reads.push(EffectTarget::Register { index: raw.a });
            let skip_pc = pc + 2;
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            explanation = format!("Test boolean R({}) <=> {}", raw.a, raw.c);
            citations.push("lvm.c:1300".to_string());
        }
        Opcode52::TestSet => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            operands.push(TypedOperand::Flag { value: raw.c != 0 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            writes.push(EffectTarget::Register { index: raw.a });
            let skip_pc = pc + 2;
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            explanation = format!("Test R({}) <=> {} and copy to R({})", raw.b, raw.c, raw.a);
            citations.push("lvm.c:1310".to_string());
        }
        Opcode52::Call => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: raw.b == 0,
            });
            operands.push(TypedOperand::Count {
                value: raw.c as usize,
                is_variable: raw.c == 0,
            });
            reads.push(EffectTarget::Register { index: raw.a });
            if raw.b > 1 {
                reads.push(EffectTarget::RegisterRange {
                    start: raw.a + 1,
                    end: raw.a + raw.b as u8 - 1,
                });
            }
            if raw.c > 1 {
                writes.push(EffectTarget::RegisterRange {
                    start: raw.a,
                    end: raw.a + raw.c as u8 - 2,
                });
            }
            metamethods.push("__call".to_string());
            explanation = format!("Call function in R({})", raw.a);
            citations.push("lvm.c:1320".to_string());
        }
        Opcode52::TailCall => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: raw.b == 0,
            });
            reads.push(EffectTarget::Register { index: raw.a });
            if raw.b > 1 {
                reads.push(EffectTarget::RegisterRange {
                    start: raw.a + 1,
                    end: raw.a + raw.b as u8 - 1,
                });
            }
            metamethods.push("__call".to_string());
            explanation = format!("Tail call function in R({})", raw.a);
            citations.push("lvm.c:1330".to_string());
        }
        Opcode52::Return => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: raw.b == 0,
            });
            if raw.b > 1 {
                reads.push(EffectTarget::RegisterRange {
                    start: raw.a,
                    end: raw.a + raw.b as u8 - 2,
                });
            }
            explanation = format!("Return values starting from R({})", raw.a);
            citations.push("lvm.c:1340".to_string());
        }
        Opcode52::ForLoop => {
            let target = (pc as i32 + 1 + raw.sbx) as usize;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Jump {
                offset: raw.sbx,
                target_pc: target,
                target_id: StableId::instruction(proto.path.clone(), target),
            });
            jump_target = Some(target);
            reads.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: raw.a + 2,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            writes.push(EffectTarget::Register { index: raw.a + 3 });
            explanation = format!("Numeric for-loop step; if not limit, jump to PC {target}");
            citations.push("lvm.c:1350".to_string());
        }
        Opcode52::ForPrep => {
            let target = (pc as i32 + 1 + raw.sbx) as usize;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Jump {
                offset: raw.sbx,
                target_pc: target,
                target_id: StableId::instruction(proto.path.clone(), target),
            });
            jump_target = Some(target);
            reads.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: raw.a + 2,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Prepare numeric for-loop and jump to PC {target}");
            citations.push("lvm.c:1360".to_string());
        }
        Opcode52::TForCall => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.c as usize,
                is_variable: false,
            });
            reads.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: raw.a + 2,
            });
            writes.push(EffectTarget::RegisterRange {
                start: raw.a + 3,
                end: raw.a + 2 + raw.c as u8,
            });
            explanation = format!("Generic for-loop call iterator in R({})", raw.a);
            citations.push("lvm.c:1370".to_string());
        }
        Opcode52::TForLoop => {
            let target = (pc as i32 + 1 + raw.sbx) as usize;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Jump {
                offset: raw.sbx,
                target_pc: target,
                target_id: StableId::instruction(proto.path.clone(), target),
            });
            jump_target = Some(target);
            reads.push(EffectTarget::Register { index: raw.a + 1 });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "Generic for-loop step; if R({}+1) != nil jump to PC {target}",
                raw.a
            );
            citations.push("lvm.c:1380".to_string());
        }
        Opcode52::SetList => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: raw.b == 0,
            });
            operands.push(TypedOperand::Count {
                value: raw.c as usize,
                is_variable: false,
            });
            reads.push(EffectTarget::RegisterRange {
                start: raw.a + 1,
                end: raw.a + (if raw.b == 0 { 1 } else { raw.b as u8 }),
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Set list elements into table R({})", raw.a);
            citations.push("lvm.c:1390".to_string());
        }
        Opcode52::Closure => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Prototype {
                index: raw.bx as usize,
                path: proto.path.child(raw.bx as usize),
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Instantiate closure proto:{} into R({})", raw.bx, raw.a);
            citations.push("lvm.c:1400".to_string());
        }
        Opcode52::VarArg => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: raw.b == 0,
            });
            if raw.b > 1 {
                writes.push(EffectTarget::RegisterRange {
                    start: raw.a,
                    end: raw.a + raw.b as u8 - 2,
                });
            }
            explanation = format!("Load vararg into R({})", raw.a);
            citations.push("lvm.c:1410".to_string());
        }
        Opcode52::ExtraArg => {
            operands.push(TypedOperand::ExtraArg { value: raw.ax });
            explanation = format!("Extra argument: {}", raw.ax);
            citations.push("lvm.c:1420".to_string());
        }
    }

    SemanticInstruction {
        id,
        pc,
        raw_word,
        raw_hex,
        mnemonic: op.name().to_string(),
        explanation,
        operands,
        reads,
        writes,
        metamethod_fallbacks: metamethods,
        implicit_effects,
        jump_target,
        companion_pc: None,
        source_citations: citations,
        confidence: Confidence::Reviewed,
        source,
    }
}
