//! Semantic lifter for Lua 5.1 bytecode.

use luad_core::id::StableId;
use luad_core::ir::{EffectTarget, ImplicitEffect, SemanticInstruction, TypedOperand};
use luad_core::model::{ConstantValue, Prototype};
use luad_core::provenance::Confidence;

use crate::opcodes::{Opcode51, RawInstruction51};

use std::collections::BTreeMap;

/// Lift an entire prototype's instructions into normalized semantic IR.
#[must_use]
pub fn lift_proto_lua51(proto: &Prototype) -> Vec<SemanticInstruction> {
    let mut lifted = Vec::with_capacity(proto.instructions.len());

    // 1. Identify all closure binding descriptor PCs
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
        let raw = RawInstruction51::decode(inst.raw_word);
        let next_word = proto
            .instructions
            .get(pc + 1)
            .map(|i| RawInstruction51::decode(i.raw_word));
        let prev_word = if pc > 0 {
            proto
                .instructions
                .get(pc - 1)
                .map(|i| RawInstruction51::decode(i.raw_word))
        } else {
            None
        };

        let binding_info = binding_descriptors.get(&pc).copied();
        let semantic =
            lift_instruction_51(proto, pc, inst, raw, next_word, prev_word, binding_info);
        lifted.push(semantic);
    }

    lifted
}

fn lift_instruction_51(
    proto: &Prototype,
    pc: usize,
    inst: &luad_core::model::InstructionWord,
    raw: RawInstruction51,
    _next: Option<RawInstruction51>,
    _prev: Option<RawInstruction51>,
    binding_info: Option<(usize, usize)>,
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
        Opcode51::Move => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Copy R({}) := R({})", raw.a, raw.b);
            citations.push("lua-5.1.5:src/lvm.c:1130".to_string());
        }
        Opcode51::LoadK => {
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
            citations.push("lua-5.1.5:src/lvm.c:1135".to_string());
        }
        Opcode51::LoadBool => {
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
            citations.push("lua-5.1.5:src/lvm.c:1145".to_string());
        }
        Opcode51::LoadNil => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: false,
            });
            writes.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: raw.b as u8,
            });
            explanation = format!("Set nil into R({}..{})", raw.a, raw.b as u8);
            citations.push("lua-5.1.5:src/lvm.c:1150".to_string());
        }
        Opcode51::GetUpval => {
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
            citations.push("lua-5.1.5:src/lvm.c:1155".to_string());
        }
        Opcode51::GetGlobal => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: raw.bx as usize,
                value: get_k_val(raw.bx as usize),
            });
            reads.push(EffectTarget::Constant {
                index: raw.bx as usize,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethods.push("__index".to_string());
            explanation = format!("Get global K[{}] into R({})", raw.bx, raw.a);
            citations.push("lua-5.1.5:src/lvm.c:1160".to_string());
        }
        Opcode51::GetTable => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            writes.push(EffectTarget::Register { index: raw.a });
            metamethods.push("__index".to_string());
            explanation = format!("Load table field R({})[C] into R({})", raw.b, raw.a);
            citations.push("lua-5.1.5:src/lvm.c:1170".to_string());
        }
        Opcode51::SetGlobal => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: raw.bx as usize,
                value: get_k_val(raw.bx as usize),
            });
            reads.push(EffectTarget::Register { index: raw.a });
            reads.push(EffectTarget::Constant {
                index: raw.bx as usize,
            });
            metamethods.push("__newindex".to_string());
            explanation = format!("Set global K[{}] := R({})", raw.bx, raw.a);
            citations.push("lua-5.1.5:src/lvm.c:1180".to_string());
        }
        Opcode51::SetUpval => {
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
            citations.push("lua-5.1.5:src/lvm.c:1190".to_string());
        }
        Opcode51::SetTable => {
            operands.push(TypedOperand::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.a });
            parse_rk(raw.is_b_k(), raw.b_index_k(), &mut reads, &mut operands);
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            metamethods.push("__newindex".to_string());
            explanation = format!("Store into table R({})[B] := C", raw.a);
            citations.push("lua-5.1.5:src/lvm.c:1200".to_string());
        }
        Opcode51::NewTable => {
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
            citations.push("lua-5.1.5:src/lvm.c:1210".to_string());
        }
        Opcode51::SelfOp => {
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
            citations.push("lua-5.1.5:src/lvm.c:1220".to_string());
        }
        Opcode51::Add
        | Opcode51::Sub
        | Opcode51::Mul
        | Opcode51::Div
        | Opcode51::Mod
        | Opcode51::Pow => {
            operands.push(TypedOperand::Register { index: raw.a });
            parse_rk(raw.is_b_k(), raw.b_index_k(), &mut reads, &mut operands);
            parse_rk(raw.is_c_k(), raw.c_index_k(), &mut reads, &mut operands);
            writes.push(EffectTarget::Register { index: raw.a });
            let mm = match op {
                Opcode51::Add => "__add",
                Opcode51::Sub => "__sub",
                Opcode51::Mul => "__mul",
                Opcode51::Div => "__div",
                Opcode51::Mod => "__mod",
                Opcode51::Pow => "__pow",
                _ => "__add",
            };
            metamethods.push(mm.to_string());
            explanation = format!("Binary op {}: R({}) := B op C", op.name(), raw.a);
            citations.push("lua-5.1.5:src/lvm.c:1230".to_string());
        }
        Opcode51::Unm | Opcode51::Not | Opcode51::Len => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b as u8 });
            reads.push(EffectTarget::Register { index: raw.b as u8 });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Unary op {}: R({}) := op R({})", op.name(), raw.a, raw.b);
            citations.push("lua-5.1.5:src/lvm.c:1260".to_string());
        }
        Opcode51::Concat => {
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
            citations.push("lua-5.1.5:src/lvm.c:1270".to_string());
        }
        Opcode51::Jmp => {
            let target = (pc as i32 + 1 + raw.sbx) as usize;
            operands.push(TypedOperand::Jump {
                offset: raw.sbx,
                target_pc: target,
                target_id: StableId::instruction(proto.path.clone(), target),
            });
            jump_target = Some(target);
            explanation = format!("Jump to PC {target}");
            citations.push("lua-5.1.5:src/lvm.c:1280".to_string());
        }
        Opcode51::Eq | Opcode51::Lt | Opcode51::Le => {
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
            citations.push("lua-5.1.5:src/lvm.c:1290".to_string());
        }
        Opcode51::Test => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: raw.c != 0 });
            reads.push(EffectTarget::Register { index: raw.a });
            let skip_pc = pc + 2;
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            explanation = format!("Test boolean R({}) <=> {}", raw.a, raw.c);
            citations.push("lua-5.1.5:src/lvm.c:1300".to_string());
        }
        Opcode51::TestSet => {
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
            citations.push("lua-5.1.5:src/lvm.c:1310".to_string());
        }
        Opcode51::Call => {
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
            citations.push("lua-5.1.5:src/lvm.c:1320".to_string());
        }
        Opcode51::TailCall => {
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
            citations.push("lua-5.1.5:src/lvm.c:1330".to_string());
        }
        Opcode51::Return => {
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
            citations.push("lua-5.1.5:src/lvm.c:1340".to_string());
        }
        Opcode51::ForLoop => {
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
            citations.push("lua-5.1.5:src/lvm.c:1350".to_string());
        }
        Opcode51::ForPrep => {
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
            citations.push("lua-5.1.5:src/lvm.c:1360".to_string());
        }
        Opcode51::TForLoop => {
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
            citations.push("lua-5.1.5:src/lvm.c:1370".to_string());
        }
        Opcode51::SetList => {
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
            citations.push("lua-5.1.5:src/lvm.c:1390".to_string());
        }
        Opcode51::Close => {
            operands.push(TypedOperand::Register { index: raw.a });
            implicit_effects.push(ImplicitEffect::CloseUpvalues {
                min_register: raw.a,
            });
            explanation = format!("Close upvalues up to R({})", raw.a);
            citations.push("lua-5.1.5:src/lvm.c:1395".to_string());
        }
        Opcode51::Closure => {
            let child_bx = raw.bx as usize;
            let nups = proto
                .protos
                .get(child_bx)
                .map(|p| p.upvalues.len())
                .unwrap_or(0);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Prototype {
                index: child_bx,
                path: proto.path.child(child_bx),
            });
            writes.push(EffectTarget::Register { index: raw.a });

            // Capture facts from following binding descriptor instructions
            for j in 0..nups {
                let desc_pc = pc + 1 + j;
                if let Some(desc_inst) = proto.instructions.get(desc_pc) {
                    let desc_raw = RawInstruction51::decode(desc_inst.raw_word);
                    if desc_raw.opcode == Some(Opcode51::Move) {
                        reads.push(EffectTarget::Register {
                            index: desc_raw.b as u8,
                        });
                        implicit_effects.push(ImplicitEffect::CaptureUpvalue {
                            register: desc_raw.b as u8,
                        });
                    } else if desc_raw.opcode == Some(Opcode51::GetUpval) {
                        reads.push(EffectTarget::Upvalue {
                            index: desc_raw.b as u8,
                            name: None,
                        });
                    }
                }
            }

            explanation = format!(
                "Instantiate closure proto:{child_bx} into R({}) with {nups} upvalue capture(s)",
                raw.a
            );
            citations.push("lua-5.1.5:src/lvm.c:1400".to_string());
        }
        Opcode51::VarArg => {
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
            citations.push("lua-5.1.5:src/lvm.c:1410".to_string());
        }
    }

    if let Some((closure_pc, upval_idx)) = binding_info {
        let is_move = op == Opcode51::Move;
        let capture_kind = if is_move { "local register" } else { "upvalue" };
        let mut desc_reads = Vec::new();
        if is_move {
            desc_reads.push(EffectTarget::Register { index: raw.b as u8 });
        } else {
            desc_reads.push(EffectTarget::Upvalue {
                index: raw.b as u8,
                name: None,
            });
        }

        return SemanticInstruction {
            id,
            pc,
            raw_word,
            raw_hex,
            mnemonic: format!("{} (binding descriptor)", op.name()),
            explanation: format!(
                "Closure-binding descriptor for closure at PC {closure_pc}: captures {capture_kind} {} into child upvalue {upval_idx}",
                raw.b
            ),
            operands: vec![
                TypedOperand::Register { index: raw.b as u8 },
                TypedOperand::Count {
                    value: upval_idx,
                    is_variable: false,
                },
            ],

            reads: desc_reads,
            writes: vec![], // CRITICAL: Binding descriptors do not execute or write registers!
            metamethod_fallbacks: vec![],
            implicit_effects: vec![ImplicitEffect::CompanionPair {
                companion_pc: closure_pc,
                companion_role: "closure_binding".to_string(),
            }],
            jump_target: None,
            companion_pc: Some(closure_pc),
            confidence: Confidence::Reviewed,
            source_citations: vec!["lua-5.1.5:src/lvm.c:1402".to_string()],
            source,
        };
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
