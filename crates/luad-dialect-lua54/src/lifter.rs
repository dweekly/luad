//! Semantic instruction lifting for Lua 5.4 bytecode operations.

use luad_core::id::StableId;
use luad_core::ir::{EffectTarget, ImplicitEffect, SemanticInstruction, TypedOperand};
use luad_core::model::{ConstantValue, Prototype};
use luad_core::provenance::Confidence;

use crate::opcodes::{Opcode54, RawInstruction54};

/// Lift all physical instructions of a Lua 5.4 prototype into normalized semantic IR.
pub fn lift_proto_lua54(proto: &Prototype) -> Vec<SemanticInstruction> {
    let mut lifted = Vec::with_capacity(proto.instructions.len());

    for (pc, inst) in proto.instructions.iter().enumerate() {
        let raw = RawInstruction54::decode(inst.raw_word);
        let next_word = proto
            .instructions
            .get(pc + 1)
            .map(|i| RawInstruction54::decode(i.raw_word));
        let prev_word = if pc > 0 {
            proto
                .instructions
                .get(pc - 1)
                .map(|i| RawInstruction54::decode(i.raw_word))
        } else {
            None
        };

        let semantic = lift_instruction_54(proto, pc, inst, raw, next_word, prev_word);
        lifted.push(semantic);
    }

    lifted
}

fn lift_instruction_54(
    proto: &Prototype,
    pc: usize,
    inst: &luad_core::model::InstructionWord,
    raw: RawInstruction54,
    next: Option<RawInstruction54>,
    prev: Option<RawInstruction54>,
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

    let mnemonic = op.name().to_string();
    let mut operands = Vec::new();
    let mut reads = Vec::new();
    let mut writes = Vec::new();
    let mut implicit_effects = Vec::new();
    let mut metamethod_fallbacks = Vec::new();
    let mut jump_target = None;
    let mut companion_pc = None;
    let mut citations = Vec::new();
    let explanation;

    // Helper closures
    let get_const_val = |idx: usize| -> ConstantValue {
        proto
            .constants
            .get(idx)
            .map(|c| c.value.clone())
            .unwrap_or(ConstantValue::Nil)
    };

    let get_upval_name = |idx: u8| -> Option<String> {
        proto
            .upvalues
            .get(idx as usize)
            .and_then(|u| u.name.as_ref().map(|n| n.display.clone()))
    };

    match op {
        Opcode54::Move => {
            citations.push("lvm.c:1120".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Copy value from R({}) into R({})", raw.b, raw.a);
        }
        Opcode54::Loadi => {
            citations.push("lvm.c:1123".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.sbx as i64,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load integer constant {} into R({})", raw.sbx, raw.a);
        }
        Opcode54::Loadf => {
            citations.push("lvm.c:1126".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateFloat {
                value: raw.sbx as f64,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load float constant {}.0 into R({})", raw.sbx, raw.a);
        }
        Opcode54::Loadk => {
            citations.push("lvm.c:1129".to_string());
            let k_idx = raw.bx as usize;
            let k_val = get_const_val(k_idx);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: k_idx,
                value: k_val.clone(),
            });
            reads.push(EffectTarget::Constant { index: k_idx });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load constant K[{k_idx}] ({k_val:?}) into R({})", raw.a);
        }
        Opcode54::Loadkx => {
            citations.push("lvm.c:1132".to_string());
            let extra_ax = next
                .filter(|n| n.opcode == Some(Opcode54::Extraarg))
                .map(|n| n.ax as usize)
                .unwrap_or(0);
            let k_val = get_const_val(extra_ax);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: extra_ax,
                value: k_val.clone(),
            });
            reads.push(EffectTarget::Constant { index: extra_ax });
            writes.push(EffectTarget::Register { index: raw.a });
            companion_pc = Some(pc + 1);
            implicit_effects.push(ImplicitEffect::CompanionPair {
                companion_pc: pc + 1,
                companion_role: "EXTRAARG (Ax constant index)".to_string(),
            });
            explanation = format!("Load extended constant K[{extra_ax}] into R({})", raw.a);
        }
        Opcode54::Loadfalse => {
            citations.push("lvm.c:1136".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: false });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Set R({}) to false", raw.a);
        }
        Opcode54::Lfalseskip => {
            citations.push("lvm.c:1139".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: false });
            writes.push(EffectTarget::Register { index: raw.a });
            let skip_pc = pc + 2;
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            explanation = format!(
                "Set R({}) to false and skip next instruction (jump to PC {skip_pc})",
                raw.a
            );
        }
        Opcode54::Loadtrue => {
            citations.push("lvm.c:1143".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: true });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Set R({}) to true", raw.a);
        }
        Opcode54::Loadnil => {
            citations.push("lvm.c:1146".to_string());
            let end_reg = raw.a + raw.b;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: (raw.b + 1) as usize,
                is_variable: false,
            });
            writes.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: end_reg,
            });
            explanation = format!("Set registers R({})..=R({end_reg}) to nil", raw.a);
        }
        Opcode54::Getupval => {
            citations.push("lvm.c:1152".to_string());
            let up_name = get_upval_name(raw.b);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            reads.push(EffectTarget::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "Read upvalue [{}] ({}) into R({})",
                raw.b,
                up_name.as_deref().unwrap_or("-"),
                raw.a
            );
        }
        Opcode54::Setupval => {
            citations.push("lvm.c:1155".to_string());
            let up_name = get_upval_name(raw.b);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            reads.push(EffectTarget::Register { index: raw.a });
            writes.push(EffectTarget::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            explanation = format!(
                "Write R({}) into upvalue [{}] ({})",
                raw.a,
                raw.b,
                up_name.as_deref().unwrap_or("-")
            );
        }
        Opcode54::Gettabup => {
            citations.push("lvm.c:1158".to_string());
            let up_name = get_upval_name(raw.b);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            let key_str = if raw.k != 0 {
                let k_val = get_const_val(raw.c as usize);
                operands.push(TypedOperand::Constant {
                    index: raw.c as usize,
                    value: k_val,
                });
                reads.push(EffectTarget::Constant {
                    index: raw.c as usize,
                });
                format!("K[{}]", raw.c)
            } else {
                operands.push(TypedOperand::Register { index: raw.c });
                reads.push(EffectTarget::Register { index: raw.c });
                format!("R({})", raw.c)
            };
            reads.push(EffectTarget::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__index".to_string());
            explanation = format!(
                "R({}) := UpValue[{}][{key_str}] (fallback __index)",
                raw.a, raw.b
            );
        }
        Opcode54::Gettable => {
            citations.push("lvm.c:1164".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::Register { index: raw.c });
            reads.push(EffectTarget::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.c });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__index".to_string());
            explanation = format!(
                "R({}) := R({})[R({})] (fallback __index)",
                raw.a, raw.b, raw.c
            );
        }
        Opcode54::Geti => {
            citations.push("lvm.c:1168".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.c as i64,
            });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__index".to_string());
            explanation = format!("R({}) := R({})[{}] (fallback __index)", raw.a, raw.b, raw.c);
        }
        Opcode54::Getfield => {
            citations.push("lvm.c:1172".to_string());
            let k_val = get_const_val(raw.c as usize);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::Constant {
                index: raw.c as usize,
                value: k_val,
            });
            reads.push(EffectTarget::Register { index: raw.b });
            reads.push(EffectTarget::Constant {
                index: raw.c as usize,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__index".to_string());
            explanation = format!(
                "R({}) := R({})[K[{}]] (fallback __index)",
                raw.a, raw.b, raw.c
            );
        }
        Opcode54::Settabup => {
            citations.push("lvm.c:1176".to_string());
            let up_name = get_upval_name(raw.a);
            operands.push(TypedOperand::Upvalue {
                index: raw.a,
                name: up_name.clone(),
            });
            let key_str = if raw.k != 0 {
                let k_val = get_const_val(raw.b as usize);
                operands.push(TypedOperand::Constant {
                    index: raw.b as usize,
                    value: k_val,
                });
                reads.push(EffectTarget::Constant {
                    index: raw.b as usize,
                });
                format!("K[{}]", raw.b)
            } else {
                operands.push(TypedOperand::Register { index: raw.b });
                reads.push(EffectTarget::Register { index: raw.b });
                format!("R({})", raw.b)
            };
            let val_str = format!("R({})", raw.c);
            operands.push(TypedOperand::Register { index: raw.c });
            reads.push(EffectTarget::Register { index: raw.c });
            writes.push(EffectTarget::Upvalue {
                index: raw.a,
                name: up_name,
            });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!(
                "UpValue[{}][{key_str}] := {val_str} (fallback __newindex)",
                raw.a
            );
        }
        Opcode54::Settable => {
            citations.push("lvm.c:1182".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            let val_str = if raw.k != 0 {
                let k_val = get_const_val(raw.c as usize);
                operands.push(TypedOperand::Constant {
                    index: raw.c as usize,
                    value: k_val,
                });
                reads.push(EffectTarget::Constant {
                    index: raw.c as usize,
                });
                format!("K[{}]", raw.c)
            } else {
                operands.push(TypedOperand::Register { index: raw.c });
                reads.push(EffectTarget::Register { index: raw.c });
                format!("R({})", raw.c)
            };
            reads.push(EffectTarget::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.b });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!(
                "R({})[R({})] := {val_str} (fallback __newindex)",
                raw.a, raw.b
            );
        }
        Opcode54::Seti => {
            citations.push("lvm.c:1186".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.b as i64,
            });
            let val_str = if raw.k != 0 {
                let k_val = get_const_val(raw.c as usize);
                operands.push(TypedOperand::Constant {
                    index: raw.c as usize,
                    value: k_val,
                });
                reads.push(EffectTarget::Constant {
                    index: raw.c as usize,
                });
                format!("K[{}]", raw.c)
            } else {
                operands.push(TypedOperand::Register { index: raw.c });
                reads.push(EffectTarget::Register { index: raw.c });
                format!("R({})", raw.c)
            };
            reads.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!("R({})[{}] := {val_str} (fallback __newindex)", raw.a, raw.b);
        }
        Opcode54::Setfield => {
            citations.push("lvm.c:1190".to_string());
            let k_key = get_const_val(raw.b as usize);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: raw.b as usize,
                value: k_key,
            });
            let val_str = if raw.k != 0 {
                let k_val = get_const_val(raw.c as usize);
                operands.push(TypedOperand::Constant {
                    index: raw.c as usize,
                    value: k_val,
                });
                reads.push(EffectTarget::Constant {
                    index: raw.c as usize,
                });
                format!("K[{}]", raw.c)
            } else {
                operands.push(TypedOperand::Register { index: raw.c });
                reads.push(EffectTarget::Register { index: raw.c });
                format!("R({})", raw.c)
            };
            reads.push(EffectTarget::Register { index: raw.a });
            reads.push(EffectTarget::Constant {
                index: raw.b as usize,
            });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!(
                "R({})[K[{}]] := {val_str} (fallback __newindex)",
                raw.a, raw.b
            );
        }
        Opcode54::Newtable => {
            citations.push("lvm.c:1194".to_string());
            let array_size = raw.b;
            let hash_size = raw.c;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: array_size as usize,
                is_variable: false,
            });
            operands.push(TypedOperand::Count {
                value: hash_size as usize,
                is_variable: false,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "Allocate new table in R({}) (array hint: {}, hash hint: {})",
                raw.a, array_size, hash_size
            );
        }
        Opcode54::SelfOp => {
            citations.push("lvm.c:1205".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            let key_str = if raw.k != 0 {
                let k_val = get_const_val(raw.c as usize);
                operands.push(TypedOperand::Constant {
                    index: raw.c as usize,
                    value: k_val,
                });
                reads.push(EffectTarget::Constant {
                    index: raw.c as usize,
                });
                format!("K[{}]", raw.c)
            } else {
                operands.push(TypedOperand::Register { index: raw.c });
                reads.push(EffectTarget::Register { index: raw.c });
                format!("R({})", raw.c)
            };
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            writes.push(EffectTarget::Register { index: raw.a + 1 });
            metamethod_fallbacks.push("__index".to_string());
            explanation = format!(
                "R({}) := R({})[{}]; R({}) := R({}) (method lookup)",
                raw.a,
                raw.b,
                key_str,
                raw.a + 1,
                raw.b
            );
        }
        Opcode54::Addi | Opcode54::Shri | Opcode54::Shli => {
            citations.push("lvm.c:1218".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.sc as i64,
            });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            let op_sym = if op == Opcode54::Addi {
                "+"
            } else if op == Opcode54::Shri {
                ">>"
            } else {
                "<<"
            };
            explanation = format!("R({}) := R({}) {op_sym} {}", raw.a, raw.b, raw.sc);
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
            citations.push("lvm.c:1225".to_string());
            let k_val = get_const_val(raw.c as usize);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::Constant {
                index: raw.c as usize,
                value: k_val,
            });
            reads.push(EffectTarget::Register { index: raw.b });
            reads.push(EffectTarget::Constant {
                index: raw.c as usize,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := R({}) {} K[{}]", raw.a, raw.b, op.name(), raw.c);
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
            citations.push("lvm.c:1240".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::Register { index: raw.c });
            reads.push(EffectTarget::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.c });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := R({}) {} R({})", raw.a, raw.b, op.name(), raw.c);
        }
        Opcode54::Mmbin | Opcode54::Mmbini | Opcode54::Mmbink => {
            citations.push("lvm.c:1255".to_string());
            companion_pc = prev.map(|_| pc - 1);
            let tm = tm_name(raw.c);
            metamethod_fallbacks.push(tm.to_string());
            if op == Opcode54::Mmbini {
                operands.push(TypedOperand::Register { index: raw.a });
                operands.push(TypedOperand::ImmediateInt {
                    value: raw.sb as i64,
                });
                operands.push(TypedOperand::ExtraArg {
                    value: raw.c as u32,
                });
                operands.push(TypedOperand::Flag { value: raw.k != 0 });
            }
            implicit_effects.push(ImplicitEffect::CompanionPair {
                companion_pc: pc.saturating_sub(1),
                companion_role: format!("Metamethod fallback {tm}"),
            });
            explanation = format!(
                "Companion instruction specifying metamethod fallback {tm} for PC {}",
                pc.saturating_sub(1)
            );
        }

        Opcode54::Unm => {
            citations.push("lvm.c:1260".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__unm".to_string());
            explanation = format!(
                "R({}) := -R({}) (unary minus, fallback __unm)",
                raw.a, raw.b
            );
        }
        Opcode54::Bnot => {
            citations.push("lvm.c:1264".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__bnot".to_string());
            explanation = format!(
                "R({}) := ~R({}) (bitwise not, fallback __bnot)",
                raw.a, raw.b
            );
        }
        Opcode54::Not => {
            citations.push("lvm.c:1268".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := not R({}) (logical not)", raw.a, raw.b);
        }
        Opcode54::Len => {
            citations.push("lvm.c:1272".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__len".to_string());
            explanation = format!(
                "R({}) := #R({}) (length operator, fallback __len)",
                raw.a, raw.b
            );
        }
        Opcode54::Concat => {
            citations.push("lvm.c:1276".to_string());
            let end_reg = raw.a.saturating_add(raw.b).saturating_sub(1);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: false,
            });
            reads.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: end_reg,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__concat".to_string());
            explanation = format!(
                "R({}) := R({})....R({end_reg}) (string concatenation)",
                raw.a, raw.a
            );
        }
        Opcode54::Close => {
            citations.push("lvm.c:1282".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            implicit_effects.push(ImplicitEffect::CloseUpvalues {
                min_register: raw.a,
            });
            explanation = format!("Close all active upvalues at or above R({})", raw.a);
        }
        Opcode54::Tbc => {
            citations.push("lvm.c:1286".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            metamethod_fallbacks.push("__close".to_string());
            explanation = format!(
                "Mark R({}) as a to-be-closed variable (will invoke __close on scope exit)",
                raw.a
            );
        }
        Opcode54::Jmp => {
            citations.push("lvm.c:1290".to_string());
            let dest_pc = (pc as i32 + 1 + raw.sj) as usize;
            let dest_id = StableId::instruction(proto.path.clone(), dest_pc);
            operands.push(TypedOperand::Jump {
                offset: raw.sj,
                target_pc: dest_pc,
                target_id: dest_id,
            });
            jump_target = Some(dest_pc);
            reads.push(EffectTarget::JumpTarget { pc: dest_pc });
            explanation = format!("Unconditional jump by offset {} to PC {dest_pc}", raw.sj);
        }
        Opcode54::Eqi | Opcode54::Lti | Opcode54::Lei | Opcode54::Gti | Opcode54::Gei => {
            citations.push("lvm.c:1300".to_string());
            let skip_pc = pc + 2;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.sb as i64,
            });
            operands.push(TypedOperand::Flag { value: raw.k != 0 });
            reads.push(EffectTarget::Register { index: raw.a });
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            let op_sym = match op {
                Opcode54::Eqi => "==",
                Opcode54::Lti => "<",
                Opcode54::Lei => "<=",
                Opcode54::Gti => ">",
                Opcode54::Gei => ">=",
                _ => "??",
            };
            explanation = format!(
                "if ((R({}) {} {}) != {}) then skip next instruction (jump to PC {skip_pc})",
                raw.a,
                op_sym,
                raw.sb,
                raw.k != 0
            );
        }
        Opcode54::Eq
        | Opcode54::Lt
        | Opcode54::Le
        | Opcode54::Eqk
        | Opcode54::Test
        | Opcode54::Testset => {
            citations.push("lvm.c:1300".to_string());
            let skip_pc = pc + 2;
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            explanation = format!("Conditional test: if result != k, skip following instruction (jump to PC {skip_pc})");
        }

        Opcode54::Call => {
            citations.push("lvm.c:1340".to_string());
            let num_args = raw.b;
            let num_results = raw.c;

            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: if num_args > 0 {
                    (num_args - 1) as usize
                } else {
                    0
                },
                is_variable: num_args == 0,
            });
            operands.push(TypedOperand::Count {
                value: if num_results > 0 {
                    (num_results - 1) as usize
                } else {
                    0
                },
                is_variable: num_results == 0,
            });

            reads.push(EffectTarget::Register { index: raw.a });
            if num_args > 1 {
                reads.push(EffectTarget::RegisterRange {
                    start: raw.a + 1,
                    end: raw.a.saturating_add(num_args).saturating_sub(1),
                });
            } else if num_args == 0 {
                reads.push(EffectTarget::RegisterRangeToTop { start: raw.a + 1 });
            }

            if num_results > 1 {
                writes.push(EffectTarget::RegisterRange {
                    start: raw.a,
                    end: raw.a + num_results - 2,
                });
            } else if num_results == 0 {
                writes.push(EffectTarget::RegisterRangeToTop { start: raw.a });
            }

            metamethod_fallbacks.push("__call".to_string());
            let args_str = if num_args == 0 {
                "top".to_string()
            } else {
                format!("{}", num_args - 1)
            };
            let rets_str = if num_results == 0 {
                "top".to_string()
            } else {
                format!("{}", num_results - 1)
            };
            explanation = format!(
                "Call function in R({}) with {args_str} arguments, expecting {rets_str} results",
                raw.a
            );
        }
        Opcode54::Tailcall => {
            citations.push("lvm.c:1360".to_string());
            let num_args = raw.b;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: if num_args > 0 {
                    (num_args - 1) as usize
                } else {
                    0
                },
                is_variable: num_args == 0,
            });
            reads.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__call".to_string());
            explanation = format!("Tail-call function in R({})", raw.a);
        }
        Opcode54::Return => {
            citations.push("lvm.c:1375".to_string());
            let num_ret = raw.b;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: if num_ret > 0 {
                    (num_ret - 1) as usize
                } else {
                    0
                },
                is_variable: num_ret == 0,
            });
            if num_ret > 1 {
                reads.push(EffectTarget::RegisterRange {
                    start: raw.a,
                    end: raw.a + num_ret - 2,
                });
            } else if num_ret == 0 {
                reads.push(EffectTarget::RegisterRangeToTop { start: raw.a });
            }
            explanation = format!("Return values from R({})", raw.a);
        }
        Opcode54::Return0 => {
            citations.push("lvm.c:1385".to_string());
            explanation = "Return with 0 values".to_string();
        }
        Opcode54::Return1 => {
            citations.push("lvm.c:1388".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Return single value in R({})", raw.a);
        }
        Opcode54::Forprep => {
            citations.push("lvm.c:1395".to_string());
            let jump_dest = pc + 1 + raw.bx as usize;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Jump {
                offset: raw.bx as i32,
                target_pc: jump_dest,
                target_id: StableId::instruction(proto.path.clone(), jump_dest),
            });
            jump_target = Some(jump_dest);
            explanation = format!(
                "Initialize numeric for-loop at R({}) and jump to PC {jump_dest}",
                raw.a
            );
        }
        Opcode54::Forloop => {
            citations.push("lvm.c:1405".to_string());
            let loop_dest = (pc + 1).saturating_sub(raw.bx as usize);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Jump {
                offset: -(raw.bx as i32),
                target_pc: loop_dest,
                target_id: StableId::instruction(proto.path.clone(), loop_dest),
            });
            jump_target = Some(loop_dest);
            explanation = format!(
                "Step numeric for-loop at R({}); if counter <= limit jump back to PC {loop_dest}",
                raw.a
            );
        }
        Opcode54::Tforprep => {
            citations.push("lvm.c:1415".to_string());
            let jump_dest = pc + 1 + raw.bx as usize;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Jump {
                offset: raw.bx as i32,
                target_pc: jump_dest,
                target_id: StableId::instruction(proto.path.clone(), jump_dest),
            });
            jump_target = Some(jump_dest);
            explanation = format!(
                "Initialize generic for-loop at R({}) and jump to PC {jump_dest}",
                raw.a
            );
        }
        Opcode54::Tforcall => {
            citations.push("lvm.c:1425".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.c as i64,
            });
            reads.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: raw.a.saturating_add(2),
            });
            writes.push(EffectTarget::RegisterRange {
                start: raw.a.saturating_add(3),
                end: raw.a.saturating_add(2).saturating_add(raw.c),
            });
            explanation = format!(
                "Call iterator function R({}): return {} results into R({})..R({})",
                raw.a,
                raw.c,
                raw.a + 3,
                raw.a + 2 + raw.c
            );
        }
        Opcode54::Tforloop => {
            citations.push("lvm.c:1435".to_string());
            let loop_dest = (pc + 1).saturating_sub(raw.bx as usize);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Jump {
                offset: -(raw.bx as i32),
                target_pc: loop_dest,
                target_id: StableId::instruction(proto.path.clone(), loop_dest),
            });
            jump_target = Some(loop_dest);

            explanation = format!(
                "Check generic for-loop condition at R({}); if active jump back to PC {loop_dest}",
                raw.a
            );
        }

        Opcode54::Setlist => {
            citations.push("lvm.c:1435".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.b as usize,
                is_variable: raw.b == 0,
            });
            reads.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Set list elements into table in R({})", raw.a);
        }
        Opcode54::Closure => {
            citations.push("lvm.c:1445".to_string());
            let child_path = proto.path.child(raw.bx as usize);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Prototype {
                index: raw.bx as usize,
                path: child_path.clone(),
            });
            reads.push(EffectTarget::Prototype {
                index: raw.bx as usize,
                path: child_path,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "Instantiate closure for child prototype {} into R({})",
                raw.bx, raw.a
            );
        }
        Opcode54::Vararg => {
            citations.push("lvm.c:1455".to_string());
            let num_results = raw.c;
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: if num_results > 0 {
                    (num_results - 1) as usize
                } else {
                    0
                },
                is_variable: num_results == 0,
            });
            explanation = format!("Load vararg values into R({})", raw.a);
        }
        Opcode54::Varargprep => {
            citations.push("lvm.c:1460".to_string());
            operands.push(TypedOperand::Count {
                value: raw.a as usize,
                is_variable: false,
            });
            explanation = format!(
                "Adjust stack frame for vararg function (fixed parameters: {})",
                raw.a
            );
        }
        Opcode54::Extraarg => {
            citations.push("lopcodes.h:280".to_string());
            operands.push(TypedOperand::ExtraArg { value: raw.ax });
            companion_pc = prev.map(|_| pc - 1);
            explanation = format!(
                "Extra argument container (Ax = {}) for previous instruction at PC {}",
                raw.ax,
                pc.saturating_sub(1)
            );
        }
    }

    SemanticInstruction {
        id,
        pc,
        raw_word,
        raw_hex,
        mnemonic,
        operands,
        reads,
        writes,
        implicit_effects,
        metamethod_fallbacks,
        jump_target,
        companion_pc,
        confidence: Confidence::Reviewed,
        source_citations: citations,

        explanation,
        source,
    }
}

fn tm_name(event: u8) -> &'static str {
    match event {
        0 => "__add",
        1 => "__sub",
        2 => "__mul",
        3 => "__mod",
        4 => "__pow",
        5 => "__div",
        6 => "__idiv",
        7 => "__band",
        8 => "__bor",
        9 => "__bxor",
        10 => "__shl",
        11 => "__shr",
        12 => "__unm",
        13 => "__bnot",
        14 => "__lt",
        15 => "__le",
        16 => "__concat",
        17 => "__len",
        18 => "__eq",
        _ => "__metamethod",
    }
}
