//! Semantic instruction lifter for Lua 5.5 bytecode operations.

use luad_core::id::StableId;
use luad_core::ir::{EffectTarget, ImplicitEffect, SemanticInstruction, TypedOperand};
use luad_core::model::{ConstantValue, Prototype};
use luad_core::provenance::Confidence;

use crate::opcodes::{Opcode55, RawInstruction55};

/// Lift all physical instructions of a Lua 5.5 prototype into normalized semantic IR.
pub fn lift_proto_lua55(proto: &Prototype) -> Vec<SemanticInstruction> {
    let mut lifted = Vec::with_capacity(proto.instructions.len());

    for (pc, inst) in proto.instructions.iter().enumerate() {
        let raw = RawInstruction55::decode(inst.raw_word);
        let next_word = proto
            .instructions
            .get(pc + 1)
            .map(|i| RawInstruction55::decode(i.raw_word));
        let prev_word = if pc > 0 {
            proto
                .instructions
                .get(pc - 1)
                .map(|i| RawInstruction55::decode(i.raw_word))
        } else {
            None
        };

        let semantic = lift_instruction_55(proto, pc, inst, raw, next_word, prev_word);
        lifted.push(semantic);
    }

    lifted
}

fn lift_instruction_55(
    proto: &Prototype,
    pc: usize,
    inst: &luad_core::model::InstructionWord,
    raw: RawInstruction55,
    next: Option<RawInstruction55>,
    prev: Option<RawInstruction55>,
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
            confidence: Confidence::Fact,
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
        Opcode55::Move => {
            citations.push("lvm.c:1130".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Copy value from R({}) into R({})", raw.b, raw.a);
        }
        Opcode55::Loadi => {
            citations.push("lvm.c:1133".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.sbx as i64,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load integer constant {} into R({})", raw.sbx, raw.a);
        }
        Opcode55::Loadf => {
            citations.push("lvm.c:1136".to_string());
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateFloat {
                value: raw.sbx as f64,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Load float constant {}.0 into R({})", raw.sbx, raw.a);
        }
        Opcode55::Loadk => {
            citations.push("lvm.c:1139".to_string());
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
        Opcode55::Loadkx => {
            citations.push("lvm.c:1142".to_string());
            let extra_ax = next
                .filter(|n| n.opcode == Some(Opcode55::Extraarg))
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
            explanation = format!("Load extended constant K[{extra_ax}] into R({})", raw.a);
        }
        Opcode55::Loadfalse => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: false });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Set R({}) to false", raw.a);
        }
        Opcode55::Lfalseskip => {
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
        Opcode55::Loadtrue => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Flag { value: true });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Set R({}) to true", raw.a);
        }
        Opcode55::Loadnil => {
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
        Opcode55::Getupval => {
            let up_name = get_upval_name(raw.b);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            reads.push(EffectTarget::Upvalue {
                index: raw.b,
                name: up_name,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Read upvalue [{}] into R({})", raw.b, raw.a);
        }
        Opcode55::Setupval => {
            let up_name = get_upval_name(raw.b);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            reads.push(EffectTarget::Register { index: raw.a });
            writes.push(EffectTarget::Upvalue {
                index: raw.b,
                name: up_name,
            });
            explanation = format!("Write R({}) into upvalue [{}]", raw.a, raw.b);
        }
        Opcode55::Gettabup => {
            let up_name = get_upval_name(raw.b);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Upvalue {
                index: raw.b,
                name: up_name.clone(),
            });
            let k_val = get_const_val(raw.c as usize);
            operands.push(TypedOperand::Constant {
                index: raw.c as usize,
                value: k_val,
            });
            reads.push(EffectTarget::Upvalue {
                index: raw.b,
                name: up_name,
            });
            reads.push(EffectTarget::Constant {
                index: raw.c as usize,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__index".to_string());
            explanation = format!(
                "R({}) := UpValue[{}][K[{}]] (fallback __index)",
                raw.a, raw.b, raw.c
            );
        }
        Opcode55::Gettable => {
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
        Opcode55::Geti => {
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
        Opcode55::Getfield => {
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
        Opcode55::Settabup => {
            let up_name = get_upval_name(raw.a);
            operands.push(TypedOperand::Upvalue {
                index: raw.a,
                name: up_name.clone(),
            });
            let k_val = get_const_val(raw.b as usize);
            operands.push(TypedOperand::Constant {
                index: raw.b as usize,
                value: k_val,
            });
            reads.push(EffectTarget::Constant {
                index: raw.b as usize,
            });
            writes.push(EffectTarget::Upvalue {
                index: raw.a,
                name: up_name,
            });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!(
                "UpValue[{}][K[{}]] := RK({}) (fallback __newindex)",
                raw.a, raw.b, raw.c
            );
        }
        Opcode55::Settable => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.b });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!(
                "R({})[R({})] := RK({}) (fallback __newindex)",
                raw.a, raw.b, raw.c
            );
        }
        Opcode55::Seti => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::ImmediateInt {
                value: raw.b as i64,
            });
            reads.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!(
                "R({})[{}] := RK({}) (fallback __newindex)",
                raw.a, raw.b, raw.c
            );
        }
        Opcode55::Setfield => {
            let k_key = get_const_val(raw.b as usize);
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: raw.b as usize,
                value: k_key,
            });
            reads.push(EffectTarget::Register { index: raw.a });
            reads.push(EffectTarget::Constant {
                index: raw.b as usize,
            });
            metamethod_fallbacks.push("__newindex".to_string());
            explanation = format!(
                "R({})[K[{}]] := RK({}) (fallback __newindex)",
                raw.a, raw.b, raw.c
            );
        }
        Opcode55::Newtable => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.vb as usize,
                is_variable: false,
            });
            operands.push(TypedOperand::Count {
                value: raw.vc as usize,
                is_variable: false,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "Allocate new table in R({}) (array hint: {}, hash hint: {})",
                raw.a, raw.vb, raw.vc
            );
        }
        Opcode55::SelfOp => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            writes.push(EffectTarget::Register { index: raw.a + 1 });
            metamethod_fallbacks.push("__index".to_string());
            explanation = format!(
                "R({}) := R({})[K[{}]]; R({}) := R({}) (method lookup)",
                raw.a,
                raw.b,
                raw.c,
                raw.a + 1,
                raw.b
            );
        }
        Opcode55::Addi | Opcode55::Shli | Opcode55::Shri => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := R({}) {} {}", raw.a, raw.b, op.name(), raw.c);
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
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::Constant {
                index: raw.c as usize,
                value: get_const_val(raw.c as usize),
            });
            reads.push(EffectTarget::Register { index: raw.b });
            reads.push(EffectTarget::Constant {
                index: raw.c as usize,
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := R({}) {} K[{}]", raw.a, raw.b, op.name(), raw.c);
        }
        Opcode55::Add
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
        | Opcode55::Shr => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::Register { index: raw.c });
            reads.push(EffectTarget::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.c });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := R({}) {} R({})", raw.a, raw.b, op.name(), raw.c);
        }
        Opcode55::Mmbin | Opcode55::Mmbini | Opcode55::Mmbink => {
            companion_pc = prev.map(|_| pc - 1);
            let tm = tm_name(raw.c);
            metamethod_fallbacks.push(tm.to_string());
            implicit_effects.push(ImplicitEffect::CompanionPair {
                companion_pc: pc.saturating_sub(1),
                companion_role: format!("Metamethod fallback {tm}"),
            });
            explanation = format!("Metamethod companion {tm} for PC {}", pc.saturating_sub(1));
        }

        Opcode55::Unm | Opcode55::Bnot | Opcode55::Not | Opcode55::Len => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.b });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := {} R({})", raw.a, op.name(), raw.b);
        }
        Opcode55::Concat => {
            operands.push(TypedOperand::Register { index: raw.a });
            reads.push(EffectTarget::RegisterRange {
                start: raw.a,
                end: raw.a.saturating_add(raw.b).saturating_sub(1),
            });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!("R({}) := concatenation of {} registers", raw.a, raw.b);
        }

        Opcode55::Close => {
            operands.push(TypedOperand::Register { index: raw.a });
            explanation = format!("Close active upvalues >= R({})", raw.a);
        }
        Opcode55::Tbc => {
            operands.push(TypedOperand::Register { index: raw.a });
            explanation = format!("Mark R({}) as to-be-closed", raw.a);
        }
        Opcode55::Jmp => {
            let dest_pc = (pc as i32 + 1 + raw.sj) as usize;
            operands.push(TypedOperand::Jump {
                offset: raw.sj,
                target_pc: dest_pc,
                target_id: StableId::instruction(proto.path.clone(), dest_pc),
            });
            jump_target = Some(dest_pc);
            explanation = format!("Unconditional jump by offset {} to PC {dest_pc}", raw.sj);
        }
        Opcode55::Eq
        | Opcode55::Lt
        | Opcode55::Le
        | Opcode55::Eqk
        | Opcode55::Eqi
        | Opcode55::Lti
        | Opcode55::Lei
        | Opcode55::Gti
        | Opcode55::Gei
        | Opcode55::Test
        | Opcode55::Testset => {
            let skip_pc = pc + 2;
            implicit_effects.push(ImplicitEffect::ConditionalSkip {
                skip_target_pc: skip_pc,
            });
            explanation = format!(
                "Conditional test: skip next instruction if condition fails (jump to PC {skip_pc})"
            );
        }
        Opcode55::Call => {
            operands.push(TypedOperand::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__call".to_string());
            explanation = format!("Call function in R({}) (B={}, C={})", raw.a, raw.b, raw.c);
        }
        Opcode55::Tailcall => {
            operands.push(TypedOperand::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.a });
            metamethod_fallbacks.push("__call".to_string());
            explanation = format!("Tail-call function in R({})", raw.a);
        }
        Opcode55::Return => {
            operands.push(TypedOperand::Register { index: raw.a });
            explanation = format!("Return values starting from R({})", raw.a);
        }
        Opcode55::Return0 => {
            explanation = "Return 0 values".to_string();
        }
        Opcode55::Return1 => {
            operands.push(TypedOperand::Register { index: raw.a });
            reads.push(EffectTarget::Register { index: raw.a });
            explanation = format!("Return 1 value in R({})", raw.a);
        }
        Opcode55::Forloop => {
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
        Opcode55::Forprep => {
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
        Opcode55::Tforprep => {
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
        Opcode55::Tforcall => {
            operands.push(TypedOperand::Register { index: raw.a });
            explanation = format!("Call iterator function at R({})", raw.a);
        }
        Opcode55::Tforloop => {
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
        Opcode55::Setlist => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Count {
                value: raw.vb as usize,
                is_variable: raw.vb == 0,
            });
            reads.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "Set list elements into table in R({}) (batch count: {}, offset: {})",
                raw.a, raw.vb, raw.vc
            );
        }
        Opcode55::Closure => {
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
        Opcode55::Vararg => {
            operands.push(TypedOperand::Register { index: raw.a });
            explanation = format!("Load vararg values into R({})", raw.a);
        }
        Opcode55::Getvarg => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Register { index: raw.b });
            operands.push(TypedOperand::Register { index: raw.c });
            reads.push(EffectTarget::Register { index: raw.b });
            reads.push(EffectTarget::Register { index: raw.c });
            writes.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "R({}) := R({})[R({})] where R({}) is vararg parameter",
                raw.a, raw.b, raw.c, raw.b
            );
        }
        Opcode55::Errnnil => {
            operands.push(TypedOperand::Register { index: raw.a });
            operands.push(TypedOperand::Constant {
                index: raw.bx.saturating_sub(1) as usize,
                value: get_const_val(raw.bx.saturating_sub(1) as usize),
            });
            reads.push(EffectTarget::Register { index: raw.a });
            explanation = format!(
                "Raise error if R({}) ~= nil (global name K[{}])",
                raw.a,
                raw.bx.saturating_sub(1)
            );
        }
        Opcode55::Varargprep => {
            operands.push(TypedOperand::Count {
                value: raw.a as usize,
                is_variable: false,
            });
            explanation = format!(
                "Adjust stack frame for vararg function (fixed parameters: {})",
                raw.a
            );
        }
        Opcode55::Extraarg => {
            operands.push(TypedOperand::ExtraArg { value: raw.ax });
            companion_pc = prev.map(|_| pc - 1);
            explanation = format!(
                "Extra argument container (Ax = {}) for previous instruction at PC {}",
                raw.ax,
                pc.saturating_sub(1)
            );
        }
    }

    if citations.is_empty() {
        citations.push(format!("lvm.c:{}", 1130 + (raw.opcode_num as usize) * 3));
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
        confidence: Confidence::Fact,
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
