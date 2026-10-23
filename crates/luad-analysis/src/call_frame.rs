//! Analysis lifetime invalidation, separate from encoded instruction result writes.

use luad_core::{EffectTarget, SemanticInstruction, TypedOperand};

/// First register whose pre-instruction value cannot be retained across this call.
///
/// Lua/C callees reuse the stack starting at their caller's function slot. Fixed
/// result counts only describe returned values, not preservation of the remaining
/// temporary slots. Transfer must invalidate this tail before establishing results.
/// This assumes the ordinary VM ABI, without arbitrary reflective/C stack mutation.
///
/// Lua 5.1 TFORLOOP calls from A+3 and conditionally replaces the control at A+2.
/// Joining its two outcomes therefore invalidates from A+2. Its count operand
/// distinguishes that combined iterator operation from Lua 5.4's jump-only TFORLOOP.
/// Raw words, operand roles and the lifter's encoded writes are not modified.
pub(crate) fn invalidation_start(instruction: &SemanticInstruction) -> Option<u8> {
    let TypedOperand::Register { index: base } = instruction.operands.first()? else {
        return None;
    };
    match instruction.mnemonic.as_str() {
        "CALL" | "TAILCALL" => Some(*base),
        "TFORLOOP"
            if matches!(
                instruction.operands.get(1),
                Some(TypedOperand::Count { .. })
            ) =>
        {
            base.checked_add(2)
        }
        _ => None,
    }
}

pub(crate) fn may_clobber(instruction: &SemanticInstruction, target: &EffectTarget) -> bool {
    matches!(
        (invalidation_start(instruction), target),
        (Some(start), EffectTarget::Register { index }) if start <= *index
    )
}
