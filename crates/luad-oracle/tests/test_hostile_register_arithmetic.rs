//! Register-effect arithmetic in the semantic lifters must stay bounded when a chunk
//! encodes operands that no real Lua code generator would emit.
//!
//! Lua register indices are `u8`, and several effect ranges are derived as `A + n` or
//! `A + B - n`. A chunk decoded from hostile bytes can carry `A = 255`, so those
//! derivations must saturate rather than overflow. The chunk itself is still invalid;
//! the raw operands remain preserved beside the derived effects, and validation
//! reports the anomaly. Lifting must not panic on the way there.

use luad_analysis::{lift_proto_for_dialect, ControlFlowGraph};
use luad_core::model::Prototype;
use luad_core::{Dialect, ParseMode, ResourceLimits, SafeReader};
use luad_dialect_lua51::Lua51Dialect;
use luad_dialect_lua54::Lua54Dialect;

/// Lua 5.1 word layout: OP[0..6) A[6..14) C[14..23) B[23..32).
fn word_51(op: u32, a: u32, b: u32, c: u32) -> u32 {
    (op & 0x3F) | ((a & 0xFF) << 6) | ((c & 0x1FF) << 14) | ((b & 0x1FF) << 23)
}

/// Lua 5.4 word layout: OP[0..7) A[7..15) k[15] B[16..24) C[24..32).
fn word_54(op: u32, a: u32, b: u32, c: u32, k: u32) -> u32 {
    (op & 0x7F) | ((a & 0xFF) << 7) | ((k & 1) << 15) | ((b & 0xFF) << 16) | ((c & 0xFF) << 24)
}

/// Replaces a decoded prototype's code with `words`, keeping every other field, so the
/// lifter runs against a real prototype rather than a hand-built one.
fn with_code(proto: &Prototype, words: &[u32]) -> Prototype {
    let template = proto
        .instructions
        .first()
        .expect("fixture prototype must carry at least one instruction")
        .clone();
    let mut hostile = proto.clone();
    hostile.instructions = words
        .iter()
        .enumerate()
        .map(|(pc, &raw_word)| {
            let mut inst = template.clone();
            inst.pc = pc;
            inst.raw_word = raw_word;
            inst.raw_hex = format!("{raw_word:08x}");
            inst
        })
        .collect();
    hostile.protos = Vec::new();
    hostile
}

#[test]
fn lua51_register_effects_saturate_on_maximal_operands() {
    let bytes = luad_oracle::load_precompiled_fixture("lua51", "control_flow", false)
        .expect("load maintained Lua 5.1 fixture");
    let mut reader =
        SafeReader::with_options(&bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    let chunk = Lua51Dialect::default()
        .decode_chunk(&mut reader)
        .expect("maintained fixture must decode");

    // Sweep the whole Lua 5.1 opcode space with maximal operand fields so every
    // register-effect derivation is driven past the end of the register file.
    let words: Vec<u32> = (0..38).map(|op| word_51(op, 0xFF, 0x1FF, 0x1FF)).collect();
    let hostile = with_code(&chunk.main_proto, &words);

    let lifted = lift_proto_for_dialect("lua5.1", &hostile);
    assert_eq!(lifted.len(), words.len(), "every instruction must lift");
    let _ = ControlFlowGraph::build(&hostile, &lifted);
}

#[test]
fn lua54_register_effects_saturate_on_maximal_operands() {
    let bytes = luad_oracle::load_precompiled_fixture("lua54", "control_flow", false)
        .expect("load maintained Lua 5.4 fixture");
    let mut reader =
        SafeReader::with_options(&bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    let chunk = Lua54Dialect
        .decode_chunk(&mut reader)
        .expect("maintained fixture must decode");

    let words: Vec<u32> = (0..83)
        .flat_map(|op| {
            [
                word_54(op, 0xFF, 0xFF, 0xFF, 0),
                word_54(op, 0xFF, 0xFF, 0xFF, 1),
            ]
        })
        .collect();
    let hostile = with_code(&chunk.main_proto, &words);

    let lifted = lift_proto_for_dialect("lua5.4", &hostile);
    assert_eq!(lifted.len(), words.len(), "every instruction must lift");
    let _ = ControlFlowGraph::build(&hostile, &lifted);
}
