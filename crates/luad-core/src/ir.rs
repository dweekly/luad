//! Normalized semantic intermediate representation for instructions and operands.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::id::{ProtoPath, StableId};
use crate::model::ConstantValue;
use crate::provenance::{Confidence, SourceLocation};

/// Target or source of a read or write effect.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum EffectTarget {
    /// Virtual register R(index).
    Register { index: u8 },
    /// Fixed range of registers R(start)..=R(end).
    RegisterRange { start: u8, end: u8 },
    /// Open register range from R(start) up to current stack top (multireturn / top-dependent).
    RegisterRangeToTop { start: u8 },
    /// Upvalue index Upvalue(index).
    Upvalue { index: u8, name: Option<String> },
    /// Constant table index K(index).
    Constant { index: usize },
    /// Nested child prototype index Proto(index).
    Prototype { index: usize, path: ProtoPath },
    /// Program counter / jump target.
    JumpTarget { pc: usize },
}

/// Category of operand in a semantic instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TypedOperand {
    /// Virtual machine register R(index).
    Register { index: u8 },
    /// Resolved constant from prototype's constant table.
    Constant { index: usize, value: ConstantValue },
    /// Upvalue reference.
    Upvalue { index: u8, name: Option<String> },
    /// Child prototype reference.
    Prototype { index: usize, path: ProtoPath },
    /// Immediate integer literal (signed 64-bit).
    ImmediateInt { value: i64 },
    /// Immediate float literal.
    ImmediateFloat { value: f64 },
    /// Resolved relative branch or jump destination.
    Jump {
        offset: i32,
        target_pc: usize,
        target_id: StableId,
    },
    /// Count operand (e.g. parameter count, return count, table size).
    /// 0 denotes variable/top-dependent count.
    Count { value: usize, is_variable: bool },
    /// Boolean flag or test condition.
    Flag { value: bool },
    /// Extra argument from companion instruction (e.g. OP_EXTRAARG).
    ExtraArg { value: u32 },
}

/// Implicit or runtime side effect of an instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ImplicitEffect {
    /// Adjusts stack top to a variable position.
    SetStackTop { base_register: u8 },
    /// Pushes or receives multiple variable return values.
    Multireturn { start_register: u8 },
    /// Captures local register into an upvalue closure.
    CaptureUpvalue { register: u8 },
    /// Closes active upvalues at or above the given register.
    CloseUpvalues { min_register: u8 },
    /// Conditionally skips the immediately following instruction.
    ConditionalSkip { skip_target_pc: usize },
    /// Sets table elements in batch (`SETLIST`).
    SetListBatch { start_index: usize, count: usize },
    /// Companion instruction relation (pairs with preceding or succeeding PC).
    CompanionPair {
        companion_pc: usize,
        companion_role: String,
    },
}

/// Normalized semantic instruction representing a lifted Lua bytecode operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SemanticInstruction {
    /// Deterministic stable ID (e.g. `proto:0:pc:14`).
    pub id: StableId,
    /// Program counter (0-indexed).
    pub pc: usize,
    /// Raw 32-bit physical instruction word.
    pub raw_word: u32,
    /// Raw hex string.
    pub raw_hex: String,
    /// Opcode mnemonic (e.g. "MOVE", "LOADK", "CALL", "GETTABUP").
    pub mnemonic: String,
    /// Semantically typed and resolved operands.
    pub operands: Vec<TypedOperand>,
    /// Explicit and implicit reads performed by this instruction.
    pub reads: Vec<EffectTarget>,
    /// Explicit and implicit writes performed by this instruction.
    pub writes: Vec<EffectTarget>,
    /// Special implicit VM side-effects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub implicit_effects: Vec<ImplicitEffect>,
    /// Possible runtime metamethod fallback triggers (e.g. "__index", "__add").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metamethod_fallbacks: Vec<String>,
    /// Direct control-flow branch target PC if branching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_target: Option<usize>,
    /// Companion instruction PC if paired with another physical instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub companion_pc: Option<usize>,
    /// Confidence tier.
    pub confidence: Confidence,
    /// Official Lua reference VM source citations (e.g. `lvm.c:1134`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_citations: Vec<String>,
    /// Human-readable explanation summary.
    pub explanation: String,
    /// Source byte location in chunk.
    pub source: SourceLocation,
}
