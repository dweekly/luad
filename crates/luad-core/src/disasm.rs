//! Typed production disassembly representation.
//!
//! Exposes a structured, dialect-neutral disassembly record containing physical
//! and semantic instruction metadata, physical role, raw encoded fields,
//! typed operands (including decoded signed immediates), companion information,
//! resolved constant/upvalue/prototype references with StableIds, source lines,
//! jump targets, provenance, and structured diagnostics.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::diagnostic::Diagnostic;
use crate::id::StableId;
use crate::model::ConstantValue;
use crate::provenance::{Confidence, SourceLocation};

/// Raw decoded bitfield operands preserved from physical instruction word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct EncodedOperands {
    pub a: u8,
    pub b: u8,
    pub c: u8,
    pub k: u8,
    pub bx: u32,
    pub sbx: i32,
    pub ax: u32,
    pub sb: i32,
    pub sc: i32,
    pub sj: i32,
}

/// Category of an operand in a disassembled instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OperandKind {
    /// Virtual register R(index).
    Register { index: u8 },
    /// Unsigned immediate integer value (e.g. Bx, Ax).
    ImmediateUnsigned { value: u64 },
    /// Signed immediate integer value (e.g. sB, sC, sBx, sJ).
    ImmediateSigned { value: i64 },
    /// 1-bit boolean or constant selection flag (k).
    Flag { value: u8 },
    /// Raw uninterpreted integer.
    Raw { value: u64 },
}

/// Resolved semantic target or value attached to an operand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ResolvedFact {
    /// Resolved constant from prototype's constant table.
    Constant {
        index: usize,
        id: StableId,
        value: ConstantValue,
        formatted_preview: String,
    },
    /// Resolved upvalue descriptor.
    Upvalue {
        index: u8,
        id: StableId,
        name: Option<String>,
    },
    /// Resolved local variable debug info.
    Local {
        index: usize,
        id: StableId,
        name: String,
    },
    /// Resolved child prototype.
    Prototype { index: usize, id: StableId },
    /// Resolved jump destination PC.
    JumpTarget { target_pc: usize, id: StableId },
    /// Resolved metamethod name for metamethod-bearing dispatch instructions.
    Metamethod { name: String },
}

/// A single typed operand within a disassembled instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisassembledOperand {
    /// Name or descriptor of operand field (e.g. "A", "B", "sC", "k", "sBx", "sJ").
    pub name: String,
    /// Typed kind and numeric value of the operand.
    pub kind: OperandKind,
    /// Canonical display string of the operand.
    pub display: String,
    /// Optional resolved semantic fact attached to this operand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<ResolvedFact>,
}

/// A disassembled instruction with physical and semantic details.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisassembledInstruction {
    /// Deterministic stable ID (e.g. `proto:0:pc:14`).
    pub id: StableId,
    /// 0-indexed physical program counter.
    pub pc: usize,
    /// Raw 32-bit physical instruction word.
    pub raw_word: u32,
    /// Hex-encoded instruction word (e.g. "0x00000046").
    pub raw_hex: String,
    /// Official opcode mnemonic (e.g. "MOVE", "ADDI", "MMBINI", "JMP").
    pub mnemonic: String,
    /// Raw numeric opcode byte.
    pub opcode_num: u8,
    /// Physical semantic role ("instruction", "companion", "closure_binding", "extra_argument").
    pub role: String,
    /// Decoded raw bitfield parameters.
    pub encoded_operands: EncodedOperands,
    /// 1-based source line number if debug info is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// Ordered list of typed operands.
    pub operands: Vec<DisassembledOperand>,
    /// Resolved jump target PC (0-indexed) if this is a branch instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jump_target: Option<usize>,
    /// Companion instruction PC if paired with another physical instruction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub companion_pc: Option<usize>,
    /// Metamethod name (e.g. "__add") if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metamethod: Option<String>,
    /// Bounded trailing comment preview (e.g. constant value, jump annotation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Analysis confidence level.
    pub confidence: Confidence,
    /// Source byte location in chunk.
    pub source: SourceLocation,
    /// Structured diagnostics emitted during disassembly (e.g. invalid opcode, invalid constant reference).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

/// Disassembled prototype containing metadata and structured disassembly rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DisassembledPrototype {
    /// Deterministic stable ID (e.g. "proto:0").
    pub id: StableId,
    /// Source filename / path if debug info is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// 1-based defined line number.
    pub line_defined: usize,
    /// 1-based last defined line number.
    pub last_line_defined: usize,
    /// Number of fixed parameters.
    pub numparams: u8,
    /// Whether this prototype accepts varargs.
    pub is_vararg: bool,
    /// Maximum virtual stack frame slots required.
    pub maxstacksize: u8,
    /// Ordered list of disassembled instructions.
    pub instructions: Vec<DisassembledInstruction>,
    /// Structured diagnostics across prototype disassembly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
    /// Child prototypes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub child_protos: Vec<DisassembledPrototype>,
}
