//! Lossless AST model representing parsed Lua chunks, headers, prototypes, constants,
//! code, upvalues, and debug metadata.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::diagnostic::{Diagnostic, Verdict};
use crate::id::{ProtoPath, StableId};
use crate::provenance::SourceLocation;

/// A lossless Lua string retaining exact byte contents along with escaped display representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LuaString {
    /// Raw byte sequence of the string.
    pub raw_bytes: Vec<u8>,
    /// Escaped ASCII/UTF-8 representation suitable for human inspection.
    pub display: String,
    /// Whether the string is valid UTF-8.
    pub is_utf8: bool,
}

impl LuaString {
    /// Create a LuaString from raw byte slice.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let is_utf8 = std::str::from_utf8(bytes).is_ok();
        let display = Self::escape_bytes(bytes);
        Self {
            raw_bytes: bytes.to_vec(),
            display,
            is_utf8,
        }
    }

    fn escape_bytes(bytes: &[u8]) -> String {
        let mut out = String::new();
        for &b in bytes {
            match b {
                b'\\' => out.push_str(r"\\"),
                b'"' => out.push_str(r#"\""#),
                b'\n' => out.push_str(r"\n"),
                b'\r' => out.push_str(r"\r"),
                b'\t' => out.push_str(r"\t"),
                0x20..=0x7E => out.push(b as char),
                _ => out.push_str(&format!(r"\x{:02x}", b)),
            }
        }
        out
    }

    /// Return the string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        if self.is_utf8 {
            std::str::from_utf8(&self.raw_bytes).unwrap_or(&self.display)
        } else {
            &self.display
        }
    }
}

impl AsRef<str> for LuaString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Constant value preserved without loss of floating-point or integer bit patterns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum ConstantValue {
    /// `nil` constant.
    Nil,
    /// Boolean `false` or `true`.
    Boolean(bool),
    /// 64-bit signed integer with raw hex representation.
    Integer {
        /// Parsed 64-bit integer value.
        val: i64,
        /// Exact hex bytes.
        raw_hex: String,
    },
    /// IEEE-754 64-bit float with raw hex representation (preserves NaN payloads and signed zero).
    Float {
        /// Parsed float value.
        val: f64,
        /// Exact 8-byte hex representation.
        raw_hex: String,
        /// Special float classifications.
        is_nan: bool,
        /// Positive or negative infinity.
        is_inf: bool,
    },
    /// Short string constant.
    ShortString(LuaString),
    /// Long string constant.
    LongString(LuaString),
}

/// A parsed constant in a prototype's constant vector.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Constant {
    /// Deterministic stable ID (e.g. `proto:0:k:3`).
    pub id: StableId,
    /// 0-indexed position in constant table.
    pub index: usize,
    /// Preserved constant value.
    pub value: ConstantValue,
    /// Source byte location.
    pub source: SourceLocation,
}

/// Raw 32-bit instruction word.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InstructionWord {
    /// Deterministic stable ID (e.g. `proto:0:pc:12`).
    pub id: StableId,
    /// 0-indexed program counter within prototype.
    pub pc: usize,
    /// Raw 32-bit instruction integer.
    pub raw_word: u32,
    /// Hex representation.
    pub raw_hex: String,
    /// Source byte location.
    pub source: SourceLocation,
}

/// Upvalue descriptor within a prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UpvalueDesc {
    /// Deterministic stable ID (e.g. `proto:0:upvalue:1`).
    pub id: StableId,
    /// 0-indexed position in upvalue vector.
    pub index: usize,
    /// Whether upvalue is in enclosing stack (1) or outer upvalue (0).
    pub instack: u8,
    /// Register or upvalue index in outer scope.
    pub idx: u8,
    /// Upvalue kind/tag (e.g. in Lua 5.4: 0 = regular, 1 = read-only/const, 2 = to-be-closed).
    pub kind: u8,
    /// Debug variable name if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<LuaString>,
    /// Source byte location.
    pub source: SourceLocation,
}

/// Local variable debug metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LocalVar {
    /// Deterministic stable ID (e.g. `proto:0:local:2`).
    pub id: StableId,
    /// 0-indexed local variable index.
    pub index: usize,
    /// Variable name.
    pub name: LuaString,
    /// Starting PC of active scope (inclusive).
    pub startpc: usize,
    /// Ending PC of active scope (exclusive/inclusive depending on version).
    pub endpc: usize,
    /// Source byte location.
    pub source: SourceLocation,
}

/// Absolute line information entry (Lua 5.4+).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AbsLineInfo {
    /// Program counter.
    pub pc: usize,
    /// Absolute source line number.
    pub line: usize,
    /// Source byte location.
    pub source: SourceLocation,
}

/// Lossless prototype representing a compiled Lua function body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Prototype {
    /// Deterministic stable ID (e.g. `proto:0/2`).
    pub id: StableId,
    /// Structural path.
    pub path: ProtoPath,
    /// Source file name if debug information is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<LuaString>,
    /// First line of source where function was defined.
    pub line_defined: usize,
    /// Last line of source where function was defined.
    pub last_line_defined: usize,
    /// Number of fixed parameters.
    pub numparams: u8,
    /// Vararg flags / boolean.
    pub is_vararg: u8,
    /// Maximum stack size (registers needed).
    pub maxstacksize: u8,
    /// Code vector of physical instruction words.
    pub instructions: Vec<InstructionWord>,
    /// Constant table.
    pub constants: Vec<Constant>,
    /// Upvalue table.
    pub upvalues: Vec<UpvalueDesc>,
    /// Nested child prototypes.
    pub protos: Vec<Prototype>,
    /// Debug line offset vector.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub line_info: Vec<u8>,
    /// Absolute line info records.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub abs_line_info: Vec<AbsLineInfo>,
    /// Local variable debug records.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub loc_vars: Vec<LocalVar>,
    /// Upvalue debug names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upvalue_names: Vec<Option<LuaString>>,
    /// Source byte location of the prototype.
    pub source: SourceLocation,
}

impl Prototype {
    /// Reconstruct the source line number for a specific instruction PC.
    #[must_use]
    pub fn get_line_for_pc(&self, pc: usize) -> usize {
        if self.line_info.is_empty() && self.abs_line_info.is_empty() {
            return self.line_defined;
        }

        // If abs_line_info directly maps every PC (Lua 5.1..5.3):
        if self.abs_line_info.len() == self.instructions.len() {
            if let Some(entry) = self.abs_line_info.get(pc) {
                return entry.line;
            }
        }

        // For Lua 5.4 / 5.5: delta-line calculation from abslineinfo or linedefined
        if !self.line_info.is_empty() {
            let mut base_pc = 0;
            let mut base_line = self.line_defined;

            for abs in &self.abs_line_info {
                if abs.pc <= pc {
                    base_pc = abs.pc;
                    base_line = abs.line;
                } else {
                    break;
                }
            }

            let mut current_line = base_line as isize;
            for i in base_pc..=pc.min(self.line_info.len().saturating_sub(1)) {
                let delta = self.line_info[i] as i8;
                if delta == -128 {
                    if let Some(abs) = self.abs_line_info.iter().find(|a| a.pc == i) {
                        current_line = abs.line as isize;
                    }
                } else {
                    current_line += delta as isize;
                }
            }
            return current_line.max(0) as usize;
        }

        self.line_defined
    }
}

fn default_sizeof_sizet() -> u8 {
    8
}

/// Serialized chunk header.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Header {
    /// Format signature (`\x1bLua`).
    pub signature: String,
    /// Version byte (e.g. 0x54 for Lua 5.4).
    pub version: u8,
    /// Format byte (0 for official stock Lua).
    pub format: u8,
    /// LUAC_DATA validation sequence.
    pub luac_data: String,
    /// Size of instruction in bytes (4).
    pub instruction_size: u8,
    /// Size of lua_Integer in bytes (8 on 64-bit, 4 on 32-bit).
    pub lua_integer_size: u8,
    /// Size of size_t in bytes (8 on 64-bit, 4 on 32-bit).
    #[serde(default = "default_sizeof_sizet")]
    pub sizeof_sizet: u8,
    /// Size of lua_Number in bytes (8).
    pub lua_number_size: u8,
    /// LUAC_INT test integer (e.g. 0x5678).
    pub luac_int: i64,

    /// LUAC_NUM test float (e.g. 370.5).
    pub luac_num: f64,
    /// Source byte location.
    pub source: SourceLocation,
}

/// A parsed Lua bytecode chunk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Chunk {
    /// SHA-256 hash of the input bytes.
    pub sha256: String,
    /// Total input byte length.
    pub byte_length: usize,
    /// Identified dialect (e.g. "lua5.4").
    pub dialect: String,
    /// Chunk header.
    pub header: Header,
    /// Main root prototype (`proto:0`).
    pub main_proto: Prototype,
    /// Trailing unparsed bytes if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trailing_bytes: Option<String>,
    /// Diagnostics emitted during parsing and validation.
    pub diagnostics: Vec<Diagnostic>,
    /// Overall validation verdict.
    pub verdict: Verdict,
}
