//! Lua 5.5 Dialect Implementation for luad.

#![allow(clippy::result_large_err)]

pub mod chunk;

pub mod header;
pub mod lifter;
pub mod opcodes;
pub mod validator;

use luad_core::diagnostic::Diagnostic;
use luad_core::dialect::{DetectionResult, Dialect};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;

pub use chunk::decode_chunk_lua55;
pub use header::{detect_lua55, parse_header_lua55};
pub use lifter::lift_proto_lua55;
pub use opcodes::{OpMode55, Opcode55, RawInstruction55};
pub use validator::validate_chunk_lua55;

/// Concrete dialect handler for official Lua 5.5.0 - 5.5.1 bytecode.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lua55Dialect;

impl Dialect for Lua55Dialect {
    fn name(&self) -> &'static str {
        "lua5.5"
    }

    fn description(&self) -> &'static str {
        "Official stock Lua 5.5.0 through 5.5.1 bytecode format"
    }

    fn detect(&self, bytes: &[u8]) -> Option<DetectionResult> {
        detect_lua55(bytes)
    }

    fn decode_chunk(&self, reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
        decode_chunk_lua55(reader)
    }
}
