//! Lua 5.1 Dialect Implementation for luad.

#![forbid(unsafe_code)]
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

pub use chunk::decode_chunk_lua51;
pub use header::{detect_lua51, parse_header_lua51};
pub use lifter::lift_proto_lua51;
pub use opcodes::{OpMode51, Opcode51, RawInstruction51};
pub use validator::validate_chunk_lua51;

/// Concrete dialect handler for official Lua 5.1.0 - 5.1.5 bytecode.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lua51Dialect;

impl Dialect for Lua51Dialect {
    fn name(&self) -> &'static str {
        "lua5.1"
    }

    fn description(&self) -> &'static str {
        "Official stock Lua 5.1.0 through 5.1.5 bytecode format"
    }

    fn detect(&self, bytes: &[u8]) -> Option<DetectionResult> {
        detect_lua51(bytes)
    }

    fn decode_chunk(&self, reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
        decode_chunk_lua51(reader)
    }
}
