//! Lua 5.3 Dialect Implementation for luad.

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

pub use chunk::decode_chunk_lua53;
pub use header::{detect_lua53, parse_header_lua53};
pub use lifter::lift_proto_lua53;
pub use opcodes::{OpMode53, Opcode53, RawInstruction53};
pub use validator::validate_chunk_lua53;

/// Concrete dialect handler for official Lua 5.3.0 - 5.3.6 bytecode.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lua53Dialect;

impl Dialect for Lua53Dialect {
    fn name(&self) -> &'static str {
        "lua5.3"
    }

    fn description(&self) -> &'static str {
        "Official stock Lua 5.3.0 through 5.3.6 bytecode format"
    }

    fn detect(&self, bytes: &[u8]) -> Option<DetectionResult> {
        detect_lua53(bytes)
    }

    fn decode_chunk(&self, reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
        decode_chunk_lua53(reader)
    }
}
