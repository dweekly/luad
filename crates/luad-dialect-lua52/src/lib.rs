//! Lua 5.2 Dialect Implementation for luad.

pub mod chunk;
pub mod header;
pub mod lifter;
pub mod opcodes;
pub mod validator;

use luad_core::diagnostic::Diagnostic;
use luad_core::dialect::{DetectionResult, Dialect};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;

pub use chunk::decode_chunk_lua52;
pub use header::{detect_lua52, parse_header_lua52};
pub use lifter::lift_proto_lua52;
pub use opcodes::{OpMode52, Opcode52, RawInstruction52};
pub use validator::validate_chunk_lua52;

/// Concrete dialect handler for official Lua 5.2.0 - 5.2.4 bytecode.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lua52Dialect;

impl Dialect for Lua52Dialect {
    fn name(&self) -> &'static str {
        "lua5.2"
    }

    fn description(&self) -> &'static str {
        "Official stock Lua 5.2.0 through 5.2.4 bytecode format"
    }

    fn detect(&self, bytes: &[u8]) -> Option<DetectionResult> {
        detect_lua52(bytes)
    }

    fn decode_chunk(&self, reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
        decode_chunk_lua52(reader)
    }
}
