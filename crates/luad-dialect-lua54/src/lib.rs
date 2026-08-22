//! Lua 5.4 Dialect Implementation for luad.

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

pub use chunk::decode_chunk_lua54;
pub use header::{detect_lua54, parse_header_lua54};
pub use lifter::lift_proto_lua54;
pub use opcodes::{OpMode54, Opcode54, RawInstruction54};
pub use validator::validate_chunk_lua54;

/// Lua 5.4 dialect handler.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lua54Dialect;

impl Dialect for Lua54Dialect {
    fn name(&self) -> &'static str {
        "lua5.4"
    }

    fn description(&self) -> &'static str {
        "Official stock Lua 5.4.0 through 5.4.8 bytecode format"
    }

    fn detect(&self, bytes: &[u8]) -> Option<DetectionResult> {
        detect_lua54(bytes)
    }

    fn decode_chunk(&self, reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
        decode_chunk_lua54(reader)
    }
}
