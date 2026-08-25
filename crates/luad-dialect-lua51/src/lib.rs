//! Lua 5.1 Dialect Implementation for luad.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

pub mod chunk;
pub mod disasm;
pub mod header;
pub mod lifter;
pub mod opcodes;
pub mod roles;
pub mod validator;

use luad_core::diagnostic::Diagnostic;
use luad_core::dialect::{DetectionResult, Dialect};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;

pub use chunk::{decode_chunk_lua51, decode_chunk_lua51_with_profile};
pub use disasm::{disassemble_proto_lua51, disassemble_proto_lua51_v1};
pub use header::{detect_lua51, parse_header_lua51, ChunkLayout, Lua51Profile};
pub use lifter::lift_proto_lua51;
pub use opcodes::{OpMode51, Opcode51, RawInstruction51, BITRK_51};
pub use roles::{discover_roles_lua51, Lua51PhysicalRole, Lua51RoleFault, Lua51RoleMap};
pub use validator::validate_chunk_lua51;

/// Concrete dialect handler for official Lua 5.1.0 - 5.1.5 bytecode.
#[derive(Debug, Default, Clone, Copy)]
pub struct Lua51Dialect {
    /// Which Lua 5.1 variant to decode. Defaults to stock.
    pub profile: Lua51Profile,
}

impl Dialect for Lua51Dialect {
    fn name(&self) -> &'static str {
        match self.profile {
            Lua51Profile::Lnum32 => "lua5.1-lnum32",
            Lua51Profile::Stock32 => "lua5.1-stock32",
            Lua51Profile::Stock => "lua5.1",
        }
    }

    fn description(&self) -> &'static str {
        match self.profile {
            Lua51Profile::Lnum32 => "Lua 5.1 bytecode with OpenWrt/eLua 32-bit LNUM patch",
            Lua51Profile::Stock32 => "Official stock Lua 5.1 bytecode with 32-bit size_t",
            Lua51Profile::Stock => "Official stock Lua 5.1.0 through 5.1.5 bytecode format",
        }
    }

    fn detect(&self, bytes: &[u8]) -> Option<DetectionResult> {
        let res = detect_lua51(bytes)?;
        match self.profile {
            Lua51Profile::Lnum32 if res.dialect == "lua5.1-lnum32" => Some(res),
            Lua51Profile::Stock if res.dialect == "lua5.1" => Some(res),
            Lua51Profile::Stock32 if res.dialect == "lua5.1" => Some(res),
            _ => None,
        }
    }

    fn decode_chunk(&self, reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
        decode_chunk_lua51_with_profile(reader, self.profile)
    }
}
