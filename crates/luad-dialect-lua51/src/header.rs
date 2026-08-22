//! Lua 5.1 header detector and decoder.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory};
use luad_core::dialect::DetectionResult;
use luad_core::id::StableId;
use luad_core::model::Header;
use luad_core::provenance::{Confidence, SourceLocation};
use luad_core::reader::SafeReader;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const LUA_SIGNATURE: &[u8; 4] = b"\x1bLua";
pub const LUAC_VERSION_51: u8 = 0x51;
pub const LUAC_FORMAT_STOCK: u8 = 0;

/// Profile selection for Lua 5.1 bytecode parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Lua51Profile {
    /// Official stock 64-bit/32-bit Lua 5.1 (standard constant tags only: 0, 1, 3, 4).
    #[default]
    Stock,
    /// Explicit 32-bit size_t stock profile.
    Stock32,
    /// OpenWrt / eLua LNUM profile with 32-bit integer constant extension (tag 9).
    Lnum,
}

/// Immutable validated chunk layout descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkLayout {
    /// Declared integer width in bytes (4 or 8).
    pub sizeof_int: u8,
    /// Declared size_t width in bytes (4 or 8).
    pub sizeof_sizet: u8,
    /// Declared instruction size in bytes (4).
    pub instruction_size: u8,
    /// Declared lua_Number size in bytes (4 or 8).
    pub lua_number_size: u8,
    /// Declared endianness (1 = Little-Endian, 0 = Big-Endian).
    pub endianness: u8,
    /// Declared integral flag (0 = floating-point VM, 1 = integer VM).
    pub integral_flag: u8,
    /// Selected dialect profile.
    pub profile: Lua51Profile,
}

impl ChunkLayout {
    /// Validate declared layout fields against architectural bounds and profile rules.
    pub fn validate(
        sizeof_int: u8,
        sizeof_sizet: u8,
        instruction_size: u8,
        lua_number_size: u8,
        endianness: u8,
        integral_flag: u8,
        profile: Lua51Profile,
    ) -> Result<Self, String> {
        if sizeof_int != 4 && sizeof_int != 8 {
            return Err(format!(
                "Unsupported sizeof(int): {sizeof_int} (expected 4 or 8)"
            ));
        }
        if sizeof_sizet != 4 && sizeof_sizet != 8 {
            return Err(format!(
                "Unsupported sizeof(size_t): {sizeof_sizet} (expected 4 or 8)"
            ));
        }
        if instruction_size != 4 {
            return Err(format!(
                "Unsupported sizeof(Instruction): {instruction_size} (expected 4)"
            ));
        }
        if lua_number_size != 4 && lua_number_size != 8 {
            return Err(format!(
                "Unsupported sizeof(lua_Number): {lua_number_size} (expected 4 or 8)"
            ));
        }
        if endianness != 1 {
            return Err(format!("Unsupported endianness {endianness}: only Little-Endian (1) is currently supported"));
        }
        if integral_flag > 1 {
            return Err(format!(
                "Invalid integral flag {integral_flag}: expected 0 or 1"
            ));
        }

        Ok(Self {
            sizeof_int,
            sizeof_sizet,
            instruction_size,
            lua_number_size,
            endianness,
            integral_flag,
            profile,
        })
    }
}

/// Detect whether the input bytes begin with a valid Lua 5.1 binary signature.
#[must_use]
pub fn detect_lua51(bytes: &[u8]) -> Option<DetectionResult> {
    if bytes.len() < 4 || &bytes[0..4] != LUA_SIGNATURE {
        return None;
    }

    if bytes.len() >= 5 && bytes[4] == LUAC_VERSION_51 {
        let format_desc = if bytes.len() >= 6 && bytes[5] == LUAC_FORMAT_STOCK {
            "official stock format"
        } else {
            "custom or non-stock format"
        };
        return Some(DetectionResult {
            dialect: "lua5.1".to_string(),
            confidence: Confidence::Fact,
            evidence: format!(
                "Lua 5.1 signature matched (0x1bLua, version 0x51, {})",
                format_desc
            ),
        });
    }

    None
}

/// Parse and validate Lua 5.1 chunk header (12 bytes).
pub fn parse_header_lua51(
    reader: &mut SafeReader,
    profile: Lua51Profile,
) -> Result<(Header, ChunkLayout), Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();

    // 1. Signature
    let sig_bytes = reader.read_exact(4)?;
    if sig_bytes != LUA_SIGNATURE {
        let diag = Diagnostic::error(
            "L51-HEADER-001",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Invalid signature: expected \\x1bLua, found {sig_bytes:?}"),
        )
        .with_source(SourceLocation::new(start_pos, sig_bytes));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let signature = String::from_utf8_lossy(sig_bytes).to_string();

    // 2. Version
    let version = reader.read_u8()?;
    if version != LUAC_VERSION_51 {
        let diag = Diagnostic::error(
            "L51-HEADER-002",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Version mismatch: expected 0x51 (Lua 5.1), found 0x{version:02x}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[version]));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 3. Format
    let format = reader.read_u8()?;

    // 4. Endianness
    let endianness = reader.read_u8()?;

    // 5. sizeof(int)
    let sizeof_int = reader.read_u8()?;

    // 6. sizeof(size_t) -- governs the width of every string length field in the chunk.
    let sizeof_sizet = reader.read_u8()?;

    // 7. sizeof(Instruction)
    let instruction_size = reader.read_u8()?;

    // 8. sizeof(lua_Number)
    let lua_number_size = reader.read_u8()?;

    // 9. Integral flag
    let integral_flag = reader.read_u8()?;

    let layout = ChunkLayout::validate(
        sizeof_int,
        sizeof_sizet,
        instruction_size,
        lua_number_size,
        endianness,
        integral_flag,
        profile,
    )
    .map_err(|msg| {
        Diagnostic::error(
            "L51-HEADER-003",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Chunk layout validation failed: {msg}"),
        )
        .with_source(SourceLocation::new(
            start_pos,
            &[
                endianness,
                sizeof_int,
                sizeof_sizet,
                instruction_size,
                lua_number_size,
                integral_flag,
            ],
        ))
    })?;

    let header_bytes = reader.slice_from_cursor(start_cursor)?;
    let loc = SourceLocation::new(start_pos, header_bytes);

    let header = Header {
        signature,
        version,
        format,
        luac_data: String::new(),
        instruction_size,
        lua_integer_size: sizeof_int,
        sizeof_sizet,
        lua_number_size,
        luac_int: 0,
        luac_num: 0.0,
        source: loc,
    };

    Ok((header, layout))
}
