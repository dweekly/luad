//! Lua 5.1 header detector and decoder.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory};
use luad_core::dialect::DetectionResult;
use luad_core::id::StableId;
use luad_core::model::Header;
use luad_core::provenance::{Confidence, SourceLocation};
use luad_core::reader::SafeReader;

pub const LUA_SIGNATURE: &[u8; 4] = b"\x1bLua";
pub const LUAC_VERSION_51: u8 = 0x51;
pub const LUAC_FORMAT_STOCK: u8 = 0;

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
pub fn parse_header_lua51(reader: &mut SafeReader) -> Result<Header, Diagnostic> {
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
    let _endianness = reader.read_u8()?;

    // 5. sizeof(int)
    let sizeof_int = reader.read_u8()?;

    // 6. sizeof(size_t) -- governs the width of every string length field in the chunk.
    let sizeof_sizet = reader.read_u8()?;
    crate::chunk::set_sizet_width(sizeof_sizet);

    // 7. sizeof(Instruction)
    let instruction_size = reader.read_u8()?;

    // 8. sizeof(lua_Number)
    let lua_number_size = reader.read_u8()?;

    // 9. Integral flag
    let _integral = reader.read_u8()?;

    let header_bytes = reader.slice_from_cursor(start_cursor)?;
    let loc = SourceLocation::new(start_pos, header_bytes);

    Ok(Header {
        signature,
        version,
        format,
        luac_data: String::new(),
        instruction_size,
        lua_integer_size: sizeof_int,
        lua_number_size,
        luac_int: 0,
        luac_num: 0.0,
        source: loc,
    })
}
