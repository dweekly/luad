//! Lua 5.4 header validation and parsing.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory};
use luad_core::id::StableId;
use luad_core::model::Header;
use luad_core::provenance::{Confidence, SourceLocation};
use luad_core::reader::SafeReader;
use luad_core::DetectionResult;

/// Lua 5.4 format constants.
pub const LUA_SIGNATURE: &[u8; 4] = b"\x1bLua";
pub const LUAC_VERSION_54: u8 = 0x54;
pub const LUAC_FORMAT_STOCK: u8 = 0;
pub const LUAC_DATA_54: &[u8; 6] = b"\x19\x93\r\n\x1a\n";
pub const LUAC_INT_54: i64 = 0x5678;
pub const LUAC_NUM_54: f64 = 370.5;

/// Header detection for Lua 5.4.
#[must_use]
pub fn detect_lua54(bytes: &[u8]) -> Option<DetectionResult> {
    if bytes.len() < 4 || &bytes[0..4] != LUA_SIGNATURE {
        return None;
    }

    if bytes.len() >= 5 && bytes[4] == LUAC_VERSION_54 {
        let format_desc = if bytes.len() >= 6 && bytes[5] == LUAC_FORMAT_STOCK {
            "official stock format"
        } else {
            "custom or non-stock format"
        };
        return Some(DetectionResult {
            dialect: "lua5.4".to_string(),
            confidence: Confidence::Fact,
            evidence: format!(
                "Lua 5.4 signature matched (0x1bLua, version 0x54, {})",
                format_desc
            ),
        });
    }

    None
}

/// Parse and validate Lua 5.4 header.
pub fn parse_header_lua54(reader: &mut SafeReader) -> Result<Header, Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();

    // 1. Signature (4 bytes)
    let sig_bytes = reader.read_exact(4)?;
    if sig_bytes != LUA_SIGNATURE {
        let diag = Diagnostic::error(
            "L54-HEADER-001",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Invalid Lua signature: expected \\x1bLua, found {sig_bytes:?}"),
        )
        .with_source(SourceLocation::new(start_pos, sig_bytes))
        .with_suggested_action("Verify that input is a valid compiled Lua binary chunk");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let signature = String::from_utf8_lossy(sig_bytes).to_string();

    // 2. Version byte (0x54)
    let version = reader.read_u8()?;
    if version != LUAC_VERSION_54 {
        let diag = Diagnostic::error(
            "L54-HEADER-002",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Invalid version byte: expected 0x54 (Lua 5.4), found 0x{version:02x}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[version]))
        .with_suggested_action("Use appropriate dialect or inspect chunk with auto-detection");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 3. Format byte (0)
    let format = reader.read_u8()?;
    if format != LUAC_FORMAT_STOCK {
        let diag = Diagnostic::warning(
            "L54-HEADER-003",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Non-standard format byte: expected 0 (stock), found {format}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[format]));
        reader.record_diagnostic(diag)?;
    }

    // 4. LUAC_DATA validation sequence (6 bytes)
    let luac_data_bytes = reader.read_exact(6)?;
    if luac_data_bytes != LUAC_DATA_54 {
        let diag = Diagnostic::error(
            "L54-HEADER-004",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            "Corrupt LUAC_DATA sequence in header",
        )
        .with_source(SourceLocation::new(reader.position() - 6, luac_data_bytes));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let luac_data = hex::encode(luac_data_bytes);

    // 5. Instruction size (1 byte, expected 4)
    let instruction_size = reader.read_u8()?;
    if instruction_size != 4 {
        let diag = Diagnostic::error(
            "L54-HEADER-005",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported instruction size: expected 4, found {instruction_size}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 1,
            &[instruction_size],
        ));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 6. lua_Integer size (1 byte, expected 8)
    let lua_integer_size = reader.read_u8()?;
    if lua_integer_size != 8 {
        let diag = Diagnostic::error(
            "L54-HEADER-006",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported lua_Integer size: expected 8, found {lua_integer_size}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 1,
            &[lua_integer_size],
        ));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 7. lua_Number size (1 byte, expected 8)
    let lua_number_size = reader.read_u8()?;
    if lua_number_size != 8 {
        let diag = Diagnostic::error(
            "L54-HEADER-007",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported lua_Number size: expected 8, found {lua_number_size}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 1,
            &[lua_number_size],
        ));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 8. LUAC_INT test integer (8 bytes, expected 0x5678)
    let luac_int = reader.read_i64_le()?;
    if luac_int != LUAC_INT_54 {
        let diag = Diagnostic::error(
            "L54-HEADER-008",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Invalid LUAC_INT test integer: expected 0x5678, found 0x{luac_int:x}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 8,
            &luac_int.to_le_bytes(),
        ));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 9. LUAC_NUM test float (8 bytes, expected 370.5)
    let luac_num = reader.read_f64_le()?;
    if (luac_num - LUAC_NUM_54).abs() > f64::EPSILON {
        let diag = Diagnostic::error(
            "L54-HEADER-009",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Invalid LUAC_NUM test float: expected 370.5, found {luac_num}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 8,
            &luac_num.to_le_bytes(),
        ));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let raw_header_bytes = reader.slice_from_cursor(start_cursor)?;
    let source = SourceLocation::new(start_pos, raw_header_bytes);

    Ok(Header {
        signature,
        version,
        format,
        luac_data,
        instruction_size,
        lua_integer_size,
        sizeof_sizet: 8,
        lua_number_size,
        luac_int,
        luac_num,
        source,
    })
}
