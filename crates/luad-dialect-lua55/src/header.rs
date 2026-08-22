//! Lua 5.5 header detector and decoder.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory};
use luad_core::dialect::DetectionResult;
use luad_core::id::StableId;
use luad_core::model::Header;
use luad_core::provenance::{Confidence, SourceLocation};
use luad_core::reader::SafeReader;

pub const LUA_SIGNATURE: &[u8; 4] = b"\x1bLua";
pub const LUAC_VERSION_55: u8 = 0x55;
pub const LUAC_FORMAT_STOCK: u8 = 0;
pub const LUAC_DATA_55: &[u8; 6] = b"\x19\x93\r\n\x1a\n";

/// Detect whether the input bytes begin with a valid Lua 5.5 binary signature.
#[must_use]
pub fn detect_lua55(bytes: &[u8]) -> Option<DetectionResult> {
    if bytes.len() < 4 || &bytes[0..4] != LUA_SIGNATURE {
        return None;
    }

    if bytes.len() >= 5 && bytes[4] == LUAC_VERSION_55 {
        let format_desc = if bytes.len() >= 6 && bytes[5] == LUAC_FORMAT_STOCK {
            "official stock format"
        } else {
            "custom or non-stock format"
        };
        return Some(DetectionResult {
            dialect: "lua5.5".to_string(),
            confidence: Confidence::Fact,
            evidence: format!(
                "Lua 5.5 signature matched (0x1bLua, version 0x55, {})",
                format_desc
            ),
        });
    }

    None
}

/// Parse and validate Lua 5.5 chunk header.
pub fn parse_header_lua55(reader: &mut SafeReader) -> Result<Header, Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();

    // 1. Signature
    let sig_bytes = reader.read_exact(4)?;
    if sig_bytes != LUA_SIGNATURE {
        let diag = Diagnostic::error(
            "L55-HEADER-001",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Invalid signature: expected \\x1bLua, found {sig_bytes:?}"),
        )
        .with_source(SourceLocation::new(start_pos, sig_bytes))
        .with_suggested_action("Ensure file is an uncorrupted Lua 5.5 bytecode chunk");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let signature = String::from_utf8_lossy(sig_bytes).to_string();

    // 2. Version
    let version = reader.read_u8()?;
    if version != LUAC_VERSION_55 {
        let diag = Diagnostic::error(
            "L55-HEADER-002",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Version mismatch: expected 0x55 (Lua 5.5), found 0x{version:02x}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[version]))
        .with_suggested_action("Parse with matching dialect decoder");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 3. Format
    let format = reader.read_u8()?;
    if format != LUAC_FORMAT_STOCK {
        let diag = Diagnostic::warning(
            "L55-HEADER-003",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Format mismatch: expected official format 0, found {format}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[format]));
        reader.record_diagnostic(diag)?;
    }

    // 4. LUAC_DATA
    let luac_data_bytes = reader.read_exact(6)?;
    if luac_data_bytes != LUAC_DATA_55 {
        let diag = Diagnostic::error(
            "L55-HEADER-004",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            "Corrupted LUAC_DATA marker in header",
        )
        .with_source(SourceLocation::new(reader.position() - 6, luac_data_bytes));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let luac_data = hex::encode(luac_data_bytes);

    // 5. checknum(int): sizeof(int) (1) + int test value (4)
    let sizeof_int = reader.read_u8()?;
    let _test_int = reader.read_exact(sizeof_int as usize)?;

    // 6. checknum(Instruction): sizeof(Instruction) (1) + Instruction test value (4)
    let sizeof_inst = reader.read_u8()?;
    let _test_inst = reader.read_exact(sizeof_inst as usize)?;

    // 7. checknum(lua_Integer): sizeof(lua_Integer) (1) + lua_Integer test value (8)
    let sizeof_lua_int = reader.read_u8()?;
    let luac_int_bytes = reader.read_exact(sizeof_lua_int as usize)?;
    let luac_int = if sizeof_lua_int == 8 {
        i64::from_le_bytes(luac_int_bytes.try_into().unwrap_or_default())
    } else {
        0
    };

    // 8. checknum(lua_Number): sizeof(lua_Number) (1) + lua_Number test value (8)
    let sizeof_num = reader.read_u8()?;
    let luac_num_bytes = reader.read_exact(sizeof_num as usize)?;
    let luac_num = if sizeof_num == 8 {
        f64::from_le_bytes(luac_num_bytes.try_into().unwrap_or_default())
    } else {
        0.0
    };

    let header_bytes = reader.slice_from_cursor(start_cursor)?;
    let loc = SourceLocation::new(start_pos, header_bytes);

    Ok(Header {
        signature,
        version,
        format,
        luac_data,
        instruction_size: sizeof_inst,
        lua_integer_size: sizeof_lua_int,
        sizeof_sizet: 8,
        lua_number_size: sizeof_num,
        luac_int,
        luac_num,
        source: loc,
    })
}
