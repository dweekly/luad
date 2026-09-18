//! Lua 5.3 header detector and decoder.

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory};
use luad_core::dialect::DetectionResult;
use luad_core::id::StableId;
use luad_core::model::Header;
use luad_core::provenance::{Confidence, SourceLocation};
use luad_core::reader::SafeReader;

pub const LUA_SIGNATURE: &[u8; 4] = b"\x1bLua";
pub const LUAC_VERSION_53: u8 = 0x53;
pub const LUAC_FORMAT_STOCK: u8 = 0;
pub const LUAC_DATA_53: &[u8; 6] = b"\x19\x93\r\n\x1a\n";
pub const LUAC_INT_53: i64 = 0x5678;
pub const LUAC_NUM_53: f64 = 370.5;

/// Detect whether the input bytes begin with a valid Lua 5.3 binary signature.
#[must_use]
pub fn detect_lua53(bytes: &[u8]) -> Option<DetectionResult> {
    if bytes.len() < 4 || &bytes[0..4] != LUA_SIGNATURE {
        return None;
    }

    if bytes.len() >= 5 && bytes[4] == LUAC_VERSION_53 {
        let format_desc = if bytes.len() >= 6 && bytes[5] == LUAC_FORMAT_STOCK {
            "official stock format"
        } else {
            "custom or non-stock format"
        };
        return Some(DetectionResult {
            dialect: "lua5.3".to_string(),
            confidence: Confidence::Fact,
            evidence: format!(
                "Lua 5.3 signature matched (0x1bLua, version 0x53, {})",
                format_desc
            ),
        });
    }

    None
}

/// Parse and validate Lua 5.3 chunk header.
pub fn parse_header_lua53(reader: &mut SafeReader) -> Result<Header, Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();

    // 1. Signature
    let sig_bytes = reader.read_exact(4)?;
    if sig_bytes != LUA_SIGNATURE {
        let diag = Diagnostic::error(
            "L53-HEADER-001",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Invalid signature: expected \\x1bLua, found {sig_bytes:?}"),
        )
        .with_source(SourceLocation::new(start_pos, sig_bytes))
        .with_suggested_action("Ensure file is an uncorrupted Lua 5.3 bytecode chunk");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let signature = String::from_utf8_lossy(sig_bytes).to_string();

    // 2. Version
    let version = reader.read_u8()?;
    if version != LUAC_VERSION_53 {
        let diag = Diagnostic::error(
            "L53-HEADER-002",
            DiagnosticCategory::Parse,
            StableId::Chunk,
            format!("Version mismatch: expected 0x53 (Lua 5.3), found 0x{version:02x}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[version]))
        .with_suggested_action("Parse with matching dialect decoder");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 3. Format
    let format = reader.read_u8()?;
    if format != LUAC_FORMAT_STOCK {
        let diag = Diagnostic::error(
            "L53-HEADER-003",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Format mismatch: expected official format 0, found {format}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[format]))
        .with_suggested_action("Verify whether chunk uses a custom compiler or dialect extension");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 4. LUAC_DATA
    let luac_data_bytes = reader.read_exact(6)?;
    if luac_data_bytes != LUAC_DATA_53 {
        let diag = Diagnostic::error(
            "L53-HEADER-004",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            "Corrupted LUAC_DATA marker in header",
        )
        .with_source(SourceLocation::new(reader.position() - 6, luac_data_bytes));
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let luac_data = hex::encode(luac_data_bytes);

    // 5. sizeof(int)
    let sizeof_int = reader.read_u8()?;
    if sizeof_int != 4 {
        let diag = Diagnostic::error(
            "L53-HEADER-005",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported sizeof(int): expected 4, found {sizeof_int}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[sizeof_int]))
        .with_suggested_action(
            "Ensure the bytecode chunk was built for a target architecture with 4-byte integers",
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 6. sizeof(size_t)
    let sizeof_sizet = reader.read_u8()?;
    if sizeof_sizet != 8 && sizeof_sizet != 4 {
        let diag = Diagnostic::error(
            "L53-HEADER-006",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported sizeof(size_t): expected 4 or 8, found {sizeof_sizet}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[sizeof_sizet]))
        .with_suggested_action(
            "Verify that target architecture size_t width is either 32-bit or 64-bit",
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 7. sizeof(Instruction)
    let instruction_size = reader.read_u8()?;
    if instruction_size != 4 {
        let diag = Diagnostic::error(
            "L53-HEADER-007",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported Instruction size: expected 4, found {instruction_size}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 1,
            &[instruction_size],
        ))
        .with_suggested_action(
            "Verify that instruction width is 4 bytes as required by the Lua 5.3 standard",
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 8. sizeof(lua_Integer)
    let lua_integer_size = reader.read_u8()?;
    if lua_integer_size != 8 {
        let diag = Diagnostic::error(
            "L53-HEADER-008",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported lua_Integer size: expected 8, found {lua_integer_size}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 1,
            &[lua_integer_size],
        ))
        .with_suggested_action(
            "64-bit integer Lua 5.3 is supported; 32-bit integer is not supported",
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 9. sizeof(lua_Number)
    let lua_number_size = reader.read_u8()?;
    if lua_number_size != 8 {
        let diag = Diagnostic::error(
            "L53-HEADER-009",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported lua_Number size: expected 8, found {lua_number_size}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 1,
            &[lua_number_size],
        ))
        .with_suggested_action("Verify that lua_Number width is 8 bytes (double)");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 10. LUAC_INT test value
    let luac_int = reader.read_i64_le()?;
    if luac_int != LUAC_INT_53 {
        let diag = Diagnostic::error(
            "L53-HEADER-010",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Endianness mismatch: expected 0x5678, found 0x{luac_int:x}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 8,
            &luac_int.to_le_bytes(),
        ))
        .with_suggested_action("Check chunk byte order; big-endian chunks are not supported");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 11. LUAC_NUM test value
    let luac_num = reader.read_f64_le()?;
    if (luac_num - LUAC_NUM_53).abs() > f64::EPSILON {
        let diag = Diagnostic::error(
            "L53-HEADER-011",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Float format mismatch: expected 370.5, found {luac_num}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 8,
            &luac_num.to_le_bytes(),
        ))
        .with_suggested_action("Verify that float representation matches IEEE-754 double");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let header_bytes = reader.slice_from_cursor(start_cursor)?;
    let loc = SourceLocation::new(start_pos, header_bytes);

    Ok(Header {
        signature,
        version,
        format,
        luac_data,
        instruction_size,
        lua_integer_size,
        sizeof_sizet,
        lua_number_size,
        luac_int,
        luac_num,
        source: loc,
    })
}
