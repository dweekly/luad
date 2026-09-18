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
        let diag = Diagnostic::error(
            "L55-HEADER-003",
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
    if sizeof_int != 4 {
        let diag = Diagnostic::error(
            "L55-HEADER-005",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported sizeof(int): expected 4, found {sizeof_int}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[sizeof_int]))
        .with_suggested_action("Ensure bytecode was compiled with 4-byte integers");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let test_int = reader.read_i32_le()?;
    if test_int != -0x5678 {
        let diag = Diagnostic::error(
            "L55-HEADER-006",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Invalid int test integer: expected -0x5678, found {test_int}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 4,
            &test_int.to_le_bytes(),
        ))
        .with_suggested_action("Check chunk byte order or corruption in int canary");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 6. checknum(Instruction): sizeof(Instruction) (1) + Instruction test value (4)
    let sizeof_inst = reader.read_u8()?;
    if sizeof_inst != 4 {
        let diag = Diagnostic::error(
            "L55-HEADER-007",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported Instruction size: expected 4, found {sizeof_inst}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[sizeof_inst]))
        .with_suggested_action("Verify instruction width is 4 bytes");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let test_inst = reader.read_u32_le()?;
    if test_inst != 0x12345678 {
        let diag = Diagnostic::error(
            "L55-HEADER-008",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Invalid Instruction test value: expected 0x12345678, found 0x{test_inst:x}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 4,
            &test_inst.to_le_bytes(),
        ))
        .with_suggested_action("Check chunk byte order or corruption in instruction canary");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 7. checknum(lua_Integer): sizeof(lua_Integer) (1) + lua_Integer test value (8)
    let sizeof_lua_int = reader.read_u8()?;
    if sizeof_lua_int != 8 {
        let diag = Diagnostic::error(
            "L55-HEADER-009",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported lua_Integer size: expected 8, found {sizeof_lua_int}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 1,
            &[sizeof_lua_int],
        ))
        .with_suggested_action(
            "64-bit integer Lua 5.5 is supported; 32-bit integer is not supported",
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let luac_int = reader.read_i64_le()?;
    if luac_int != -0x5678 {
        let diag = Diagnostic::error(
            "L55-HEADER-010",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Invalid lua_Integer test integer: expected -0x5678, found {luac_int}"),
        )
        .with_source(SourceLocation::new(
            reader.position() - 8,
            &luac_int.to_le_bytes(),
        ))
        .with_suggested_action("Check chunk byte order or corruption in lua_Integer canary");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    // 8. checknum(lua_Number): sizeof(lua_Number) (1) + lua_Number test value (8)
    let sizeof_num = reader.read_u8()?;
    if sizeof_num != 8 {
        let diag = Diagnostic::error(
            "L55-HEADER-011",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Unsupported lua_Number size: expected 8, found {sizeof_num}"),
        )
        .with_source(SourceLocation::new(reader.position() - 1, &[sizeof_num]))
        .with_suggested_action("Verify that lua_Number width is 8 bytes (double)");
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let luac_num = reader.read_f64_le()?;
    if (luac_num - (-370.5)).abs() > f64::EPSILON {
        let diag = Diagnostic::error(
            "L55-HEADER-012",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!("Invalid lua_Number test float: expected -370.5, found {luac_num}"),
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
        instruction_size: sizeof_inst,
        lua_integer_size: sizeof_lua_int,
        sizeof_sizet: 0,
        lua_number_size: sizeof_num,
        luac_int,
        luac_num,
        source: loc,
    })
}
