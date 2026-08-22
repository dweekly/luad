use std::fs;
use luad_core::diagnostic::Verdict;
use luad_core::Dialect;
use luad_oracle::{compile_and_parse_lua54, compile_source_lua54, verify_byte_accounting, verify_truncation_safety};

#[test]
fn test_all_fixtures_byte_accounting_and_validation() {
    let fixture_files = [
        "../../tests/fixtures/hello.lua",
        "../../tests/fixtures/control_flow.lua",
        "../../tests/fixtures/closures.lua",
        "../../tests/fixtures/tables.lua",
        "../../tests/fixtures/numerics.lua",
    ];

    for fixture_path in fixture_files {
        let source = fs::read_to_string(fixture_path)
            .unwrap_or_else(|_| panic!("Failed to read {fixture_path}"));

        // 1. Test normal debug chunk
        let raw_debug = compile_source_lua54(&source, false)
            .unwrap_or_else(|e| panic!("Failed to compile {fixture_path}: {e}"));
        let chunk_debug = compile_and_parse_lua54(&source, false)
            .unwrap_or_else(|e| panic!("Failed to parse {fixture_path}: {e}"));

        assert_eq!(chunk_debug.dialect, "lua5.4");
        assert_eq!(chunk_debug.verdict, Verdict::ValidForParser);
        verify_byte_accounting(&chunk_debug, &raw_debug);

        // 2. Test stripped chunk (luac -s)
        let raw_stripped = compile_source_lua54(&source, true)
            .unwrap_or_else(|e| panic!("Failed to compile stripped {fixture_path}: {e}"));
        let chunk_stripped = compile_and_parse_lua54(&source, true)
            .unwrap_or_else(|e| panic!("Failed to parse stripped {fixture_path}: {e}"));

        assert_eq!(chunk_stripped.dialect, "lua5.4");
        assert_eq!(chunk_stripped.verdict, Verdict::ValidForParser);
        verify_byte_accounting(&chunk_stripped, &raw_stripped);

        // 3. Test truncation safety (every byte boundary from 0..len must not panic)
        verify_truncation_safety(&raw_debug);
        verify_truncation_safety(&raw_stripped);
    }
}

#[test]
fn test_numeric_constant_fidelity() {
    let source = "local a = 123456789012345; local b = 3.141592653589793; return a, b";
    let chunk = compile_and_parse_lua54(source, false).expect("parse failed");

    assert!(chunk.main_proto.constants.len() >= 2);
    let mut found_int = false;
    let mut found_float = false;

    for c in &chunk.main_proto.constants {
        match &c.value {
            luad_core::ConstantValue::Integer { val, .. } if *val == 123456789012345 => {
                found_int = true;
            }
            luad_core::ConstantValue::Float { val, .. } if (*val - 3.141592653589793).abs() < 1e-12 => {
                found_float = true;
            }
            _ => {}
        }
    }

    assert!(found_int, "Expected integer constant 123456789012345");
    assert!(found_float, "Expected float constant 3.141592653589793");
}

#[test]
fn test_corrupted_header_detection() {
    let source = "return 42";
    let mut raw = compile_source_lua54(source, false).expect("compilation failed");

    // Corrupt signature
    raw[0] = b'X';
    let dialect = luad_dialect_lua54::Lua54Dialect;
    let mut reader = luad_core::SafeReader::new(&raw);
    assert!(dialect.decode_chunk(&mut reader).is_err());

    // Corrupt version
    raw[0] = 0x1b;
    raw[4] = 0x55; // Lua 5.5 version byte passed to 5.4 reader
    let mut reader = luad_core::SafeReader::new(&raw);
    assert!(dialect.decode_chunk(&mut reader).is_err());
}

#[test]
fn test_trailing_bytes_detection() {
    let source = "return 'test'";
    let mut raw = compile_source_lua54(source, false).expect("compilation failed");
    raw.extend_from_slice(b"\xde\xad\xbe\xef");

    let dialect = luad_dialect_lua54::Lua54Dialect;
    let mut reader = luad_core::SafeReader::with_options(
        &raw,
        0,
        luad_core::ResourceLimits::default(),
        luad_core::ParseMode::Permissive,
    );
    let chunk = dialect.decode_chunk(&mut reader).expect("permissive decode failed");

    assert_eq!(chunk.trailing_bytes.as_deref(), Some("deadbeef"));
    assert!(chunk.diagnostics.iter().any(|d| d.code == "L54-CHUNK-001"));
}

#[test]
fn test_string_with_null_bytes() {
    let source = "local s = \"hello\\0world\\0!\"; return s";
    let chunk = compile_and_parse_lua54(source, false).expect("parse failed");

    let mut found_null_string = false;
    for c in &chunk.main_proto.constants {
        if let luad_core::ConstantValue::ShortString(s) = &c.value {
            if s.raw_bytes == b"hello\0world\0!" {
                found_null_string = true;
                assert_eq!(s.display, r"hello\x00world\x00!");
            }
        }
    }
    assert!(found_null_string, "Expected string with embedded null bytes");
}

