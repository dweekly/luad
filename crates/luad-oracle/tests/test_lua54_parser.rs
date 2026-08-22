use luad_core::diagnostic::Verdict;
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::Lua54Dialect;
use luad_oracle::{get_fixture_bytes, verify_byte_accounting, verify_truncation_safety};

#[test]
fn test_all_fixtures_byte_accounting_and_validation() {
    let fixture_names = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixture_names {
        // 1. Test normal debug chunk
        let raw_debug = get_fixture_bytes("lua5.4", fixture_name, false)
            .unwrap_or_else(|e| panic!("Failed to get debug fixture '{fixture_name}': {e:?}"));
        let mut reader_debug = SafeReader::new(&raw_debug);
        let chunk_debug = luad_dialect_lua54::decode_chunk_lua54(&mut reader_debug)
            .unwrap_or_else(|e| panic!("Failed to parse debug fixture '{fixture_name}': {e:?}"));

        assert_eq!(chunk_debug.dialect, "lua5.4");
        assert_eq!(chunk_debug.verdict, Verdict::ValidForParser);
        verify_byte_accounting(&chunk_debug, &raw_debug);

        // 2. Test stripped chunk (luac -s)
        let raw_stripped = get_fixture_bytes("lua5.4", fixture_name, true)
            .unwrap_or_else(|e| panic!("Failed to get stripped fixture '{fixture_name}': {e:?}"));
        let mut reader_stripped = SafeReader::new(&raw_stripped);
        let chunk_stripped = luad_dialect_lua54::decode_chunk_lua54(&mut reader_stripped)
            .unwrap_or_else(|e| panic!("Failed to parse stripped fixture '{fixture_name}': {e:?}"));

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
    let raw_bytes = get_fixture_bytes("lua5.4", "numerics", false).expect("get fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("parse failed");

    assert!(!chunk.main_proto.constants.is_empty());
    let mut found_int = false;
    let mut found_float = false;

    for c in &chunk.main_proto.constants {
        match &c.value {
            luad_core::ConstantValue::Integer { val, .. } if *val == 9223372036854775807 => {
                found_int = true;
            }
            luad_core::ConstantValue::Float { val, .. }
                if (*val - 3.141592653589793).abs() < 1e-12 =>
            {
                found_float = true;
            }
            _ => {}
        }
    }

    assert!(found_int, "Expected max_int constant in numerics fixture");
    assert!(
        found_float,
        "Expected float constant 3.14159... in numerics fixture"
    );
}

#[test]
fn test_string_with_null_bytes() {
    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("get fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("parse failed");
    assert_eq!(chunk.verdict, Verdict::ValidForParser);
}

#[test]
fn test_corrupted_header_detection() {
    let mut raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("get fixture failed");
    raw_bytes[0] = b'X'; // Corrupt signature byte

    let dialect = Lua54Dialect;
    let mut reader = SafeReader::new(&raw_bytes);
    let result = dialect.decode_chunk(&mut reader);
    assert!(result.is_err());
}

#[test]
fn test_trailing_bytes_detection() {
    let mut raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("get fixture failed");
    raw_bytes.extend_from_slice(b"DEADBEEF_EXTRA_DATA");

    let dialect = Lua54Dialect;
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = dialect
        .decode_chunk(&mut reader)
        .expect("Should parse with warning");

    assert!(chunk.trailing_bytes.is_some());
    assert_eq!(
        chunk.trailing_bytes.as_deref(),
        Some("44454144424545465f45585452415f44415441")
    );
    assert!(chunk.diagnostics.iter().any(|d| d.code == "L54-CHUNK-001"));
}
