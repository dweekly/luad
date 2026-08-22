use luad_core::diagnostic::Verdict;
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua55::Lua55Dialect;
use luad_oracle::{get_fixture_bytes, verify_truncation_safety_for_dialect};

#[test]
fn test_all_fixtures_lua55_parsing_and_truncation() {
    let fixture_names = ["hello", "control_flow", "closures", "tables", "numerics"];

    let dialect = Lua55Dialect;

    for fixture_name in fixture_names {
        // 1. Test normal debug chunk
        let raw_debug = get_fixture_bytes("lua5.5", fixture_name, false).unwrap_or_else(|e| {
            panic!("Failed to get debug fixture '{fixture_name}' for Lua 5.5: {e:?}")
        });
        let mut reader_debug = SafeReader::new(&raw_debug);
        let chunk_debug =
            luad_dialect_lua55::decode_chunk_lua55(&mut reader_debug).unwrap_or_else(|e| {
                panic!("Failed to parse debug fixture '{fixture_name}' for Lua 5.5: {e:?}")
            });

        assert_eq!(chunk_debug.dialect, "lua5.5");
        assert_eq!(chunk_debug.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_debug.byte_length, raw_debug.len());

        // 2. Test stripped chunk (luac -s)
        let raw_stripped = get_fixture_bytes("lua5.5", fixture_name, true).unwrap_or_else(|e| {
            panic!("Failed to get stripped fixture '{fixture_name}' for Lua 5.5: {e:?}")
        });
        let mut reader_stripped = SafeReader::new(&raw_stripped);
        let chunk_stripped = luad_dialect_lua55::decode_chunk_lua55(&mut reader_stripped)
            .unwrap_or_else(|e| {
                panic!("Failed to parse stripped fixture '{fixture_name}' for Lua 5.5: {e:?}")
            });

        assert_eq!(chunk_stripped.dialect, "lua5.5");
        assert_eq!(chunk_stripped.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_stripped.byte_length, raw_stripped.len());

        // 3. Truncation safety across every byte boundary
        verify_truncation_safety_for_dialect(&raw_debug, &dialect);
        verify_truncation_safety_for_dialect(&raw_stripped, &dialect);
    }
}

#[test]
fn test_lua55_string_reuse_table() {
    let raw_bytes = get_fixture_bytes("lua5.5", "closures", false).expect("get fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua55::decode_chunk_lua55(&mut reader).expect("parse failed");
    assert_eq!(chunk.dialect, "lua5.5");
    assert_eq!(chunk.verdict, Verdict::ValidForParser);
    assert!(!chunk.main_proto.protos.is_empty());
}

#[test]
fn test_lua55_corrupted_header() {
    let mut raw_bytes = get_fixture_bytes("lua5.5", "hello", false).expect("get fixture failed");
    raw_bytes[4] = 0x99; // Corrupted version byte

    let dialect = Lua55Dialect;
    let mut reader = SafeReader::new(&raw_bytes);
    let result = dialect.decode_chunk(&mut reader);
    assert!(result.is_err());
}
