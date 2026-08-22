use luad_core::diagnostic::Verdict;
use luad_dialect_lua52::Lua52Dialect;
use luad_oracle::{get_fixture_bytes, verify_truncation_safety_for_dialect};

#[test]
fn test_all_fixtures_lua52_parsing_and_truncation() {
    let fixture_names = ["hello", "control_flow", "closures", "tables", "numerics"];

    let dialect = Lua52Dialect;

    for fixture_name in fixture_names {
        // 1. Test normal debug chunk
        let raw_debug = get_fixture_bytes("lua5.2", fixture_name, false)
            .unwrap_or_else(|e| panic!("Failed to get debug fixture '{fixture_name}': {e}"));
        let mut reader_debug = luad_core::reader::SafeReader::new(&raw_debug);
        let chunk_debug = luad_dialect_lua52::decode_chunk_lua52(&mut reader_debug)
            .expect("Parsing debug chunk must succeed");
        assert_eq!(chunk_debug.dialect, "lua5.2");
        assert_eq!(chunk_debug.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_debug.byte_length, raw_debug.len());
        assert!(chunk_debug.diagnostics.is_empty());

        // 2. Test stripped chunk (-s)
        let raw_stripped = get_fixture_bytes("lua5.2", fixture_name, true)
            .unwrap_or_else(|e| panic!("Failed to get stripped fixture '{fixture_name}': {e}"));
        let mut reader_stripped = luad_core::reader::SafeReader::new(&raw_stripped);
        let chunk_stripped = luad_dialect_lua52::decode_chunk_lua52(&mut reader_stripped)
            .expect("Parsing stripped chunk must succeed");
        assert_eq!(chunk_stripped.dialect, "lua5.2");
        assert_eq!(chunk_stripped.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_stripped.byte_length, raw_stripped.len());

        // 3. Truncation safety across every byte
        verify_truncation_safety_for_dialect(&raw_debug, &dialect);
        verify_truncation_safety_for_dialect(&raw_stripped, &dialect);
    }
}
