use std::fs;
use luad_core::diagnostic::Verdict;
use luad_dialect_lua51::Lua51Dialect;
use luad_oracle::{compile_and_parse_lua51, compile_source_lua51, find_luac51, verify_truncation_safety_for_dialect};


#[test]
fn test_all_fixtures_lua51_parsing_and_truncation() {
    if find_luac51().is_none() {
        eprintln!("Skipping test: Lua 5.1 compiler not found on system");
        return;
    }

    let fixture_files = [
        "../../tests/fixtures/hello.lua",
        "../../tests/fixtures/control_flow.lua",
        "../../tests/fixtures/closures.lua",
        "../../tests/fixtures/tables.lua",
        "../../tests/fixtures/numerics.lua",
    ];

    let dialect = Lua51Dialect;

    for fixture_path in fixture_files {
        let source = fs::read_to_string(fixture_path)
            .unwrap_or_else(|_| panic!("Failed to read {fixture_path}"));

        // 1. Test normal debug chunk
        let raw_debug = compile_source_lua51(&source, false).expect("Compilation must succeed");
        let chunk_debug = compile_and_parse_lua51(&source, false).expect("Parsing must succeed");
        assert_eq!(chunk_debug.dialect, "lua5.1");
        assert_eq!(chunk_debug.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_debug.byte_length, raw_debug.len());
        assert!(chunk_debug.diagnostics.is_empty());

        // 2. Test stripped chunk (-s)
        let raw_stripped = compile_source_lua51(&source, true).expect("Stripped compilation must succeed");
        let chunk_stripped = compile_and_parse_lua51(&source, true).expect("Parsing stripped chunk must succeed");
        assert_eq!(chunk_stripped.dialect, "lua5.1");
        assert_eq!(chunk_stripped.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_stripped.byte_length, raw_stripped.len());

        // 3. Truncation safety across every byte
        verify_truncation_safety_for_dialect(&raw_debug, &dialect);
        verify_truncation_safety_for_dialect(&raw_stripped, &dialect);
    }
}
