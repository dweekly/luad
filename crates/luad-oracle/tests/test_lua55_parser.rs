use std::fs;
use luad_core::diagnostic::Verdict;
use luad_core::Dialect;
use luad_oracle::{compile_and_parse_lua55, compile_source_lua55, verify_truncation_safety};

#[test]
fn test_all_fixtures_lua55_parsing_and_truncation() {
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
        let raw_debug = compile_source_lua55(&source, false)
            .unwrap_or_else(|e| panic!("Failed to compile {fixture_path} with Lua 5.5: {e}"));
        let chunk_debug = compile_and_parse_lua55(&source, false)
            .unwrap_or_else(|e| panic!("Failed to parse {fixture_path} with Lua 5.5: {e}"));

        assert_eq!(chunk_debug.dialect, "lua5.5");
        assert_eq!(chunk_debug.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_debug.byte_length, raw_debug.len());

        // 2. Test stripped chunk (luac -s)
        let raw_stripped = compile_source_lua55(&source, true)
            .unwrap_or_else(|e| panic!("Failed to compile stripped {fixture_path} with Lua 5.5: {e}"));
        let chunk_stripped = compile_and_parse_lua55(&source, true)
            .unwrap_or_else(|e| panic!("Failed to parse stripped {fixture_path} with Lua 5.5: {e}"));

        assert_eq!(chunk_stripped.dialect, "lua5.5");
        assert_eq!(chunk_stripped.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_stripped.byte_length, raw_stripped.len());

        // 3. Truncation safety across every byte boundary
        verify_truncation_safety(&raw_debug);
        verify_truncation_safety(&raw_stripped);
    }
}

#[test]
fn test_lua55_string_reuse_table() {
    // String reuse: "repeated_name" occurs multiple times across locals, upvalues, and table keys
    let source = r#"
        local repeated_name = "hello"
        local function f()
            local repeated_name = "hello"
            return repeated_name
        end
        return repeated_name, f()
    "#;

    let chunk = compile_and_parse_lua55(source, false).expect("parse failed");
    assert_eq!(chunk.dialect, "lua5.5");
    assert_eq!(chunk.verdict, Verdict::ValidForParser);
}

#[test]
fn test_lua55_corrupted_header() {
    let source = "return 42";
    let mut raw = compile_source_lua55(source, false).expect("compilation failed");

    // Corrupt signature
    raw[0] = b'Z';
    let dialect = luad_dialect_lua55::Lua55Dialect;
    let mut reader = luad_core::SafeReader::new(&raw);
    assert!(dialect.decode_chunk(&mut reader).is_err());
}
