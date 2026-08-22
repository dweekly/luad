use std::fs;
use std::path::Path;
use luad_oracle::{compile_source_lua54, verify_byte_accounting, verify_truncation_safety, compile_and_parse_lua54};
use luad_core::diagnostic::Verdict;

#[test]
fn test_all_fixtures_byte_accounting_and_validation() {
    let fixture_files = [
        "tests/fixtures/hello.lua",
        "tests/fixtures/control_flow.lua",
        "tests/fixtures/closures.lua",
        "tests/fixtures/tables.lua",
        "tests/fixtures/numerics.lua",
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
