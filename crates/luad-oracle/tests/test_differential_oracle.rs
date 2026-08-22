//! Canonical differential oracle test suite comparing field-by-field against official `luac -l -l`.

use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::Lua54Dialect;
use luad_dialect_lua55::Lua55Dialect;
use luad_oracle::{
    assert_chunk_matches_luac, compile_source_lua54, compile_source_lua55, dump_source_luac,
    load_source_fixture, require_luac51, require_luac52, require_luac53, require_luac54,
    require_luac55,
};

const TEST_SOURCES: &[(&str, &str)] = &[
    (
        "simple_arithmetic",
        "local a = 10\nlocal b = 20\nreturn a + b * 2",
    ),
    (
        "closures_and_upvalues",
        "local x = 100\nlocal function outer(a)\n  local b = a + 1\n  return function(c) return x + b + c end\nend\nreturn outer(5)(10)",
    ),
    (
        "control_flow_loops",
        "local sum = 0\nfor i = 1, 10 do\n  if i % 2 == 0 then\n    sum = sum + i\n  end\nend\nreturn sum",
    ),
    (
        "table_operations",
        "local t = { x = 1, y = 2, [3] = \"three\" }\nt.z = t.x + t.y\nreturn t",
    ),
    (
        "numerics_and_constants",
        "local i = 9223372036854775807\nlocal f = 3.141592653589793\nlocal s = \"hello\\0world\"\nreturn i, f, s",
    ),
];

#[test]
fn test_canonical_differential_oracle_lua54() {
    let luac_path = require_luac54();
    let dialect = Lua54Dialect;

    // Test synthetic test cases
    for (name, source) in TEST_SOURCES {
        let raw_bytes = compile_source_lua54(source, false)
            .unwrap_or_else(|e| panic!("Failed to compile '{name}' with luac 5.4: {e}"));
        let mut reader =
            SafeReader::with_options(&raw_bytes, 0, ResourceLimits::default(), ParseMode::Strict);
        let chunk = dialect
            .decode_chunk(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode '{name}' with luad 5.4: {e:?}"));

        let luac_dump = dump_source_luac(&luac_path, source)
            .unwrap_or_else(|e| panic!("Failed to dump '{name}' with luac 5.4: {e}"));

        assert_chunk_matches_luac(&chunk, &luac_dump);
    }

    // Test named fixtures
    for fixture in &["hello", "control_flow", "closures", "tables", "numerics"] {
        if let Ok(source) = load_source_fixture(fixture) {
            let raw_bytes = compile_source_lua54(&source, false).unwrap_or_else(|e| {
                panic!("Failed to compile fixture '{fixture}' with luac 5.4: {e}")
            });
            let mut reader = SafeReader::with_options(
                &raw_bytes,
                0,
                ResourceLimits::default(),
                ParseMode::Strict,
            );
            let chunk = dialect.decode_chunk(&mut reader).unwrap_or_else(|e| {
                panic!("Failed to decode fixture '{fixture}' with luad 5.4: {e:?}")
            });

            let luac_dump = dump_source_luac(&luac_path, &source).unwrap_or_else(|e| {
                panic!("Failed to dump fixture '{fixture}' with luac 5.4: {e}")
            });

            assert_chunk_matches_luac(&chunk, &luac_dump);
        }
    }
}

#[test]
fn test_canonical_differential_oracle_lua55() {
    let luac_path = require_luac55();
    let dialect = Lua55Dialect;

    // Test synthetic test cases
    for (name, source) in TEST_SOURCES {
        let raw_bytes = compile_source_lua55(source, false)
            .unwrap_or_else(|e| panic!("Failed to compile '{name}' with luac 5.5: {e}"));
        let mut reader =
            SafeReader::with_options(&raw_bytes, 0, ResourceLimits::default(), ParseMode::Strict);
        let chunk = dialect
            .decode_chunk(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode '{name}' with luad 5.5: {e:?}"));

        let luac_dump = dump_source_luac(&luac_path, source)
            .unwrap_or_else(|e| panic!("Failed to dump '{name}' with luac 5.5: {e}"));

        assert_chunk_matches_luac(&chunk, &luac_dump);
    }

    // Test named fixtures
    for fixture in &["hello", "control_flow", "closures", "tables", "numerics"] {
        if let Ok(source) = load_source_fixture(fixture) {
            let raw_bytes = compile_source_lua55(&source, false).unwrap_or_else(|e| {
                panic!("Failed to compile fixture '{fixture}' with luac 5.5: {e}")
            });
            let mut reader = SafeReader::with_options(
                &raw_bytes,
                0,
                ResourceLimits::default(),
                ParseMode::Strict,
            );
            let chunk = dialect.decode_chunk(&mut reader).unwrap_or_else(|e| {
                panic!("Failed to decode fixture '{fixture}' with luad 5.5: {e:?}")
            });

            let luac_dump = dump_source_luac(&luac_path, &source).unwrap_or_else(|e| {
                panic!("Failed to dump fixture '{fixture}' with luac 5.5: {e}")
            });

            assert_chunk_matches_luac(&chunk, &luac_dump);
        }
    }
}

#[test]
fn test_canonical_differential_oracle_lua53() {
    let luac_path = require_luac53();
    let dialect = luad_dialect_lua53::Lua53Dialect;

    for (name, source) in TEST_SOURCES {
        let raw_bytes = luad_oracle::compile_source_lua53(source, false)
            .unwrap_or_else(|e| panic!("Failed to compile '{name}' with luac 5.3: {e}"));
        let mut reader =
            SafeReader::with_options(&raw_bytes, 0, ResourceLimits::default(), ParseMode::Strict);
        let chunk = dialect
            .decode_chunk(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode '{name}' with luad 5.3: {e:?}"));

        let luac_dump = dump_source_luac(&luac_path, source)
            .unwrap_or_else(|e| panic!("Failed to dump '{name}' with luac 5.3: {e}"));

        assert_chunk_matches_luac(&chunk, &luac_dump);
    }
}

#[test]
fn test_canonical_differential_oracle_lua52() {
    let luac_path = require_luac52();
    let dialect = luad_dialect_lua52::Lua52Dialect;

    for (name, source) in TEST_SOURCES {
        let raw_bytes = luad_oracle::compile_source_lua52(source, false)
            .unwrap_or_else(|e| panic!("Failed to compile '{name}' with luac 5.2: {e}"));
        let mut reader =
            SafeReader::with_options(&raw_bytes, 0, ResourceLimits::default(), ParseMode::Strict);
        let chunk = dialect
            .decode_chunk(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode '{name}' with luad 5.2: {e:?}"));

        let luac_dump = dump_source_luac(&luac_path, source)
            .unwrap_or_else(|e| panic!("Failed to dump '{name}' with luac 5.2: {e}"));

        assert_chunk_matches_luac(&chunk, &luac_dump);
    }
}

#[test]
fn test_canonical_differential_oracle_lua51() {
    let luac_path = require_luac51();
    let dialect = luad_dialect_lua51::Lua51Dialect;

    for (name, source) in TEST_SOURCES {
        let raw_bytes = luad_oracle::compile_source_lua51(source, false)
            .unwrap_or_else(|e| panic!("Failed to compile '{name}' with luac 5.1: {e}"));
        let mut reader =
            SafeReader::with_options(&raw_bytes, 0, ResourceLimits::default(), ParseMode::Strict);
        let chunk = dialect
            .decode_chunk(&mut reader)
            .unwrap_or_else(|e| panic!("Failed to decode '{name}' with luad 5.1: {e:?}"));

        let luac_dump = dump_source_luac(&luac_path, source)
            .unwrap_or_else(|e| panic!("Failed to dump '{name}' with luac 5.1: {e}"));

        assert_chunk_matches_luac(&chunk, &luac_dump);
    }
}
