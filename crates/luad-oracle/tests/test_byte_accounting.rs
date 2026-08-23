//! Comprehensive byte accounting and lossless serialization test suite across all dialects and fixtures.

use luad_core::diagnostic::Verdict;
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_oracle::get_fixture_bytes;

#[test]
fn test_all_50_fixtures_byte_accounting_and_lossless_serde() {
    let dialects: &[(&str, &str, Box<dyn Dialect>)] = &[
        (
            "lua5.1",
            "lua51",
            Box::new(luad_dialect_lua51::Lua51Dialect::default()),
        ),
        (
            "lua5.2",
            "lua52",
            Box::new(luad_dialect_lua52::Lua52Dialect),
        ),
        (
            "lua5.3",
            "lua53",
            Box::new(luad_dialect_lua53::Lua53Dialect),
        ),
        (
            "lua5.4",
            "lua54",
            Box::new(luad_dialect_lua54::Lua54Dialect),
        ),
        (
            "lua5.5",
            "lua55",
            Box::new(luad_dialect_lua55::Lua55Dialect),
        ),
    ];

    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for (dialect_name, _dir_name, dialect_impl) in dialects {
        for fixture_name in fixtures {
            for is_stripped in [false, true] {
                let raw_bytes = get_fixture_bytes(dialect_name, fixture_name, is_stripped)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Failed to load fixture '{fixture_name}' for {dialect_name} (stripped={is_stripped}): {e}"
                        )
                    });

                let mut reader = SafeReader::with_options(
                    &raw_bytes,
                    0,
                    ResourceLimits::default(),
                    ParseMode::Strict,
                );

                let chunk = dialect_impl
                    .decode_chunk(&mut reader)
                    .unwrap_or_else(|e| {
                        panic!(
                            "Failed to decode chunk '{fixture_name}' for {dialect_name} (stripped={is_stripped}): {e:?}"
                        )
                    });

                // 1. Verify byte length accounting
                assert_eq!(
                    chunk.byte_length,
                    raw_bytes.len(),
                    "Byte length mismatch for {dialect_name} '{fixture_name}' (stripped={is_stripped})"
                );
                assert_eq!(
                    chunk.verdict,
                    Verdict::ValidForParser,
                    "Expected ValidForParser verdict for {dialect_name} '{fixture_name}'"
                );

                // 2. Verify lossless JSON serialization round-trip
                let serialized_json =
                    serde_json::to_string(&chunk).expect("JSON serialization must succeed");
                let deserialized_chunk: Chunk = serde_json::from_str(&serialized_json)
                    .expect("JSON deserialization must succeed");

                assert_eq!(
                    chunk, deserialized_chunk,
                    "Lossless serialization round-trip failed for {dialect_name} '{fixture_name}'"
                );
            }
        }
    }
}
