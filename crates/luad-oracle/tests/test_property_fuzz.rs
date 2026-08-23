//! Property-based fuzzing and resource bounds testing.

use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua51::Lua51Dialect;
use luad_dialect_lua52::Lua52Dialect;
use luad_dialect_lua53::Lua53Dialect;
use luad_dialect_lua54::Lua54Dialect;
use luad_dialect_lua55::Lua55Dialect;
use luad_oracle::get_fixture_bytes;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn test_arbitrary_bytes_no_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let dialects: [&dyn Dialect; 5] = [
            &Lua51Dialect::default(),
            &Lua52Dialect,
            &Lua53Dialect,
            &Lua54Dialect,
            &Lua55Dialect,
        ];

        for dialect in dialects {
            // Strict mode
            let mut reader_strict = SafeReader::with_options(
                &bytes,
                0,
                ResourceLimits::default(),
                ParseMode::Strict,
            );
            let _ = dialect.decode_chunk(&mut reader_strict);

            // Permissive mode
            let mut reader_perm = SafeReader::with_options(
                &bytes,
                0,
                ResourceLimits::default(),
                ParseMode::Permissive,
            );
            let _ = dialect.decode_chunk(&mut reader_perm);
        }
    }

    #[test]
    fn test_bounded_resource_limits(
        max_bytes in 10usize..100,
        max_depth in 1usize..3,
        mutation_index in 0usize..100,
        mutation_byte in any::<u8>(),
    ) {
        let mut raw = get_fixture_bytes("lua5.4", "closures", false).unwrap();
        if !raw.is_empty() {
            let idx = mutation_index % raw.len();
            raw[idx] = mutation_byte;
        }

        let limits = ResourceLimits {
            max_input_bytes: max_bytes,
            max_nesting_depth: max_depth,
            max_total_prototypes: 10,
            max_instructions_per_proto: 50,
            max_constants_per_proto: 50,
            max_upvalues_per_proto: 20,
            max_string_bytes: 100,
            max_diagnostics: 1000,
        };

        let dialect = Lua54Dialect;
        let mut reader = SafeReader::with_options(
            &raw,
            0,
            limits,
            ParseMode::Permissive,
        );

        // Never panic even with strictly constrained limits and mutated bytes
        let _ = dialect.decode_chunk(&mut reader);
    }
}
