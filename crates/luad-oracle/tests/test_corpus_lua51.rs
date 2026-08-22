//! Gate L4: Field corpus regression, stock vs LNUM profile identity, and differential oracle tests for Lua 5.1.

use luad_core::diagnostic::Verdict;
use luad_core::reader::SafeReader;
use luad_dialect_lua51::{decode_chunk_lua51_with_profile, Lua51Profile};
use luad_oracle::get_fixture_bytes;

#[test]
fn test_lua51_stock_corpus_regression() {
    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixtures {
        for is_stripped in [false, true] {
            let raw_bytes = get_fixture_bytes("lua5.1", fixture_name, is_stripped)
                .unwrap_or_else(|e| panic!("Failed to load fixture {fixture_name}: {e}"));

            let mut reader = SafeReader::new(&raw_bytes);
            let chunk = decode_chunk_lua51_with_profile(&mut reader, Lua51Profile::Stock)
                .unwrap_or_else(|e| panic!("Failed to decode {fixture_name} (Stock): {e:?}"));

            assert_eq!(
                chunk.verdict,
                Verdict::ValidForParser,
                "Fixture {fixture_name} (stripped={is_stripped}) failed validation under Stock profile"
            );
            assert_eq!(chunk.byte_length, raw_bytes.len());
        }
    }
}

#[test]
fn test_lua51_lnum_corpus_regression() {
    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixtures {
        for is_stripped in [false, true] {
            let raw_bytes = get_fixture_bytes("lua5.1", fixture_name, is_stripped)
                .unwrap_or_else(|e| panic!("Failed to load fixture {fixture_name}: {e}"));

            let mut reader = SafeReader::new(&raw_bytes);
            let chunk = decode_chunk_lua51_with_profile(&mut reader, Lua51Profile::Lnum)
                .unwrap_or_else(|e| panic!("Failed to decode {fixture_name} (Lnum): {e:?}"));

            assert_eq!(
                chunk.verdict,
                Verdict::ValidForParser,
                "Fixture {fixture_name} (stripped={is_stripped}) failed validation under Lnum profile"
            );
            assert_eq!(chunk.byte_length, raw_bytes.len());
        }
    }
}

#[test]
fn test_negative_control_stock_lnum_identity_on_standard_chunks() {
    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixtures {
        for is_stripped in [false, true] {
            let raw_bytes = get_fixture_bytes("lua5.1", fixture_name, is_stripped)
                .unwrap_or_else(|e| panic!("Failed to load fixture {fixture_name}: {e}"));

            let mut reader_stock = SafeReader::new(&raw_bytes);
            let chunk_stock =
                decode_chunk_lua51_with_profile(&mut reader_stock, Lua51Profile::Stock)
                    .expect("Stock decode");

            let mut reader_lnum = SafeReader::new(&raw_bytes);
            let chunk_lnum = decode_chunk_lua51_with_profile(&mut reader_lnum, Lua51Profile::Lnum)
                .expect("Lnum decode");

            assert_eq!(
                chunk_stock, chunk_lnum,
                "Stock and Lnum profiles MUST produce identical ASTs on standard chunk '{fixture_name}' (stripped={is_stripped})"
            );
        }
    }
}

#[test]
fn test_negative_control_corrupted_sizet_chunk_fails() {
    let mut raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    raw_bytes[8] = 3; // Corrupt sizeof(size_t) to 3 (unsupported size)

    let mut reader = SafeReader::new(&raw_bytes);
    let res = decode_chunk_lua51_with_profile(&mut reader, Lua51Profile::Stock);
    assert!(
        res.is_err(),
        "Corrupted sizeof(size_t) must fail validation"
    );
    let diag = res.unwrap_err();
    assert_eq!(diag.code, "L51-HEADER-003");
}
