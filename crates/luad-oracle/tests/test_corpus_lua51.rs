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
fn test_lua51_lnum32_fixture_regression() {
    let root = luad_oracle::find_workspace_root();
    let lnum_path = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");
    let lnum_bytes = std::fs::read(&lnum_path).expect("Read lnum32 fixture");

    let mut reader = SafeReader::new(&lnum_bytes);
    let chunk = decode_chunk_lua51_with_profile(&mut reader, Lua51Profile::Lnum32)
        .expect("Decode LNUM32 fixture");

    assert_eq!(chunk.verdict, Verdict::ValidForParser);
    assert_eq!(chunk.dialect, "lua5.1-lnum32");
    assert_eq!(chunk.header.lua_integer_size, 4);
    assert_eq!(chunk.header.sizeof_sizet, 4);

    // 32-bit stock fixture
    let stock32_path = root.join("tests/fixtures/precompiled/lua51_32bit/hello.luac");
    let stock32_bytes = std::fs::read(&stock32_path).expect("Read stock32 fixture");

    let mut reader32 = SafeReader::new(&stock32_bytes);
    let chunk32 = decode_chunk_lua51_with_profile(&mut reader32, Lua51Profile::Stock32)
        .expect("Decode stock32 fixture");

    assert_eq!(chunk32.verdict, Verdict::ValidForParser);
    assert_eq!(chunk32.header.sizeof_sizet, 4);
}

#[test]
fn test_negative_control_stock_fixtures_rejected_by_lnum32() {
    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixtures {
        for is_stripped in [false, true] {
            let raw_bytes = get_fixture_bytes("lua5.1", fixture_name, is_stripped)
                .unwrap_or_else(|e| panic!("Failed to load fixture {fixture_name}: {e}"));

            let mut reader = SafeReader::new(&raw_bytes);
            let res = decode_chunk_lua51_with_profile(&mut reader, Lua51Profile::Lnum32);
            assert!(
                res.is_err(),
                "Stock fixture '{fixture_name}' MUST be rejected under LNUM32 profile"
            );
            let diag = res.unwrap_err();
            assert_eq!(diag.code, "L51-HEADER-003");
            assert!(diag
                .message
                .contains("Invalid lua_Integer size 0 for LNUM32"));
        }
    }
}

#[test]
fn test_negative_control_lnum32_fixture_rejected_by_stock() {
    let root = luad_oracle::find_workspace_root();
    let lnum_path = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");
    let lnum_bytes = std::fs::read(&lnum_path).expect("Read lnum32 fixture");

    let mut reader = SafeReader::new(&lnum_bytes);
    let res = decode_chunk_lua51_with_profile(&mut reader, Lua51Profile::Stock);
    assert!(
        res.is_err(),
        "Lnum32 fixture MUST be rejected under Stock profile"
    );
    let diag = res.unwrap_err();
    assert_eq!(diag.code, "L51-HEADER-003");
    assert!(diag.message.contains("lua5.1-lnum32"));
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
