//! Gate L-55: Truthful layout validation and negative controls for Lua 5.5.

use luad_core::diagnostic::Verdict;
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::ConstantValue;
use luad_core::reader::SafeReader;
use luad_dialect_lua55::{decode_chunk_lua55, parse_header_lua55};
use luad_oracle::get_fixture_bytes;

#[test]
fn test_lua55_clean_stock_fixtures_truthful_layout() {
    let fixture_names = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixture_names {
        let raw_debug = get_fixture_bytes("lua5.5", fixture_name, false)
            .unwrap_or_else(|e| panic!("Failed to get debug fixture '{fixture_name}': {e}"));

        // 1. Header parsing directly
        let mut reader = SafeReader::new(&raw_debug);
        let header = parse_header_lua55(&mut reader).expect("stock header must parse");
        assert_eq!(header.signature, "\u{1b}Lua");
        assert_eq!(header.version, 0x55);
        assert_eq!(header.format, 0);
        assert_eq!(header.instruction_size, 4);
        assert_eq!(header.lua_integer_size, 8);
        assert_eq!(
            header.sizeof_sizet, 0,
            "Must not invent sizeof_sizet for 5.5"
        );
        assert_eq!(header.lua_number_size, 8);
        assert_eq!(header.luac_int, -0x5678);
        assert!((header.luac_num - (-370.5)).abs() < f64::EPSILON);
        assert_eq!(header.luac_data, "19930d0a1a0a");

        // 2. Chunk decoding
        let mut reader = SafeReader::new(&raw_debug);
        let chunk = decode_chunk_lua55(&mut reader).expect("stock chunk must decode");
        assert_eq!(chunk.dialect, "lua5.5");
        assert_eq!(chunk.verdict, Verdict::ValidForParser);
        assert!(chunk.diagnostics.is_empty());

        let interp = chunk
            .interpretation
            .expect("interpretation must be recorded");
        assert_eq!(interp.base_dialect, "lua5.5");
        assert_eq!(interp.profile, "lua5.5");
        assert_eq!(
            interp.validated_layout.as_deref(),
            Some("int=4,inst=4,lua_int=8,num=8,endian=1")
        );
        assert!(
            !interp.validated_layout.unwrap().contains("sizet"),
            "Lua 5.5 layout must omit sizet"
        );
    }
}

#[test]
fn test_lua55_negative_control_bad_signature() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    raw[0] = b'X';
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-001");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(0));
}

#[test]
fn test_lua55_negative_control_bad_version() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    raw[4] = 0x54;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-002");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(4));
    assert!(err.message.contains("0x54"));
}

#[test]
fn test_lua55_negative_control_non_stock_format() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    raw[5] = 1;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-003");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(5));
    assert!(err.message.contains("Format mismatch"));
    assert!(err.message.contains('1'));
}

#[test]
fn test_lua55_negative_control_corrupted_luac_data() {
    for offset in 6..12 {
        let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
        raw[offset] ^= 0xff;
        let mut reader = SafeReader::new(&raw);
        let err = parse_header_lua55(&mut reader).unwrap_err();
        assert_eq!(err.code, "L55-HEADER-004");
        assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(6));
    }
}

#[test]
fn test_lua55_negative_control_unsupported_sizeof_int() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    raw[12] = 8;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-005");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(12));
    assert!(err.message.contains("sizeof(int)"));
    assert!(err.message.contains('8'));
}

#[test]
fn test_lua55_negative_control_corrupted_int_canary() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    // Offset 13..17 is int test canary (-0x5678). Mutate byte 13.
    raw[13] ^= 0xff;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-006");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(13));
    assert!(err.message.contains("-0x5678"));
}

#[test]
fn test_lua55_negative_control_unsupported_instruction_size() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    raw[17] = 8;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-007");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(17));
    assert!(err.message.contains("Instruction size"));
    assert!(err.message.contains('8'));
}

#[test]
fn test_lua55_negative_control_corrupted_instruction_canary() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    // Offset 18..22 is Instruction test canary (0x12345678). Mutate byte 18.
    raw[18] ^= 0xff;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-008");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(18));
    assert!(err.message.contains("0x12345678"));
}

#[test]
fn test_lua55_negative_control_unsupported_lua_integer_size() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    raw[22] = 4;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-009");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(22));
    assert!(err.message.contains("lua_Integer size"));
    assert!(err.message.contains('4'));
}

#[test]
fn test_lua55_negative_control_corrupted_lua_integer_canary() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    // Offset 23..31 is lua_Integer test canary (-0x5678). Mutate byte 23.
    raw[23] ^= 0xff;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-010");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(23));
    assert!(err.message.contains("-0x5678"));
}

#[test]
fn test_lua55_negative_control_unsupported_lua_number_size() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    raw[31] = 4;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-011");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(31));
    assert!(err.message.contains("lua_Number size"));
    assert!(err.message.contains('4'));
}

#[test]
fn test_lua55_negative_control_corrupted_lua_number_canary() {
    let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
    // Offset 32..40 is lua_Number test canary (-370.5). Mutate byte 32.
    raw[32] ^= 0xff;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua55(&mut reader).unwrap_err();
    assert_eq!(err.code, "L55-HEADER-012");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(32));
    assert!(err.message.contains("-370.5"));
}

#[test]
fn test_lua55_permissive_mode_fails_closed_on_unsupported_declarations() {
    // Permissive mode must NEVER guess an unsupported layout
    let mutations: [(usize, u8, &str); 8] = [
        (5, 1, "L55-HEADER-003"),  // format
        (12, 8, "L55-HEADER-005"), // sizeof_int
        (13, 0, "L55-HEADER-006"), // int canary
        (17, 8, "L55-HEADER-007"), // instruction_size
        (18, 0, "L55-HEADER-008"), // instruction canary
        (22, 4, "L55-HEADER-009"), // lua_integer_size
        (23, 0, "L55-HEADER-010"), // lua_integer canary
        (31, 4, "L55-HEADER-011"), // lua_number_size
    ];

    for (byte_idx, val, expected_code) in mutations {
        let mut raw = get_fixture_bytes("lua5.5", "hello", false).unwrap();
        raw[byte_idx] = val;
        let mut reader =
            SafeReader::with_options(&raw, 0, ResourceLimits::default(), ParseMode::Permissive);
        let res = decode_chunk_lua55(&mut reader);
        assert!(
            res.is_err(),
            "Permissive mode must fail closed on invalid declaration at byte {byte_idx}"
        );
        let diag = res.unwrap_err();
        assert_eq!(diag.code, expected_code);
    }
}

#[test]
fn test_lua55_exact_numeric_constants_preserved() {
    let raw = get_fixture_bytes("lua5.5", "numerics", false).unwrap();
    let mut reader = SafeReader::new(&raw);
    let chunk = decode_chunk_lua55(&mut reader).expect("decode numerics");

    let interp = chunk.interpretation.unwrap();
    assert_eq!(
        interp.validated_layout.as_deref(),
        Some("int=4,inst=4,lua_int=8,num=8,endian=1")
    );

    let constants = &chunk.main_proto.constants;
    let has_int = constants
        .iter()
        .any(|c| matches!(&c.value, ConstantValue::Integer { .. }));
    let has_float = constants
        .iter()
        .any(|c| matches!(&c.value, ConstantValue::Float { .. }));
    assert!(has_int, "Must contain Integer constants");
    assert!(has_float, "Must contain Float constants");
}
