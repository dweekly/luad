//! Gate L-53: Truthful layout validation and negative controls for Lua 5.3.

use luad_core::diagnostic::Verdict;
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::ConstantValue;
use luad_core::reader::SafeReader;
use luad_dialect_lua53::{decode_chunk_lua53, parse_header_lua53};
use luad_oracle::get_fixture_bytes;

#[test]
fn test_lua53_clean_stock_fixtures_truthful_layout() {
    let fixture_names = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixture_names {
        let raw_debug = get_fixture_bytes("lua5.3", fixture_name, false)
            .unwrap_or_else(|e| panic!("Failed to get debug fixture '{fixture_name}': {e}"));

        // 1. Header parsing directly
        let mut reader = SafeReader::new(&raw_debug);
        let header = parse_header_lua53(&mut reader).expect("stock header must parse");
        assert_eq!(header.signature, "\u{1b}Lua");
        assert_eq!(header.version, 0x53);
        assert_eq!(header.format, 0);
        assert_eq!(header.instruction_size, 4);
        assert_eq!(header.lua_integer_size, 8);
        assert_eq!(header.sizeof_sizet, 8);
        assert_eq!(header.lua_number_size, 8);
        assert_eq!(header.luac_int, 0x5678);
        assert!((header.luac_num - 370.5).abs() < f64::EPSILON);
        assert_eq!(header.luac_data, "19930d0a1a0a");

        // 2. Chunk decoding
        let mut reader = SafeReader::new(&raw_debug);
        let chunk = decode_chunk_lua53(&mut reader).expect("stock chunk must decode");
        assert_eq!(chunk.dialect, "lua5.3");
        assert_eq!(chunk.verdict, Verdict::ValidForParser);
        assert!(chunk.diagnostics.is_empty());

        let interp = chunk
            .interpretation
            .expect("interpretation must be recorded");
        assert_eq!(interp.base_dialect, "lua5.3");
        assert_eq!(interp.profile, "lua5.3");
        assert_eq!(
            interp.validated_layout.as_deref(),
            Some("int=4,sizet=8,inst=4,lua_int=8,num=8,endian=1")
        );
    }
}

#[test]
fn test_lua53_negative_control_bad_signature() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[0] = b'X';
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-001");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(0));
}

#[test]
fn test_lua53_negative_control_bad_version() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[4] = 0x54; // Lua 5.4 version
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-002");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(4));
    assert!(err.message.contains("0x54"));
}

#[test]
fn test_lua53_negative_control_non_stock_format() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[5] = 1; // non-stock format
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-003");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(5));
    assert!(err.message.contains("Format mismatch"));
    assert!(err.message.contains('1'));
}

#[test]
fn test_lua53_negative_control_corrupted_luac_data() {
    for offset in 6..12 {
        let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
        raw[offset] ^= 0xff;
        let mut reader = SafeReader::new(&raw);
        let err = parse_header_lua53(&mut reader).unwrap_err();
        assert_eq!(err.code, "L53-HEADER-004");
        assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(6));
    }
}

#[test]
fn test_lua53_negative_control_unsupported_sizeof_int() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[12] = 8;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-005");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(12));
    assert!(err.message.contains("sizeof(int)"));
    assert!(err.message.contains('8'));
}

#[test]
fn test_lua53_negative_control_unsupported_sizeof_sizet() {
    for bad_size in [1, 2, 16] {
        let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
        raw[13] = bad_size;
        let mut reader = SafeReader::new(&raw);
        let err = parse_header_lua53(&mut reader).unwrap_err();
        assert_eq!(err.code, "L53-HEADER-006");
        assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(13));
        assert!(err.message.contains("sizeof(size_t)"));
        assert!(err.message.contains(&bad_size.to_string()));
    }
}

#[test]
fn test_lua53_negative_control_unsupported_instruction_size() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[14] = 8;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-007");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(14));
    assert!(err.message.contains("Instruction size"));
    assert!(err.message.contains('8'));
}

#[test]
fn test_lua53_negative_control_unsupported_lua_integer_size() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[15] = 4; // 32-bit integer
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-008");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(15));
    assert!(err.message.contains("lua_Integer size"));
    assert!(err.message.contains('4'));
}

#[test]
fn test_lua53_negative_control_unsupported_lua_number_size() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[16] = 4; // 32-bit float
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-009");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(16));
    assert!(err.message.contains("lua_Number size"));
    assert!(err.message.contains('4'));
}

#[test]
fn test_lua53_negative_control_corrupted_luac_int_canary() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    // Offset 17..25 is LUAC_INT (0x5678). Invert byte 17.
    raw[17] ^= 0xff;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-010");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(17));
    assert!(err.message.contains("Endianness mismatch"));
}

#[test]
fn test_lua53_negative_control_corrupted_luac_num_canary() {
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    // Offset 25..33 is LUAC_NUM (370.5). Invert byte 25.
    raw[25] ^= 0xff;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua53(&mut reader).unwrap_err();
    assert_eq!(err.code, "L53-HEADER-011");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(25));
    assert!(err.message.contains("Float format mismatch"));
}

#[test]
fn test_lua53_permissive_mode_fails_closed_on_unsupported_declarations() {
    // Permissive mode must NEVER guess an unsupported layout
    let mutations: [(usize, u8, &str); 7] = [
        (5, 1, "L53-HEADER-003"),  // format
        (12, 8, "L53-HEADER-005"), // sizeof_int
        (13, 2, "L53-HEADER-006"), // sizeof_sizet
        (14, 8, "L53-HEADER-007"), // instruction_size
        (15, 4, "L53-HEADER-008"), // lua_integer_size
        (16, 4, "L53-HEADER-009"), // lua_number_size
        (17, 0, "L53-HEADER-010"), // luac_int canary
    ];

    for (byte_idx, val, expected_code) in mutations {
        let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
        raw[byte_idx] = val;
        let mut reader =
            SafeReader::with_options(&raw, 0, ResourceLimits::default(), ParseMode::Permissive);
        let res = decode_chunk_lua53(&mut reader);
        assert!(
            res.is_err(),
            "Permissive mode must fail closed on invalid declaration at byte {byte_idx}"
        );
        let diag = res.unwrap_err();
        assert_eq!(diag.code, expected_code);
    }
}

#[test]
fn test_lua53_supported_32bit_sizet_layout() {
    // In Lua 5.3, short strings (< 0xFF) use 1 byte length prefix regardless of sizeof(size_t).
    // Strings >= 0xFF (255) bytes have a 0xFF byte followed by sizeof(size_t) bytes.
    // In hello.luac, all strings are short (< 255 bytes), so setting byte 13 to 4 is a valid 32-bit size_t chunk!
    let mut raw = get_fixture_bytes("lua5.3", "hello", false).unwrap();
    raw[13] = 4; // sizeof(size_t) = 4

    let mut reader = SafeReader::new(&raw);
    let chunk = decode_chunk_lua53(&mut reader).expect("32-bit size_t chunk must decode");
    assert_eq!(chunk.dialect, "lua5.3");
    assert_eq!(chunk.verdict, Verdict::ValidForParser);
    assert_eq!(chunk.header.sizeof_sizet, 4);

    let interp = chunk.interpretation.unwrap();
    assert_eq!(
        interp.validated_layout.as_deref(),
        Some("int=4,sizet=4,inst=4,lua_int=8,num=8,endian=1")
    );
}

#[test]
fn test_lua53_distinct_int_and_lua_integer_in_layout() {
    let raw = get_fixture_bytes("lua5.3", "numerics", false).unwrap();
    let mut reader = SafeReader::new(&raw);
    let chunk = decode_chunk_lua53(&mut reader).expect("decode numerics");

    let interp = chunk.interpretation.unwrap();
    let layout = interp.validated_layout.unwrap();
    // Layout must explicitly distinguish int=4 and lua_int=8
    assert!(
        layout.contains("int=4"),
        "Layout must report int=4: {layout}"
    );
    assert!(
        layout.contains("lua_int=8"),
        "Layout must report lua_int=8: {layout}"
    );

    // Verify exact constants preserved
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
