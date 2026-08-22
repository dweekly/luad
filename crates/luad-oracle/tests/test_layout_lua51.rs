//! Gate L1: ChunkLayout, endianness, 32-bit size_t, and LNUM profile tests for Lua 5.1.

use luad_core::reader::SafeReader;
use luad_dialect_lua51::{
    decode_chunk_lua51, decode_chunk_lua51_with_profile, parse_header_lua51, ChunkLayout,
    Lua51Profile,
};
use luad_oracle::get_fixture_bytes;

#[test]
fn test_chunk_layout_validation_stock51() {
    let raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let (header, layout) = parse_header_lua51(&mut reader, Lua51Profile::Stock).expect("valid header");

    assert_eq!(layout.sizeof_int, 4);
    assert_eq!(layout.sizeof_sizet, 8);
    assert_eq!(layout.instruction_size, 4);
    assert_eq!(layout.lua_number_size, 8);
    assert_eq!(layout.endianness, 1);
    assert_eq!(layout.integral_flag, 0);
    assert_eq!(layout.profile, Lua51Profile::Stock);
    assert_eq!(header.version, 0x51);
}

#[test]
fn test_chunk_layout_validation_32bit_sizet() {
    // Construct a synthetic 32-bit size_t chunk header: byte 8 is sizeof(size_t) = 4
    let mut raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    raw_bytes[8] = 4; // set sizeof(size_t) to 4

    let mut reader = SafeReader::new(&raw_bytes);
    let (_header, layout) =
        parse_header_lua51(&mut reader, Lua51Profile::Stock32).expect("valid 32-bit sizet header");
    assert_eq!(layout.sizeof_sizet, 4);
    assert_eq!(layout.profile, Lua51Profile::Stock32);
}

#[test]
fn test_chunk_layout_rejects_mismatched_reader() {
    // Unsupported instruction size (e.g. 8)
    assert!(ChunkLayout::validate(4, 8, 8, 8, 1, 0, Lua51Profile::Stock).is_err());
    // Unsupported endianness (e.g. 0)
    assert!(ChunkLayout::validate(4, 8, 4, 8, 0, 0, Lua51Profile::Stock).is_err());
    // Unsupported sizeof(size_t) (e.g. 2)
    assert!(ChunkLayout::validate(4, 2, 4, 8, 1, 0, Lua51Profile::Stock).is_err());
}

#[test]
fn test_stock_lua51_rejects_lnum_tag_9() {
    // Create a Lua 5.1 chunk with tag 9 injected as a constant
    let raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");


    // In hello fixture, find constant table position and change constant tag to 9
    // Hello fixture has string constant "Hello world"
    // Find tag 4 (string) after line numbers and change to 9
    let mut mutated = raw_bytes.clone();
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");
    let const_offset = chunk.main_proto.constants[0].source.byte_offset;

    // Mutate constant tag to 9 (LNUM)
    mutated[const_offset] = 9;

    let mut reader_mut = SafeReader::new(&mutated);
    let res = decode_chunk_lua51_with_profile(&mut reader_mut, Lua51Profile::Stock);
    assert!(res.is_err(), "Stock profile must reject tag 9");
    let diag = res.unwrap_err();
    assert_eq!(diag.code, "L51-CONST-002");
    assert!(diag.message.contains("LNUM extension"));
}

#[test]
fn test_profile_lua51_lnum_accepts_tag_9() {
    let raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");
    let const_offset = chunk.main_proto.constants[0].source.byte_offset;

    // Construct valid LNUM constant: tag 9 followed by 4-byte LE int (42)
    let mut mutated = raw_bytes[..const_offset].to_vec();
    mutated.push(9); // tag 9
    mutated.extend_from_slice(&42i32.to_le_bytes()); // 4-byte int
    // Rest of prototype following the original string constant
    let orig_const_len = chunk.main_proto.constants[0].source.byte_length;
    mutated.extend_from_slice(&raw_bytes[const_offset + orig_const_len..]);

    let mut reader_lnum = SafeReader::new(&mutated);
    let res = decode_chunk_lua51_with_profile(&mut reader_lnum, Lua51Profile::Lnum);
    assert!(res.is_ok(), "Lnum profile must accept tag 9: {:?}", res.err());
}

#[test]
fn test_negative_control_endianness_mismatch() {
    let mut raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    raw_bytes[6] = 0; // set endianness to 0 (Big-Endian)

    let mut reader = SafeReader::new(&raw_bytes);
    let res = parse_header_lua51(&mut reader, Lua51Profile::Stock);
    assert!(res.is_err(), "Big-endian chunk must fail validation");
    let diag = res.unwrap_err();
    assert_eq!(diag.code, "L51-HEADER-003");
}

#[test]
fn test_negative_control_number_format_mismatch() {
    let mut raw_bytes = get_fixture_bytes("lua5.1", "hello", false).expect("fixture failed");
    raw_bytes[10] = 16; // set sizeof(lua_Number) to 16

    let mut reader = SafeReader::new(&raw_bytes);
    let res = parse_header_lua51(&mut reader, Lua51Profile::Stock);
    assert!(res.is_err(), "Invalid number size must fail validation");
    let diag = res.unwrap_err();
    assert_eq!(diag.code, "L51-HEADER-003");
}
