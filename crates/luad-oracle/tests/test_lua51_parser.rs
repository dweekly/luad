use luad_core::diagnostic::Verdict;
use luad_dialect_lua51::Lua51Dialect;
use luad_oracle::{get_fixture_bytes, verify_truncation_safety_for_dialect};

#[test]
fn test_all_fixtures_lua51_parsing_and_truncation() {
    let fixture_names = ["hello", "control_flow", "closures", "tables", "numerics"];

    let dialect = Lua51Dialect::default();

    for fixture_name in fixture_names {
        // 1. Test normal debug chunk
        let raw_debug = get_fixture_bytes("lua5.1", fixture_name, false)
            .unwrap_or_else(|e| panic!("Failed to get debug fixture '{fixture_name}': {e}"));
        let mut reader_debug = luad_core::reader::SafeReader::new(&raw_debug);
        let chunk_debug = luad_dialect_lua51::decode_chunk_lua51(&mut reader_debug)
            .expect("Parsing debug chunk must succeed");
        assert_eq!(chunk_debug.dialect, "lua5.1");
        assert_eq!(chunk_debug.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_debug.byte_length, raw_debug.len());
        assert!(chunk_debug.diagnostics.is_empty());

        // 2. Test stripped chunk (-s)
        let raw_stripped = get_fixture_bytes("lua5.1", fixture_name, true)
            .unwrap_or_else(|e| panic!("Failed to get stripped fixture '{fixture_name}': {e}"));
        let mut reader_stripped = luad_core::reader::SafeReader::new(&raw_stripped);
        let chunk_stripped = luad_dialect_lua51::decode_chunk_lua51(&mut reader_stripped)
            .expect("Parsing stripped chunk must succeed");
        assert_eq!(chunk_stripped.dialect, "lua5.1");
        assert_eq!(chunk_stripped.verdict, Verdict::ValidForParser);
        assert_eq!(chunk_stripped.byte_length, raw_stripped.len());

        // 3. Truncation safety across every byte
        verify_truncation_safety_for_dialect(&raw_debug, &dialect);
        verify_truncation_safety_for_dialect(&raw_stripped, &dialect);
    }
}

#[test]
fn test_lua51_32bit_sizet_and_lnum_constants() {
    // Construct a synthetic 32-bit Lua 5.1 chunk (sizeof(size_t) == 4) containing:
    // - A 4-byte size_t source name "test32.lua"
    // - Opcode RETURN
    // - Constant 0: tag 4 (String) with 4-byte length "hello32"
    // - Constant 1: tag 9 (OpenWrt/eLua LNUM integer constant) with 4-byte i32 value 1337
    let mut bytes = Vec::new();

    // Header (12 bytes)
    bytes.extend_from_slice(b"\x1bLua"); // signature
    bytes.push(0x51); // version 5.1
    bytes.push(0x00); // format 0
    bytes.push(0x01); // endianness LE
    bytes.push(0x04); // sizeof(int) = 4
    bytes.push(0x04); // sizeof(size_t) = 4 (32-bit target)
    bytes.push(0x04); // sizeof(Instruction) = 4
    bytes.push(0x08); // sizeof(lua_Number) = 8
    bytes.push(0x00); // integral flag = 0

    // Proto: source name (4-byte size_t = 11: "test32.lua\0")
    bytes.extend_from_slice(&11u32.to_le_bytes());
    bytes.extend_from_slice(b"test32.lua\0");

    // linedefined, lastlinedefined
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&1i32.to_le_bytes());
    // nups, numparams, is_vararg, maxstacksize
    bytes.push(0); // nups
    bytes.push(0); // numparams
    bytes.push(2); // is_vararg
    bytes.push(2); // maxstacksize

    // instructions: 1 instruction (OP_RETURN 0 1)
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&0x0000001eu32.to_le_bytes());

    // constants: 2 constants
    bytes.extend_from_slice(&2i32.to_le_bytes());
    // Constant 0: String tag 4, 4-byte length 8: "hello32\0"
    bytes.push(4);
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(b"hello32\0");
    // Constant 1: LNUM int tag 9, 4-byte i32 1337
    bytes.push(9);
    bytes.extend_from_slice(&1337i32.to_le_bytes());

    // child protos: 0
    bytes.extend_from_slice(&0i32.to_le_bytes());
    // line info: 1 entry
    bytes.extend_from_slice(&1i32.to_le_bytes());
    bytes.extend_from_slice(&1i32.to_le_bytes());
    // locvars: 0
    bytes.extend_from_slice(&0i32.to_le_bytes());
    // upvalnames: 0
    bytes.extend_from_slice(&0i32.to_le_bytes());

    let mut reader = luad_core::reader::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51_with_profile(
        &mut reader,
        luad_dialect_lua51::Lua51Profile::Lnum,
    )
    .expect("32-bit Lua 5.1 chunk with LNUM constants must parse successfully");

    assert_eq!(chunk.dialect, "lua5.1");
    assert_eq!(chunk.header.sizeof_sizet, 4);
    assert_eq!(chunk.header.lua_integer_size, 4);
    assert_eq!(
        chunk.main_proto.source_name.as_ref().map(|s| s.as_str()),
        Some("test32.lua")
    );
    assert_eq!(chunk.main_proto.constants.len(), 2);

    match &chunk.main_proto.constants[0].value {
        luad_core::model::ConstantValue::ShortString(s) => {
            assert_eq!(s.as_str(), "hello32");
        }
        other => panic!("Expected ShortString, got {other:?}"),
    }

    match &chunk.main_proto.constants[1].value {
        luad_core::model::ConstantValue::Float { val, .. } => {
            assert_eq!(*val, 1337.0);
        }
        other => panic!("Expected Float for LNUM int, got {other:?}"),
    }

    // Truncation safety
    verify_truncation_safety_for_dialect(&bytes, &Lua51Dialect::default());
}
