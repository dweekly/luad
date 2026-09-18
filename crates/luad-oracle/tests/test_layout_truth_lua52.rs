//! Gate L-52: Truthful layout validation and negative controls for Lua 5.2.

use luad_core::diagnostic::Verdict;
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::reader::SafeReader;
use luad_dialect_lua52::{decode_chunk_lua52, parse_header_lua52};
use luad_oracle::get_fixture_bytes;

#[test]
fn test_lua52_clean_stock_fixtures_truthful_layout() {
    let fixture_names = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixture_names {
        let raw_debug = get_fixture_bytes("lua5.2", fixture_name, false)
            .unwrap_or_else(|e| panic!("Failed to get debug fixture '{fixture_name}': {e}"));

        // 1. Header parsing directly
        let mut reader = SafeReader::new(&raw_debug);
        let header = parse_header_lua52(&mut reader).expect("stock header must parse");
        assert_eq!(header.signature, "\u{1b}Lua");
        assert_eq!(header.version, 0x52);
        assert_eq!(header.format, 0);
        assert_eq!(header.instruction_size, 4);
        assert_eq!(header.lua_integer_size, 4);
        assert_eq!(header.sizeof_sizet, 8);
        assert_eq!(header.lua_number_size, 8);
        assert_eq!(header.luac_data, "19930d0a1a0a");

        // 2. Chunk decoding
        let mut reader = SafeReader::new(&raw_debug);
        let chunk = decode_chunk_lua52(&mut reader).expect("stock chunk must decode");
        assert_eq!(chunk.dialect, "lua5.2");
        assert_eq!(chunk.verdict, Verdict::ValidForParser);
        assert!(chunk.diagnostics.is_empty());

        let interp = chunk
            .interpretation
            .expect("interpretation must be recorded");
        assert_eq!(interp.base_dialect, "lua5.2");
        assert_eq!(interp.profile, "lua5.2");
        assert_eq!(
            interp.validated_layout.as_deref(),
            Some("int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0")
        );
    }
}

#[test]
fn test_lua52_negative_control_bad_signature() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[0] = b'X';
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-001");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(0));
}

#[test]
fn test_lua52_negative_control_bad_version() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[4] = 0x53; // Lua 5.3 version
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-002");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(4));
    assert!(err.message.contains("0x53"));
}

#[test]
fn test_lua52_negative_control_non_stock_format() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[5] = 1; // non-stock format
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-003");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(5));
    assert!(err.message.contains("Format mismatch"));
    assert!(err.message.contains('1'));
}

#[test]
fn test_lua52_negative_control_big_endian_rejected() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[6] = 0; // big-endian
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-004");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(6));
    assert!(err.message.contains("Unsupported endianness"));
    assert!(err.message.contains('0'));
}

#[test]
fn test_lua52_negative_control_unsupported_sizeof_int() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[7] = 8; // 64-bit C int
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-005");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(7));
    assert!(err.message.contains("sizeof(int)"));
    assert!(err.message.contains('8'));
}

#[test]
fn test_lua52_negative_control_unsupported_sizeof_sizet() {
    for bad_size in [1, 2, 16] {
        let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
        raw[8] = bad_size;
        let mut reader = SafeReader::new(&raw);
        let err = parse_header_lua52(&mut reader).unwrap_err();
        assert_eq!(err.code, "L52-HEADER-006");
        assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(8));
        assert!(err.message.contains("sizeof(size_t)"));
        assert!(err.message.contains(&bad_size.to_string()));
    }
}

#[test]
fn test_lua52_negative_control_unsupported_instruction_size() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[9] = 8;
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-007");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(9));
    assert!(err.message.contains("Instruction size"));
    assert!(err.message.contains('8'));
}

#[test]
fn test_lua52_negative_control_unsupported_lua_number_size() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[10] = 4; // 32-bit float
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-008");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(10));
    assert!(err.message.contains("lua_Number size"));
    assert!(err.message.contains('4'));
}

#[test]
fn test_lua52_negative_control_integral_vm_rejected() {
    let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    raw[11] = 1; // integer-only VM
    let mut reader = SafeReader::new(&raw);
    let err = parse_header_lua52(&mut reader).unwrap_err();
    assert_eq!(err.code, "L52-HEADER-009");
    assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(11));
    assert!(err.message.contains("integral flag"));
    assert!(err.message.contains('1'));
}

#[test]
fn test_lua52_negative_control_corrupted_luac_tail() {
    for offset in 12..18 {
        let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
        raw[offset] ^= 0xff;
        let mut reader = SafeReader::new(&raw);
        let err = parse_header_lua52(&mut reader).unwrap_err();
        assert_eq!(err.code, "L52-HEADER-010");
        assert_eq!(err.source.as_ref().map(|s| s.byte_offset), Some(12));
    }
}

#[test]
fn test_lua52_permissive_mode_fails_closed_on_unsupported_declarations() {
    // Permissive mode must NEVER guess an unsupported layout
    let mutations: [(usize, u8, &str); 5] = [
        (5, 1, "L52-HEADER-003"),  // format
        (6, 0, "L52-HEADER-004"),  // endianness
        (7, 8, "L52-HEADER-005"),  // sizeof_int
        (8, 2, "L52-HEADER-006"),  // sizeof_sizet
        (11, 1, "L52-HEADER-009"), // integral_flag
    ];

    for (byte_idx, val, expected_code) in mutations {
        let mut raw = get_fixture_bytes("lua5.2", "hello", false).unwrap();
        raw[byte_idx] = val;
        let mut reader =
            SafeReader::with_options(&raw, 0, ResourceLimits::default(), ParseMode::Permissive);
        let res = decode_chunk_lua52(&mut reader);
        assert!(
            res.is_err(),
            "Permissive mode must fail closed on invalid declaration at byte {byte_idx}"
        );
        let diag = res.unwrap_err();
        assert_eq!(diag.code, expected_code);
    }
}

#[test]
fn test_lua52_supported_32bit_sizet_layout() {
    let raw_64 = get_fixture_bytes("lua5.2", "hello", false).unwrap();
    let mut reader_64 = SafeReader::new(&raw_64);
    let chunk_64 = decode_chunk_lua52(&mut reader_64).expect("original decode");

    // Build a synthetic 32-bit size_t buffer from hello.luac:
    let mut raw_32 = Vec::new();
    // 1. Header (18 bytes), but byte 8 set to 4
    raw_32.extend_from_slice(&raw_64[..8]);
    raw_32.push(4); // sizeof(size_t) = 4
    raw_32.extend_from_slice(&raw_64[9..18]);

    // 2. Body:
    let mut r = SafeReader::new(&raw_64[18..]);

    // 1. Line definitions & stack: 11 bytes
    // linedefined (4), lastlinedefined (4), numparams (1), is_vararg (1), maxstacksize (1)
    raw_32.extend_from_slice(r.read_exact(11).unwrap());

    // 2. Instructions
    let sizecode = r.read_i32_le().unwrap() as usize;
    raw_32.extend_from_slice(&(sizecode as i32).to_le_bytes());
    raw_32.extend_from_slice(r.read_exact(sizecode * 4).unwrap());

    // 3. Constants
    let sizek = r.read_i32_le().unwrap() as usize;
    raw_32.extend_from_slice(&(sizek as i32).to_le_bytes());
    for _ in 0..sizek {
        let tag = r.read_u8().unwrap();
        raw_32.push(tag);
        match tag {
            0 => {}
            1 => {
                raw_32.push(r.read_u8().unwrap());
            }
            3 => {
                raw_32.extend_from_slice(r.read_exact(8).unwrap());
            }
            4 => {
                let slen_64 = r.read_u64_le().unwrap();
                let slen_32 = slen_64 as u32;
                raw_32.extend_from_slice(&slen_32.to_le_bytes());
                if slen_64 > 0 {
                    raw_32.extend_from_slice(r.read_exact(slen_64 as usize).unwrap());
                }
            }
            other => panic!("unexpected tag {other}"),
        }
    }

    // 4. Sub-prototypes
    let sizep = r.read_i32_le().unwrap() as usize;
    raw_32.extend_from_slice(&(sizep as i32).to_le_bytes());
    assert_eq!(sizep, 0); // hello has no subprotos

    // 5. Upvalues (each is instack: u8, idx: u8)
    let sizeupval = r.read_i32_le().unwrap() as usize;
    raw_32.extend_from_slice(&(sizeupval as i32).to_le_bytes());
    raw_32.extend_from_slice(r.read_exact(sizeupval * 2).unwrap());

    // 6. Source Name (string)
    let src_len_64 = r.read_u64_le().unwrap();
    let src_len_32 = src_len_64 as u32;
    raw_32.extend_from_slice(&src_len_32.to_le_bytes());
    if src_len_64 > 0 {
        raw_32.extend_from_slice(r.read_exact(src_len_64 as usize).unwrap());
    }

    // 7. Debug line info (each entry is an i32)
    let sizelineinfo = r.read_i32_le().unwrap() as usize;
    raw_32.extend_from_slice(&(sizelineinfo as i32).to_le_bytes());
    raw_32.extend_from_slice(r.read_exact(sizelineinfo * 4).unwrap());

    // 8. Local variables (string name, startpc: i32, endpc: i32)
    let sizelocvars = r.read_i32_le().unwrap() as usize;
    raw_32.extend_from_slice(&(sizelocvars as i32).to_le_bytes());
    for _ in 0..sizelocvars {
        let slen_64 = r.read_u64_le().unwrap();
        let slen_32 = slen_64 as u32;
        raw_32.extend_from_slice(&slen_32.to_le_bytes());
        if slen_64 > 0 {
            raw_32.extend_from_slice(r.read_exact(slen_64 as usize).unwrap());
        }
        raw_32.extend_from_slice(r.read_exact(8).unwrap());
    }

    // 9. Upvalue debug names (each is a string)
    let sizeupvalnames = r.read_i32_le().unwrap() as usize;
    raw_32.extend_from_slice(&(sizeupvalnames as i32).to_le_bytes());
    for _ in 0..sizeupvalnames {
        let slen_64 = r.read_u64_le().unwrap();
        let slen_32 = slen_64 as u32;
        raw_32.extend_from_slice(&slen_32.to_le_bytes());
        if slen_64 > 0 {
            raw_32.extend_from_slice(r.read_exact(slen_64 as usize).unwrap());
        }
    }

    // Parse with Lua 5.2 decoder
    let mut reader_32 = SafeReader::new(&raw_32);
    let chunk_32 = decode_chunk_lua52(&mut reader_32).expect("32-bit size_t chunk must decode");
    assert_eq!(chunk_32.dialect, "lua5.2");
    assert_eq!(chunk_32.verdict, Verdict::ValidForParser);
    assert_eq!(chunk_32.header.sizeof_sizet, 4);

    let interp = chunk_32.interpretation.unwrap();
    assert_eq!(
        interp.validated_layout.as_deref(),
        Some("int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=0")
    );

    // Assert that constants match original chunk_64 constants
    assert_eq!(
        chunk_32.main_proto.constants.len(),
        chunk_64.main_proto.constants.len()
    );
    for (c32, c64) in chunk_32
        .main_proto
        .constants
        .iter()
        .zip(chunk_64.main_proto.constants.iter())
    {
        assert_eq!(c32.value, c64.value);
    }
}
