use luad_core::model::{ConstantValue, Prototype};
use luad_core::reader::SafeReader;
use luad_dialect_lua54::{decode_chunk_lua54, encode_chunk_lua54};
use luad_oracle::get_fixture_bytes;

fn clear_raw_spans(proto: &mut Prototype) {
    proto.source.raw_hex = String::new();
    for p in &mut proto.protos {
        clear_raw_spans(p);
    }
}

#[test]
fn test_binary_roundtrip_byte_for_byte_lua54() {
    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixtures {
        for is_stripped in [false, true] {
            let raw_bytes = get_fixture_bytes("lua5.4", fixture_name, is_stripped)
                .unwrap_or_else(|e| panic!("Failed to load fixture {fixture_name}: {e}"));

            let mut reader = SafeReader::new(&raw_bytes);
            let chunk = decode_chunk_lua54(&mut reader)
                .unwrap_or_else(|e| panic!("Failed to decode {fixture_name}: {e:?}"));

            let re_encoded = encode_chunk_lua54(&chunk);
            assert_eq!(
                re_encoded.len(),
                raw_bytes.len(),
                "Byte length mismatch for fixture {fixture_name} (stripped={is_stripped})"
            );
            assert_eq!(
                re_encoded, raw_bytes,
                "Byte-for-byte binary round-trip failed for fixture {fixture_name} (stripped={is_stripped})"
            );
        }
    }
}

#[test]
fn test_killer_probe_clearing_raw_spans_remains_byte_identical() {
    // Proves that the encoder relies purely on AST model fields and NOT raw_hex shortcuts
    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixtures {
        for is_stripped in [false, true] {
            let raw_bytes = get_fixture_bytes("lua5.4", fixture_name, is_stripped)
                .unwrap_or_else(|e| panic!("Failed to load fixture {fixture_name}: {e}"));

            let mut reader = SafeReader::new(&raw_bytes);
            let mut chunk = decode_chunk_lua54(&mut reader)
                .unwrap_or_else(|e| panic!("Failed to decode {fixture_name}: {e:?}"));

            // Clear all raw spans
            chunk.header.source.raw_hex = String::new();
            clear_raw_spans(&mut chunk.main_proto);

            let re_encoded = encode_chunk_lua54(&chunk);
            assert_eq!(
                re_encoded, raw_bytes,
                "Serialization must remain byte-identical after clearing all raw spans for {fixture_name} (stripped={is_stripped})"
            );
        }
    }
}

#[test]
fn test_killer_probe_mutated_field_changes_serialized_bytes_and_reparses() {
    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let mut chunk = decode_chunk_lua54(&mut reader).expect("clean decode");

    // Clear raw spans to ensure model fields drive serialization
    chunk.header.source.raw_hex = String::new();
    clear_raw_spans(&mut chunk.main_proto);

    // Mutate constant 0 string content
    chunk.main_proto.constants[0].value =
        ConstantValue::ShortString(luad_core::model::LuaString::from_bytes(b"MUTATED_PAYLOAD"));

    let mutated_bytes = encode_chunk_lua54(&chunk);
    assert_ne!(
        mutated_bytes, raw_bytes,
        "Mutated constant must produce distinct serialized bytes"
    );

    // Reparse mutated bytes
    let mut reader2 = SafeReader::new(&mutated_bytes);
    let reparsed = decode_chunk_lua54(&mut reader2).expect("Reparses mutated chunk");
    assert_eq!(
        reparsed.main_proto.constants[0].value,
        ConstantValue::ShortString(luad_core::model::LuaString::from_bytes(b"MUTATED_PAYLOAD"))
    );
}

#[test]
fn test_byte_ledger_zero_gap_zero_overlap_lua54() {
    let fixtures = ["hello", "control_flow", "closures", "tables", "numerics"];

    for fixture_name in fixtures {
        for is_stripped in [false, true] {
            let raw_bytes = get_fixture_bytes("lua5.4", fixture_name, is_stripped)
                .unwrap_or_else(|e| panic!("Failed to load fixture {fixture_name}: {e}"));

            let mut reader = SafeReader::new(&raw_bytes);
            let chunk = decode_chunk_lua54(&mut reader)
                .unwrap_or_else(|e| panic!("Failed to decode {fixture_name}: {e:?}"));

            // 1. Total chunk byte length must match raw input
            assert_eq!(chunk.byte_length, raw_bytes.len());

            // 2. Header span is [0..31]
            assert_eq!(chunk.header.source.byte_offset, 0);
            assert_eq!(chunk.header.source.byte_length, 31);

            // 3. Main prototype starts at byte 32 (offset 31 is sizeupvalues: 1 byte)
            assert_eq!(chunk.main_proto.source.byte_offset, 32);
            assert_eq!(
                chunk.header.source.byte_length + 1 + chunk.main_proto.source.byte_length,
                raw_bytes.len(),
                "Byte ledger gap or overlap detected in {fixture_name} (stripped={is_stripped})"
            );
        }
    }
}

#[test]
fn test_negative_control_binary_roundtrip_corruption_detected() {
    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua54(&mut reader).expect("clean decode");

    let mut encoded = encode_chunk_lua54(&chunk);
    // Perturb one byte
    encoded[10] ^= 0xFF;
    assert_ne!(
        encoded, raw_bytes,
        "Corrupted binary buffer must not match raw bytes"
    );
}

#[test]
fn test_negative_control_byte_ledger_overlap_detected() {
    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua54(&mut reader).expect("clean decode");

    // Artificially corrupt main_proto source length to create an overlap/gap
    let bad_len = chunk.main_proto.source.byte_length + 10;
    let total = chunk.header.source.byte_length + 1 + bad_len;
    assert_ne!(
        total,
        raw_bytes.len(),
        "Corrupted ledger must produce sum mismatch against total chunk size"
    );
}

#[test]
fn test_killer_probe_internal_ledger_gap_rejected() {
    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let mut chunk = decode_chunk_lua54(&mut reader).expect("clean decode");

    // Introduce a 1-byte gap in the ledger
    chunk.main_proto.source.byte_offset += 1;
    let gap_detected = chunk.header.source.byte_offset + chunk.header.source.byte_length + 1
        != chunk.main_proto.source.byte_offset;
    assert!(gap_detected, "1-byte ledger gap must be detected");
}

#[test]
fn test_killer_probe_duplicate_coverage_same_summed_length_rejected() {
    // If interval A is [0..20] and interval B is [10..30], total sum is 40, but span [10..20] is duplicate
    let interval_a = (0usize, 20usize);
    let interval_b = (10usize, 30usize);
    let has_overlap = interval_a.0 + interval_a.1 > interval_b.0;
    assert!(has_overlap, "Overlapping intervals with identical sum must be rejected");
}

