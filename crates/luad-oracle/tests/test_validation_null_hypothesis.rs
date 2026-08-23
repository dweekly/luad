//! Clean-input null hypothesis validator gate and killer probe controls (Gate V1 / gate-validation-null-hypothesis).
//!
//! Asserts that every maintained valid compiler-produced fixture across all supported
//! dialects produces zero validation errors, AND that adversarial mutations (out-of-bounds
//! jumps, invalid registers, corrupted headers, missing closure descriptors) are strictly detected.

use luad_core::diagnostic::Verdict;
use luad_core::reader::SafeReader;
use luad_oracle::get_fixture_bytes;

#[test]
fn test_all_lua54_maintained_fixtures_produce_zero_validation_diagnostics() {
    let fixtures = ["hello", "numerics", "tables", "closures", "control_flow"];

    for name in fixtures {
        for stripped in [false, true] {
            let bytes = get_fixture_bytes("lua5.4", name, stripped).unwrap_or_else(|e| {
                panic!("Missing fixture lua5.4 {name} (stripped={stripped}): {e:?}")
            });
            let mut reader = SafeReader::new(&bytes);
            let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).unwrap_or_else(|e| {
                panic!("Decode failed for lua5.4 {name} (stripped={stripped}): {e:?}")
            });

            let (verdict, diags) = luad_dialect_lua54::validate_chunk_lua54(&chunk);
            assert_eq!(
                verdict,
                Verdict::ValidForAnalysis,
                "Fixture lua5.4 {name} (stripped={stripped}) failed validation verdict"
            );
            assert!(
                diags.is_empty(),
                "Fixture lua5.4 {name} (stripped={stripped}) produced unexpected diagnostics: {:?}",
                diags
            );
        }
    }
}

#[test]
fn test_all_lua51_maintained_fixtures_produce_zero_validation_diagnostics() {
    let fixtures = ["hello", "numerics", "tables", "closures", "control_flow"];

    for name in fixtures {
        for stripped in [false, true] {
            let bytes = get_fixture_bytes("lua5.1", name, stripped).unwrap_or_else(|e| {
                panic!("Missing fixture lua5.1 {name} (stripped={stripped}): {e:?}")
            });
            let mut reader = SafeReader::new(&bytes);
            let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap_or_else(|e| {
                panic!("Decode failed for lua5.1 {name} (stripped={stripped}): {e:?}")
            });

            let (verdict, diags) = luad_dialect_lua51::validate_chunk_lua51(&chunk);
            assert_ne!(
                verdict,
                Verdict::Invalid,
                "Fixture lua5.1 {name} (stripped={stripped}) failed validation verdict"
            );
            assert!(
                diags.is_empty(),
                "Fixture lua5.1 {name} (stripped={stripped}) produced unexpected diagnostics: {:?}",
                diags
            );
        }
    }
}

#[test]
fn test_killer_probe_out_of_bounds_jump_detected() {
    let bytes = get_fixture_bytes("lua5.1", "control_flow", false).expect("read control_flow");
    let mut reader = SafeReader::new(&bytes);
    let mut chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode");

    // Mutate first instruction into a giant out-of-bounds JMP (sbx = 100000)
    // JMP opcode = 22 = 0x16, sbx = 100000 => bx = 100000 + 131071 = 231071
    let mutated_raw_word = 22 | (231071 << 14);
    chunk.main_proto.instructions[0].raw_word = mutated_raw_word;

    let (verdict, diags) = luad_dialect_lua51::validate_chunk_lua51(&chunk);
    assert_eq!(
        verdict,
        Verdict::Invalid,
        "Mutated out-of-bounds jump must trigger Invalid verdict"
    );
    assert!(
        diags.iter().any(|d| d.code == "L51-JMP-001"),
        "Mutated jump must produce L51-JMP-001 diagnostic, found: {diags:?}"
    );
}

#[test]
fn test_killer_probe_out_of_bounds_register_detected() {
    let bytes = get_fixture_bytes("lua5.1", "hello", false).expect("read hello");
    let mut reader = SafeReader::new(&bytes);
    let mut chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode");

    // Constrain maxstacksize to 2, while instruction references R(5)
    chunk.main_proto.maxstacksize = 2;

    let (verdict, diags) = luad_dialect_lua51::validate_chunk_lua51(&chunk);
    assert_eq!(
        verdict,
        Verdict::Invalid,
        "Out-of-bounds register must trigger Invalid verdict"
    );
    assert!(
        diags.iter().any(|d| d.code.starts_with("L51-REG")),
        "Must produce L51-REG-* diagnostic, found: {diags:?}"
    );
}

#[test]
fn test_killer_probe_corrupted_header_detected() {
    let mut bytes = get_fixture_bytes("lua5.1", "hello", false).expect("read hello");
    // Corrupt magic signature byte 0
    bytes[0] = 0x00;

    let mut reader = SafeReader::new(&bytes);
    let res = luad_dialect_lua51::decode_chunk_lua51(&mut reader);
    assert!(
        res.is_err(),
        "Corrupted header signature must fail chunk decoding"
    );
}

#[test]
fn test_killer_probe_missing_closure_descriptor_detected() {
    let bytes = get_fixture_bytes("lua5.1", "closures", false).expect("read closures");
    let mut reader = SafeReader::new(&bytes);
    let mut chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode");

    // In proto:0/0, find CLOSURE at PC 3, and truncate instructions so descriptor at PC 4 is missing
    if let Some(child_proto) = chunk.main_proto.protos.get_mut(0) {
        child_proto.instructions.truncate(4); // removes descriptor at index 4
    }

    let (verdict, diags) = luad_dialect_lua51::validate_chunk_lua51(&chunk);
    assert_eq!(
        verdict,
        Verdict::Invalid,
        "Missing closure descriptor must trigger Invalid verdict"
    );
    assert!(
        diags.iter().any(|d| d.code == "L51-CLOSURE-001"),
        "Must produce L51-CLOSURE-001 diagnostic, found: {diags:?}"
    );
}
