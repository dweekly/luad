//! Adversarial size, corrupted header, truncation safety, and memory limit test suite.

use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua51::Lua51Dialect;
use luad_dialect_lua52::Lua52Dialect;
use luad_dialect_lua53::Lua53Dialect;
use luad_dialect_lua54::Lua54Dialect;
use luad_dialect_lua55::Lua55Dialect;
use luad_oracle::{load_precompiled_fixture, verify_truncation_safety_for_dialect};

#[test]
fn test_all_50_fixtures_truncation_safety() {
    let dialects: &[(&str, &dyn Dialect)] = &[
        ("lua51", &Lua51Dialect),
        ("lua52", &Lua52Dialect),
        ("lua53", &Lua53Dialect),
        ("lua54", &Lua54Dialect),
        ("lua55", &Lua55Dialect),
    ];
    let fixtures = &["hello", "control_flow", "closures", "tables", "numerics"];

    for (d_name, dialect) in dialects {
        for fixture in fixtures {
            for strip in [false, true] {
                let bytes = load_precompiled_fixture(d_name, fixture, strip)
                    .unwrap_or_else(|e| panic!("Failed to load fixture {d_name}/{fixture}: {e}"));
                verify_truncation_safety_for_dialect(&bytes, *dialect);
            }
        }
    }
}

#[test]
fn test_adversarial_corrupted_headers() {
    let base_header = [
        0x1b, 0x4c, 0x75, 0x61, // \x1bLua
        0x54, // version 5.4
        0x00, // format 0
        0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a, // LUAC_DATA
        0x04, 0x08, 0x08, // sizes (inst=4, int=8, num=8)
        0x78, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // LUAC_INT (0x5678)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x77, 0x40, // LUAC_NUM (370.5)
    ];

    let dialect = Lua54Dialect;

    // 1. Corrupt signature
    let mut bad_sig = base_header;
    bad_sig[0] = 0x00;
    let mut reader =
        SafeReader::with_options(&bad_sig, 0, ResourceLimits::default(), ParseMode::Strict);
    assert!(dialect.decode_chunk(&mut reader).is_err());

    // 2. Corrupt LUAC_DATA
    let mut bad_data = base_header;
    bad_data[6] = 0x00;
    let mut reader =
        SafeReader::with_options(&bad_data, 0, ResourceLimits::default(), ParseMode::Strict);
    assert!(dialect.decode_chunk(&mut reader).is_err());

    // 3. Corrupt LUAC_INT
    let mut bad_int = base_header;
    bad_int[15] = 0xFF;
    let mut reader =
        SafeReader::with_options(&bad_int, 0, ResourceLimits::default(), ParseMode::Strict);
    assert!(dialect.decode_chunk(&mut reader).is_err());

    // 4. Corrupt LUAC_NUM
    let mut bad_num = base_header;
    bad_num[23] = 0xFF;
    let mut reader =
        SafeReader::with_options(&bad_num, 0, ResourceLimits::default(), ParseMode::Strict);
    assert!(dialect.decode_chunk(&mut reader).is_err());
}

#[test]
fn test_adversarial_giant_counts_and_allocations() {
    let header = [
        0x1b, 0x4c, 0x75, 0x61, 0x54, 0x00, 0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a, 0x04, 0x08, 0x08,
        0x78, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x77,
        0x40, 0x01, // sizeupvalues
    ];

    let dialect = Lua54Dialect;

    // Craft a payload with giant varint instruction count (0xFF, 0xFF, 0xFF, 0x7F = 268435455)
    let mut payload = header.to_vec();
    // main proto header
    payload.extend_from_slice(&[
        0x00, // source string null
        0x00, // line defined
        0x00, // last line defined
        0x00, // numparams
        0x00, // is_vararg
        0x02, // maxstacksize
        // giant sizecode: 0xFF, 0xFF, 0xFF, 0x7F
        0xFF, 0xFF, 0xFF, 0x7F,
    ]);

    // SafeReader must gracefully fail closed due to limit checks without allocating gigabytes of RAM or panicking
    let limits = ResourceLimits {
        max_instructions_per_proto: 10_000,
        ..Default::default()
    };

    let mut reader = SafeReader::with_options(&payload, 0, limits, ParseMode::Strict);
    let result = dialect.decode_chunk(&mut reader);
    assert!(result.is_err(), "Must fail closed on giant sizecode");
}

#[test]
fn test_adversarial_deep_nesting_recursion_limit() {
    let limits = ResourceLimits {
        max_nesting_depth: 3,
        ..Default::default()
    };

    let mut reader = SafeReader::with_options(&[], 0, limits, ParseMode::Strict);
    let mut g1 = reader.enter_proto(0).expect("Depth 1 ok");
    let mut g2 = g1.enter_proto(0).expect("Depth 2 ok");
    let mut g3 = g2.enter_proto(0).expect("Depth 3 ok");
    let g4 = g3.enter_proto(0);
    assert!(g4.is_err(), "Depth 4 exceeding limit 3 must fail closed");
}

