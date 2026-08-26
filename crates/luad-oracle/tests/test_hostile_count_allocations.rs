use luad_core::{Dialect, ParseMode, ResourceLimits, SafeReader};
use luad_dialect_lua52::Lua52Dialect;

#[test]
fn lua52_upvalue_name_count_is_bounded_before_allocation() {
    let mut bytes = luad_oracle::load_precompiled_fixture("lua52", "control_flow", false)
        .expect("load maintained Lua 5.2 fixture");

    // The final debug record begins with the upvalue-name count at byte 506.
    // A large declared count followed by EOF must be rejected without allocating it.
    bytes[506..510].copy_from_slice(&0x4000_0000_i32.to_le_bytes());
    bytes.truncate(510);

    let mut reader =
        SafeReader::with_options(&bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    let result = Lua52Dialect.decode_chunk(&mut reader);

    assert!(result.is_err(), "hostile debug count must be rejected");
    assert!(
        reader.position() <= bytes.len(),
        "rejection must retain an in-bounds parser position"
    );
}
