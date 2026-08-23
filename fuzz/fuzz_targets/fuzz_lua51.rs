#![no_main]

use libfuzzer_sys::fuzz_target;
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua51::Lua51Dialect;

fuzz_target!(|data: &[u8]| {
    let dialect = Lua51Dialect::default();

    // Strict mode
    let mut reader_strict =
        SafeReader::with_options(data, 0, ResourceLimits::default(), ParseMode::Strict);
    let _ = dialect.decode_chunk(&mut reader_strict);

    // Permissive mode
    let mut reader_perm =
        SafeReader::with_options(data, 0, ResourceLimits::default(), ParseMode::Permissive);
    let _ = dialect.decode_chunk(&mut reader_perm);
});
