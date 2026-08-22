#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz dialect detection logic
    let _ = luad_core::DialectRegistry::detect_dialect(data);
});
