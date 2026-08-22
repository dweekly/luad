#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz dialect detection logic across all dialects
    let _ = luad_dialect_lua51::detect_lua51(data);
    let _ = luad_dialect_lua52::detect_lua52(data);
    let _ = luad_dialect_lua53::detect_lua53(data);
    let _ = luad_dialect_lua54::detect_lua54(data);
    let _ = luad_dialect_lua55::detect_lua55(data);
});

