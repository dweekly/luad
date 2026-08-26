#![no_main]

use libfuzzer_sys::fuzz_target;
use luad_analysis::{lift_proto_for_dialect, ControlFlowGraph, XrefIndex};
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::Prototype;
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::{disassemble_proto_lua54, validate_chunk_lua54, Lua54Dialect};

fn exercise_prototype_analysis(proto: &Prototype) {
    let lifted = lift_proto_for_dialect("lua5.4", proto);
    serde_json::to_vec(&lifted).expect("Lua 5.4 lifted facts must serialize");

    let cfg = ControlFlowGraph::build(proto, &lifted);
    serde_json::to_vec(&cfg).expect("Lua 5.4 CFG facts must serialize");

    for child in &proto.protos {
        exercise_prototype_analysis(child);
    }
}

fuzz_target!(|data: &[u8]| {
    let dialect = Lua54Dialect;

    let mut reader_strict =
        SafeReader::with_options(data, 0, ResourceLimits::default(), ParseMode::Strict);
    if let Ok(chunk) = dialect.decode_chunk(&mut reader_strict) {
        let disasm = disassemble_proto_lua54(&chunk.main_proto);
        serde_json::to_vec(&disasm).expect("Lua 5.4 disassembly facts must serialize");

        let (verdict, diags) = validate_chunk_lua54(&chunk);
        serde_json::to_vec(&(verdict, &diags))
            .expect("Lua 5.4 validation facts must serialize");

        exercise_prototype_analysis(&chunk.main_proto);

        let xrefs = XrefIndex::build(&chunk);
        serde_json::to_vec(&xrefs).expect("Lua 5.4 xref facts must serialize");
    }
});
