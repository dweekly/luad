use std::fs;
use luad_analysis::{diff_chunks, execute_query, ControlFlowGraph, XrefIndex, XrefRelation};
use luad_core::id::StableId;
use luad_dialect_lua54::lift_proto_lua54;
use luad_oracle::compile_and_parse_lua54;

#[test]
fn test_cfg_block_partitioning_and_reachability() {
    let source = fs::read_to_string("../../tests/fixtures/control_flow.lua").expect("read failed");
    let chunk = compile_and_parse_lua54(&source, false).expect("parse failed");

    let lifted = lift_proto_lua54(&chunk.main_proto);
    let cfg = ControlFlowGraph::build(&chunk.main_proto, &lifted);

    assert!(cfg.blocks.len() > 5);
    assert_eq!(cfg.blocks[0].is_entry, true);
    assert!(cfg.blocks.iter().any(|b| b.is_exit));

    // Entry block must be reachable
    assert!(cfg.blocks[0].is_reachable);

    // DOT rendering output check
    let dot = cfg.to_dot();
    assert!(dot.contains("digraph"));
    assert!(dot.contains("LoopBack"));
}

#[test]
fn test_xrefs_indexing_and_query() {
    let source = fs::read_to_string("../../tests/fixtures/closures.lua").expect("read failed");
    let chunk = compile_and_parse_lua54(&source, false).expect("parse failed");

    let index = XrefIndex::build(&chunk);
    assert!(!index.entries.is_empty());

    // Query references to upvalue
    let upval_id: StableId = "proto:0/0/0:upvalue:0".parse().unwrap();
    let to_refs = index.query_to(&upval_id);
    assert_eq!(to_refs.len(), 3);
    assert!(to_refs.iter().any(|r| r.relation == XrefRelation::Writes));
    assert!(to_refs.iter().any(|r| r.relation == XrefRelation::Reads));
}

#[test]
fn test_structured_query_engine() {
    let source = fs::read_to_string("../../tests/fixtures/closures.lua").expect("read failed");
    let chunk = compile_and_parse_lua54(&source, false).expect("parse failed");

    let resp = execute_query(&chunk, Some("opcode == \"OP_CALL\""), 10, None);
    assert_eq!(resp.count, 3);
    assert!(!resp.is_truncated);

    // Test pagination limit
    let paginated = execute_query(&chunk, Some("opcode == \"OP_CALL\""), 2, None);
    assert_eq!(paginated.count, 2);
    assert!(paginated.is_truncated);
    assert_eq!(paginated.next_cursor.as_deref(), Some("2"));

    // Follow cursor
    let page2 = execute_query(&chunk, Some("opcode == \"OP_CALL\""), 2, paginated.next_cursor.as_deref());
    assert_eq!(page2.count, 1);
    assert!(!page2.is_truncated);
}

#[test]
fn test_chunk_diffing() {
    let src1 = "local x = 10; return x";
    let src2 = "local x = 20; return x";

    let chunk1 = compile_and_parse_lua54(src1, false).expect("parse failed");
    let chunk2 = compile_and_parse_lua54(src2, false).expect("parse failed");

    let diff = diff_chunks(&chunk1, &chunk2, true, false);
    assert!(!diff.is_identical);
    assert_eq!(diff.proto_diffs.len(), 1);

    // Same chunk compared against itself
    let self_diff = diff_chunks(&chunk1, &chunk1, true, false);
    assert!(self_diff.is_identical);
    assert!(self_diff.proto_diffs.is_empty());
}
