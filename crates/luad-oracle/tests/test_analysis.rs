use luad_analysis::{diff_chunks, execute_query, ControlFlowGraph, XrefIndex, XrefRelation};
use luad_core::id::StableId;
use luad_core::reader::SafeReader;
use luad_dialect_lua54::lift_proto_lua54;
use luad_oracle::get_fixture_bytes;

#[test]
fn test_cfg_block_partitioning_and_reachability() {
    let raw_bytes = get_fixture_bytes("lua5.4", "control_flow", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("parse failed");

    let lifted = lift_proto_lua54(&chunk.main_proto);
    let cfg = ControlFlowGraph::build(&chunk.main_proto, &lifted);

    assert!(cfg.blocks.len() > 5);
    assert!(cfg.blocks[0].is_entry);
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
    let raw_bytes = get_fixture_bytes("lua5.4", "closures", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("parse failed");

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
    let raw_bytes = get_fixture_bytes("lua5.4", "closures", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("parse failed");

    let resp = execute_query(&chunk, Some("opcode == \"OP_CALL\""), 10, None);
    assert_eq!(resp.count, 3);
    assert!(!resp.is_truncated);

    // Test pagination limit
    let paginated = execute_query(&chunk, Some("opcode == \"OP_CALL\""), 2, None);
    assert_eq!(paginated.count, 2);
    assert!(paginated.is_truncated);
    assert_eq!(paginated.next_cursor.as_deref(), Some("2"));

    // Follow cursor
    let page2 = execute_query(
        &chunk,
        Some("opcode == \"OP_CALL\""),
        2,
        paginated.next_cursor.as_deref(),
    );
    assert_eq!(page2.count, 1);
    assert!(!page2.is_truncated);
}

#[test]
fn test_chunk_diffing() {
    let raw1 = get_fixture_bytes("lua5.4", "hello", false).expect("fixture 1 failed");
    let mut reader1 = SafeReader::new(&raw1);
    let chunk1 = luad_dialect_lua54::decode_chunk_lua54(&mut reader1).expect("parse failed");

    let raw2 = get_fixture_bytes("lua5.4", "closures", false).expect("fixture 2 failed");
    let mut reader2 = SafeReader::new(&raw2);
    let chunk2 = luad_dialect_lua54::decode_chunk_lua54(&mut reader2).expect("parse failed");

    let diff = diff_chunks(&chunk1, &chunk2, true, false);
    assert!(!diff.is_identical);
    assert_ne!(diff.old_sha256, diff.new_sha256);
}

#[test]
fn test_cfg_dominator_tree_golden_topologies() {
    let raw_bytes = get_fixture_bytes("lua5.4", "control_flow", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("parse failed");

    let lifted = lift_proto_lua54(&chunk.main_proto);
    let cfg = ControlFlowGraph::build(&chunk.main_proto, &lifted);

    // Entry block (0) dominates reachable blocks
    assert_eq!(cfg.blocks[0].immediate_dominator, None);

    for block in &cfg.blocks {
        if block.is_reachable && block.index != 0 {
            assert!(
                block.immediate_dominator.is_some(),
                "Reachable block {} must have immediate dominator",
                block.index
            );
            let idom = block.immediate_dominator.unwrap();
            assert!(
                idom < block.index || cfg.blocks[idom].is_reachable,
                "Immediate dominator {idom} must be valid"
            );
        }
    }
}

#[test]
fn test_analysis_refuses_invalid_chunks() {
    use luad_analysis::validate_for_analysis;
    use luad_core::model::InstructionWord;
    use luad_core::SourceLocation;

    let raw_bytes = get_fixture_bytes("lua5.4", "hello", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let mut chunk = luad_dialect_lua54::decode_chunk_lua54(&mut reader).expect("parse failed");

    // Clean chunk passes validation
    assert!(validate_for_analysis(&chunk).is_ok());

    // Corrupt with out-of-bounds jump (JMP +5000)
    let bad_jmp_word =
        luad_dialect_lua54::RawInstruction54::encode_isj(luad_dialect_lua54::Opcode54::Jmp, 5000);
    chunk.main_proto.instructions.push(InstructionWord {
        id: luad_core::id::StableId::instruction(chunk.main_proto.path.clone(), 99),
        pc: 99,
        raw_word: bad_jmp_word,
        raw_hex: hex::encode(bad_jmp_word.to_le_bytes()),
        source: SourceLocation::new(0, &bad_jmp_word.to_le_bytes()),
    });

    let res = validate_for_analysis(&chunk);
    assert!(res.is_err(), "Must refuse invalid jump destination");
    let diags = res.unwrap_err();
    assert!(
        diags.iter().any(|d| d.code == "L54-VAL-JUMP-001"),
        "Expected L54-VAL-JUMP-001 diagnostic"
    );
}
