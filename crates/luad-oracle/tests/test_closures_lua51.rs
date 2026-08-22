//! Gate L2: Lua 5.1 closure-binding and capture facts tests.

use luad_core::reader::SafeReader;
use luad_dialect_lua51::{decode_chunk_lua51, lift_proto_lua51, validate_chunk_lua51, RawInstruction51, Opcode51};
use luad_oracle::get_fixture_bytes;

#[test]
fn test_lua51_closure_binding_descriptors_attached_to_closure() {
    let raw_bytes = get_fixture_bytes("lua5.1", "closures", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    // The inner closure is created in child proto 0
    let child_proto = &chunk.main_proto.protos[0];
    let lifted = lift_proto_lua51(child_proto);

    // Find OP_CLOSURE in child_proto
    let closure_inst = lifted
        .iter()
        .find(|i| i.mnemonic == "CLOSURE")
        .expect("CLOSURE instruction present in child proto");

    // Parent closure must have captured facts in reads / implicit_effects
    assert!(
        !closure_inst.reads.is_empty(),
        "CLOSURE instruction must record reads of captured variables"
    );
    assert!(
        closure_inst
            .implicit_effects
            .iter()
            .any(|e| matches!(e, luad_core::ir::ImplicitEffect::CaptureUpvalue { .. })),
        "CLOSURE instruction must record CaptureUpvalue implicit effects"
    );
}

#[test]
fn test_lua51_closure_bindings_not_executed_as_standalone_instructions() {
    let raw_bytes = get_fixture_bytes("lua5.1", "closures", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    let child_proto = &chunk.main_proto.protos[0];
    let lifted = lift_proto_lua51(child_proto);

    let binding_descs: Vec<_> = lifted
        .iter()
        .filter(|i| i.mnemonic.contains("binding descriptor"))
        .collect();

    assert!(
        !binding_descs.is_empty(),
        "Closures fixture child proto must contain binding descriptors"
    );

    for desc in &binding_descs {
        assert!(
            desc.writes.is_empty(),
            "Closure binding descriptor at PC {} must have empty writes (cannot execute standalone)",
            desc.pc
        );
        assert!(
            desc.companion_pc.is_some(),
            "Binding descriptor must link to parent closure PC"
        );
    }
}


#[test]
fn test_lua51_closure_binding_preserves_physical_pc_words() {
    let raw_bytes = get_fixture_bytes("lua5.1", "closures", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    let lifted = lift_proto_lua51(&chunk.main_proto);

    // Every physical instruction word in the prototype must be represented in lifted IR
    assert_eq!(lifted.len(), chunk.main_proto.instructions.len());

    for (i, inst) in lifted.iter().enumerate() {
        assert_eq!(inst.pc, i);
        assert_eq!(inst.raw_word, chunk.main_proto.instructions[i].raw_word);
        assert_eq!(inst.source.byte_length, 4);
    }
}

#[test]
fn test_negative_control_binding_move_produces_no_standalone_write() {
    let raw_bytes = get_fixture_bytes("lua5.1", "closures", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    let child_proto = &chunk.main_proto.protos[0];
    let lifted = lift_proto_lua51(child_proto);

    for (pc, inst) in lifted.iter().enumerate() {
        if inst.mnemonic == "CLOSURE" {
            // Check immediately following descriptor instruction
            if let Some(next) = lifted.get(pc + 1) {
                if next.mnemonic.contains("binding descriptor") {
                    assert!(
                        next.writes.is_empty(),
                        "Pseudo-MOVE at PC {} must produce 0 register writes",
                        next.pc
                    );
                }
            }
        }
    }
}

#[test]
fn test_negative_control_invalid_binding_opcode_rejected() {
    let raw_bytes = get_fixture_bytes("lua5.1", "closures", false).expect("fixture failed");
    let mut reader = SafeReader::new(&raw_bytes);
    let mut chunk = decode_chunk_lua51(&mut reader).expect("clean decode");

    // In child proto 0, find CLOSURE instruction and corrupt the following binding descriptor to OP_ADD
    let child = &mut chunk.main_proto.protos[0];
    let mut closure_pc = None;
    for (pc, inst) in child.instructions.iter().enumerate() {
        let raw = RawInstruction51::decode(inst.raw_word);
        if raw.opcode == Some(Opcode51::Closure) {
            closure_pc = Some(pc);
            break;
        }
    }

    let c_pc = closure_pc.expect("CLOSURE instruction found in child proto");
    // Replace instruction at c_pc + 1 with OP_ADD
    let add_word = RawInstruction51::encode_iabc(Opcode51::Add, 0, 0, 0);
    child.instructions[c_pc + 1].raw_word = add_word;

    let (verdict, diags) = validate_chunk_lua51(&chunk);
    assert_eq!(
        verdict,
        luad_core::diagnostic::Verdict::Invalid,
        "Invalid binding opcode must fail validation"
    );
    assert!(
        diags.iter().any(|d| d.code == "L51-CLOSURE-002"),
        "Expected L51-CLOSURE-002 diagnostic for invalid binding opcode, found: {:?}",
        diags
    );
}

