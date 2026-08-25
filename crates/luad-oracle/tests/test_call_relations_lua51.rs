//! Mutation-sensitive evidence for Lua 5.1 caller-to-prototype relations.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::Command;

use luad_analysis::{
    analyze_chunk_call_relations, CallRelationBasis, CallRelationResolution,
    CallRelationUnresolvedReason, ChunkCallRelationAnalysis, XrefIndex, XrefRelation,
};
use luad_core::envelope::{JsonlDataRecord, MachineDocument};

fn fixture_source() -> String {
    let root = luad_oracle::find_workspace_root();
    std::fs::read_to_string(root.join("tests/fixtures/call_relations.lua"))
        .expect("read call relation fixture")
}

fn fixture_chunk() -> luad_core::Chunk {
    let _ = luad_oracle::require_luac51();
    luad_oracle::compile_and_parse_lua51(&fixture_source(), false).expect("compile fixture")
}

fn get_luad_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path;
    }
    static LUAD: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LUAD.get_or_init(|| {
        let root = luad_oracle::find_workspace_root();
        let output = Command::new("cargo")
            .args(["build", "-p", "luad-cli", "--bin", "luad"])
            .current_dir(&root)
            .output()
            .expect("build luad");
        assert!(output.status.success(), "luad build failed");
        root.join("target/debug/luad").display().to_string()
    })
    .clone()
}

fn compiled_fixture_file() -> tempfile::NamedTempFile {
    let bytes = luad_oracle::compile_source_lua51(&fixture_source(), false)
        .expect("compile call relation fixture");
    let mut file = tempfile::NamedTempFile::new().expect("temp fixture");
    file.write_all(&bytes).expect("write fixture");
    file
}

fn all_facts(analysis: &ChunkCallRelationAnalysis) -> Vec<&luad_analysis::CallRelationFact> {
    analysis
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
        .collect()
}

#[test]
fn test_call_relation_matrix_histogram_and_cardinality_are_pinned() {
    let analysis = analyze_chunk_call_relations(&fixture_chunk());
    let mut histogram = BTreeMap::new();
    for fact in all_facts(&analysis) {
        let key = match &fact.resolution {
            CallRelationResolution::Resolved { basis, .. } => format!("resolved:{basis:?}"),
            CallRelationResolution::Unresolved { reason, .. } => {
                format!("unresolved:{reason:?}")
            }
        };
        *histogram.entry(key).or_insert(0usize) += 1;
    }
    assert_eq!(
        histogram,
        BTreeMap::from([
            ("resolved:ClosureValue".to_string(), 5),
            ("resolved:UniqueGlobalStore".to_string(), 2),
            ("unresolved:ControlFlowConflict".to_string(), 1),
            ("unresolved:MissingPrototypeStore".to_string(), 1),
            ("unresolved:MultiplePrototypeStores".to_string(), 1),
            ("unresolved:MutableCapture".to_string(), 1),
            ("unresolved:NonClosureStore".to_string(), 1),
            ("unresolved:Overwritten".to_string(), 2),
        ])
    );
    assert_eq!(all_facts(&analysis).len(), 14);
}

#[test]
fn test_store_time_targets_and_multihop_capture_are_exact() {
    let analysis = analyze_chunk_call_relations(&fixture_chunk());
    let facts = all_facts(&analysis);

    let first = facts
        .iter()
        .find(|fact| fact.pc == 8)
        .expect("first global");
    let second = facts
        .iter()
        .find(|fact| fact.pc == 13)
        .expect("second global");
    assert!(matches!(
        first.resolution,
        CallRelationResolution::Resolved {
            ref callee,
            basis: CallRelationBasis::UniqueGlobalStore,
            ..
        } if callee.to_string() == "0/0"
    ));
    assert!(matches!(
        second.resolution,
        CallRelationResolution::Resolved {
            ref callee,
            basis: CallRelationBasis::UniqueGlobalStore,
            ..
        } if callee.to_string() == "0/1"
    ));
    let first_evidence = match &first.resolution {
        CallRelationResolution::Resolved { evidence, .. } => evidence,
        _ => unreachable!(),
    };
    let second_evidence = match &second.resolution {
        CallRelationResolution::Resolved { evidence, .. } => evidence,
        _ => unreachable!(),
    };
    assert!(first_evidence
        .iter()
        .any(|id| id.to_string() == "proto:0:pc:5"));
    assert!(second_evidence
        .iter()
        .any(|id| id.to_string() == "proto:0:pc:10"));

    let nested = facts
        .iter()
        .find(|fact| fact.call_id.to_string() == "proto:0/2/0/0:pc:2")
        .expect("three-hop captured closure call");
    let CallRelationResolution::Resolved {
        callee, evidence, ..
    } = &nested.resolution
    else {
        panic!("captured closure relation must resolve")
    };
    assert_eq!(callee.to_string(), "0/0");
    assert!(evidence.len() >= 7, "every capture hop remains auditable");
    assert!(evidence.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn test_every_call_has_one_relation_and_every_resolved_relation_has_one_xref() {
    fn count_calls(dialect: &str, proto: &luad_core::Prototype) -> usize {
        let here = luad_analysis::lift_proto_for_dialect(dialect, proto)
            .iter()
            .filter(|instruction| matches!(instruction.mnemonic.as_str(), "CALL" | "TAILCALL"))
            .count();
        here + proto
            .protos
            .iter()
            .map(|child| count_calls(dialect, child))
            .sum::<usize>()
    }

    let chunk = fixture_chunk();
    let analysis = analyze_chunk_call_relations(&chunk);
    let facts = all_facts(&analysis);
    assert_eq!(facts.len(), count_calls(&chunk.dialect, &chunk.main_proto));
    assert!(
        facts.iter().any(|fact| fact.call_kind == "TAILCALL"),
        "fixture must exercise the physical TAILCALL form"
    );
    assert_eq!(
        facts
            .iter()
            .map(|fact| &fact.call_id)
            .collect::<BTreeSet<_>>()
            .len(),
        facts.len()
    );

    let expected: BTreeSet<_> = facts
        .iter()
        .filter_map(|fact| match &fact.resolution {
            CallRelationResolution::Resolved { callee, .. } => Some((
                fact.call_id.clone(),
                luad_core::StableId::proto(callee.clone()),
            )),
            CallRelationResolution::Unresolved { .. } => None,
        })
        .collect();
    let actual: BTreeSet<_> = XrefIndex::build(&chunk)
        .entries
        .into_iter()
        .filter(|entry| entry.relation == XrefRelation::Calls)
        .map(|entry| (entry.source, entry.target))
        .collect();
    assert_eq!(actual, expected);

    let unresolved = facts
        .iter()
        .find(|fact| matches!(fact.resolution, CallRelationResolution::Unresolved { .. }))
        .expect("unresolved call");
    let mut invented = actual.clone();
    invented.insert((
        unresolved.call_id.clone(),
        luad_core::StableId::proto(luad_core::ProtoPath::root().child(0)),
    ));
    assert_ne!(invented, expected, "unresolved calls cannot acquire xrefs");
}

#[test]
fn test_call_relation_killer_mutations_are_rejected() {
    let expected = analyze_chunk_call_relations(&fixture_chunk());

    let mut deleted = expected.clone();
    deleted.prototypes[0].calls.remove(0);
    assert_ne!(deleted, expected, "missing physical call must be detected");

    let mut swapped = expected.clone();
    let global = swapped.prototypes[0]
        .calls
        .iter_mut()
        .find(|fact| fact.pc == 8)
        .expect("global relation");
    let CallRelationResolution::Resolved { callee, .. } = &mut global.resolution else {
        panic!("resolved global")
    };
    *callee = luad_core::ProtoPath::root().child(1);
    assert_ne!(swapped, expected, "adjacent target swap must be detected");

    let mut invented = expected.clone();
    let conflict = invented.prototypes[0]
        .calls
        .iter_mut()
        .find(|fact| {
            matches!(
                fact.resolution,
                CallRelationResolution::Unresolved {
                    reason: CallRelationUnresolvedReason::ControlFlowConflict,
                    ..
                }
            )
        })
        .expect("conflict");
    conflict.resolution = CallRelationResolution::Resolved {
        callee: luad_core::ProtoPath::root().child(0),
        basis: CallRelationBasis::ClosureValue,
        evidence: vec![conflict.call_id.clone()],
    };
    assert_ne!(invented, expected, "erased CFG conflict must be detected");

    let mut collapsed = expected.clone();
    let collision = collapsed.prototypes[0]
        .calls
        .iter_mut()
        .find(|fact| {
            matches!(
                fact.resolution,
                CallRelationResolution::Unresolved {
                    reason: CallRelationUnresolvedReason::MultiplePrototypeStores,
                    ..
                }
            )
        })
        .expect("multiple stores");
    collision.resolution = CallRelationResolution::Resolved {
        callee: luad_core::ProtoPath::root().child(0),
        basis: CallRelationBasis::UniqueGlobalStore,
        evidence: vec![collision.call_id.clone()],
    };
    assert_ne!(
        collapsed, expected,
        "multiple stores cannot choose a target"
    );

    let mut evidence_mutation = expected.clone();
    let CallRelationResolution::Resolved {
        evidence: relation_evidence,
        ..
    } = &mut evidence_mutation.prototypes[0].calls[0].resolution
    else {
        panic!("resolved relation")
    };
    relation_evidence.clear();
    assert_ne!(
        evidence_mutation, expected,
        "evidence removal must be detected"
    );

    let mut dropped_capture = expected.clone();
    let nested = dropped_capture
        .prototypes
        .iter_mut()
        .flat_map(|prototype| prototype.calls.iter_mut())
        .find(|fact| fact.call_id.to_string() == "proto:0/2/0/0:pc:2")
        .expect("three-hop captured call");
    let CallRelationResolution::Resolved { evidence, .. } = &mut nested.resolution else {
        panic!("captured relation")
    };
    evidence.remove(1);
    assert_ne!(
        dropped_capture, expected,
        "missing closure-binding evidence must be detected"
    );
}

#[test]
fn test_public_callgraph_json_jsonl_and_text_agree() {
    let luad = get_luad_bin();
    let fixture = compiled_fixture_file();
    let path = fixture.path().to_str().expect("path");

    let json = Command::new(&luad)
        .args(["callgraph", path, "--format", "json"])
        .output()
        .expect("callgraph json");
    assert!(json.status.success());
    let document: MachineDocument<ChunkCallRelationAnalysis> =
        serde_json::from_slice(&json.stdout).expect("typed callgraph document");
    let expected = all_facts(&document.data).len();

    let jsonl = Command::new(&luad)
        .args(["callgraph", path, "--format", "jsonl"])
        .output()
        .expect("callgraph jsonl");
    assert!(jsonl.status.success());
    let records: Vec<serde_json::Value> = jsonl
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("jsonl record"))
        .collect();
    let facts: Vec<_> = records
        .iter()
        .filter(|record| record["record_type"] == "call_relation")
        .collect();
    assert_eq!(facts.len(), expected);
    for fact in facts {
        let _: JsonlDataRecord<luad_analysis::CallRelationFact> =
            serde_json::from_value(fact.clone()).expect("typed relation record");
        assert_eq!(
            fact["context"]["input_identity"]["sha256"],
            document.input_identity.sha256
        );
    }

    let text = Command::new(&luad)
        .args(["callgraph", path, "--format", "text"])
        .output()
        .expect("callgraph text");
    assert!(text.status.success());
    assert_eq!(
        text.stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        expected
    );
    let rendered = String::from_utf8(text.stdout).expect("utf8 text");
    assert!(rendered.contains("proto:0/0"));
    assert!(rendered.contains("unresolved:MultiplePrototypeStores"));
}

#[test]
fn test_export_relations_equal_direct_command() {
    let luad = get_luad_bin();
    let fixture = compiled_fixture_file();
    let path = fixture.path().to_str().expect("path");
    let direct: MachineDocument<ChunkCallRelationAnalysis> = serde_json::from_slice(
        &Command::new(&luad)
            .args(["callgraph", path, "--format", "json"])
            .output()
            .expect("direct")
            .stdout,
    )
    .expect("direct document");
    let exported = Command::new(&luad)
        .args(["export", path, "--format", "jsonl"])
        .output()
        .expect("export");
    assert!(exported.status.success());
    let export_facts: Vec<luad_analysis::CallRelationFact> = exported
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_slice(line).expect("jsonl");
            (value["record_type"] == "call_relation")
                .then(|| serde_json::from_value(value["data"].clone()).expect("relation"))
        })
        .collect();
    let direct_facts: Vec<_> = direct
        .data
        .prototypes
        .into_iter()
        .flat_map(|prototype| prototype.calls)
        .collect();
    assert_eq!(export_facts, direct_facts);
}

#[test]
fn test_callgraph_schema_capability_and_lnum_profile_are_public() {
    let luad = get_luad_bin();
    let schema = Command::new(&luad)
        .args(["schema", "callgraph"])
        .output()
        .expect("schema");
    assert!(schema.status.success());
    let schema_json: serde_json::Value =
        serde_json::from_slice(&schema.stdout).expect("schema json");
    assert!(schema_json["definitions"]["CallRelationResolution"].is_object());

    let capabilities = Command::new(&luad)
        .args(["capabilities", "--format", "json"])
        .output()
        .expect("capabilities");
    let manifest: serde_json::Value =
        serde_json::from_slice(&capabilities.stdout).expect("capabilities json");
    let lua51 = manifest["dialects"]
        .as_array()
        .expect("dialects")
        .iter()
        .find(|dialect| dialect["id"] == "lua5.1")
        .expect("lua5.1");
    assert!(lua51["features"]
        .as_array()
        .expect("features")
        .iter()
        .any(|feature| feature == "provable call relations (experimental)"));

    let root = luad_oracle::find_workspace_root();
    let lnum = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");
    let output = Command::new(&luad)
        .args([
            "callgraph",
            lnum.to_str().expect("lnum"),
            "--format",
            "json",
        ])
        .output()
        .expect("lnum callgraph");
    assert!(output.status.success());
    let document: MachineDocument<ChunkCallRelationAnalysis> =
        serde_json::from_slice(&output.stdout).expect("lnum document");
    assert_eq!(document.interpretation.profile, "lua5.1-lnum32");
}
