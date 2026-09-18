//! Sound symbolic-callee facts across the Lua 5.1 library and public CLI surfaces.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::Command;

use luad_analysis::{
    analyze_chunk_callees, CalleeResolution, CalleeUnresolvedReason, ChunkCalleeAnalysis,
    SymbolicPathBasis,
};
use luad_core::envelope::{JsonlDataRecord, MachineDocument};

fn fixture_source() -> String {
    let root = luad_oracle::find_workspace_root();
    std::fs::read_to_string(root.join("tests/fixtures/callees.lua")).expect("read callees.lua")
}

fn fixture_chunk() -> luad_core::Chunk {
    let _ = luad_oracle::require_luac51();
    luad_oracle::compile_and_parse_lua51(&fixture_source(), false).expect("compile fixture")
}

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

fn compiled_fixture_file() -> tempfile::NamedTempFile {
    let bytes = luad_oracle::compile_source_lua51(&fixture_source(), false)
        .expect("compile callees fixture");
    let mut file = tempfile::NamedTempFile::new().expect("temp fixture");
    file.write_all(&bytes).expect("write fixture");
    file
}

fn all_facts(analysis: &ChunkCalleeAnalysis) -> Vec<&luad_analysis::CalleeFact> {
    analysis
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
        .collect()
}

#[test]
fn test_callee_resolution_fixture_histogram_is_pinned() {
    let analysis = analyze_chunk_callees(&fixture_chunk());
    let mut histogram = BTreeMap::new();
    for fact in all_facts(&analysis) {
        let key = match &fact.resolution {
            CalleeResolution::ResolvedPath { basis, .. } => format!("path:{basis:?}"),
            CalleeResolution::ResolvedPrototype { .. } => "prototype".to_string(),
            CalleeResolution::LookupLabel { .. } => "lookup-label".to_string(),
            CalleeResolution::Unresolved { reason } => format!("unresolved:{reason:?}"),
        };
        *histogram.entry(key).or_insert(0usize) += 1;
    }
    assert_eq!(
        histogram,
        BTreeMap::from([
            ("path:GlobalLabel".to_string(), 5),
            ("path:ModuleLabel".to_string(), 3),
            ("prototype".to_string(), 4),
            ("unresolved:ControlFlowConflict".to_string(), 1),
            ("unresolved:MissingDefinition".to_string(), 1),
            ("unresolved:MutableCapture".to_string(), 1),
            ("unresolved:Overwritten".to_string(), 2),
        ])
    );
}

#[test]
fn test_callee_resolution_proves_paths_joins_and_multihop_captures() {
    let chunk = fixture_chunk();
    let analysis = analyze_chunk_callees(&chunk);
    let facts = all_facts(&analysis);

    let module_paths: Vec<_> = facts
        .iter()
        .filter_map(|fact| match &fact.resolution {
            CalleeResolution::ResolvedPath {
                basis: SymbolicPathBasis::ModuleLabel,
                segments,
                evidence,
            } => Some((segments.join("."), evidence)),
            _ => None,
        })
        .collect();
    assert!(module_paths.iter().any(|(path, _)| path == "luci.sys.call"));
    assert!(module_paths.iter().any(|(path, _)| path == "luci.sys.exec"));
    let nested = module_paths
        .iter()
        .find(|(path, _)| path == "luci.sys.fork_exec")
        .expect("three-level capture path");
    assert!(
        nested.1.len() >= 6,
        "capture evidence must retain every hop"
    );
    assert!(nested.1.windows(2).all(|pair| pair[0] < pair[1]));

    let same_branch = facts.iter().find(|fact| fact.pc == 23).expect("same join");
    let CalleeResolution::ResolvedPath { evidence, .. } = &same_branch.resolution else {
        panic!("identical branch labels must survive")
    };
    assert_eq!(
        evidence.len(),
        3,
        "both branch definitions and MOVE must remain"
    );

    assert!(facts.iter().any(|fact| matches!(
        fact.resolution,
        CalleeResolution::Unresolved {
            reason: CalleeUnresolvedReason::ControlFlowConflict
        }
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact.resolution,
        CalleeResolution::Unresolved {
            reason: CalleeUnresolvedReason::MutableCapture
        }
    )));

    let origins = luad_analysis::analyze_chunk_origins(&chunk);
    let origin_facts: Vec<_> = origins
        .prototypes
        .iter()
        .flat_map(|proto| &proto.calls)
        .collect();

    let forward_call = facts
        .iter()
        .find(|fact| {
            matches!(
                &fact.resolution,
                CalleeResolution::ResolvedPath {
                    basis: SymbolicPathBasis::GlobalLabel,
                    segments,
                    ..
                } if segments == &["print"]
            ) && fact.proto_path.to_string() != "0"
        })
        .expect("forward(...) print callee must resolve");

    let CalleeResolution::ResolvedPath {
        basis: SymbolicPathBasis::GlobalLabel,
        segments,
        evidence,
    } = &forward_call.resolution
    else {
        unreachable!()
    };
    assert_eq!(segments, &["print"]);
    assert!(
        !evidence.is_empty(),
        "forwarded callee must retain instruction evidence"
    );

    let forward_origin = origin_facts
        .iter()
        .find(|origin| origin.call_id == forward_call.call_id)
        .expect("forward origin fact must exist");
    assert!(
        matches!(
            forward_origin.argument_window,
            luad_analysis::CallArgumentWindow::Open {
                reason: luad_analysis::OriginUnknownReason::OpenArgumentWindow
            }
        ),
        "forwarded call origin must retain an open argument window"
    );

    let dynamic_call = facts
        .iter()
        .find(|fact| {
            matches!(
                fact.resolution,
                CalleeResolution::Unresolved {
                    reason: CalleeUnresolvedReason::MissingDefinition
                }
            ) && fact.proto_path.to_string() != "0"
        })
        .expect("dynamic forwarder callee must remain unresolved due to missing definition");

    let dynamic_origin = origin_facts
        .iter()
        .find(|origin| origin.call_id == dynamic_call.call_id)
        .expect("dynamic forwarder origin fact must exist");
    assert!(
        matches!(
            dynamic_origin.argument_window,
            luad_analysis::CallArgumentWindow::Open {
                reason: luad_analysis::OriginUnknownReason::OpenArgumentWindow
            }
        ),
        "dynamic forwarder call origin must retain an open argument window"
    );
}

#[test]
fn test_every_physical_call_has_exactly_one_fact() {
    fn count_calls(dialect: &str, proto: &luad_core::Prototype) -> usize {
        let here = luad_analysis::lift_proto_for_dialect(dialect, proto)
            .iter()
            .filter(|inst| matches!(inst.mnemonic.as_str(), "CALL" | "TAILCALL"))
            .count();
        here + proto
            .protos
            .iter()
            .map(|child| count_calls(dialect, child))
            .sum::<usize>()
    }

    let chunk = fixture_chunk();
    let analysis = analyze_chunk_callees(&chunk);
    let facts = all_facts(&analysis);
    assert_eq!(facts.len(), count_calls(&chunk.dialect, &chunk.main_proto));
    let ids: std::collections::BTreeSet<_> = facts.iter().map(|fact| &fact.call_id).collect();
    assert_eq!(ids.len(), facts.len(), "call facts must be one-to-one");
}

#[test]
fn test_callee_killer_mutations_do_not_match_recomputed_facts() {
    let expected = analyze_chunk_callees(&fixture_chunk());

    let mut deleted = expected.clone();
    deleted.prototypes[0].calls.remove(0);
    assert_ne!(deleted, expected, "deleting a fact must be detected");

    let mut invented = expected.clone();
    let unresolved = invented
        .prototypes
        .iter_mut()
        .flat_map(|prototype| &mut prototype.calls)
        .find(|fact| matches!(fact.resolution, CalleeResolution::Unresolved { .. }))
        .expect("unresolved fact");
    unresolved.resolution = CalleeResolution::ResolvedPath {
        basis: SymbolicPathBasis::ModuleLabel,
        segments: vec!["invented".into()],
        evidence: vec![unresolved.call_id.clone()],
    };
    assert_ne!(invented, expected, "inventing a path must be detected");

    let mut evidence_mutation = expected.clone();
    let resolved = evidence_mutation
        .prototypes
        .iter_mut()
        .flat_map(|prototype| &mut prototype.calls)
        .find_map(|fact| match &mut fact.resolution {
            CalleeResolution::ResolvedPath { evidence, .. } => Some(evidence),
            _ => None,
        })
        .expect("resolved evidence");
    resolved.clear();
    assert_ne!(
        evidence_mutation, expected,
        "evidence mutation must be detected"
    );
}

#[test]
fn test_public_callees_json_jsonl_and_text_agree() {
    let luad = get_luad_bin();
    let fixture = compiled_fixture_file();
    let path = fixture.path().to_str().expect("path");
    let json = Command::new(&luad)
        .args(["callees", path, "--format", "json"])
        .output()
        .expect("callees json");
    assert!(json.status.success());
    let document: MachineDocument<ChunkCalleeAnalysis> =
        serde_json::from_slice(&json.stdout).expect("typed document");
    let expected = all_facts(&document.data).len();

    let jsonl = Command::new(&luad)
        .args(["callees", path, "--format", "jsonl"])
        .output()
        .expect("callees jsonl");
    assert!(jsonl.status.success());
    let records: Vec<serde_json::Value> = jsonl
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("jsonl record"))
        .collect();
    let facts: Vec<_> = records
        .iter()
        .filter(|record| record["record_type"] == "callee")
        .collect();
    assert_eq!(facts.len(), expected);
    for fact in facts {
        let _: JsonlDataRecord<luad_analysis::CalleeFact> =
            serde_json::from_value(fact.clone()).expect("typed callee record");
        assert_eq!(
            fact["context"]["input_identity"]["sha256"],
            document.input_identity.sha256
        );
        assert_eq!(
            fact["context"]["interpretation"]["profile"],
            document.interpretation.profile
        );
    }

    let text = Command::new(&luad)
        .args(["callees", path, "--format", "text"])
        .output()
        .expect("callees text");
    assert!(text.status.success());
    assert_eq!(
        text.stdout
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        expected
    );
}

#[test]
fn test_export_emits_self_identifying_callee_facts() {
    let luad = get_luad_bin();
    let fixture = compiled_fixture_file();
    let path = fixture.path().to_str().expect("path");
    let expected_analysis = analyze_chunk_callees(&fixture_chunk());
    let expected_call_id = all_facts(&expected_analysis)
        .into_iter()
        .find_map(|fact| match &fact.resolution {
            CalleeResolution::ResolvedPath {
                basis: SymbolicPathBasis::GlobalLabel,
                segments,
                ..
            } if segments == &["print"] && fact.proto_path.to_string() != "0" => {
                Some(fact.call_id.to_string())
            }
            _ => None,
        })
        .expect("open-window forwarded print call");
    let output = Command::new(&luad)
        .args(["export", path, "--format", "jsonl"])
        .output()
        .expect("export");
    assert!(output.status.success());
    let callees: Vec<serde_json::Value> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("jsonl"))
        .filter(|record: &serde_json::Value| record["record_type"] == "callee")
        .collect();
    assert_eq!(callees.len(), 17);
    assert!(callees.iter().all(|record| {
        record["context"]["input_identity"]["sha256"].is_string()
            && record["context"]["interpretation"]["profile"].is_string()
    }));
    assert!(callees
        .iter()
        .any(|record| record["data"]["call_id"] == expected_call_id));

    let query_output = Command::new(&luad)
        .args([
            "query",
            path,
            "--where",
            "callee.path == \"print\"",
            "--format",
            "json",
        ])
        .output()
        .expect("query");
    assert!(query_output.status.success());
    let query_doc: serde_json::Value =
        serde_json::from_slice(&query_output.stdout).expect("query json");
    let matches = query_doc["data"]["matches"].as_array().expect("matches");
    assert!(
        matches
            .iter()
            .any(|query_match| query_match["id"] == expected_call_id),
        "query must retain the exact open-window forwarded print callee"
    );
}

#[test]
fn test_callees_schema_capability_and_lnum_profile_are_public() {
    let luad = get_luad_bin();
    let schema = Command::new(&luad)
        .args(["schema", "callees"])
        .output()
        .expect("schema");
    assert!(schema.status.success());
    let schema_json: serde_json::Value =
        serde_json::from_slice(&schema.stdout).expect("schema json");
    assert!(schema_json["definitions"]["CalleeResolution"].is_object());

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
        .any(|feature| feature == "symbolic callees (experimental)"));

    let root = luad_oracle::find_workspace_root();
    let lnum = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");
    let output = Command::new(&luad)
        .args(["callees", lnum.to_str().expect("lnum"), "--format", "json"])
        .output()
        .expect("lnum callees");
    assert!(output.status.success());
    let document: MachineDocument<ChunkCalleeAnalysis> =
        serde_json::from_slice(&output.stdout).expect("lnum document");
    assert_eq!(document.interpretation.profile, "lua5.1-lnum32");
    assert!(matches!(
        document.data.prototypes[0].calls[0].resolution,
        CalleeResolution::ResolvedPath {
            basis: SymbolicPathBasis::GlobalLabel,
            ..
        }
    ));
}

#[test]
fn test_lua51_skip_opcodes_are_cfg_edges_for_callee_analysis() {
    let root = luad_oracle::find_workspace_root();
    let source = std::fs::read_to_string(root.join("tests/fixtures/lua51_cfg_skips.lua"))
        .expect("skip fixture");
    let chunk = luad_oracle::compile_and_parse_lua51(&source, false).expect("compile skip fixture");
    let instructions = luad_analysis::lift_proto_for_dialect(&chunk.dialect, &chunk.main_proto);
    let cfg = luad_analysis::ControlFlowGraph::build(&chunk.main_proto, &instructions);

    for mnemonic in ["LOADBOOL", "TFORLOOP"] {
        let instruction = instructions
            .iter()
            .find(|instruction| {
                instruction.mnemonic == mnemonic
                    && instruction.implicit_effects.iter().any(|effect| {
                        matches!(effect, luad_core::ImplicitEffect::ConditionalSkip { .. })
                    })
            })
            .unwrap_or_else(|| panic!("{mnemonic} must expose its executed skip role"));
        let target = instruction
            .implicit_effects
            .iter()
            .find_map(|effect| match effect {
                luad_core::ImplicitEffect::ConditionalSkip { skip_target_pc } => {
                    Some(*skip_target_pc)
                }
                _ => None,
            })
            .expect("skip target");
        assert!(cfg.blocks.iter().any(|block| {
            block.instruction_pcs.contains(&instruction.pc)
                && block.successors.iter().any(|edge| {
                    cfg.blocks[edge.to_block].instruction_pcs.contains(&target)
                        && edge.kind == luad_analysis::CfgEdgeKind::ConditionalSkip
                })
        }));
    }
}
