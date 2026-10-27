//! `luad callers`: one-hop caller attribution over an explicit corpus.
//!
//! The command reorganizes accepted facts, so its oracle is those facts: a test-side
//! classifier rebuilt from the library analyses, independent of the production module,
//! must reproduce every listed caller, argument window and per-file class count. Boundary
//! controls pin how an empty, degraded, partial or truncated answer is told apart, and
//! comparator mutations prove the oracle notices a dropped, fabricated or moved site.
//! Sources are compiled with the required official Lua 5.1.5 compiler and never executed.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};

use luad_analysis::{
    analyze_chunk_call_relations, analyze_chunk_callees,
    analyze_chunk_callees_with_mutation_budget, analyze_chunk_origins, analyze_corpus_links,
    attribute_file_callers, CallRelationResolution, CallRelationUnresolvedReason, CalleeResolution,
    CalleeUnresolvedReason, CallerBasis, CallerFileFacts, ChunkLinkResult, CrossChunkLinkFact,
    LinkConvention, LinkStatus, SiteClass,
};
use luad_core::envelope::InputIdentity;
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::Chunk;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const CONVENTION: &str = "luci-module-setglobal";

// The cross-chunk linking fixtures' library shape: one target reached from two chunks and
// from inside its own module, one reached once, one never reached.
const MOD_SVC: &str = r#"
module("svc.config", package.seeall)

function network_get_firm(iface)
    os.execute("network_get_firm " .. iface)
end

function merge_profile(name)
    network_get_firm(name)
    os.execute("mkdir /tmp/profile.d/" .. name)
end

function never_called(path)
    os.execute("ls /tmp/merge/" .. path)
end
"#;

const CALLER_SVC_A: &str = r#"
local cfg = require("svc.config")

local function handle(request)
    cfg.network_get_firm(request.ifname)
end

local function handle_constant(_request)
    cfg.network_get_firm("eth0")
end

return { handle = handle, handle_constant = handle_constant }
"#;

const CALLER_SVC_B: &str = r#"
local cfg = require("svc.config")

local function handle(request)
    cfg.network_get_firm(request.query.iface .. "0")
end

local function unrelated(request)
    cfg.merge_profile(request.name)
end

return { handle = handle, unrelated = unrelated }
"#;

const MOD_SYS: &str = "module(\"luci.sys\")\n\nfunction exec(cmd)\n    return cmd\nend\n";
const MOD_SYS_DUP: &str = "module(\"luci.sys\")\n\nfunction exec(cmd)\n    return \"dup\"\nend\n";
const CALLER_SYS: &str = "luci.sys.exec(\"uname -a\")\n";
const CALLER_MISSING: &str = "luci.sys.missing(\"x\")\n";
const MOD_DYNAMIC: &str =
    "local name = ...\nmodule(name)\n\nfunction exec(cmd)\n    return cmd\nend\n";

// Same-artifact shapes: two direct calls, a same-named decoy in another prototype, a call
// through a captured closure and a call through a unique global store.
const SAME_ARTIFACT: &str = r#"
local function target(x) return x end
local function decoy()
    local function target(y) return y end
    return target(1)
end
local function via_capture() return target(2) end
function global_target(v) return v end
target(3)
target(4)
global_target(5)
return decoy, via_capture
"#;

struct Corpus {
    _dir: tempfile::TempDir,
    paths: BTreeMap<&'static str, String>,
}

impl Corpus {
    fn path(&self, name: &str) -> &str {
        &self.paths[name]
    }
}

fn compile(entries: &[(&'static str, &str)], strip: bool) -> Corpus {
    let _ = luad_oracle::require_luac51();
    let dir = tempfile::tempdir().expect("tempdir");
    let mut paths = BTreeMap::new();
    for (name, source) in entries {
        let bytes = luad_oracle::compile_source_lua51(source, strip).expect("official luac 5.1");
        let path = dir.path().join(format!("{name}.luac"));
        std::fs::write(&path, bytes).expect("write chunk");
        paths.insert(*name, path.display().to_string());
    }
    Corpus { _dir: dir, paths }
}

fn svc_corpus(strip: bool) -> Corpus {
    compile(
        &[
            ("mod_svc", MOD_SVC),
            ("caller_svc_a", CALLER_SVC_A),
            ("caller_svc_b", CALLER_SVC_B),
            ("mod_dynamic", MOD_DYNAMIC),
            ("mod_sys", MOD_SYS),
            ("mod_sys_dup", MOD_SYS_DUP),
            ("caller_sys", CALLER_SYS),
            ("caller_missing", CALLER_MISSING),
            ("same", SAME_ARTIFACT),
        ],
        strip,
    )
}

fn load(path: &str) -> (InputIdentity, Chunk) {
    let bytes = std::fs::read(path).expect("read chunk");
    let identity = InputIdentity {
        path: path.to_string(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        byte_length: bytes.len(),
    };
    let mut reader = luad_core::reader::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode chunk");
    (identity, chunk)
}

fn run(args: &[&str]) -> Output {
    Command::new(luad_oracle::luad_binary_path())
        .args(args)
        .output()
        .expect("run luad")
}

fn callers_json(target: &str, proto: &str, corpus: &[&str], link: bool) -> (Option<i32>, Value) {
    let mut args = vec!["callers", target, "--proto", proto, "-f", "json"];
    args.extend_from_slice(corpus);
    if link {
        args.extend(["--link-convention", CONVENTION]);
    }
    let output = run(&args);
    let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "callers {args:?} stdout is not JSON ({error}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code(), document)
}

// ---------------------------------------------------------------------------
// Test-side oracle, built from library facts without the production classifier.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
struct Expected {
    target_sha256: String,
    /// (caller path, call id) -> sorted basis sources.
    callers: BTreeMap<(String, String), Vec<String>>,
    windows: BTreeMap<(String, String), Value>,
    /// path -> serialized class counts.
    counts: BTreeMap<String, Value>,
}

fn limit_callee(reason: CalleeUnresolvedReason) -> bool {
    matches!(
        reason,
        CalleeUnresolvedReason::PathLimit | CalleeUnresolvedReason::AnalysisLimit
    )
}

fn label(value: impl serde::Serialize) -> String {
    serde_json::to_value(value)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn oracle(target: &str, proto: &ProtoPath, corpus: &[&str], link: bool) -> Expected {
    let mut files: Vec<(InputIdentity, Chunk)> = std::iter::once(target)
        .chain(corpus.iter().copied())
        .map(load)
        .collect();
    files.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    let target_identity = files
        .iter()
        .find(|(identity, _)| identity.path == target)
        .unwrap()
        .0
        .clone();
    let links: Vec<CrossChunkLinkFact> = if link {
        analyze_corpus_links(&files, LinkConvention::LuciModuleSetglobal)
    } else {
        Vec::new()
    };

    let mut expected = Expected {
        target_sha256: target_identity.sha256.clone(),
        ..Expected::default()
    };
    for (identity, chunk) in &files {
        let is_target = identity == &target_identity;
        let relations: BTreeMap<String, CallRelationResolution> = if is_target {
            analyze_chunk_call_relations(chunk)
                .prototypes
                .into_iter()
                .flat_map(|p| p.calls)
                .map(|c| (c.call_id.to_string(), c.resolution))
                .collect()
        } else {
            BTreeMap::new()
        };
        let windows: BTreeMap<String, Value> = analyze_chunk_origins(chunk)
            .prototypes
            .into_iter()
            .flat_map(|p| p.calls)
            .map(|c| {
                (
                    c.call_id.to_string(),
                    serde_json::to_value(c.argument_window).unwrap(),
                )
            })
            .collect();
        let mut caller = 0usize;
        let mut conflicting = 0usize;
        let mut elsewhere = 0usize;
        let mut unmapped = 0usize;
        let mut degraded: BTreeMap<String, usize> = BTreeMap::new();
        let mut unattributed: BTreeMap<String, usize> = BTreeMap::new();
        let mut sites = 0usize;
        for call in analyze_chunk_callees(chunk)
            .prototypes
            .into_iter()
            .flat_map(|p| p.calls)
        {
            sites += 1;
            let id = call.call_id.to_string();
            let relation = relations.get(&id);
            let site_links: Vec<&CrossChunkLinkFact> = links
                .iter()
                .filter(|l| l.caller_path == identity.path && l.call_id == call.call_id)
                .collect();

            let relation_hit = matches!(relation, Some(CallRelationResolution::Resolved { callee, .. }) if callee == proto);
            let relation_other = matches!(relation, Some(CallRelationResolution::Resolved { callee, .. }) if callee != proto);
            let local_closure =
                !is_target && matches!(call.resolution, CalleeResolution::ResolvedPrototype { .. });
            let link_hit = site_links.iter().any(|l| {
                l.status == LinkStatus::Resolved
                    && l.target_artifact.as_ref() == Some(&target_identity)
                    && l.target_proto.as_ref() == Some(proto)
            });
            let link_other = site_links.iter().any(|l| {
                l.status == LinkStatus::Resolved
                    && !(l.target_artifact.as_ref() == Some(&target_identity)
                        && l.target_proto.as_ref() == Some(proto))
            });
            let hit = relation_hit || link_hit;
            let other = relation_other || link_other || local_closure;

            let callee_limit = match call.resolution {
                CalleeResolution::Unresolved { reason } if limit_callee(reason) => {
                    Some(format!("callee:{}", label(reason)))
                }
                _ => None,
            };
            let relation_limit = match relation {
                Some(CallRelationResolution::Unresolved { reason, .. })
                    if matches!(
                        reason,
                        CallRelationUnresolvedReason::PathLimit
                            | CallRelationUnresolvedReason::AnalysisLimit
                    ) =>
                {
                    Some(format!("call_relation:{}", label(reason)))
                }
                _ => None,
            };
            let link_limit = site_links
                .iter()
                .find(|l| matches!(l.status, LinkStatus::Dynamic | LinkStatus::LimitExceeded))
                .map(|l| format!("link:{}", l.status));
            let label_proof = matches!(
                call.resolution,
                CalleeResolution::ResolvedPath { .. } | CalleeResolution::LookupLabel { .. }
            ) && match relation {
                None => true,
                Some(CallRelationResolution::Unresolved { reason, .. }) => matches!(
                    reason,
                    CallRelationUnresolvedReason::SymbolicPathOnly
                        | CallRelationUnresolvedReason::LookupLabelOnly
                ),
                Some(_) => false,
            };

            match (hit, other) {
                (true, false) => {
                    caller += 1;
                    let mut sources = Vec::new();
                    if relation_hit {
                        sources.push("call_relation".to_string());
                    }
                    if link_hit {
                        sources.push("cross_chunk_link".to_string());
                    }
                    let key = (identity.path.clone(), id.clone());
                    expected.windows.insert(key.clone(), windows[&id].clone());
                    expected.callers.insert(key, sources);
                    continue;
                }
                (true, true) => {
                    conflicting += 1;
                    continue;
                }
                _ => {}
            }
            if let Some(reason) = callee_limit.or(relation_limit).or(link_limit) {
                *degraded.entry(reason).or_default() += 1;
            } else if other {
                elsewhere += 1;
            } else if link && site_links.is_empty() && label_proof {
                unmapped += 1;
            } else {
                let reason = if let CalleeResolution::Unresolved { reason } = call.resolution {
                    format!("callee:{}", label(reason))
                } else if let Some(CallRelationResolution::Unresolved { reason, .. }) = relation {
                    format!("call_relation:{}", label(reason))
                } else if let Some(first) = site_links.first() {
                    format!("link:{}", first.status)
                } else {
                    "cross_artifact:not-requested".to_string()
                };
                *unattributed.entry(reason).or_default() += 1;
            }
        }
        expected.counts.insert(
            identity.path.clone(),
            json!({
                "call_sites": sites,
                "caller": caller,
                "conflicting": conflicting,
                "degraded": degraded,
                "attributed_elsewhere": elsewhere,
                "unmapped_label": unmapped,
                "unattributed": unattributed,
            }),
        );
    }
    expected
}

/// Every disagreement between an answer document and the oracle.
fn mismatches(expected: &Expected, document: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if document["input_identity"]["sha256"] != json!(expected.target_sha256) {
        out.push("target sha256 differs".to_string());
    }
    let data = &document["data"];
    let mut seen = BTreeMap::new();
    for caller in data["callers"].as_array().unwrap() {
        let key = (
            caller["caller"]["path"].as_str().unwrap().to_string(),
            caller["call_id"].as_str().unwrap().to_string(),
        );
        let mut sources: Vec<String> = caller["bases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["source"].as_str().unwrap().to_string())
            .collect();
        sources.sort();
        if seen.insert(key.clone(), sources).is_some() {
            out.push(format!("duplicate caller {key:?}"));
        }
        if expected.windows.get(&key) != Some(&caller["argument_window"]) {
            out.push(format!("argument window differs at {key:?}"));
        }
    }
    if seen != expected.callers {
        out.push(format!(
            "callers differ: expected {:?}, got {:?}",
            expected.callers.keys().collect::<Vec<_>>(),
            seen.keys().collect::<Vec<_>>()
        ));
    }
    let mut counts = BTreeMap::new();
    for file in data["files"].as_array().unwrap() {
        if file["status"] == "analyzed" {
            counts.insert(
                file["path"].as_str().unwrap().to_string(),
                file["counts"].clone(),
            );
        }
    }
    if counts != expected.counts {
        out.push(format!(
            "class counts differ: expected {:?}, got {:?}",
            expected.counts, counts
        ));
    }
    for (path, file_counts) in &counts {
        let sum = |v: &Value| -> u64 {
            v.as_object()
                .map_or(0, |m| m.values().map(|x| x.as_u64().unwrap()).sum())
        };
        let classified = file_counts["caller"].as_u64().unwrap()
            + file_counts["conflicting"].as_u64().unwrap()
            + sum(&file_counts["degraded"])
            + file_counts["attributed_elsewhere"].as_u64().unwrap()
            + file_counts["unmapped_label"].as_u64().unwrap()
            + sum(&file_counts["unattributed"]);
        if classified != file_counts["call_sites"].as_u64().unwrap() {
            out.push(format!("{path}: classes do not sum to call sites"));
        }
    }
    out
}

fn assert_equal_to_oracle(target: &str, proto: &str, corpus: &[&str], link: bool) -> Value {
    let (code, document) = callers_json(target, proto, corpus, link);
    let expected = oracle(target, &proto.parse().unwrap(), corpus, link);
    let problems = mismatches(&expected, &document);
    assert!(
        problems.is_empty(),
        "callers {target} {proto} {corpus:?} link={link} (exit {code:?}): {problems:#?}"
    );
    document
}

fn callers_of(document: &Value) -> Vec<(String, String)> {
    document["data"]["callers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            let path = c["caller"]["path"].as_str().unwrap();
            let name = Path::new(path)
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            (name, c["call_id"].as_str().unwrap().to_string())
        })
        .collect()
}

#[test]
fn test_callers_equal_library_facts_on_every_fixture_corpus() {
    for strip in [false, true] {
        let c = svc_corpus(strip);
        let svc = [c.path("caller_svc_a"), c.path("caller_svc_b")];
        for proto in ["0/0", "0/1", "0/2"] {
            assert_equal_to_oracle(c.path("mod_svc"), proto, &svc, true);
            assert_equal_to_oracle(c.path("mod_svc"), proto, &[], false);
        }
        let dynamic = [
            c.path("caller_svc_a"),
            c.path("caller_svc_b"),
            c.path("mod_dynamic"),
        ];
        assert_equal_to_oracle(c.path("mod_svc"), "0/0", &dynamic, true);
        let sys = [c.path("caller_sys"), c.path("caller_missing")];
        assert_equal_to_oracle(c.path("mod_sys"), "0/0", &sys, true);
        let dup = [c.path("caller_sys"), c.path("mod_sys_dup")];
        assert_equal_to_oracle(c.path("mod_sys"), "0/0", &dup, true);
        for proto in ["0/0", "0/1", "0/1/0", "0/2", "0/3"] {
            assert_equal_to_oracle(c.path("same"), proto, &[], false);
        }
    }
}

#[test]
fn test_callers_pin_the_firmware_shaped_answers() {
    let c = svc_corpus(false);
    let svc = [c.path("caller_svc_a"), c.path("caller_svc_b")];
    let (code, document) = callers_json(c.path("mod_svc"), "0/0", &svc, true);
    assert_eq!(code, Some(0));
    assert_eq!(
        callers_of(&document),
        vec![
            ("caller_svc_a".to_string(), "proto:0/0:pc:3".to_string()),
            ("caller_svc_a".to_string(), "proto:0/1:pc:3".to_string()),
            ("caller_svc_b".to_string(), "proto:0/0:pc:6".to_string()),
            ("mod_svc".to_string(), "proto:0/1:pc:2".to_string()),
        ],
        "three cross-artifact sites plus merge_profile's same-artifact call"
    );
    let first_kinds: Vec<&str> = document["data"]["callers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            c["argument_window"]["arguments"][0]["origin"]["kind"]
                .as_str()
                .unwrap()
        })
        .collect();
    assert_eq!(first_kinds, ["field", "literal", "concat", "parameter"]);
    let summary = &document["data"]["summary"];
    assert_eq!(summary["coverage_complete"], true);
    assert_eq!(summary["degraded"], false);
    assert_eq!(summary["cross_artifact_searched"], true);

    // merge_profile is reached once, from caller_svc_b only.
    let (_, merge) = callers_json(c.path("mod_svc"), "0/1", &svc, true);
    assert_eq!(
        callers_of(&merge),
        vec![("caller_svc_b".to_string(), "proto:0/1:pc:3".to_string())]
    );

    // never_called: an empty observed list on a clean corpus.
    let (code, never) = callers_json(c.path("mod_svc"), "0/2", &svc, true);
    assert_eq!(code, Some(0));
    assert!(callers_of(&never).is_empty());
    assert_eq!(never["data"]["summary"]["degraded"], false);
    assert_eq!(never["data"]["summary"]["coverage_complete"], true);

    // Same-artifact shapes: both direct calls and the captured call, not the decoy.
    let (_, same) = callers_json(c.path("same"), "0/0", &[], false);
    let same_callers = callers_of(&same);
    assert!(same_callers.len() >= 2, "{same_callers:?}");
    assert!(
        same_callers
            .iter()
            .all(|(_, id)| !id.starts_with("proto:0/1:")),
        "the decoy's own local target is not the outer target: {same_callers:?}"
    );
    let (_, global) = callers_json(c.path("same"), "0/3", &[], false);
    let bases = &global["data"]["callers"][0]["bases"][0];
    assert_eq!(bases["source"], "call_relation");
    assert_eq!(bases["basis"], "unique-global-store");
    assert_eq!(global["data"]["summary"]["cross_artifact_searched"], false);
}

#[test]
fn test_callers_dynamic_index_is_degraded_not_a_clean_negative() {
    let c = svc_corpus(false);
    let clean = [c.path("caller_svc_a"), c.path("caller_svc_b")];
    let dynamic = [
        c.path("caller_svc_a"),
        c.path("caller_svc_b"),
        c.path("mod_dynamic"),
    ];
    let (code, degraded) = callers_json(c.path("mod_svc"), "0/0", &dynamic, true);
    assert_eq!(code, Some(0), "index uncertainty is not a resource limit");
    let summary = &degraded["data"]["summary"];
    assert_eq!(summary["degraded"], true);
    assert_eq!(summary["dynamic_providers"], json!([c.path("mod_dynamic")]));
    assert_eq!(
        callers_of(&degraded),
        vec![("mod_svc".to_string(), "proto:0/1:pc:2".to_string())],
        "only the same-artifact relation survives a dynamic index"
    );
    let caller_a = degraded["data"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == c.path("caller_svc_a"))
        .unwrap();
    assert_eq!(caller_a["counts"]["degraded"]["link:dynamic"], 2);

    let (_, never_clean) = callers_json(c.path("mod_svc"), "0/2", &clean, true);
    let (_, never_dynamic) = callers_json(c.path("mod_svc"), "0/2", &dynamic, true);
    assert!(callers_of(&never_clean).is_empty() && callers_of(&never_dynamic).is_empty());
    assert_ne!(
        never_clean["data"]["summary"], never_dynamic["data"]["summary"],
        "an empty degraded answer must not look like an empty clean answer"
    );

    // A duplicate definition is counted, never listed.
    let (code, dup) = callers_json(
        c.path("mod_sys"),
        "0/0",
        &[c.path("caller_sys"), c.path("mod_sys_dup")],
        true,
    );
    assert_eq!(code, Some(0));
    assert!(callers_of(&dup).is_empty());
    let caller_sys = dup["data"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == c.path("caller_sys"))
        .unwrap();
    assert_eq!(caller_sys["counts"]["unattributed"]["link:duplicate"], 1);
}

#[test]
fn test_callers_classifier_degrades_starved_analysis_and_separates_conflicts() {
    let c = svc_corpus(false);
    let (identity, chunk) = load(c.path("caller_svc_a"));
    let (target, _) = load(c.path("mod_svc"));
    let proto = ProtoPath::root().child(0);

    // A starved callee analysis (explicit budget, as the accepted exhaustion test does)
    // degrades every site and lists nothing.
    let starved = analyze_chunk_callees_with_mutation_budget(&chunk, 0);
    let facts = CallerFileFacts {
        identity: &identity,
        callees: &starved,
        relations: None,
        links: None,
    };
    let attribution = attribute_file_callers(&target, &proto, &facts);
    assert!(attribution.callers.is_empty());
    assert_eq!(
        attribution.counts.classified(),
        attribution.counts.call_sites
    );
    assert_eq!(
        attribution.counts.degraded.get("callee:analysis-limit"),
        Some(&attribution.counts.call_sites)
    );

    // Two resolved sources naming the target and another prototype conflict. No compiled
    // shape reaching this was found under the current rules, so it is pinned on facts.
    let callees = analyze_chunk_callees(&chunk);
    let site = callees
        .prototypes
        .iter()
        .flat_map(|p| &p.calls)
        .find(|call| call.call_id.to_string() == "proto:0/0:pc:3");
    let site = site.expect("caller_svc_a site");
    let link = |proto: ProtoPath| CrossChunkLinkFact {
        call_id: site.call_id.clone(),
        caller_path: identity.path.clone(),
        caller_proto: site.proto_path.clone(),
        call_pc: site.pc,
        label_segments: vec!["svc".into(), "config".into(), "network_get_firm".into()],
        status: LinkStatus::Resolved,
        target_artifact: Some(target.clone()),
        target_proto: Some(proto),
        evidence: vec![StableId::Chunk],
        assumptions: Vec::new(),
    };
    let result = ChunkLinkResult {
        facts: vec![link(proto.clone()), link(ProtoPath::root().child(1))],
        diagnostics: vec![],
    };
    let facts = CallerFileFacts {
        identity: &identity,
        callees: &callees,
        relations: None,
        links: Some((&result, LinkConvention::LuciModuleSetglobal)),
    };
    let attribution = attribute_file_callers(&target, &proto, &facts);
    assert!(attribution.callers.is_empty());
    assert_eq!(attribution.counts.conflicting, 1);
    assert_eq!(
        attribution.counts.classified(),
        attribution.counts.call_sites
    );

    // A same-artifact relation and a link that disagree conflict in either direction.
    let (svc, svc_chunk) = load(c.path("mod_svc"));
    let svc_callees = analyze_chunk_callees(&svc_chunk);
    let internal = svc_callees
        .prototypes
        .iter()
        .flat_map(|p| &p.calls)
        .find(|call| call.call_id.to_string() == "proto:0/1:pc:2")
        .expect("merge_profile's internal call");
    for (relation_names, link_names) in [
        (ProtoPath::root().child(2), proto.clone()),
        (proto.clone(), ProtoPath::root().child(2)),
    ] {
        let relations = luad_analysis::ChunkCallRelationAnalysis {
            prototypes: vec![luad_analysis::CallRelationAnalysis {
                proto_id: StableId::Proto(internal.proto_path.clone()),
                calls: vec![luad_analysis::CallRelationFact {
                    call_id: internal.call_id.clone(),
                    caller: internal.proto_path.clone(),
                    pc: internal.pc,
                    call_kind: internal.call_kind.clone(),
                    resolution: CallRelationResolution::Resolved {
                        callee: relation_names.clone(),
                        basis: luad_analysis::CallRelationBasis::UniqueGlobalStore,
                        evidence: vec![StableId::Chunk],
                    },
                }],
            }],
        };
        let links = ChunkLinkResult {
            facts: vec![CrossChunkLinkFact {
                call_id: internal.call_id.clone(),
                caller_path: svc.path.clone(),
                caller_proto: internal.proto_path.clone(),
                call_pc: internal.pc,
                label_segments: vec!["svc".into(), "config".into(), "network_get_firm".into()],
                status: LinkStatus::Resolved,
                target_artifact: Some(svc.clone()),
                target_proto: Some(link_names.clone()),
                evidence: vec![StableId::Chunk],
                assumptions: Vec::new(),
            }],
            diagnostics: vec![],
        };
        let facts = CallerFileFacts {
            identity: &svc,
            callees: &svc_callees,
            relations: Some(&relations),
            links: Some((&links, LinkConvention::LuciModuleSetglobal)),
        };
        let attribution = attribute_file_callers(&svc, &proto, &facts);
        assert!(
            attribution.callers.is_empty(),
            "relation {relation_names} vs link {link_names} must not list a caller"
        );
        assert_eq!(attribution.counts.conflicting, 1);
        assert_eq!(
            attribution.counts.classified(),
            attribution.counts.call_sites
        );
    }

    // A limit outranks a resolution elsewhere: the starved site might still be a caller.
    let elsewhere = ChunkLinkResult {
        facts: vec![link(ProtoPath::root().child(1))],
        diagnostics: vec![],
    };
    let facts = CallerFileFacts {
        identity: &identity,
        callees: &starved,
        relations: None,
        links: Some((&elsewhere, LinkConvention::LuciModuleSetglobal)),
    };
    let attribution = attribute_file_callers(&target, &proto, &facts);
    assert_eq!(attribution.counts.attributed_elsewhere, 0);
    assert_eq!(
        attribution.counts.degraded.get("callee:analysis-limit"),
        Some(&attribution.counts.call_sites)
    );

    // A link cutoff degrades the unrecorded sites rather than calling them unmapped.
    let cutoff = ChunkLinkResult {
        facts: vec![],
        diagnostics: vec![luad_core::diagnostic::Diagnostic::error(
            "ANA-LIMIT-002",
            luad_core::diagnostic::DiagnosticCategory::Analysis,
            StableId::Chunk,
            "cutoff".to_string(),
        )],
    };
    let facts = CallerFileFacts {
        identity: &identity,
        callees: &callees,
        relations: None,
        links: Some((&cutoff, LinkConvention::LuciModuleSetglobal)),
    };
    let attribution = attribute_file_callers(&target, &proto, &facts);
    assert_eq!(attribution.counts.unmapped_label, 0);
    assert!(attribution.counts.degraded.contains_key("link:cutoff"));

    // SiteClass stays exhaustive over its documented classes.
    let _ = |class: SiteClass| match class {
        SiteClass::Caller(bases) => bases.iter().all(|b| {
            matches!(
                b,
                CallerBasis::CallRelation { .. } | CallerBasis::CrossChunkLink { .. }
            )
        }),
        SiteClass::Conflicting
        | SiteClass::Degraded(_)
        | SiteClass::AttributedElsewhere
        | SiteClass::UnmappedLabel
        | SiteClass::Unattributed(_) => false,
    };
}

#[test]
fn test_callers_partial_unsupported_truncated_and_refused_inputs() {
    let c = svc_corpus(false);
    let svc = [c.path("caller_svc_a"), c.path("caller_svc_b")];
    let (_, clean) = callers_json(c.path("mod_svc"), "0/0", &svc, true);

    // A Lua 5.4 corpus file is reported, not dropped, and leaves the 5.1 answer intact.
    let dir = tempfile::tempdir().unwrap();
    let lua54 = dir.path().join("modern.luac");
    std::fs::write(
        &lua54,
        luad_oracle::compile_source_lua54("return 1", false).unwrap(),
    )
    .unwrap();
    let lua54 = lua54.display().to_string();
    let (code, mixed) = callers_json(
        c.path("mod_svc"),
        "0/0",
        &[svc[0], svc[1], lua54.as_str()],
        true,
    );
    assert_eq!(code, Some(1));
    assert_eq!(callers_of(&mixed), callers_of(&clean));
    assert_eq!(mixed["data"]["summary"]["coverage_complete"], false);
    assert_eq!(mixed["data"]["summary"]["files_unsupported"], 1);

    // Garbage is a failed input and, as a possible provider, makes the index uncertain.
    let garbage = dir.path().join("garbage.luac");
    std::fs::write(&garbage, b"\x1bLua\x51garbage").unwrap();
    let garbage = garbage.display().to_string();
    let (code, failed) = callers_json(c.path("mod_svc"), "0/0", &[svc[0], garbage.as_str()], true);
    assert_eq!(code, Some(1));
    assert_eq!(failed["data"]["summary"]["files_failed"], 1);
    assert_eq!(failed["data"]["summary"]["degraded"], true);
    assert_eq!(
        failed["data"]["summary"]["dynamic_providers"],
        json!([garbage])
    );

    // Truncation keeps the first callers in order and full class counts.
    let mut args = vec!["callers", c.path("mod_svc"), "--proto", "0/0", "-f", "json"];
    args.extend(svc);
    args.extend(["--link-convention", CONVENTION, "--max-callers", "1"]);
    let output = run(&args);
    assert_eq!(output.status.code(), Some(5));
    let truncated: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(callers_of(&truncated), callers_of(&clean)[..1].to_vec());
    assert_eq!(truncated["data"]["summary"]["is_truncated"], true);
    assert_eq!(truncated["data"]["summary"]["callers_omitted"], 3);
    assert_eq!(truncated["data"]["files"], clean["data"]["files"]);

    // Refusals leave stdout empty.
    let lua52 = dir.path().join("old.luac");
    std::fs::write(
        &lua52,
        luad_oracle::compile_source_lua52("return 1", false).unwrap(),
    )
    .unwrap();
    for (args, code) in [
        (vec!["callers", lua52.to_str().unwrap(), "--proto", "0"], 4),
        (vec!["callers", c.path("mod_svc"), "--proto", "0/9"], 2),
        (vec!["callers", c.path("mod_svc"), "--proto", "x"], 2),
        (
            vec!["callers", c.path("mod_svc"), "--proto", "0/0", svc[0]],
            2,
        ),
        (
            vec![
                "callers",
                c.path("mod_svc"),
                "--proto",
                "0/0",
                "--max-callers",
                "0",
            ],
            2,
        ),
        (vec!["callers", "-", "--proto", "0/0"], 2),
        (vec!["callers", "/nonexistent/x.luac", "--proto", "0/0"], 3),
    ] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(code), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?} printed stdout");
    }

    // One file spelled two ways is one provider, not a duplicate definition.
    let target_path = Path::new(c.path("mod_svc"));
    let respelled = target_path
        .parent()
        .unwrap()
        .join(".")
        .join(target_path.file_name().unwrap())
        .display()
        .to_string();
    let (code, twice) = callers_json(
        c.path("mod_svc"),
        "0/0",
        &[svc[0], svc[1], respelled.as_str()],
        true,
    );
    assert_eq!(code, Some(0));
    assert_eq!(callers_of(&twice), callers_of(&clean));
    assert_eq!(twice["data"]["files"], clean["data"]["files"]);

    // The OpenWrt LNUM32 authority fixture answers on its own profile.
    let authority = luad_oracle::find_workspace_root()
        .join("tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32.luac");
    let (code, lnum) = callers_json(authority.to_str().unwrap(), "0/0", &[], false);
    assert_eq!(code, Some(0));
    assert_eq!(lnum["interpretation"]["profile"], "lua5.1-lnum32");
}

/// A callee path one segment past the analysis bound is a real limit outcome from
/// official compiler output (parsed only): exit 5 and `degraded`, while the genuine caller
/// stays listed and the limited site is never one.
#[test]
fn test_callers_real_path_limit_exits_five_and_degrades() {
    let chain: Vec<String> = (0..32).map(|i| format!("s{i}")).collect();
    let source = format!(
        "local function target(x) return x end\ntarget(1)\nroot.{}(2)\n",
        chain.join(".")
    );
    for strip in [false, true] {
        let c = compile(&[("limited", source.as_str())], strip);
        let (identity, chunk) = load(c.path("limited"));
        let limited: Vec<String> = analyze_chunk_callees(&chunk)
            .prototypes
            .iter()
            .flat_map(|p| &p.calls)
            .filter(|call| {
                matches!(
                    call.resolution,
                    CalleeResolution::Unresolved {
                        reason: CalleeUnresolvedReason::PathLimit
                    }
                )
            })
            .map(|call| call.call_id.to_string())
            .collect();
        assert_eq!(limited.len(), 1, "control must reach the real path bound");
        let (code, document) = callers_json(&identity.path, "0/0", &[], false);
        assert_eq!(code, Some(5));
        let data = &document["data"];
        assert_eq!(data["summary"]["degraded"], true);
        assert_eq!(
            data["files"][0]["counts"]["degraded"]["callee:path-limit"],
            1
        );
        let listed: Vec<&str> = data["callers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["call_id"].as_str().unwrap())
            .collect();
        assert_eq!(listed, ["proto:0:pc:3"]);
        assert!(!listed.contains(&limited[0].as_str()));
        assert!(mismatches(
            &oracle(&identity.path, &"0/0".parse().unwrap(), &[], false),
            &document
        )
        .is_empty());
    }
}

#[test]
fn test_callers_text_view_summarizes_each_callers_arguments() {
    let c = svc_corpus(false);
    let output = run(&[
        "callers",
        c.path("mod_svc"),
        "--proto",
        "0/0",
        c.path("caller_svc_a"),
        c.path("caller_svc_b"),
        "--link-convention",
        CONVENTION,
    ]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("(field)"), "{text}");
    assert!(text.contains("(\"eth0\")"), "{text}");
    assert!(text.contains("(concat)"), "{text}");
    assert!(text.contains("(param#0)"), "{text}");
    assert!(
        text.contains("not proof") || text.contains("4 caller(s)"),
        "{text}"
    );
}

#[test]
fn test_callers_text_view_prints_literal_values_through_the_scalar_authority() {
    let source = "local function f(n) return n end\nf(42)\nf(1.5)\nf(true)\n";
    let c = compile(&[("literals", source)], false);
    let output = run(&["callers", c.path("literals"), "--proto", "0/0"]);
    let text = String::from_utf8(output.stdout).unwrap();
    // Stock Lua 5.1 numbers are binary64, rendered visibly as floats.
    for expected in ["(42.0)", "(1.5)", "(true)"] {
        assert!(text.contains(expected), "{expected} missing: {text}");
    }
}

#[test]
fn test_callers_debug_and_stripped_twins_agree() {
    let debug = svc_corpus(false);
    let stripped = svc_corpus(true);
    for (target, proto, corpus, link) in [
        ("mod_svc", "0/0", vec!["caller_svc_a", "caller_svc_b"], true),
        ("same", "0/0", vec![], false),
    ] {
        let answer = |c: &Corpus| {
            let paths: Vec<&str> = corpus.iter().map(|n| c.path(n)).collect();
            callers_json(c.path(target), proto, &paths, link).1
        };
        let shape = |d: &Value| -> Vec<(String, Value)> {
            callers_of(d)
                .into_iter()
                .zip(d["data"]["callers"].as_array().unwrap())
                .map(|((name, id), c)| {
                    let sources: Vec<Value> = c["bases"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|b| b["source"].clone())
                        .collect();
                    (format!("{name} {id}"), Value::Array(sources))
                })
                .collect()
        };
        assert_eq!(shape(&answer(&debug)), shape(&answer(&stripped)));
    }
}

fn schema_validator(definition: Option<&str>) -> jsonschema::Validator {
    let root = luad_oracle::find_workspace_root();
    let mut schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("tests/schemas/callers.schema.json")).unwrap(),
    )
    .unwrap();
    if let Some(name) = definition {
        let definitions = schema["definitions"].clone();
        schema = json!({ "$ref": format!("#/definitions/{name}"), "definitions": definitions });
    }
    jsonschema::validator_for(&schema).expect("compile callers schema")
}

#[test]
fn test_callers_json_and_jsonl_match_the_schema_and_each_other() {
    let c = svc_corpus(false);
    let svc = [
        c.path("caller_svc_a"),
        c.path("caller_svc_b"),
        c.path("mod_dynamic"),
    ];
    let (_, document) = callers_json(c.path("mod_svc"), "0/0", &svc, true);
    let whole = schema_validator(None);
    if let Err(error) = whole.validate(&document) {
        panic!("callers JSON rejected by schema: {error}");
    }

    let mut args = vec![
        "callers",
        c.path("mod_svc"),
        "--proto",
        "0/0",
        "-f",
        "jsonl",
    ];
    args.extend(svc);
    args.extend(["--link-convention", CONVENTION]);
    let output = run(&args);
    assert_eq!(output.status.code(), Some(0));
    let records: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let types: Vec<&str> = records
        .iter()
        .map(|r| r["record_type"].as_str().unwrap())
        .collect();
    assert_eq!(types.first(), Some(&"metadata"));
    assert_eq!(types.get(1), Some(&"target"));
    assert_eq!(types.last(), Some(&"summary"));
    let data = &document["data"];
    let by_type = |t: &str| -> Vec<Value> {
        records
            .iter()
            .filter(|r| r["record_type"] == t)
            .map(|r| r["data"].clone())
            .collect()
    };
    assert_eq!(by_type("caller"), *data["callers"].as_array().unwrap());
    assert_eq!(by_type("file_coverage"), *data["files"].as_array().unwrap());
    assert_eq!(by_type("target")[0], data["target"]);
    let mut summary = records.last().unwrap().clone();
    summary.as_object_mut().unwrap().remove("record_type");
    assert_eq!(summary, data["summary"]);
    for (record_type, definition) in [
        ("caller", "CallerSite"),
        ("file_coverage", "CallersFileCoverage"),
        ("target", "CallersTarget"),
    ] {
        let validator = schema_validator(Some(definition));
        for record in records.iter().filter(|r| r["record_type"] == record_type) {
            if let Err(error) = validator.validate(&record["data"]) {
                panic!("{record_type} record rejected by schema: {error}");
            }
            assert!(
                record["context"].is_object(),
                "{record_type} carries its context"
            );
        }
    }
    // Each caller record carries its caller's own identity as context.
    for record in records.iter().filter(|r| r["record_type"] == "caller") {
        assert_eq!(
            record["context"]["input_identity"], record["data"]["caller"],
            "caller context is the caller artifact"
        );
    }
}

#[test]
fn test_callers_comparator_rejects_dropped_fabricated_swapped_and_moved_sites() {
    let c = svc_corpus(false);
    let svc = [c.path("caller_svc_a"), c.path("caller_svc_b")];
    let (_, document) = callers_json(c.path("mod_svc"), "0/0", &svc, true);
    let expected = oracle(c.path("mod_svc"), &ProtoPath::root().child(0), &svc, true);
    assert!(mismatches(&expected, &document).is_empty());

    let mutate = |name: &str, change: &dyn Fn(&mut Value)| {
        let mut copy = document.clone();
        change(&mut copy);
        assert!(
            !mismatches(&expected, &copy).is_empty(),
            "comparator accepted mutation: {name}"
        );
    };
    mutate("dropped caller", &|d| {
        d["data"]["callers"].as_array_mut().unwrap().remove(1);
    });
    mutate("fabricated caller", &|d| {
        let mut fake = d["data"]["callers"][0].clone();
        fake["call_id"] = json!("proto:0/0:pc:99");
        d["data"]["callers"].as_array_mut().unwrap().push(fake);
    });
    mutate("swapped argument windows", &|d| {
        let callers = d["data"]["callers"].as_array_mut().unwrap();
        let first = callers[0]["argument_window"].clone();
        callers[0]["argument_window"] = callers[1]["argument_window"].clone();
        callers[1]["argument_window"] = first;
    });
    mutate("site moved between classes", &|d| {
        let files = d["data"]["files"].as_array_mut().unwrap();
        let counts = &mut files[0]["counts"];
        let unmapped = counts["unmapped_label"].as_u64().unwrap();
        counts["unmapped_label"] = json!(unmapped - 1);
        counts["attributed_elsewhere"] =
            json!(counts["attributed_elsewhere"].as_u64().unwrap() + 1);
    });
    mutate("altered target sha256", &|d| {
        d["input_identity"]["sha256"] = json!("0".repeat(64));
    });
    mutate("basis source relabelled", &|d| {
        d["data"]["callers"][0]["bases"][0]["source"] = json!("call_relation");
    });
}
