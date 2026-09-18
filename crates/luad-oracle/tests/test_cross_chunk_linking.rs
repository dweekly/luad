//! Convention-gated cross-chunk linking oracle tests (R-2).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_analysis::{
    analyze_corpus_links, index_chunk_module_exports, index_chunk_module_exports_bounded,
    resolve_chunk_links, resolve_chunk_links_bounded, CrossChunkLinkFact, LinkConvention,
    LinkStatus, ModuleExportIndex,
};
use luad_core::envelope::{InputIdentity, JsonlDataRecord};
use luad_core::id::ProtoPath;
use sha2::{Digest, Sha256};

fn workspace_root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn fixture_dir() -> PathBuf {
    workspace_root().join("tests/fixtures/cross_chunk")
}

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

const MOD_SYS_SRC: &str = r#"
module("luci.sys")

function exec(cmd)
    return cmd
end
"#;

const CALLER_SYS_SRC: &str = r#"
luci.sys.exec("uname -a")
"#;

const MOD_SYS_DUP_SRC: &str = r#"
module("luci.sys")

function exec(cmd)
    return "dup"
end
"#;

const CALLER_MISSING_SRC: &str = r#"
luci.missing.func("hello")
"#;

const MOD_DYNAMIC_SRC: &str = r#"
local m = ...
module(m)

function dynamic_func()
    return 42
end
"#;

/// Ensure the fixture binaries and MANIFEST.json exist in tests/fixtures/cross_chunk/.
fn ensure_fixtures() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let dir = fixture_dir();
        fs::create_dir_all(&dir).expect("create fixture dir");

        let fixtures = [
            ("mod_sys.luac", MOD_SYS_SRC, "defining_module_luci_sys"),
            ("caller_sys.luac", CALLER_SYS_SRC, "caller_luci_sys_exec"),
            (
                "mod_sys_dup.luac",
                MOD_SYS_DUP_SRC,
                "duplicate_module_luci_sys",
            ),
            (
                "caller_missing.luac",
                CALLER_MISSING_SRC,
                "caller_missing_symbol",
            ),
            (
                "mod_dynamic.luac",
                MOD_DYNAMIC_SRC,
                "dynamic_module_declaration",
            ),
        ];

        let mut manifest_cases = Vec::new();

        for (filename, source, role) in fixtures {
            let path = dir.join(filename);
            if !path.exists() {
                let bytes = luad_oracle::compile_source_lua51(source, false)
                    .unwrap_or_else(|e| panic!("failed to compile {filename}: {e}"));
                fs::write(&path, &bytes).expect("write fixture");
            }

            let bytes = fs::read(&path).expect("read fixture");
            let hash = hex::encode(Sha256::digest(&bytes));
            manifest_cases.push(serde_json::json!({
                "path": format!("tests/fixtures/cross_chunk/{filename}"),
                "sha256": hash,
                "byte_length": bytes.len(),
                "role": role,
                "license": "MIT",
                "profile": "lua5.1",
            }));
        }

        let manifest_path = dir.join("MANIFEST.json");
        if !manifest_path.exists() {
            let manifest = serde_json::json!({
                "schema_version": 1,
                "purpose": "Mini-corpus fixtures for convention-gated cross-chunk linking (R-2)",
                "convention": "luci-module-setglobal",
                "cases": manifest_cases,
            });
            fs::write(
                &manifest_path,
                serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
            )
            .expect("write manifest");
        }
    });
}

fn parse_fixture_chunk(path: &Path) -> (InputIdentity, luad_core::Chunk) {
    let bytes = fs::read(path).expect("read fixture chunk");
    let sha256 = hex::encode(Sha256::digest(&bytes));
    let identity = InputIdentity {
        path: path.display().to_string(),
        sha256,
        byte_length: bytes.len(),
    };
    let mut reader = luad_core::reader::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode chunk");
    (identity, chunk)
}

#[test]
fn test_cross_chunk_linking_resolved() {
    ensure_fixtures();
    let dir = fixture_dir();
    let mod_sys = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let caller_sys = parse_fixture_chunk(&dir.join("caller_sys.luac"));

    let chunks = vec![mod_sys.clone(), caller_sys.clone()];
    let links = analyze_corpus_links(&chunks, LinkConvention::LuciModuleSetglobal);

    assert_eq!(links.len(), 1, "expected exactly 1 cross-chunk link fact");
    let link = &links[0];
    assert_eq!(link.status, LinkStatus::Resolved);
    assert_eq!(link.label_segments, vec!["luci", "sys", "exec"]);
    assert_eq!(link.caller_path, caller_sys.0.path);
    assert_eq!(link.caller_proto, ProtoPath::root());

    let target_art = link.target_artifact.as_ref().expect("target artifact");
    assert_eq!(target_art.path, mod_sys.0.path);
    assert_eq!(target_art.sha256, mod_sys.0.sha256);

    let target_proto = link.target_proto.as_ref().expect("target proto");
    assert_eq!(*target_proto, ProtoPath::root().child(0));
    assert!(!link.evidence.is_empty(), "evidence must be present");
}

#[test]
fn test_cross_chunk_linking_input_order_invariance() {
    ensure_fixtures();
    let dir = fixture_dir();
    let mod_sys = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let caller_sys = parse_fixture_chunk(&dir.join("caller_sys.luac"));

    let order1 = vec![mod_sys.clone(), caller_sys.clone()];
    let order2 = vec![caller_sys.clone(), mod_sys.clone()];

    let links1 = analyze_corpus_links(&order1, LinkConvention::LuciModuleSetglobal);
    let links2 = analyze_corpus_links(&order2, LinkConvention::LuciModuleSetglobal);

    assert_eq!(
        links1, links2,
        "linking must be invariant to corpus input order"
    );
}

#[test]
fn test_cross_chunk_linking_duplicate_conflict() {
    ensure_fixtures();
    let dir = fixture_dir();
    let mod_sys = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let mod_sys_dup = parse_fixture_chunk(&dir.join("mod_sys_dup.luac"));
    let caller_sys = parse_fixture_chunk(&dir.join("caller_sys.luac"));

    let chunks = vec![mod_sys, mod_sys_dup, caller_sys.clone()];
    let links = analyze_corpus_links(&chunks, LinkConvention::LuciModuleSetglobal);

    assert_eq!(links.len(), 1);
    let link = &links[0];
    assert_eq!(
        link.status,
        LinkStatus::Duplicate,
        "multiple conflicting definitions must yield duplicate status"
    );
    assert_eq!(
        link.target_artifact, None,
        "duplicate must not select a target artifact"
    );
    assert_eq!(
        link.target_proto, None,
        "duplicate must not select a target prototype"
    );
    assert!(!link.evidence.is_empty());
}

#[test]
fn test_cross_chunk_linking_absent() {
    ensure_fixtures();
    let dir = fixture_dir();
    let mod_sys = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let caller_missing = parse_fixture_chunk(&dir.join("caller_missing.luac"));

    let chunks = vec![mod_sys, caller_missing.clone()];
    let links = analyze_corpus_links(&chunks, LinkConvention::LuciModuleSetglobal);

    assert_eq!(links.len(), 1);
    let link = &links[0];
    assert_eq!(
        link.status,
        LinkStatus::Absent,
        "unmatched module symbol must yield absent status"
    );
    assert_eq!(link.label_segments, vec!["luci", "missing", "func"]);
    assert_eq!(link.target_artifact, None);
    assert_eq!(link.target_proto, None);
}

#[test]
fn test_cross_chunk_linking_dynamic_declaration() {
    ensure_fixtures();
    let dir = fixture_dir();
    let mod_dynamic = parse_fixture_chunk(&dir.join("mod_dynamic.luac"));
    let caller_missing = parse_fixture_chunk(&dir.join("caller_missing.luac"));

    let chunks = vec![mod_dynamic, caller_missing.clone()];
    let links = analyze_corpus_links(&chunks, LinkConvention::LuciModuleSetglobal);

    assert_eq!(links.len(), 1);
    let link = &links[0];
    assert_eq!(
        link.status,
        LinkStatus::Dynamic,
        "presence of dynamic module declaration in corpus must yield dynamic status for unproved symbols"
    );
    assert_eq!(link.target_artifact, None);
    assert_eq!(link.target_proto, None);
    assert!(!link.evidence.is_empty());
}

#[test]
fn test_cross_chunk_linking_unsupported_dialect() {
    ensure_fixtures();
    let dir = fixture_dir();
    let (identity, mut chunk) = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    chunk.dialect = "lua5.2".to_string();

    let index = ModuleExportIndex::default();
    let facts = resolve_chunk_links(
        &identity,
        &chunk,
        &index,
        LinkConvention::LuciModuleSetglobal,
    );

    assert_eq!(facts.len(), 1);
    assert_eq!(
        facts[0].status,
        LinkStatus::Unsupported,
        "non-5.1 chunk must yield unsupported status"
    );
}

#[test]
fn test_cli_export_with_link_convention() {
    ensure_fixtures();
    let dir = fixture_dir();
    let mod_sys_path = dir.join("mod_sys.luac");
    let caller_sys_path = dir.join("caller_sys.luac");

    let output = Command::new(get_luad_bin())
        .arg("export")
        .arg("--link-convention")
        .arg("luci-module-setglobal")
        .arg(&mod_sys_path)
        .arg(&caller_sys_path)
        .output()
        .expect("run luad export");

    assert!(output.status.success(), "export command must succeed");
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");

    let mut link_records: Vec<JsonlDataRecord<CrossChunkLinkFact>> = Vec::new();
    for line in stdout.lines() {
        if line.contains("\"record_type\":\"cross_chunk_link\"") {
            let rec: JsonlDataRecord<CrossChunkLinkFact> =
                serde_json::from_str(line).expect("parse link record");
            link_records.push(rec);
        }
    }

    assert_eq!(link_records.len(), 1, "expected 1 cross_chunk_link record");
    let rec = &link_records[0];
    assert_eq!(rec.record_type, "cross_chunk_link");
    assert_eq!(rec.data.status, LinkStatus::Resolved);
    assert_eq!(rec.data.label_segments, vec!["luci", "sys", "exec"]);
    assert!(rec.data.target_artifact.is_some());
}

#[test]
fn test_cli_export_unknown_link_convention_fails_closed() {
    ensure_fixtures();
    let dir = fixture_dir();
    let caller_sys_path = dir.join("caller_sys.luac");

    let output = Command::new(get_luad_bin())
        .arg("export")
        .arg("--link-convention")
        .arg("invented-convention")
        .arg(&caller_sys_path)
        .output()
        .expect("run luad export");

    assert_eq!(
        output.status.code(),
        Some(2),
        "must exit with UsageError (2)"
    );
    let stderr = String::from_utf8(output.stderr).expect("utf8 stderr");
    assert!(
        stderr.contains("unknown link convention 'invented-convention'"),
        "stderr must explain unknown link convention: {stderr}"
    );
    assert!(
        stderr.contains("Supported conventions: luci-module-setglobal"),
        "stderr must list supported conventions: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty on usage error"
    );
}

#[test]
fn test_negative_mutation_control() {
    ensure_fixtures();
    let dir = fixture_dir();
    let mod_sys = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let caller_sys = parse_fixture_chunk(&dir.join("caller_sys.luac"));

    let chunks = vec![mod_sys.clone(), caller_sys.clone()];
    let links = analyze_corpus_links(&chunks, LinkConvention::LuciModuleSetglobal);
    assert_eq!(links.len(), 1);

    // Baseline comparator against ground truth
    let expected = links[0].clone();

    // Negative mutation 1: mutate target artifact path
    let mut mutated_target_path = expected.clone();
    if let Some(art) = &mut mutated_target_path.target_artifact {
        art.path = "corrupted/path/mod_sys.luac".to_string();
    }
    assert_ne!(
        links[0], mutated_target_path,
        "negative control: mutated target path must fail comparator"
    );

    // Negative mutation 2: mutate target proto path
    let mut mutated_proto = expected.clone();
    mutated_proto.target_proto = Some(ProtoPath::root().child(99));
    assert_ne!(
        links[0], mutated_proto,
        "negative control: mutated target proto must fail comparator"
    );

    // Negative mutation 3: mutate status
    let mut mutated_status = expected.clone();
    mutated_status.status = LinkStatus::Absent;
    assert_ne!(
        links[0], mutated_status,
        "negative control: mutated status must fail comparator"
    );
}

#[test]
fn test_cross_chunk_link_schema_validation() {
    ensure_fixtures();
    let root = workspace_root();
    let schema_bytes =
        fs::read(root.join("tests/schemas/link.schema.json")).expect("read link schema");
    let schema_json: serde_json::Value =
        serde_json::from_slice(&schema_bytes).expect("parse link schema");
    let validator = jsonschema::validator_for(&schema_json).expect("compile link schema");

    let dir = fixture_dir();
    let mod_sys = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let caller_sys = parse_fixture_chunk(&dir.join("caller_sys.luac"));
    let chunks = vec![mod_sys, caller_sys];
    let links = analyze_corpus_links(&chunks, LinkConvention::LuciModuleSetglobal);
    assert_eq!(links.len(), 1);

    let rec = JsonlDataRecord {
        record_type: "cross_chunk_link".to_string(),
        context: luad_core::envelope::JsonlRecordContext::failed_read(),
        data: &links[0],
    };
    let rec_val = serde_json::to_value(&rec).expect("serialize record");
    assert!(
        validator.is_valid(&rec_val),
        "link record must validate against link.schema.json"
    );
}

#[test]
fn test_cross_chunk_linking_export_cap_fail_closed_and_limit_exceeded() {
    ensure_fixtures();
    let dir = fixture_dir();
    let (mod_sys_id, mod_sys_chunk) = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let (caller_missing_id, caller_missing_chunk) =
        parse_fixture_chunk(&dir.join("caller_missing.luac"));

    // Case 1: Cap is hit during export indexing (max_exports = 0).
    let mut capped_index = ModuleExportIndex::default();
    index_chunk_module_exports_bounded(
        &mod_sys_id,
        &mod_sys_chunk,
        LinkConvention::LuciModuleSetglobal,
        &mut capped_index,
        0,
    );

    assert!(
        capped_index.export_limit_exceeded,
        "export_limit_exceeded must be set when capacity is exceeded"
    );
    assert!(
        capped_index
            .diagnostics
            .iter()
            .any(|d| d.code == "ANA-LIMIT-001"),
        "ANA-LIMIT-001 diagnostic must be emitted when export indexing limit is hit"
    );

    // Resolving a call against the capped index MUST NOT yield LinkStatus::Absent!
    // Silent truncation leading to false proof of absence is strictly forbidden.
    let capped_res = resolve_chunk_links(
        &caller_missing_id,
        &caller_missing_chunk,
        &capped_index,
        LinkConvention::LuciModuleSetglobal,
    );
    assert_eq!(capped_res.facts.len(), 1);
    assert_eq!(
        capped_res.facts[0].status,
        LinkStatus::LimitExceeded,
        "unmatched module symbol must fail closed with LimitExceeded status, NOT Absent"
    );
    assert_ne!(
        capped_res.facts[0].status,
        LinkStatus::Absent,
        "capped index must never claim proof of absence"
    );
    assert!(
        capped_res
            .diagnostics
            .iter()
            .any(|d| d.code == "ANA-LIMIT-001"),
        "ANA-LIMIT-001 must propagate into chunk link result diagnostics"
    );

    // Negative control:
    // With normal capacity (max_exports = 100), the missing symbol resolves to Absent
    // and no ANA-LIMIT-001 is emitted.
    let mut uncapped_index = ModuleExportIndex::default();
    index_chunk_module_exports_bounded(
        &mod_sys_id,
        &mod_sys_chunk,
        LinkConvention::LuciModuleSetglobal,
        &mut uncapped_index,
        100,
    );
    assert!(!uncapped_index.export_limit_exceeded);
    assert!(uncapped_index.diagnostics.is_empty());

    let uncapped_res = resolve_chunk_links(
        &caller_missing_id,
        &caller_missing_chunk,
        &uncapped_index,
        LinkConvention::LuciModuleSetglobal,
    );
    assert_eq!(uncapped_res.facts.len(), 1);
    assert_eq!(
        uncapped_res.facts[0].status,
        LinkStatus::Absent,
        "uncapped index correctly reports absent for genuinely unexported symbol"
    );
    assert!(uncapped_res.diagnostics.is_empty());

    // Negative assertion proving that corrupting the capped status to Absent fails
    let mut mutated = capped_res.facts[0].clone();
    mutated.status = LinkStatus::Absent;
    assert_ne!(
        capped_res.facts[0].status, mutated.status,
        "negative control: capped verdict must never equal Absent"
    );
}

#[test]
fn test_cross_chunk_linking_fact_cap_fail_closed_and_limit_exceeded() {
    ensure_fixtures();
    let dir = fixture_dir();
    let (mod_sys_id, mod_sys_chunk) = parse_fixture_chunk(&dir.join("mod_sys.luac"));
    let (caller_sys_id, caller_sys_chunk) = parse_fixture_chunk(&dir.join("caller_sys.luac"));

    let mut index = ModuleExportIndex::default();
    index_chunk_module_exports(
        &mod_sys_id,
        &mod_sys_chunk,
        LinkConvention::LuciModuleSetglobal,
        &mut index,
    );

    // Case 1: Cap is hit during link resolution (max_links = 0).
    let capped_res = resolve_chunk_links_bounded(
        &caller_sys_id,
        &caller_sys_chunk,
        &index,
        LinkConvention::LuciModuleSetglobal,
        0,
    );

    assert_eq!(capped_res.facts.len(), 1);
    assert_eq!(
        capped_res.facts[0].status,
        LinkStatus::LimitExceeded,
        "hit call must be explicitly marked LimitExceeded"
    );
    assert!(
        capped_res
            .diagnostics
            .iter()
            .any(|d| d.code == "ANA-LIMIT-002"),
        "ANA-LIMIT-002 must be emitted when link fact limit is reached"
    );

    // Case 2: Uncapped (max_links = 10) resolves successfully.
    let uncapped_res = resolve_chunk_links_bounded(
        &caller_sys_id,
        &caller_sys_chunk,
        &index,
        LinkConvention::LuciModuleSetglobal,
        10,
    );
    assert_eq!(uncapped_res.facts.len(), 1);
    assert_eq!(uncapped_res.facts[0].status, LinkStatus::Resolved);
    assert!(uncapped_res.diagnostics.is_empty());

    // Negative control:
    let mut mutated = capped_res.facts[0].clone();
    mutated.status = LinkStatus::Resolved;
    assert_ne!(
        capped_res.facts[0].status, mutated.status,
        "negative control: capped verdict must never equal Resolved"
    );
}

#[test]
fn test_cross_chunk_link_limit_exceeded_schema_validation() {
    let root = workspace_root();
    let schema_bytes =
        fs::read(root.join("tests/schemas/link.schema.json")).expect("read link schema");
    let schema_json: serde_json::Value =
        serde_json::from_slice(&schema_bytes).expect("parse link schema");
    let validator = jsonschema::validator_for(&schema_json).expect("compile link schema");

    let fact = CrossChunkLinkFact {
        call_id: luad_core::id::StableId::Chunk,
        caller_path: "test/caller.luac".to_string(),
        caller_proto: ProtoPath::root(),
        call_pc: 0,
        label_segments: vec!["luci".to_string(), "sys".to_string(), "exec".to_string()],
        status: LinkStatus::LimitExceeded,
        target_artifact: None,
        target_proto: None,
        evidence: Vec::new(),
    };

    let rec = JsonlDataRecord {
        record_type: "cross_chunk_link".to_string(),
        context: luad_core::envelope::JsonlRecordContext::failed_read(),
        data: &fact,
    };
    let rec_val = serde_json::to_value(&rec).expect("serialize record");
    assert!(
        validator.is_valid(&rec_val),
        "link record with LimitExceeded status must validate against link.schema.json"
    );
}
