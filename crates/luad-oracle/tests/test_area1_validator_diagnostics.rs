//! Closure evidence for Lua 5.1 validator authority and diagnostic discoverability.
//!
//! The tests exercise the public CLI against every maintained Lua 5.1 layout/profile,
//! a public firmware-shaped stress fixture, and exact corruptions. The closure contract
//! also pins the complete prerequisite graph so a narrower result cannot stand in for
//! the Area 1 claim.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use luad_core::{Prototype, SafeReader};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

const EMBEDDED_SOURCE: &str = "tests/fixtures/embedded/area1_validator.lua";
const EMBEDDED_BINARY: &str = "tests/fixtures/embedded/area1_validator.luac";
const EMBEDDED_MANIFEST: &str = "tests/fixtures/embedded/MANIFEST.json";
const SOURCE_SHA256: &str = "d123c19a4f2f6dc4e06a2dacfc27d3fd75c0c766dba0fa27eb7f47e5f531f8b8";
const BINARY_SHA256: &str = "01857f082dfc5c8b21238c55db7a03e2a6bf3d6e48c36df96fd279f9ce611cab";
const COMPILER_SHA256: &str = "eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239";
const ACCEPTED_COMPILER_SHA256S: &[&str] = &[
    COMPILER_SHA256,
    "b7f80fd88b683a3e8ebe5b98f50c57e17659b56f659a37149fd81f752bcc48e8",
    "e2ba74327f3a4662689b9e58909b410af8635add51a35b951021d0b1d90c6000",
];
const DEEPEST: &str = "proto:0/0/0/0/0/0";

const AREA1_PREREQUISITES: &[&str] = &[
    "gate-cli-selection-contract",
    "gate-closure-prototype-identity-lua51",
    "gate-diagnostic-catalog",
    "gate-layout-lua51-stock",
    "gate-profile-lua51-lnum",
    "gate-proof-harness",
    "gate-public-disasm-lua51",
    "gate-validation-null-hypothesis",
    "gate-validator-closure-capture-span-lua51",
    "gate-validator-count-spans-lua51",
    "gate-validator-nested-rk-owner-lua51",
    "gate-validator-numeric-for-span-lua51",
    "gate-validator-reference-operands-lua51",
    "gate-validator-register-a-lua51",
    "gate-validator-register-b-lua51",
    "gate-validator-register-c-lua51",
    "gate-validator-rk-b-lua51",
    "gate-validator-rk-c-lua51",
    "gate-validator-self-span-lua51",
    "gate-validator-tforloop-span-lua51",
];

const AREA1_TESTS: &[&str] = &[
    "test_area1_gate_closure_is_exact_and_rejects_substitution",
    "test_public_corruptions_emit_exact_catalog_backed_diagnostics",
    "test_public_embedded_case_provenance_and_stress_shape",
    "test_public_owner_paths_agree_on_deep_embedded_case",
    "test_public_valid_lua51_profile_matrix_has_zero_diagnostics",
];

fn workspace() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn luad_bin() -> PathBuf {
    static LUAD: OnceLock<PathBuf> = OnceLock::new();
    LUAD.get_or_init(|| {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
            return path.into();
        }
        let output = Command::new("cargo")
            .args(["build", "-p", "luad-cli", "--bin", "luad"])
            .current_dir(workspace())
            .output()
            .expect("build public CLI");
        assert!(
            output.status.success(),
            "luad build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        workspace().join("target/debug/luad")
    })
    .clone()
}

fn run(args: &[&str]) -> Output {
    Command::new(luad_bin())
        .args(args)
        .current_dir(workspace())
        .output()
        .expect("run public CLI")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn live_validator(schema_name: &str) -> jsonschema::Validator {
    let output = run(&["schema", schema_name]);
    assert!(output.status.success(), "schema command failed");
    jsonschema::validator_for(&json(&output)).expect("compile live schema")
}

fn assert_schema(validator: &jsonschema::Validator, value: &Value) {
    let errors: Vec<_> = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "live schema rejected response: {errors:?}"
    );
}

fn object_by_id<'a>(value: &'a Value, id: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => {
            if map.get("id").and_then(Value::as_str) == Some(id) {
                return Some(value);
            }
            map.values().find_map(|child| object_by_id(child, id))
        }
        Value::Array(items) => items.iter().find_map(|child| object_by_id(child, id)),
        _ => None,
    }
}

fn collect_proto_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("maxstacksize") {
                if let Some(id) = map.get("id").and_then(Value::as_str) {
                    ids.insert(id.to_string());
                }
            }
            for child in map.values() {
                collect_proto_ids(child, ids);
            }
        }
        Value::Array(items) => {
            for child in items {
                collect_proto_ids(child, ids);
            }
        }
        _ => {}
    }
}

#[test]
fn test_public_embedded_case_provenance_and_stress_shape() {
    let root = workspace();
    let manifest: Value = serde_json::from_slice(
        &fs::read(root.join(EMBEDDED_MANIFEST)).expect("read embedded manifest"),
    )
    .expect("parse embedded manifest");
    let case = &manifest["cases"][0];
    assert_eq!(manifest["schema_version"].as_u64(), Some(1));
    assert_eq!(manifest["cases"].as_array().map(Vec::len), Some(1));
    assert_eq!(case["redistribution_license"].as_str(), Some("MIT"));
    assert_eq!(case["source_path"].as_str(), Some(EMBEDDED_SOURCE));
    assert_eq!(case["binary_path"].as_str(), Some(EMBEDDED_BINARY));
    assert_eq!(case["source_sha256"].as_str(), Some(SOURCE_SHA256));
    assert_eq!(case["binary_sha256"].as_str(), Some(BINARY_SHA256));
    assert_eq!(
        case["compiler_binary_sha256"].as_str(),
        Some(COMPILER_SHA256)
    );
    assert_eq!(case["target_profile"].as_str(), Some("stock"));
    assert_eq!(case["target_layout"].as_str(), Some("lua51-stock-64bit"));

    let source = fs::read(root.join(EMBEDDED_SOURCE)).expect("read embedded source");
    let binary = fs::read(root.join(EMBEDDED_BINARY)).expect("read embedded bytecode");
    assert_eq!(sha256(&source), SOURCE_SHA256);
    assert_eq!(sha256(&binary), BINARY_SHA256);
    assert_eq!(case["byte_length"].as_u64(), Some(binary.len() as u64));

    let rebuilt = NamedTempFile::new().expect("temporary compiler output");
    let compiler = Path::new("/tmp/lua-tools/bin/luac5.1");
    let compiler_sha256 = sha256(&fs::read(compiler).expect("read compiler"));
    assert!(
        ACCEPTED_COMPILER_SHA256S.contains(&compiler_sha256.as_str()),
        "unrecognized Lua 5.1 compiler binary SHA-256: {compiler_sha256}"
    );
    let status = Command::new(compiler)
        .args(["-o"])
        .arg(rebuilt.path())
        .arg(EMBEDDED_SOURCE)
        .current_dir(&root)
        .status()
        .expect("run official Lua 5.1 compiler");
    assert!(status.success(), "official compiler failed");
    assert_eq!(
        fs::read(rebuilt.path()).expect("read rebuilt chunk"),
        binary
    );

    let inspect = run(&[
        "inspect",
        EMBEDDED_BINARY,
        "--dialect",
        "lua5.1",
        "--format",
        "json",
    ]);
    assert!(inspect.status.success(), "inspect failed");
    assert!(inspect.stderr.is_empty(), "inspect wrote stderr");
    let document = json(&inspect);
    let deepest = object_by_id(&document, DEEPEST).expect("deepest prototype in public document");
    assert_eq!(deepest["maxstacksize"].as_u64(), Some(222));
    assert_eq!(deepest["constants"].as_array().map(Vec::len), Some(450));
    assert_eq!(deepest["instructions"].as_array().map(Vec::len), Some(471));

    let disasm = run(&[
        "disasm",
        EMBEDDED_BINARY,
        "--proto",
        DEEPEST,
        "--format",
        "json",
    ]);
    assert!(disasm.status.success(), "deepest disassembly failed");
    let disasm_document = json(&disasm);
    let instructions = disasm_document["data"]["instructions"]
        .as_array()
        .expect("public instruction array");
    let max_a = instructions
        .iter()
        .filter_map(|instruction| instruction["encoded_operands"]["a"].as_u64())
        .max();
    let max_loadk_bx = instructions
        .iter()
        .filter(|instruction| instruction["mnemonic"].as_str() == Some("LOADK"))
        .filter_map(|instruction| instruction["encoded_operands"]["bx"].as_u64())
        .max();
    assert_eq!(max_a, Some(221));
    assert_eq!(max_loadk_bx, Some(449));
}

#[test]
fn test_public_valid_lua51_profile_matrix_has_zero_diagnostics() {
    let mut cases = Vec::new();
    for name in ["hello", "control_flow", "closures", "tables", "numerics"] {
        cases.push((
            format!("tests/fixtures/precompiled/lua51/{name}.luac"),
            "lua5.1",
        ));
        cases.push((
            format!("tests/fixtures/precompiled/lua51/{name}_stripped.luac"),
            "lua5.1",
        ));
    }
    cases.extend([
        (EMBEDDED_BINARY.to_string(), "lua5.1"),
        (
            "tests/fixtures/precompiled/lua51_32bit/hello.luac".to_string(),
            "lua5.1",
        ),
        (
            "tests/fixtures/precompiled/lua51_lnum32/hello.luac".to_string(),
            "lua5.1-lnum32",
        ),
    ]);

    let validator = live_validator("validate");
    for (path, dialect) in cases {
        for explicit in [false, true] {
            let mut args = vec!["validate", path.as_str(), "--format", "json", "--strict"];
            if explicit {
                args.extend_from_slice(&["--dialect", dialect]);
            }
            let output = run(&args);
            assert!(
                output.status.success(),
                "valid case failed: path={path} explicit={explicit} stderr={}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty(), "valid case wrote stderr: {path}");
            let document = json(&output);
            assert_schema(&validator, &document);
            assert_eq!(document["data"]["diagnostic_count"].as_u64(), Some(0));
            assert_eq!(
                document["interpretation"]["profile"].as_str(),
                Some(dialect),
                "selected profile: {path} explicit={explicit}"
            );
        }
    }
}

fn deepest_proto(proto: &Prototype) -> &Prototype {
    let mut deepest = proto;
    for child in &proto.protos {
        let candidate = deepest_proto(child);
        if candidate.path.0.len() > deepest.path.0.len() {
            deepest = candidate;
        }
    }
    deepest
}

fn patch_word(bytes: &[u8], offset: usize, word: u32) -> NamedTempFile {
    let mut mutated = bytes.to_vec();
    mutated[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    let file = NamedTempFile::new().expect("temporary mutated chunk");
    fs::write(file.path(), mutated).expect("write mutated chunk");
    file
}

fn assert_public_diagnostic(file: &NamedTempFile, code: &str, target: &str) {
    let path = file.path().to_str().expect("UTF-8 temporary path");
    let output = run(&["validate", path, "--dialect", "lua5.1", "--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "corruption must be invalid");
    assert!(output.stderr.is_empty(), "machine validation wrote stderr");
    let document = json(&output);
    let diagnostics = document["data"]["diagnostics"]
        .as_array()
        .expect("diagnostics array");
    assert_eq!(
        diagnostics.len(),
        1,
        "corruption must have one exact finding"
    );
    assert_eq!(diagnostics[0]["code"].as_str(), Some(code));
    assert_eq!(diagnostics[0]["target"].as_str(), Some(target));

    let lookup = run(&["diagnostics", code, "--format", "json"]);
    assert!(lookup.status.success(), "catalog lookup failed for {code}");
    let catalog = json(&lookup);
    assert_eq!(catalog["diagnostic_count"].as_u64(), Some(1));
    assert_eq!(catalog["diagnostics"][0]["code"].as_str(), Some(code));
    assert!(catalog["diagnostics"][0]["semantics"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
    assert!(catalog["diagnostics"][0]["suggested_action"]
        .as_str()
        .is_some_and(|text| !text.is_empty()));
}

#[test]
fn test_public_corruptions_emit_exact_catalog_backed_diagnostics() {
    let bytes = fs::read(workspace().join(EMBEDDED_BINARY)).expect("read embedded fixture");
    let mut reader = SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode fixture");
    let root = &chunk.main_proto;
    let deepest = deepest_proto(root);
    assert_eq!(deepest.id.to_string(), DEEPEST);

    let first = &deepest.instructions[0];
    assert_eq!(first.raw_word & 0x3f, 1, "deepest PC 0 is LOADK");
    let bad_a = (first.raw_word & !(0xff << 6)) | (u32::from(deepest.maxstacksize) << 6);
    let register = patch_word(&bytes, first.source.byte_offset, bad_a);
    assert_public_diagnostic(&register, "L51-REG-001", &format!("{DEEPEST}:pc:0"));

    let bad_bx = (first.raw_word & 0x3fff) | ((deepest.constants.len() as u32) << 14);
    let constant = patch_word(&bytes, first.source.byte_offset, bad_bx);
    assert_public_diagnostic(&constant, "L51-CONST-003", &format!("{DEEPEST}:pc:0"));

    let root_first = &root.instructions[0];
    assert_eq!(root_first.raw_word & 0x3f, 36, "root PC 0 is CLOSURE");
    let bad_proto = (root_first.raw_word & 0x3fff) | ((root.protos.len() as u32) << 14);
    let prototype = patch_word(&bytes, root_first.source.byte_offset, bad_proto);
    assert_public_diagnostic(&prototype, "L51-PROTO-002", "proto:0:pc:0");

    let bad_jump = 22 | (0x3ffff << 14);
    let jump = patch_word(&bytes, root_first.source.byte_offset, bad_jump);
    assert_public_diagnostic(&jump, "L51-JMP-001", "proto:0:pc:0");
}

#[test]
fn test_public_owner_paths_agree_on_deep_embedded_case() {
    let inspect = run(&["inspect", EMBEDDED_BINARY, "--format", "json"]);
    assert!(inspect.status.success());
    let inspect_document = json(&inspect);
    let mut inspect_ids = BTreeSet::new();
    collect_proto_ids(&inspect_document, &mut inspect_ids);
    let expected: BTreeSet<_> = [
        "proto:0",
        "proto:0/0",
        "proto:0/0/0",
        "proto:0/0/0/0",
        "proto:0/0/0/0/0",
        DEEPEST,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    assert_eq!(inspect_ids, expected);

    for id in &expected {
        let disasm = run(&["disasm", EMBEDDED_BINARY, "--proto", id, "--format", "json"]);
        assert!(disasm.status.success(), "disasm selection failed: {id}");
        assert_eq!(json(&disasm)["data"]["id"].as_str(), Some(id.as_str()));
    }

    let xrefs = run(&["xrefs", EMBEDDED_BINARY, "--format", "json"]);
    assert!(xrefs.status.success());
    let document = json(&xrefs);
    let instantiated: BTreeSet<_> = document["data"]["entries"]
        .as_array()
        .expect("xref entries")
        .iter()
        .filter(|entry| entry["relation"].as_str() == Some("instantiates"))
        .map(|entry| entry["target"].as_str().expect("xref target").to_string())
        .collect();
    assert_eq!(
        instantiated,
        expected.into_iter().filter(|id| id != "proto:0").collect()
    );
}

fn closure_contract(spec: &Value) -> bool {
    let prerequisites: BTreeSet<_> = spec["prerequisite_gates"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let expected_prerequisites: BTreeSet<_> = AREA1_PREREQUISITES.iter().copied().collect();
    let tests: BTreeSet<_> = spec["expected_tests"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let expected_tests: BTreeSet<_> = AREA1_TESTS.iter().copied().collect();
    let fixtures = spec["required_fixtures"].as_array();
    prerequisites == expected_prerequisites
        && tests == expected_tests
        && fixtures.is_some_and(|fixtures| {
            fixtures.len() == 1
                && fixtures[0]["path"].as_str() == Some(EMBEDDED_BINARY)
                && fixtures[0]["sha256"].as_str() == Some(BINARY_SHA256)
        })
        && spec["required_compiler_version"].as_str() == Some("Lua 5.1.5")
        && spec["required_compiler_sha256"].as_str() == Some(COMPILER_SHA256)
        && spec["required_profile"].as_str() == Some("lua5.1-area1-validator-diagnostics")
        && spec["allowed_capability_mutations"]
            .as_array()
            .is_some_and(Vec::is_empty)
}

#[test]
fn test_area1_gate_closure_is_exact_and_rejects_substitution() {
    let path = workspace().join("tests/gates/gate-area1-validator-diagnostics.json");
    let spec: Value = serde_json::from_slice(&fs::read(path).expect("read Area 1 gate spec"))
        .expect("parse Area 1 gate spec");
    assert!(closure_contract(&spec), "canonical closure contract");

    let mut missing = spec.clone();
    missing["prerequisite_gates"]
        .as_array_mut()
        .expect("prerequisites")
        .pop();
    assert!(!closure_contract(&missing), "missing prerequisite rejected");

    let mut substituted = spec.clone();
    substituted["prerequisite_gates"][0] = Value::String("gate-facts-lua54-8".into());
    assert!(
        !closure_contract(&substituted),
        "cross-dialect substitution rejected"
    );

    let mut fixture = spec.clone();
    fixture["required_fixtures"][0]["sha256"] = Value::String("0".repeat(64));
    assert!(!closure_contract(&fixture), "fixture substitution rejected");

    let mut tests = spec.clone();
    tests["expected_tests"]
        .as_array_mut()
        .expect("expected tests")
        .pop();
    assert!(
        !closure_contract(&tests),
        "missing acceptance test rejected"
    );

    let mut capability = spec;
    capability["allowed_capability_mutations"] =
        Value::Array(vec![Value::String("lua5.1=supported".into())]);
    assert!(
        !closure_contract(&capability),
        "premature promotion rejected"
    );
}
