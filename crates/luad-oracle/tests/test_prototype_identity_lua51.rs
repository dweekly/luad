//! Mutation-sensitive public evidence for Lua 5.1 prototype subtree identities.

use std::collections::BTreeMap;
use std::io::Write;
use std::process::Command;

use luad_analysis::{
    analyze_chunk_prototype_identities, analyze_chunk_prototype_identities_v1,
    PrototypeIdentityFact, PROTOTYPE_IDENTITY_SCHEME_V2,
};
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::{Chunk, ConstantValue, UpvalueDesc};
use luad_core::reader::SafeReader;
use luad_core::{Dialect, ProtoPath, SourceLocation, StableId};

fn parse_lua51(bytes: &[u8]) -> Chunk {
    let dialect = luad_dialect_lua51::Lua51Dialect::default();
    let mut reader =
        SafeReader::with_options(bytes, 0, ResourceLimits::default(), ParseMode::Strict);
    dialect.decode_chunk(&mut reader).expect("parse Lua 5.1")
}

fn fixture(name: &str, stripped: bool) -> Chunk {
    parse_lua51(
        &luad_oracle::load_precompiled_fixture("lua51", name, stripped).expect("load fixture"),
    )
}

fn identities(chunk: &Chunk) -> Vec<PrototypeIdentityFact> {
    analyze_chunk_prototype_identities(chunk)
        .expect("identity analysis")
        .prototypes
}

fn digest_map(chunk: &Chunk) -> BTreeMap<String, String> {
    identities(chunk)
        .into_iter()
        .map(|fact| (fact.proto_id.to_string(), fact.digest))
        .collect()
}

fn root_digest(chunk: &Chunk) -> String {
    identities(chunk)
        .into_iter()
        .next()
        .expect("root identity")
        .digest
}

fn v1_root_digest(chunk: &Chunk) -> String {
    analyze_chunk_prototype_identities_v1(chunk)
        .expect("v1 compatibility identity analysis")
        .prototypes
        .into_iter()
        .next()
        .expect("root v1 identity")
        .digest
}

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

fn write_fixture(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temp fixture");
    file.write_all(bytes).expect("write fixture");
    file
}

fn exported_identities(output: &[u8]) -> Vec<PrototypeIdentityFact> {
    output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_slice(line).expect("JSONL record");
            (value["record_type"] == "prototype_identity").then(|| {
                serde_json::from_value(value["data"].clone()).expect("typed identity fact")
            })
        })
        .collect()
}

fn collect_proto_ids(proto: &luad_core::Prototype, ids: &mut Vec<String>) {
    ids.push(proto.id.to_string());
    for child in &proto.protos {
        collect_proto_ids(child, ids);
    }
}

fn mutate_first_capture_descriptor(proto: &mut luad_core::Prototype) -> bool {
    let disassembly = luad_dialect_lua51::disassemble_proto_lua51(proto);
    if let Some(pc) = disassembly
        .instructions
        .iter()
        .find(|instruction| instruction.role == "closure_binding")
        .map(|instruction| instruction.pc)
    {
        proto.instructions[pc].raw_word ^= 1 << 23;
        return true;
    }
    proto.protos.iter_mut().any(mutate_first_capture_descriptor)
}

#[test]
fn test_identity_golden_and_debug_invariance() {
    let with_debug = fixture("hello", false);
    let stripped = fixture("hello", true);
    let expected = "sha256:c5c865906c6cb306ef43694f504a01a191e588a04f595b6c5c1ba964be27da29";
    assert_eq!(v1_root_digest(&with_debug), expected);
    assert_eq!(v1_root_digest(&stripped), expected);

    let mut relocated = with_debug.clone();
    relocated.sha256 = "different-artifact".to_string();
    relocated.main_proto.source_name = None;
    relocated.main_proto.line_defined = 999;
    relocated.main_proto.last_line_defined = 1001;
    relocated.main_proto.line_info.clear();
    relocated.main_proto.abs_line_info.clear();
    relocated.main_proto.loc_vars.clear();
    relocated.main_proto.upvalue_names.clear();
    relocated.main_proto.source.byte_offset += 7;
    relocated.main_proto.instructions[0].raw_hex = "ffffffff".to_string();
    relocated.main_proto.constants[0].source.raw_hex = "00".to_string();
    relocated.main_proto.id = StableId::proto(ProtoPath(vec![99]));
    relocated.main_proto.path = ProtoPath(vec![99]);
    assert_eq!(v1_root_digest(&relocated), expected);
}

#[test]
fn test_every_included_field_family_changes_identity() {
    let baseline = fixture("closures", false);
    let expected = root_digest(&baseline);

    let mut mutations: Vec<(&str, Chunk)> = Vec::new();
    let mut numparams = baseline.clone();
    numparams.main_proto.numparams ^= 1;
    mutations.push(("numparams", numparams));
    let mut vararg = baseline.clone();
    vararg.main_proto.is_vararg ^= 2;
    mutations.push(("vararg flags", vararg));
    let mut stack = baseline.clone();
    stack.main_proto.maxstacksize += 1;
    mutations.push(("maximum stack", stack));
    let mut instruction = baseline.clone();
    instruction.main_proto.instructions[0].raw_word ^= 1 << 6;
    mutations.push(("typed instruction operand", instruction));
    let mut instruction_order = baseline.clone();
    instruction_order.main_proto.instructions.swap(0, 1);
    mutations.push(("instruction order", instruction_order));
    let mut nups = baseline.clone();
    nups.main_proto.upvalues.push(UpvalueDesc {
        id: StableId::upvalue(ProtoPath::root(), 0),
        index: 0,
        instack: 0,
        idx: 0,
        kind: 0,
        name: None,
        source: SourceLocation::new(0, &[]),
    });
    mutations.push(("upvalue count", nups));

    let mut capture = baseline.clone();
    assert!(mutate_first_capture_descriptor(&mut capture.main_proto));
    mutations.push(("capture descriptor", capture));

    for (label, mutation) in mutations {
        assert_ne!(
            root_digest(&mutation),
            expected,
            "{label} must be committed"
        );
    }

    let mut constant = fixture("hello", false);
    let constant_baseline = root_digest(&constant);
    constant.main_proto.constants[0].value = ConstantValue::Boolean(false);
    assert_ne!(
        root_digest(&constant),
        constant_baseline,
        "constant type and value must be committed"
    );
    let mut constant_order = fixture("hello", false);
    let constant_order_baseline = root_digest(&constant_order);
    constant_order.main_proto.constants.swap(0, 1);
    assert_ne!(
        root_digest(&constant_order),
        constant_order_baseline,
        "constant order must be committed"
    );
}

#[test]
fn test_child_propagation_order_and_twin_position_invariance() {
    let _ = luad_oracle::require_luac51();
    let source = r#"
        local function first(x) return x + 1 end
        local function second(x) return x + 1 end
        return first, second
    "#;
    let baseline = luad_oracle::compile_and_parse_lua51(source, false).expect("compile fixture");
    assert_eq!(baseline.main_proto.protos.len(), 2);
    let base = digest_map(&baseline);
    assert_eq!(base["proto:0/0"], base["proto:0/1"]);

    let mut changed = baseline.clone();
    changed.main_proto.protos[0].maxstacksize += 1;
    let changed_map = digest_map(&changed);
    assert_ne!(changed_map["proto:0/0"], base["proto:0/0"]);
    assert_eq!(changed_map["proto:0/1"], base["proto:0/1"]);
    assert_ne!(changed_map["proto:0"], base["proto:0"]);

    let mut distinct = baseline.clone();
    distinct.main_proto.protos[1].maxstacksize += 1;
    let distinct_digest = root_digest(&distinct);
    let mut reordered = distinct.clone();
    reordered.main_proto.protos.swap(0, 1);
    assert_ne!(root_digest(&reordered), distinct_digest);
}

#[test]
fn test_recursive_export_matches_direct_analysis_and_count_closure() {
    let bytes =
        luad_oracle::load_precompiled_fixture("lua51", "closures", false).expect("load closures");
    let chunk = parse_lua51(&bytes);
    let expected = identities(&chunk);
    let file = write_fixture(&bytes);
    let output = Command::new(get_luad_bin())
        .args([
            "export",
            file.path().to_str().expect("path"),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("export");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(exported_identities(&output.stdout), expected);

    let mut structural_ids = Vec::new();
    collect_proto_ids(&chunk.main_proto, &mut structural_ids);
    assert_eq!(
        expected
            .iter()
            .map(|fact| fact.proto_id.to_string())
            .collect::<Vec<_>>(),
        structural_ids
    );

    let records: Vec<serde_json::Value> = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("JSONL"))
        .collect();
    let file_end = records
        .iter()
        .find(|record| record["record_type"] == "file_end")
        .expect("file_end");
    let counted = records
        .iter()
        .filter(|record| {
            matches!(
                record["record_type"].as_str(),
                Some(
                    "prototype"
                        | "prototype_identity"
                        | "instruction"
                        | "constant"
                        | "upvalue"
                        | "xref"
                        | "callee"
                        | "origin"
                        | "call_relation"
                )
            )
        })
        .count();
    assert_eq!(file_end["available_fact_count"], counted);
    assert_eq!(file_end["emitted_fact_count"], counted);
}

#[test]
fn test_lnum_selection_agrees_and_other_dialects_emit_no_identity() {
    let root = luad_oracle::find_workspace_root();
    let lnum = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");
    let luad = get_luad_bin();
    let automatic = Command::new(&luad)
        .args(["export", lnum.to_str().expect("path"), "--format", "jsonl"])
        .output()
        .expect("automatic export");
    let explicit = Command::new(&luad)
        .args([
            "export",
            lnum.to_str().expect("path"),
            "--format",
            "jsonl",
            "--dialect",
            "lua5.1-lnum32",
        ])
        .output()
        .expect("explicit export");
    assert!(automatic.status.success());
    assert!(explicit.status.success());
    assert_eq!(
        exported_identities(&automatic.stdout),
        exported_identities(&explicit.stdout)
    );

    let lua54 = root.join("tests/fixtures/precompiled/lua54/hello.luac");
    let other = Command::new(&luad)
        .args(["export", lua54.to_str().expect("path"), "--format", "jsonl"])
        .output()
        .expect("Lua 5.4 export");
    assert!(other.status.success());
    assert!(exported_identities(&other.stdout).is_empty());
}

#[test]
fn test_identity_schema_capability_and_format_are_public() {
    let luad = get_luad_bin();
    let schema = Command::new(&luad)
        .args(["schema", "export"])
        .output()
        .expect("export schema");
    assert!(schema.status.success());
    let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).expect("schema JSON");
    assert!(schema["definitions"]["PrototypeIdentityFact"].is_object());

    let capabilities = Command::new(&luad)
        .args(["capabilities", "--format", "json"])
        .output()
        .expect("capabilities");
    let manifest: serde_json::Value =
        serde_json::from_slice(&capabilities.stdout).expect("capabilities JSON");
    let lua51 = manifest["dialects"]
        .as_array()
        .expect("dialects")
        .iter()
        .find(|dialect| dialect["id"] == "lua5.1")
        .expect("Lua 5.1");
    assert!(lua51["features"]
        .as_array()
        .expect("features")
        .iter()
        .any(|feature| feature == "prototype subtree identity (experimental)"));

    let fact = identities(&fixture("hello", false)).remove(0);
    assert_eq!(fact.scheme, PROTOTYPE_IDENTITY_SCHEME_V2);
    assert_eq!(fact.digest.len(), "sha256:".len() + 64);
    assert!(fact.digest.starts_with("sha256:"));
    assert!(fact.digest["sha256:".len()..]
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
}
