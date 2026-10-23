//! Caller answers on a pinned, unmodified public LuCI subset, checked against source text.
//!
//! The oracle uses only the Lua source: every listed caller's call instruction must sit on
//! a debug line that calls the target by the name its own definition line declares. That
//! is independent of luad's resolution rules, so it can catch a fact the accepted analyses
//! got wrong. Sources are compiled with the required official Lua 5.1.5 compiler and never
//! executed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_analysis::{
    analyze_chunk_call_relations, analyze_chunk_callees, attribute_file_callers, CallerFileFacts,
};
use luad_core::envelope::InputIdentity;
use luad_core::model::{Chunk, Prototype};
use luad_core::ProtoPath;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn corpus_dir() -> PathBuf {
    luad_oracle::find_workspace_root().join("tests/corpus/luci-23.05")
}

/// `(path, sha256)` rows of the notice table.
fn notice() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(corpus_dir().join("NOTICE.md")).expect("NOTICE.md");
    text.lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let [_, path, hash, _] = cells.as_slice() else {
                return None;
            };
            let path = path.strip_prefix('`')?.strip_suffix('`')?;
            let hash = hash.strip_prefix('`')?.strip_suffix('`')?;
            (path.ends_with(".lua") && hash.len() == 64)
                .then(|| (path.to_string(), hash.to_string()))
        })
        .collect()
}

fn lua_files(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            lua_files(&path, base, out);
        } else if path.extension().is_some_and(|e| e == "lua") {
            out.insert(path.strip_prefix(base).unwrap().display().to_string());
        }
    }
}

struct Module {
    source: String,
    lines: Vec<String>,
    identity: InputIdentity,
    chunk: Chunk,
    path: String,
    _dir: tempfile::TempDir,
}

fn compile_all(strip: bool) -> Vec<Module> {
    let _ = luad_oracle::require_luac51();
    notice()
        .keys()
        .map(|source| {
            let text = std::fs::read_to_string(corpus_dir().join(source)).unwrap();
            let bytes = luad_oracle::compile_source_lua51(&text, strip).expect("official luac 5.1");
            let dir = tempfile::tempdir().unwrap();
            let path = dir
                .path()
                .join(source.replace('/', "__").replace(".lua", ".luac"));
            std::fs::write(&path, &bytes).unwrap();
            let identity = InputIdentity {
                path: path.display().to_string(),
                sha256: hex::encode(Sha256::digest(&bytes)),
                byte_length: bytes.len(),
            };
            let mut reader = luad_core::reader::SafeReader::new(&bytes);
            let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode");
            Module {
                source: source.clone(),
                lines: text.lines().map(str::to_string).collect(),
                path: identity.path.clone(),
                identity,
                chunk,
                _dir: dir,
            }
        })
        .collect()
}

fn walk<'a>(proto: &'a Prototype, out: &mut Vec<&'a Prototype>) {
    out.push(proto);
    for child in &proto.protos {
        walk(child, out);
    }
}

fn prototypes(chunk: &Chunk) -> Vec<&Prototype> {
    let mut out = Vec::new();
    walk(&chunk.main_proto, &mut out);
    out
}

/// The name a prototype's definition line declares, if it is a named function.
fn declared_name(module: &Module, proto: &Prototype) -> Option<String> {
    let line = module.lines.get(proto.line_defined.checked_sub(1)?)?;
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':';
    // `function a.b:c(` or `local function c(`
    let full = if let Some(at) = line.find("function ") {
        let rest = line[at + "function ".len()..].trim_start();
        let name: String = rest.chars().take_while(|&c| is_name(c)).collect();
        let after = rest[name.len()..].trim_start();
        (!name.is_empty() && after.starts_with('(')).then_some(name)
    } else {
        None
    };
    // `a.b = function(`
    let full = full.or_else(|| {
        let (lhs, rhs) = line.split_once('=')?;
        let rhs = rhs.trim_start();
        let name = lhs.trim();
        (rhs.starts_with("function")
            && rhs["function".len()..].trim_start().starts_with('(')
            && !name.is_empty()
            && name.chars().all(is_name))
        .then(|| name.to_string())
    })?;
    full.rsplit(['.', ':']).next().map(str::to_string)
}

/// Whether `line` contains `name` as a whole identifier immediately applied as a call.
fn calls_by_name(line: &str, name: &str) -> bool {
    line.match_indices(name).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let whole = before.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
        let after = line[at + name.len()..].trim_start();
        whole && after.starts_with(['(', '"', '\'', '{'])
    })
}

fn line_of(chunk: &Chunk, call_id: &str) -> usize {
    for proto in prototypes(chunk) {
        for word in &proto.instructions {
            if word.id.to_string() == call_id {
                return proto.get_line_for_pc(word.pc);
            }
        }
    }
    panic!("no instruction {call_id}")
}

#[test]
fn test_luci_corpus_is_unmodified_and_fully_noticed() {
    let rows = notice();
    assert!(rows.len() >= 10, "notice lists the vendored files");
    let mut on_disk = BTreeSet::new();
    lua_files(&corpus_dir(), &corpus_dir(), &mut on_disk);
    assert_eq!(on_disk, rows.keys().cloned().collect::<BTreeSet<_>>());
    for (path, expected) in &rows {
        let bytes = std::fs::read(corpus_dir().join(path)).unwrap();
        assert_eq!(
            &hex::encode(Sha256::digest(&bytes)),
            expected,
            "{path} changed"
        );
    }
    let license = std::fs::read_to_string(corpus_dir().join("LICENSE")).unwrap();
    assert!(license.contains("Apache License") && license.contains("Version 2.0"));
    // Apache-2.0 section 4(d): the upstream NOTICE travels with the redistributed files.
    let upstream = std::fs::read(corpus_dir().join("UPSTREAM-NOTICE")).unwrap();
    let notice_text = std::fs::read_to_string(corpus_dir().join("NOTICE.md")).unwrap();
    assert!(notice_text.contains(&hex::encode(Sha256::digest(&upstream))));
    assert!(String::from_utf8_lossy(&upstream).contains("Apache License, Version 2.0"));
}

/// Every library-level caller of every named prototype lies on a source line that calls
/// the target by its declared name.
#[test]
fn test_luci_callers_land_on_source_lines_that_call_the_target() {
    let modules = compile_all(false);
    let mut checked = 0usize;
    let mut anonymous = 0usize;
    let mut callers_per_module: BTreeMap<String, usize> = BTreeMap::new();
    for module in &modules {
        let callees = analyze_chunk_callees(&module.chunk);
        let relations = analyze_chunk_call_relations(&module.chunk);
        let facts = CallerFileFacts {
            identity: &module.identity,
            callees: &callees,
            relations: Some(&relations),
            links: None,
        };
        for proto in prototypes(&module.chunk) {
            if proto.path == ProtoPath::root() {
                continue;
            }
            let Some(name) = declared_name(module, proto) else {
                anonymous += 1;
                continue;
            };
            let attribution = attribute_file_callers(&module.identity, &proto.path, &facts);
            assert_eq!(
                attribution.counts.classified(),
                attribution.counts.call_sites
            );
            for caller in &attribution.callers {
                let line = line_of(&module.chunk, &caller.call_id.to_string());
                assert!(
                    line > 0,
                    "{} {} has no debug line",
                    module.source,
                    caller.call_id
                );
                let text = &module.lines[line - 1];
                assert!(
                    calls_by_name(text, &name),
                    "{}: {} listed as a caller of {name} ({}) but line {line} is: {text}",
                    module.source,
                    caller.call_id,
                    proto.id
                );
                checked += 1;
                *callers_per_module.entry(module.source.clone()).or_default() += 1;
            }
        }
    }
    for library in [
        "libs/luci-lib-base/luasrc/util.lua",
        "modules/luci-lua-runtime/luasrc/sys.lua",
        "modules/luci-compat/luasrc/cbi/datatypes.lua",
        "modules/luci-lua-runtime/luasrc/model/uci.lua",
    ] {
        assert!(
            callers_per_module.get(library).copied().unwrap_or(0) > 0,
            "{library} must contribute checked callers"
        );
    }
    assert!(checked >= 100, "only {checked} callers were source-checked");
    eprintln!("source-checked callers: {checked}; anonymous targets counted: {anonymous}");
}

#[test]
fn test_luci_source_line_oracle_rejects_fabricated_and_shifted_callers() {
    let modules = compile_all(false);
    let sys = modules
        .iter()
        .find(|m| m.source.ends_with("luasrc/sys.lua"))
        .unwrap();
    let callees = analyze_chunk_callees(&sys.chunk);
    let relations = analyze_chunk_call_relations(&sys.chunk);
    let facts = CallerFileFacts {
        identity: &sys.identity,
        callees: &callees,
        relations: Some(&relations),
        links: None,
    };
    let lines_of = |proto: &str| -> Vec<usize> {
        attribute_file_callers(&sys.identity, &proto.parse().unwrap(), &facts)
            .callers
            .iter()
            .map(|c| line_of(&sys.chunk, &c.call_id.to_string()))
            .collect()
    };
    let init_action = lines_of("0/28");
    let xclose = lines_of("0/20");
    assert!(!init_action.is_empty() && !xclose.is_empty());
    // Callers attributed to the wrong target are rejected in both directions.
    for line in &init_action {
        assert!(calls_by_name(&sys.lines[line - 1], "init_action"));
        assert!(!calls_by_name(&sys.lines[line - 1], "xclose"));
    }
    for line in &xclose {
        assert!(!calls_by_name(&sys.lines[line - 1], "init_action"));
    }
    // A caller reported one line off is rejected.
    let shifted_rejected = init_action
        .iter()
        .filter(|line| !calls_by_name(&sys.lines[**line], "init_action"))
        .count();
    assert!(
        shifted_rejected > 0,
        "a one-line shift must not pass the oracle"
    );
    // Partial identifiers and non-call mentions are not calls.
    assert!(!calls_by_name(
        "local initialize = init_action",
        "init_action"
    ));
    assert!(!calls_by_name("myinit_action(1)", "init_action"));
    assert!(calls_by_name(
        "x = sys.init_action(\"start\", n)",
        "init_action"
    ));
    assert!(calls_by_name("init_action \"start\"", "init_action"));
}

fn callers_json(target: &str, proto: &str, extra: &[&str]) -> (Option<i32>, Value) {
    let mut args = vec!["callers", target, "--proto", proto, "-f", "json"];
    args.extend_from_slice(extra);
    let output = Command::new(luad_oracle::luad_binary_path())
        .args(&args)
        .output()
        .unwrap();
    (
        output.status.code(),
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null),
    )
}

fn call_ids(document: &Value) -> Vec<String> {
    document["data"]["callers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["call_id"].as_str().unwrap().to_string())
        .collect()
}

/// A few answers an investigator would ask for, pinned with their source lines and
/// first-argument evidence, in debug and stripped builds.
#[test]
fn test_luci_pinned_caller_answers() {
    let debug = compile_all(false);
    let stripped = compile_all(true);
    let find = |modules: &[Module], suffix: &str| -> usize {
        modules
            .iter()
            .position(|m| m.source.ends_with(suffix))
            .unwrap()
    };
    struct Pin {
        module: &'static str,
        proto: &'static str,
        name: &'static str,
        callers: &'static [&'static str],
        first_literals: &'static [&'static str],
    }
    let pins = [
        Pin {
            module: "luasrc/sys.lua",
            proto: "0/28",
            name: "init_action",
            callers: &[
                "proto:0/29:pc:3",
                "proto:0/30:pc:3",
                "proto:0/31:pc:3",
                "proto:0/32:pc:3",
                "proto:0/33:pc:3",
                "proto:0/34:pc:3",
                "proto:0/35:pc:3",
            ],
            first_literals: &[
                "enabled", "enable", "disable", "start", "stop", "restart", "reload",
            ],
        },
        Pin {
            module: "luasrc/controller/lxc.lua",
            proto: "0/4",
            name: "lxc_get_config_path",
            callers: &["proto:0/2:pc:6", "proto:0/5:pc:8", "proto:0/6:pc:20"],
            first_literals: &[],
        },
    ];
    for pin in &pins {
        let module = &debug[find(&debug, pin.module)];
        let (code, document) = callers_json(&module.path, pin.proto, &[]);
        assert_eq!(code, Some(0), "{} {}", pin.module, pin.proto);
        assert_eq!(call_ids(&document), pin.callers, "{}", pin.name);
        for caller in pin.callers {
            let line = line_of(&module.chunk, caller);
            assert!(calls_by_name(&module.lines[line - 1], pin.name));
        }
        let literals: Vec<String> = document["data"]["callers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| {
                let origin = &c["argument_window"]["arguments"][0]["origin"];
                (origin["kind"] == "literal")
                    .then(|| {
                        origin["value"]["value"]["display"]
                            .as_str()
                            .map(str::to_string)
                    })
                    .flatten()
            })
            .collect();
        if !pin.first_literals.is_empty() {
            let expected: Vec<String> = pin.first_literals.iter().map(|s| s.to_string()).collect();
            assert_eq!(
                literals,
                expected,
                "{}: first-argument literals {}",
                pin.name,
                serde_json::to_string(&document["data"]["callers"][0]["argument_window"]).unwrap()
            );
        }
        let twin = &stripped[find(&stripped, pin.module)];
        let (_, stripped_document) = callers_json(&twin.path, pin.proto, &[]);
        assert_eq!(
            call_ids(&stripped_document),
            pin.callers,
            "stripped {}",
            pin.name
        );
    }

    // The dispatcher's `node(unpack(path))` keeps its open argument window explicit.
    let dispatcher = &debug[find(&debug, "luasrc/dispatcher.lua")];
    let (_, nodes) = callers_json(&dispatcher.path, "0/5", &[]);
    let first = &nodes["data"]["callers"][0];
    assert_eq!(first["call_id"], "proto:0/2:pc:4");
    assert_eq!(first["argument_window"]["kind"], "open");
}

/// The strict convention's admission is the current boundary: pin which modules it
/// cannot admit, so a later admission change is a visible, reviewed change.
#[test]
fn test_luci_strict_link_index_boundary_is_pinned() {
    let modules = compile_all(false);
    let util = modules
        .iter()
        .find(|m| m.source.ends_with("luasrc/util.lua"))
        .unwrap();
    let mut args: Vec<&str> = modules
        .iter()
        .filter(|m| m.path != util.path)
        .map(|m| m.path.as_str())
        .collect();
    args.extend(["--link-convention", "luci-module-setglobal"]);
    let (code, document) = callers_json(&util.path, "0/35", &args);
    assert_eq!(code, Some(0));
    let summary = &document["data"]["summary"];
    assert_eq!(summary["degraded"], true);
    assert_eq!(summary["coverage_complete"], true);
    let by_path: BTreeMap<&str, &str> = modules
        .iter()
        .map(|m| (m.path.as_str(), m.source.as_str()))
        .collect();
    let dynamic: BTreeSet<&str> = summary["dynamic_providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| by_path[p.as_str().unwrap()])
        .collect();
    let admitted: BTreeSet<&str> = by_path
        .values()
        .copied()
        .filter(|s| !dynamic.contains(s))
        .collect();
    assert_eq!(
        admitted,
        BTreeSet::from([
            "applications/luci-app-ahcp/luasrc/controller/ahcp.lua",
            "applications/luci-app-nft-qos/luasrc/controller/nft-qos.lua",
            "applications/luci-app-openvpn/luasrc/controller/openvpn.lua",
            "modules/luci-mod-admin-mini/luasrc/controller/mini/index.lua",
            "modules/luci-mod-admin-mini/luasrc/controller/mini/network.lua",
            "modules/luci-mod-admin-mini/luasrc/controller/mini/system.lua",
        ]),
        "strict admission changed"
    );
}
