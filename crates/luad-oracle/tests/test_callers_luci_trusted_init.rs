//! Cross-file caller answers under `luci-module-trusted-init` on the pinned public LuCI
//! subset, checked against source text.
//!
//! The oracle reads only the Lua source:
//! - a module's name, from its `module("...")` line;
//! - its top-level functions, from `function name(` lines at column 0;
//! - its cross-module call sites, from `luci.x.name(` text.
//!
//! That is independent of luad's resolution rules. Precision means every reported
//! cross-file caller sits on a line that calls the target by name, in a file that names
//! the target module. Recall means every literal `luci.x.name(` call to a vendored
//! top-level function is reported, or is classed degraded. Sources are compiled with the
//! required official Lua 5.1.5 compiler and never executed. The corpus itself is checked
//! by `test_callers_luci_corpus.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use luad_analysis::{
    analyze_chunk_call_relations, analyze_chunk_callees, attribute_file_callers,
    index_chunk_module_exports, resolve_chunk_links, CallerFileFacts, ChunkLinkResult,
    LinkConvention, LinkStatus, ModuleExportIndex,
};
use luad_core::envelope::InputIdentity;
use luad_core::model::{Chunk, Prototype};
use luad_core::ProtoPath;
use serde_json::Value;
use sha2::{Digest, Sha256};

const CONVENTION: LinkConvention = LinkConvention::LuciModuleTrustedInit;

fn corpus_dir() -> PathBuf {
    luad_oracle::find_workspace_root().join("tests/corpus/luci-23.05")
}

fn sources() -> Vec<String> {
    let text = std::fs::read_to_string(corpus_dir().join("NOTICE.md")).expect("NOTICE.md");
    text.lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            let [_, path, _, _] = cells.as_slice() else {
                return None;
            };
            let path = path.strip_prefix('`')?.strip_suffix('`')?;
            path.ends_with(".lua").then(|| path.to_string())
        })
        .collect()
}

struct Module {
    source: String,
    text: String,
    lines: Vec<String>,
    identity: InputIdentity,
    chunk: Chunk,
    _dir: tempfile::TempDir,
}

fn compile_all() -> Vec<Module> {
    let _ = luad_oracle::require_luac51();
    sources()
        .into_iter()
        .map(|source| {
            let text = std::fs::read_to_string(corpus_dir().join(&source)).unwrap();
            let bytes = luad_oracle::compile_source_lua51(&text, false).expect("official luac");
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
                lines: text.lines().map(str::to_string).collect(),
                text,
                source,
                identity,
                chunk,
                _dir: dir,
            }
        })
        .collect()
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// A line with string literal contents blanked and any `--` comment removed. Long
/// strings and comments spanning lines do not occur on call lines in this corpus.
fn code(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == '\\' {
                    chars.next();
                } else if c == q {
                    quote = None;
                    out.push(c);
                }
            }
            None if c == '"' || c == '\'' => {
                quote = Some(c);
                out.push(c);
            }
            None if c == '-' && chars.peek() == Some(&'-') => break,
            None => out.push(c),
        }
    }
    out
}

/// The name in `module("luci.x"...)` or `module "luci.x"`.
fn module_name(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim_start();
        if line.starts_with("--") {
            continue;
        }
        let Some(rest) = line.strip_prefix("module") else {
            continue;
        };
        let rest = rest.trim_start().trim_start_matches('(').trim_start();
        let quote = rest.chars().next()?;
        if quote != '"' && quote != '\'' {
            continue;
        }
        let name: String = rest[1..].chars().take_while(|&c| c != quote).collect();
        return Some(name);
    }
    None
}

/// `function name(` at column 0, with a plain name.
fn top_level_function(line: &str) -> Option<String> {
    let rest = line.strip_prefix("function ")?;
    let name: String = rest.chars().take_while(|&c| is_ident(c)).collect();
    (!name.is_empty() && rest[name.len()..].trim_start().starts_with('(')).then_some(name)
}

/// Every `luci.a.b.name(` in a line, as `(module path, name)`.
fn literal_calls(line: &str) -> Vec<(String, String)> {
    let line = code(line);
    let line = line.as_str();
    let mut out = Vec::new();
    for (at, _) in line.match_indices("luci.") {
        if line[..at]
            .chars()
            .next_back()
            .is_some_and(|c| is_ident(c) || c == '.')
        {
            continue;
        }
        let path: String = line[at..]
            .chars()
            .take_while(|&c| is_ident(c) || c == '.')
            .collect();
        let after = line[at + path.len()..].trim_start();
        if !after.starts_with(['(', '"', '\'', '{']) {
            continue;
        }
        if let Some((module, name)) = path.rsplit_once('.') {
            out.push((module.to_string(), name.to_string()));
        }
    }
    out
}

fn walk<'a>(proto: &'a Prototype, out: &mut Vec<&'a Prototype>) {
    out.push(proto);
    for child in &proto.protos {
        walk(child, out);
    }
}

fn line_of(chunk: &Chunk, call_id: &str) -> usize {
    let mut protos = Vec::new();
    walk(&chunk.main_proto, &mut protos);
    for proto in protos {
        for word in &proto.instructions {
            if word.id.to_string() == call_id {
                return proto.get_line_for_pc(word.pc);
            }
        }
    }
    panic!("no instruction {call_id}")
}

struct Corpus {
    modules: Vec<Module>,
    index: ModuleExportIndex,
    links: Vec<ChunkLinkResult>,
    callees: Vec<luad_analysis::ChunkCalleeAnalysis>,
    relations: Vec<luad_analysis::ChunkCallRelationAnalysis>,
}

fn corpus() -> Corpus {
    let modules = compile_all();
    let mut index = ModuleExportIndex::default();
    for module in &modules {
        index_chunk_module_exports(&module.identity, &module.chunk, CONVENTION, &mut index);
    }
    let links = modules
        .iter()
        .map(|m| resolve_chunk_links(&m.identity, &m.chunk, &index, CONVENTION))
        .collect();
    let callees = modules
        .iter()
        .map(|m| analyze_chunk_callees(&m.chunk))
        .collect();
    let relations = modules
        .iter()
        .map(|m| analyze_chunk_call_relations(&m.chunk))
        .collect();
    Corpus {
        modules,
        index,
        links,
        callees,
        relations,
    }
}

/// One oracle target: a vendored module's top-level function.
struct Target {
    module: usize,
    namespace: String,
    name: String,
    proto: ProtoPath,
}

fn targets(corpus: &Corpus) -> Vec<Target> {
    let mut out = Vec::new();
    for (i, module) in corpus.modules.iter().enumerate() {
        let Some(namespace) = module_name(&module.text) else {
            continue;
        };
        for (child, proto) in module.chunk.main_proto.protos.iter().enumerate() {
            let Some(line) = module.lines.get(proto.line_defined.saturating_sub(1)) else {
                continue;
            };
            if let Some(name) = top_level_function(line) {
                out.push(Target {
                    module: i,
                    namespace: namespace.clone(),
                    name,
                    proto: ProtoPath::root().child(child),
                });
            }
        }
    }
    out
}

/// `(caller module, line)` for every caller luad reports for `target`.
fn reported_callers(corpus: &Corpus, target: &Target) -> BTreeSet<(usize, usize)> {
    let target_identity = &corpus.modules[target.module].identity;
    let mut out = BTreeSet::new();
    for (i, module) in corpus.modules.iter().enumerate() {
        let facts = CallerFileFacts {
            identity: &module.identity,
            callees: &corpus.callees[i],
            relations: (i == target.module).then(|| &corpus.relations[i]),
            links: Some((&corpus.links[i], CONVENTION)),
        };
        let attribution = attribute_file_callers(target_identity, &target.proto, &facts);
        assert_eq!(
            attribution.counts.classified(),
            attribution.counts.call_sites
        );
        for caller in attribution.callers {
            out.insert((i, line_of(&module.chunk, &caller.call_id.to_string())));
        }
    }
    out
}

/// Names a file binds to `namespace`: the namespace itself, and every identifier assigned
/// from it or from `require` of it (`x = luci.sys`, `local x = require "luci.sys"`).
fn namespace_spellings(text: &str, namespace: &str) -> Vec<String> {
    let mut out = vec![namespace.to_string()];
    for line in text.lines() {
        // String contents matter here, so only a comment is cut.
        let line = line.split(" --").next().unwrap_or("");
        let Some((lhs, rhs)) = line.split_once('=') else {
            continue;
        };
        let rhs = rhs.trim();
        let quoted = [format!("\"{namespace}\""), format!("'{namespace}'")];
        let names_it = rhs == namespace
            || (rhs.starts_with("require") && quoted.iter().any(|q| rhs.contains(q.as_str())));
        let name = lhs.trim().trim_start_matches("local").trim();
        if names_it && !name.is_empty() && name.chars().all(is_ident) {
            out.push(name.to_string());
        }
    }
    out
}

/// Whether `line` calls `spelling.name(` or `spelling:name(` with `spelling` a whole name.
fn calls_through(line: &str, spelling: &str, name: &str) -> bool {
    [format!("{spelling}.{name}"), format!("{spelling}:{name}")]
        .iter()
        .any(|needle| {
            line.match_indices(needle.as_str()).any(|(at, _)| {
                let before = line[..at].chars().next_back();
                let whole = before.is_none_or(|c| !(is_ident(c) || c == '.'));
                let after = line[at + needle.len()..].trim_start();
                whole && after.starts_with(['(', '"', '\'', '{'])
            })
        })
}

/// Precision check for one reported cross-file caller: the line calls the target by its
/// name through the target's namespace or a name the file binds to it.
fn caller_matches_source(corpus: &Corpus, target: &Target, caller: (usize, usize)) -> bool {
    let module = &corpus.modules[caller.0];
    if caller.1 == 0 {
        return false;
    }
    let raw = &module.lines[caller.1 - 1];
    let line = code(raw);
    let ns = &target.namespace;
    // `require "luci.x".f()` calls through the literal, so match it before blanking.
    let required = [
        format!("require \"{ns}\""),
        format!("require '{ns}'"),
        format!("require(\"{ns}\")"),
        format!("require('{ns}')"),
    ];
    namespace_spellings(&module.text, ns)
        .iter()
        .any(|spelling| calls_through(&line, spelling, &target.name))
        || required
            .iter()
            .any(|spelling| calls_through(raw, spelling, &target.name))
}

#[test]
fn test_trusted_init_cross_file_callers_match_source_both_ways() {
    let corpus = corpus();
    assert!(
        corpus.index.dynamic_artifacts.is_empty(),
        "every vendored module is admitted: {:?}",
        corpus.index.dynamic_artifacts
    );
    assert!(!corpus.index.assumed_artifacts.is_empty());
    let targets = targets(&corpus);
    let by_label: BTreeMap<(String, String), &Target> = targets
        .iter()
        .map(|t| ((t.namespace.clone(), t.name.clone()), t))
        .collect();

    let mut cross_checked = 0usize;
    let mut reported: BTreeMap<(String, String), BTreeSet<(usize, usize)>> = BTreeMap::new();
    for target in &targets {
        let callers = reported_callers(&corpus, target);
        for &caller in &callers {
            if caller.0 == target.module {
                continue;
            }
            assert!(
                caller_matches_source(&corpus, target, caller),
                "{}:{} listed as a caller of {}.{} but reads: {}",
                corpus.modules[caller.0].source,
                caller.1,
                target.namespace,
                target.name,
                corpus.modules[caller.0].lines[caller.1 - 1]
            );
            cross_checked += 1;
        }
        reported.insert((target.namespace.clone(), target.name.clone()), callers);
    }

    // Recall: each literal call to a vendored top-level function is reported or degraded.
    let mut literal_sites = 0usize;
    let mut degraded_sites = 0usize;
    for (i, module) in corpus.modules.iter().enumerate() {
        // `local luci = {}` makes `luci.x.f(` a local field call, not a global path.
        if module
            .lines
            .iter()
            .any(|l| code(l).trim_start().starts_with("local luci"))
        {
            continue;
        }
        for (n, line) in module.lines.iter().enumerate() {
            for (namespace, name) in literal_calls(line) {
                let key = (namespace.clone(), name.clone());
                if !by_label.contains_key(&key) {
                    continue;
                }
                literal_sites += 1;
                if reported[&key].contains(&(i, n + 1)) {
                    continue;
                }
                let degraded = corpus.links[i].facts.iter().any(|link| {
                    link.label_segments.join(".") == format!("{namespace}.{name}")
                        && line_of(&module.chunk, &link.call_id.to_string()) == n + 1
                        && matches!(link.status, LinkStatus::Dynamic | LinkStatus::LimitExceeded)
                });
                assert!(
                    degraded,
                    "{}:{} calls {namespace}.{name} but luad neither lists nor degrades it: {line}",
                    module.source,
                    n + 1
                );
                degraded_sites += 1;
            }
        }
    }
    eprintln!(
        "cross-file callers source-checked: {cross_checked}; literal call sites: {literal_sites}; degraded: {degraded_sites}"
    );
    // Pinned so an admission change is a visible, reviewed change.
    assert_eq!(
        (cross_checked, literal_sites, degraded_sites),
        (70, 39, 0),
        "trusted-init answers on the vendored subset changed"
    );
}

#[test]
fn test_trusted_init_source_oracle_rejects_fabricated_callers() {
    let corpus = corpus();
    let targets = targets(&corpus);
    let mut rejected_shift = 0usize;
    let mut rejected_rename = 0usize;
    for target in &targets {
        for caller in reported_callers(&corpus, target) {
            if caller.0 == target.module {
                continue;
            }
            assert!(caller_matches_source(&corpus, target, caller));
            // A caller reported one line off is rejected somewhere in the corpus.
            if caller.1 < corpus.modules[caller.0].lines.len()
                && !caller_matches_source(&corpus, target, (caller.0, caller.1 + 1))
            {
                rejected_shift += 1;
            }
            // The same site attributed to a differently named target is rejected.
            let renamed = Target {
                module: target.module,
                namespace: target.namespace.clone(),
                name: format!("{}_renamed", target.name),
                proto: target.proto.clone(),
            };
            if !caller_matches_source(&corpus, &renamed, caller) {
                rejected_rename += 1;
            }
            // The same name in a different namespace is rejected too.
            let moved = Target {
                module: target.module,
                namespace: format!("{}.elsewhere", target.namespace),
                name: target.name.clone(),
                proto: target.proto.clone(),
            };
            assert!(
                !caller_matches_source(&corpus, &moved, caller),
                "{}.{} accepted for another namespace",
                target.namespace,
                target.name
            );
        }
    }
    assert!(rejected_shift > 0 && rejected_rename > 0);
    // The recall scanner sees calls and nothing else.
    assert_eq!(
        literal_calls("x = luci.sys.exec('a') -- luci.util.split(b)"),
        [("luci.sys".to_string(), "exec".to_string())]
    );
    assert!(literal_calls("local f = luci.sys.exec").is_empty());
    assert!(literal_calls("myluci.sys.exec(1)").is_empty());
    assert_eq!(
        module_name("-- module 'x'\nmodule(\"luci.a\", package.seeall)"),
        Some("luci.a".to_string())
    );
    assert_eq!(top_level_function("function f(a)"), Some("f".to_string()));
    assert_eq!(top_level_function("function a.f(a)"), None);
    assert_eq!(top_level_function("\tfunction f(a)"), None);
}

fn callers_json(args: &[&str]) -> (Option<i32>, Value, String) {
    let output = Command::new(luad_oracle::luad_binary_path())
        .args(args)
        .output()
        .unwrap();
    (
        output.status.code(),
        serde_json::from_slice(&output.stdout).unwrap_or(Value::Null),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// The command-line answer carries the assumption everywhere it is relied on, and the
/// strict convention's answer on the same corpus carries none of it.
#[test]
fn test_trusted_init_answer_is_labeled_and_strict_answer_is_not() {
    let corpus = corpus();
    let targets = targets(&corpus);
    let target = targets
        .iter()
        .max_by_key(|t| {
            reported_callers(&corpus, t)
                .iter()
                .filter(|c| c.0 != t.module)
                .count()
        })
        .unwrap();
    let util = target.module;
    let proto = target.proto.to_string();
    let mut args = vec![
        "callers",
        corpus.modules[util].identity.path.as_str(),
        "--proto",
        proto.as_str(),
        "-f",
        "json",
    ];
    for module in &corpus.modules {
        if module.source != corpus.modules[util].source {
            args.push(module.identity.path.as_str());
        }
    }
    let mut trusted_args = args.clone();
    trusted_args.extend(["--link-convention", "luci-module-trusted-init"]);
    let (code, document, _) = callers_json(&trusted_args);
    assert_eq!(code, Some(0), "{document}");
    let summary = &document["data"]["summary"];
    assert_eq!(summary["assumptions"], serde_json::json!(["trusted-init"]));
    assert!(!summary["assumed_providers"].as_array().unwrap().is_empty());
    assert!(summary.get("dynamic_providers").is_none());
    let cross: Vec<&Value> = document["data"]["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["caller"]["path"] != corpus.modules[util].identity.path.as_str())
        .collect();
    assert!(!cross.is_empty(), "{}.{}", target.namespace, target.name);
    for caller in cross {
        let bases = caller["bases"].as_array().unwrap();
        assert!(bases.iter().all(|b| b["source"] != "cross_chunk_link"
            || b["assumptions"] == serde_json::json!(["trusted-init"])));
    }

    let mut strict_args = args.clone();
    strict_args.extend(["--link-convention", "luci-module-setglobal"]);
    let (_, strict, raw) = callers_json(&strict_args);
    assert_eq!(strict["data"]["summary"]["degraded"], true);
    assert!(!raw.contains("assumption") && !raw.contains("assumed_providers"));

    trusted_args.retain(|a| *a != "json");
    let position = trusted_args.iter().position(|a| *a == "-f").unwrap();
    trusted_args.insert(position + 1, "text");
    let output = Command::new(luad_oracle::luad_binary_path())
        .args(&trusted_args)
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("assuming trusted-init"), "{text}");
    assert!(text.contains("Assumes trusted-init for:"), "{text}");
}
