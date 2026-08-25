//! Independent acceptance for the Lua 5.1 retrieval and machine-contract freeze.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::Value;
use tempfile::TempDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vocabulary {
    Closed,
    Open,
    Integer,
}
type Field = (&'static str, Vocabulary, &'static [&'static str]);

const EQ: &[&str] = &["==", "!="];
const EQ_CONTAINS: &[&str] = &["==", "!=", "contains"];

#[rustfmt::skip]
const RETRIEVAL_VOCABULARY: &[Field] = &[
    ("constant",              Vocabulary::Open,    EQ_CONTAINS),
    ("constant.type",         Vocabulary::Closed,  EQ),
    ("callee.status",         Vocabulary::Closed,  EQ),
    ("callee.path",           Vocabulary::Open,    EQ_CONTAINS),
    ("callee.lookup.kind",    Vocabulary::Closed,  EQ),
    ("callee.lookup.key",     Vocabulary::Open,    EQ_CONTAINS),
    ("callee.reason",         Vocabulary::Closed,  EQ),
    ("call.reason",           Vocabulary::Closed,  EQ),
    ("call.target",           Vocabulary::Open,    EQ),
    ("origin.kind",           Vocabulary::Closed,  EQ),
    ("origin.argument.index", Vocabulary::Integer, EQ),
    ("interpretation.profile", Vocabulary::Closed, EQ),
    ("prototype.digest",      Vocabulary::Open,    EQ),
];

const RESULT_KINDS: &[&str] = &[
    "instruction",
    "constant",
    "prototype",
    "upvalue",
    "call",
    "interpretation",
];

fn luad_bin() -> PathBuf {
    static LUAD: OnceLock<PathBuf> = OnceLock::new();
    LUAD.get_or_init(|| {
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_luad") {
            return p.into();
        }
        let root = luad_oracle::find_workspace_root();
        let out = Command::new("cargo")
            .args(["build", "-p", "luad-cli", "--bin", "luad"])
            .current_dir(&root)
            .output()
            .expect("build");
        assert!(
            out.status.success(),
            "build: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        root.join("target/debug/luad")
    })
    .clone()
}

fn run(args: &[&str]) -> Output {
    Command::new(luad_bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("run {args:?}: {e}"))
}

fn run_ok(args: &[&str]) -> String {
    let out = run(args);
    assert_eq!(
        out.status.code(),
        Some(0),
        "failed {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run_json(args: &[&str]) -> Value {
    let s = run_ok(args);
    serde_json::from_str(&s).unwrap_or_else(|e| panic!("JSON {args:?}: {e}\n{s}"))
}

fn jsonl(s: &str) -> Vec<Value> {
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("JSONL"))
        .collect()
}

fn records_of<'a>(records: &'a [Value], ty: &str) -> Vec<&'a Value> {
    records.iter().filter(|r| r["record_type"] == ty).collect()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("string expected: {v}"))
}

fn query_ids(file: &str, pred: &str) -> BTreeSet<String> {
    let doc = run_json(&[
        "query", file, "--where", pred, "--limit", "5000", "--format", "json",
    ]);
    let matches = doc["data"]["matches"].as_array().expect("matches");
    assert_eq!(
        doc["data"]["count"].as_u64().map(|n| n as usize),
        Some(matches.len())
    );
    for e in matches {
        let k = text(&e["kind"]);
        assert!(
            RESULT_KINDS.contains(&k),
            "undeclared kind {k:?} for {pred:?}"
        );
    }
    matches.iter().map(|e| text(&e["id"]).to_string()).collect()
}

fn query_seq(file: &str, pred: &str, limit: usize, cursor: Option<&str>) -> Value {
    let lim = limit.to_string();
    let mut args = vec![
        "query", file, "--where", pred, "--limit", &lim, "--format", "json",
    ];
    if let Some(c) = cursor {
        args.extend_from_slice(&["--cursor", c]);
    }
    run_json(&args)["data"].clone()
}

fn ids_in(page: &Value) -> Vec<String> {
    page["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|e| text(&e["id"]).to_string())
        .collect()
}

const PROBE_SOURCE: &str = r#"
local fmt = string.format
local handler = require "app.handler"
local counter = 0
local function target(a, b) return a + b end
local function forward(f, x) return f(x) end
local function dispatch(t, key, n)
  local label = fmt("%s-%d", "retrieval-probe", n)
  t.execute(key)
  t:invoke(label)
  handler.dispatch(label, n + 1, { n, "tail-probe" })
  counter = counter + 1
  return target(n, 2), label, counter, forward(target, n)
end
return dispatch, target, forward
"#;

const fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    (op as u32) | ((a as u32) << 6) | ((c as u32) << 14) | ((b as u32) << 23)
}
const fn iabx(op: u8, a: u8, bx: u32) -> u32 {
    (op as u32) | ((a as u32) << 6) | (bx << 14)
}

#[derive(Clone)]
enum K {
    Nil,
    Bool(bool),
    Num(f64),
    Str(&'static str),
}
struct P {
    nups: u8,
    is_vararg: u8,
    maxstack: u8,
    code: Vec<u32>,
    consts: Vec<K>,
    locals: Vec<&'static str>,
    children: Vec<P>,
}

fn write_str(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&((b.len() + 1) as u64).to_le_bytes());
    out.extend_from_slice(b);
    out.push(0);
}

fn write_p(out: &mut Vec<u8>, p: &P) {
    write_str(out, b"@synth_capture_probe.lua");
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&[p.nups, 0, p.is_vararg, p.maxstack]);
    out.extend_from_slice(&(p.code.len() as u32).to_le_bytes());
    for w in &p.code {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&(p.consts.len() as u32).to_le_bytes());
    for c in &p.consts {
        match c {
            K::Nil => out.push(0),
            K::Bool(v) => {
                out.push(1);
                out.push(u8::from(*v));
            }
            K::Num(v) => {
                out.push(3);
                out.extend_from_slice(&v.to_le_bytes());
            }
            K::Str(v) => {
                out.push(4);
                write_str(out, v.as_bytes());
            }
        }
    }
    out.extend_from_slice(&(p.children.len() as u32).to_le_bytes());
    for ch in &p.children {
        write_p(out, ch);
    }
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(p.locals.len() as u32).to_le_bytes());
    for name in &p.locals {
        write_str(out, name.as_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(p.code.len().saturating_sub(1) as u32).to_le_bytes());
    }
    out.extend_from_slice(&0u32.to_le_bytes());
}

fn synth_chunk(with_findings: bool) -> Vec<u8> {
    let grandchild = P {
        nups: 1,
        is_vararg: 0,
        maxstack: 2,
        code: vec![iabc(4, 0, 0, 0), iabc(30, 0, 1, 0)],
        consts: vec![],
        locals: vec![],
        children: vec![],
    };
    let child = P {
        nups: 2,
        is_vararg: 0,
        maxstack: 3,
        code: vec![
            iabc(4, 0, 0, 0),
            iabx(36, 1, 0),
            iabc(4, 0, 1, 0),
            iabc(30, 0, 1, 0),
        ],
        consts: vec![],
        locals: vec![],
        children: vec![grandchild],
    };
    let tail = if with_findings {
        iabc(0, 30, 0, 0)
    } else {
        iabx(1, 5, 2)
    };
    let root = P {
        nups: 0,
        is_vararg: 2,
        maxstack: 8,
        code: vec![
            iabc(10, 0, 0, 0),
            iabc(10, 1, 0, 0),
            iabc(10, 2, 0, 0),
            iabx(36, 3, 0),
            iabc(0, 0, 0, 0),
            iabc(0, 0, 1, 0),
            iabx(36, 4, 0),
            iabc(0, 0, 2, 0),
            iabc(0, 0, 2, 0),
            tail,
            iabc(30, 0, 1, 0),
        ],
        consts: vec![
            K::Num(0.0),
            K::Num(-0.0),
            K::Str("0"),
            K::Bool(true),
            K::Nil,
            K::Str("synth-probe"),
        ],
        locals: vec!["alpha", "beta", "gamma"],
        children: vec![child],
    };
    let mut out = b"\x1bLua\x51\0\x01\x04\x08\x04\x08\0".to_vec();
    write_p(&mut out, &root);
    out
}

struct Corpus {
    _dir: TempDir,
    probe: String,
    probe_copy: String,
    synth: String,
    findings: String,
    truncated: String,
    alien: String,
    oversized: String,
    plain_source: String,
    missing: String,
}

fn corpus() -> &'static Corpus {
    static CORPUS: OnceLock<Corpus> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let _ = luad_oracle::require_luac51();
        let bytes = luad_oracle::compile_source_lua51(PROBE_SOURCE, false).expect("probe compile");
        let dir = TempDir::new().expect("dir");
        let write = |name: &str, data: &[u8]| {
            let p = dir.path().join(name);
            std::fs::write(&p, data).expect("write");
            p.to_str().expect("utf8").to_string()
        };
        let oversized = dir.path().join("oversized.luac");
        let f = std::fs::File::create(&oversized).expect("create");
        f.set_len(64 * 1024 * 1024 + 1).expect("set_len");
        drop(f);

        Corpus {
            probe: write("probe.luac", &bytes),
            probe_copy: write("probe_copy.luac", &bytes),
            synth: write("synth.luac", &synth_chunk(false)),
            findings: write("findings.luac", &synth_chunk(true)),
            truncated: write("truncated.luac", &bytes[..16.min(bytes.len())]),
            alien: write("alien.bin", b"NOT-A-LUA-CHUNK-AT-ALL-0123456789"),
            plain_source: write("plain.lua", PROBE_SOURCE.as_bytes()),
            missing: dir
                .path()
                .join("absent.luac")
                .to_str()
                .expect("utf8")
                .to_string(),
            oversized: oversized.to_str().expect("utf8").to_string(),
            _dir: dir,
        }
    })
}

struct Facts {
    records: Vec<Value>,
}
impl Facts {
    fn of(path: &str) -> Self {
        Self {
            records: jsonl(&run_ok(&["export", path, "--format", "jsonl"])),
        }
    }
    fn data(&self, ty: &str) -> Vec<&Value> {
        self.records
            .iter()
            .filter(|r| r["record_type"] == ty)
            .map(|r| &r["data"])
            .collect()
    }
}

fn path_text(res: &Value) -> Option<String> {
    (res["status"] == "resolved-path")
        .then(|| {
            res["segments"]
                .as_array()
                .map(|segments| segments.iter().map(text).collect::<Vec<_>>().join("."))
        })
        .flatten()
}

fn key_text(res: &Value) -> Option<String> {
    (res["status"] == "lookup-label")
        .then(|| res["key"]["value"]["display"].as_str().map(String::from))
        .flatten()
}

fn ids(facts: &Facts, ty: &str, pred: impl Fn(&Value) -> bool) -> BTreeSet<String> {
    let k = if ty == "prototype_identity" {
        "proto_id"
    } else if ty == "constant" || ty == "instruction" || ty == "prototype" {
        "id"
    } else {
        "call_id"
    };
    facts
        .data(ty)
        .into_iter()
        .filter(|f| pred(f))
        .map(|f| text(&f[k]).to_string())
        .collect()
}

struct Row {
    name: &'static str,
    pred: String,
    expected: BTreeSet<String>,
    min: usize,
}

#[rustfmt::skip]
fn matrix(facts: &Facts) -> Vec<Row> {
    let empty = BTreeSet::new();
    let digest = text(&facts.data("prototype_identity")[0]["digest"]).to_string();
    let target = facts.data("call_relation").into_iter().find_map(|f| (f["resolution"]["status"] == "resolved").then(|| format!("proto:{}", text(&f["resolution"]["callee"])))).expect("target");

    let mut literal_calls = BTreeSet::new();
    let mut idx2_calls = BTreeSet::new();
    for f in facts.data("origin") {
        if f["argument_window"]["kind"] == "fixed" {
            for a in f["argument_window"]["arguments"].as_array().expect("args") {
                let call = text(&f["call_id"]).to_string();
                if a["origin"]["kind"] == "literal" { literal_calls.insert(call.clone()); }
                if a["argument_index"] == 2 { idx2_calls.insert(call); }
            }
        }
    }

    let r = |name: &'static str, pred: &str, exp: BTreeSet<String>, min: usize| Row { name, pred: pred.into(), expected: exp, min };

    let mut rows = vec![
        r("constant-substring", "constant contains \"probe\"", ids(facts, "constant", |c| c["value"]["value"]["display"].as_str().is_some_and(|d| d.contains("probe"))), 2),
        r("constant-exact-string", "constant == \"retrieval-probe\"", ids(facts, "constant", |c| c["value"]["value"]["display"] == "retrieval-probe"), 1),
        r("constant-type-short-string", "constant.type == \"short-string\"", ids(facts, "constant", |c| c["value"]["type"] == "short-string"), 5),
        r("callee-status-lookup-label", "callee.status == \"lookup-label\"", ids(facts, "callee", |f| f["resolution"]["status"] == "lookup-label"), 2),
        r("callee-status-resolved-prototype", "callee.status == \"resolved-prototype\"", ids(facts, "callee", |f| f["resolution"]["status"] == "resolved-prototype"), 1),
        r("callee-lookup-kind-self", "callee.lookup.kind == \"self\"", ids(facts, "callee", |f| f["resolution"]["lookup_kind"] == "self"), 1),
        r("callee-lookup-key-exact", "callee.lookup.key == \"execute\"", ids(facts, "callee", |f| key_text(&f["resolution"]).as_deref() == Some("execute")), 1),
        r("callee-path-exact", "callee.path == \"string.format\"", ids(facts, "callee", |f| path_text(&f["resolution"]).as_deref() == Some("string.format")), 1),
        r("callee-path-substring", "callee.path contains \"handler\"", ids(facts, "callee", |f| path_text(&f["resolution"]).is_some_and(|p| p.contains("handler"))), 1),
        r("callee-reason-missing-definition", "callee.reason == \"missing-definition\"", ids(facts, "callee", |f| f["resolution"]["reason"] == "missing-definition"), 1),
        r("call-reason-lookup-label-only", "call.reason == \"lookup-label-only\"", ids(facts, "call_relation", |f| f["resolution"]["reason"] == "lookup-label-only"), 2),
        r("call-target-exact", &format!("call.target == \"{target}\""), ids(facts, "call_relation", |f| f["resolution"]["status"] == "resolved" && format!("proto:{}", text(&f["resolution"]["callee"])) == target), 1),
        r("origin-kind-literal", "origin.kind == \"literal\"", literal_calls, 2),
        r("origin-argument-index-two", "origin.argument.index == 2", idx2_calls, 1),
        r("interpretation-profile-match", "interpretation.profile == \"lua5.1\"", ["chunk".into()].into_iter().collect(), 1),
        r("prototype-digest-exact", &format!("prototype.digest == \"{digest}\""), ids(facts, "prototype_identity", |f| text(&f["digest"]) == digest), 1),
        r("existing-mnemonic-predicate-unchanged", "mnemonic == \"CALL\"", ids(facts, "instruction", |i| i["mnemonic"] == "CALL"), 5),
        r("zero-constant-substring", "constant contains \"absent-token-zzz\"", empty.clone(), 0),
        r("zero-callee-path", "callee.path == \"no.such.module.path\"", empty.clone(), 0),
        r("zero-lookup-key", "callee.lookup.key == \"no-such-key\"", empty.clone(), 0),
        r("zero-call-target-uncalled-prototype", "call.target == \"proto:0\"", empty.clone(), 0),
        r("zero-prototype-digest", &format!("prototype.digest == \"sha256:{}\"", "0".repeat(64)), empty.clone(), 0),
        r("zero-interpretation-profile", "interpretation.profile == \"lua5.4\"", empty, 0),
    ];

    let labels = rows.iter().find(|r| r.name == "callee-status-lookup-label").unwrap().expected.clone();
    let self_kind = rows.iter().find(|r| r.name == "callee-lookup-kind-self").unwrap().expected.clone();
    let protos = rows.iter().find(|r| r.name == "callee-status-resolved-prototype").unwrap().expected.clone();
    rows.push(r("conjunction-label-and-gettable", "callee.status == \"lookup-label\" and callee.lookup.kind != \"self\"", labels.difference(&self_kind).cloned().collect(), 1));
    rows.push(r("disjunction-self-or-prototype", "callee.lookup.kind == \"self\" or callee.status == \"resolved-prototype\"", self_kind.union(&protos).cloned().collect(), 2));
    rows
}

#[test]
fn test_retrieval_predicates_select_exact_records_with_deterministic_order() {
    let probe = corpus().probe.as_str();
    let facts = Facts::of(probe);
    let rows = matrix(&facts);

    for (name, _, _) in RETRIEVAL_VOCABULARY {
        assert!(rows.iter().any(|r| r.pred.contains(name)), "missing {name}");
    }
    for r in &rows {
        assert!(r.expected.len() >= r.min, "vacuous row {}", r.name);
        assert_eq!(query_ids(probe, &r.pred), r.expected, "row {}", r.name);
        let a = run_ok(&[
            "query", probe, "--where", &r.pred, "--limit", "5000", "--format", "json",
        ]);
        let b = run_ok(&[
            "query", probe, "--where", &r.pred, "--limit", "5000", "--format", "json",
        ]);
        assert_eq!(a, b, "determinism row {}", r.name);
    }
}

#[test]
fn test_retrieval_predicates_fail_closed_on_operands_they_cannot_apply() {
    let probe = corpus().probe.as_str();
    let refuse = |name: &str, pred: &str, marker: &str| {
        let out = run(&["query", probe, "--where", pred, "--format", "json"]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{name} ({pred:?}) exit code: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty(), "{name} non-empty stdout");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(marker), "{name} missing {marker:?}: {err}");
    };

    for (name, vocab, ops) in RETRIEVAL_VOCABULARY {
        for op in ["==", "!=", "contains"] {
            if !ops.contains(&op) {
                refuse(
                    &format!("unsupported-op-{name}-{op}"),
                    &format!("{name} {op} \"probe\""),
                    name,
                );
            }
        }
        let opnd = match vocab {
            Vocabulary::Open => continue,
            Vocabulary::Closed => "not-a-declared-member",
            Vocabulary::Integer => "not-an-integer",
        };
        refuse(
            &format!("unusable-opnd-{name}"),
            &format!("{name} == \"{opnd}\""),
            name,
        );
    }

    #[rustfmt::skip]
    let rows = [
        ("unknown-field", "callee.unknown == \"x\"", "Unknown query field"),
        ("unknown-subfield", "origin.argument == 1", "Unknown query field"),
        ("unknown-namespace", "capture.kind == \"local\"", "Unknown query field"),
        ("contains-on-opcode", "opcode contains \"CALL\"", "Unsupported operator"),
        ("register-not-an-integer", "effect.write.register == \"not-a-register\"", "effect.write.register"),
        ("upvalue-negative", "effect.read.upvalue == -1", "effect.read.upvalue"),
        ("absent-call-target", "call.target == \"proto:0/99\"", "call.target"),
        ("malformed-call-target", "call.target == \"not-an-id\"", "call.target"),
        ("missing-value", "callee.status ==", "Missing query value"),
        ("unbalanced", "(callee.status == \"unresolved\"", "Unbalanced parentheses"),
        ("trailing-tokens", "callee.status == \"unresolved\" leftover", "Unexpected trailing tokens"),
        ("bare-operator", "and", "Malformed query expression"),
        ("constant-contains-bare", "constant contains 0", "constant"),
        ("constant-bare-not-a-literal", "constant == not-a-typed-literal", "constant"),
    ];
    for (name, pred, marker) in rows {
        refuse(name, pred, marker);
    }

    let lua54 =
        luad_oracle::find_workspace_root().join("tests/fixtures/precompiled/lua54/hello.luac");
    let out = run(&[
        "query",
        lua54.to_str().unwrap(),
        "--where",
        "callee.status == \"unresolved\"",
        "--format",
        "json",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("callee.status"));
}

#[test]
fn test_retrieval_pagination_binds_cursors_and_bounds_resources() {
    let probe = corpus().probe.as_str();
    let pred = "constant.type == \"short-string\"";
    let complete = ids_in(&query_seq(probe, pred, 5000, None));
    assert!(complete.len() >= 4);

    let mut walked = Vec::new();
    let mut cursor = None;
    for _ in 0..complete.len() + 2 {
        let page = query_seq(probe, pred, 1, cursor.as_deref());
        walked.extend(ids_in(&page));
        cursor = page["next_cursor"].as_str().map(String::from);
        if cursor.is_none() {
            assert_eq!(page["is_truncated"], false);
            break;
        }
        assert_eq!(page["is_truncated"], true);
    }
    assert_eq!(walked, complete);

    let cur = text(&query_seq(probe, pred, 1, None)["next_cursor"]).to_string();
    let parts: Vec<&str> = cur.split('_').collect();
    assert_eq!(parts.len(), 3);

    for (p, c) in [
        (pred, format!("{}_{}_{}", parts[0], parts[1], 99)),
        (pred, format!("{}_{}_{}", parts[0], "00000000", parts[2])),
        ("callee.status == \"lookup-label\"", cur.clone()),
        (pred, (complete.len() + 1).to_string()),
    ] {
        let out = run(&[
            "query", probe, "--where", p, "--limit", "1", "--cursor", &c, "--format", "json",
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }

    let foreign = run(&[
        "query",
        &corpus().synth,
        "--where",
        pred,
        "--limit",
        "1",
        "--cursor",
        &cur,
        "--format",
        "json",
    ]);
    assert_eq!(foreign.status.code(), Some(2));
    assert!(foreign.stdout.is_empty());

    let total = complete.len().to_string();
    for (file, where_clause, bare) in [
        (probe, pred, "0"),
        (probe, "callee.status == \"lookup-label\"", "1"),
        (corpus().synth.as_str(), pred, total.as_str()),
    ] {
        let out = run(&[
            "query",
            file,
            "--where",
            where_clause,
            "--limit",
            "5",
            "--cursor",
            bare,
            "--format",
            "json",
        ]);
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }

    let over = run(&["query", &corpus().oversized, "--format", "json"]);
    assert_eq!(over.status.code(), Some(5));
    assert!(over.stdout.is_empty());

    let bounded = jsonl(&run_ok(&[
        "export",
        probe,
        "--format",
        "jsonl",
        "--max-facts-per-file",
        "1",
    ]));
    let fe = bounded
        .iter()
        .find(|r| r["record_type"] == "file_end")
        .unwrap();
    assert_eq!(fe["is_truncated"], true);
    assert_eq!(fe["emitted_fact_count"], 1);
    assert!(fe["available_fact_count"].as_u64().unwrap() > 1);
}

#[test]
fn test_capture_xrefs_stay_site_accurate_across_repeated_closure_sites() {
    let synth = corpus().synth.as_str();
    let val = run_json(&["validate", synth, "--format", "json"]);
    assert_ne!(
        val["data"]["verdict"], "invalid",
        "diagnostics: {}",
        val["data"]["diagnostics"]
    );

    let xrefs = |mode: &str, target: &str| -> BTreeSet<String> {
        run_json(&["xrefs", synth, mode, target, "--format", "json"])["data"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["relation"] == "binds")
            .map(|e| text(&e[if mode == "--to" { "source" } else { "target" }]).to_string())
            .collect()
    };
    let src = |t: &str| xrefs("--to", t);
    let tgt = |s: &str| xrefs("--from", s);

    let slot0 = src("proto:0/0:upvalue:0");
    let slot1 = src("proto:0/0:upvalue:1");
    for req in [
        "proto:0:local:0",
        "proto:0:local:2",
        "proto:0:pc:3",
        "proto:0:pc:4",
        "proto:0:pc:6",
        "proto:0:pc:7",
    ] {
        assert!(slot0.contains(req), "slot0 missing {req}: {slot0:?}");
    }
    for req in [
        "proto:0:local:1",
        "proto:0:local:2",
        "proto:0:pc:3",
        "proto:0:pc:5",
        "proto:0:pc:6",
        "proto:0:pc:8",
    ] {
        assert!(slot1.contains(req), "slot1 missing {req}: {slot1:?}");
    }
    assert!(!slot0.contains("proto:0:local:1") && !slot1.contains("proto:0:local:0"));

    assert_eq!(
        tgt("proto:0:local:0"),
        ["proto:0/0:upvalue:0".into()].into_iter().collect()
    );
    assert_eq!(
        tgt("proto:0:local:1"),
        ["proto:0/0:upvalue:1".into()].into_iter().collect()
    );
    assert_eq!(
        tgt("proto:0:local:2"),
        ["proto:0/0:upvalue:0".into(), "proto:0/0:upvalue:1".into()]
            .into_iter()
            .collect()
    );

    for (d, s) in [
        ("proto:0:pc:4", "proto:0/0:upvalue:0"),
        ("proto:0:pc:5", "proto:0/0:upvalue:1"),
        ("proto:0:pc:7", "proto:0/0:upvalue:0"),
        ("proto:0:pc:8", "proto:0/0:upvalue:1"),
    ] {
        assert_eq!(tgt(d), [s.into()].into_iter().collect());
    }
    for site in ["proto:0:pc:3", "proto:0:pc:6"] {
        assert_eq!(
            tgt(site),
            ["proto:0/0:upvalue:0".into(), "proto:0/0:upvalue:1".into()]
                .into_iter()
                .collect()
        );
    }
    for (descriptor, parent, child) in [
        ("proto:0:pc:4", "proto:0:local:0", "proto:0/0:upvalue:0"),
        ("proto:0:pc:5", "proto:0:local:1", "proto:0/0:upvalue:1"),
        ("proto:0:pc:7", "proto:0:local:2", "proto:0/0:upvalue:0"),
        ("proto:0:pc:8", "proto:0:local:2", "proto:0/0:upvalue:1"),
    ] {
        let entries = run_json(&["xrefs", synth, "--from", descriptor, "--format", "json"])["data"]
            ["entries"]
            .as_array()
            .unwrap()
            .clone();
        assert!(entries
            .iter()
            .any(|edge| { edge["relation"] == "reads" && edge["target"] == parent }));
        assert!(entries
            .iter()
            .any(|edge| { edge["relation"] == "binds" && edge["target"] == child }));
    }
    let g = src("proto:0/0/0:upvalue:0");
    for req in ["proto:0/0:upvalue:1", "proto:0/0:pc:1", "proto:0/0:pc:2"] {
        assert!(g.contains(req), "grandchild missing {req}: {g:?}");
    }
}

#[test]
fn test_cli_outcome_table_pins_exit_codes_and_output_channels() {
    let c = corpus();
    let probe = c.probe.as_str();

    #[rustfmt::skip]
    let table: [(&str, &[&str], i32, bool); 10] = [
        ("successful-query", &["query", probe, "--where", "mnemonic == \"CALL\""], 0, true),
        ("no-match-query", &["query", probe, "--where", "constant contains \"absent-zzz\""], 0, true),
        ("invalid-predicate", &["query", probe, "--where", "callee.status == \"resolved\""], 2, false),
        ("malformed-input", &["query", c.truncated.as_str()], 1, false),
        ("unrecognized-format", &["query", c.alien.as_str()], 4, false),
        ("resource-exhaustion", &["query", c.oversized.as_str()], 5, false),
        ("io-failure", &["query", c.missing.as_str()], 3, false),
        ("clean-validation", &["validate", probe], 0, true),
        ("validation-findings", &["validate", c.findings.as_str()], 1, true),
        ("unknown-command", &["frobnicate", probe], 2, false),
    ];

    for (name, argv, exit, is_json) in table {
        let mut args = argv.to_vec();
        if args[0] != "frobnicate" {
            args.extend_from_slice(&["--format", "json"]);
        }
        let out = run(&args);
        assert_eq!(
            out.status.code(),
            Some(exit),
            "{name} exit: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let s = String::from_utf8_lossy(&out.stdout);
        if is_json {
            let parsed: Value =
                serde_json::from_str(&s).unwrap_or_else(|e| panic!("{name} JSON: {e}"));
            assert!(parsed.is_object() && !s.contains('\u{1b}'));
        } else {
            assert!(s.is_empty(), "{name} stdout non-empty: {s}");
            assert!(!out.stderr.is_empty(), "{name} empty stderr");
        }
    }

    let mixed = run(&[
        "export",
        probe,
        c.plain_source.as_str(),
        c.missing.as_str(),
        "--format",
        "jsonl",
    ]);
    assert_eq!(mixed.status.code(), Some(0));
    let recs = jsonl(&String::from_utf8_lossy(&mixed.stdout));
    let end = recs
        .iter()
        .find(|r| r["record_type"] == "export_end")
        .expect("export_end");
    assert_eq!(end["files_processed"], 3);
    assert_eq!(end["files_succeeded"], 1);
    assert_eq!(end["files_skipped"], 1);
    assert_eq!(end["files_failed"], 1);
    let err = String::from_utf8_lossy(&mixed.stderr);
    assert!(
        err.trim_end().ends_with("1 exported, 1 skipped, 1 failed"),
        "summary: {err}"
    );

    let strict = run(&[
        "export",
        probe,
        c.plain_source.as_str(),
        c.missing.as_str(),
        "--format",
        "jsonl",
        "--strict",
    ]);
    assert_ne!(strict.status.code(), Some(0));
    assert!(jsonl(&String::from_utf8_lossy(&strict.stdout))
        .iter()
        .any(|r| r["record_type"] == "export_end"));
}

#[test]
fn test_schema_major_one_closed_variants_and_open_vocabularies() {
    let probe = corpus().probe.as_str();
    assert_eq!(
        run_json(&["query", probe, "--format", "json"])["schema_version"],
        1
    );
    assert_eq!(
        run_json(&["capabilities", "--format", "json"])["schema_version"],
        2
    );
    let capabilities = run_json(&["capabilities", "--format", "json"]);
    let lua51 = capabilities["dialects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|dialect| dialect["id"] == "lua5.1")
        .unwrap();
    assert!(lua51["features"]
        .as_array()
        .unwrap()
        .iter()
        .any(|feature| feature == "typed structured retrieval (experimental)"));
    let start = jsonl(&run_ok(&["export", probe, "--format", "jsonl"]))
        .into_iter()
        .find(|r| r["record_type"] == "export_start")
        .unwrap();
    assert_eq!(start["schema_version"], 2);

    for (name, req, exit) in [
        ("query-major-1", "1", 0),
        ("query-major-2", "2", 2),
        ("export-major-2", "2", 0),
        ("export-major-1", "1", 2),
    ] {
        let sch = if name.starts_with("query") {
            "query"
        } else {
            "export"
        };
        assert_eq!(
            run(&["schema", sch, "--schema-version", req]).status.code(),
            Some(exit),
            "{name}"
        );
    }

    let facts = Facts::of(probe);
    let callee = facts
        .data("callee")
        .into_iter()
        .find(|f| f["resolution"]["status"] == "unresolved")
        .unwrap()
        .clone();
    let parsed: luad_analysis::CalleeFact = serde_json::from_value(callee.clone()).unwrap();
    assert_eq!(text(&callee["call_id"]), parsed.call_id.to_string());

    let patch = |f: &str, v: &str| {
        let mut r = callee.clone();
        r["resolution"][f] = Value::from(v);
        r
    };
    assert!(
        serde_json::from_value::<luad_analysis::CalleeFact>(patch("status", "future-status"))
            .is_err()
    );
    assert!(
        serde_json::from_value::<luad_analysis::CalleeFact>(patch("reason", "future-reason"))
            .is_err()
    );

    let mut xref = facts.data("xref")[0].clone();
    assert!(serde_json::from_value::<luad_analysis::XrefEntry>(xref.clone()).is_ok());
    xref["relation"] = Value::from("future-relation");
    assert!(serde_json::from_value::<luad_analysis::XrefEntry>(xref).is_err());

    let mut unknown_kind = callee.clone();
    unknown_kind["call_kind"] = Value::from("FUTURECALL");
    let ret: luad_analysis::CalleeFact = serde_json::from_value(unknown_kind).unwrap();
    assert_eq!(ret.call_kind, "FUTURECALL");

    let mut ident = facts.data("prototype_identity")[0].clone();
    ident["scheme"] = Value::from("luad-prototype-v99");
    let ret: luad_analysis::PrototypeIdentityFact = serde_json::from_value(ident).unwrap();
    assert_eq!(ret.scheme, "luad-prototype-v99");

    let sch = run_json(&["schema", "callees"]);
    let reasons = &sch["definitions"]["CalleeUnresolvedReason"];
    let enum_len = reasons["enum"]
        .as_array()
        .or_else(|| reasons["oneOf"].as_array())
        .map(|l| l.len())
        .unwrap_or(0);
    assert!(enum_len >= 10);
    assert!(
        sch["definitions"]["CalleeResolution"]["oneOf"]
            .as_array()
            .unwrap()
            .len()
            >= 4
    );
}

#[test]
fn test_composition_recipes_execute_the_seven_documented_workflows() {
    let c = corpus();
    let stream = run_ok(&[
        "export",
        &c.probe,
        &c.probe_copy,
        &c.synth,
        "--format",
        "jsonl",
        "--max-facts-per-file",
        "20000",
    ]);
    let records = jsonl(&stream);
    let path = |r: &Value| text(&r["context"]["input_identity"]["path"]).to_string();

    // Recipe 1: exact and substring constant search
    let substr: BTreeSet<(String, String)> = records_of(&records, "constant")
        .into_iter()
        .filter(|r| {
            r["data"]["value"]["value"]["display"]
                .as_str()
                .is_some_and(|d| d.contains("probe"))
        })
        .map(|r| (path(r), text(&r["data"]["id"]).into()))
        .collect();
    let exact: BTreeSet<(String, String)> = records_of(&records, "constant")
        .into_iter()
        .filter(|r| r["data"]["value"]["value"]["display"] == "retrieval-probe")
        .map(|r| (path(r), text(&r["data"]["id"]).into()))
        .collect();
    assert!(exact.iter().all(|h| substr.contains(h)) && exact.len() < substr.len());
    assert_eq!(
        substr
            .iter()
            .map(|(f, _)| f.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        3
    );

    // Recipe 2: symbolic path and constant key
    let by_path: Vec<&Value> = records_of(&records, "callee")
        .into_iter()
        .filter(|r| {
            path_text(&r["data"]["resolution"]).is_some_and(|p| p.starts_with("app.handler"))
        })
        .collect();
    let by_key: Vec<&Value> = records_of(&records, "callee")
        .into_iter()
        .filter(|r| key_text(&r["data"]["resolution"]).as_deref() == Some("invoke"))
        .collect();
    assert!(!by_path.is_empty() && !by_key.is_empty());

    // Recipe 3: calls grouped by unresolved reason
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for r in records_of(&records, "call_relation") {
        *by_reason
            .entry(
                r["data"]["resolution"]["reason"]
                    .as_str()
                    .unwrap_or("resolved")
                    .into(),
            )
            .or_default() += 1;
    }
    assert_eq!(
        by_reason.values().sum::<usize>(),
        records_of(&records, "call_relation").len()
    );
    assert!(by_reason.len() >= 2);

    // Recipe 4: call arguments grouped by origin shape
    let mut by_shape: BTreeMap<String, usize> = BTreeMap::new();
    let mut total_fixed = 0;
    for r in records_of(&records, "origin") {
        if r["data"]["argument_window"]["kind"] == "fixed" {
            for a in r["data"]["argument_window"]["arguments"]
                .as_array()
                .unwrap()
            {
                total_fixed += 1;
                *by_shape
                    .entry(text(&a["origin"]["kind"]).into())
                    .or_default() += 1;
            }
        }
    }
    assert_eq!(by_shape.values().sum::<usize>(), total_fixed);
    assert!(by_shape.len() >= 3);

    // Recipe 5: multi-hop capture forward and inverse
    let binds: BTreeSet<(String, String, String)> = records_of(&records, "xref")
        .into_iter()
        .filter(|r| r["data"]["relation"] == "binds")
        .map(|r| {
            (
                path(r),
                text(&r["data"]["source"]).into(),
                text(&r["data"]["target"]).into(),
            )
        })
        .collect();
    let synth_binds: BTreeSet<(String, String)> = binds
        .iter()
        .filter(|(f, _, _)| f == &c.synth)
        .map(|(_, s, t)| (s.clone(), t.clone()))
        .collect();
    let fwd = |from: &str| {
        synth_binds
            .iter()
            .filter(|(s, _)| s == from)
            .map(|(_, t)| t.clone())
            .collect::<BTreeSet<_>>()
    };
    let inv = |to: &str| {
        synth_binds
            .iter()
            .filter(|(_, t)| t == to)
            .map(|(s, _)| s.clone())
            .collect::<BTreeSet<_>>()
    };
    assert!(fwd("proto:0:local:1").contains("proto:0/0:upvalue:1"));
    assert!(fwd("proto:0/0:upvalue:1").contains("proto:0/0/0:upvalue:0"));
    let back = inv("proto:0/0/0:upvalue:0");
    assert!(back.contains("proto:0/0:upvalue:1") && back.contains("proto:0/0:pc:1"));

    // Recipe 6: call site to child prototype navigation
    let resolved: Vec<(String, String, String)> = records_of(&records, "call_relation")
        .into_iter()
        .filter(|r| r["data"]["resolution"]["status"] == "resolved")
        .map(|r| {
            (
                path(r),
                text(&r["data"]["call_id"]).into(),
                format!("proto:{}", text(&r["data"]["resolution"]["callee"])),
            )
        })
        .collect();
    assert!(!resolved.is_empty());
    let calls_edges: BTreeSet<(String, String, String)> = records_of(&records, "xref")
        .into_iter()
        .filter(|r| r["data"]["relation"] == "calls")
        .map(|r| {
            (
                path(r),
                text(&r["data"]["source"]).into(),
                text(&r["data"]["target"]).into(),
            )
        })
        .collect();
    let protos: BTreeSet<(String, String)> = records_of(&records, "prototype")
        .into_iter()
        .map(|r| (path(r), text(&r["data"]["id"]).into()))
        .collect();
    for (f, call, tgt) in &resolved {
        assert!(calls_edges.contains(&(f.clone(), call.clone(), tgt.clone())));
        assert!(protos.contains(&(f.clone(), tgt.clone())));
    }

    // Recipe 7: prototype content identity joins
    let mut inventory: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for r in records_of(&records, "prototype_identity") {
        inventory
            .entry(text(&r["data"]["digest"]).into())
            .or_default()
            .insert(path(r));
    }
    let joined: Vec<&String> = inventory
        .iter()
        .filter(|(_, files)| files.contains(&c.probe) && files.contains(&c.probe_copy))
        .map(|(d, _)| d)
        .collect();
    assert!(!joined.is_empty());
    assert!(inventory
        .values()
        .all(|files| !(files.contains(&c.probe) && files.contains(&c.synth))));
    let profiles: BTreeSet<(String, String)> = records_of(&records, "file_start")
        .into_iter()
        .map(|r| {
            (
                text(&r["path"]).into(),
                text(&r["interpretation"]["profile"]).into(),
            )
        })
        .collect();
    assert!(profiles.iter().all(|(_, p)| p.starts_with("lua5.1")));
    assert_eq!(profiles.len(), 3);
}

#[test]
fn test_compile_surface_is_removed_and_rejected_as_an_unknown_command() {
    let help = run_ok(&["--help"]);
    assert!(
        !help.lines().any(|l| l.trim_start().starts_with("compile ")),
        "help: {help}"
    );
    assert!(!run_ok(&["capabilities", "--format", "json"]).contains("\"compile\""));
    for name in ["compile", "compiler"] {
        assert_ne!(run(&["schema", name]).status.code(), Some(0));
    }

    let out = run(&["compile", &corpus().plain_source, "--compiler", "/bin/true"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        !err.contains("not supported in bytecode analysis mode"),
        "stub: {err}"
    );
}

#[test]
fn test_live_killer_controls_reject_plausible_wrong_retrieval_engines() {
    let c = corpus();
    let probe = c.probe.as_str();
    let synth = c.synth.as_str();

    // Killer 1: contains ignores operand
    let all_str = query_ids(probe, "constant.type == \"short-string\"");
    let hit = query_ids(probe, "constant contains \"probe\"");
    let miss = query_ids(probe, "constant contains \"absent-token-zzz\"");
    assert!(
        !hit.is_empty() && hit.len() < all_str.len() && miss.is_empty() && hit.is_subset(&all_str)
    );

    // Killer 2: stringifying constants vs exact typed matching
    let float_ids = query_ids(synth, "constant.type == \"float\"");
    assert_eq!(float_ids.len(), 2, "synth has +0.0 and -0.0");
    let str_zero = query_ids(synth, "constant == \"0\"");
    assert_eq!(str_zero.len(), 1, "constant == \"0\" returns only string");
    assert!(str_zero.is_disjoint(&float_ids));

    let pos_zero = query_ids(synth, "constant == 0");
    assert_eq!(pos_zero.len(), 1, "constant == 0 returns only +0.0");
    assert!(pos_zero.is_subset(&float_ids) && pos_zero.is_disjoint(&str_zero));

    let neg_zero = query_ids(synth, "constant == -0");
    assert_eq!(neg_zero.len(), 1, "constant == -0 returns only -0.0");
    assert!(neg_zero.is_subset(&float_ids) && neg_zero.is_disjoint(&pos_zero));

    let contains_zero = query_ids(synth, "constant contains \"0\"");
    assert!(contains_zero.is_disjoint(&float_ids) && contains_zero == str_zero);
    assert_eq!(
        query_ids(synth, "constant.type == \"float\" and constant == 0"),
        pos_zero
    );

    // Killer 3: cursor honoured for different request
    let cur = text(&query_seq(probe, "constant.type == \"short-string\"", 1, None)["next_cursor"])
        .to_string();
    let reused = run(&[
        "query",
        probe,
        "--where",
        "constant.type == \"float\"",
        "--limit",
        "1",
        "--cursor",
        &cur,
        "--format",
        "json",
    ]);
    assert_eq!(reused.status.code(), Some(2));
    assert!(reused.stdout.is_empty());

    // Killer 4: capture-site collapse
    let s0: BTreeSet<String> = run_json(&[
        "xrefs",
        synth,
        "--to",
        "proto:0/0:upvalue:0",
        "--format",
        "json",
    ])["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["relation"] == "binds")
        .filter_map(|e| {
            let s = text(&e["source"]);
            s.contains(":local:").then(|| s.to_string())
        })
        .collect();
    assert_eq!(
        s0,
        ["proto:0:local:0".into(), "proto:0:local:2".into()]
            .into_iter()
            .collect()
    );

    // Killer 5: invalid predicates fail closed exit 2
    for pred in [
        "callee.status == \"resolved\"",
        "origin.kind == \"not-a-kind\"",
        "origin.argument.index == \"first\"",
        "constant.type == \"string\"",
        "constant contains 0",
        "constant == not-a-typed-literal",
    ] {
        let out = run(&["query", probe, "--where", pred, "--format", "json"]);
        assert_eq!(out.status.code(), Some(2), "{pred:?} must exit 2");
        assert!(out.stdout.is_empty(), "{pred:?} stdout empty");
    }
}
