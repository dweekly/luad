//! Independent acceptance for the Lua 5.1 retrieval and machine-contract freeze.
//!
//! This family freezes the whole claim of `docs/NEXT-SPRINT.md` as one table-driven public
//! matrix over the live `luad` binary: every release-critical Lua 5.1 fact is directly
//! retrievable through a fail-closed query vocabulary, capture xrefs stay site-accurate when
//! one child prototype is instantiated at several physical `CLOSURE` sites, the process
//! outcome table is exact, schema-major 1 records distinguish closed variants from open
//! vocabularies, the seven documented composition recipes execute, and the nonfunctional
//! `compile` surface is gone.
//!
//! ## What is and is not reimplemented here
//!
//! There is deliberately no second semantic model. Expectations come from two sources only:
//!
//! 1. hand-written literals over fixtures whose bytes this file controls (the synthesized
//!    chunk) or whose source text this file controls (the compiled probe);
//! 2. the *other* public surfaces of the same tool — the recursive `export` stream and the
//!    `callees` / `callgraph` / `origins` / `xrefs` commands.
//!
//! Source (2) is the point of the sprint: the retrieval vocabulary must be a view over the
//! same facts rather than a second decoder. A `query` answer that disagrees with the export
//! records for the same artifact is a defect regardless of which one is "right", so using
//! export as the reference index is a genuine cross-surface oracle, not a mock.
//!
//! ## Assumptions recorded before implementation
//!
//! The sprint names the retrieval *families* but not their concrete spellings. Everything
//! this file assumes about spelling is confined to `RETRIEVAL_VOCABULARY` below, so an
//! implementation that chooses other names can be reconciled by editing one table. The
//! behavioural requirements around those names — complete typed operands, closed vocabularies
//! failing closed, open vocabularies answering exactly zero, deterministic ordering,
//! cursor binding, and record identity — are the actual contract and are not negotiable.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::Value;
use tempfile::TempDir;

// ===========================================================================
// 1. The retrieval vocabulary under test.
// ===========================================================================

/// How an operand of one field is validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vocabulary {
    /// A closed set of members within schema-major 1. An unknown member is a usage error,
    /// never an empty or overbroad answer.
    Closed,
    /// An unbounded artifact-derived value. A well-formed absent value answers exactly zero.
    Open,
    /// A bounded integer. A non-integer operand is a usage error.
    Integer,
}

/// Field name, operand vocabulary, and the complete set of operators the field accepts.
/// Every other operator is a usage error.
///
/// ASSUMPTION (spelling only): these names extend the existing `--where` grammar, which
/// already carries `opcode`, `mnemonic`, `constant`, `string`, and `effect.*`. The sprint
/// requires the families, not these identifiers. Each comment below names the sprint family.
type Field = (&'static str, Vocabulary, &'static [&'static str]);

const EQ: &[&str] = &["==", "!="];
const EQ_CONTAINS: &[&str] = &["==", "!=", "contains"];

#[rustfmt::skip]
const RETRIEVAL_VOCABULARY: &[Field] = &[
    // typed constants and exact string containment
    ("constant",              Vocabulary::Open,    EQ_CONTAINS),
    ("constant.type",         Vocabulary::Closed,  EQ),
    // callee resolution kind, symbolic path, lookup kind, typed lookup key
    ("callee.status",         Vocabulary::Closed,  EQ),
    ("callee.path",           Vocabulary::Open,    EQ_CONTAINS),
    ("callee.lookup.kind",    Vocabulary::Closed,  EQ),
    ("callee.lookup.key",     Vocabulary::Open,    EQ_CONTAINS),
    // callee and call-relation unresolved reasons
    ("callee.reason",         Vocabulary::Closed,  EQ),
    ("call.reason",           Vocabulary::Closed,  EQ),
    // exact child-prototype call target
    ("call.target",           Vocabulary::Open,    EQ),
    // argument index and origin-expression kind
    ("origin.kind",           Vocabulary::Closed,  EQ),
    ("origin.argument.index", Vocabulary::Integer, EQ),
    // artifact interpretation identity and prototype content identity
    ("interpretation.profile", Vocabulary::Closed, EQ),
    ("prototype.digest",      Vocabulary::Open,    EQ),
];

/// Result-record categories a retrieval answer may use.
///
/// ASSUMPTION: call-scoped predicates (`callee.*`, `call.*`, `origin.*`) select the physical
/// call instruction, keeping `QueryMatch.id` inside the published `StableId` vocabulary rather
/// than inventing per-argument identities. `interpretation.*` selects the artifact (`chunk`).
const RESULT_KINDS: &[&str] = &[
    "instruction",
    "constant",
    "prototype",
    "upvalue",
    "call",
    "interpretation",
];

// ===========================================================================
// 2. Live CLI harness.
// ===========================================================================

fn luad_bin() -> PathBuf {
    static LUAD: OnceLock<PathBuf> = OnceLock::new();
    LUAD.get_or_init(|| {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
            return path.into();
        }
        let root = luad_oracle::find_workspace_root();
        let output = Command::new("cargo")
            .args(["build", "-p", "luad-cli", "--bin", "luad"])
            .current_dir(&root)
            .output()
            .expect("build luad CLI");
        assert!(
            output.status.success(),
            "luad build failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        root.join("target/debug/luad")
    })
    .clone()
}

fn run(args: &[&str]) -> Output {
    Command::new(luad_bin())
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("run luad {args:?}: {error}"))
}

fn run_ok(args: &[&str]) -> String {
    let output = run(args);
    assert_eq!(
        output.status.code(),
        Some(0),
        "luad {args:?} must succeed; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn run_json(args: &[&str]) -> Value {
    let stdout = run_ok(args);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("luad {args:?} stdout is not JSON: {error}\n{stdout}"))
}

fn jsonl(stdout: &str) -> Vec<Value> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("JSONL record"))
        .collect()
}

fn records_of<'a>(records: &'a [Value], record_type: &str) -> Vec<&'a Value> {
    records
        .iter()
        .filter(|record| record["record_type"] == record_type)
        .collect()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_else(|| panic!("string: {value}"))
}

/// Every match id returned for one predicate, with the page limit high enough to be complete.
fn query_ids(file: &str, predicate: &str) -> BTreeSet<String> {
    let document = run_json(&[
        "query", file, "--where", predicate, "--limit", "5000", "--format", "json",
    ]);
    let matches = document["data"]["matches"]
        .as_array()
        .expect("query matches array");
    assert_eq!(
        document["data"]["count"].as_u64().map(|n| n as usize),
        Some(matches.len()),
        "count must equal the returned page for {predicate:?}"
    );
    for entry in matches {
        let kind = text(&entry["kind"]);
        assert!(
            RESULT_KINDS.contains(&kind),
            "predicate {predicate:?} returned an undeclared record kind {kind:?}"
        );
    }
    matches
        .iter()
        .map(|entry| text(&entry["id"]).to_string())
        .collect()
}

/// The ordered match ids for one predicate, for pagination and ordering proofs.
fn query_sequence(file: &str, predicate: &str, limit: usize, cursor: Option<&str>) -> Value {
    let limit = limit.to_string();
    let mut args = vec![
        "query", file, "--where", predicate, "--limit", &limit, "--format", "json",
    ];
    if let Some(cursor) = cursor {
        args.push("--cursor");
        args.push(cursor);
    }
    run_json(&args)["data"].clone()
}

fn ordered_ids(page: &Value) -> Vec<String> {
    page["matches"]
        .as_array()
        .expect("matches")
        .iter()
        .map(|entry| text(&entry["id"]).to_string())
        .collect()
}

// ===========================================================================
// 3. Fixtures. Bytes and source text are both under test control.
// ===========================================================================

/// The compiled probe. Every construct here exists to make one retrieval family observable:
/// a safely captured global alias, a `require` module label, constant-key `GETTABLE` and
/// `SELF` selectors, an exactly resolved child prototype, an unresolvable parameter callee,
/// a mutated upvalue, and literal/parameter/binary/table/call-result argument shapes.
const PROBE_SOURCE: &str = r#"
local fmt = string.format
local handler = require "app.handler"
local counter = 0

local function target(a, b)
  return a + b
end

local function forward(f, x)
  return f(x)
end

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

const OP_MOVE: u8 = 0;
const OP_LOADK: u8 = 1;
const OP_GETUPVAL: u8 = 4;
const OP_NEWTABLE: u8 = 10;
const OP_RETURN: u8 = 30;
const OP_CLOSURE: u8 = 36;

const fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    (op as u32) | ((a as u32) << 6) | ((c as u32) << 14) | ((b as u32) << 23)
}

const fn iabx(op: u8, a: u8, bx: u32) -> u32 {
    (op as u32) | ((a as u32) << 6) | (bx << 14)
}

/// A Lua 5.1 constant written by exact serialized bytes, so signed zero and type tags survive.
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

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&((bytes.len() + 1) as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out.push(0);
}

fn write_proto(out: &mut Vec<u8>, spec: &P) {
    write_string(out, b"@synth_capture_probe.lua");
    write_u32(out, 0);
    write_u32(out, 0);
    out.push(spec.nups);
    out.push(0); // numparams
    out.push(spec.is_vararg);
    out.push(spec.maxstack);
    write_u32(out, spec.code.len() as u32);
    for word in &spec.code {
        write_u32(out, *word);
    }
    write_u32(out, spec.consts.len() as u32);
    for constant in &spec.consts {
        match constant {
            K::Nil => out.push(0),
            K::Bool(value) => {
                out.push(1);
                out.push(u8::from(*value));
            }
            K::Num(value) => {
                out.push(3);
                out.extend_from_slice(&value.to_le_bytes());
            }
            K::Str(value) => {
                out.push(4);
                write_string(out, value.as_bytes());
            }
        }
    }
    write_u32(out, spec.children.len() as u32);
    for child in &spec.children {
        write_proto(out, child);
    }
    write_u32(out, 0); // lineinfo
    write_u32(out, spec.locals.len() as u32);
    for name in &spec.locals {
        write_string(out, name.as_bytes());
        write_u32(out, 0);
        write_u32(out, spec.code.len().saturating_sub(1) as u32);
    }
    write_u32(out, 0); // upvalue names
}

/// One stock little-endian 64-bit Lua 5.1 chunk in which the child prototype `proto:0/0` is
/// instantiated at two physical `CLOSURE` sites with different register binders, and which
/// carries the typed constants used by the stringification control.
///
/// ```text
/// proto:0                              proto:0/0 (nups 2)
///   0 NEWTABLE  R0                       0 GETUPVAL R0 U0
///   1 NEWTABLE  R1                       1 CLOSURE  R1 proto:0/0/0
///   2 NEWTABLE  R2                       2   GETUPVAL descriptor <- U1
///   3 CLOSURE   R3 proto:0/0  (site A)   3 RETURN
///   4   MOVE descriptor slot0 <- R0
///   5   MOVE descriptor slot1 <- R1    proto:0/0/0 (nups 1)
///   6 CLOSURE   R4 proto:0/0  (site B)   0 GETUPVAL R0 U0
///   7   MOVE descriptor slot0 <- R2      1 RETURN
///   8   MOVE descriptor slot1 <- R2
///   9 LOADK     R5 K2
///  10 RETURN
/// ```
fn synth_chunk(with_validation_findings: bool) -> Vec<u8> {
    let grandchild = P {
        nups: 1,
        is_vararg: 0,
        maxstack: 2,
        code: vec![iabc(OP_GETUPVAL, 0, 0, 0), iabc(OP_RETURN, 0, 1, 0)],
        consts: Vec::new(),
        locals: Vec::new(),
        children: Vec::new(),
    };
    let child = P {
        nups: 2,
        is_vararg: 0,
        maxstack: 3,
        code: vec![
            iabc(OP_GETUPVAL, 0, 0, 0),
            iabx(OP_CLOSURE, 1, 0),
            iabc(OP_GETUPVAL, 0, 1, 0),
            iabc(OP_RETURN, 0, 1, 0),
        ],
        consts: Vec::new(),
        locals: Vec::new(),
        children: vec![grandchild],
    };
    // The findings variant writes a destination register past `maxstacksize`, which parses
    // but must fail validation.
    let tail = if with_validation_findings {
        iabc(OP_MOVE, 30, 0, 0)
    } else {
        iabx(OP_LOADK, 5, 2)
    };
    let root = P {
        nups: 0,
        is_vararg: 2,
        maxstack: 8,
        code: vec![
            iabc(OP_NEWTABLE, 0, 0, 0),
            iabc(OP_NEWTABLE, 1, 0, 0),
            iabc(OP_NEWTABLE, 2, 0, 0),
            iabx(OP_CLOSURE, 3, 0),
            iabc(OP_MOVE, 0, 0, 0),
            iabc(OP_MOVE, 0, 1, 0),
            iabx(OP_CLOSURE, 4, 0),
            iabc(OP_MOVE, 0, 2, 0),
            iabc(OP_MOVE, 0, 2, 0),
            tail,
            iabc(OP_RETURN, 0, 1, 0),
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

    let mut out = Vec::new();
    out.extend_from_slice(b"\x1bLua");
    out.extend_from_slice(&[0x51, 0, 1, 4, 8, 4, 8, 0]);
    write_proto(&mut out, &root);
    out
}

struct Corpus {
    _dir: TempDir,
    /// The compiled probe.
    probe: String,
    /// A byte-identical second copy of the probe, for content-identity joins.
    probe_copy: String,
    /// The synthesized repeated-closure-site chunk.
    synth: String,
    /// The same chunk with one validation finding.
    findings: String,
    /// A valid header with a truncated body.
    truncated: String,
    /// Bytes that match no known dialect header.
    alien: String,
    /// A file larger than the configured input ceiling.
    oversized: String,
    /// Readable Lua source text, which export must skip rather than fail.
    plain_source: String,
    /// A path that does not exist.
    missing: String,
}

fn corpus() -> &'static Corpus {
    static CORPUS: OnceLock<Corpus> = OnceLock::new();
    CORPUS.get_or_init(|| {
        // Fails closed rather than skipping when the pinned Lua 5.1 authority is absent.
        let _ = luad_oracle::require_luac51();
        let probe_bytes = luad_oracle::compile_source_lua51(PROBE_SOURCE, false)
            .expect("probe source must compile with the pinned Lua 5.1.5 compiler");

        let dir = TempDir::new().expect("corpus directory");
        let write = |name: &str, bytes: &[u8]| -> String {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).expect("write corpus file");
            path.to_str().expect("UTF-8 path").to_string()
        };

        let probe = write("probe.luac", &probe_bytes);
        let probe_copy = write("probe_copy.luac", &probe_bytes);
        let synth = write("synth.luac", &synth_chunk(false));
        let findings = write("findings.luac", &synth_chunk(true));
        let truncated = write("truncated.luac", &probe_bytes[..16.min(probe_bytes.len())]);
        let alien = write("alien.bin", b"NOT-A-LUA-CHUNK-AT-ALL-0123456789");
        let plain_source = write("plain.lua", PROBE_SOURCE.as_bytes());

        let oversized_path = dir.path().join("oversized.luac");
        let file = std::fs::File::create(&oversized_path).expect("create oversized file");
        file.set_len(64 * 1024 * 1024 + 1)
            .expect("extend oversized file past the input ceiling");
        drop(file);

        Corpus {
            missing: dir
                .path()
                .join("absent.luac")
                .to_str()
                .expect("UTF-8 path")
                .to_string(),
            oversized: oversized_path.to_str().expect("UTF-8 path").to_string(),
            probe,
            probe_copy,
            synth,
            findings,
            truncated,
            alien,
            plain_source,
            _dir: dir,
        }
    })
}

// ===========================================================================
// 4. The reference fact index: the same tool's recursive export stream.
// ===========================================================================

struct Facts {
    records: Vec<Value>,
}

impl Facts {
    fn of(path: &str) -> Self {
        Self {
            records: jsonl(&run_ok(&["export", path, "--format", "jsonl"])),
        }
    }

    fn data(&self, record_type: &str) -> Vec<&Value> {
        self.records
            .iter()
            .filter(|record| record["record_type"] == record_type)
            .map(|record| &record["data"])
            .collect()
    }
}

/// The dot-joined symbolic path of a `resolved-path` resolution.
fn symbolic_path(resolution: &Value) -> Option<String> {
    if resolution["status"] != "resolved-path" {
        return None;
    }
    Some(
        resolution["segments"]
            .as_array()?
            .iter()
            .map(|segment| text(segment).to_string())
            .collect::<Vec<_>>()
            .join("."),
    )
}

/// The displayed text of a string-valued lookup key.
fn lookup_key_text(resolution: &Value) -> Option<String> {
    if resolution["status"] != "lookup-label" {
        return None;
    }
    let key = &resolution["key"];
    match key["type"].as_str()? {
        "short-string" | "long-string" => Some(key["value"]["display"].as_str()?.to_string()),
        _ => None,
    }
}

fn ids_where(
    facts: &Facts,
    record_type: &str,
    id_field: &str,
    keep: impl Fn(&Value) -> bool,
) -> BTreeSet<String> {
    facts
        .data(record_type)
        .into_iter()
        .filter(|fact| keep(fact))
        .map(|fact| text(&fact[id_field]).to_string())
        .collect()
}

/// Every fixed argument of every call, as `(call id, argument index, origin kind)`.
fn fixed_arguments(facts: &Facts) -> Vec<(String, u64, String)> {
    let mut out = Vec::new();
    for fact in facts.data("origin") {
        let window = &fact["argument_window"];
        if window["kind"] != "fixed" {
            continue;
        }
        for argument in window["arguments"].as_array().expect("arguments") {
            out.push((
                text(&fact["call_id"]).to_string(),
                argument["argument_index"].as_u64().expect("index"),
                text(&argument["origin"]["kind"]).to_string(),
            ));
        }
    }
    out
}

// ===========================================================================
// 5. The positive and zero-result matrix.
// ===========================================================================

struct Row {
    name: &'static str,
    predicate: String,
    expected: BTreeSet<String>,
    /// A positive row must not pass vacuously.
    min: usize,
}

fn row(name: &'static str, predicate: String, expected: BTreeSet<String>, min: usize) -> Row {
    Row {
        name,
        predicate,
        expected,
        min,
    }
}

fn matrix(facts: &Facts) -> Vec<Row> {
    let empty = BTreeSet::new();

    let one_digest = text(&facts.data("prototype_identity")[0]["digest"]).to_string();
    let one_target = facts
        .data("call_relation")
        .into_iter()
        .find_map(|fact| {
            (fact["resolution"]["status"] == "resolved")
                .then(|| format!("proto:{}", text(&fact["resolution"]["callee"])))
        })
        .expect("the probe must contain one exactly resolved call relation");

    let arguments = fixed_arguments(facts);
    let literal_calls: BTreeSet<String> = arguments
        .iter()
        .filter(|(_, _, kind)| kind.as_str() == "literal")
        .map(|(call, _, _)| call.clone())
        .collect();
    let index_two_calls: BTreeSet<String> = arguments
        .iter()
        .filter(|(_, index, _)| *index == 2)
        .map(|(call, _, _)| call.clone())
        .collect();

    let mut rows = vec![
        // --- typed constants and exact string containment -----------------
        row(
            "constant-substring",
            "constant contains \"probe\"".to_string(),
            ids_where(facts, "constant", "id", |c| {
                c["value"]["value"]["display"]
                    .as_str()
                    .is_some_and(|display| display.contains("probe"))
            }),
            2,
        ),
        row(
            "constant-exact-string",
            "constant == \"retrieval-probe\"".to_string(),
            ids_where(facts, "constant", "id", |c| {
                c["value"]["value"]["display"].as_str() == Some("retrieval-probe")
            }),
            1,
        ),
        row(
            "constant-type-short-string",
            "constant.type == \"short-string\"".to_string(),
            ids_where(facts, "constant", "id", |c| {
                c["value"]["type"] == "short-string"
            }),
            5,
        ),
        // --- callee resolution kind, path, lookup kind and key ------------
        row(
            "callee-status-lookup-label",
            "callee.status == \"lookup-label\"".to_string(),
            ids_where(facts, "callee", "call_id", |f| {
                f["resolution"]["status"] == "lookup-label"
            }),
            2,
        ),
        row(
            "callee-status-resolved-prototype",
            "callee.status == \"resolved-prototype\"".to_string(),
            ids_where(facts, "callee", "call_id", |f| {
                f["resolution"]["status"] == "resolved-prototype"
            }),
            1,
        ),
        row(
            "callee-lookup-kind-self",
            "callee.lookup.kind == \"self\"".to_string(),
            ids_where(facts, "callee", "call_id", |f| {
                f["resolution"]["lookup_kind"] == "self"
            }),
            1,
        ),
        row(
            "callee-lookup-key-exact",
            "callee.lookup.key == \"execute\"".to_string(),
            ids_where(facts, "callee", "call_id", |f| {
                lookup_key_text(&f["resolution"]).as_deref() == Some("execute")
            }),
            1,
        ),
        row(
            "callee-path-exact",
            "callee.path == \"string.format\"".to_string(),
            ids_where(facts, "callee", "call_id", |f| {
                symbolic_path(&f["resolution"]).as_deref() == Some("string.format")
            }),
            1,
        ),
        row(
            "callee-path-substring",
            "callee.path contains \"handler\"".to_string(),
            ids_where(facts, "callee", "call_id", |f| {
                symbolic_path(&f["resolution"]).is_some_and(|path| path.contains("handler"))
            }),
            1,
        ),
        // --- unresolved reasons -------------------------------------------
        row(
            "callee-reason-missing-definition",
            "callee.reason == \"missing-definition\"".to_string(),
            ids_where(facts, "callee", "call_id", |f| {
                f["resolution"]["reason"] == "missing-definition"
            }),
            1,
        ),
        row(
            "call-reason-lookup-label-only",
            "call.reason == \"lookup-label-only\"".to_string(),
            ids_where(facts, "call_relation", "call_id", |f| {
                f["resolution"]["reason"] == "lookup-label-only"
            }),
            2,
        ),
        // --- exact child-prototype call target ----------------------------
        row(
            "call-target-exact",
            format!("call.target == \"{one_target}\""),
            ids_where(facts, "call_relation", "call_id", |f| {
                f["resolution"]["status"] == "resolved"
                    && format!("proto:{}", text(&f["resolution"]["callee"])) == one_target
            }),
            1,
        ),
        // --- argument index and origin-expression kind --------------------
        row(
            "origin-kind-literal",
            "origin.kind == \"literal\"".to_string(),
            literal_calls,
            2,
        ),
        row(
            "origin-argument-index-two",
            "origin.argument.index == 2".to_string(),
            index_two_calls,
            1,
        ),
        // --- interpretation and prototype content identity ----------------
        row(
            "interpretation-profile-match",
            "interpretation.profile == \"lua5.1\"".to_string(),
            ["chunk".to_string()].into_iter().collect(),
            1,
        ),
        row(
            "prototype-digest-exact",
            format!("prototype.digest == \"{one_digest}\""),
            ids_where(facts, "prototype_identity", "proto_id", |f| {
                text(&f["digest"]) == one_digest
            }),
            1,
        ),
        // --- composition with the pre-existing grammar --------------------
        row(
            "existing-mnemonic-predicate-unchanged",
            "mnemonic == \"CALL\"".to_string(),
            ids_where(facts, "instruction", "id", |i| i["mnemonic"] == "CALL"),
            5,
        ),
        // --- exact zero-result rows over well-formed open operands --------
        row(
            "zero-constant-substring",
            "constant contains \"absent-token-zzz\"".to_string(),
            empty.clone(),
            0,
        ),
        row(
            "zero-callee-path",
            "callee.path == \"no.such.module.path\"".to_string(),
            empty.clone(),
            0,
        ),
        row(
            "zero-lookup-key",
            "callee.lookup.key == \"no-such-key\"".to_string(),
            empty.clone(),
            0,
        ),
        row(
            "zero-call-target-uncalled-prototype",
            "call.target == \"proto:0\"".to_string(),
            empty.clone(),
            0,
        ),
        row(
            "zero-prototype-digest",
            format!("prototype.digest == \"sha256:{}\"", "0".repeat(64)),
            empty.clone(),
            0,
        ),
        row(
            "zero-interpretation-profile",
            "interpretation.profile == \"lua5.4\"".to_string(),
            empty,
            0,
        ),
    ];

    // Boolean composition must be exact set algebra over the same records.
    let labels = rows
        .iter()
        .find(|r| r.name == "callee-status-lookup-label")
        .expect("label row")
        .expected
        .clone();
    let self_kind = rows
        .iter()
        .find(|r| r.name == "callee-lookup-kind-self")
        .expect("self row")
        .expected
        .clone();
    let prototypes = rows
        .iter()
        .find(|r| r.name == "callee-status-resolved-prototype")
        .expect("prototype row")
        .expected
        .clone();
    rows.push(row(
        "conjunction-label-and-gettable",
        "callee.status == \"lookup-label\" and callee.lookup.kind != \"self\"".to_string(),
        labels.difference(&self_kind).cloned().collect(),
        1,
    ));
    rows.push(row(
        "disjunction-self-or-prototype",
        "callee.lookup.kind == \"self\" or callee.status == \"resolved-prototype\"".to_string(),
        self_kind.union(&prototypes).cloned().collect(),
        2,
    ));
    rows
}

// ===========================================================================
// 6. Tests.
// ===========================================================================

#[test]
fn test_retrieval_predicates_select_exact_records_with_deterministic_order() {
    let probe = corpus().probe.as_str();
    let facts = Facts::of(probe);
    let rows = matrix(&facts);

    // Coverage: every declared family must contribute at least one live field to the matrix,
    // so a family cannot be frozen by an empty table.
    for (name, _, _) in RETRIEVAL_VOCABULARY {
        assert!(
            rows.iter().any(|r| r.predicate.contains(name)),
            "no matrix row exercises the {name} retrieval field"
        );
    }

    for entry in &rows {
        assert!(
            entry.expected.len() >= entry.min,
            "row {} is vacuous: the fixture yielded {} records, {} required",
            entry.name,
            entry.expected.len(),
            entry.min
        );

        let observed = query_ids(probe, &entry.predicate);
        assert_eq!(
            observed, entry.expected,
            "row {} selected the wrong records for {:?}",
            entry.name, entry.predicate
        );

        // Determinism: the same request must produce byte-identical stdout.
        let first = run_ok(&[
            "query",
            probe,
            "--where",
            &entry.predicate,
            "--limit",
            "5000",
            "--format",
            "json",
        ]);
        let second = run_ok(&[
            "query",
            probe,
            "--where",
            &entry.predicate,
            "--limit",
            "5000",
            "--format",
            "json",
        ]);
        assert_eq!(
            first, second,
            "row {} is not byte-deterministic across invocations",
            entry.name
        );
    }
}

#[test]
fn test_retrieval_predicates_fail_closed_on_operands_they_cannot_apply() {
    let probe = corpus().probe.as_str();

    // Every row must exit 2 with no stdout at all: a usage error may not be dressed up as an
    // empty or overbroad answer.
    let refuse = |name: String, predicate: String, marker: String| {
        let output = run(&["query", probe, "--where", &predicate, "--format", "json"]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "row {name} ({predicate:?}) must be a usage error; stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stdout.is_empty(),
            "row {name} produced a plausible partial answer on stdout:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&marker),
            "row {name} stderr must name {marker:?}, got:\n{stderr}"
        );
    };

    // Generated directly from the declared vocabulary, so the table cannot drift from the
    // behaviour: an operator a field does not declare is a usage error, and an operand that
    // is not a member of a closed vocabulary (or not an integer, where one is required) is a
    // usage error rather than a silently empty answer.
    for (name, vocabulary, operators) in RETRIEVAL_VOCABULARY {
        for operator in ["==", "!=", "contains"] {
            if operators.contains(&operator) {
                continue;
            }
            refuse(
                format!("unsupported-operator-{name}-{operator}"),
                format!("{name} {operator} \"probe\""),
                name.to_string(),
            );
        }
        let operand = match vocabulary {
            // An open vocabulary answers exactly zero for a well-formed absent value; that
            // case belongs to the positive matrix, not here.
            Vocabulary::Open => continue,
            Vocabulary::Closed => "not-a-declared-member",
            Vocabulary::Integer => "not-an-integer",
        };
        refuse(
            format!("unusable-operand-{name}"),
            format!("{name} == \"{operand}\""),
            name.to_string(),
        );
    }

    // Hand-written rows for conditions the table cannot express.
    let rows: Vec<(&str, &str, &str)> = vec![
        // unknown fields
        (
            "unknown-field",
            "callee.unknown == \"x\"",
            "Unknown query field",
        ),
        (
            "unknown-subfield",
            "origin.argument == 1",
            "Unknown query field",
        ),
        (
            "unknown-namespace",
            "capture.kind == \"local\"",
            "Unknown query field",
        ),
        // an operator the pre-existing grammar already refuses
        (
            "contains-on-opcode",
            "opcode contains \"CALL\"",
            "Unsupported operator",
        ),
        // wrong operand types on the pre-existing effect fields, which must stop silently
        // ignoring an operand they cannot apply
        (
            "register-not-an-integer",
            "effect.write.register == \"not-a-register\"",
            "effect.write.register",
        ),
        (
            "upvalue-negative",
            "effect.read.upvalue == -1",
            "effect.read.upvalue",
        ),
        // operands that name an artifact which does not exist or is not an identifier
        (
            "absent-call-target",
            "call.target == \"proto:0/99\"",
            "call.target",
        ),
        (
            "malformed-call-target",
            "call.target == \"not-an-id\"",
            "call.target",
        ),
        // malformed expressions
        ("missing-value", "callee.status ==", "Missing query value"),
        (
            "unbalanced",
            "(callee.status == \"unresolved\"",
            "Unbalanced parentheses",
        ),
        (
            "trailing-tokens",
            "callee.status == \"unresolved\" leftover",
            "Unexpected trailing tokens",
        ),
        ("bare-operator", "and", "Malformed query expression"),
    ];

    for (name, predicate, marker) in rows {
        refuse(name.to_string(), predicate.to_string(), marker.to_string());
    }
}

#[test]
fn test_retrieval_pagination_binds_cursors_and_bounds_resources() {
    let probe = corpus().probe.as_str();
    let predicate = "constant.type == \"short-string\"";
    let other = "callee.status == \"lookup-label\"";

    let complete = ordered_ids(&query_sequence(probe, predicate, 5000, None));
    assert!(
        complete.len() >= 4,
        "the probe must offer enough constants to paginate"
    );

    // Cursor replay: consecutive bounded pages reconstruct the complete ordered answer.
    let mut walked: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..complete.len() + 2 {
        let page = query_sequence(probe, predicate, 1, cursor.as_deref());
        walked.extend(ordered_ids(&page));
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_string()),
            None => {
                assert_eq!(page["is_truncated"], false);
                break;
            }
        }
        assert_eq!(page["is_truncated"], true, "a continued page is truncated");
    }
    assert_eq!(
        walked, complete,
        "cursor replay must reconstruct the complete deterministic order"
    );

    let first = query_sequence(probe, predicate, 1, None);
    let cursor = text(&first["next_cursor"]).to_string();
    let parts: Vec<&str> = cursor.split('_').collect();
    assert_eq!(parts.len(), 3, "cursor shape is cur_<signature>_<offset>");

    // Cursor tampering and cross-context reuse fail closed.
    let tampered_offset = format!("{}_{}_{}", parts[0], parts[1], 99);
    let tampered_signature = format!("{}_{}_{}", parts[0], "00000000", parts[2]);
    let beyond_total = (complete.len() + 1).to_string();
    let at_total = complete.len().to_string();

    for (name, predicate_used, cursor_used) in [
        ("tampered-offset", predicate, tampered_offset.as_str()),
        ("tampered-signature", predicate, tampered_signature.as_str()),
        // A cursor issued for one predicate must not be honoured by another.
        ("foreign-predicate", other, cursor.as_str()),
        ("beyond-total", predicate, beyond_total.as_str()),
    ] {
        let output = run(&[
            "query",
            probe,
            "--where",
            predicate_used,
            "--limit",
            "1",
            "--cursor",
            cursor_used,
            "--format",
            "json",
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "cursor row {name} must fail closed"
        );
        assert!(
            output.stdout.is_empty(),
            "cursor row {name} answered anyway"
        );
    }

    // A cursor issued for another artifact is rejected as well.
    let foreign_file = run(&[
        "query",
        corpus().synth.as_str(),
        "--where",
        predicate,
        "--limit",
        "1",
        "--cursor",
        cursor.as_str(),
        "--format",
        "json",
    ]);
    assert_eq!(foreign_file.status.code(), Some(2));
    assert!(foreign_file.stdout.is_empty());

    // The exact end offset is an empty success, not an error.
    let end = query_sequence(probe, predicate, 5, Some(at_total.as_str()));
    assert_eq!(end["count"], 0);
    assert_eq!(end["is_truncated"], false);
    assert_eq!(end["next_cursor"], Value::Null);

    // Bounded resources: an input past the configured ceiling stops before any answer.
    let oversized = run(&["query", corpus().oversized.as_str(), "--format", "json"]);
    assert_eq!(
        oversized.status.code(),
        Some(5),
        "an input past the ceiling must report resource exhaustion"
    );
    assert!(oversized.stdout.is_empty());

    // Bounded export: the per-file fact bound truncates deterministically and says so.
    let bounded = jsonl(&run_ok(&[
        "export",
        probe,
        "--format",
        "jsonl",
        "--max-facts-per-file",
        "1",
    ]));
    let file_end = bounded
        .iter()
        .find(|record| record["record_type"] == "file_end")
        .expect("file_end record");
    assert_eq!(file_end["is_truncated"], true);
    assert_eq!(file_end["emitted_fact_count"], 1);
    assert!(
        file_end["available_fact_count"]
            .as_u64()
            .expect("available")
            > 1,
        "truncation must remain honest about what was withheld"
    );
}

#[test]
fn test_capture_xrefs_stay_site_accurate_across_repeated_closure_sites() {
    let synth = corpus().synth.as_str();

    // Precondition: the synthesized chunk is a well-formed Lua 5.1 artifact.
    let validated = run_json(&["validate", synth, "--format", "json"]);
    assert_ne!(
        validated["data"]["verdict"], "invalid",
        "the capture fixture must be analysable: {}",
        validated["data"]["diagnostics"]
    );

    let binds = |args: &[&str]| -> BTreeSet<(String, String)> {
        let mut full = vec!["xrefs", synth];
        full.extend_from_slice(args);
        full.extend_from_slice(&["--format", "json"]);
        run_json(&full)["data"]["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .filter(|entry| entry["relation"] == "binds")
            .map(|entry| {
                (
                    text(&entry["source"]).to_string(),
                    text(&entry["target"]).to_string(),
                )
            })
            .collect()
    };
    let sources = |args: &[&str]| -> BTreeSet<String> {
        binds(args).into_iter().map(|(source, _)| source).collect()
    };
    let targets = |args: &[&str]| -> BTreeSet<String> {
        binds(args).into_iter().map(|(_, target)| target).collect()
    };

    // Inverse traversal. Slot 0 is bound from R0 at site A and from R2 at site B; slot 1 is
    // bound from R1 at site A and from R2 at site B. Collapsing the two sites, or inferring
    // the relation from the child prototype's position alone, cannot produce both.
    let into_slot0 = sources(&["--to", "proto:0/0:upvalue:0"]);
    let into_slot1 = sources(&["--to", "proto:0/0:upvalue:1"]);
    for required in [
        "proto:0:local:0",
        "proto:0:local:2",
        "proto:0:pc:3",
        "proto:0:pc:4",
        "proto:0:pc:6",
        "proto:0:pc:7",
    ] {
        assert!(
            into_slot0.contains(required),
            "slot 0 lost the {required} binder; observed {into_slot0:?}"
        );
    }
    for required in [
        "proto:0:local:1",
        "proto:0:local:2",
        "proto:0:pc:3",
        "proto:0:pc:5",
        "proto:0:pc:6",
        "proto:0:pc:8",
    ] {
        assert!(
            into_slot1.contains(required),
            "slot 1 lost the {required} binder; observed {into_slot1:?}"
        );
    }
    assert!(
        !into_slot0.contains("proto:0:local:1"),
        "slot 0 acquired slot 1's binder: {into_slot0:?}"
    );
    assert!(
        !into_slot1.contains("proto:0:local:0"),
        "slot 1 acquired slot 0's binder: {into_slot1:?}"
    );

    // Forward traversal from the parent sources.
    assert_eq!(
        targets(&["--from", "proto:0:local:0"]),
        ["proto:0/0:upvalue:0".to_string()].into_iter().collect(),
        "R0 binds slot 0 only"
    );
    assert_eq!(
        targets(&["--from", "proto:0:local:1"]),
        ["proto:0/0:upvalue:1".to_string()].into_iter().collect(),
        "R1 binds slot 1 only"
    );
    assert_eq!(
        targets(&["--from", "proto:0:local:2"]),
        [
            "proto:0/0:upvalue:0".to_string(),
            "proto:0/0:upvalue:1".to_string()
        ]
        .into_iter()
        .collect(),
        "R2 binds both slots at site B"
    );

    // Descriptor-level site identity: each physical binding word reaches exactly its own slot.
    for (descriptor, slot) in [
        ("proto:0:pc:4", "proto:0/0:upvalue:0"),
        ("proto:0:pc:5", "proto:0/0:upvalue:1"),
        ("proto:0:pc:7", "proto:0/0:upvalue:0"),
        ("proto:0:pc:8", "proto:0/0:upvalue:1"),
    ] {
        assert_eq!(
            targets(&["--from", descriptor]),
            [slot.to_string()].into_iter().collect(),
            "binding descriptor {descriptor} must reach {slot} and nothing else"
        );
    }

    // The physical closure sites remain distinct owners of the whole capture set.
    for site in ["proto:0:pc:3", "proto:0:pc:6"] {
        assert_eq!(
            targets(&["--from", site]),
            [
                "proto:0/0:upvalue:0".to_string(),
                "proto:0/0:upvalue:1".to_string()
            ]
            .into_iter()
            .collect(),
            "closure site {site} must own both child slots"
        );
    }

    // Multi-hop: the grandchild slot is reached from the child upvalue, not from a parent
    // register, and keeps its own closure site and descriptor.
    let into_grandchild = sources(&["--to", "proto:0/0/0:upvalue:0"]);
    for required in ["proto:0/0:upvalue:1", "proto:0/0:pc:1", "proto:0/0:pc:2"] {
        assert!(
            into_grandchild.contains(required),
            "multi-hop capture lost {required}; observed {into_grandchild:?}"
        );
    }
}

#[test]
fn test_cli_outcome_table_pins_exit_codes_and_output_channels() {
    let c = corpus();
    let probe = c.probe.as_str();

    // `Json`: stdout must be exactly one complete machine document.
    // `Empty`: stdout must carry nothing at all and stderr must explain the outcome.
    #[derive(PartialEq, Eq)]
    enum Stdout {
        Json,
        Empty,
    }
    use Stdout::{Empty, Json};

    #[rustfmt::skip]
    let outcomes: Vec<(&str, Vec<&str>, i32, Stdout)> = vec![
        ("successful-query", vec!["query", probe, "--where", "mnemonic == \"CALL\""], 0, Json),
        ("no-match-query", vec!["query", probe, "--where", "constant contains \"absent-zzz\""], 0, Json),
        ("invalid-predicate", vec!["query", probe, "--where", "callee.status == \"resolved\""], 2, Empty),
        ("malformed-input", vec!["query", c.truncated.as_str()], 1, Empty),
        ("unrecognized-format", vec!["query", c.alien.as_str()], 4, Empty),
        ("resource-exhaustion", vec!["query", c.oversized.as_str()], 5, Empty),
        ("io-failure", vec!["query", c.missing.as_str()], 3, Empty),
        ("clean-validation", vec!["validate", probe], 0, Json),
        // Validation findings still publish the complete typed document, then exit nonzero.
        ("validation-findings", vec!["validate", c.findings.as_str()], 1, Json),
        ("unknown-command", vec!["frobnicate", probe], 2, Empty),
    ];

    for (name, argv, exit, stdout_shape) in &outcomes {
        let mut args = argv.clone();
        if args[0] != "frobnicate" {
            args.extend_from_slice(&["--format", "json"]);
        }
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(*exit),
            "outcome {name} expected exit {exit}; stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        match stdout_shape {
            Empty => {
                assert!(
                    stdout.is_empty(),
                    "outcome {name} answered anyway:\n{stdout}"
                );
                assert!(
                    !output.stderr.is_empty(),
                    "outcome {name} must explain itself on stderr"
                );
            }
            Json => {
                let parsed: Value = serde_json::from_str(&stdout)
                    .unwrap_or_else(|e| panic!("outcome {name} stdout is not JSON: {e}"));
                assert!(parsed.is_object());
                assert!(
                    !stdout.contains('\u{1b}'),
                    "outcome {name} leaked ANSI styling into machine stdout"
                );
            }
        }
    }

    // Mixed batch export: one chunk, one readable source, one unreadable path.
    let mixed = run(&[
        "export",
        probe,
        c.plain_source.as_str(),
        c.missing.as_str(),
        "--format",
        "jsonl",
    ]);
    assert_eq!(
        mixed.status.code(),
        Some(0),
        "a mixed batch with at least one success is a success by default"
    );
    let records = jsonl(&String::from_utf8_lossy(&mixed.stdout));
    let end = records
        .iter()
        .find(|record| record["record_type"] == "export_end")
        .expect("export_end completeness marker");
    assert_eq!(end["files_processed"], 3);
    assert_eq!(end["files_succeeded"], 1);
    assert_eq!(end["files_skipped"], 1);
    assert_eq!(end["files_failed"], 1);
    let stderr = String::from_utf8_lossy(&mixed.stderr);
    assert!(
        stderr
            .trim_end()
            .ends_with("1 exported, 1 skipped, 1 failed"),
        "mixed batch stderr must end with the deterministic summary, got:\n{stderr}"
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
    assert_ne!(
        strict.status.code(),
        Some(0),
        "--strict must fail a batch containing a skip or failure"
    );
    assert!(
        jsonl(&String::from_utf8_lossy(&strict.stdout))
            .iter()
            .any(|record| record["record_type"] == "export_end"),
        "--strict must still emit the complete framed stream"
    );
}

#[test]
fn test_schema_major_one_closed_variants_and_open_vocabularies() {
    let probe = corpus().probe.as_str();

    // Current majors, taken live rather than from prose.
    assert_eq!(
        run_json(&["query", probe, "--format", "json"])["schema_version"],
        1
    );
    assert_eq!(
        run_json(&["capabilities", "--format", "json"])["schema_version"],
        2
    );
    let export_start = jsonl(&run_ok(&["export", probe, "--format", "jsonl"]))
        .into_iter()
        .find(|record| record["record_type"] == "export_start")
        .expect("export_start");
    assert_eq!(export_start["schema_version"], 2);

    for (name, requested, expected_exit) in [
        ("query-major-1", "1", 0),
        ("query-major-2", "2", 2),
        ("export-major-2", "2", 0),
        ("export-major-1", "1", 2),
    ] {
        let schema = if name.starts_with("query") {
            "query"
        } else {
            "export"
        };
        let output = run(&["schema", schema, "--schema-version", requested]);
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "schema request {name} must not silently default"
        );
    }

    // The rule under test, applied to live records rather than to the schema text alone:
    // tagged variants and typed reason vocabularies are CLOSED within the major, so an
    // unknown member is rejected; string-typed fields are OPEN vocabularies, so an unknown
    // member is retained verbatim.
    let facts = Facts::of(probe);
    let callee = facts
        .data("callee")
        .into_iter()
        .find(|f| f["resolution"]["status"] == "unresolved")
        .expect("one unresolved callee fact")
        .clone();

    let parsed: luad_analysis::CalleeFact =
        serde_json::from_value(callee.clone()).expect("a current record must deserialize");
    assert_eq!(text(&callee["call_id"]), parsed.call_id.to_string());

    let with_resolution_field = |field: &str, value: &str| -> Value {
        let mut record = callee.clone();
        record["resolution"][field] = Value::from(value);
        record
    };

    // CLOSED: an unknown tagged variant is refused, never coerced to a default.
    let unknown_status = with_resolution_field("status", "future-status");
    assert!(
        serde_json::from_value::<luad_analysis::CalleeFact>(unknown_status).is_err(),
        "an unknown resolution variant must be rejected within schema-major 1"
    );

    // CLOSED: an unknown reason member is refused.
    let unknown_reason = with_resolution_field("reason", "future-reason");
    assert!(
        serde_json::from_value::<luad_analysis::CalleeFact>(unknown_reason).is_err(),
        "an unknown unresolved reason must be rejected within schema-major 1"
    );

    // CLOSED: xref relations are a tagged vocabulary too.
    let mut xref = facts.data("xref")[0].clone();
    assert!(serde_json::from_value::<luad_analysis::XrefEntry>(xref.clone()).is_ok());
    xref["relation"] = Value::from("future-relation");
    assert!(
        serde_json::from_value::<luad_analysis::XrefEntry>(xref).is_err(),
        "an unknown xref relation must be rejected within schema-major 1"
    );

    // OPEN: `call_kind` is a string-typed vocabulary, so an unknown member is retained
    // exactly and remains available to the caller for a deliberate decision.
    let mut unknown_kind = callee.clone();
    unknown_kind["call_kind"] = Value::from("FUTURECALL");
    let retained: luad_analysis::CalleeFact = serde_json::from_value(unknown_kind)
        .expect("an unknown open-vocabulary member must be retained, not rejected");
    assert_eq!(retained.call_kind, "FUTURECALL");

    // OPEN: the prototype identity scheme is likewise retained rather than misread.
    let mut identity = facts.data("prototype_identity")[0].clone();
    identity["scheme"] = Value::from("luad-prototype-v99");
    let retained: luad_analysis::PrototypeIdentityFact = serde_json::from_value(identity)
        .expect("an unknown identity scheme must be retained for a deliberate decision");
    assert_eq!(retained.scheme, "luad-prototype-v99");

    // The published schema must state the same rule: closed vocabularies enumerate members.
    // Either generator shape is acceptable, an open `"type": "string"` is not.
    let schema = run_json(&["schema", "callees"]);
    let reasons = &schema["definitions"]["CalleeUnresolvedReason"];
    let enumerated = reasons["enum"]
        .as_array()
        .or_else(|| reasons["oneOf"].as_array())
        .map(|list| list.len())
        .unwrap_or(0);
    assert!(
        enumerated >= 10,
        "the callee unresolved reason must be published as a closed enumeration, got {reasons}"
    );
    let variants = schema["definitions"]["CalleeResolution"]["oneOf"]
        .as_array()
        .expect("CalleeResolution is a tagged union");
    assert!(
        variants.len() >= 4,
        "the resolution union must publish its complete closed variant set"
    );
}

#[test]
fn test_composition_recipes_execute_the_seven_documented_workflows() {
    let c = corpus();
    let tree = [c.probe.as_str(), c.probe_copy.as_str(), c.synth.as_str()];

    // The stream every recipe consumes:
    //   luad export firmware/*.luac --format jsonl
    let stream = run_ok(&[
        "export",
        tree[0],
        tree[1],
        tree[2],
        "--format",
        "jsonl",
        "--max-facts-per-file",
        "20000",
    ]);
    let records = jsonl(&stream);
    let path_of = |record: &Value| text(&record["context"]["input_identity"]["path"]).to_string();

    // Recipe 1: exact and substring constant search over a firmware tree.
    //   jq 'select(.record_type=="constant" and (.data.value.value.display // "" | contains("probe")))'
    let substring: BTreeSet<(String, String)> = records_of(&records, "constant")
        .into_iter()
        .filter(|record| {
            record["data"]["value"]["value"]["display"]
                .as_str()
                .is_some_and(|display| display.contains("probe"))
        })
        .map(|record| (path_of(record), text(&record["data"]["id"]).to_string()))
        .collect();
    let exact: BTreeSet<(String, String)> = records_of(&records, "constant")
        .into_iter()
        .filter(|record| record["data"]["value"]["value"]["display"] == "retrieval-probe")
        .map(|record| (path_of(record), text(&record["data"]["id"]).to_string()))
        .collect();
    assert!(
        exact.iter().all(|hit| substring.contains(hit)) && exact.len() < substring.len(),
        "exact search must be a strict refinement of substring search"
    );
    let files: BTreeSet<String> = substring.iter().map(|(file, _)| file.clone()).collect();
    assert_eq!(files.len(), 3, "the search must span the whole tree");

    // Recipe 2: calls selected by a symbolic path or by a constant key.
    //   jq 'select(.record_type=="callee") | select(.data.resolution.status=="resolved-path")'
    let by_path: Vec<&Value> = records_of(&records, "callee")
        .into_iter()
        .filter(|record| {
            symbolic_path(&record["data"]["resolution"])
                .is_some_and(|path| path.starts_with("app.handler"))
        })
        .collect();
    let by_key: Vec<&Value> = records_of(&records, "callee")
        .into_iter()
        .filter(|record| {
            lookup_key_text(&record["data"]["resolution"]).as_deref() == Some("invoke")
        })
        .collect();
    assert!(!by_path.is_empty(), "recipe 2 found no symbolic-path call");
    assert!(!by_key.is_empty(), "recipe 2 found no constant-key call");

    // Recipe 3: calls grouped by unresolved reason, with no call silently dropped.
    //   jq -r 'select(.record_type=="call_relation") | .data.resolution.reason // "resolved"'
    let mut by_reason: BTreeMap<String, usize> = BTreeMap::new();
    for record in records_of(&records, "call_relation") {
        let resolution = &record["data"]["resolution"];
        let bucket = resolution["reason"]
            .as_str()
            .unwrap_or("resolved")
            .to_string();
        *by_reason.entry(bucket).or_default() += 1;
    }
    assert_eq!(
        by_reason.values().sum::<usize>(),
        records_of(&records, "call_relation").len(),
        "every call relation must land in exactly one reason bucket"
    );
    assert!(
        by_reason.len() >= 2,
        "the tree must exercise more than one stop reason: {by_reason:?}"
    );

    // Recipe 4: fixed call arguments grouped by origin-expression shape.
    //   jq 'select(.record_type=="origin") | .data.argument_window.arguments[]?.origin.kind'
    let mut by_shape: BTreeMap<String, usize> = BTreeMap::new();
    let mut fixed_total = 0usize;
    for record in records_of(&records, "origin") {
        let window = &record["data"]["argument_window"];
        if window["kind"] != "fixed" {
            continue;
        }
        for argument in window["arguments"].as_array().expect("arguments") {
            fixed_total += 1;
            *by_shape
                .entry(text(&argument["origin"]["kind"]).to_string())
                .or_default() += 1;
        }
    }
    assert_eq!(by_shape.values().sum::<usize>(), fixed_total);
    assert!(
        by_shape.len() >= 3,
        "the tree must exercise several argument shapes: {by_shape:?}"
    );

    // Recipe 5: forward and inverse multi-hop capture traversal with closure-site identity.
    //   jq 'select(.record_type=="xref" and .data.relation=="binds")'
    let binds: BTreeSet<(String, String, String)> = records_of(&records, "xref")
        .into_iter()
        .filter(|record| record["data"]["relation"] == "binds")
        .map(|record| {
            (
                path_of(record),
                text(&record["data"]["source"]).to_string(),
                text(&record["data"]["target"]).to_string(),
            )
        })
        .collect();
    let synth_binds: BTreeSet<(String, String)> = binds
        .iter()
        .filter(|(file, _, _)| file == &c.synth)
        .map(|(_, source, target)| (source.clone(), target.clone()))
        .collect();
    let forward = |from: &str| -> BTreeSet<String> {
        synth_binds
            .iter()
            .filter(|(source, _)| source.as_str() == from)
            .map(|(_, target)| target.clone())
            .collect()
    };
    let inverse = |to: &str| -> BTreeSet<String> {
        synth_binds
            .iter()
            .filter(|(_, target)| target.as_str() == to)
            .map(|(source, _)| source.clone())
            .collect()
    };
    let hop_one = forward("proto:0:local:1");
    assert!(
        hop_one.contains("proto:0/0:upvalue:1"),
        "recipe 5 lost the first capture hop: {hop_one:?}"
    );
    let hop_two = forward("proto:0/0:upvalue:1");
    assert!(
        hop_two.contains("proto:0/0/0:upvalue:0"),
        "recipe 5 lost the second capture hop: {hop_two:?}"
    );
    let back = inverse("proto:0/0/0:upvalue:0");
    assert!(
        back.contains("proto:0/0:upvalue:1") && back.contains("proto:0/0:pc:1"),
        "recipe 5 lost the inverse hop or its closure site: {back:?}"
    );

    // Recipe 6: navigate from a call site to an exact child prototype when proven.
    //   jq 'select(.record_type=="call_relation" and .data.resolution.status=="resolved")'
    let resolved: Vec<(String, String, String)> = records_of(&records, "call_relation")
        .into_iter()
        .filter(|record| record["data"]["resolution"]["status"] == "resolved")
        .map(|record| {
            (
                path_of(record),
                text(&record["data"]["call_id"]).to_string(),
                format!("proto:{}", text(&record["data"]["resolution"]["callee"])),
            )
        })
        .collect();
    assert!(!resolved.is_empty(), "recipe 6 found no proven relation");
    let calls_edges: BTreeSet<(String, String, String)> = records_of(&records, "xref")
        .into_iter()
        .filter(|record| record["data"]["relation"] == "calls")
        .map(|record| {
            (
                path_of(record),
                text(&record["data"]["source"]).to_string(),
                text(&record["data"]["target"]).to_string(),
            )
        })
        .collect();
    let prototypes: BTreeSet<(String, String)> = records_of(&records, "prototype")
        .into_iter()
        .map(|record| (path_of(record), text(&record["data"]["id"]).to_string()))
        .collect();
    for (file, call, target) in &resolved {
        assert!(
            calls_edges.contains(&(file.clone(), call.clone(), target.clone())),
            "recipe 6: {call} has no matching calls xref to {target}"
        );
        assert!(
            prototypes.contains(&(file.clone(), target.clone())),
            "recipe 6: {target} is not a navigable prototype record"
        );
    }

    // Recipe 7: compare by artifact interpretation identity and prototype content identity.
    //   jq -r 'select(.record_type=="prototype_identity") | [.data.digest, .context...path] | @tsv'
    let mut inventory: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for record in records_of(&records, "prototype_identity") {
        inventory
            .entry(text(&record["data"]["digest"]).to_string())
            .or_default()
            .insert(path_of(record));
    }
    let joined: Vec<&String> = inventory
        .iter()
        .filter(|(_, files)| files.contains(&c.probe) && files.contains(&c.probe_copy))
        .map(|(digest, _)| digest)
        .collect();
    assert!(
        !joined.is_empty(),
        "identical artifacts must join on prototype content identity"
    );
    assert!(
        inventory
            .values()
            .all(|files| !(files.contains(&c.probe) && files.contains(&c.synth))),
        "unrelated artifacts must not share a prototype content identity"
    );
    let interpretations: BTreeSet<(String, String)> = records_of(&records, "file_start")
        .into_iter()
        .map(|record| {
            (
                text(&record["path"]).to_string(),
                text(&record["interpretation"]["profile"]).to_string(),
            )
        })
        .collect();
    assert!(
        interpretations
            .iter()
            .all(|(_, profile)| profile.starts_with("lua5.1")),
        "recipe 7 must expose the resolved interpretation identity: {interpretations:?}"
    );
    assert_eq!(interpretations.len(), 3);
}

#[test]
fn test_compile_surface_is_removed_and_rejected_as_an_unknown_command() {
    let help = run_ok(&["--help"]);
    assert!(
        !help.to_lowercase().contains("compile"),
        "help still advertises the removed compiler-laboratory surface:\n{help}"
    );

    let capabilities = run_ok(&["capabilities", "--format", "json"]);
    assert!(
        !capabilities.to_lowercase().contains("compile"),
        "the capability document still declares a compile surface"
    );

    for name in ["compile", "compiler"] {
        let output = run(&["schema", name]);
        assert_ne!(
            output.status.code(),
            Some(0),
            "schema {name:?} must not exist"
        );
    }

    // The command is not merely inert: it is not a command at all.
    let output = run(&[
        "compile",
        corpus().plain_source.as_str(),
        "--compiler",
        "/bin/true",
    ]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "compile must be rejected as an unknown command, not answered with a stub"
    );
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert!(
        !stderr.contains("not supported in bytecode analysis mode"),
        "the nonfunctional compile stub is still installed:\n{stderr}"
    );
}

#[test]
fn test_live_killer_controls_reject_plausible_wrong_retrieval_engines() {
    let c = corpus();
    let probe = c.probe.as_str();
    let synth = c.synth.as_str();

    // Killer 1: an evaluator that accepts `contains` but ignores its operand.
    // A correct engine returns a strict, non-empty subset for a present token and exactly
    // nothing for an absent one; an operand-ignoring engine returns every string constant
    // for both.
    let all_strings = query_ids(probe, "constant.type == \"short-string\"");
    let hit = query_ids(probe, "constant contains \"probe\"");
    let miss = query_ids(probe, "constant contains \"absent-token-zzz\"");
    assert!(
        !hit.is_empty() && hit.len() < all_strings.len(),
        "contains ignored its operand: {} hits out of {} string constants",
        hit.len(),
        all_strings.len()
    );
    assert!(
        miss.is_empty(),
        "an absent containment operand returned {} records",
        miss.len()
    );
    assert!(hit.is_subset(&all_strings));

    // Killer 2: stringifying typed constants. The synthesized chunk holds float +0.0,
    // float -0.0 and the short string "0". Text containment is defined for string constants
    // only, and equality is byte-exact, so neither float may answer either predicate.
    let float_ids = query_ids(synth, "constant.type == \"float\"");
    assert_eq!(float_ids.len(), 2, "the fixture holds both signed zeros");
    let contains_zero = query_ids(synth, "constant contains \"0\"");
    assert!(
        contains_zero.is_disjoint(&float_ids),
        "typed float constants were stringified into a text containment answer: {contains_zero:?}"
    );
    assert!(
        !contains_zero.is_empty(),
        "the short string \"0\" must still answer text containment"
    );
    let equals_zero = query_ids(synth, "constant.type == \"float\" and constant == 0");
    assert_eq!(
        equals_zero.len(),
        1,
        "byte identity must separate +0.0 from -0.0, got {equals_zero:?}"
    );

    // Killer 3: a cursor honoured for a different complete request.
    let page = query_sequence(probe, "constant.type == \"short-string\"", 1, None);
    let cursor = text(&page["next_cursor"]).to_string();
    let reused = run(&[
        "query",
        probe,
        "--where",
        "constant.type == \"float\"",
        "--limit",
        "1",
        "--cursor",
        cursor.as_str(),
        "--format",
        "json",
    ]);
    assert_eq!(
        reused.status.code(),
        Some(2),
        "a cursor bound to one predicate was accepted for another"
    );
    assert!(reused.stdout.is_empty());

    // Killer 4: capture-site collapse. Two physical closure sites bind child slot 0 from two
    // different parent registers; an implementation keyed on child-prototype position alone
    // reports only one of them.
    let into_slot0: BTreeSet<String> = run_json(&[
        "xrefs",
        synth,
        "--to",
        "proto:0/0:upvalue:0",
        "--format",
        "json",
    ])["data"]["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|entry| entry["relation"] == "binds")
        .filter_map(|entry| {
            let source = text(&entry["source"]).to_string();
            source.contains(":local:").then_some(source)
        })
        .collect();
    assert_eq!(
        into_slot0,
        ["proto:0:local:0".to_string(), "proto:0:local:2".to_string()]
            .into_iter()
            .collect::<BTreeSet<String>>(),
        "the two closure sites collapsed into one binder"
    );

    // Killer 5: an invalid predicate answered with success. Each of these is well-formed
    // syntax over a real field with an operand the engine cannot apply.
    for predicate in [
        "callee.status == \"resolved\"",
        "origin.kind == \"not-a-kind\"",
        "origin.argument.index == \"first\"",
        "constant.type == \"string\"",
    ] {
        let output = run(&["query", probe, "--where", predicate, "--format", "json"]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "invalid predicate {predicate:?} was answered instead of refused"
        );
        assert!(
            output.stdout.is_empty(),
            "invalid predicate {predicate:?} still emitted an answer"
        );
    }
}
