//! Comparing two LuCI releases by content identity, and predicting an external handoff.
//!
//! `luci.util` changed between openwrt/luci 22.03 and 23.05. The textual source diff is
//! the oracle: a prototype whose content digest has no match in the other release must
//! contain a changed source line, and every changed line must sit at root level or inside
//! such a prototype. The handoff check asks whether luad's validated layout predicts
//! exactly when the official Lua 5.1.5 lister accepts an artifact. Sources are compiled,
//! never executed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_analysis::analyze_chunk_prototype_identities;
use luad_core::model::{Chunk, Prototype};
use sha2::{Digest, Sha256};

const UTIL: &str = "libs/luci-lib-base/luasrc/util.lua";
const SYS: &str = "modules/luci-lua-runtime/luasrc/sys.lua";

fn corpus(release: &str) -> PathBuf {
    luad_oracle::find_workspace_root()
        .join("tests/corpus")
        .join(release)
}

fn read(release: &str, path: &str) -> String {
    std::fs::read_to_string(corpus(release).join(path)).unwrap()
}

fn compile(source: &str, strip: bool) -> Chunk {
    let _ = luad_oracle::require_luac51();
    let bytes = luad_oracle::compile_source_lua51(source, strip).expect("official luac 5.1");
    let mut reader = luad_core::reader::SafeReader::new(&bytes);
    luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode")
}

fn walk<'a>(proto: &'a Prototype, out: &mut BTreeMap<String, &'a Prototype>) {
    out.insert(proto.id.to_string(), proto);
    for child in &proto.protos {
        walk(child, out);
    }
}

fn prototypes(chunk: &Chunk) -> BTreeMap<String, &Prototype> {
    let mut out = BTreeMap::new();
    walk(&chunk.main_proto, &mut out);
    out
}

fn digests(chunk: &Chunk) -> BTreeMap<String, String> {
    analyze_chunk_prototype_identities(chunk)
        .expect("prototype identities")
        .prototypes
        .into_iter()
        .map(|fact| (fact.proto_id.to_string(), fact.digest))
        .collect()
}

/// Prototypes of each side whose digest does not occur on the other side.
fn unmatched(old: &Chunk, new: &Chunk) -> (BTreeSet<String>, BTreeSet<String>) {
    let (a, b) = (digests(old), digests(new));
    let a_set: BTreeSet<&String> = a.values().collect();
    let b_set: BTreeSet<&String> = b.values().collect();
    (
        a.iter()
            .filter(|(_, d)| !b_set.contains(d))
            .map(|(p, _)| p.clone())
            .collect(),
        b.iter()
            .filter(|(_, d)| !a_set.contains(d))
            .map(|(p, _)| p.clone())
            .collect(),
    )
}

/// One side's changes: lines the longest common subsequence leaves out, and gaps where
/// the other side's lines were removed. A gap `g` lies between lines `g` and `g + 1`.
#[derive(Default)]
struct Changes {
    lines: BTreeSet<usize>,
    gaps: BTreeSet<usize>,
}

fn changed_lines(old: &str, new: &str) -> (Changes, Changes) {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let mut lcs = vec![vec![0u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let (mut old_side, mut new_side) = (Changes::default(), Changes::default());
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            i += 1;
            j += 1;
        } else if j < b.len() && (i == a.len() || lcs[i][j + 1] >= lcs[i + 1][j]) {
            new_side.lines.insert(j + 1);
            old_side.gaps.insert(i);
            j += 1;
        } else {
            old_side.lines.insert(i + 1);
            new_side.gaps.insert(j);
            i += 1;
        }
    }
    (old_side, new_side)
}

fn range(proto: &Prototype) -> std::ops::RangeInclusive<usize> {
    proto.line_defined..=proto.last_line_defined
}

/// The source-diff oracle for one side: unmatched prototypes contain a changed line, and
/// every changed line is at root level or inside an unmatched prototype.
fn oracle_violations(
    chunk: &Chunk,
    unmatched: &BTreeSet<String>,
    changes: &Changes,
) -> Vec<String> {
    let lines = &changes.lines;
    let protos = prototypes(chunk);
    let mut out = Vec::new();
    for id in unmatched {
        let proto = protos[id];
        if proto.line_defined == 0 {
            continue; // the root spans the whole file
        }
        let gap_inside = changes
            .gaps
            .iter()
            .any(|g| proto.line_defined <= *g && *g < proto.last_line_defined);
        if !gap_inside && !lines.iter().any(|line| range(proto).contains(line)) {
            out.push(format!(
                "{id} is unmatched but no changed line lies in {:?}",
                range(proto)
            ));
        }
    }
    for line in lines {
        let enclosing: Vec<&String> = protos
            .iter()
            .filter(|(_, p)| p.line_defined != 0 && range(p).contains(line))
            .map(|(id, _)| id)
            .collect();
        if !enclosing.is_empty() && !enclosing.iter().any(|id| unmatched.contains(*id)) {
            out.push(format!(
                "changed line {line} lies only in matched {enclosing:?}"
            ));
        }
    }
    out
}

#[test]
fn test_luci_22_03_util_is_unmodified_and_differs_from_23_05() {
    let notice = std::fs::read_to_string(corpus("luci-22.03").join("NOTICE.md")).unwrap();
    let old = std::fs::read(corpus("luci-22.03").join(UTIL)).unwrap();
    let new = std::fs::read(corpus("luci-23.05").join(UTIL)).unwrap();
    assert!(notice.contains(&hex::encode(Sha256::digest(&old))));
    assert_ne!(old, new);
    for extra in ["LICENSE", "UPSTREAM-NOTICE"] {
        assert_eq!(
            std::fs::read(corpus("luci-22.03").join(extra)).unwrap(),
            std::fs::read(corpus("luci-23.05").join(extra)).unwrap()
        );
    }
}

#[test]
fn test_release_digest_join_isolates_exactly_the_source_changes() {
    let (old_text, new_text) = (read("luci-22.03", UTIL), read("luci-23.05", UTIL));
    let (gone, added) = changed_lines(&old_text, &new_text);
    assert!(!gone.lines.is_empty() && !added.lines.is_empty());
    let mut sets = Vec::new();
    for strip in [false, true] {
        let (old, new) = (compile(&old_text, strip), compile(&new_text, strip));
        sets.push(unmatched(&old, &new));
    }
    assert_eq!(
        sets[0], sets[1],
        "debug and stripped builds must compare alike"
    );
    let (old_only, new_only) = &sets[0];
    let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(
        *old_only,
        ids(&[
            "proto:0",
            "proto:0/4",
            "proto:0/5",
            "proto:0/6",
            "proto:0/48"
        ])
    );
    assert_eq!(*new_only, ids(&["proto:0", "proto:0/4", "proto:0/46"]));

    // The oracle needs line ranges, so it reads the debug builds.
    let (old, new) = (compile(&old_text, false), compile(&new_text, false));
    let violations: Vec<String> = oracle_violations(&old, old_only, &gone)
        .into_iter()
        .chain(oracle_violations(&new, new_only, &added))
        .collect();
    assert!(violations.is_empty(), "{violations:#?}");

    // A file identical in both releases matches every prototype.
    let sys = read("luci-23.05", SYS);
    let (left, right) = unmatched(&compile(&sys, false), &compile(&sys, true));
    assert!(left.is_empty() && right.is_empty());
}

#[test]
fn test_release_oracle_detects_a_one_token_edit() {
    let old_text = read("luci-22.03", UTIL);
    let old = compile(&old_text, false);
    // Edit one string literal inside `split`, which did not change between releases.
    let split_line = old_text
        .lines()
        .position(|l| l.starts_with("function split("))
        .unwrap()
        + 1;
    let split = prototypes(&old)
        .into_values()
        .find(|p| p.line_defined == split_line)
        .map(|p| p.id.to_string())
        .unwrap();
    let body: Vec<&str> = old_text.lines().collect();
    let target = (split_line..split_line + 30)
        .find(|n| body[*n - 1].contains('"'))
        .expect("a string literal in split");
    let edited: String = old_text
        .lines()
        .enumerate()
        .map(|(n, l)| {
            if n + 1 == target {
                l.replacen('"', "\"x", 1)
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let changed = compile(&edited, false);
    let (old_only, new_only) = unmatched(&old, &changed);
    let expected: BTreeSet<String> = ["proto:0".to_string(), split.clone()].into();
    assert_eq!(old_only, expected);
    assert_eq!(new_only, expected);
    let (gone, added) = changed_lines(&old_text, &edited);
    assert_eq!(gone.lines, BTreeSet::from([target]));
    assert_eq!(added.lines, BTreeSet::from([target]));
    // Pretending the edited function matched is caught.
    let mut wrong = old_only.clone();
    wrong.remove(&split);
    assert!(!oracle_violations(&old, &wrong, &gone).is_empty());
}

fn layout(luad: &Path, artifact: &Path) -> String {
    let output = Command::new(luad)
        .args(["inspect", artifact.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert!(output.status.success(), "inspect {}", artifact.display());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    document["interpretation"]["validated_layout"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn test_handoff_layout_predicts_the_official_lister() {
    let luac = luad_oracle::require_luac51();
    let luad = luad_oracle::luad_binary_path();
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, source: &str, strip: bool| -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(
            &path,
            luad_oracle::compile_source_lua51(source, strip).unwrap(),
        )
        .unwrap();
        path
    };
    // The tool's own layout is whatever it writes for a trivial probe.
    let probe = write("probe.luac", "return 1\n", false);
    let tool = layout(&luad, &probe);
    let root = luad_oracle::find_workspace_root();
    let artifacts = vec![
        write("util_new.luac", &read("luci-23.05", UTIL), false),
        write("util_new_s.luac", &read("luci-23.05", UTIL), true),
        write("util_old.luac", &read("luci-22.03", UTIL), false),
        root.join("tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32.luac"),
        root.join("tests/fixtures/authority/lua51-openwrt-lnum32/authority_lnum32_stripped.luac"),
        root.join("tests/fixtures/firmware_tree/dispatcher.lua"),
    ];
    let mut outcomes = BTreeSet::new();
    for artifact in &artifacts {
        let predicted = layout(&luad, artifact) == tool;
        let accepted = Command::new(&luac)
            .args(["-l", "-p"])
            .arg(artifact)
            .output()
            .unwrap()
            .status
            .success();
        assert_eq!(predicted, accepted, "{}", artifact.display());
        outcomes.insert(accepted);
    }
    assert_eq!(
        outcomes.len(),
        2,
        "both accepted and refused handoffs are exercised"
    );
}
