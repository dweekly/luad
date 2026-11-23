//! CLI evidence for exact string retrieval in stripped Lua 5.1 chunks.
use serde_json::{json, Value};
use std::process::{Command, Output};
use tempfile::NamedTempFile;

fn fixture() -> NamedTempFile {
    let source = r#"
local function msg() return "\nNotice" end
local function other() return "\nNotice" end
local function lookup(t) return t["\b"]() end
return "\\nNotice", "b", "\b", "f", "\f", "\255Notice", "", msg, other, lookup
"#;
    let bytes =
        luad_oracle::compile_source_lua51(source, true).expect("require official Lua 5.1.5");
    let file = NamedTempFile::new().unwrap();
    std::fs::write(file.path(), bytes).unwrap();
    file
}

fn run(command: &str, file: &NamedTempFile, args: &[&str]) -> Output {
    Command::new(luad_oracle::resolve_test_binary().unwrap())
        .arg(command)
        .arg(file.path())
        .args(args)
        .output()
        .unwrap()
}

fn stdout(out: Output) -> String {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn document(out: Output) -> Value {
    serde_json::from_str(&stdout(out)).unwrap()
}

#[test]
fn quoted_predicates_compare_bytes() {
    let file = fixture();
    for (predicate, ids) in [
        (
            r#"string == "\nNotice""#,
            vec!["proto:0/0:k:0", "proto:0/1:k:0"],
        ),
        (r#"string == "\\nNotice""#, vec!["proto:0:k:0"]),
        (r#"string contains "nNotice""#, vec!["proto:0:k:0"]),
        (r#"constant == "\b""#, vec!["proto:0:k:2", "proto:0/2:k:0"]),
        (r#"constant == "\f""#, vec!["proto:0:k:4"]),
        (r#"constant == "f""#, vec!["proto:0:k:3"]),
        (
            r#"string contains "Notice" and string != "\nNotice""#,
            vec!["proto:0:k:0", "proto:0:k:5"],
        ),
        (
            r#"string == "" and string contains """#,
            vec!["proto:0:k:6"],
        ),
        (r#"callee.lookup.key == "\b""#, vec!["proto:0/2:pc:1"]),
        (r#"callee.lookup.key == "b""#, vec![]),
    ] {
        let doc = document(run("query", &file, &["--where", predicate]));
        let matches = doc["data"]["matches"].as_array().unwrap();
        let actual: Vec<_> = matches.iter().map(|m| m["id"].as_str().unwrap()).collect();
        assert_eq!(actual, ids, "{predicate}");
        assert_eq!(doc["data"]["is_truncated"], false);
    }
    let bad = run("query", &file, &["--where", r#"string == "\q""#]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(bad.stdout.is_empty());
}

#[test]
fn literal_xrefs_preserve_owners_and_intersect_endpoints() {
    let file = fixture();
    let query = |args: &[&str]| run("xrefs", &file, args);
    let data = document(query(&["--to-string", "\nNotice", "-f", "json"]))["data"].clone();
    let first = json!({"source":"proto:0/0:pc:0","target":"proto:0/0:k:0","relation":"reads"});
    let second = json!({"source":"proto:0/1:pc:0","target":"proto:0/1:k:0","relation":"reads"});
    assert_eq!(data["entries"], json!([first, second]));
    assert_eq!(data["total_count"], 2);
    assert_eq!(data["target_string"], "\nNotice");

    let lines = stdout(query(&[
        "--from",
        "proto:0/0:pc:0",
        "--to-string",
        "\nNotice",
        "-f",
        "jsonl",
    ]));
    let records: Vec<Value> = lines
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(records.len(), 3);
    assert_eq!(records[1]["data"], first);
    assert_eq!(records[2]["total_records"], 1);
    let empty = document(query(&[
        "--from",
        "proto:0/1:pc:0",
        "--to",
        "proto:0/0:k:0",
        "-f",
        "json",
    ]));
    assert_eq!(empty["data"]["entries"], json!([]));
    let exact = document(query(&[
        "--from",
        "proto:0/0:pc:0",
        "--to",
        "proto:0/0:k:0",
        "-f",
        "json",
    ]));
    assert_eq!(exact["data"]["entries"], json!([first]));
    assert!(exact["data"].get("target_string").is_none());
    let absent = stdout(query(&["--to-string", "Notice"]));
    assert!(absent.contains("No matching cross-references"));
    let conflict = query(&["--to-string", "", "--to", "proto:0:k:0"]);
    assert_eq!(conflict.status.code(), Some(2));
    assert!(conflict.stdout.is_empty());
}
