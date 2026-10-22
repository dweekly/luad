//! Public comparison boundary: a required official compiler and typed output checks.
use luad_oracle::{compile_source_lua51, luad_binary_path};
use serde_json::Value;
use std::{fs, process::Command};

fn run(
    old: &std::path::Path,
    new: &std::path::Path,
    format: &str,
    semantic: bool,
    ignore: Option<&str>,
) -> std::process::Output {
    let mut cmd = Command::new(luad_binary_path());
    cmd.arg("diff").arg(old).arg(new).args(["--format", format]);
    if semantic {
        cmd.arg("--semantic");
    }
    if let Some(ignore) = ignore {
        cmd.args(["--ignore", ignore]);
    }
    cmd.env("NO_COLOR", "1").output().expect("run luad")
}

fn assert_result(output: std::process::Output, format: &str, changed: bool) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    match format {
        "text" => assert!(
            text.contains(if changed {
                "Differences detected"
            } else {
                "Equal compared content (0 differences)"
            }),
            "{text}"
        ),
        "json" => {
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                value["data"]["is_identical"].as_bool(),
                Some(!changed),
                "{value}"
            );
        }
        "jsonl" => {
            let records: Vec<Value> = text
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
            assert_eq!(records.first().unwrap()["record_type"], "metadata");
            let differences: Vec<_> = records
                .iter()
                .filter(|r| r["record_type"] == "diff_prototype")
                .collect();
            assert_eq!(!differences.is_empty(), changed, "{text}");
            assert_eq!(
                records.last().unwrap()["total_records"].as_u64(),
                Some(differences.len() as u64)
            );
        }
        _ => panic!("unknown test format"),
    }
}

#[test]
fn public_constant_only_pair_and_identical_controls_all_formats() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.luac");
    let new = dir.path().join("new.luac");
    fs::write(
        &old,
        compile_source_lua51(
            include_str!("../../../tests/fixtures/comparison/before.lua"),
            true,
        )
        .expect("required official Lua 5.1.5"),
    )
    .unwrap();
    fs::write(
        &new,
        compile_source_lua51(
            include_str!("../../../tests/fixtures/comparison/after.lua"),
            true,
        )
        .expect("required official Lua 5.1.5"),
    )
    .unwrap();
    for semantic in [false, true] {
        for format in ["text", "json", "jsonl"] {
            assert_result(run(&old, &new, format, semantic, None), format, true);
            assert_result(run(&old, &old, format, semantic, None), format, false);
        }
        let json: Value =
            serde_json::from_slice(&run(&old, &new, "json", semantic, None).stdout).unwrap();
        assert_eq!(
            json["data"]["proto_diffs"][0]["constant_diffs"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(json["data"]["proto_diffs"][0]["instruction_diffs"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}

#[test]
fn public_debug_ignore_controls_and_invalid_selector_refusal() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.luac");
    let new = dir.path().join("new.luac");
    fs::write(
        &old,
        compile_source_lua51("local first = 1; return first", false).expect("required Lua 5.1.5"),
    )
    .unwrap();
    fs::write(
        &new,
        compile_source_lua51("local other = 1; return other", false).expect("required Lua 5.1.5"),
    )
    .unwrap();
    for semantic in [false, true] {
        for format in ["text", "json", "jsonl"] {
            assert_result(run(&old, &new, format, semantic, None), format, true);
            assert_result(
                run(&old, &new, format, semantic, Some("debug")),
                format,
                false,
            );
        }
    }
    let output = run(&old, &new, "json", false, Some("typo"));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown --ignore selector"));
}

#[test]
fn jsonl_retains_header_only_changes() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.luac");
    let new = dir.path().join("new.luac");
    let bytes = compile_source_lua51("return 1", true).expect("required Lua 5.1.5");
    fs::write(&old, &bytes).unwrap();
    let mut trailing = bytes;
    trailing.push(0);
    fs::write(&new, trailing).unwrap();
    let output = run(&old, &new, "jsonl", false, None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    let proto = records
        .iter()
        .find(|r| r["record_type"] == "diff_prototype")
        .expect("header-only change record");
    assert_eq!(proto["data"]["path"], "0");
    assert!(proto["data"]["header_diffs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x.as_str().unwrap().contains("Chunk: trailing bytes")));
}
