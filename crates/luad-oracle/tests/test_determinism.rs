//! Tests ensuring deterministic, reproducible outputs across runs and dialects.

use luad_oracle::get_fixture_bytes;
use std::process::Command;

fn get_luad_bin() -> String {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let mut path = std::path::PathBuf::from(manifest_dir);
    path.pop();
    path.pop();
    path.push("target");
    path.push("debug");
    path.push("luad");
    path.to_str().unwrap().to_string()
}

#[test]
fn test_cli_output_determinism() {
    let luad = get_luad_bin();
    let bytes = get_fixture_bytes("lua5.4", "closures", false).unwrap();
    let temp_file1 = tempfile::NamedTempFile::new().unwrap();
    let temp_file2 = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file1.path(), &bytes).unwrap();
    std::fs::write(temp_file2.path(), &bytes).unwrap();

    let path1 = temp_file1.path().to_str().unwrap().to_string();
    let path2 = temp_file2.path().to_str().unwrap().to_string();

    let commands_to_test: Vec<Vec<String>> = vec![
        vec![
            "inspect".into(),
            "--format".into(),
            "json".into(),
            path1.clone(),
        ],
        vec![
            "disasm".into(),
            "--effects".into(),
            "--format".into(),
            "text".into(),
            path1.clone(),
        ],
        vec![
            "disasm".into(),
            "--format".into(),
            "json".into(),
            path1.clone(),
        ],
        vec![
            "validate".into(),
            "--format".into(),
            "json".into(),
            path1.clone(),
        ],
        vec!["explain".into(), path1.clone(), "proto:0:pc:0".into()],
        vec!["cfg".into(), "--format".into(), "dot".into(), path1.clone()],
        vec![
            "cfg".into(),
            "--format".into(),
            "json".into(),
            path1.clone(),
        ],
        vec![
            "xrefs".into(),
            "--format".into(),
            "json".into(),
            path1.clone(),
        ],
        vec![
            "query".into(),
            "--format".into(),
            "json".into(),
            path1.clone(),
        ],
        vec![
            "schema".into(),
            "chunk".into(),
            "--schema-version".into(),
            "1".into(),
        ],
        vec![
            "schema".into(),
            "instruction".into(),
            "--schema-version".into(),
            "1".into(),
        ],
        vec!["capabilities".into()],
    ];

    for mut full_args in commands_to_test {
        let out1 = Command::new(&luad)
            .args(&full_args)
            .output()
            .unwrap_or_else(|e| panic!("Failed to run luad with args {full_args:?}: {e}"));

        // Replace path1 with path2 in arguments
        for arg in &mut full_args {
            if *arg == path1 {
                *arg = path2.clone();
            }
        }

        let out2 = Command::new(&luad)
            .args(&full_args)
            .output()
            .unwrap_or_else(|e| panic!("Failed to run luad with args {full_args:?}: {e}"));

        assert_eq!(out1.status.code(), out2.status.code());
        assert_eq!(
            out1.stdout, out2.stdout,
            "Nondeterministic stdout across files for args {:?}",
            full_args
        );
        assert_eq!(
            out1.stderr, out2.stderr,
            "Nondeterministic stderr across files for args {:?}",
            full_args
        );
    }
}
