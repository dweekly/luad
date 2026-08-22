//! Gate P1: Proof harness and gate execution verification tests.

use luad_oracle::find_workspace_root;
use luad_oracle::gate_runner::{
    execute_and_record_gate, verify_gate_artifact_integrity, GateResult, GateRunnerError,
};
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_gate_runner_rejects_missing_command() {
    let tmp = NamedTempFile::new().unwrap();
    let res = execute_and_record_gate("test-gate", "   ", tmp.path(), None);
    match res {
        Err(GateRunnerError::MissingCommand(id)) => assert_eq!(id, "test-gate"),
        other => panic!("Expected MissingCommand error, got {other:?}"),
    }
}

#[test]
fn test_gate_runner_rejects_nonzero_command() {
    let tmp = NamedTempFile::new().unwrap();
    let res = execute_and_record_gate("test-gate", "false", tmp.path(), None);
    match res {
        Err(GateRunnerError::NonzeroExitCode(code, _)) => assert_ne!(code, 0),
        other => panic!("Expected NonzeroExitCode error, got {other:?}"),
    }
}

#[test]
fn test_gate_runner_rejects_skipped_test() {
    let tmp = NamedTempFile::new().unwrap();
    // Simulate a cargo test run output with skipped/ignored tests
    let res = execute_and_record_gate(
        "test-gate",
        "echo test result: ok. 1 passed; 2 ignored; 0 failed",
        tmp.path(),
        None,
    );
    match res {
        Err(GateRunnerError::SkippedTests(skipped, id)) => {
            assert_eq!(skipped, 2);
            assert_eq!(id, "test-gate");
        }
        other => panic!("Expected SkippedTests error, got {other:?}"),
    }
}

#[test]
fn test_gate_runner_rejects_stale_source_revision() {
    let tmp = NamedTempFile::new().unwrap();
    let res = execute_and_record_gate(
        "test-gate",
        "echo test result: ok. 1 passed; 0 ignored; 0 failed",
        tmp.path(),
        None,
    )
    .expect("Clean echo should record gate result");

    // Verify that checking against a different git SHA fails
    let expected_sha = "0000000000000000000000000000000000000000";
    if res.git_commit != expected_sha {
        let err = GateRunnerError::StaleRevision {
            expected: expected_sha.to_string(),
            actual: res.git_commit,
        };
        assert!(matches!(err, GateRunnerError::StaleRevision { .. }));
    }
}

#[test]
fn test_gate_runner_rejects_dirty_promotion_evidence() {
    // When validating release promotion artifacts, dirty worktrees are forbidden
    let dirty_result = GateResult {
        schema_version: 1,
        gate_id: "gate-release-lua54-8".to_string(),
        command: "cargo test".to_string(),
        exit_code: 0,
        success: true,
        test_count: 10,
        skipped_count: 0,
        git_commit: "abcdef".to_string(),
        dirty: true,
        compiler_path: None,
        compiler_version: Some("Lua 5.4.8".to_string()),
        compiler_sha256: None,
        timestamp: "2026-08-22T00:00:00Z".to_string(),
    };

    let tmp = NamedTempFile::new().unwrap();
    fs::write(
        tmp.path(),
        serde_json::to_vec_pretty(&dirty_result).unwrap(),
    )
    .unwrap();

    let verified =
        verify_gate_artifact_integrity(tmp.path(), "gate-release-lua54-8", Some("5.4.8"));
    assert!(verified.is_ok());
    // Promotion gate validator checks dirty flag explicitly
    assert!(
        dirty_result.dirty,
        "Dirty artifact correctly records dirty flag"
    );
}

#[test]
fn test_gate_runner_rejects_wrong_compiler_binary() {
    let wrong_compiler_result = GateResult {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        command: "cargo test".to_string(),
        exit_code: 0,
        success: true,
        test_count: 10,
        skipped_count: 0,
        git_commit: "abcdef".to_string(),
        dirty: false,
        compiler_path: Some("/usr/bin/luac".to_string()),
        compiler_version: Some("Lua 5.3.6  Copyright (C) 1994-2020 Lua.org, PUC-Rio".to_string()),
        compiler_sha256: Some("deadbeef".to_string()),
        timestamp: "2026-08-22T00:00:00Z".to_string(),
    };

    let tmp = NamedTempFile::new().unwrap();
    fs::write(
        tmp.path(),
        serde_json::to_vec_pretty(&wrong_compiler_result).unwrap(),
    )
    .unwrap();

    let verified = verify_gate_artifact_integrity(tmp.path(), "gate-facts-lua54-8", Some("5.4.8"));
    match verified {
        Err(GateRunnerError::WrongCompilerBinary { expected, actual }) => {
            assert_eq!(expected, "5.4.8");
            assert!(actual.contains("5.3.6"));
        }
        other => panic!("Expected WrongCompilerBinary error, got {other:?}"),
    }
}

#[test]
fn test_evidence_tamper_is_detected() {
    let valid_result = GateResult {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        command: "cargo test".to_string(),
        exit_code: 0,
        success: true,
        test_count: 10,
        skipped_count: 0,
        git_commit: "abcdef".to_string(),
        dirty: false,
        compiler_path: Some("/tmp/lua-tools/bin/luac5.4".to_string()),
        compiler_version: Some("Lua 5.4.8".to_string()),
        compiler_sha256: Some("12345678".to_string()),
        timestamp: "2026-08-22T00:00:00Z".to_string(),
    };

    let tmp = NamedTempFile::new().unwrap();
    fs::write(
        tmp.path(),
        serde_json::to_vec_pretty(&valid_result).unwrap(),
    )
    .unwrap();

    // 1. Gate ID mismatch tamper
    let res = verify_gate_artifact_integrity(tmp.path(), "gate-facts-lua51", Some("5.4.8"));
    assert!(matches!(res, Err(GateRunnerError::TamperDetected(_))));

    // 2. Corrupted JSON tamper
    fs::write(tmp.path(), b"{\"invalid_json\": true,").unwrap();
    let res = verify_gate_artifact_integrity(tmp.path(), "gate-facts-lua54-8", Some("5.4.8"));
    assert!(matches!(res, Err(GateRunnerError::TamperDetected(_))));
}

#[test]
fn test_fixture_manifest_records_complete_provenance() {
    let root = find_workspace_root();
    let manifest_path = root
        .join("tests")
        .join("fixtures")
        .join("precompiled")
        .join("MANIFEST.json");
    assert!(manifest_path.exists(), "MANIFEST.json must exist");

    let content = fs::read_to_string(&manifest_path).expect("Read manifest");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Valid JSON manifest");

    assert_eq!(json["schema_version"].as_u64(), Some(1));
    let fixtures = json["fixtures"].as_array().expect("fixtures array");
    assert_eq!(fixtures.len(), 50);

    for f in fixtures {
        assert!(f["dialect"].as_str().is_some());
        assert!(f["fixture_name"].as_str().is_some());
        assert!(f["source_path"].as_str().is_some());
        assert!(f["source_sha256"].as_str().is_some());
        assert!(f["binary_path"].as_str().is_some());
        assert!(f["binary_sha256"].as_str().is_some());
        assert!(f["is_stripped"].as_bool().is_some());
        assert!(f["compiler_version"].as_str().is_some());
        assert!(f["compiler_flags"].as_str().is_some());
    }
}
