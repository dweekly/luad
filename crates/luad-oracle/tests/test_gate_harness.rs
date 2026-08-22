//! Gate R1: Proof harness and gate execution verification tests.
//!
//! Conforms to Coding-Agent Plan v3 Section 7: all required adversarial probes.

use luad_oracle::find_workspace_root;
use luad_oracle::gate_runner::{
    assemble_release_manifest, execute_gate_spec, verify_gate_result, verify_release_manifest,
    FixtureRequirement, GateResult, GateRunnerError, GateSpec,
};
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn test_probe_1_zero_tests_executed_rejected() {
    let root = find_workspace_root();
    let tmp = NamedTempFile::new().unwrap();
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["echo".to_string(), "success".to_string()],
        expected_tests: vec![],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let res = execute_gate_spec(&spec, tmp.path(), &root, None);
    match res {
        Err(GateRunnerError::ZeroTestsExecuted(id)) => assert_eq!(id, "test-gate"),
        other => panic!("Expected ZeroTestsExecuted error, got {other:?}"),
    }
}

#[test]
fn test_probe_2_nonexistent_test_filter_rejected() {
    let root = find_workspace_root();
    let tmp = NamedTempFile::new().unwrap();
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "luad-core".to_string(),
            "--".to_string(),
            "nonexistent_test_filter_xyz_12345".to_string(),
        ],
        expected_tests: vec!["expected_test_name".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let res = execute_gate_spec(&spec, tmp.path(), &root, None);
    assert!(res.is_err(), "Nonexistent test filter must fail execution");
}

#[test]
fn test_probe_3_ignored_test_rejected() {
    let root = find_workspace_root();
    let tmp = NamedTempFile::new().unwrap();
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec![
            "echo".to_string(),
            "test test_foo ... ok\ntest result: ok. 1 passed; 1 ignored; 0 failed".to_string(),
        ],
        expected_tests: vec!["test_foo".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let res = execute_gate_spec(&spec, tmp.path(), &root, None);
    match res {
        Err(GateRunnerError::SkippedTests(skipped, id)) => {
            assert_eq!(skipped, 1);
            assert_eq!(id, "test-gate");
        }
        other => panic!("Expected SkippedTests error, got {other:?}"),
    }
}

#[test]
fn test_probe_4_stale_git_commit_rejected() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_one".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_one".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111111111111111111111111111111111111111".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let verified = verify_gate_result(
        &result,
        &spec,
        Some("2222222222222222222222222222222222222222"),
        false,
    );
    match verified {
        Err(GateRunnerError::StaleRevision { expected, actual }) => {
            assert_eq!(expected, "2222222222222222222222222222222222222222");
            assert_eq!(actual, "1111111111111111111111111111111111111111");
        }
        other => panic!("Expected StaleRevision error, got {other:?}"),
    }
}

#[test]
fn test_probe_5_dirty_result_rejected_for_promotion() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_one".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let dirty_result = GateResult {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_one".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111111111111111111111111111111111111111".to_string(),
        dirty: true,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let verified = verify_gate_result(
        &dirty_result,
        &spec,
        Some("1111111111111111111111111111111111111111"),
        true, // require_clean = true
    );
    assert_eq!(
        verified.unwrap_err(),
        GateRunnerError::DirtyPromotionArtifact
    );
}

#[test]
fn test_probe_6_wrong_compiler_binary_sha256_rejected() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_one".to_string()],
        required_compiler_version: Some("Lua 5.4.8".to_string()),
        required_compiler_sha256: Some(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_one".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: false,
        compiler_path: Some("/usr/bin/luac".to_string()),
        compiler_version: Some("Lua 5.4.8".to_string()),
        compiler_sha256: Some(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        ),
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let verified = verify_gate_result(&result, &spec, None, false);
    match verified {
        Err(GateRunnerError::WrongCompilerBinary { expected, actual }) => {
            assert_eq!(
                expected,
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
            assert_eq!(
                actual,
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            );
        }
        other => panic!("Expected WrongCompilerBinary error, got {other:?}"),
    }
}

#[test]
fn test_probe_7_wrong_compiler_version_rejected() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_one".to_string()],
        required_compiler_version: Some("Lua 5.4.8".to_string()),
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_one".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: false,
        compiler_path: Some("/usr/bin/luac".to_string()),
        compiler_version: Some("Lua 5.4.7".to_string()),
        compiler_sha256: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let verified = verify_gate_result(&result, &spec, None, false);
    match verified {
        Err(GateRunnerError::WrongCompilerVersion { expected, actual }) => {
            assert_eq!(expected, "Lua 5.4.8");
            assert_eq!(actual, "Lua 5.4.7");
        }
        other => panic!("Expected WrongCompilerVersion error, got {other:?}"),
    }
}

#[test]
fn test_probe_8_missing_compiler_rejected_before_tests() {
    let root = find_workspace_root();
    let tmp = NamedTempFile::new().unwrap();
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["echo".to_string(), "success".to_string()],
        expected_tests: vec![],
        required_compiler_version: Some("Lua 5.4.8".to_string()),
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let missing_path = std::path::Path::new("/nonexistent/bin/luac5.4");
    let res = execute_gate_spec(&spec, tmp.path(), &root, Some(missing_path));
    match res {
        Err(GateRunnerError::CompilerMissing(p)) => {
            assert_eq!(p, "/nonexistent/bin/luac5.4");
        }
        other => panic!("Expected CompilerMissing error, got {other:?}"),
    }
}

#[test]
fn test_probe_9_mutated_fixture_rejected_before_evaluation() {
    let root = find_workspace_root();
    let tmp = NamedTempFile::new().unwrap();
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["echo".to_string(), "success".to_string()],
        expected_tests: vec![],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![FixtureRequirement {
            path: "README.md".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        }],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let res = execute_gate_spec(&spec, tmp.path(), &root, None);
    match res {
        Err(GateRunnerError::FixtureCorrupted {
            path,
            expected,
            actual: _,
        }) => {
            assert_eq!(path, "README.md");
            assert_eq!(
                expected,
                "0000000000000000000000000000000000000000000000000000000000000000"
            );
        }
        other => panic!("Expected FixtureCorrupted error, got {other:?}"),
    }
}

#[test]
fn test_probe_10_mutated_result_after_manifest_assembly_rejected() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_one".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let mut result = GateResult {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_one".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let manifest = assemble_release_manifest(
        "rel-1",
        "lua5.4",
        "Lua 5.4.8",
        "1111",
        true,
        &[(result.clone(), spec.clone())],
    )
    .expect("Clean assembly");

    // Mutate result after assembly (e.g. change exit code or platform)
    result.platform = "linux".to_string();

    let verified = verify_release_manifest(&manifest, "1111", &[(result, spec)]);
    assert!(
        matches!(verified, Err(GateRunnerError::TamperDetected(..))),
        "Mutated result must fail manifest verification"
    );
}

#[test]
fn test_probe_11_success_boolean_flip_rejected() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_one".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    // Fraudulent result: exit_code is 1, but success is claimed to be true
    let flipped_result = GateResult {
        schema_version: 1,
        gate_id: "test-gate".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 1,
        success: true, // FLIPPED
        enumerated_tests: vec!["test_one".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let verified = verify_gate_result(&flipped_result, &spec, None, false);
    assert!(
        matches!(verified, Err(GateRunnerError::TamperDetected(..))),
        "Flipped success boolean must be rejected by derived verifier"
    );
}

#[test]
fn test_fixture_manifest_records_complete_provenance() {
    let root = find_workspace_root();
    let manifest_path = root
        .join("tests")
        .join("fixtures")
        .join("precompiled")
        .join("MANIFEST.json");
    assert!(
        manifest_path.exists(),
        "MANIFEST.json must exist at tests/fixtures/precompiled/MANIFEST.json"
    );

    let content = fs::read_to_string(&manifest_path).expect("Failed to read provenance manifest");
    let json: serde_json::Value =
        serde_json::from_str(&content).expect("Valid JSON provenance manifest");

    let fixtures = json["fixtures"].as_array().expect("fixtures array");
    assert_eq!(fixtures.len(), 50, "Must record all 50 fixtures");

    for f in fixtures {
        assert!(f["dialect"].as_str().is_some(), "dialect must be present");
        assert!(
            f["fixture_name"].as_str().is_some(),
            "fixture_name must be present"
        );
        assert!(
            f["source_path"].as_str().is_some(),
            "source_path must be present"
        );
        assert!(
            f["source_sha256"].as_str().is_some(),
            "source_sha256 must be present"
        );
        assert!(
            f["binary_path"].as_str().is_some(),
            "binary_path must be present"
        );
        assert!(
            f["binary_sha256"].as_str().is_some(),
            "binary_sha256 must be present"
        );
        assert!(
            f["byte_length"].as_u64().is_some(),
            "byte_length must be present"
        );
        assert!(
            f["is_stripped"].as_bool().is_some(),
            "is_stripped must be present"
        );
        assert!(
            f["source_archive_url"].as_str().is_some(),
            "source_archive_url must be present"
        );
        assert!(
            f["source_archive_sha256"].as_str().is_some(),
            "source_archive_sha256 must be present"
        );
        assert!(
            f["compiler_binary_sha256"].as_str().is_some(),
            "compiler_binary_sha256 must be present"
        );
        assert!(
            f["target_layout"].as_str().is_some(),
            "target_layout must be present"
        );
        assert!(
            f["generator_revision"].as_str().is_some(),
            "generator_revision must be present"
        );
        assert!(
            f["generation_command"].as_str().is_some(),
            "generation_command must be present"
        );
    }
}
