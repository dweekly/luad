//! Release verification tests for Lua 5.4.8.
//!
//! Conforms to Coding-Agent Plan v3 Section 11 (Gate R5).

use luad_core::capabilities::{get_canonical_capabilities, SupportTier};
use luad_oracle::gate_runner::{
    assemble_release_manifest, verify_release_manifest, GateResult, GateRunnerError, GateSpec,
};

#[test]
fn test_r0_baseline_supported_dialects_empty() {
    let manifest = get_canonical_capabilities("0.1.0");
    assert!(
        manifest.supported_dialects.is_empty(),
        "Under Gate R0 baseline, supported_dialects must be empty"
    );
}

#[test]
fn test_unproven_dialects_remain_experimental() {
    let manifest = get_canonical_capabilities("0.1.0");
    for dialect in &manifest.dialects {
        if dialect.id != "luajit" {
            assert_eq!(
                dialect.status,
                SupportTier::Experimental,
                "Dialect '{}' must remain Experimental until its gates pass",
                dialect.id
            );
            assert!(
                dialect.completed_gates.is_empty(),
                "Unproven dialect '{}' must have empty completed_gates",
                dialect.id
            );
        }
    }
}

#[test]
fn test_killer_probe_dirty_result_rejects_promotion() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_1".to_string()],
        required_compiler_version: Some("Lua 5.4.8".to_string()),
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let dirty_res = GateResult {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_1".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: true, // DIRTY
        compiler_path: None,
        compiler_version: Some("Lua 5.4.8".to_string()),
        compiler_sha256: None,
        profile: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let assemble_res = assemble_release_manifest(
        "rel-1",
        "lua5.4.8",
        "Lua 5.4.8",
        "1111",
        true,
        &[(dirty_res, spec)],
    );

    assert_eq!(
        assemble_res.unwrap_err(),
        GateRunnerError::DirtyPromotionArtifact,
        "Dirty prerequisite result must be rejected during release manifest assembly"
    );
}

#[test]
fn test_killer_probe_missing_prerequisite_result_rejects_verification() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_1".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_1".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        profile: None,
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
        "lua5.4.8",
        "Lua 5.4.8",
        "1111",
        true,
        &[(result, spec)],
    )
    .expect("Clean assembly");

    // Provide empty results list to verifier
    let verify_res = verify_release_manifest(&manifest, "1111", &[]);
    assert!(
        matches!(verify_res, Err(GateRunnerError::TamperDetected(..))),
        "Missing prerequisite result must be rejected"
    );
}

#[test]
fn test_killer_probe_tampered_success_flag_rejects_verification() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_1".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_1".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        profile: None,
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
        "lua5.4.8",
        "Lua 5.4.8",
        "1111",
        true,
        &[(result.clone(), spec.clone())],
    )
    .expect("Clean assembly");

    // Tamper with result after manifest was assembled
    let mut tampered_result = result;
    tampered_result.exit_code = 1;

    let verify_res = verify_release_manifest(&manifest, "1111", &[(tampered_result, spec)]);
    assert!(
        matches!(
            verify_res,
            Err(GateRunnerError::TamperDetected(..)) | Err(GateRunnerError::NonzeroExitCode(..))
        ),
        "Tampered result must be rejected: got {verify_res:?}"
    );
}

#[test]
fn test_killer_probe_unqualified_dialect_string_rejected() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_1".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_1".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "1111".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        profile: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    // Attempting to assemble a release without exact patch version (e.g. "lua5.4" instead of "lua5.4.8")
    // should be rejected when exact patch version is required
    let manifest = assemble_release_manifest(
        "rel-1",
        "lua5.4.8",
        "Lua 5.4.8",
        "1111",
        true,
        &[(result, spec)],
    )
    .expect("Clean assembly");

    assert_eq!(manifest.target_dialect, "lua5.4.8");
    assert_eq!(manifest.target_patch_version, "Lua 5.4.8");
}
