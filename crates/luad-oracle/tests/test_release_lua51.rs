//! Release verification tests for embedded Lua 5.1 and exact profiles (Gate REL51).
//!
//! Asserts that Lua 5.1 release manifests strictly verify against clean, target-separated
//! prerequisites without inheriting Lua 5.4 results or permitting dirty/tampered artifacts.

use luad_oracle::gate_runner::{
    assemble_release_manifest, verify_release_manifest, GateResult, GateRunnerError, GateSpec,
};

#[test]
fn test_lua51_release_manifest_rejects_dirty_promotion_artifact() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "gate-public-disasm-lua51".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_1".to_string()],
        required_compiler_version: Some("5.1.5".to_string()),
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: Some("lua5.1".to_string()),
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let dirty_res = GateResult {
        schema_version: 1,
        gate_id: "gate-public-disasm-lua51".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_1".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "2222".to_string(),
        dirty: true,
        compiler_path: None,
        compiler_version: Some("5.1.5".to_string()),
        compiler_sha256: None,
        profile: Some("lua5.1".to_string()),
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let assemble_res = assemble_release_manifest(
        "rel-lua51",
        "lua5.1.5",
        "5.1.5",
        Some("lua5.1"),
        Some("int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0"),
        "2222",
        true,
        &[(dirty_res, spec)],
    );

    assert_eq!(
        assemble_res.unwrap_err(),
        GateRunnerError::DirtyPromotionArtifact,
        "Dirty prerequisite result must be rejected during Lua 5.1 release manifest assembly"
    );
}

#[test]
fn test_lua51_release_manifest_requires_exact_profile_and_prerequisites() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "gate-profile-lua51-lnum".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_lnum".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: Some("lua5.1-lnum32".to_string()),
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "gate-profile-lua51-lnum".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_lnum".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "2222".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        profile: Some("lua5.1-lnum32".to_string()),
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    let manifest = assemble_release_manifest(
        "rel-lua51",
        "lua5.1.5",
        "5.1.5",
        Some("lua5.1-lnum32"),
        Some("int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4"),
        "2222",
        true,
        &[(result.clone(), spec.clone())],
    )
    .expect("Clean assembly");

    assert_eq!(manifest.target_profile.as_deref(), Some("lua5.1-lnum32"));
    assert_eq!(
        manifest.target_layout.as_deref(),
        Some("int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4")
    );
    let verify_res = verify_release_manifest(&manifest, "2222", &[(result, spec)]);
    assert!(
        verify_res.is_ok(),
        "Clean Lua 5.1 release manifest must verify"
    );
}

#[test]
fn test_lua51_release_manifest_rejects_missing_target_profile_or_layout() {
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "gate-profile-lua51-lnum".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_lnum".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: Some("lua5.1-lnum32".to_string()),
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let result = GateResult {
        schema_version: 1,
        gate_id: "gate-profile-lua51-lnum".to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_lnum".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "2222".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        profile: Some("lua5.1-lnum32".to_string()),
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "arm64".to_string(),
        start_timestamp: "0".to_string(),
        end_timestamp: "1".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    };

    // 1. Missing target_profile
    let res_no_profile = assemble_release_manifest(
        "rel-lua51",
        "lua5.1.5",
        "5.1.5",
        None,
        Some("int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4"),
        "2222",
        true,
        &[(result.clone(), spec.clone())],
    );
    assert!(matches!(
        res_no_profile,
        Err(GateRunnerError::MissingTargetProfileOrLayout { .. })
    ));

    // 2. Missing target_layout
    let res_no_layout = assemble_release_manifest(
        "rel-lua51",
        "lua5.1.5",
        "5.1.5",
        Some("lua5.1-lnum32"),
        None,
        "2222",
        true,
        &[(result, spec)],
    );
    assert!(matches!(
        res_no_layout,
        Err(GateRunnerError::MissingTargetProfileOrLayout { .. })
    ));
}

#[test]
fn test_lua51_release_manifest_rejects_lua54_prerequisite_substitution() {
    let spec54 = GateSpec {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_54".to_string()],
        required_compiler_version: Some("5.4.8".to_string()),
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let res54 = GateResult {
        schema_version: 1,
        gate_id: "gate-facts-lua54-8".to_string(),
        spec_hash: spec54.compute_hash(),
        command_argv: spec54.command_argv.clone(),
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_54".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "2222".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: Some("5.4.8".to_string()),
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

    // Attempting to assemble a Lua 5.1 release manifest using Lua 5.4 gates must fail with PrerequisiteDialectMismatch
    let assemble_res = assemble_release_manifest(
        "rel-lua51",
        "lua5.1.5",
        "5.1.5",
        Some("lua5.1"),
        Some("int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0"),
        "2222",
        true,
        &[(res54, spec54)],
    );

    assert!(
        matches!(
            assemble_res,
            Err(GateRunnerError::PrerequisiteDialectMismatch { .. })
        ),
        "Lua 5.4 gates must be rejected when assembling a Lua 5.1 release manifest"
    );
}
