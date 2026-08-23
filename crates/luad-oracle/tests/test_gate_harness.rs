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

fn mock_valid_spec(gate_id: &str) -> GateSpec {
    GateSpec {
        schema_version: 1,
        gate_id: gate_id.to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec!["test_sample".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    }
}

fn mock_valid_result(gate_id: &str) -> GateResult {
    let spec = mock_valid_spec(gate_id);
    GateResult {
        schema_version: 1,
        gate_id: gate_id.to_string(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv,
        exit_code: 0,
        success: true,
        enumerated_tests: vec!["test_sample".to_string()],
        passed_count: 1,
        failed_count: 0,
        ignored_count: 0,
        missing_expected_tests: vec![],
        git_commit: "feedface00000000000000000000000000000000".to_string(),
        dirty: false,
        compiler_path: None,
        compiler_version: None,
        compiler_sha256: None,
        profile: None,
        fixture_hashes: vec![],
        platform: "macos".to_string(),
        arch: "aarch64".to_string(),
        start_timestamp: "2026-08-22T12:00:00Z".to_string(),
        end_timestamp: "2026-08-22T12:00:01Z".to_string(),
        stdout_sha256: "abc".to_string(),
        stderr_sha256: "def".to_string(),
    }
}

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
    assert!(
        matches!(
            res,
            Err(GateRunnerError::UntrustedRunner(..)) | Err(GateRunnerError::ZeroTestsExecuted(..))
        ),
        "Echo command must be rejected by trusted runner adapter: got {res:?}"
    );
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
    let spec = mock_valid_spec("probe-3-ignored");
    let mut fake_res = mock_valid_result("probe-3-ignored");
    fake_res.ignored_count = 1;
    fake_res.spec_hash = spec.compute_hash();
    fake_res.success = false;
    let res = verify_gate_result(&fake_res, &spec, None, false);
    match res {
        Err(GateRunnerError::SkippedTests(skipped, id)) => {
            assert_eq!(skipped, 1);
            assert_eq!(id, "probe-3-ignored");
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
        profile: None,
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
        profile: None,
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
        profile: None,
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
        profile: None,
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
        profile: None,
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
        matches!(
            verified,
            Err(GateRunnerError::TamperDetected(..))
                | Err(GateRunnerError::NonzeroExitCode(..))
                | Err(GateRunnerError::FailedTests(..))
        ),
        "Flipped success boolean must be rejected by verifier: got {verified:?}"
    );
}

#[test]
fn test_probe_12_printf_spoofed_libtest_output_rejected() {
    let root = find_workspace_root();
    let tmp = NamedTempFile::new().unwrap();
    let spec = GateSpec {
        schema_version: 1,
        gate_id: "probe-12-printf-spoof".to_string(),
        command_argv: vec![
            "printf".to_string(),
            "test fake_required_test ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored\n"
                .to_string(),
        ],
        expected_tests: vec!["fake_required_test".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };

    let res = execute_gate_spec(&spec, tmp.path(), &root, None);
    assert!(
        matches!(res, Err(GateRunnerError::UntrustedRunner(..))),
        "Printf spoofing libtest output must be rejected by trusted runner adapter: got {res:?}"
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

    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    for f in fixtures {
        assert!(f["dialect"].as_str().is_some(), "dialect must be present");
        assert!(
            f["fixture_name"].as_str().is_some(),
            "fixture_name must be present"
        );

        let src_path = f["source_path"].as_str().expect("source_path string");
        assert!(
            root.join(src_path).exists(),
            "source_path file must exist on disk"
        );

        let bin_path = f["binary_path"].as_str().expect("binary_path string");
        assert!(
            root.join(bin_path).exists(),
            "binary_path file must exist on disk"
        );

        let src_sha = f["source_sha256"].as_str().expect("source_sha256 string");
        assert_ne!(src_sha, empty_hash, "source_sha256 must not be empty hash");

        let bin_sha = f["binary_sha256"].as_str().expect("binary_sha256 string");
        assert_ne!(bin_sha, empty_hash, "binary_sha256 must not be empty hash");

        let byte_len = f["byte_length"].as_u64().expect("byte_length number");
        assert!(byte_len > 0, "byte_length must be > 0");

        assert!(
            f["is_stripped"].as_bool().is_some(),
            "is_stripped must be boolean"
        );

        let arc_url = f["source_archive_url"]
            .as_str()
            .expect("source_archive_url string");
        assert!(
            arc_url.starts_with("https://www.lua.org/"),
            "source_archive_url must be official lua.org URL"
        );

        let arc_sha = f["source_archive_sha256"]
            .as_str()
            .expect("source_archive_sha256 string");
        let dialect = f["dialect"].as_str().expect("dialect string");
        let expected_archive_sha = match dialect {
            "lua51" => "2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333",
            "lua52" => "b9e2e4aad6789b3b63a056d442f7b39f0ecfca3ae0f1fc0ae4e9614401b69f4b",
            "lua53" => "fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60",
            "lua54" => "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
            "lua55" => "1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce",
            other => panic!("Unknown dialect in fixture manifest: {other}"),
        };
        assert_eq!(
            arc_sha, expected_archive_sha,
            "source_archive_sha256 for {dialect} must match authoritative official lua.org release hash"
        );

        let comp_sha = f["compiler_binary_sha256"]
            .as_str()
            .expect("compiler_binary_sha256 string");
        let expected_compiler_sha = match dialect {
            "lua51" => "eb8251b1f15553447f0978e5b783d69667863b7acfd929c9521dad21d13c9239",
            "lua52" => "f9c391541b15f620a50bf07f729e3c72dd63aa5af0bad3722a939673588d6c0b",
            "lua53" => "f78a04d412ca144c8aefe0275f74c5cde4dc83225996a71575be66ce581cfaa1",
            "lua54" => "5a1fb31d912159030a60894276606914f51a186a69aecc1cd92d6619bb2fa80f",
            "lua55" => "2e916949110e641c3aee9922e79d4d4f8e48e0fcfcc42cc5316721bed2cb34e0",
            other => panic!("Unknown dialect in fixture manifest: {other}"),
        };
        assert_eq!(
            comp_sha, expected_compiler_sha,
            "compiler_binary_sha256 for {dialect} must match genuine compiler binary hash"
        );

        let comp_ver = f["compiler_version"]
            .as_str()
            .expect("compiler_version string");
        assert!(
            comp_ver.starts_with("Lua 5."),
            "compiler_version must be official version string"
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

#[test]
fn test_all_canonical_gate_scripts_and_specs_consistency() {
    let root = find_workspace_root();
    let scripts_dir = root.join("scripts").join("gates");
    let specs_dir = root.join("tests").join("gates");

    assert!(scripts_dir.exists(), "scripts/gates directory must exist");
    assert!(specs_dir.exists(), "tests/gates directory must exist");

    let mut script_gates = std::collections::BTreeSet::new();
    for entry in fs::read_dir(&scripts_dir).expect("Read scripts/gates") {
        let entry = entry.expect("Valid entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("sh") {
            let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
            script_gates.insert(stem);
        }
    }

    let mut spec_gates = std::collections::BTreeSet::new();
    let mut all_specs = Vec::new();
    for entry in fs::read_dir(&specs_dir).expect("Read tests/gates") {
        let entry = entry.expect("Valid entry");
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
            let content = fs::read_to_string(&path).expect("Read spec file");
            let spec: GateSpec = serde_json::from_str(&content)
                .unwrap_or_else(|e| panic!("Failed to parse {stem}.json: {e}"));
            assert_eq!(
                spec.gate_id, stem,
                "gate_id inside {stem}.json must match filename stem"
            );
            assert_eq!(
                spec.schema_version, 1,
                "schema_version in {stem}.json must be 1"
            );
            assert!(
                !spec.expected_tests.is_empty(),
                "expected_tests in {stem}.json must not be empty"
            );
            spec_gates.insert(stem);
            all_specs.push(spec);
        }
    }

    // Exact 1-to-1 matching
    assert_eq!(
        script_gates, spec_gates,
        "scripts/gates and tests/gates must have exact 1-to-1 matching gate sets"
    );

    // Verify prerequisite gate integrity
    for spec in &all_specs {
        for prereq in &spec.prerequisite_gates {
            assert!(
                spec_gates.contains(prereq),
                "Prerequisite gate '{prereq}' referenced in '{}' does not exist in canonical gate set",
                spec.gate_id
            );
        }
    }

    // Verify required plan probes appear in each specification
    for spec in &all_specs {
        match spec.gate_id.as_str() {
            "gate-proof-harness" => {
                let required_probes = [
                    "test_probe_1_zero_tests_executed_rejected",
                    "test_probe_2_nonexistent_test_filter_rejected",
                    "test_probe_3_ignored_test_rejected",
                    "test_probe_4_stale_git_commit_rejected",
                    "test_probe_5_dirty_result_rejected_for_promotion",
                    "test_probe_6_wrong_compiler_binary_sha256_rejected",
                    "test_probe_7_wrong_compiler_version_rejected",
                    "test_probe_8_missing_compiler_rejected_before_tests",
                    "test_probe_9_mutated_fixture_rejected_before_evaluation",
                    "test_probe_10_mutated_result_after_manifest_assembly_rejected",
                    "test_probe_11_success_boolean_flip_rejected",
                    "test_probe_12_printf_spoofed_libtest_output_rejected",
                    "test_fixture_manifest_records_complete_provenance",
                    "test_all_canonical_gate_scripts_and_specs_consistency",
                ];
                for probe in required_probes {
                    assert!(
                        spec.expected_tests.contains(&probe.to_string()),
                        "gate-proof-harness spec missing required probe '{probe}'"
                    );
                }
            }
            "gate-facts-lua54-8" => {
                let required_probes = [
                    "test_all_10_fixtures_lua54_against_differential_oracle",
                    "test_negative_control_signed_immediate_offset_sb",
                    "test_negative_control_bit15_b_decoder_bug",
                    "test_negative_control_jmp_comment_changed_to_arbitrary_text_rejected",
                    "test_negative_control_jmp_comment_changed_to_wrong_target_rejected",
                    "test_negative_control_malformed_zero_valued_field_rejected",
                    "test_negative_control_recognized_unconsumed_field_sweep",
                    "test_negative_control_string_constant_exact_formatting_required",
                    "test_negative_control_signed_zero_float_exact",
                    "test_negative_control_missing_constant_tag_rejected",
                    "test_negative_control_missing_upvalue_columns_rejected",
                ];
                for probe in required_probes {
                    assert!(
                        spec.expected_tests.contains(&probe.to_string()),
                        "gate-facts-lua54-8 spec missing required probe '{probe}'"
                    );
                }
            }
            "gate-public-disasm-lua54-8" => {
                let required_probes = [
                    "test_three_way_agreement_on_all_10_fixtures",
                    "test_exact_signed_immediate_and_control_flow_goldens",
                    "test_killer_probe_signed_operand_mutation_rejected_by_comparator",
                    "test_killer_probe_independent_decoder_mutation_rejected_by_comparator",
                    "test_killer_probe_missing_jump_target_rejected_by_comparator",
                    "test_killer_probe_missing_source_line_rejected_by_comparator",
                    "test_killer_probe_missing_k_flag_rejected_by_comparator",
                    "test_killer_probe_json_mutation_rejected_by_comparator",
                    "test_killer_probe_text_renderer_mutation_rejected_by_golden",
                    "test_killer_probe_unknown_opcode_produces_structured_diagnostic",
                    "test_killer_probe_oob_constant_reference_emits_diagnostic",
                    "test_cli_disasm_json_and_text_goldens",
                ];
                for probe in required_probes {
                    assert!(
                        spec.expected_tests.contains(&probe.to_string()),
                        "gate-public-disasm-lua54-8 spec missing required probe '{probe}'"
                    );
                }
            }
            "gate-release-lua54-8" => {
                let required_probes = [
                    "test_killer_probe_dirty_result_rejects_promotion",
                    "test_killer_probe_unqualified_dialect_string_rejected",
                    "test_killer_probe_tampered_success_flag_rejects_verification",
                    "test_killer_probe_missing_prerequisite_result_rejects_verification",
                    "test_r0_baseline_supported_dialects_empty",
                    "test_unproven_dialects_remain_experimental",
                ];
                for probe in required_probes {
                    assert!(
                        spec.expected_tests.contains(&probe.to_string()),
                        "gate-release-lua54-8 spec missing required probe '{probe}'"
                    );
                }
            }
            _ => (),
        }
    }
}
