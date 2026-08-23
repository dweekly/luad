//! Executable gate harness and verification runner.
//!
//! Enforces repository gate specifications, clean-revision evidence, and promotion invariants.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Exact specification of an executable gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateSpec {
    pub schema_version: u32,
    pub gate_id: String,
    pub command_argv: Vec<String>,
    pub expected_tests: Vec<String>,
    pub required_compiler_version: Option<String>,
    pub required_compiler_sha256: Option<String>,
    pub required_fixtures: Vec<FixtureRequirement>,
    pub required_profile: Option<String>,
    pub prerequisite_gates: Vec<String>,
    pub allowed_capability_mutations: Vec<String>,
}

impl GateSpec {
    /// Compute canonical SHA-256 hash of this gate specification.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let json_bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        format!("{:x}", hasher.finalize())
    }
}

/// Recorded requirement on a fixture file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixtureRequirement {
    pub path: String,
    pub sha256: String,
}

/// Recorded outcome of executing a gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateResult {
    pub schema_version: u32,
    pub gate_id: String,
    pub spec_hash: String,
    pub command_argv: Vec<String>,
    pub exit_code: i32,
    pub success: bool,
    pub enumerated_tests: Vec<String>,
    pub passed_count: usize,
    pub failed_count: usize,
    pub ignored_count: usize,
    pub missing_expected_tests: Vec<String>,
    pub git_commit: String,
    pub dirty: bool,
    pub compiler_path: Option<String>,
    pub compiler_version: Option<String>,
    pub compiler_sha256: Option<String>,
    pub profile: Option<String>,
    pub fixture_hashes: Vec<FixtureRequirement>,
    pub platform: String,
    pub arch: String,
    pub start_timestamp: String,
    pub end_timestamp: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

impl GateResult {
    /// Compute canonical SHA-256 hash of this recorded gate result.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let json_bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        format!("{:x}", hasher.finalize())
    }
}

/// Immutable release manifest recording closure over verified prerequisite gates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub release_id: String,
    pub target_dialect: String,
    pub target_patch_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_layout: Option<String>,
    pub git_commit: String,
    pub clean: bool,
    pub prerequisite_results: Vec<PrerequisiteResultRef>,
    pub assembled_at: String,
}

/// Reference to a prerequisite gate result and its matching spec.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrerequisiteResultRef {
    pub gate_id: String,
    pub result_sha256: String,
    pub spec_hash: String,
}

impl ReleaseManifest {
    /// Compute the SHA-256 of the release manifest.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let json_bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        format!("{:x}", hasher.finalize())
    }
}

/// Structured report of an adversarial probe rejection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProbeReport {
    pub probe_id: usize,
    pub probe_name: String,
    pub target_failure_mode: String,
    pub rejected: bool,
    pub error_variant: String,
    pub rejection_message: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateRunnerError {
    #[error("Missing command argv for gate '{0}'")]
    MissingCommand(String),
    #[error("Untrusted test runner command '{0}': gates must execute through trusted test runner adapter (cargo test)")]
    UntrustedRunner(String),
    #[error("Nonzero exit code {0} from command: {1:?}")]
    NonzeroExitCode(i32, Vec<String>),
    #[error("Zero tests executed in gate '{0}' (at least one test must execute)")]
    ZeroTestsExecuted(String),
    #[error("Missing expected test(s) in gate '{0}': {1:?}")]
    MissingExpectedTests(String, Vec<String>),
    #[error("Skipped/ignored tests detected ({0} ignored) in gate '{1}'")]
    SkippedTests(usize, String),
    #[error("Failed tests detected ({0} failed) in gate '{1}'")]
    FailedTests(usize, String),
    #[error("Stale source revision: expected {expected}, got {actual}")]
    StaleRevision { expected: String, actual: String },
    #[error("Dirty worktree rejected for release promotion artifact")]
    DirtyPromotionArtifact,
    #[error("Compiler missing at path '{0}'")]
    CompilerMissing(String),
    #[error("Wrong compiler patch version: expected '{expected}', got '{actual}'")]
    WrongCompilerVersion { expected: String, actual: String },
    #[error("Wrong compiler binary hash: expected {expected}, got {actual}")]
    WrongCompilerBinary { expected: String, actual: String },
    #[error("Profile mismatch in result '{gate_id}': expected {expected:?}, got {actual:?}")]
    ProfileMismatch {
        gate_id: String,
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error("Fixture missing or corrupted at '{path}': expected SHA {expected}, got {actual}")]
    FixtureCorrupted {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("Spec hash mismatch in result '{gate_id}': expected {expected}, got {actual}")]
    SpecHashMismatch {
        gate_id: String,
        expected: String,
        actual: String,
    },
    #[error("Prerequisite dialect mismatch: gate '{gate_id}' is incompatible with release target '{target_dialect}'")]
    PrerequisiteDialectMismatch {
        gate_id: String,
        target_dialect: String,
    },
    #[error("Missing target profile or layout for dialect '{target_dialect}': profile={profile:?}, layout={layout:?}")]
    MissingTargetProfileOrLayout {
        target_dialect: String,
        profile: Option<String>,
        layout: Option<String>,
    },
    #[error("Evidence tampering detected in '{0}': {1}")]
    TamperDetected(String, String),
    #[error("IO or parsing error: {0}")]
    Io(String),
}

/// Execute a gate using its formal GateSpec, record the GateResult, and verify it.
pub fn execute_gate_spec(
    spec: &GateSpec,
    output_path: &Path,
    workspace_root: &Path,
    compiler_path: Option<&Path>,
) -> Result<GateResult, GateRunnerError> {
    if spec.command_argv.is_empty() {
        return Err(GateRunnerError::MissingCommand(spec.gate_id.clone()));
    }

    if spec.schema_version != 1 {
        return Err(GateRunnerError::TamperDetected(
            spec.gate_id.clone(),
            format!("Unsupported spec schema version: {}", spec.schema_version),
        ));
    }

    // 1. Verify required fixtures before running tests
    let mut recorded_fixture_hashes = Vec::new();
    for fixture in &spec.required_fixtures {
        let fixture_full_path = workspace_root.join(&fixture.path);
        if !fixture_full_path.exists() {
            return Err(GateRunnerError::FixtureCorrupted {
                path: fixture.path.clone(),
                expected: fixture.sha256.clone(),
                actual: "MISSING".to_string(),
            });
        }
        let bytes = fs::read(&fixture_full_path).map_err(|e| {
            GateRunnerError::Io(format!(
                "Failed to read fixture {:?}: {e}",
                fixture_full_path
            ))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual_sha = format!("{:x}", hasher.finalize());
        if actual_sha != fixture.sha256 {
            return Err(GateRunnerError::FixtureCorrupted {
                path: fixture.path.clone(),
                expected: fixture.sha256.clone(),
                actual: actual_sha,
            });
        }
        recorded_fixture_hashes.push(FixtureRequirement {
            path: fixture.path.clone(),
            sha256: actual_sha,
        });
    }

    // 2. Verify required compiler before running tests
    let mut comp_ver = None;
    let mut comp_sha = None;
    let mut comp_path_str = None;

    if let Some(cp) = compiler_path {
        comp_path_str = Some(cp.to_string_lossy().to_string());
        if !cp.exists() {
            return Err(GateRunnerError::CompilerMissing(
                cp.to_string_lossy().to_string(),
            ));
        }

        let ver_out = Command::new(cp).arg("-v").output().map_err(|e| {
            GateRunnerError::Io(format!("Failed to execute compiler {:?}: {e}", cp))
        })?;
        let v = format!(
            "{}{}",
            String::from_utf8_lossy(&ver_out.stdout),
            String::from_utf8_lossy(&ver_out.stderr)
        );
        let actual_ver = v.trim().to_string();
        comp_ver = Some(actual_ver.clone());

        if let Some(expected_ver) = &spec.required_compiler_version {
            let first_line = actual_ver.lines().next().unwrap_or("").trim();
            let words: Vec<&str> = first_line.split_whitespace().collect();
            let actual_token = if words.len() >= 2 {
                format!("{} {}", words[0], words[1])
            } else {
                first_line.to_string()
            };
            if actual_token != *expected_ver && first_line != expected_ver {
                return Err(GateRunnerError::WrongCompilerVersion {
                    expected: expected_ver.clone(),
                    actual: actual_ver,
                });
            }
        }

        let bytes = fs::read(cp).map_err(|e| {
            GateRunnerError::Io(format!("Failed to read compiler binary {:?}: {e}", cp))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual_sha = format!("{:x}", hasher.finalize());
        comp_sha = Some(actual_sha.clone());

        if let Some(expected_sha) = &spec.required_compiler_sha256 {
            if &actual_sha != expected_sha {
                return Err(GateRunnerError::WrongCompilerBinary {
                    expected: expected_sha.clone(),
                    actual: actual_sha,
                });
            }
        }
    } else if spec.required_compiler_version.is_some() {
        return Err(GateRunnerError::CompilerMissing(
            "Compiler required but no compiler path provided".to_string(),
        ));
    }

    // 3. Trusted test runner validation: arbitrary commands like `printf` or `echo` are rejected
    let prog = &spec.command_argv[0];
    let args = &spec.command_argv[1..];
    if prog != "cargo" || args.is_empty() || args[0] != "test" {
        return Err(GateRunnerError::UntrustedRunner(format!(
            "Command '{prog}' is not a trusted test runner adapter (must be 'cargo test ...')"
        )));
    }

    // 3. Query compiled tests from libtest runner binary using `-- --list`
    let mut list_args: Vec<String> = Vec::new();
    for a in args {
        if a == "--" {
            break;
        }
        list_args.push(a.clone());
    }
    list_args.push("--".to_string());
    list_args.push("--list".to_string());

    let mut list_cmd = Command::new(prog);
    list_cmd.args(&list_args);
    list_cmd.current_dir(workspace_root);

    let list_output = list_cmd.output().map_err(|e| {
        GateRunnerError::Io(format!(
            "Failed to query test list via '{:?}': {e}",
            spec.command_argv
        ))
    })?;

    if !list_output.status.success() {
        return Err(GateRunnerError::NonzeroExitCode(
            list_output.status.code().unwrap_or(-1),
            spec.command_argv.clone(),
        ));
    }

    let list_str = String::from_utf8_lossy(&list_output.stdout);
    let mut compiled_tests = Vec::new();
    for line in list_str.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(": test") {
            if let Some(tname) = trimmed.strip_suffix(": test") {
                compiled_tests.push(tname.trim().to_string());
            }
        }
    }

    let start_timestamp = current_iso_timestamp();

    // 4. Execute test suite
    let mut cmd = Command::new(prog);
    cmd.args(args);
    cmd.current_dir(workspace_root);

    let output = cmd.output().map_err(|e| {
        GateRunnerError::Io(format!(
            "Failed to execute command '{:?}': {e}",
            spec.command_argv
        ))
    })?;

    let end_timestamp = current_iso_timestamp();

    let exit_code = output.status.code().unwrap_or(-1);
    let stdout_bytes = output.stdout;
    let stderr_bytes = output.stderr;

    let mut stdout_hasher = Sha256::new();
    stdout_hasher.update(&stdout_bytes);
    let stdout_sha256 = format!("{:x}", stdout_hasher.finalize());

    let mut stderr_hasher = Sha256::new();
    stderr_hasher.update(&stderr_bytes);
    let stderr_sha256 = format!("{:x}", stderr_hasher.finalize());

    let stdout_str = String::from_utf8_lossy(&stdout_bytes);
    let stderr_str = String::from_utf8_lossy(&stderr_bytes);
    let combined = format!("{stdout_str}\n{stderr_str}");

    // Validate execution output contains genuine cargo libtest runner execution header
    if !combined.contains("Running tests/") && !combined.contains("Running unittests") {
        return Err(GateRunnerError::UntrustedRunner(
            "Test execution output missing cargo libtest execution header".to_string(),
        ));
    }

    // 5. Parse test results and enumerated test names
    let mut enumerated_tests = Vec::new();
    let mut passed_count = 0;
    let mut failed_count = 0;
    let mut ignored_count = 0;

    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("test ")
            && (trimmed.ends_with("... ok")
                || trimmed.ends_with("... FAILED")
                || trimmed.ends_with("... ignored"))
        {
            if let Some(rest) = trimmed.strip_prefix("test ") {
                if let Some(test_name) = rest.split_whitespace().next() {
                    if compiled_tests.contains(&test_name.to_string()) {
                        enumerated_tests.push(test_name.to_string());
                    }
                }
            }
        }

        if trimmed.contains("test result:") {
            if let Some(passed_part) = trimmed.split("passed").next() {
                if let Some(num_str) = passed_part.split_whitespace().last() {
                    if let Ok(n) = num_str.parse::<usize>() {
                        passed_count += n;
                    }
                }
            }
            if trimmed.contains("failed") {
                if let Some(failed_part) = trimmed.split("failed").next() {
                    if let Some(num_str) = failed_part.split_whitespace().last() {
                        if let Ok(n) = num_str.parse::<usize>() {
                            failed_count += n;
                        }
                    }
                }
            }
            if trimmed.contains("ignored") {
                if let Some(ignored_part) = trimmed.split("ignored").next() {
                    if let Some(num_str) = ignored_part.split_whitespace().last() {
                        if let Ok(n) = num_str.parse::<usize>() {
                            ignored_count += n;
                        }
                    }
                }
            }
        }
    }

    // Check missing expected tests
    let mut missing_expected_tests = Vec::new();
    for expected in &spec.expected_tests {
        if !enumerated_tests.contains(expected) {
            missing_expected_tests.push(expected.clone());
        }
    }

    let git_commit = get_current_git_commit(workspace_root);
    let dirty = is_git_dirty(workspace_root);

    let success = exit_code == 0
        && failed_count == 0
        && ignored_count == 0
        && passed_count > 0
        && missing_expected_tests.is_empty();

    let result = GateResult {
        schema_version: 1,
        gate_id: spec.gate_id.clone(),
        spec_hash: spec.compute_hash(),
        command_argv: spec.command_argv.clone(),
        exit_code,
        success,
        enumerated_tests: enumerated_tests.clone(),
        passed_count,
        failed_count,
        ignored_count,
        missing_expected_tests: missing_expected_tests.clone(),
        git_commit,
        dirty,
        compiler_path: comp_path_str,
        compiler_version: comp_ver,
        compiler_sha256: comp_sha,
        profile: spec.required_profile.clone(),
        fixture_hashes: recorded_fixture_hashes,
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        start_timestamp,
        end_timestamp,
        stdout_sha256,
        stderr_sha256,
    };

    // Serialize result and logs
    if let Some(parent) = output_path.parent() {
        let _ = fs::create_dir_all(parent);
        let _ = fs::write(parent.join("stdout.log"), &stdout_bytes);
        let _ = fs::write(parent.join("stderr.log"), &stderr_bytes);
    }
    let json_bytes = serde_json::to_vec_pretty(&result)
        .map_err(|e| GateRunnerError::Io(format!("Failed to serialize GateResult: {e}")))?;
    fs::write(output_path, json_bytes).map_err(|e| {
        GateRunnerError::Io(format!(
            "Failed to write GateResult to {output_path:?}: {e}"
        ))
    })?;

    // Validate execution constraints
    if exit_code != 0 {
        return Err(GateRunnerError::NonzeroExitCode(
            exit_code,
            spec.command_argv.clone(),
        ));
    }

    if passed_count == 0 && enumerated_tests.is_empty() {
        return Err(GateRunnerError::ZeroTestsExecuted(spec.gate_id.clone()));
    }

    if ignored_count > 0 {
        return Err(GateRunnerError::SkippedTests(
            ignored_count,
            spec.gate_id.clone(),
        ));
    }

    if failed_count > 0 {
        return Err(GateRunnerError::FailedTests(
            failed_count,
            spec.gate_id.clone(),
        ));
    }

    if !missing_expected_tests.is_empty() {
        return Err(GateRunnerError::MissingExpectedTests(
            spec.gate_id.clone(),
            missing_expected_tests,
        ));
    }

    Ok(result)
}

/// Verify that a recorded GateResult matches its specification and execution constraints.
pub fn verify_gate_result(
    result: &GateResult,
    spec: &GateSpec,
    expected_git_commit: Option<&str>,
    require_clean: bool,
) -> Result<(), GateRunnerError> {
    if result.schema_version != 1 || spec.schema_version != 1 {
        return Err(GateRunnerError::TamperDetected(
            result.gate_id.clone(),
            format!(
                "Unsupported schema version: result={}, spec={}",
                result.schema_version, spec.schema_version
            ),
        ));
    }

    if result.gate_id != spec.gate_id {
        return Err(GateRunnerError::TamperDetected(
            result.gate_id.clone(),
            format!(
                "Gate ID mismatch: expected '{}', got '{}'",
                spec.gate_id, result.gate_id
            ),
        ));
    }

    let expected_spec_hash = spec.compute_hash();
    if result.spec_hash != expected_spec_hash {
        return Err(GateRunnerError::SpecHashMismatch {
            gate_id: result.gate_id.clone(),
            expected: expected_spec_hash,
            actual: result.spec_hash.clone(),
        });
    }

    if result.command_argv != spec.command_argv {
        return Err(GateRunnerError::TamperDetected(
            result.gate_id.clone(),
            "Command argv mismatch against spec".to_string(),
        ));
    }

    if result.profile != spec.required_profile {
        return Err(GateRunnerError::ProfileMismatch {
            gate_id: result.gate_id.clone(),
            expected: spec.required_profile.clone(),
            actual: result.profile.clone(),
        });
    }

    if result.exit_code != 0 {
        return Err(GateRunnerError::NonzeroExitCode(
            result.exit_code,
            result.command_argv.clone(),
        ));
    }

    if result.ignored_count > 0 {
        return Err(GateRunnerError::SkippedTests(
            result.ignored_count,
            result.gate_id.clone(),
        ));
    }

    if result.failed_count > 0 {
        return Err(GateRunnerError::FailedTests(
            result.failed_count,
            result.gate_id.clone(),
        ));
    }

    if !result.missing_expected_tests.is_empty() {
        return Err(GateRunnerError::MissingExpectedTests(
            result.gate_id.clone(),
            result.missing_expected_tests.clone(),
        ));
    }

    // Runner derived success check: success MUST match actual fields
    let derived_success = result.exit_code == 0
        && result.failed_count == 0
        && result.ignored_count == 0
        && result.passed_count > 0
        && result.missing_expected_tests.is_empty();

    if result.success != derived_success || !result.success {
        return Err(GateRunnerError::TamperDetected(
            result.gate_id.clone(),
            "Result success flag does not match derived execution results".to_string(),
        ));
    }

    for expected in &spec.expected_tests {
        if !result.enumerated_tests.contains(expected) {
            return Err(GateRunnerError::MissingExpectedTests(
                result.gate_id.clone(),
                vec![expected.clone()],
            ));
        }
    }

    // Verify fixture requirements
    for req in &spec.required_fixtures {
        match result.fixture_hashes.iter().find(|f| f.path == req.path) {
            Some(f) if f.sha256 == req.sha256 => {}
            Some(f) => {
                return Err(GateRunnerError::FixtureCorrupted {
                    path: req.path.clone(),
                    expected: req.sha256.clone(),
                    actual: f.sha256.clone(),
                });
            }
            None => {
                return Err(GateRunnerError::FixtureCorrupted {
                    path: req.path.clone(),
                    expected: req.sha256.clone(),
                    actual: "missing".to_string(),
                });
            }
        }
    }

    if let Some(exp_commit) = expected_git_commit {
        if result.git_commit != exp_commit {
            return Err(GateRunnerError::StaleRevision {
                expected: exp_commit.to_string(),
                actual: result.git_commit.clone(),
            });
        }
    }

    if require_clean && result.dirty {
        return Err(GateRunnerError::DirtyPromotionArtifact);
    }

    if let Some(exp_comp_ver) = &spec.required_compiler_version {
        let actual_ver = result.compiler_version.as_deref().unwrap_or("");
        let first_line = actual_ver.lines().next().unwrap_or("").trim();
        let words: Vec<&str> = first_line.split_whitespace().collect();
        let actual_token = if words.len() >= 2 {
            format!("{} {}", words[0], words[1])
        } else {
            first_line.to_string()
        };
        if actual_token != *exp_comp_ver && first_line != exp_comp_ver {
            return Err(GateRunnerError::WrongCompilerVersion {
                expected: exp_comp_ver.clone(),
                actual: actual_ver.to_string(),
            });
        }
    }

    if let Some(exp_comp_sha) = &spec.required_compiler_sha256 {
        let actual_sha = result.compiler_sha256.as_deref().unwrap_or("");
        if actual_sha != exp_comp_sha {
            return Err(GateRunnerError::WrongCompilerBinary {
                expected: exp_comp_sha.clone(),
                actual: actual_sha.to_string(),
            });
        }
    }

    Ok(())
}

/// Assemble a ReleaseManifest from validated prerequisite GateResults.
#[allow(clippy::too_many_arguments)]
pub fn assemble_release_manifest(
    release_id: &str,
    target_dialect: &str,
    target_patch_version: &str,
    target_profile: Option<&str>,
    target_layout: Option<&str>,
    git_commit: &str,
    clean: bool,
    prerequisite_results: &[(GateResult, GateSpec)],
) -> Result<ReleaseManifest, GateRunnerError> {
    if !clean {
        return Err(GateRunnerError::DirtyPromotionArtifact);
    }

    if target_dialect.starts_with("lua5.1") && (target_profile.is_none() || target_layout.is_none())
    {
        return Err(GateRunnerError::MissingTargetProfileOrLayout {
            target_dialect: target_dialect.to_string(),
            profile: target_profile.map(String::from),
            layout: target_layout.map(String::from),
        });
    }

    let mut refs = Vec::new();
    for (result, spec) in prerequisite_results {
        verify_gate_result(result, spec, Some(git_commit), true)?;

        // Validate dialect compatibility of prerequisite gates
        if target_dialect.starts_with("lua5.1") {
            if let Some(req_ver) = &spec.required_compiler_version {
                if !req_ver.contains("5.1") {
                    return Err(GateRunnerError::PrerequisiteDialectMismatch {
                        gate_id: spec.gate_id.clone(),
                        target_dialect: target_dialect.to_string(),
                    });
                }
            }
            if let Some(req_prof) = &spec.required_profile {
                if !req_prof.starts_with("lua5.1") {
                    return Err(GateRunnerError::PrerequisiteDialectMismatch {
                        gate_id: spec.gate_id.clone(),
                        target_dialect: target_dialect.to_string(),
                    });
                }
            }
            if spec.gate_id.contains("lua54")
                || spec.gate_id.contains("lua52")
                || spec.gate_id.contains("lua53")
                || spec.gate_id.contains("lua55")
            {
                return Err(GateRunnerError::PrerequisiteDialectMismatch {
                    gate_id: spec.gate_id.clone(),
                    target_dialect: target_dialect.to_string(),
                });
            }
        } else if target_dialect.starts_with("lua5.4")
            && (spec.gate_id.contains("lua51")
                || spec.gate_id.contains("lua52")
                || spec.gate_id.contains("lua53")
                || spec.gate_id.contains("lua55"))
        {
            return Err(GateRunnerError::PrerequisiteDialectMismatch {
                gate_id: spec.gate_id.clone(),
                target_dialect: target_dialect.to_string(),
            });
        }

        refs.push(PrerequisiteResultRef {
            gate_id: result.gate_id.clone(),
            result_sha256: result.compute_hash(),
            spec_hash: spec.compute_hash(),
        });
    }

    Ok(ReleaseManifest {
        schema_version: 1,
        release_id: release_id.to_string(),
        target_dialect: target_dialect.to_string(),
        target_patch_version: target_patch_version.to_string(),
        target_profile: target_profile.map(|s| s.to_string()),
        target_layout: target_layout.map(|s| s.to_string()),
        git_commit: git_commit.to_string(),
        clean,
        prerequisite_results: refs,
        assembled_at: current_iso_timestamp(),
    })
}

/// Verify an assembled ReleaseManifest against its prerequisite results and specs.
pub fn verify_release_manifest(
    manifest: &ReleaseManifest,
    expected_commit: &str,
    results_and_specs: &[(GateResult, GateSpec)],
) -> Result<(), GateRunnerError> {
    if manifest.schema_version != 1 {
        return Err(GateRunnerError::TamperDetected(
            manifest.release_id.clone(),
            format!(
                "Unsupported manifest schema version: {}",
                manifest.schema_version
            ),
        ));
    }

    if manifest.target_dialect.starts_with("lua5.1")
        && (manifest.target_profile.is_none() || manifest.target_layout.is_none())
    {
        return Err(GateRunnerError::MissingTargetProfileOrLayout {
            target_dialect: manifest.target_dialect.clone(),
            profile: manifest.target_profile.clone(),
            layout: manifest.target_layout.clone(),
        });
    }

    if manifest.git_commit != expected_commit {
        return Err(GateRunnerError::StaleRevision {
            expected: expected_commit.to_string(),
            actual: manifest.git_commit.clone(),
        });
    }

    if !manifest.clean {
        return Err(GateRunnerError::DirtyPromotionArtifact);
    }

    if manifest.prerequisite_results.len() != results_and_specs.len() {
        return Err(GateRunnerError::TamperDetected(
            manifest.release_id.clone(),
            format!(
                "Prerequisite count mismatch: manifest has {}, provided {}",
                manifest.prerequisite_results.len(),
                results_and_specs.len()
            ),
        ));
    }

    for (result, spec) in results_and_specs {
        verify_gate_result(result, spec, Some(expected_commit), true)?;

        let prereq_ref = manifest
            .prerequisite_results
            .iter()
            .find(|r| r.gate_id == result.gate_id)
            .ok_or_else(|| {
                GateRunnerError::TamperDetected(
                    manifest.release_id.clone(),
                    format!("Missing prerequisite result '{}'", result.gate_id),
                )
            })?;

        let actual_res_hash = result.compute_hash();
        if actual_res_hash != prereq_ref.result_sha256 {
            return Err(GateRunnerError::TamperDetected(
                manifest.release_id.clone(),
                format!(
                    "Result hash mismatch for '{}': expected {}, got {}",
                    prereq_ref.gate_id, prereq_ref.result_sha256, actual_res_hash
                ),
            ));
        }

        let actual_spec_hash = spec.compute_hash();
        if actual_spec_hash != prereq_ref.spec_hash {
            return Err(GateRunnerError::TamperDetected(
                manifest.release_id.clone(),
                format!(
                    "Spec hash mismatch for '{}': expected {}, got {}",
                    prereq_ref.gate_id, prereq_ref.spec_hash, actual_spec_hash
                ),
            ));
        }

        // Prerequisite closure: check that every gate required by this spec is present in manifest
        for required_prereq_id in &spec.prerequisite_gates {
            if !manifest
                .prerequisite_results
                .iter()
                .any(|r| &r.gate_id == required_prereq_id)
            {
                return Err(GateRunnerError::TamperDetected(
                    manifest.release_id.clone(),
                    format!(
                        "Prerequisite closure broken: gate '{}' requires '{}' which is missing from manifest",
                        spec.gate_id, required_prereq_id
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Execute all adversarial probes against production verification logic and record structured reports.
pub fn record_all_adversarial_probes(
    workspace_root: &Path,
    out_path: &Path,
) -> Result<Vec<ProbeReport>, GateRunnerError> {
    let mut reports = Vec::new();

    // Probe 1: Zero tests executed (echo success)
    let spec1 = GateSpec {
        schema_version: 1,
        gate_id: "probe-1-zero-tests".to_string(),
        command_argv: vec!["echo".to_string(), "success".to_string()],
        expected_tests: vec![],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };
    let tmp_out1 = tempfile::NamedTempFile::new().unwrap();
    let res1 = execute_gate_spec(&spec1, tmp_out1.path(), workspace_root, None);
    reports.push(ProbeReport {
        probe_id: 1,
        probe_name: "probe_1_zero_tests_executed_rejected".to_string(),
        target_failure_mode: "Untrusted command (echo) rejected by trusted runner adapter"
            .to_string(),
        rejected: res1.is_err(),
        error_variant: format!("{:?}", res1.as_ref().err().unwrap()),
        rejection_message: res1.err().unwrap().to_string(),
    });

    // Probe 2: Nonexistent test filter
    let spec2 = GateSpec {
        schema_version: 1,
        gate_id: "probe-2-nonexistent-filter".to_string(),
        command_argv: vec![
            "cargo".to_string(),
            "test".to_string(),
            "-p".to_string(),
            "luad-oracle".to_string(),
            "--test".to_string(),
            "test_gate_harness".to_string(),
            "--".to_string(),
            "nonexistent_filter_xyz_123".to_string(),
        ],
        expected_tests: vec!["test_probe_1_zero_tests_executed_rejected".to_string()],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };
    let tmp_out2 = tempfile::NamedTempFile::new().unwrap();
    let res2 = execute_gate_spec(&spec2, tmp_out2.path(), workspace_root, None);
    reports.push(ProbeReport {
        probe_id: 2,
        probe_name: "probe_2_nonexistent_test_filter_rejected".to_string(),
        target_failure_mode: "Nonexistent test filter executes zero matching tests".to_string(),
        rejected: res2.is_err(),
        error_variant: format!("{:?}", res2.as_ref().err().unwrap()),
        rejection_message: res2.err().unwrap().to_string(),
    });

    // Probe 3: Ignored/skipped required test
    let mut fake_res3 = mock_valid_result("probe-3-ignored");
    fake_res3.ignored_count = 1;
    let spec3 = mock_valid_spec("probe-3-ignored");
    fake_res3.spec_hash = spec3.compute_hash();
    let res3 = verify_gate_result(&fake_res3, &spec3, None, false);
    reports.push(ProbeReport {
        probe_id: 3,
        probe_name: "probe_3_ignored_test_rejected".to_string(),
        target_failure_mode: "Gate result records ignored/skipped test count > 0".to_string(),
        rejected: res3.is_err(),
        error_variant: format!("{:?}", res3.as_ref().err().unwrap()),
        rejection_message: res3.err().unwrap().to_string(),
    });

    // Probe 4: Stale git commit
    let fake_res4 = mock_valid_result("probe-4-stale-commit");
    let spec4 = mock_valid_spec("probe-4-stale-commit");
    let res4 = verify_gate_result(
        &fake_res4,
        &spec4,
        Some("deadbeef00000000000000000000000000000000"),
        false,
    );
    reports.push(ProbeReport {
        probe_id: 4,
        probe_name: "probe_4_stale_git_commit_rejected".to_string(),
        target_failure_mode: "Result git commit does not match expected source revision"
            .to_string(),
        rejected: res4.is_err(),
        error_variant: format!("{:?}", res4.as_ref().err().unwrap()),
        rejection_message: res4.err().unwrap().to_string(),
    });

    // Probe 5: Dirty result rejected for promotion
    let mut fake_res5 = mock_valid_result("probe-5-dirty");
    fake_res5.dirty = true;
    let spec5 = mock_valid_spec("probe-5-dirty");
    fake_res5.spec_hash = spec5.compute_hash();
    let res5 = verify_gate_result(&fake_res5, &spec5, None, true);
    reports.push(ProbeReport {
        probe_id: 5,
        probe_name: "probe_5_dirty_result_rejected_for_promotion".to_string(),
        target_failure_mode: "Result records dirty working tree when require_clean is true"
            .to_string(),
        rejected: res5.is_err(),
        error_variant: format!("{:?}", res5.as_ref().err().unwrap()),
        rejection_message: res5.err().unwrap().to_string(),
    });

    // Probe 6: Wrong compiler binary SHA-256
    let fake_res6 = mock_valid_result("probe-6-wrong-comp-sha");
    let mut spec6 = mock_valid_spec("probe-6-wrong-comp-sha");
    spec6.required_compiler_sha256 =
        Some("1111111111111111111111111111111111111111111111111111111111111111".to_string());
    let mut fake_res6_mut = fake_res6.clone();
    fake_res6_mut.spec_hash = spec6.compute_hash();
    fake_res6_mut.compiler_sha256 =
        Some("2222222222222222222222222222222222222222222222222222222222222222".to_string());
    let res6 = verify_gate_result(&fake_res6_mut, &spec6, None, false);
    reports.push(ProbeReport {
        probe_id: 6,
        probe_name: "probe_6_wrong_compiler_binary_sha256_rejected".to_string(),
        target_failure_mode: "Compiler binary SHA-256 does not match spec required hash"
            .to_string(),
        rejected: res6.is_err(),
        error_variant: format!("{:?}", res6.as_ref().err().unwrap()),
        rejection_message: res6.err().unwrap().to_string(),
    });

    // Probe 7: Wrong compiler patch version
    let fake_res7 = mock_valid_result("probe-7-wrong-comp-ver");
    let mut spec7 = mock_valid_spec("probe-7-wrong-comp-ver");
    spec7.required_compiler_version = Some("Lua 5.4.8".to_string());
    let mut fake_res7_mut = fake_res7.clone();
    fake_res7_mut.spec_hash = spec7.compute_hash();
    fake_res7_mut.compiler_version = Some("Lua 5.4.7".to_string());
    let res7 = verify_gate_result(&fake_res7_mut, &spec7, None, false);
    reports.push(ProbeReport {
        probe_id: 7,
        probe_name: "probe_7_wrong_compiler_version_rejected".to_string(),
        target_failure_mode:
            "Compiler version string does not exactly match required patch version".to_string(),
        rejected: res7.is_err(),
        error_variant: format!("{:?}", res7.as_ref().err().unwrap()),
        rejection_message: res7.err().unwrap().to_string(),
    });

    // Probe 8: Missing compiler before tests run
    let spec8 = GateSpec {
        schema_version: 1,
        gate_id: "probe-8-missing-comp".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec![],
        required_compiler_version: Some("Lua 5.4.8".to_string()),
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };
    let tmp_out8 = tempfile::NamedTempFile::new().unwrap();
    let res8 = execute_gate_spec(
        &spec8,
        tmp_out8.path(),
        workspace_root,
        Some(Path::new("/tmp/nonexistent_luac_binary_probe8")),
    );
    reports.push(ProbeReport {
        probe_id: 8,
        probe_name: "probe_8_missing_compiler_rejected_before_tests".to_string(),
        target_failure_mode: "Required compiler binary is missing from filesystem before execution"
            .to_string(),
        rejected: res8.is_err(),
        error_variant: format!("{:?}", res8.as_ref().err().unwrap()),
        rejection_message: res8.err().unwrap().to_string(),
    });

    // Probe 9: Mutated fixture byte
    let spec9 = GateSpec {
        schema_version: 1,
        gate_id: "probe-9-fixture-corrupt".to_string(),
        command_argv: vec!["cargo".to_string(), "test".to_string()],
        expected_tests: vec![],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![FixtureRequirement {
            path: "tests/fixtures/hello.lua".to_string(),
            sha256: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        }],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };
    let tmp_out9 = tempfile::NamedTempFile::new().unwrap();
    let res9 = execute_gate_spec(&spec9, tmp_out9.path(), workspace_root, None);
    reports.push(ProbeReport {
        probe_id: 9,
        probe_name: "probe_9_mutated_fixture_rejected_before_evaluation".to_string(),
        target_failure_mode: "Fixture SHA-256 does not match spec requirement before evaluation"
            .to_string(),
        rejected: res9.is_err(),
        error_variant: format!("{:?}", res9.as_ref().err().unwrap()),
        rejection_message: res9.err().unwrap().to_string(),
    });

    // Probe 10: Mutated result after manifest assembly
    let fake_res10 = mock_valid_result("probe-10-manifest-tamper");
    let spec10 = mock_valid_spec("probe-10-manifest-tamper");
    let mut fake_res10_clean = fake_res10.clone();
    fake_res10_clean.spec_hash = spec10.compute_hash();
    let manifest10 = assemble_release_manifest(
        "checkpoint-probe10",
        "proof-harness-checkpoint-r1",
        "R1-Harness-v1",
        None,
        None,
        "feedface00000000000000000000000000000000",
        true,
        &[(fake_res10_clean.clone(), spec10.clone())],
    )
    .unwrap();
    let mut tampered_res10 = fake_res10_clean.clone();
    tampered_res10.passed_count = 999;
    let res10 = verify_release_manifest(
        &manifest10,
        "feedface00000000000000000000000000000000",
        &[(tampered_res10, spec10)],
    );
    reports.push(ProbeReport {
        probe_id: 10,
        probe_name: "probe_10_mutated_result_after_manifest_assembly_rejected".to_string(),
        target_failure_mode: "Gate result hash tampered after ReleaseManifest assembly".to_string(),
        rejected: res10.is_err(),
        error_variant: format!("{:?}", res10.as_ref().err().unwrap()),
        rejection_message: res10.err().unwrap().to_string(),
    });

    // Probe 11: Flipped success boolean
    let mut fake_res11 = mock_valid_result("probe-11-boolean-flip");
    fake_res11.exit_code = 1;
    fake_res11.failed_count = 1;
    fake_res11.success = true; // In-memory tamper
    let spec11 = mock_valid_spec("probe-11-boolean-flip");
    fake_res11.spec_hash = spec11.compute_hash();
    let res11 = verify_gate_result(&fake_res11, &spec11, None, false);
    reports.push(ProbeReport {
        probe_id: 11,
        probe_name: "probe_11_success_boolean_flip_rejected".to_string(),
        target_failure_mode:
            "Flipped in-memory success boolean contradicts nonzero exit/failure count".to_string(),
        rejected: res11.is_err(),
        error_variant: format!("{:?}", res11.as_ref().err().unwrap()),
        rejection_message: res11.err().unwrap().to_string(),
    });

    // Probe 12: printf spoofed libtest output
    let spec12 = GateSpec {
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
    let tmp_out12 = tempfile::NamedTempFile::new().unwrap();
    let res12 = execute_gate_spec(&spec12, tmp_out12.path(), workspace_root, None);
    reports.push(ProbeReport {
        probe_id: 12,
        probe_name: "probe_12_printf_spoofed_libtest_output_rejected".to_string(),
        target_failure_mode:
            "Untrusted command (printf) attempting to forge libtest output rejected".to_string(),
        rejected: res12.is_err(),
        error_variant: format!("{:?}", res12.as_ref().err().unwrap()),
        rejection_message: res12.err().unwrap().to_string(),
    });

    if let Some(parent) = out_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json_bytes = serde_json::to_vec_pretty(&reports)
        .map_err(|e| GateRunnerError::Io(format!("Failed to serialize probe reports: {e}")))?;
    fs::write(out_path, json_bytes).map_err(|e| {
        GateRunnerError::Io(format!(
            "Failed to write probe reports to {out_path:?}: {e}"
        ))
    })?;

    Ok(reports)
}

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

pub fn get_current_git_commit(workspace_root: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(workspace_root)
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn is_git_dirty(workspace_root: &Path) -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(workspace_root)
        .output()
        .ok()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false)
}

pub fn current_iso_timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs = now % 60;
    let mins = (now / 60) % 60;
    let hours = (now / 3600) % 24;
    let mut days = (now / 86400) as i64;

    let mut year = 1970;
    loop {
        let leap = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
            1
        } else {
            0
        };
        let days_in_year = 365 + leap;
        if days >= days_in_year {
            days -= days_in_year;
            year += 1;
        } else {
            break;
        }
    }

    let leap = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) {
        1
    } else {
        0
    };
    let month_days = [31, 28 + leap, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1;
    for &md in &month_days {
        if days >= md as i64 {
            days -= md as i64;
            month += 1;
        } else {
            break;
        }
    }
    let day = days + 1;

    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z")
}
