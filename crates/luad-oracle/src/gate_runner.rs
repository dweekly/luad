//! Executable gate harness and versioned gate-result schema.
//!
//! Provides deterministic gate execution, artifact recording, release manifest assembly,
//! and tamper detection conforming to Coding-Agent Plan v3 Section 4 & 7.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Exact requirement for a fixture file used in a gate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixtureRequirement {
    /// Relative path from workspace root.
    pub path: String,
    /// Expected SHA-256 hex string of fixture content.
    pub sha256: String,
}

/// Versioned schema for gate specifications.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateSpec {
    /// Schema version for gate specifications (always 1).
    pub schema_version: u32,
    /// Unique gate identifier (e.g. `gate-facts-lua54-8`).
    pub gate_id: String,
    /// Exact command argv array (never a whitespace-split shell string).
    pub command_argv: Vec<String>,
    /// Exact test names expected to execute in this gate.
    pub expected_tests: Vec<String>,
    /// Required compiler version string (e.g. `Lua 5.4.8`).
    pub required_compiler_version: Option<String>,
    /// Required compiler binary SHA-256 hex string.
    pub required_compiler_sha256: Option<String>,
    /// Required fixtures and their exact SHA-256 values.
    pub required_fixtures: Vec<FixtureRequirement>,
    /// Required profile/layout identifier if applicable.
    pub required_profile: Option<String>,
    /// Prerequisite gate IDs.
    pub prerequisite_gates: Vec<String>,
    /// Exact capability fields this gate is allowed to mutate.
    pub allowed_capability_mutations: Vec<String>,
}

impl GateSpec {
    /// Compute the canonical SHA-256 hash of this specification.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let json_bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        format!("{:x}", hasher.finalize())
    }
}

/// Versioned schema for gate execution results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateResult {
    /// Schema version for gate results (always 1).
    pub schema_version: u32,
    /// Unique gate identifier.
    pub gate_id: String,
    /// Canonical SHA-256 hash of the GateSpec that generated this result.
    pub spec_hash: String,
    /// Exact command argv executed.
    pub command_argv: Vec<String>,
    /// Process exit code.
    pub exit_code: i32,
    /// Success flag derived strictly by the runner.
    pub success: bool,
    /// Exact enumerated test names executed.
    pub enumerated_tests: Vec<String>,
    /// Number of tests that passed.
    pub passed_count: usize,
    /// Number of tests that failed.
    pub failed_count: usize,
    /// Number of tests that were ignored/skipped.
    pub ignored_count: usize,
    /// Expected tests that did not execute.
    pub missing_expected_tests: Vec<String>,
    /// Git commit SHA at time of execution.
    pub git_commit: String,
    /// Whether the git worktree had uncommitted changes.
    pub dirty: bool,
    /// Target compiler path.
    pub compiler_path: Option<String>,
    /// Target compiler version string.
    pub compiler_version: Option<String>,
    /// Target compiler binary SHA-256.
    pub compiler_sha256: Option<String>,
    /// Recorded fixture paths and hashes.
    pub fixture_hashes: Vec<FixtureRequirement>,
    /// Platform OS.
    pub platform: String,
    /// Host architecture.
    pub arch: String,
    /// UTC start timestamp.
    pub start_timestamp: String,
    /// UTC end timestamp.
    pub end_timestamp: String,
    /// SHA-256 hash of stdout.
    pub stdout_sha256: String,
    /// SHA-256 hash of stderr.
    pub stderr_sha256: String,
}

impl GateResult {
    /// Compute the canonical SHA-256 hash of this result artifact.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let json_bytes = serde_json::to_vec(self).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        format!("{:x}", hasher.finalize())
    }
}

/// Reference to a prerequisite gate result in a release manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrerequisiteResultRef {
    /// Gate ID.
    pub gate_id: String,
    /// SHA-256 hash of the GateResult JSON artifact.
    pub result_sha256: String,
    /// SHA-256 hash of the GateSpec that generated it.
    pub spec_hash: String,
}

/// Versioned schema for an assembled release manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseManifest {
    /// Schema version (always 1).
    pub schema_version: u32,
    /// Unique release identifier (e.g. `release-lua54-8`).
    pub release_id: String,
    /// Target dialect ID (e.g. `lua5.4`).
    pub target_dialect: String,
    /// Exact target patch release (e.g. `Lua 5.4.8`).
    pub target_patch_version: String,
    /// Git commit SHA of the release.
    pub git_commit: String,
    /// Whether the worktree was clean (must be true for promotion).
    pub clean: bool,
    /// List of validated prerequisite result references.
    pub prerequisite_results: Vec<PrerequisiteResultRef>,
    /// ISO-8601 UTC timestamp of assembly.
    pub assembled_at: String,
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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateRunnerError {
    #[error("Missing command argv for gate '{0}'")]
    MissingCommand(String),
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
            if !actual_ver.contains(expected_ver) {
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

    let start_timestamp = current_iso_timestamp();

    // 3. Execute command
    let prog = &spec.command_argv[0];
    let args = &spec.command_argv[1..];
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

    // 4. Parse test results and enumerated test names
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
            // E.g.: "test test_lua54_golden_word_vectors ... ok"
            if let Some(rest) = trimmed.strip_prefix("test ") {
                if let Some(test_name) = rest.split_whitespace().next() {
                    enumerated_tests.push(test_name.to_string());
                }
            }
        }

        if trimmed.contains("test result:") {
            // E.g.: "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
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
        fixture_hashes: recorded_fixture_hashes,
        platform: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        start_timestamp,
        end_timestamp,
        stdout_sha256,
        stderr_sha256,
    };

    // Serialize result
    if let Some(parent) = output_path.parent() {
        let _ = fs::create_dir_all(parent);
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

    // Verify all expected tests are in enumerated tests
    for expected in &spec.expected_tests {
        if !result.enumerated_tests.contains(expected) {
            return Err(GateRunnerError::MissingExpectedTests(
                result.gate_id.clone(),
                vec![expected.clone()],
            ));
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
        if !actual_ver.contains(exp_comp_ver) {
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
pub fn assemble_release_manifest(
    release_id: &str,
    target_dialect: &str,
    target_patch_version: &str,
    git_commit: &str,
    clean: bool,
    prerequisite_results: &[(GateResult, GateSpec)],
) -> Result<ReleaseManifest, GateRunnerError> {
    if !clean {
        return Err(GateRunnerError::DirtyPromotionArtifact);
    }

    let mut refs = Vec::new();
    for (result, spec) in prerequisite_results {
        // Validate each prerequisite result strictly
        verify_gate_result(result, spec, Some(git_commit), true)?;
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
        git_commit: git_commit.to_string(),
        clean,
        prerequisite_results: refs,
        assembled_at: current_iso_timestamp(),
    })
}

/// Verify an assembled ReleaseManifest against its prerequisite results.
pub fn verify_release_manifest(
    manifest: &ReleaseManifest,
    expected_commit: &str,
    results: &[GateResult],
) -> Result<(), GateRunnerError> {
    if manifest.git_commit != expected_commit {
        return Err(GateRunnerError::StaleRevision {
            expected: expected_commit.to_string(),
            actual: manifest.git_commit.clone(),
        });
    }

    if !manifest.clean {
        return Err(GateRunnerError::DirtyPromotionArtifact);
    }

    for prereq_ref in &manifest.prerequisite_results {
        let matching_result = results
            .iter()
            .find(|r| r.gate_id == prereq_ref.gate_id)
            .ok_or_else(|| {
                GateRunnerError::TamperDetected(
                    manifest.release_id.clone(),
                    format!("Missing prerequisite result '{}'", prereq_ref.gate_id),
                )
            })?;

        let actual_res_hash = matching_result.compute_hash();
        if actual_res_hash != prereq_ref.result_sha256 {
            return Err(GateRunnerError::TamperDetected(
                manifest.release_id.clone(),
                format!(
                    "Result hash mismatch for '{}': expected {}, got {}",
                    prereq_ref.gate_id, prereq_ref.result_sha256, actual_res_hash
                ),
            ));
        }
    }

    Ok(())
}

/// Helper for backwards compatibility with earlier execute_and_record_gate calls.
pub fn execute_and_record_gate(
    gate_id: &str,
    command_str: &str,
    output_path: &Path,
    compiler_path: Option<&Path>,
) -> Result<GateResult, GateRunnerError> {
    let workspace_root = find_workspace_root_dir();
    let parts: Vec<String> = command_str
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let spec = GateSpec {
        schema_version: 1,
        gate_id: gate_id.to_string(),
        command_argv: parts,
        expected_tests: vec![],
        required_compiler_version: None,
        required_compiler_sha256: None,
        required_fixtures: vec![],
        required_profile: None,
        prerequisite_gates: vec![],
        allowed_capability_mutations: vec![],
    };
    execute_gate_spec(&spec, output_path, &workspace_root, compiler_path)
}

/// Helper for backwards compatibility with earlier verify_gate_artifact_integrity calls.
pub fn verify_gate_artifact_integrity(
    artifact_path: &Path,
    expected_gate_id: &str,
    expected_compiler_version_substr: Option<&str>,
) -> Result<GateResult, GateRunnerError> {
    let content = fs::read_to_string(artifact_path).map_err(|e| {
        GateRunnerError::Io(format!("Failed to read artifact {artifact_path:?}: {e}"))
    })?;
    let result: GateResult = serde_json::from_str(&content).map_err(|e| {
        GateRunnerError::TamperDetected(expected_gate_id.to_string(), format!("Invalid JSON: {e}"))
    })?;

    if result.gate_id != expected_gate_id {
        return Err(GateRunnerError::TamperDetected(
            result.gate_id,
            format!("Gate ID mismatch: expected {expected_gate_id}"),
        ));
    }

    if !result.success || result.exit_code != 0 {
        return Err(GateRunnerError::NonzeroExitCode(
            result.exit_code,
            result.command_argv,
        ));
    }

    if result.ignored_count > 0 {
        return Err(GateRunnerError::SkippedTests(
            result.ignored_count,
            result.gate_id,
        ));
    }

    if let Some(expected_ver) = expected_compiler_version_substr {
        let actual_ver = result.compiler_version.as_deref().unwrap_or("");
        if !actual_ver.contains(expected_ver) {
            return Err(GateRunnerError::WrongCompilerVersion {
                expected: expected_ver.to_string(),
                actual: actual_ver.to_string(),
            });
        }
    }

    Ok(result)
}

fn get_current_git_commit(workspace_root: &Path) -> String {
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

fn is_git_dirty(workspace_root: &Path) -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(workspace_root)
        .output()
        .ok()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false)
}

fn current_iso_timestamp() -> String {
    format!(
        "{:?}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    )
}

fn find_workspace_root_dir() -> PathBuf {
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let p = PathBuf::from(manifest_dir);
        if p.join("Cargo.toml").exists() && p.join("crates").exists() {
            return p;
        }
        if let Some(parent) = p.parent() {
            if parent.join("Cargo.toml").exists() && parent.join("crates").exists() {
                return parent.to_path_buf();
            }
            if let Some(gparent) = parent.parent() {
                if gparent.join("Cargo.toml").exists() && gparent.join("crates").exists() {
                    return gparent.to_path_buf();
                }
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}
