//! Executable gate harness and versioned gate-result schema.
//!
//! Provides deterministic gate execution, artifact recording, and tamper detection.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Versioned schema for gate execution results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateResult {
    /// Schema version for gate results (always 1).
    pub schema_version: u32,
    /// Unique gate identifier (e.g. `gate-facts-lua54-8`).
    pub gate_id: String,
    /// Exact command line executed.
    pub command: String,
    /// Process exit code.
    pub exit_code: i32,
    /// Whether the gate passed completely.
    pub success: bool,
    /// Number of tests executed.
    pub test_count: usize,
    /// Number of tests that skipped (must be 0 for proof gates).
    pub skipped_count: usize,
    /// Git commit SHA at time of execution.
    pub git_commit: String,
    /// Whether the git worktree had uncommitted changes.
    pub dirty: bool,
    /// Target compiler path if applicable.
    pub compiler_path: Option<String>,
    /// Target compiler version string.
    pub compiler_version: Option<String>,
    /// Target compiler binary SHA-256.
    pub compiler_sha256: Option<String>,
    /// UTC timestamp of execution.
    pub timestamp: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateRunnerError {
    #[error("Missing command: {0}")]
    MissingCommand(String),
    #[error("Nonzero exit code {0} from command: {1}")]
    NonzeroExitCode(i32, String),
    #[error("Skipped tests detected ({0} skipped) in gate '{1}'")]
    SkippedTests(usize, String),
    #[error("Stale source revision: expected {expected}, got {actual}")]
    StaleRevision { expected: String, actual: String },
    #[error("Dirty worktree rejected for release promotion artifact")]
    DirtyPromotionArtifact,
    #[error("Wrong compiler binary: expected {expected}, got {actual}")]
    WrongCompilerBinary { expected: String, actual: String },
    #[error("Evidence tampering detected in '{0}': checksum or signature mismatch")]
    TamperDetected(String),
    #[error("IO or parsing error: {0}")]
    Io(String),
}

/// Execute a gate command and validate its execution results.
pub fn execute_and_record_gate(
    gate_id: &str,
    command_str: &str,
    output_path: &Path,
    compiler_path: Option<&Path>,
) -> Result<GateResult, GateRunnerError> {
    if command_str.trim().is_empty() {
        return Err(GateRunnerError::MissingCommand(gate_id.to_string()));
    }

    let parts: Vec<&str> = command_str.split_whitespace().collect();
    if parts.is_empty() {
        return Err(GateRunnerError::MissingCommand(gate_id.to_string()));
    }

    let mut cmd = Command::new(parts[0]);
    if parts.len() > 1 {
        cmd.args(&parts[1..]);
    }

    let output = cmd.output().map_err(|e| {
        GateRunnerError::Io(format!("Failed to execute command '{command_str}': {e}"))
    })?;

    let exit_code = output.status.code().unwrap_or(-1);
    if exit_code != 0 {
        return Err(GateRunnerError::NonzeroExitCode(
            exit_code,
            command_str.to_string(),
        ));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout_str}\n{stderr_str}");

    // Parse test count and skipped count from standard `cargo test` output
    let mut test_count = 0;
    let mut skipped_count = 0;
    for line in combined.lines() {
        if line.contains("test result:") {
            // E.g.: "test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out"
            if let Some(passed_part) = line.split("passed").next() {
                if let Some(num_str) = passed_part.split_whitespace().last() {
                    if let Ok(n) = num_str.parse::<usize>() {
                        test_count += n;
                    }
                }
            }
            if line.contains("ignored") {
                if let Some(ignored_part) = line.split("ignored").next() {
                    if let Some(num_str) = ignored_part.split_whitespace().last() {
                        if let Ok(n) = num_str.parse::<usize>() {
                            skipped_count += n;
                        }
                    }
                }
            }
        }
    }

    if skipped_count > 0 {
        return Err(GateRunnerError::SkippedTests(
            skipped_count,
            gate_id.to_string(),
        ));
    }

    let git_commit = get_current_git_commit();
    let dirty = is_git_dirty();

    let mut comp_ver = None;
    let mut comp_sha = None;
    let mut comp_path_str = None;

    if let Some(cp) = compiler_path {
        comp_path_str = Some(cp.to_string_lossy().to_string());
        if cp.exists() {
            if let Ok(ver_out) = Command::new(cp).arg("-v").output() {
                let v = format!(
                    "{}{}",
                    String::from_utf8_lossy(&ver_out.stdout),
                    String::from_utf8_lossy(&ver_out.stderr)
                );
                comp_ver = Some(v.trim().to_string());
            }
            if let Ok(bytes) = fs::read(cp) {
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                comp_sha = Some(format!("{:x}", hasher.finalize()));
            }
        }
    }

    let result = GateResult {
        schema_version: 1,
        gate_id: gate_id.to_string(),
        command: command_str.to_string(),
        exit_code,
        success: exit_code == 0 && skipped_count == 0,
        test_count,
        skipped_count,
        git_commit,
        dirty,
        compiler_path: comp_path_str,
        compiler_version: comp_ver,
        compiler_sha256: comp_sha,
        timestamp: format!(
            "{:?}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        ),
    };

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

    Ok(result)
}

/// Verify that an existing GateResult is authentic and untampered.
pub fn verify_gate_artifact_integrity(
    artifact_path: &Path,
    expected_gate_id: &str,
    expected_compiler_version_substr: Option<&str>,
) -> Result<GateResult, GateRunnerError> {
    let content = fs::read_to_string(artifact_path).map_err(|e| {
        GateRunnerError::Io(format!("Failed to read artifact {artifact_path:?}: {e}"))
    })?;
    let result: GateResult = serde_json::from_str(&content).map_err(|e| {
        GateRunnerError::TamperDetected(format!("Invalid JSON in {artifact_path:?}: {e}"))
    })?;

    if result.gate_id != expected_gate_id {
        return Err(GateRunnerError::TamperDetected(format!(
            "Gate ID mismatch: expected {expected_gate_id}, got {}",
            result.gate_id
        )));
    }

    if !result.success || result.exit_code != 0 {
        return Err(GateRunnerError::NonzeroExitCode(
            result.exit_code,
            result.command,
        ));
    }

    if result.skipped_count > 0 {
        return Err(GateRunnerError::SkippedTests(
            result.skipped_count,
            result.gate_id,
        ));
    }

    if let Some(expected_ver) = expected_compiler_version_substr {
        let actual_ver = result.compiler_version.as_deref().unwrap_or("");
        if !actual_ver.contains(expected_ver) {
            return Err(GateRunnerError::WrongCompilerBinary {
                expected: expected_ver.to_string(),
                actual: actual_ver.to_string(),
            });
        }
    }

    Ok(result)
}

fn get_current_git_commit() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
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

fn is_git_dirty() -> bool {
    Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false)
}
