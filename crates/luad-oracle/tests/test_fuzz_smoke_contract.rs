//! Contract tests for the hostile-input fuzz smoke runner and targets.
//!
//! Exercises:
//! 1. Canonical 8-target list integrity and registration.
//! 2. Dry-run evidence generation and schema validity.
//! 3. Rejection of unpinned toolchain versions.
//! 4. Rejection of target omission.
//! 5. Rejection of zero-execution results.
//! 6. Rejection of inferred success from absent output.
//! 7. Rejection of valuable output in temporary storage.
//! 8. Immutability of the pinned resource-detection envelope.
//! 9. Agreement between the CI workflow pins and the runner constants.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

const CANONICAL_TARGETS: [&str; 8] = [
    "fuzz_detect",
    "fuzz_lua51",
    "fuzz_lua52",
    "fuzz_lua53",
    "fuzz_lua54",
    "fuzz_lua55",
    "fuzz_lua51_analysis",
    "fuzz_lua54_analysis",
];

#[test]
fn test_canonical_targets_exist_and_are_registered() {
    let root = workspace_root();
    let fuzz_cargo =
        fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("read fuzz/Cargo.toml");

    for target in CANONICAL_TARGETS {
        let target_file = root.join(format!("fuzz/fuzz_targets/{target}.rs"));
        assert!(
            target_file.exists(),
            "Fuzz target file must exist at {:?}",
            target_file
        );

        let bin_decl = format!("name = \"{target}\"");
        assert!(
            fuzz_cargo.contains(&bin_decl),
            "fuzz/Cargo.toml must register [[bin]] with {}",
            bin_decl
        );
    }
}

#[test]
fn test_fuzz_runner_dry_run_generates_valid_evidence() {
    let root = workspace_root();
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let out_dir = temp_dir.path();

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(out_dir)
        .env("LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT", "1")
        .output()
        .expect("execute fuzz_smoke.sh in dry-run mode");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    assert!(
        output.status.success(),
        "fuzz_smoke.sh dry run must succeed, got error:\n{combined}"
    );

    let evidence_path = out_dir.join("fuzz-smoke-evidence.json");
    assert!(
        evidence_path.exists(),
        "Evidence file must be written to {:?}",
        evidence_path
    );

    let evidence_content = fs::read_to_string(&evidence_path).expect("read evidence JSON");
    let v: serde_json::Value =
        serde_json::from_str(&evidence_content).expect("evidence must parse as valid JSON");

    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["mode"], "dry-run");
    assert_eq!(v["campaign_executed"], false);
    assert_eq!(v["success"], false);
    assert_eq!(v["target_count"], 8);

    // The resource detector that finds unbounded allocation must be pinned by the
    // runner, not inherited from a libFuzzer default.
    assert_eq!(v["detection_envelope"]["sanitizer"], "address");
    assert_eq!(v["detection_envelope"]["rss_limit_mb"], 512);
    assert_eq!(v["detection_envelope"]["malloc_limit_mb"], 128);

    assert_eq!(v["budget"]["runs_per_target"], 1000);
    assert_eq!(v["budget"]["max_input_bytes"], 4096);
    assert_eq!(v["budget"]["input_timeout_seconds"], 5);
    assert_eq!(v["budget"]["outer_timeout_seconds"], 300);
    assert_eq!(v["budget"]["mutation_seed"], 1);

    let targets_arr = v["targets"].as_array().expect("targets array");
    assert_eq!(targets_arr.len(), 8);

    for (idx, target_val) in targets_arr.iter().enumerate() {
        let target_name = target_val["target"].as_str().expect("target name");
        assert_eq!(target_name, CANONICAL_TARGETS[idx]);
        assert_eq!(target_val["executed"], false);

        let execs = target_val["executions"].as_u64().expect("executions count");
        assert!(
            execs > 0,
            "Target {target_name} must have positive executions"
        );

        assert_eq!(target_val["exit_code"], 0);

        let corpus_count = target_val["seed_corpus_count"]
            .as_u64()
            .expect("seed corpus count");
        assert!(
            corpus_count > 0,
            "Target {target_name} must have non-zero seed corpus"
        );

        let corpus_files = target_val["seed_corpus_files"]
            .as_array()
            .expect("seed_corpus_files");
        assert!(!corpus_files.is_empty());

        let log_name = target_val["log_file"].as_str().expect("log_file");
        let log_path = out_dir.join(log_name);
        assert!(log_path.exists(), "Log file {:?} must exist", log_path);
    }
}

#[test]
fn test_fuzz_runner_rejects_unpinned_toolchain() {
    let root = workspace_root();
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let out_dir = temp_dir.path();

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(out_dir)
        .env("LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT", "1")
        .env("LUAD_FUZZ_TEST_CARGO_FUZZ_VERSION", "cargo-fuzz 99.99.99")
        .output()
        .expect("execute fuzz_smoke.sh with mismatched toolchain");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "Runner must FAIL on unpinned/mismatched toolchain version, got success with output:\n{combined}"
    );
    assert!(
        combined.contains("cargo-fuzz version mismatch"),
        "Error message must cite toolchain version mismatch, got:\n{combined}"
    );
}

#[test]
fn test_fuzz_runner_rejects_target_omission() {
    let root = workspace_root();
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let out_dir = temp_dir.path();

    // Pass an incomplete subset of targets via override
    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(out_dir)
        .env("LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT", "1")
        .env("LUAD_FUZZ_TEST_TARGETS", "fuzz_detect,fuzz_lua51")
        .output()
        .expect("execute fuzz_smoke.sh with omitted targets");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "Runner must FAIL when canonical targets are omitted, got success:\n{combined}"
    );
    assert!(
        combined.contains("canonical target list mismatch"),
        "Error message must cite target omission, got:\n{combined}"
    );
}

#[test]
fn test_fuzz_runner_rejects_zero_executions() {
    let root = workspace_root();
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let out_dir = temp_dir.path();

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(out_dir)
        .env("LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT", "1")
        .env("LUAD_FUZZ_TEST_EXECUTIONS", "0")
        .output()
        .expect("execute fuzz_smoke.sh with 0 executions");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "Runner must FAIL when executions are 0, got success:\n{combined}"
    );
    assert!(
        combined.contains("zero executions"),
        "Error message must cite zero executions, got:\n{combined}"
    );
}

#[test]
fn test_fuzz_runner_rejects_target_failure() {
    let root = workspace_root();
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let out_dir = temp_dir.path();

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(out_dir)
        .env("LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT", "1")
        .env("LUAD_FUZZ_TEST_EXIT_CODE", "1")
        .output()
        .expect("execute fuzz_smoke.sh with simulated target failure");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "Runner must FAIL when a target exits non-zero, got success:\n{combined}"
    );
}

#[test]
fn test_fuzz_runner_rejects_valuable_output_in_tmp_by_default() {
    let root = workspace_root();

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("/tmp/unauthorized_fuzz_smoke_out")
        .output()
        .expect("execute fuzz_smoke.sh with /tmp output");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "Runner must FAIL when output is placed in /tmp without explicit ALLOW_TMP_OUTPUT, got success:\n{combined}"
    );
    assert!(
        combined.contains("output directory is temporary storage"),
        "Error message must warn against /tmp output, got:\n{combined}"
    );
}

#[test]
fn test_fuzz_runner_rejects_missing_target_output() {
    let root = workspace_root();
    let temp_dir = tempfile::tempdir().expect("create tempdir");

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(temp_dir.path())
        .env("LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT", "1")
        .env("LUAD_FUZZ_TEST_MISSING_LOG_TARGET", "fuzz_lua53")
        .output()
        .expect("execute fuzz_smoke.sh with absent target output");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "Runner must not infer success when target output is absent:\n{combined}"
    );
    assert!(
        combined.contains("missing target output"),
        "Error must identify missing target output:\n{combined}"
    );
}

#[test]
fn test_fuzz_runner_rejects_rust_toolchain_mismatch() {
    let root = workspace_root();
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let out_dir = temp_dir.path();

    let output = Command::new("bash")
        .arg(root.join("scripts/fuzz_smoke.sh"))
        .arg("--dry-run")
        .arg("--out-dir")
        .arg(out_dir)
        .env("LUAD_FUZZ_TEST_ALLOW_TEMP_OUTPUT", "1")
        .env("LUAD_FUZZ_TEST_RUST_TOOLCHAIN", "nightly-1999-01-01")
        .output()
        .expect("execute fuzz_smoke.sh with mismatched Rust toolchain");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "Runner must FAIL on a Rust toolchain other than the pin, got success:\n{combined}"
    );
    assert!(
        combined.contains("Rust toolchain mismatch"),
        "Error message must cite the Rust toolchain mismatch, got:\n{combined}"
    );
}

/// Reads a `readonly name="value"` or `readonly name=value` constant from the runner.
fn runner_constant(script: &str, name: &str) -> String {
    let prefix = format!("readonly {name}=");
    let line = script
        .lines()
        .find(|line| line.trim_start().starts_with(&prefix))
        .unwrap_or_else(|| panic!("scripts/fuzz_smoke.sh must define {name}"));
    line.trim_start()[prefix.len()..]
        .trim()
        .trim_matches('"')
        .to_string()
}

#[test]
fn test_ci_workflow_pins_agree_with_runner_constants() {
    let root = workspace_root();
    let script =
        fs::read_to_string(root.join("scripts/fuzz_smoke.sh")).expect("read scripts/fuzz_smoke.sh");
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .expect("read .github/workflows/ci.yml");

    let toolchain = runner_constant(&script, "pinned_rust_toolchain");
    let cargo_fuzz = runner_constant(&script, "pinned_cargo_fuzz_version");

    assert!(
        workflow.contains(&format!("toolchain: {toolchain}")),
        "CI must install the runner's pinned toolchain {toolchain}"
    );
    assert!(
        workflow.contains(&format!(
            "cargo +{toolchain} install cargo-fuzz --version {cargo_fuzz} --locked"
        )),
        "CI must install cargo-fuzz {cargo_fuzz} with --locked under the pinned toolchain"
    );
    assert!(
        workflow.contains("scripts/fuzz_smoke.sh"),
        "CI must invoke the canonical runner rather than reimplementing its flags"
    );

    // The detection envelope and run budget belong to the runner alone. CI must not
    // restate libFuzzer flags, or the two pins can drift silently.
    for flag in [
        "-rss_limit_mb",
        "-malloc_limit_mb",
        "-runs=",
        "-max_len",
        "-seed=",
        "--sanitizer",
    ] {
        assert!(
            !workflow.contains(flag),
            "CI must not duplicate runner flag {flag}"
        );
    }
}
