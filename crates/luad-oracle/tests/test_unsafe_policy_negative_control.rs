//! Negative control test for workspace-owned unsafe_code = "forbid" lint policy.
//!
//! Asserts that:
//! 1. Every workspace crate inherits the forbid-unsafe lint configuration without opt-outs.
//! 2. An actual unsafe block is rejected under a workspace that carries the policy
//!    exactly the way the shipped crates do: `[workspace.lints.rust]` in the root and
//!    `[lints] workspace = true` in the member, so the inheritance edge itself is
//!    exercised rather than a direct per-package lint declaration.
//! 3. Clean safe code compiles successfully (positive control).

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

#[test]
fn test_workspace_crates_inherit_forbid_unsafe_lint() {
    let root = workspace_root();

    // 1. Root Cargo.toml must declare [workspace.lints.rust] unsafe_code = "forbid"
    let root_cargo = fs::read_to_string(root.join("Cargo.toml")).expect("read root Cargo.toml");
    assert!(
        root_cargo.contains("unsafe_code = \"forbid\""),
        "Root Cargo.toml must declare unsafe_code = \"forbid\" in [workspace.lints.rust]"
    );

    // 2. All workspace crate Cargo.tomls must inherit workspace lints
    let crate_dirs = [
        "crates/luad-core",
        "crates/luad-dialect-lua51",
        "crates/luad-dialect-lua52",
        "crates/luad-dialect-lua53",
        "crates/luad-dialect-lua54",
        "crates/luad-dialect-lua55",
        "crates/luad-analysis",
        "crates/luad-cli",
        "crates/luad-oracle",
        "fuzz",
    ];

    for crate_dir in crate_dirs {
        let cargo_path = root.join(crate_dir).join("Cargo.toml");
        assert!(cargo_path.exists(), "Cargo.toml exists at {:?}", cargo_path);
        let content = fs::read_to_string(&cargo_path).expect("read crate Cargo.toml");
        let has_workspace_lints = content.contains("[lints]\nworkspace = true")
            || content.contains("[lints.rust]\nunsafe_code = \"forbid\"")
            || (content.contains("workspace = true") && content.contains("[lints]"));
        assert!(
            has_workspace_lints,
            "Crate at {:?} must inherit workspace lints or forbid unsafe_code",
            crate_dir
        );
    }
}

#[test]
fn test_no_local_unsafe_lint_opt_outs() {
    let root = workspace_root();

    fn visit_dir(dir: &Path, violations: &mut Vec<PathBuf>) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if file_name != "target" && file_name != ".git" {
                        visit_dir(&path, violations);
                    }
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    if let Ok(src) = fs::read_to_string(&path) {
                        let opt_out = ["allow", "(unsafe_code)"].concat();
                        if src.contains(&opt_out) {
                            violations.push(path);
                        }
                    }
                }
            }
        }
    }

    let mut violations = Vec::new();
    visit_dir(&root.join("crates"), &mut violations);
    visit_dir(&root.join("fuzz"), &mut violations);

    assert!(
        violations.is_empty(),
        "Detected unauthorized local unsafe-code lint opt-outs in: {:?}",
        violations
    );
}

/// Builds a two-manifest probe workspace that carries the forbid policy through the
/// same `[workspace.lints]` -> `[lints] workspace = true` edge the shipped crates use,
/// then lints it with the repository's ordinary tool.
///
/// Returns the combined clippy output and whether the run succeeded.
fn lint_probe_workspace(package_name: &str, member_src: &str) -> (bool, String) {
    let temp_dir = tempfile::tempdir().expect("create tempdir");
    let probe_root = temp_dir.path();
    let member_dir = probe_root.join("probe");

    let root_manifest = r#"[workspace]
members = ["probe"]
resolver = "2"

[workspace.lints.rust]
unsafe_code = "forbid"
"#;

    let member_manifest = format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2021"

[lints]
workspace = true
"#
    );

    fs::create_dir_all(member_dir.join("src")).expect("create probe/src/");
    fs::write(probe_root.join("Cargo.toml"), root_manifest).expect("write probe-root Cargo.toml");
    fs::write(member_dir.join("Cargo.toml"), member_manifest).expect("write probe Cargo.toml");
    fs::write(member_dir.join("src/lib.rs"), member_src).expect("write probe src/lib.rs");

    let output = Command::new("cargo")
        .args([
            "clippy",
            "--offline",
            "--workspace",
            "--message-format=short",
            "--",
            "-D",
            "warnings",
        ])
        .current_dir(probe_root)
        .output()
        .expect("execute cargo clippy on the probe workspace");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    (output.status.success(), combined)
}

#[test]
fn test_negative_control_unsafe_block_is_rejected_by_compiler() {
    let unsafe_src = r#"
pub fn probe_raw_deref() -> u8 {
    let val: u8 = 42;
    let ptr = &val as *const u8;
    // Deliberate unsafe block to verify forbid(unsafe_code) triggers a hard compile error
    unsafe {
        *ptr
    }
}
"#;

    let (succeeded, combined) = lint_probe_workspace("unsafe-probe-negative-control", unsafe_src);

    assert!(
        !succeeded,
        "Negative control FAILED: Unsafe probe unexpectedly compiled successfully!\nOutput:\n{combined}"
    );

    assert!(
        combined.contains("error: usage of an `unsafe` block"),
        "Negative control must fail specifically on the forbidden unsafe block, got:\n{combined}"
    );
}

#[test]
fn test_positive_control_safe_probe_compiles_cleanly() {
    let safe_src = r#"
pub fn probe_safe_add(a: u32, b: u32) -> u32 {
    a.saturating_add(b)
}
"#;

    let (succeeded, combined) = lint_probe_workspace("safe-probe-positive-control", safe_src);

    assert!(
        succeeded,
        "Positive control FAILED: Safe probe failed to compile under inherited forbid(unsafe_code):\n{combined}"
    );
}
