//! Executable gate runner CLI tool.
//!
//! Executes a GateSpec, emitting a verified GateResult, ReleaseManifest, probe rejection report, and logs.

use luad_oracle::find_workspace_root;
use luad_oracle::gate_runner::{
    assemble_release_manifest, execute_gate_spec, get_current_git_commit, is_git_dirty,
    record_all_adversarial_probes, verify_gate_result, verify_release_manifest, GateSpec,
};
use std::path::{Path, PathBuf};
use std::process::exit;

fn print_usage() {
    eprintln!(
        "Usage: run_gate --spec <spec_file.json> --out-dir <output_dir> [--compiler-path <path>] [--require-clean] [--record-probes]"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut spec_path: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut compiler_path: Option<PathBuf> = None;
    let mut require_clean = false;
    let mut record_probes = true;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" => {
                if i + 1 < args.len() {
                    spec_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    print_usage();
                    exit(1);
                }
            }
            "--out-dir" => {
                if i + 1 < args.len() {
                    out_dir = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    print_usage();
                    exit(1);
                }
            }
            "--compiler-path" => {
                if i + 1 < args.len() {
                    compiler_path = Some(PathBuf::from(&args[i + 1]));
                    i += 2;
                } else {
                    print_usage();
                    exit(1);
                }
            }
            "--require-clean" => {
                require_clean = true;
                i += 1;
            }
            "--record-probes" => {
                record_probes = true;
                i += 1;
            }
            "-h" | "--help" => {
                print_usage();
                exit(0);
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_usage();
                exit(1);
            }
        }
    }

    let spec_path = match spec_path {
        Some(p) => p,
        None => {
            eprintln!("Error: --spec is required");
            print_usage();
            exit(1);
        }
    };

    let out_dir = match out_dir {
        Some(p) => p,
        None => {
            eprintln!("Error: --out-dir is required");
            print_usage();
            exit(1);
        }
    };

    if !spec_path.exists() {
        eprintln!("Error: spec file does not exist: {spec_path:?}");
        exit(1);
    }

    let spec_bytes = match std::fs::read(&spec_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading spec file {spec_path:?}: {e}");
            exit(1);
        }
    };

    let spec: GateSpec = match serde_json::from_slice(&spec_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error parsing GateSpec JSON from {spec_path:?}: {e}");
            exit(1);
        }
    };

    let workspace_root = find_workspace_root();
    let current_commit = get_current_git_commit(&workspace_root);
    let dirty = is_git_dirty(&workspace_root);

    if require_clean && dirty {
        eprintln!(
            "Error: Gate execution requires a clean git working tree, but worktree is dirty."
        );
        exit(1);
    }

    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("Error creating output directory {out_dir:?}: {e}");
        exit(1);
    }

    // Write copy of GateSpec to output directory
    let spec_copy_path = out_dir.join("gate-spec.json");
    if let Ok(spec_json_pretty) = serde_json::to_vec_pretty(&spec) {
        let _ = std::fs::write(&spec_copy_path, spec_json_pretty);
    }

    let result_path = out_dir.join("gate-result.json");
    let comp_ref: Option<&Path> = compiler_path.as_deref();

    println!("==> Executing GateSpec '{}'...", spec.gate_id);
    let result = match execute_gate_spec(&spec, &result_path, &workspace_root, comp_ref) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("==> Gate '{}' FAILED execution: {e}", spec.gate_id);
            exit(1);
        }
    };

    if let Err(e) = verify_gate_result(&result, &spec, Some(&current_commit), require_clean) {
        eprintln!(
            "==> Gate '{}' FAILED post-execution verification: {e}",
            spec.gate_id
        );
        exit(1);
    }

    // Assemble and verify release manifest demo artifact
    let manifest_path = out_dir.join("release-manifest.json");
    match assemble_release_manifest(
        &format!("release-{}", spec.gate_id),
        "lua5.4.8",
        "Lua 5.4.8",
        &current_commit,
        !result.dirty,
        &[(result.clone(), spec.clone())],
    ) {
        Ok(manifest) => {
            if let Err(e) = verify_release_manifest(
                &manifest,
                &current_commit,
                &[(result.clone(), spec.clone())],
            ) {
                eprintln!("==> Failed to verify release manifest artifact: {e}");
                exit(1);
            }
            if let Ok(json_bytes) = serde_json::to_vec_pretty(&manifest) {
                let _ = std::fs::write(&manifest_path, json_bytes);
            }
        }
        Err(e) => {
            if require_clean {
                eprintln!("==> Failed to assemble release manifest: {e}");
                exit(1);
            }
        }
    }

    // Record all 11 adversarial probes rejection report
    if record_probes {
        let probes_path = out_dir.join("probe-rejections.json");
        if let Err(e) = record_all_adversarial_probes(&workspace_root, &probes_path) {
            eprintln!("==> Failed to record adversarial probe reports: {e}");
            exit(1);
        }
        println!(
            "==> Adversarial probe rejection report written to: {}",
            probes_path.display()
        );
    }

    println!(
        "==> Gate '{}' PASSED: {} tests passed, 0 failed, 0 ignored.",
        result.gate_id, result.passed_count
    );
    println!("==> GateSpec artifact: {}", spec_copy_path.display());
    println!("==> GateResult artifact: {}", result_path.display());
    println!("==> ReleaseManifest artifact: {}", manifest_path.display());
}
