//! Executable gate runner CLI tool.
//!
//! Executes a GateSpec, deriving and emitting a verified GateResult artifact.

use luad_oracle::find_workspace_root;
use luad_oracle::gate_runner::{execute_gate_spec, verify_gate_result, GateSpec};
use std::path::{Path, PathBuf};
use std::process::exit;

fn print_usage() {
    eprintln!(
        "Usage: run_gate --spec <spec_file.json> --out-dir <output_dir> [--compiler-path <path>] [--require-clean]"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut spec_path: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut compiler_path: Option<PathBuf> = None;
    let mut require_clean = false;

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
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("Error creating output directory {out_dir:?}: {e}");
        exit(1);
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

    if let Err(e) = verify_gate_result(&result, &spec, None, require_clean) {
        eprintln!(
            "==> Gate '{}' FAILED post-execution verification: {e}",
            spec.gate_id
        );
        exit(1);
    }

    println!(
        "==> Gate '{}' PASSED: {} tests passed, 0 failed, 0 ignored.",
        result.gate_id, result.passed_count
    );
    println!(
        "==> GateResult artifact written to: {}",
        result_path.display()
    );
}
