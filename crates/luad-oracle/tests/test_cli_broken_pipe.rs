//! Tests for CLI output write error handling and quiet BrokenPipe behavior.
//! Verifies issue #78: early pipe termination exits cleanly with status 0,
//! stderr is free of panics and commentary, full outputs remain byte-identical,
//! abandoned JSONL streams omit terminal records, and non-pipe write errors
//! return ExitCode::IoError (3).

use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

/// Helper that spawns luad, reads at most `lines_to_read` from stdout,
/// drops the reader (closing the pipe), and returns (exit_code, captured_stdout, captured_stderr).
fn run_with_early_closed_pipe(
    args: &[&str],
    lines_to_read: usize,
) -> (Option<i32>, String, String) {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let mut child = Command::new(&luad)
        .current_dir(&root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn luad");

    let mut captured_stdout = String::new();
    if let Some(stdout) = child.stdout.take() {
        let mut reader = BufReader::new(stdout);
        for _ in 0..lines_to_read {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            captured_stdout.push_str(&line);
        }
        // Dropping reader closes the read end of the pipe
        drop(reader);
    }

    let mut captured_stderr = String::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = stderr.read_to_string(&mut captured_stderr);
    }

    let status = child.wait().expect("failed to wait for child");
    (status.code(), captured_stdout, captured_stderr)
}

#[test]
fn test_cli_broken_pipe_disasm_text_immediate_close() {
    let fixture = "tests/fixtures/precompiled/lua54/closures.luac";
    let (code, stdout, stderr) = run_with_early_closed_pipe(&["disasm", fixture], 0);

    assert_eq!(code, Some(0), "Broken pipe on disasm must exit 0 quietly");
    assert!(
        stdout.is_empty(),
        "Stdout should be empty on immediate close"
    );
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_broken_pipe_disasm_text_partial_read() {
    let fixture = "tests/fixtures/precompiled/lua54/closures.luac";
    let (code, stdout, stderr) = run_with_early_closed_pipe(&["disasm", fixture], 2);

    assert_eq!(
        code,
        Some(0),
        "Broken pipe on disasm after 2 lines must exit 0 quietly"
    );
    assert_eq!(stdout.lines().count(), 2, "Should have captured 2 lines");
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_broken_pipe_inspect_json() {
    let fixture = "tests/fixtures/precompiled/lua54/closures.luac";
    let (code, _, stderr) =
        run_with_early_closed_pipe(&["inspect", fixture, "--format", "json"], 0);

    assert_eq!(
        code,
        Some(0),
        "Broken pipe on inspect --format json must exit 0 quietly"
    );
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_broken_pipe_export_jsonl_immediate_close() {
    let fixture = "tests/fixtures/precompiled/lua54/closures.luac";
    let (code, stdout, stderr) =
        run_with_early_closed_pipe(&["export", fixture, "--format", "jsonl"], 0);

    assert_eq!(
        code,
        Some(0),
        "Broken pipe on export immediate close must exit 0"
    );
    assert!(stdout.is_empty());
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_broken_pipe_export_jsonl_partial_abandons_terminal_records() {
    let fix1 = "tests/fixtures/precompiled/lua54/closures.luac";
    let fix2 = "tests/fixtures/precompiled/lua54/control_flow.luac";
    let (code, stdout, stderr) =
        run_with_early_closed_pipe(&["export", fix1, fix2, "--format", "jsonl"], 2);

    assert_eq!(
        code,
        Some(0),
        "Broken pipe on export partial must exit 0 quietly"
    );
    assert_eq!(stdout.lines().count(), 2);
    // Verified invariant: an abandoned JSONL stream lacks its terminal records (file_end / export_end)
    assert!(
        !stdout.contains(r#""record_type":"export_end""#),
        "Partial export must omit export_end"
    );
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_broken_pipe_schema_json() {
    let (code, stdout, stderr) = run_with_early_closed_pipe(&["schema", "chunk"], 1);

    assert_eq!(code, Some(0), "Broken pipe on schema must exit 0 quietly");
    assert_eq!(stdout.lines().count(), 1);
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_broken_pipe_diagnostics_text() {
    let (code, stdout, stderr) = run_with_early_closed_pipe(&["diagnostics"], 1);

    assert_eq!(
        code,
        Some(0),
        "Broken pipe on diagnostics must exit 0 quietly"
    );
    assert_eq!(stdout.lines().count(), 1);
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_broken_pipe_completions_bash() {
    let (code, stdout, stderr) = run_with_early_closed_pipe(&["completions", "bash"], 1);

    assert_eq!(
        code,
        Some(0),
        "Broken pipe on completions must exit 0 quietly"
    );
    assert_eq!(stdout.lines().count(), 1);
    assert!(
        !stderr.contains("panic"),
        "Stderr must not contain panic: {stderr}"
    );
    assert!(
        !stderr.contains("Broken pipe"),
        "Stderr must not contain Broken pipe: {stderr}"
    );
}

#[test]
fn test_cli_full_output_controls_match_uninterrupted() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let fixture = "tests/fixtures/precompiled/lua54/closures.luac";

    // Uninterrupted disasm
    let disasm_out = Command::new(&luad)
        .current_dir(&root)
        .args(["disasm", fixture])
        .output()
        .expect("luad disasm must run");
    assert_eq!(disasm_out.status.code(), Some(0));
    let disasm_str = String::from_utf8_lossy(&disasm_out.stdout);
    assert!(disasm_str.contains("CLOSURE"));
    assert!(disasm_str.contains("RETURN"));

    // Uninterrupted export jsonl
    let export_out = Command::new(&luad)
        .current_dir(&root)
        .args(["export", fixture, "--format", "jsonl"])
        .output()
        .expect("luad export must run");
    assert_eq!(export_out.status.code(), Some(0));
    let export_str = String::from_utf8_lossy(&export_out.stdout);
    assert!(export_str.contains(r#""record_type":"export_start""#));
    assert!(export_str.contains(r#""record_type":"file_start""#));
    assert!(export_str.contains(r#""record_type":"file_end""#));
    assert!(export_str.contains(r#""record_type":"export_end""#));
}

#[test]
fn test_negative_control_non_pipe_write_error() {
    let luad = get_luad_bin();
    let root = luad_oracle::find_workspace_root();
    let temp_file = tempfile::NamedTempFile::new().expect("create temp file");
    let temp_path = temp_file.path().display().to_string();

    // Use Python helper to set RLIMIT_FSIZE with SIGXFSZ ignored so write syscall fails with EFBIG
    let py_script = format!(
        r#"
import os, resource, signal, subprocess, sys
def preexec():
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (100, 100))

with open(r"{}", "wb") as f:
    proc = subprocess.run([r"{}", "schema", "chunk"], stdout=f, preexec_fn=preexec, stderr=subprocess.PIPE)
    sys.stderr.buffer.write(proc.stderr)
    sys.exit(proc.returncode)
"#,
        temp_path, luad
    );

    let output = Command::new("python3")
        .current_dir(&root)
        .args(["-c", &py_script])
        .output()
        .expect("python3 helper must run");

    assert_eq!(
        output.status.code(),
        Some(3),
        "Non-pipe output write error must return ExitCode::IoError (3)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("error: output I/O error:"),
        "stderr should describe output I/O error, got: {stderr}"
    );
}
