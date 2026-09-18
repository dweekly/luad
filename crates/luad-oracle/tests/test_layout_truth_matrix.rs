//! Cross-dialect layout truth matrix, CLI integration, and regression controls.

use std::fs;
use std::process::Command;

use luad_oracle::{get_fixture_bytes, luad_binary_path};

#[test]
fn test_cli_layout_truth_across_all_dialects_json() {
    let luad = luad_binary_path();
    let temp_dir = tempfile::tempdir().unwrap();

    let dialects_and_expected_layouts = [
        (
            "lua5.1",
            "int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0",
        ),
        (
            "lua5.2",
            "int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0",
        ),
        ("lua5.3", "int=4,sizet=8,inst=4,lua_int=8,num=8,endian=1"),
        ("lua5.4", "int=8,sizet=8,inst=4,num=8,endian=1"),
        ("lua5.5", "int=4,inst=4,lua_int=8,num=8,endian=1"),
    ];

    for (dialect, expected_layout) in dialects_and_expected_layouts {
        let raw = get_fixture_bytes(dialect, "hello", false).unwrap();
        let fixture_path = temp_dir.path().join(format!("{dialect}_hello.luac"));
        fs::write(&fixture_path, &raw).unwrap();

        // 1. Auto-detected dialect
        let out_auto = Command::new(&luad)
            .args([
                "inspect",
                fixture_path.to_str().unwrap(),
                "--format",
                "json",
            ])
            .output()
            .unwrap_or_else(|e| panic!("failed to run luad inspect auto for {dialect}: {e}"));
        assert_eq!(
            out_auto.status.code(),
            Some(0),
            "Auto inspect failed for {dialect}: stderr={}",
            String::from_utf8_lossy(&out_auto.stderr)
        );
        let doc_auto: serde_json::Value = serde_json::from_slice(&out_auto.stdout).unwrap();
        assert_eq!(doc_auto["interpretation"]["base_dialect"], dialect);
        assert_eq!(
            doc_auto["interpretation"]["selection_mode"], "detected",
            "Auto mode should report detected for {dialect}"
        );
        assert_eq!(
            doc_auto["interpretation"]["validated_layout"], expected_layout,
            "Validated layout mismatch for {dialect} in auto mode"
        );

        // 2. Explicit dialect (-d)
        let out_explicit = Command::new(&luad)
            .args([
                "inspect",
                fixture_path.to_str().unwrap(),
                "-d",
                dialect,
                "--format",
                "json",
            ])
            .output()
            .unwrap_or_else(|e| panic!("failed to run luad inspect explicit for {dialect}: {e}"));
        assert_eq!(
            out_explicit.status.code(),
            Some(0),
            "Explicit inspect failed for {dialect}: stderr={}",
            String::from_utf8_lossy(&out_explicit.stderr)
        );
        let doc_explicit: serde_json::Value = serde_json::from_slice(&out_explicit.stdout).unwrap();
        assert_eq!(doc_explicit["interpretation"]["base_dialect"], dialect);
        assert_eq!(
            doc_explicit["interpretation"]["selection_mode"], "explicit",
            "Explicit mode should report explicit for {dialect}"
        );
        assert_eq!(
            doc_explicit["interpretation"]["validated_layout"], expected_layout,
            "Validated layout mismatch for {dialect} in explicit mode"
        );
    }
}

#[test]
fn test_cli_layout_truth_text_format() {
    let luad = luad_binary_path();

    let dialects_and_expected_layouts = [
        (
            "lua5.2",
            "int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0",
        ),
        ("lua5.3", "int=4,sizet=8,inst=4,lua_int=8,num=8,endian=1"),
        ("lua5.5", "int=4,inst=4,lua_int=8,num=8,endian=1"),
    ];

    let temp_dir = tempfile::tempdir().unwrap();
    for (dialect, expected_layout) in dialects_and_expected_layouts {
        let raw = get_fixture_bytes(dialect, "hello", false).unwrap();
        let fixture_path = temp_dir.path().join(format!("{dialect}_hello.luac"));
        fs::write(&fixture_path, &raw).unwrap();
        let out = Command::new(&luad)
            .args([
                "inspect",
                fixture_path.to_str().unwrap(),
                "--format",
                "text",
            ])
            .output()
            .expect("run luad inspect text");

        assert_eq!(out.status.code(), Some(0));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(expected_layout),
            "Text output for {dialect} must contain validated layout '{expected_layout}':\n{stdout}"
        );
    }
}

#[test]
fn test_cli_rejection_of_corrupted_headers_with_exact_offset_and_code() {
    let luad = luad_binary_path();
    let temp_dir = tempfile::tempdir().unwrap();

    let cases = [
        // Dialect, byte index, expected error snippet / offset
        ("lua5.2", 6, "offset 6", "endianness"),
        ("lua5.2", 7, "offset 7", "sizeof(int)"),
        ("lua5.2", 11, "offset 11", "integral flag"),
        ("lua5.3", 5, "offset 5", "Format mismatch"),
        ("lua5.3", 15, "offset 15", "lua_Integer size"),
        ("lua5.3", 17, "offset 17", "Endianness mismatch"),
        ("lua5.3", 25, "offset 25", "Float format mismatch"),
        ("lua5.5", 5, "offset 5", "Format mismatch"),
        ("lua5.5", 13, "offset 13", "int test integer"),
        ("lua5.5", 18, "offset 18", "Instruction test value"),
        ("lua5.5", 23, "offset 23", "lua_Integer test integer"),
        ("lua5.5", 32, "offset 32", "lua_Number test float"),
    ];

    for (dialect, byte_idx, expected_offset, expected_snippet) in cases {
        let mut raw = get_fixture_bytes(dialect, "hello", false).unwrap();
        raw[byte_idx] ^= 0xff;

        let corrupted_file = temp_dir
            .path()
            .join(format!("{dialect}_corrupted_{byte_idx}.luac"));
        fs::write(&corrupted_file, &raw).unwrap();

        // 1. Detected mode
        let out_detected = Command::new(&luad)
            .args(["inspect", corrupted_file.to_str().unwrap()])
            .output()
            .expect("run luad");

        assert_eq!(
            out_detected.status.code(),
            Some(1),
            "Corrupted chunk must fail with exit code 1"
        );
        let stderr = String::from_utf8_lossy(&out_detected.stderr);
        assert!(
            stderr.contains(expected_offset),
            "Stderr must report '{expected_offset}' for {dialect} byte {byte_idx}: {stderr}"
        );
        assert!(
            stderr.contains(expected_snippet),
            "Stderr must report '{expected_snippet}' for {dialect} byte {byte_idx}: {stderr}"
        );

        // 2. Explicit mode (-d)
        let out_explicit = Command::new(&luad)
            .args(["inspect", corrupted_file.to_str().unwrap(), "-d", dialect])
            .output()
            .expect("run luad");

        assert_eq!(
            out_explicit.status.code(),
            Some(1),
            "Corrupted chunk in explicit mode must fail with exit code 1"
        );
        let stderr_exp = String::from_utf8_lossy(&out_explicit.stderr);
        assert!(
            stderr_exp.contains(expected_offset),
            "Explicit stderr must report '{expected_offset}' for {dialect} byte {byte_idx}: {stderr_exp}"
        );
        assert!(
            stderr_exp.contains(expected_snippet),
            "Explicit stderr must report '{expected_snippet}' for {dialect} byte {byte_idx}: {stderr_exp}"
        );
    }
}
