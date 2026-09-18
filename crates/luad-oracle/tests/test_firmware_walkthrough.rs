//! Automated reproducible firmware investigation walkthrough test (Stage 7 / Package W).
//!
//! Replays the 4-phase firmware investigation workflow against the public redistributable
//! fixture tree at `tests/fixtures/firmware_tree/`:
//! - Phase 1: Inventory and batch triage via `luad export` with exact closure assertions.
//! - Phase 2: Inspection and layout detection/rejection with truthful exit codes (0, 1, 4).
//! - Phase 3: Auditing facts (constants, global query, disassembly with raw/effects, callees, origins).
//! - Phase 4: Pinned decompiler handoff boundary and refusal analysis.
//! - Negative controls: Fixture tampering, truncated JSONL stream, and strict batch failure.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

fn fixture_dir() -> PathBuf {
    luad_oracle::find_workspace_root().join("tests/fixtures/firmware_tree")
}

fn parse_jsonl(output: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(output.to_vec())
        .expect("output is UTF-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid JSON line"))
        .collect()
}

// ---------------------------------------------------------------------------
// Test 1: Fixture tree manifest integrity
// ---------------------------------------------------------------------------

#[test]
fn test_firmware_tree_manifest_integrity() {
    let manifest_path = fixture_dir().join("MANIFEST.json");
    let manifest_content = fs::read_to_string(&manifest_path).expect("read MANIFEST.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_content).expect("valid MANIFEST.json");

    assert_eq!(manifest["schema_version"], 1);
    let cases = manifest["cases"]
        .as_array()
        .expect("cases array in manifest");
    assert_eq!(cases.len(), 5, "manifest must declare exactly 5 test cases");

    let root = luad_oracle::find_workspace_root();

    for case in cases {
        let rel_path = case["path"].as_str().expect("case path");
        let expected_sha256 = case["sha256"].as_str().expect("case sha256");
        let expected_len = case["byte_length"].as_u64().expect("case byte_length");

        let abs_path = root.join(rel_path);
        let bytes = fs::read(&abs_path)
            .unwrap_or_else(|e| panic!("failed to read fixture at {:?}: {}", abs_path, e));

        assert_eq!(
            bytes.len() as u64,
            expected_len,
            "byte length mismatch for {rel_path}"
        );

        let actual_hash = format!("{:x}", Sha256::digest(&bytes));
        assert_eq!(
            actual_hash, expected_sha256,
            "sha256 mismatch for {rel_path}"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 2: Phase 1 — Inventory and batch triage via `luad export`
// ---------------------------------------------------------------------------

#[test]
fn test_firmware_walkthrough_phase1_inventory_batch_export() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();

    let files = [
        fdir.join("dispatcher.lua"),
        fdir.join("system_service.luac"),
        fdir.join("network_setup.lua"),
        fdir.join("corrupted_module.luac"),
        fdir.join("mips_be_legacy.luac"),
    ];

    // 1. Default batch export on mixed firmware tree: exits 0 because at least 1 succeeded
    let mut cmd = Command::new(&luad);
    cmd.arg("export");
    for f in &files {
        cmd.arg(f);
    }
    cmd.args(["--format", "jsonl"]);

    let output = cmd.output().expect("execute batch export");
    assert_eq!(
        output.status.code(),
        Some(0),
        "default batch export should exit 0 on mixed tree with valid chunks: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let records = parse_jsonl(&output.stdout);
    assert!(
        !records.is_empty(),
        "batch export should emit JSONL records"
    );

    // Terminal record MUST be export_end
    let last_record = records
        .last()
        .expect("export should have at least one record");
    assert_eq!(
        last_record["record_type"], "export_end",
        "terminal record must be export_end"
    );

    let processed = last_record["files_processed"]
        .as_u64()
        .expect("files_processed");
    let succeeded = last_record["files_succeeded"]
        .as_u64()
        .expect("files_succeeded");
    let skipped = last_record["files_skipped"]
        .as_u64()
        .expect("files_skipped");
    let failed = last_record["files_failed"].as_u64().expect("files_failed");
    let total_instructions = last_record["total_instructions"]
        .as_u64()
        .expect("total_instructions");

    assert_eq!(processed, 5, "files_processed must be 5");
    assert_eq!(succeeded, 2, "files_succeeded must be 2");
    assert_eq!(skipped, 3, "files_skipped must be 3");
    assert_eq!(failed, 0, "files_failed must be 0");
    assert_eq!(
        processed,
        succeeded + skipped + failed,
        "closure invariant: processed == succeeded + skipped + failed"
    );
    assert_eq!(
        total_instructions, 102,
        "total instructions across succeeded chunks must match 75 + 27 = 102"
    );

    // Verify per-file file_end records
    let file_ends: BTreeMap<String, &serde_json::Value> = records
        .iter()
        .filter(|r| r["record_type"] == "file_end")
        .map(|r| {
            let path = r["path"].as_str().expect("file_end path");
            let filename = Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            (filename, r)
        })
        .collect();

    assert_eq!(file_ends.len(), 5, "must have 5 file_end records");
    assert_eq!(file_ends["dispatcher.lua"]["status"], "succeeded");
    assert_eq!(file_ends["system_service.luac"]["status"], "succeeded");
    assert_eq!(file_ends["network_setup.lua"]["status"], "skipped");
    assert_eq!(file_ends["corrupted_module.luac"]["status"], "skipped");
    assert_eq!(file_ends["mips_be_legacy.luac"]["status"], "skipped");

    // 2. Strict batch export on mixed firmware tree: exits 1 because inputs were skipped
    let mut strict_cmd = Command::new(&luad);
    strict_cmd.arg("export");
    for f in &files {
        strict_cmd.arg(f);
    }
    strict_cmd.args(["--format", "jsonl", "--strict"]);

    let strict_output = strict_cmd.output().expect("execute strict batch export");
    assert_eq!(
        strict_output.status.code(),
        Some(1),
        "strict batch export must exit 1 when any file is skipped"
    );

    let strict_records = parse_jsonl(&strict_output.stdout);
    let strict_last = strict_records.last().expect("strict export_end");
    assert_eq!(
        strict_last["record_type"], "export_end",
        "terminal record in strict export must still be export_end"
    );
    assert_eq!(strict_last["files_processed"], 5);
    assert_eq!(strict_last["files_skipped"], 3);
}

// ---------------------------------------------------------------------------
// Test 3: Phase 2 — Inspection and layout detection/rejection
// ---------------------------------------------------------------------------

#[test]
fn test_firmware_walkthrough_phase2_inspection_and_layout() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();

    // 1. dispatcher.lua: Valid OpenWrt LNUM32 bytecode
    let output = Command::new(&luad)
        .args([
            "inspect",
            fdir.join("dispatcher.lua").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect dispatcher.lua");
    assert_eq!(
        output.status.code(),
        Some(0),
        "dispatcher.lua must inspect successfully"
    );
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from inspect");
    assert_eq!(v["interpretation"]["profile"], "lua5.1-lnum32");
    assert_eq!(
        v["interpretation"]["validated_layout"],
        "int=4,sizet=4,inst=4,num=8,endian=1,integral_flag=4"
    );
    assert_eq!(
        v["input_identity"]["sha256"],
        "21b751768c37a930607c8a04e803206554887ef9b8a6f9c415a8cba6a8be4a3c"
    );

    // 2. system_service.luac: Valid stock Lua 5.1 bytecode
    let output = Command::new(&luad)
        .args([
            "inspect",
            fdir.join("system_service.luac").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect system_service.luac");
    assert_eq!(
        output.status.code(),
        Some(0),
        "system_service.luac must inspect successfully"
    );
    let v: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON from inspect");
    assert_eq!(v["interpretation"]["profile"], "lua5.1");
    assert_eq!(
        v["interpretation"]["validated_layout"],
        "int=4,sizet=8,inst=4,num=8,endian=1,integral_flag=0"
    );

    // 3. network_setup.lua: Plain text source file -> must exit 4 (UnsupportedFormat)
    let output = Command::new(&luad)
        .args([
            "inspect",
            fdir.join("network_setup.lua").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect network_setup.lua");
    assert_eq!(
        output.status.code(),
        Some(4),
        "network_setup.lua must exit 4 (UnsupportedFormat)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown or unsupported bytecode format")
            || stderr.contains("PARSE-SOURCE-001"),
        "stderr must explain format rejection: {stderr}"
    );

    // 4. corrupted_module.luac: Truncated header -> must exit 1 (InvalidInput) with offset 10
    let output = Command::new(&luad)
        .args([
            "inspect",
            fdir.join("corrupted_module.luac").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect corrupted_module.luac");
    assert_eq!(
        output.status.code(),
        Some(1),
        "corrupted_module.luac must exit 1 (InvalidInput)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("offset 10"),
        "stderr must identify failure offset 10: {stderr}"
    );

    // 5. mips_be_legacy.luac: Big-endian unsupported layout -> must exit 1 (InvalidInput) with offset 6
    let output = Command::new(&luad)
        .args([
            "inspect",
            fdir.join("mips_be_legacy.luac").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect mips_be_legacy.luac");
    assert_eq!(
        output.status.code(),
        Some(1),
        "mips_be_legacy.luac must exit 1 (InvalidInput)"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("offset 6"),
        "stderr must identify failure offset 6: {stderr}"
    );
    assert!(
        stderr.contains("endianness"),
        "stderr must mention endianness rejection: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Phase 3 — Auditing facts (constants, query, disasm, callees, origins)
// ---------------------------------------------------------------------------

#[test]
fn test_firmware_walkthrough_phase3_auditing_facts() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();
    let target = fdir.join("dispatcher.lua");

    // 1. Fact extraction: string constants via `export --facts constant`
    let output = Command::new(&luad)
        .args([
            "export",
            target.to_str().unwrap(),
            "--format",
            "jsonl",
            "--facts",
            "constant",
        ])
        .output()
        .expect("export constants");
    assert_eq!(output.status.code(), Some(0));
    let records = parse_jsonl(&output.stdout);

    let mut string_constants = Vec::new();
    for r in records {
        if r["record_type"] == "constant" {
            if let Some(display) = r["data"]["value"]["value"]["display"].as_str() {
                string_constants.push(display.to_string());
            }
        }
    }

    assert!(
        string_constants.iter().any(|s| s == "openwrt-lnum32"),
        "should find 'openwrt-lnum32' constant: {:?}",
        string_constants
    );
    assert!(
        string_constants.iter().any(|s| s == "key"),
        "should find 'key' constant"
    );
    assert!(
        string_constants.iter().any(|s| s == "branch"),
        "should find 'branch' constant"
    );
    assert!(
        string_constants.iter().any(|s| s == "never"),
        "should find 'never' constant"
    );

    // 2. Global lookup query: `query --where "mnemonic == 'GETGLOBAL'"`
    let output = Command::new(&luad)
        .args([
            "query",
            target.to_str().unwrap(),
            "--where",
            "mnemonic == 'GETGLOBAL'",
            "--format",
            "json",
        ])
        .output()
        .expect("query GETGLOBAL");
    assert_eq!(output.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("query JSON");
    let matches = v["data"]["matches"]
        .as_array()
        .expect("query matches array");
    assert_eq!(matches.len(), 2, "dispatcher.lua contains 2 GETGLOBAL ops");

    // 3. Raw disassembly with effect annotations: `disasm --raw --effects`
    let output = Command::new(&luad)
        .args([
            "disasm",
            target.to_str().unwrap(),
            "--raw",
            "--effects",
            "--format",
            "text",
        ])
        .output()
        .expect("disasm raw effects");
    assert_eq!(output.status.code(), Some(0));
    let disasm_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        disasm_text.contains("[0x"),
        "disassembly must include raw hex instruction words"
    );
    assert!(
        disasm_text.contains("reads:") && disasm_text.contains("writes:"),
        "disassembly must include effect annotations"
    );
    assert!(
        disasm_text.contains("GETGLOBAL"),
        "disassembly must include mnemonics"
    );
    assert!(
        disasm_text.contains("CLOSURE"),
        "disassembly must include closure instructions"
    );

    // 4. Callee resolution: `callees --format json`
    let output = Command::new(&luad)
        .args(["callees", target.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("callees");
    assert_eq!(output.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("callees JSON");
    assert_eq!(v["schema_version"], 1);
    assert!(v["data"]["prototypes"].as_array().is_some());

    // 5. Origin tracing: `origins --format json`
    let output = Command::new(&luad)
        .args(["origins", target.to_str().unwrap(), "--format", "json"])
        .output()
        .expect("origins");
    assert_eq!(output.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("origins JSON");
    assert_eq!(v["schema_version"], 1);
    assert!(v["data"]["prototypes"].as_array().is_some());
}

// ---------------------------------------------------------------------------
// Test 5: Phase 4 — Pinned decompiler handoff boundary
// ---------------------------------------------------------------------------

#[test]
fn test_firmware_walkthrough_phase4_decompiler_handoff_boundary() {
    let luad = get_luad_bin();
    let fdir = fixture_dir();

    // 1. Stock candidate (system_service.luac):
    // Standard desktop layout: 64-bit size_t (8), integral flag 0.
    // Stock decompilers (e.g. unluac, ChunkSpy, luadec) can decompile this cleanly.
    let output = Command::new(&luad)
        .args([
            "inspect",
            fdir.join("system_service.luac").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect stock candidate");
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(v["interpretation"]["profile"], "lua5.1");
    let layout_str = v["interpretation"]["validated_layout"].as_str().unwrap();
    assert!(layout_str.contains("sizet=8"));
    assert!(layout_str.contains("integral_flag=0"));

    // 2. Embedded candidate (dispatcher.lua):
    // Non-stock OpenWrt layout: 32-bit size_t (4), integral flag 4.
    // Standard decompilers will reject or corrupt this chunk because of the non-stock integral flag.
    let output = Command::new(&luad)
        .args([
            "inspect",
            fdir.join("dispatcher.lua").to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("inspect embedded candidate");
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(v["interpretation"]["profile"], "lua5.1-lnum32");
    let layout_str = v["interpretation"]["validated_layout"].as_str().unwrap();
    assert!(layout_str.contains("sizet=4"));
    assert!(layout_str.contains("integral_flag=4"));

    // Verify that validating dispatcher.lua under strict stock expectations reports the layout divergence
    let lnum_bytes = fs::read(fdir.join("dispatcher.lua")).expect("read dispatcher.lua");
    // Header format byte 0, but size_t is 4 (offset 8) and integral_flag is 4 (offset 11)
    assert_eq!(lnum_bytes[8], 4, "size_t is 4 in lnum32");
    assert_eq!(lnum_bytes[11], 4, "integral_flag is 4 in lnum32");

    let stock_bytes = fs::read(fdir.join("system_service.luac")).expect("read system_service.luac");
    assert_eq!(stock_bytes[8], 8, "size_t is 8 in stock 64-bit");
    assert_eq!(stock_bytes[11], 0, "integral_flag is 0 in stock");
}

// ---------------------------------------------------------------------------
// Test 6: Negative controls (tampering, truncation, strict mode)
// ---------------------------------------------------------------------------

#[test]
fn test_firmware_walkthrough_negative_controls() {
    let fdir = fixture_dir();
    let root = luad_oracle::find_workspace_root();

    // 1. Fixture Tampering Negative Control:
    // Any mutation to fixture bytes must cause manifest hash check to fail
    let original_bytes = fs::read(fdir.join("dispatcher.lua")).expect("read dispatcher");
    let mut tampered = original_bytes.clone();
    tampered[12] ^= 0xFF; // flip byte in prototype header

    let original_hash = format!("{:x}", Sha256::digest(&original_bytes));
    let tampered_hash = format!("{:x}", Sha256::digest(&tampered));
    assert_ne!(
        original_hash, tampered_hash,
        "tampering must alter SHA-256 hash"
    );

    let manifest_path = fdir.join("MANIFEST.json");
    let manifest_content = fs::read_to_string(&manifest_path).expect("read MANIFEST.json");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_content).unwrap();
    let expected_hash = manifest["cases"][0]["sha256"].as_str().unwrap();
    assert_eq!(original_hash, expected_hash);
    assert_ne!(
        tampered_hash, expected_hash,
        "tampered fixture must fail manifest hash verification"
    );

    // 2. Stream Truncation Negative Control:
    // A downstream consumer requiring `export_end` must reject an incomplete JSONL stream
    let luad = get_luad_bin();
    let output = Command::new(&luad)
        .args([
            "export",
            root.join("tests/fixtures/firmware_tree/dispatcher.lua")
                .to_str()
                .unwrap(),
            "--format",
            "jsonl",
        ])
        .output()
        .expect("export single");
    assert_eq!(output.status.code(), Some(0));

    let full_lines: Vec<&str> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert!(full_lines.len() > 1);

    // Function simulating consumer completion check
    fn verify_export_stream_complete(lines: &[&str]) -> Result<u64, &'static str> {
        let last = lines.last().ok_or("empty stream")?;
        let rec: serde_json::Value =
            serde_json::from_str(last).map_err(|_| "malformed JSON line")?;
        if rec["record_type"] == "export_end" {
            Ok(rec["files_processed"].as_u64().unwrap_or(0))
        } else {
            Err("stream truncated: missing terminal export_end record")
        }
    }

    // Complete stream passes
    assert!(verify_export_stream_complete(&full_lines).is_ok());

    // Truncated stream (omitting last line) fails
    let truncated_lines = &full_lines[..full_lines.len() - 1];
    let err = verify_export_stream_complete(truncated_lines).unwrap_err();
    assert_eq!(err, "stream truncated: missing terminal export_end record");

    // 3. Strict Mode Negative Control:
    // Verify that --strict turns batch export on mixed tree into exit code 1
    let strict_status = Command::new(&luad)
        .args([
            "export",
            fdir.join("dispatcher.lua").to_str().unwrap(),
            fdir.join("network_setup.lua").to_str().unwrap(),
            "--format",
            "jsonl",
            "--strict",
        ])
        .output()
        .expect("strict export");
    assert_eq!(
        strict_status.status.code(),
        Some(1),
        "--strict must exit with code 1 when any file cannot be exported"
    );
}
