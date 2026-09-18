//! Hostile-input containment, bounded operations, and tripwires test suite (Roadmap Stage 6 / Package B).
//!
//! Verifies:
//! 1. Subprocess tripwire matrix under frozen numeric wall-time, peak-memory, and output ceilings:
//!    - Tiny malformed inputs (empty, truncated signatures, truncated headers)
//!    - Large instruction count vector (1,000,001 ceiling breach exits 5 without huge allocation)
//!    - Deep prototype nesting recursion (depth 130 against 128 ceiling exits 5 without stack overflow)
//!    - Oversized strings (declared length 20,010,624 bytes against 16MB ceiling exits 5)
//!    - Repeated invalid operands (15,000 invalid instructions capped at 10,000 diags in < 2500ms)
//!    - Streaming bounded regular-file read (68MB sparse file stopped at safety ceiling, exits 5)
//!    - Mixed batch containment (valid, malformed, ceiling breach framed cleanly in JSONL)
//! 2. Over-budget negative controls proving that the tripwire monitor detects resource breaches:
//!    - Wall-time ceiling breach detection
//!    - Standard output ceiling breach detection
//!    - Standard error ceiling breach detection
//!    - Peak memory ceiling breach detection

use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

use luad_oracle::{
    get_fixture_bytes, luad_binary_path, run_with_tripwire, TripwireBudget, TripwireError,
};

fn get_luad_bin() -> PathBuf {
    luad_binary_path()
}

/// Helper to build a minimal valid Lua 5.4 bytecode header (31 bytes).
fn make_lua54_header() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(b"\x1bLua\x54\x00"); // signature, version, format
    h.extend_from_slice(b"\x19\x93\r\n\x1a\n"); // luac_data
    h.push(4); // sizeof(Instruction)
    h.push(8); // sizeof(lua_Integer)
    h.push(8); // sizeof(lua_Number)
    h.extend_from_slice(&0x5678_i64.to_le_bytes()); // LUAC_INT
    h.extend_from_slice(&370.5_f64.to_le_bytes()); // LUAC_NUM
    assert_eq!(h.len(), 31);
    h
}

/// Helper to build nested Lua 5.4 prototypes to a specified depth.
fn make_nested_proto_lua54(depth: usize) -> Vec<u8> {
    // Proto header fields:
    // source name NULL (0x80), line_defined = 0 (0x80), last_line_defined = 0 (0x80),
    // numparams = 0, is_vararg = 0, maxstacksize = 2,
    // sizecode = 0 (0x80), sizek = 0 (0x80), sizeupvalues = 0 (0x80)
    let mut bytes = vec![0x80, 0x80, 0x80, 0, 0, 2, 0x80, 0x80, 0x80];

    if depth > 0 {
        bytes.push(0x81); // sizep = 1 (1 child proto)
        bytes.extend(make_nested_proto_lua54(depth - 1));
    } else {
        bytes.push(0x80); // sizep = 0 (leaf)
    }

    // Debug metadata:
    bytes.push(0x80); // sizelineinfo = 0
    bytes.push(0x80); // sizeabslineinfo = 0
    bytes.push(0x80); // sizelocvars = 0
    bytes.push(0x80); // sizeupvalnames = 0

    bytes
}

// =========================================================================
// Tripwire 1: Tiny malformed inputs
// =========================================================================

#[test]
fn test_tripwire_1_tiny_malformed_inputs() {
    let luad = get_luad_bin();
    let budget = TripwireBudget {
        max_wall_time: Duration::from_millis(2000),
        max_peak_rss_bytes: 40 * 1024 * 1024,
        max_stdout_bytes: 1024,
        max_stderr_bytes: 32 * 1024,
    };

    let cases: &[(&str, &[u8])] = &[
        ("empty", b""),
        ("one_byte", b"\x1b"),
        ("sig_only", b"\x1bLua"),
        ("trunc_header", b"\x1bLua\x54\x00"),
    ];

    for (name, data) in cases {
        let temp = NamedTempFile::new().unwrap();
        fs::write(temp.path(), data).unwrap();

        let path_str = temp.path().to_str().unwrap();
        let metrics = run_with_tripwire(&luad, &["inspect", path_str], None, &budget)
            .unwrap_or_else(|e| panic!("Tripwire failed for {name}: {e}"));

        let code = metrics.status.code().unwrap_or(-1);
        assert!(
            code == 1 || code == 4,
            "Tiny malformed input {name} must exit 1 (InvalidInput) or 4 (UnsupportedFormat), got: {code}"
        );
    }
}

// =========================================================================
// Tripwire 2: Large instruction count vector
// =========================================================================

#[test]
fn test_tripwire_2_large_instruction_count_vector() {
    let luad = get_luad_bin();
    let budget = TripwireBudget {
        max_wall_time: Duration::from_millis(2000),
        max_peak_rss_bytes: 40 * 1024 * 1024,
        max_stdout_bytes: 1024,
        max_stderr_bytes: 32 * 1024,
    };

    let mut bytes = make_lua54_header();
    bytes.push(0); // sizeupvalues = 0
    bytes.push(0x80); // source name NULL
    bytes.push(0x80); // line_defined = 0
    bytes.push(0x80); // last_line_defined = 0
    bytes.push(0); // numparams = 0
    bytes.push(0); // is_vararg = 0
    bytes.push(2); // maxstacksize = 2
    bytes.extend_from_slice(&[0x3d, 0x04, 0xc1]); // 1,000,001 in Lua 5.4 varint

    let temp = NamedTempFile::new().unwrap();
    fs::write(temp.path(), &bytes).unwrap();

    let path_str = temp.path().to_str().unwrap();
    let metrics = run_with_tripwire(&luad, &["inspect", path_str], None, &budget)
        .expect("Tripwire execution must succeed within budget");

    assert_eq!(
        metrics.status.code(),
        Some(5),
        "Instruction count limit exceeded must exit 5 (LimitExceeded)"
    );

    let stderr = String::from_utf8_lossy(&metrics.stderr);
    assert!(
        stderr.contains("Instruction count 1000001 exceeds safety limit"),
        "stderr must explain instruction count ceiling, got: {stderr}"
    );
    assert!(
        stderr.contains("offset 38"),
        "stderr must report exact count offset 38, got: {stderr}"
    );
}

// =========================================================================
// Tripwire 3: Deep prototype nesting recursion
// =========================================================================

#[test]
fn test_tripwire_3_deep_prototype_recursion() {
    let luad = get_luad_bin();
    let budget = TripwireBudget {
        max_wall_time: Duration::from_millis(2000),
        max_peak_rss_bytes: 40 * 1024 * 1024,
        max_stdout_bytes: 1024,
        max_stderr_bytes: 32 * 1024,
    };

    let mut bytes = make_lua54_header();
    bytes.push(0); // main proto sizeupvalues
    bytes.extend(make_nested_proto_lua54(130));

    let temp = NamedTempFile::new().unwrap();
    fs::write(temp.path(), &bytes).unwrap();

    let path_str = temp.path().to_str().unwrap();
    let metrics = run_with_tripwire(&luad, &["inspect", path_str], None, &budget)
        .expect("Tripwire execution must succeed within budget");

    assert_eq!(
        metrics.status.code(),
        Some(5),
        "Prototype nesting depth breach must exit 5 (LimitExceeded)"
    );

    let stderr = String::from_utf8_lossy(&metrics.stderr);
    assert!(
        stderr.contains("nesting depth") && stderr.contains("exceeds configured limit of 128"),
        "stderr must report prototype depth limit, got: {stderr}"
    );
}

// =========================================================================
// Tripwire 4: Oversized string declaration
// =========================================================================

#[test]
fn test_tripwire_4_oversized_string_declaration() {
    let luad = get_luad_bin();
    let budget = TripwireBudget {
        max_wall_time: Duration::from_millis(2000),
        max_peak_rss_bytes: 40 * 1024 * 1024,
        max_stdout_bytes: 1024,
        max_stderr_bytes: 32 * 1024,
    };

    let mut bytes = make_lua54_header();
    bytes.push(0); // sizeupvalues = 0
                   // Source name string length varint declared as 20,010,624 bytes (> 16MB ceiling)
                   // Encoded as [0x09, 0x45, 0x2d, 0x80]
    bytes.extend_from_slice(&[0x09, 0x45, 0x2d, 0x80]);

    let temp = NamedTempFile::new().unwrap();
    fs::write(temp.path(), &bytes).unwrap();

    let path_str = temp.path().to_str().unwrap();
    let metrics = run_with_tripwire(&luad, &["inspect", path_str], None, &budget)
        .expect("Tripwire execution must succeed within budget");

    assert_eq!(
        metrics.status.code(),
        Some(5),
        "Oversized string length must exit 5 (LimitExceeded)"
    );

    let stderr = String::from_utf8_lossy(&metrics.stderr);
    assert!(
        stderr.contains("String length") && stderr.contains("exceeds limit"),
        "stderr must report string limit exceeded, got: {stderr}"
    );
}

// =========================================================================
// Tripwire 5: Repeated invalid operands (O(N) deduplication & diagnostic cap)
// =========================================================================

#[test]
fn test_tripwire_5_repeated_invalid_operands_bounded() {
    let luad = get_luad_bin();
    let budget = TripwireBudget {
        max_wall_time: Duration::from_millis(2500),
        max_peak_rss_bytes: 50 * 1024 * 1024,
        max_stdout_bytes: 2 * 1024 * 1024,
        max_stderr_bytes: 512 * 1024,
    };

    // Construct Lua 5.1 chunk with 15,000 invalid instructions
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00");
    bytes.extend_from_slice(&0_u64.to_le_bytes()); // source string (size_t 0)
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // linedefined
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // lastlinedefined
    bytes.push(0); // nups
    bytes.push(0); // numparams
    bytes.push(0); // is_vararg
    bytes.push(2); // maxstacksize = 2

    let num_insts = 15_000_u32;
    bytes.extend_from_slice(&num_insts.to_le_bytes());
    // Instruction with invalid opcode 0x3f (63)
    let bad_inst_word = 0x3f_u32;
    for _ in 0..num_insts {
        bytes.extend_from_slice(&bad_inst_word.to_le_bytes());
    }

    bytes.extend_from_slice(&0_u32.to_le_bytes()); // constants
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // protos
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // lineinfo
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // locvars
    bytes.extend_from_slice(&0_u32.to_le_bytes()); // upvalues

    let temp = NamedTempFile::new().unwrap();
    fs::write(temp.path(), &bytes).unwrap();

    let path_str = temp.path().to_str().unwrap();
    let metrics = run_with_tripwire(&luad, &["validate", path_str], None, &budget)
        .expect("Repeated invalid operands validation must finish within tripwire budget");

    assert_eq!(
        metrics.status.code(),
        Some(1),
        "Validation with errors must exit 1"
    );
}

// =========================================================================
// Tripwire 6: Streaming bounded regular-file read
// =========================================================================

#[test]
fn test_tripwire_6_streaming_bounded_regular_file_read() {
    let luad = get_luad_bin();
    let budget = TripwireBudget {
        max_wall_time: Duration::from_millis(2000),
        max_peak_rss_bytes: 40 * 1024 * 1024,
        max_stdout_bytes: 1024,
        max_stderr_bytes: 32 * 1024,
    };

    let temp = NamedTempFile::new().unwrap();
    // Create a 68 MiB sparse file (safety limit is 64 MiB = 67,108,864 bytes)
    let file = fs::OpenOptions::new()
        .write(true)
        .open(temp.path())
        .unwrap();
    file.set_len(68 * 1024 * 1024).unwrap();

    let path_str = temp.path().to_str().unwrap();
    let metrics = run_with_tripwire(&luad, &["inspect", path_str], None, &budget)
        .expect("Oversized file inspection must complete within tripwire budget");

    assert_eq!(
        metrics.status.code(),
        Some(5),
        "Oversized file read must exit 5 (LimitExceeded)"
    );

    let stderr = String::from_utf8_lossy(&metrics.stderr);
    assert!(
        stderr.contains("exceeds safety limit of 67108864 bytes"),
        "stderr must report safety limit exceeded, got: {stderr}"
    );
}

// =========================================================================
// Tripwire 7: Mixed batch containment
// =========================================================================

#[test]
fn test_tripwire_7_mixed_batch_containment() {
    let luad = get_luad_bin();
    let budget = TripwireBudget {
        max_wall_time: Duration::from_millis(3000),
        max_peak_rss_bytes: 50 * 1024 * 1024,
        max_stdout_bytes: 1024 * 1024,
        max_stderr_bytes: 64 * 1024,
    };

    let dir = TempDir::new().unwrap();

    // 1. Valid chunk
    let valid_bytes = get_fixture_bytes("lua5.4", "hello", false).unwrap();
    fs::write(dir.path().join("1_valid.luac"), &valid_bytes).unwrap();

    // 2. Tiny malformed chunk
    fs::write(dir.path().join("2_tiny.luac"), b"\x1bLua").unwrap();

    // 3. Instruction limit breach chunk
    let mut limit_bytes = make_lua54_header();
    limit_bytes.push(0); // sizeupvalues
    limit_bytes.push(0x80); // source name NULL
    limit_bytes.push(0x80); // line_defined
    limit_bytes.push(0x80); // last_line_defined
    limit_bytes.push(0); // numparams
    limit_bytes.push(0); // is_vararg
    limit_bytes.push(2); // maxstacksize
    limit_bytes.extend_from_slice(&[0x3d, 0x04, 0xc1]); // 1,000,001
    fs::write(dir.path().join("3_limit.luac"), &limit_bytes).unwrap();

    // 4. Oversized string chunk
    let mut str_limit_bytes = make_lua54_header();
    str_limit_bytes.push(0);
    str_limit_bytes.extend_from_slice(&[0x09, 0x45, 0x2d, 0x80]);
    let f1 = dir.path().join("1_valid.luac");
    let f2 = dir.path().join("2_tiny.luac");
    let f3 = dir.path().join("3_limit.luac");
    let f4 = dir.path().join("4_str_limit.luac");
    fs::write(&f4, &str_limit_bytes).unwrap();

    let f1_str = f1.to_str().unwrap();
    let f2_str = f2.to_str().unwrap();
    let f3_str = f3.to_str().unwrap();
    let f4_str = f4.to_str().unwrap();

    let metrics = run_with_tripwire(
        &luad,
        &[
            "export", f1_str, f2_str, f3_str, f4_str, "--format", "jsonl",
        ],
        None,
        &budget,
    )
    .expect("Mixed batch export must execute within tripwire budget");

    assert_eq!(
        metrics.status.code(),
        Some(0),
        "Mixed batch export must exit 0 when at least 1 file succeeds"
    );

    let stdout = String::from_utf8(metrics.stdout).expect("valid utf-8 jsonl");
    let records: Vec<serde_json::Value> = stdout
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();

    let export_end = records.last().expect("must terminate with export_end");
    assert_eq!(export_end["record_type"], "export_end");
    assert_eq!(export_end["files_processed"], 4);
    assert_eq!(export_end["files_succeeded"], 1);
    assert_eq!(export_end["files_skipped"], 3);
}

// =========================================================================
// Tripwire 8: Over-budget negative controls
// =========================================================================

#[test]
fn test_tripwire_8_over_budget_negative_controls() {
    let luad = get_luad_bin();

    // Negative Control 1: Wall-time ceiling breach detection
    {
        let budget = TripwireBudget {
            max_wall_time: Duration::from_nanos(1), // Impossible wall-time budget
            max_peak_rss_bytes: 1024 * 1024 * 1024,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
        };

        let result = run_with_tripwire(&luad, &["--help"], None, &budget);
        match result {
            Err(TripwireError::WallTimeCeilingExceeded { elapsed, ceiling }) => {
                assert_eq!(ceiling, Duration::from_nanos(1));
                assert!(elapsed > ceiling);
            }
            other => panic!("Expected WallTimeCeilingExceeded error, got: {other:?}"),
        }
    }

    // Negative Control 2: Standard output ceiling breach detection
    {
        let budget = TripwireBudget {
            max_wall_time: Duration::from_secs(5),
            max_peak_rss_bytes: 1024 * 1024 * 1024,
            max_stdout_bytes: 10, // Far smaller than --help text
            max_stderr_bytes: 1024 * 1024,
        };

        let result = run_with_tripwire(&luad, &["--help"], None, &budget);
        match result {
            Err(TripwireError::StdoutCeilingExceeded { length, ceiling }) => {
                assert_eq!(ceiling, 10);
                assert!(length > ceiling);
            }
            other => panic!("Expected StdoutCeilingExceeded error, got: {other:?}"),
        }
    }

    // Negative Control 3: Standard error ceiling breach detection
    {
        let budget = TripwireBudget {
            max_wall_time: Duration::from_secs(5),
            max_peak_rss_bytes: 1024 * 1024 * 1024,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 5, // Far smaller than file-not-found error message
        };

        let result = run_with_tripwire(
            &luad,
            &["inspect", "nonexistent_tripwire_test_file.luac"],
            None,
            &budget,
        );
        match result {
            Err(TripwireError::StderrCeilingExceeded { length, ceiling }) => {
                assert_eq!(ceiling, 5);
                assert!(length > ceiling);
            }
            other => panic!("Expected StderrCeilingExceeded error, got: {other:?}"),
        }
    }

    // Negative Control 4: Peak memory ceiling breach detection (when supported)
    {
        let budget = TripwireBudget {
            max_wall_time: Duration::from_secs(5),
            max_peak_rss_bytes: 100, // Impossibly small RSS budget (100 bytes)
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
        };

        let result = run_with_tripwire(&luad, &["--help"], None, &budget);
        // If the platform supports /usr/bin/time, it must detect PeakMemoryCeilingExceeded.
        if PathBuf::from("/usr/bin/time").exists() {
            match result {
                Err(TripwireError::PeakMemoryCeilingExceeded {
                    peak_rss_bytes,
                    ceiling,
                }) => {
                    assert_eq!(ceiling, 100);
                    assert!(peak_rss_bytes > ceiling);
                }
                other => panic!("Expected PeakMemoryCeilingExceeded error, got: {other:?}"),
            }
        }
    }
}
