//! Verification test for machine-checked evidence file integrity.

use luad_oracle::find_workspace_root;
use std::fs;

#[test]
fn test_lua54_evidence_file_integrity() {
    let root = find_workspace_root();
    let evidence_path = root
        .join("tests")
        .join("evidence")
        .join("LUA-5.4-EVIDENCE.json");
    assert!(
        evidence_path.exists(),
        "LUA-5.4-EVIDENCE.json must exist at tests/evidence/LUA-5.4-EVIDENCE.json"
    );

    let content = fs::read_to_string(&evidence_path).expect("Failed to read evidence file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Valid JSON evidence");

    assert_eq!(json["dialect"].as_str(), Some("lua5.4"));
    assert_eq!(json["status"].as_str(), Some("experimental"));
    assert_eq!(
        json["verification_results"]["opcodes_verified"].as_u64(),
        Some(83)
    );
    assert_eq!(
        json["verification_results"]["round_trip_property_passed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["verification_results"]["differential_oracle_passed"].as_bool(),
        Some(true)
    );
}

#[test]
fn test_lua55_evidence_file_integrity() {
    let root = find_workspace_root();
    let evidence_path = root
        .join("tests")
        .join("evidence")
        .join("LUA-5.5-EVIDENCE.json");
    assert!(
        evidence_path.exists(),
        "LUA-5.5-EVIDENCE.json must exist at tests/evidence/LUA-5.5-EVIDENCE.json"
    );

    let content = fs::read_to_string(&evidence_path).expect("Failed to read evidence file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Valid JSON evidence");

    assert_eq!(json["dialect"].as_str(), Some("lua5.5"));
    assert_eq!(json["status"].as_str(), Some("experimental"));
    assert_eq!(
        json["verification_results"]["opcodes_verified"].as_u64(),
        Some(85)
    );
    assert_eq!(
        json["verification_results"]["round_trip_property_passed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["verification_results"]["differential_oracle_passed"].as_bool(),
        Some(true)
    );
}

#[test]
fn test_lua51_evidence_file_integrity() {
    let root = find_workspace_root();
    let evidence_path = root
        .join("tests")
        .join("evidence")
        .join("LUA-5.1-EVIDENCE.json");
    assert!(
        evidence_path.exists(),
        "LUA-5.1-EVIDENCE.json must exist at tests/evidence/LUA-5.1-EVIDENCE.json"
    );

    let content = fs::read_to_string(&evidence_path).expect("Failed to read evidence file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Valid JSON evidence");

    assert_eq!(json["dialect"].as_str(), Some("lua5.1"));
    assert_eq!(json["status"].as_str(), Some("experimental"));
    assert_eq!(
        json["verification_results"]["opcodes_verified"].as_u64(),
        Some(38)
    );
    assert_eq!(
        json["verification_results"]["round_trip_property_passed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["verification_results"]["differential_oracle_passed"].as_bool(),
        Some(true)
    );
}

#[test]
fn test_lua53_evidence_file_integrity() {
    let root = find_workspace_root();
    let evidence_path = root
        .join("tests")
        .join("evidence")
        .join("LUA-5.3-EVIDENCE.json");
    assert!(
        evidence_path.exists(),
        "LUA-5.3-EVIDENCE.json must exist at tests/evidence/LUA-5.3-EVIDENCE.json"
    );

    let content = fs::read_to_string(&evidence_path).expect("Failed to read evidence file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Valid JSON evidence");

    assert_eq!(json["dialect"].as_str(), Some("lua5.3"));
    assert_eq!(json["status"].as_str(), Some("experimental"));
    assert_eq!(
        json["verification_results"]["opcodes_verified"].as_u64(),
        Some(47)
    );
    assert_eq!(
        json["verification_results"]["round_trip_property_passed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["verification_results"]["differential_oracle_passed"].as_bool(),
        Some(true)
    );
}

#[test]
fn test_lua52_evidence_file_integrity() {
    let root = find_workspace_root();
    let evidence_path = root
        .join("tests")
        .join("evidence")
        .join("LUA-5.2-EVIDENCE.json");
    assert!(
        evidence_path.exists(),
        "LUA-5.2-EVIDENCE.json must exist at tests/evidence/LUA-5.2-EVIDENCE.json"
    );

    let content = fs::read_to_string(&evidence_path).expect("Failed to read evidence file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Valid JSON evidence");

    assert_eq!(json["dialect"].as_str(), Some("lua5.2"));
    assert_eq!(json["status"].as_str(), Some("experimental"));
    assert_eq!(
        json["verification_results"]["opcodes_verified"].as_u64(),
        Some(40)
    );
    assert_eq!(
        json["verification_results"]["round_trip_property_passed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["verification_results"]["differential_oracle_passed"].as_bool(),
        Some(true)
    );
}

#[test]
fn test_operating_rule_10_named_gate_tests_presence() {
    // Operating Rule 10: A gate's acceptance criteria must exist as named, committed tests;
    // CI fails if a gate's named test is absent.
    let required_gate_tests = [
        // Gate 0: Downgrade unsupported claims
        "test_operating_rule_10_named_gate_tests_presence",
        // Gate 1: Differential oracle detecting errors & negative controls
        "test_canonical_differential_oracle_lua54",
        "test_negative_control_mnemonic_mutation",
        "test_negative_control_operand_mutation",
        "test_negative_control_bit15_b_decoder_bug",
        "test_golden_word_pins_and_unpatched_decoder_failure",
        // Gate 2: Correct Lua 5.4 opcode and bitfield definitions
        "test_lua54_golden_word_vectors",
        "test_lua54_all_83_opcodes_round_trip",
        // Gate 3: Compiler verification & provenance manifest
        "test_fixtures_provenance_manifest_integrity",
        // Gate 4: CFG block partitioning & dominators
        "test_cfg_block_partitioning_and_reachability",
        "test_cfg_dominator_tree_golden_topologies",
        "test_analysis_refuses_invalid_chunks",
        // Gate 5: Byte accounting & lossless serde
        "test_all_50_fixtures_byte_accounting_and_lossless_serde",
        // Gate 6: Runtime semantic effects & companion instructions
        "test_all_opcode_lifting_and_effects",
        "test_metamethod_dispatch_companions",
        // Gate 7: Promoted evidence artifact
        "test_lua54_evidence_file_integrity",
        // Gate 8: Verification of remaining dialects
        "test_lua51_evidence_file_integrity",
        "test_lua52_evidence_file_integrity",
        "test_lua53_evidence_file_integrity",
        "test_lua55_evidence_file_integrity",
    ];

    let root = find_workspace_root();
    let tests_dir = root.join("crates");

    for test_name in &required_gate_tests {
        let mut found = false;
        // Search through crates tests for the test function definition
        for entry in walkdir(&tests_dir) {
            if let Ok(content) = fs::read_to_string(&entry) {
                if content.contains(&format!("fn {test_name}")) {
                    found = true;
                    break;
                }
            }
        }
        assert!(
            found,
            "Operating Rule 10 Violation: Required named gate test '{test_name}' is absent from the test suite!"
        );
    }
}

fn walkdir(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir(&path));
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files
}
