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
    assert_eq!(json["status"].as_str(), Some("supported"));
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
    assert_eq!(json["status"].as_str(), Some("supported"));
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
    assert_eq!(json["status"].as_str(), Some("supported"));
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
    assert_eq!(json["status"].as_str(), Some("supported"));
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
    assert_eq!(json["status"].as_str(), Some("supported"));
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
