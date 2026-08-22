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
