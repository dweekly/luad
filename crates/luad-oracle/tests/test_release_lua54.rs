//! Gate P5: Promotion and release verification tests for Lua 5.4.8.

use luad_core::capabilities::{get_canonical_capabilities, SupportTier};
use luad_oracle::find_workspace_root;
use std::fs;

#[test]
fn test_release_gate_promotes_only_lua54_8() {
    let manifest = get_canonical_capabilities("0.1.0");
    assert_eq!(
        manifest.supported_dialects,
        vec!["lua5.4"],
        "Under Gate P5, only lua5.4 is promoted to supported"
    );
    let lua54 = manifest
        .dialects
        .iter()
        .find(|d| d.id == "lua5.4")
        .expect("lua5.4 present");
    assert_eq!(lua54.display_name, "Lua 5.4.8");
    assert_eq!(lua54.status, SupportTier::Supported);
    assert_eq!(
        lua54.completed_gates,
        vec![
            "gate-facts-lua54-8",
            "gate-analysis-cfg",
            "gate-lossless-lua54-8",
            "gate-release-lua54-8"
        ]
    );
}

#[test]
fn test_unproven_dialects_remain_experimental() {
    let manifest = get_canonical_capabilities("0.1.0");
    for dialect in &manifest.dialects {
        if dialect.id != "lua5.4" && dialect.id != "luajit" {
            assert_eq!(
                dialect.status,
                SupportTier::Experimental,
                "Dialect '{}' must remain Experimental until its gates pass",
                dialect.id
            );
            assert!(
                dialect.completed_gates.is_empty(),
                "Unproven dialect '{}' must have empty completed_gates",
                dialect.id
            );
        }
    }
}

#[test]
fn test_capabilities_manifest_matches_evidence_file() {
    let root = find_workspace_root();
    let proof_path = root
        .join("tests")
        .join("evidence")
        .join("LUA-5.4.8-PROOF.json");
    assert!(proof_path.exists(), "LUA-5.4.8-PROOF.json must exist");

    let content = fs::read_to_string(&proof_path).expect("Read proof file");
    let json: serde_json::Value = serde_json::from_str(&content).expect("Valid JSON proof");

    assert_eq!(json["dialect"].as_str(), Some("lua5.4"));
    assert_eq!(json["display_name"].as_str(), Some("Lua 5.4.8"));
    assert_eq!(json["status"].as_str(), Some("supported"));
    assert_eq!(json["compiler_version"].as_str(), Some("Lua 5.4.8"));

    let completed_gates = json["completed_gates"]
        .as_array()
        .expect("completed_gates array");
    let gates_str: Vec<&str> = completed_gates.iter().filter_map(|g| g.as_str()).collect();
    assert_eq!(
        gates_str,
        vec![
            "gate-facts-lua54-8",
            "gate-analysis-cfg",
            "gate-lossless-lua54-8",
            "gate-release-lua54-8"
        ]
    );
}

#[test]
fn test_negative_control_incomplete_gate_set_rejects_promotion() {
    let mut manifest = get_canonical_capabilities("0.1.0");
    let lua54 = manifest
        .dialects
        .iter_mut()
        .find(|d| d.id == "lua5.4")
        .unwrap();

    // Drop one required gate from completed_gates
    lua54.completed_gates.pop();

    // Verification must fail when any required gate is missing
    let has_all_gates = lua54
        .required_gates
        .iter()
        .all(|req| lua54.completed_gates.contains(req));
    assert!(
        !has_all_gates,
        "Incomplete completed_gates MUST reject promotion"
    );
}
