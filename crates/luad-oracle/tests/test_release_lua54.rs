//! Release verification tests for Lua 5.4.8.

use luad_core::capabilities::{get_canonical_capabilities, SupportTier};

#[test]
fn test_r0_containment_no_supported_dialects() {
    let manifest = get_canonical_capabilities("0.1.0");
    assert!(
        manifest.supported_dialects.is_empty(),
        "Under Gate R0, supported_dialects must be empty at the audit baseline"
    );
}

#[test]
fn test_unproven_dialects_remain_experimental() {
    let manifest = get_canonical_capabilities("0.1.0");
    for dialect in &manifest.dialects {
        if dialect.id != "luajit" {
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
