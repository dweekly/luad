//! Verification test suite for fixture provenance and MANIFEST.json integrity.

use luad_oracle::find_workspace_root;
use sha2::{Digest, Sha256};
use std::fs;

#[test]
fn test_fixtures_provenance_manifest_integrity() {
    let root = find_workspace_root();
    let manifest_path = root
        .join("tests")
        .join("fixtures")
        .join("precompiled")
        .join("MANIFEST.json");

    assert!(
        manifest_path.exists(),
        "MANIFEST.json must exist at tests/fixtures/precompiled/MANIFEST.json"
    );

    let manifest_bytes = fs::read(&manifest_path).expect("Failed to read MANIFEST.json");
    let manifest_json: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).expect("Valid MANIFEST.json");

    let fixtures = manifest_json["fixtures"]
        .as_array()
        .expect("fixtures array in MANIFEST.json");
    assert_eq!(
        fixtures.len(),
        50,
        "Expected 50 precompiled fixture entries in manifest"
    );

    for entry in fixtures {
        let source_path_rel = entry["source_path"].as_str().unwrap();
        let expected_source_sha = entry["source_sha256"].as_str().unwrap();
        let binary_path_rel = entry["binary_path"].as_str().unwrap();
        let expected_binary_sha = entry["binary_sha256"].as_str().unwrap();

        let source_path = root.join(source_path_rel);
        assert!(
            source_path.exists(),
            "Source fixture file must exist: {source_path:?}"
        );
        let source_data = fs::read(&source_path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&source_data);
        let actual_source_sha = hex::encode(hasher.finalize());
        assert_eq!(
            actual_source_sha, expected_source_sha,
            "Source SHA-256 mismatch for {source_path_rel}"
        );

        let binary_path = root.join(binary_path_rel);
        assert!(
            binary_path.exists(),
            "Binary fixture file must exist: {binary_path:?}"
        );
        let binary_data = fs::read(&binary_path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&binary_data);
        let actual_binary_sha = hex::encode(hasher.finalize());
        assert_eq!(
            actual_binary_sha, expected_binary_sha,
            "Binary SHA-256 mismatch for {binary_path_rel}"
        );
    }
}
