//! Verification test for machine-checked dialect manifest and fixture provenance integrity.

use luad_oracle::find_workspace_root;
use std::fs;

fn verify_manifest_dialect(dialect: &str, expected_count: usize, expected_archive_sha: &str) {
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

    let content = fs::read_to_string(&manifest_path).expect("Failed to read provenance manifest");
    let json: serde_json::Value =
        serde_json::from_str(&content).expect("Valid JSON provenance manifest");

    let fixtures = json["fixtures"].as_array().expect("fixtures array");
    let dialect_fixtures: Vec<&serde_json::Value> = fixtures
        .iter()
        .filter(|f| f["dialect"].as_str() == Some(dialect))
        .collect();

    assert_eq!(
        dialect_fixtures.len(),
        expected_count,
        "Must record all {expected_count} {dialect} fixtures in manifest"
    );

    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    for f in dialect_fixtures {
        assert_eq!(f["dialect"].as_str(), Some(dialect));
        assert!(
            f["fixture_name"].as_str().is_some(),
            "fixture_name must be present"
        );

        let src_path = f["source_path"].as_str().expect("source_path string");
        assert!(
            root.join(src_path).exists(),
            "source_path file must exist on disk: {src_path}"
        );

        let bin_path = f["binary_path"].as_str().expect("binary_path string");
        assert!(
            root.join(bin_path).exists(),
            "binary_path file must exist on disk: {bin_path}"
        );

        let src_sha = f["source_sha256"].as_str().expect("source_sha256 string");
        assert_ne!(src_sha, empty_hash, "source_sha256 must not be empty hash");

        let bin_sha = f["binary_sha256"].as_str().expect("binary_sha256 string");
        assert_ne!(bin_sha, empty_hash, "binary_sha256 must not be empty hash");

        let byte_len = f["byte_length"].as_u64().expect("byte_length number");
        assert!(byte_len > 0, "byte_length must be > 0");

        assert!(
            f["is_stripped"].as_bool().is_some(),
            "is_stripped must be boolean"
        );

        let arc_url = f["source_archive_url"]
            .as_str()
            .expect("source_archive_url string");
        assert!(
            arc_url.starts_with("https://www.lua.org/"),
            "source_archive_url must be official lua.org URL"
        );

        let arc_sha = f["source_archive_sha256"]
            .as_str()
            .expect("source_archive_sha256 string");
        assert_eq!(
            arc_sha, expected_archive_sha,
            "source_archive_sha256 for {dialect} must match authoritative official lua.org release hash"
        );

        let comp_ver = f["compiler_version"]
            .as_str()
            .expect("compiler_version string");
        assert!(
            comp_ver.starts_with("Lua 5."),
            "compiler_version must be official version string"
        );
    }
}

#[test]
fn test_lua51_evidence_file_integrity() {
    verify_manifest_dialect(
        "lua51",
        10,
        "2640fc56a795f29d28ef15e13c34a47e223960b0240e8cb0a82d9b0738695333",
    );
}

#[test]
fn test_lua52_evidence_file_integrity() {
    verify_manifest_dialect(
        "lua52",
        10,
        "b9e2e4aad6789b3b63a056d442f7b39f0ecfca3ae0f1fc0ae4e9614401b69f4b",
    );
}

#[test]
fn test_lua53_evidence_file_integrity() {
    verify_manifest_dialect(
        "lua53",
        10,
        "fc5fd69bb8736323f026672b1b7235da613d7177e72558893a0bdcd320466d60",
    );
}

#[test]
fn test_lua54_evidence_file_integrity() {
    verify_manifest_dialect(
        "lua54",
        10,
        "4f18ddae154e793e46eeab727c59ef1c0c0c2b744e7b94219710d76f530629ae",
    );
}

#[test]
fn test_lua55_evidence_file_integrity() {
    verify_manifest_dialect(
        "lua55",
        10,
        "1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce",
    );
}
