//! Ordinary package-identity and source-install contract tests.

use std::fs;
use std::path::Path;
use std::process::Command;

use luad_oracle::candidate::sha256_digest;
use luad_oracle::find_workspace_root;
use serde_json::Value;

const REPOSITORY: &str = "https://github.com/dweekly/luad";
const LICENSE_EXPRESSION: &str = "MIT OR Apache-2.0";
const MIT_SHA256: &str = "f9ad3423044ff24a94051b055745fbe7059b1ecdb83ea2a00b36d32e95bd54fa";
const APACHE_SHA256: &str = "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4";

const PACKAGES: [(&str, &str); 9] = [
    (
        "luad-core",
        "Memory-safe Lua bytecode models, parsing primitives, and diagnostics for luad",
    ),
    (
        "luad-dialect-lua51",
        "Lua 5.1 bytecode parsing, decoding, lifting, and validation for luad",
    ),
    (
        "luad-dialect-lua52",
        "Lua 5.2 bytecode parsing, decoding, lifting, and validation for luad",
    ),
    (
        "luad-dialect-lua53",
        "Lua 5.3 bytecode parsing, decoding, lifting, and validation for luad",
    ),
    (
        "luad-dialect-lua54",
        "Lua 5.4 bytecode parsing, decoding, lifting, and validation for luad",
    ),
    (
        "luad-dialect-lua55",
        "Lua 5.5 bytecode parsing, decoding, lifting, and validation for luad",
    ),
    (
        "luad-analysis",
        "Deterministic control-flow, query, cross-reference, and comparison analysis for luad",
    ),
    (
        "luad-cli",
        "Inspect, disassemble, validate, and analyze compiled Lua bytecode without executing it",
    ),
    (
        "luad-oracle",
        "Independent compiler-oracle, qualification, and release verification tools for luad",
    ),
];

fn cargo_metadata() -> Value {
    let root = find_workspace_root();
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .expect("execute cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse cargo metadata")
}

fn package_mut<'a>(metadata: &'a mut Value, name: &str) -> &'a mut Value {
    metadata["packages"]
        .as_array_mut()
        .expect("packages array")
        .iter_mut()
        .find(|package| package["name"] == name)
        .expect("named package")
}

fn validate_metadata(metadata: &Value) -> Result<(), String> {
    let packages = metadata["packages"]
        .as_array()
        .ok_or("metadata packages must be an array")?;
    if packages.len() != PACKAGES.len() {
        return Err(format!(
            "workspace package count mismatch: expected {}, got {}",
            PACKAGES.len(),
            packages.len()
        ));
    }

    for (name, expected_description) in PACKAGES {
        let package = packages
            .iter()
            .find(|package| package["name"] == name)
            .ok_or_else(|| format!("missing workspace package '{name}'"))?;
        if package["description"].as_str() != Some(expected_description) {
            return Err(format!(
                "package '{name}' has a missing or wrong description"
            ));
        }
        if package["license"].as_str() != Some(LICENSE_EXPRESSION) {
            return Err(format!("package '{name}' has a missing or wrong license"));
        }
        if package["repository"].as_str() != Some(REPOSITORY) {
            return Err(format!(
                "package '{name}' has a missing or wrong repository"
            ));
        }
        if package["homepage"].as_str() != Some(REPOSITORY) {
            return Err(format!("package '{name}' has a missing or wrong homepage"));
        }
        if package["readme"].as_str() != Some("../../README.md") {
            return Err(format!("package '{name}' does not inherit the root README"));
        }
        if !matches!(package.get("publish"), Some(Value::Array(registries)) if registries.is_empty())
        {
            return Err(format!("package '{name}' is publishable"));
        }
        if !matches!(package.get("rust_version"), Some(Value::Null)) {
            return Err(format!(
                "package '{name}' declares an unproved minimum Rust version"
            ));
        }

        let binaries: Vec<&str> = package["targets"]
            .as_array()
            .ok_or_else(|| format!("package '{name}' targets must be an array"))?
            .iter()
            .filter(|target| {
                target["kind"]
                    .as_array()
                    .is_some_and(|kinds| kinds.iter().any(|kind| kind == "bin"))
            })
            .filter_map(|target| target["name"].as_str())
            .collect();
        if name == "luad-cli" {
            if binaries != ["luad"] {
                return Err(format!(
                    "luad-cli binary target mismatch: expected [luad], got {binaries:?}"
                ));
            }
        } else if binaries.contains(&"luad") {
            return Err(format!("non-CLI package '{name}' exposes a luad binary"));
        }
    }
    Ok(())
}

fn validate_license_files(root: &Path) -> Result<(), String> {
    for (name, expected_sha) in [("LICENSE", MIT_SHA256), ("LICENSE-APACHE", APACHE_SHA256)] {
        let path = root.join(name);
        let bytes = fs::read(&path).map_err(|error| format!("read {name}: {error}"))?;
        let actual = sha256_digest(&bytes);
        if actual != expected_sha {
            return Err(format!(
                "{name} canonical digest mismatch: expected {expected_sha}, got {actual}"
            ));
        }
    }
    Ok(())
}

fn validate_fuzz_manifest(text: &str) -> Result<(), String> {
    if !text.lines().any(|line| line.trim() == "publish = false") {
        return Err("fuzz package must remain unpublished".to_string());
    }
    if text.lines().any(|line| {
        line.trim_start().starts_with("rust-version")
            || line.trim_start().starts_with("rust_version")
    }) {
        return Err("fuzz package declares an unproved minimum Rust version".to_string());
    }
    Ok(())
}

#[test]
fn test_workspace_package_metadata_is_honest() {
    let root = find_workspace_root();
    validate_metadata(&cargo_metadata()).expect("live package metadata must match policy");
    validate_license_files(&root).expect("repository license texts must match policy");
    let fuzz = fs::read_to_string(root.join("fuzz/Cargo.toml")).expect("read fuzz manifest");
    validate_fuzz_manifest(&fuzz).expect("fuzz package metadata must match policy");
}

#[test]
fn test_package_metadata_mutations_are_rejected() {
    let live = cargo_metadata();
    let cases = [
        "description",
        "repository",
        "homepage",
        "readme",
        "license",
        "publish",
        "rust-version",
        "binary",
    ];
    for case in cases {
        let mut mutated = live.clone();
        let package = package_mut(&mut mutated, "luad-cli");
        match case {
            "description" => package["description"] = Value::Null,
            "repository" => package["repository"] = Value::String("https://invalid".to_string()),
            "homepage" => package["homepage"] = Value::String("https://invalid".to_string()),
            "readme" => package["readme"] = Value::Null,
            "license" => package["license"] = Value::Null,
            "publish" => package["publish"] = Value::Null,
            "rust-version" => package["rust_version"] = Value::String("1.97.1".to_string()),
            "binary" => {
                let target = package["targets"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|target| target["name"] == "luad")
                    .unwrap();
                target["name"] = Value::String("not-luad".to_string());
            }
            _ => unreachable!(),
        }
        assert!(
            validate_metadata(&mutated).is_err(),
            "{case} mutation must be rejected"
        );
    }

    let root = find_workspace_root();
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("LICENSE"),
        fs::read(root.join("LICENSE")).unwrap(),
    )
    .unwrap();
    assert!(
        validate_license_files(temp.path()).is_err(),
        "missing Apache license must be rejected"
    );

    assert!(validate_fuzz_manifest("publish = true\n").is_err());
    assert!(validate_fuzz_manifest("publish = false\nrust-version = \"1.97.1\"\n").is_err());
}

#[test]
fn test_locked_source_install_works_without_registry() {
    let root = find_workspace_root();
    let temp = tempfile::tempdir().expect("tempdir");
    let install_root = temp.path().join("install");
    let target_dir = temp.path().join("target");
    let output = Command::new("cargo")
        .args([
            "install",
            "--path",
            "crates/luad-cli",
            "--locked",
            "--offline",
            "--root",
        ])
        .arg(&install_root)
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(&root)
        .output()
        .expect("execute cargo install");
    assert!(
        output.status.success(),
        "locked offline source install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let binary = install_root.join("bin/luad");
    assert!(binary.is_file(), "installed luad binary must exist");
    let version = Command::new(&binary).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    assert_eq!(version.stdout, b"luad 0.1.0\n");

    let capabilities = Command::new(&binary)
        .args(["capabilities", "--format", "json"])
        .output()
        .unwrap();
    assert!(capabilities.status.success());
    assert!(capabilities.stderr.is_empty());
    let document: Value = serde_json::from_slice(&capabilities.stdout).unwrap();
    assert_eq!(document["tool_name"], "luad");
    assert_eq!(document["tool_version"], "0.1.0");
    assert_eq!(document["supported_dialects"], Value::Array(vec![]));
}
