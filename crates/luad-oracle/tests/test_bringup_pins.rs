//! Agreement between `scripts/pins.env`, the manifests that own the remaining pins, the
//! CI workflow, and the bring-up documentation.
//!
//! Exercises:
//! 1. Every pin in `scripts/pins.env` is present and non-empty.
//! 2. The compiler-directory pin matches the Rust search constant, and the legacy
//!    directory is still reachable as a fallback.
//! 3. `scripts/install_ci_compilers.sh` installs into the pinned default.
//! 4. CI installs the exact pinned `cargo-cyclonedx` and `cargo-deny` releases.
//! 5. CI installs the toolchains declared by `rust-toolchain.toml` and `Cargo.toml`.
//! 6. The CI `Test` jobs run the bring-up doctor.
//! 7. Every three-component version number in `docs/BRINGUP.md` is a declared pin.
//! 8. `docs/RELEASING.md` states the pinned `cargo-deny` version.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

/// Reads a `NAME="value"` assignment from `scripts/pins.env`.
fn pin(pins: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    let line = pins
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("scripts/pins.env must define {name}"));
    let value = line[prefix.len()..].trim().trim_matches('"').to_string();
    assert!(!value.is_empty(), "{name} must not be empty");
    value
}

/// Reads a `key = "value"` assignment from a TOML manifest.
fn toml_string(manifest: &str, key: &str) -> String {
    let prefix = format!("{key} = \"");
    let line = manifest
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("manifest must define {key}"));
    let value = line[prefix.len()..]
        .split('"')
        .next()
        .expect("closing quote")
        .to_string();
    assert!(!value.is_empty(), "{key} must not be empty");
    value
}

/// Reads a `readonly name="value"` constant from a shell runner.
fn shell_constant(script: &str, name: &str) -> String {
    let prefix = format!("readonly {name}=");
    let line = script
        .lines()
        .map(str::trim_start)
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("script must define {name}"));
    let value = line[prefix.len()..].trim().trim_matches('"').to_string();
    assert!(!value.is_empty(), "{name} must not be empty");
    value
}

/// Every maximal `<digits>.<digits>.<digits>` run in `text`.
fn three_component_versions(text: &str) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == '.') {
            index += 1;
        }
        let run: String = bytes[start..index].iter().collect();
        let run = run.trim_end_matches('.');
        let components: Vec<&str> = run.split('.').collect();
        if components.len() == 3 && components.iter().all(|c| !c.is_empty()) {
            found.insert(run.to_string());
        }
    }
    found
}

#[test]
fn test_compiler_directory_pin_matches_oracle_search_constant() {
    let pins = read("scripts/pins.env");

    // The pin is stored unexpanded so a shell can source it; the Rust constant holds
    // only the part below the home directory.
    let expected = format!("${{HOME}}/{}", luad_oracle::PERSISTENT_COMPILER_SUBDIR);
    assert_eq!(
        pin(&pins, "LUAD_COMPILER_DIR_DEFAULT"),
        expected,
        "scripts/pins.env and luad_oracle::PERSISTENT_COMPILER_SUBDIR must name one directory"
    );

    let legacy = pin(&pins, "LUAD_LEGACY_COMPILER_DIR");
    let oracle = read("crates/luad-oracle/src/lib.rs");
    for series in ["5.1", "5.2", "5.3", "5.4", "5.5"] {
        assert!(
            oracle.contains(&format!("\"{legacy}/luac{series}\"")),
            "the oracle must retain {legacy}/luac{series} as a fallback candidate"
        );
    }
}

#[test]
fn test_compiler_installer_uses_the_pinned_default_directory() {
    let installer = read("scripts/install_ci_compilers.sh");
    assert!(
        installer.contains(". \"${SCRIPT_DIR}/pins.env\""),
        "scripts/install_ci_compilers.sh must source scripts/pins.env"
    );
    assert!(
        installer.contains("DEST_DIR=\"${LUAD_COMPILER_DIR:-${LUAD_COMPILER_DIR_DEFAULT}}\""),
        "scripts/install_ci_compilers.sh must default to the pinned compiler directory"
    );
}

#[test]
fn test_ci_workflow_installs_the_pinned_release_tools() {
    let pins = read("scripts/pins.env");
    let workflow = read(".github/workflows/ci.yml");

    let cyclonedx = pin(&pins, "LUAD_CARGO_CYCLONEDX_VERSION");
    assert!(
        workflow.contains(&format!("cargo-cyclonedx-{cyclonedx}/")),
        "CI must download the cargo-cyclonedx {cyclonedx} release asset"
    );
    assert!(
        workflow.contains(&format!("= \"cargo-cyclonedx-cyclonedx {cyclonedx}\"")),
        "CI must assert the downloaded cargo-cyclonedx reports {cyclonedx}"
    );

    // CI obtains cargo-deny through the pinned action tag rather than a version flag,
    // so the tag is what has to agree with the pin file.
    let deny_action = pin(&pins, "LUAD_CARGO_DENY_ACTION");
    assert!(
        workflow.contains(&format!("uses: {deny_action}")),
        "CI must use the pinned cargo-deny action {deny_action}"
    );
}

#[test]
fn test_ci_workflow_installs_the_declared_toolchains() {
    let workflow = read(".github/workflows/ci.yml");

    let channel = toml_string(&read("rust-toolchain.toml"), "channel");
    assert!(
        workflow.contains(&format!("toolchain: {channel}")),
        "CI must install the rust-toolchain.toml channel {channel}"
    );

    // Cargo's rust-version omits the patch; rustup and CI name all three components.
    let msrv = toml_string(&read("Cargo.toml"), "rust-version");
    let msrv_toolchain = if msrv.matches('.').count() == 2 {
        msrv.clone()
    } else {
        format!("{msrv}.0")
    };
    assert!(
        workflow.contains(&format!("toolchain: {msrv_toolchain}")),
        "CI must install the MSRV toolchain {msrv_toolchain} declared by Cargo.toml"
    );
}

#[test]
fn test_ci_test_jobs_run_the_bringup_doctor() {
    let workflow = read(".github/workflows/ci.yml");
    assert!(
        workflow.contains("bash scripts/bringup.sh --doctor --scope ci-test"),
        "the CI Test jobs must run the bring-up doctor so it cannot drift from CI"
    );
}

#[test]
fn test_bringup_document_states_only_declared_pins() {
    let pins = read("scripts/pins.env");
    let fuzz = read("scripts/fuzz_smoke.sh");

    let msrv = toml_string(&read("Cargo.toml"), "rust-version");
    let mut declared: BTreeSet<String> = BTreeSet::new();
    declared.insert(toml_string(&read("rust-toolchain.toml"), "channel"));
    declared.insert(if msrv.matches('.').count() == 2 {
        msrv
    } else {
        format!("{msrv}.0")
    });
    declared.insert(shell_constant(&fuzz, "pinned_cargo_fuzz_version"));
    declared.insert(pin(&pins, "LUAD_CARGO_DENY_VERSION"));
    declared.insert(pin(&pins, "LUAD_CARGO_CYCLONEDX_VERSION"));

    // The official Lua releases are owned by the installer's build_lua arguments.
    let installer = read("scripts/install_ci_compilers.sh");
    let mut lua_releases = 0;
    for line in installer.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("build_lua \"") {
            let version = rest.split('"').next().expect("closing quote");
            declared.insert(version.to_string());
            lua_releases += 1;
        }
    }
    assert!(
        lua_releases > 0,
        "scripts/install_ci_compilers.sh must declare official Lua releases"
    );

    let bringup = read("docs/BRINGUP.md");
    let undeclared: Vec<String> = three_component_versions(&bringup)
        .into_iter()
        .filter(|version| !declared.contains(version))
        .collect();
    assert!(
        undeclared.is_empty(),
        "docs/BRINGUP.md states version numbers that are not pins: {undeclared:?}\n\
         declared pins: {declared:?}"
    );
}

#[test]
fn test_release_document_states_the_pinned_dependency_auditor() {
    let deny = pin(&read("scripts/pins.env"), "LUAD_CARGO_DENY_VERSION");
    let releasing = read("docs/RELEASING.md");
    assert!(
        releasing.contains(&format!("`cargo-deny` {deny}")),
        "docs/RELEASING.md must state the pinned cargo-deny version {deny}"
    );
}

#[test]
fn test_version_scanner_rejects_an_undeclared_number() {
    // Negative control: the scanner used above must actually find a stray version.
    let found = three_component_versions("pin 1.97.1 and stray 9.9.9 here; 1.85 is not one.");
    assert!(found.contains("1.97.1"));
    assert!(found.contains("9.9.9"));
    assert!(!found.contains("1.85"));
}
