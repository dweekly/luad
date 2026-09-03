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
//! 9. The Rust compiler search is pinned to the same releases the installer builds.
//! 10. A same-minor, different-patch compiler earlier in the search order is skipped.
//! 11. The shell and Rust compiler-banner predicates are one rule with one definition.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Official Lua releases in `scripts/install_ci_compilers.sh`, in declaration order.
fn installer_lua_releases(installer: &str) -> Vec<String> {
    installer
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("build_lua \""))
        .map(|rest| {
            rest.split('"')
                .next()
                .expect("closing quote after the release")
                .to_string()
        })
        .collect()
}

/// Write an executable stub whose `-v` banner is `banner`.
fn plant_luac_stub(dir: &Path, bin_name: &str, banner: &str) -> PathBuf {
    let path = dir.join(bin_name);
    fs::write(&path, format!("#!/bin/sh\necho \"{banner}\"\n")).expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
    }
    path
}

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
    let releases = installer_lua_releases(&read("scripts/install_ci_compilers.sh"));
    assert!(
        !releases.is_empty(),
        "scripts/install_ci_compilers.sh must declare official Lua releases"
    );
    declared.extend(releases);

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

#[test]
fn test_oracle_search_is_pinned_to_the_installed_releases() {
    let releases = installer_lua_releases(&read("scripts/install_ci_compilers.sh"));
    assert_eq!(
        luad_oracle::LUA_RELEASES.to_vec(),
        releases,
        "luad_oracle::LUA_RELEASES and the installer's build_lua arguments must name \
         the same releases in the same order"
    );

    // A series prefix would accept any patch release a host happens to carry.
    for release in luad_oracle::LUA_RELEASES {
        assert_eq!(
            release.split('.').count(),
            3,
            "pinned release {release} must name a full major.minor.patch version"
        );
    }
}

#[test]
fn test_search_skips_a_same_minor_different_patch_compiler() {
    // Negative control for the rule every find_luac5x depends on: the first candidate
    // reports the pinned series with the wrong patch and must be passed over for the
    // exact release later in the order. Both candidates are stubs under a name no host
    // carries, so the result depends on the acceptance rule alone rather than on which
    // compilers this machine has installed.
    let temp = tempfile::tempdir().expect("create tempdir");
    let wrong_dir = temp.path().join("wrong");
    let right_dir = temp.path().join("right");
    fs::create_dir_all(&wrong_dir).expect("create wrong dir");
    fs::create_dir_all(&right_dir).expect("create right dir");

    for release in luad_oracle::LUA_RELEASES {
        let (series, patch) = release
            .rsplit_once('.')
            .expect("release has a patch component");
        let patch: u32 = patch.parse().expect("numeric patch");
        // Any patch in the same series other than the pinned one.
        let decoy = format!("{series}.{}", patch + 1);
        let bin_name = format!("luac{series}-pin-control");

        let wrong = plant_luac_stub(
            &wrong_dir,
            &bin_name,
            &format!("Lua {decoy}  Copyright (C) 1994-2026 Lua.org, PUC-Rio"),
        );
        let right = plant_luac_stub(
            &right_dir,
            &bin_name,
            &format!("Lua {release}  Copyright (C) 1994-2026 Lua.org, PUC-Rio"),
        );

        let wrong_str = wrong.to_str().expect("utf-8 path");
        let right_str = right.to_str().expect("utf-8 path");
        assert_eq!(
            luad_oracle::find_compiler_binary(&bin_name, &[wrong_str, right_str], release)
                .as_deref(),
            Some(right.as_path()),
            "search for Lua {release} must skip the {decoy} stub at {wrong_str}"
        );

        // The decoy alone is not an acceptable answer.
        assert_eq!(
            luad_oracle::find_compiler_binary(&bin_name, &[wrong_str], release),
            None,
            "search for Lua {release} must reject a lone {decoy} compiler"
        );
    }
}

/// Runs `banner_names_release` from `scripts/pins.env` and reports whether it accepted.
fn shell_banner_names_release(banner: &str, release: &str) -> bool {
    let pins = workspace_root().join("scripts/pins.env");
    let output = Command::new("bash")
        .arg("-c")
        .arg(r#". "$1"; banner_names_release "$2" "$3""#)
        .arg("bash")
        .arg(&pins)
        .arg(banner)
        .arg(release)
        .output()
        .expect("run the shell banner predicate");
    assert!(
        output
            .status
            .code()
            .is_some_and(|code| code == 0 || code == 1),
        "the shell predicate must answer true or false, got {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    output.status.success()
}

#[test]
fn test_shell_and_rust_banner_predicates_are_one_rule() {
    // One definition: the sourcing scripts call it and never carry their own copy.
    for script in ["scripts/bringup.sh", "scripts/install_ci_compilers.sh"] {
        let text = read(script);
        assert!(
            !text.contains("banner_names_release() {"),
            "{script} must use the definition in scripts/pins.env, not its own"
        );
        assert!(
            text.contains("banner_names_release \""),
            "{script} must test compiler banners through banner_names_release"
        );
    }

    for release in luad_oracle::LUA_RELEASES {
        let (series, patch) = release.rsplit_once('.').expect("patch component");
        let patch: u32 = patch.parse().expect("numeric patch");
        let accepted = [
            format!("Lua {release}  Copyright (C) 1994-2026 Lua.org, PUC-Rio"),
            format!("Lua {release}"),
        ];
        let rejected = [
            format!("Lua {series}.{}  Copyright", patch + 1),
            format!("Lua {release}0  Copyright"),
            format!("Lua {release}.1  Copyright"),
            format!("luac {release}"),
            String::new(),
        ];

        for banner in &accepted {
            assert!(
                luad_oracle::banner_names_release(banner, release),
                "Rust predicate rejected {banner:?} for Lua {release}"
            );
            assert!(
                shell_banner_names_release(banner, release),
                "shell predicate rejected {banner:?} for Lua {release}"
            );
        }
        for banner in &rejected {
            assert!(
                !luad_oracle::banner_names_release(banner, release),
                "Rust predicate accepted {banner:?} for Lua {release}"
            );
            assert!(
                !shell_banner_names_release(banner, release),
                "shell predicate accepted {banner:?} for Lua {release}"
            );
        }
    }
}
