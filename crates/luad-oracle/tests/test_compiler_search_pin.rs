//! End-to-end control that every `find_luac5x` matches a whole pinned release.
//!
//! A search that asks for a series prefix such as `5.4` accepts whatever 5.4.x a host
//! carries, and a differential result is evidence only about the release that produced
//! it. This plants a same-series, different-patch compiler at the front of the real
//! search order and requires each finder to pass over it.
//!
//! This is the only test in its binary because it sets process environment variables to
//! control the search. Another test running concurrently could read them mid-change.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_oracle::{
    find_luac51, find_luac52, find_luac53, find_luac54, find_luac55, LUA51_RELEASE, LUA52_RELEASE,
    LUA53_RELEASE, LUA54_RELEASE, LUA55_RELEASE,
};

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

/// The `-v` banner a resolved compiler prints.
fn banner_of(path: &Path) -> String {
    let output = Command::new(path)
        .arg("-v")
        .output()
        .unwrap_or_else(|error| panic!("run {} -v: {error}", path.display()));
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .trim()
    .to_string()
}

/// A different patch in the same series, which a whole-release match must reject.
fn decoy_release(release: &str) -> String {
    let (series, patch) = release
        .rsplit_once('.')
        .unwrap_or_else(|| panic!("pinned release {release} must name a patch component"));
    let patch: u32 = patch
        .parse()
        .unwrap_or_else(|error| panic!("pinned release {release} has a numeric patch: {error}"));
    format!("{series}.{}", patch + 1)
}

#[test]
fn test_finders_reject_a_same_series_different_patch_compiler() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let decoys = temp.path().join("decoys");
    let good = temp.path().join("good");
    let empty_home = temp.path().join("home");
    fs::create_dir_all(&decoys).expect("create decoy dir");
    fs::create_dir_all(&good).expect("create good dir");
    fs::create_dir_all(&empty_home).expect("create home dir");

    let cases = [
        ("luac5.1", LUA51_RELEASE),
        ("luac5.2", LUA52_RELEASE),
        ("luac5.3", LUA53_RELEASE),
        ("luac5.4", LUA54_RELEASE),
        ("luac5.5", LUA55_RELEASE),
    ];

    let mut decoy_paths = Vec::new();
    for (bin_name, release) in cases {
        let decoy = decoy_release(release);
        decoy_paths.push(plant_luac_stub(
            &decoys,
            bin_name,
            &format!("Lua {decoy}  Copyright (C) 1994-2026 Lua.org, PUC-Rio"),
        ));
        // Reached through the bare-name entry of each candidate list, so a host with no
        // official compiler still resolves one and this can never pass by finding
        // nothing.
        plant_luac_stub(
            &good,
            bin_name,
            &format!("Lua {release}  Copyright (C) 1994-2026 Lua.org, PUC-Rio"),
        );
    }

    // LUAD_ORACLE_BIN_DIR is the first location every search consults, so the decoys sit
    // ahead of everything else. HOME is redirected at an empty directory so the
    // persistent compiler directory of the machine running this cannot decide the
    // outcome, and PATH exposes only the correct stubs.
    std::env::set_var("LUAD_ORACLE_BIN_DIR", &decoys);
    std::env::set_var("HOME", &empty_home);
    std::env::set_var("PATH", &good);

    let found = [
        find_luac51(),
        find_luac52(),
        find_luac53(),
        find_luac54(),
        find_luac55(),
    ];

    for (index, (bin_name, release)) in cases.iter().enumerate() {
        let resolved = found[index]
            .as_ref()
            .unwrap_or_else(|| panic!("{bin_name} must resolve to the planted Lua {release}"));
        assert_ne!(
            resolved,
            &decoy_paths[index],
            "{bin_name} accepted the Lua {} decoy at {}",
            decoy_release(release),
            decoy_paths[index].display()
        );
        let banner = banner_of(resolved);
        assert!(
            banner.contains(release),
            "{bin_name} resolved {} whose banner {banner:?} does not name Lua {release}",
            resolved.display()
        );
    }
}
