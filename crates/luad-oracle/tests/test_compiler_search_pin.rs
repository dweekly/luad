//! End-to-end control that every `find_luac5x` matches a whole pinned release.
//!
//! A search that accepts anything less than the complete version token takes evidence
//! from a release nobody pinned: a series prefix such as `5.4` accepts any 5.4.x, and a
//! substring test accepts `5.4.80` for `5.4.8`. This plants each of those shapes at the
//! front of the real search order and requires every finder to pass over it, through the
//! `LUAD_ORACLE_BIN_DIR` override, through the candidate list every finder falls through
//! to when the override and the persistent directory are both absent, and against the
//! shared candidate matcher directly.
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

const CASES: [(&str, &str); 5] = [
    ("luac5.1", LUA51_RELEASE),
    ("luac5.2", LUA52_RELEASE),
    ("luac5.3", LUA53_RELEASE),
    ("luac5.4", LUA54_RELEASE),
    ("luac5.5", LUA55_RELEASE),
];

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

/// The banner shape every official Lua compiler prints for `version`.
fn banner_for(version: &str) -> String {
    format!("Lua {version}  Copyright (C) 1994-2026 Lua.org, PUC-Rio")
}

/// Versions a whole-token match must reject when `release` is required:
/// a different patch in the same series, a longer patch that `release` is a prefix of,
/// and a further version component appended to `release`.
fn decoy_releases(release: &str) -> Vec<String> {
    let (series, patch) = release
        .rsplit_once('.')
        .unwrap_or_else(|| panic!("pinned release {release} must name a patch component"));
    let patch: u32 = patch
        .parse()
        .unwrap_or_else(|error| panic!("pinned release {release} has a numeric patch: {error}"));
    vec![
        format!("{series}.{}", patch + 1),
        format!("{release}0"),
        format!("{release}.1"),
    ]
}

#[test]
fn test_finders_reject_every_version_that_is_not_the_pinned_release() {
    let temp = tempfile::tempdir().expect("create tempdir");
    let good = temp.path().join("good");
    let empty_home = temp.path().join("home");
    fs::create_dir_all(&good).expect("create good dir");
    fs::create_dir_all(&empty_home).expect("create home dir");

    // Reached through the bare-name entry of each candidate list, so a host with no
    // official compiler still resolves one and this can never pass by finding nothing.
    for (bin_name, release) in CASES {
        plant_luac_stub(&good, bin_name, &banner_for(release));
    }

    // HOME is redirected at an empty directory so the persistent compiler directory of
    // the machine running this cannot decide the outcome, and PATH exposes only the
    // correct stubs.
    std::env::set_var("HOME", &empty_home);
    std::env::set_var("PATH", &good);

    for round in 0..decoy_releases(LUA54_RELEASE).len() {
        let decoys = temp.path().join(format!("decoys-{round}"));
        fs::create_dir_all(&decoys).expect("create decoy dir");

        let mut planted = Vec::new();
        for (bin_name, release) in CASES {
            let decoy = decoy_releases(release).remove(round);
            let path = plant_luac_stub(&decoys, bin_name, &banner_for(&decoy));
            planted.push((decoy, path));
        }

        // Round A. LUAD_ORACLE_BIN_DIR is the first location every search consults, so
        // this round's decoys sit ahead of everything else, and the correct stubs are
        // reachable through the bare-name entry of each candidate list.
        std::env::set_var("LUAD_ORACLE_BIN_DIR", &decoys);
        std::env::set_var("PATH", &good);
        let overridden = [
            find_luac51(),
            find_luac52(),
            find_luac53(),
            find_luac54(),
            find_luac55(),
        ];
        for (index, (bin_name, release)) in CASES.iter().enumerate() {
            let (decoy, decoy_path) = &planted[index];
            let resolved = overridden[index]
                .as_ref()
                .unwrap_or_else(|| panic!("{bin_name} must resolve to the planted Lua {release}"));
            assert_ne!(
                resolved,
                decoy_path,
                "{bin_name} accepted the Lua {decoy} decoy at {} through the override",
                decoy_path.display()
            );
            let banner = banner_of(resolved);
            assert!(
                banner.contains(release),
                "{bin_name} resolved {} whose banner {banner:?} does not name Lua {release}",
                resolved.display()
            );
        }

        // Round B. No override and an empty home, so every finder falls through to its
        // candidate list, where only the decoy is reachable. Rejecting it and resolving
        // nothing is correct; returning it is not.
        std::env::remove_var("LUAD_ORACLE_BIN_DIR");
        std::env::set_var("PATH", &decoys);
        let fell_through = [
            find_luac51(),
            find_luac52(),
            find_luac53(),
            find_luac54(),
            find_luac55(),
        ];
        for (index, (bin_name, release)) in CASES.iter().enumerate() {
            let (decoy, decoy_path) = &planted[index];
            if let Some(resolved) = fell_through[index].as_ref() {
                assert_ne!(
                    resolved,
                    decoy_path,
                    "{bin_name} accepted the Lua {decoy} decoy at {} through its candidate list",
                    decoy_path.display()
                );
                let banner = banner_of(resolved);
                assert!(
                    banner.contains(release),
                    "{bin_name} resolved {} whose banner {banner:?} does not name Lua {release}",
                    resolved.display()
                );
            }
        }
        std::env::set_var("PATH", &good);
    }

    // Round C. The candidate list alone, under a name no host carries so the override
    // and persistent probes cannot answer, with both candidates under this test's
    // control. Unlike round B this holds whatever compilers the machine has installed.
    for (bin_name, release) in CASES {
        let control_name = format!("{bin_name}-pin-control");
        for decoy in decoy_releases(release) {
            let decoy_dir = temp.path().join(format!("control-decoy-{decoy}"));
            let good_dir = temp.path().join(format!("control-good-{decoy}"));
            fs::create_dir_all(&decoy_dir).expect("create control decoy dir");
            fs::create_dir_all(&good_dir).expect("create control good dir");
            let decoy_path = plant_luac_stub(&decoy_dir, &control_name, &banner_for(&decoy));
            let good_path = plant_luac_stub(&good_dir, &control_name, &banner_for(release));

            let decoy_str = decoy_path.to_str().expect("utf-8 path");
            let good_str = good_path.to_str().expect("utf-8 path");
            assert_eq!(
                luad_oracle::find_compiler_binary(&control_name, &[decoy_str, good_str], release)
                    .as_deref(),
                Some(good_path.as_path()),
                "the candidate list accepted the Lua {decoy} decoy at {decoy_str}"
            );
            assert_eq!(
                luad_oracle::find_compiler_binary(&control_name, &[decoy_str], release),
                None,
                "the candidate list accepted a lone Lua {decoy} compiler for Lua {release}"
            );
        }
    }
}

#[test]
fn test_gate_compiler_comparison_requires_the_exact_leading_token() {
    // The gate runner asks for a compiler by its whole `Lua <release>` token. That is
    // stricter than the search predicate and must stay that way.
    for (_, release) in CASES {
        let expected = format!("Lua {release}");
        assert!(luad_oracle::banner_reports_exact_version(
            &banner_for(release),
            &expected
        ));
        for decoy in decoy_releases(release) {
            assert!(
                !luad_oracle::banner_reports_exact_version(&banner_for(&decoy), &expected),
                "a gate requiring {expected} must reject Lua {decoy}"
            );
        }
        // The token has to lead the banner, not merely appear in it.
        assert!(!luad_oracle::banner_reports_exact_version(
            &format!("luac wrapper for {expected}"),
            &expected
        ));
    }
}

#[test]
fn test_banner_predicate_requires_a_complete_version_token() {
    // The predicate the searches above rely on, exercised directly so a failure names
    // the rule rather than a path.
    for (_, release) in CASES {
        assert!(luad_oracle::banner_names_release(
            &banner_for(release),
            release
        ));
        // A banner that ends at the release is still a complete token.
        assert!(luad_oracle::banner_names_release(
            &format!("Lua {release}"),
            release
        ));
        for decoy in decoy_releases(release) {
            assert!(
                !luad_oracle::banner_names_release(&banner_for(&decoy), release),
                "Lua {decoy} must not satisfy a search for Lua {release}"
            );
        }
        // The release has to follow `Lua `, not merely appear somewhere in the banner.
        assert!(!luad_oracle::banner_names_release(
            &format!("luac {release}"),
            release
        ));
    }
}
