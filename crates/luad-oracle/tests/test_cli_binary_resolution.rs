//! Dedicated acceptance tests for CLI test-binary resolution without nested builds.
//!
//! Verifies:
//! 1. Authoritative `LUAD_CANDIDATE_BIN` fails closed on empty, missing, directory, and non-executable values.
//! 2. `CARGO_BIN_EXE_luad` points to an explicit binary and is honored.
//! 3. `CARGO_TARGET_DIR` is honored for locating `<target-dir>/debug/luad`.
//! 4. Missing binary sentinel: when no binary is found and a dummy failing `cargo` executable is placed first
//!    on `PATH`, resolution fails actionably and never spawns a nested `cargo build`.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use luad_oracle::candidate::{resolve_test_binary, BinaryResolutionError};

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvGuard {
    fn new(vars: &[&'static str]) -> Self {
        let saved = vars
            .iter()
            .map(|&var| (var, std::env::var_os(var)))
            .collect();
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (var, original) in &self.saved {
            if let Some(val) = original {
                std::env::set_var(var, val);
            } else {
                std::env::remove_var(var);
            }
        }
    }
}

fn make_dummy_executable(path: &Path, content: &[u8]) {
    fs::write(path, content).expect("write dummy binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();
    }
}

#[test]
fn test_candidate_bin_authoritative_valid() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
    ]);

    let tmp = tempfile::tempdir().unwrap();
    let custom_bin = tmp.path().join("my-custom-luad");
    make_dummy_executable(&custom_bin, b"#!/bin/sh\nexit 0\n");

    std::env::set_var("LUAD_CANDIDATE_BIN", &custom_bin);
    let resolved = resolve_test_binary().expect("resolve custom candidate bin");
    assert_eq!(resolved, custom_bin);
}

#[test]
fn test_candidate_bin_fail_closed_empty() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
    ]);

    std::env::set_var("LUAD_CANDIDATE_BIN", "   ");
    let err = resolve_test_binary().unwrap_err();
    assert_eq!(err, BinaryResolutionError::Empty);
}

#[test]
fn test_candidate_bin_fail_closed_missing() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
    ]);

    let missing_path = PathBuf::from("/nonexistent/luad_path/bin");
    std::env::set_var("LUAD_CANDIDATE_BIN", &missing_path);
    let err = resolve_test_binary().unwrap_err();
    assert_eq!(err, BinaryResolutionError::Missing(missing_path));
}

#[test]
fn test_candidate_bin_fail_closed_directory() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
    ]);

    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("LUAD_CANDIDATE_BIN", tmp.path());
    let err = resolve_test_binary().unwrap_err();
    assert_eq!(
        err,
        BinaryResolutionError::Directory(tmp.path().to_path_buf())
    );
}

#[test]
#[cfg(unix)]
fn test_candidate_bin_fail_closed_not_executable() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
    ]);

    let tmp = tempfile::tempdir().unwrap();
    let non_exec = tmp.path().join("not-exec");
    fs::write(&non_exec, b"hello").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&non_exec).unwrap().permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&non_exec, perms).unwrap();

    std::env::set_var("LUAD_CANDIDATE_BIN", &non_exec);
    let err = resolve_test_binary().unwrap_err();
    assert_eq!(err, BinaryResolutionError::NotExecutable(non_exec));
}

#[test]
fn test_cargo_bin_exe_precedence() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
    ]);

    std::env::remove_var("LUAD_CANDIDATE_BIN");

    let tmp = tempfile::tempdir().unwrap();
    let bin_path = tmp.path().join("cargo-bin-luad");
    make_dummy_executable(&bin_path, b"#!/bin/sh\nexit 0\n");

    std::env::set_var("CARGO_BIN_EXE_luad", &bin_path);
    let resolved = resolve_test_binary().expect("resolve CARGO_BIN_EXE_luad");
    assert_eq!(resolved, bin_path);

    // Missing path for CARGO_BIN_EXE_luad fails actionably
    let missing_path = tmp.path().join("does-not-exist");
    std::env::set_var("CARGO_BIN_EXE_luad", &missing_path);
    let err = resolve_test_binary().unwrap_err();
    match err {
        BinaryResolutionError::WorkspaceFallbackFailed(msg) => {
            assert!(msg.contains("missing path"));
        }
        other => panic!("expected WorkspaceFallbackFailed, got {other:?}"),
    }
}

#[test]
fn test_custom_target_dir_honored() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
    ]);

    std::env::remove_var("LUAD_CANDIDATE_BIN");
    std::env::remove_var("CARGO_BIN_EXE_luad");

    let tmp = tempfile::tempdir().unwrap();
    let debug_dir = tmp.path().join("debug");
    fs::create_dir_all(&debug_dir).unwrap();
    let bin_name = if cfg!(windows) { "luad.exe" } else { "luad" };
    let custom_target_bin = debug_dir.join(bin_name);
    make_dummy_executable(&custom_target_bin, b"#!/bin/sh\nexit 0\n");

    std::env::set_var("CARGO_TARGET_DIR", tmp.path());
    let resolved = resolve_test_binary().expect("resolve custom target dir binary");
    assert_eq!(resolved, custom_target_bin);
}

#[test]
fn test_missing_binary_fails_actionably_without_cargo_build_sentinel() {
    let _lock = ENV_LOCK.lock().unwrap();
    let _guard = EnvGuard::new(&[
        "LUAD_CANDIDATE_BIN",
        "CARGO_BIN_EXE_luad",
        "CARGO_TARGET_DIR",
        "PATH",
    ]);

    std::env::remove_var("LUAD_CANDIDATE_BIN");
    std::env::remove_var("CARGO_BIN_EXE_luad");

    // Point CARGO_TARGET_DIR to an empty temp dir with no debug/luad
    let empty_target = tempfile::tempdir().unwrap();
    std::env::set_var("CARGO_TARGET_DIR", empty_target.path());

    // Create a sentinel cargo script in a temp bin dir that fails if invoked
    let sentinel_dir = tempfile::tempdir().unwrap();
    let sentinel_witness = sentinel_dir.path().join("cargo_was_called.txt");
    let sentinel_cargo =
        sentinel_dir
            .path()
            .join(if cfg!(windows) { "cargo.bat" } else { "cargo" });

    #[cfg(unix)]
    {
        let script = format!(
            "#!/bin/sh\necho 'CALLED' > '{}'\nexit 99\n",
            sentinel_witness.display()
        );
        make_dummy_executable(&sentinel_cargo, script.as_bytes());
    }
    #[cfg(windows)]
    {
        let script = format!(
            "@echo off\r\necho CALLED > \"{}\"\r\nexit /b 99\r\n",
            sentinel_witness.display()
        );
        fs::write(&sentinel_cargo, script.as_bytes()).unwrap();
    }

    // Prepend sentinel dir to PATH
    let original_path = std::env::var("PATH").unwrap_or_default();
    let separator = if cfg!(windows) { ";" } else { ":" };
    let new_path = format!(
        "{}{}{}",
        sentinel_dir.path().display(),
        separator,
        original_path
    );
    std::env::set_var("PATH", &new_path);

    // Call resolve_test_binary
    let err = resolve_test_binary().unwrap_err();
    match err {
        BinaryResolutionError::WorkspaceFallbackFailed(msg) => {
            assert!(
                msg.contains("Build it explicitly before running tests"),
                "Error message must be actionable with build instructions, got: {msg}"
            );
            assert!(
                msg.contains("cargo build -p luad-cli --bin luad"),
                "Error message must name the exact build command, got: {msg}"
            );
        }
        other => panic!("expected WorkspaceFallbackFailed, got {other:?}"),
    }

    // Assert that the sentinel cargo executable was NEVER called
    assert!(
        !sentinel_witness.exists(),
        "Sentinel witness file must NOT exist: nested cargo build must never be invoked!"
    );
}
