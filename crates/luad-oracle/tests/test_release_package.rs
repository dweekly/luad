//! Public-boundary tests for deterministic, non-promoting release archives.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_core::capabilities::get_canonical_capabilities;
use luad_oracle::candidate::{
    create_deterministic_gzip, create_ustar_header, decompress_gzip, parse_tar, sha256_digest,
    MemberLedger, MemberLedgerEntry, ParsedTarEntry,
};
use luad_oracle::find_workspace_root;
use luad_oracle::release_package::{
    clean_source_revision, extract_verified_release, pack_release, package_clean_workspace,
    smoke_release_binary, verify_release, ReleaseArtifactPaths, ReleaseIdentity, ReleaseInputs,
};

struct Fixture {
    binary: PathBuf,
    readme: PathBuf,
    license_mit: PathBuf,
    license_apache: PathBuf,
    identity: ReleaseIdentity,
}

impl Fixture {
    fn inputs(&self) -> ReleaseInputs<'_> {
        ReleaseInputs {
            binary: &self.binary,
            readme: &self.readme,
            license_mit: &self.license_mit,
            license_apache: &self.license_apache,
            identity: self.identity.clone(),
        }
    }
}

fn fixture(temp: &Path) -> Fixture {
    let root = find_workspace_root();
    let binary = temp.join("mock-luad");
    fs::write(
        &binary,
        br##"#!/bin/sh
case "$1" in
  --version)
    printf 'luad 0.1.0\n'
    ;;
  capabilities)
    if [ "$2" != "--format" ] || [ "$3" != "json" ]; then
      exit 2
    fi
    printf '{"tool_name":"luad","tool_version":"0.1.0","supported_dialects":[]}\n'
    ;;
  *)
    exit 2
    ;;
esac
"##,
    )
    .expect("write mock executable");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755))
            .expect("make mock executable");
    }

    Fixture {
        binary,
        readme: root.join("README.md"),
        license_mit: root.join("LICENSE"),
        license_apache: root.join("LICENSE-APACHE"),
        identity: ReleaseIdentity {
            schema_version: 1,
            version: "0.1.0".to_string(),
            source_revision: "1111111111111111111111111111111111111111".to_string(),
            dirty: false,
            platform: "macos-aarch64".to_string(),
            target_triple: "aarch64-apple-darwin".to_string(),
        },
    }
}

fn parsed_entries(paths: &ReleaseArtifactPaths) -> Vec<ParsedTarEntry> {
    let archive = fs::read(&paths.archive).expect("read archive");
    let tar = decompress_gzip(&archive).expect("decompress archive");
    parse_tar(&tar).expect("parse archive")
}

fn rewrite_bundle(paths: &ReleaseArtifactPaths, entries: &[ParsedTarEntry]) {
    let mut tar = Vec::new();
    let mut ledger_entries = Vec::new();
    for entry in entries {
        tar.extend_from_slice(&create_ustar_header(
            &entry.name,
            entry.mode,
            entry.data.len(),
        ));
        tar.extend_from_slice(&entry.data);
        let padding = (512 - (entry.data.len() % 512)) % 512;
        tar.extend(std::iter::repeat_n(0, padding));
        ledger_entries.push(MemberLedgerEntry {
            path: entry.name.clone(),
            mode: entry.mode,
            uid: 0,
            gid: 0,
            mtime: 0,
            size: entry.data.len(),
            sha256: sha256_digest(&entry.data),
        });
    }
    tar.extend(std::iter::repeat_n(0, 1024));
    let archive = create_deterministic_gzip(&tar);
    fs::write(&paths.archive, &archive).expect("rewrite archive");

    let mut ledger = serde_json::to_vec_pretty(&MemberLedger {
        members: ledger_entries,
    })
    .expect("serialize ledger");
    ledger.push(b'\n');
    fs::write(&paths.ledger, ledger).expect("rewrite ledger");

    let archive_name = paths.archive.file_name().unwrap().to_str().unwrap();
    fs::write(
        &paths.checksums,
        format!("{}  {archive_name}\n", sha256_digest(&archive)),
    )
    .expect("rewrite checksum");
}

fn replace_identity(entries: &mut [ParsedTarEntry], mutate: impl FnOnce(&mut ReleaseIdentity)) {
    let identity_entry = entries
        .iter_mut()
        .find(|entry| entry.name.ends_with("/VERSION.json"))
        .expect("identity member");
    let mut identity: ReleaseIdentity =
        serde_json::from_slice(&identity_entry.data).expect("parse identity");
    mutate(&mut identity);
    identity_entry.data = serde_json::to_vec_pretty(&identity).expect("serialize identity");
    identity_entry.data.push(b'\n');
    identity_entry.size = identity_entry.data.len();
}

#[test]
fn test_release_package_reproducible_and_installable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(temp.path());
    let first = pack_release(&fixture.inputs(), &temp.path().join("first")).expect("first pack");
    let second = pack_release(&fixture.inputs(), &temp.path().join("second")).expect("second pack");

    assert_eq!(
        first.archive.file_name().unwrap(),
        "luad-0.1.0-macos-aarch64.tar.gz"
    );
    assert_eq!(
        fs::read(&first.archive).unwrap(),
        fs::read(&second.archive).unwrap(),
        "identical inputs must produce byte-identical archives"
    );
    assert_eq!(
        fs::read(&first.ledger).unwrap(),
        fs::read(&second.ledger).unwrap(),
        "identical inputs must produce byte-identical ledgers"
    );

    let verified = verify_release(&first, &fixture.inputs()).expect("verify package");
    let expected_names = [
        "luad-0.1.0-macos-aarch64/LICENSE",
        "luad-0.1.0-macos-aarch64/LICENSE-APACHE",
        "luad-0.1.0-macos-aarch64/README.md",
        "luad-0.1.0-macos-aarch64/VERSION.json",
        "luad-0.1.0-macos-aarch64/luad",
    ];
    assert_eq!(
        verified
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        expected_names
    );
    for (index, entry) in verified.entries.iter().enumerate() {
        assert_eq!((entry.uid, entry.gid, entry.mtime), (0, 0, 0));
        assert_eq!(entry.size, entry.data.len());
        assert_eq!(entry.mode, if index == 4 { 0o755 } else { 0o644 });
    }

    let install_root = temp.path().join("install");
    let binary = extract_verified_release(&verified, &install_root).expect("extract verified");
    let transcript = smoke_release_binary(
        &binary,
        &fixture.identity,
        "luad-0.1.0-macos-aarch64.tar.gz",
    )
    .expect("smoke installed binary");
    assert_eq!(transcript.version_stdout, "luad 0.1.0");
    assert!(transcript.supported_dialects.is_empty());
    assert_eq!(transcript.source_revision, fixture.identity.source_revision);
}

#[test]
fn test_release_package_mutations_rejected() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(temp.path());
    let cases = [
        "archive-byte",
        "checksum",
        "ledger-digest",
        "missing-member",
        "added-member",
        "unsafe-path",
        "executable-mode",
        "version",
        "revision",
        "target-triple",
        "platform",
    ];

    for case in cases {
        let output = temp.path().join(case);
        let paths = pack_release(&fixture.inputs(), &output).expect("base pack");
        let mut entries = parsed_entries(&paths);
        match case {
            "archive-byte" => {
                let mut bytes = fs::read(&paths.archive).unwrap();
                let index = bytes.len() / 2;
                bytes[index] ^= 0x01;
                fs::write(&paths.archive, bytes).unwrap();
            }
            "checksum" => {
                let archive_name = paths.archive.file_name().unwrap().to_str().unwrap();
                fs::write(
                    &paths.checksums,
                    format!("{}  {archive_name}\n", "0".repeat(64)),
                )
                .unwrap();
            }
            "ledger-digest" => {
                let mut ledger: serde_json::Value =
                    serde_json::from_slice(&fs::read(&paths.ledger).unwrap()).unwrap();
                ledger["members"][0]["sha256"] = serde_json::Value::String("0".repeat(64));
                let mut bytes = serde_json::to_vec_pretty(&ledger).unwrap();
                bytes.push(b'\n');
                fs::write(&paths.ledger, bytes).unwrap();
            }
            "missing-member" => {
                entries.remove(1);
                rewrite_bundle(&paths, &entries);
            }
            "added-member" => {
                entries.push(ParsedTarEntry {
                    name: "luad-0.1.0-macos-aarch64/release-manifest.json".to_string(),
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    size: 3,
                    mtime: 0,
                    data: b"{}\n".to_vec(),
                });
                rewrite_bundle(&paths, &entries);
            }
            "unsafe-path" => {
                entries[2].name = "../README.md".to_string();
                rewrite_bundle(&paths, &entries);
            }
            "executable-mode" => {
                entries.last_mut().unwrap().mode = 0o644;
                rewrite_bundle(&paths, &entries);
            }
            "version" => {
                replace_identity(&mut entries, |identity| {
                    identity.version = "9.9.9".to_string()
                });
                rewrite_bundle(&paths, &entries);
            }
            "revision" => {
                replace_identity(&mut entries, |identity| {
                    identity.source_revision = "2".repeat(40)
                });
                rewrite_bundle(&paths, &entries);
            }
            "target-triple" => {
                replace_identity(&mut entries, |identity| {
                    identity.target_triple = "x86_64-unknown-linux-gnu".to_string()
                });
                rewrite_bundle(&paths, &entries);
            }
            "platform" => {
                replace_identity(&mut entries, |identity| {
                    identity.platform = "linux-x86_64".to_string()
                });
                rewrite_bundle(&paths, &entries);
            }
            _ => unreachable!(),
        }

        let error = verify_release(&paths, &fixture.inputs())
            .expect_err("independent corruption control must be rejected");
        assert!(!error.is_empty(), "{case} must return an actionable error");
    }
}

fn git(repository: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repository)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_release_package_refuses_dirty_or_unsupported_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    git(temp.path(), &["init", "-q"]);
    fs::write(temp.path().join("tracked.txt"), "clean\n").unwrap();
    git(temp.path(), &["add", "tracked.txt"]);
    git(
        temp.path(),
        &[
            "-c",
            "user.name=luad test",
            "-c",
            "user.email=luad@example.invalid",
            "commit",
            "-qm",
            "initial",
        ],
    );
    let revision = clean_source_revision(temp.path()).expect("clean revision");
    assert_eq!(revision.len(), 40);

    fs::write(temp.path().join("tracked.txt"), "dirty\n").unwrap();
    assert!(clean_source_revision(temp.path())
        .expect_err("dirty source must fail")
        .contains("dirty"));
    assert!(
        package_clean_workspace(temp.path(), "macos-aarch64", &temp.path().join("output"))
            .expect_err("maintained command must stop on dirty source")
            .contains("dirty")
    );
    assert!(
        package_clean_workspace(temp.path(), "windows-x86_64", &temp.path().join("output"))
            .expect_err("unknown platform must fail before packaging")
            .contains("unsupported release platform")
    );

    let mut identity = fixture(temp.path()).identity;
    identity.dirty = true;
    assert!(identity.validate().is_err());
    identity.dirty = false;
    identity.platform = "linux-x86_64".to_string();
    assert!(
        identity.validate().is_err(),
        "platform/triple mismatch must fail"
    );
    identity.platform = "unknown".to_string();
    assert!(
        identity.validate().is_err(),
        "unknown identity platform must fail"
    );

    let fixture = fixture(temp.path());
    let nonempty = temp.path().join("nonempty-output");
    fs::create_dir(&nonempty).unwrap();
    fs::write(nonempty.join("unrelated"), "keep\n").unwrap();
    assert!(pack_release(&fixture.inputs(), &nonempty)
        .expect_err("nonempty output must fail before writing")
        .contains("must be empty"));
    assert_eq!(
        fs::read_to_string(nonempty.join("unrelated")).unwrap(),
        "keep\n"
    );
}

#[test]
fn test_release_package_non_promotion() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture = fixture(temp.path());
    let paths = pack_release(&fixture.inputs(), &temp.path().join("package")).expect("pack");
    let verified = verify_release(&paths, &fixture.inputs()).expect("verify");

    for entry in &verified.entries {
        let lower = entry.name.to_ascii_lowercase();
        assert!(!lower.contains("candidate"));
        assert!(!lower.contains("release-manifest"));
        assert!(!lower.contains("evidence-index"));
    }
    assert!(get_canonical_capabilities("0.1.0")
        .supported_dialects
        .is_empty());

    let script = find_workspace_root().join("scripts/package-release.sh");
    assert!(
        script.exists(),
        "maintained release packaging script must exist"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(script).unwrap().permissions().mode() & 0o111,
            0,
            "maintained release packaging script must be executable"
        );
    }
}
