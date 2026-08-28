//! Public-command and corruption evidence for non-promoting release-bundle composition.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_oracle::release_bundle::{
    assemble_release_bundle, verify_release_bundle, BundleMember, BundleMemberLedger,
    EvidenceConclusion, PrerequisiteDocument, PrerequisiteResult, ReleaseBundleResult,
    ReleaseEvidenceIndex,
};
use luad_oracle::release_package::InstallationTranscript;
use luad_oracle::{candidate::sha256_digest, find_workspace_root};
use serde::Serialize;
use serde_json::{json, Value};

const VERSION: &str = "0.1.0";
type PrerequisiteMutation = (&'static str, Box<dyn Fn(&mut Value)>);

struct Fixture {
    _temp: tempfile::TempDir,
    repository: PathBuf,
    archives: PathBuf,
    sbom: PathBuf,
    prerequisites: PathBuf,
    revision: String,
}

fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize canonical JSON");
    bytes.push(b'\n');
    bytes
}

fn write_canonical<T: Serialize>(path: &Path, value: &T) {
    fs::write(path, canonical_bytes(value)).expect("write canonical JSON");
}

fn run(command: &mut Command) {
    let output = command.output().expect("execute command");
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_repository(root: &Path) -> String {
    fs::create_dir_all(root.join("luad-cli/src")).expect("create fixture crate");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[workspace]\nmembers = [\"luad-cli\"]\nresolver = \"2\"\n\n[workspace.package]\nversion = \"{VERSION}\"\n"
        ),
    )
    .expect("write fixture workspace");
    fs::write(
        root.join("luad-cli/Cargo.toml"),
        "[package]\nname = \"luad-cli\"\nversion.workspace = true\nedition = \"2021\"\n",
    )
    .expect("write fixture package");
    fs::write(root.join("luad-cli/src/main.rs"), "fn main() {}\n").expect("write fixture source");

    run(Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(root));
    run(Command::new("git")
        .args(["config", "user.email", "release-bundle@example.invalid"])
        .current_dir(root));
    run(Command::new("git")
        .args(["config", "user.name", "Release Bundle Test"])
        .current_dir(root));
    run(Command::new("git").args(["add", "."]).current_dir(root));
    run(Command::new("git")
        .args(["commit", "--quiet", "-m", "fixture"])
        .current_dir(root));
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .expect("resolve fixture revision");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("revision UTF-8")
        .trim()
        .to_string()
}

fn member_ledger(platform: &str) -> BundleMemberLedger {
    let stem = format!("luad-{VERSION}-{platform}");
    let names = [
        "LICENSE",
        "LICENSE-APACHE",
        "README.md",
        "VERSION.json",
        "luad",
    ];
    BundleMemberLedger {
        members: names
            .iter()
            .enumerate()
            .map(|(index, name)| BundleMember {
                path: format!("{stem}/{name}"),
                mode: if index + 1 == names.len() {
                    0o755
                } else {
                    0o644
                },
                uid: 0,
                gid: 0,
                mtime: 0,
                size: index + 1,
                sha256: format!("{:064x}", index + 1),
            })
            .collect(),
    }
}

fn installation(revision: &str, platform: &str, target_triple: &str) -> InstallationTranscript {
    InstallationTranscript {
        schema_version: 1,
        archive: format!("luad-{VERSION}-{platform}.tar.gz"),
        version: VERSION.to_string(),
        source_revision: revision.to_string(),
        platform: platform.to_string(),
        target_triple: target_triple.to_string(),
        version_stdout: format!("luad {VERSION}"),
        capabilities_sha256: "a".repeat(64),
        supported_dialects: Vec::new(),
    }
}

fn prerequisite_document(revision: &str) -> PrerequisiteDocument {
    let run_url = "https://github.com/dweekly/luad/actions/runs/123456789";
    PrerequisiteDocument {
        schema_version: 1,
        results: vec![
            PrerequisiteResult {
                evidence_id: "dependency-audit".to_string(),
                check_name: "Dependency Audit".to_string(),
                source_revision: revision.to_string(),
                conclusion: EvidenceConclusion::Success,
                result_url: run_url.to_string(),
            },
            PrerequisiteResult {
                evidence_id: "hosted-release-archives".to_string(),
                check_name: "Release Archives".to_string(),
                source_revision: revision.to_string(),
                conclusion: EvidenceConclusion::Success,
                result_url: run_url.to_string(),
            },
            PrerequisiteResult {
                evidence_id: "local-release-archive".to_string(),
                check_name: "Test (ubuntu-latest)".to_string(),
                source_revision: revision.to_string(),
                conclusion: EvidenceConclusion::Success,
                result_url: run_url.to_string(),
            },
            PrerequisiteResult {
                evidence_id: "release-sbom".to_string(),
                check_name: "Release SBOM".to_string(),
                source_revision: revision.to_string(),
                conclusion: EvidenceConclusion::Success,
                result_url: run_url.to_string(),
            },
        ],
    }
}

fn create_archive_inputs(root: &Path, revision: &str) {
    fs::create_dir_all(root).expect("create archive inputs");
    let platforms = [
        (
            "linux-x86_64",
            "x86_64-unknown-linux-gnu",
            b"linux archive bytes\n".as_slice(),
        ),
        (
            "macos-aarch64",
            "aarch64-apple-darwin",
            b"macos archive bytes\n".as_slice(),
        ),
    ];
    let mut checksums = BTreeMap::new();
    for (platform, triple, bytes) in platforms {
        let stem = format!("luad-{VERSION}-{platform}");
        let archive = format!("{stem}.tar.gz");
        fs::write(root.join(&archive), bytes).expect("write fixture archive");
        checksums.insert(archive, sha256_digest(bytes));
        write_canonical(
            &root.join(format!("{stem}.ledger.json")),
            &member_ledger(platform),
        );
        write_canonical(
            &root.join(format!("{stem}.installation.json")),
            &installation(revision, platform, triple),
        );
    }
    let text: String = checksums
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect();
    fs::write(root.join("SHA256SUMS"), text).expect("write archive checksums");
}

fn create_sbom(path: &Path, revision: &str) {
    write_canonical(
        path,
        &json!({
            "bomFormat": "CycloneDX",
            "components": [
                {"bom-ref": "pkg:cargo/serde@1.0.0", "name": "serde", "version": "1.0.0"}
            ],
            "metadata": {
                "component": {"name": "luad", "type": "application", "version": VERSION},
                "properties": [
                    {"name": "luad:cargo_lock_sha256", "value": "b".repeat(64)},
                    {"name": "luad:source_revision", "value": revision}
                ]
            },
            "specVersion": "1.5",
            "version": 1
        }),
    );
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().expect("create fixture tempdir");
        let repository = temp.path().join("repository");
        fs::create_dir(&repository).expect("create fixture repository");
        let revision = init_repository(&repository);
        let archives = temp.path().join("archives");
        create_archive_inputs(&archives, &revision);
        let sbom = temp.path().join(format!("luad-{VERSION}.cdx.json"));
        create_sbom(&sbom, &revision);
        let prerequisites = temp.path().join("prerequisites.json");
        write_canonical(&prerequisites, &prerequisite_document(&revision));
        Self {
            _temp: temp,
            repository,
            archives,
            sbom,
            prerequisites,
            revision,
        }
    }

    fn assemble(&self, output: &Path) -> Result<ReleaseBundleResult, String> {
        assemble_release_bundle(
            &self.repository,
            &self.archives,
            &self.sbom,
            &self.prerequisites,
            output,
        )
    }
}

fn copy_files(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("create copy destination");
    for entry in fs::read_dir(source).expect("read copy source") {
        let entry = entry.expect("read source entry");
        fs::copy(entry.path(), destination.join(entry.file_name())).expect("copy fixture file");
    }
}

fn rewrite_bundle_checksums(bundle: &Path) {
    let mut checksums = BTreeMap::new();
    for name in [
        "evidence-index.json".to_string(),
        format!("luad-{VERSION}-linux-x86_64.tar.gz"),
        format!("luad-{VERSION}-macos-aarch64.tar.gz"),
        format!("luad-{VERSION}.cdx.json"),
    ] {
        checksums.insert(
            name.clone(),
            sha256_digest(&fs::read(bundle.join(name)).unwrap()),
        );
    }
    let text: String = checksums
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect();
    fs::write(bundle.join("SHA256SUMS"), text).expect("rewrite bundle checksums");
}

fn tool_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_luad-release"))
}

#[test]
fn test_release_bundle_public_command_is_deterministic_and_non_promoting() {
    let fixture = Fixture::new();
    let first = fixture._temp.path().join("bundle-one");
    let second = fixture._temp.path().join("bundle-two");

    let output = Command::new(tool_path())
        .args([
            "bundle",
            "--repository",
            fixture.repository.to_str().unwrap(),
            "--archive-dir",
            fixture.archives.to_str().unwrap(),
            "--sbom",
            fixture.sbom.to_str().unwrap(),
            "--prerequisites",
            fixture.prerequisites.to_str().unwrap(),
            "--output-dir",
            first.to_str().unwrap(),
        ])
        .output()
        .expect("run release bundle command");
    assert!(
        output.status.success(),
        "bundle command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "machine success must not use stderr"
    );
    let result: ReleaseBundleResult =
        serde_json::from_slice(&output.stdout).expect("parse command result");
    assert_eq!(result.version, VERSION);
    assert_eq!(result.source_revision, fixture.revision);
    assert_eq!(result.files.len(), 5);
    assert_eq!(result.sha256.len(), 4);

    fixture.assemble(&second).expect("assemble second bundle");
    for name in &result.files {
        assert_eq!(
            fs::read(first.join(name)).unwrap(),
            fs::read(second.join(name)).unwrap(),
            "bundle file must be deterministic: {name}"
        );
    }

    let verify = Command::new(tool_path())
        .args([
            "verify-bundle",
            "--repository",
            fixture.repository.to_str().unwrap(),
            "--bundle-dir",
            first.to_str().unwrap(),
        ])
        .output()
        .expect("run release bundle verifier");
    assert!(
        verify.status.success(),
        "verify failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(verify.stderr.is_empty());

    let index: ReleaseEvidenceIndex = serde_json::from_slice(
        &fs::read(first.join("evidence-index.json")).expect("read evidence index"),
    )
    .expect("parse evidence index");
    assert_eq!(index.kind, "non_promoting_release_dry_run");
    assert!(!index.dirty);
    assert!(index.promoted_targets.is_empty());
    assert_eq!(index.prerequisites.len(), 4);
    assert_eq!(index.platforms.len(), 2);
    assert_eq!(index.sbom.spec_version, "1.5");
    assert_eq!(index.sbom.component_count, 1);
    let index_text = fs::read_to_string(first.join("evidence-index.json")).unwrap();
    assert!(!index_text.contains("target_manifest"));
    assert!(!index_text.contains(fixture._temp.path().to_str().unwrap()));
}

#[test]
fn test_release_bundle_payload_and_promotion_mutations_are_rejected() {
    let fixture = Fixture::new();
    let accepted = fixture._temp.path().join("accepted");
    fixture
        .assemble(&accepted)
        .expect("assemble accepted bundle");

    for (case, name) in [
        ("archive", format!("luad-{VERSION}-linux-x86_64.tar.gz")),
        ("sbom", format!("luad-{VERSION}.cdx.json")),
        ("index", "evidence-index.json".to_string()),
    ] {
        let mutated = fixture._temp.path().join(format!("mutated-{case}"));
        copy_files(&accepted, &mutated);
        let path = mutated.join(name);
        let mut bytes = fs::read(&path).unwrap();
        bytes[0] ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(
            verify_release_bundle(&fixture.repository, &mutated).is_err(),
            "{case} corruption must fail verification"
        );
    }

    let promoted = fixture._temp.path().join("promoted");
    copy_files(&accepted, &promoted);
    let index_path = promoted.join("evidence-index.json");
    let mut index: ReleaseEvidenceIndex =
        serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
    index.promoted_targets = vec!["lua5.1-lnum32".to_string()];
    write_canonical(&index_path, &index);
    rewrite_bundle_checksums(&promoted);
    let error = verify_release_bundle(&fixture.repository, &promoted).unwrap_err();
    assert!(
        error.contains("promoted targets"),
        "unexpected error: {error}"
    );

    let target_manifest = fixture._temp.path().join("target-manifest");
    copy_files(&accepted, &target_manifest);
    let index_path = target_manifest.join("evidence-index.json");
    let mut index: Value = serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
    index["target_manifests"] = json!([]);
    write_canonical(&index_path, &index);
    rewrite_bundle_checksums(&target_manifest);
    assert!(verify_release_bundle(&fixture.repository, &target_manifest).is_err());
}

#[test]
fn test_release_bundle_prerequisite_substitution_fails_closed() {
    let fixture = Fixture::new();
    let original: Value =
        serde_json::from_slice(&fs::read(&fixture.prerequisites).unwrap()).unwrap();
    let mutations: Vec<PrerequisiteMutation> = vec![
        (
            "missing",
            Box::new(|value| {
                value["results"].as_array_mut().unwrap().pop();
            }),
        ),
        (
            "extra",
            Box::new(|value| {
                let extra = value["results"][0].clone();
                value["results"].as_array_mut().unwrap().push(extra);
            }),
        ),
        (
            "failed",
            Box::new(|value| value["results"][0]["conclusion"] = json!("failure")),
        ),
        (
            "skipped",
            Box::new(|value| value["results"][0]["conclusion"] = json!("skipped")),
        ),
        (
            "duplicate",
            Box::new(|value| {
                value["results"][1]["evidence_id"] = json!("dependency-audit");
            }),
        ),
        (
            "substituted",
            Box::new(|value| {
                value["results"][2]["check_name"] = json!("Test (macos-latest)");
            }),
        ),
        (
            "cross-revision",
            Box::new(|value| {
                value["results"][3]["source_revision"] = json!("0".repeat(40));
            }),
        ),
        (
            "foreign-url",
            Box::new(|value| {
                value["results"][0]["result_url"] = json!("https://example.invalid/actions/runs/1");
            }),
        ),
    ];

    for (case, mutate) in mutations {
        let path = fixture
            ._temp
            .path()
            .join(format!("prerequisites-{case}.json"));
        let mut value = original.clone();
        mutate(&mut value);
        write_canonical(&path, &value);
        let output = fixture._temp.path().join(format!("bundle-{case}"));
        let result = assemble_release_bundle(
            &fixture.repository,
            &fixture.archives,
            &fixture.sbom,
            &path,
            &output,
        );
        assert!(result.is_err(), "{case} prerequisite mutation must fail");
    }
}

#[test]
fn test_release_bundle_sidecar_identity_paths_and_file_sets_fail_closed() {
    let fixture = Fixture::new();

    let bad_ledger = fixture._temp.path().join("archives-bad-ledger");
    copy_files(&fixture.archives, &bad_ledger);
    let ledger_path = bad_ledger.join(format!("luad-{VERSION}-linux-x86_64.ledger.json"));
    let mut ledger: Value = serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
    ledger["members"][0]["path"] = json!("../LICENSE");
    write_canonical(&ledger_path, &ledger);
    assert!(assemble_release_bundle(
        &fixture.repository,
        &bad_ledger,
        &fixture.sbom,
        &fixture.prerequisites,
        &fixture._temp.path().join("bad-ledger-output")
    )
    .is_err());

    let bad_installation = fixture._temp.path().join("archives-bad-installation");
    copy_files(&fixture.archives, &bad_installation);
    let installation_path =
        bad_installation.join(format!("luad-{VERSION}-macos-aarch64.installation.json"));
    let mut installation: Value =
        serde_json::from_slice(&fs::read(&installation_path).unwrap()).unwrap();
    installation["source_revision"] = json!("0".repeat(40));
    write_canonical(&installation_path, &installation);
    assert!(assemble_release_bundle(
        &fixture.repository,
        &bad_installation,
        &fixture.sbom,
        &fixture.prerequisites,
        &fixture._temp.path().join("bad-installation-output")
    )
    .is_err());

    let bad_sbom = fixture
        ._temp
        .path()
        .join(format!("bad-luad-{VERSION}.cdx.json"));
    let mut sbom: Value = serde_json::from_slice(&fs::read(&fixture.sbom).unwrap()).unwrap();
    sbom["metadata"]["component"]["version"] = json!("9.9.9");
    write_canonical(&bad_sbom, &sbom);
    assert!(assemble_release_bundle(
        &fixture.repository,
        &fixture.archives,
        &bad_sbom,
        &fixture.prerequisites,
        &fixture._temp.path().join("bad-sbom-output")
    )
    .is_err());

    let extra_input = fixture._temp.path().join("archives-extra");
    copy_files(&fixture.archives, &extra_input);
    fs::write(extra_input.join("unexpected.txt"), "unexpected\n").unwrap();
    assert!(assemble_release_bundle(
        &fixture.repository,
        &extra_input,
        &fixture.sbom,
        &fixture.prerequisites,
        &fixture._temp.path().join("extra-input-output")
    )
    .is_err());

    let nonempty_output = fixture._temp.path().join("nonempty-output");
    fs::create_dir(&nonempty_output).unwrap();
    fs::write(nonempty_output.join("keep.txt"), "keep\n").unwrap();
    assert!(fixture.assemble(&nonempty_output).is_err());

    let accepted = fixture._temp.path().join("accepted-for-extra");
    fixture
        .assemble(&accepted)
        .expect("assemble accepted bundle");
    fs::write(accepted.join("unexpected.txt"), "unexpected\n").unwrap();
    assert!(verify_release_bundle(&fixture.repository, &accepted).is_err());

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let linked = fixture._temp.path().join("linked-bundle");
        let clean = fixture._temp.path().join("clean-for-link");
        fixture.assemble(&clean).expect("assemble link source");
        copy_files(&clean, &linked);
        let sbom_name = format!("luad-{VERSION}.cdx.json");
        fs::remove_file(linked.join(&sbom_name)).unwrap();
        symlink(clean.join(&sbom_name), linked.join(&sbom_name)).unwrap();
        assert!(verify_release_bundle(&fixture.repository, &linked).is_err());
    }
}

#[test]
fn test_release_bundle_script_is_maintained_and_executable() {
    let script = find_workspace_root().join("scripts/assemble-release-bundle.sh");
    let contents = fs::read_to_string(&script).expect("read maintained bundle script");
    assert!(contents.starts_with("#!/usr/bin/env bash\nset -euo pipefail\n"));
    assert!(contents.contains("-p luad-oracle --bin luad-release --"));
    assert!(contents.contains("bundle"));
    assert!(contents.contains("--archive-dir"));
    assert!(contents.contains("--prerequisites"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(script).unwrap().permissions().mode() & 0o111,
            0
        );
    }
}
