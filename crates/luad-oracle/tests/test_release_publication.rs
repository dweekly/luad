//! Offline public-script regression for release publication, verification, and withdrawal.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use luad_oracle::candidate::sha256_digest;
use luad_oracle::find_workspace_root;
use serde_json::{json, Value};

const VERSION: &str = "0.1.0";
const RUN_ID: &str = "123456789";

const FAKE_GH: &str = r###"#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import shutil
import sys
import tarfile
import zipfile

args = sys.argv[1:]
root = pathlib.Path(os.environ["FAKE_GH_STATE"])
root.mkdir(parents=True, exist_ok=True)
log = root / "gh.log"
with log.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(args, separators=(",", ":")) + "\n")

state_path = root / "state.json"
if state_path.exists():
    state = json.loads(state_path.read_text(encoding="utf-8"))
else:
    state = {"latest": "v0.0.1", "releases": {}, "tags": {}}
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

revision = os.environ["FAKE_GH_REVISION"]
run_id = os.environ["FAKE_GH_RUN_ID"]
bundle = pathlib.Path(os.environ["FAKE_GH_BUNDLE"])
mode = os.environ.get("FAKE_GH_MODE", "ok")

def save():
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

def not_found():
    print("gh: Not Found (HTTP 404)", file=sys.stderr)
    sys.exit(1)

def archive_not_found():
    print("404: Not Found", end="", file=sys.stderr)
    print("gh: HTTP 404", file=sys.stderr)
    sys.exit(1)

def reference_does_not_exist():
    print("gh: Reference does not exist (HTTP 422)", file=sys.stderr)
    sys.exit(1)

def option(name, default=None):
    if name not in args:
        return default
    index = args.index(name)
    if index + 1 >= len(args):
        print(f"missing value for {name}", file=sys.stderr)
        sys.exit(2)
    return args[index + 1]

def required_jobs():
    names = [
        "Dependency Audit",
        "Hostile Input Fuzz Smoke (Linux)",
        "MSRV (macos-latest)",
        "MSRV (ubuntu-latest)",
        "Release Archive Build (linux-x86_64, replica one)",
        "Release Archive Build (linux-x86_64, replica two)",
        "Release Archive Build (macos-aarch64, replica one)",
        "Release Archive Build (macos-aarch64, replica two)",
        "Release Archives",
        "Release Bundle",
        "Release SBOM",
        "Test (macos-latest)",
        "Test (ubuntu-latest)",
    ]
    jobs = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
    if mode == "failed_job":
        jobs[0]["conclusion"] = "failure"
    elif mode == "skipped_job":
        jobs[0]["conclusion"] = "skipped"
    elif mode == "missing_job":
        jobs.pop()
    elif mode == "duplicate_job":
        jobs.append(dict(jobs[0]))
    elif mode == "extra_job":
        jobs.append({"name": "Uncontracted Job", "status": "completed", "conclusion": "success"})
    return jobs

if not args:
    sys.exit(2)

if args[0] == "run" and len(args) >= 3 and args[1] == "view":
    document = {
        "event": "pull_request" if mode == "wrong_event" else "push",
        "headBranch": "other" if mode == "wrong_branch" else "main",
        "headSha": ("f" * 40) if mode == "wrong_run_revision" else revision,
        "status": "completed",
        "conclusion": "failure" if mode == "failed_run" else "success",
        "workflowName": "Other" if mode == "wrong_workflow" else "CI",
        "jobs": required_jobs(),
    }
    print(json.dumps(document, separators=(",", ":")))
    sys.exit(0)

if args[0] == "run" and len(args) >= 3 and args[1] == "download":
    if args[2] != run_id or option("--name") != "release-bundle":
        print("unexpected run download", file=sys.stderr)
        sys.exit(1)
    destination = pathlib.Path(option("--dir"))
    destination.mkdir(parents=True, exist_ok=True)
    for source in bundle.iterdir():
        shutil.copyfile(source, destination / source.name)
    sys.exit(0)

if args[0] == "api":
    method = option("--method", "GET")
    endpoint = next((arg for arg in args[1:] if not arg.startswith("-") and arg not in {method, "DELETE", ".sha"}), None)
    if endpoint is None:
        print("missing endpoint", file=sys.stderr)
        sys.exit(2)
    if method == "DELETE":
        prefix = "repos/dweekly/luad/git/refs/tags/"
        if endpoint.startswith(prefix):
            tag = endpoint[len(prefix):]
            if tag not in state["tags"]:
                reference_does_not_exist()
            del state["tags"][tag]
            save()
            sys.exit(0)
        print("unsupported delete", file=sys.stderr)
        sys.exit(2)
    if endpoint == "repos/dweekly/luad":
        name = "other/luad" if mode == "wrong_repository" else "dweekly/luad"
        print(json.dumps({"full_name": name, "html_url": "https://github.com/dweekly/luad"}))
        sys.exit(0)
    if endpoint == "repos/dweekly/luad/commits/main":
        main_revision = ("e" * 40) if mode == "wrong_main" else revision
        if "--jq" in args:
            print(main_revision)
        else:
            print(json.dumps({"sha": main_revision}))
        sys.exit(0)
    if endpoint == f"repos/dweekly/luad/actions/runs/{run_id}/artifacts?per_page=100":
        artifacts = [{
            "name": "release-bundle",
            "expired": mode == "expired_artifact",
            "archive_download_url": "https://api.github.com/repos/dweekly/luad/actions/artifacts/99/zip",
        }]
        if mode == "missing_artifact":
            artifacts = []
        elif mode == "duplicate_artifact":
            artifacts.append(dict(artifacts[0]))
        print(json.dumps([{"artifacts": artifacts}], separators=(",", ":")))
        sys.exit(0)
    release_prefix = "repos/dweekly/luad/releases/tags/"
    if endpoint.startswith(release_prefix):
        tag = endpoint[len(release_prefix):]
        if mode == "preexisting_probe" and tag.startswith("publication-failure-probe-"):
            print(json.dumps({"tag_name": tag}))
            sys.exit(0)
        release = state["releases"].get(tag)
        if release is None:
            not_found()
        print(json.dumps(release, separators=(",", ":")))
        sys.exit(0)
    tag_prefix = "repos/dweekly/luad/git/ref/tags/"
    if endpoint.startswith(tag_prefix):
        tag = endpoint[len(tag_prefix):]
        if mode == "preexisting_probe" and tag.startswith("publication-failure-probe-"):
            print(json.dumps({"object": {"type": "commit", "sha": revision}}))
            sys.exit(0)
        target = state["tags"].get(tag)
        if mode == "tag_conflict" and tag.startswith("v"):
            print(json.dumps({"object": {"type": "commit", "sha": "d" * 40}}))
            sys.exit(0)
        if target is None:
            not_found()
        if mode == "tag_moved":
            target = "d" * 40
        print(json.dumps({"object": {"type": "commit", "sha": target}}))
        sys.exit(0)
    if endpoint == "repos/dweekly/luad/releases/latest":
        if state["latest"] is None:
            not_found()
        print(json.dumps({"tag_name": state["latest"]}))
        sys.exit(0)
    for prefix in ("repos/dweekly/luad/tarball/", "repos/dweekly/luad/zipball/"):
        if endpoint.startswith(prefix):
            tag = endpoint[len(prefix):]
            if tag not in state["tags"]:
                archive_not_found()
            print("archive")
            sys.exit(0)
    print(f"unsupported api endpoint: {endpoint}", file=sys.stderr)
    sys.exit(2)

if args[0] == "release" and len(args) >= 3 and args[1] == "create":
    tag = args[2]
    if tag in state["releases"] or tag in state["tags"]:
        print("release identity exists", file=sys.stderr)
        sys.exit(1)
    positional = []
    for arg in args[3:]:
        if arg.startswith("--"):
            break
        positional.append(arg)
    asset_root = root / "assets" / tag
    asset_root.mkdir(parents=True, exist_ok=False)
    assets = []
    for value in positional:
        source = pathlib.Path(value)
        shutil.copyfile(source, asset_root / source.name)
        assets.append({"name": source.name})
    title = option("--title")
    notes = pathlib.Path(option("--notes-file")).read_text(encoding="utf-8")
    target = option("--target")
    if "--draft" not in args:
        state["tags"][tag] = target
    state["releases"][tag] = {
        "tag_name": tag,
        "name": title,
        "target_commitish": target,
        "draft": "--draft" in args,
        "prerelease": "--prerelease" in args,
        "html_url": f"https://github.com/dweekly/luad/releases/tag/{tag}",
        "body": notes,
        "assets": assets,
    }
    if mode == "missing_release_asset":
        state["releases"][tag]["assets"].pop()
    elif mode == "extra_release_asset":
        state["releases"][tag]["assets"].append({"name": "unexpected.bin"})
    if mode == "latest_changed" and "--draft" not in args:
        state["latest"] = tag
    save()
    print(state["releases"][tag]["html_url"])
    sys.exit(0)

if args[0] == "release" and len(args) >= 3 and args[1] == "download":
    tag = args[2]
    release = state["releases"].get(tag)
    if release is None:
        not_found()
    if "--archive" in args:
        kind = option("--archive")
        output = pathlib.Path(option("--output"))
        output.parent.mkdir(parents=True, exist_ok=True)
        if mode == "revision_source_root":
            archive_root = f"dweekly-luad-{revision}"
        else:
            archive_root = f"luad-{tag}"
        payload = root / "source-readme"
        payload.write_text("source\n", encoding="utf-8")
        if kind == "tar.gz":
            with tarfile.open(output, "w:gz") as archive:
                archive.add(payload, arcname=f"{archive_root}/README.md")
        elif kind == "zip":
            with zipfile.ZipFile(output, "w") as archive:
                archive.write(payload, arcname=f"{archive_root}/README.md")
        else:
            print("unsupported archive kind", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)
    destination = pathlib.Path(option("--dir"))
    destination.mkdir(parents=True, exist_ok=True)
    asset_root = root / "assets" / tag
    for asset in release["assets"]:
        source = asset_root / asset["name"]
        shutil.copyfile(source, destination / source.name)
    if mode == "changed_download":
        archive = destination / "luad-0.1.0-linux-x86_64.tar.gz"
        if archive.exists():
            data = bytearray(archive.read_bytes())
            data[0] ^= 0xff
            archive.write_bytes(data)
    sys.exit(0)

if args[0] == "release" and len(args) >= 3 and args[1] == "delete":
    tag = args[2]
    if tag not in state["releases"]:
        not_found()
    if mode != "delete_noop":
        del state["releases"][tag]
        if "--cleanup-tag" in args:
            if tag not in state["tags"]:
                save()
                reference_does_not_exist()
            del state["tags"][tag]
        save()
    sys.exit(0)

if args[0] == "attestation" and len(args) >= 3 and args[1] == "verify":
    target_archive = pathlib.Path(args[2])
    if not target_archive.exists():
        print(f"file not found: {target_archive}", file=sys.stderr)
        sys.exit(1)
    if mode == "attestation_fail":
        print("gh: no attestation found for artifact", file=sys.stderr)
        sys.exit(1)
    digest = hashlib.sha256(target_archive.read_bytes()).hexdigest()
    if mode == "corrupted_archive":
        print("gh: attestation verification failed: digest mismatch", file=sys.stderr)
        sys.exit(1)
    att_revision = ("f" * 40) if mode == "attestation_wrong_revision" else revision
    att_workflow = ".github/workflows/other.yml" if mode == "attestation_wrong_workflow" else ".github/workflows/ci.yml"
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": target_archive.name,
                "digest": {
                    "sha256": digest
                }
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.com/buildtypes/runner/v1",
                "externalParameters": {
                    "workflow": {
                        "path": att_workflow,
                        "repository": "https://github.com/dweekly/luad",
                        "ref": "refs/heads/main"
                    }
                },
                "internalParameters": {
                    "github": {
                        "event_name": "push",
                        "sha": att_revision
                    }
                }
            }
        }
    }
    print(json.dumps([{"statement": statement}], separators=(",", ":")))
    sys.exit(0)

if args[0] == "release" and len(args) >= 3 and args[1] == "edit":
    tag = args[2]
    if tag not in state["releases"]:
        not_found()
    if "--latest" in args:
        state["latest"] = tag
    save()
    sys.exit(0)

print(f"unsupported gh command: {args}", file=sys.stderr)
sys.exit(2)
"###;

const FAKE_CARGO: &str = r###"#!/usr/bin/env python3
import hashlib
import json
import os
import pathlib
import sys

args = sys.argv[1:]
root = pathlib.Path(os.environ["FAKE_GH_STATE"])
with (root / "cargo.log").open("a", encoding="utf-8") as handle:
    handle.write(json.dumps(args, separators=(",", ":")) + "\n")

if "verify-bundle" not in args or "--bundle-dir" not in args:
    print("unexpected cargo command", file=sys.stderr)
    sys.exit(2)
directory = pathlib.Path(args[args.index("--bundle-dir") + 1])
version = "0.1.0"
expected = sorted([
    "SHA256SUMS",
    "evidence-index.json",
    f"luad-{version}-linux-x86_64.tar.gz",
    f"luad-{version}-macos-aarch64.tar.gz",
    f"luad-{version}.cdx.json",
])
actual = sorted(path.name for path in directory.iterdir() if path.is_file())
if actual != expected:
    sys.exit(1)
checksums = {}
for line in (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, name = line.split("  ", 1)
    checksums[name] = digest
for name, digest in checksums.items():
    if hashlib.sha256((directory / name).read_bytes()).hexdigest() != digest:
        sys.exit(1)
index = json.loads((directory / "evidence-index.json").read_text(encoding="utf-8"))
if index.get("version") != version or index.get("source_revision") != os.environ["FAKE_GH_REVISION"]:
    sys.exit(1)
if index.get("dirty") is not False or index.get("promoted_targets") != []:
    sys.exit(1)
print(json.dumps({
    "version": version,
    "source_revision": os.environ["FAKE_GH_REVISION"],
    "files": expected,
    "sha256": checksums,
}, separators=(",", ":")))
"###;

struct Fixture {
    _temp: tempfile::TempDir,
    repository: PathBuf,
    state: PathBuf,
    bin: PathBuf,
    bundle: PathBuf,
    revision: String,
}

fn make_executable(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write fake executable");
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("make fake executable executable");
}

fn run_success(command: &mut Command) {
    let output = command.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_repository(root: &Path) -> String {
    fs::create_dir_all(root).expect("create fixture repository");
    fs::write(
        root.join("Cargo.toml"),
        format!("[workspace]\nresolver = \"2\"\n\n[workspace.package]\nversion = \"{VERSION}\"\n"),
    )
    .unwrap();
    run_success(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(root),
    );
    run_success(
        Command::new("git")
            .args(["config", "user.email", "publication@example.invalid"])
            .current_dir(root),
    );
    run_success(
        Command::new("git")
            .args(["config", "user.name", "Publication Test"])
            .current_dir(root),
    );
    run_success(
        Command::new("git")
            .args(["remote", "add", "origin", "https://github.com/dweekly/luad"])
            .current_dir(root),
    );
    run_success(Command::new("git").args(["add", "."]).current_dir(root));
    run_success(
        Command::new("git")
            .args(["commit", "--quiet", "-m", "fixture"])
            .current_dir(root),
    );
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn create_bundle(root: &Path, revision: &str, promoted: bool) {
    fs::create_dir_all(root).unwrap();
    let payloads = [
        ("evidence-index.json".to_owned(), Vec::new()),
        (
            format!("luad-{VERSION}-linux-x86_64.tar.gz"),
            b"linux archive\n".to_vec(),
        ),
        (
            format!("luad-{VERSION}-macos-aarch64.tar.gz"),
            b"macos archive\n".to_vec(),
        ),
        (
            format!("luad-{VERSION}.cdx.json"),
            b"{\"bomFormat\":\"CycloneDX\"}\n".to_vec(),
        ),
    ];
    let index = serde_json::to_vec_pretty(&json!({
        "schema_version": 1,
        "kind": "luad-release-bundle-v1",
        "version": VERSION,
        "source_revision": revision,
        "dirty": false,
        "promoted_targets": if promoted { vec!["forbidden"] } else { Vec::<&str>::new() },
        "prerequisites": [],
        "platforms": [],
        "sbom": {}
    }))
    .unwrap();
    fs::write(
        root.join("evidence-index.json"),
        [index, b"\n".to_vec()].concat(),
    )
    .unwrap();
    for (name, bytes) in payloads.into_iter().skip(1) {
        fs::write(root.join(name), bytes).unwrap();
    }
    let names = [
        "evidence-index.json".to_owned(),
        format!("luad-{VERSION}-linux-x86_64.tar.gz"),
        format!("luad-{VERSION}-macos-aarch64.tar.gz"),
        format!("luad-{VERSION}.cdx.json"),
    ];
    let mut checksums = BTreeMap::new();
    for name in names {
        checksums.insert(
            name.clone(),
            sha256_digest(&fs::read(root.join(name)).unwrap()),
        );
    }
    let text: String = checksums
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect();
    fs::write(root.join("SHA256SUMS"), text).unwrap();
}

impl Fixture {
    fn new() -> Self {
        Self::with_promoted_targets(false)
    }

    fn with_promoted_targets(promoted: bool) -> Self {
        let temp = tempfile::tempdir().expect("create fixture tempdir");
        let repository = temp.path().join("repository");
        let revision = init_repository(&repository);
        let state = temp.path().join("state");
        fs::create_dir(&state).unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        make_executable(&bin.join("gh"), FAKE_GH);
        make_executable(&bin.join("cargo"), FAKE_CARGO);
        let bundle = temp.path().join("bundle");
        create_bundle(&bundle, &revision, promoted);
        Self {
            _temp: temp,
            repository,
            state,
            bin,
            bundle,
            revision,
        }
    }

    fn command(&self, mode: &str) -> Command {
        let path = std::env::var("PATH").unwrap();
        let mut command =
            Command::new(find_workspace_root().join("scripts/release-publication.sh"));
        command
            .current_dir(&self.repository)
            .env("PATH", format!("{}:{path}", self.bin.display()))
            .env("GITHUB_REF", "refs/heads/main")
            .env("GITHUB_REPOSITORY", "dweekly/luad")
            .env("GITHUB_WORKSPACE", &self.repository)
            .env("RUNNER_TEMP", self._temp.path())
            .env("FAKE_GH_STATE", &self.state)
            .env("FAKE_GH_REVISION", &self.revision)
            .env("FAKE_GH_RUN_ID", RUN_ID)
            .env("FAKE_GH_BUNDLE", &self.bundle)
            .env("FAKE_GH_MODE", mode);
        command
    }

    fn rehearse(&self, mode: &str) -> Output {
        self.command(mode)
            .args(["rehearse", &self.revision, RUN_ID])
            .output()
            .expect("run publication rehearsal")
    }

    fn publish(&self, mode: &str) -> Output {
        self.command(mode)
            .args(["publish", &self.revision, RUN_ID])
            .output()
            .expect("run publication")
    }

    fn state(&self) -> Value {
        let path = self.state.join("state.json");
        if path.exists() {
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
        } else {
            json!({"latest": "v0.0.1", "releases": {}, "tags": {}})
        }
    }

    fn log(&self, name: &str) -> Vec<Vec<String>> {
        fs::read_to_string(self.state.join(name))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "rehearsal failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output, label: &str) {
    assert!(
        !output.status.success(),
        "negative control unexpectedly passed: {label}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn command_has(log: &[Vec<String>], words: &[&str]) -> bool {
    log.iter().any(|command| {
        words
            .iter()
            .all(|word| command.iter().any(|argument| argument.contains(word)))
    })
}

fn audit_success_log(log: &[Vec<String>], revision: &str) -> Result<(), String> {
    for words in [
        vec!["run", "view", RUN_ID],
        vec!["run", "download", RUN_ID, "release-bundle"],
        vec![
            "release",
            "create",
            "--target",
            revision,
            "--prerelease",
            "--latest=false",
        ],
        vec![
            "release",
            "create",
            "publication-failure-probe-0.1.0",
            "--draft",
            "--target",
            revision,
            "--latest=false",
        ],
        vec![
            "release",
            "create",
            "publication-withdrawal-probe-0.1.0",
            "--target",
            revision,
            "--prerelease",
            "--latest=false",
        ],
        vec![
            "release",
            "create",
            "publication-rehearsal-0.1.0",
            "--target",
            revision,
            "--prerelease",
            "--latest=false",
        ],
        vec![
            "release",
            "delete",
            "publication-failure-probe-0.1.0",
            "--yes",
        ],
        vec![
            "release",
            "delete",
            "publication-withdrawal-probe-0.1.0",
            "--yes",
        ],
        vec![
            "api",
            "--method",
            "DELETE",
            "git/refs/tags/publication-withdrawal-probe-0.1.0",
        ],
        vec!["release", "download", "--archive", "tar.gz"],
        vec!["release", "download", "--archive", "zip"],
    ] {
        if !command_has(log, &words) {
            return Err(format!("missing command evidence: {words:?}"));
        }
    }
    if command_has(log, &["release", "delete", "--cleanup-tag"]) {
        return Err("release deletion must tolerate a draft without a tag".to_owned());
    }
    Ok(())
}

fn audit_publish_success_log(log: &[Vec<String>], revision: &str) -> Result<(), String> {
    for words in [
        vec!["run", "view", RUN_ID],
        vec!["run", "download", RUN_ID, "release-bundle"],
        vec![
            "release",
            "create",
            &format!("v{VERSION}"),
            "--target",
            revision,
            "--latest=false",
        ],
        vec!["release", "download", &format!("v{VERSION}")],
        vec![
            "release",
            "download",
            &format!("v{VERSION}"),
            "--archive",
            "tar.gz",
        ],
        vec![
            "release",
            "download",
            &format!("v{VERSION}"),
            "--archive",
            "zip",
        ],
        vec![
            "attestation",
            "verify",
            &format!("luad-{VERSION}-linux-x86_64.tar.gz"),
            "--repo",
            "dweekly/luad",
        ],
        vec![
            "attestation",
            "verify",
            &format!("luad-{VERSION}-macos-aarch64.tar.gz"),
            "--repo",
            "dweekly/luad",
        ],
        vec!["release", "edit", &format!("v{VERSION}"), "--latest"],
    ] {
        if !command_has(log, &words) {
            return Err(format!("missing publish command evidence: {words:?}"));
        }
    }
    Ok(())
}

#[test]
fn test_release_publication_rehearses_idempotently_and_withdraws_exact_identity() {
    let fixture = Fixture::new();
    let tag = format!(
        "publication-rehearsal-{VERSION}-{}",
        &fixture.revision[..12]
    );
    let first = fixture.rehearse("ok");
    assert_success(&first);
    assert_eq!(
        String::from_utf8(first.stdout).unwrap().trim(),
        format!("https://github.com/dweekly/luad/releases/tag/{tag}")
    );

    let state = fixture.state();
    assert_eq!(state["latest"], "v0.0.1");
    assert_eq!(state["releases"].as_object().unwrap().len(), 1);
    assert_eq!(state["tags"].as_object().unwrap().len(), 1);
    let retained = &state["releases"][&tag];
    assert_eq!(retained["draft"], false);
    assert_eq!(retained["prerelease"], true);
    let body = retained["body"].as_str().unwrap();
    assert!(body.starts_with("NOT A PRODUCT RELEASE"));
    assert!(body.contains(&format!(
        "Accepted CI run: https://github.com/dweekly/luad/actions/runs/{RUN_ID}"
    )));
    assert!(body.contains("Supported targets: `none`"));
    assert!(body.contains("Signing: `not signed`"));
    assert_eq!(body.matches("  luad-").count(), 3);
    assert_eq!(body.matches("  evidence-index.json").count(), 1);
    let mut asset_names: Vec<_> = retained["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|asset| asset["name"].as_str().unwrap())
        .collect();
    asset_names.sort_unstable();
    assert_eq!(
        asset_names,
        vec![
            "SHA256SUMS",
            "evidence-index.json",
            "luad-0.1.0-linux-x86_64.tar.gz",
            "luad-0.1.0-macos-aarch64.tar.gz",
            "luad-0.1.0.cdx.json",
        ]
    );

    let first_log = fixture.log("gh.log");
    audit_success_log(&first_log, &fixture.revision).expect("complete command evidence");
    let retained_creates_before = first_log
        .iter()
        .filter(|command| command_has(&[(*command).clone()], &["release", "create", &tag]))
        .count();
    assert_eq!(retained_creates_before, 1);
    assert!(fixture.log("cargo.log").len() >= 3);

    let second = fixture.rehearse("ok");
    assert_success(&second);
    let second_log = fixture.log("gh.log");
    let retained_creates_after = second_log
        .iter()
        .filter(|command| command_has(&[(*command).clone()], &["release", "create", &tag]))
        .count();
    assert_eq!(
        retained_creates_after, 1,
        "idempotent rerun must not overwrite release"
    );

    fs::write(fixture.repository.join("later-main"), b"later\n").unwrap();
    run_success(
        Command::new("git")
            .args(["add", "later-main"])
            .current_dir(&fixture.repository),
    );
    run_success(
        Command::new("git")
            .args(["commit", "--quiet", "-m", "later main"])
            .current_dir(&fixture.repository),
    );
    let next_main = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&fixture.repository)
        .output()
        .unwrap();
    assert!(next_main.status.success());
    let next_main = String::from_utf8(next_main.stdout)
        .unwrap()
        .trim()
        .to_owned();
    let withdrawn = fixture
        .command("ok")
        .env("FAKE_GH_REVISION", next_main)
        .args(["withdraw", &tag, &fixture.revision])
        .output()
        .unwrap();
    assert_success(&withdrawn);
    let final_state = fixture.state();
    assert!(final_state["releases"].as_object().unwrap().is_empty());
    assert!(final_state["tags"].as_object().unwrap().is_empty());
    assert_eq!(final_state["latest"], "v0.0.1");
}

#[test]
fn test_release_publication_rejects_untrusted_or_incomplete_hosted_inputs() {
    for mode in [
        "wrong_repository",
        "wrong_main",
        "wrong_event",
        "wrong_branch",
        "wrong_run_revision",
        "wrong_workflow",
        "failed_run",
        "failed_job",
        "skipped_job",
        "missing_job",
        "duplicate_job",
        "extra_job",
        "missing_artifact",
        "duplicate_artifact",
        "expired_artifact",
        "preexisting_probe",
    ] {
        let fixture = Fixture::new();
        assert_failure(&fixture.rehearse(mode), mode);
    }

    let fixture = Fixture::with_promoted_targets(true);
    assert_failure(&fixture.rehearse("ok"), "non-empty promoted target set");
}

#[test]
fn test_release_publication_rejects_remote_corruption_and_cleanup_failures() {
    for mode in [
        "changed_download",
        "latest_changed",
        "tag_moved",
        "revision_source_root",
        "delete_noop",
        "missing_release_asset",
        "extra_release_asset",
    ] {
        let fixture = Fixture::new();
        assert_failure(&fixture.rehearse(mode), mode);
    }
}

#[test]
fn test_release_publication_rejects_local_identity_and_name_substitution() {
    let fixture = Fixture::new();
    let wrong_ref = fixture
        .command("ok")
        .env("GITHUB_REF", "refs/heads/feature")
        .args(["rehearse", &fixture.revision, RUN_ID])
        .output()
        .unwrap();
    assert_failure(&wrong_ref, "wrong checkout ref");

    let wrong_repository = fixture
        .command("ok")
        .env("GITHUB_REPOSITORY", "attacker/luad")
        .args(["rehearse", &fixture.revision, RUN_ID])
        .output()
        .unwrap();
    assert_failure(&wrong_repository, "wrong repository environment");

    fs::write(fixture.repository.join("dirty"), b"dirty\n").unwrap();
    assert_failure(&fixture.rehearse("ok"), "dirty checkout");

    let unsafe_revision = fixture
        .command("ok")
        .args(["rehearse", "ABC;touch-pwned", RUN_ID])
        .output()
        .unwrap();
    assert_failure(&unsafe_revision, "unsafe revision");
    let unsafe_run = fixture
        .command("ok")
        .args(["rehearse", &fixture.revision, "1;touch-pwned"])
        .output()
        .unwrap();
    assert_failure(&unsafe_run, "unsafe run ID");
}

#[test]
fn test_release_publication_fake_command_audit_has_negative_controls() {
    let fixture = Fixture::new();
    assert_success(&fixture.rehearse("ok"));
    let log = fixture.log("gh.log");
    audit_success_log(&log, &fixture.revision).expect("unmodified fake command log");

    let without_verification: Vec<_> = log
        .iter()
        .filter(|command| !command_has(&[(*command).clone()], &["release", "download", "tar.gz"]))
        .cloned()
        .collect();
    assert!(
        audit_success_log(&without_verification, &fixture.revision).is_err(),
        "removing source verification must be detected"
    );

    let without_cleanup: Vec<_> = log
        .iter()
        .filter(|command| !command_has(&[(*command).clone()], &["release", "delete"]))
        .cloned()
        .collect();
    assert!(
        audit_success_log(&without_cleanup, &fixture.revision).is_err(),
        "removing cleanup must be detected"
    );

    let without_one_cleanup: Vec<_> = log
        .iter()
        .filter(|command| {
            !command_has(
                &[(*command).clone()],
                &["release", "delete", "publication-failure-probe-0.1.0"],
            )
        })
        .cloned()
        .collect();
    assert!(
        audit_success_log(&without_one_cleanup, &fixture.revision).is_err(),
        "removing either probe cleanup must be detected"
    );

    let mut with_draft_cleanup_tag = log.clone();
    let failure_delete = with_draft_cleanup_tag
        .iter_mut()
        .find(|command| {
            command_has(
                &[(**command).clone()],
                &["release", "delete", "publication-failure-probe-0.1.0"],
            )
        })
        .expect("failure probe deletion command");
    failure_delete.push("--cleanup-tag".to_owned());
    assert!(
        audit_success_log(&with_draft_cleanup_tag, &fixture.revision).is_err(),
        "reintroducing tag cleanup for a tagless draft must be detected"
    );

    let pub_fixture = Fixture::new();
    assert_success(&pub_fixture.publish("ok"));
    let pub_log = pub_fixture.log("gh.log");
    audit_publish_success_log(&pub_log, &pub_fixture.revision)
        .expect("unmodified publish command log");

    let without_attestation: Vec<_> = pub_log
        .iter()
        .filter(|command| !command_has(&[(*command).clone()], &["attestation", "verify"]))
        .cloned()
        .collect();
    assert!(
        audit_publish_success_log(&without_attestation, &pub_fixture.revision).is_err(),
        "omitting attestation verification must fail publish audit"
    );

    let without_latest_edit: Vec<_> = pub_log
        .iter()
        .filter(|command| !command_has(&[(*command).clone()], &["release", "edit", "--latest"]))
        .cloned()
        .collect();
    assert!(
        audit_publish_success_log(&without_latest_edit, &pub_fixture.revision).is_err(),
        "omitting release promotion must fail publish audit"
    );
}

#[test]
fn test_release_publication_publishes_and_verifies_attestations() {
    let fixture = Fixture::new();
    let tag = format!("v{VERSION}");
    let first = fixture.publish("ok");
    assert_success(&first);
    assert_eq!(
        String::from_utf8(first.stdout).unwrap().trim(),
        format!("https://github.com/dweekly/luad/releases/tag/{tag}")
    );

    let state = fixture.state();
    assert_eq!(state["latest"], tag);
    assert_eq!(state["releases"].as_object().unwrap().len(), 1);
    assert_eq!(state["tags"].as_object().unwrap().len(), 1);
    let published = &state["releases"][&tag];
    assert_eq!(published["draft"], false);
    assert_eq!(published["prerelease"], false);
    let body = published["body"].as_str().unwrap();
    assert!(body.starts_with("# luad 0.1.0"));
    assert!(body.contains(&format!(
        "Accepted CI run: https://github.com/dweekly/luad/actions/runs/{RUN_ID}"
    )));
    assert!(body.contains("gh attestation verify"));

    let mut asset_names: Vec<_> = published["assets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|asset| asset["name"].as_str().unwrap())
        .collect();
    asset_names.sort_unstable();
    assert_eq!(
        asset_names,
        vec![
            "SHA256SUMS",
            "evidence-index.json",
            "luad-0.1.0-linux-x86_64.tar.gz",
            "luad-0.1.0-macos-aarch64.tar.gz",
            "luad-0.1.0.cdx.json",
        ]
    );

    let first_log = fixture.log("gh.log");
    audit_publish_success_log(&first_log, &fixture.revision)
        .expect("complete publish command evidence");
    let create_count = first_log
        .iter()
        .filter(|command| command_has(&[(*command).clone()], &["release", "create", &tag]))
        .count();
    assert_eq!(create_count, 1);

    // Idempotent rerun against matching revision
    let second = fixture.publish("ok");
    assert_success(&second);
    let second_log = fixture.log("gh.log");
    let create_count_after = second_log
        .iter()
        .filter(|command| command_has(&[(*command).clone()], &["release", "create", &tag]))
        .count();
    assert_eq!(
        create_count_after, 1,
        "idempotent rerun must not recreate release"
    );
}

#[test]
fn test_release_publication_rejects_tag_conflict_on_different_commit() {
    let fixture = Fixture::new();
    let res = fixture.publish("tag_conflict");
    assert_failure(&res, "tag conflict on different commit");
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(stderr.contains("version tags cannot be moved"));
    let state = fixture.state();
    assert_eq!(state["latest"], "v0.0.1");
}

#[test]
fn test_release_publication_rejects_attestation_failure() {
    let fixture = Fixture::new();
    let res = fixture.publish("attestation_fail");
    assert_failure(&res, "missing or invalid attestation");
    let state = fixture.state();
    assert_eq!(state["latest"], "v0.0.1");
}

#[test]
fn test_release_publication_rejects_attestation_revision_mismatch() {
    let fixture = Fixture::new();
    let res = fixture.publish("attestation_wrong_revision");
    assert_failure(&res, "attestation revision mismatch");
    let state = fixture.state();
    assert_eq!(state["latest"], "v0.0.1");
}

#[test]
fn test_release_publication_rejects_attestation_workflow_mismatch() {
    let fixture = Fixture::new();
    let res = fixture.publish("attestation_wrong_workflow");
    assert_failure(&res, "attestation workflow mismatch");
    let state = fixture.state();
    assert_eq!(state["latest"], "v0.0.1");
}

#[test]
fn test_release_publication_rejects_corrupted_archive_attestation() {
    let fixture = Fixture::new();
    let res = fixture.publish("corrupted_archive");
    assert_failure(&res, "corrupted archive attestation");
    let state = fixture.state();
    assert_eq!(state["latest"], "v0.0.1");
}
