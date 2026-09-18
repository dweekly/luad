//! Public-boundary tests for deterministic release SBOM generation and verification.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use luad_core::capabilities::get_canonical_capabilities;
use luad_oracle::find_workspace_root;
use luad_oracle::release_sbom::{generate_release_sbom, verify_release_sbom};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    name: String,
    version: String,
}

#[derive(Debug, Clone)]
struct Package {
    key: Key,
    source: Option<String>,
    checksum: Option<String>,
    license: String,
    description: Option<String>,
    repository: Option<String>,
}

type SbomMutation = Box<dyn Fn(&mut Value)>;

fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value
        .get(name)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {name}"))
}

fn cargo_metadata(repository: &Path) -> Value {
    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(repository)
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("parse cargo metadata")
}

fn cargo_lock_checksums(repository: &Path) -> BTreeMap<Key, String> {
    let contents = fs::read_to_string(repository.join("Cargo.lock")).expect("read Cargo.lock");
    let mut checksums = BTreeMap::new();
    let mut name = None;
    let mut version = None;
    let mut source = None;
    let mut checksum = None;
    let mut in_package = false;
    let record = |name: &mut Option<String>,
                  version: &mut Option<String>,
                  source: &mut Option<String>,
                  checksum: &mut Option<String>,
                  checksums: &mut BTreeMap<Key, String>| {
        if source
            .as_deref()
            .is_some_and(|value| value.starts_with("registry+"))
        {
            let key = Key {
                name: name.take().expect("registry lock package name"),
                version: version.take().expect("registry lock package version"),
            };
            assert!(
                checksums
                    .insert(key, checksum.take().expect("registry lock checksum"))
                    .is_none(),
                "duplicate registry lock package"
            );
        }
        *name = None;
        *version = None;
        *source = None;
        *checksum = None;
    };
    for line in contents.lines().map(str::trim) {
        if line == "[[package]]" {
            if in_package {
                record(
                    &mut name,
                    &mut version,
                    &mut source,
                    &mut checksum,
                    &mut checksums,
                );
            }
            in_package = true;
            continue;
        }
        if !in_package {
            continue;
        }
        for (key, slot) in [
            ("name", &mut name),
            ("version", &mut version),
            ("source", &mut source),
            ("checksum", &mut checksum),
        ] {
            if let Some(value) = line.strip_prefix(&format!("{key} = ")) {
                *slot = Some(serde_json::from_str(value).expect("Cargo.lock string"));
                break;
            }
        }
    }
    if in_package {
        record(
            &mut name,
            &mut version,
            &mut source,
            &mut checksum,
            &mut checksums,
        );
    }
    checksums
}

fn kinds(dependency: &Value) -> (bool, bool) {
    let mut normal = false;
    let mut build = false;
    for kind in dependency["dep_kinds"].as_array().expect("dep_kinds") {
        match kind.get("kind").and_then(Value::as_str) {
            None | Some("normal") => normal = true,
            Some("build") => build = true,
            Some("dev") => {}
            other => panic!("unexpected dependency kind {other:?}"),
        }
    }
    (normal, build)
}

fn package_ref(package: &Package, raw_root: &str) -> String {
    match &package.source {
        Some(source) => format!("{source}#{}@{}", package.key.name, package.key.version),
        None => format!(
            "path+file://{raw_root}/crates/{}#{}",
            package.key.name, package.key.version
        ),
    }
}

fn license_value(license: &str) -> Value {
    if license.contains('/') {
        json!({"license": {"name": license}})
    } else {
        json!({"expression": license})
    }
}

fn raw_document(repository: &Path, raw_root: &str) -> Value {
    let metadata = cargo_metadata(repository);
    let checksums = cargo_lock_checksums(repository);
    let mut packages = HashMap::new();
    let mut root_id = None;
    for package in metadata["packages"].as_array().expect("packages") {
        let id = field(package, "id").to_string();
        let key = Key {
            name: field(package, "name").to_string(),
            version: field(package, "version").to_string(),
        };
        let source = package
            .get("source")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let checksum = source
            .as_deref()
            .filter(|value| value.starts_with("registry+"))
            .map(|_| {
                checksums
                    .get(&key)
                    .expect("locked registry checksum")
                    .clone()
            });
        let parsed = Package {
            key,
            source,
            checksum,
            license: field(package, "license").to_string(),
            description: package
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned),
            repository: package
                .get("repository")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        if parsed.key.name == "luad-cli" && parsed.source.is_none() {
            assert!(root_id.replace(id.clone()).is_none());
        }
        packages.insert(id, parsed);
    }
    let root_id = root_id.expect("luad-cli root");
    let root = packages.get(&root_id).expect("root package");

    let mut nodes = HashMap::new();
    for node in metadata["resolve"]["nodes"]
        .as_array()
        .expect("resolve nodes")
    {
        nodes.insert(field(node, "id").to_string(), node);
    }
    let mut required = HashMap::from([(root_id.clone(), true)]);
    let mut queue = VecDeque::from([root_id.clone()]);
    while let Some(parent_id) = queue.pop_front() {
        let parent_required = required[&parent_id];
        for dependency in nodes[&parent_id]["deps"].as_array().expect("deps") {
            let child = field(dependency, "pkg").to_string();
            let (normal, build) = kinds(dependency);
            if !normal && !build {
                continue;
            }
            let child_required = parent_required && normal;
            let update = match required.get(&child) {
                None => true,
                Some(false) if child_required => true,
                _ => false,
            };
            if update {
                required.insert(child.clone(), child_required);
                queue.push_back(child);
            }
        }
    }

    let refs: HashMap<_, _> = required
        .keys()
        .map(|id| {
            let package = &packages[id];
            (id.clone(), package_ref(package, raw_root))
        })
        .collect();
    let mut components = Vec::new();
    for (id, is_required) in &required {
        if id == &root_id {
            continue;
        }
        let package = &packages[id];
        let mut component = json!({
            "type": "library",
            "bom-ref": refs[id],
            "name": package.key.name,
            "version": package.key.version,
            "scope": if *is_required { "required" } else { "excluded" },
            "licenses": [license_value(&package.license)],
        });
        if package
            .source
            .as_deref()
            .is_some_and(|source| source.starts_with("registry+"))
        {
            component["hashes"] = json!([{
                "alg": "SHA-256",
                "content": package.checksum.as_deref().expect("registry checksum"),
            }]);
            component["purl"] = json!(format!(
                "pkg:cargo/{}@{}",
                package.key.name, package.key.version
            ));
        }
        components.push(component);
    }

    let mut dependencies = Vec::new();
    for id in required.keys() {
        let mut children = BTreeSet::new();
        for dependency in nodes[id]["deps"].as_array().expect("deps") {
            let child = field(dependency, "pkg");
            let (normal, build) = kinds(dependency);
            if (normal || build) && required.contains_key(child) {
                children.insert(refs[child].clone());
            }
        }
        dependencies.push(json!({
            "ref": refs[id],
            "dependsOn": children,
        }));
    }

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": "1970-01-01T00:00:00.000000000Z",
            "tools": [{
                "vendor": "CycloneDX",
                "name": "cargo-cyclonedx",
                "version": "0.5.9",
            }],
            "component": {
                "type": "application",
                "bom-ref": refs[&root_id],
                "name": "luad",
                "version": root.key.version,
                "description": root.description,
                "scope": "required",
                "licenses": [license_value(&root.license)],
                "externalReferences": [{
                    "type": "vcs",
                    "url": root.repository,
                }],
            },
            "properties": [{
                "name": "cdx:rustc:sbom:target:all_targets",
                "value": "true",
            }],
        },
        "components": components,
        "dependencies": dependencies,
    })
}

fn write_fake_generator(temp: &Path, raw: &Value, version: &str) -> PathBuf {
    fs::create_dir_all(temp).expect("create fake generator directory");
    let raw_path = temp.join("raw.cdx.json");
    fs::write(
        &raw_path,
        serde_json::to_vec_pretty(raw).expect("serialize raw SBOM"),
    )
    .expect("write raw SBOM");
    let script = temp.join("cargo-cyclonedx");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nset -eu\nif [ \"${{1:-}}\" = cyclonedx ] && [ \"${{2:-}}\" = --version ]; then\n  printf '%s\\n' '{}'\n  exit 0\nfi\ncp '{}' crates/luad-cli/luad_bin.cdx.json\n",
            version,
            raw_path.display()
        ),
    )
    .expect("write fake cargo-cyclonedx");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
            .expect("make fake generator executable");
    }
    script
}

fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialize mutation");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("write mutation");
}

fn remove_component_and_edges(value: &mut Value) {
    let components = value["components"].as_array_mut().expect("components");
    let removed = components.pop().expect("component to remove");
    let removed_ref = field(&removed, "bom-ref").to_string();
    value["dependencies"]
        .as_array_mut()
        .expect("dependencies")
        .retain(|dependency| field(dependency, "ref") != removed_ref);
    for dependency in value["dependencies"].as_array_mut().expect("dependencies") {
        if let Some(children) = dependency["dependsOn"].as_array_mut() {
            children.retain(|child| child.as_str() != Some(&removed_ref));
        }
    }
}

#[test]
fn test_release_sbom_deterministic_complete_and_non_promoting() {
    let repository = find_workspace_root();
    let temp = tempfile::tempdir().expect("tempdir");
    let raw = raw_document(&repository, "/first/checkout");
    let generator = write_fake_generator(temp.path(), &raw, "cargo-cyclonedx-cyclonedx 0.5.9");

    let first_dir = temp.path().join("first");
    let first =
        generate_release_sbom(&repository, &generator, &first_dir).expect("generate first SBOM");
    assert_eq!(first.sbom, "luad-0.1.0.cdx.json");
    assert_eq!(first.generator, "cargo-cyclonedx 0.5.9");
    assert!(first.component_count > 0);

    let second_raw = raw_document(&repository, "/unrelated/second/checkout");
    let second_generator = write_fake_generator(
        &temp.path().join("second-tool"),
        &second_raw,
        "cargo-cyclonedx-cyclonedx 0.5.9",
    );
    let second_dir = temp.path().join("second");
    let second = generate_release_sbom(&repository, &second_generator, &second_dir)
        .expect("generate second SBOM");
    assert_eq!(first, second);
    assert_eq!(
        fs::read(first_dir.join(&first.sbom)).unwrap(),
        fs::read(second_dir.join(&second.sbom)).unwrap(),
        "checkout paths must not affect canonical SBOM bytes"
    );

    let verified =
        verify_release_sbom(&repository, &first_dir.join(&first.sbom)).expect("verify SBOM");
    assert_eq!(verified.component_count, first.component_count);
    assert_eq!(verified.source_revision, first.source_revision);
    assert!(get_canonical_capabilities(&first.version)
        .supported_dialects
        .is_empty());

    let text = fs::read_to_string(first_dir.join(&first.sbom)).expect("read SBOM text");
    assert!(!text.contains("path+file://"));
    assert!(!text.contains("/first/checkout"));
    assert!(!text.contains("candidate"));
    assert!(!text.contains("release-manifest"));
    assert!(!text.contains("evidence-index"));
}

#[test]
fn test_release_sbom_mutations_and_bad_tools_are_rejected() {
    let repository = find_workspace_root();
    let temp = tempfile::tempdir().expect("tempdir");
    let raw = raw_document(&repository, "/raw/checkout");
    let generator = write_fake_generator(temp.path(), &raw, "cargo-cyclonedx-cyclonedx 0.5.9");
    let good_dir = temp.path().join("good");
    let result =
        generate_release_sbom(&repository, &generator, &good_dir).expect("generate good SBOM");
    let good_path = good_dir.join(&result.sbom);
    let good: Value = serde_json::from_slice(&fs::read(&good_path).unwrap()).unwrap();

    let cases: BTreeMap<&str, SbomMutation> = BTreeMap::from([
        (
            "missing-component",
            Box::new(remove_component_and_edges) as SbomMutation,
        ),
        (
            "root-version",
            Box::new(|value| value["metadata"]["component"]["version"] = json!("9.9.9")),
        ),
        (
            "root-license",
            Box::new(|value| {
                value["metadata"]["component"]["licenses"] = json!([{"expression": "MIT"}])
            }),
        ),
        (
            "source-revision",
            Box::new(|value| {
                let property = value["metadata"]["properties"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|property| property["name"] == "luad:source_revision")
                    .unwrap();
                property["value"] = json!("0".repeat(40));
            }),
        ),
        (
            "registry-checksum",
            Box::new(|value| {
                let component = value["components"]
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|component| component.get("hashes").is_some())
                    .unwrap();
                component["hashes"][0]["content"] = json!("0".repeat(64));
            }),
        ),
        (
            "development-only",
            Box::new(|value| {
                value["components"].as_array_mut().unwrap().push(json!({
                    "type": "library",
                    "bom-ref": "registry+https://github.com/rust-lang/crates.io-index#proptest@1.11.0",
                    "name": "proptest",
                    "version": "1.11.0",
                    "scope": "required",
                    "licenses": [{"expression": "MIT OR Apache-2.0"}],
                }));
            }),
        ),
        (
            "unresolved-edge",
            Box::new(|value| {
                value["dependencies"][0]["dependsOn"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!("urn:missing"));
            }),
        ),
        (
            "absolute-path",
            Box::new(|value| value["metadata"]["component"]["bom-ref"] = json!("/tmp/leak")),
        ),
        (
            "timestamp",
            Box::new(|value| value["metadata"]["timestamp"] = json!("2026-08-27T00:00:00Z")),
        ),
        (
            "serial-number",
            Box::new(|value| value["serialNumber"] = json!("urn:uuid:random")),
        ),
        (
            "missing-serial-number",
            Box::new(|value| {
                value.as_object_mut().unwrap().remove("serialNumber");
            }),
        ),
    ]);

    for (name, mutate) in cases {
        let case_dir = temp.path().join(name);
        fs::create_dir(&case_dir).unwrap();
        let case_path = case_dir.join(&result.sbom);
        let mut value = good.clone();
        mutate(&mut value);
        write_json(&case_path, &value);
        let error = verify_release_sbom(&repository, &case_path)
            .expect_err("SBOM corruption must be rejected");
        assert!(!error.is_empty(), "{name} must produce an actionable error");
    }

    let nonempty = temp.path().join("nonempty");
    fs::create_dir(&nonempty).unwrap();
    fs::write(nonempty.join("keep"), "keep\n").unwrap();
    assert!(generate_release_sbom(&repository, &generator, &nonempty)
        .expect_err("nonempty output must fail")
        .contains("must be empty"));
    assert_eq!(fs::read_to_string(nonempty.join("keep")).unwrap(), "keep\n");

    let bad_tool_dir = temp.path().join("bad-tool");
    fs::create_dir(&bad_tool_dir).unwrap();
    let bad_tool = write_fake_generator(&bad_tool_dir, &raw, "cargo-cyclonedx-cyclonedx 9.9.9");
    assert!(
        generate_release_sbom(&repository, &bad_tool, &temp.path().join("bad-tool-output"))
            .expect_err("wrong generator version must fail")
            .contains("version mismatch")
    );
}

#[test]
fn test_release_sbom_script_is_maintained_and_executable() {
    let script = find_workspace_root().join("scripts/generate-release-sbom.sh");
    assert!(script.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_ne!(
            fs::metadata(script).unwrap().permissions().mode() & 0o111,
            0
        );
    }
}
