//! Deterministic generation and independent verification of the release SBOM.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::Path;
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::candidate::sha256_digest;
use crate::release_package::{cargo_metadata, clean_source_revision, workspace_version};

const CARGO_CYCLONEDX_VERSION_OUTPUT: &str = "cargo-cyclonedx-cyclonedx 0.5.9";
const CARGO_CYCLONEDX_DOCUMENT_VERSION: &str = "0.5.9";
const CYCLONEDX_SPEC_VERSION: &str = "1.5";
const CANONICAL_TIMESTAMP: &str = "1970-01-01T00:00:00.000000000Z";
const MAX_SBOM_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMPONENTS: usize = 4096;
const SOURCE_REVISION_PROPERTY: &str = "luad:source_revision";
const CARGO_LOCK_PROPERTY: &str = "luad:cargo_lock_sha256";
const ALL_TARGETS_PROPERTY: &str = "cdx:rustc:sbom:target:all_targets";

/// Deterministic result printed by the maintained SBOM command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseSbomResult {
    pub sbom: String,
    pub version: String,
    pub source_revision: String,
    pub cargo_lock_sha256: String,
    pub generator: String,
    pub component_count: usize,
}

/// Verified identity and size of a canonical release SBOM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedReleaseSbom {
    pub version: String,
    pub source_revision: String,
    pub cargo_lock_sha256: String,
    pub component_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PackageKey {
    name: String,
    version: String,
}

#[derive(Debug, Clone)]
struct CargoPackage {
    key: PackageKey,
    source: Option<String>,
    checksum: Option<String>,
    license: String,
    description: Option<String>,
    repository: Option<String>,
}

#[derive(Debug, Default)]
struct LockPackage {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComponentScope {
    Excluded,
    Required,
}

impl ComponentScope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Excluded => "excluded",
            Self::Required => "required",
        }
    }
}

#[derive(Debug)]
struct ExpectedGraph {
    root: CargoPackage,
    packages: BTreeMap<PackageKey, CargoPackage>,
    scopes: BTreeMap<PackageKey, ComponentScope>,
    edges: BTreeMap<PackageKey, BTreeSet<PackageKey>>,
}

fn required_str<'a>(value: &'a Value, key: &str, context: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing string field '{key}'"))
}

fn optional_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn metadata_with_locked_graph(repository: &Path) -> Result<Value, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("execute locked cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "locked cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.len() > MAX_SBOM_BYTES * 2 {
        return Err(format!(
            "locked cargo metadata exceeds {} bytes",
            MAX_SBOM_BYTES * 2
        ));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("parse locked cargo metadata: {error}"))
}

fn lock_string(line: &str, key: &str) -> Result<Option<String>, String> {
    let Some(value) = line.strip_prefix(&format!("{key} = ")) else {
        return Ok(None);
    };
    serde_json::from_str(value)
        .map(Some)
        .map_err(|error| format!("parse Cargo.lock {key}: {error}"))
}

fn record_lock_checksum(
    package: &mut LockPackage,
    checksums: &mut BTreeMap<PackageKey, String>,
) -> Result<(), String> {
    if !package
        .source
        .as_deref()
        .is_some_and(|source| source.starts_with("registry+"))
    {
        return Ok(());
    }
    let key = PackageKey {
        name: package
            .name
            .take()
            .ok_or("registry Cargo.lock package is missing name")?,
        version: package
            .version
            .take()
            .ok_or("registry Cargo.lock package is missing version")?,
    };
    let checksum = package
        .checksum
        .take()
        .ok_or_else(|| format!("registry Cargo.lock package {} has no checksum", key.name))?;
    if checksums.insert(key.clone(), checksum).is_some() {
        return Err(format!(
            "Cargo.lock contains duplicate registry package {} {}",
            key.name, key.version
        ));
    }
    Ok(())
}

fn locked_registry_checksums(repository: &Path) -> Result<BTreeMap<PackageKey, String>, String> {
    let bytes = fs::read(repository.join("Cargo.lock"))
        .map_err(|error| format!("read Cargo.lock: {error}"))?;
    if bytes.len() > MAX_SBOM_BYTES {
        return Err(format!("Cargo.lock exceeds {MAX_SBOM_BYTES} bytes"));
    }
    let contents = std::str::from_utf8(&bytes)
        .map_err(|error| format!("Cargo.lock is not valid UTF-8: {error}"))?;
    let mut checksums = BTreeMap::new();
    let mut package = None;
    for line in contents.lines().map(str::trim) {
        if line == "[[package]]" {
            if let Some(mut previous) = package.take() {
                record_lock_checksum(&mut previous, &mut checksums)?;
            }
            package = Some(LockPackage::default());
            continue;
        }
        let Some(current) = package.as_mut() else {
            continue;
        };
        if let Some(value) = lock_string(line, "name")? {
            current.name = Some(value);
        } else if let Some(value) = lock_string(line, "version")? {
            current.version = Some(value);
        } else if let Some(value) = lock_string(line, "source")? {
            current.source = Some(value);
        } else if let Some(value) = lock_string(line, "checksum")? {
            current.checksum = Some(value);
        }
    }
    if let Some(mut final_package) = package {
        record_lock_checksum(&mut final_package, &mut checksums)?;
    }
    Ok(checksums)
}

fn dependency_kinds(dep: &Value) -> Result<(bool, bool), String> {
    let kinds = dep
        .get("dep_kinds")
        .and_then(Value::as_array)
        .ok_or("cargo metadata dependency is missing dep_kinds")?;
    let mut normal = false;
    let mut build = false;
    for kind in kinds {
        match kind.get("kind").and_then(Value::as_str) {
            None | Some("normal") => normal = true,
            Some("build") => build = true,
            Some("dev") => {}
            Some(other) => {
                return Err(format!("unknown Cargo dependency kind '{other}'"));
            }
        }
    }
    Ok((normal, build))
}

fn expected_graph(repository: &Path) -> Result<ExpectedGraph, String> {
    let metadata = metadata_with_locked_graph(repository)?;
    let lock_checksums = locked_registry_checksums(repository)?;
    let packages = metadata
        .get("packages")
        .and_then(Value::as_array)
        .ok_or("locked cargo metadata is missing packages")?;

    let mut by_id = HashMap::new();
    let mut root_candidates = Vec::new();
    for package in packages {
        let id = required_str(package, "id", "Cargo package")?.to_string();
        let name = required_str(package, "name", "Cargo package")?.to_string();
        let version = required_str(package, "version", "Cargo package")?.to_string();
        let license =
            required_str(package, "license", &format!("Cargo package {name}"))?.to_string();
        let key = PackageKey {
            name: name.clone(),
            version,
        };
        let source = optional_str(package, "source");
        let checksum = if source
            .as_deref()
            .is_some_and(|value| value.starts_with("registry+"))
        {
            Some(
                lock_checksums
                    .get(&key)
                    .ok_or_else(|| {
                        format!(
                            "Cargo.lock has no checksum for registry package {} {}",
                            key.name, key.version
                        )
                    })?
                    .clone(),
            )
        } else {
            None
        };
        let parsed = CargoPackage {
            key,
            source,
            checksum,
            license,
            description: optional_str(package, "description"),
            repository: optional_str(package, "repository"),
        };
        if name == "luad-cli" && parsed.source.is_none() {
            root_candidates.push(id.clone());
        }
        if by_id.insert(id.clone(), parsed).is_some() {
            return Err(format!("duplicate Cargo package id '{id}'"));
        }
    }
    if root_candidates.len() != 1 {
        return Err(format!(
            "expected exactly one local luad-cli package, got {}",
            root_candidates.len()
        ));
    }
    let root_id = root_candidates.remove(0);
    let root = by_id
        .get(&root_id)
        .ok_or("luad-cli package disappeared from Cargo metadata")?
        .clone();

    let nodes = metadata
        .pointer("/resolve/nodes")
        .and_then(Value::as_array)
        .ok_or("locked cargo metadata is missing resolve nodes")?;
    let mut nodes_by_id = HashMap::new();
    for node in nodes {
        let id = required_str(node, "id", "Cargo resolve node")?.to_string();
        if nodes_by_id.insert(id.clone(), node.clone()).is_some() {
            return Err(format!("duplicate Cargo resolve node '{id}'"));
        }
    }

    let mut scope_by_id = HashMap::new();
    scope_by_id.insert(root_id.clone(), ComponentScope::Required);
    let mut queue = VecDeque::from([root_id.clone()]);
    while let Some(parent_id) = queue.pop_front() {
        let parent_scope = *scope_by_id
            .get(&parent_id)
            .ok_or("reachable Cargo node is missing its scope")?;
        let node = nodes_by_id
            .get(&parent_id)
            .ok_or_else(|| format!("reachable Cargo package has no resolve node: {parent_id}"))?;
        let deps = node
            .get("deps")
            .and_then(Value::as_array)
            .ok_or("Cargo resolve node is missing deps")?;
        for dep in deps {
            let child_id = required_str(dep, "pkg", "Cargo dependency")?.to_string();
            let (normal, build) = dependency_kinds(dep)?;
            if !normal && !build {
                continue;
            }
            let candidate = if parent_scope == ComponentScope::Required && normal {
                ComponentScope::Required
            } else {
                ComponentScope::Excluded
            };
            let should_update = match scope_by_id.get(&child_id) {
                None => true,
                Some(ComponentScope::Excluded) if candidate == ComponentScope::Required => true,
                _ => false,
            };
            if should_update {
                scope_by_id.insert(child_id.clone(), candidate);
                queue.push_back(child_id);
            }
        }
    }

    let mut id_to_key = HashMap::new();
    let mut expected_packages = BTreeMap::new();
    let mut expected_scopes = BTreeMap::new();
    for (id, scope) in &scope_by_id {
        let package = by_id
            .get(id)
            .ok_or_else(|| format!("reachable package is missing metadata: {id}"))?;
        id_to_key.insert(id.clone(), package.key.clone());
        if id == &root_id {
            continue;
        }
        if expected_packages
            .insert(package.key.clone(), package.clone())
            .is_some()
        {
            return Err(format!(
                "reachable Cargo graph has ambiguous package {} {}",
                package.key.name, package.key.version
            ));
        }
        expected_scopes.insert(package.key.clone(), *scope);
    }

    let mut edges = BTreeMap::new();
    for parent_id in scope_by_id.keys() {
        let parent_key = id_to_key
            .get(parent_id)
            .ok_or("reachable Cargo package is missing a package key")?
            .clone();
        let node = nodes_by_id
            .get(parent_id)
            .ok_or_else(|| format!("reachable Cargo package has no resolve node: {parent_id}"))?;
        let mut children = BTreeSet::new();
        for dep in node
            .get("deps")
            .and_then(Value::as_array)
            .ok_or("Cargo resolve node is missing deps")?
        {
            let child_id = required_str(dep, "pkg", "Cargo dependency")?;
            let (normal, build) = dependency_kinds(dep)?;
            if (normal || build) && scope_by_id.contains_key(child_id) {
                children.insert(
                    id_to_key
                        .get(child_id)
                        .ok_or("reachable Cargo dependency is missing a package key")?
                        .clone(),
                );
            }
        }
        edges.insert(parent_key, children);
    }

    Ok(ExpectedGraph {
        root,
        packages: expected_packages,
        scopes: expected_scopes,
        edges,
    })
}

fn cargo_lock_sha256(repository: &Path) -> Result<String, String> {
    let path = repository.join("Cargo.lock");
    let metadata =
        fs::metadata(&path).map_err(|error| format!("read Cargo.lock metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_SBOM_BYTES as u64 {
        return Err(
            "Cargo.lock is missing, not a file, or exceeds the SBOM input bound".to_string(),
        );
    }
    fs::read(&path)
        .map(|bytes| sha256_digest(&bytes))
        .map_err(|error| format!("read Cargo.lock: {error}"))
}

fn stable_root_ref(version: &str) -> String {
    format!("urn:luad:application:luad@{version}")
}

fn stable_workspace_ref(key: &PackageKey) -> String {
    format!("urn:luad:workspace:{}@{}", key.name, key.version)
}

fn expected_component_ref(package: &CargoPackage) -> String {
    match &package.source {
        None => stable_workspace_ref(&package.key),
        Some(source) => format!("{source}#{}@{}", package.key.name, package.key.version),
    }
}

fn replace_refs(value: &mut Value, replacements: &BTreeMap<String, String>) {
    match value {
        Value::Array(values) => {
            for value in values {
                replace_refs(value, replacements);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                replace_refs(value, replacements);
            }
        }
        Value::String(text) => {
            if let Some(replacement) = replacements.get(text) {
                *text = replacement.clone();
            }
        }
        _ => {}
    }
}

fn sort_array_by_field(value: &mut Value, pointer: &str, field: &str) -> Result<(), String> {
    let array = value
        .pointer_mut(pointer)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("SBOM is missing array at {pointer}"))?;
    array.sort_by(|left, right| {
        left.get(field)
            .and_then(Value::as_str)
            .cmp(&right.get(field).and_then(Value::as_str))
    });
    Ok(())
}

fn sort_document(value: &mut Value) -> Result<(), String> {
    sort_array_by_field(value, "/components", "bom-ref")?;
    sort_array_by_field(value, "/dependencies", "ref")?;
    sort_array_by_field(value, "/metadata/properties", "name")?;
    if let Some(dependencies) = value.get_mut("dependencies").and_then(Value::as_array_mut) {
        for dependency in dependencies {
            if let Some(depends_on) = dependency
                .get_mut("dependsOn")
                .and_then(Value::as_array_mut)
            {
                depends_on.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
            }
        }
    }
    sort_object_keys(value);
    Ok(())
}

fn sort_object_keys(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                sort_object_keys(value);
            }
        }
        Value::Object(values) => {
            let old = std::mem::take(values);
            let mut entries: Vec<_> = old.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, mut value) in entries {
                sort_object_keys(&mut value);
                sorted.insert(key, value);
            }
            *values = sorted;
        }
        _ => {}
    }
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("serialize SBOM: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_SBOM_BYTES {
        return Err(format!("canonical SBOM exceeds {MAX_SBOM_BYTES} bytes"));
    }
    Ok(bytes)
}

fn contains_host_path(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_host_path),
        Value::Object(values) => values.values().any(contains_host_path),
        Value::String(text) => {
            text.starts_with('/')
                || text.contains("path+file://")
                || text.contains("file:///")
                || text.contains("/target/")
        }
        _ => false,
    }
}

fn component_license_matches(component: &Value, expected: &str) -> bool {
    component
        .get("licenses")
        .and_then(Value::as_array)
        .is_some_and(|licenses| {
            licenses.iter().any(|license| {
                license.get("expression").and_then(Value::as_str) == Some(expected)
                    || license.pointer("/license/name").and_then(Value::as_str) == Some(expected)
                    || license.pointer("/license/id").and_then(Value::as_str) == Some(expected)
            })
        })
}

fn verify_properties(
    value: &Value,
    source_revision: &str,
    lock_sha256: &str,
) -> Result<(), String> {
    let properties = value
        .pointer("/metadata/properties")
        .and_then(Value::as_array)
        .ok_or("SBOM metadata is missing properties")?;
    let mut actual = BTreeMap::new();
    for property in properties {
        let name = required_str(property, "name", "SBOM property")?.to_string();
        let property_value = required_str(property, "value", "SBOM property")?.to_string();
        if actual.insert(name.clone(), property_value).is_some() {
            return Err(format!("duplicate SBOM property '{name}'"));
        }
    }
    let expected = BTreeMap::from([
        (ALL_TARGETS_PROPERTY.to_string(), "true".to_string()),
        (CARGO_LOCK_PROPERTY.to_string(), lock_sha256.to_string()),
        (
            SOURCE_REVISION_PROPERTY.to_string(),
            source_revision.to_string(),
        ),
    ]);
    if actual != expected {
        return Err(
            "SBOM metadata properties do not match the all-target locked source identity"
                .to_string(),
        );
    }
    Ok(())
}

fn verify_document(
    value: &Value,
    expected: &ExpectedGraph,
    source_revision: &str,
    lock_sha256: &str,
) -> Result<VerifiedReleaseSbom, String> {
    if value.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX")
        || value.get("specVersion").and_then(Value::as_str) != Some(CYCLONEDX_SPEC_VERSION)
        || value.get("version").and_then(Value::as_u64) != Some(1)
    {
        return Err("SBOM must be CycloneDX 1.5 document version 1".to_string());
    }
    if value.get("serialNumber").is_some() {
        return Err("SBOM must not contain a random serialNumber".to_string());
    }
    if value.pointer("/metadata/timestamp").and_then(Value::as_str) != Some(CANONICAL_TIMESTAMP) {
        return Err("SBOM timestamp is not the canonical SOURCE_DATE_EPOCH=0 value".to_string());
    }
    if contains_host_path(value) {
        return Err("SBOM contains an absolute checkout, target, or temporary path".to_string());
    }

    let tools = value
        .pointer("/metadata/tools")
        .and_then(Value::as_array)
        .ok_or("SBOM metadata is missing generator tools")?;
    if tools.len() != 1
        || tools[0].get("name").and_then(Value::as_str) != Some("cargo-cyclonedx")
        || tools[0].get("version").and_then(Value::as_str) != Some(CARGO_CYCLONEDX_DOCUMENT_VERSION)
    {
        return Err("SBOM generator identity is not cargo-cyclonedx 0.5.9".to_string());
    }

    let root = value
        .pointer("/metadata/component")
        .ok_or("SBOM metadata is missing its root component")?;
    let root_ref = required_str(root, "bom-ref", "SBOM root")?;
    if root_ref != stable_root_ref(&expected.root.key.version)
        || root.get("type").and_then(Value::as_str) != Some("application")
        || root.get("name").and_then(Value::as_str) != Some("luad")
        || root.get("version").and_then(Value::as_str) != Some(expected.root.key.version.as_str())
        || root.get("description").and_then(Value::as_str) != expected.root.description.as_deref()
        || !component_license_matches(root, &expected.root.license)
    {
        return Err("SBOM root application metadata does not match luad-cli".to_string());
    }
    let repository = expected
        .root
        .repository
        .as_deref()
        .ok_or("luad-cli Cargo metadata is missing repository")?;
    let references = root
        .get("externalReferences")
        .and_then(Value::as_array)
        .ok_or("SBOM root is missing external references")?;
    if !references
        .iter()
        .any(|reference| reference.get("url").and_then(Value::as_str) == Some(repository))
    {
        return Err("SBOM root repository URL does not match Cargo metadata".to_string());
    }
    verify_properties(value, source_revision, lock_sha256)?;

    let components = value
        .get("components")
        .and_then(Value::as_array)
        .ok_or("SBOM is missing components")?;
    if components.len() > MAX_COMPONENTS {
        return Err(format!("SBOM exceeds the {MAX_COMPONENTS}-component bound"));
    }
    let mut ref_to_key = BTreeMap::new();
    ref_to_key.insert(root_ref.to_string(), expected.root.key.clone());
    let mut actual_keys = BTreeSet::new();
    for component in components {
        let name = required_str(component, "name", "SBOM component")?.to_string();
        let version = required_str(component, "version", "SBOM component")?.to_string();
        let key = PackageKey { name, version };
        let expected_package = expected.packages.get(&key).ok_or_else(|| {
            format!(
                "SBOM contains unexpected component {} {}",
                key.name, key.version
            )
        })?;
        if !actual_keys.insert(key.clone()) {
            return Err(format!(
                "SBOM contains duplicate component {} {}",
                key.name, key.version
            ));
        }
        let component_ref = required_str(component, "bom-ref", "SBOM component")?;
        if component_ref != expected_component_ref(expected_package) {
            return Err(format!(
                "SBOM component reference mismatch for {} {}",
                key.name, key.version
            ));
        }
        if ref_to_key
            .insert(component_ref.to_string(), key.clone())
            .is_some()
        {
            return Err(format!("duplicate SBOM reference '{component_ref}'"));
        }
        let expected_scope = expected
            .scopes
            .get(&key)
            .ok_or("expected component is missing scope")?
            .as_str();
        if component.get("scope").and_then(Value::as_str) != Some(expected_scope) {
            return Err(format!(
                "SBOM scope mismatch for {} {}: expected {expected_scope}",
                key.name, key.version
            ));
        }
        if !component_license_matches(component, &expected_package.license) {
            return Err(format!(
                "SBOM license mismatch for {} {}",
                key.name, key.version
            ));
        }
        if let Some(source) = &expected_package.source {
            if source.starts_with("registry+") {
                let checksum = expected_package.checksum.as_deref().ok_or_else(|| {
                    format!("registry package {} has no Cargo checksum", key.name)
                })?;
                let hashes = component
                    .get("hashes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| format!("registry component {} has no hashes", key.name))?;
                if !hashes.iter().any(|hash| {
                    hash.get("alg").and_then(Value::as_str) == Some("SHA-256")
                        && hash.get("content").and_then(Value::as_str) == Some(checksum)
                }) {
                    return Err(format!(
                        "SBOM Cargo.lock checksum mismatch for {} {}",
                        key.name, key.version
                    ));
                }
                let expected_purl = format!("pkg:cargo/{}@{}", key.name, key.version);
                if component.get("purl").and_then(Value::as_str) != Some(&expected_purl) {
                    return Err(format!(
                        "SBOM package URL mismatch for {} {}",
                        key.name, key.version
                    ));
                }
            }
        }
    }
    let expected_keys: BTreeSet<_> = expected.packages.keys().cloned().collect();
    if actual_keys != expected_keys {
        let missing: Vec<_> = expected_keys.difference(&actual_keys).collect();
        return Err(format!("SBOM omits locked Cargo components: {missing:?}"));
    }

    let dependencies = value
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or("SBOM is missing dependencies")?;
    if dependencies.len() != ref_to_key.len() || dependencies.len() > MAX_COMPONENTS + 1 {
        return Err(
            "SBOM dependency ledger does not cover every component exactly once".to_string(),
        );
    }
    let mut actual_edges = BTreeMap::new();
    for dependency in dependencies {
        let parent_ref = required_str(dependency, "ref", "SBOM dependency")?;
        let parent = ref_to_key
            .get(parent_ref)
            .ok_or_else(|| format!("SBOM dependency has unknown ref '{parent_ref}'"))?
            .clone();
        let mut children = BTreeSet::new();
        if let Some(depends_on) = dependency.get("dependsOn") {
            let depends_on = depends_on
                .as_array()
                .ok_or("SBOM dependsOn must be an array")?;
            if depends_on.len() > MAX_COMPONENTS {
                return Err("SBOM dependency edge list exceeds the component bound".to_string());
            }
            for child_ref in depends_on {
                let child_ref = child_ref
                    .as_str()
                    .ok_or("SBOM dependency reference is not a string")?;
                let child = ref_to_key.get(child_ref).ok_or_else(|| {
                    format!("SBOM dependency points at unknown ref '{child_ref}'")
                })?;
                if !children.insert(child.clone()) {
                    return Err(format!("duplicate SBOM dependency edge to '{child_ref}'"));
                }
            }
        }
        if actual_edges.insert(parent.clone(), children).is_some() {
            return Err(format!(
                "SBOM has duplicate dependency record for {} {}",
                parent.name, parent.version
            ));
        }
    }
    if actual_edges != expected.edges {
        return Err("SBOM dependency edges do not match locked Cargo metadata".to_string());
    }

    let mut reached = BTreeSet::new();
    let mut queue = VecDeque::from([expected.root.key.clone()]);
    while let Some(parent) = queue.pop_front() {
        if !reached.insert(parent.clone()) {
            continue;
        }
        if let Some(children) = actual_edges.get(&parent) {
            queue.extend(children.iter().cloned());
        }
    }
    if reached.len() != expected.packages.len() + 1 {
        return Err("SBOM root does not reach every locked component".to_string());
    }

    Ok(VerifiedReleaseSbom {
        version: expected.root.key.version.clone(),
        source_revision: source_revision.to_string(),
        cargo_lock_sha256: lock_sha256.to_string(),
        component_count: components.len(),
    })
}

fn canonicalize_generated(
    repository: &Path,
    raw: &[u8],
    source_revision: &str,
    lock_sha256: &str,
) -> Result<(Vec<u8>, VerifiedReleaseSbom), String> {
    if raw.len() > MAX_SBOM_BYTES {
        return Err(format!("generated SBOM exceeds {MAX_SBOM_BYTES} bytes"));
    }
    let mut value: Value =
        serde_json::from_slice(raw).map_err(|error| format!("parse generated SBOM: {error}"))?;
    let expected = expected_graph(repository)?;

    let root = value
        .pointer("/metadata/component")
        .ok_or("generated SBOM is missing its root component")?;
    let old_root_ref = required_str(root, "bom-ref", "generated SBOM root")?.to_string();
    let mut replacements =
        BTreeMap::from([(old_root_ref, stable_root_ref(&expected.root.key.version))]);
    let components = value
        .get("components")
        .and_then(Value::as_array)
        .ok_or("generated SBOM is missing components")?;
    for component in components {
        let old_ref = required_str(component, "bom-ref", "generated SBOM component")?;
        if old_ref.starts_with("path+file://") {
            let key = PackageKey {
                name: required_str(component, "name", "generated SBOM component")?.to_string(),
                version: required_str(component, "version", "generated SBOM component")?
                    .to_string(),
            };
            replacements.insert(old_ref.to_string(), stable_workspace_ref(&key));
        }
    }
    replace_refs(&mut value, &replacements);

    let properties = value
        .pointer_mut("/metadata/properties")
        .and_then(Value::as_array_mut)
        .ok_or("generated SBOM metadata is missing properties")?;
    if properties.iter().any(|property| {
        property
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.starts_with("luad:"))
    }) {
        return Err("generated SBOM unexpectedly contains luad-owned properties".to_string());
    }
    properties.push(serde_json::json!({
        "name": CARGO_LOCK_PROPERTY,
        "value": lock_sha256,
    }));
    properties.push(serde_json::json!({
        "name": SOURCE_REVISION_PROPERTY,
        "value": source_revision,
    }));

    sort_document(&mut value)?;
    let verified = verify_document(&value, &expected, source_revision, lock_sha256)?;
    let bytes = canonical_bytes(&value)?;
    Ok((bytes, verified))
}

fn read_bounded_sbom(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("read SBOM metadata: {error}"))?;
    if !metadata.is_file() || metadata.len() > MAX_SBOM_BYTES as u64 {
        return Err(format!(
            "SBOM is missing, not a file, or exceeds {MAX_SBOM_BYTES} bytes"
        ));
    }
    fs::read(path).map_err(|error| format!("read SBOM: {error}"))
}

fn require_empty_output_directory(output_dir: &Path) -> Result<(), String> {
    if !output_dir.exists() {
        return Ok(());
    }
    if !output_dir.is_dir() {
        return Err(format!(
            "SBOM output path is not a directory: {output_dir:?}"
        ));
    }
    if fs::read_dir(output_dir)
        .map_err(|error| format!("read SBOM output directory: {error}"))?
        .next()
        .transpose()
        .map_err(|error| format!("inspect SBOM output directory: {error}"))?
        .is_some()
    {
        return Err(format!(
            "SBOM output directory must be empty: {output_dir:?}"
        ));
    }
    Ok(())
}

fn run_checked(command: &mut Command, label: &str) -> Result<(), String> {
    let output = command
        .output()
        .map_err(|error| format!("{label}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{label}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(format!(
            "{label} produced unexpected output: stdout='{}', stderr='{}'",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn generator_version(executable: &Path) -> Result<String, String> {
    let output = Command::new(executable)
        .args(["cyclonedx", "--version"])
        .output()
        .map_err(|error| format!("execute cargo-cyclonedx --version: {error}"))?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "cargo-cyclonedx version probe failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let version = String::from_utf8(output.stdout)
        .map_err(|error| format!("cargo-cyclonedx version UTF-8: {error}"))?
        .trim()
        .to_string();
    if version != CARGO_CYCLONEDX_VERSION_OUTPUT {
        return Err(format!(
            "cargo-cyclonedx version mismatch: expected '{CARGO_CYCLONEDX_VERSION_OUTPUT}', got '{version}'"
        ));
    }
    Ok(format!(
        "cargo-cyclonedx {CARGO_CYCLONEDX_DOCUMENT_VERSION}"
    ))
}

fn stage_clean_source(repository: &Path, revision: &str) -> Result<tempfile::TempDir, String> {
    let stage = tempfile::tempdir().map_err(|error| format!("create SBOM staging dir: {error}"))?;
    let source = stage.path().join("source");
    run_checked(
        Command::new("git")
            .args(["clone", "--quiet", "--no-hardlinks", "--no-checkout"])
            .arg(repository)
            .arg(&source),
        "clone clean SBOM source",
    )?;
    run_checked(
        Command::new("git")
            .args(["checkout", "--quiet", "--detach", revision])
            .current_dir(&source),
        "checkout SBOM source revision",
    )?;
    Ok(stage)
}

/// Verify one canonical SBOM against clean source and independent locked Cargo metadata.
pub fn verify_release_sbom(
    repository: &Path,
    sbom_path: &Path,
) -> Result<VerifiedReleaseSbom, String> {
    let source_revision = clean_source_revision(repository)?;
    let lock_sha256 = cargo_lock_sha256(repository)?;
    let metadata = cargo_metadata(repository)?;
    let version = workspace_version(&metadata)?;
    let expected_name = format!("luad-{version}.cdx.json");
    if sbom_path.file_name().and_then(|name| name.to_str()) != Some(&expected_name) {
        return Err(format!(
            "SBOM file name mismatch: expected '{expected_name}'"
        ));
    }
    let bytes = read_bounded_sbom(sbom_path)?;
    let mut value: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse SBOM: {error}"))?;
    let expected = expected_graph(repository)?;
    let verified = verify_document(&value, &expected, &source_revision, &lock_sha256)?;
    sort_document(&mut value)?;
    let canonical = canonical_bytes(&value)?;
    if bytes != canonical {
        return Err("SBOM is not in canonical deterministic JSON form".to_string());
    }
    Ok(verified)
}

/// Generate, canonicalize, and independently verify one non-promoting release SBOM.
pub fn generate_release_sbom(
    repository: &Path,
    cargo_cyclonedx: &Path,
    output_dir: &Path,
) -> Result<ReleaseSbomResult, String> {
    require_empty_output_directory(output_dir)?;
    let source_revision = clean_source_revision(repository)?;
    let lock_sha256 = cargo_lock_sha256(repository)?;
    let metadata = cargo_metadata(repository)?;
    let version = workspace_version(&metadata)?;
    let generator = generator_version(cargo_cyclonedx)?;

    let stage = stage_clean_source(repository, &source_revision)?;
    let source = stage.path().join("source");
    run_checked(
        Command::new(cargo_cyclonedx)
            .args([
                "cyclonedx",
                "--quiet",
                "--manifest-path",
                "Cargo.toml",
                "--format",
                "json",
                "--describe",
                "binaries",
                "--target",
                "all",
                "--all",
                "--license-strict",
                "--license-accept-named",
                "MIT/Apache-2.0",
                "--license-accept-named",
                "Apache-2.0 / MIT",
                "--spec-version",
                CYCLONEDX_SPEC_VERSION,
            ])
            .env("SOURCE_DATE_EPOCH", "0")
            .current_dir(&source),
        "generate cargo-cyclonedx SBOM",
    )?;
    let raw_path = source.join("crates/luad-cli/luad_bin.cdx.json");
    let raw = read_bounded_sbom(&raw_path)?;
    let (canonical, verified) =
        canonicalize_generated(repository, &raw, &source_revision, &lock_sha256)?;

    if clean_source_revision(repository)? != source_revision {
        return Err("release source revision changed during SBOM generation".to_string());
    }
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("create SBOM output directory: {error}"))?;
    let sbom_name = format!("luad-{version}.cdx.json");
    let sbom_path = output_dir.join(&sbom_name);
    if sbom_path.exists() {
        return Err(format!("refusing to overwrite release SBOM: {sbom_path:?}"));
    }
    fs::write(&sbom_path, canonical).map_err(|error| format!("write release SBOM: {error}"))?;
    let final_verified = verify_release_sbom(repository, &sbom_path)?;
    if verified != final_verified {
        return Err("written SBOM verification differs from canonicalization result".to_string());
    }

    Ok(ReleaseSbomResult {
        sbom: sbom_name,
        version,
        source_revision,
        cargo_lock_sha256: lock_sha256,
        generator,
        component_count: verified.component_count,
    })
}
