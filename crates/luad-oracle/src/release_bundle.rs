//! Bounded composition and verification of the non-promoting release bundle.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::candidate::sha256_digest;
use crate::release_package::cargo_metadata;
use crate::release_package::{clean_source_revision, workspace_version, InstallationTranscript};

const MAX_ARCHIVE_BYTES: usize = 160 * 1024 * 1024;
const MAX_SIDECAR_BYTES: usize = 4 * 1024 * 1024;
const MAX_SBOM_BYTES: usize = 8 * 1024 * 1024;
const MAX_PREREQUISITES_BYTES: usize = 64 * 1024;
const MAX_INDEX_BYTES: usize = 8 * 1024 * 1024;
const MAX_COMPONENTS: usize = 4096;
const MAX_LEDGER_MEMBERS: usize = 64;
const MAX_REFERENCE_BYTES: usize = 2048;
const BUNDLE_KIND: &str = "non_promoting_release_dry_run";

const PLATFORMS: [(&str, &str); 2] = [
    ("linux-x86_64", "x86_64-unknown-linux-gnu"),
    ("macos-aarch64", "aarch64-apple-darwin"),
];

const PREREQUISITES: [(&str, &str); 4] = [
    ("dependency-audit", "Dependency Audit"),
    ("hosted-release-archives", "Release Archives"),
    ("local-release-archive", "Test (ubuntu-latest)"),
    ("release-sbom", "Release SBOM"),
];

/// One hosted result referenced by the release evidence index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrerequisiteResult {
    pub evidence_id: String,
    pub check_name: String,
    pub source_revision: String,
    pub conclusion: EvidenceConclusion,
    pub result_url: String,
}

/// Only a successful prerequisite may enter a release bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConclusion {
    Success,
}

/// Bounded prerequisite-reference input document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrerequisiteDocument {
    pub schema_version: u32,
    pub results: Vec<PrerequisiteResult>,
}

/// Closed copy of one accepted member-ledger entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleMember {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub size: usize,
    pub sha256: String,
}

/// Closed copy of an accepted archive member ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleMemberLedger {
    pub members: Vec<BundleMember>,
}

/// Archive bytes named and hashed by one platform record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleArchive {
    pub name: String,
    pub sha256: String,
}

/// One exact platform's package evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundlePlatform {
    pub platform: String,
    pub target_triple: String,
    pub archive: BundleArchive,
    pub member_ledger: BundleMemberLedger,
    pub installation: InstallationTranscript,
}

/// Cross-artifact identity retained for the accepted SBOM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleSbom {
    pub name: String,
    pub sha256: String,
    pub format: String,
    pub spec_version: String,
    pub component_count: usize,
    pub cargo_lock_sha256: String,
}

/// Canonical non-promoting release evidence index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidenceIndex {
    pub schema_version: u32,
    pub kind: String,
    pub version: String,
    pub source_revision: String,
    pub dirty: bool,
    pub promoted_targets: Vec<String>,
    pub prerequisites: Vec<PrerequisiteResult>,
    pub platforms: Vec<BundlePlatform>,
    pub sbom: BundleSbom,
}

/// Deterministic result printed by release-bundle commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseBundleResult {
    pub version: String,
    pub source_revision: String,
    pub files: Vec<String>,
    pub sha256: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SbomIdentity {
    version: String,
    source_revision: String,
    cargo_lock_sha256: String,
    component_count: usize,
}

#[derive(Debug, Clone, Copy)]
enum ChecksumOrder {
    Filename,
    WholeLine,
}

fn validate_revision(revision: &str) -> Result<(), String> {
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("source revision must be a lowercase 40- or 64-digit object ID".to_string());
    }
    Ok(())
}

fn validate_sha256(digest: &str, label: &str) -> Result<(), String> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!("{label} must be 64 lowercase hexadecimal digits"));
    }
    Ok(())
}

fn require_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("read {label} directory metadata: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must be a real directory: {path:?}"));
    }
    Ok(())
}

fn require_new_or_empty_directory(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    require_directory(path, "release bundle output")?;
    if fs::read_dir(path)
        .map_err(|error| format!("read release bundle output directory: {error}"))?
        .next()
        .transpose()
        .map_err(|error| format!("inspect release bundle output directory: {error}"))?
        .is_some()
    {
        return Err(format!(
            "release bundle output directory must be empty: {path:?}"
        ));
    }
    Ok(())
}

fn read_regular_bounded(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("read {label} metadata: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} must be a regular non-symlink file: {path:?}"
        ));
    }
    let length = usize::try_from(metadata.len())
        .map_err(|_| format!("{label} size does not fit this host"))?;
    if length > limit {
        return Err(format!("{label} exceeds its {limit}-byte limit: {length}"));
    }
    fs::read(path).map_err(|error| format!("read {label} '{path:?}': {error}"))
}

fn canonical_json<T>(value: &T, label: &str) -> Result<Vec<u8>, String>
where
    T: Serialize,
{
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|error| format!("serialize {label}: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn read_canonical_json<T>(path: &Path, limit: usize, label: &str) -> Result<T, String>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = read_regular_bounded(path, limit, label)?;
    let value: T =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse {label}: {error}"))?;
    if canonical_json(&value, label)? != bytes {
        return Err(format!("{label} is not canonical deterministic JSON"));
    }
    Ok(value)
}

fn exact_file_names(root: &Path, expected: &[String], label: &str) -> Result<(), String> {
    require_directory(root, label)?;
    let mut actual = Vec::new();
    for entry in fs::read_dir(root).map_err(|error| format!("read {label}: {error}"))? {
        let entry = entry.map_err(|error| format!("read {label} entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{label} contains a non-UTF-8 filename"))?;
        actual.push(name);
    }
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    if actual != expected {
        return Err(format!(
            "{label} filenames differ: expected {expected:?}, got {actual:?}"
        ));
    }
    Ok(())
}

fn path_is_safe_relative(path: &str) -> bool {
    let mut count = 0usize;
    for component in Path::new(path).components() {
        match component {
            Component::Normal(_) => count += 1,
            _ => return false,
        }
    }
    count > 1
}

fn validate_result_url(url: &str) -> Result<(), String> {
    if url.len() > MAX_REFERENCE_BYTES {
        return Err("prerequisite result URL exceeds its length bound".to_string());
    }
    let prefix = "https://github.com/dweekly/luad/actions/runs/";
    let suffix = url
        .strip_prefix(prefix)
        .ok_or("prerequisite result URL must name this repository's GitHub Actions run")?;
    let mut parts = suffix.split('/');
    let run = parts.next().unwrap_or_default();
    if run.is_empty() || !run.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("prerequisite result URL has an invalid Actions run ID".to_string());
    }
    match (parts.next(), parts.next(), parts.next()) {
        (None, None, None) => Ok(()),
        (Some("job"), Some(job), None)
            if !job.is_empty() && job.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            Ok(())
        }
        _ => Err("prerequisite result URL has an unsupported suffix".to_string()),
    }
}

fn validate_prerequisites(
    document: &PrerequisiteDocument,
    source_revision: &str,
) -> Result<(), String> {
    if document.schema_version != 1 {
        return Err(format!(
            "unsupported prerequisite schema_version: expected 1, got {}",
            document.schema_version
        ));
    }
    if document.results.len() != PREREQUISITES.len() {
        return Err(format!(
            "prerequisite result count mismatch: expected {}, got {}",
            PREREQUISITES.len(),
            document.results.len()
        ));
    }
    for (result, (expected_id, expected_check)) in document.results.iter().zip(PREREQUISITES) {
        if result.evidence_id != expected_id || result.check_name != expected_check {
            return Err(format!(
                "prerequisite identity mismatch: expected '{expected_id}'/'{expected_check}', got '{}/{}'",
                result.evidence_id, result.check_name
            ));
        }
        if result.source_revision != source_revision {
            return Err(format!(
                "prerequisite '{}' revision mismatch: expected {source_revision}, got {}",
                result.evidence_id, result.source_revision
            ));
        }
        validate_result_url(&result.result_url)?;
    }
    Ok(())
}

fn parse_checksums(
    bytes: &[u8],
    expected_names: &[String],
    order: ChecksumOrder,
) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("SHA256SUMS UTF-8: {error}"))?;
    let mut actual = BTreeMap::new();
    for line in text.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or("SHA256SUMS entry must use two spaces between digest and filename")?;
        validate_sha256(digest, "SHA256SUMS digest")?;
        if name.is_empty() || name.contains('/') || name.contains('\\') {
            return Err("SHA256SUMS contains an unsafe filename".to_string());
        }
        if actual
            .insert(name.to_string(), digest.to_string())
            .is_some()
        {
            return Err(format!("SHA256SUMS contains duplicate filename '{name}'"));
        }
    }
    let expected: BTreeSet<_> = expected_names.iter().cloned().collect();
    let names: BTreeSet<_> = actual.keys().cloned().collect();
    if names != expected || actual.len() != expected_names.len() {
        return Err(format!(
            "SHA256SUMS filenames differ: expected {expected:?}, got {names:?}"
        ));
    }
    let canonical = match order {
        ChecksumOrder::Filename => checksum_bytes(&actual),
        ChecksumOrder::WholeLine => checksum_line_bytes(&actual),
    };
    if bytes != canonical {
        return Err("SHA256SUMS is not in canonical deterministic form".to_string());
    }
    Ok(actual)
}

fn checksum_line_bytes(entries: &BTreeMap<String, String>) -> Vec<u8> {
    let mut lines: Vec<_> = entries
        .iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect();
    lines.sort();
    lines.concat().into_bytes()
}

fn checksum_bytes(entries: &BTreeMap<String, String>) -> Vec<u8> {
    let mut output = String::new();
    for (name, digest) in entries {
        output.push_str(digest);
        output.push_str("  ");
        output.push_str(name);
        output.push('\n');
    }
    output.into_bytes()
}

fn archive_names(version: &str) -> Vec<String> {
    PLATFORMS
        .iter()
        .map(|(platform, _)| format!("luad-{version}-{platform}.tar.gz"))
        .collect()
}

fn archive_input_names(version: &str) -> Vec<String> {
    let mut names = vec!["SHA256SUMS".to_string()];
    for (platform, _) in PLATFORMS {
        let stem = format!("luad-{version}-{platform}");
        names.push(format!("{stem}.installation.json"));
        names.push(format!("{stem}.ledger.json"));
        names.push(format!("{stem}.tar.gz"));
    }
    names
}

fn bundle_names(version: &str) -> Vec<String> {
    vec![
        "SHA256SUMS".to_string(),
        "evidence-index.json".to_string(),
        format!("luad-{version}-linux-x86_64.tar.gz"),
        format!("luad-{version}-macos-aarch64.tar.gz"),
        format!("luad-{version}.cdx.json"),
    ]
}

fn validate_ledger(
    ledger: &BundleMemberLedger,
    version: &str,
    platform: &str,
) -> Result<(), String> {
    if ledger.members.is_empty() || ledger.members.len() > MAX_LEDGER_MEMBERS {
        return Err(format!(
            "member ledger count must be 1 through {MAX_LEDGER_MEMBERS}"
        ));
    }
    let stem = format!("luad-{version}-{platform}");
    let expected = [
        format!("{stem}/LICENSE"),
        format!("{stem}/LICENSE-APACHE"),
        format!("{stem}/README.md"),
        format!("{stem}/VERSION.json"),
        format!("{stem}/luad"),
    ];
    if ledger.members.len() != expected.len() {
        return Err(format!(
            "member ledger for {platform} must contain exactly {} accepted members",
            expected.len()
        ));
    }
    for (member, expected_path) in ledger.members.iter().zip(expected) {
        if member.path != expected_path || !path_is_safe_relative(&member.path) {
            return Err(format!(
                "member ledger path mismatch for {platform}: expected '{expected_path}', got '{}'",
                member.path
            ));
        }
        validate_sha256(&member.sha256, "member ledger SHA-256")?;
    }
    Ok(())
}

fn validate_installation(
    installation: &InstallationTranscript,
    version: &str,
    source_revision: &str,
    platform: &str,
    target_triple: &str,
    archive: &str,
) -> Result<(), String> {
    if installation.schema_version != 1
        || installation.archive != archive
        || installation.version != version
        || installation.source_revision != source_revision
        || installation.platform != platform
        || installation.target_triple != target_triple
        || installation.version_stdout != format!("luad {version}")
        || !installation.supported_dialects.is_empty()
    {
        return Err(format!(
            "installation transcript identity mismatch for {platform}"
        ));
    }
    validate_sha256(
        &installation.capabilities_sha256,
        "installation capabilities SHA-256",
    )
}

fn sbom_property(value: &Value, name: &str) -> Result<String, String> {
    let properties = value
        .pointer("/metadata/properties")
        .and_then(Value::as_array)
        .ok_or("SBOM is missing metadata properties")?;
    let values: Vec<_> = properties
        .iter()
        .filter(|property| property.get("name").and_then(Value::as_str) == Some(name))
        .filter_map(|property| property.get("value").and_then(Value::as_str))
        .collect();
    if values.len() != 1 {
        return Err(format!("SBOM must contain exactly one '{name}' property"));
    }
    Ok(values[0].to_string())
}

fn parse_sbom(path: &Path) -> Result<(Vec<u8>, SbomIdentity), String> {
    let bytes = read_regular_bounded(path, MAX_SBOM_BYTES, "release SBOM")?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse release SBOM: {error}"))?;
    if canonical_json(&value, "release SBOM")? != bytes {
        return Err("release SBOM is not canonical deterministic JSON".to_string());
    }
    if value.get("bomFormat").and_then(Value::as_str) != Some("CycloneDX")
        || value.get("specVersion").and_then(Value::as_str) != Some("1.5")
    {
        return Err("release SBOM must identify CycloneDX 1.5".to_string());
    }
    let version = value
        .pointer("/metadata/component/version")
        .and_then(Value::as_str)
        .ok_or("release SBOM is missing root component version")?
        .to_string();
    let source_revision = sbom_property(&value, "luad:source_revision")?;
    validate_revision(&source_revision)?;
    let cargo_lock_sha256 = sbom_property(&value, "luad:cargo_lock_sha256")?;
    validate_sha256(&cargo_lock_sha256, "SBOM Cargo.lock SHA-256")?;
    let component_count = value
        .get("components")
        .and_then(Value::as_array)
        .ok_or("release SBOM is missing components")?
        .len();
    if component_count > MAX_COMPONENTS {
        return Err(format!(
            "release SBOM exceeds the {MAX_COMPONENTS}-component composition bound"
        ));
    }
    Ok((
        bytes,
        SbomIdentity {
            version,
            source_revision,
            cargo_lock_sha256,
            component_count,
        },
    ))
}

fn validate_index(
    index: &ReleaseEvidenceIndex,
    version: &str,
    source_revision: &str,
) -> Result<(), String> {
    if index.schema_version != 1 || index.kind != BUNDLE_KIND {
        return Err("unsupported release evidence index identity".to_string());
    }
    if index.version != version || index.source_revision != source_revision || index.dirty {
        return Err("release evidence index source identity mismatch".to_string());
    }
    if !index.promoted_targets.is_empty() {
        return Err("non-promoting release bundle contains promoted targets".to_string());
    }
    validate_prerequisites(
        &PrerequisiteDocument {
            schema_version: 1,
            results: index.prerequisites.clone(),
        },
        source_revision,
    )?;
    if index.platforms.len() != PLATFORMS.len() {
        return Err("release evidence index platform count mismatch".to_string());
    }
    for (entry, (platform, target_triple)) in index.platforms.iter().zip(PLATFORMS) {
        let archive = format!("luad-{version}-{platform}.tar.gz");
        if entry.platform != platform
            || entry.target_triple != target_triple
            || entry.archive.name != archive
        {
            return Err(format!(
                "release evidence index platform mismatch for {platform}"
            ));
        }
        validate_sha256(&entry.archive.sha256, "release archive SHA-256")?;
        validate_ledger(&entry.member_ledger, version, platform)?;
        validate_installation(
            &entry.installation,
            version,
            source_revision,
            platform,
            target_triple,
            &archive,
        )?;
    }
    let expected_sbom = format!("luad-{version}.cdx.json");
    if index.sbom.name != expected_sbom
        || index.sbom.format != "CycloneDX"
        || index.sbom.spec_version != "1.5"
        || index.sbom.component_count > MAX_COMPONENTS
    {
        return Err("release evidence index SBOM identity mismatch".to_string());
    }
    validate_sha256(&index.sbom.sha256, "release SBOM SHA-256")?;
    validate_sha256(
        &index.sbom.cargo_lock_sha256,
        "release evidence index Cargo.lock SHA-256",
    )?;
    Ok(())
}

fn repository_identity(repository: &Path) -> Result<(String, String), String> {
    let source_revision = clean_source_revision(repository)?;
    let metadata = cargo_metadata(repository)?;
    let version = workspace_version(&metadata)?;
    Ok((version, source_revision))
}

/// Assemble the exact five-file non-promoting release bundle and verify it.
pub fn assemble_release_bundle(
    repository: &Path,
    archive_dir: &Path,
    sbom_path: &Path,
    prerequisites_path: &Path,
    output_dir: &Path,
) -> Result<ReleaseBundleResult, String> {
    require_new_or_empty_directory(output_dir)?;
    let (version, source_revision) = repository_identity(repository)?;
    let expected_archive_inputs = archive_input_names(&version);
    exact_file_names(
        archive_dir,
        &expected_archive_inputs,
        "release archive input",
    )?;

    let archive_names = archive_names(&version);
    let archive_checksum_bytes = read_regular_bounded(
        &archive_dir.join("SHA256SUMS"),
        MAX_SIDECAR_BYTES,
        "release archive SHA256SUMS",
    )?;
    let archive_checksums = parse_checksums(
        &archive_checksum_bytes,
        &archive_names,
        ChecksumOrder::WholeLine,
    )?;

    let mut platforms = Vec::new();
    let mut archive_bytes = BTreeMap::new();
    for (platform, target_triple) in PLATFORMS {
        let stem = format!("luad-{version}-{platform}");
        let archive_name = format!("{stem}.tar.gz");
        let bytes = read_regular_bounded(
            &archive_dir.join(&archive_name),
            MAX_ARCHIVE_BYTES,
            "release archive",
        )?;
        let actual_sha256 = sha256_digest(&bytes);
        if archive_checksums.get(&archive_name) != Some(&actual_sha256) {
            return Err(format!(
                "release archive checksum mismatch for {archive_name}"
            ));
        }
        let member_ledger: BundleMemberLedger = read_canonical_json(
            &archive_dir.join(format!("{stem}.ledger.json")),
            MAX_SIDECAR_BYTES,
            "release member ledger",
        )?;
        validate_ledger(&member_ledger, &version, platform)?;
        let installation: InstallationTranscript = read_canonical_json(
            &archive_dir.join(format!("{stem}.installation.json")),
            MAX_SIDECAR_BYTES,
            "release installation transcript",
        )?;
        validate_installation(
            &installation,
            &version,
            &source_revision,
            platform,
            target_triple,
            &archive_name,
        )?;
        platforms.push(BundlePlatform {
            platform: platform.to_string(),
            target_triple: target_triple.to_string(),
            archive: BundleArchive {
                name: archive_name.clone(),
                sha256: actual_sha256,
            },
            member_ledger,
            installation,
        });
        archive_bytes.insert(archive_name, bytes);
    }

    let expected_sbom_name = format!("luad-{version}.cdx.json");
    if sbom_path.file_name().and_then(|name| name.to_str()) != Some(&expected_sbom_name) {
        return Err(format!(
            "release SBOM filename mismatch: expected '{expected_sbom_name}'"
        ));
    }
    let (sbom_bytes, sbom_identity) = parse_sbom(sbom_path)?;
    if sbom_identity.version != version || sbom_identity.source_revision != source_revision {
        return Err("release SBOM does not describe the bundle source revision".to_string());
    }

    let prerequisites: PrerequisiteDocument = read_canonical_json(
        prerequisites_path,
        MAX_PREREQUISITES_BYTES,
        "release prerequisite references",
    )?;
    validate_prerequisites(&prerequisites, &source_revision)?;

    let index = ReleaseEvidenceIndex {
        schema_version: 1,
        kind: BUNDLE_KIND.to_string(),
        version: version.clone(),
        source_revision: source_revision.clone(),
        dirty: false,
        promoted_targets: Vec::new(),
        prerequisites: prerequisites.results,
        platforms,
        sbom: BundleSbom {
            name: expected_sbom_name.clone(),
            sha256: sha256_digest(&sbom_bytes),
            format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            component_count: sbom_identity.component_count,
            cargo_lock_sha256: sbom_identity.cargo_lock_sha256,
        },
    };
    validate_index(&index, &version, &source_revision)?;
    let index_bytes = canonical_json(&index, "release evidence index")?;
    if index_bytes.len() > MAX_INDEX_BYTES {
        return Err(format!(
            "release evidence index exceeds its {MAX_INDEX_BYTES}-byte limit"
        ));
    }

    fs::create_dir_all(output_dir)
        .map_err(|error| format!("create release bundle output directory: {error}"))?;
    for (name, bytes) in &archive_bytes {
        fs::write(output_dir.join(name), bytes)
            .map_err(|error| format!("write release bundle archive '{name}': {error}"))?;
    }
    fs::write(output_dir.join(&expected_sbom_name), &sbom_bytes)
        .map_err(|error| format!("write release bundle SBOM: {error}"))?;
    fs::write(output_dir.join("evidence-index.json"), &index_bytes)
        .map_err(|error| format!("write release evidence index: {error}"))?;

    let mut checksums = BTreeMap::new();
    for (name, bytes) in archive_bytes {
        checksums.insert(name, sha256_digest(&bytes));
    }
    checksums.insert(expected_sbom_name, sha256_digest(&sbom_bytes));
    checksums.insert(
        "evidence-index.json".to_string(),
        sha256_digest(&index_bytes),
    );
    fs::write(output_dir.join("SHA256SUMS"), checksum_bytes(&checksums))
        .map_err(|error| format!("write release bundle SHA256SUMS: {error}"))?;

    verify_release_bundle(repository, output_dir)
}

/// Verify the exact five-file bundle without rerunning prerequisite semantic gates.
pub fn verify_release_bundle(
    repository: &Path,
    bundle_dir: &Path,
) -> Result<ReleaseBundleResult, String> {
    let (version, source_revision) = repository_identity(repository)?;
    let expected_files = bundle_names(&version);
    exact_file_names(bundle_dir, &expected_files, "release bundle")?;

    let payload_names: Vec<_> = expected_files
        .iter()
        .filter(|name| name.as_str() != "SHA256SUMS")
        .cloned()
        .collect();
    let checksum_file = read_regular_bounded(
        &bundle_dir.join("SHA256SUMS"),
        MAX_SIDECAR_BYTES,
        "release bundle SHA256SUMS",
    )?;
    let checksums = parse_checksums(&checksum_file, &payload_names, ChecksumOrder::Filename)?;
    for name in &payload_names {
        let limit = if name.ends_with(".tar.gz") {
            MAX_ARCHIVE_BYTES
        } else if name.ends_with(".cdx.json") {
            MAX_SBOM_BYTES
        } else {
            MAX_INDEX_BYTES
        };
        let bytes = read_regular_bounded(&bundle_dir.join(name), limit, "release bundle file")?;
        if checksums.get(name) != Some(&sha256_digest(&bytes)) {
            return Err(format!("release bundle checksum mismatch for {name}"));
        }
    }

    let index: ReleaseEvidenceIndex = read_canonical_json(
        &bundle_dir.join("evidence-index.json"),
        MAX_INDEX_BYTES,
        "release evidence index",
    )?;
    validate_index(&index, &version, &source_revision)?;

    for platform in &index.platforms {
        let bytes = read_regular_bounded(
            &bundle_dir.join(&platform.archive.name),
            MAX_ARCHIVE_BYTES,
            "release archive",
        )?;
        if sha256_digest(&bytes) != platform.archive.sha256 {
            return Err(format!(
                "release evidence index archive hash mismatch for {}",
                platform.platform
            ));
        }
    }

    let sbom_path = bundle_dir.join(&index.sbom.name);
    let (sbom_bytes, sbom_identity) = parse_sbom(&sbom_path)?;
    if sha256_digest(&sbom_bytes) != index.sbom.sha256
        || sbom_identity.version != version
        || sbom_identity.source_revision != source_revision
        || sbom_identity.cargo_lock_sha256 != index.sbom.cargo_lock_sha256
        || sbom_identity.component_count != index.sbom.component_count
    {
        return Err("release evidence index SBOM facts do not match the bundled SBOM".to_string());
    }

    Ok(ReleaseBundleResult {
        version,
        source_revision,
        files: expected_files,
        sha256: checksums,
    })
}
