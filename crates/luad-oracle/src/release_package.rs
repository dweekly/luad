//! Deterministic, non-promoting release archive construction and verification.

use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::candidate::{
    create_deterministic_gzip, create_ustar_header, decompress_gzip, parse_tar, sha256_digest,
    MemberLedger, MemberLedgerEntry, ParsedTarEntry,
};

const MAX_BINARY_BYTES: usize = 128 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: usize = 160 * 1024 * 1024;
const MAX_SIDECAR_BYTES: usize = 4 * 1024 * 1024;
const FILE_MODE: u32 = 0o644;
const EXECUTABLE_MODE: u32 = 0o755;

/// Exact identity embedded in every release archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub schema_version: u32,
    pub version: String,
    pub source_revision: String,
    pub dirty: bool,
    pub platform: String,
    pub target_triple: String,
}

/// Paths emitted for one local release archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseArtifactPaths {
    pub archive: PathBuf,
    pub ledger: PathBuf,
    pub checksums: PathBuf,
}

/// Inputs whose exact bytes are packaged and later compared independently.
#[derive(Debug, Clone)]
pub struct ReleaseInputs<'a> {
    pub binary: &'a Path,
    pub readme: &'a Path,
    pub license_mit: &'a Path,
    pub license_apache: &'a Path,
    pub identity: ReleaseIdentity,
}

/// Verified archive state retained for safe extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub identity: ReleaseIdentity,
    pub entries: Vec<ParsedTarEntry>,
}

/// Deterministic smoke record for the extracted executable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallationTranscript {
    pub schema_version: u32,
    pub archive: String,
    pub version: String,
    pub source_revision: String,
    pub platform: String,
    pub target_triple: String,
    pub version_stdout: String,
    pub capabilities_sha256: String,
    pub supported_dialects: Vec<String>,
}

/// Result printed by the maintained packaging command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageCommandResult {
    pub archive: String,
    pub ledger: String,
    pub checksums: String,
    pub installation_transcript: String,
    pub identity: ReleaseIdentity,
}

fn platform_target_triple(platform: &str) -> Result<&'static str, String> {
    match platform {
        "linux-x86_64" => Ok("x86_64-unknown-linux-gnu"),
        "macos-aarch64" => Ok("aarch64-apple-darwin"),
        other => Err(format!("unsupported release platform '{other}'")),
    }
}

fn validate_version(version: &str) -> Result<(), String> {
    if version.is_empty() || version.len() > 64 {
        return Err("release version must contain 1 through 64 characters".to_string());
    }
    if !version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        return Err(format!(
            "release version contains unsafe characters: '{version}'"
        ));
    }
    if matches!(version, "." | "..") {
        return Err(format!(
            "release version is not a safe path component: '{version}'"
        ));
    }
    Ok(())
}

fn validate_revision(revision: &str) -> Result<(), String> {
    if !matches!(revision.len(), 40 | 64)
        || !revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(
            "source revision must be a lowercase 40- or 64-digit Git object ID".to_string(),
        );
    }
    Ok(())
}

impl ReleaseIdentity {
    /// Validate the non-promoting release identity and exact platform mapping.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err(format!(
                "unsupported release identity schema_version: expected 1, got {}",
                self.schema_version
            ));
        }
        validate_version(&self.version)?;
        validate_revision(&self.source_revision)?;
        if self.dirty {
            return Err("release source tree is marked dirty".to_string());
        }
        let expected_triple = platform_target_triple(&self.platform)?;
        if self.target_triple != expected_triple {
            return Err(format!(
                "target triple mismatch for '{}': expected {expected_triple}, got {}",
                self.platform, self.target_triple
            ));
        }
        Ok(())
    }

    /// Canonical archive stem used for the directory and sidecar names.
    #[must_use]
    pub fn archive_stem(&self) -> String {
        format!("luad-{}-{}", self.version, self.platform)
    }
}

fn read_bounded(path: &Path, limit: usize, label: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("read {label} metadata: {error}"))?;
    if !metadata.is_file() {
        return Err(format!("{label} is not a regular file: {path:?}"));
    }
    let size = usize::try_from(metadata.len())
        .map_err(|_| format!("{label} size does not fit this host"))?;
    if size > limit {
        return Err(format!(
            "{label} exceeds {limit}-byte packaging limit: {size}"
        ));
    }
    fs::read(path).map_err(|error| format!("read {label} '{path:?}': {error}"))
}

fn canonical_member_names(identity: &ReleaseIdentity) -> Vec<String> {
    let root = identity.archive_stem();
    vec![
        format!("{root}/LICENSE"),
        format!("{root}/LICENSE-APACHE"),
        format!("{root}/README.md"),
        format!("{root}/VERSION.json"),
        format!("{root}/luad"),
    ]
}

fn build_archive(members: &[(String, u32, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut tar_bytes = Vec::new();
    for (name, mode, data) in members {
        if name.len() > 100 {
            return Err(format!(
                "release member path exceeds ustar name limit: '{name}'"
            ));
        }
        let header = create_ustar_header(name, *mode, data.len());
        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(data);
        let padding = (512 - (data.len() % 512)) % 512;
        tar_bytes.extend(std::iter::repeat_n(0, padding));
    }
    tar_bytes.extend(std::iter::repeat_n(0, 1024));
    Ok(create_deterministic_gzip(&tar_bytes))
}

fn ledger_for_members(members: &[(String, u32, Vec<u8>)]) -> MemberLedger {
    MemberLedger {
        members: members
            .iter()
            .map(|(path, mode, data)| MemberLedgerEntry {
                path: path.clone(),
                mode: *mode,
                uid: 0,
                gid: 0,
                mtime: 0,
                size: data.len(),
                sha256: sha256_digest(data),
            })
            .collect(),
    }
}

fn output_paths(output_dir: &Path, identity: &ReleaseIdentity) -> ReleaseArtifactPaths {
    let stem = identity.archive_stem();
    ReleaseArtifactPaths {
        archive: output_dir.join(format!("{stem}.tar.gz")),
        ledger: output_dir.join(format!("{stem}.ledger.json")),
        checksums: output_dir.join("SHA256SUMS"),
    }
}

fn refuse_overwrite(paths: &ReleaseArtifactPaths) -> Result<(), String> {
    for path in [&paths.archive, &paths.ledger, &paths.checksums] {
        if path.exists() {
            return Err(format!("refusing to overwrite release artifact: {path:?}"));
        }
    }
    Ok(())
}

fn require_empty_output_directory(output_dir: &Path) -> Result<(), String> {
    if !output_dir.exists() {
        return Ok(());
    }
    if !output_dir.is_dir() {
        return Err(format!(
            "release output path is not a directory: {output_dir:?}"
        ));
    }
    let mut entries = fs::read_dir(output_dir)
        .map_err(|error| format!("read release output directory: {error}"))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| format!("inspect release output directory entry: {error}"))?
        .is_some()
    {
        return Err(format!(
            "release output directory must be empty: {output_dir:?}"
        ));
    }
    Ok(())
}

/// Construct one deterministic release archive, ledger, and checksum file.
pub fn pack_release(
    inputs: &ReleaseInputs<'_>,
    output_dir: &Path,
) -> Result<ReleaseArtifactPaths, String> {
    inputs.identity.validate()?;
    require_empty_output_directory(output_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(inputs.binary)
            .map_err(|error| format!("read binary metadata: {error}"))?
            .permissions()
            .mode();
        if mode & 0o111 == 0 {
            return Err(format!(
                "release binary is not executable: {:?}",
                inputs.binary
            ));
        }
    }

    let binary = read_bounded(inputs.binary, MAX_BINARY_BYTES, "release binary")?;
    let readme = read_bounded(inputs.readme, MAX_TEXT_BYTES, "README")?;
    let license_mit = read_bounded(inputs.license_mit, MAX_TEXT_BYTES, "MIT license")?;
    let license_apache = read_bounded(inputs.license_apache, MAX_TEXT_BYTES, "Apache-2.0 license")?;
    let mut identity_json = serde_json::to_vec_pretty(&inputs.identity)
        .map_err(|error| format!("serialize release identity: {error}"))?;
    identity_json.push(b'\n');

    let names = canonical_member_names(&inputs.identity);
    let members = vec![
        (names[0].clone(), FILE_MODE, license_mit),
        (names[1].clone(), FILE_MODE, license_apache),
        (names[2].clone(), FILE_MODE, readme),
        (names[3].clone(), FILE_MODE, identity_json),
        (names[4].clone(), EXECUTABLE_MODE, binary),
    ];
    let archive_bytes = build_archive(&members)?;
    if archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(format!(
            "release archive exceeds {MAX_ARCHIVE_BYTES}-byte limit: {}",
            archive_bytes.len()
        ));
    }

    let ledger = ledger_for_members(&members);
    let mut ledger_bytes = serde_json::to_vec_pretty(&ledger)
        .map_err(|error| format!("serialize release ledger: {error}"))?;
    ledger_bytes.push(b'\n');

    let paths = output_paths(output_dir, &inputs.identity);
    refuse_overwrite(&paths)?;
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("create release output directory: {error}"))?;
    fs::write(&paths.archive, &archive_bytes)
        .map_err(|error| format!("write release archive: {error}"))?;
    fs::write(&paths.ledger, ledger_bytes)
        .map_err(|error| format!("write release ledger: {error}"))?;

    let archive_name = paths
        .archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("release archive has a non-UTF-8 file name")?;
    let checksum_line = format!("{}  {archive_name}\n", sha256_digest(&archive_bytes));
    fs::write(&paths.checksums, checksum_line.as_bytes())
        .map_err(|error| format!("write SHA256SUMS: {error}"))?;
    Ok(paths)
}

fn parse_checksum(bytes: &[u8], expected_name: &str) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| format!("SHA256SUMS UTF-8: {error}"))?;
    let expected_suffix = format!("  {expected_name}");
    let mut lines = text.lines();
    let line = lines.next().ok_or("SHA256SUMS is empty")?;
    if lines.next().is_some() {
        return Err("SHA256SUMS must contain exactly one entry for this local package".to_string());
    }
    let digest = line
        .strip_suffix(&expected_suffix)
        .ok_or_else(|| format!("SHA256SUMS archive name mismatch: expected '{expected_name}'"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("SHA256SUMS digest must be 64 lowercase hexadecimal digits".to_string());
    }
    Ok(digest.to_string())
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

fn reconstruct_archive(entries: &[ParsedTarEntry]) -> Result<Vec<u8>, String> {
    let members: Vec<_> = entries
        .iter()
        .map(|entry| (entry.name.clone(), entry.mode, entry.data.clone()))
        .collect();
    build_archive(&members)
}

/// Verify one archive against its checksum, ledger, identity, and canonical source inputs.
pub fn verify_release(
    paths: &ReleaseArtifactPaths,
    inputs: &ReleaseInputs<'_>,
) -> Result<VerifiedRelease, String> {
    inputs.identity.validate()?;
    let expected_paths = output_paths(
        paths
            .archive
            .parent()
            .ok_or("release archive has no parent directory")?,
        &inputs.identity,
    );
    if paths != &expected_paths {
        return Err(
            "release artifact names do not match the expected version and platform".to_string(),
        );
    }

    let archive_bytes = read_bounded(&paths.archive, MAX_ARCHIVE_BYTES, "release archive")?;
    let ledger_bytes = read_bounded(&paths.ledger, MAX_SIDECAR_BYTES, "release ledger")?;
    let checksum_bytes = read_bounded(&paths.checksums, MAX_SIDECAR_BYTES, "SHA256SUMS")?;
    let archive_name = paths
        .archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("release archive has a non-UTF-8 file name")?;
    let expected_archive_sha = parse_checksum(&checksum_bytes, archive_name)?;
    let canonical_checksum = format!("{expected_archive_sha}  {archive_name}\n");
    if checksum_bytes != canonical_checksum.as_bytes() {
        return Err("SHA256SUMS is not in canonical deterministic form".to_string());
    }
    let actual_archive_sha = sha256_digest(&archive_bytes);
    if actual_archive_sha != expected_archive_sha {
        return Err(format!(
            "release archive SHA-256 mismatch: expected {expected_archive_sha}, got {actual_archive_sha}"
        ));
    }

    let tar_bytes = decompress_gzip(&archive_bytes)
        .map_err(|error| format!("decompress release archive: {error}"))?;
    let entries =
        parse_tar(&tar_bytes).map_err(|error| format!("parse release archive: {error}"))?;
    let rebuilt = reconstruct_archive(&entries)?;
    if rebuilt != archive_bytes {
        return Err(
            "release archive is not in canonical deterministic ustar/gzip form".to_string(),
        );
    }

    let expected_names = canonical_member_names(&inputs.identity);
    if entries.len() != expected_names.len() {
        return Err(format!(
            "release archive member count mismatch: expected {}, got {}",
            expected_names.len(),
            entries.len()
        ));
    }
    for (entry, expected_name) in entries.iter().zip(&expected_names) {
        if !path_is_safe_relative(&entry.name) {
            return Err(format!(
                "unsafe release archive member path: '{}'",
                entry.name
            ));
        }
        if &entry.name != expected_name {
            return Err(format!(
                "release archive member mismatch: expected '{expected_name}', got '{}'",
                entry.name
            ));
        }
    }

    let ledger: MemberLedger = serde_json::from_slice(&ledger_bytes)
        .map_err(|error| format!("parse release ledger: {error}"))?;
    let mut canonical_ledger = serde_json::to_vec_pretty(&ledger)
        .map_err(|error| format!("serialize canonical release ledger: {error}"))?;
    canonical_ledger.push(b'\n');
    if ledger_bytes != canonical_ledger {
        return Err("release ledger is not in canonical deterministic form".to_string());
    }
    if ledger.members.len() != entries.len() {
        return Err(format!(
            "release ledger member count mismatch: expected {}, got {}",
            entries.len(),
            ledger.members.len()
        ));
    }

    for (index, (entry, ledger_entry)) in entries.iter().zip(&ledger.members).enumerate() {
        let expected_mode = if index + 1 == entries.len() {
            EXECUTABLE_MODE
        } else {
            FILE_MODE
        };
        if entry.mode != expected_mode || ledger_entry.mode != expected_mode {
            return Err(format!(
                "release member mode mismatch for '{}': expected {expected_mode:o}, tar={:o}, ledger={:o}",
                entry.name, entry.mode, ledger_entry.mode
            ));
        }
        if entry.uid != 0
            || entry.gid != 0
            || entry.mtime != 0
            || ledger_entry.uid != 0
            || ledger_entry.gid != 0
            || ledger_entry.mtime != 0
        {
            return Err(format!(
                "release member ownership or timestamp is not canonical for '{}'",
                entry.name
            ));
        }
        let actual_sha = sha256_digest(&entry.data);
        if ledger_entry.path != entry.name
            || ledger_entry.size != entry.size
            || entry.size != entry.data.len()
            || ledger_entry.sha256 != actual_sha
        {
            return Err(format!(
                "release ledger does not match archive member '{}'",
                entry.name
            ));
        }
    }

    let embedded_identity: ReleaseIdentity = serde_json::from_slice(&entries[3].data)
        .map_err(|error| format!("parse embedded VERSION.json: {error}"))?;
    embedded_identity.validate()?;
    if embedded_identity != inputs.identity {
        return Err("embedded VERSION.json does not match expected release identity".to_string());
    }

    let expected_bytes = [
        read_bounded(inputs.license_mit, MAX_TEXT_BYTES, "MIT license")?,
        read_bounded(inputs.license_apache, MAX_TEXT_BYTES, "Apache-2.0 license")?,
        read_bounded(inputs.readme, MAX_TEXT_BYTES, "README")?,
        {
            let mut bytes = serde_json::to_vec_pretty(&inputs.identity)
                .map_err(|error| format!("serialize expected release identity: {error}"))?;
            bytes.push(b'\n');
            bytes
        },
        read_bounded(inputs.binary, MAX_BINARY_BYTES, "release binary")?,
    ];
    for (entry, expected) in entries.iter().zip(expected_bytes) {
        if entry.data != expected {
            return Err(format!(
                "release member '{}' does not match its canonical input",
                entry.name
            ));
        }
    }

    Ok(VerifiedRelease {
        identity: embedded_identity,
        entries,
    })
}

/// Extract already verified members without following archive-provided paths.
pub fn extract_verified_release(
    verified: &VerifiedRelease,
    destination: &Path,
) -> Result<PathBuf, String> {
    if destination.exists() {
        return Err(format!(
            "refusing to extract into an existing path: {destination:?}"
        ));
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("create extraction directory: {error}"))?;
    for (index, entry) in verified.entries.iter().enumerate() {
        let relative = Path::new(&entry.name);
        if !path_is_safe_relative(&entry.name) {
            return Err(format!("unsafe verified member path: '{}'", entry.name));
        }
        let output = destination.join(relative);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("create extracted member directory: {error}"))?;
        }
        fs::write(&output, &entry.data)
            .map_err(|error| format!("write extracted member: {error}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if index + 1 == verified.entries.len() {
                EXECUTABLE_MODE
            } else {
                FILE_MODE
            };
            fs::set_permissions(&output, fs::Permissions::from_mode(mode))
                .map_err(|error| format!("set extracted member permissions: {error}"))?;
        }
    }
    Ok(destination
        .join(verified.identity.archive_stem())
        .join("luad"))
}

/// Execute the two accepted install smokes and return a deterministic transcript.
pub fn smoke_release_binary(
    binary: &Path,
    identity: &ReleaseIdentity,
    archive_name: &str,
) -> Result<InstallationTranscript, String> {
    let version_output = Command::new(binary)
        .arg("--version")
        .output()
        .map_err(|error| format!("execute packaged luad --version: {error}"))?;
    if !version_output.status.success() || !version_output.stderr.is_empty() {
        return Err("packaged luad --version did not exit cleanly on stdout only".to_string());
    }
    let version_stdout = std::str::from_utf8(&version_output.stdout)
        .map_err(|error| format!("packaged luad --version UTF-8: {error}"))?
        .trim_end_matches(['\r', '\n'])
        .to_string();
    let expected_version = format!("luad {}", identity.version);
    if version_stdout != expected_version {
        return Err(format!(
            "packaged luad version mismatch: expected '{expected_version}', got '{version_stdout}'"
        ));
    }

    let capabilities_output = Command::new(binary)
        .args(["capabilities", "--format", "json"])
        .output()
        .map_err(|error| format!("execute packaged luad capabilities: {error}"))?;
    if !capabilities_output.status.success() || !capabilities_output.stderr.is_empty() {
        return Err("packaged luad capabilities did not exit cleanly on stdout only".to_string());
    }
    let capabilities: serde_json::Value = serde_json::from_slice(&capabilities_output.stdout)
        .map_err(|error| format!("parse packaged capabilities JSON: {error}"))?;
    if capabilities
        .get("tool_name")
        .and_then(|value| value.as_str())
        != Some("luad")
        || capabilities
            .get("tool_version")
            .and_then(|value| value.as_str())
            != Some(identity.version.as_str())
    {
        return Err("packaged capabilities tool identity mismatch".to_string());
    }
    let supported_dialects: Vec<String> = capabilities
        .get("supported_dialects")
        .and_then(|value| value.as_array())
        .ok_or("packaged capabilities missing supported_dialects array")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or("packaged supported_dialects entry is not a string")
        })
        .collect::<Result<_, _>>()?;
    if !supported_dialects.is_empty() {
        return Err("non-promoting package unexpectedly contains supported dialects".to_string());
    }

    Ok(InstallationTranscript {
        schema_version: 1,
        archive: archive_name.to_string(),
        version: identity.version.clone(),
        source_revision: identity.source_revision.clone(),
        platform: identity.platform.clone(),
        target_triple: identity.target_triple.clone(),
        version_stdout,
        capabilities_sha256: sha256_digest(&capabilities_output.stdout),
        supported_dialects,
    })
}

/// Resolve and reject a dirty Git source tree before packaging starts.
pub fn clean_source_revision(repository: &Path) -> Result<String, String> {
    let status = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("inspect release source tree: {error}"))?;
    if !status.status.success() {
        return Err(format!(
            "inspect release source tree: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }
    if !status.stdout.is_empty() {
        return Err("release source tree is dirty".to_string());
    }
    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("resolve release source revision: {error}"))?;
    if !revision.status.success() {
        return Err(format!(
            "resolve release source revision: {}",
            String::from_utf8_lossy(&revision.stderr).trim()
        ));
    }
    let revision = String::from_utf8(revision.stdout)
        .map_err(|error| format!("release source revision UTF-8: {error}"))?
        .trim()
        .to_string();
    validate_revision(&revision)?;
    Ok(revision)
}

fn cargo_metadata(repository: &Path) -> Result<serde_json::Value, String> {
    let output = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("execute cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| format!("parse cargo metadata: {error}"))
}

fn workspace_version(metadata: &serde_json::Value) -> Result<String, String> {
    let packages = metadata
        .get("packages")
        .and_then(|value| value.as_array())
        .ok_or("cargo metadata is missing packages")?;
    let package = packages
        .iter()
        .find(|package| package.get("name").and_then(|value| value.as_str()) == Some("luad-cli"))
        .ok_or("cargo metadata is missing luad-cli")?;
    let version = package
        .get("version")
        .and_then(|value| value.as_str())
        .ok_or("luad-cli package is missing version")?
        .to_string();
    validate_version(&version)?;
    Ok(version)
}

fn rustc_host(repository: &Path) -> Result<String, String> {
    let output = Command::new("rustc")
        .arg("-vV")
        .current_dir(repository)
        .output()
        .map_err(|error| format!("execute rustc -vV: {error}"))?;
    if !output.status.success() {
        return Err("rustc -vV failed".to_string());
    }
    let text =
        String::from_utf8(output.stdout).map_err(|error| format!("rustc -vV UTF-8: {error}"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("host: ").map(ToOwned::to_owned))
        .ok_or("rustc -vV did not report a host target".to_string())
}

/// Run the complete clean-revision package, verify, extract, and smoke workflow.
pub fn package_clean_workspace(
    repository: &Path,
    platform: &str,
    output_dir: &Path,
) -> Result<PackageCommandResult, String> {
    let expected_target = platform_target_triple(platform)?;
    let source_revision = clean_source_revision(repository)?;
    let metadata = cargo_metadata(repository)?;
    let version = workspace_version(&metadata)?;
    let host = rustc_host(repository)?;
    if host != expected_target {
        return Err(format!(
            "release platform '{platform}' requires rustc host '{expected_target}', got '{host}'"
        ));
    }

    let build = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--locked",
            "-p",
            "luad-cli",
            "--bin",
            "luad",
        ])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("build release binary: {error}"))?;
    if !build.status.success() {
        return Err(format!(
            "release build failed: {}",
            String::from_utf8_lossy(&build.stderr).trim()
        ));
    }
    let post_build_revision = clean_source_revision(repository)?;
    if post_build_revision != source_revision {
        return Err(format!(
            "release source revision changed during build: before={source_revision}, after={post_build_revision}"
        ));
    }

    let target_directory = metadata
        .get("target_directory")
        .and_then(|value| value.as_str())
        .ok_or("cargo metadata is missing target_directory")?;
    let binary = Path::new(target_directory).join("release/luad");
    let identity = ReleaseIdentity {
        schema_version: 1,
        version,
        source_revision,
        dirty: false,
        platform: platform.to_string(),
        target_triple: expected_target.to_string(),
    };
    let inputs = ReleaseInputs {
        binary: &binary,
        readme: &repository.join("README.md"),
        license_mit: &repository.join("LICENSE"),
        license_apache: &repository.join("LICENSE-APACHE"),
        identity: identity.clone(),
    };
    let paths = pack_release(&inputs, output_dir)?;
    let verified = verify_release(&paths, &inputs)?;
    let extraction = tempfile::tempdir().map_err(|error| format!("create smoke dir: {error}"))?;
    let smoke_root = extraction.path().join("install");
    let installed_binary = extract_verified_release(&verified, &smoke_root)?;
    let archive_name = paths
        .archive
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("release archive has a non-UTF-8 file name")?;
    let transcript = smoke_release_binary(&installed_binary, &identity, archive_name)?;
    let transcript_name = format!("{}.installation.json", identity.archive_stem());
    let transcript_path = output_dir.join(&transcript_name);
    if transcript_path.exists() {
        return Err(format!(
            "refusing to overwrite installation transcript: {transcript_path:?}"
        ));
    }
    let mut transcript_bytes = serde_json::to_vec_pretty(&transcript)
        .map_err(|error| format!("serialize installation transcript: {error}"))?;
    transcript_bytes.push(b'\n');
    fs::write(&transcript_path, transcript_bytes)
        .map_err(|error| format!("write installation transcript: {error}"))?;

    Ok(PackageCommandResult {
        archive: archive_name.to_string(),
        ledger: paths
            .ledger
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("release ledger has a non-UTF-8 file name")?
            .to_string(),
        checksums: "SHA256SUMS".to_string(),
        installation_transcript: transcript_name,
        identity,
    })
}
