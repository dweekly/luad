//! Candidate qualification, packaging, attestation, and index verification module.
//!
//! Provides deterministic archive packaging, member ledger generation, fail-closed
//! platform attestation verification, multi-platform evidence index assembly,
//! binary resolution, and checked analysis transcript generation.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Compute canonical hex SHA-256 digest of bytes.
#[must_use]
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Compute standard IEEE 802.3 / ISO 3309 CRC-32 checksum.
#[must_use]
pub fn compute_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Source-controlled candidate release specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateSpec {
    pub schema_version: u32,
    pub candidate_id: String,
    pub target: TargetSpec,
    pub schema_majors: BTreeMap<String, u32>,
    pub required_platforms: Vec<PlatformSpec>,
    pub required_prerequisites: Vec<PrerequisiteSpec>,
    pub required_fixtures: Vec<FixtureSpec>,
    pub archive_policy: ArchivePolicySpec,
}

/// Target dialect, patch, profile, and layout specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetSpec {
    pub dialect: String,
    pub patch_version: String,
    pub profile: String,
    pub layout: String,
}

/// Platform requirement specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformSpec {
    pub platform_id: String,
    pub os: String,
    pub arch: String,
    pub target_triple: String,
}

/// Required prerequisite gate specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrerequisiteSpec {
    pub gate_id: String,
    pub spec_path: String,
    pub file_sha256: String,
}

/// Required fixture file requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixtureSpec {
    pub path: String,
    pub sha256: String,
}

/// Archive packaging policy specification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchivePolicySpec {
    pub format: String,
    pub member_order: String,
    pub mtime: u64,
    pub uid: u32,
    pub gid: u32,
    pub file_mode: u32,
    pub executable_mode: u32,
    pub extended_attributes: bool,
}

/// One entry in the external archive member ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberLedgerEntry {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub size: usize,
    pub sha256: String,
}

/// External member ledger metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberLedger {
    pub members: Vec<MemberLedgerEntry>,
}

/// External per-platform attestation sidecar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformAttestation {
    pub schema_version: u32,
    pub candidate_id: String,
    pub spec_hash: String,
    pub git_commit: String,
    pub dirty: bool,
    pub platform: String,
    pub os: String,
    pub arch: String,
    pub target_triple: String,
    pub toolchain: String,
    pub build_host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
    pub archive_sha256: String,
    pub binary_sha256: String,
    pub member_ledger: Vec<MemberLedgerEntry>,
    pub target: TargetSpec,
    pub prerequisite_results: Vec<AttestationPrereqResult>,
    pub aggregate_check_success: bool,
}

/// Prerequisite gate result summary within an attestation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationPrereqResult {
    pub gate_id: String,
    pub spec_hash: String,
    pub result_sha256: String,
    pub exit_code: i32,
    pub success: bool,
    pub passed_count: usize,
    pub failed_count: usize,
    pub ignored_count: usize,
    pub missing_expected_tests: Vec<String>,
}

/// Candidate evidence index binding all platform artifacts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceIndex {
    pub schema_version: u32,
    pub candidate_id: String,
    pub spec_hash: String,
    pub git_commit: String,
    pub artifacts: Vec<PlatformArtifactEntry>,
}

/// Entry for one platform in the evidence index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformArtifactEntry {
    pub platform: String,
    pub os: String,
    pub arch: String,
    pub target_triple: String,
    pub toolchain: String,
    pub build_host: String,
    pub git_commit: String,
    pub spec_hash: String,
    pub archive_path: String,
    pub archive_sha256: String,
    pub binary_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_sha256: Option<String>,
    pub member_ledger: Vec<MemberLedgerEntry>,
    pub prerequisite_results: Vec<AttestationPrereqResult>,
    pub aggregate_check_success: bool,
}

/// Structured document output from resolve-bin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BinaryResolutionDoc {
    pub selected_binary_path: String,
    pub override_active: bool,
}

/// Structured document output from transcript.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranscriptDoc {
    pub selected_binary_sha256: String,
    pub input_fixture_sha256: String,
    pub profile: String,
    pub layout: String,
    pub workflows: BTreeMap<String, WorkflowTranscript>,
}

/// Workflow outcome within checked transcript.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowTranscript {
    pub status: String,
    pub evidence: serde_json::Value,
}

/// Binary resolution failure mode.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BinaryResolutionError {
    #[error("LUAD_CANDIDATE_BIN is empty")]
    Empty,
    #[error("LUAD_CANDIDATE_BIN path is missing: {0:?}")]
    Missing(PathBuf),
    #[error("LUAD_CANDIDATE_BIN path is a directory: {0:?}")]
    Directory(PathBuf),
    #[error("LUAD_CANDIDATE_BIN path is not executable: {0:?}")]
    NotExecutable(PathBuf),
    #[error("Failed to build or locate workspace luad binary: {0}")]
    WorkspaceFallbackFailed(String),
}

/// Shared test-binary resolver.
///
/// When `LUAD_CANDIDATE_BIN` is present—even empty—it is authoritative and errors for empty,
/// missing, directory, or non-executable values without fallback. When absent, it falls back
/// to workspace binary detection / build.
pub fn resolve_test_binary() -> Result<PathBuf, BinaryResolutionError> {
    if let Some(val) = std::env::var_os("LUAD_CANDIDATE_BIN") {
        let s = val.to_string_lossy();
        if s.trim().is_empty() {
            return Err(BinaryResolutionError::Empty);
        }
        let path = PathBuf::from(val);
        if !path.exists() {
            return Err(BinaryResolutionError::Missing(path));
        }
        if path.is_dir() {
            return Err(BinaryResolutionError::Directory(path));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = fs::metadata(&path) {
                if meta.permissions().mode() & 0o111 == 0 {
                    return Err(BinaryResolutionError::NotExecutable(path));
                }
            }
        }
        return Ok(path);
    }

    // One resolver owns the workspace fallback so the target directory, the on-demand
    // build, and the exported-variable precedence cannot diverge between call sites.
    crate::try_luad_binary_path().map_err(BinaryResolutionError::WorkspaceFallbackFailed)
}

/// Create a 512-byte POSIX ustar tar header.
pub fn create_ustar_header(name: &str, mode: u32, size: usize) -> [u8; 512] {
    let mut header = [0u8; 512];

    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len().min(100);
    header[..name_len].copy_from_slice(&name_bytes[..name_len]);

    let mode_str = format!("{mode:07o}\0");
    header[100..108].copy_from_slice(mode_str.as_bytes());

    let uid_str = format!("{:07o}\0", 0);
    header[108..116].copy_from_slice(uid_str.as_bytes());

    let gid_str = format!("{:07o}\0", 0);
    header[116..124].copy_from_slice(gid_str.as_bytes());

    let size_str = format!("{size:011o}\0");
    header[124..136].copy_from_slice(size_str.as_bytes());

    let mtime_str = format!("{:011o}\0", 0);
    header[136..148].copy_from_slice(mtime_str.as_bytes());

    header[156] = b'0';

    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    for b in &mut header[148..156] {
        *b = b' ';
    }
    let sum: u32 = header.iter().map(|&b| b as u32).sum();
    let chksum_str = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(chksum_str.as_bytes());

    header
}

/// Create deterministic gzip bytes using stored DEFLATE blocks.
pub fn create_deterministic_gzip(tar_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tar_bytes.len() + 128);

    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00]);
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0x00, 0xff]);

    if tar_bytes.is_empty() {
        out.push(0x01);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(!0u16).to_le_bytes());
    } else {
        let chunk_size = 32768;
        let chunks: Vec<&[u8]> = tar_bytes.chunks(chunk_size).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let is_final = i + 1 == chunks.len();
            let bfinal_byte = if is_final { 0x01 } else { 0x00 };
            out.push(bfinal_byte);
            let len = chunk.len() as u16;
            let nlen = !len;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&nlen.to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }

    let crc = compute_crc32(tar_bytes);
    out.extend_from_slice(&crc.to_le_bytes());
    let isize = (tar_bytes.len() as u64 % (1u64 << 32)) as u32;
    out.extend_from_slice(&isize.to_le_bytes());

    out
}

/// Decompress deterministic gzip archive.
pub fn decompress_gzip(gzip_bytes: &[u8]) -> Result<Vec<u8>, String> {
    if gzip_bytes.len() < 18 {
        return Err("Gzip archive too short".to_string());
    }
    if gzip_bytes[0..3] != [0x1f, 0x8b, 0x08] {
        return Err("Invalid gzip magic or compression method".to_string());
    }
    let flg = gzip_bytes[3];
    let mtime = u32::from_le_bytes(
        gzip_bytes[4..8]
            .try_into()
            .map_err(|e| format!("read mtime: {e}"))?,
    );
    if mtime != 0 {
        return Err(format!("Gzip mtime must be 0, found {mtime}"));
    }

    let mut pos = 10;
    if flg & 0x04 != 0 {
        if pos + 2 > gzip_bytes.len() {
            return Err("Truncated FEXTRA in gzip header".to_string());
        }
        let xlen = u16::from_le_bytes(
            gzip_bytes[pos..pos + 2]
                .try_into()
                .map_err(|e| format!("read xlen: {e}"))?,
        ) as usize;
        pos += 2 + xlen;
    }
    if flg & 0x08 != 0 {
        while pos < gzip_bytes.len() && gzip_bytes[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flg & 0x10 != 0 {
        while pos < gzip_bytes.len() && gzip_bytes[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flg & 0x02 != 0 {
        pos += 2;
    }

    let mut uncompressed = Vec::new();
    let footer_start = gzip_bytes
        .len()
        .checked_sub(8)
        .ok_or("Missing gzip footer")?;

    while pos < footer_start {
        let header_byte = gzip_bytes[pos];
        let bfinal = (header_byte & 0x01) != 0;
        let btype = (header_byte >> 1) & 0x03;
        pos += 1;

        if btype == 0 {
            if pos + 4 > footer_start {
                return Err("Truncated stored block header".to_string());
            }
            let len = u16::from_le_bytes(
                gzip_bytes[pos..pos + 2]
                    .try_into()
                    .map_err(|e| format!("read len: {e}"))?,
            ) as usize;
            let nlen = u16::from_le_bytes(
                gzip_bytes[pos + 2..pos + 4]
                    .try_into()
                    .map_err(|e| format!("read nlen: {e}"))?,
            ) as usize;
            pos += 4;
            if len != (!nlen as u16 as usize) {
                return Err("Stored block len/nlen mismatch".to_string());
            }
            if pos + len > footer_start {
                return Err("Truncated stored block data".to_string());
            }
            uncompressed.extend_from_slice(&gzip_bytes[pos..pos + len]);
            pos += len;
        } else {
            return Err(format!("Unsupported deflate btype: {btype}"));
        }

        if bfinal {
            break;
        }
    }

    let expected_crc = u32::from_le_bytes(
        gzip_bytes[footer_start..footer_start + 4]
            .try_into()
            .map_err(|e| format!("read crc: {e}"))?,
    );
    let expected_isize = u32::from_le_bytes(
        gzip_bytes[footer_start + 4..footer_start + 8]
            .try_into()
            .map_err(|e| format!("read isize: {e}"))?,
    );

    let actual_crc = compute_crc32(&uncompressed);
    if actual_crc != expected_crc {
        return Err(format!(
            "Gzip CRC32 mismatch: expected {expected_crc:x}, actual {actual_crc:x}"
        ));
    }
    let actual_isize = (uncompressed.len() as u64 % (1u64 << 32)) as u32;
    if actual_isize != expected_isize {
        return Err(format!(
            "Gzip ISIZE mismatch: expected {expected_isize}, actual {actual_isize}"
        ));
    }

    Ok(uncompressed)
}

/// Parsed tar member entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarEntry {
    pub name: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: usize,
    pub mtime: u64,
    pub data: Vec<u8>,
}

fn parse_octal(bytes: &[u8]) -> u64 {
    let s = std::str::from_utf8(bytes)
        .unwrap_or("")
        .trim_matches(&['\0', ' '][..]);
    u64::from_str_radix(s, 8).unwrap_or(0)
}

/// Parse uncompressed ustar tar byte stream.
pub fn parse_tar(tar_bytes: &[u8]) -> Result<Vec<ParsedTarEntry>, String> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while offset + 512 <= tar_bytes.len() {
        let block = &tar_bytes[offset..offset + 512];
        if block.iter().all(|&b| b == 0) {
            break;
        }
        let name = std::str::from_utf8(&block[0..100])
            .unwrap_or("")
            .trim_matches('\0')
            .to_string();
        let mode = parse_octal(&block[100..108]) as u32;
        let uid = parse_octal(&block[108..116]) as u32;
        let gid = parse_octal(&block[116..124]) as u32;
        let size = parse_octal(&block[124..136]) as usize;
        let mtime = parse_octal(&block[136..148]);

        offset += 512;
        if offset + size > tar_bytes.len() {
            return Err(format!("Truncated member data for {name}"));
        }
        let data = tar_bytes[offset..offset + size].to_vec();
        entries.push(ParsedTarEntry {
            name,
            mode,
            uid,
            gid,
            size,
            mtime,
            data,
        });
        let pad = (512 - (size % 512)) % 512;
        offset += size + pad;
    }
    Ok(entries)
}

/// Pack a deterministic archive and ledger.
pub fn pack_candidate(
    spec_path: &Path,
    binary_path: &Path,
    license_path: &Path,
    version_path: &Path,
    out_archive: &Path,
    out_ledger: &Path,
) -> Result<(), String> {
    let spec_bytes = fs::read(spec_path)
        .map_err(|e| format!("Failed to read spec file '{spec_path:?}': {e}"))?;
    let binary_bytes = fs::read(binary_path)
        .map_err(|e| format!("Failed to read binary file '{binary_path:?}': {e}"))?;
    let license_bytes = fs::read(license_path)
        .map_err(|e| format!("Failed to read license file '{license_path:?}': {e}"))?;
    let version_bytes = fs::read(version_path)
        .map_err(|e| format!("Failed to read version file '{version_path:?}': {e}"))?;

    let members = [
        ("CANDIDATE.json", 420u32, &spec_bytes),
        ("LICENSE", 420u32, &license_bytes),
        ("VERSION.json", 420u32, &version_bytes),
        ("bin/luad", 493u32, &binary_bytes),
    ];

    let mut tar_bytes = Vec::new();
    let mut ledger_members = Vec::new();

    for (name, mode, data) in members {
        let header = create_ustar_header(name, mode, data.len());
        tar_bytes.extend_from_slice(&header);
        tar_bytes.extend_from_slice(data);
        let pad = (512 - (data.len() % 512)) % 512;
        tar_bytes.extend(std::iter::repeat_n(0u8, pad));

        ledger_members.push(MemberLedgerEntry {
            path: name.to_string(),
            mode,
            uid: 0,
            gid: 0,
            mtime: 0,
            size: data.len(),
            sha256: sha256_digest(data),
        });
    }

    tar_bytes.extend(std::iter::repeat_n(0u8, 1024));

    let gzip_bytes = create_deterministic_gzip(&tar_bytes);

    if let Some(p) = out_archive.parent() {
        fs::create_dir_all(p).map_err(|e| format!("Create archive dir: {e}"))?;
    }
    fs::write(out_archive, gzip_bytes).map_err(|e| format!("Write archive: {e}"))?;

    let ledger = MemberLedger {
        members: ledger_members,
    };
    let ledger_json =
        serde_json::to_vec_pretty(&ledger).map_err(|e| format!("Serialize ledger JSON: {e}"))?;

    if let Some(p) = out_ledger.parent() {
        fs::create_dir_all(p).map_err(|e| format!("Create ledger dir: {e}"))?;
    }
    fs::write(out_ledger, ledger_json).map_err(|e| format!("Write ledger: {e}"))?;

    Ok(())
}

/// Verify a platform attestation against candidate specification and archive bytes.
pub fn verify_platform_attestation(
    spec_path: &Path,
    attestation_path: &Path,
    archive_path: &Path,
) -> Result<(), String> {
    let spec_bytes = fs::read(spec_path)
        .map_err(|e| format!("Failed to read candidate spec '{spec_path:?}': {e}"))?;
    let canonical_spec_hash = sha256_digest(&spec_bytes);
    let spec: CandidateSpec = serde_json::from_slice(&spec_bytes)
        .map_err(|e| format!("Failed to parse candidate spec JSON: {e}"))?;

    let att_bytes = fs::read(attestation_path)
        .map_err(|e| format!("Failed to read attestation file '{attestation_path:?}': {e}"))?;
    let att: PlatformAttestation = serde_json::from_slice(&att_bytes)
        .map_err(|e| format!("Failed to parse platform attestation JSON: {e}"))?;

    if att.schema_version != 1 {
        return Err(format!(
            "Unsupported schema_version: expected 1, got {}",
            att.schema_version
        ));
    }
    if att.candidate_id != spec.candidate_id {
        return Err(format!(
            "candidate_id mismatch: expected '{}', got '{}'",
            spec.candidate_id, att.candidate_id
        ));
    }

    if att.dirty {
        return Err("Attestation source tree is marked dirty".to_string());
    }

    if att.git_commit.trim().is_empty() {
        return Err("Attestation git_commit must be a nonempty commit hash".to_string());
    }

    if att.spec_hash != canonical_spec_hash {
        return Err(format!(
            "spec_hash mismatch: expected {canonical_spec_hash}, got {}",
            att.spec_hash
        ));
    }

    let req_plat = spec
        .required_platforms
        .iter()
        .find(|p| p.platform_id == att.platform)
        .ok_or_else(|| format!("unsupported platform '{}'", att.platform))?;

    if att.os != req_plat.os {
        return Err(format!(
            "operating system mismatch for platform '{}': expected {}, got {}",
            att.platform, req_plat.os, att.os
        ));
    }

    if att.arch != req_plat.arch {
        return Err(format!(
            "architecture mismatch for platform '{}': expected {}, got {}",
            att.platform, req_plat.arch, att.arch
        ));
    }

    if att.target_triple != req_plat.target_triple {
        return Err(format!(
            "target_triple mismatch for platform '{}': expected {}, got {}",
            att.platform, req_plat.target_triple, att.target_triple
        ));
    }

    if att.build_host.trim().is_empty() {
        return Err("missing build_host identity".to_string());
    }

    if att.toolchain.trim().is_empty() {
        return Err("missing toolchain identity".to_string());
    }

    if !att.aggregate_check_success {
        return Err("aggregate check failed".to_string());
    }

    if att.target.profile != spec.target.profile {
        return Err(format!(
            "target profile mismatch: expected {}, got {}",
            spec.target.profile, att.target.profile
        ));
    }
    if att.target.layout != spec.target.layout {
        return Err(format!(
            "target layout mismatch: expected {}, got {}",
            spec.target.layout, att.target.layout
        ));
    }
    if att.target.dialect != spec.target.dialect {
        return Err(format!(
            "target dialect mismatch: expected {}, got {}",
            spec.target.dialect, att.target.dialect
        ));
    }
    if att.target.patch_version != spec.target.patch_version {
        return Err(format!(
            "target patch_version mismatch: expected {}, got {}",
            spec.target.patch_version, att.target.patch_version
        ));
    }

    let archive_bytes = fs::read(archive_path)
        .map_err(|e| format!("Failed to read archive file '{archive_path:?}': {e}"))?;
    let actual_archive_sha = sha256_digest(&archive_bytes);
    if actual_archive_sha != att.archive_sha256 {
        return Err(format!(
            "archive SHA-256 mismatch: archive={actual_archive_sha}, attestation={}",
            att.archive_sha256
        ));
    }

    let decompressed = decompress_gzip(&archive_bytes)
        .map_err(|e| format!("Failed to decompress archive: {e}"))?;
    let tar_members =
        parse_tar(&decompressed).map_err(|e| format!("Failed to parse tar archive: {e}"))?;

    if att.member_ledger.len() != 4 {
        return Err(format!(
            "missing member in ledger: expected 4, got {}",
            att.member_ledger.len()
        ));
    }
    if tar_members.len() != 4 {
        return Err(format!(
            "archive member count mismatch: expected 4, got {}",
            tar_members.len()
        ));
    }

    for i in 0..att.member_ledger.len().saturating_sub(1) {
        if att.member_ledger[i].path >= att.member_ledger[i + 1].path {
            return Err(format!(
                "out of order member ledger: {} >= {}",
                att.member_ledger[i].path,
                att.member_ledger[i + 1].path
            ));
        }
    }

    let required_member_paths = ["CANDIDATE.json", "LICENSE", "VERSION.json", "bin/luad"];
    for ((lm, tm), required_path) in att
        .member_ledger
        .iter()
        .zip(tar_members.iter())
        .zip(required_member_paths)
    {
        if lm.path != required_path {
            return Err(format!(
                "unexpected archive member: expected {required_path}, got {}",
                lm.path
            ));
        }
        if lm.path != tm.name {
            return Err(format!(
                "member path mismatch: ledger={}, tar={}",
                lm.path, tm.name
            ));
        }
        let exp_mode = if lm.path == "bin/luad" {
            spec.archive_policy.executable_mode
        } else {
            spec.archive_policy.file_mode
        };
        if lm.mode != exp_mode {
            return Err(format!(
                "wrong member permission mode for '{}': expected {}, got {}",
                lm.path, exp_mode, lm.mode
            ));
        }
        if tm.mode != exp_mode {
            return Err(format!(
                "wrong tar member permission mode for '{}': expected {}, got {}",
                tm.name, exp_mode, tm.mode
            ));
        }
        if lm.uid != spec.archive_policy.uid || tm.uid != spec.archive_policy.uid {
            return Err(format!(
                "wrong uid for '{}': expected {}, ledger={}, tar={}",
                lm.path, spec.archive_policy.uid, lm.uid, tm.uid
            ));
        }
        if lm.gid != spec.archive_policy.gid || tm.gid != spec.archive_policy.gid {
            return Err(format!(
                "wrong gid for '{}': expected {}, ledger={}, tar={}",
                lm.path, spec.archive_policy.gid, lm.gid, tm.gid
            ));
        }
        if lm.mtime != spec.archive_policy.mtime || tm.mtime != spec.archive_policy.mtime {
            return Err(format!(
                "wrong mtime for '{}': expected {}, ledger={}, tar={}",
                lm.path, spec.archive_policy.mtime, lm.mtime, tm.mtime
            ));
        }
        if lm.size != tm.size || tm.size != tm.data.len() {
            return Err(format!(
                "wrong size for '{}': ledger={}, tar={}, data={}",
                lm.path,
                lm.size,
                tm.size,
                tm.data.len()
            ));
        }
        let actual_member_sha = sha256_digest(&tm.data);
        if lm.sha256 != actual_member_sha {
            return Err(format!(
                "tampered member ledger spec hash for '{}': ledger={}, actual={}",
                lm.path, lm.sha256, actual_member_sha
            ));
        }
    }

    let bin_tar_entry = tar_members
        .iter()
        .find(|m| m.name == "bin/luad")
        .ok_or("missing binary member in archive")?;
    let bin_sha = sha256_digest(&bin_tar_entry.data);
    if bin_sha != att.binary_sha256 {
        return Err(format!(
            "binary SHA-256 mismatch: tar={bin_sha}, attestation={}",
            att.binary_sha256
        ));
    }

    let cand_tar_entry = tar_members
        .iter()
        .find(|m| m.name == "CANDIDATE.json")
        .ok_or("missing CANDIDATE.json in archive")?;
    let archived_spec_sha = sha256_digest(&cand_tar_entry.data);
    if archived_spec_sha != att.spec_hash || archived_spec_sha != canonical_spec_hash {
        return Err(format!(
            "Three-way spec check failed: archived={archived_spec_sha}, attested={}, canonical={canonical_spec_hash}",
            att.spec_hash
        ));
    }

    for res in &att.prerequisite_results {
        if res.gate_id.contains("candidate") || res.gate_id == spec.candidate_id {
            return Err(format!(
                "self inclusion of candidate gate '{}' in prerequisites",
                res.gate_id
            ));
        }
    }

    if att.prerequisite_results.len() != spec.required_prerequisites.len() {
        return Err(format!(
            "missing prerequisite gate: expected {}, got {}",
            spec.required_prerequisites.len(),
            att.prerequisite_results.len()
        ));
    }

    for req in &spec.required_prerequisites {
        let res = att
            .prerequisite_results
            .iter()
            .find(|r| r.gate_id == req.gate_id)
            .ok_or_else(|| format!("missing prerequisite gate '{}'", req.gate_id))?;

        if res.spec_hash != req.file_sha256 {
            return Err(format!(
                "prerequisite '{}' spec_hash mismatch: expected {}, got {}",
                req.gate_id, req.file_sha256, res.spec_hash
            ));
        }

        if res.result_sha256.trim().is_empty()
            || res.result_sha256
                == "0000000000000000000000000000000000000000000000000000000000000000"
        {
            return Err(format!(
                "prerequisite '{}' invalid result_sha256 '{}'",
                req.gate_id, res.result_sha256
            ));
        }

        if res.ignored_count > 0 {
            return Err(format!(
                "prerequisite '{}' has ignored tests: count={}",
                req.gate_id, res.ignored_count
            ));
        }

        if !res.missing_expected_tests.is_empty() {
            return Err(format!(
                "prerequisite '{}' has missing_expected_tests: {:?}",
                req.gate_id, res.missing_expected_tests
            ));
        }

        if res.failed_count > 0 || res.exit_code != 0 || !res.success {
            return Err(format!(
                "prerequisite '{}' has failed tests: count={}, exit={}",
                req.gate_id, res.failed_count, res.exit_code
            ));
        }
    }

    Ok(())
}

fn artifact_path(artifact_root: &Path, name: &str) -> Result<PathBuf, String> {
    let path = Path::new(name);
    let mut components = path.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(format!("artifact path must be one file name: '{name}'"));
    }
    Ok(artifact_root.join(path))
}

fn artifact_entry_from_attestation(
    att: PlatformAttestation,
    attestation_name: String,
    attestation_sha256: String,
) -> PlatformArtifactEntry {
    let archive_path = att
        .archive_path
        .clone()
        .unwrap_or_else(|| format!("luad-{}.tar.gz", att.platform));
    PlatformArtifactEntry {
        platform: att.platform,
        os: att.os,
        arch: att.arch,
        target_triple: att.target_triple,
        toolchain: att.toolchain,
        build_host: att.build_host,
        git_commit: att.git_commit,
        spec_hash: att.spec_hash,
        archive_path,
        archive_sha256: att.archive_sha256,
        binary_sha256: att.binary_sha256,
        attestation_path: Some(attestation_name),
        attestation_sha256: Some(attestation_sha256),
        member_ledger: att.member_ledger,
        prerequisite_results: att.prerequisite_results,
        aggregate_check_success: att.aggregate_check_success,
    }
}

/// Assemble multi-platform candidate evidence index.
pub fn assemble_evidence_index(
    spec_path: &Path,
    artifact_root: &Path,
    attestation_paths: &[PathBuf],
    out_index: &Path,
) -> Result<(), String> {
    let spec_bytes = fs::read(spec_path)
        .map_err(|e| format!("Failed to read candidate spec '{spec_path:?}': {e}"))?;
    let canonical_spec_hash = sha256_digest(&spec_bytes);
    let spec: CandidateSpec = serde_json::from_slice(&spec_bytes)
        .map_err(|e| format!("Failed to parse candidate spec JSON: {e}"))?;

    let mut artifacts = Vec::new();
    let mut root_commit: Option<String> = None;

    for att_path in attestation_paths {
        let att_bytes = fs::read(att_path)
            .map_err(|e| format!("Failed to read attestation '{att_path:?}': {e}"))?;
        let att: PlatformAttestation = serde_json::from_slice(&att_bytes)
            .map_err(|e| format!("Failed to parse attestation '{att_path:?}': {e}"))?;

        if let Some(ref c) = root_commit {
            if &att.git_commit != c {
                return Err(format!(
                    "mismatched git commit across platforms: {c} vs {}",
                    att.git_commit
                ));
            }
        } else {
            root_commit = Some(att.git_commit.clone());
        }

        let arc_name = att
            .archive_path
            .clone()
            .unwrap_or_else(|| format!("luad-{}.tar.gz", att.platform));
        let att_name = att_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("attestation-{}.json", att.platform));

        let archive_path = artifact_path(artifact_root, &arc_name)?;
        verify_platform_attestation(spec_path, att_path, &archive_path).map_err(|error| {
            format!(
                "platform attestation '{}' failed verification: {error}",
                att.platform
            )
        })?;

        artifacts.push(artifact_entry_from_attestation(
            att,
            att_name,
            sha256_digest(&att_bytes),
        ));
    }

    artifacts.sort_by(|a, b| a.platform.cmp(&b.platform));

    let index = EvidenceIndex {
        schema_version: 1,
        candidate_id: spec.candidate_id,
        spec_hash: canonical_spec_hash,
        git_commit: root_commit.unwrap_or_default(),
        artifacts,
    };

    if let Some(p) = out_index.parent() {
        fs::create_dir_all(p).map_err(|e| format!("Create index dir: {e}"))?;
    }
    let json_bytes = serde_json::to_vec_pretty(&index)
        .map_err(|e| format!("Serialize evidence index JSON: {e}"))?;
    fs::write(out_index, json_bytes).map_err(|e| format!("Write evidence index: {e}"))?;

    Ok(())
}

/// Verify multi-platform evidence index.
pub fn verify_evidence_index(
    spec_path: &Path,
    artifact_root: &Path,
    index_path: &Path,
) -> Result<(), String> {
    let spec_bytes = fs::read(spec_path)
        .map_err(|e| format!("Failed to read candidate spec '{spec_path:?}': {e}"))?;
    let canonical_spec_hash = sha256_digest(&spec_bytes);
    let spec: CandidateSpec = serde_json::from_slice(&spec_bytes)
        .map_err(|e| format!("Failed to parse candidate spec JSON: {e}"))?;

    let index_bytes = fs::read(index_path)
        .map_err(|e| format!("Failed to read evidence index '{index_path:?}': {e}"))?;
    let index: EvidenceIndex = serde_json::from_slice(&index_bytes)
        .map_err(|e| format!("Failed to parse evidence index JSON: {e}"))?;

    if index.schema_version != 1 {
        return Err(format!(
            "Unsupported index schema_version: expected 1, got {}",
            index.schema_version
        ));
    }

    if index.candidate_id != spec.candidate_id {
        return Err(format!(
            "candidate_id mismatch: expected '{}', got '{}'",
            spec.candidate_id, index.candidate_id
        ));
    }

    if index.spec_hash != canonical_spec_hash {
        return Err(format!(
            "spec_hash mismatch: expected {canonical_spec_hash}, got {}",
            index.spec_hash
        ));
    }

    if index.git_commit.trim().is_empty() {
        return Err("missing git commit in evidence index".to_string());
    }

    if index.artifacts.len() != spec.required_platforms.len() {
        return Err(format!(
            "missing platform in index: expected {}, got {}",
            spec.required_platforms.len(),
            index.artifacts.len()
        ));
    }

    let mut seen_plats = HashSet::new();
    let mut seen_bin_shas = HashSet::new();

    for art in &index.artifacts {
        if !seen_plats.insert(&art.platform) {
            return Err(format!("duplicate platform '{}' in index", art.platform));
        }

        if !spec
            .required_platforms
            .iter()
            .any(|p| p.platform_id == art.platform)
        {
            return Err(format!(
                "unknown extra platform '{}' in index",
                art.platform
            ));
        }

        if art.git_commit != index.git_commit {
            return Err(format!(
                "mismatched git commit across platforms: index={}, platform {}={}",
                index.git_commit, art.platform, art.git_commit
            ));
        }

        if art.spec_hash != canonical_spec_hash {
            return Err(format!(
                "mismatched spec_hash across platforms for {}: expected {canonical_spec_hash}, got {}",
                art.platform, art.spec_hash
            ));
        }

        if !seen_bin_shas.insert(&art.binary_sha256) {
            return Err(format!(
                "identical binary_sha256 '{}' across distinct platforms",
                art.binary_sha256
            ));
        }

        let att_name = art
            .attestation_path
            .as_deref()
            .ok_or_else(|| format!("missing attestation path for {}", art.platform))?;
        let att_file = artifact_path(artifact_root, att_name)?;
        if !att_file.exists() {
            return Err(format!("missing sidecar attestation file: {:?}", att_file));
        }

        let att_bytes = fs::read(&att_file)
            .map_err(|e| format!("Failed to read attestation '{att_file:?}': {e}"))?;
        let actual_attestation_sha = sha256_digest(&att_bytes);
        let indexed_attestation_sha = art
            .attestation_sha256
            .as_deref()
            .ok_or_else(|| format!("missing attestation SHA-256 for {}", art.platform))?;
        if actual_attestation_sha != indexed_attestation_sha {
            return Err(format!(
                "attestation SHA-256 mismatch for {}: actual={}, index={}",
                art.platform, actual_attestation_sha, indexed_attestation_sha
            ));
        }

        let att: PlatformAttestation = serde_json::from_slice(&att_bytes)
            .map_err(|e| format!("Failed to parse attestation '{att_file:?}': {e}"))?;
        let arc_file = artifact_path(artifact_root, &art.archive_path)?;
        if !arc_file.exists() {
            return Err(format!("missing archive file: {:?}", arc_file));
        }
        let arc_bytes = fs::read(&arc_file)
            .map_err(|e| format!("Failed to read archive '{arc_file:?}': {e}"))?;
        let actual_arc_sha = sha256_digest(&arc_bytes);
        if actual_arc_sha != art.archive_sha256 {
            return Err(format!(
                "tampered archive hash in index for {}: actual={}, index={}",
                art.platform, actual_arc_sha, art.archive_sha256
            ));
        }

        let expected_entry =
            artifact_entry_from_attestation(att, att_name.to_string(), actual_attestation_sha);
        if &expected_entry != art {
            return Err(format!(
                "evidence index entry does not match sidecar for {}",
                art.platform
            ));
        }

        verify_platform_attestation(spec_path, &att_file, &arc_file).map_err(|error| {
            format!(
                "platform attestation '{}' failed verification: {error}",
                art.platform
            )
        })?;
    }

    Ok(())
}

/// Execute checked analysis transcript against the selected binary and fixture.
pub fn execute_checked_transcript(
    spec_path: &Path,
    fixture_path: &Path,
) -> Result<TranscriptDoc, String> {
    let spec_bytes = fs::read(spec_path)
        .map_err(|e| format!("Failed to read candidate spec '{spec_path:?}': {e}"))?;
    let spec: CandidateSpec = serde_json::from_slice(&spec_bytes)
        .map_err(|e| format!("Failed to parse candidate spec JSON: {e}"))?;

    let bin_path = resolve_test_binary().map_err(|e| e.to_string())?;
    let bin_bytes =
        fs::read(&bin_path).map_err(|e| format!("Failed to read binary '{bin_path:?}': {e}"))?;
    let selected_binary_sha256 = sha256_digest(&bin_bytes);

    let fixture_bytes = fs::read(fixture_path)
        .map_err(|e| format!("Failed to read fixture '{fixture_path:?}': {e}"))?;
    let input_fixture_sha256 = sha256_digest(&fixture_bytes);

    let fixture_str = fixture_path.to_str().ok_or("Invalid fixture path string")?;

    let mut workflows = BTreeMap::new();

    // 1. inspect
    let inspect_out = Command::new(&bin_path)
        .args(["inspect", fixture_str, "--format", "json"])
        .output()
        .map_err(|e| format!("Execute inspect: {e}"))?;
    if !inspect_out.status.success() {
        return Err(format!(
            "Inspect workflow failed: {}",
            String::from_utf8_lossy(&inspect_out.stderr)
        ));
    }
    let inspect_val: serde_json::Value = serde_json::from_slice(&inspect_out.stdout)
        .map_err(|e| format!("Parse inspect JSON: {e}"))?;
    workflows.insert(
        "inspect".to_string(),
        WorkflowTranscript {
            status: "ok".to_string(),
            evidence: inspect_val,
        },
    );

    // 2. validate
    let validate_out = Command::new(&bin_path)
        .args(["validate", fixture_str, "--format", "json"])
        .output()
        .map_err(|e| format!("Execute validate: {e}"))?;
    if !validate_out.status.success() {
        return Err(format!(
            "Validate workflow failed: {}",
            String::from_utf8_lossy(&validate_out.stderr)
        ));
    }
    let validate_val: serde_json::Value = serde_json::from_slice(&validate_out.stdout)
        .map_err(|e| format!("Parse validate JSON: {e}"))?;
    workflows.insert(
        "validate".to_string(),
        WorkflowTranscript {
            status: "ok".to_string(),
            evidence: validate_val,
        },
    );

    // 3. disasm
    let disasm_out = Command::new(&bin_path)
        .args(["disasm", fixture_str, "--format", "json"])
        .output()
        .map_err(|e| format!("Execute disasm: {e}"))?;
    if !disasm_out.status.success() {
        return Err(format!(
            "Disasm workflow failed: {}",
            String::from_utf8_lossy(&disasm_out.stderr)
        ));
    }
    let disasm_val: serde_json::Value = serde_json::from_slice(&disasm_out.stdout)
        .map_err(|e| format!("Parse disasm JSON: {e}"))?;
    workflows.insert(
        "disasm".to_string(),
        WorkflowTranscript {
            status: "ok".to_string(),
            evidence: disasm_val,
        },
    );

    // 4. query
    let query_out = Command::new(&bin_path)
        .args(["query", fixture_str, "--format", "json"])
        .output()
        .map_err(|e| format!("Execute query: {e}"))?;
    if !query_out.status.success() {
        return Err(format!(
            "Query workflow failed: {}",
            String::from_utf8_lossy(&query_out.stderr)
        ));
    }
    let query_val: serde_json::Value =
        serde_json::from_slice(&query_out.stdout).map_err(|e| format!("Parse query JSON: {e}"))?;
    workflows.insert(
        "query".to_string(),
        WorkflowTranscript {
            status: "ok".to_string(),
            evidence: query_val,
        },
    );

    // 5. xrefs
    let xrefs_out = Command::new(&bin_path)
        .args(["xrefs", fixture_str, "--format", "json"])
        .output()
        .map_err(|e| format!("Execute xrefs: {e}"))?;
    if !xrefs_out.status.success() {
        return Err(format!(
            "Xrefs workflow failed: {}",
            String::from_utf8_lossy(&xrefs_out.stderr)
        ));
    }
    let xrefs_val: serde_json::Value =
        serde_json::from_slice(&xrefs_out.stdout).map_err(|e| format!("Parse xrefs JSON: {e}"))?;
    workflows.insert(
        "xrefs".to_string(),
        WorkflowTranscript {
            status: "ok".to_string(),
            evidence: xrefs_val,
        },
    );

    // 6. export
    let export_out = Command::new(&bin_path)
        .args(["export", fixture_str, "--format", "jsonl"])
        .output()
        .map_err(|e| format!("Execute export: {e}"))?;
    if !export_out.status.success() {
        return Err(format!(
            "Export workflow failed: {}",
            String::from_utf8_lossy(&export_out.stderr)
        ));
    }
    let export_lines_str = String::from_utf8_lossy(&export_out.stdout);
    let mut export_records = Vec::new();
    for line in export_lines_str.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let record: serde_json::Value = serde_json::from_str(trimmed)
                .map_err(|e| format!("Parse export JSONL line: {e}"))?;
            export_records.push(record);
        }
    }
    if export_records.is_empty() {
        return Err("Export emitted zero JSONL records".to_string());
    }
    workflows.insert(
        "export".to_string(),
        WorkflowTranscript {
            status: "ok".to_string(),
            evidence: serde_json::Value::Array(export_records),
        },
    );

    Ok(TranscriptDoc {
        selected_binary_sha256,
        input_fixture_sha256,
        profile: spec.target.profile,
        layout: spec.target.layout,
        workflows,
    })
}
