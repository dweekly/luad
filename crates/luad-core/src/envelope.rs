//! Machine interface document envelope and JSONL streaming records.
//!
//! Provides the generic `MachineDocument<T>` envelope for all machine-readable CLI responses,
//! ensuring consistent versioning, provenance identity, dialect interpretation, analysis configuration,
//! and diagnostics across all commands.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::diagnostic::{Diagnostic, Verdict};
use crate::dialect::ResolvedInterpretation;
use crate::limits::{ParseMode, ResourceLimits};

/// Identity and provenance metadata for an analyzed input artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InputIdentity {
    /// File path or source identifier (e.g. "hello.luac" or "`<stdin>`").
    pub path: String,
    /// SHA-256 hash of the complete input byte stream.
    pub sha256: String,
    /// Total byte length of the input.
    pub byte_length: usize,
}

/// Analysis and execution configuration used to produce the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisConfiguration {
    /// Parser mode (e.g. "strict" or "permissive").
    pub mode: ParseMode,
    /// Resource limit thresholds applied during parsing and analysis.
    pub limits: ResourceLimits,
    /// Explicit dialect or profile override requested by caller, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dialect_override: Option<String>,
}

/// Generic machine document envelope wrapping all top-level machine outputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MachineDocument<T> {
    /// Schema major version (pinned to 1).
    pub schema_version: u32,
    /// Tool semver version (e.g. "0.1.0").
    pub tool_version: String,
    /// Provenance identity of the analyzed input.
    pub input_identity: InputIdentity,
    /// Resolved dialect, profile, layout, and selection evidence.
    pub interpretation: ResolvedInterpretation,
    /// Analysis configuration applied.
    pub analysis_configuration: AnalysisConfiguration,
    /// Command-specific payload data.
    pub data: T,
    /// Structured diagnostics emitted during processing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

/// Structured response payload for the `validate` command.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationResponse {
    /// Overall validity verdict.
    pub verdict: Verdict,
    /// Total number of diagnostics.
    pub diagnostic_count: usize,
    /// Structured diagnostics list.
    pub diagnostics: Vec<Diagnostic>,
}

/// JSONL streaming metadata prologue record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JsonlMetadataRecord {
    /// Discriminator: "metadata".
    pub record_type: String,
    /// Schema major version.
    pub schema_version: u32,
    /// Tool semver version.
    pub tool_version: String,
    /// Provenance identity of the analyzed input.
    pub input_identity: InputIdentity,
    /// Resolved interpretation.
    pub interpretation: ResolvedInterpretation,
    /// Applied configuration.
    pub analysis_configuration: AnalysisConfiguration,
}

/// JSONL streaming typed item record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JsonlDataRecord<T> {
    /// Discriminator (e.g. "instruction", "prototype", "xref", "diagnostic").
    pub record_type: String,
    /// Item payload.
    pub data: T,
}

/// JSONL streaming summary epilogue record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct JsonlSummaryRecord {
    /// Discriminator: "summary".
    pub record_type: String,
    /// Total records emitted in stream.
    pub total_records: usize,
    /// Total diagnostics recorded.
    pub diagnostic_count: usize,
    /// Whether the output was truncated by pagination/limits.
    pub is_truncated: bool,
}

/// JSONL batch export start record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExportStartRecord {
    pub record_type: String,
    pub tool_version: String,
    pub total_files: usize,
}

/// JSONL batch export end record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ExportEndRecord {
    pub record_type: String,
    pub files_processed: usize,
    pub files_succeeded: usize,
    pub files_failed: usize,
    pub total_instructions: usize,
}

/// JSONL batch export per-file start record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FileStartRecord {
    pub record_type: String,
    pub path: String,
    pub sha256: String,
    pub byte_length: usize,
    pub interpretation: Option<ResolvedInterpretation>,
}

/// JSONL batch export per-file end record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FileEndRecord {
    pub record_type: String,
    pub path: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub instruction_count: usize,
    pub diagnostic_count: usize,
}
