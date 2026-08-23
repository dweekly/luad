//! Dialect trait and format detection architecture.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::diagnostic::Diagnostic;
use crate::model::Chunk;
use crate::provenance::Confidence;
use crate::reader::SafeReader;

/// Selection mode for dialect and profile resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SelectionMode {
    /// Dialect / profile was automatically detected from bytecode header.
    Detected,
    /// Dialect / profile was explicitly selected via CLI option or API.
    Explicit,
}

/// Resolved interpretation record capturing base dialect, vendor profile, layout, and selection evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedInterpretation {
    /// Base Lua language dialect (e.g. "lua5.1", "lua5.4").
    pub base_dialect: String,
    /// Patch or vendor variant if applicable (e.g. "lnum32").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_or_oracle_version: Option<String>,
    /// Exact resolved profile identifier (e.g. "lua5.1", "lua5.1-lnum32").
    pub profile: String,
    /// Specific profile version or cryptographic specification hash if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_version_or_hash: Option<String>,
    /// Summary of validated architectural layout widths and byte order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated_layout: Option<String>,
    /// Parse mode ("strict" or "permissive").
    pub parse_mode: String,
    /// How the profile was selected.
    pub selection_mode: SelectionMode,
    /// Human-readable evidence explaining why this dialect/profile was resolved.
    pub detection_evidence: String,
}

/// Format detection outcome with confidence and supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetectionResult {
    /// Identified dialect name (e.g. "lua5.4", "lua5.1-lnum32").
    pub dialect: String,
    /// Confidence tier.
    pub confidence: Confidence,
    /// Human-readable explanation of the detected features.
    pub evidence: String,
}

/// Abstract trait implemented by each Lua bytecode dialect/version family.
pub trait Dialect: Send + Sync {
    /// Canonical dialect name (e.g. "lua5.4", "lua5.5", "lua5.1").
    fn name(&self) -> &'static str;

    /// Dialect description.
    fn description(&self) -> &'static str;

    /// Inspect header bytes and return detection confidence if recognized.
    fn detect(&self, bytes: &[u8]) -> Option<DetectionResult>;

    /// Parse a complete chunk from a SafeReader.
    fn decode_chunk(&self, reader: &mut SafeReader) -> Result<Chunk, Diagnostic>;
}
