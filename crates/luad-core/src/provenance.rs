//! Provenance records and confidence taxonomy.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::id::StableId;

/// Confidence level of an analysis fact or artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Directly parsed fact from raw input bytes (ground truth).
    #[default]
    Fact,
    /// Derived mathematically or structurally through deterministic rule/analysis (e.g. CFG edge, use-def set).
    Derived,
    /// Inferred using heuristics or pattern matching (e.g. loop structure, high-level expression reconstruction).
    Heuristic,
}

/// Source byte location and raw byte representation of a field or instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SourceLocation {
    /// Absolute byte offset in the input chunk.
    pub byte_offset: usize,
    /// Encoded length in bytes.
    pub byte_length: usize,
    /// Lowercase hex encoding of the raw bytes.
    pub raw_hex: String,
}

impl SourceLocation {
    /// Create a source location from byte offset and raw bytes slice.
    #[must_use]
    pub fn new(byte_offset: usize, bytes: &[u8]) -> Self {
        Self {
            byte_offset,
            byte_length: bytes.len(),
            raw_hex: hex::encode(bytes),
        }
    }
}

/// Complete provenance record for an artifact in the analyzed chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProvenanceRecord {
    /// Deterministic stable ID.
    pub id: StableId,
    /// Artifact kind (e.g. "header", "prototype", "instruction", "constant", "upvalue", "block").
    pub kind: String,
    /// Confidence tier.
    pub confidence: Confidence,
    /// Source location in raw input if directly parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    /// Precursor stable IDs from which this artifact was computed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<StableId>,
    /// Associated diagnostic stable IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostic_ids: Vec<StableId>,
}
