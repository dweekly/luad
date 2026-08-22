//! Dialect trait and format detection architecture.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::diagnostic::Diagnostic;
use crate::model::Chunk;
use crate::provenance::Confidence;
use crate::reader::SafeReader;

/// Format detection outcome with confidence and supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetectionResult {
    /// Identified dialect name (e.g. "lua5.4").
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
