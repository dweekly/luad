//! Single source of truth for dialect capabilities and tool metadata.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Support tier for a dialect or feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SupportTier {
    /// Dialect is planned on roadmap but not yet implemented.
    Planned,
    /// Dialect implementation is present but proof gates are incomplete.
    Experimental,
    /// All required evidence and differential oracle gates pass.
    Supported,
}

impl std::fmt::Display for SupportTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Planned => write!(f, "planned"),
            Self::Experimental => write!(f, "experimental"),
            Self::Supported => write!(f, "supported"),
        }
    }
}

/// Detailed metadata for a supported or planned bytecode dialect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DialectCapability {
    /// Canonical identifier (e.g. "lua5.4").
    pub id: String,
    /// Human-readable title and version span.
    pub display_name: String,
    /// Number of verified opcodes in the instruction set table.
    pub opcode_count: usize,
    /// Feature capabilities supported by luad for this dialect.
    pub features: Vec<String>,
    /// Support tier: planned, experimental, supported.
    pub status: SupportTier,
    /// Required evidence gates needed before becoming `supported`.
    pub required_gates: Vec<String>,
    /// Completed and verified evidence gates.
    pub completed_gates: Vec<String>,
    /// Provenance evidence backing the dialect claims.
    pub evidence: Vec<String>,
}

/// Global tool capability manifest serialized across text and JSON interfaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapabilityManifest {
    /// Tool name.
    pub tool_name: String,
    /// Tool semver version.
    pub tool_version: String,
    /// Schema major version.
    pub schema_version: u32,
    /// List of dialect identifiers currently in `supported` tier (empty until full release gates pass).
    pub supported_dialects: Vec<String>,
    /// List of dialect identifiers currently in `experimental` tier.
    pub experimental_dialects: Vec<String>,
    /// List of dialect identifiers currently in `planned` tier.
    pub planned_dialects: Vec<String>,
    /// Full capabilities by dialect.
    pub dialects: Vec<DialectCapability>,
    /// Verification and evidence claims.
    pub evidence: Vec<String>,
}

/// Generate the canonical capabilities manifest for `luad`.
#[must_use]
pub fn get_canonical_capabilities(tool_version: &str) -> CapabilityManifest {
    let standard_required_gates = vec![
        "gate-facts".to_string(),
        "gate-oracle-negative-controls".to_string(),
        "gate-lossless".to_string(),
        "gate-analysis-cfg".to_string(),
    ];

    let dialects = vec![
        DialectCapability {
            id: "lua5.1".to_string(),
            display_name: "Lua 5.1.0 - 5.1.5".to_string(),
            opcode_count: 38,
            features: vec![
                "lossless parse".to_string(),
                "32-bit/64-bit size_t support".to_string(),
                "LNUM integer constants".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
                "CFG".to_string(),
                "xrefs".to_string(),
                "diff".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: standard_required_gates.clone(),
            completed_gates: vec![],
            evidence: vec![
                "38/38 opcode table coverage; differential oracle in progress".to_string(),
            ],
        },
        DialectCapability {
            id: "lua5.2".to_string(),
            display_name: "Lua 5.2.0 - 5.2.4".to_string(),
            opcode_count: 40,
            features: vec![
                "lossless parse".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
                "CFG".to_string(),
                "xrefs".to_string(),
                "diff".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: standard_required_gates.clone(),
            completed_gates: vec![],
            evidence: vec![
                "40/40 opcode table coverage; differential oracle in progress".to_string(),
            ],
        },
        DialectCapability {
            id: "lua5.3".to_string(),
            display_name: "Lua 5.3.0 - 5.3.6".to_string(),
            opcode_count: 47,
            features: vec![
                "lossless parse".to_string(),
                "direct integer lineinfo".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
                "CFG".to_string(),
                "xrefs".to_string(),
                "diff".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: standard_required_gates.clone(),
            completed_gates: vec![],
            evidence: vec![
                "47/47 opcode table coverage; differential oracle in progress".to_string(),
            ],
        },
        DialectCapability {
            id: "lua5.4".to_string(),
            display_name: "Lua 5.4.0 - 5.4.8".to_string(),
            opcode_count: 83,
            features: vec![
                "lossless parse".to_string(),
                "varint lineinfo".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
                "CFG".to_string(),
                "xrefs".to_string(),
                "diff".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: standard_required_gates.clone(),
            completed_gates: vec![],
            evidence: vec![
                "83/83 opcode table coverage; Gate 1 & 2 remediation in progress".to_string(),
            ],
        },
        DialectCapability {
            id: "lua5.5".to_string(),
            display_name: "Lua 5.5.0 - 5.5.1".to_string(),
            opcode_count: 85,
            features: vec![
                "lossless parse".to_string(),
                "string reuse table".to_string(),
                "ivABC format".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
                "CFG".to_string(),
                "xrefs".to_string(),
                "diff".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: standard_required_gates,
            completed_gates: vec![],
            evidence: vec![
                "85/85 opcode table coverage; signed-immediate gate in progress".to_string(),
            ],
        },
        DialectCapability {
            id: "luajit".to_string(),
            display_name: "LuaJIT 2.0 / 2.1".to_string(),
            opcode_count: 0,
            features: vec!["planned".to_string()],
            status: SupportTier::Planned,
            required_gates: vec!["gate-luajit-parser".to_string()],
            completed_gates: vec![],
            evidence: vec!["Phase 8 roadmap item".to_string()],
        },
    ];

    let supported_dialects = dialects
        .iter()
        .filter(|d| d.status == SupportTier::Supported)
        .map(|d| d.id.clone())
        .collect();

    let experimental_dialects = dialects
        .iter()
        .filter(|d| d.status == SupportTier::Experimental)
        .map(|d| d.id.clone())
        .collect();

    let planned_dialects = dialects
        .iter()
        .filter(|d| d.status == SupportTier::Planned)
        .map(|d| d.id.clone())
        .collect();

    let evidence = vec![
        "All stock-Lua dialects currently in experimental tier pending CODING-AGENT-PLAN gates"
            .to_string(),
        "Bounded SafeReader with safe capacity allocation, varints, and recursion limits"
            .to_string(),
        "Exact bit-level integer and IEEE-754 float preservation".to_string(),
    ];

    CapabilityManifest {
        tool_name: "luad".to_string(),
        tool_version: tool_version.to_string(),
        schema_version: 1,
        supported_dialects,
        experimental_dialects,
        planned_dialects,
        dialects,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_supported_dialect_without_completed_gates() {
        let manifest = get_canonical_capabilities("0.1.0");
        for dialect in &manifest.dialects {
            if dialect.status == SupportTier::Supported {
                assert!(
                    !dialect.required_gates.is_empty(),
                    "Dialect '{}' marked supported must have non-empty required gates",
                    dialect.id
                );
                for req in &dialect.required_gates {
                    assert!(
                        dialect.completed_gates.contains(req),
                        "Dialect '{}' marked supported but missing required gate '{}'",
                        dialect.id,
                        req
                    );
                }
            }
        }
    }

    #[test]
    fn test_manifest_dialect_partitioning() {
        let manifest = get_canonical_capabilities("0.1.0");
        assert_eq!(
            manifest.dialects.len(),
            manifest.supported_dialects.len()
                + manifest.experimental_dialects.len()
                + manifest.planned_dialects.len()
        );
        assert!(manifest.supported_dialects.is_empty());
        assert_eq!(
            manifest.experimental_dialects,
            vec!["lua5.1", "lua5.2", "lua5.3", "lua5.4", "lua5.5"]
        );
        assert_eq!(manifest.planned_dialects, vec!["luajit"]);
    }
}
