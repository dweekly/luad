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

/// Machine-discoverable entry point for the public diagnostic catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DiagnosticCatalogCapability {
    /// CLI command that lists or looks up diagnostic descriptors.
    pub command: String,
    /// Schema name accepted by `luad schema`.
    pub schema: String,
    /// Output formats supported by the command.
    pub formats: Vec<String>,
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
    /// Public diagnostic-catalog discovery entry point.
    pub diagnostic_catalog: DiagnosticCatalogCapability,
    /// Verification and evidence claims.
    pub evidence: Vec<String>,
}

/// Generate the canonical capabilities manifest for `luad`.
#[must_use]
pub fn get_canonical_capabilities(tool_version: &str) -> CapabilityManifest {
    let dialects = vec![
        DialectCapability {
            id: "lua5.1".to_string(),
            display_name: "Lua 5.1.5".to_string(),
            opcode_count: 38,
            features: vec![
                "lossless parse (experimental)".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: vec![
                "gate-layout-lua51-stock".to_string(),
                "gate-profile-lua51-lnum".to_string(),
                "gate-closures-lua51".to_string(),
                "gate-resolved-constants-lua51".to_string(),
            ],
            completed_gates: vec![],
            evidence: vec![
                "Experimental dialect; exact target qualification remains required before promotion"
                    .to_string(),
            ],
        },
        DialectCapability {
            id: "lua5.2".to_string(),
            display_name: "Lua 5.2.4".to_string(),
            opcode_count: 40,
            features: vec![
                "lossless parse (experimental)".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: vec![],
            completed_gates: vec![],
            evidence: vec!["Experimental dialect; formal proof gates deferred".to_string()],
        },
        DialectCapability {
            id: "lua5.3".to_string(),
            display_name: "Lua 5.3.6".to_string(),
            opcode_count: 47,
            features: vec![
                "lossless parse (experimental)".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: vec![],
            completed_gates: vec![],
            evidence: vec!["Experimental dialect; formal proof gates deferred".to_string()],
        },
        DialectCapability {
            id: "lua5.4".to_string(),
            display_name: "Lua 5.4.8".to_string(),
            opcode_count: 83,
            features: vec![
                "lossless parse (experimental)".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: vec![
                "gate-proof-harness".to_string(),
                "gate-facts-lua54-8".to_string(),
                "gate-public-disasm-lua54-8".to_string(),
                "gate-analysis-r3".to_string(),
                "gate-lossless-lua54-8".to_string(),
                "gate-release-lua54-8".to_string(),
            ],
            completed_gates: vec![],
            evidence: vec![
                "Experimental dialect; named evidence gates do not by themselves promote support"
                    .to_string(),
            ],
        },
        DialectCapability {
            id: "lua5.5".to_string(),
            display_name: "Lua 5.5.1".to_string(),
            opcode_count: 85,
            features: vec![
                "lossless parse (experimental)".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
            ],
            status: SupportTier::Experimental,
            required_gates: vec![],
            completed_gates: vec![],
            evidence: vec!["Experimental dialect; formal proof gates deferred".to_string()],
        },
        DialectCapability {
            id: "luajit".to_string(),
            display_name: "LuaJIT 2.0 / 2.1".to_string(),
            opcode_count: 0,
            features: vec!["planned".to_string()],
            status: SupportTier::Planned,
            required_gates: vec!["gate-luajit-parser".to_string()],
            completed_gates: vec![],
            evidence: vec!["Planned dialect; formal specification and parser deferred".to_string()],
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
        "Stock Lua dialects (5.1..5.5) are experimental; formal proof gates are evaluated strictly against named gate specifications in tests/gates/".to_string(),
        "Bounded SafeReader with safe capacity allocation, varints, and recursion limits"
            .to_string(),
        "Exact bit-level integer and IEEE-754 float preservation".to_string(),
    ];

    CapabilityManifest {
        tool_name: "luad".to_string(),
        tool_version: tool_version.to_string(),
        schema_version: 2,
        supported_dialects,
        experimental_dialects,
        planned_dialects,
        dialects,
        diagnostic_catalog: DiagnosticCatalogCapability {
            command: "diagnostics".to_string(),
            schema: "diagnostics".to_string(),
            formats: vec!["json".to_string(), "text".to_string()],
        },
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

    #[test]
    fn test_no_supported_dialect_without_verified_artifact() {
        let manifest = get_canonical_capabilities("0.1.0");
        assert!(
            manifest.supported_dialects.is_empty(),
            "supported_dialects must remain empty without promoted release evidence"
        );
    }

    #[test]
    fn test_all_stock_dialects_experimental_without_promoted_release_evidence() {
        let manifest = get_canonical_capabilities("0.1.0");
        for dialect in &manifest.dialects {
            if dialect.id != "luajit" {
                assert_eq!(
                    dialect.status,
                    SupportTier::Experimental,
                    "Dialect '{}' must remain Experimental without promoted release evidence",
                    dialect.id
                );
                assert!(
                    dialect.completed_gates.is_empty(),
                    "Dialect '{}' must have empty completed_gates",
                    dialect.id
                );
            }
        }
    }

    #[test]
    fn test_completed_gate_requires_validated_result() {
        let manifest = get_canonical_capabilities("0.1.0");
        for dialect in &manifest.dialects {
            if dialect.status == SupportTier::Experimental {
                assert!(
                    dialect.completed_gates.is_empty(),
                    "Experimental dialect '{}' must have empty completed_gates",
                    dialect.id
                );
            }
        }
    }

    #[test]
    fn test_capabilities_do_not_claim_version_ranges_from_one_patch() {
        let manifest = get_canonical_capabilities("0.1.0");
        for dialect in &manifest.dialects {
            if dialect.id.starts_with("lua5.") {
                assert!(
                    !dialect.display_name.contains('-'),
                    "Dialect '{}' display_name '{}' must not claim an unproved version range",
                    dialect.id,
                    dialect.display_name
                );
            }
        }
    }
}
