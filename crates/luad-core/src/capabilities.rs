//! Single source of truth for dialect capabilities and tool metadata.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// Support tier: "supported" or "planned".
    pub status: String,
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
    /// List of dialect identifiers currently supported.
    pub supported_dialects: Vec<String>,
    /// Full capabilities by dialect.
    pub dialects: Vec<DialectCapability>,
    /// Verification and evidence claims.
    pub evidence: Vec<String>,
}

/// Generate the canonical capabilities manifest for `luad`.
#[must_use]
pub fn get_canonical_capabilities(tool_version: &str) -> CapabilityManifest {
    let dialects = vec![
        DialectCapability {
            id: "lua5.1".to_string(),
            display_name: "Lua 5.1.0 - 5.1.5".to_string(),
            opcode_count: 38,
            features: vec![
                "lossless parse".to_string(),
                "disasm".to_string(),
                "validate".to_string(),
                "CFG".to_string(),
                "xrefs".to_string(),
                "diff".to_string(),
            ],
            status: "supported".to_string(),
            evidence: vec![
                "38/38 opcodes verified with lvm.c citations and semantic lifters".to_string(),
                "Differential testing against Lua 5.1.5 compiler dumps".to_string(),
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
            status: "supported".to_string(),
            evidence: vec![
                "40/40 opcodes verified with lvm.c citations and semantic lifters".to_string(),
                "Differential testing against Lua 5.2.4 compiler dumps".to_string(),
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
            status: "supported".to_string(),
            evidence: vec![
                "47/47 opcodes verified with lvm.c citations and semantic lifters".to_string(),
                "Differential testing against Lua 5.3.6 compiler dumps".to_string(),
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
            status: "supported".to_string(),
            evidence: vec![
                "83/83 opcodes verified with lvm.c citations and semantic lifters".to_string(),
                "Differential testing against Lua 5.4.8 compiler dumps".to_string(),
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
            status: "supported".to_string(),
            evidence: vec![
                "85/85 opcodes verified with lvm.c citations and semantic lifters".to_string(),
                "Differential testing against Lua 5.5.1 compiler dumps".to_string(),
            ],
        },
        DialectCapability {
            id: "luajit".to_string(),
            display_name: "LuaJIT 2.0 / 2.1".to_string(),
            opcode_count: 0,
            features: vec!["planned".to_string()],
            status: "planned".to_string(),
            evidence: vec!["Phase 8 roadmap item".to_string()],
        },
    ];

    let supported_dialects = dialects
        .iter()
        .filter(|d| d.status == "supported")
        .map(|d| d.id.clone())
        .collect();

    let evidence = vec![
        "100% opcode table coverage across Lua 5.1 (38), 5.2 (40), 5.3 (47), 5.4 (83), 5.5 (85) with operand and effect validation".to_string(),
        "Bounded SafeReader with safe capacity allocation, varints, and recursion limits".to_string(),
        "Exact bit-level integer and IEEE-754 float preservation".to_string(),
        "Field-by-field canonical differential testing against official Lua 5.1.5, 5.2.4, 5.3.6, 5.4.8, 5.5.1 compiler dumps".to_string(),
    ];

    CapabilityManifest {
        tool_name: "luad".to_string(),
        tool_version: tool_version.to_string(),
        schema_version: 1,
        supported_dialects,
        dialects,
        evidence,
    }
}
