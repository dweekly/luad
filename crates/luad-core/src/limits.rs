//! Configurable safety and resource limits for parsing and analysis.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Resource and safety limits for parsing unknown chunks safely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceLimits {
    /// Maximum allowed input file size in bytes (default 64 MiB).
    pub max_input_bytes: usize,
    /// Maximum recursive prototype nesting depth (default 128).
    pub max_nesting_depth: usize,
    /// Maximum total number of prototypes across the entire chunk (default 10,000).
    pub max_total_prototypes: usize,
    /// Maximum instruction count per prototype (default 1,000,000).
    pub max_instructions_per_proto: usize,
    /// Maximum constant count per prototype (default 262,144).
    pub max_constants_per_proto: usize,
    /// Maximum upvalue count per prototype (default 1,024).
    pub max_upvalues_per_proto: usize,
    /// Maximum single string byte length (default 16 MiB).
    pub max_string_bytes: usize,
    /// Maximum number of diagnostics to collect before terminating early (default 50,000).
    pub max_diagnostics: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_nesting_depth: 128,
            max_total_prototypes: 10_000,
            max_instructions_per_proto: 1_000_000,
            max_constants_per_proto: 262_144,
            max_upvalues_per_proto: 1_024,
            max_string_bytes: 16 * 1024 * 1024,
            max_diagnostics: 50_000,
        }
    }
}

/// Parsing mode behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ParseMode {
    /// Stop and fail immediately at the first invalid condition.
    #[default]
    Strict,
    /// Safely record diagnostics and attempt recovery where bounds allow.
    Permissive,
}
