//! Canonical registry of export fact families and export capability definitions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Selectable counted fact families emitted by `luad export --facts`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ExportFactFamily {
    Prototype,
    PrototypeIdentity,
    Instruction,
    Constant,
    Upvalue,
    Xref,
    Callee,
    Origin,
    CallRelation,
}

/// The 9 selectable counted fact families in canonical pipeline order.
pub const EXPORT_FACT_FAMILIES: [ExportFactFamily; 9] = [
    ExportFactFamily::Prototype,
    ExportFactFamily::PrototypeIdentity,
    ExportFactFamily::Instruction,
    ExportFactFamily::Constant,
    ExportFactFamily::Upvalue,
    ExportFactFamily::Xref,
    ExportFactFamily::Callee,
    ExportFactFamily::Origin,
    ExportFactFamily::CallRelation,
];

/// The 9 selectable counted fact families in canonical pipeline order as string slices.
pub const EXPORT_FACT_FAMILY_NAMES: [&str; 9] = [
    "prototype",
    "prototype_identity",
    "instruction",
    "constant",
    "upvalue",
    "xref",
    "callee",
    "origin",
    "call_relation",
];

/// The 9 selectable counted fact families in alphabetical order as string slices.
pub const SORTED_FACT_FAMILY_NAMES: [&str; 9] = [
    "call_relation",
    "callee",
    "constant",
    "instruction",
    "origin",
    "prototype",
    "prototype_identity",
    "upvalue",
    "xref",
];

impl ExportFactFamily {
    /// Returns the canonical string representation of this fact family.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prototype => "prototype",
            Self::PrototypeIdentity => "prototype_identity",
            Self::Instruction => "instruction",
            Self::Constant => "constant",
            Self::Upvalue => "upvalue",
            Self::Xref => "xref",
            Self::Callee => "callee",
            Self::Origin => "origin",
            Self::CallRelation => "call_relation",
        }
    }

    /// Parses a string slice into an `ExportFactFamily`, if recognized.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        EXPORT_FACT_FAMILIES
            .iter()
            .copied()
            .find(|family| family.as_str() == value)
    }

    /// All fact families in canonical pipeline order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &EXPORT_FACT_FAMILIES
    }
}

impl std::fmt::Display for ExportFactFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Machine-discoverable entry point for the export interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExportCapability {
    /// CLI command that runs batch export.
    pub command: String,
    /// Schema name accepted by `luad schema`.
    pub schema: String,
    /// Output formats supported by the command.
    pub formats: Vec<String>,
    /// Selectable counted fact families supported by `--facts`.
    pub fact_families: Vec<String>,
    /// Optional linking conventions supported by `--link-convention`.
    pub link_conventions: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_fact_family_round_trip() {
        for family in &EXPORT_FACT_FAMILIES {
            let s = family.as_str();
            let parsed = ExportFactFamily::parse(s).expect("parse must succeed");
            assert_eq!(*family, parsed);
        }
    }

    #[test]
    fn test_sorted_fact_family_names_are_sorted() {
        let mut sorted = SORTED_FACT_FAMILY_NAMES.to_vec();
        sorted.sort_unstable();
        assert_eq!(SORTED_FACT_FAMILY_NAMES.to_vec(), sorted);
    }

    #[test]
    fn test_canonical_names_match_sorted_set() {
        let mut canonical = EXPORT_FACT_FAMILY_NAMES.to_vec();
        canonical.sort_unstable();
        assert_eq!(SORTED_FACT_FAMILY_NAMES.to_vec(), canonical);
    }
}
