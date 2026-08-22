//! Structured diagnostic taxonomy and validation verdicts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::id::StableId;
use crate::provenance::SourceLocation;

/// Diagnostic severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Informational note or hint.
    Info,
    /// Warning about suspicious, unconventional, or non-fatal condition.
    Warning,
    /// Error indicating structural invalidity or parsing failure.
    Error,
}

/// Category of diagnostic check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DiagnosticCategory {
    /// Raw binary parsing, truncation, or format-envelope error.
    Parse,
    /// Structural integrity or header consistency error.
    Structure,
    /// Opcode, operand, or companion-instruction invariant violation.
    Instruction,
    /// Control-flow anomaly, out-of-bounds jump, or unreachable entry.
    ControlFlow,
    /// Corrupt, inconsistent, or missing debug metadata.
    DebugMetadata,
    /// Higher-level analysis precondition failure.
    Analysis,
}

/// Structured diagnostic item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Diagnostic {
    /// Stable diagnostic error code (e.g. "L54-HEADER-001", "L54-JUMP-003").
    pub code: String,
    /// Category of the diagnostic.
    pub category: DiagnosticCategory,
    /// Severity level.
    pub severity: Severity,
    /// Target artifact stable ID.
    pub target: StableId,
    /// Human-readable explanation.
    pub message: String,
    /// Raw byte location if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceLocation>,
    /// Supporting evidence or context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Suggested next action for researcher or agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_action: Option<String>,
    /// Topic resolvable via `luad help <topic>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help_topic: Option<String>,
}

impl Diagnostic {
    /// Construct a diagnostic error.
    pub fn error(
        code: impl Into<String>,
        category: DiagnosticCategory,
        target: StableId,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            category,
            severity: Severity::Error,
            target,
            message: message.into(),
            source: None,
            evidence: None,
            suggested_action: None,
            help_topic: None,
        }
    }

    /// Construct a diagnostic warning.
    pub fn warning(
        code: impl Into<String>,
        category: DiagnosticCategory,
        target: StableId,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            category,
            severity: Severity::Warning,
            target,
            message: message.into(),
            source: None,
            evidence: None,
            suggested_action: None,
            help_topic: None,
        }
    }

    /// Attach source location.
    #[must_use]
    pub fn with_source(mut self, source: SourceLocation) -> Self {
        self.source = Some(source);
        self
    }

    /// Attach evidence.
    #[must_use]
    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// Attach suggested action.
    #[must_use]
    pub fn with_suggested_action(mut self, action: impl Into<String>) -> Self {
        self.suggested_action = Some(action.into());
        self
    }

    /// Attach help topic.
    #[must_use]
    pub fn with_help_topic(mut self, topic: impl Into<String>) -> Self {
        self.help_topic = Some(topic.into());
        self
    }

    /// Formulate the diagnostic stable ID.
    #[must_use]
    pub fn stable_id(&self) -> StableId {
        StableId::diagnostic(&self.code, self.target.clone())
    }
}

/// Overall summarized validation verdict (PRD section 5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Conforms to format checks without structural errors.
    #[default]
    ValidForParser,
    /// All invariants required by enabled analyses hold.
    ValidForAnalysis,
    /// Violates a known format or VM requirement.
    Invalid,
    /// Parsing or analysis could not finish due to truncation or safety limits.
    Incomplete,
    /// More than one format interpretation remains plausible.
    Ambiguous,
}
