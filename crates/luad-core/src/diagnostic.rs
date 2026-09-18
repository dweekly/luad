//! Structured diagnostic taxonomy and validation verdicts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::id::StableId;
use crate::provenance::SourceLocation;

/// Diagnostic severity level.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
    /// Construct a general diagnostic item.
    pub fn new(
        code: impl Into<String>,
        category: DiagnosticCategory,
        severity: Severity,
        target: StableId,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            category,
            severity,
            target,
            message: message.into(),
            source: None,
            evidence: None,
            suggested_action: None,
            help_topic: None,
        }
    }

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

/// Deduplicate diagnostics preserving order and truncate to `max_count`, ensuring errors are prioritized
/// over warnings so that truncation never conceals bytecode invalidity, and preserving `CORE-LIMIT-003` at the end.
pub fn truncate_and_dedup_diagnostics(
    diagnostics: Vec<Diagnostic>,
    max_count: usize,
) -> Vec<Diagnostic> {
    let mut deduped = Vec::with_capacity(diagnostics.len().min(max_count + 1));
    let mut seen = std::collections::HashSet::new();

    for diag in diagnostics {
        if seen.insert(diag.clone()) {
            deduped.push(diag);
        }
    }

    if deduped.len() <= max_count {
        return deduped;
    }

    let (errors, warnings): (Vec<Diagnostic>, Vec<Diagnostic>) = deduped
        .into_iter()
        .partition(|d| d.severity == Severity::Error);

    let (core_limit, errors): (Vec<Diagnostic>, Vec<Diagnostic>) =
        errors.into_iter().partition(|d| d.code == "CORE-LIMIT-003");

    let mut result = Vec::with_capacity(max_count);
    let reserved_for_core_limit = core_limit.len().min(max_count);
    let budget_for_others = max_count.saturating_sub(reserved_for_core_limit);

    let error_take = errors.len().min(budget_for_others);
    result.extend(errors.into_iter().take(error_take));

    let remaining_budget = budget_for_others.saturating_sub(result.len());
    if remaining_budget > 0 {
        result.extend(warnings.into_iter().take(remaining_budget));
    }

    result.extend(core_limit.into_iter().take(reserved_for_core_limit));

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ProtoPath;

    fn make_test_diag(code: &str, sev: Severity) -> Diagnostic {
        Diagnostic::new(
            code,
            DiagnosticCategory::Parse,
            sev,
            StableId::proto(ProtoPath::root()),
            "msg",
        )
    }

    #[test]
    fn test_truncate_and_dedup_preserves_order_under_cap() {
        let diags = vec![
            make_test_diag("W1", Severity::Warning),
            make_test_diag("W2", Severity::Warning),
            make_test_diag("W1", Severity::Warning),
            make_test_diag("E1", Severity::Error),
        ];
        let result = truncate_and_dedup_diagnostics(diags, 10);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].code, "W1");
        assert_eq!(result[1].code, "W2");
        assert_eq!(result[2].code, "E1");
    }

    #[test]
    fn test_truncate_and_dedup_prioritizes_errors_over_warnings() {
        let mut diags = Vec::new();
        for i in 0..100 {
            diags.push(make_test_diag(&format!("W{i}"), Severity::Warning));
        }
        diags.push(make_test_diag("E1", Severity::Error));
        diags.push(make_test_diag("CORE-LIMIT-003", Severity::Error));

        // Cap at 10 items
        let result = truncate_and_dedup_diagnostics(diags, 10);
        assert_eq!(result.len(), 10);
        // First item must be the error E1
        assert_eq!(result[0].code, "E1");
        // Last item must be CORE-LIMIT-003
        assert_eq!(result[9].code, "CORE-LIMIT-003");
        // Intermediate items are the first warnings W0..W7
        for i in 0..8 {
            assert_eq!(result[1 + i].code, format!("W{i}"));
        }
    }
}
