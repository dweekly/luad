//! Safe, bounded structured query engine over bytecode instructions and artifacts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use luad_core::id::StableId;
use luad_core::ir::{EffectTarget, SemanticInstruction};
use luad_core::model::{Chunk, ConstantValue, Prototype};

/// Result record returned by a query.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct QueryMatch {
    /// Stable identifier of the matching artifact.
    pub id: StableId,
    /// Artifact category ("instruction", "constant", "prototype", "upvalue").
    pub kind: String,
    /// Human-readable match summary.
    pub summary: String,
}

/// Paginated query response document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct QueryResponse {
    /// Matching records.
    pub matches: Vec<QueryMatch>,
    /// Total number of matches returned in this page.
    pub count: usize,
    /// Continuation cursor if more results exist beyond the limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// Whether results were truncated by the limit ceiling.
    pub is_truncated: bool,
}

/// Execute a structured query over a chunk with limit and cursor pagination.
#[must_use]
pub fn execute_query(
    chunk: &Chunk,
    where_expr: Option<&str>,
    limit: usize,
    cursor: Option<&str>,
) -> QueryResponse {
    let start_index: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
    let mut all_matches = Vec::new();

    collect_proto_matches(&chunk.dialect, &chunk.main_proto, where_expr, &mut all_matches);

    let total_matches = all_matches.len();
    let page_items: Vec<QueryMatch> = all_matches
        .into_iter()
        .skip(start_index)
        .take(limit)
        .collect();

    let returned_count = page_items.len();
    let next_index = start_index + returned_count;
    let is_truncated = next_index < total_matches;
    let next_cursor = if is_truncated {
        Some(next_index.to_string())
    } else {
        None
    };

    QueryResponse {
        matches: page_items,
        count: returned_count,
        next_cursor,
        is_truncated,
    }
}

fn collect_proto_matches(
    dialect: &str,
    proto: &Prototype,
    where_expr: Option<&str>,
    results: &mut Vec<QueryMatch>,
) {
    let lifted = crate::lift_proto_for_dialect(dialect, proto);

    for sem in &lifted {
        if matches_predicate(sem, proto, where_expr) {
            results.push(QueryMatch {
                id: sem.id.clone(),
                kind: "instruction".to_string(),
                summary: format!("{:<12} {}", sem.mnemonic, sem.explanation),
            });
        }
    }

    // Also match constants if query mentions constant or string
    if let Some(expr) = where_expr {
        if expr.contains("string") || expr.contains("constant") || expr.contains("k") {
            for c in &proto.constants {
                let is_match = match &c.value {
                    ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
                        if let Some((_, pattern)) = expr.split_once("contains(") {
                            let clean_pat = pattern.trim_matches(|c| c == ')' || c == '"' || c == '\'');
                            s.display.contains(clean_pat)
                        } else {
                            true
                        }
                    }
                    _ => false,
                };
                if is_match {
                    results.push(QueryMatch {
                        id: c.id.clone(),
                        kind: "constant".to_string(),
                        summary: format!("Constant K[{}] = {:?}", c.index, c.value),
                    });
                }
            }
        }
    }

    for child in &proto.protos {
        collect_proto_matches(dialect, child, where_expr, results);
    }
}


fn matches_predicate(sem: &SemanticInstruction, _proto: &Prototype, where_expr: Option<&str>) -> bool {
    let Some(expr) = where_expr else {
        return true;
    };

    let expr = expr.trim();

    // Mnemonic / opcode equality: opcode == "OP_CALL" or mnemonic == "CALL" or "CALL"
    if let Some((_, val)) = expr.split_once("==") {
        let val_clean = val.trim().trim_matches('"').trim_matches('\'');
        let val_upper = val_clean.to_uppercase();
        let target_mnem = if val_upper.starts_with("OP_") {
            &val_upper[3..]
        } else {
            &val_upper
        };

        if expr.contains("opcode") || expr.contains("mnemonic") {
            return sem.mnemonic == target_mnem;
        }

        if expr.contains("effect.write.upvalue") || expr.contains("write.upvalue") {
            if let Ok(idx) = val_clean.parse::<u8>() {
                return sem.writes.iter().any(|w| matches!(w, EffectTarget::Upvalue { index, .. } if *index == idx));
            }
        }

        if expr.contains("effect.read.upvalue") || expr.contains("read.upvalue") {
            if let Ok(idx) = val_clean.parse::<u8>() {
                return sem.reads.iter().any(|r| matches!(r, EffectTarget::Upvalue { index, .. } if *index == idx));
            }
        }
    }

    // Direct token search
    if sem.mnemonic.eq_ignore_ascii_case(expr) {
        return true;
    }

    if sem.explanation.to_lowercase().contains(&expr.to_lowercase()) {
        return true;
    }

    false
}
