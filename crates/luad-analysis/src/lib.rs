//! Analysis engine for CFG, Dominators, Xrefs, Query, Chunk Diffing, and Callee Resolution.

pub mod callees;
pub mod cfg;
pub mod diff;
pub mod query;
pub mod xrefs;

pub use callees::{
    analyze_callees, analyze_chunk_callees, CalleeAnalysis, CalleeFact, CalleeResolution,
    CalleeUnresolvedReason, CaptureEnvironment, CaptureValue, ChunkCalleeAnalysis,
    SymbolicPathBasis,
};
pub use cfg::{BasicBlock, CfgEdge, CfgEdgeKind, ControlFlowGraph};
pub use diff::{diff_chunks, ChunkDiff, InstructionDiff, ProtoDiff};
pub use query::{
    execute_query, QueryError, QueryExpr, QueryField, QueryMatch, QueryOp, QueryResponse,
};
pub use xrefs::{find_proto, validate_target, XrefEntry, XrefIndex, XrefRelation, XrefResponse};

/// Validate chunk for analysis preconditions.
pub fn validate_for_analysis(
    chunk: &luad_core::model::Chunk,
) -> Result<(), Vec<luad_core::diagnostic::Diagnostic>> {
    let (verdict, diagnostics) = match chunk.dialect.as_str() {
        "lua5.5" => luad_dialect_lua55::validate_chunk_lua55(chunk),
        "lua5.4" => luad_dialect_lua54::validate_chunk_lua54(chunk),
        "lua5.3" => luad_dialect_lua53::validate_chunk_lua53(chunk),
        "lua5.2" => luad_dialect_lua52::validate_chunk_lua52(chunk),
        d if d.starts_with("lua5.1") => luad_dialect_lua51::validate_chunk_lua51(chunk),
        _ => (chunk.verdict, chunk.diagnostics.clone()),
    };

    let has_errors = verdict == luad_core::diagnostic::Verdict::Invalid
        || diagnostics
            .iter()
            .any(|d| d.severity == luad_core::diagnostic::Severity::Error);

    if has_errors {
        Err(diagnostics)
    } else {
        Ok(())
    }
}

/// Lift prototype instructions into semantic IR using the appropriate dialect lifter.
#[must_use]
pub fn lift_proto_for_dialect(
    dialect: &str,
    proto: &luad_core::model::Prototype,
) -> Vec<luad_core::SemanticInstruction> {
    match dialect {
        "lua5.5" => luad_dialect_lua55::lift_proto_lua55(proto),
        "lua5.4" => luad_dialect_lua54::lift_proto_lua54(proto),
        "lua5.3" => luad_dialect_lua53::lift_proto_lua53(proto),
        "lua5.2" => luad_dialect_lua52::lift_proto_lua52(proto),
        d if d.starts_with("lua5.1") => luad_dialect_lua51::lift_proto_lua51(proto),
        _ => luad_dialect_lua54::lift_proto_lua54(proto),
    }
}
