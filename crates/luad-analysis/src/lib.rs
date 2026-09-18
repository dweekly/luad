//! Analysis engine for CFG, Dominators, Xrefs, Query, Chunk Diffing, and Callee Resolution.

pub mod callees;
pub mod callgraph;
pub mod capture_mutation;
pub mod cfg;
pub mod diff;
pub mod linking;
pub mod origins;
pub mod prototype_identity;
pub mod query;
pub mod xrefs;

pub use callees::{
    analyze_callees, analyze_chunk_callees, analyze_chunk_callees_with_mutation_budget,
    CalleeAnalysis, CalleeFact, CalleeLookupKind, CalleeResolution, CalleeUnresolvedReason,
    CaptureEnvironment, CaptureValue, ChunkCalleeAnalysis, SymbolicPathBasis,
};
pub use callgraph::{
    analyze_chunk_call_relations, CallRelationAnalysis, CallRelationBasis, CallRelationFact,
    CallRelationResolution, CallRelationUnresolvedReason, ChunkCallRelationAnalysis,
};
pub use cfg::{BasicBlock, CfgEdge, CfgEdgeKind, ControlFlowGraph};
pub use diff::{diff_chunks, ChunkDiff, InstructionDiff, ProtoDiff};
pub use linking::{
    analyze_corpus_links, build_module_export_index, index_chunk_module_exports,
    resolve_chunk_links, CrossChunkLinkFact, ExportDefinition, LinkConvention, LinkStatus,
    ModuleExportIndex,
};
pub use origins::{
    analyze_chunk_origins, CallArgumentWindow, CallOriginFact, ChunkOriginAnalysis,
    FixedArgumentOrigin, OriginAnalysis, OriginExpression, OriginExpressionKind, OriginLiteral,
    OriginUnknownReason, TableLiteralField,
};
pub use prototype_identity::{
    analyze_chunk_prototype_identities, analyze_chunk_prototype_identities_v1,
    ChunkPrototypeIdentityAnalysis, PrototypeIdentityError, PrototypeIdentityFact,
    PROTOTYPE_IDENTITY_SCHEME_V1, PROTOTYPE_IDENTITY_SCHEME_V2,
};
pub use query::{
    execute_query, execute_query_with_total, QueryError, QueryExpr, QueryField, QueryMatch,
    QueryOp, QueryResponse,
};
pub use xrefs::{find_proto, validate_target, XrefEntry, XrefIndex, XrefRelation, XrefResponse};

/// Validate chunk for analysis preconditions.
pub fn validate_for_analysis(
    chunk: &luad_core::model::Chunk,
) -> Result<(), Vec<luad_core::diagnostic::Diagnostic>> {
    let (verdict, mut diagnostics) = match chunk.dialect.as_str() {
        "lua5.5" => luad_dialect_lua55::validate_chunk_lua55(chunk),
        "lua5.4" => luad_dialect_lua54::validate_chunk_lua54(chunk),
        "lua5.3" => luad_dialect_lua53::validate_chunk_lua53(chunk),
        "lua5.2" => luad_dialect_lua52::validate_chunk_lua52(chunk),
        "lua5.1" | "lua5.1-lnum32" | "lua5.1-stock32" => {
            luad_dialect_lua51::validate_chunk_lua51(chunk)
        }
        _ => (chunk.verdict, chunk.diagnostics.clone()),
    };

    let has_errors = verdict == luad_core::diagnostic::Verdict::Invalid
        || verdict == luad_core::diagnostic::Verdict::Incomplete
        || diagnostics
            .iter()
            .any(|d| d.severity == luad_core::diagnostic::Severity::Error);

    if has_errors {
        return Err(diagnostics);
    }

    // Explicit analysis qualification: only recognized Lua 5.1 profiles and Lua 5.4 are qualified for semantic analysis.
    const QUALIFIED_DIALECTS: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32", "lua5.4"];
    let is_qualified = QUALIFIED_DIALECTS.contains(&chunk.dialect.as_str());
    if !is_qualified {
        diagnostics.push(
            luad_core::diagnostic::Diagnostic::error(
                "ANA-PRECOND-001",
                luad_core::diagnostic::DiagnosticCategory::Analysis,
                luad_core::id::StableId::Chunk,
                format!(
                    "Semantic analysis is not qualified for dialect '{}' in this release; raw inspection (inspect, disasm) is available",
                    chunk.dialect
                ),
            )
            .with_suggested_action("Perform raw inspection or disassembly instead, or select a qualified analysis dialect."),
        );
        return Err(diagnostics);
    }

    Ok(())
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
        "lua5.1" | "lua5.1-lnum32" | "lua5.1-stock32" => {
            luad_dialect_lua51::lift_proto_lua51(proto)
        }
        _ => Vec::new(),
    }
}
