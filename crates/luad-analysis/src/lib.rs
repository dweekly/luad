//! Analysis engine for CFG, Dominators, Xrefs, Query, and Chunk Diffing.

pub mod cfg;
pub mod diff;
pub mod query;
pub mod xrefs;

pub use cfg::{BasicBlock, CfgEdge, CfgEdgeKind, ControlFlowGraph};
pub use diff::{diff_chunks, ChunkDiff, InstructionDiff, ProtoDiff};
pub use query::{execute_query, QueryMatch, QueryResponse};
pub use xrefs::{XrefEntry, XrefIndex, XrefRelation};

/// Lift prototype instructions into semantic IR using the appropriate dialect lifter.
#[must_use]
pub fn lift_proto_for_dialect(
    dialect: &str,
    proto: &luad_core::model::Prototype,
) -> Vec<luad_core::SemanticInstruction> {
    if dialect == "lua5.5" {
        luad_dialect_lua55::lift_proto_lua55(proto)
    } else {
        luad_dialect_lua54::lift_proto_lua54(proto)
    }
}
