//! Core types, safe parsing primitives, stable identifiers, diagnostics, and domain models for `luad`.

pub mod diagnostic;
pub mod dialect;
pub mod id;
pub mod ir;
pub mod limits;
pub mod model;
pub mod provenance;
pub mod reader;

pub use diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
pub use dialect::{DetectionResult, Dialect};
pub use id::{ProtoPath, StableId};
pub use ir::{EffectTarget, ImplicitEffect, SemanticInstruction, TypedOperand};
pub use limits::{ParseMode, ResourceLimits};
pub use model::{
    AbsLineInfo, Chunk, Constant, ConstantValue, Header, InstructionWord, LocalVar, LuaString,
    Prototype, UpvalueDesc,
};
pub use provenance::{Confidence, ProvenanceRecord, SourceLocation};
pub use reader::SafeReader;
