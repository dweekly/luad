//! Core types, safe parsing primitives, stable identifiers, diagnostics, and domain models for `luad`.

#![allow(clippy::result_large_err)]

pub mod capabilities;
pub mod diagnostic;
pub mod dialect;
pub mod disasm;
pub mod envelope;
pub mod id;
pub mod ir;
pub mod limits;
pub mod model;
pub mod provenance;
pub mod reader;

pub use capabilities::{
    get_canonical_capabilities, CapabilityManifest, DialectCapability, SupportTier,
};

pub use diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
pub use dialect::{DetectionResult, Dialect, ResolvedInterpretation, SelectionMode};
pub use disasm::{
    DisassembledInstruction, DisassembledOperand, DisassembledPrototype, EncodedOperands,
    OperandKind, ResolvedFact,
};
pub use envelope::{
    AnalysisConfiguration, ExportEndRecord, ExportStartRecord, FileEndRecord, FileStartRecord,
    InputIdentity, JsonlDataRecord, JsonlMetadataRecord, JsonlSummaryRecord, MachineDocument,
    ValidationResponse,
};
pub use id::{ProtoPath, StableId};

pub use ir::{EffectTarget, ImplicitEffect, SemanticInstruction, TypedOperand};
pub use limits::{ParseMode, ResourceLimits};
pub use model::{
    AbsLineInfo, Chunk, Constant, ConstantValue, Header, InstructionWord, LocalVar, LuaString,
    Prototype, UpvalueDesc,
};
pub use provenance::{Confidence, ProvenanceRecord, SourceLocation};
pub use reader::SafeReader;
