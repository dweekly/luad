//! Core types, safe parsing primitives, stable identifiers, diagnostics, and domain models for `luad`.

#![allow(clippy::result_large_err)]

pub mod capabilities;
pub mod diagnostic;
pub mod diagnostic_catalog;
pub mod dialect;
pub mod disasm;
pub mod envelope;
pub mod export;
pub mod id;
pub mod ir;
pub mod limits;
pub mod model;
pub mod provenance;
pub mod reader;
pub mod scalar;

pub use capabilities::{
    get_canonical_capabilities, CapabilityManifest, DiagnosticCatalogCapability, DialectCapability,
    SupportTier,
};

pub use diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
pub use diagnostic_catalog::{
    build_catalog_response, get_diagnostic_catalog, list_diagnostics, lookup_diagnostic,
    DiagnosticCatalogResponse, DiagnosticDescriptor, StaticDiagnosticDescriptor,
    DIAGNOSTIC_ENTRIES,
};
pub use dialect::{DetectionResult, Dialect, ResolvedInterpretation, SelectionMode};
pub use disasm::{
    DisassembledInstruction, DisassembledOperand, DisassembledPrototype, EncodedOperands,
    OperandKind, ResolvedFact,
};
pub use envelope::{
    AnalysisConfiguration, ExportEndRecord, ExportStartRecord, FileEndRecord, FileStartRecord,
    InputIdentity, JsonlDataRecord, JsonlMetadataRecord, JsonlRecordContext, JsonlSummaryRecord,
    MachineDocument, QueryEndRecord, QueryStartRecord, ValidationResponse, JSONL_SCHEMA_VERSION,
};
pub use export::{
    ExportCapability, ExportFactFamily, EXPORT_FACT_FAMILIES, EXPORT_FACT_FAMILY_NAMES,
    SORTED_FACT_FAMILY_NAMES,
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
pub use scalar::{
    escape_bytes, render_byte_string, render_constant, render_float, render_integer,
    BYTE_STRING_PREVIEW_BYTES,
};
