//! Convention-gated cross-chunk linking (R-2).
//!
//! Provides deterministic, auditable linking between symbolic call-sites and defining
//! module exports across a batch corpus under explicit conventions such as
//! `--link-convention luci-module-setglobal`.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory};
use luad_core::envelope::InputIdentity;
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::{Chunk, ConstantValue};

use crate::callees::{
    analyze_chunk_callees, analyze_chunk_global_stores, CalleeResolution, GlobalStoreValue,
};

/// Supported explicit linking conventions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LinkConvention {
    /// LuCI module pattern: literal `module("...")` followed by exported `CLOSURE`/`SETGLOBAL`.
    LuciModuleSetglobal,
}

impl LinkConvention {
    /// Canonical string identifier for the convention.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LuciModuleSetglobal => "luci-module-setglobal",
        }
    }

    /// Parse convention name from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "luci-module-setglobal" => Some(Self::LuciModuleSetglobal),
            _ => None,
        }
    }

    /// List all supported link convention identifiers.
    #[must_use]
    pub const fn all_names() -> &'static [&'static str] {
        &["luci-module-setglobal"]
    }
}

impl std::fmt::Display for LinkConvention {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Status of cross-chunk linking for a specific call-site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinkStatus {
    /// Exactly one unique matching module export was proved in the corpus.
    Resolved,
    /// The target label belongs to the module namespace, but no defining export exists in the corpus.
    Absent,
    /// Multiple conflicting definitions exist in the corpus for this export label.
    Duplicate,
    /// Target or module declaration involves dynamic expressions and cannot be statically resolved.
    Dynamic,
    /// Dialect or input format is unsupported for the chosen linking convention.
    Unsupported,
    /// Linking could not be completed because a resource safety limit was exceeded.
    LimitExceeded,
}

impl std::fmt::Display for LinkStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resolved => write!(f, "resolved"),
            Self::Absent => write!(f, "absent"),
            Self::Duplicate => write!(f, "duplicate"),
            Self::Dynamic => write!(f, "dynamic"),
            Self::Unsupported => write!(f, "unsupported"),
            Self::LimitExceeded => write!(f, "limit_exceeded"),
        }
    }
}

/// An auditable cross-chunk link fact connecting a call-site to its defining artifact and prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CrossChunkLinkFact {
    /// Stable identifier of the calling instruction.
    pub call_id: StableId,
    /// File path of the calling artifact.
    pub caller_path: String,
    /// Prototype path within the calling artifact.
    pub caller_proto: ProtoPath,
    /// Physical instruction PC within the calling prototype.
    pub call_pc: usize,
    /// Symbolic path segments (e.g. `["luci", "sys", "exec"]`).
    pub label_segments: Vec<String>,
    /// Outcome status of the link.
    pub status: LinkStatus,
    /// Defining artifact identity when resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_artifact: Option<InputIdentity>,
    /// Defining prototype path within target artifact when resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_proto: Option<ProtoPath>,
    /// Evidence IDs from both defining export and calling site.
    pub evidence: Vec<StableId>,
}

/// A candidate export definition recorded during corpus indexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportDefinition {
    pub defining_artifact: InputIdentity,
    pub defining_proto: ProtoPath,
    pub label_segments: Vec<String>,
    pub evidence: Vec<StableId>,
}

/// Corpus-wide index of exported module definitions.
#[derive(Debug, Clone, Default)]
pub struct ModuleExportIndex {
    /// Map from full symbol segments (e.g. `["luci", "sys", "exec"]`) to definitions.
    pub exports: BTreeMap<Vec<String>, Vec<ExportDefinition>>,
    /// Artifacts with dynamic module declarations.
    pub dynamic_artifacts: BTreeSet<String>,
    /// Evidence of dynamic module declarations in the corpus.
    pub dynamic_evidence: Vec<StableId>,
    /// Whether indexing was capped by the safety limit.
    pub export_limit_exceeded: bool,
    /// Diagnostics accumulated during indexing.
    pub diagnostics: Vec<Diagnostic>,
}

pub const MAX_INDEXED_EXPORTS: usize = 10_000;
pub const MAX_LINK_FACTS: usize = 100_000;

/// Result of scanning a chunk for `module("...")` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ModuleDeclaration {
    Literal {
        segments: Vec<String>,
        evidence: Vec<StableId>,
    },
    Dynamic {
        evidence: Vec<StableId>,
    },
}

fn as_str_constant(val: &ConstantValue) -> Option<String> {
    match val {
        ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
            Some(s.as_str().to_string())
        }
        _ => None,
    }
}

/// Detect a `module(...)` call in the main prototype of a Lua 5.1 chunk.
fn detect_module_declaration(chunk: &Chunk) -> Option<ModuleDeclaration> {
    if !chunk.dialect.starts_with("lua5.1") {
        return None;
    }

    let main_proto = &chunk.main_proto;
    let instructions = &main_proto.instructions;
    let constants = &main_proto.constants;

    // Scan for GETGLOBAL loading "module"
    for (pc, inst) in instructions.iter().enumerate() {
        let raw = luad_dialect_lua51::RawInstruction51::decode(inst.raw_word);
        if raw.opcode != Some(luad_dialect_lua51::Opcode51::GetGlobal) {
            continue;
        }

        let k_idx = raw.bx as usize;
        let is_module_global = constants
            .get(k_idx)
            .and_then(|c| as_str_constant(&c.value))
            .is_some_and(|name| name == "module");

        if !is_module_global {
            continue;
        }

        let module_reg = raw.a;
        let getglobal_id = inst.id.clone();

        // Find the subsequent CALL on module_reg
        let mut arg_reg_val: Option<(Result<String, ()>, StableId)> = None;

        for next_inst in instructions.iter().skip(pc + 1) {
            let next_raw = luad_dialect_lua51::RawInstruction51::decode(next_inst.raw_word);

            // If module_reg is overwritten by an instruction other than CALL R(module_reg), abort
            if next_raw.a == module_reg
                && next_raw.opcode != Some(luad_dialect_lua51::Opcode51::Call)
            {
                break;
            }

            // Track definitions of module_reg + 1 (first argument to module)
            if next_raw.a == module_reg.saturating_add(1) {
                if next_raw.opcode == Some(luad_dialect_lua51::Opcode51::LoadK) {
                    let name_k_idx = next_raw.bx as usize;
                    if let Some(c) = constants.get(name_k_idx) {
                        if let Some(s) = as_str_constant(&c.value) {
                            arg_reg_val = Some((Ok(s), next_inst.id.clone()));
                        } else {
                            arg_reg_val = Some((Err(()), next_inst.id.clone()));
                        }
                    } else {
                        arg_reg_val = Some((Err(()), next_inst.id.clone()));
                    }
                } else {
                    // Non-LoadK write to argument register -> dynamic
                    arg_reg_val = Some((Err(()), next_inst.id.clone()));
                }
            }

            // Check for CALL R(module_reg)
            if next_raw.opcode == Some(luad_dialect_lua51::Opcode51::Call)
                && next_raw.a == module_reg
            {
                let call_id = next_inst.id.clone();
                match arg_reg_val {
                    Some((Ok(name), loadk_id)) => {
                        let segments: Vec<String> =
                            name.split('.').map(|s| s.to_string()).collect();
                        let mut evidence = vec![getglobal_id, loadk_id, call_id];
                        evidence.sort();
                        evidence.dedup();
                        return Some(ModuleDeclaration::Literal { segments, evidence });
                    }
                    Some((Err(()), load_id)) => {
                        let mut evidence = vec![getglobal_id, load_id, call_id];
                        evidence.sort();
                        evidence.dedup();
                        return Some(ModuleDeclaration::Dynamic { evidence });
                    }
                    None => {
                        return Some(ModuleDeclaration::Dynamic {
                            evidence: vec![getglobal_id, call_id],
                        });
                    }
                }
            }
        }
    }

    None
}

/// Index module exports from one chunk under the chosen convention.
pub fn index_chunk_module_exports(
    identity: &InputIdentity,
    chunk: &Chunk,
    convention: LinkConvention,
    index: &mut ModuleExportIndex,
) {
    index_chunk_module_exports_bounded(identity, chunk, convention, index, MAX_INDEXED_EXPORTS);
}

/// Index module exports from one chunk with an explicit capacity limit.
pub fn index_chunk_module_exports_bounded(
    identity: &InputIdentity,
    chunk: &Chunk,
    convention: LinkConvention,
    index: &mut ModuleExportIndex,
    max_exports: usize,
) {
    if convention != LinkConvention::LuciModuleSetglobal {
        return;
    }

    if !chunk.dialect.starts_with("lua5.1") {
        return;
    }

    match detect_module_declaration(chunk) {
        Some(ModuleDeclaration::Literal {
            segments: module_segments,
            evidence: mod_evidence,
        }) => {
            let global_stores = analyze_chunk_global_stores(chunk);
            for store in global_stores {
                if index.exports.len() >= max_exports {
                    index.export_limit_exceeded = true;
                    if !index.diagnostics.iter().any(|d| d.code == "ANA-LIMIT-001") {
                        index.diagnostics.push(Diagnostic::error(
                            "ANA-LIMIT-001",
                            DiagnosticCategory::Analysis,
                            StableId::Chunk,
                            format!(
                                "Corpus module export indexing safety limit ({max_exports}) exceeded; cross-chunk linking is incomplete"
                            ),
                        ));
                    }
                    break;
                }

                if let GlobalStoreValue::Closure {
                    prototype,
                    evidence,
                } = store.value
                {
                    let export_name = String::from_utf8_lossy(&store.name_raw).to_string();
                    let mut full_segments = module_segments.clone();
                    full_segments.push(export_name);

                    let mut combined_evidence = mod_evidence.clone();
                    combined_evidence.extend(evidence);
                    combined_evidence.push(store.store_id);
                    combined_evidence.sort();
                    combined_evidence.dedup();

                    index
                        .exports
                        .entry(full_segments.clone())
                        .or_default()
                        .push(ExportDefinition {
                            defining_artifact: identity.clone(),
                            defining_proto: prototype,
                            label_segments: full_segments,
                            evidence: combined_evidence,
                        });
                }
            }
        }
        Some(ModuleDeclaration::Dynamic { evidence }) => {
            index.dynamic_artifacts.insert(identity.path.clone());
            index.dynamic_evidence.extend(evidence);
            index.dynamic_evidence.sort();
            index.dynamic_evidence.dedup();
        }
        None => {}
    }
}

/// Build the corpus-wide module export index across all provided chunks.
#[must_use]
pub fn build_module_export_index<'a>(
    chunks: impl IntoIterator<Item = (&'a InputIdentity, &'a Chunk)>,
    convention: LinkConvention,
) -> ModuleExportIndex {
    build_module_export_index_bounded(chunks, convention, MAX_INDEXED_EXPORTS)
}

/// Build the corpus-wide module export index with an explicit capacity limit.
#[must_use]
pub fn build_module_export_index_bounded<'a>(
    chunks: impl IntoIterator<Item = (&'a InputIdentity, &'a Chunk)>,
    convention: LinkConvention,
    max_exports: usize,
) -> ModuleExportIndex {
    let mut index = ModuleExportIndex::default();
    for (identity, chunk) in chunks {
        index_chunk_module_exports_bounded(identity, chunk, convention, &mut index, max_exports);
    }
    index
}

/// Result of resolving cross-chunk links for one chunk, including any emitted diagnostics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkLinkResult {
    pub facts: Vec<CrossChunkLinkFact>,
    pub diagnostics: Vec<Diagnostic>,
}

impl std::ops::Deref for ChunkLinkResult {
    type Target = [CrossChunkLinkFact];
    fn deref(&self) -> &Self::Target {
        &self.facts
    }
}

impl IntoIterator for ChunkLinkResult {
    type Item = CrossChunkLinkFact;
    type IntoIter = std::vec::IntoIter<CrossChunkLinkFact>;
    fn into_iter(self) -> Self::IntoIter {
        self.facts.into_iter()
    }
}

/// Resolve cross-chunk links for one chunk against the corpus module export index.
#[must_use]
pub fn resolve_chunk_links(
    identity: &InputIdentity,
    chunk: &Chunk,
    index: &ModuleExportIndex,
    convention: LinkConvention,
) -> ChunkLinkResult {
    resolve_chunk_links_bounded(identity, chunk, index, convention, MAX_LINK_FACTS)
}

/// Resolve cross-chunk links for one chunk with an explicit maximum link facts limit.
#[must_use]
pub fn resolve_chunk_links_bounded(
    identity: &InputIdentity,
    chunk: &Chunk,
    index: &ModuleExportIndex,
    convention: LinkConvention,
    max_links: usize,
) -> ChunkLinkResult {
    if convention != LinkConvention::LuciModuleSetglobal {
        return ChunkLinkResult::default();
    }

    if !chunk.dialect.starts_with("lua5.1") {
        return ChunkLinkResult {
            facts: vec![CrossChunkLinkFact {
                call_id: StableId::Chunk,
                caller_path: identity.path.clone(),
                caller_proto: ProtoPath::root(),
                call_pc: 0,
                label_segments: Vec::new(),
                status: LinkStatus::Unsupported,
                target_artifact: None,
                target_proto: None,
                evidence: Vec::new(),
            }],
            diagnostics: Vec::new(),
        };
    }

    let callee_analysis = analyze_chunk_callees(chunk);
    let mut links = Vec::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    // Propagate index diagnostics if the export indexing limit was breached
    if index.export_limit_exceeded {
        for diag in &index.diagnostics {
            if !diagnostics.iter().any(|d| d.code == diag.code) {
                diagnostics.push(diag.clone());
            }
        }
    }

    'outer: for proto_callees in &callee_analysis.prototypes {
        for call in &proto_callees.calls {
            match &call.resolution {
                CalleeResolution::ResolvedPath {
                    segments, evidence, ..
                } => {
                    // Check if this path targets the module namespace
                    if segments.first().is_some_and(|s| s == "luci")
                        || index.exports.contains_key(segments)
                    {
                        if links.len() >= max_links {
                            diagnostics.push(Diagnostic::error(
                                "ANA-LIMIT-002",
                                DiagnosticCategory::Analysis,
                                call.call_id.clone(),
                                format!(
                                    "Cross-chunk link facts safety limit ({max_links}) exceeded; linking fact generation terminated early"
                                ),
                            ));
                            let mut sorted_evidence = evidence.clone();
                            sorted_evidence.sort();
                            sorted_evidence.dedup();
                            links.push(CrossChunkLinkFact {
                                call_id: call.call_id.clone(),
                                caller_path: identity.path.clone(),
                                caller_proto: call.proto_path.clone(),
                                call_pc: call.pc,
                                label_segments: segments.clone(),
                                status: LinkStatus::LimitExceeded,
                                target_artifact: None,
                                target_proto: None,
                                evidence: sorted_evidence,
                            });
                            break 'outer;
                        }

                        let link = match index.exports.get(segments) {
                            Some(candidates) if candidates.len() == 1 => {
                                let candidate = &candidates[0];
                                let mut combined_evidence = evidence.clone();
                                combined_evidence.extend(candidate.evidence.clone());
                                combined_evidence.sort();
                                combined_evidence.dedup();

                                CrossChunkLinkFact {
                                    call_id: call.call_id.clone(),
                                    caller_path: identity.path.clone(),
                                    caller_proto: call.proto_path.clone(),
                                    call_pc: call.pc,
                                    label_segments: segments.clone(),
                                    status: LinkStatus::Resolved,
                                    target_artifact: Some(candidate.defining_artifact.clone()),
                                    target_proto: Some(candidate.defining_proto.clone()),
                                    evidence: combined_evidence,
                                }
                            }
                            Some(candidates) if candidates.len() > 1 => {
                                let mut sorted_evidence = evidence.clone();
                                for candidate in candidates {
                                    sorted_evidence.extend(candidate.evidence.clone());
                                }
                                sorted_evidence.sort();
                                sorted_evidence.dedup();

                                CrossChunkLinkFact {
                                    call_id: call.call_id.clone(),
                                    caller_path: identity.path.clone(),
                                    caller_proto: call.proto_path.clone(),
                                    call_pc: call.pc,
                                    label_segments: segments.clone(),
                                    status: LinkStatus::Duplicate,
                                    target_artifact: None,
                                    target_proto: None,
                                    evidence: sorted_evidence,
                                }
                            }
                            _ => {
                                if !index.dynamic_artifacts.is_empty() {
                                    let mut combined_evidence = evidence.clone();
                                    combined_evidence.extend(index.dynamic_evidence.clone());
                                    combined_evidence.sort();
                                    combined_evidence.dedup();

                                    CrossChunkLinkFact {
                                        call_id: call.call_id.clone(),
                                        caller_path: identity.path.clone(),
                                        caller_proto: call.proto_path.clone(),
                                        call_pc: call.pc,
                                        label_segments: segments.clone(),
                                        status: LinkStatus::Dynamic,
                                        target_artifact: None,
                                        target_proto: None,
                                        evidence: combined_evidence,
                                    }
                                } else if index.export_limit_exceeded {
                                    // When the export index cap was exceeded, unindexed exports cannot prove absence.
                                    let mut sorted_evidence = evidence.clone();
                                    sorted_evidence.sort();
                                    sorted_evidence.dedup();

                                    CrossChunkLinkFact {
                                        call_id: call.call_id.clone(),
                                        caller_path: identity.path.clone(),
                                        caller_proto: call.proto_path.clone(),
                                        call_pc: call.pc,
                                        label_segments: segments.clone(),
                                        status: LinkStatus::LimitExceeded,
                                        target_artifact: None,
                                        target_proto: None,
                                        evidence: sorted_evidence,
                                    }
                                } else {
                                    let mut sorted_evidence = evidence.clone();
                                    sorted_evidence.sort();
                                    sorted_evidence.dedup();

                                    CrossChunkLinkFact {
                                        call_id: call.call_id.clone(),
                                        caller_path: identity.path.clone(),
                                        caller_proto: call.proto_path.clone(),
                                        call_pc: call.pc,
                                        label_segments: segments.clone(),
                                        status: LinkStatus::Absent,
                                        target_artifact: None,
                                        target_proto: None,
                                        evidence: sorted_evidence,
                                    }
                                }
                            }
                        };
                        links.push(link);
                    }
                }
                CalleeResolution::LookupLabel {
                    lookup_kind,
                    key,
                    evidence,
                } => {
                    // Constant lookup key that might match a top-level module export
                    if let Some(name) = as_str_constant(key) {
                        let segments = vec![name];
                        if index.exports.contains_key(&segments) {
                            if links.len() >= max_links {
                                diagnostics.push(Diagnostic::error(
                                    "ANA-LIMIT-002",
                                    DiagnosticCategory::Analysis,
                                    call.call_id.clone(),
                                    format!(
                                        "Cross-chunk link facts safety limit ({max_links}) exceeded; linking fact generation terminated early"
                                    ),
                                ));
                                let mut sorted_evidence = evidence.clone();
                                sorted_evidence.sort();
                                sorted_evidence.dedup();
                                links.push(CrossChunkLinkFact {
                                    call_id: call.call_id.clone(),
                                    caller_path: identity.path.clone(),
                                    caller_proto: call.proto_path.clone(),
                                    call_pc: call.pc,
                                    label_segments: segments,
                                    status: LinkStatus::LimitExceeded,
                                    target_artifact: None,
                                    target_proto: None,
                                    evidence: sorted_evidence,
                                });
                                break 'outer;
                            }

                            let candidates = &index.exports[&segments];
                            if candidates.len() == 1 {
                                let candidate = &candidates[0];
                                let mut combined_evidence = evidence.clone();
                                combined_evidence.extend(candidate.evidence.clone());
                                combined_evidence.sort();
                                combined_evidence.dedup();

                                links.push(CrossChunkLinkFact {
                                    call_id: call.call_id.clone(),
                                    caller_path: identity.path.clone(),
                                    caller_proto: call.proto_path.clone(),
                                    call_pc: call.pc,
                                    label_segments: segments,
                                    status: LinkStatus::Resolved,
                                    target_artifact: Some(candidate.defining_artifact.clone()),
                                    target_proto: Some(candidate.defining_proto.clone()),
                                    evidence: combined_evidence,
                                });
                            } else {
                                let mut sorted_evidence = evidence.clone();
                                for candidate in candidates {
                                    sorted_evidence.extend(candidate.evidence.clone());
                                }
                                sorted_evidence.sort();
                                sorted_evidence.dedup();

                                links.push(CrossChunkLinkFact {
                                    call_id: call.call_id.clone(),
                                    caller_path: identity.path.clone(),
                                    caller_proto: call.proto_path.clone(),
                                    call_pc: call.pc,
                                    label_segments: segments,
                                    status: LinkStatus::Duplicate,
                                    target_artifact: None,
                                    target_proto: None,
                                    evidence: sorted_evidence,
                                });
                            }
                        }
                    }
                    let _ = lookup_kind;
                }
                _ => {}
            }
        }
    }

    // Deterministic sort: caller_path, caller_proto, call_pc, call_id
    links.sort_by(|a, b| {
        a.caller_path
            .cmp(&b.caller_path)
            .then_with(|| a.caller_proto.cmp(&b.caller_proto))
            .then_with(|| a.call_pc.cmp(&b.call_pc))
            .then_with(|| a.call_id.cmp(&b.call_id))
    });

    ChunkLinkResult {
        facts: links,
        diagnostics,
    }
}

/// Analyze cross-chunk links across an entire batch corpus.
#[must_use]
pub fn analyze_corpus_links(
    chunks: &[(InputIdentity, Chunk)],
    convention: LinkConvention,
) -> Vec<CrossChunkLinkFact> {
    let (links, _) = analyze_corpus_links_detailed(chunks, convention);
    links
}

/// Analyze cross-chunk links across an entire batch corpus and return accumulated diagnostics.
#[must_use]
pub fn analyze_corpus_links_detailed(
    chunks: &[(InputIdentity, Chunk)],
    convention: LinkConvention,
) -> (Vec<CrossChunkLinkFact>, Vec<Diagnostic>) {
    let index = build_module_export_index(chunks.iter().map(|(id, c)| (id, c)), convention);
    let mut all_links = Vec::new();
    let mut all_diagnostics = index.diagnostics.clone();

    for (identity, chunk) in chunks {
        let result = resolve_chunk_links(identity, chunk, &index, convention);
        all_links.extend(result.facts);
        for diag in result.diagnostics {
            if !all_diagnostics.iter().any(|d| d.code == diag.code) {
                all_diagnostics.push(diag);
            }
        }
    }

    // Deterministic sort: caller_path, caller_proto, call_pc, call_id
    all_links.sort_by(|a, b| {
        a.caller_path
            .cmp(&b.caller_path)
            .then_with(|| a.caller_proto.cmp(&b.caller_proto))
            .then_with(|| a.call_pc.cmp(&b.call_pc))
            .then_with(|| a.call_id.cmp(&b.call_id))
    });

    (all_links, all_diagnostics)
}
