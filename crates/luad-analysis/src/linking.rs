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
    analyze_chunk_callees, analyze_root_global_stores, CalleeResolution, GlobalStoreValue,
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
    /// One admitted definition in a complete index under the selected convention.
    Resolved,
    /// No admitted definition for the selected label in a complete convention index.
    Absent,
    /// At least two admitted definitions exist for this export label.
    Duplicate,
    /// Initialization, final value, or provider completeness is uncertain.
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
    /// Artifacts with unadmitted initialization or incomplete provider input.
    pub dynamic_artifacts: BTreeSet<String>,
    /// Evidence for initialization or provider uncertainty in the corpus.
    pub dynamic_evidence: Vec<StableId>,
    /// Whether indexing was capped by the safety limit.
    pub export_limit_exceeded: bool,
    /// Diagnostics accumulated during indexing.
    pub diagnostics: Vec<Diagnostic>,
}

pub const MAX_INDEXED_EXPORTS: usize = 10_000;
pub const MAX_LINK_FACTS: usize = 100_000;

/// Physical words admitted before allocating semantic instructions.
pub const MAX_MODULE_INIT_WORDS: usize = 16_384;
/// Sum of referenced constant representations, counted once per physical use.
pub const MAX_MODULE_INIT_CONSTANT_BYTES: usize = 16 * 1024 * 1024;
/// Bound the proof-ID sets copied by the shared root transfer authority.
pub const MAX_MODULE_INIT_ALIAS_STEPS: usize = 64;
/// Charge both index-key and retained-definition label payloads.
pub const MAX_MODULE_INDEX_LABEL_BYTES: usize = 32 * 1024 * 1024;

enum ModuleDeclaration {
    Literal {
        segments: Vec<String>,
        evidence: Vec<StableId>,
    },
    Dynamic {
        evidence: Vec<StableId>,
    },
    Limited,
}

fn is_lua51(dialect: &str) -> bool {
    matches!(dialect, "lua5.1" | "lua5.1-lnum32" | "lua5.1-stock32")
}

fn string_bytes(value: &ConstantValue) -> Option<&[u8]> {
    match value {
        ConstantValue::ShortString(s) | ConstantValue::LongString(s) => Some(&s.raw_bytes),
        _ => None,
    }
}

fn admitted_selector(bytes: &[u8]) -> bool {
    !bytes.is_empty()
        && bytes
            .iter()
            .all(|b| (0x20..=0x7e).contains(b) && !matches!(b, b'\\' | b'"'))
}

fn as_str_constant(value: &ConstantValue) -> Option<String> {
    string_bytes(value)
        .and_then(|b| std::str::from_utf8(b).ok())
        .map(str::to_owned)
}

fn has_module_lookup(chunk: &Chunk) -> bool {
    use luad_dialect_lua51::{Opcode51, RawInstruction51};
    let mut pending = vec![&chunk.main_proto];
    while let Some(proto) = pending.pop() {
        let roles = luad_dialect_lua51::roles::discover_roles_lua51(proto);
        for (pc, word) in proto.instructions.iter().enumerate() {
            let raw = RawInstruction51::decode(word.raw_word);
            if roles.is_executable(pc)
                && raw.opcode == Some(Opcode51::GetGlobal)
                && proto
                    .constants
                    .get(raw.bx as usize)
                    .and_then(|c| string_bytes(&c.value))
                    == Some(b"module")
            {
                return true;
            }
        }
        pending.extend(&proto.protos);
    }
    false
}

/// Admit a small declarative initialization language, not arbitrary Lua execution.
/// Register tokens only recognize the direct module call and package.seeall;
/// closure values and aliases remain the shared store authority's responsibility.
fn detect_module_declaration(chunk: &Chunk) -> Option<ModuleDeclaration> {
    use luad_dialect_lua51::{Opcode51 as Op, RawInstruction51};
    if !is_lua51(&chunk.dialect) {
        return None;
    }
    let refused = || ModuleDeclaration::Dynamic {
        evidence: vec![chunk.main_proto.id.clone()],
    };
    if crate::validate_for_analysis(chunk).is_err() {
        return Some(refused());
    }
    if !has_module_lookup(chunk) {
        return None;
    }
    let p = &chunk.main_proto;
    if p.instructions.len() > MAX_MODULE_INIT_WORDS {
        return Some(ModuleDeclaration::Limited);
    }
    let roles = luad_dialect_lua51::roles::discover_roles_lua51(p);
    #[derive(Clone, Copy)]
    enum Token<'a> {
        Other,
        Module,
        Package,
        Seeall,
        Literal(&'a [u8], usize),
    }
    let mut registers = [Token::Other; 256];
    let mut proof_steps = [0usize; 256];
    let mut module_loads = 0;
    let mut module_load_pc = 0;
    let mut declaration = None;
    let mut returned = false;
    let mut constant_bytes = 0usize;
    for (pc, word) in p.instructions.iter().enumerate() {
        if !roles.is_executable(pc) {
            continue;
        }
        if returned {
            return Some(refused());
        }
        let raw = RawInstruction51::decode(word.raw_word);
        let key = match raw.opcode {
            Some(Op::LoadK | Op::GetGlobal | Op::SetGlobal) => Some(raw.bx as usize),
            Some(Op::GetTable) if raw.c >= 256 => Some((raw.c - 256) as usize),
            _ => None,
        };
        if let Some(key) = key {
            let Some(c) = p.constants.get(key) else {
                return Some(refused());
            };
            let size = match &c.value {
                ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
                    s.raw_bytes.len().saturating_add(s.display.len())
                }
                ConstantValue::Float { raw_hex, .. } | ConstantValue::Integer { raw_hex, .. } => {
                    raw_hex.len()
                }
                _ => 1,
            };
            constant_bytes = constant_bytes.saturating_add(size);
            if constant_bytes > MAX_MODULE_INIT_CONSTANT_BYTES {
                return Some(ModuleDeclaration::Limited);
            }
        }
        let a = raw.a as usize;
        match raw.opcode {
            Some(Op::GetGlobal) => {
                proof_steps[a] = 1;
                let name = p
                    .constants
                    .get(raw.bx as usize)
                    .and_then(|c| string_bytes(&c.value));
                registers[a] = match name {
                    Some(b"module") => {
                        module_loads += 1;
                        module_load_pc = pc;
                        Token::Module
                    }
                    Some(b"package") => Token::Package,
                    _ => Token::Other,
                };
                if module_loads > 1 {
                    return Some(refused());
                }
            }
            Some(Op::LoadK) => {
                proof_steps[a] = 1;
                registers[a] = p
                    .constants
                    .get(raw.bx as usize)
                    .and_then(|c| string_bytes(&c.value))
                    .map_or(Token::Other, |s| Token::Literal(s, pc));
            }
            Some(Op::GetTable) => {
                let seeall = raw.b < 256
                    && matches!(registers[raw.b as usize], Token::Package)
                    && raw.c >= 256
                    && p.constants
                        .get((raw.c - 256) as usize)
                        .and_then(|c| string_bytes(&c.value))
                        == Some(b"seeall");
                if !seeall || declaration.is_some() {
                    return Some(refused());
                }
                proof_steps[a] = proof_steps[raw.b as usize] + 1;
                registers[a] = Token::Seeall;
            }
            Some(Op::Call) => {
                if declaration.is_some()
                    || !matches!(registers[a], Token::Module)
                    || raw.c != 1
                    || !(raw.b == 2
                        || (raw.b == 3 && a + 2 < 256 && matches!(registers[a + 2], Token::Seeall)))
                {
                    return Some(refused());
                }
                let Some(Token::Literal(name, load_pc)) = registers.get(a + 1) else {
                    return Some(refused());
                };
                let Ok(name) = std::str::from_utf8(name) else {
                    return Some(refused());
                };
                // Lua 5.1.5 loadlib.c::ll_module passes the name through C-string
                // APIs. Never map an embedded NUL as a complete Lua namespace.
                if name.as_bytes().contains(&0) {
                    return Some(refused());
                }
                // Callee segments are escaped byte labels. Restrict this
                // convention to selectors whose raw and escaped spellings agree.
                if !admitted_selector(name.as_bytes()) {
                    return Some(refused());
                }
                // Callee symbolic paths admit at most 32 segments; reserve one
                // for the exported field and bound allocation before collecting.
                let parts: Vec<_> = name.split('.').take(32).collect();
                if parts.len() >= 32 {
                    return Some(ModuleDeclaration::Limited);
                }
                if parts.iter().any(|s| s.is_empty()) {
                    return Some(refused());
                }
                declaration = Some(ModuleDeclaration::Literal {
                    segments: parts.into_iter().map(str::to_owned).collect(),
                    evidence: vec![
                        p.instructions[module_load_pc].id.clone(),
                        p.instructions[*load_pc].id.clone(),
                        word.id.clone(),
                    ],
                });
                registers[a..].fill(Token::Other);
                proof_steps[a..].fill(0);
            }
            Some(Op::SetGlobal) => {
                if declaration.is_none()
                    || p.constants
                        .get(raw.bx as usize)
                        .and_then(|c| string_bytes(&c.value))
                        .filter(|s| admitted_selector(s))
                        .is_none()
                {
                    return Some(refused());
                }
            }
            Some(Op::LoadBool) if raw.c == 0 => {
                registers[a] = Token::Other;
                proof_steps[a] = 1;
            }
            Some(Op::LoadNil) => {
                if raw.b < raw.a as u16 {
                    return Some(refused());
                }
                let end = (raw.b as usize).min(255);
                registers[a..=end].fill(Token::Other);
                proof_steps[a..=end].fill(1);
            }
            Some(Op::Move) => {
                let steps = proof_steps
                    .get(raw.b as usize)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1);
                if steps > MAX_MODULE_INIT_ALIAS_STEPS {
                    return Some(ModuleDeclaration::Limited);
                }
                proof_steps[a] = steps;
                registers[a] = Token::Other;
            }
            Some(Op::Closure) => {
                registers[a] = Token::Other;
                proof_steps[a] = 1;
            }
            Some(Op::Return) if raw.b == 1 => returned = true,
            // This includes branches, skips, loops, table/upvalue mutation and
            // arbitrary calls. Even a read can invoke an unproved metamethod.
            _ => return Some(refused()),
        }
    }
    if !returned {
        return Some(refused());
    }
    declaration.or_else(|| Some(refused()))
}

fn mark_index_limit(index: &mut ModuleExportIndex, message: String) {
    index.export_limit_exceeded = true;
    if !index.diagnostics.iter().any(|d| d.code == "ANA-LIMIT-001") {
        index.diagnostics.push(Diagnostic::error(
            "ANA-LIMIT-001",
            DiagnosticCategory::Analysis,
            StableId::Chunk,
            message,
        ));
    }
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

    if !is_lua51(&chunk.dialect) {
        return;
    }

    match detect_module_declaration(chunk) {
        Some(ModuleDeclaration::Literal {
            segments: module_segments,
            evidence: mod_evidence,
        }) => {
            let Ok(stores) = analyze_root_global_stores(chunk) else {
                mark_index_limit(
                    index,
                    "Module initialization analysis exhausted; export index is incomplete".into(),
                );
                return;
            };
            let mut last_stores = BTreeMap::new();
            for store in stores {
                // Store facts are rooted in physical instruction identities, not
                // lexical child bodies. Sort by numeric PC rather than ID text.
                if let StableId::Instruction { proto, pc } = &store.store_id {
                    if proto == &ProtoPath::root() {
                        let entry = last_stores
                            .entry(store.name_raw.clone())
                            .or_insert((*pc, store.clone()));
                        if *pc >= entry.0 {
                            *entry = (*pc, store);
                        }
                    }
                }
            }
            let mut count: usize = index.exports.values().map(Vec::len).sum();
            let mut retained_label_bytes: usize = index
                .exports
                .values()
                .flatten()
                .map(|d| {
                    d.label_segments
                        .iter()
                        .map(String::len)
                        .sum::<usize>()
                        .saturating_mul(2)
                })
                .sum();
            let namespace_bytes: usize = module_segments.iter().map(String::len).sum();
            for (_, (_, store)) in last_stores {
                if let GlobalStoreValue::Closure {
                    prototype,
                    evidence,
                } = store.value
                {
                    if count >= max_exports {
                        mark_index_limit(index, format!("Corpus module export indexing safety limit ({max_exports} definitions) exceeded; cross-chunk linking is incomplete"));
                        continue;
                    }
                    let label_cost = namespace_bytes
                        .saturating_add(store.name_raw.len())
                        .saturating_mul(2);
                    if retained_label_bytes.saturating_add(label_cost)
                        > MAX_MODULE_INDEX_LABEL_BYTES
                    {
                        mark_index_limit(index, "Module index label payload budget exceeded; export index is incomplete".into());
                        continue;
                    }
                    retained_label_bytes += label_cost;
                    // Admission validated UTF-8; preserve raw bytes until this
                    // explicit boundary, never merge distinct lossy spellings.
                    let Ok(export_name) = String::from_utf8(store.name_raw) else {
                        unreachable!("admitted export name")
                    };
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
                    count += 1;
                } else if matches!(store.value, GlobalStoreValue::Unknown { .. }) {
                    index.dynamic_artifacts.insert(identity.path.clone());
                    index.dynamic_evidence.push(store.store_id);
                }
            }
        }
        Some(ModuleDeclaration::Limited) => mark_index_limit(
            index,
            "Module initialization admission budget exceeded; export index is incomplete".into(),
        ),
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
    // The caller supplies a bounded corpus. Stable preselection keeps a cap from
    // choosing a different apparent target when input arguments are permuted.
    let mut chunks: Vec<_> = chunks.into_iter().collect();
    chunks.sort_by(|(a, _), (b, _)| {
        (&a.path, &a.sha256, a.byte_length).cmp(&(&b.path, &b.sha256, b.byte_length))
    });
    chunks.dedup_by(|(a, _), (b, _)| *a == *b);
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

    if !is_lua51(&chunk.dialect) {
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
                    let escaped_selector =
                        segments.iter().any(|s| !admitted_selector(s.as_bytes()));
                    // Check if this path targets the module namespace. Escaped
                    // paths cannot be compared to admitted raw selectors.
                    if segments.first().is_some_and(|s| s == "luci")
                        || index.exports.contains_key(segments)
                        || escaped_selector
                        || ((!index.dynamic_artifacts.is_empty() || index.export_limit_exceeded)
                            && segments.len() > 1)
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
                            _ if escaped_selector => CrossChunkLinkFact {
                                call_id: call.call_id.clone(),
                                caller_path: identity.path.clone(),
                                caller_proto: call.proto_path.clone(),
                                call_pc: call.pc,
                                label_segments: segments.clone(),
                                status: LinkStatus::Dynamic,
                                target_artifact: None,
                                target_proto: None,
                                evidence: evidence.clone(),
                            },
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

    for link in &mut links {
        if matches!(link.status, LinkStatus::Resolved | LinkStatus::Absent) {
            let uncertain = if !index.dynamic_artifacts.is_empty() {
                Some(LinkStatus::Dynamic)
            } else if index.export_limit_exceeded {
                Some(LinkStatus::LimitExceeded)
            } else {
                None
            };
            if let Some(status) = uncertain {
                link.status = status;
                link.target_artifact = None;
                link.target_proto = None;
                link.evidence.extend(index.dynamic_evidence.iter().cloned());
                link.evidence.sort();
                link.evidence.dedup();
            }
        }
    }
    links.sort_by(compare_links);

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

    all_links.sort_by(compare_links);

    (all_links, all_diagnostics)
}

fn compare_links(a: &CrossChunkLinkFact, b: &CrossChunkLinkFact) -> std::cmp::Ordering {
    // Caller location is the primary order. All reported fields break ties, so
    // same-path/different-content library inputs cannot inherit iteration order.
    (
        &a.caller_path,
        &a.caller_proto,
        a.call_pc,
        &a.call_id,
        &a.label_segments,
        a.status as u8,
        a.target_artifact
            .as_ref()
            .map(|i| (&i.path, &i.sha256, i.byte_length)),
        &a.target_proto,
        &a.evidence,
    )
        .cmp(&(
            &b.caller_path,
            &b.caller_proto,
            b.call_pc,
            &b.call_id,
            &b.label_segments,
            b.status as u8,
            b.target_artifact
                .as_ref()
                .map(|i| (&i.path, &i.sha256, i.byte_length)),
            &b.target_proto,
            &b.evidence,
        ))
}
