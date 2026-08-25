//! Cross-reference indexing for registers, constants, upvalues, sub-prototypes, and jump targets.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use luad_core::id::StableId;
use luad_core::ir::EffectTarget;
use luad_core::model::{Chunk, Prototype};

/// Semantic nature of a reference.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum XrefRelation {
    /// Source reads from target.
    Reads,
    /// Source writes or mutates target.
    Writes,
    /// Source invokes or calls target function/closure.
    Calls,
    /// Source instantiates child prototype.
    Instantiates,
    /// Source branches or jumps to target instruction PC.
    JumpsTo,
    /// Parent closure instruction or binding descriptor binds to child upvalue.
    Binds,
}

/// A cross-reference relationship between two stable artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XrefEntry {
    /// Originating artifact StableId (e.g. `proto:0:pc:4`).
    pub source: StableId,
    /// Referenced target StableId (e.g. `proto:0:k:2`, `proto:0:upvalue:0`).
    pub target: StableId,
    /// Reference type.
    pub relation: XrefRelation,
}

/// Structured response for cross-reference queries over a chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XrefResponse {
    /// Target filter queried, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<StableId>,
    /// Source filter queried, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<StableId>,
    /// Matching cross-reference entries.
    pub entries: Vec<XrefEntry>,
    /// Total count of matching entries.
    pub total_count: usize,
}

/// Queryable cross-reference index over an entire chunk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct XrefIndex {
    /// All indexed cross-references.
    pub entries: Vec<XrefEntry>,
}

impl XrefIndex {
    /// Build a complete cross-reference index from a parsed chunk.
    #[must_use]
    pub fn build(chunk: &Chunk) -> Self {
        let mut index = Self::default();
        index.index_proto(&chunk.dialect, &chunk.main_proto);
        if chunk.dialect.starts_with("lua5.1") {
            let call_relations = crate::analyze_chunk_call_relations(chunk);
            for fact in call_relations
                .prototypes
                .into_iter()
                .flat_map(|prototype| prototype.calls)
            {
                if let crate::CallRelationResolution::Resolved { callee, .. } = fact.resolution {
                    index.entries.push(XrefEntry {
                        source: fact.call_id,
                        target: StableId::proto(callee),
                        relation: XrefRelation::Calls,
                    });
                }
            }
        }
        index.entries.sort_by(|left, right| {
            (&left.source, &left.target, left.relation).cmp(&(
                &right.source,
                &right.target,
                right.relation,
            ))
        });
        index.entries.dedup();
        index
    }

    fn index_proto(&mut self, dialect: &str, proto: &Prototype) {
        let lifted = crate::lift_proto_for_dialect(dialect, proto);

        for sem in &lifted {
            let src_id = sem.id.clone();

            // 1. Reads
            for r in &sem.reads {
                if let Some(target_id) = self.effect_to_stable_id(proto, r) {
                    self.entries.push(XrefEntry {
                        source: src_id.clone(),
                        target: target_id,
                        relation: XrefRelation::Reads,
                    });
                }
            }

            // 2. Writes
            for w in &sem.writes {
                if let Some(target_id) = self.effect_to_stable_id(proto, w) {
                    self.entries.push(XrefEntry {
                        source: src_id.clone(),
                        target: target_id,
                        relation: XrefRelation::Writes,
                    });
                }
            }

            // 3. Jumps
            if let Some(dest_pc) = sem.jump_target {
                self.entries.push(XrefEntry {
                    source: src_id.clone(),
                    target: StableId::instruction(proto.path.clone(), dest_pc),
                    relation: XrefRelation::JumpsTo,
                });
            }

            // 4. Closures & Binds
            if sem.mnemonic.starts_with("CLOSURE") {
                for op in &sem.operands {
                    if let luad_core::TypedOperand::Prototype {
                        index: child_idx,
                        path,
                    } = op
                    {
                        self.entries.push(XrefEntry {
                            source: src_id.clone(),
                            target: StableId::proto(path.clone()),
                            relation: XrefRelation::Instantiates,
                        });

                        if let Some(child_proto) = proto.protos.get(*child_idx) {
                            if dialect.starts_with("lua5.1") {
                                for upval_idx in 0..child_proto.upvalues.len() {
                                    let child_upval_id =
                                        StableId::upvalue(child_proto.path.clone(), upval_idx);
                                    let desc_pc = sem.pc + 1 + upval_idx;
                                    if let Some(descriptor) = lifted.get(desc_pc).filter(|desc| {
                                        desc.companion_pc == Some(sem.pc)
                                            && desc.implicit_effects.iter().any(|effect| {
                                                matches!(
                                                    effect,
                                                    luad_core::ImplicitEffect::CompanionPair {
                                                        companion_role,
                                                        ..
                                                    } if companion_role == "closure_binding"
                                                )
                                            })
                                    }) {
                                        if let Some(parent_id) =
                                            descriptor.reads.first().and_then(|read| match read {
                                                EffectTarget::Register { index } => {
                                                    Some(StableId::local(
                                                        proto.path.clone(),
                                                        *index as usize,
                                                    ))
                                                }
                                                EffectTarget::Upvalue { index, .. } => {
                                                    Some(StableId::upvalue(
                                                        proto.path.clone(),
                                                        *index as usize,
                                                    ))
                                                }
                                                _ => None,
                                            })
                                        {
                                            self.entries.push(XrefEntry {
                                                source: parent_id.clone(),
                                                target: child_upval_id.clone(),
                                                relation: XrefRelation::Binds,
                                            });
                                            self.entries.push(XrefEntry {
                                                source: descriptor.id.clone(),
                                                target: parent_id,
                                                relation: XrefRelation::Reads,
                                            });
                                        }
                                        self.entries.push(XrefEntry {
                                            source: descriptor.id.clone(),
                                            target: child_upval_id.clone(),
                                            relation: XrefRelation::Binds,
                                        });
                                    }
                                    self.entries.push(XrefEntry {
                                        source: src_id.clone(),
                                        target: child_upval_id,
                                        relation: XrefRelation::Binds,
                                    });
                                }
                            } else {
                                for (upval_idx, u) in child_proto.upvalues.iter().enumerate() {
                                    let child_upval_id =
                                        StableId::upvalue(child_proto.path.clone(), upval_idx);
                                    if u.instack == 1 {
                                        let parent_loc_id =
                                            StableId::local(proto.path.clone(), u.idx as usize);
                                        self.entries.push(XrefEntry {
                                            source: parent_loc_id,
                                            target: child_upval_id.clone(),
                                            relation: XrefRelation::Binds,
                                        });
                                    } else {
                                        let parent_upval_id =
                                            StableId::upvalue(proto.path.clone(), u.idx as usize);
                                        self.entries.push(XrefEntry {
                                            source: parent_upval_id,
                                            target: child_upval_id.clone(),
                                            relation: XrefRelation::Binds,
                                        });
                                    }
                                    self.entries.push(XrefEntry {
                                        source: src_id.clone(),
                                        target: child_upval_id,
                                        relation: XrefRelation::Binds,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        // Recursively index child prototypes
        for child in &proto.protos {
            self.index_proto(dialect, child);
        }
    }

    fn effect_to_stable_id(&self, proto: &Prototype, effect: &EffectTarget) -> Option<StableId> {
        match effect {
            EffectTarget::Constant { index } => {
                Some(StableId::constant(proto.path.clone(), *index))
            }
            EffectTarget::Upvalue { index, .. } => {
                Some(StableId::upvalue(proto.path.clone(), *index as usize))
            }
            EffectTarget::Prototype { path, .. } => Some(StableId::proto(path.clone())),
            EffectTarget::JumpTarget { pc } => Some(StableId::instruction(proto.path.clone(), *pc)),
            _ => None,
        }
    }

    /// Query all cross-references pointing TO a given target StableId.
    #[must_use]
    pub fn query_to(&self, target: &StableId) -> Vec<&XrefEntry> {
        self.entries
            .iter()
            .filter(|e| &e.target == target)
            .collect()
    }

    /// Query all cross-references originating FROM a given source StableId.
    #[must_use]
    pub fn query_from(&self, source: &StableId) -> Vec<&XrefEntry> {
        self.entries
            .iter()
            .filter(|e| &e.source == source)
            .collect()
    }
}

/// Recursively find a prototype with the given `ProtoPath` within a root prototype hierarchy.
#[must_use]
pub fn find_proto<'a>(
    root: &'a Prototype,
    path: &luad_core::id::ProtoPath,
) -> Option<&'a Prototype> {
    if &root.path == path {
        return Some(root);
    }
    for child in &root.protos {
        if let Some(p) = find_proto(child, path) {
            return Some(p);
        }
    }
    None
}

/// Validate whether a given `StableId` target exists within the parsed `Chunk`.
#[must_use]
pub fn validate_target(chunk: &Chunk, target: &StableId) -> bool {
    match target {
        StableId::Chunk => true,
        StableId::Proto(path) => find_proto(&chunk.main_proto, path).is_some(),
        StableId::Instruction { proto, pc } => {
            if let Some(p) = find_proto(&chunk.main_proto, proto) {
                *pc < p.instructions.len()
            } else {
                false
            }
        }
        StableId::Constant { proto, index } => {
            if let Some(p) = find_proto(&chunk.main_proto, proto) {
                *index < p.constants.len()
            } else {
                false
            }
        }
        StableId::Upvalue { proto, index } => {
            if let Some(p) = find_proto(&chunk.main_proto, proto) {
                *index < p.upvalues.len()
            } else {
                false
            }
        }
        StableId::Local { proto, index } => {
            if let Some(p) = find_proto(&chunk.main_proto, proto) {
                *index < p.loc_vars.len()
            } else {
                false
            }
        }
        StableId::Block { proto, .. } => find_proto(&chunk.main_proto, proto).is_some(),
        StableId::Diagnostic { target, .. } => validate_target(chunk, target),
    }
}
