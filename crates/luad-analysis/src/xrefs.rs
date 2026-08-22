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

            // 4. Closures
            if sem.mnemonic == "CLOSURE" {
                for op in &sem.operands {
                    if let luad_core::TypedOperand::Prototype { path, .. } = op {
                        self.entries.push(XrefEntry {
                            source: src_id.clone(),
                            target: StableId::proto(path.clone()),
                            relation: XrefRelation::Instantiates,
                        });
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
