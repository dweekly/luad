//! Evidence-linked Lua 5.1 caller-to-prototype relations.

use std::collections::{BTreeMap, BTreeSet};

use luad_core::{ProtoPath, StableId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::callees::{
    analyze_chunk_global_lookups, analyze_chunk_global_stores, GlobalStoreFact, GlobalStoreValue,
};
use crate::{analyze_chunk_callees, CalleeResolution, CalleeUnresolvedReason, SymbolicPathBasis};

/// Closed evidence bases for a resolved caller-to-prototype relation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum CallRelationBasis {
    /// The callee value is an exact closure constructed in the caller's value flow.
    ClosureValue,
    /// A literal global path has one closure-valued store in the analyzed chunk.
    UniqueGlobalStore,
}

/// Closed reasons why no unique prototype relation is available.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum CallRelationUnresolvedReason {
    MissingDefinition,
    ControlFlowConflict,
    DynamicKey,
    Overwritten,
    CallResult,
    OpenRegisterWindow,
    UnsupportedValue,
    UnsupportedInstruction,
    MutableCapture,
    AmbiguousCapture,
    PathLimit,
    AnalysisLimit,
    Unreachable,
    SymbolicPathOnly,
    MissingPrototypeStore,
    MultiplePrototypeStores,
    NonClosureStore,
    AmbiguousStoreValue,
    LookupLabelOnly,
}

impl From<CalleeUnresolvedReason> for CallRelationUnresolvedReason {
    fn from(reason: CalleeUnresolvedReason) -> Self {
        match reason {
            CalleeUnresolvedReason::MissingDefinition => Self::MissingDefinition,
            CalleeUnresolvedReason::ControlFlowConflict => Self::ControlFlowConflict,
            CalleeUnresolvedReason::DynamicKey => Self::DynamicKey,
            CalleeUnresolvedReason::Overwritten => Self::Overwritten,
            CalleeUnresolvedReason::CallResult => Self::CallResult,
            CalleeUnresolvedReason::OpenRegisterWindow => Self::OpenRegisterWindow,
            CalleeUnresolvedReason::UnsupportedValue => Self::UnsupportedValue,
            CalleeUnresolvedReason::UnsupportedInstruction => Self::UnsupportedInstruction,
            CalleeUnresolvedReason::MutableCapture => Self::MutableCapture,
            CalleeUnresolvedReason::AmbiguousCapture => Self::AmbiguousCapture,
            CalleeUnresolvedReason::PathLimit => Self::PathLimit,
            CalleeUnresolvedReason::AnalysisLimit => Self::AnalysisLimit,
            CalleeUnresolvedReason::Unreachable => Self::Unreachable,
        }
    }
}

/// Resolution attached to one physical call instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum CallRelationResolution {
    Resolved {
        callee: ProtoPath,
        basis: CallRelationBasis,
        evidence: Vec<StableId>,
    },
    Unresolved {
        reason: CallRelationUnresolvedReason,
        evidence: Vec<StableId>,
    },
}

/// One total caller-to-prototype result for a physical call instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallRelationFact {
    pub call_id: StableId,
    pub caller: ProtoPath,
    pub pc: usize,
    pub call_kind: String,
    pub resolution: CallRelationResolution,
}

/// Call-relation facts for one prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallRelationAnalysis {
    pub proto_id: StableId,
    pub calls: Vec<CallRelationFact>,
}

/// Call-relation facts for every prototype in one chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ChunkCallRelationAnalysis {
    pub prototypes: Vec<CallRelationAnalysis>,
}

/// Analyze every physical Lua 5.1 call against exact closure and unique global-store facts.
#[must_use]
pub fn analyze_chunk_call_relations(chunk: &luad_core::model::Chunk) -> ChunkCallRelationAnalysis {
    let stores = index_global_stores(analyze_chunk_global_stores(chunk));
    let lookups = analyze_chunk_global_lookups(chunk);
    let callees = analyze_chunk_callees(chunk);
    let prototypes = callees
        .prototypes
        .into_iter()
        .map(|prototype| CallRelationAnalysis {
            proto_id: prototype.proto_id,
            calls: prototype
                .calls
                .into_iter()
                .map(|call| CallRelationFact {
                    call_id: call.call_id,
                    caller: call.proto_path,
                    pc: call.pc,
                    call_kind: call.call_kind,
                    resolution: resolve_relation(call.resolution, &stores, &lookups),
                })
                .collect(),
        })
        .collect();
    ChunkCallRelationAnalysis { prototypes }
}

fn index_global_stores(stores: Vec<GlobalStoreFact>) -> BTreeMap<Vec<u8>, Vec<GlobalStoreFact>> {
    let mut index: BTreeMap<Vec<u8>, Vec<GlobalStoreFact>> = BTreeMap::new();
    for store in stores {
        index.entry(store.name_raw.clone()).or_default().push(store);
    }
    index
}

fn resolve_relation(
    callee: CalleeResolution,
    stores: &BTreeMap<Vec<u8>, Vec<GlobalStoreFact>>,
    lookups: &BTreeMap<StableId, Vec<u8>>,
) -> CallRelationResolution {
    match callee {
        CalleeResolution::LookupLabel { evidence, .. } => {
            unresolved(CallRelationUnresolvedReason::LookupLabelOnly, evidence)
        }
        CalleeResolution::ResolvedPrototype {
            prototype,
            evidence,
        } => resolved(prototype, CallRelationBasis::ClosureValue, evidence),
        CalleeResolution::ResolvedPath {
            basis: SymbolicPathBasis::GlobalLabel,
            segments,
            evidence,
        } if segments.len() == 1 => {
            let names = evidence
                .iter()
                .filter_map(|id| lookups.get(id).cloned())
                .collect::<BTreeSet<_>>();
            if names.len() == 1 {
                resolve_global(
                    names.iter().next().expect("one lookup name"),
                    evidence,
                    stores,
                )
            } else {
                unresolved(CallRelationUnresolvedReason::SymbolicPathOnly, evidence)
            }
        }
        CalleeResolution::ResolvedPath { evidence, .. } => {
            unresolved(CallRelationUnresolvedReason::SymbolicPathOnly, evidence)
        }
        CalleeResolution::Unresolved { reason } => unresolved(reason.into(), []),
    }
}

fn resolve_global(
    name_raw: &[u8],
    lookup_evidence: Vec<StableId>,
    stores: &BTreeMap<Vec<u8>, Vec<GlobalStoreFact>>,
) -> CallRelationResolution {
    let Some(candidates) = stores.get(name_raw) else {
        return unresolved(
            CallRelationUnresolvedReason::MissingPrototypeStore,
            lookup_evidence,
        );
    };
    if candidates.len() != 1 {
        return unresolved(
            CallRelationUnresolvedReason::MultiplePrototypeStores,
            lookup_evidence.into_iter().chain(
                candidates
                    .iter()
                    .map(|candidate| candidate.store_id.clone()),
            ),
        );
    }
    match &candidates[0].value {
        GlobalStoreValue::Closure {
            prototype,
            evidence,
        } => resolved(
            prototype.clone(),
            CallRelationBasis::UniqueGlobalStore,
            lookup_evidence.iter().chain(evidence).cloned(),
        ),
        GlobalStoreValue::NonClosure { evidence } => unresolved(
            CallRelationUnresolvedReason::NonClosureStore,
            lookup_evidence.iter().chain(evidence).cloned(),
        ),
        GlobalStoreValue::Unknown { reason } => unresolved(
            match reason {
                CalleeUnresolvedReason::AnalysisLimit => {
                    CallRelationUnresolvedReason::AnalysisLimit
                }
                _ => CallRelationUnresolvedReason::AmbiguousStoreValue,
            },
            lookup_evidence
                .into_iter()
                .chain([candidates[0].store_id.clone()]),
        ),
    }
}

fn resolved(
    callee: ProtoPath,
    basis: CallRelationBasis,
    evidence: impl IntoIterator<Item = StableId>,
) -> CallRelationResolution {
    CallRelationResolution::Resolved {
        callee,
        basis,
        evidence: normalize_evidence(evidence),
    }
}

fn unresolved(
    reason: CallRelationUnresolvedReason,
    evidence: impl IntoIterator<Item = StableId>,
) -> CallRelationResolution {
    CallRelationResolution::Unresolved {
        reason,
        evidence: normalize_evidence(evidence),
    }
}

fn normalize_evidence(evidence: impl IntoIterator<Item = StableId>) -> Vec<StableId> {
    evidence
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callee_stop_reasons_have_total_call_relation_mapping() {
        let reasons = [
            CalleeUnresolvedReason::MissingDefinition,
            CalleeUnresolvedReason::ControlFlowConflict,
            CalleeUnresolvedReason::DynamicKey,
            CalleeUnresolvedReason::Overwritten,
            CalleeUnresolvedReason::CallResult,
            CalleeUnresolvedReason::OpenRegisterWindow,
            CalleeUnresolvedReason::UnsupportedValue,
            CalleeUnresolvedReason::UnsupportedInstruction,
            CalleeUnresolvedReason::MutableCapture,
            CalleeUnresolvedReason::AmbiguousCapture,
            CalleeUnresolvedReason::PathLimit,
            CalleeUnresolvedReason::AnalysisLimit,
            CalleeUnresolvedReason::Unreachable,
        ];
        assert_eq!(
            reasons
                .into_iter()
                .map(CallRelationUnresolvedReason::from)
                .collect::<BTreeSet<_>>()
                .len(),
            reasons.len()
        );
    }
}
