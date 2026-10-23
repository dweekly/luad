//! One-hop caller attribution assembled from accepted call-relation, link and origin facts.
//!
//! No resolution rule lives here. Each physical call site of an analyzed file is placed in
//! exactly one class from facts other analyses already proved, so a caller list can be
//! read beside the residue that might still reach the target.

use std::collections::BTreeMap;

use luad_core::envelope::InputIdentity;
use luad_core::{ProtoPath, StableId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    CallArgumentWindow, CallRelationBasis, CallRelationResolution, CallRelationUnresolvedReason,
    CalleeResolution, CalleeUnresolvedReason, ChunkCallRelationAnalysis, ChunkCalleeAnalysis,
    ChunkLinkResult, ChunkOriginAnalysis, CrossChunkLinkFact, LinkConvention, LinkStatus,
};

/// One accepted fact naming the target as a call site's callee.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CallerBasis {
    /// A same-artifact call relation.
    CallRelation {
        basis: CallRelationBasis,
        evidence: Vec<StableId>,
    },
    /// A resolved cross-chunk link under the requested convention.
    CrossChunkLink {
        convention: String,
        label_segments: Vec<String>,
        evidence: Vec<StableId>,
    },
}

/// One call site whose callee accepted facts prove to be the target.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CallerSite {
    pub caller: InputIdentity,
    pub caller_proto: ProtoPath,
    pub pc: usize,
    pub call_id: StableId,
    pub call_kind: String,
    pub bases: Vec<CallerBasis>,
    /// The site's argument window from origin analysis, verbatim.
    pub argument_window: CallArgumentWindow,
}

/// Exactly-once classification counts for every call site of one analyzed file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallSiteCounts {
    pub call_sites: usize,
    pub caller: usize,
    pub conflicting: usize,
    /// Sites weakened by a limit or by index uncertainty, by first reason.
    pub degraded: BTreeMap<String, usize>,
    pub attributed_elsewhere: usize,
    /// A proven label or lookup the requested convention did not map to any definition.
    pub unmapped_label: usize,
    /// Sites with no proven callee, by first reason.
    pub unattributed: BTreeMap<String, usize>,
}

impl CallSiteCounts {
    /// Sum of all classes; equals `call_sites` by construction.
    #[must_use]
    pub fn classified(&self) -> usize {
        self.caller
            + self.conflicting
            + self.degraded.values().sum::<usize>()
            + self.attributed_elsewhere
            + self.unmapped_label
            + self.unattributed.values().sum::<usize>()
    }

    /// Whether any site in this file was classed degraded.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        !self.degraded.is_empty()
    }
}

/// The class of one call site with respect to the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SiteClass {
    Caller(Vec<CallerBasis>),
    Conflicting,
    Degraded(String),
    AttributedElsewhere,
    UnmappedLabel,
    Unattributed(String),
}

/// Facts for one analyzed corpus file.
pub struct CallerFileFacts<'a> {
    pub identity: &'a InputIdentity,
    pub callees: &'a ChunkCalleeAnalysis,
    /// Present for the target's own artifact only.
    pub relations: Option<&'a ChunkCallRelationAnalysis>,
    /// Present when a link convention was requested.
    pub links: Option<(&'a ChunkLinkResult, LinkConvention)>,
}

/// A site that classified as a caller, before its argument window is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributedCaller {
    pub caller_proto: ProtoPath,
    pub pc: usize,
    pub call_id: StableId,
    pub call_kind: String,
    pub bases: Vec<CallerBasis>,
}

/// Classification of every call site in one analyzed file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileCallerAttribution {
    pub callers: Vec<AttributedCaller>,
    pub counts: CallSiteCounts,
}

fn is_limit_callee(reason: CalleeUnresolvedReason) -> bool {
    matches!(
        reason,
        CalleeUnresolvedReason::PathLimit | CalleeUnresolvedReason::AnalysisLimit
    )
}

fn is_limit_relation(reason: CallRelationUnresolvedReason) -> bool {
    matches!(
        reason,
        CallRelationUnresolvedReason::PathLimit | CallRelationUnresolvedReason::AnalysisLimit
    )
}

/// The serialized (kebab-case) name of a reason; callee reasons share these names.
fn reason_name(reason: CallRelationUnresolvedReason) -> &'static str {
    use CallRelationUnresolvedReason as R;
    match reason {
        R::MissingDefinition => "missing-definition",
        R::ControlFlowConflict => "control-flow-conflict",
        R::DynamicKey => "dynamic-key",
        R::Overwritten => "overwritten",
        R::CallResult => "call-result",
        R::OpenRegisterWindow => "open-register-window",
        R::UnsupportedValue => "unsupported-value",
        R::UnsupportedInstruction => "unsupported-instruction",
        R::MutableCapture => "mutable-capture",
        R::AmbiguousCapture => "ambiguous-capture",
        R::PathLimit => "path-limit",
        R::AnalysisLimit => "analysis-limit",
        R::Unreachable => "unreachable",
        R::SymbolicPathOnly => "symbolic-path-only",
        R::MissingPrototypeStore => "missing-prototype-store",
        R::MultiplePrototypeStores => "multiple-prototype-stores",
        R::NonClosureStore => "non-closure-store",
        R::AmbiguousStoreValue => "ambiguous-store-value",
        R::LookupLabelOnly => "lookup-label-only",
    }
}

/// Classify every call site of one analyzed file against `target`.
#[must_use]
pub fn attribute_file_callers(
    target: &InputIdentity,
    target_proto: &ProtoPath,
    file: &CallerFileFacts<'_>,
) -> FileCallerAttribution {
    let relations: BTreeMap<&StableId, &CallRelationResolution> = file
        .relations
        .iter()
        .flat_map(|analysis| &analysis.prototypes)
        .flat_map(|prototype| &prototype.calls)
        .map(|fact| (&fact.call_id, &fact.resolution))
        .collect();
    let mut links: BTreeMap<&StableId, Vec<&CrossChunkLinkFact>> = BTreeMap::new();
    let mut link_cutoff = false;
    if let Some((result, _)) = file.links {
        for link in &result.facts {
            links.entry(&link.call_id).or_default().push(link);
        }
        link_cutoff = result.diagnostics.iter().any(|d| d.code == "ANA-LIMIT-002");
    }
    let convention = file.links.map(|(_, convention)| convention);

    let mut attribution = FileCallerAttribution::default();
    for call in file
        .callees
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
    {
        let relation = relations.get(&call.call_id).copied();
        let site_links = links.get(&call.call_id).map(Vec::as_slice).unwrap_or(&[]);
        let class = classify_site(
            target,
            target_proto,
            file.identity,
            &call.resolution,
            relation,
            site_links,
            convention,
            link_cutoff,
        );
        let counts = &mut attribution.counts;
        counts.call_sites += 1;
        match class {
            SiteClass::Caller(bases) => {
                counts.caller += 1;
                attribution.callers.push(AttributedCaller {
                    caller_proto: call.proto_path.clone(),
                    pc: call.pc,
                    call_id: call.call_id.clone(),
                    call_kind: call.call_kind.clone(),
                    bases,
                });
            }
            SiteClass::Conflicting => counts.conflicting += 1,
            SiteClass::Degraded(reason) => *counts.degraded.entry(reason).or_default() += 1,
            SiteClass::AttributedElsewhere => counts.attributed_elsewhere += 1,
            SiteClass::UnmappedLabel => counts.unmapped_label += 1,
            SiteClass::Unattributed(reason) => *counts.unattributed.entry(reason).or_default() += 1,
        }
    }
    attribution
}

#[allow(clippy::too_many_arguments)]
fn classify_site(
    target: &InputIdentity,
    target_proto: &ProtoPath,
    identity: &InputIdentity,
    callee: &CalleeResolution,
    relation: Option<&CallRelationResolution>,
    links: &[&CrossChunkLinkFact],
    convention: Option<LinkConvention>,
    link_cutoff: bool,
) -> SiteClass {
    let mut target_bases = Vec::new();
    let mut names_other = false;
    if let Some(CallRelationResolution::Resolved {
        callee: proto,
        basis,
        evidence,
    }) = relation
    {
        if identity == target && proto == target_proto {
            target_bases.push(CallerBasis::CallRelation {
                basis: *basis,
                evidence: evidence.clone(),
            });
        } else {
            names_other = true;
        }
    }
    if relation.is_none() {
        // Outside the target artifact a proven closure names a local prototype.
        if let CalleeResolution::ResolvedPrototype { .. } = callee {
            names_other = names_other || identity != target;
        }
    }
    for link in links {
        if link.status != LinkStatus::Resolved {
            continue;
        }
        let reaches_target = link.target_artifact.as_ref() == Some(target)
            && link.target_proto.as_ref() == Some(target_proto);
        if reaches_target {
            target_bases.push(CallerBasis::CrossChunkLink {
                convention: convention.map_or("", LinkConvention::as_str).to_string(),
                label_segments: link.label_segments.clone(),
                evidence: link.evidence.clone(),
            });
        } else {
            names_other = true;
        }
    }

    if !target_bases.is_empty() {
        return if names_other {
            SiteClass::Conflicting
        } else {
            SiteClass::Caller(target_bases)
        };
    }

    if let CalleeResolution::Unresolved { reason } = callee {
        if is_limit_callee(*reason) {
            return SiteClass::Degraded(format!("callee:{}", reason_name((*reason).into())));
        }
    }
    if let Some(CallRelationResolution::Unresolved { reason, .. }) = relation {
        if is_limit_relation(*reason) {
            return SiteClass::Degraded(format!("call_relation:{}", reason_name(*reason)));
        }
    }
    for link in links {
        if matches!(link.status, LinkStatus::Dynamic | LinkStatus::LimitExceeded) {
            return SiteClass::Degraded(format!("link:{}", link.status));
        }
    }
    if convention.is_some() && links.is_empty() && link_cutoff {
        return SiteClass::Degraded("link:cutoff".to_string());
    }

    if names_other {
        return SiteClass::AttributedElsewhere;
    }

    let proven_label = matches!(
        callee,
        CalleeResolution::ResolvedPath { .. } | CalleeResolution::LookupLabel { .. }
    );
    // A relation that only reports the label is the same proof as the callee's label.
    let relation_label_only = relation.is_none_or(|resolution| {
        matches!(
            resolution,
            CallRelationResolution::Unresolved {
                reason: CallRelationUnresolvedReason::SymbolicPathOnly
                    | CallRelationUnresolvedReason::LookupLabelOnly,
                ..
            }
        )
    });
    if convention.is_some() && links.is_empty() && proven_label && relation_label_only {
        return SiteClass::UnmappedLabel;
    }

    if let CalleeResolution::Unresolved { reason } = callee {
        return SiteClass::Unattributed(format!("callee:{}", reason_name((*reason).into())));
    }
    if let Some(CallRelationResolution::Unresolved { reason, .. }) = relation {
        return SiteClass::Unattributed(format!("call_relation:{}", reason_name(*reason)));
    }
    if let Some(link) = links.first() {
        return SiteClass::Unattributed(format!("link:{}", link.status));
    }
    // A proven label outside any requested convention, in a file analyzed without links.
    SiteClass::Unattributed("cross_artifact:not-requested".to_string())
}

/// Attach each caller's verbatim argument window. A caller without an origin fact is an
/// internal inconsistency between accepted analyses and is returned as an error.
pub fn attach_argument_windows(
    caller: &InputIdentity,
    attributed: Vec<AttributedCaller>,
    origins: &ChunkOriginAnalysis,
) -> Result<Vec<CallerSite>, StableId> {
    let windows: BTreeMap<&StableId, &CallArgumentWindow> = origins
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
        .map(|fact| (&fact.call_id, &fact.argument_window))
        .collect();
    attributed
        .into_iter()
        .map(|site| {
            let window = windows
                .get(&site.call_id)
                .copied()
                .cloned()
                .ok_or_else(|| site.call_id.clone())?;
            Ok(CallerSite {
                caller: caller.clone(),
                caller_proto: site.caller_proto,
                pc: site.pc,
                call_id: site.call_id,
                call_kind: site.call_kind,
                bases: site.bases,
                argument_window: window,
            })
        })
        .collect()
}
