//! `luad callers`: one-hop caller attribution over an explicit corpus.
//!
//! Every fact comes from an accepted analysis; this module reads the corpus once,
//! classifies each call site exactly once and renders the answer with its coverage.

use std::collections::BTreeMap;
use std::io;

use colored::Colorize;
use luad_analysis::{
    analyze_chunk_call_relations, analyze_chunk_callees, analyze_chunk_origins,
    analyze_chunk_prototype_identities, attach_argument_windows, attribute_file_callers,
    index_chunk_module_exports, resolve_chunk_links, validate_for_analysis, CallSiteCounts,
    CallerFileFacts, CallerSite, LinkConvention, ModuleExportIndex, PrototypeIdentityFact,
};
use luad_core::diagnostic::Diagnostic;
use luad_core::dialect::ResolvedInterpretation;
use luad_core::envelope::{
    AnalysisConfiguration, InputIdentity, JsonlDataRecord, JsonlMetadataRecord, JsonlRecordContext,
};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::Chunk;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::args::{CallersArgs, OutputFormat};
use crate::exit_codes::ExitCode;

/// Total corpus bytes read before any analysis; repeated per-file work is charged here.
pub const MAX_CALLERS_CORPUS_BYTES: usize = 512 * 1024 * 1024;

const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];

/// The prototype whose callers are listed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CallersTarget {
    pub proto: ProtoPath,
    pub proto_id: StableId,
    /// Existing structural identity of the target prototype's subtree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prototype_identity: Option<PrototypeIdentityFact>,
}

/// What happened to one corpus input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CallersFileStatus {
    Analyzed,
    Failed,
    UnsupportedProfile,
    Unreadable,
}

/// Coverage for one corpus input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CallersFileCoverage {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_identity: Option<InputIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpretation: Option<ResolvedInterpretation>,
    pub status: CallersFileStatus,
    pub is_target: bool,
    /// Exactly-once call-site classes; present for analyzed inputs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<CallSiteCounts>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

/// Terminal accounting for one answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallersSummary {
    pub caller_count: usize,
    pub callers_omitted: usize,
    pub files_analyzed: usize,
    pub files_failed: usize,
    pub files_unsupported: usize,
    pub files_unreadable: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_convention: Option<String>,
    /// False when no convention was requested: other artifacts were not searched.
    pub cross_artifact_searched: bool,
    pub is_truncated: bool,
    /// Every corpus input was analyzed.
    pub coverage_complete: bool,
    /// A limit or index uncertainty weakened attribution somewhere in the corpus.
    pub degraded: bool,
    /// Providers whose definitions the convention index could not admit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dynamic_providers: Vec<String>,
}

/// `luad callers` payload. An empty `callers` list means no observed caller in the
/// analyzed corpus, never unreachable code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CallersAnswer {
    pub target: CallersTarget,
    pub callers: Vec<CallerSite>,
    pub files: Vec<CallersFileCoverage>,
    pub summary: CallersSummary,
}

#[derive(Serialize)]
struct CallersSummaryRecord<'a> {
    record_type: &'static str,
    #[serde(flatten)]
    summary: &'a CallersSummary,
}

enum Loaded {
    Parsed {
        chunk: Box<Chunk>,
        identity: InputIdentity,
        interpretation: ResolvedInterpretation,
        valid: Result<(), Vec<Diagnostic>>,
    },
    ParseFailed {
        identity: Option<InputIdentity>,
        diagnostic: Option<Box<Diagnostic>>,
    },
    Unreadable,
}

fn parse_target_proto(text: &str) -> Option<ProtoPath> {
    text.strip_prefix("proto:").unwrap_or(text).parse().ok()
}

fn is_limit_reason(reason: &str) -> bool {
    matches!(
        reason,
        "callee:path-limit"
            | "callee:analysis-limit"
            | "call_relation:path-limit"
            | "call_relation:analysis-limit"
            | "link:limit_exceeded"
            | "link:cutoff"
    )
}

pub(crate) fn handle_callers(
    args: CallersArgs,
    writer: &mut impl io::Write,
) -> io::Result<ExitCode> {
    let Some(target_proto) = parse_target_proto(&args.proto) else {
        eprintln!(
            "{}: invalid --proto '{}'; expected e.g. '0/1' or 'proto:0/1'",
            "error".red(),
            args.proto
        );
        return Ok(ExitCode::UsageError);
    };
    if args.max_callers == 0 {
        eprintln!("{}: --max-callers must be at least 1", "error".red());
        return Ok(ExitCode::UsageError);
    }
    if matches!(args.format, OutputFormat::Dot) {
        eprintln!("{}: DOT format not applicable to callers", "error".red());
        return Ok(ExitCode::UsageError);
    }
    let convention = match args.link_convention.as_deref() {
        Some(name) => match LinkConvention::parse(name) {
            Some(convention) => Some(convention),
            None => {
                eprintln!(
                    "{}: unknown link convention '{name}'. Supported conventions: {}",
                    "error".red(),
                    LinkConvention::all_names().join(", ")
                );
                return Ok(ExitCode::UsageError);
            }
        },
        None => None,
    };
    let mut corpus = args.corpus.clone();
    if let Some(list) = &args.input_list {
        match super::parse_input_list(list) {
            Ok(paths) => corpus.extend(paths),
            Err((message, code)) => {
                eprintln!("{}: {message}", "error".red());
                return Ok(code);
            }
        }
    }
    if convention.is_none() && !corpus.is_empty() {
        eprintln!(
            "{}: corpus files are searched only through a link convention; add --link-convention or omit them",
            "error".red()
        );
        return Ok(ExitCode::UsageError);
    }
    if args.target == "-" || corpus.iter().any(|path| path == "-") {
        eprintln!(
            "{}: callers needs replayable file inputs; stdin '-' is refused",
            "error".red()
        );
        return Ok(ExitCode::UsageError);
    }

    // The target decides whether an answer is possible at all.
    let target_bytes = match super::read_input_bytes(&args.target) {
        Ok(bytes) => bytes,
        Err(code) => return Ok(code),
    };
    let (target_chunk, target_identity, config, target_interp) = match super::parse_chunk(
        &args.target,
        &target_bytes,
        args.strict,
        args.dialect.as_deref(),
    ) {
        Ok(parsed) => parsed,
        Err(code) => return Ok(code),
    };
    if !LUA51_PROFILES.contains(&target_chunk.dialect.as_str()) {
        eprintln!(
            "{}: caller attribution currently requires a Lua 5.1 profile target",
            "error".red()
        );
        return Ok(ExitCode::UnsupportedFormat);
    }
    if let Err(diagnostics) = validate_for_analysis(&target_chunk) {
        return Ok(super::handle_analysis_validation_failure(
            "target",
            &diagnostics,
        ));
    }
    let target_proto_id = StableId::Proto(target_proto.clone());
    if super::find_proto_by_stable_id(&target_chunk.main_proto, &target_proto_id).is_none() {
        eprintln!(
            "{}: prototype '{target_proto_id}' not found in target",
            "error".red()
        );
        return Ok(ExitCode::UsageError);
    }

    // Deduplicate by canonical location so one artifact spelled two ways is indexed once.
    let canonical = |path: &str| std::fs::canonicalize(path).ok();
    let target_location = canonical(&args.target);
    let mut seen = std::collections::BTreeSet::new();
    let mut paths: Vec<String> = Vec::new();
    let mut sorted = corpus;
    sorted.sort();
    sorted.dedup();
    for path in sorted {
        let location = canonical(&path);
        if path == args.target || (location.is_some() && location == target_location) {
            continue;
        }
        if location.as_ref().is_some_and(|l| !seen.insert(l.clone())) {
            continue;
        }
        paths.push(path);
    }
    let mut total_bytes = target_bytes.len();
    let mut loaded: BTreeMap<String, Loaded> = BTreeMap::new();
    for path in &paths {
        let Ok(bytes) = super::read_input_bytes_with_reporting(path, false) else {
            loaded.insert(path.clone(), Loaded::Unreadable);
            continue;
        };
        total_bytes = total_bytes.saturating_add(bytes.len());
        if total_bytes > MAX_CALLERS_CORPUS_BYTES {
            eprintln!(
                "{}: corpus exceeds the {MAX_CALLERS_CORPUS_BYTES}-byte aggregate ceiling",
                "error".red()
            );
            return Ok(ExitCode::LimitExceeded);
        }
        let entry = match super::parse_chunk_detailed(
            path,
            &bytes,
            args.strict,
            args.dialect.as_deref(),
            false,
        ) {
            Ok((chunk, identity, _config, interpretation)) => {
                let valid = if LUA51_PROFILES.contains(&chunk.dialect.as_str()) {
                    validate_for_analysis(&chunk)
                } else {
                    Ok(())
                };
                Loaded::Parsed {
                    chunk: Box::new(chunk),
                    identity,
                    interpretation,
                    valid,
                }
            }
            Err((_code, diagnostic)) => Loaded::ParseFailed {
                identity: Some(InputIdentity {
                    path: path.clone(),
                    sha256: hex::encode(Sha256::digest(&bytes)),
                    byte_length: bytes.len(),
                }),
                diagnostic,
            },
        };
        loaded.insert(path.clone(), entry);
    }

    let mut index = ModuleExportIndex::default();
    if let Some(convention) = convention {
        index_chunk_module_exports(&target_identity, &target_chunk, convention, &mut index);
        for (path, entry) in &loaded {
            match entry {
                Loaded::Parsed {
                    chunk,
                    identity,
                    valid: Ok(()),
                    ..
                } => index_chunk_module_exports(identity, chunk, convention, &mut index),
                // A provider that could not be read, parsed or validated may conceal a
                // definition, exactly as export treats it.
                _ => {
                    index.dynamic_artifacts.insert(path.clone());
                }
            }
        }
    }

    let mut callers: Vec<CallerSite> = Vec::new();
    let mut files: Vec<CallersFileCoverage> = Vec::new();
    let mut diagnostics = target_chunk.diagnostics.clone();
    diagnostics.extend(index.diagnostics.iter().cloned());

    let analyze = |identity: &InputIdentity,
                   chunk: &Chunk,
                   is_target: bool,
                   callers: &mut Vec<CallerSite>|
     -> Result<(CallSiteCounts, Vec<Diagnostic>), StableId> {
        let callees = analyze_chunk_callees(chunk);
        let relations = is_target.then(|| analyze_chunk_call_relations(chunk));
        let links = convention.map(|c| (resolve_chunk_links(identity, chunk, &index, c), c));
        let facts = CallerFileFacts {
            identity,
            callees: &callees,
            relations: relations.as_ref(),
            links: links.as_ref().map(|(result, c)| (result, *c)),
        };
        let attribution = attribute_file_callers(&target_identity, &target_proto, &facts);
        if !attribution.callers.is_empty() {
            let origins = analyze_chunk_origins(chunk);
            callers.extend(attach_argument_windows(
                identity,
                attribution.callers,
                &origins,
            )?);
        }
        let mut file_diagnostics = chunk.diagnostics.clone();
        if let Some((result, _)) = &links {
            file_diagnostics.extend(result.diagnostics.iter().cloned());
        }
        Ok((attribution.counts, file_diagnostics))
    };

    let mut all: Vec<(String, bool)> = vec![(args.target.clone(), true)];
    all.extend(paths.iter().map(|path| (path.clone(), false)));
    all.sort();
    for (path, is_target) in all {
        let coverage = if is_target {
            match analyze(&target_identity, &target_chunk, true, &mut callers) {
                Ok((counts, file_diagnostics)) => CallersFileCoverage {
                    path,
                    input_identity: Some(target_identity.clone()),
                    interpretation: Some(target_interp.clone()),
                    status: CallersFileStatus::Analyzed,
                    is_target: true,
                    counts: Some(counts),
                    diagnostics: file_diagnostics,
                },
                Err(call_id) => return Ok(internal_join_error(&call_id)),
            }
        } else {
            match &loaded[&path] {
                Loaded::Parsed {
                    chunk,
                    identity,
                    interpretation,
                    valid,
                } => {
                    if !LUA51_PROFILES.contains(&chunk.dialect.as_str()) {
                        CallersFileCoverage {
                            path,
                            input_identity: Some(identity.clone()),
                            interpretation: Some(interpretation.clone()),
                            status: CallersFileStatus::UnsupportedProfile,
                            is_target: false,
                            counts: None,
                            diagnostics: chunk.diagnostics.clone(),
                        }
                    } else if let Err(validation) = valid {
                        CallersFileCoverage {
                            path,
                            input_identity: Some(identity.clone()),
                            interpretation: Some(interpretation.clone()),
                            status: CallersFileStatus::Failed,
                            is_target: false,
                            counts: None,
                            diagnostics: validation.clone(),
                        }
                    } else {
                        match analyze(identity, chunk, false, &mut callers) {
                            Ok((counts, file_diagnostics)) => CallersFileCoverage {
                                path,
                                input_identity: Some(identity.clone()),
                                interpretation: Some(interpretation.clone()),
                                status: CallersFileStatus::Analyzed,
                                is_target: false,
                                counts: Some(counts),
                                diagnostics: file_diagnostics,
                            },
                            Err(call_id) => return Ok(internal_join_error(&call_id)),
                        }
                    }
                }
                Loaded::ParseFailed {
                    identity,
                    diagnostic,
                } => CallersFileCoverage {
                    path,
                    input_identity: identity.clone(),
                    interpretation: None,
                    status: CallersFileStatus::Failed,
                    is_target: false,
                    counts: None,
                    diagnostics: diagnostic.iter().map(|d| (**d).clone()).collect(),
                },
                Loaded::Unreadable => CallersFileCoverage {
                    path,
                    input_identity: None,
                    interpretation: None,
                    status: CallersFileStatus::Unreadable,
                    is_target: false,
                    counts: None,
                    diagnostics: Vec::new(),
                },
            }
        };
        files.push(coverage);
    }

    callers.sort_by(|a, b| {
        (&a.caller.path, &a.caller_proto, a.pc).cmp(&(&b.caller.path, &b.caller_proto, b.pc))
    });
    let caller_count = callers.len();
    let is_truncated = caller_count > args.max_callers;
    callers.truncate(args.max_callers);

    let count = |status| files.iter().filter(|f| f.status == status).count();
    let limit_class = index.export_limit_exceeded
        || files
            .iter()
            .filter_map(|f| f.counts.as_ref())
            .any(|counts| counts.degraded.keys().any(|reason| is_limit_reason(reason)));
    let degraded = !index.dynamic_artifacts.is_empty()
        || index.export_limit_exceeded
        || files
            .iter()
            .filter_map(|f| f.counts.as_ref())
            .any(CallSiteCounts::is_degraded);
    let summary = CallersSummary {
        caller_count: callers.len(),
        callers_omitted: caller_count - callers.len(),
        files_analyzed: count(CallersFileStatus::Analyzed),
        files_failed: count(CallersFileStatus::Failed),
        files_unsupported: count(CallersFileStatus::UnsupportedProfile),
        files_unreadable: count(CallersFileStatus::Unreadable),
        link_convention: convention.map(|c| c.as_str().to_string()),
        cross_artifact_searched: convention.is_some(),
        is_truncated,
        coverage_complete: files
            .iter()
            .all(|f| f.status == CallersFileStatus::Analyzed),
        degraded,
        dynamic_providers: index.dynamic_artifacts.iter().cloned().collect(),
    };
    let exit = answer_exit(is_truncated, limit_class, summary.coverage_complete);
    if is_truncated {
        eprintln!(
            "{}: --max-callers {} reached; {} caller(s) omitted",
            "warning".yellow(),
            args.max_callers,
            summary.callers_omitted
        );
    }

    let identities = analyze_chunk_prototype_identities(&target_chunk).ok();
    let target = CallersTarget {
        proto: target_proto.clone(),
        prototype_identity: identities.and_then(|analysis| {
            analysis
                .prototypes
                .into_iter()
                .find(|fact| fact.proto_id == target_proto_id)
        }),
        proto_id: target_proto_id,
    };
    let answer = CallersAnswer {
        target,
        callers,
        files,
        summary,
    };
    render(
        &answer,
        args.format,
        target_identity,
        target_interp,
        config,
        diagnostics,
        writer,
    )?;
    Ok(exit)
}

/// A limit outranks partial coverage; an unanalyzed input outranks success.
fn answer_exit(is_truncated: bool, limit_class: bool, coverage_complete: bool) -> ExitCode {
    if is_truncated || limit_class {
        ExitCode::LimitExceeded
    } else if !coverage_complete {
        ExitCode::InvalidInput
    } else {
        ExitCode::Success
    }
}

fn internal_join_error(call_id: &StableId) -> ExitCode {
    eprintln!(
        "{}: listed caller {call_id} has no origin fact; accepted analyses disagree",
        "error".red()
    );
    ExitCode::InternalError
}

fn render(
    answer: &CallersAnswer,
    format: OutputFormat,
    identity: InputIdentity,
    interpretation: ResolvedInterpretation,
    config: AnalysisConfiguration,
    diagnostics: Vec<Diagnostic>,
    writer: &mut impl io::Write,
) -> io::Result<()> {
    match format {
        OutputFormat::Json => crate::render::print_json(
            &super::wrap_document(identity, interpretation, config, answer, diagnostics),
            writer,
        ),
        OutputFormat::Jsonl => {
            let metadata = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: luad_core::envelope::JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interpretation.clone(),
                analysis_configuration: config,
            };
            line(writer, &metadata)?;
            let target_context = JsonlRecordContext::successful(identity, interpretation);
            line(
                writer,
                &JsonlDataRecord {
                    record_type: "target".to_string(),
                    context: target_context.clone(),
                    data: &answer.target,
                },
            )?;
            for diagnostic in &diagnostics {
                line(
                    writer,
                    &JsonlDataRecord {
                        record_type: "diagnostic".to_string(),
                        context: target_context.clone(),
                        data: diagnostic,
                    },
                )?;
            }
            let contexts: BTreeMap<&str, JsonlRecordContext> = answer
                .files
                .iter()
                .map(|file| {
                    let context = match (&file.input_identity, &file.interpretation) {
                        (Some(identity), Some(interpretation)) => {
                            JsonlRecordContext::successful(identity.clone(), interpretation.clone())
                        }
                        (Some(identity), None) => {
                            JsonlRecordContext::failed_parse(identity.clone())
                        }
                        _ => JsonlRecordContext::failed_read(),
                    };
                    (file.path.as_str(), context)
                })
                .collect();
            for caller in &answer.callers {
                line(
                    writer,
                    &JsonlDataRecord {
                        record_type: "caller".to_string(),
                        context: contexts[caller.caller.path.as_str()].clone(),
                        data: caller,
                    },
                )?;
            }
            for file in &answer.files {
                line(
                    writer,
                    &JsonlDataRecord {
                        record_type: "file_coverage".to_string(),
                        context: contexts[file.path.as_str()].clone(),
                        data: file,
                    },
                )?;
            }
            line(
                writer,
                &CallersSummaryRecord {
                    record_type: "summary",
                    summary: &answer.summary,
                },
            )
        }
        OutputFormat::Text | OutputFormat::Dot => render_text(answer, writer),
    }
}

fn line<T: Serialize>(writer: &mut impl io::Write, value: &T) -> io::Result<()> {
    writeln!(
        writer,
        "{}",
        serde_json::to_string(value).unwrap_or_default()
    )
}

fn render_text(answer: &CallersAnswer, writer: &mut impl io::Write) -> io::Result<()> {
    let summary = &answer.summary;
    writeln!(writer, "Callers of {}", answer.target.proto_id)?;
    if !summary.cross_artifact_searched {
        writeln!(
            writer,
            "  Cross-artifact callers were not searched (no --link-convention)."
        )?;
    }
    if answer.callers.is_empty() {
        writeln!(
            writer,
            "  No observed caller in the analyzed corpus (not proof of unreachability)."
        )?;
    }
    for caller in &answer.callers {
        let sources: Vec<String> = caller
            .bases
            .iter()
            .map(|basis| match basis {
                luad_analysis::CallerBasis::CallRelation { basis, .. } => {
                    format!("call_relation:{}", serde_plain(basis))
                }
                luad_analysis::CallerBasis::CrossChunkLink { label_segments, .. } => {
                    format!("link:{}", label_segments.join("."))
                }
            })
            .collect();
        writeln!(
            writer,
            "  {} {} [{}]",
            caller.caller.path,
            caller.call_id,
            sources.join(", ")
        )?;
    }
    if !summary.dynamic_providers.is_empty() {
        writeln!(
            writer,
            "  Index uncertain because of: {}",
            summary.dynamic_providers.join(", ")
        )?;
    }
    writeln!(writer, "Coverage:")?;
    for file in &answer.files {
        match &file.counts {
            Some(counts) => writeln!(
                writer,
                "  {} analyzed: {} call sites, {} caller, {} conflicting, {} degraded, {} elsewhere, {} unmapped label, {} unattributed",
                file.path,
                counts.call_sites,
                counts.caller,
                counts.conflicting,
                counts.degraded.values().sum::<usize>(),
                counts.attributed_elsewhere,
                counts.unmapped_label,
                counts.unattributed.values().sum::<usize>(),
            )?,
            None => writeln!(writer, "  {} {}", file.path, serde_plain(&file.status))?,
        }
    }
    writeln!(
        writer,
        "Summary: {} caller(s){}; coverage {}; {}",
        summary.caller_count,
        if summary.is_truncated {
            format!(", {} omitted by --max-callers", summary.callers_omitted)
        } else {
            String::new()
        },
        if summary.coverage_complete {
            "complete"
        } else {
            "incomplete"
        },
        if summary.degraded {
            "attribution degraded by limits or index uncertainty"
        } else {
            "attribution not degraded"
        }
    )
}

fn serde_plain<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limit_outcomes_exit_five_and_partial_coverage_exits_one() {
        assert_eq!(answer_exit(false, false, true), ExitCode::Success);
        assert_eq!(answer_exit(false, false, false), ExitCode::InvalidInput);
        assert_eq!(answer_exit(true, false, true), ExitCode::LimitExceeded);
        assert_eq!(answer_exit(false, true, false), ExitCode::LimitExceeded);
    }

    #[test]
    fn only_limit_reasons_are_limit_class() {
        for reason in [
            "callee:path-limit",
            "callee:analysis-limit",
            "call_relation:path-limit",
            "call_relation:analysis-limit",
            "link:limit_exceeded",
            "link:cutoff",
        ] {
            assert!(is_limit_reason(reason), "{reason}");
        }
        for reason in ["link:dynamic", "callee:missing-definition", "link:absent"] {
            assert!(!is_limit_reason(reason), "{reason}");
        }
    }
}
