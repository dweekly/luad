//! `luad` command-line interface entry point.

use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::path::Path;

use clap::{CommandFactory, Parser};
use colored::Colorize;
use schemars::schema_for;
use sha2::{Digest, Sha256};

mod args;
mod exit_codes;
mod render;

use args::{
    CalleesArgs, CallgraphArgs, CapabilitiesArgs, CfgArgs, Cli, Commands, CompletionsArgs,
    DiagnosticsArgs, DiffArgs, DisasmArgs, ExplainArgs, ExportArgs, InspectArgs, OriginsArgs,
    OutputFormat, QueryArgs, SchemaArgs, ValidateArgs, XrefsArgs,
};
use exit_codes::ExitCode;
use luad_analysis::{
    execute_query, validate_for_analysis, validate_target, ControlFlowGraph, QueryResponse,
    XrefIndex, XrefResponse,
};
use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::dialect::{ResolvedInterpretation, SelectionMode};
use luad_core::disasm::DisassembledPrototype;
use luad_core::envelope::{
    AnalysisConfiguration, ExportEndRecord, ExportStartRecord, FileEndRecord, FileStartRecord,
    InputIdentity, JsonlDataRecord, JsonlMetadataRecord, JsonlRecordContext, JsonlSummaryRecord,
    MachineDocument, QueryEndRecord, QueryStartRecord, ValidationResponse, JSONL_SCHEMA_VERSION,
};
use luad_core::id::{ProtoPath, StableId};
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::{Chunk, Prototype};
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::Lua54Dialect;

fn read_input_bytes(file_path: &str) -> Result<Vec<u8>, ExitCode> {
    read_input_bytes_with_reporting(file_path, true)
}

fn read_input_bytes_with_reporting(
    file_path: &str,
    report_errors: bool,
) -> Result<Vec<u8>, ExitCode> {
    let max_bytes = ResourceLimits::default().max_input_bytes;

    if file_path == "-" {
        let mut buffer = Vec::new();
        let mut reader = io::stdin().take((max_bytes + 1) as u64);
        reader.read_to_end(&mut buffer).map_err(|e| {
            if report_errors {
                eprintln!("{}: Failed to read from stdin: {e}", "error".red().bold());
            }
            ExitCode::IoError
        })?;
        if buffer.len() > max_bytes {
            if report_errors {
                eprintln!(
                    "{}: Stdin input exceeds safety limit of {max_bytes} bytes",
                    "error".red().bold()
                );
            }
            return Err(ExitCode::LimitExceeded);
        }
        Ok(buffer)
    } else {
        let path = Path::new(file_path);
        if !path.exists() {
            if report_errors {
                eprintln!("{}: File not found: '{}'", "error".red().bold(), file_path);
            }
            return Err(ExitCode::IoError);
        }
        let metadata = fs::metadata(path).map_err(|e| {
            if report_errors {
                eprintln!(
                    "{}: Failed to inspect metadata for '{}': {e}",
                    "error".red().bold(),
                    file_path
                );
            }
            ExitCode::IoError
        })?;
        if metadata.len() > max_bytes as u64 {
            if report_errors {
                eprintln!(
                    "{}: File '{}' size ({} bytes) exceeds safety limit of {max_bytes} bytes",
                    "error".red().bold(),
                    file_path,
                    metadata.len()
                );
            }
            return Err(ExitCode::LimitExceeded);
        }
        let file = fs::File::open(path).map_err(|e| {
            if report_errors {
                eprintln!(
                    "{}: Failed to open file '{}': {e}",
                    "error".red().bold(),
                    file_path
                );
            }
            ExitCode::IoError
        })?;
        let mut buffer = Vec::new();
        let mut reader = io::BufReader::new(file).take((max_bytes + 1) as u64);
        reader.read_to_end(&mut buffer).map_err(|e| {
            if report_errors {
                eprintln!(
                    "{}: Failed to read file '{}': {e}",
                    "error".red().bold(),
                    file_path
                );
            }
            ExitCode::IoError
        })?;
        if buffer.len() > max_bytes {
            if report_errors {
                eprintln!(
                    "{}: File '{}' size ({} bytes) exceeds safety limit of {max_bytes} bytes",
                    "error".red().bold(),
                    file_path,
                    buffer.len()
                );
            }
            return Err(ExitCode::LimitExceeded);
        }
        Ok(buffer)
    }
}

fn parse_input_list(list_file: &str) -> Result<Vec<String>, (String, ExitCode)> {
    let mut file_paths = Vec::new();
    if list_file == "-" {
        let stdin = io::stdin();
        for l in stdin.lock().lines().map_while(Result::ok) {
            let trimmed = l.trim();
            if !trimmed.is_empty() {
                file_paths.push(trimmed.to_string());
            }
        }
    } else {
        let content = match fs::read_to_string(list_file) {
            Ok(c) => c,
            Err(e) => {
                return Err((
                    format!("Failed to read input list '{list_file}': {e}"),
                    ExitCode::IoError,
                ));
            }
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                file_paths.push(trimmed.to_string());
            }
        }
    }
    Ok(file_paths)
}

pub fn classify_diagnostic(diag: &Diagnostic) -> ExitCode {
    if diag.code.starts_with("IO-") {
        return ExitCode::IoError;
    }
    if is_resource_limit_code(&diag.code)
        || diag.code.starts_with("CORE-LIMIT-")
        || diag.message.contains("exceeds configured safety limit")
        || diag.message.contains("exceeds safety limit of")
    {
        return ExitCode::LimitExceeded;
    }
    if diag.code == "ANA-PRECOND-001"
        || diag.code == "PARSE-SOURCE-001"
        || diag.code == "PARSE-UNKNOWN-001"
        || diag.code == "L51-CONST-002"
        || is_unsupported_format_or_layout_code(&diag.code)
    {
        return ExitCode::UnsupportedFormat;
    }
    ExitCode::InvalidInput
}

/// Typed classification of diagnostic codes representing resource exhaustion or safety limits.
fn is_resource_limit_code(code: &str) -> bool {
    matches!(
        code,
        "CORE-LIMIT-001"
            | "CORE-LIMIT-002"
            | "CORE-LIMIT-003"
            | "CORE-OVERFLOW-001"
            | "CORE-DEPTH-001"
            | "CORE-COUNT-001"
            | "L51-CODE-001"
            | "L51-CONST-001"
            | "L51-PROTO-001"
            | "L51-UPVAL-001"
            | "L51-STR-001"
            | "L52-CODE-001"
            | "L52-CONST-001"
            | "L52-PROTO-001"
            | "L52-UPVAL-001"
            | "L52-STR-001"
            | "L53-CODE-001"
            | "L53-CONST-001"
            | "L53-PROTO-001"
            | "L53-UPVAL-001"
            | "L53-STR-001"
            | "L54-CODE-001"
            | "L54-CONST-001"
            | "L54-PROTO-001"
            | "L54-UPVAL-001"
            | "L54-STR-001"
            | "L54-SIZE-001"
            | "L55-CODE-001"
            | "L55-CONST-001"
            | "L55-PROTO-001"
            | "L55-UPVAL-001"
            | "L55-STR-001"
    )
}

/// Typed classification of diagnostic codes representing unsupported bytecode formats,
/// vendor dialects, version mismatches, or unsupported target architecture layouts.
fn is_unsupported_format_or_layout_code(code: &str) -> bool {
    matches!(
        code,
        "L51-HEADER-001"
            | "L51-HEADER-002"
            | "L51-HEADER-003"
            | "L52-HEADER-001"
            | "L52-HEADER-002"
            | "L52-HEADER-003"
            | "L52-HEADER-004"
            | "L52-HEADER-005"
            | "L52-HEADER-006"
            | "L52-HEADER-007"
            | "L52-HEADER-008"
            | "L52-HEADER-009"
            | "L53-HEADER-001"
            | "L53-HEADER-002"
            | "L53-HEADER-003"
            | "L53-HEADER-005"
            | "L53-HEADER-006"
            | "L53-HEADER-007"
            | "L53-HEADER-008"
            | "L53-HEADER-009"
            | "L53-HEADER-010"
            | "L53-HEADER-011"
            | "L54-HEADER-001"
            | "L54-HEADER-002"
            | "L54-HEADER-003"
            | "L54-HEADER-005"
            | "L54-HEADER-006"
            | "L54-HEADER-007"
            | "L54-HEADER-008"
            | "L54-HEADER-009"
            | "L54-VAL-HEADER-001"
            | "L54-VAL-HEADER-002"
            | "L54-VAL-HEADER-003"
            | "L55-HEADER-001"
            | "L55-HEADER-002"
            | "L55-HEADER-003"
            | "L55-HEADER-005"
            | "L55-HEADER-006"
            | "L55-HEADER-007"
            | "L55-HEADER-008"
            | "L55-HEADER-009"
            | "L55-HEADER-010"
            | "L55-HEADER-011"
            | "L55-HEADER-012"
    )
}

type ParsedChunkTuple = (
    Chunk,
    InputIdentity,
    AnalysisConfiguration,
    ResolvedInterpretation,
);
type ParseDetailedResult = Result<ParsedChunkTuple, (ExitCode, Option<Box<Diagnostic>>)>;

fn parse_chunk(
    file_path: &str,
    bytes: &[u8],
    strict: bool,
    dialect_override: Option<&str>,
) -> Result<ParsedChunkTuple, ExitCode> {
    parse_chunk_with_reporting(file_path, bytes, strict, dialect_override, true)
}

fn parse_chunk_with_reporting(
    file_path: &str,
    bytes: &[u8],
    strict: bool,
    dialect_override: Option<&str>,
    report_errors: bool,
) -> Result<ParsedChunkTuple, ExitCode> {
    parse_chunk_detailed(file_path, bytes, strict, dialect_override, report_errors)
        .map_err(|(code, _)| code)
}

fn parse_chunk_detailed(
    file_path: &str,
    bytes: &[u8],
    strict: bool,
    dialect_override: Option<&str>,
    report_errors: bool,
) -> ParseDetailedResult {
    let mode = if strict {
        ParseMode::Strict
    } else {
        ParseMode::Permissive
    };

    let limits = ResourceLimits::default();
    if bytes.len() > limits.max_input_bytes {
        if report_errors {
            eprintln!(
                "{}: Input size ({} bytes) exceeds safety limit of {} bytes",
                "error".red().bold(),
                bytes.len(),
                limits.max_input_bytes
            );
        }
        return Err((ExitCode::LimitExceeded, None));
    }

    let sha256 = hex::encode(Sha256::digest(bytes));
    let input_identity = InputIdentity {
        path: file_path.to_string(),
        sha256,
        byte_length: bytes.len(),
    };

    let analysis_config = AnalysisConfiguration {
        mode,
        limits: limits.clone(),
        dialect_override: dialect_override.map(ToString::to_string),
    };

    let lua55 = luad_dialect_lua55::Lua55Dialect;
    let lua54 = Lua54Dialect;
    let lua53 = luad_dialect_lua53::Lua53Dialect;
    let lua52 = luad_dialect_lua52::Lua52Dialect;
    let lua51 = luad_dialect_lua51::Lua51Dialect::default();
    let lua51_lnum = luad_dialect_lua51::Lua51Dialect {
        profile: luad_dialect_lua51::Lua51Profile::Lnum32,
    };
    let lua51_stock32 = luad_dialect_lua51::Lua51Dialect {
        profile: luad_dialect_lua51::Lua51Profile::Stock32,
    };

    let (selected_dialect, selection_mode): (&dyn Dialect, SelectionMode) = if let Some(d) =
        dialect_override
    {
        let dialect: &dyn Dialect = match d {
            "lua5.5" => &lua55,
            "lua5.4" => &lua54,
            "lua5.3" => &lua53,
            "lua5.2" => &lua52,
            "lua5.1" => &lua51,
            "lua5.1-stock32" => &lua51_stock32,
            "lua5.1-lnum32" => &lua51_lnum,
            "lua5.1-lnum" => {
                if report_errors {
                    eprintln!(
                        "{}: Ambiguous dialect 'lua5.1-lnum'. Please specify exact profile '--dialect lua5.1-lnum32'",
                        "error".red().bold()
                    );
                }
                return Err((ExitCode::UsageError, None));
            }
            other => {
                if report_errors {
                    eprintln!(
                        "{}: Dialect '{other}' is not yet supported in this build",
                        "error".red().bold()
                    );
                }
                return Err((ExitCode::UnsupportedFormat, None));
            }
        };
        (dialect, SelectionMode::Explicit)
    } else if lua55.detect(bytes).is_some() {
        (&lua55, SelectionMode::Detected)
    } else if lua54.detect(bytes).is_some() {
        (&lua54, SelectionMode::Detected)
    } else if lua53.detect(bytes).is_some() {
        (&lua53, SelectionMode::Detected)
    } else if lua52.detect(bytes).is_some() {
        (&lua52, SelectionMode::Detected)
    } else if lua51_lnum.detect(bytes).is_some() {
        (&lua51_lnum, SelectionMode::Detected)
    } else if lua51.detect(bytes).is_some() {
        (&lua51, SelectionMode::Detected)
    } else {
        if report_errors {
            eprintln!(
                "{}: Unknown or unsupported bytecode format (header did not match known dialects)",
                "error".red().bold()
            );
        }
        return Err((ExitCode::UnsupportedFormat, None));
    };

    let mut reader = SafeReader::with_options(bytes, 0, limits, mode);
    match selected_dialect.decode_chunk(&mut reader) {
        Ok(mut chunk) => {
            if let Some(interp) = &mut chunk.interpretation {
                interp.selection_mode = selection_mode;
            }
            let interpretation =
                chunk
                    .interpretation
                    .clone()
                    .unwrap_or_else(|| ResolvedInterpretation {
                        base_dialect: chunk.dialect.clone(),
                        patch_or_oracle_version: None,
                        profile: chunk.dialect.clone(),
                        profile_version_or_hash: None,
                        validated_layout: None,
                        parse_mode: match mode {
                            ParseMode::Strict => "strict".to_string(),
                            ParseMode::Permissive => "permissive".to_string(),
                        },
                        selection_mode,
                        detection_evidence: String::new(),
                    });
            Ok((chunk, input_identity, analysis_config, interpretation))
        }
        Err(diag) => {
            let exit_code = classify_diagnostic(&diag);
            if report_errors {
                if let Some(loc) = &diag.source {
                    eprintln!(
                        "{}: Parsing failed at offset {}: {}",
                        "error".red().bold(),
                        loc.byte_offset,
                        diag.message
                    );
                } else {
                    eprintln!("{}: Parsing failed: {}", "error".red().bold(), diag.message);
                }
            }
            Err((exit_code, Some(Box::new(diag))))
        }
    }
}

fn wrap_document<T>(
    input_identity: InputIdentity,
    interpretation: ResolvedInterpretation,
    analysis_configuration: AnalysisConfiguration,
    data: T,
    diagnostics: Vec<Diagnostic>,
) -> MachineDocument<T> {
    MachineDocument {
        schema_version: 1,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        input_identity,
        interpretation,
        analysis_configuration,
        data,
        diagnostics,
    }
}

struct TrackedWriter<'a, W: io::Write> {
    inner: &'a mut W,
    error: Option<io::Error>,
}

impl<'a, W: io::Write> TrackedWriter<'a, W> {
    fn new(inner: &'a mut W) -> Self {
        Self { inner, error: None }
    }

    fn check_error(self) -> io::Result<()> {
        if let Some(err) = self.error {
            Err(err)
        } else {
            Ok(())
        }
    }
}

impl<'a, W: io::Write> io::Write for TrackedWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.inner.write(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                let kind = e.kind();
                let err_msg = e.to_string();
                if self.error.is_none() {
                    self.error = Some(io::Error::new(kind, err_msg));
                }
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.inner.flush() {
            Ok(()) => Ok(()),
            Err(e) => {
                let kind = e.kind();
                let err_msg = e.to_string();
                if self.error.is_none() {
                    self.error = Some(io::Error::new(kind, err_msg));
                }
                Err(e)
            }
        }
    }
}

fn handle_write_error(err: &io::Error) -> ! {
    if err.kind() == io::ErrorKind::BrokenPipe {
        std::process::exit(0);
    }
    eprintln!("error: output I/O error: {err}");
    ExitCode::IoError.exit();
}

fn main() {
    let cli = Cli::parse();
    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    let result = match cli.command {
        Commands::Inspect(args) => handle_inspect(args, &mut writer),
        Commands::Disasm(args) => handle_disasm(args, &mut writer),
        Commands::Validate(args) => handle_validate(args, &mut writer),
        Commands::Capabilities(args) => handle_capabilities(args, &mut writer),
        Commands::Diagnostics(args) => handle_diagnostics(args, &mut writer),
        Commands::Schema(args) => handle_schema(args, &mut writer),
        Commands::Completions(args) => handle_completions(args, &mut writer),
        Commands::Cfg(args) => handle_cfg(args, &mut writer),
        Commands::Callees(args) => handle_callees(args, &mut writer),
        Commands::Callgraph(args) => handle_callgraph(args, &mut writer),
        Commands::Origins(args) => handle_origins(args, &mut writer),
        Commands::Xrefs(args) => handle_xrefs(args, &mut writer),
        Commands::Explain(args) => handle_explain(args, &mut writer),
        Commands::Query(args) => handle_query(args, &mut writer),
        Commands::Diff(args) => handle_diff(args, &mut writer),
        Commands::Export(args) => handle_export(args, &mut writer),
    };

    match result {
        Ok(code) => {
            if let Err(err) = writer.flush() {
                handle_write_error(&err);
            }
            code.exit();
        }
        Err(err) => {
            handle_write_error(&err);
        }
    }
}

fn handle_inspect(args: InspectArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, args.strict, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => return Ok(code),
        };

    match args.format {
        OutputFormat::Text => render::render_inspect(&chunk, args.summary, writer)?,
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                chunk.clone(),
                chunk.diagnostics.clone(),
            );
            render::print_json(&doc, writer)?;
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interp.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&meta).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interp);
            let data_rec = JsonlDataRecord {
                record_type: "chunk".to_string(),
                context,
                data: chunk.clone(),
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&data_rec).unwrap_or_default()
            )?;
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: 1,
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not supported for inspect", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }

    Ok(ExitCode::Success)
}

fn get_disasm_proto(dialect: &str, proto: &luad_core::model::Prototype) -> DisassembledPrototype {
    const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];
    if dialect == "lua5.4" {
        luad_dialect_lua54::disassemble_proto_lua54(proto)
    } else if LUA51_PROFILES.contains(&dialect) {
        luad_dialect_lua51::disassemble_proto_lua51(proto)
    } else {
        let lifted = luad_analysis::lift_proto_for_dialect(dialect, proto);
        let instructions: Vec<_> = lifted
            .into_iter()
            .map(|sem| luad_core::DisassembledInstruction {
                id: sem.id,
                pc: sem.pc,
                raw_word: sem.raw_word,
                raw_hex: sem.raw_hex,
                mnemonic: sem.mnemonic,
                opcode_num: 0,
                role: "instruction".to_string(),
                encoded_operands: luad_core::EncodedOperands::default(),
                line: None,
                operands: vec![],
                jump_target: sem.jump_target,
                companion_pc: sem.companion_pc,
                metamethod: None,
                comment: None,
                confidence: sem.confidence,
                source: sem.source,
                diagnostics: vec![],
            })
            .collect();

        DisassembledPrototype {
            id: proto.id.clone(),
            source_name: proto.source_name.as_ref().map(|s| s.display.clone()),
            line_defined: proto.line_defined,
            last_line_defined: proto.last_line_defined,
            numparams: proto.numparams,
            is_vararg: proto.is_vararg != 0,
            maxstacksize: proto.maxstacksize,
            instructions,
            diagnostics: vec![],
            child_protos: vec![],
        }
    }
}

fn handle_disasm(args: DisasmArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, args.strict, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => return Ok(code),
        };

    let target_proto = if let Some(path_str) = &args.proto {
        let path: StableId = match path_str.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{}: Invalid prototype selector '{path_str}': {e}",
                    "error".red()
                );
                return Ok(ExitCode::UsageError);
            }
        };
        let Some(proto) = find_proto_by_stable_id(&chunk.main_proto, &path) else {
            eprintln!("{}: Prototype '{path}' not found in chunk", "error".red());
            return Ok(ExitCode::UsageError);
        };
        proto
    } else {
        &chunk.main_proto
    };

    let disasm_proto = get_disasm_proto(&chunk.dialect, target_proto);

    match args.format {
        OutputFormat::Text => {
            if chunk.dialect == "lua5.5" {
                eprintln!(
                    "{}: Dialect 'lua5.5' disassembly is experimental and unverified",
                    "warning".yellow().bold()
                );
            }
            render::render_disasm(
                &chunk.dialect,
                target_proto,
                args.raw,
                args.debug_info,
                args.effects,
                writer,
            )?;
        }
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                disasm_proto.clone(),
                disasm_proto.diagnostics.clone(),
            );
            render::print_json(&doc, writer)?;
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interp.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&meta).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interp);
            for inst in &disasm_proto.instructions {
                let rec = JsonlDataRecord {
                    record_type: "instruction".to_string(),
                    context: context.clone(),
                    data: inst.clone(),
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&rec).unwrap_or_default()
                )?;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: disasm_proto.instructions.len(),
                diagnostic_count: disasm_proto.diagnostics.len(),
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => {
            eprintln!(
                "{}: Use 'luad cfg --format dot' for graphviz output",
                "error".red()
            );
            return Ok(ExitCode::UsageError);
        }
    }

    Ok(ExitCode::Success)
}

fn find_proto_by_stable_id<'a>(
    proto: &'a luad_core::model::Prototype,
    target_id: &StableId,
) -> Option<&'a luad_core::model::Prototype> {
    if &proto.id == target_id {
        return Some(proto);
    }
    for child in &proto.protos {
        if let Some(found) = find_proto_by_stable_id(child, target_id) {
            return Some(found);
        }
    }
    None
}

fn handle_validate(args: ValidateArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, args.strict, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => return Ok(code),
        };

    let (verdict, diagnostics) = match chunk.dialect.as_str() {
        "lua5.5" => luad_dialect_lua55::validate_chunk_lua55(&chunk),
        "lua5.4" => luad_dialect_lua54::validate_chunk_lua54(&chunk),
        "lua5.3" => luad_dialect_lua53::validate_chunk_lua53(&chunk),
        "lua5.2" => luad_dialect_lua52::validate_chunk_lua52(&chunk),
        "lua5.1" | "lua5.1-lnum32" | "lua5.1-stock32" => {
            luad_dialect_lua51::validate_chunk_lua51(&chunk)
        }
        _ => (chunk.verdict, chunk.diagnostics.clone()),
    };

    let is_limit = verdict == Verdict::Incomplete
        || diagnostics
            .iter()
            .any(|d| classify_diagnostic(d) == ExitCode::LimitExceeded);
    let is_invalid = verdict == Verdict::Invalid
        || is_limit
        || (args.strict
            && (diagnostics
                .iter()
                .any(|d| d.severity == Severity::Error || d.severity == Severity::Warning)));

    match args.format {
        OutputFormat::Text => render::render_validate(verdict, &diagnostics, writer)?,
        OutputFormat::Json => {
            let val_resp = ValidationResponse {
                verdict,
                diagnostic_count: diagnostics.len(),
                diagnostics: diagnostics.clone(),
            };
            let doc = wrap_document(identity, interp, config, val_resp, diagnostics);
            render::print_json(&doc, writer)?;
        }
        _ => {
            eprintln!("{}: Format not supported for validate", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }

    if is_limit {
        Ok(ExitCode::LimitExceeded)
    } else if is_invalid {
        Ok(ExitCode::InvalidInput)
    } else {
        Ok(ExitCode::Success)
    }
}

fn handle_capabilities(
    args: CapabilitiesArgs,
    writer: &mut impl io::Write,
) -> io::Result<ExitCode> {
    let mut manifest = luad_core::get_canonical_capabilities(env!("CARGO_PKG_VERSION"));
    if !args.evidence {
        manifest.evidence.clear();
        for d in &mut manifest.dialects {
            d.evidence.clear();
        }
    }

    match args.format {
        OutputFormat::Text => render::render_capabilities(&manifest, args.evidence, writer)?,
        OutputFormat::Json => {
            render::print_json(&manifest, writer)?;
        }
        _ => {
            return Ok(ExitCode::UsageError);
        }
    }
    Ok(ExitCode::Success)
}

fn handle_diagnostics(args: DiagnosticsArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    if matches!(args.format, OutputFormat::Jsonl | OutputFormat::Dot) {
        return Ok(ExitCode::UsageError);
    }

    let descriptors = match args.code {
        Some(code) => match luad_core::lookup_diagnostic(&code) {
            Some(desc) => vec![desc],
            None => {
                eprintln!("error: Unknown diagnostic code '{code}'");
                return Ok(ExitCode::UsageError);
            }
        },
        None => luad_core::list_diagnostics(),
    };

    match args.format {
        OutputFormat::Text => {
            render::render_diagnostic_descriptors(&descriptors, writer)?;
        }
        OutputFormat::Json => {
            let response = luad_core::build_catalog_response(descriptors);
            render::print_json(&response, writer)?;
        }
        _ => {
            return Ok(ExitCode::UsageError);
        }
    }

    Ok(ExitCode::Success)
}

fn handle_schema(args: SchemaArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let current_version = match args.name.as_str() {
        "capabilities" | "manifest" | "export" => 2,
        _ => 1,
    };
    if args
        .schema_version
        .is_some_and(|version| version != current_version)
    {
        eprintln!(
            "{}: Schema '{}' supports major version {} in this build",
            "error".red(),
            args.name,
            current_version
        );
        return Ok(ExitCode::UsageError);
    }

    match args.name.as_str() {
        "chunk" => {
            let schema = schema_for!(MachineDocument<Chunk>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "diagnostic" => {
            let schema = schema_for!(Diagnostic);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "diagnostics" => {
            let schema = schema_for!(luad_core::DiagnosticCatalogResponse);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "instruction" => {
            let schema = schema_for!(luad_core::SemanticInstruction);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "cfg" => {
            let schema = schema_for!(MachineDocument<ControlFlowGraph>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "callees" => {
            let schema = schema_for!(MachineDocument<luad_analysis::ChunkCalleeAnalysis>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "callgraph" => {
            let schema = schema_for!(MachineDocument<luad_analysis::ChunkCallRelationAnalysis>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "origins" => {
            let schema = schema_for!(MachineDocument<luad_analysis::ChunkOriginAnalysis>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "xrefs" => {
            let schema = schema_for!(MachineDocument<XrefResponse>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "query" | "analysis" => {
            let schema = schema_for!(MachineDocument<QueryResponse>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "diff" => {
            let schema = schema_for!(MachineDocument<luad_analysis::ChunkDiff>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "capabilities" | "manifest" => {
            let schema = schema_for!(luad_core::CapabilityManifest);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "disasm" => {
            let schema = schema_for!(MachineDocument<DisassembledPrototype>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "validate" => {
            let schema = schema_for!(MachineDocument<ValidationResponse>);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        "export" => {
            let schema = schema_for!(ExportRecord);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            )?;
        }
        other => {
            eprintln!(
                "{}: Unknown schema '{other}'. Supported: chunk, disasm, validate, diagnostic, diagnostics, instruction, cfg, callees, callgraph, origins, xrefs, query, analysis, diff, capabilities, manifest, export",
                "error".red()
            );
            return Ok(ExitCode::UsageError);
        }
    }

    Ok(ExitCode::Success)
}

fn handle_completions(args: CompletionsArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let mut cmd = Cli::command();
    let mut tracked = TrackedWriter::new(writer);
    clap_complete::generate(args.shell, &mut cmd, "luad", &mut tracked);
    tracked.check_error()?;
    Ok(ExitCode::Success)
}

fn handle_explain(args: ExplainArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };

    let (chunk, _, _, _) = match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
        Ok(c) => c,
        Err(code) => return Ok(code),
    };

    let target_id: StableId = match args.target.parse() {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "{}: Invalid target StableId '{}': {e}",
                "error".red(),
                args.target
            );
            return Ok(ExitCode::UsageError);
        }
    };

    match target_id {
        StableId::Instruction { proto, pc } => {
            let proto_id = StableId::Proto(proto.clone());
            let Some(target_proto) = find_proto_by_stable_id(&chunk.main_proto, &proto_id) else {
                eprintln!(
                    "{}: Prototype '{}' not found in chunk",
                    "error".red(),
                    proto_id
                );
                return Ok(ExitCode::UsageError);
            };

            let disasm_proto = get_disasm_proto(&chunk.dialect, target_proto);
            let disasm_inst = disasm_proto.instructions.get(pc);

            let lifted = luad_analysis::lift_proto_for_dialect(&chunk.dialect, target_proto);
            let Some(sem_inst) = lifted.get(pc) else {
                eprintln!(
                    "{}: Instruction at PC {} not found in prototype '{}' (size {})",
                    "error".red(),
                    pc,
                    proto_id,
                    lifted.len()
                );
                return Ok(ExitCode::UsageError);
            };

            match args.format {
                OutputFormat::Text => {
                    render::render_explain_instruction(sem_inst, disasm_inst, writer)?
                }
                OutputFormat::Json => render::print_json(sem_inst, writer)?,
                OutputFormat::Jsonl => render::print_jsonl(&[sem_inst], writer)?,
                OutputFormat::Dot => {
                    eprintln!("{}: DOT format not applicable to explain", "error".red());
                    return Ok(ExitCode::UsageError);
                }
            }
        }
        _ => {
            eprintln!(
                "{}: Explanation currently supports instruction targets (e.g. 'proto:0:pc:3')",
                "info".cyan()
            );
        }
    }

    Ok(ExitCode::Success)
}

fn handle_analysis_validation_failure(
    prefix: &str,
    diags: &[luad_core::diagnostic::Diagnostic],
) -> ExitCode {
    eprintln!(
        "{}: Analysis refused: {prefix} failed validation checks",
        "error".red()
    );
    let mut is_unsupported_format = false;
    let mut is_limit_exceeded = false;
    for d in diags {
        if d.severity == Severity::Error {
            eprintln!("  - [{}] {}", d.code, d.message);
            if d.code == "ANA-PRECOND-001" {
                is_unsupported_format = true;
            }
            if classify_diagnostic(d) == ExitCode::LimitExceeded {
                is_limit_exceeded = true;
            }
        }
    }
    if is_limit_exceeded {
        ExitCode::LimitExceeded
    } else if is_unsupported_format {
        ExitCode::UnsupportedFormat
    } else {
        ExitCode::InvalidInput
    }
}

fn handle_cfg(args: CfgArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => return Ok(code),
        };

    if let Err(diags) = validate_for_analysis(&chunk) {
        return Ok(handle_analysis_validation_failure("chunk", &diags));
    }

    let target_id: StableId = match args.proto.parse() {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "{}: Invalid prototype selector '{}': {e}",
                "error".red(),
                args.proto
            );
            return Ok(ExitCode::UsageError);
        }
    };

    let Some(target_proto) = find_proto_by_stable_id(&chunk.main_proto, &target_id) else {
        eprintln!(
            "{}: Prototype '{}' not found in chunk",
            "error".red(),
            target_id
        );
        return Ok(ExitCode::UsageError);
    };

    let lifted = luad_analysis::lift_proto_for_dialect(&chunk.dialect, target_proto);
    let cfg = ControlFlowGraph::build(target_proto, &lifted);

    match args.format {
        OutputFormat::Text => render::render_cfg(&cfg, writer)?,
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                cfg.clone(),
                chunk.diagnostics.clone(),
            );
            render::print_json(&doc, writer)?;
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interp.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&meta).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interp);
            for block in &cfg.blocks {
                let rec = JsonlDataRecord {
                    record_type: "basic_block".to_string(),
                    context: context.clone(),
                    data: block.clone(),
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&rec).unwrap_or_default()
                )?;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: cfg.blocks.len(),
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => write!(writer, "{}", cfg.to_dot())?,
    }

    Ok(ExitCode::Success)
}

fn handle_callees(args: CalleesArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(bytes) => bytes,
        Err(code) => return Ok(code),
    };
    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(parsed) => parsed,
            Err(code) => return Ok(code),
        };
    const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];
    if !LUA51_PROFILES.contains(&chunk.dialect.as_str()) {
        eprintln!(
            "{}: Symbolic callee analysis currently requires a Lua 5.1 profile",
            "error".red()
        );
        return Ok(ExitCode::UnsupportedFormat);
    }
    if let Err(diags) = validate_for_analysis(&chunk) {
        return Ok(handle_analysis_validation_failure("chunk", &diags));
    }

    let analysis = luad_analysis::analyze_chunk_callees(&chunk);
    let total_calls: usize = analysis
        .prototypes
        .iter()
        .map(|prototype| prototype.calls.len())
        .sum();
    match args.format {
        OutputFormat::Text => render::render_callees(&analysis, writer)?,
        OutputFormat::Json => render::print_json(
            &wrap_document(
                identity,
                interp,
                config,
                analysis,
                chunk.diagnostics.clone(),
            ),
            writer,
        )?,
        OutputFormat::Jsonl => {
            let metadata = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interp.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&metadata).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interp);
            for fact in analysis
                .prototypes
                .iter()
                .flat_map(|prototype| &prototype.calls)
            {
                let record = JsonlDataRecord {
                    record_type: "callee".to_string(),
                    context: context.clone(),
                    data: fact,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&record).unwrap_or_default()
                )?;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: total_calls,
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to callees", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }
    Ok(ExitCode::Success)
}

fn handle_callgraph(args: CallgraphArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(bytes) => bytes,
        Err(code) => return Ok(code),
    };
    let (chunk, identity, config, interpretation) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(parsed) => parsed,
            Err(code) => return Ok(code),
        };
    const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];
    if !LUA51_PROFILES.contains(&chunk.dialect.as_str()) {
        eprintln!(
            "{}: Call-relation analysis currently requires a Lua 5.1 profile",
            "error".red()
        );
        return Ok(ExitCode::UnsupportedFormat);
    }
    if let Err(diagnostics) = validate_for_analysis(&chunk) {
        return Ok(handle_analysis_validation_failure("chunk", &diagnostics));
    }

    let analysis = luad_analysis::analyze_chunk_call_relations(&chunk);
    let total_calls: usize = analysis
        .prototypes
        .iter()
        .map(|prototype| prototype.calls.len())
        .sum();
    match args.format {
        OutputFormat::Text => render::render_callgraph(&analysis, writer)?,
        OutputFormat::Json => render::print_json(
            &wrap_document(
                identity,
                interpretation,
                config,
                analysis,
                chunk.diagnostics.clone(),
            ),
            writer,
        )?,
        OutputFormat::Jsonl => {
            let metadata = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interpretation.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&metadata).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interpretation);
            for fact in analysis
                .prototypes
                .iter()
                .flat_map(|prototype| &prototype.calls)
            {
                let record = JsonlDataRecord {
                    record_type: "call_relation".to_string(),
                    context: context.clone(),
                    data: fact,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&record).unwrap_or_default()
                )?;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: total_calls,
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to callgraph", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }
    Ok(ExitCode::Success)
}

fn handle_origins(args: OriginsArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(bytes) => bytes,
        Err(code) => return Ok(code),
    };
    let (chunk, identity, config, interpretation) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(parsed) => parsed,
            Err(code) => return Ok(code),
        };
    const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];
    if !LUA51_PROFILES.contains(&chunk.dialect.as_str()) {
        eprintln!(
            "{}: Call-argument origin analysis currently requires a Lua 5.1 profile",
            "error".red()
        );
        return Ok(ExitCode::UnsupportedFormat);
    }
    if let Err(diagnostics) = validate_for_analysis(&chunk) {
        return Ok(handle_analysis_validation_failure("chunk", &diagnostics));
    }

    let analysis = luad_analysis::analyze_chunk_origins(&chunk);
    let total_calls: usize = analysis
        .prototypes
        .iter()
        .map(|prototype| prototype.calls.len())
        .sum();
    match args.format {
        OutputFormat::Text => render::render_origins(&analysis, writer)?,
        OutputFormat::Json => render::print_json(
            &wrap_document(
                identity,
                interpretation,
                config,
                analysis,
                chunk.diagnostics.clone(),
            ),
            writer,
        )?,
        OutputFormat::Jsonl => {
            let metadata = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interpretation.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&metadata).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interpretation);
            for fact in analysis
                .prototypes
                .iter()
                .flat_map(|prototype| &prototype.calls)
            {
                let record = JsonlDataRecord {
                    record_type: "origin".to_string(),
                    context: context.clone(),
                    data: fact,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&record).unwrap_or_default()
                )?;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: total_calls,
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to origins", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }
    Ok(ExitCode::Success)
}

fn handle_xrefs(args: XrefsArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => return Ok(code),
        };

    if let Err(diags) = validate_for_analysis(&chunk) {
        return Ok(handle_analysis_validation_failure("chunk", &diags));
    }

    let index = XrefIndex::build(&chunk);

    let target_id = if let Some(to_str) = &args.to {
        let to_id: StableId = match to_str.parse() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("{}: Invalid target ID '{to_str}': {e}", "error".red());
                return Ok(ExitCode::UsageError);
            }
        };
        if !validate_target(&chunk, &to_id) {
            eprintln!(
                "{}: Target '{}' does not exist in chunk",
                "error".red(),
                to_id
            );
            return Ok(ExitCode::UsageError);
        }
        Some(to_id)
    } else {
        None
    };

    let source_id = if let Some(from_str) = &args.from {
        let from_id: StableId = match from_str.parse() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("{}: Invalid source ID '{from_str}': {e}", "error".red());
                return Ok(ExitCode::UsageError);
            }
        };
        if !validate_target(&chunk, &from_id) {
            eprintln!(
                "{}: Source target '{}' does not exist in chunk",
                "error".red(),
                from_id
            );
            return Ok(ExitCode::UsageError);
        }
        Some(from_id)
    } else {
        None
    };

    let matching_refs: Vec<luad_analysis::XrefEntry> = if let Some(t) = &target_id {
        index.query_to(t).into_iter().cloned().collect()
    } else if let Some(s) = &source_id {
        index.query_from(s).into_iter().cloned().collect()
    } else {
        index.entries.clone()
    };

    let total_count = matching_refs.len();
    let xref_response = XrefResponse {
        target: target_id,
        source: source_id,
        entries: matching_refs.clone(),
        total_count,
    };

    match args.format {
        OutputFormat::Text => {
            render::render_xrefs(&matching_refs.iter().collect::<Vec<_>>(), writer)?
        }
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                xref_response,
                chunk.diagnostics.clone(),
            );
            render::print_json(&doc, writer)?;
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interp.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&meta).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interp);
            for entry in &matching_refs {
                let rec = JsonlDataRecord {
                    record_type: "xref".to_string(),
                    context: context.clone(),
                    data: entry.clone(),
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&rec).unwrap_or_default()
                )?;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: total_count,
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to xrefs", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }

    Ok(ExitCode::Success)
}

fn handle_query(args: QueryArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let has_file = args.file.is_some();
    let has_input_list = args.input_list.is_some();
    match (has_file, has_input_list) {
        (true, false) => {
            let file = args.file.as_ref().unwrap();
            let format = args.format.unwrap_or(OutputFormat::Json);
            let bytes = match read_input_bytes(file) {
                Ok(b) => b,
                Err(code) => return Ok(code),
            };

            let (chunk, identity, config, interp) =
                match parse_chunk(file, &bytes, args.strict, args.dialect.as_deref()) {
                    Ok(c) => c,
                    Err(code) => return Ok(code),
                };

            if let Err(diags) = validate_for_analysis(&chunk) {
                return Ok(handle_analysis_validation_failure("chunk", &diags));
            }

            let response = match execute_query(
                &chunk,
                args.r#where.as_deref(),
                args.limit,
                args.cursor.as_deref(),
            ) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("{}: Query error: {e}", "error".red());
                    return Ok(ExitCode::UsageError);
                }
            };

            match format {
                OutputFormat::Text => render::render_query(&response, writer)?,
                OutputFormat::Json => {
                    let doc = wrap_document(
                        identity,
                        interp,
                        config,
                        response.clone(),
                        chunk.diagnostics.clone(),
                    );
                    render::print_json(&doc, writer)?;
                }
                OutputFormat::Jsonl => {
                    let meta = JsonlMetadataRecord {
                        record_type: "metadata".to_string(),
                        schema_version: JSONL_SCHEMA_VERSION,
                        tool_version: env!("CARGO_PKG_VERSION").to_string(),
                        input_identity: identity.clone(),
                        interpretation: interp.clone(),
                        analysis_configuration: config,
                    };
                    writeln!(
                        writer,
                        "{}",
                        serde_json::to_string(&meta).unwrap_or_default()
                    )?;
                    let context = JsonlRecordContext::successful(identity, interp);
                    for m in &response.matches {
                        let rec = JsonlDataRecord {
                            record_type: "query_match".to_string(),
                            context: context.clone(),
                            data: m.clone(),
                        };
                        writeln!(
                            writer,
                            "{}",
                            serde_json::to_string(&rec).unwrap_or_default()
                        )?;
                    }
                    let summary = JsonlSummaryRecord {
                        record_type: "summary".to_string(),
                        total_records: response.matches.len(),
                        diagnostic_count: chunk.diagnostics.len(),
                        is_truncated: response.is_truncated,
                    };
                    writeln!(
                        writer,
                        "{}",
                        serde_json::to_string(&summary).unwrap_or_default()
                    )?;
                }
                OutputFormat::Dot => {
                    eprintln!("{}: DOT format not applicable to query", "error".red());
                    return Ok(ExitCode::UsageError);
                }
            }

            Ok(ExitCode::Success)
        }
        (false, true) => {
            let input_list = args.input_list.clone().unwrap();
            handle_batch_query(args, &input_list, writer)
        }
        (true, true) => {
            eprintln!(
                "{}: Cannot specify both a file and --input-list",
                "error".red()
            );
            Ok(ExitCode::UsageError)
        }
        (false, false) => {
            eprintln!(
                "{}: Either a file or --input-list must be provided",
                "error".red()
            );
            Ok(ExitCode::UsageError)
        }
    }
}

fn handle_batch_query(
    args: QueryArgs,
    input_list: &str,
    writer: &mut impl io::Write,
) -> io::Result<ExitCode> {
    let format = args.format.unwrap_or(OutputFormat::Jsonl);
    if format != OutputFormat::Jsonl {
        eprintln!(
            "{}: Batch query requires JSONL format (--format jsonl)",
            "error".red()
        );
        return Ok(ExitCode::UsageError);
    }

    if args.cursor.is_some() {
        eprintln!(
            "{}: --cursor is not supported with --input-list",
            "error".red()
        );
        return Ok(ExitCode::UsageError);
    }

    if let Some(where_expr) = args.r#where.as_deref() {
        if let Err(err) = luad_analysis::QueryExpr::parse(where_expr) {
            eprintln!("{}: Query error: {err}", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }

    let file_paths = match parse_input_list(input_list) {
        Ok(paths) => paths,
        Err((msg, code)) => {
            eprintln!("{}: {msg}", "error".red());
            return Ok(code);
        }
    };

    if file_paths.is_empty() {
        eprintln!("{}: No input files provided for query", "error".red());
        return Ok(ExitCode::UsageError);
    }

    let mut succeeded_count = 0;
    let mut skipped_count = 0;
    let mut failed_count = 0;
    let mut total_matches = 0;

    writeln!(
        writer,
        "{}",
        serde_json::to_string(&QueryStartRecord {
            record_type: "query_start".to_string(),
            schema_version: JSONL_SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            total_files: file_paths.len(),
            r#where: args.r#where.clone(),
            limit: args.limit,
        })
        .unwrap_or_default()
    )?;

    for path_str in &file_paths {
        let bytes = match read_input_bytes_with_reporting(path_str, false) {
            Ok(b) => b,
            Err(_) => {
                failed_count += 1;
                let start_rec = FileStartRecord {
                    record_type: "file_start".to_string(),
                    path: path_str.clone(),
                    sha256: String::new(),
                    byte_length: 0,
                    interpretation: None,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&start_rec).unwrap_or_default()
                )?;
                let diag = Diagnostic::error(
                    "IO-001",
                    DiagnosticCategory::Structure,
                    StableId::Chunk,
                    format!("Failed to read input file '{path_str}'"),
                );
                let diag_rec = JsonlDataRecord {
                    record_type: "diagnostic".to_string(),
                    context: JsonlRecordContext::failed_read(),
                    data: diag,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&diag_rec).unwrap_or_default()
                )?;
                let end_rec = FileEndRecord {
                    record_type: "file_end".to_string(),
                    path: path_str.clone(),
                    status: "failed".to_string(),
                    error: Some(format!("Failed to read input file '{path_str}'")),
                    instruction_count: 0,
                    diagnostic_count: 1,
                    is_truncated: false,
                    emitted_fact_count: 0,
                    available_fact_count: 0,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&end_rec).unwrap_or_default()
                )?;
                eprintln!("error: {path_str}: failed to read input file");
                continue;
            }
        };

        let parse_res = parse_chunk_detailed(
            path_str,
            &bytes,
            args.strict,
            args.dialect.as_deref(),
            false,
        );
        let (chunk, identity, _config, interp) = match parse_res {
            Ok(c) => c,
            Err((parse_code, parse_diag)) => {
                skipped_count += 1;
                let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
                let start_rec = FileStartRecord {
                    record_type: "file_start".to_string(),
                    path: path_str.clone(),
                    sha256: sha256.clone(),
                    byte_length: bytes.len(),
                    interpretation: None,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&start_rec).unwrap_or_default()
                )?;
                let is_source = !bytes.starts_with(b"\x1bLua")
                    && (bytes.starts_with(b"--")
                        || bytes
                            .iter()
                            .take(256)
                            .all(|&b| b.is_ascii() || b.is_ascii_whitespace()));
                let (diag, msg) = if is_source {
                    let msg = format!("Plain Lua source text is unsupported for bytecode query; compile with luac first: '{path_str}'");
                    let diag = Diagnostic::error(
                        "PARSE-SOURCE-001",
                        DiagnosticCategory::Parse,
                        StableId::Chunk,
                        msg.clone(),
                    );
                    (diag, msg)
                } else if parse_code == ExitCode::UnsupportedFormat {
                    let msg = format!("Unknown or unsupported bytecode format: '{path_str}'");
                    let mut diag = Diagnostic::error(
                        "PARSE-UNKNOWN-001",
                        DiagnosticCategory::Parse,
                        StableId::Chunk,
                        msg.clone(),
                    );
                    if let Some(underlying) = &parse_diag {
                        if let Some(loc) = &underlying.source {
                            diag = diag.with_source(loc.clone());
                        }
                        diag.evidence =
                            Some(format!("{}: {}", underlying.code, underlying.message));
                    }
                    (diag, msg)
                } else {
                    let msg = format!("Failed to parse Lua bytecode chunk '{path_str}'");
                    let mut diag = Diagnostic::error(
                        "PARSE-001",
                        DiagnosticCategory::Parse,
                        StableId::Chunk,
                        msg.clone(),
                    );
                    if let Some(underlying) = &parse_diag {
                        if let Some(loc) = &underlying.source {
                            diag = diag.with_source(loc.clone());
                        }
                        diag.evidence =
                            Some(format!("{}: {}", underlying.code, underlying.message));
                    }
                    (diag, msg)
                };
                let stderr_reason = match diag.code.as_str() {
                    "PARSE-SOURCE-001" => "plain Lua source text is unsupported",
                    "PARSE-UNKNOWN-001" => "unknown or unsupported bytecode format",
                    _ => "failed to parse Lua bytecode chunk",
                };
                let parse_identity = InputIdentity {
                    path: path_str.clone(),
                    sha256,
                    byte_length: bytes.len(),
                };
                let diag_rec = JsonlDataRecord {
                    record_type: "diagnostic".to_string(),
                    context: JsonlRecordContext::failed_parse(parse_identity),
                    data: diag,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&diag_rec).unwrap_or_default()
                )?;
                let end_rec = FileEndRecord {
                    record_type: "file_end".to_string(),
                    path: path_str.clone(),
                    status: "skipped".to_string(),
                    error: Some(if let Some(underlying) = &parse_diag {
                        format!("{msg}: {}", underlying.message)
                    } else {
                        msg.clone()
                    }),
                    instruction_count: 0,
                    diagnostic_count: 1,
                    is_truncated: false,
                    emitted_fact_count: 0,
                    available_fact_count: 0,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&end_rec).unwrap_or_default()
                )?;
                eprintln!("error: {path_str}: {stderr_reason}");
                continue;
            }
        };

        if let Err(diags) = validate_for_analysis(&chunk) {
            failed_count += 1;
            let start_rec = FileStartRecord {
                record_type: "file_start".to_string(),
                path: identity.path.clone(),
                sha256: identity.sha256.clone(),
                byte_length: identity.byte_length,
                interpretation: Some(interp.clone()),
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&start_rec).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity.clone(), interp.clone());
            for diag in &diags {
                let diag_rec = JsonlDataRecord {
                    record_type: "diagnostic".to_string(),
                    context: context.clone(),
                    data: diag.clone(),
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&diag_rec).unwrap_or_default()
                )?;
            }
            let end_rec = FileEndRecord {
                record_type: "file_end".to_string(),
                path: identity.path.clone(),
                status: "failed".to_string(),
                error: Some("Analysis validation failed".to_string()),
                instruction_count: 0,
                diagnostic_count: diags.len(),
                is_truncated: false,
                emitted_fact_count: 0,
                available_fact_count: 0,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&end_rec).unwrap_or_default()
            )?;
            eprintln!("error: {path_str}: analysis validation failed");
            continue;
        }

        writeln!(
            writer,
            "{}",
            serde_json::to_string(&FileStartRecord {
                record_type: "file_start".to_string(),
                path: identity.path.clone(),
                sha256: identity.sha256.clone(),
                byte_length: identity.byte_length,
                interpretation: Some(interp.clone()),
            })
            .unwrap_or_default()
        )?;

        let query_result = luad_analysis::query::execute_query_with_total(
            &chunk,
            args.r#where.as_deref(),
            args.limit,
            None,
        );

        let (response, available_fact_count) = match query_result {
            Ok(res) => res,
            Err(e) => {
                failed_count += 1;
                let diagnostic = Diagnostic::error(
                    "INTERNAL-IDENTITY-001",
                    DiagnosticCategory::Analysis,
                    StableId::Chunk,
                    e.to_string(),
                );
                let context = JsonlRecordContext::successful(identity.clone(), interp);
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&JsonlDataRecord {
                        record_type: "diagnostic".to_string(),
                        context,
                        data: diagnostic,
                    })
                    .unwrap_or_default()
                )?;
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&FileEndRecord {
                        record_type: "file_end".to_string(),
                        path: identity.path.clone(),
                        status: "failed".to_string(),
                        error: Some(e.to_string()),
                        instruction_count: 0,
                        diagnostic_count: 1,
                        is_truncated: false,
                        emitted_fact_count: 0,
                        available_fact_count: 0,
                    })
                    .unwrap_or_default()
                )?;
                eprintln!("error: {path_str}: query execution failed");
                continue;
            }
        };

        let context = JsonlRecordContext::successful(identity.clone(), interp);
        for m in &response.matches {
            let rec = JsonlDataRecord {
                record_type: "query_match".to_string(),
                context: context.clone(),
                data: m.clone(),
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&rec).unwrap_or_default()
            )?;
        }

        for diag in &chunk.diagnostics {
            let rec = JsonlDataRecord {
                record_type: "diagnostic".to_string(),
                context: context.clone(),
                data: diag.clone(),
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&rec).unwrap_or_default()
            )?;
        }

        succeeded_count += 1;
        total_matches += response.matches.len();

        let end_rec = FileEndRecord {
            record_type: "file_end".to_string(),
            path: identity.path.clone(),
            status: "succeeded".to_string(),
            error: None,
            instruction_count: 0,
            diagnostic_count: chunk.diagnostics.len(),
            is_truncated: response.is_truncated,
            emitted_fact_count: response.matches.len(),
            available_fact_count,
        };
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&end_rec).unwrap_or_default()
        )?;
    }

    writeln!(
        writer,
        "{}",
        serde_json::to_string(&QueryEndRecord {
            record_type: "query_end".to_string(),
            files_processed: file_paths.len(),
            files_succeeded: succeeded_count,
            files_skipped: skipped_count,
            files_failed: failed_count,
            total_matches,
        })
        .unwrap_or_default()
    )?;

    eprintln!(
        "{succeeded_count} queried, {skipped_count} skipped, {failed_count} failed ({total_matches} matches)"
    );

    if succeeded_count == 0 || (args.strict && (skipped_count > 0 || failed_count > 0)) {
        Ok(ExitCode::InvalidInput)
    } else {
        Ok(ExitCode::Success)
    }
}

fn handle_diff(args: DiffArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    let old_bytes = match read_input_bytes(&args.old_file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };
    let new_bytes = match read_input_bytes(&args.new_file) {
        Ok(b) => b,
        Err(code) => return Ok(code),
    };

    let (old_chunk, identity, config, interp) =
        match parse_chunk(&args.old_file, &old_bytes, false, None) {
            Ok(c) => c,
            Err(code) => return Ok(code),
        };
    let (new_chunk, _, _, _) = match parse_chunk(&args.new_file, &new_bytes, false, None) {
        Ok(c) => c,
        Err(code) => return Ok(code),
    };

    if let Err(diags) = validate_for_analysis(&old_chunk) {
        return Ok(handle_analysis_validation_failure("old chunk", &diags));
    }

    if let Err(diags) = validate_for_analysis(&new_chunk) {
        return Ok(handle_analysis_validation_failure("new chunk", &diags));
    }

    if old_chunk.dialect != new_chunk.dialect && !args.semantic {
        eprintln!(
            "{}: Cross-dialect diff between '{}' and '{}' requires --semantic flag",
            "error".red(),
            old_chunk.dialect,
            new_chunk.dialect
        );
        return Ok(ExitCode::UsageError);
    }

    let ignore_debug = args.ignore.as_deref() == Some("debug");
    let diff = luad_analysis::diff_chunks(&old_chunk, &new_chunk, args.semantic, ignore_debug);

    match args.format {
        OutputFormat::Text => render::render_diff(&diff, writer)?,
        OutputFormat::Json => {
            let doc = wrap_document(identity, interp, config, diff.clone(), vec![]);
            render::print_json(&doc, writer)?;
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: JSONL_SCHEMA_VERSION,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity.clone(),
                interpretation: interp.clone(),
                analysis_configuration: config,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&meta).unwrap_or_default()
            )?;
            let context = JsonlRecordContext::successful(identity, interp);
            let mut record_count = 0;
            for proto_diff in &diff.proto_diffs {
                let rec = JsonlDataRecord {
                    record_type: "diff_prototype".to_string(),
                    context: context.clone(),
                    data: proto_diff.clone(),
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&rec).unwrap_or_default()
                )?;
                record_count += 1;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: record_count,
                diagnostic_count: 0,
                is_truncated: false,
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&summary).unwrap_or_default()
            )?;
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to diff", "error".red());
            return Ok(ExitCode::UsageError);
        }
    }

    Ok(ExitCode::Success)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ExportFactFamily {
    Prototype,
    PrototypeIdentity,
    Instruction,
    Constant,
    Upvalue,
    Xref,
    Callee,
    Origin,
    CallRelation,
}

const EXPORT_FACT_FAMILIES: [ExportFactFamily; 9] = [
    ExportFactFamily::Prototype,
    ExportFactFamily::PrototypeIdentity,
    ExportFactFamily::Instruction,
    ExportFactFamily::Constant,
    ExportFactFamily::Upvalue,
    ExportFactFamily::Xref,
    ExportFactFamily::Callee,
    ExportFactFamily::Origin,
    ExportFactFamily::CallRelation,
];

impl ExportFactFamily {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Prototype => "prototype",
            Self::PrototypeIdentity => "prototype_identity",
            Self::Instruction => "instruction",
            Self::Constant => "constant",
            Self::Upvalue => "upvalue",
            Self::Xref => "xref",
            Self::Callee => "callee",
            Self::Origin => "origin",
            Self::CallRelation => "call_relation",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        EXPORT_FACT_FAMILIES
            .iter()
            .copied()
            .find(|family| family.as_str() == value)
    }
}

#[derive(Debug, Clone)]
struct ExportFactSelection {
    families: std::collections::BTreeSet<ExportFactFamily>,
    explicit: bool,
}

impl ExportFactSelection {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        let Some(value) = value else {
            return Ok(Self {
                families: EXPORT_FACT_FAMILIES.into_iter().collect(),
                explicit: false,
            });
        };

        if value.is_empty() {
            return Err("--facts requires a non-empty comma-separated family list".to_string());
        }

        let mut families = std::collections::BTreeSet::new();
        for name in value.split(',') {
            let Some(family) = ExportFactFamily::parse(name) else {
                return Err(format!("unknown export fact family '{name}'"));
            };
            if !families.insert(family) {
                return Err(format!("duplicate export fact family '{name}'"));
            }
        }

        Ok(Self {
            families,
            explicit: true,
        })
    }

    fn includes(&self, family: ExportFactFamily) -> bool {
        self.families.contains(&family)
    }

    fn includes_proto_tree_family(&self) -> bool {
        [
            ExportFactFamily::Prototype,
            ExportFactFamily::PrototypeIdentity,
            ExportFactFamily::Instruction,
            ExportFactFamily::Constant,
            ExportFactFamily::Upvalue,
        ]
        .into_iter()
        .any(|family| self.includes(family))
    }

    fn explicit_names(&self) -> Option<Vec<String>> {
        self.explicit.then(|| {
            EXPORT_FACT_FAMILIES
                .iter()
                .copied()
                .filter(|family| self.includes(*family))
                .map(|family| family.as_str().to_string())
                .collect()
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
struct ExportProtoMeta {
    id: StableId,
    path: ProtoPath,
    source_name: Option<String>,
    line_defined: usize,
    last_line_defined: usize,
    numparams: usize,
    is_vararg: bool,
    maxstacksize: usize,
    instructions_count: usize,
    constants_count: usize,
    upvalues_count: usize,
    protos_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(tag = "record_type", rename_all = "snake_case")]
enum ExportRecord {
    ExportStart {
        schema_version: u32,
        tool_version: String,
        total_files: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        fact_families: Option<Vec<String>>,
    },
    FileStart {
        path: String,
        sha256: String,
        byte_length: usize,
        interpretation: Option<ResolvedInterpretation>,
    },
    Prototype {
        context: JsonlRecordContext,
        data: ExportProtoMeta,
    },
    Instruction {
        context: JsonlRecordContext,
        data: luad_core::DisassembledInstruction,
    },
    Constant {
        context: JsonlRecordContext,
        data: luad_core::model::Constant,
    },
    Upvalue {
        context: JsonlRecordContext,
        data: luad_core::model::UpvalueDesc,
    },
    Xref {
        context: JsonlRecordContext,
        data: luad_analysis::XrefEntry,
    },
    Callee {
        context: JsonlRecordContext,
        data: luad_analysis::CalleeFact,
    },
    CallRelation {
        context: JsonlRecordContext,
        data: luad_analysis::CallRelationFact,
    },
    PrototypeIdentity {
        context: JsonlRecordContext,
        data: luad_analysis::PrototypeIdentityFact,
    },
    Origin {
        context: JsonlRecordContext,
        data: luad_analysis::CallOriginFact,
    },
    Diagnostic {
        context: JsonlRecordContext,
        data: luad_core::Diagnostic,
    },
    FileEnd {
        path: String,
        status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        instruction_count: usize,
        diagnostic_count: usize,
        is_truncated: bool,
        emitted_fact_count: usize,
        available_fact_count: usize,
    },
    ExportEnd {
        files_processed: usize,
        files_succeeded: usize,
        files_skipped: usize,
        files_failed: usize,
        total_instructions: usize,
    },
}

struct FactEmitter<'a, W: io::Write> {
    writer: &'a mut W,
    context: JsonlRecordContext,
    max_facts: Option<usize>,
    emitted_count: usize,
    instruction_count: usize,
}

impl<'a, W: io::Write> FactEmitter<'a, W> {
    fn new(writer: &'a mut W, context: JsonlRecordContext, max_facts: Option<usize>) -> Self {
        Self {
            writer,
            context,
            max_facts,
            emitted_count: 0,
            instruction_count: 0,
        }
    }

    fn should_emit(&self) -> bool {
        match self.max_facts {
            Some(limit) => self.emitted_count < limit,
            None => true,
        }
    }

    fn emit_fact<T: serde::Serialize>(&mut self, record_type: &str, data: &T) -> io::Result<bool> {
        if !self.should_emit() {
            return Ok(false);
        }
        let rec = JsonlDataRecord {
            record_type: record_type.to_string(),
            context: self.context.clone(),
            data,
        };
        writeln!(
            self.writer,
            "{}",
            serde_json::to_string(&rec).unwrap_or_default()
        )?;
        self.emitted_count += 1;
        Ok(true)
    }

    fn emit_instruction(&mut self, inst: &luad_core::DisassembledInstruction) -> io::Result<bool> {
        if !self.should_emit() {
            return Ok(false);
        }
        let rec = JsonlDataRecord {
            record_type: "instruction".to_string(),
            context: self.context.clone(),
            data: inst,
        };
        writeln!(
            self.writer,
            "{}",
            serde_json::to_string(&rec).unwrap_or_default()
        )?;
        self.emitted_count += 1;
        self.instruction_count += 1;
        Ok(true)
    }
}

fn count_available_facts_proto_tree(proto: &Prototype, selection: &ExportFactSelection) -> usize {
    let mut count = 0;
    if selection.includes(ExportFactFamily::Prototype) {
        count += 1;
    }
    if selection.includes(ExportFactFamily::Instruction) {
        count += proto.instructions.len();
    }
    if selection.includes(ExportFactFamily::Constant) {
        count += proto.constants.len();
    }
    if selection.includes(ExportFactFamily::Upvalue) {
        count += proto.upvalues.len();
    }
    for child in &proto.protos {
        count += count_available_facts_proto_tree(child, selection);
    }
    count
}

fn emit_export_proto_tree<W: io::Write>(
    proto: &Prototype,
    disasm: Option<&DisassembledPrototype>,
    identities: &std::collections::BTreeMap<StableId, luad_analysis::PrototypeIdentityFact>,
    selection: &ExportFactSelection,
    emitter: &mut FactEmitter<'_, W>,
) -> io::Result<()> {
    if !emitter.should_emit() {
        return Ok(());
    }

    if selection.includes(ExportFactFamily::Prototype) {
        let proto_meta = ExportProtoMeta {
            id: proto.id.clone(),
            path: proto.path.clone(),
            source_name: proto.source_name.as_ref().map(|s| s.display.clone()),
            line_defined: proto.line_defined,
            last_line_defined: proto.last_line_defined,
            numparams: proto.numparams as usize,
            is_vararg: proto.is_vararg != 0,
            maxstacksize: proto.maxstacksize as usize,
            instructions_count: proto.instructions.len(),
            constants_count: proto.constants.len(),
            upvalues_count: proto.upvalues.len(),
            protos_count: proto.protos.len(),
        };
        if !emitter.emit_fact("prototype", &proto_meta)? {
            return Ok(());
        }
    }

    if selection.includes(ExportFactFamily::PrototypeIdentity) {
        if let Some(identity) = identities.get(&proto.id) {
            if !emitter.emit_fact("prototype_identity", identity)? {
                return Ok(());
            }
        }
    }

    if selection.includes(ExportFactFamily::Instruction) {
        for inst in &disasm
            .expect("selected instruction facts require disassembly")
            .instructions
        {
            if !emitter.emit_instruction(inst)? {
                return Ok(());
            }
        }
    }

    if selection.includes(ExportFactFamily::Constant) {
        for c in &proto.constants {
            if !emitter.emit_fact("constant", c)? {
                return Ok(());
            }
        }
    }

    if selection.includes(ExportFactFamily::Upvalue) {
        for u in &proto.upvalues {
            if !emitter.emit_fact("upvalue", u)? {
                return Ok(());
            }
        }
    }

    for (index, child) in proto.protos.iter().enumerate() {
        if !emitter.should_emit() {
            return Ok(());
        }
        let child_disasm = disasm.map(|parent| &parent.child_protos[index]);
        emit_export_proto_tree(child, child_disasm, identities, selection, emitter)?;
    }

    Ok(())
}

fn handle_export(args: ExportArgs, writer: &mut impl io::Write) -> io::Result<ExitCode> {
    if args.format != OutputFormat::Jsonl {
        eprintln!(
            "{}: Export command requires JSONL format (--format jsonl)",
            "error".red()
        );
        return Ok(ExitCode::UsageError);
    }

    let fact_selection = match ExportFactSelection::parse(args.facts.as_deref()) {
        Ok(selection) => selection,
        Err(error) => {
            eprintln!("{}: {error}", "error".red());
            return Ok(ExitCode::UsageError);
        }
    };

    let mut file_paths = args.files;

    if let Some(list_file) = &args.input_list {
        match parse_input_list(list_file) {
            Ok(paths) => file_paths.extend(paths),
            Err((msg, code)) => {
                eprintln!("{}: {msg}", "error".red());
                return Ok(code);
            }
        }
    }

    if file_paths.is_empty() {
        eprintln!("{}: No input files provided for export", "error".red());
        return Ok(ExitCode::UsageError);
    }

    let mut succeeded_count = 0;
    let mut skipped_count = 0;
    let mut failed_count = 0;
    let mut total_instructions = 0;

    writeln!(
        writer,
        "{}",
        serde_json::to_string(&ExportStartRecord {
            record_type: "export_start".to_string(),
            schema_version: JSONL_SCHEMA_VERSION,
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            total_files: file_paths.len(),
            fact_families: fact_selection.explicit_names(),
        })
        .unwrap_or_default()
    )?;

    for path_str in &file_paths {
        let bytes = match read_input_bytes_with_reporting(path_str, false) {
            Ok(b) => b,
            Err(_) => {
                failed_count += 1;
                let start_rec = FileStartRecord {
                    record_type: "file_start".to_string(),
                    path: path_str.clone(),
                    sha256: String::new(),
                    byte_length: 0,
                    interpretation: None,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&start_rec).unwrap_or_default()
                )?;
                let diag = Diagnostic::error(
                    "IO-001",
                    DiagnosticCategory::Structure,
                    StableId::Chunk,
                    format!("Failed to read input file '{path_str}'"),
                );
                let diag_rec = JsonlDataRecord {
                    record_type: "diagnostic".to_string(),
                    context: JsonlRecordContext::failed_read(),
                    data: diag,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&diag_rec).unwrap_or_default()
                )?;
                let end_rec = FileEndRecord {
                    record_type: "file_end".to_string(),
                    path: path_str.clone(),
                    status: "failed".to_string(),
                    error: Some(format!("Failed to read input file '{path_str}'")),
                    instruction_count: 0,
                    diagnostic_count: 1,
                    is_truncated: false,
                    emitted_fact_count: 0,
                    available_fact_count: 0,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&end_rec).unwrap_or_default()
                )?;
                eprintln!("error: {path_str}: failed to read input file");
                continue;
            }
        };

        let parse_res = parse_chunk_detailed(
            path_str,
            &bytes,
            args.strict,
            args.dialect.as_deref(),
            false,
        );
        let (chunk, identity, _config, interp) = match parse_res {
            Ok(c) => c,
            Err((parse_code, parse_diag)) => {
                skipped_count += 1;
                let sha256 = hex::encode(sha2::Sha256::digest(&bytes));
                let start_rec = FileStartRecord {
                    record_type: "file_start".to_string(),
                    path: path_str.clone(),
                    sha256: sha256.clone(),
                    byte_length: bytes.len(),
                    interpretation: None,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&start_rec).unwrap_or_default()
                )?;
                let is_source = !bytes.starts_with(b"\x1bLua")
                    && (bytes.starts_with(b"--")
                        || bytes
                            .iter()
                            .take(256)
                            .all(|&b| b.is_ascii() || b.is_ascii_whitespace()));
                let (diag, msg) = if is_source {
                    let msg = format!("Plain Lua source text is unsupported for bytecode export; compile with luac first: '{path_str}'");
                    let diag = Diagnostic::error(
                        "PARSE-SOURCE-001",
                        DiagnosticCategory::Parse,
                        StableId::Chunk,
                        msg.clone(),
                    );
                    (diag, msg)
                } else if parse_code == ExitCode::UnsupportedFormat {
                    let msg = format!("Unknown or unsupported bytecode format: '{path_str}'");
                    let mut diag = Diagnostic::error(
                        "PARSE-UNKNOWN-001",
                        DiagnosticCategory::Parse,
                        StableId::Chunk,
                        msg.clone(),
                    );
                    if let Some(underlying) = &parse_diag {
                        if let Some(loc) = &underlying.source {
                            diag = diag.with_source(loc.clone());
                        }
                        diag.evidence =
                            Some(format!("{}: {}", underlying.code, underlying.message));
                    }
                    (diag, msg)
                } else {
                    let msg = format!("Failed to parse Lua bytecode chunk '{path_str}'");
                    let mut diag = Diagnostic::error(
                        "PARSE-001",
                        DiagnosticCategory::Parse,
                        StableId::Chunk,
                        msg.clone(),
                    );
                    if let Some(underlying) = &parse_diag {
                        if let Some(loc) = &underlying.source {
                            diag = diag.with_source(loc.clone());
                        }
                        diag.evidence =
                            Some(format!("{}: {}", underlying.code, underlying.message));
                    }
                    (diag, msg)
                };
                let stderr_reason = match diag.code.as_str() {
                    "PARSE-SOURCE-001" => "plain Lua source text is unsupported",
                    "PARSE-UNKNOWN-001" => "unknown or unsupported bytecode format",
                    _ => "failed to parse Lua bytecode chunk",
                };
                let parse_identity = InputIdentity {
                    path: path_str.clone(),
                    sha256,
                    byte_length: bytes.len(),
                };
                let diag_rec = JsonlDataRecord {
                    record_type: "diagnostic".to_string(),
                    context: JsonlRecordContext::failed_parse(parse_identity),
                    data: diag,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&diag_rec).unwrap_or_default()
                )?;
                let end_rec = FileEndRecord {
                    record_type: "file_end".to_string(),
                    path: path_str.clone(),
                    status: "skipped".to_string(),
                    error: Some(if let Some(underlying) = &parse_diag {
                        format!("{msg}: {}", underlying.message)
                    } else {
                        msg.clone()
                    }),
                    instruction_count: 0,
                    diagnostic_count: 1,
                    is_truncated: false,
                    emitted_fact_count: 0,
                    available_fact_count: 0,
                };
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&end_rec).unwrap_or_default()
                )?;
                eprintln!("error: {path_str}: {stderr_reason}");
                continue;
            }
        };

        writeln!(
            writer,
            "{}",
            serde_json::to_string(&FileStartRecord {
                record_type: "file_start".to_string(),
                path: identity.path.clone(),
                sha256: identity.sha256.clone(),
                byte_length: identity.byte_length,
                interpretation: Some(interp.clone()),
            })
            .unwrap_or_default()
        )?;

        let disasm = fact_selection
            .includes(ExportFactFamily::Instruction)
            .then(|| get_disasm_proto(&chunk.dialect, &chunk.main_proto));
        const LUA51_PROFILES: &[&str] = &["lua5.1", "lua5.1-lnum32", "lua5.1-stock32"];
        let is_lua51_profile = LUA51_PROFILES.contains(&chunk.dialect.as_str());
        let prototype_identity_analysis =
            if fact_selection.includes(ExportFactFamily::PrototypeIdentity) && is_lua51_profile {
                match luad_analysis::analyze_chunk_prototype_identities(&chunk) {
                    Ok(analysis) => Some(analysis),
                    Err(error) => {
                        failed_count += 1;
                        let diagnostic = Diagnostic::error(
                            "INTERNAL-IDENTITY-001",
                            DiagnosticCategory::Analysis,
                            StableId::Chunk,
                            error.to_string(),
                        );
                        let context = JsonlRecordContext::successful(identity.clone(), interp);
                        writeln!(
                            writer,
                            "{}",
                            serde_json::to_string(&JsonlDataRecord {
                                record_type: "diagnostic".to_string(),
                                context,
                                data: diagnostic,
                            })
                            .unwrap_or_default()
                        )?;
                        writeln!(
                            writer,
                            "{}",
                            serde_json::to_string(&FileEndRecord {
                                record_type: "file_end".to_string(),
                                path: identity.path.clone(),
                                status: "failed".to_string(),
                                error: Some(error.to_string()),
                                instruction_count: 0,
                                diagnostic_count: 1,
                                is_truncated: false,
                                emitted_fact_count: 0,
                                available_fact_count: 0,
                            })
                            .unwrap_or_default()
                        )?;
                        eprintln!("error: {path_str}: prototype identity analysis failed");
                        continue;
                    }
                }
            } else {
                None
            };
        let prototype_identities = prototype_identity_analysis
            .as_ref()
            .map(|analysis| {
                analysis
                    .prototypes
                    .iter()
                    .cloned()
                    .map(|fact| (fact.proto_id.clone(), fact))
                    .collect::<std::collections::BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let xref_index = fact_selection
            .includes(ExportFactFamily::Xref)
            .then(|| XrefIndex::build(&chunk));
        let callee_analysis = (fact_selection.includes(ExportFactFamily::Callee)
            && is_lua51_profile)
            .then(|| luad_analysis::analyze_chunk_callees(&chunk));
        let available_callee_count = callee_analysis
            .as_ref()
            .map(|analysis| {
                analysis
                    .prototypes
                    .iter()
                    .map(|prototype| prototype.calls.len())
                    .sum::<usize>()
            })
            .unwrap_or(0);
        let origin_analysis = (fact_selection.includes(ExportFactFamily::Origin)
            && is_lua51_profile)
            .then(|| luad_analysis::analyze_chunk_origins(&chunk));
        let available_origin_count = origin_analysis
            .as_ref()
            .map(|analysis| {
                analysis
                    .prototypes
                    .iter()
                    .map(|prototype| prototype.calls.len())
                    .sum::<usize>()
            })
            .unwrap_or(0);
        let call_relation_analysis = (fact_selection.includes(ExportFactFamily::CallRelation)
            && is_lua51_profile)
            .then(|| luad_analysis::analyze_chunk_call_relations(&chunk));
        let available_call_relation_count = call_relation_analysis
            .as_ref()
            .map(|analysis| {
                analysis
                    .prototypes
                    .iter()
                    .map(|prototype| prototype.calls.len())
                    .sum::<usize>()
            })
            .unwrap_or(0);
        let available_fact_count =
            count_available_facts_proto_tree(&chunk.main_proto, &fact_selection)
                + xref_index
                    .as_ref()
                    .map(|index| index.entries.len())
                    .unwrap_or(0)
                + available_callee_count
                + available_origin_count
                + available_call_relation_count
                + prototype_identities.len();

        let context = JsonlRecordContext::successful(identity.clone(), interp);
        let mut emitter = FactEmitter::new(writer, context.clone(), args.max_facts_per_file);
        if fact_selection.includes_proto_tree_family() {
            emit_export_proto_tree(
                &chunk.main_proto,
                disasm.as_ref(),
                &prototype_identities,
                &fact_selection,
                &mut emitter,
            )?;
        }

        if let Some(index) = &xref_index {
            for entry in &index.entries {
                if !emitter.emit_fact("xref", entry)? {
                    break;
                }
            }
        }

        if let Some(analysis) = &callee_analysis {
            'callees: for prototype in &analysis.prototypes {
                for fact in &prototype.calls {
                    if !emitter.emit_fact("callee", fact)? {
                        break 'callees;
                    }
                }
            }
        }

        if let Some(analysis) = &origin_analysis {
            'origins: for prototype in &analysis.prototypes {
                for fact in &prototype.calls {
                    if !emitter.emit_fact("origin", fact)? {
                        break 'origins;
                    }
                }
            }
        }

        if let Some(analysis) = &call_relation_analysis {
            'call_relations: for prototype in &analysis.prototypes {
                for fact in &prototype.calls {
                    if !emitter.emit_fact("call_relation", fact)? {
                        break 'call_relations;
                    }
                }
            }
        }

        let emitted_count = emitter.emitted_count;
        let instruction_count = emitter.instruction_count;
        drop(emitter);

        for diag in &chunk.diagnostics {
            let rec = JsonlDataRecord {
                record_type: "diagnostic".to_string(),
                context: context.clone(),
                data: diag.clone(),
            };
            writeln!(
                writer,
                "{}",
                serde_json::to_string(&rec).unwrap_or_default()
            )?;
        }

        succeeded_count += 1;
        total_instructions += instruction_count;

        let is_truncated = emitted_count < available_fact_count;
        let end_rec = FileEndRecord {
            record_type: "file_end".to_string(),
            path: identity.path.clone(),
            status: "succeeded".to_string(),
            error: None,
            instruction_count,
            diagnostic_count: chunk.diagnostics.len(),
            is_truncated,
            emitted_fact_count: emitted_count,
            available_fact_count,
        };
        writeln!(
            writer,
            "{}",
            serde_json::to_string(&end_rec).unwrap_or_default()
        )?;
    }

    writeln!(
        writer,
        "{}",
        serde_json::to_string(&ExportEndRecord {
            record_type: "export_end".to_string(),
            files_processed: file_paths.len(),
            files_succeeded: succeeded_count,
            files_skipped: skipped_count,
            files_failed: failed_count,
            total_instructions,
        })
        .unwrap_or_default()
    )?;

    eprintln!("{succeeded_count} exported, {skipped_count} skipped, {failed_count} failed");

    if succeeded_count == 0 || (args.strict && (skipped_count > 0 || failed_count > 0)) {
        Ok(ExitCode::InvalidInput)
    } else {
        Ok(ExitCode::Success)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fact_emitter_budget_and_counts() {
        let context = JsonlRecordContext::failed_parse(InputIdentity {
            path: "test.luac".to_string(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            byte_length: 32,
        });
        let mut buf = Vec::new();
        let mut emitter = FactEmitter::new(&mut buf, context, Some(2));
        assert!(emitter.should_emit());
        assert_eq!(emitter.emitted_count, 0);
        assert_eq!(emitter.instruction_count, 0);

        assert!(emitter.emit_fact("prototype", &"proto_data").unwrap());
        assert_eq!(emitter.emitted_count, 1);
        assert_eq!(emitter.instruction_count, 0);

        let dummy_inst = luad_core::DisassembledInstruction {
            id: StableId::instruction(luad_core::ProtoPath::root(), 0),
            pc: 0,
            raw_word: 0,
            raw_hex: "0x00000000".to_string(),
            mnemonic: "MOVE".to_string(),
            opcode_num: 0,
            role: "instruction".to_string(),
            encoded_operands: luad_core::EncodedOperands::default(),
            line: None,
            operands: vec![],
            jump_target: None,
            companion_pc: None,
            metamethod: None,
            comment: None,
            confidence: luad_core::Confidence::Fact,
            source: luad_core::SourceLocation {
                byte_offset: 0,
                byte_length: 4,
                raw_hex: "00000000".to_string(),
            },
            diagnostics: vec![],
        };

        assert!(emitter.emit_instruction(&dummy_inst).unwrap());
        assert_eq!(emitter.emitted_count, 2);
        assert_eq!(emitter.instruction_count, 1);

        assert!(!emitter.should_emit());
        assert!(!emitter.emit_fact("constant", &"const_data").unwrap());
        assert_eq!(emitter.emitted_count, 2);
    }

    #[test]
    fn test_fact_emitter_unbounded() {
        let context = JsonlRecordContext::failed_read();
        let mut buf = Vec::new();
        let mut emitter = FactEmitter::new(&mut buf, context, None);
        assert!(emitter.should_emit());
        assert!(emitter.emit_fact("prototype", &"proto_data").unwrap());
        assert!(emitter.emit_fact("constant", &"const_data").unwrap());
        assert!(emitter.emit_fact("upvalue", &"upvalue_data").unwrap());
        assert_eq!(emitter.emitted_count, 3);
    }

    #[test]
    fn test_export_fact_selection_gates_each_independent_family() {
        for selected in EXPORT_FACT_FAMILIES {
            let selection = ExportFactSelection::parse(Some(selected.as_str())).unwrap();
            for family in EXPORT_FACT_FAMILIES {
                assert_eq!(
                    selection.includes(family),
                    family == selected,
                    "{} selection must gate {} independently",
                    selected.as_str(),
                    family.as_str()
                );
            }
        }

        let default = ExportFactSelection::parse(None).unwrap();
        assert!(EXPORT_FACT_FAMILIES
            .iter()
            .all(|family| default.includes(*family)));
        assert_eq!(default.explicit_names(), None);

        let reordered = ExportFactSelection::parse(Some("instruction,prototype")).unwrap();
        assert_eq!(
            reordered.explicit_names(),
            Some(vec!["prototype".to_string(), "instruction".to_string()])
        );
    }

    #[test]
    fn test_classify_diagnostic_operand_vs_limits() {
        let dummy_id = StableId::proto(luad_core::id::ProtoPath::root());
        let make_item = |c: &str| {
            Diagnostic::new(
                c,
                DiagnosticCategory::Parse,
                Severity::Error,
                dummy_id.clone(),
                "test",
            )
        };

        // Operand bounds check failures must return InvalidInput (exit 1)
        assert_eq!(
            classify_diagnostic(&make_item("L54-VAL-CONST-001")),
            ExitCode::InvalidInput
        );
        assert_eq!(
            classify_diagnostic(&make_item("L54-VAL-UPVAL-001")),
            ExitCode::InvalidInput
        );

        // Resource count limits must return LimitExceeded (exit 5)
        assert_eq!(
            classify_diagnostic(&make_item("L54-CONST-001")),
            ExitCode::LimitExceeded
        );
        assert_eq!(
            classify_diagnostic(&make_item("CORE-LIMIT-003")),
            ExitCode::LimitExceeded
        );

        // Unsupported format/layout must return UnsupportedFormat (exit 4)
        assert_eq!(
            classify_diagnostic(&make_item("L52-HEADER-003")),
            ExitCode::UnsupportedFormat
        );
    }
}
