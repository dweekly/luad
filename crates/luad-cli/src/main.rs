//! `luad` command-line interface entry point.

use std::fs;
use std::io::{self, BufRead, Read};
use std::path::Path;

use clap::{CommandFactory, Parser};
use colored::Colorize;
use schemars::schema_for;
use sha2::{Digest, Sha256};

mod args;
mod exit_codes;
mod render;

use args::{
    CapabilitiesArgs, CfgArgs, Cli, Commands, CompletionsArgs, DiagnosticsArgs, DiffArgs,
    DisasmArgs, ExplainArgs, ExportArgs, InspectArgs, OutputFormat, QueryArgs, SchemaArgs,
    ValidateArgs, XrefsArgs,
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
    InputIdentity, JsonlDataRecord, JsonlMetadataRecord, JsonlSummaryRecord, MachineDocument,
    ValidationResponse,
};
use luad_core::id::{ProtoPath, StableId};
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::{Chunk, Prototype};
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::Lua54Dialect;

fn read_input_bytes(file_path: &str) -> Result<Vec<u8>, ExitCode> {
    let max_bytes = ResourceLimits::default().max_input_bytes;

    if file_path == "-" {
        let mut buffer = Vec::new();
        let mut reader = io::stdin().take((max_bytes + 1) as u64);
        reader.read_to_end(&mut buffer).map_err(|e| {
            eprintln!("{}: Failed to read from stdin: {e}", "error".red().bold());
            ExitCode::IoError
        })?;
        if buffer.len() > max_bytes {
            eprintln!(
                "{}: Stdin input exceeds safety limit of {max_bytes} bytes",
                "error".red().bold()
            );
            return Err(ExitCode::LimitExceeded);
        }
        Ok(buffer)
    } else {
        let path = Path::new(file_path);
        if !path.exists() {
            eprintln!("{}: File not found: '{}'", "error".red().bold(), file_path);
            return Err(ExitCode::IoError);
        }
        let metadata = fs::metadata(path).map_err(|e| {
            eprintln!(
                "{}: Failed to inspect metadata for '{}': {e}",
                "error".red().bold(),
                file_path
            );
            ExitCode::IoError
        })?;
        if metadata.len() > max_bytes as u64 {
            eprintln!(
                "{}: File '{}' size ({} bytes) exceeds safety limit of {max_bytes} bytes",
                "error".red().bold(),
                file_path,
                metadata.len()
            );
            return Err(ExitCode::LimitExceeded);
        }
        fs::read(path).map_err(|e| {
            eprintln!(
                "{}: Failed to read file '{}': {e}",
                "error".red().bold(),
                file_path
            );
            ExitCode::IoError
        })
    }
}

fn parse_chunk(
    file_path: &str,
    bytes: &[u8],
    strict: bool,
    dialect_override: Option<&str>,
) -> Result<
    (
        Chunk,
        InputIdentity,
        AnalysisConfiguration,
        ResolvedInterpretation,
    ),
    ExitCode,
> {
    let mode = if strict {
        ParseMode::Strict
    } else {
        ParseMode::Permissive
    };

    let limits = ResourceLimits::default();
    if bytes.len() > limits.max_input_bytes {
        eprintln!(
            "{}: Input size ({} bytes) exceeds safety limit of {} bytes",
            "error".red().bold(),
            bytes.len(),
            limits.max_input_bytes
        );
        return Err(ExitCode::LimitExceeded);
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
                eprintln!(
                        "{}: Ambiguous dialect 'lua5.1-lnum'. Please specify exact profile '--dialect lua5.1-lnum32'",
                        "error".red().bold()
                    );
                return Err(ExitCode::UsageError);
            }
            other => {
                eprintln!(
                    "{}: Dialect '{other}' is not yet supported in this build",
                    "error".red().bold()
                );
                return Err(ExitCode::UnsupportedFormat);
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
        eprintln!(
            "{}: Unknown or unsupported bytecode format (header did not match known dialects)",
            "error".red().bold()
        );
        return Err(ExitCode::UnsupportedFormat);
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
            eprintln!(
                "{}: Parsing failed at offset {}: {}",
                "error".red().bold(),
                diag.source.as_ref().map(|s| s.byte_offset).unwrap_or(0),
                diag.message
            );
            Err(ExitCode::InvalidInput)
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect(args) => handle_inspect(args),
        Commands::Disasm(args) => handle_disasm(args),
        Commands::Validate(args) => handle_validate(args),
        Commands::Capabilities(args) => handle_capabilities(args),
        Commands::Diagnostics(args) => handle_diagnostics(args),
        Commands::Schema(args) => handle_schema(args),
        Commands::Completions(args) => handle_completions(args),
        Commands::Cfg(args) => handle_cfg(args),
        Commands::Xrefs(args) => handle_xrefs(args),
        Commands::Explain(args) => handle_explain(args),
        Commands::Query(args) => handle_query(args),
        Commands::Diff(args) => handle_diff(args),
        Commands::Export(args) => handle_export(args),
        Commands::Compile(_) => {
            eprintln!(
                "{}: 'compile' command is not supported in bytecode analysis mode",
                "error".red().bold()
            );
            ExitCode::UnsupportedFormat.exit();
        }
    }
}

fn handle_inspect(args: InspectArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, args.strict, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => code.exit(),
        };

    match args.format {
        OutputFormat::Text => render::render_inspect(&chunk, args.summary),
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                chunk.clone(),
                chunk.diagnostics.clone(),
            );
            render::print_json(&doc);
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity,
                interpretation: interp,
                analysis_configuration: config,
            };
            println!("{}", serde_json::to_string(&meta).unwrap_or_default());
            let data_rec = JsonlDataRecord {
                record_type: "chunk".to_string(),
                data: chunk.clone(),
            };
            println!("{}", serde_json::to_string(&data_rec).unwrap_or_default());
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: 1,
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            println!("{}", serde_json::to_string(&summary).unwrap_or_default());
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not supported for inspect", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}

fn get_disasm_proto(dialect: &str, proto: &luad_core::model::Prototype) -> DisassembledPrototype {
    if dialect == "lua5.4" {
        luad_dialect_lua54::disassemble_proto_lua54(proto)
    } else if dialect.starts_with("lua5.1") {
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

fn handle_disasm(args: DisasmArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, args.strict, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => code.exit(),
        };

    let target_proto = if let Some(path_str) = &args.proto {
        let path: StableId = match path_str.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "{}: Invalid prototype selector '{path_str}': {e}",
                    "error".red()
                );
                ExitCode::UsageError.exit();
            }
        };
        let Some(proto) = find_proto_by_stable_id(&chunk.main_proto, &path) else {
            eprintln!("{}: Prototype '{path}' not found in chunk", "error".red());
            ExitCode::UsageError.exit();
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
            );
        }
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                disasm_proto.clone(),
                disasm_proto.diagnostics.clone(),
            );
            render::print_json(&doc);
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity,
                interpretation: interp,
                analysis_configuration: config,
            };
            println!("{}", serde_json::to_string(&meta).unwrap_or_default());
            for inst in &disasm_proto.instructions {
                let rec = JsonlDataRecord {
                    record_type: "instruction".to_string(),
                    data: inst.clone(),
                };
                println!("{}", serde_json::to_string(&rec).unwrap_or_default());
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: disasm_proto.instructions.len(),
                diagnostic_count: disasm_proto.diagnostics.len(),
                is_truncated: false,
            };
            println!("{}", serde_json::to_string(&summary).unwrap_or_default());
        }
        OutputFormat::Dot => {
            eprintln!(
                "{}: Use 'luad cfg --format dot' for graphviz output",
                "error".red()
            );
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
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

fn handle_validate(args: ValidateArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, args.strict, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => code.exit(),
        };

    let (verdict, diagnostics) = match chunk.dialect.as_str() {
        "lua5.5" => luad_dialect_lua55::validate_chunk_lua55(&chunk),
        "lua5.4" => luad_dialect_lua54::validate_chunk_lua54(&chunk),
        "lua5.3" => luad_dialect_lua53::validate_chunk_lua53(&chunk),
        "lua5.2" => luad_dialect_lua52::validate_chunk_lua52(&chunk),
        d if d.starts_with("lua5.1") => luad_dialect_lua51::validate_chunk_lua51(&chunk),
        _ => (chunk.verdict, chunk.diagnostics.clone()),
    };

    let is_invalid = verdict == Verdict::Invalid
        || (args.strict
            && (diagnostics
                .iter()
                .any(|d| d.severity == Severity::Error || d.severity == Severity::Warning)));

    match args.format {
        OutputFormat::Text => render::render_validate(verdict, &diagnostics),
        OutputFormat::Json => {
            let val_resp = ValidationResponse {
                verdict,
                diagnostic_count: diagnostics.len(),
                diagnostics: diagnostics.clone(),
            };
            let doc = wrap_document(identity, interp, config, val_resp, diagnostics);
            render::print_json(&doc);
        }
        _ => {
            eprintln!("{}: Format not supported for validate", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    if is_invalid {
        ExitCode::InvalidInput.exit();
    } else {
        ExitCode::Success.exit();
    }
}

fn handle_capabilities(args: CapabilitiesArgs) {
    let mut manifest = luad_core::get_canonical_capabilities(env!("CARGO_PKG_VERSION"));
    if !args.evidence {
        manifest.evidence.clear();
        for d in &mut manifest.dialects {
            d.evidence.clear();
        }
    }

    match args.format {
        OutputFormat::Text => render::render_capabilities(&manifest, args.evidence),
        OutputFormat::Json => {
            render::print_json(&manifest);
        }
        _ => {
            ExitCode::UsageError.exit();
        }
    }
    ExitCode::Success.exit();
}

fn handle_diagnostics(args: DiagnosticsArgs) {
    if matches!(args.format, OutputFormat::Jsonl | OutputFormat::Dot) {
        ExitCode::UsageError.exit();
    }

    let descriptors = match args.code {
        Some(code) => match luad_core::lookup_diagnostic(&code) {
            Some(desc) => vec![desc],
            None => {
                eprintln!("error: Unknown diagnostic code '{code}'");
                ExitCode::UsageError.exit();
            }
        },
        None => luad_core::list_diagnostics(),
    };

    match args.format {
        OutputFormat::Text => {
            render::render_diagnostic_descriptors(&descriptors);
        }
        OutputFormat::Json => {
            let response = luad_core::build_catalog_response(descriptors);
            render::print_json(&response);
        }
        _ => {
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}

fn handle_schema(args: SchemaArgs) {
    if args.schema_version != 1 {
        eprintln!(
            "{}: Only schema version 1 is supported by this build",
            "error".red()
        );
        ExitCode::UsageError.exit();
    }

    match args.name.as_str() {
        "chunk" => {
            let schema = schema_for!(MachineDocument<Chunk>);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "diagnostic" => {
            let schema = schema_for!(Diagnostic);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "diagnostics" => {
            let schema = schema_for!(luad_core::DiagnosticCatalogResponse);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "instruction" => {
            let schema = schema_for!(luad_core::SemanticInstruction);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "cfg" => {
            let schema = schema_for!(MachineDocument<ControlFlowGraph>);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "xrefs" => {
            let schema = schema_for!(MachineDocument<XrefResponse>);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "query" | "analysis" => {
            let schema = schema_for!(MachineDocument<QueryResponse>);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "diff" => {
            let schema = schema_for!(MachineDocument<luad_analysis::ChunkDiff>);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "capabilities" | "manifest" => {
            let schema = schema_for!(luad_core::CapabilityManifest);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "disasm" => {
            let schema = schema_for!(MachineDocument<DisassembledPrototype>);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "validate" => {
            let schema = schema_for!(MachineDocument<ValidationResponse>);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        "export" => {
            let schema = schema_for!(ExportRecord);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).unwrap_or_default()
            );
        }
        other => {
            eprintln!(
                "{}: Unknown schema '{other}'. Supported: chunk, disasm, validate, diagnostic, diagnostics, instruction, cfg, xrefs, query, analysis, diff, capabilities, manifest",
                "error".red()
            );
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}

fn handle_completions(args: CompletionsArgs) {
    let mut cmd = Cli::command();
    clap_complete::generate(args.shell, &mut cmd, "luad", &mut io::stdout());
    ExitCode::Success.exit();
}

fn handle_explain(args: ExplainArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (chunk, _, _, _) = match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let target_id: StableId = match args.target.parse() {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "{}: Invalid target StableId '{}': {e}",
                "error".red(),
                args.target
            );
            ExitCode::UsageError.exit();
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
                ExitCode::UsageError.exit();
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
                ExitCode::UsageError.exit();
            };

            match args.format {
                OutputFormat::Text => render::render_explain_instruction(sem_inst, disasm_inst),
                OutputFormat::Json => render::print_json(sem_inst),
                OutputFormat::Jsonl => render::print_jsonl(&[sem_inst]),
                OutputFormat::Dot => {
                    eprintln!("{}: DOT format not applicable to explain", "error".red());
                    ExitCode::UsageError.exit();
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

    ExitCode::Success.exit();
}

fn handle_cfg(args: CfgArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => code.exit(),
        };

    if let Err(diags) = validate_for_analysis(&chunk) {
        eprintln!(
            "{}: Analysis refused: chunk failed validation checks",
            "error".red()
        );
        for d in diags {
            if d.severity == Severity::Error {
                eprintln!("  - [{}] {}", d.code, d.message);
            }
        }
        ExitCode::InvalidInput.exit();
    }

    let target_id: StableId = match args.proto.parse() {
        Ok(id) => id,
        Err(e) => {
            eprintln!(
                "{}: Invalid prototype selector '{}': {e}",
                "error".red(),
                args.proto
            );
            ExitCode::UsageError.exit();
        }
    };

    let Some(target_proto) = find_proto_by_stable_id(&chunk.main_proto, &target_id) else {
        eprintln!(
            "{}: Prototype '{}' not found in chunk",
            "error".red(),
            target_id
        );
        ExitCode::UsageError.exit();
    };

    let lifted = luad_analysis::lift_proto_for_dialect(&chunk.dialect, target_proto);
    let cfg = ControlFlowGraph::build(target_proto, &lifted);

    match args.format {
        OutputFormat::Text => render::render_cfg(&cfg),
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                cfg.clone(),
                chunk.diagnostics.clone(),
            );
            render::print_json(&doc);
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity,
                interpretation: interp,
                analysis_configuration: config,
            };
            println!("{}", serde_json::to_string(&meta).unwrap_or_default());
            for block in &cfg.blocks {
                let rec = JsonlDataRecord {
                    record_type: "basic_block".to_string(),
                    data: block.clone(),
                };
                println!("{}", serde_json::to_string(&rec).unwrap_or_default());
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: cfg.blocks.len(),
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            println!("{}", serde_json::to_string(&summary).unwrap_or_default());
        }
        OutputFormat::Dot => print!("{}", cfg.to_dot()),
    }

    ExitCode::Success.exit();
}

fn handle_xrefs(args: XrefsArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => code.exit(),
        };

    if let Err(diags) = validate_for_analysis(&chunk) {
        eprintln!(
            "{}: Analysis refused: chunk failed validation checks",
            "error".red()
        );
        for d in diags {
            if d.severity == Severity::Error {
                eprintln!("  - [{}] {}", d.code, d.message);
            }
        }
        ExitCode::InvalidInput.exit();
    }

    let index = XrefIndex::build(&chunk);

    let target_id = if let Some(to_str) = &args.to {
        let to_id: StableId = match to_str.parse() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("{}: Invalid target ID '{to_str}': {e}", "error".red());
                ExitCode::UsageError.exit();
            }
        };
        if !validate_target(&chunk, &to_id) {
            eprintln!(
                "{}: Target '{}' does not exist in chunk",
                "error".red(),
                to_id
            );
            ExitCode::UsageError.exit();
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
                ExitCode::UsageError.exit();
            }
        };
        if !validate_target(&chunk, &from_id) {
            eprintln!(
                "{}: Source target '{}' does not exist in chunk",
                "error".red(),
                from_id
            );
            ExitCode::UsageError.exit();
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
        OutputFormat::Text => render::render_xrefs(&matching_refs.iter().collect::<Vec<_>>()),
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                xref_response,
                chunk.diagnostics.clone(),
            );
            render::print_json(&doc);
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity,
                interpretation: interp,
                analysis_configuration: config,
            };
            println!("{}", serde_json::to_string(&meta).unwrap_or_default());
            for entry in &matching_refs {
                let rec = JsonlDataRecord {
                    record_type: "xref".to_string(),
                    data: entry.clone(),
                };
                println!("{}", serde_json::to_string(&rec).unwrap_or_default());
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: total_count,
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: false,
            };
            println!("{}", serde_json::to_string(&summary).unwrap_or_default());
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to xrefs", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}

fn handle_query(args: QueryArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (chunk, identity, config, interp) =
        match parse_chunk(&args.file, &bytes, false, args.dialect.as_deref()) {
            Ok(c) => c,
            Err(code) => code.exit(),
        };

    if let Err(diags) = validate_for_analysis(&chunk) {
        eprintln!(
            "{}: Analysis refused: chunk failed validation checks",
            "error".red()
        );
        for d in diags {
            if d.severity == Severity::Error {
                eprintln!("  - [{}] {}", d.code, d.message);
            }
        }
        ExitCode::InvalidInput.exit();
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
            ExitCode::UsageError.exit();
        }
    };

    match args.format {
        OutputFormat::Text => render::render_query(&response),
        OutputFormat::Json => {
            let doc = wrap_document(
                identity,
                interp,
                config,
                response.clone(),
                chunk.diagnostics.clone(),
            );
            render::print_json(&doc);
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity,
                interpretation: interp,
                analysis_configuration: config,
            };
            println!("{}", serde_json::to_string(&meta).unwrap_or_default());
            for m in &response.matches {
                let rec = JsonlDataRecord {
                    record_type: "query_match".to_string(),
                    data: m.clone(),
                };
                println!("{}", serde_json::to_string(&rec).unwrap_or_default());
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: response.matches.len(),
                diagnostic_count: chunk.diagnostics.len(),
                is_truncated: response.is_truncated,
            };
            println!("{}", serde_json::to_string(&summary).unwrap_or_default());
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to query", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}

fn handle_diff(args: DiffArgs) {
    let old_bytes = match read_input_bytes(&args.old_file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };
    let new_bytes = match read_input_bytes(&args.new_file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let (old_chunk, identity, config, interp) =
        match parse_chunk(&args.old_file, &old_bytes, false, None) {
            Ok(c) => c,
            Err(code) => code.exit(),
        };
    let (new_chunk, _, _, _) = match parse_chunk(&args.new_file, &new_bytes, false, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    if let Err(diags) = validate_for_analysis(&old_chunk) {
        eprintln!(
            "{}: Analysis refused: old chunk failed validation checks",
            "error".red()
        );
        for d in diags {
            if d.severity == Severity::Error {
                eprintln!("  - [{}] {}", d.code, d.message);
            }
        }
        ExitCode::InvalidInput.exit();
    }

    if let Err(diags) = validate_for_analysis(&new_chunk) {
        eprintln!(
            "{}: Analysis refused: new chunk failed validation checks",
            "error".red()
        );
        for d in diags {
            if d.severity == Severity::Error {
                eprintln!("  - [{}] {}", d.code, d.message);
            }
        }
        ExitCode::InvalidInput.exit();
    }

    if old_chunk.dialect != new_chunk.dialect && !args.semantic {
        eprintln!(
            "{}: Cross-dialect diff between '{}' and '{}' requires --semantic flag",
            "error".red(),
            old_chunk.dialect,
            new_chunk.dialect
        );
        ExitCode::UsageError.exit();
    }

    let ignore_debug = args.ignore.as_deref() == Some("debug");
    let diff = luad_analysis::diff_chunks(&old_chunk, &new_chunk, args.semantic, ignore_debug);

    match args.format {
        OutputFormat::Text => render::render_diff(&diff),
        OutputFormat::Json => {
            let doc = wrap_document(identity, interp, config, diff.clone(), vec![]);
            render::print_json(&doc);
        }
        OutputFormat::Jsonl => {
            let meta = JsonlMetadataRecord {
                record_type: "metadata".to_string(),
                schema_version: 1,
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                input_identity: identity,
                interpretation: interp,
                analysis_configuration: config,
            };
            println!("{}", serde_json::to_string(&meta).unwrap_or_default());
            let mut record_count = 0;
            for proto_diff in &diff.proto_diffs {
                let rec = JsonlDataRecord {
                    record_type: "diff_prototype".to_string(),
                    data: proto_diff.clone(),
                };
                println!("{}", serde_json::to_string(&rec).unwrap_or_default());
                record_count += 1;
            }
            let summary = JsonlSummaryRecord {
                record_type: "summary".to_string(),
                total_records: record_count,
                diagnostic_count: 0,
                is_truncated: false,
            };
            println!("{}", serde_json::to_string(&summary).unwrap_or_default());
        }
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to diff", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
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
        tool_version: String,
        total_files: usize,
    },
    FileStart {
        path: String,
        sha256: String,
        byte_length: usize,
        interpretation: Option<ResolvedInterpretation>,
    },
    Prototype {
        data: ExportProtoMeta,
    },
    Instruction {
        data: luad_core::DisassembledInstruction,
    },
    Constant {
        data: luad_core::model::Constant,
    },
    Upvalue {
        data: luad_core::model::UpvalueDesc,
    },
    Xref {
        data: luad_analysis::XrefEntry,
    },
    Diagnostic {
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
        files_failed: usize,
        total_instructions: usize,
    },
}

struct FactEmitter {
    max_facts: Option<usize>,
    emitted_count: usize,
    instruction_count: usize,
}

impl FactEmitter {
    fn new(max_facts: Option<usize>) -> Self {
        Self {
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

    fn emit_fact<T: serde::Serialize>(&mut self, record_type: &str, data: &T) -> bool {
        if !self.should_emit() {
            return false;
        }
        let rec = JsonlDataRecord {
            record_type: record_type.to_string(),
            data,
        };
        println!("{}", serde_json::to_string(&rec).unwrap_or_default());
        self.emitted_count += 1;
        true
    }

    fn emit_instruction(&mut self, inst: &luad_core::DisassembledInstruction) -> bool {
        if !self.should_emit() {
            return false;
        }
        let rec = JsonlDataRecord {
            record_type: "instruction".to_string(),
            data: inst,
        };
        println!("{}", serde_json::to_string(&rec).unwrap_or_default());
        self.emitted_count += 1;
        self.instruction_count += 1;
        true
    }
}

fn count_available_facts_proto_tree(proto: &Prototype, disasm: &DisassembledPrototype) -> usize {
    let mut count = 1 + disasm.instructions.len() + proto.constants.len() + proto.upvalues.len();
    for (child, child_disasm) in proto.protos.iter().zip(disasm.child_protos.iter()) {
        count += count_available_facts_proto_tree(child, child_disasm);
    }
    count
}

fn emit_export_proto_tree(
    proto: &Prototype,
    disasm: &DisassembledPrototype,
    emitter: &mut FactEmitter,
) {
    if !emitter.should_emit() {
        return;
    }

    let proto_rec = JsonlDataRecord {
        record_type: "prototype".to_string(),
        data: ExportProtoMeta {
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
        },
    };
    if !emitter.emit_fact("prototype", &proto_rec.data) {
        return;
    }

    for inst in &disasm.instructions {
        if !emitter.emit_instruction(inst) {
            return;
        }
    }

    for c in &proto.constants {
        if !emitter.emit_fact("constant", c) {
            return;
        }
    }

    for u in &proto.upvalues {
        if !emitter.emit_fact("upvalue", u) {
            return;
        }
    }

    for (child, child_disasm) in proto.protos.iter().zip(disasm.child_protos.iter()) {
        if !emitter.should_emit() {
            return;
        }
        emit_export_proto_tree(child, child_disasm, emitter);
    }
}

fn handle_export(args: ExportArgs) {
    if args.format != OutputFormat::Jsonl {
        eprintln!(
            "{}: Export command requires JSONL format (--format jsonl)",
            "error".red()
        );
        ExitCode::UsageError.exit();
    }

    let mut file_paths = args.files;

    if let Some(list_file) = &args.input_list {
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
                    eprintln!(
                        "{}: Failed to read input list '{}': {e}",
                        "error".red(),
                        list_file
                    );
                    ExitCode::IoError.exit();
                }
            };
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    file_paths.push(trimmed.to_string());
                }
            }
        }
    }

    if file_paths.is_empty() {
        eprintln!("{}: No input files provided for export", "error".red());
        ExitCode::UsageError.exit();
    }

    let mut any_failed = false;
    let mut succeeded_count = 0;
    let mut failed_count = 0;
    let mut total_instructions = 0;

    println!(
        "{}",
        serde_json::to_string(&ExportStartRecord {
            record_type: "export_start".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            total_files: file_paths.len(),
        })
        .unwrap_or_default()
    );

    for path_str in &file_paths {
        let bytes = match read_input_bytes(path_str) {
            Ok(b) => b,
            Err(_) => {
                any_failed = true;
                failed_count += 1;
                let start_rec = FileStartRecord {
                    record_type: "file_start".to_string(),
                    path: path_str.clone(),
                    sha256: String::new(),
                    byte_length: 0,
                    interpretation: None,
                };
                println!("{}", serde_json::to_string(&start_rec).unwrap_or_default());
                let diag = Diagnostic::error(
                    "IO-001",
                    DiagnosticCategory::Structure,
                    StableId::Chunk,
                    format!("Failed to read input file '{path_str}'"),
                );
                let diag_rec = JsonlDataRecord {
                    record_type: "diagnostic".to_string(),
                    data: diag,
                };
                println!("{}", serde_json::to_string(&diag_rec).unwrap_or_default());
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
                println!("{}", serde_json::to_string(&end_rec).unwrap_or_default());
                continue;
            }
        };

        let parse_res = parse_chunk(path_str, &bytes, args.strict, args.dialect.as_deref());
        let (chunk, identity, _config, interp) = match parse_res {
            Ok(c) => c,
            Err(_) => {
                any_failed = true;
                failed_count += 1;
                let sha256 = format!("{:x}", sha2::Sha256::digest(&bytes));
                let start_rec = FileStartRecord {
                    record_type: "file_start".to_string(),
                    path: path_str.clone(),
                    sha256,
                    byte_length: bytes.len(),
                    interpretation: None,
                };
                println!("{}", serde_json::to_string(&start_rec).unwrap_or_default());
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
                } else {
                    let msg = format!("Failed to parse Lua bytecode chunk '{path_str}'");
                    let diag = Diagnostic::error(
                        "PARSE-001",
                        DiagnosticCategory::Parse,
                        StableId::Chunk,
                        msg.clone(),
                    );
                    (diag, msg)
                };
                let diag_rec = JsonlDataRecord {
                    record_type: "diagnostic".to_string(),
                    data: diag,
                };
                println!("{}", serde_json::to_string(&diag_rec).unwrap_or_default());
                let end_rec = FileEndRecord {
                    record_type: "file_end".to_string(),
                    path: path_str.clone(),
                    status: "failed".to_string(),
                    error: Some(msg),
                    instruction_count: 0,
                    diagnostic_count: 1,
                    is_truncated: false,
                    emitted_fact_count: 0,
                    available_fact_count: 0,
                };
                println!("{}", serde_json::to_string(&end_rec).unwrap_or_default());
                continue;
            }
        };

        println!(
            "{}",
            serde_json::to_string(&FileStartRecord {
                record_type: "file_start".to_string(),
                path: identity.path.clone(),
                sha256: identity.sha256.clone(),
                byte_length: identity.byte_length,
                interpretation: Some(interp),
            })
            .unwrap_or_default()
        );

        let disasm = get_disasm_proto(&chunk.dialect, &chunk.main_proto);
        let xref_index = XrefIndex::build(&chunk);
        let available_fact_count =
            count_available_facts_proto_tree(&chunk.main_proto, &disasm) + xref_index.entries.len();

        let mut emitter = FactEmitter::new(args.max_facts_per_file);
        emit_export_proto_tree(&chunk.main_proto, &disasm, &mut emitter);

        for entry in &xref_index.entries {
            if !emitter.emit_fact("xref", entry) {
                break;
            }
        }

        for diag in &chunk.diagnostics {
            let rec = JsonlDataRecord {
                record_type: "diagnostic".to_string(),
                data: diag.clone(),
            };
            println!("{}", serde_json::to_string(&rec).unwrap_or_default());
        }

        succeeded_count += 1;
        total_instructions += emitter.instruction_count;

        let is_truncated = emitter.emitted_count < available_fact_count;
        let end_rec = FileEndRecord {
            record_type: "file_end".to_string(),
            path: identity.path.clone(),
            status: "succeeded".to_string(),
            error: None,
            instruction_count: emitter.instruction_count,
            diagnostic_count: chunk.diagnostics.len(),
            is_truncated,
            emitted_fact_count: emitter.emitted_count,
            available_fact_count,
        };
        println!("{}", serde_json::to_string(&end_rec).unwrap_or_default());
    }

    println!(
        "{}",
        serde_json::to_string(&ExportEndRecord {
            record_type: "export_end".to_string(),
            files_processed: file_paths.len(),
            files_succeeded: succeeded_count,
            files_failed: failed_count,
            total_instructions,
        })
        .unwrap_or_default()
    );

    if any_failed {
        ExitCode::InvalidInput.exit();
    } else {
        ExitCode::Success.exit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fact_emitter_budget_and_counts() {
        let mut emitter = FactEmitter::new(Some(2));
        assert!(emitter.should_emit());
        assert_eq!(emitter.emitted_count, 0);
        assert_eq!(emitter.instruction_count, 0);

        assert!(emitter.emit_fact("prototype", &"proto_data"));
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

        assert!(emitter.emit_instruction(&dummy_inst));
        assert_eq!(emitter.emitted_count, 2);
        assert_eq!(emitter.instruction_count, 1);

        assert!(!emitter.should_emit());
        assert!(!emitter.emit_fact("constant", &"const_data"));
        assert_eq!(emitter.emitted_count, 2);
    }

    #[test]
    fn test_fact_emitter_unbounded() {
        let mut emitter = FactEmitter::new(None);
        assert!(emitter.should_emit());
        assert!(emitter.emit_fact("prototype", &"proto_data"));
        assert!(emitter.emit_fact("constant", &"const_data"));
        assert!(emitter.emit_fact("upvalue", &"upvalue_data"));
        assert_eq!(emitter.emitted_count, 3);
    }
}
