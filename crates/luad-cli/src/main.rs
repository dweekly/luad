//! `luad` command-line interface entry point.

use std::fs;
use std::io::{self, Read};
use std::path::Path;

use clap::{CommandFactory, Parser};
use colored::Colorize;
use schemars::schema_for;

mod args;
mod exit_codes;
mod render;

use args::{
    CapabilitiesArgs, CfgArgs, Cli, Commands, CompletionsArgs, DiffArgs, DisasmArgs, ExplainArgs,
    InspectArgs, OutputFormat, QueryArgs, SchemaArgs, ValidateArgs, XrefsArgs,
};
use exit_codes::ExitCode;
use luad_core::diagnostic::{Diagnostic, Severity, Verdict};
use luad_core::id::StableId;
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::Chunk;
use luad_core::reader::SafeReader;
use luad_core::Dialect;
use luad_dialect_lua54::{validate_chunk_lua54, Lua54Dialect};

fn read_input_bytes(file_path: &str) -> Result<Vec<u8>, ExitCode> {
    if file_path == "-" {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer).map_err(|e| {
            eprintln!("{}: Failed to read from stdin: {e}", "error".red().bold());
            ExitCode::IoError
        })?;
        Ok(buffer)
    } else {
        let path = Path::new(file_path);
        if !path.exists() {
            eprintln!(
                "{}: File not found: '{}'",
                "error".red().bold(),
                file_path
            );
            return Err(ExitCode::IoError);
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

fn parse_chunk(bytes: &[u8], strict: bool, dialect_override: Option<&str>) -> Result<Chunk, ExitCode> {
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

    let lua55 = luad_dialect_lua55::Lua55Dialect;
    let lua54 = Lua54Dialect;
    let lua53 = luad_dialect_lua53::Lua53Dialect;
    let lua52 = luad_dialect_lua52::Lua52Dialect;
    let lua51 = luad_dialect_lua51::Lua51Dialect;

    let selected_dialect: &dyn Dialect = if let Some(d) = dialect_override {
        match d {
            "lua5.5" => &lua55,
            "lua5.4" => &lua54,
            "lua5.3" => &lua53,
            "lua5.2" => &lua52,
            "lua5.1" => &lua51,
            other => {
                eprintln!(
                    "{}: Dialect '{other}' is not yet supported in this build",
                    "error".red().bold()
                );
                return Err(ExitCode::UnsupportedFormat);
            }
        }
    } else if lua55.detect(bytes).is_some() {
        &lua55
    } else if lua54.detect(bytes).is_some() {
        &lua54
    } else if lua53.detect(bytes).is_some() {
        &lua53
    } else if lua52.detect(bytes).is_some() {
        &lua52
    } else if lua51.detect(bytes).is_some() {
        &lua51
    } else {
        eprintln!(
            "{}: Unknown or unsupported bytecode format (header did not match known dialects)",
            "error".red().bold()
        );
        return Err(ExitCode::UnsupportedFormat);
    };



    let mut reader = SafeReader::with_options(bytes, 0, limits, mode);
    match selected_dialect.decode_chunk(&mut reader) {
        Ok(chunk) => Ok(chunk),
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect(args) => handle_inspect(args),
        Commands::Disasm(args) => handle_disasm(args),
        Commands::Validate(args) => handle_validate(args),
        Commands::Capabilities(args) => handle_capabilities(args),
        Commands::Schema(args) => handle_schema(args),
        Commands::Completions(args) => handle_completions(args),
        Commands::Cfg(args) => handle_cfg(args),
        Commands::Xrefs(args) => handle_xrefs(args),
        Commands::Explain(args) => handle_explain(args),
        Commands::Query(args) => handle_query(args),
        Commands::Diff(args) => handle_diff(args),
        Commands::Compile(_) => {
            eprintln!("{}: 'compile' command is scheduled for Phase 0/1 tooling", "info".cyan());
            ExitCode::Success.exit();
        }
    }
}


fn handle_inspect(args: InspectArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let chunk = match parse_chunk(&bytes, args.strict, args.dialect.as_deref()) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    match args.format {
        OutputFormat::Text => render::render_inspect(&chunk, args.summary),
        OutputFormat::Json => render::print_json(&chunk),
        OutputFormat::Jsonl => render::print_jsonl(&[chunk]),
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not supported for inspect", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}

fn handle_disasm(args: DisasmArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let chunk = match parse_chunk(&bytes, args.strict, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let target_proto = if let Some(path_str) = &args.proto {
        let path: StableId = match path_str.parse() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}: Invalid prototype selector '{path_str}': {e}", "error".red());
                ExitCode::UsageError.exit();
            }
        };
        find_proto(&chunk.main_proto, &path).unwrap_or(&chunk.main_proto)
    } else {
        &chunk.main_proto
    };

    match args.format {
        OutputFormat::Text => {
            render::render_disasm(&chunk.dialect, target_proto, args.raw, args.debug_info, args.effects);
        }

        OutputFormat::Json => render::print_json(target_proto),
        OutputFormat::Jsonl => render::print_jsonl(&target_proto.instructions),
        OutputFormat::Dot => {
            eprintln!("{}: Use 'luad cfg --format dot' for graphviz output", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}

fn find_proto<'a>(proto: &'a luad_core::model::Prototype, target_id: &StableId) -> Option<&'a luad_core::model::Prototype> {
    if &proto.id == target_id {
        return Some(proto);
    }
    for child in &proto.protos {
        if let Some(found) = find_proto(child, target_id) {
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

    let chunk = match parse_chunk(&bytes, args.strict, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let (verdict, diagnostics) = match chunk.dialect.as_str() {
        "lua5.4" => validate_chunk_lua54(&chunk),
        _ => (chunk.verdict, chunk.diagnostics.clone()),
    };


    let is_strict_invalid = args.strict
        && (verdict == Verdict::Invalid
            || diagnostics.iter().any(|d| d.severity == Severity::Error));

    match args.format {
        OutputFormat::Text => render::render_validate(verdict, &diagnostics),
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct ValidateOutput {
                verdict: Verdict,
                diagnostics: Vec<Diagnostic>,
            }
            render::print_json(&ValidateOutput {
                verdict,
                diagnostics,
            });
        }
        _ => {
            eprintln!("{}: Format not supported for validate", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    if is_strict_invalid {
        ExitCode::InvalidInput.exit();
    } else {
        ExitCode::Success.exit();
    }
}


fn handle_capabilities(args: CapabilitiesArgs) {
    match args.format {
        OutputFormat::Text => render::render_capabilities(args.evidence),
        OutputFormat::Json => {
            #[derive(serde::Serialize)]
            struct CapabilityManifest {
                tool_name: String,
                tool_version: String,
                schema_version: u32,
                supported_dialects: Vec<String>,
                evidence: Vec<String>,
            }
            let manifest = CapabilityManifest {
                tool_name: "luad".to_string(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                schema_version: 1,
                supported_dialects: vec!["lua5.4".to_string()],
                evidence: if args.evidence {
                    vec![
                        "83/83 Lua 5.4 opcodes supported".to_string(),
                        "Exact integer and IEEE-754 bit preservation".to_string(),
                        "Tested against Lua 5.4.8 compiler oracle".to_string(),
                    ]
                } else {
                    vec![]
                },
            };
            render::print_json(&manifest);
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
            let schema = schema_for!(Chunk);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap_or_default());
        }
        "diagnostic" => {
            let schema = schema_for!(Diagnostic);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap_or_default());
        }
        "instruction" => {
            let schema = schema_for!(luad_core::SemanticInstruction);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap_or_default());
        }
        "cfg" => {
            let schema = schema_for!(luad_analysis::ControlFlowGraph);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap_or_default());
        }
        "xrefs" => {
            let schema = schema_for!(luad_analysis::XrefEntry);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap_or_default());
        }
        "query" => {
            let schema = schema_for!(luad_analysis::QueryResponse);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap_or_default());
        }
        "diff" => {
            let schema = schema_for!(luad_analysis::ChunkDiff);
            println!("{}", serde_json::to_string_pretty(&schema).unwrap_or_default());
        }
        other => {
            eprintln!(
                "{}: Unknown schema '{other}'. Supported: chunk, diagnostic, instruction, cfg, xrefs, query, diff",
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

    let chunk = match parse_chunk(&bytes, false, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let target_id: StableId = match args.target.parse() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{}: Invalid target StableId '{}': {e}", "error".red(), args.target);
            ExitCode::UsageError.exit();
        }
    };

    match target_id {
        StableId::Instruction { proto, pc } => {
            let proto_id = StableId::Proto(proto);
            let Some(target_proto) = find_proto(&chunk.main_proto, &proto_id) else {
                eprintln!("{}: Prototype '{}' not found in chunk", "error".red(), proto_id);
                ExitCode::UsageError.exit();
            };

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
                OutputFormat::Text => render::render_explain_instruction(sem_inst),
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

    let chunk = match parse_chunk(&bytes, false, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let target_id: StableId = match args.proto.parse() {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{}: Invalid prototype selector '{}': {e}", "error".red(), args.proto);
            ExitCode::UsageError.exit();
        }
    };

    let Some(target_proto) = find_proto(&chunk.main_proto, &target_id) else {
        eprintln!("{}: Prototype '{}' not found in chunk", "error".red(), target_id);
        ExitCode::UsageError.exit();
    };

    let lifted = luad_analysis::lift_proto_for_dialect(&chunk.dialect, target_proto);
    let cfg = luad_analysis::ControlFlowGraph::build(target_proto, &lifted);

    match args.format {
        OutputFormat::Text => render::render_cfg(&cfg),
        OutputFormat::Json => render::print_json(&cfg),
        OutputFormat::Jsonl => render::print_jsonl(&cfg.blocks),
        OutputFormat::Dot => print!("{}", cfg.to_dot()),
    }

    ExitCode::Success.exit();
}

fn handle_xrefs(args: XrefsArgs) {
    let bytes = match read_input_bytes(&args.file) {
        Ok(b) => b,
        Err(code) => code.exit(),
    };

    let chunk = match parse_chunk(&bytes, false, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let index = luad_analysis::XrefIndex::build(&chunk);

    let matching_refs: Vec<&luad_analysis::XrefEntry> = if let Some(to_str) = &args.to {
        let to_id: StableId = match to_str.parse() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("{}: Invalid target ID '{to_str}': {e}", "error".red());
                ExitCode::UsageError.exit();
            }
        };
        index.query_to(&to_id)
    } else if let Some(from_str) = &args.from {
        let from_id: StableId = match from_str.parse() {
            Ok(id) => id,
            Err(e) => {
                eprintln!("{}: Invalid source ID '{from_str}': {e}", "error".red());
                ExitCode::UsageError.exit();
            }
        };
        index.query_from(&from_id)
    } else {
        index.entries.iter().collect()
    };

    match args.format {
        OutputFormat::Text => render::render_xrefs(&matching_refs),
        OutputFormat::Json => render::print_json(&matching_refs),
        OutputFormat::Jsonl => render::print_jsonl(&matching_refs),
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

    let chunk = match parse_chunk(&bytes, false, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let response = luad_analysis::execute_query(
        &chunk,
        args.r#where.as_deref(),
        args.limit,
        args.cursor.as_deref(),
    );

    match args.format {
        OutputFormat::Text => render::render_query(&response),
        OutputFormat::Json => render::print_json(&response),
        OutputFormat::Jsonl => render::print_jsonl(&response.matches),
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

    let old_chunk = match parse_chunk(&old_bytes, false, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };
    let new_chunk = match parse_chunk(&new_bytes, false, None) {
        Ok(c) => c,
        Err(code) => code.exit(),
    };

    let ignore_debug = args.ignore.as_deref() == Some("debug");
    let diff = luad_analysis::diff_chunks(&old_chunk, &new_chunk, args.semantic, ignore_debug);

    match args.format {
        OutputFormat::Text => render::render_diff(&diff),
        OutputFormat::Json => render::print_json(&diff),
        OutputFormat::Jsonl => render::print_jsonl(&[diff]),
        OutputFormat::Dot => {
            eprintln!("{}: DOT format not applicable to diff", "error".red());
            ExitCode::UsageError.exit();
        }
    }

    ExitCode::Success.exit();
}


