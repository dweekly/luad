//! CLI argument parser definition using Clap.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Format for CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Jsonl,
    Dot,
}

/// Root command-line options for `luad`.
#[derive(Parser, Debug)]
#[command(
    name = "luad",
    about = "Explainable Lua bytecode laboratory for inspection, validation, and analysis",
    version,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Identify and summarize a compiled Lua chunk.
    Inspect(InspectArgs),

    /// Produce a faithful disassembly and metadata listing.
    Disasm(DisasmArgs),

    /// Validate chunk structure and VM invariants.
    Validate(ValidateArgs),

    /// List or export control-flow graphs.
    Cfg(CfgArgs),

    /// Resolve symbolic labels for every call instruction.
    Callees(CalleesArgs),

    /// Trace bounded value-expression origins for call arguments.
    Origins(OriginsArgs),

    /// Query cross-references to and from an artifact.
    Xrefs(XrefsArgs),

    /// Explain a field, prototype, instruction, or diagnostic.
    Explain(ExplainArgs),

    /// Run a bounded structured query over the bytecode.
    Query(QueryArgs),

    /// Compare two chunks structurally and semantically.
    Diff(DiffArgs),

    /// Deterministic batch export of firmware artifacts in streaming JSONL format.
    Export(ExportArgs),

    /// Compile trusted Lua source with an explicit external compiler.
    Compile(CompileArgs),

    /// Describe commands, dialects, features, limits, and schemas.
    Capabilities(CapabilitiesArgs),

    /// Browse or query the public diagnostic code catalog.
    Diagnostics(DiagnosticsArgs),

    /// Print a selected JSON Schema.
    Schema(SchemaArgs),

    /// Generate shell completions.
    Completions(CompletionsArgs),
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Path to compiled Lua bytecode file (or '-' for standard input).
    pub file: String,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Emit a compact bounded summary.
    #[arg(short, long)]
    pub summary: bool,

    /// Explicit dialect override (e.g. 'lua5.1', 'lua5.1-lnum32', 'lua5.4', 'lua5.5').
    #[arg(short, long)]
    pub dialect: Option<String>,

    /// Fail immediately at the first invalid byte or invariant violation.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub struct DisasmArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Filter output to a specific prototype path (e.g. 'proto:0/2').
    #[arg(short, long)]
    pub proto: Option<String>,

    /// Explicit dialect override (e.g. 'lua5.1', 'lua5.1-lnum32', 'lua5.4').
    #[arg(short, long)]
    pub dialect: Option<String>,

    /// Include raw instruction words in hex.
    #[arg(long)]
    pub raw: bool,

    /// Include debug lines, locals, and upvalue names.
    #[arg(long)]
    pub debug_info: bool,

    /// Include register use/def effects.
    #[arg(long)]
    pub effects: bool,

    /// Fail immediately on invalid instructions or structure.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub struct ValidateArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Explicit dialect override (e.g. 'lua5.1', 'lua5.1-lnum32', 'lua5.4').
    #[arg(short, long)]
    pub dialect: Option<String>,

    /// Strict mode: exit with code 1 on any warning or structural flaw.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub struct CfgArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Output format (text, json, or dot).
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Target prototype path (e.g. 'proto:0').
    #[arg(short, long, default_value = "proto:0")]
    pub proto: String,

    /// Explicit dialect override.
    #[arg(short, long)]
    pub dialect: Option<String>,
}

#[derive(Args, Debug)]
pub struct CalleesArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Output format (text, json, or jsonl).
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Explicit Lua 5.1 dialect/profile override.
    #[arg(short, long)]
    pub dialect: Option<String>,
}

#[derive(Args, Debug)]
pub struct OriginsArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Output format (text, json, or jsonl).
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Explicit Lua 5.1 dialect/profile override.
    #[arg(short, long)]
    pub dialect: Option<String>,
}

#[derive(Args, Debug)]
pub struct XrefsArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Target stable ID to find references to (e.g. 'proto:0:k:3').
    #[arg(long)]
    pub to: Option<String>,

    /// Source stable ID to find references from.
    #[arg(long)]
    pub from: Option<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Explicit dialect override.
    #[arg(short, long)]
    pub dialect: Option<String>,
}

#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Target stable ID (e.g. 'proto:0:pc:12').
    pub target: String,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Explicit dialect override.
    #[arg(short, long)]
    pub dialect: Option<String>,
}

#[derive(Args, Debug)]
pub struct QueryArgs {
    /// Path to compiled Lua bytecode file.
    pub file: String,

    /// Filter predicate expression (e.g. 'effect.write.upvalue == 2').
    #[arg(long, rename_all = "kebab-case")]
    pub r#where: Option<String>,

    /// Maximum number of results to return.
    #[arg(long, default_value_t = 100)]
    pub limit: usize,

    /// Continuation cursor from a previous query response.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,

    /// Explicit dialect override.
    #[arg(short, long)]
    pub dialect: Option<String>,
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// Path to first (old) Lua bytecode file.
    pub old_file: String,

    /// Path to second (new) Lua bytecode file.
    pub new_file: String,

    /// Perform normalized semantic instruction comparison.
    #[arg(long)]
    pub semantic: bool,

    /// Ignore specific aspects during comparison (e.g. 'debug').
    #[arg(long)]
    pub ignore: Option<String>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Input bytecode files to batch export.
    pub files: Vec<String>,

    /// Path to file containing list of input files (or '-' for standard input).
    #[arg(long)]
    pub input_list: Option<String>,

    /// Output format (jsonl is canonical).
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Jsonl)]
    pub format: OutputFormat,

    /// Maximum number of counted facts (prototype, instruction, constant, upvalue, xref) to emit per input file.
    #[arg(long)]
    pub max_facts_per_file: Option<usize>,

    /// Explicit dialect override.
    #[arg(short, long)]
    pub dialect: Option<String>,

    /// Strict fail-fast parsing mode.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Args, Debug)]
pub struct CompileArgs {
    /// Trusted source file to compile.
    pub source_file: String,

    /// Explicit path to external compiler binary (e.g. '/opt/homebrew/opt/lua@5.4/bin/luac').
    #[arg(long)]
    pub compiler: String,

    /// Compiler arguments.
    #[arg(long, allow_hyphen_values = true)]
    pub args: Option<String>,
}

#[derive(Args, Debug)]
pub struct CapabilitiesArgs {
    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Include full proof and evidence manifest.
    #[arg(long)]
    pub evidence: bool,
}

#[derive(Args, Debug)]
pub struct DiagnosticsArgs {
    /// Optional diagnostic code to lookup (e.g. 'L51-REG-SPAN-001').
    pub code: Option<String>,

    /// Output format (text or json).
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,
}

#[derive(Args, Debug)]
#[command(disable_version_flag = true)]
pub struct SchemaArgs {
    /// Schema name (e.g. 'chunk', 'disasm', 'validate', 'callees', 'origins', 'xrefs', 'query', 'cfg', 'diff', 'capabilities', 'export').
    #[arg(default_value = "chunk")]
    pub name: String,

    /// Schema major version.
    #[arg(long = "schema-version", short = 's')]
    pub schema_version: Option<u32>,
}

#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Target shell to generate completions for.
    pub shell: clap_complete::Shell,
}
