//! Human-readable text formatters.

use colored::Colorize;
use luad_core::diagnostic::{Diagnostic, Severity, Verdict};
use luad_core::model::{Chunk, Prototype};
use luad_core::scalar::{
    render_byte_string, render_constant, render_constant_full, render_float, render_integer,
};

/// Render human-readable inspection summary or detailed chunk overview.
pub fn render_inspect(chunk: &Chunk, summary: bool) {
    println!("{}", "=== Chunk Overview ===".bold());
    println!("{:<18} {}", "SHA-256:".dimmed(), chunk.sha256);
    println!(
        "{:<18} {} bytes",
        "Byte Length:".dimmed(),
        chunk.byte_length
    );
    println!(
        "{:<18} {}",
        "Dialect:".dimmed(),
        chunk.dialect.green().bold()
    );
    if let Some(interp) = &chunk.interpretation {
        println!("{:<18} {}", "Profile:".dimmed(), interp.profile);
        println!(
            "{:<18} {:?}",
            "Selection Mode:".dimmed(),
            interp.selection_mode
        );
        if let Some(layout) = &interp.validated_layout {
            println!("{:<18} {}", "Layout:".dimmed(), layout);
        }
    }
    println!("{:<18} {:?}", "Verdict:".dimmed(), chunk.verdict);

    if let Some(trailing) = &chunk.trailing_bytes {
        println!(
            "{:<18} {} hex bytes",
            "Trailing Bytes:".yellow(),
            trailing.len() / 2
        );
    }

    if summary {
        println!();
        println!("{}", "=== Summary Metrics ===".bold());
        println!("{:<18} {}", "Main Proto ID:".dimmed(), chunk.main_proto.id);
        println!(
            "{:<18} {}",
            "Instructions:".dimmed(),
            chunk.main_proto.instructions.len()
        );
        println!(
            "{:<18} {}",
            "Constants:".dimmed(),
            chunk.main_proto.constants.len()
        );
        println!(
            "{:<18} {}",
            "Upvalues:".dimmed(),
            chunk.main_proto.upvalues.len()
        );
        println!(
            "{:<18} {}",
            "Child Protos:".dimmed(),
            chunk.main_proto.protos.len()
        );
        println!(
            "{:<18} {}",
            "Diagnostics:".dimmed(),
            chunk.diagnostics.len()
        );
        return;
    }

    println!();
    println!("{}", "=== Header ===".bold());
    println!("{:<18} {}", "Signature:".dimmed(), chunk.header.signature);
    println!("{:<18} 0x{:02x}", "Version:".dimmed(), chunk.header.version);
    println!("{:<18} {}", "Format:".dimmed(), chunk.header.format);
    println!("{:<18} {}", "LUAC_DATA:".dimmed(), chunk.header.luac_data);
    println!(
        "{:<18} {}",
        "Instruction Size:".dimmed(),
        chunk.header.instruction_size
    );
    println!(
        "{:<18} {}",
        "Integer Size:".dimmed(),
        chunk.header.lua_integer_size
    );
    println!(
        "{:<18} {}",
        "Number Size:".dimmed(),
        chunk.header.lua_number_size
    );
    println!("{:<18} 0x{:x}", "LUAC_INT:".dimmed(), chunk.header.luac_int);
    println!("{:<18} {}", "LUAC_NUM:".dimmed(), chunk.header.luac_num);

    println!();
    render_proto_tree(&chunk.main_proto, 0);
}

fn render_proto_tree(proto: &Prototype, indent: usize) {
    let pad = "  ".repeat(indent);
    let src_desc = proto
        .source_name
        .as_ref()
        .map(|s| s.display.clone())
        .unwrap_or_else(|| "<stripped>".to_string());

    println!(
        "{}{} {} (lines {}-{}, {} instructions, {} constants, {} upvalues, {} child protos)",
        pad,
        "Prototype".cyan().bold(),
        proto.id.to_string().bold(),
        proto.line_defined,
        proto.last_line_defined,
        proto.instructions.len(),
        proto.constants.len(),
        proto.upvalues.len(),
        proto.protos.len()
    );
    println!("{}  source: {}", pad, src_desc.dimmed());
    println!(
        "{}  params: {}, vararg: {}, maxstacksize: {}",
        pad, proto.numparams, proto.is_vararg, proto.maxstacksize
    );

    for child in &proto.protos {
        render_proto_tree(child, indent + 1);
    }
}

/// Render faithful disassembly of a prototype.
pub fn render_disasm(dialect: &str, proto: &Prototype, raw: bool, debug_info: bool, effects: bool) {
    let src_desc = proto
        .source_name
        .as_ref()
        .map(|s| s.display.as_str())
        .unwrap_or("<stripped>");

    println!("; ==========================================================================");
    println!(
        "; {} (source: {}, lines {}-{}, stack: {})",
        proto.id.to_string().bold(),
        src_desc,
        proto.line_defined,
        proto.last_line_defined,
        proto.maxstacksize
    );
    println!(
        "; params: {}, is_vararg: {}, instructions: {}, constants: {}",
        proto.numparams,
        proto.is_vararg,
        proto.instructions.len(),
        proto.constants.len()
    );
    println!("; ==========================================================================");

    if !proto.constants.is_empty() {
        println!("; Constants:");
        for c in &proto.constants {
            // `--raw` widens this listing to the untruncated constant. Operand
            // previews inside the instruction stream stay bounded so a long
            // constant cannot push the disassembly off screen.
            let val_str = if raw {
                render_constant_full(&c.value)
            } else {
                render_constant(&c.value)
            };
            println!(";   k[{}] = {}", c.index, val_str);
        }
    }

    if !proto.upvalues.is_empty() {
        println!("; Upvalues:");
        for u in &proto.upvalues {
            let name_str = u.name.as_ref().map(|n| n.display.as_str()).unwrap_or("-");
            println!(
                ";   upvalue[{}] = {} (instack={}, idx={}, kind={})",
                u.index, name_str, u.instack, u.idx, u.kind
            );
        }
    }

    if debug_info && !proto.loc_vars.is_empty() {
        println!("; Locals:");
        for l in &proto.loc_vars {
            println!(
                ";   local[{}] = \"{}\" (pc {}..{})",
                l.index, l.name.display, l.startpc, l.endpc
            );
        }
    }

    println!();
    for inst in &proto.instructions {
        let (op_name, operands_str) = if dialect.starts_with("lua5.1") {
            let d_proto = luad_dialect_lua51::disassemble_proto_lua51(proto);
            let d_inst = &d_proto.instructions[inst.pc];
            if d_inst.role == "closure_binding" {
                let binding_text = d_inst.comment.as_deref().unwrap_or("closure_binding");
                ("|->".to_string(), binding_text.to_string())
            } else {
                let ops_str = d_inst
                    .operands
                    .iter()
                    .map(|o| o.display.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let comment_suffix = if let Some(c) = &d_inst.comment {
                    format!(" ; {c}")
                } else {
                    String::new()
                };
                (
                    d_inst.mnemonic.clone(),
                    format!("{ops_str}{comment_suffix}"),
                )
            }
        } else if dialect.starts_with("lua5.5") {
            let raw_info = luad_dialect_lua55::RawInstruction55::decode(inst.raw_word);
            let name = raw_info.opcode.map(|op| op.name()).unwrap_or("UNKNOWN_OP");
            let ops = if let Some(op) = raw_info.opcode {
                match op.mode() {
                    luad_dialect_lua55::OpMode55::IABC => {
                        if raw_info.k != 0 {
                            format!(
                                "{} {} {} (k={})",
                                raw_info.a, raw_info.b, raw_info.c, raw_info.k
                            )
                        } else {
                            format!("{} {} {}", raw_info.a, raw_info.b, raw_info.c)
                        }
                    }
                    luad_dialect_lua55::OpMode55::IvABC => {
                        format!(
                            "{} {} {} (k={})",
                            raw_info.a, raw_info.vb, raw_info.vc, raw_info.k
                        )
                    }
                    luad_dialect_lua55::OpMode55::IABx => {
                        format!("{} {}", raw_info.a, raw_info.bx)
                    }
                    luad_dialect_lua55::OpMode55::IAsBx => {
                        format!("{} {}", raw_info.a, raw_info.sbx)
                    }
                    luad_dialect_lua55::OpMode55::IAx => format!("{}", raw_info.ax),
                    luad_dialect_lua55::OpMode55::IsJ => format!("{}", raw_info.sj),
                }
            } else {
                format!("(raw=0x{:08x})", inst.raw_word)
            };
            (name.to_string(), ops)
        } else if dialect.starts_with("lua5.3") {
            let raw_info = luad_dialect_lua53::RawInstruction53::decode(inst.raw_word);
            let name = raw_info.opcode.map(|op| op.name()).unwrap_or("UNKNOWN_OP");
            let ops = if let Some(op) = raw_info.opcode {
                match op.mode() {
                    luad_dialect_lua53::OpMode53::IABC => {
                        let b_str = if raw_info.is_b_k() {
                            format!("k({})", raw_info.b_index_k())
                        } else {
                            raw_info.b.to_string()
                        };
                        let c_str = if raw_info.is_c_k() {
                            format!("k({})", raw_info.c_index_k())
                        } else {
                            raw_info.c.to_string()
                        };
                        format!("{} {} {}", raw_info.a, b_str, c_str)
                    }
                    luad_dialect_lua53::OpMode53::IABx => {
                        format!("{} {}", raw_info.a, raw_info.bx)
                    }
                    luad_dialect_lua53::OpMode53::IAsBx => {
                        format!("{} {}", raw_info.a, raw_info.sbx)
                    }
                    luad_dialect_lua53::OpMode53::IAx => format!("{}", raw_info.ax),
                }
            } else {
                format!("(raw=0x{:08x})", inst.raw_word)
            };
            (name.to_string(), ops)
        } else if dialect.starts_with("lua5.2") {
            let raw_info = luad_dialect_lua52::RawInstruction52::decode(inst.raw_word);
            let name = raw_info.opcode.map(|op| op.name()).unwrap_or("UNKNOWN_OP");
            let ops = if let Some(op) = raw_info.opcode {
                match op.mode() {
                    luad_dialect_lua52::OpMode52::IABC => {
                        let b_str = if raw_info.is_b_k() {
                            format!("k({})", raw_info.b_index_k())
                        } else {
                            raw_info.b.to_string()
                        };
                        let c_str = if raw_info.is_c_k() {
                            format!("k({})", raw_info.c_index_k())
                        } else {
                            raw_info.c.to_string()
                        };
                        format!("{} {} {}", raw_info.a, b_str, c_str)
                    }
                    luad_dialect_lua52::OpMode52::IABx => {
                        format!("{} {}", raw_info.a, raw_info.bx)
                    }
                    luad_dialect_lua52::OpMode52::IAsBx => {
                        format!("{} {}", raw_info.a, raw_info.sbx)
                    }
                    luad_dialect_lua52::OpMode52::IAx => format!("{}", raw_info.ax),
                }
            } else {
                format!("(raw=0x{:08x})", inst.raw_word)
            };
            (name.to_string(), ops)
        } else {
            let d_inst =
                luad_dialect_lua54::disassemble_instruction_lua54(proto, inst.pc, inst.raw_word);
            let name = d_inst.mnemonic;
            let ops_str = d_inst
                .operands
                .iter()
                .map(|o| o.display.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let comment_suffix = if let Some(c) = d_inst.comment {
                format!(" ; {c}")
            } else {
                String::new()
            };
            (name, format!("{ops_str}{comment_suffix}"))
        };

        let raw_col = if raw {
            format!("[0x{:08x}]  ", inst.raw_word)
        } else {
            String::new()
        };

        if effects {
            let lifted = luad_analysis::lift_proto_for_dialect(dialect, proto);
            if let Some(sem) = lifted.get(inst.pc) {
                let reads_str: Vec<String> = sem.reads.iter().map(|r| format!("{r:?}")).collect();
                let writes_str: Vec<String> = sem.writes.iter().map(|w| format!("{w:?}")).collect();
                let effects_col = format!(
                    " ; reads: [{}], writes: [{}]",
                    reads_str.join(", "),
                    writes_str.join(", ")
                );
                println!(
                    "{:>4}  {}{:<12} {}{}",
                    inst.pc,
                    raw_col.dimmed(),
                    op_name.bold(),
                    operands_str,
                    effects_col.dimmed()
                );
                continue;
            }
        }

        println!(
            "{:>4}  {}{:<12} {}",
            inst.pc,
            raw_col.dimmed(),
            op_name.bold(),
            operands_str
        );
    }

    for child in &proto.protos {
        println!();
        render_disasm(dialect, child, raw, debug_info, effects);
    }
}

/// Render validation report.
pub fn render_validate(verdict: Verdict, diagnostics: &[Diagnostic]) {
    println!("{}", "=== Validation Report ===".bold());
    let verdict_str = match verdict {
        Verdict::ValidForParser | Verdict::ValidForAnalysis => {
            format!("{verdict:?}").green().bold()
        }
        Verdict::Incomplete | Verdict::Ambiguous => format!("{verdict:?}").yellow().bold(),
        Verdict::Invalid => format!("{verdict:?}").red().bold(),
    };

    println!("{:<15} {}", "Verdict:".dimmed(), verdict_str);
    println!("{:<15} {}", "Diagnostics:".dimmed(), diagnostics.len());

    if diagnostics.is_empty() {
        println!("{}", "No warnings or errors detected.".green());
        return;
    }

    println!();
    for d in diagnostics {
        let sev = match d.severity {
            Severity::Info => "INFO".cyan(),
            Severity::Warning => "WARN".yellow(),
            Severity::Error => "ERROR".red().bold(),
        };

        println!("[{sev}] [{}] on {}: {}", d.code.bold(), d.target, d.message);
        if let Some(ev) = &d.evidence {
            println!("  Evidence: {ev}");
        }
        if let Some(act) = &d.suggested_action {
            println!("  Action:   {act}");
        }
    }
}

/// Render tool capabilities.
pub fn render_capabilities(manifest: &luad_core::CapabilityManifest, evidence: bool) {
    println!("{}", "=== luad Capabilities ===".bold());
    println!("{:<20} {}", "Tool Name:".dimmed(), manifest.tool_name);
    println!("{:<20} {}", "Tool Version:".dimmed(), manifest.tool_version);
    println!(
        "{:<20} {}",
        "Schema Version:".dimmed(),
        manifest.schema_version
    );
    println!();
    println!("{}", "Diagnostic Catalog:".bold());
    println!(
        "  {} (schema: {}, formats: {})",
        manifest.diagnostic_catalog.command,
        manifest.diagnostic_catalog.schema,
        manifest.diagnostic_catalog.formats.join(", ")
    );
    println!();
    println!("{}", "Dialect Matrix:".bold());
    for d in &manifest.dialects {
        let features_str = d.features.join(", ");
        let status_str = match d.status {
            luad_core::SupportTier::Supported => "[supported]".green().bold(),
            luad_core::SupportTier::Experimental => "[experimental]".yellow().bold(),
            luad_core::SupportTier::Planned => "[planned]".dimmed(),
        };
        println!(
            "  - {:<10} {:<15} {:<24} ({})",
            d.id.bold(),
            status_str,
            d.display_name,
            features_str
        );
    }

    if evidence {
        println!();
        println!("{}", "=== Proof & Evidence Manifest ===".bold());
        for ev in &manifest.evidence {
            println!("  - {ev}");
        }
    }
}

/// Render one line per call with an explicit resolution or unresolved reason.
///
/// The caller restricts symbolic callee analysis to Lua 5.1 profiles, so this
/// renderer never sees another dialect's constants.
pub fn render_callees(analysis: &luad_analysis::ChunkCalleeAnalysis) {
    for prototype in &analysis.prototypes {
        for fact in &prototype.calls {
            let resolution = match &fact.resolution {
                luad_analysis::CalleeResolution::LookupLabel {
                    lookup_kind,
                    key,
                    evidence,
                } => {
                    let kind_str = match lookup_kind {
                        luad_analysis::CalleeLookupKind::Gettable => "gettable",
                        luad_analysis::CalleeLookupKind::SelfOp => "self",
                    };
                    let key_str = render_constant(key);
                    format!(
                        "lookup:{kind_str}:{key_str} [{}]",
                        evidence
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
                luad_analysis::CalleeResolution::ResolvedPath {
                    basis,
                    segments,
                    evidence,
                } => format!(
                    "{:?}:{} [{}]",
                    basis,
                    segments.join("."),
                    evidence
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                luad_analysis::CalleeResolution::ResolvedPrototype {
                    prototype,
                    evidence,
                } => format!(
                    "proto:{prototype} [{}]",
                    evidence
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                luad_analysis::CalleeResolution::Unresolved { reason } => {
                    format!("unresolved:{reason:?}")
                }
            };
            println!(
                "{} {:<8} R({}) {}",
                fact.call_id, fact.call_kind, fact.callee_register, resolution
            );
        }
    }
}

/// Render one line per physical call with an exact relation or stop reason.
pub fn render_callgraph(analysis: &luad_analysis::ChunkCallRelationAnalysis) {
    for prototype in &analysis.prototypes {
        for fact in &prototype.calls {
            let resolution = match &fact.resolution {
                luad_analysis::CallRelationResolution::Resolved {
                    callee,
                    basis,
                    evidence,
                } => format!(
                    "proto:{callee} basis:{basis:?} [{}]",
                    evidence
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                luad_analysis::CallRelationResolution::Unresolved { reason, evidence } => {
                    format!(
                        "unresolved:{reason:?} [{}]",
                        evidence
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            };
            println!("{} {:<8} {}", fact.call_id, fact.call_kind, resolution);
        }
    }
}

/// Render bounded call-argument origin expressions.
pub fn render_origins(analysis: &luad_analysis::ChunkOriginAnalysis) {
    for prototype in &analysis.prototypes {
        for fact in &prototype.calls {
            println!(
                "{} {:<8} R({})",
                fact.call_id, fact.call_kind, fact.callee_register
            );
            match &fact.argument_window {
                luad_analysis::CallArgumentWindow::Fixed { arguments } => {
                    for argument in arguments {
                        println!(
                            "  arg[{}] R({}) <- {}",
                            argument.argument_index,
                            argument.register,
                            format_origin_expression(&argument.origin)
                        );
                    }
                }
                luad_analysis::CallArgumentWindow::Open { reason } => {
                    println!("  arguments <- open:{reason:?}");
                }
            }
        }
    }
}

/// Decode a preserved little-endian binary64 constant back to its value.
fn float_from_raw_hex(raw_hex: &str) -> Option<f64> {
    let bytes = hex::decode(raw_hex).ok()?;
    let bytes: [u8; 8] = bytes.try_into().ok()?;
    Some(f64::from_bits(u64::from_le_bytes(bytes)))
}

fn format_origin_expression(expression: &luad_analysis::OriginExpression) -> String {
    use luad_analysis::{OriginExpressionKind, OriginLiteral};

    fn literal(value: &OriginLiteral) -> String {
        match value {
            OriginLiteral::Nil => "nil".to_string(),
            OriginLiteral::Boolean { value } => value.to_string(),
            OriginLiteral::Integer { value, .. } => render_integer(*value),
            // `OriginLiteral::Float` stores only the preserved bytes because the
            // enum derives `Eq`. Decode them back to binary64 so the scalar
            // authority owns this spelling too; a byte width other than eight is
            // not a float this renderer can speak for, so it shows the bytes.
            OriginLiteral::Float { raw_hex, .. } => match float_from_raw_hex(raw_hex) {
                Some(value) => render_float(value),
                None => format!("float({raw_hex})"),
            },
            OriginLiteral::String { value } => render_byte_string(&value.raw_bytes),
        }
    }

    match &expression.kind {
        OriginExpressionKind::Literal { value, .. } => literal(value),
        OriginExpressionKind::Parameter { owner, index } => {
            format!("proto:{owner}:parameter[{index}]")
        }
        OriginExpressionKind::Upvalue { owner, index, .. } => {
            format!("proto:{owner}:upvalue:{index}")
        }
        OriginExpressionKind::Global { name } => format!("global({})", name.display),
        OriginExpressionKind::Field { base, key, .. } => {
            format!(
                "field({}, {})",
                format_origin_expression(base),
                literal(key)
            )
        }
        OriginExpressionKind::CallResult {
            call_id,
            result_index,
        } => format!("call-result({call_id}, {result_index})"),
        OriginExpressionKind::Concat { parts } => format!(
            "CONCAT({})",
            parts
                .iter()
                .map(format_origin_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        OriginExpressionKind::Table { entries } => format!(
            "table({})",
            entries
                .iter()
                .map(format_origin_expression)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        OriginExpressionKind::Unary { operator, operand } => {
            format!("{operator}({})", format_origin_expression(operand))
        }
        OriginExpressionKind::Binary {
            operator,
            left,
            right,
        } => format!(
            "{operator}({}, {})",
            format_origin_expression(left),
            format_origin_expression(right)
        ),
        OriginExpressionKind::Unknown { reason } => format!("unknown:{reason:?}"),
    }
}

/// Render instruction explanation with provenance, disassembly facts, and source citations.
pub fn render_explain_instruction(
    inst: &luad_core::SemanticInstruction,
    disasm_inst: Option<&luad_core::DisassembledInstruction>,
) {
    println!("{}", "=== Instruction Explanation ===".bold());
    println!(
        "{:<20} {}",
        "Target ID:".dimmed(),
        inst.id.to_string().bold()
    );
    println!("{:<20} {}", "PC:".dimmed(), inst.pc);
    println!(
        "{:<20} 0x{:08x} ({})",
        "Raw Word:".dimmed(),
        inst.raw_word,
        inst.raw_hex
    );
    println!(
        "{:<20} {}",
        "Mnemonic:".dimmed(),
        inst.mnemonic.green().bold()
    );
    println!("{:<20} {:?}", "Confidence:".dimmed(), inst.confidence);

    if let Some(d_inst) = disasm_inst {
        println!("{:<20} {}", "Role:".dimmed(), d_inst.role);
        if !d_inst.operands.is_empty() {
            let ops_desc: Vec<String> = d_inst
                .operands
                .iter()
                .map(|op| {
                    if let Some(res) = &op.resolved {
                        match res {
                            luad_core::ResolvedFact::Constant {
                                formatted_preview, ..
                            } => {
                                format!("{}={formatted_preview}", op.name)
                            }
                            luad_core::ResolvedFact::Upvalue { name, .. } => {
                                format!("{}={}", op.name, name.as_deref().unwrap_or("_ENV"))
                            }
                            luad_core::ResolvedFact::Prototype { id, .. } => {
                                format!("{}={id}", op.name)
                            }
                            _ => format!("{}={}", op.name, op.display),
                        }
                    } else {
                        format!("{}={}", op.name, op.display)
                    }
                })
                .collect();
            println!("{:<20} {}", "Operands:".dimmed(), ops_desc.join(", "));
        }
    }

    println!();
    println!("{}", "Semantic Meaning:".bold());
    println!("  {}", inst.explanation.cyan());

    if !inst.reads.is_empty() {
        println!();
        println!("{}", "Reads:".bold());
        for r in &inst.reads {
            println!("  - {:?}", r);
        }
    }

    if !inst.writes.is_empty() {
        println!();
        println!("{}", "Writes:".bold());
        for w in &inst.writes {
            println!("  - {:?}", w);
        }
    }

    if !inst.metamethod_fallbacks.is_empty() {
        println!();
        println!("{}", "Possible Metamethod Fallbacks:".bold());
        for m in &inst.metamethod_fallbacks {
            println!("  - {}", m.yellow());
        }
    }

    if let Some(target_pc) = inst.jump_target {
        println!();
        println!("{:<20} PC {}", "Branch Target:".bold(), target_pc);
    }

    if let Some(comp_pc) = inst.companion_pc {
        println!();
        println!("{:<20} PC {}", "Companion Instruction:".bold(), comp_pc);
    }

    if !inst.source_citations.is_empty() {
        println!();
        println!("{}", "Official Source Citations:".bold());
        for cite in &inst.source_citations {
            println!("  - {}", cite.dimmed());
        }
    }

    println!();
    println!(
        "{:<20} offset {}, length {} bytes",
        "Source Location:".dimmed(),
        inst.source.byte_offset,
        inst.source.byte_length
    );
}

/// Render CFG overview.
pub fn render_cfg(cfg: &luad_analysis::ControlFlowGraph) {
    println!("{}", "=== Control Flow Graph ===".bold());
    println!(
        "{:<18} {}",
        "Target Proto:".dimmed(),
        cfg.proto_id.to_string().bold()
    );
    println!("{:<18} {}", "Basic Blocks:".dimmed(), cfg.blocks.len());
    println!("{:<18} {}", "Instructions:".dimmed(), cfg.instruction_count);

    println!();
    for block in &cfg.blocks {
        let status = if !block.is_reachable {
            " (unreachable)".red().to_string()
        } else if block.is_entry {
            " (entry)".green().to_string()
        } else if block.is_exit {
            " (exit)".magenta().to_string()
        } else {
            String::new()
        };

        let idom_str = block
            .immediate_dominator
            .map(|d| format!(" (idom=b{d})"))
            .unwrap_or_default();

        println!(
            "{} {}: PCs {}..{} ({} instructions){}{}",
            "Block".bold(),
            block.index,
            block.start_pc,
            block.end_pc,
            block.instruction_pcs.len(),
            status,
            idom_str.dimmed()
        );

        if !block.predecessors.is_empty() {
            let preds: Vec<String> = block.predecessors.iter().map(|p| format!("b{p}")).collect();
            println!("  predecessors: [{}]", preds.join(", ").dimmed());
        }

        if !block.successors.is_empty() {
            let succs: Vec<String> = block
                .successors
                .iter()
                .map(|e| format!("b{} ({:?})", e.to_block, e.kind))
                .collect();
            println!("  successors:   [{}]", succs.join(", "));
        }
    }
}

/// Render cross-references table.
pub fn render_xrefs(entries: &[&luad_analysis::XrefEntry]) {
    println!("{}", "=== Cross References ===".bold());
    println!("{:<18} {}", "Total References:".dimmed(), entries.len());

    if entries.is_empty() {
        println!("{}", "No matching cross-references found.".dimmed());
        return;
    }

    println!();
    println!(
        "{:<24} {:<14} {}",
        "SOURCE".dimmed(),
        "RELATION".dimmed(),
        "TARGET".dimmed()
    );
    println!("{}", "-".repeat(70).dimmed());

    for e in entries {
        println!(
            "{:<24} {:<14} {}",
            e.source.to_string().cyan(),
            format!("{:?}", e.relation).bold(),
            e.target
        );
    }
}

/// Render query results.
pub fn render_query(response: &luad_analysis::QueryResponse) {
    println!("{}", "=== Query Results ===".bold());
    println!("{:<18} {}", "Matches:".dimmed(), response.count);
    if response.is_truncated {
        println!(
            "{:<18} yes (use --cursor to continue)",
            "Truncated:".yellow()
        );
        if let Some(cursor) = &response.next_cursor {
            println!("{:<18} {}", "Next Cursor:".dimmed(), cursor);
        }
    }

    if response.matches.is_empty() {
        println!("{}", "No matching artifacts found.".dimmed());
        return;
    }

    println!();
    for m in &response.matches {
        println!(
            "[{}] {}: {}",
            m.kind.dimmed(),
            m.id.to_string().bold(),
            m.summary
        );
    }
}

/// Render diff comparison.
pub fn render_diff(diff: &luad_analysis::ChunkDiff) {
    println!("{}", "=== Chunk Comparison ===".bold());
    println!("{:<16} {}", "Old SHA-256:".dimmed(), diff.old_sha256);
    println!("{:<16} {}", "New SHA-256:".dimmed(), diff.new_sha256);
    println!(
        "{:<16} {}",
        "Result:".dimmed(),
        if diff.is_identical {
            "Identical (0 differences)".green().bold()
        } else {
            "Differences detected".yellow().bold()
        }
    );

    if !diff.header_diffs.is_empty() {
        println!();
        println!("{}", "Header Differences:".bold());
        for h in &diff.header_diffs {
            println!("  - {h}");
        }
    }

    if !diff.proto_diffs.is_empty() {
        println!();
        println!("{}", "Prototype Differences:".bold());
        for p in &diff.proto_diffs {
            println!("  {} proto:{}", "Path:".bold(), p.path);
            for h in &p.header_diffs {
                println!("    [header] {h}");
            }
            for c in &p.constant_diffs {
                println!("    [constant] {c}");
            }
            for u in &p.upvalue_diffs {
                println!("    [upvalue] {u}");
            }
            for i in &p.instruction_diffs {
                println!(
                    "    [PC {:>3}] {} -> {}",
                    i.pc,
                    i.old.as_deref().unwrap_or("<none>").red(),
                    i.new.as_deref().unwrap_or("<none>").green()
                );
            }
        }
    }
}

/// Render a single diagnostic descriptor in standard 3-line format.
pub fn render_diagnostic_descriptor(desc: &luad_core::DiagnosticDescriptor) {
    let severity = match desc.severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
    };
    let category = match desc.category {
        luad_core::DiagnosticCategory::Parse => "parse",
        luad_core::DiagnosticCategory::Structure => "structure",
        luad_core::DiagnosticCategory::Instruction => "instruction",
        luad_core::DiagnosticCategory::ControlFlow => "control-flow",
        luad_core::DiagnosticCategory::DebugMetadata => "debug-metadata",
        luad_core::DiagnosticCategory::Analysis => "analysis",
    };
    print!(
        "{} [{}/{}]\n  Semantics: {}\n  Next action: {}\n",
        desc.code, severity, category, desc.semantics, desc.suggested_action
    );
}

/// Render a slice of diagnostic descriptors in standard 3-line format.
pub fn render_diagnostic_descriptors(descriptors: &[luad_core::DiagnosticDescriptor]) {
    for desc in descriptors {
        render_diagnostic_descriptor(desc);
    }
}
