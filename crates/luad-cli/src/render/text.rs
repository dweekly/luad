//! Human-readable text formatters.

use colored::Colorize;
use luad_core::diagnostic::{Diagnostic, Severity, Verdict};
use luad_core::model::{Chunk, ConstantValue, Prototype};
use luad_dialect_lua54::{OpMode54, RawInstruction54};

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
            let val_str = match &c.value {
                ConstantValue::Nil => "nil".to_string(),
                ConstantValue::Boolean(b) => b.to_string(),
                ConstantValue::Integer { val, .. } => val.to_string(),
                ConstantValue::Float { val, .. } => format!("{val:?}"),
                ConstantValue::ShortString(s) | ConstantValue::LongString(s) => {
                    format!("\"{}\"", s.display)
                }
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
        let (op_name, operands_str) = match dialect {
            "lua5.5" => {
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
                (name, ops)
            }
            "lua5.3" => {
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
                (name, ops)
            }
            "lua5.2" => {
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
                (name, ops)
            }
            "lua5.1" => {
                let raw_info = luad_dialect_lua51::RawInstruction51::decode(inst.raw_word);
                let name = raw_info.opcode.map(|op| op.name()).unwrap_or("UNKNOWN_OP");
                let ops = if let Some(op) = raw_info.opcode {
                    match op.mode() {
                        luad_dialect_lua51::OpMode51::IABC => {
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
                        luad_dialect_lua51::OpMode51::IABx => {
                            format!("{} {}", raw_info.a, raw_info.bx)
                        }
                        luad_dialect_lua51::OpMode51::IAsBx => {
                            format!("{} {}", raw_info.a, raw_info.sbx)
                        }
                    }
                } else {
                    format!("(raw=0x{:08x})", inst.raw_word)
                };
                (name, ops)
            }
            _ => {
                let raw_info = RawInstruction54::decode(inst.raw_word);
                let name = raw_info.opcode.map(|op| op.name()).unwrap_or("UNKNOWN_OP");
                let ops = if let Some(op) = raw_info.opcode {
                    match op.mode() {
                        OpMode54::IABC => {
                            if raw_info.k != 0 {
                                format!(
                                    "{} {} {} (k={})",
                                    raw_info.a, raw_info.b, raw_info.c, raw_info.k
                                )
                            } else {
                                format!("{} {} {}", raw_info.a, raw_info.b, raw_info.c)
                            }
                        }
                        OpMode54::IABx => format!("{} {}", raw_info.a, raw_info.bx),
                        OpMode54::IAsBx => format!("{} {}", raw_info.a, raw_info.sbx),
                        OpMode54::IAx => format!("{}", raw_info.ax),
                        OpMode54::IsJ => format!("{}", raw_info.sj),
                    }
                } else {
                    format!("(raw=0x{:08x})", inst.raw_word)
                };
                (name, ops)
            }
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
    println!("{}", "Supported Dialects:".bold());
    for d in &manifest.dialects {
        let features_str = d.features.join(", ");
        if d.status == "supported" {
            println!(
                "  - {:<12} {} ({})",
                d.id.green().bold(),
                d.display_name,
                features_str
            );
        } else {
            println!(
                "  - {:<12} {} ({})",
                d.id.dimmed(),
                d.display_name,
                features_str
            );
        }
    }

    if evidence {
        println!();
        println!("{}", "=== Proof & Evidence Manifest ===".bold());
        for ev in &manifest.evidence {
            println!("  - {ev}");
        }
    }
}

/// Render instruction explanation with provenance and source citations.
pub fn render_explain_instruction(inst: &luad_core::SemanticInstruction) {
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
