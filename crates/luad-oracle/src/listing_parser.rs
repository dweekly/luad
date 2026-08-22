//! Parser and differential comparator for canonical `luac -l -l` compiler dumps.

use luad_core::model::{Chunk, Prototype};

/// Full structured representation of a `luac -l -l` compiler dump.
#[derive(Debug, Clone, PartialEq)]
pub struct LuacDump {
    pub functions: Vec<LuacProtoDump>,
}

/// Structured prototype representation parsed from `luac -l -l`.
#[derive(Debug, Clone, PartialEq)]
pub struct LuacProtoDump {
    pub is_main: bool,
    pub linedefined: usize,
    pub lastlinedefined: usize,
    pub numparams: usize,
    pub is_vararg: bool,
    pub maxstacksize: usize,
    pub instructions: Vec<LuacInstDump>,
    pub constants: Vec<LuacConstDump>,
    pub locals: Vec<LuacLocVarDump>,
    pub upvalues: Vec<LuacUpvalDump>,
}

/// Structured instruction representation parsed from `luac -l -l`.
#[derive(Debug, Clone, PartialEq)]
pub struct LuacInstDump {
    pub pc: usize, // 0-based PC
    pub line: usize,
    pub mnemonic: String,
    pub operands_raw: String,
    pub comment: Option<String>,
}

/// Structured constant representation parsed from `luac -l -l`.
#[derive(Debug, Clone, PartialEq)]
pub struct LuacConstDump {
    pub index: usize,
    pub raw_text: String,
}

/// Structured local variable debug info parsed from `luac -l -l`.
#[derive(Debug, Clone, PartialEq)]
pub struct LuacLocVarDump {
    pub index: usize,
    pub name: String,
    pub startpc: usize,
    pub endpc: usize,
}

/// Structured upvalue debug info parsed from `luac -l -l`.
#[derive(Debug, Clone, PartialEq)]
pub struct LuacUpvalDump {
    pub index: usize,
    pub name: String,
    pub instack: Option<u8>,
    pub idx: Option<u8>,
}

enum Section {
    Instructions,
    Constants,
    Locals,
    Upvalues,
}

/// Parse the text output of `luac -l -l` into a `LuacDump`.
#[must_use]
pub fn parse_luac_dump(output: &str) -> LuacDump {
    let mut functions = Vec::new();
    let mut current_proto: Option<LuacProtoDump> = None;
    let mut current_section = Section::Instructions;

    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Header start: "main <...:0,0> (N instructions at 0x...)" or "function <...:1,5> (...)"
        if trimmed.starts_with("main <") || trimmed.starts_with("function <") {
            if let Some(proto) = current_proto.take() {
                functions.push(proto);
            }

            let is_main = trimmed.starts_with("main <");
            let mut linedefined = 0;
            let mut lastlinedefined = 0;

            if let Some(start_bracket) = trimmed.find('<') {
                if let Some(end_bracket) = trimmed.find('>') {
                    let loc_str = &trimmed[start_bracket + 1..end_bracket];
                    if let Some(colon) = loc_str.rfind(':') {
                        let lines_part = &loc_str[colon + 1..];
                        if let Some((l1, l2)) = lines_part.split_once(',') {
                            linedefined = l1.parse().unwrap_or(0);
                            lastlinedefined = l2.parse().unwrap_or(0);
                        }
                    }
                }
            }

            current_proto = Some(LuacProtoDump {
                is_main,
                linedefined,
                lastlinedefined,
                numparams: 0,
                is_vararg: false,
                maxstacksize: 0,
                instructions: Vec::new(),
                constants: Vec::new(),
                locals: Vec::new(),
                upvalues: Vec::new(),
            });
            current_section = Section::Instructions;
            continue;
        }

        // Param / slot metadata: "0+ params, 5 slots, 1 upvalue, 2 locals, 0 constants, 1 function"
        if trimmed.contains("param") && trimmed.contains("slot") {
            if let Some(ref mut proto) = current_proto {
                let parts: Vec<&str> = trimmed.split(',').map(str::trim).collect();
                for part in parts {
                    if part.contains("param") {
                        let num_part = part.split_whitespace().next().unwrap_or("0");
                        if num_part.ends_with('+') {
                            proto.is_vararg = true;
                            proto.numparams = num_part.trim_end_matches('+').parse().unwrap_or(0);
                        } else {
                            proto.numparams = num_part.parse().unwrap_or(0);
                        }
                    } else if part.contains("slot") {
                        let num_part = part.split_whitespace().next().unwrap_or("0");
                        proto.maxstacksize = num_part.parse().unwrap_or(0);
                    }
                }
            }
            continue;
        }

        // Section Headers
        if trimmed.starts_with("constants (") {
            current_section = Section::Constants;
            continue;
        } else if trimmed.starts_with("locals (") {
            current_section = Section::Locals;
            continue;
        } else if trimmed.starts_with("upvalues (") {
            current_section = Section::Upvalues;
            continue;
        }

        let Some(ref mut proto) = current_proto else {
            continue;
        };

        match current_section {
            Section::Instructions => {
                // E.g. "	1	[1]	VARARGPREP	0"
                // or   "	2	[1]	LOADK    	0 0	; \"hello\""
                let parts: Vec<&str> = line.split('\t').filter(|s| !s.is_empty()).collect();
                if parts.len() >= 3 {
                    let pc_1based: usize = parts[0].trim().parse().unwrap_or(0);
                    let pc = if pc_1based > 0 { pc_1based - 1 } else { 0 };

                    let line_str = parts[1].trim().trim_matches('[').trim_matches(']');
                    let line_num: usize = line_str.parse().unwrap_or(0);

                    let mnem_and_ops = parts[2].trim();
                    let mut comment = None;
                    let (op_part, comment_part) = if let Some((o, c)) = mnem_and_ops.split_once(';')
                    {
                        (o.trim(), Some(c.trim().to_string()))
                    } else if parts.len() >= 4 && parts[3].trim().starts_with(';') {
                        (
                            mnem_and_ops,
                            Some(parts[3].trim().trim_start_matches(';').trim().to_string()),
                        )
                    } else {
                        (mnem_and_ops, None)
                    };
                    if comment.is_none() {
                        comment = comment_part;
                    }

                    let mut tokens = op_part.split_whitespace();
                    if let Some(mnemonic) = tokens.next() {
                        let ops_raw: Vec<&str> = tokens.collect();
                        proto.instructions.push(LuacInstDump {
                            pc,
                            line: line_num,
                            mnemonic: mnemonic.to_string(),
                            operands_raw: ops_raw.join(" "),
                            comment,
                        });
                    }
                }
            }
            Section::Constants => {
                // E.g. "	0	S	\"hello\"" (Lua 5.4/5.5) or "	1	\"hello\"" (Lua 5.1-5.3)
                let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                if !tokens.is_empty() {
                    let idx: usize = tokens[0].parse().unwrap_or(0);
                    let text = trimmed;
                    proto.constants.push(LuacConstDump {
                        index: idx,
                        raw_text: text.to_string(),
                    });
                }
            }
            Section::Locals => {
                // E.g. "\t0\t(for state)\t5\t7" (startpc and endpc are 1-based in luac.c: startpc + 1, endpc + 1)
                let parts: Vec<&str> = line.split('\t').filter(|s| !s.is_empty()).collect();
                if parts.len() >= 4 {
                    let idx: usize = parts[0].trim().parse().unwrap_or(0);
                    let name = parts[1].trim().to_string();
                    let startpc_1based: usize = parts[2].trim().parse().unwrap_or(0);
                    let endpc_1based: usize = parts[3].trim().parse().unwrap_or(0);
                    let startpc = if startpc_1based > 0 {
                        startpc_1based - 1
                    } else {
                        0
                    };
                    let endpc = if endpc_1based > 0 {
                        endpc_1based - 1
                    } else {
                        0
                    };
                    proto.locals.push(LuacLocVarDump {
                        index: idx,
                        name,
                        startpc,
                        endpc,
                    });
                }
            }

            Section::Upvalues => {
                // E.g. "\t0\t_ENV\t1\t0"
                let parts: Vec<&str> = line.split('\t').filter(|s| !s.is_empty()).collect();
                if parts.len() >= 2 {
                    let idx: usize = parts[0].trim().parse().unwrap_or(0);
                    let name = parts[1].trim().to_string();
                    let instack = parts.get(2).and_then(|s| s.trim().parse().ok());
                    let upval_idx = parts.get(3).and_then(|s| s.trim().parse().ok());
                    proto.upvalues.push(LuacUpvalDump {
                        index: idx,
                        name,
                        instack,
                        idx: upval_idx,
                    });
                }
            }
        }
    }

    if let Some(proto) = current_proto {
        functions.push(proto);
    }

    LuacDump { functions }
}

/// Structured mismatch variants emitted by the canonical differential comparator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleMismatch {
    PrototypeCount {
        actual: usize,
        expected: usize,
    },
    Metadata {
        proto: usize,
        field: String,
        actual: String,
        expected: String,
    },
    InstructionCount {
        proto: usize,
        actual: usize,
        expected: usize,
    },
    Mnemonic {
        proto: usize,
        pc: usize,
        raw_word: u32,
        actual: String,
        expected: String,
    },
    Operand {
        proto: usize,
        pc: usize,
        raw_word: u32,
        index: usize,
        actual: String,
        expected: String,
    },
    Line {
        proto: usize,
        pc: usize,
        actual: usize,
        expected: usize,
    },
    ConstantCount {
        proto: usize,
        actual: usize,
        expected: usize,
    },
    Constant {
        proto: usize,
        index: usize,
        actual: String,
        expected: String,
    },
    LocalCount {
        proto: usize,
        actual: usize,
        expected: usize,
    },
    Local {
        proto: usize,
        index: usize,
        field: String,
        actual: String,
        expected: String,
    },
    UpvalueCount {
        proto: usize,
        actual: usize,
        expected: usize,
    },
    Upvalue {
        proto: usize,
        index: usize,
        field: String,
        actual: String,
        expected: String,
    },
}

/// Recursively collect all prototypes from a root prototype in preorder.
fn flatten_protos<'a>(proto: &'a Prototype, acc: &mut Vec<&'a Prototype>) {
    acc.push(proto);
    for child in &proto.protos {
        flatten_protos(child, acc);
    }
}

/// Decode opcode mnemonic for a given dialect and instruction word.
#[must_use]
pub fn decode_instruction_mnemonic(dialect: &str, raw_word: u32) -> Option<&'static str> {
    match dialect {
        "lua5.1" => {
            let op = (raw_word & 0x3F) as u8;
            luad_dialect_lua51::Opcode51::from_u8(op).map(|o| o.name())
        }
        "lua5.2" => {
            let op = (raw_word & 0x3F) as u8;
            luad_dialect_lua52::Opcode52::from_u8(op).map(|o| o.name())
        }
        "lua5.3" => {
            let op = (raw_word & 0x3F) as u8;
            luad_dialect_lua53::Opcode53::from_u8(op).map(|o| o.name())
        }
        "lua5.4" => {
            let op = (raw_word & 0x7F) as u8;
            luad_dialect_lua54::Opcode54::from_u8(op).map(|o| o.name())
        }
        "lua5.5" => {
            let op = (raw_word & 0x7F) as u8;
            luad_dialect_lua55::Opcode55::from_u8(op).map(|o| o.name())
        }
        _ => None,
    }
}

fn format_luac_string(bytes: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            7 => out.push_str("\\a"),
            8 => out.push_str("\\b"),
            12 => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            11 => out.push_str("\\v"),
            32..=126 => out.push(b as char),
            _ => out.push_str(&format!("\\{:03}", b)),
        }
    }
    out.push('"');
    out
}

fn check_constant_matches(val: &luad_core::model::ConstantValue, exp_raw: &str) -> bool {
    match val {
        luad_core::model::ConstantValue::Nil => exp_raw.to_ascii_lowercase().contains("nil"),
        luad_core::model::ConstantValue::Boolean(b) => {
            let s = if *b { "true" } else { "false" };
            exp_raw.to_ascii_lowercase().contains(s)
        }
        luad_core::model::ConstantValue::Integer { val, .. } => exp_raw.contains(&val.to_string()),
        luad_core::model::ConstantValue::Float { val, .. } => {
            let mut matched = false;
            for token in exp_raw.split_whitespace() {
                if let Ok(parsed_f) = token.parse::<f64>() {
                    let diff = (parsed_f - *val).abs();
                    let scale = val.abs().max(parsed_f.abs()).max(1.0);
                    if diff / scale < 1e-5 {
                        matched = true;
                        break;
                    }
                }
            }
            matched
        }
        luad_core::model::ConstantValue::ShortString(s)
        | luad_core::model::ConstantValue::LongString(s) => {
            let formatted_luac = format_luac_string(&s.raw_bytes);
            exp_raw.contains(&formatted_luac) || exp_raw.contains(s.as_str())
        }
    }
}

/// Perform structured field-by-field differential comparison between `luad`'s parsed `Chunk` and `luac -l -l`.
#[must_use]
pub fn compare_chunk_with_luac(chunk: &Chunk, luac_output: &str) -> Vec<OracleMismatch> {
    let mut mismatches = Vec::new();
    let dump = parse_luac_dump(luac_output);

    let mut actual_protos = Vec::new();
    flatten_protos(&chunk.main_proto, &mut actual_protos);

    if actual_protos.len() != dump.functions.len() {
        mismatches.push(OracleMismatch::PrototypeCount {
            actual: actual_protos.len(),
            expected: dump.functions.len(),
        });
        return mismatches;
    }

    for (i, (actual, expected)) in actual_protos.iter().zip(dump.functions.iter()).enumerate() {
        // 1. Lines defined
        if actual.line_defined != expected.linedefined {
            mismatches.push(OracleMismatch::Metadata {
                proto: i,
                field: "line_defined".to_string(),
                actual: actual.line_defined.to_string(),
                expected: expected.linedefined.to_string(),
            });
        }
        if actual.last_line_defined != expected.lastlinedefined {
            mismatches.push(OracleMismatch::Metadata {
                proto: i,
                field: "last_line_defined".to_string(),
                actual: actual.last_line_defined.to_string(),
                expected: expected.lastlinedefined.to_string(),
            });
        }

        // 2. Parameters & stack
        if actual.numparams as usize != expected.numparams {
            mismatches.push(OracleMismatch::Metadata {
                proto: i,
                field: "numparams".to_string(),
                actual: actual.numparams.to_string(),
                expected: expected.numparams.to_string(),
            });
        }
        if (actual.is_vararg != 0) != expected.is_vararg {
            mismatches.push(OracleMismatch::Metadata {
                proto: i,
                field: "is_vararg".to_string(),
                actual: (actual.is_vararg != 0).to_string(),
                expected: expected.is_vararg.to_string(),
            });
        }
        if actual.maxstacksize as usize != expected.maxstacksize {
            mismatches.push(OracleMismatch::Metadata {
                proto: i,
                field: "maxstacksize".to_string(),
                actual: actual.maxstacksize.to_string(),
                expected: expected.maxstacksize.to_string(),
            });
        }

        // 3. Instructions count, line numbers, and mnemonics
        if actual.instructions.len() != expected.instructions.len() {
            mismatches.push(OracleMismatch::InstructionCount {
                proto: i,
                actual: actual.instructions.len(),
                expected: expected.instructions.len(),
            });
        } else {
            for (pc, (act_inst, exp_inst)) in actual
                .instructions
                .iter()
                .zip(expected.instructions.iter())
                .enumerate()
            {
                let act_line = actual.get_line_for_pc(pc);
                if exp_inst.line > 0 && act_line > 0 && act_line != exp_inst.line {
                    mismatches.push(OracleMismatch::Line {
                        proto: i,
                        pc,
                        actual: act_line,
                        expected: exp_inst.line,
                    });
                }

                if let Some(act_mnem) =
                    decode_instruction_mnemonic(&chunk.dialect, act_inst.raw_word)
                {
                    if !act_mnem.eq_ignore_ascii_case(&exp_inst.mnemonic) {
                        mismatches.push(OracleMismatch::Mnemonic {
                            proto: i,
                            pc,
                            raw_word: act_inst.raw_word,
                            actual: act_mnem.to_string(),
                            expected: exp_inst.mnemonic.clone(),
                        });
                    }
                }
            }
        }

        // 4. Constants count and values
        if actual.constants.len() != expected.constants.len() {
            mismatches.push(OracleMismatch::ConstantCount {
                proto: i,
                actual: actual.constants.len(),
                expected: expected.constants.len(),
            });
        } else {
            for (c_idx, act_c) in actual.constants.iter().enumerate() {
                if let Some(exp_c) = expected.constants.get(c_idx) {
                    if !check_constant_matches(&act_c.value, &exp_c.raw_text) {
                        mismatches.push(OracleMismatch::Constant {
                            proto: i,
                            index: c_idx,
                            actual: format!("{:?}", act_c.value),
                            expected: exp_c.raw_text.clone(),
                        });
                    }
                }
            }
        }

        // 5. Locals count and debug info
        if actual.loc_vars.len() != expected.locals.len() {
            mismatches.push(OracleMismatch::LocalCount {
                proto: i,
                actual: actual.loc_vars.len(),
                expected: expected.locals.len(),
            });
        } else {
            for (loc_idx, (act_loc, exp_loc)) in actual
                .loc_vars
                .iter()
                .zip(expected.locals.iter())
                .enumerate()
            {
                if act_loc.name.as_str() != exp_loc.name.as_str() {
                    mismatches.push(OracleMismatch::Local {
                        proto: i,
                        index: loc_idx,
                        field: "name".to_string(),
                        actual: act_loc.name.as_str().to_string(),
                        expected: exp_loc.name.clone(),
                    });
                }
                if act_loc.startpc != exp_loc.startpc {
                    mismatches.push(OracleMismatch::Local {
                        proto: i,
                        index: loc_idx,
                        field: "startpc".to_string(),
                        actual: act_loc.startpc.to_string(),
                        expected: exp_loc.startpc.to_string(),
                    });
                }
                if act_loc.endpc != exp_loc.endpc {
                    mismatches.push(OracleMismatch::Local {
                        proto: i,
                        index: loc_idx,
                        field: "endpc".to_string(),
                        actual: act_loc.endpc.to_string(),
                        expected: exp_loc.endpc.to_string(),
                    });
                }
            }
        }

        // 6. Upvalues count and debug info
        if actual.upvalues.len() != expected.upvalues.len() {
            mismatches.push(OracleMismatch::UpvalueCount {
                proto: i,
                actual: actual.upvalues.len(),
                expected: expected.upvalues.len(),
            });
        } else {
            for (up_idx, (act_up, exp_up)) in actual
                .upvalues
                .iter()
                .zip(expected.upvalues.iter())
                .enumerate()
            {
                if let Some(act_name) = &act_up.name {
                    if act_name.as_str() != exp_up.name.as_str() {
                        mismatches.push(OracleMismatch::Upvalue {
                            proto: i,
                            index: up_idx,
                            field: "name".to_string(),
                            actual: act_name.as_str().to_string(),
                            expected: exp_up.name.clone(),
                        });
                    }
                }
                if let Some(exp_instack) = exp_up.instack {
                    if act_up.instack != exp_instack {
                        mismatches.push(OracleMismatch::Upvalue {
                            proto: i,
                            index: up_idx,
                            field: "instack".to_string(),
                            actual: act_up.instack.to_string(),
                            expected: exp_instack.to_string(),
                        });
                    }
                }
                if let Some(exp_idx) = exp_up.idx {
                    if act_up.idx != exp_idx {
                        mismatches.push(OracleMismatch::Upvalue {
                            proto: i,
                            index: up_idx,
                            field: "idx".to_string(),
                            actual: act_up.idx.to_string(),
                            expected: exp_idx.to_string(),
                        });
                    }
                }
            }
        }
    }

    mismatches
}

/// Perform field-by-field differential comparison between `luad`'s parsed `Chunk` and `luac -l -l`.
pub fn assert_chunk_matches_luac(chunk: &Chunk, luac_output: &str) {
    let mismatches = compare_chunk_with_luac(chunk, luac_output);
    if !mismatches.is_empty() {
        let mut msg = format!(
            "Canonical differential oracle detected {} mismatch(es) for dialect '{}':\n",
            mismatches.len(),
            chunk.dialect
        );
        for (idx, m) in mismatches.iter().enumerate() {
            msg.push_str(&format!("  {}. {:?}\n", idx + 1, m));
        }
        panic!("{msg}");
    }
}
