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
                // E.g. "\t0\t(for state)\t5\t7"
                let parts: Vec<&str> = line.split('\t').filter(|s| !s.is_empty()).collect();
                if parts.len() >= 4 {
                    let idx: usize = parts[0].trim().parse().unwrap_or(0);
                    let name = parts[1].trim().to_string();
                    let startpc: usize = parts[2].trim().parse().unwrap_or(0);
                    let endpc: usize = parts[3].trim().parse().unwrap_or(0);
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

/// Recursively collect all prototypes from a root prototype in preorder.
fn flatten_protos<'a>(proto: &'a Prototype, acc: &mut Vec<&'a Prototype>) {
    acc.push(proto);
    for child in &proto.protos {
        flatten_protos(child, acc);
    }
}

/// Perform field-by-field differential comparison between `luad`'s parsed `Chunk` and `luac -l -l`.
pub fn assert_chunk_matches_luac(chunk: &Chunk, luac_output: &str) {
    let dump = parse_luac_dump(luac_output);

    let mut actual_protos = Vec::new();
    flatten_protos(&chunk.main_proto, &mut actual_protos);

    assert_eq!(
        actual_protos.len(),
        dump.functions.len(),
        "Prototype count mismatch: actual {}, luac dump {}",
        actual_protos.len(),
        dump.functions.len()
    );

    for (i, (actual, expected)) in actual_protos.iter().zip(dump.functions.iter()).enumerate() {
        // 1. Lines defined
        assert_eq!(
            actual.line_defined, expected.linedefined,
            "Proto #{i} line_defined mismatch: actual {}, expected {}",
            actual.line_defined, expected.linedefined
        );
        assert_eq!(
            actual.last_line_defined, expected.lastlinedefined,
            "Proto #{i} last_line_defined mismatch: actual {}, expected {}",
            actual.last_line_defined, expected.lastlinedefined
        );

        // 2. Parameters & stack
        assert_eq!(
            actual.numparams as usize, expected.numparams,
            "Proto #{i} numparams mismatch: actual {}, expected {}",
            actual.numparams, expected.numparams
        );
        assert_eq!(
            (actual.is_vararg != 0),
            expected.is_vararg,
            "Proto #{i} is_vararg mismatch: actual {}, expected {}",
            actual.is_vararg,
            expected.is_vararg
        );
        assert_eq!(
            actual.maxstacksize as usize, expected.maxstacksize,
            "Proto #{i} maxstacksize mismatch: actual {}, expected {}",
            actual.maxstacksize, expected.maxstacksize
        );

        // 3. Instructions count and line numbers
        assert_eq!(
            actual.instructions.len(),
            expected.instructions.len(),
            "Proto #{i} instructions count mismatch: actual {}, expected {}",
            actual.instructions.len(),
            expected.instructions.len()
        );

        for (pc, (act_inst, exp_inst)) in actual
            .instructions
            .iter()
            .zip(expected.instructions.iter())
            .enumerate()
        {
            assert_eq!(
                act_inst.pc, exp_inst.pc,
                "Proto #{i} PC mismatch at instruction #{pc}"
            );
            let act_line = actual.get_line_for_pc(pc);
            if exp_inst.line > 0 && act_line > 0 {
                assert_eq!(
                    act_line, exp_inst.line,
                    "Proto #{i} line mismatch at PC {pc}: actual {}, expected {}",
                    act_line, exp_inst.line
                );
            }
        }

        // 4. Constants count
        assert_eq!(
            actual.constants.len(),
            expected.constants.len(),
            "Proto #{i} constants count mismatch: actual {}, expected {}",
            actual.constants.len(),
            expected.constants.len()
        );

        // 5. Locals count and names
        assert_eq!(
            actual.loc_vars.len(),
            expected.locals.len(),
            "Proto #{i} locals count mismatch: actual {}, expected {}",
            actual.loc_vars.len(),
            expected.locals.len()
        );
        for (loc_idx, (act_loc, exp_loc)) in actual
            .loc_vars
            .iter()
            .zip(expected.locals.iter())
            .enumerate()
        {
            assert_eq!(
                act_loc.name.as_str(),
                exp_loc.name.as_str(),
                "Proto #{i} local #{loc_idx} name mismatch"
            );
        }

        // 6. Upvalues count and names
        assert_eq!(
            actual.upvalues.len(),
            expected.upvalues.len(),
            "Proto #{i} upvalues count mismatch: actual {}, expected {}",
            actual.upvalues.len(),
            expected.upvalues.len()
        );
        for (up_idx, (act_up, exp_up)) in actual
            .upvalues
            .iter()
            .zip(expected.upvalues.iter())
            .enumerate()
        {
            if let Some(act_name) = &act_up.name {
                assert_eq!(
                    act_name.as_str(),
                    exp_up.name.as_str(),
                    "Proto #{i} upvalue #{up_idx} name mismatch"
                );
            }
        }
    }
}
