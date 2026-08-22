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
    pub tag: Option<char>,
    pub value_str: String,
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

                    let mnem_field = parts[2].trim();
                    let (mnemonic, maybe_ops) =
                        if let Some((m, o)) = mnem_field.split_once(char::is_whitespace) {
                            (m.trim().to_string(), o.trim().to_string())
                        } else {
                            (mnem_field.to_string(), String::new())
                        };

                    let mut operands_raw = maybe_ops;
                    let mut comment = None;

                    for part in &parts[3..] {
                        let trimmed_part = part.trim();
                        if trimmed_part.starts_with(';') {
                            comment = Some(trimmed_part.trim_start_matches(';').trim().to_string());
                        } else if let Some((before_semi, after_semi)) = trimmed_part.split_once(';')
                        {
                            if operands_raw.is_empty() {
                                operands_raw = before_semi.trim().to_string();
                            }
                            comment = Some(after_semi.trim().to_string());
                        } else if operands_raw.is_empty() {
                            operands_raw = trimmed_part.to_string();
                        }
                    }

                    proto.instructions.push(LuacInstDump {
                        pc,
                        line: line_num,
                        mnemonic,
                        operands_raw,
                        comment,
                    });
                }
            }
            Section::Constants => {
                // E.g. "	0	S	\"hello\"" (Lua 5.4/5.5) or "	1	\"hello\"" (Lua 5.1-5.3)
                let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                if !tokens.is_empty() {
                    let idx: usize = tokens[0].parse().unwrap_or(0);
                    let (tag, value_str) = if tokens.len() >= 3
                        && tokens[1].len() == 1
                        && "IFSNB".contains(tokens[1].chars().next().unwrap_or(' '))
                    {
                        let tag_char = tokens[1].chars().next().unwrap();
                        let remainder = trimmed
                            .split_once(tokens[1])
                            .map(|(_, r)| r.trim())
                            .unwrap_or("");
                        (Some(tag_char), remainder.to_string())
                    } else {
                        let remainder = trimmed
                            .split_once(tokens[0])
                            .map(|(_, r)| r.trim())
                            .unwrap_or("");
                        (None, remainder.to_string())
                    };

                    proto.constants.push(LuacConstDump {
                        index: idx,
                        tag,
                        value_str,
                        raw_text: trimmed.to_string(),
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

/// Decode instruction operands string for a given dialect and instruction word formatted as `luac -l -l`.
#[must_use]
pub fn decode_instruction_operands(dialect: &str, raw_word: u32) -> Option<String> {
    match dialect {
        "lua5.1" => decode_instruction_operands_51(raw_word),
        "lua5.2" => decode_instruction_operands_52(raw_word),
        "lua5.3" => decode_instruction_operands_53(raw_word),
        "lua5.4" => decode_instruction_operands_54(raw_word),
        "lua5.5" => decode_instruction_operands_55(raw_word),
        _ => None,
    }
}

fn decode_instruction_operands_51(raw_word: u32) -> Option<String> {
    let raw = luad_dialect_lua51::RawInstruction51::decode(raw_word);
    let op = raw.opcode?;
    use luad_dialect_lua51::Opcode51;

    let b_str = if raw.is_b_k() {
        format!("-{}", raw.b_index_k() + 1)
    } else {
        format!("{}", raw.b)
    };
    let c_str = if raw.is_c_k() {
        format!("-{}", raw.c_index_k() + 1)
    } else {
        format!("{}", raw.c)
    };

    let s = match op {
        Opcode51::Move => format!("{} {}", raw.a, raw.b),
        Opcode51::LoadK => format!("{} -{}", raw.a, raw.bx + 1),
        Opcode51::LoadBool => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode51::LoadNil => format!("{} {}", raw.a, raw.b),
        Opcode51::GetUpval | Opcode51::SetUpval => format!("{} {}", raw.a, raw.b),
        Opcode51::GetGlobal | Opcode51::SetGlobal => format!("{} -{}", raw.a, raw.bx + 1),
        Opcode51::GetTable | Opcode51::SetTable => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode51::NewTable => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode51::SelfOp => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode51::Add
        | Opcode51::Sub
        | Opcode51::Mul
        | Opcode51::Div
        | Opcode51::Mod
        | Opcode51::Pow => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode51::Unm | Opcode51::Not | Opcode51::Len => format!("{} {}", raw.a, raw.b),
        Opcode51::Concat => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode51::Jmp => format!("{}", raw.sbx),
        Opcode51::Eq | Opcode51::Lt | Opcode51::Le => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode51::Test => format!("{} {}", raw.a, raw.c),
        Opcode51::TestSet => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode51::Call | Opcode51::TailCall => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode51::Return => format!("{} {}", raw.a, raw.b),
        Opcode51::ForLoop | Opcode51::ForPrep => format!("{} {}", raw.a, raw.sbx),
        Opcode51::TForLoop => format!("{} {}", raw.a, raw.c),
        Opcode51::SetList => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode51::Close => format!("{}", raw.a),
        Opcode51::Closure => format!("{} {}", raw.a, raw.bx),
        Opcode51::VarArg => format!("{} {}", raw.a, raw.b),
    };
    Some(s)
}

fn decode_instruction_operands_52(raw_word: u32) -> Option<String> {
    let raw = luad_dialect_lua52::RawInstruction52::decode(raw_word);
    let op = raw.opcode?;
    use luad_dialect_lua52::Opcode52;

    let b_str = if raw.is_b_k() {
        format!("-{}", raw.b_index_k() + 1)
    } else {
        format!("{}", raw.b)
    };
    let c_str = if raw.is_c_k() {
        format!("-{}", raw.c_index_k() + 1)
    } else {
        format!("{}", raw.c)
    };

    let s = match op {
        Opcode52::Move => format!("{} {}", raw.a, raw.b),
        Opcode52::LoadK => format!("{} -{}", raw.a, raw.bx + 1),
        Opcode52::LoadKx => format!("{}", raw.a),
        Opcode52::LoadBool => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode52::LoadNil => format!("{} {}", raw.a, raw.b),
        Opcode52::GetUpval | Opcode52::SetUpval => format!("{} {}", raw.a, raw.b),
        Opcode52::GetTabUp | Opcode52::SetTabUp | Opcode52::GetTable | Opcode52::SetTable => {
            format!("{} {} {}", raw.a, b_str, c_str)
        }
        Opcode52::NewTable => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode52::SelfOp => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode52::Add
        | Opcode52::Sub
        | Opcode52::Mul
        | Opcode52::Div
        | Opcode52::Mod
        | Opcode52::Pow => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode52::Unm | Opcode52::Not | Opcode52::Len => format!("{} {}", raw.a, raw.b),
        Opcode52::Concat => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode52::Jmp => format!("{} {}", raw.a, raw.sbx),
        Opcode52::Eq | Opcode52::Lt | Opcode52::Le => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode52::Test => format!("{} {}", raw.a, raw.c),
        Opcode52::TestSet => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode52::Call | Opcode52::TailCall => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode52::Return => format!("{} {}", raw.a, raw.b),
        Opcode52::ForLoop | Opcode52::ForPrep => format!("{} {}", raw.a, raw.sbx),
        Opcode52::TForCall => format!("{} {}", raw.a, raw.c),
        Opcode52::TForLoop => format!("{} {}", raw.a, raw.sbx),
        Opcode52::SetList => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode52::Closure => format!("{} {}", raw.a, raw.bx),
        Opcode52::VarArg => format!("{} {}", raw.a, raw.b),
        Opcode52::ExtraArg => format!("{}", raw.ax),
    };
    Some(s)
}

fn decode_instruction_operands_53(raw_word: u32) -> Option<String> {
    let raw = luad_dialect_lua53::RawInstruction53::decode(raw_word);
    let op = raw.opcode?;
    use luad_dialect_lua53::Opcode53;

    let b_str = if raw.is_b_k() {
        format!("-{}", raw.b_index_k() + 1)
    } else {
        format!("{}", raw.b)
    };
    let c_str = if raw.is_c_k() {
        format!("-{}", raw.c_index_k() + 1)
    } else {
        format!("{}", raw.c)
    };

    let s = match op {
        Opcode53::Move => format!("{} {}", raw.a, raw.b),
        Opcode53::LoadK => format!("{} -{}", raw.a, raw.bx + 1),
        Opcode53::LoadKx => format!("{}", raw.a),
        Opcode53::LoadBool => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode53::LoadNil => format!("{} {}", raw.a, raw.b),
        Opcode53::GetUpval | Opcode53::SetUpval => format!("{} {}", raw.a, raw.b),
        Opcode53::GetTabUp | Opcode53::SetTabUp | Opcode53::GetTable | Opcode53::SetTable => {
            format!("{} {} {}", raw.a, b_str, c_str)
        }
        Opcode53::NewTable => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode53::SelfOp => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode53::Add
        | Opcode53::Sub
        | Opcode53::Mul
        | Opcode53::Mod
        | Opcode53::Pow
        | Opcode53::Div
        | Opcode53::IDiv
        | Opcode53::BAnd
        | Opcode53::BOr
        | Opcode53::BXor
        | Opcode53::Shl
        | Opcode53::Shr => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode53::Unm | Opcode53::BNot | Opcode53::Not | Opcode53::Len => {
            format!("{} {}", raw.a, raw.b)
        }
        Opcode53::Concat => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode53::Jmp => format!("{} {}", raw.a, raw.sbx),
        Opcode53::Eq | Opcode53::Lt | Opcode53::Le => format!("{} {} {}", raw.a, b_str, c_str),
        Opcode53::Test => format!("{} {}", raw.a, raw.c),
        Opcode53::TestSet => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode53::Call | Opcode53::TailCall => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode53::Return => format!("{} {}", raw.a, raw.b),
        Opcode53::ForLoop | Opcode53::ForPrep => format!("{} {}", raw.a, raw.sbx),
        Opcode53::TForCall => format!("{} {}", raw.a, raw.c),
        Opcode53::TForLoop => format!("{} {}", raw.a, raw.sbx),
        Opcode53::SetList => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode53::Closure => format!("{} {}", raw.a, raw.bx),
        Opcode53::VarArg => format!("{} {}", raw.a, raw.b),
        Opcode53::ExtraArg => format!("{}", raw.ax),
    };
    Some(s)
}

fn decode_instruction_operands_54(raw_word: u32) -> Option<String> {
    let raw = luad_dialect_lua54::RawInstruction54::decode(raw_word);
    let op = raw.opcode?;
    use luad_dialect_lua54::Opcode54;

    let k_suffix = if raw.k != 0 { "k" } else { "" };

    let s = match op {
        Opcode54::Move => format!("{} {}", raw.a, raw.b),
        Opcode54::Loadi | Opcode54::Loadf => format!("{} {}", raw.a, raw.sbx),
        Opcode54::Loadk => format!("{} {}", raw.a, raw.bx),
        Opcode54::Loadkx => format!("{}", raw.a),
        Opcode54::Loadfalse | Opcode54::Lfalseskip | Opcode54::Loadtrue => format!("{}", raw.a),
        Opcode54::Loadnil => format!("{} {}", raw.a, raw.b),
        Opcode54::Getupval | Opcode54::Setupval => format!("{} {}", raw.a, raw.b),
        Opcode54::Gettabup | Opcode54::Gettable | Opcode54::Geti | Opcode54::Getfield => {
            format!("{} {} {}", raw.a, raw.b, raw.c)
        }
        Opcode54::Settabup | Opcode54::Settable | Opcode54::Seti | Opcode54::Setfield => {
            format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix)
        }
        Opcode54::Newtable => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode54::SelfOp => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode54::Addi | Opcode54::Shri | Opcode54::Shli => {
            format!("{} {} {}", raw.a, raw.b, raw.sc)
        }
        Opcode54::Addk
        | Opcode54::Subk
        | Opcode54::Mulk
        | Opcode54::Modk
        | Opcode54::Powk
        | Opcode54::Divk
        | Opcode54::Idivk
        | Opcode54::Bandk
        | Opcode54::Bork
        | Opcode54::Bxork => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode54::Add
        | Opcode54::Sub
        | Opcode54::Mul
        | Opcode54::Mod
        | Opcode54::Pow
        | Opcode54::Div
        | Opcode54::Idiv
        | Opcode54::Band
        | Opcode54::Bor
        | Opcode54::Bxor
        | Opcode54::Shl
        | Opcode54::Shr => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode54::Mmbin => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode54::Mmbini => format!("{} {} {} {}", raw.a, raw.sb, raw.c, raw.k),
        Opcode54::Mmbink => format!("{} {} {} {}", raw.a, raw.b, raw.c, raw.k),
        Opcode54::Unm | Opcode54::Bnot | Opcode54::Not | Opcode54::Len | Opcode54::Concat => {
            format!("{} {}", raw.a, raw.b)
        }
        Opcode54::Close | Opcode54::Tbc => format!("{}", raw.a),
        Opcode54::Jmp => format!("{}", raw.sj),
        Opcode54::Eq | Opcode54::Lt | Opcode54::Le | Opcode54::Eqk => {
            format!("{} {} {}", raw.a, raw.b, raw.k)
        }
        Opcode54::Eqi | Opcode54::Lti | Opcode54::Lei | Opcode54::Gti | Opcode54::Gei => {
            format!("{} {} {}", raw.a, raw.sb, raw.k)
        }
        Opcode54::Test => format!("{} {}", raw.a, raw.k),
        Opcode54::Testset => format!("{} {} {}", raw.a, raw.b, raw.k),
        Opcode54::Call => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode54::Tailcall => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode54::Return => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode54::Return0 => String::new(),
        Opcode54::Return1 => format!("{}", raw.a),
        Opcode54::Forloop | Opcode54::Forprep | Opcode54::Tforprep => {
            format!("{} {}", raw.a, raw.bx)
        }
        Opcode54::Tforcall => format!("{} {}", raw.a, raw.c),
        Opcode54::Tforloop => format!("{} {}", raw.a, raw.bx),
        Opcode54::Setlist => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode54::Closure => format!("{} {}", raw.a, raw.bx),
        Opcode54::Vararg => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode54::Varargprep => format!("{}", raw.a),
        Opcode54::Extraarg => format!("{}", raw.ax),
    };
    Some(s)
}

fn decode_instruction_operands_55(raw_word: u32) -> Option<String> {
    let raw = luad_dialect_lua55::RawInstruction55::decode(raw_word);
    let op = raw.opcode?;
    use luad_dialect_lua55::Opcode55;

    let k_suffix = if raw.k != 0 { "k" } else { "" };

    let s = match op {
        Opcode55::Move => format!("{} {}", raw.a, raw.b),
        Opcode55::Loadi | Opcode55::Loadf => format!("{} {}", raw.a, raw.sbx),
        Opcode55::Loadk => format!("{} {}", raw.a, raw.bx),
        Opcode55::Loadkx => format!("{}", raw.a),
        Opcode55::Loadfalse | Opcode55::Lfalseskip | Opcode55::Loadtrue => format!("{}", raw.a),
        Opcode55::Loadnil => format!("{} {}", raw.a, raw.b),
        Opcode55::Getupval | Opcode55::Setupval => format!("{} {}", raw.a, raw.b),
        Opcode55::Gettabup | Opcode55::Gettable | Opcode55::Geti | Opcode55::Getfield => {
            format!("{} {} {}", raw.a, raw.b, raw.c)
        }
        Opcode55::Settabup | Opcode55::Settable | Opcode55::Seti | Opcode55::Setfield => {
            format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix)
        }
        Opcode55::Newtable => format!("{} {} {}{}", raw.a, raw.vb, raw.vc, k_suffix),
        Opcode55::SelfOp => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode55::Addi | Opcode55::Shri | Opcode55::Shli => {
            format!("{} {} {}", raw.a, raw.b, raw.sc)
        }
        Opcode55::Addk
        | Opcode55::Subk
        | Opcode55::Mulk
        | Opcode55::Modk
        | Opcode55::Powk
        | Opcode55::Divk
        | Opcode55::Idivk
        | Opcode55::Bandk
        | Opcode55::Bork
        | Opcode55::Bxork => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode55::Add
        | Opcode55::Sub
        | Opcode55::Mul
        | Opcode55::Mod
        | Opcode55::Pow
        | Opcode55::Div
        | Opcode55::Idiv
        | Opcode55::Band
        | Opcode55::Bor
        | Opcode55::Bxor
        | Opcode55::Shl
        | Opcode55::Shr => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode55::Mmbin => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode55::Mmbini => format!("{} {} {} {}", raw.a, raw.sb, raw.c, raw.k),
        Opcode55::Mmbink => format!("{} {} {} {}", raw.a, raw.b, raw.c, raw.k),
        Opcode55::Unm | Opcode55::Bnot | Opcode55::Not | Opcode55::Len | Opcode55::Concat => {
            format!("{} {}", raw.a, raw.b)
        }
        Opcode55::Close | Opcode55::Tbc => format!("{}", raw.a),
        Opcode55::Jmp => format!("{}", raw.sj),
        Opcode55::Eq | Opcode55::Lt | Opcode55::Le | Opcode55::Eqk => {
            format!("{} {} {}", raw.a, raw.b, raw.k)
        }
        Opcode55::Eqi | Opcode55::Lti | Opcode55::Lei | Opcode55::Gti | Opcode55::Gei => {
            format!("{} {} {}", raw.a, raw.sb, raw.k)
        }
        Opcode55::Test => format!("{} {}", raw.a, raw.k),
        Opcode55::Testset => format!("{} {} {}", raw.a, raw.b, raw.k),
        Opcode55::Call => format!("{} {} {}", raw.a, raw.b, raw.c),
        Opcode55::Tailcall => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode55::Return => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode55::Return0 => String::new(),
        Opcode55::Return1 => format!("{}", raw.a),
        Opcode55::Forloop | Opcode55::Forprep | Opcode55::Tforprep => {
            format!("{} {}", raw.a, raw.bx)
        }
        Opcode55::Tforcall => format!("{} {}", raw.a, raw.c),
        Opcode55::Tforloop => format!("{} {}", raw.a, raw.bx),
        Opcode55::Setlist => format!("{} {} {}{}", raw.a, raw.vb, raw.vc, k_suffix),
        Opcode55::Closure => format!("{} {}", raw.a, raw.bx),
        Opcode55::Vararg => format!("{} {} {}{}", raw.a, raw.b, raw.c, k_suffix),
        Opcode55::Varargprep => format!("{}", raw.a),
        Opcode55::Extraarg => format!("{}", raw.ax),
        _ => format!("{} {} {}", raw.a, raw.b, raw.c),
    };
    Some(s)
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

fn check_constant_matches(val: &luad_core::model::ConstantValue, exp_c: &LuacConstDump) -> bool {
    let exp_str = exp_c.value_str.trim();
    match val {
        luad_core::model::ConstantValue::Nil => {
            if let Some(tag) = exp_c.tag {
                tag == 'N' || exp_str == "nil"
            } else {
                exp_str == "nil"
            }
        }
        luad_core::model::ConstantValue::Boolean(b) => {
            if let Some(tag) = exp_c.tag {
                if tag != 'B' {
                    return false;
                }
            }
            let s = if *b { "true" } else { "false" };
            exp_str == s
        }
        luad_core::model::ConstantValue::Integer { val, .. } => {
            if let Some(tag) = exp_c.tag {
                if tag != 'I' {
                    return false;
                }
            }
            if let Ok(parsed_int) = exp_str.parse::<i64>() {
                *val == parsed_int
            } else {
                exp_str == val.to_string()
            }
        }
        luad_core::model::ConstantValue::Float { val, .. } => {
            if let Some(tag) = exp_c.tag {
                if tag != 'F' {
                    return false;
                }
            }
            if let Ok(parsed_f) = exp_str.parse::<f64>() {
                if (val.is_nan() && parsed_f.is_nan()) || val.to_bits() == parsed_f.to_bits() {
                    true
                } else {
                    let val_str = format!("{}", val);
                    val_str == exp_str
                        || (*val - parsed_f).abs() <= f64::EPSILON
                        || (val.is_finite()
                            && parsed_f.is_finite()
                            && (*val - parsed_f).abs() / (val.abs().max(parsed_f.abs()).max(1.0))
                                < 1e-12)
                }
            } else {
                false
            }
        }
        luad_core::model::ConstantValue::ShortString(s)
        | luad_core::model::ConstantValue::LongString(s) => {
            if let Some(tag) = exp_c.tag {
                if tag != 'S' {
                    return false;
                }
            }
            let formatted_luac = format_luac_string(&s.raw_bytes);
            exp_str == formatted_luac || exp_str == s.as_str()
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

                let act_mnem = decode_instruction_mnemonic(&chunk.dialect, act_inst.raw_word)
                    .unwrap_or("<unknown>");
                if !act_mnem.eq_ignore_ascii_case(&exp_inst.mnemonic) {
                    mismatches.push(OracleMismatch::Mnemonic {
                        proto: i,
                        pc,
                        raw_word: act_inst.raw_word,
                        actual: act_mnem.to_string(),
                        expected: exp_inst.mnemonic.clone(),
                    });
                }

                let act_ops = decode_instruction_operands(&chunk.dialect, act_inst.raw_word)
                    .unwrap_or_else(|| "<invalid>".to_string());
                let exp_ops = &exp_inst.operands_raw;
                if act_ops.trim() != exp_ops.trim() {
                    let act_tokens: Vec<&str> = act_ops.split_whitespace().collect();
                    let exp_tokens: Vec<&str> = exp_ops.split_whitespace().collect();
                    let max_len = act_tokens.len().max(exp_tokens.len());
                    for op_idx in 0..max_len {
                        let act_tok = act_tokens.get(op_idx).unwrap_or(&"");
                        let exp_tok = exp_tokens.get(op_idx).unwrap_or(&"");
                        if act_tok != exp_tok {
                            mismatches.push(OracleMismatch::Operand {
                                proto: i,
                                pc,
                                raw_word: act_inst.raw_word,
                                index: op_idx,
                                actual: (*act_tok).to_string(),
                                expected: (*exp_tok).to_string(),
                            });
                        }
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
                    if !check_constant_matches(&act_c.value, exp_c) {
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
                let act_name = act_up.name.as_ref().map(|s| s.as_str()).unwrap_or("");
                if act_name != exp_up.name.as_str() {
                    mismatches.push(OracleMismatch::Upvalue {
                        proto: i,
                        index: up_idx,
                        field: "name".to_string(),
                        actual: act_name.to_string(),
                        expected: exp_up.name.clone(),
                    });
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
