//! Lossless chunk and prototype undumper for Lua 5.5 bytecode chunks.

use sha2::{Digest, Sha256};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::{
    AbsLineInfo, Chunk, Constant, ConstantValue, InstructionWord, LocalVar, LuaString, Prototype,
    UpvalueDesc,
};
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;

use crate::header::parse_header_lua55;
use crate::validator::validate_chunk_lua55;

/// String reuse table maintaining the list of strings loaded in the chunk.
#[derive(Debug, Default)]
struct StringReuseTable {
    strings: Vec<LuaString>,
}

impl StringReuseTable {
    fn get(&self, index: usize) -> Option<LuaString> {
        if index == 0 {
            None
        } else {
            self.strings.get(index - 1).cloned()
        }
    }

    fn push(&mut self, s: LuaString) {
        self.strings.push(s);
    }
}

/// Decode an entire Lua 5.5 binary chunk.
pub fn decode_chunk_lua55(reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
    let raw_input = reader.raw_data().to_vec();
    let sha256 = hex::encode(Sha256::digest(&raw_input));
    let byte_length = raw_input.len();

    let header = parse_header_lua55(reader)?;

    // Read top-level closure sizeupvalues
    let _closure_upvals = reader.read_u8()?;

    let mut string_table = StringReuseTable::default();
    let main_proto = load_proto_55(reader, &mut string_table, &ProtoPath::root())?;

    // Check for trailing unparsed bytes
    let trailing_bytes = if reader.has_remaining() {
        let trailing_pos = reader.position();
        let remaining = reader.remaining_bytes();
        let trailing_raw = remaining.to_vec();
        let _ = reader.read_exact(remaining.len())?;

        let diag = Diagnostic::warning(
            "L55-CHUNK-001",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!(
                "Chunk contains {} unparsed trailing bytes at EOF",
                trailing_raw.len()
            ),
        )
        .with_source(SourceLocation::new(trailing_pos, &trailing_raw));
        reader.record_diagnostic(diag)?;

        Some(hex::encode(trailing_raw))
    } else {
        None
    };

    let diagnostics = reader.take_diagnostics();
    let verdict = if diagnostics
        .iter()
        .any(|d| d.severity == luad_core::diagnostic::Severity::Error)
    {
        Verdict::Invalid
    } else {
        Verdict::ValidForParser
    };

    let interpretation = luad_core::dialect::ResolvedInterpretation {
        base_dialect: "lua5.5".to_string(),
        patch_or_oracle_version: Some("5.5.1".to_string()),
        profile: "lua5.5".to_string(),
        profile_version_or_hash: None,
        validated_layout: Some("int=8,sizet=8,inst=4,num=8,endian=1".to_string()),
        parse_mode: match reader.mode() {
            luad_core::limits::ParseMode::Strict => "strict".to_string(),
            luad_core::limits::ParseMode::Permissive => "permissive".to_string(),
        },
        selection_mode: luad_core::dialect::SelectionMode::Detected,
        detection_evidence: "Lua 5.5 signature matched (0x1bLua, version 0x55)".to_string(),
    };

    let mut chunk = Chunk {
        sha256,
        byte_length,
        dialect: "lua5.5".to_string(),
        interpretation: Some(interpretation),
        verdict,
        header,
        main_proto,
        diagnostics,
        trailing_bytes,
    };

    let (v, d) = validate_chunk_lua55(&chunk);
    chunk.verdict = v;
    chunk.diagnostics = d;

    Ok(chunk)
}

fn load_string_55(
    reader: &mut SafeReader,
    table: &mut StringReuseTable,
) -> Result<Option<LuaString>, Diagnostic> {
    let (size, _) = reader.read_varint_lua55()?;
    if size == 0 {
        let (idx, _) = reader.read_varint_lua55()?;
        if idx == 0 {
            Ok(None)
        } else {
            match table.get(idx as usize) {
                Some(s) => Ok(Some(s)),
                None => {
                    let diag = Diagnostic::error(
                        "L55-STR-001",
                        DiagnosticCategory::Parse,
                        StableId::Proto(reader.current_proto_path().clone()),
                        format!("Invalid string reuse table index {idx}"),
                    );
                    reader.record_diagnostic(diag.clone())?;
                    Err(diag)
                }
            }
        }
    } else {
        let content_len = size - 1;
        reader.check_string_limit(content_len, |target, message| {
            Diagnostic::error("L55-STR-002", DiagnosticCategory::Parse, target, message)
        })?;
        let payload_len = usize::try_from(size).map_err(|_| {
            Diagnostic::error(
                "CORE-OVERFLOW-001",
                DiagnosticCategory::Parse,
                StableId::Proto(reader.current_proto_path().clone()),
                format!("Lua 5.5 string payload length {size} exceeds host pointer width"),
            )
        })?;
        let len = payload_len - 1;
        let bytes_with_null = reader.read_exact(payload_len)?;
        let content_bytes = &bytes_with_null[..len];
        let lua_str = LuaString::from_bytes(content_bytes);
        table.push(lua_str.clone());
        Ok(Some(lua_str))
    }
}

fn load_proto_55(
    reader: &mut SafeReader,
    table: &mut StringReuseTable,
    path: &ProtoPath,
) -> Result<Prototype, Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();

    // 1. Function definition lines
    let (linedefined, _) = reader.read_varint_lua55()?;
    let (lastlinedefined, _) = reader.read_varint_lua55()?;
    let numparams = reader.read_u8()?;
    let is_vararg = reader.read_u8()?;
    let maxstacksize = reader.read_u8()?;

    // 2. Instructions
    let (sizecode, _) = reader.read_varint_lua55()?;
    let code_len = sizecode as usize;
    if code_len > reader.limits().max_instructions_per_proto {
        let diag = Diagnostic::error(
            "L55-CODE-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Instruction count {code_len} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    reader.align_to(4)?;

    let mut instructions = Vec::with_capacity(reader.safe_capacity(code_len, 4));
    for pc in 0..code_len {
        let inst_pos = reader.position();
        let inst_cursor = reader.cursor_offset();
        let raw_word = reader.read_u32_le()?;
        let raw_hex = hex::encode(raw_word.to_le_bytes());
        let raw_bytes = reader.slice_from_cursor(inst_cursor)?;
        instructions.push(InstructionWord {
            id: StableId::instruction(path.clone(), pc),
            pc,
            raw_word,
            raw_hex,
            source: SourceLocation::new(inst_pos, raw_bytes),
        });
    }

    // 3. Constants
    let (sizek, _) = reader.read_varint_lua55()?;
    let k_len = sizek as usize;
    if k_len > reader.limits().max_constants_per_proto {
        let diag = Diagnostic::error(
            "L55-CONST-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Constant count {k_len} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut constants = Vec::with_capacity(reader.safe_capacity(k_len, 1));
    for idx in 0..k_len {
        let const_pos = reader.position();
        let const_cursor = reader.cursor_offset();
        let tag = reader.read_u8()?;

        let val = match tag {
            0 => ConstantValue::Nil,
            1 => ConstantValue::Boolean(false),
            17 => ConstantValue::Boolean(true),
            19 => {
                let f_val = reader.read_f64_le()?;
                ConstantValue::Float {
                    val: f_val,
                    raw_hex: hex::encode(f_val.to_le_bytes()),
                    is_nan: f_val.is_nan(),
                    is_inf: f_val.is_infinite(),
                }
            }
            3 => {
                let (cx, _) = reader.read_varint_lua55()?;
                let ival = if (cx & 1) != 0 {
                    !(cx >> 1) as i64
                } else {
                    (cx >> 1) as i64
                };
                ConstantValue::Integer {
                    val: ival,
                    raw_hex: hex::encode(ival.to_le_bytes()),
                }
            }
            4 | 20 => {
                let s_opt = load_string_55(reader, table)?;
                match s_opt {
                    Some(s) => {
                        if tag == 4 {
                            ConstantValue::ShortString(s)
                        } else {
                            ConstantValue::LongString(s)
                        }
                    }
                    None => ConstantValue::Nil,
                }
            }
            other => {
                let diag = Diagnostic::error(
                    "L55-CONST-001",
                    DiagnosticCategory::Parse,
                    StableId::constant(path.clone(), idx),
                    format!("Invalid constant tag {other}"),
                );
                reader.record_diagnostic(diag.clone())?;
                return Err(diag);
            }
        };

        let raw_bytes = reader.slice_from_cursor(const_cursor)?;
        constants.push(Constant {
            id: StableId::constant(path.clone(), idx),
            index: idx,
            value: val,
            source: SourceLocation::new(const_pos, raw_bytes),
        });
    }

    // 4. Upvalues
    let (sizeupvalues, _) = reader.read_varint_lua55()?;
    let u_len = sizeupvalues as usize;
    if u_len > reader.limits().max_upvalues_per_proto {
        let diag = Diagnostic::error(
            "L55-UPVAL-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Upvalue count {u_len} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut upvalues = Vec::with_capacity(reader.safe_capacity(u_len, 3));
    for idx in 0..u_len {
        let u_pos = reader.position();
        let u_cursor = reader.cursor_offset();
        let instack = reader.read_u8()?;
        let u_idx = reader.read_u8()?;
        let kind = reader.read_u8()?;
        let raw_bytes = reader.slice_from_cursor(u_cursor)?;

        upvalues.push(UpvalueDesc {
            id: StableId::upvalue(path.clone(), idx),
            index: idx,
            instack,
            idx: u_idx,
            kind,
            name: None,
            source: SourceLocation::new(u_pos, raw_bytes),
        });
    }

    // 5. Child Prototypes
    let (sizep, _) = reader.read_varint_lua55()?;
    let p_len = sizep as usize;
    if p_len > reader.limits().max_total_prototypes {
        let diag = Diagnostic::error(
            "L55-PROTO-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Prototype count {p_len} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut protos = Vec::with_capacity(reader.safe_capacity(p_len, 10));
    for child_idx in 0..p_len {
        let child_path = path.child(child_idx);
        let mut child_guard = reader.enter_proto(child_idx)?;
        let child_proto = load_proto_55(&mut child_guard, table, &child_path)?;
        protos.push(child_proto);
    }

    // 6. Source Name
    let source_name = load_string_55(reader, table)?;

    // 7. Debug line info
    let (sizelineinfo, _) = reader.read_varint_lua55()?;
    let lineinfo_bytes = reader.read_exact(sizelineinfo as usize)?;
    let line_info: Vec<u8> = lineinfo_bytes.to_vec();

    // 8. Absolute line info
    let (sizeabslineinfo, _) = reader.read_varint_lua55()?;
    let abs_len = sizeabslineinfo as usize;
    let mut abs_line_info = Vec::with_capacity(reader.safe_capacity(abs_len, 8));
    if abs_len > 0 {
        reader.align_to(4)?;
        for _ in 0..abs_len {
            let abs_pos = reader.position();
            let abs_cursor = reader.cursor_offset();
            let pc = reader.read_i32_le()? as usize;
            let line = reader.read_i32_le()? as usize;
            let raw_bytes = reader.slice_from_cursor(abs_cursor)?;
            abs_line_info.push(AbsLineInfo {
                pc,
                line,
                source: SourceLocation::new(abs_pos, raw_bytes),
            });
        }
    }

    // 9. Local variables
    let (sizelocvars, _) = reader.read_varint_lua55()?;
    let loc_len = sizelocvars as usize;
    let mut loc_vars = Vec::with_capacity(reader.safe_capacity(loc_len, 2));
    for idx in 0..loc_len {
        let loc_pos = reader.position();
        let loc_cursor = reader.cursor_offset();
        let varname = load_string_55(reader, table)?.unwrap_or_else(|| LuaString::from_bytes(b"?"));
        let (startpc, _) = reader.read_varint_lua55()?;
        let (endpc, _) = reader.read_varint_lua55()?;
        let raw_bytes = reader.slice_from_cursor(loc_cursor)?;

        loc_vars.push(LocalVar {
            id: StableId::local(path.clone(), idx),
            index: idx,
            name: varname,
            startpc: startpc as usize,
            endpc: endpc as usize,
            source: SourceLocation::new(loc_pos, raw_bytes),
        });
    }

    // 10. Upvalue Names
    let (sizeupvalnames, _) = reader.read_varint_lua55()?;
    let mut upvalue_names = Vec::with_capacity(sizeupvalnames as usize);
    for idx in 0..(sizeupvalnames as usize) {
        let name = load_string_55(reader, table)?;
        if let Some(upval) = upvalues.get_mut(idx) {
            upval.name = name.clone();
        }
        upvalue_names.push(name);
    }

    let proto_bytes = reader.slice_from_cursor(start_cursor)?;

    Ok(Prototype {
        id: StableId::proto(path.clone()),
        path: path.clone(),
        source_name,
        line_defined: linedefined as usize,
        last_line_defined: lastlinedefined as usize,
        numparams,
        is_vararg,
        maxstacksize,
        instructions,
        constants,
        upvalues,
        protos,
        line_info,
        abs_line_info,
        loc_vars,
        upvalue_names,
        source: SourceLocation::new(start_pos, proto_bytes),
    })
}
