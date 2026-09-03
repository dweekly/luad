//! Lossless chunk and prototype undumper for Lua 5.1 bytecode chunks.

use sha2::{Digest, Sha256};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::{
    AbsLineInfo, Chunk, Constant, ConstantValue, InstructionWord, LocalVar, LuaString, Prototype,
    UpvalueDesc,
};
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;

use crate::header::{parse_header_lua51, ChunkLayout, Lua51Profile};
use crate::validator::validate_chunk_lua51;

/// Decode an entire Lua 5.1 binary chunk using default stock profile.
pub fn decode_chunk_lua51(reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
    decode_chunk_lua51_with_profile(reader, Lua51Profile::Stock)
}

/// Decode an entire Lua 5.1 binary chunk with explicit profile selection.
pub fn decode_chunk_lua51_with_profile(
    reader: &mut SafeReader,
    profile: Lua51Profile,
) -> Result<Chunk, Diagnostic> {
    let raw_input = reader.raw_data().to_vec();
    let sha256 = hex::encode(Sha256::digest(&raw_input));
    let byte_length = raw_input.len();

    let (header, layout) = parse_header_lua51(reader, profile)?;

    let main_proto = load_proto_51(reader, &ProtoPath::root(), None, &layout)?;

    // Check for trailing unparsed bytes
    let trailing_bytes = if reader.has_remaining() {
        let trailing_pos = reader.position();
        let remaining = reader.remaining_bytes();
        let trailing_raw = remaining.to_vec();
        let _ = reader.read_exact(remaining.len())?;

        let diag = Diagnostic::warning(
            "L51-CHUNK-001",
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

    let dialect_name = match profile {
        Lua51Profile::Lnum32 => "lua5.1-lnum32",
        Lua51Profile::Stock32 => "lua5.1-stock32",
        Lua51Profile::Stock => "lua5.1",
    };

    let interpretation = luad_core::dialect::ResolvedInterpretation {
        base_dialect: "lua5.1".to_string(),
        patch_or_oracle_version: match profile {
            Lua51Profile::Lnum32 => Some("lnum32".to_string()),
            _ => None,
        },
        profile: dialect_name.to_string(),
        profile_version_or_hash: None,
        validated_layout: Some(format!(
            "int={},sizet={},inst={},num={},endian={},integral_flag={}",
            layout.sizeof_int,
            layout.sizeof_sizet,
            layout.instruction_size,
            layout.lua_number_size,
            layout.endianness,
            layout.integral_flag,
        )),
        parse_mode: match reader.mode() {
            luad_core::limits::ParseMode::Strict => "strict".to_string(),
            luad_core::limits::ParseMode::Permissive => "permissive".to_string(),
        },
        selection_mode: luad_core::dialect::SelectionMode::Detected,
        detection_evidence: format!(
            "Lua 5.1 signature matched (version 0x51, format {}, profile {})",
            header.format, dialect_name
        ),
    };

    let mut chunk = Chunk {
        sha256,
        byte_length,
        dialect: dialect_name.to_string(),
        interpretation: Some(interpretation),
        verdict,
        header,
        main_proto,
        diagnostics,
        trailing_bytes,
    };

    let (v, d) = validate_chunk_lua51(&chunk);
    chunk.verdict = v;
    chunk.diagnostics = d;

    Ok(chunk)
}

fn load_string_51(
    reader: &mut SafeReader,
    sizeof_sizet: u8,
) -> Result<Option<LuaString>, Diagnostic> {
    // Lua 5.1 encodes a string's payload plus terminator in the header-declared size_t
    // width. The terminator is serialized data and is not part of the Lua string.
    let size = if sizeof_sizet == 4 {
        reader.read_u32_le()? as usize
    } else {
        reader.read_u64_le()? as usize
    };
    if size == 0 {
        Ok(None)
    } else {
        let content_len = size.saturating_sub(1);
        reader.check_string_limit(content_len as u64, |target, message| {
            Diagnostic::error("L51-STR-001", DiagnosticCategory::Parse, target, message)
        })?;
        let bytes_with_null = reader.read_exact(size)?;
        let content = &bytes_with_null[..content_len];
        Ok(Some(LuaString::from_bytes(content)))
    }
}

fn load_proto_51(
    reader: &mut SafeReader,
    path: &ProtoPath,
    parent_source: Option<&LuaString>,
    layout: &ChunkLayout,
) -> Result<Prototype, Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();

    // 1. Source name
    let source_name_opt = load_string_51(reader, layout.sizeof_sizet)?;

    let source_name = source_name_opt.or_else(|| parent_source.cloned());

    // 2. Lines & stack
    let linedefined = reader.read_i32_le()? as usize;
    let lastlinedefined = reader.read_i32_le()? as usize;
    let nups = reader.read_u8()? as usize;
    let numparams = reader.read_u8()?;
    let is_vararg = reader.read_u8()?;
    let maxstacksize = reader.read_u8()?;

    // 3. Instructions
    let sizecode = reader.read_i32_le()? as usize;
    if sizecode > reader.limits().max_instructions_per_proto {
        let diag = Diagnostic::error(
            "L51-CODE-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Instruction count {sizecode} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut instructions = Vec::with_capacity(reader.safe_capacity(sizecode, 4));
    for pc in 0..sizecode {
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

    // 4. Constants
    let sizek = reader.read_i32_le()? as usize;
    if sizek > reader.limits().max_constants_per_proto {
        let diag = Diagnostic::error(
            "L51-CONST-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Constant count {sizek} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut constants = Vec::with_capacity(reader.safe_capacity(sizek, 1));
    for idx in 0..sizek {
        let const_pos = reader.position();
        let const_cursor = reader.cursor_offset();
        let tag = reader.read_u8()?;

        let val = match tag {
            0 => ConstantValue::Nil,
            1 => {
                let b = reader.read_u8()?;
                ConstantValue::Boolean(b != 0)
            }
            // LUA_TNUMBER carries one `lua_Number` of the declared width. The stock
            // header's integral flag (byte 11, `lundump.c`: `(lua_Number)0.5 == 0`)
            // says whether that type is an integer or a floating-point type, so the
            // same four or eight bytes decode as a two's-complement integer under
            // flag 1 and as IEEE-754 under flag 0. The LNUM32 profile keeps tag 3
            // floating-point and carries its integers in tag 9 below; its byte 11 is
            // `sizeof(lua_Integer)`, which `ChunkLayout::validate` pins to 4.
            3 => {
                if layout.integral_flag == 1 {
                    if layout.lua_number_size == 4 {
                        let i_val = reader.read_i32_le()?;
                        ConstantValue::Integer {
                            val: i64::from(i_val),
                            raw_hex: hex::encode(i_val.to_le_bytes()),
                        }
                    } else {
                        let i_val = reader.read_i64_le()?;
                        ConstantValue::Integer {
                            val: i_val,
                            raw_hex: hex::encode(i_val.to_le_bytes()),
                        }
                    }
                } else if layout.lua_number_size == 4 {
                    let raw_bits = reader.read_u32_le()?;
                    let f32_val = f32::from_bits(raw_bits);
                    let f_val = f64::from(f32_val);
                    ConstantValue::Float {
                        val: f_val,
                        raw_hex: hex::encode(raw_bits.to_le_bytes()),
                        is_nan: f_val.is_nan(),
                        is_inf: f_val.is_infinite(),
                    }
                } else {
                    let f_val = reader.read_f64_le()?;
                    ConstantValue::Float {
                        val: f_val,
                        raw_hex: hex::encode(f_val.to_le_bytes()),
                        is_nan: f_val.is_nan(),
                        is_inf: f_val.is_infinite(),
                    }
                }
            }
            4 => {
                let s_opt = load_string_51(reader, layout.sizeof_sizet)?;
                s_opt
                    .map(ConstantValue::ShortString)
                    .unwrap_or(ConstantValue::Nil)
            }
            // OpenWrt/eLua LNUM patch adds LUA_TINT = 9: a 4-byte little-endian signed integer
            // constant. Explicitly gated behind Lua51Profile::Lnum32.
            9 => {
                if layout.profile == Lua51Profile::Lnum32 {
                    let i_val = reader.read_i32_le()?;
                    ConstantValue::Integer {
                        val: i_val as i64,
                        raw_hex: hex::encode(i_val.to_le_bytes()),
                    }
                } else {
                    let diag = Diagnostic::error(
                        "L51-CONST-002",
                        DiagnosticCategory::Parse,
                        StableId::constant(path.clone(), idx),
                        "Invalid constant tag 9: tag 9 is an LNUM extension; use profile 'lua5.1-lnum32' to decode",
                    );
                    reader.record_diagnostic(diag.clone())?;
                    return Err(diag);
                }
            }
            other => {
                let diag = Diagnostic::error(
                    "L51-CONST-001",
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

    // 5. Child Prototypes
    let sizep = reader.read_i32_le()? as usize;
    if sizep > reader.limits().max_total_prototypes {
        let diag = Diagnostic::error(
            "L51-PROTO-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Prototype count {sizep} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut protos = Vec::with_capacity(reader.safe_capacity(sizep, 10));
    for child_idx in 0..sizep {
        let child_path = path.child(child_idx);
        let mut child_guard = reader.enter_proto(child_idx)?;
        let child_proto =
            load_proto_51(&mut child_guard, &child_path, source_name.as_ref(), layout)?;
        protos.push(child_proto);
    }

    // 6. Debug line info
    let sizelineinfo = reader.read_i32_le()? as usize;
    let mut line_info = Vec::with_capacity(reader.safe_capacity(sizelineinfo, 4) * 4);
    let mut abs_line_info = Vec::with_capacity(reader.safe_capacity(sizelineinfo, 4));
    for pc in 0..sizelineinfo {
        let line_pos = reader.position();
        let line_cursor = reader.cursor_offset();
        let line = reader.read_i32_le()? as usize;
        line_info.extend_from_slice(&(line as u32).to_le_bytes());
        let raw_bytes = reader.slice_from_cursor(line_cursor)?;
        abs_line_info.push(AbsLineInfo {
            pc,
            line,
            source: SourceLocation::new(line_pos, raw_bytes),
        });
    }

    // 7. Local variables
    let sizelocvars = reader.read_i32_le()? as usize;
    let mut loc_vars = Vec::with_capacity(reader.safe_capacity(sizelocvars, 8));
    for idx in 0..sizelocvars {
        let loc_pos = reader.position();
        let loc_cursor = reader.cursor_offset();
        let varname = load_string_51(reader, layout.sizeof_sizet)?
            .unwrap_or_else(|| LuaString::from_bytes(b"?"));
        let startpc = reader.read_i32_le()? as usize;
        let endpc = reader.read_i32_le()? as usize;
        let raw_bytes = reader.slice_from_cursor(loc_cursor)?;

        loc_vars.push(LocalVar {
            id: StableId::local(path.clone(), idx),
            index: idx,
            name: varname,
            startpc,
            endpc,
            source: SourceLocation::new(loc_pos, raw_bytes),
        });
    }

    // 8. Upvalue Names
    let sizeupvalnames = reader.read_i32_le()? as usize;
    let mut upvalue_names = Vec::with_capacity(reader.safe_capacity(sizeupvalnames, 1));
    let mut upvalues = Vec::with_capacity(reader.safe_capacity(nups, 1));

    for idx in 0..nups {
        upvalues.push(UpvalueDesc {
            id: StableId::upvalue(path.clone(), idx),
            index: idx,
            instack: 0,
            idx: 0,
            kind: 0,
            name: None,
            source: SourceLocation::new(start_pos, &[]),
        });
    }

    for idx in 0..sizeupvalnames {
        let name = load_string_51(reader, layout.sizeof_sizet)?;

        if let Some(upval) = upvalues.get_mut(idx) {
            upval.name = name.clone();
        }
        upvalue_names.push(name);
    }

    // Resolve capture metadata only from executable closure owners and their claimed
    // descriptors. Opcode-shaped companion data cannot rebind a child prototype.
    let role_map = crate::roles::discover_roles_from_parts_lua51(&instructions, &protos);
    for (pc, inst) in instructions.iter().enumerate() {
        if !role_map.is_executable(pc) {
            continue;
        }
        let raw = crate::opcodes::RawInstruction51::decode(inst.raw_word);
        if raw.opcode == Some(crate::opcodes::Opcode51::Closure) {
            let child_idx = raw.bx as usize;
            if let Some(child) = protos.get_mut(child_idx) {
                let nups_child = child.upvalues.len();
                for j in 0..nups_child {
                    let desc_pc = pc + 1 + j;
                    if desc_pc < instructions.len()
                        && matches!(
                            role_map.get(desc_pc),
                            crate::roles::Lua51PhysicalRole::ClosureBinding {
                                owner_pc,
                                upvalue_index,
                            } if owner_pc == pc && upvalue_index == j
                        )
                    {
                        let desc_raw = crate::opcodes::RawInstruction51::decode(
                            instructions[desc_pc].raw_word,
                        );
                        if let Some(u) = child.upvalues.get_mut(j) {
                            if desc_raw.opcode == Some(crate::opcodes::Opcode51::Move) {
                                u.instack = 1;
                                u.idx = desc_raw.b as u8;
                                u.source = instructions[desc_pc].source.clone();
                            } else if desc_raw.opcode == Some(crate::opcodes::Opcode51::GetUpval) {
                                u.instack = 0;
                                u.idx = desc_raw.b as u8;
                                u.source = instructions[desc_pc].source.clone();
                            }
                        }
                    }
                }
            }
        }
    }

    let proto_bytes = reader.slice_from_cursor(start_cursor)?;

    Ok(Prototype {
        id: StableId::proto(path.clone()),
        path: path.clone(),
        source_name,
        line_defined: linedefined,
        last_line_defined: lastlinedefined,
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
