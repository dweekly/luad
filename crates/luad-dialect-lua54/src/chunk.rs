//! Lossless chunk and prototype parser for Lua 5.4.

use sha2::{Digest, Sha256};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::{
    AbsLineInfo, Chunk, Constant, ConstantValue, InstructionWord, LocalVar, LuaString, Prototype,
    UpvalueDesc,
};
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;

use crate::header::{parse_header_lua54, LUAC_DATA_54, LUA_SIGNATURE};

/// Constant type tags in Lua 5.4 bytecode.
pub const LUA_VNIL: u8 = 0;
pub const LUA_VFALSE: u8 = 1;
pub const LUA_VTRUE: u8 = 1 | (1 << 4); // 0x11
pub const LUA_VNUMINT: u8 = 3;
pub const LUA_VNUMFLT: u8 = 3 | (1 << 4); // 0x13
pub const LUA_VSHRSTR: u8 = 4;
pub const LUA_VLNGSTR: u8 = 4 | (1 << 4); // 0x14

/// Decode a complete Lua 5.4 binary chunk.
pub fn decode_chunk_lua54(reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
    let raw_input = reader.raw_data();
    let byte_length = raw_input.len();
    let mut hasher = Sha256::new();
    hasher.update(raw_input);
    let sha256 = hex::encode(hasher.finalize());

    // 1. Parse Header
    let header = parse_header_lua54(reader)?;

    // 2. Read top-level closure sizeupvalues (1 byte)
    let _main_closure_size_upvalues = reader.read_u8()?;

    // 3. Parse Main Root Prototype
    let main_proto = decode_proto_lua54(reader, &ProtoPath::root(), None)?;

    // 4. Check for Trailing Bytes
    let trailing_bytes = if reader.has_remaining() {
        let remaining = reader.remaining_bytes();
        let diag = Diagnostic::warning(
            "L54-CHUNK-001",
            DiagnosticCategory::Structure,
            StableId::Chunk,
            format!(
                "Chunk contains {} trailing unparsed bytes at offset {}",
                remaining.len(),
                reader.position()
            ),
        )
        .with_source(SourceLocation::new(reader.position(), remaining));
        reader.record_diagnostic(diag)?;
        Some(hex::encode(remaining))
    } else {
        None
    };

    let diagnostics = reader.take_diagnostics();
    let has_errors = diagnostics.iter().any(|d| d.severity == Severity::Error);
    let verdict = if has_errors {
        Verdict::Invalid
    } else {
        Verdict::ValidForParser
    };

    let interpretation = luad_core::dialect::ResolvedInterpretation {
        base_dialect: "lua5.4".to_string(),
        patch_or_oracle_version: Some("5.4.8".to_string()),
        profile: "lua5.4".to_string(),
        profile_version_or_hash: None,
        validated_layout: Some("int=8,sizet=8,inst=4,num=8,endian=1".to_string()),
        parse_mode: match reader.mode() {
            luad_core::limits::ParseMode::Strict => "strict".to_string(),
            luad_core::limits::ParseMode::Permissive => "permissive".to_string(),
        },
        selection_mode: luad_core::dialect::SelectionMode::Detected,
        detection_evidence: "Lua 5.4 signature matched (0x1bLua, version 0x54)".to_string(),
    };

    Ok(Chunk {
        sha256,
        byte_length,
        dialect: "lua5.4".to_string(),
        interpretation: Some(interpretation),
        header,
        main_proto,
        trailing_bytes,
        diagnostics,
        verdict,
    })
}

/// Recursively decode a Lua 5.4 function prototype.
/// Recursively decode a Lua 5.4 function prototype.
pub fn decode_proto_lua54(
    reader: &mut SafeReader,
    proto_path: &ProtoPath,
    parent_source: Option<&LuaString>,
) -> Result<Prototype, Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();
    let id = StableId::proto(proto_path.clone());

    // 1. Header fields
    // source name string
    let (source_name_bytes, _) = reader.read_string_lua54()?;
    let source_name = source_name_bytes
        .map(|b| LuaString::from_bytes(&b))
        .or_else(|| parent_source.cloned());

    // line defined & last line defined (varints)
    let (line_defined_val, _) = reader.read_varint_lua54()?;
    let line_defined = line_defined_val as usize;

    let (last_line_defined_val, _) = reader.read_varint_lua54()?;
    let last_line_defined = last_line_defined_val as usize;

    // numparams, is_vararg, maxstacksize
    let numparams = reader.read_u8()?;
    let is_vararg = reader.read_u8()?;
    let maxstacksize = reader.read_u8()?;

    // 2. Code vector
    let (code_size_val, _) = reader.read_varint_lua54()?;
    let code_size = code_size_val as usize;

    if code_size > reader.limits().max_instructions_per_proto {
        let diag = Diagnostic::error(
            "L54-CODE-001",
            DiagnosticCategory::Parse,
            id.clone(),
            format!("Instruction count {code_size} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let mut instructions = Vec::with_capacity(reader.safe_capacity(code_size, 4));
    for pc in 0..code_size {
        let word_pos = reader.position();
        let word = reader.read_u32_le()?;
        let word_bytes = word.to_le_bytes();
        instructions.push(InstructionWord {
            id: StableId::instruction(proto_path.clone(), pc),
            pc,
            raw_word: word,
            raw_hex: hex::encode(word_bytes),
            source: SourceLocation::new(word_pos, &word_bytes),
        });
    }

    // 3. Constants vector
    let (k_size_val, _) = reader.read_varint_lua54()?;
    let k_size = k_size_val as usize;

    if k_size > reader.limits().max_constants_per_proto {
        let diag = Diagnostic::error(
            "L54-CONST-001",
            DiagnosticCategory::Parse,
            id.clone(),
            format!("Constant count {k_size} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let mut constants = Vec::with_capacity(reader.safe_capacity(k_size, 1));
    for k_idx in 0..k_size {
        let k_pos = reader.position();
        let k_cursor = reader.cursor_offset();
        let tag = reader.read_u8()?;
        let const_id = StableId::constant(proto_path.clone(), k_idx);

        let value = match tag {
            LUA_VNIL => ConstantValue::Nil,
            LUA_VFALSE => ConstantValue::Boolean(false),
            LUA_VTRUE => ConstantValue::Boolean(true),
            LUA_VNUMINT => {
                let val = reader.read_i64_le()?;
                ConstantValue::Integer {
                    val,
                    raw_hex: hex::encode(val.to_le_bytes()),
                }
            }
            LUA_VNUMFLT => {
                let val = reader.read_f64_le()?;
                ConstantValue::Float {
                    val,
                    raw_hex: hex::encode(val.to_le_bytes()),
                    is_nan: val.is_nan(),
                    is_inf: val.is_infinite(),
                }
            }
            LUA_VSHRSTR => {
                let (str_bytes, _) = reader.read_string_lua54()?;
                let raw = str_bytes.unwrap_or_default();
                ConstantValue::ShortString(LuaString::from_bytes(&raw))
            }
            LUA_VLNGSTR => {
                let (str_bytes, _) = reader.read_string_lua54()?;
                let raw = str_bytes.unwrap_or_default();
                ConstantValue::LongString(LuaString::from_bytes(&raw))
            }
            unknown => {
                let diag = Diagnostic::error(
                    "L54-CONST-002",
                    DiagnosticCategory::Parse,
                    const_id.clone(),
                    format!("Unknown constant tag: 0x{unknown:02x}"),
                )
                .with_source(SourceLocation::new(k_pos, &[unknown]));
                reader.record_diagnostic(diag.clone())?;
                return Err(diag);
            }
        };

        let raw_bytes = reader.slice_from_cursor(k_cursor)?;
        constants.push(Constant {
            id: const_id,
            index: k_idx,
            value,
            source: SourceLocation::new(k_pos, raw_bytes),
        });
    }

    // 4. Upvalues vector
    let (upvalues_size_val, _) = reader.read_varint_lua54()?;
    let upvalues_size = upvalues_size_val as usize;

    if upvalues_size > reader.limits().max_upvalues_per_proto {
        let diag = Diagnostic::error(
            "L54-UPVAL-001",
            DiagnosticCategory::Parse,
            id.clone(),
            format!("Upvalue count {upvalues_size} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let mut upvalues = Vec::with_capacity(reader.safe_capacity(upvalues_size, 3));
    for u_idx in 0..upvalues_size {
        let u_pos = reader.position();
        let u_cursor = reader.cursor_offset();
        let instack = reader.read_u8()?;
        let idx = reader.read_u8()?;
        let kind = reader.read_u8()?;
        let raw_bytes = reader.slice_from_cursor(u_cursor)?;

        upvalues.push(UpvalueDesc {
            id: StableId::upvalue(proto_path.clone(), u_idx),
            index: u_idx,
            instack,
            idx,
            kind,
            name: None,
            source: SourceLocation::new(u_pos, raw_bytes),
        });
    }

    // 5. Nested Prototypes vector
    let (protos_size_val, _) = reader.read_varint_lua54()?;
    let protos_size = protos_size_val as usize;

    if protos_size > reader.limits().max_total_prototypes {
        let diag = Diagnostic::error(
            "L54-PROTO-001",
            DiagnosticCategory::Parse,
            id.clone(),
            format!("Prototype count {protos_size} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let mut protos = Vec::with_capacity(reader.safe_capacity(protos_size, 10));
    for p_idx in 0..protos_size {
        let mut child_guard = reader.enter_proto(p_idx)?;
        let child_proto = decode_proto_lua54(
            &mut child_guard,
            &proto_path.child(p_idx),
            source_name.as_ref(),
        )?;
        protos.push(child_proto);
    }

    // 6. Debug metadata
    // Line info
    let (lineinfo_size_val, _) = reader.read_varint_lua54()?;
    let lineinfo_size = lineinfo_size_val as usize;
    let line_info_bytes = reader.read_exact(lineinfo_size)?;
    let line_info = line_info_bytes.to_vec();

    // Absolute line info
    let (abslineinfo_size_val, _) = reader.read_varint_lua54()?;
    let abslineinfo_size = abslineinfo_size_val as usize;
    let mut abs_line_info = Vec::with_capacity(reader.safe_capacity(abslineinfo_size, 2));
    for _ in 0..abslineinfo_size {
        let abs_pos = reader.position();
        let abs_cursor = reader.cursor_offset();
        let (pc_val, _) = reader.read_varint_lua54()?;
        let (line_val, _) = reader.read_varint_lua54()?;
        let raw_bytes = reader.slice_from_cursor(abs_cursor)?;
        abs_line_info.push(AbsLineInfo {
            pc: pc_val as usize,
            line: line_val as usize,
            source: SourceLocation::new(abs_pos, raw_bytes),
        });
    }

    // Local variables
    let (locvars_size_val, _) = reader.read_varint_lua54()?;
    let locvars_size = locvars_size_val as usize;
    let mut loc_vars = Vec::with_capacity(reader.safe_capacity(locvars_size, 2));
    for l_idx in 0..locvars_size {
        let loc_pos = reader.position();
        let loc_cursor = reader.cursor_offset();
        let (varname_bytes, _) = reader.read_string_lua54()?;
        let (startpc_val, _) = reader.read_varint_lua54()?;
        let (endpc_val, _) = reader.read_varint_lua54()?;
        let raw_bytes = reader.slice_from_cursor(loc_cursor)?;

        let varname = varname_bytes
            .map(|b| LuaString::from_bytes(&b))
            .unwrap_or_else(|| LuaString::from_bytes(b"?"));

        loc_vars.push(LocalVar {
            id: StableId::local(proto_path.clone(), l_idx),
            index: l_idx,
            name: varname,
            startpc: startpc_val as usize,
            endpc: endpc_val as usize,
            source: SourceLocation::new(loc_pos, raw_bytes),
        });
    }

    // Upvalue names
    let (upvalnames_size_val, _) = reader.read_varint_lua54()?;
    let upvalnames_size = upvalnames_size_val as usize;
    let mut upvalue_names = Vec::with_capacity(reader.safe_capacity(upvalnames_size, 1));
    for u_idx in 0..upvalnames_size {
        let (name_bytes, _) = reader.read_string_lua54()?;
        let name_opt = name_bytes.map(|b| LuaString::from_bytes(&b));
        if let Some(upval) = upvalues.get_mut(u_idx) {
            upval.name = name_opt.clone();
        }
        upvalue_names.push(name_opt);
    }

    let raw_proto_bytes = reader.slice_from_cursor(start_cursor)?;
    let source = SourceLocation::new(start_pos, raw_proto_bytes);

    Ok(Prototype {
        id,
        path: proto_path.clone(),
        source_name,
        line_defined,
        last_line_defined,
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
        source,
    })
}

/// Write a Lua 5.4 variable-length integer.
pub fn write_varint_lua54(buf: &mut Vec<u8>, val: u64) {
    if val == 0 {
        buf.push(0x80);
        return;
    }
    let mut temp = Vec::new();
    let mut v = val;
    temp.push((v & 0x7f) as u8 | 0x80);
    v >>= 7;
    while v > 0 {
        temp.push((v & 0x7f) as u8);
        v >>= 7;
    }
    for b in temp.into_iter().rev() {
        buf.push(b);
    }
}

/// Write a Lua 5.4 string with length prefix.
pub fn write_string_lua54(buf: &mut Vec<u8>, s: Option<&[u8]>) {
    match s {
        None => write_varint_lua54(buf, 0),
        Some(bytes) => {
            write_varint_lua54(buf, (bytes.len() + 1) as u64);
            buf.extend_from_slice(bytes);
        }
    }
}

/// Encode a Lua 5.4 prototype to binary bytecode purely from its AST model fields.
pub fn encode_proto_lua54(buf: &mut Vec<u8>, proto: &Prototype) {
    // 1. source_name (only root proto writes source name, sub-protos inherit unless distinct)
    let s_name = if proto.path.depth() == 0 {
        proto.source_name.as_ref().map(|s| s.raw_bytes.as_slice())
    } else {
        None
    };
    write_string_lua54(buf, s_name);

    // 2. lines defined
    write_varint_lua54(buf, proto.line_defined as u64);
    write_varint_lua54(buf, proto.last_line_defined as u64);

    // 3. params & flags
    buf.push(proto.numparams);
    buf.push(proto.is_vararg);
    buf.push(proto.maxstacksize);

    // 4. code instructions
    write_varint_lua54(buf, proto.instructions.len() as u64);
    for inst in &proto.instructions {
        buf.extend_from_slice(&inst.raw_word.to_le_bytes());
    }

    // 5. constants
    write_varint_lua54(buf, proto.constants.len() as u64);
    for k in &proto.constants {
        match &k.value {
            ConstantValue::Nil => buf.push(LUA_VNIL),
            ConstantValue::Boolean(false) => buf.push(LUA_VFALSE),
            ConstantValue::Boolean(true) => buf.push(LUA_VTRUE),
            ConstantValue::Integer { val, .. } => {
                buf.push(LUA_VNUMINT);
                buf.extend_from_slice(&val.to_le_bytes());
            }
            ConstantValue::Float { val, .. } => {
                buf.push(LUA_VNUMFLT);
                buf.extend_from_slice(&val.to_le_bytes());
            }
            ConstantValue::ShortString(s) => {
                buf.push(LUA_VSHRSTR);
                write_string_lua54(buf, Some(&s.raw_bytes));
            }
            ConstantValue::LongString(s) => {
                buf.push(LUA_VLNGSTR);
                write_string_lua54(buf, Some(&s.raw_bytes));
            }
        }
    }

    // 6. upvalues
    write_varint_lua54(buf, proto.upvalues.len() as u64);
    for u in &proto.upvalues {
        buf.push(u.instack);
        buf.push(u.idx);
        buf.push(u.kind);
    }

    // 7. sub-prototypes
    write_varint_lua54(buf, proto.protos.len() as u64);
    for p in &proto.protos {
        encode_proto_lua54(buf, p);
    }

    // 8. line_info
    write_varint_lua54(buf, proto.line_info.len() as u64);
    for &li in &proto.line_info {
        buf.push(li);
    }

    // 9. abs_line_info
    write_varint_lua54(buf, proto.abs_line_info.len() as u64);
    for ali in &proto.abs_line_info {
        write_varint_lua54(buf, ali.pc as u64);
        write_varint_lua54(buf, ali.line as u64);
    }

    // 10. loc_vars
    write_varint_lua54(buf, proto.loc_vars.len() as u64);
    for lv in &proto.loc_vars {
        write_string_lua54(buf, Some(&lv.name.raw_bytes));
        write_varint_lua54(buf, lv.startpc as u64);
        write_varint_lua54(buf, lv.endpc as u64);
    }

    // 11. upvalue_names
    write_varint_lua54(buf, proto.upvalue_names.len() as u64);
    for un in &proto.upvalue_names {
        write_string_lua54(buf, un.as_ref().map(|s| s.raw_bytes.as_slice()));
    }
}

/// Encode a complete Lua 5.4 binary chunk purely from its AST model fields.
#[must_use]
pub fn encode_chunk_lua54(chunk: &Chunk) -> Vec<u8> {
    let mut buf = Vec::with_capacity(chunk.byte_length);

    // 1. Header (official Lua 5.4.8 layout: 30 bytes)
    buf.extend_from_slice(LUA_SIGNATURE); // 4 bytes: "\x1bLua"
    buf.push(0x54); // Version 5.4
    buf.push(0x00); // Format 0
    buf.extend_from_slice(LUAC_DATA_54); // 6 bytes: "\x19\x93\r\n\x1a\n"

    buf.push(chunk.header.instruction_size); // 4
    buf.push(chunk.header.lua_integer_size); // 8
    buf.push(chunk.header.lua_number_size); // 8

    buf.extend_from_slice(&0x5678i64.to_le_bytes()); // LUAC_INT test integer
    buf.extend_from_slice(&370.5f64.to_le_bytes()); // LUAC_NUM test float

    // 2. Main closure sizeupvalues
    buf.push(chunk.main_proto.upvalues.len() as u8);

    // 3. Main Prototype (recursive)
    encode_proto_lua54(&mut buf, &chunk.main_proto);

    // 4. Trailing bytes if any
    if let Some(tb) = &chunk.trailing_bytes {
        if let Ok(bytes) = hex::decode(tb) {
            buf.extend_from_slice(&bytes);
        }
    }

    buf
}
