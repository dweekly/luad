//! Lossless chunk and prototype parser for Lua 5.4.

use sha2::{Digest, Sha256};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::{
    AbsLineInfo, Chunk, Constant, ConstantValue, InstructionWord, LocalVar, LuaString,
    Prototype, UpvalueDesc,
};
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;

use crate::header::parse_header_lua54;

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
    let has_errors = diagnostics
        .iter()
        .any(|d| d.severity == Severity::Error);
    let verdict = if has_errors {
        Verdict::Invalid
    } else {
        Verdict::ValidForParser
    };

    Ok(Chunk {
        sha256,
        byte_length,
        dialect: "lua5.4".to_string(),
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

    if code_size > 1_000_000 {
        let diag = Diagnostic::error(
            "L54-CODE-001",
            DiagnosticCategory::Parse,
            id.clone(),
            format!("Instruction count {code_size} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let mut instructions = Vec::with_capacity(code_size);
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

    if k_size > 262_144 {
        let diag = Diagnostic::error(
            "L54-CONST-001",
            DiagnosticCategory::Parse,
            id.clone(),
            format!("Constant count {k_size} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }

    let mut constants = Vec::with_capacity(k_size);
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

    let mut upvalues = Vec::with_capacity(upvalues_size);
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

    let mut protos = Vec::with_capacity(protos_size);
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
    let mut abs_line_info = Vec::with_capacity(abslineinfo_size);
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
    let mut loc_vars = Vec::with_capacity(locvars_size);
    for l_idx in 0..locvars_size {
        let loc_pos = reader.position();
        let loc_cursor = reader.cursor_offset();
        let (name_bytes, _) = reader.read_string_lua54()?;
        let (startpc_val, _) = reader.read_varint_lua54()?;
        let (endpc_val, _) = reader.read_varint_lua54()?;
        let raw_bytes = reader.slice_from_cursor(loc_cursor)?;

        let name = name_bytes
            .map(|b| LuaString::from_bytes(&b))
            .unwrap_or_else(|| LuaString::from_bytes(b"(null)"));

        loc_vars.push(LocalVar {
            id: StableId::local(proto_path.clone(), l_idx),
            index: l_idx,
            name,
            startpc: startpc_val as usize,
            endpc: endpc_val as usize,
            source: SourceLocation::new(loc_pos, raw_bytes),
        });
    }

    // Upvalue names
    let (upvalue_names_size_val, _) = reader.read_varint_lua54()?;
    let upvalue_names_size = upvalue_names_size_val as usize;
    let mut upvalue_names = Vec::with_capacity(upvalue_names_size);
    for u_idx in 0..upvalue_names_size {
        let (name_bytes, _) = reader.read_string_lua54()?;
        let name = name_bytes.map(|b| LuaString::from_bytes(&b));
        if u_idx < upvalues.len() {
            upvalues[u_idx].name = name.clone();
        }
        upvalue_names.push(name);
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
