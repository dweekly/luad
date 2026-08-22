//! Lossless chunk and prototype undumper for Lua 5.3 bytecode chunks.

use sha2::{Digest, Sha256};

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Verdict};
use luad_core::id::{ProtoPath, StableId};
use luad_core::model::{
    AbsLineInfo, Chunk, Constant, ConstantValue, InstructionWord, LocalVar, LuaString, Prototype,
    UpvalueDesc,
};
use luad_core::provenance::SourceLocation;
use luad_core::reader::SafeReader;

use crate::header::parse_header_lua53;
use crate::validator::validate_chunk_lua53;

/// Decode an entire Lua 5.3 binary chunk.
pub fn decode_chunk_lua53(reader: &mut SafeReader) -> Result<Chunk, Diagnostic> {
    let raw_input = reader.raw_data().to_vec();
    let sha256 = hex::encode(Sha256::digest(&raw_input));
    let byte_length = raw_input.len();

    let header = parse_header_lua53(reader)?;

    // Top-level closure sizeupvalues (usually 1 for _ENV)
    let _closure_upvals = reader.read_u8()?;

    let main_proto = load_proto_53(reader, &ProtoPath::root(), None, header.sizeof_sizet)?;

    // Check for trailing unparsed bytes
    let trailing_bytes = if reader.has_remaining() {
        let trailing_pos = reader.position();
        let remaining = reader.remaining_bytes();
        let trailing_raw = remaining.to_vec();
        let _ = reader.read_exact(remaining.len())?;

        let diag = Diagnostic::warning(
            "L53-CHUNK-001",
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

    let mut chunk = Chunk {
        sha256,
        byte_length,
        dialect: "lua5.3".to_string(),
        verdict,
        header,
        main_proto,
        diagnostics,
        trailing_bytes,
    };

    let (v, d) = validate_chunk_lua53(&chunk);
    chunk.verdict = v;
    chunk.diagnostics = d;

    Ok(chunk)
}

fn load_string_53(
    reader: &mut SafeReader,
    sizeof_sizet: u8,
) -> Result<Option<LuaString>, Diagnostic> {
    let size_byte = reader.read_u8()?;
    let size = if size_byte == 0xFF {
        if sizeof_sizet == 4 {
            reader.read_u32_le()? as usize
        } else {
            reader.read_u64_le()? as usize
        }
    } else {
        size_byte as usize
    };

    if size == 0 {
        Ok(None)
    } else {
        let len = size - 1;
        let bytes = reader.read_exact(len)?;
        Ok(Some(LuaString::from_bytes(bytes)))
    }
}

fn load_proto_53(
    reader: &mut SafeReader,
    path: &ProtoPath,
    parent_source: Option<&LuaString>,
    sizeof_sizet: u8,
) -> Result<Prototype, Diagnostic> {
    let start_pos = reader.position();
    let start_cursor = reader.cursor_offset();

    // 1. Source name
    let source_name_opt = load_string_53(reader, sizeof_sizet)?;
    let source_name = source_name_opt.or_else(|| parent_source.cloned());

    // 2. Lines & parameters
    let linedefined = reader.read_i32_le()? as usize;
    let lastlinedefined = reader.read_i32_le()? as usize;
    let numparams = reader.read_u8()?;
    let is_vararg = reader.read_u8()?;
    let maxstacksize = reader.read_u8()?;

    // 3. Instructions
    let sizecode = reader.read_i32_le()? as usize;
    if sizecode > reader.limits().max_instructions_per_proto {
        let diag = Diagnostic::error(
            "L53-CODE-001",
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
        let word = reader.read_u32_le()?;
        let raw_bytes = reader.slice_from_cursor(inst_cursor)?;
        instructions.push(InstructionWord {
            id: StableId::instruction(path.clone(), pc),
            pc,
            raw_word: word,
            raw_hex: hex::encode(word.to_le_bytes()),
            source: SourceLocation::new(inst_pos, raw_bytes),
        });
    }

    // 4. Constants
    let sizek = reader.read_i32_le()? as usize;
    if sizek > reader.limits().max_constants_per_proto {
        let diag = Diagnostic::error(
            "L53-CONST-002",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Constant count {sizek} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut constants = Vec::with_capacity(reader.safe_capacity(sizek, 2));
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
                let ival = reader.read_i64_le()?;
                ConstantValue::Integer {
                    val: ival,
                    raw_hex: hex::encode(ival.to_le_bytes()),
                }
            }
            4 => {
                let s_opt = load_string_53(reader, sizeof_sizet)?;
                s_opt
                    .map(ConstantValue::ShortString)
                    .unwrap_or(ConstantValue::Nil)
            }
            20 => {
                let s_opt = load_string_53(reader, sizeof_sizet)?;
                s_opt
                    .map(ConstantValue::LongString)
                    .unwrap_or(ConstantValue::Nil)
            }
            other => {
                let diag = Diagnostic::error(
                    "L53-CONST-001",
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

    // 5. Upvalues
    let sizeupvalues = reader.read_i32_le()? as usize;
    if sizeupvalues > reader.limits().max_upvalues_per_proto {
        let diag = Diagnostic::error(
            "L53-UPVAL-001",
            DiagnosticCategory::Parse,
            StableId::proto(path.clone()),
            format!("Upvalue count {sizeupvalues} exceeds safety limit"),
        );
        reader.record_diagnostic(diag.clone())?;
        return Err(diag);
    }
    let mut upvalues = Vec::with_capacity(reader.safe_capacity(sizeupvalues, 2));
    for idx in 0..sizeupvalues {
        let u_pos = reader.position();
        let u_cursor = reader.cursor_offset();
        let instack = reader.read_u8()?;
        let u_idx = reader.read_u8()?;
        let raw_bytes = reader.slice_from_cursor(u_cursor)?;

        upvalues.push(UpvalueDesc {
            id: StableId::upvalue(path.clone(), idx),
            index: idx,
            instack,
            idx: u_idx,
            kind: 0,
            name: None,
            source: SourceLocation::new(u_pos, raw_bytes),
        });
    }

    // 6. Child Prototypes
    let sizep = reader.read_i32_le()? as usize;
    if sizep > reader.limits().max_total_prototypes {
        let diag = Diagnostic::error(
            "L53-PROTO-001",
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
        let child_proto = load_proto_53(
            &mut child_guard,
            &child_path,
            source_name.as_ref(),
            sizeof_sizet,
        )?;
        protos.push(child_proto);
    }

    // 7. Debug line info (each entry is an i32)
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

    // 8. Local variables
    let sizelocvars = reader.read_i32_le()? as usize;
    let mut loc_vars = Vec::with_capacity(reader.safe_capacity(sizelocvars, 8));
    for idx in 0..sizelocvars {
        let loc_pos = reader.position();
        let loc_cursor = reader.cursor_offset();
        let varname =
            load_string_53(reader, sizeof_sizet)?.unwrap_or_else(|| LuaString::from_bytes(b"?"));
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

    // 9. Upvalue Names
    let sizeupvalnames = reader.read_i32_le()? as usize;
    let mut upvalue_names = Vec::with_capacity(sizeupvalnames);
    for idx in 0..sizeupvalnames {
        let name = load_string_53(reader, sizeof_sizet)?;

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
