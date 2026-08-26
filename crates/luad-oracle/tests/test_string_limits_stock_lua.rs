//! Table-oriented acceptance test suite for uniform stock-Lua string resource limits.
//!
//! Contract: `docs/NEXT-SPRINT.md`
//! Pinned diagnostics: `L51-STR-001`, `L52-STR-001`, `L53-STR-001`, `L54-STR-001`, `L55-STR-002`.
//!
//! Acceptance matrix:
//! - Lua 5.1: 32-bit and 64-bit `size_t`
//! - Lua 5.2: 32-bit and 64-bit `size_t`
//! - Lua 5.3: Short (1-byte) and `0xFF` extended (32-bit and 64-bit `size_t`) lengths
//! - Lua 5.4: Variable-length integer
//! - Lua 5.5: Variable-length integer and string-table reuse insertion

use luad_core::diagnostic::{Diagnostic, DiagnosticCategory, Severity, Verdict};
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::ConstantValue;
use luad_core::reader::SafeReader;
use luad_oracle::load_precompiled_fixture;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StockTarget {
    Lua51_32Bit,
    Lua51_64Bit,
    Lua52_32Bit,
    Lua52_64Bit,
    Lua53_Short,
    Lua53_Extended32Bit,
    Lua53_Extended64Bit,
    Lua54,
    Lua55,
}

impl StockTarget {
    fn name(&self) -> &'static str {
        match self {
            Self::Lua51_32Bit => "Lua 5.1 (32-bit size_t)",
            Self::Lua51_64Bit => "Lua 5.1 (64-bit size_t)",
            Self::Lua52_32Bit => "Lua 5.2 (32-bit size_t)",
            Self::Lua52_64Bit => "Lua 5.2 (64-bit size_t)",
            Self::Lua53_Short => "Lua 5.3 (short 1-byte length)",
            Self::Lua53_Extended32Bit => "Lua 5.3 (0xff extended 32-bit length)",
            Self::Lua53_Extended64Bit => "Lua 5.3 (0xff extended 64-bit length)",
            Self::Lua54 => "Lua 5.4 (varint length)",
            Self::Lua55 => "Lua 5.5 (varint length + reuse)",
        }
    }

    fn expected_diagnostic_code(&self) -> &'static str {
        match self {
            Self::Lua51_32Bit | Self::Lua51_64Bit => "L51-STR-001",
            Self::Lua52_32Bit | Self::Lua52_64Bit => "L52-STR-001",
            Self::Lua53_Short | Self::Lua53_Extended32Bit | Self::Lua53_Extended64Bit => {
                "L53-STR-001"
            }
            Self::Lua54 => "L54-STR-001",
            Self::Lua55 => "L55-STR-002",
        }
    }

    #[allow(clippy::result_large_err)]
    fn decode(&self, reader: &mut SafeReader) -> Result<luad_core::model::Chunk, Diagnostic> {
        match self {
            Self::Lua51_32Bit | Self::Lua51_64Bit => luad_dialect_lua51::decode_chunk_lua51(reader),
            Self::Lua52_32Bit | Self::Lua52_64Bit => luad_dialect_lua52::decode_chunk_lua52(reader),
            Self::Lua53_Short | Self::Lua53_Extended32Bit | Self::Lua53_Extended64Bit => {
                luad_dialect_lua53::decode_chunk_lua53(reader)
            }
            Self::Lua54 => luad_dialect_lua54::decode_chunk_lua54(reader),
            Self::Lua55 => luad_dialect_lua55::decode_chunk_lua55(reader),
        }
    }

    fn build_chunk_with_constant_string(&self, string_bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Lua51_32Bit => build_lua51_chunk(4, None, &[string_bytes], &[], &[]),
            Self::Lua51_64Bit => build_lua51_chunk(8, None, &[string_bytes], &[], &[]),
            Self::Lua52_32Bit => build_lua52_chunk(4, None, &[string_bytes], &[], &[]),
            Self::Lua52_64Bit => build_lua52_chunk(8, None, &[string_bytes], &[], &[]),
            Self::Lua53_Short => build_lua53_chunk(8, false, None, &[string_bytes], &[], &[]),
            Self::Lua53_Extended32Bit => {
                build_lua53_chunk(4, true, None, &[string_bytes], &[], &[])
            }
            Self::Lua53_Extended64Bit => {
                build_lua53_chunk(8, true, None, &[string_bytes], &[], &[])
            }
            Self::Lua54 => build_lua54_chunk(None, &[string_bytes], &[], &[]),
            Self::Lua55 => build_lua55_chunk(None, &[Lua55StringSpec::New(string_bytes)], &[], &[]),
        }
    }

    fn build_chunk_declared_over_limit_absent_payload(
        &self,
        declared_content_len: usize,
    ) -> Vec<u8> {
        match self {
            Self::Lua51_32Bit => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x51\x00\x01\x04\x04\x04\x08\x00");
                buf.extend_from_slice(&0u32.to_le_bytes()); // source null
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.push(0);
                buf.push(2);
                buf.extend_from_slice(&0i32.to_le_bytes()); // sizecode = 0
                buf.extend_from_slice(&1i32.to_le_bytes()); // sizek = 1
                buf.push(4); // tag 4 = string
                let size = (declared_content_len + 1) as u32;
                buf.extend_from_slice(&size.to_le_bytes());
                // ABSENT PAYLOAD: stream ends here
                buf
            }
            Self::Lua51_64Bit => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00");
                buf.extend_from_slice(&0u64.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.push(0);
                buf.push(2);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&1i32.to_le_bytes());
                buf.push(4);
                let size = (declared_content_len + 1) as u64;
                buf.extend_from_slice(&size.to_le_bytes());
                buf
            }
            Self::Lua52_32Bit => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x52\x00\x01\x04\x04\x04\x08\x00\x19\x93\r\n\x1a\n");
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.push(2);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&1i32.to_le_bytes());
                buf.push(4);
                let size = (declared_content_len + 1) as u32;
                buf.extend_from_slice(&size.to_le_bytes());
                buf
            }
            Self::Lua52_64Bit => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x52\x00\x01\x04\x08\x04\x08\x00\x19\x93\r\n\x1a\n");
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.push(2);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&1i32.to_le_bytes());
                buf.push(4);
                let size = (declared_content_len + 1) as u64;
                buf.extend_from_slice(&size.to_le_bytes());
                buf
            }
            Self::Lua53_Short => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x53\x00\x19\x93\r\n\x1a\n\x04\x08\x04\x08\x08");
                buf.extend_from_slice(&0x5678i64.to_le_bytes());
                buf.extend_from_slice(&370.5f64.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.push(2);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&1i32.to_le_bytes());
                buf.push(4);
                let size = (declared_content_len + 1) as u8;
                buf.push(size);
                buf
            }
            Self::Lua53_Extended32Bit => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x53\x00\x19\x93\r\n\x1a\n\x04\x04\x04\x08\x08");
                buf.extend_from_slice(&0x5678i64.to_le_bytes());
                buf.extend_from_slice(&370.5f64.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.push(2);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&1i32.to_le_bytes());
                buf.push(4);
                buf.push(0xFF);
                let size = (declared_content_len + 1) as u32;
                buf.extend_from_slice(&size.to_le_bytes());
                buf
            }
            Self::Lua53_Extended64Bit => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x53\x00\x19\x93\r\n\x1a\n\x04\x08\x04\x08\x08");
                buf.extend_from_slice(&0x5678i64.to_le_bytes());
                buf.extend_from_slice(&370.5f64.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.push(0);
                buf.push(0);
                buf.push(2);
                buf.extend_from_slice(&0i32.to_le_bytes());
                buf.extend_from_slice(&1i32.to_le_bytes());
                buf.push(4);
                buf.push(0xFF);
                let size = (declared_content_len + 1) as u64;
                buf.extend_from_slice(&size.to_le_bytes());
                buf
            }
            Self::Lua54 => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x54\x00\x19\x93\r\n\x1a\n\x04\x08\x08");
                buf.extend_from_slice(&0x5678i64.to_le_bytes());
                buf.extend_from_slice(&370.5f64.to_le_bytes());
                buf.push(0);
                write_string_54(&mut buf, None);
                write_varint_54(&mut buf, 0);
                write_varint_54(&mut buf, 0);
                buf.push(0);
                buf.push(0);
                buf.push(2);
                write_varint_54(&mut buf, 0);
                write_varint_54(&mut buf, 1);
                buf.push(4);
                let size = (declared_content_len + 1) as u64;
                write_varint_54(&mut buf, size);
                buf
            }
            Self::Lua55 => {
                let mut buf = Vec::new();
                buf.extend_from_slice(b"\x1bLua\x55\x00\x19\x93\r\n\x1a\n\x04");
                buf.extend_from_slice(&0x5678i32.to_le_bytes());
                buf.push(0x04);
                buf.extend_from_slice(&0x5678i32.to_le_bytes());
                buf.push(0x08);
                buf.extend_from_slice(&0x5678i64.to_le_bytes());
                buf.push(0x08);
                buf.extend_from_slice(&370.5f64.to_le_bytes());
                buf.push(0);
                write_varint_55(&mut buf, 0);
                write_varint_55(&mut buf, 0);
                buf.push(0);
                buf.push(0);
                buf.push(2);
                write_varint_55(&mut buf, 0);
                let rem = buf.len() % 4;
                if rem != 0 {
                    buf.extend(std::iter::repeat_n(0, 4 - rem));
                }
                write_varint_55(&mut buf, 1);
                buf.push(4);
                let size = (declared_content_len + 1) as u64;
                write_varint_55(&mut buf, size);
                buf
            }
        }
    }
}

const ALL_TARGETS: [StockTarget; 9] = [
    StockTarget::Lua51_32Bit,
    StockTarget::Lua51_64Bit,
    StockTarget::Lua52_32Bit,
    StockTarget::Lua52_64Bit,
    StockTarget::Lua53_Short,
    StockTarget::Lua53_Extended32Bit,
    StockTarget::Lua53_Extended64Bit,
    StockTarget::Lua54,
    StockTarget::Lua55,
];

fn build_lua51_chunk(
    sizeof_sizet: u8,
    source_name: Option<&[u8]>,
    constants: &[&[u8]],
    loc_vars: &[&[u8]],
    upval_names: &[&[u8]],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\x1bLua");
    buf.push(0x51);
    buf.push(0x00);
    buf.push(0x01);
    buf.push(0x04);
    buf.push(sizeof_sizet);
    buf.push(0x04);
    buf.push(0x08);
    buf.push(0x00);

    write_string_51(&mut buf, sizeof_sizet, source_name);

    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.push(upval_names.len().min(255) as u8);
    buf.push(0);
    buf.push(0);
    buf.push(2);

    buf.extend_from_slice(&0i32.to_le_bytes());

    buf.extend_from_slice(&(constants.len() as i32).to_le_bytes());
    for s in constants {
        buf.push(4);
        write_string_51(&mut buf, sizeof_sizet, Some(s));
    }

    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());

    buf.extend_from_slice(&(loc_vars.len() as i32).to_le_bytes());
    for var in loc_vars {
        write_string_51(&mut buf, sizeof_sizet, Some(var));
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    buf.extend_from_slice(&(upval_names.len() as i32).to_le_bytes());
    for u in upval_names {
        write_string_51(&mut buf, sizeof_sizet, Some(u));
    }

    buf
}

fn write_string_51(buf: &mut Vec<u8>, sizeof_sizet: u8, s: Option<&[u8]>) {
    match s {
        None => {
            if sizeof_sizet == 4 {
                buf.extend_from_slice(&0u32.to_le_bytes());
            } else {
                buf.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        Some(bytes) => {
            let size = bytes.len() + 1;
            if sizeof_sizet == 4 {
                buf.extend_from_slice(&(size as u32).to_le_bytes());
            } else {
                buf.extend_from_slice(&(size as u64).to_le_bytes());
            }
            buf.extend_from_slice(bytes);
            buf.push(0);
        }
    }
}

fn build_lua52_chunk(
    sizeof_sizet: u8,
    source_name: Option<&[u8]>,
    constants: &[&[u8]],
    loc_vars: &[&[u8]],
    upval_names: &[&[u8]],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\x1bLua");
    buf.push(0x52);
    buf.push(0x00);
    buf.push(0x01);
    buf.push(0x04);
    buf.push(sizeof_sizet);
    buf.push(0x04);
    buf.push(0x08);
    buf.push(0x00);
    buf.extend_from_slice(b"\x19\x93\r\n\x1a\n");

    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.push(0);
    buf.push(0);
    buf.push(2);

    buf.extend_from_slice(&0i32.to_le_bytes());

    buf.extend_from_slice(&(constants.len() as i32).to_le_bytes());
    for s in constants {
        buf.push(4);
        write_string_51(&mut buf, sizeof_sizet, Some(s));
    }

    buf.extend_from_slice(&0i32.to_le_bytes());

    buf.extend_from_slice(&(upval_names.len() as i32).to_le_bytes());
    for _ in upval_names {
        buf.push(0);
        buf.push(0);
    }

    write_string_51(&mut buf, sizeof_sizet, source_name);

    buf.extend_from_slice(&0i32.to_le_bytes());

    buf.extend_from_slice(&(loc_vars.len() as i32).to_le_bytes());
    for var in loc_vars {
        write_string_51(&mut buf, sizeof_sizet, Some(var));
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    buf.extend_from_slice(&(upval_names.len() as i32).to_le_bytes());
    for u in upval_names {
        write_string_51(&mut buf, sizeof_sizet, Some(u));
    }

    buf
}

fn build_lua53_chunk(
    sizeof_sizet: u8,
    force_extended: bool,
    source_name: Option<&[u8]>,
    constants: &[&[u8]],
    loc_vars: &[&[u8]],
    upval_names: &[&[u8]],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\x1bLua");
    buf.push(0x53);
    buf.push(0x00);
    buf.extend_from_slice(b"\x19\x93\r\n\x1a\n");
    buf.push(0x04);
    buf.push(sizeof_sizet);
    buf.push(0x04);
    buf.push(0x08);
    buf.push(0x08);
    buf.extend_from_slice(&0x5678i64.to_le_bytes());
    buf.extend_from_slice(&370.5f64.to_le_bytes());

    buf.push(0);

    write_string_53(&mut buf, sizeof_sizet, force_extended, source_name);

    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.push(0);
    buf.push(0);
    buf.push(2);

    buf.extend_from_slice(&0i32.to_le_bytes());

    buf.extend_from_slice(&(constants.len() as i32).to_le_bytes());
    for s in constants {
        buf.push(4);
        write_string_53(&mut buf, sizeof_sizet, force_extended, Some(s));
    }

    buf.extend_from_slice(&(upval_names.len() as i32).to_le_bytes());
    for _ in upval_names {
        buf.push(0);
        buf.push(0);
    }

    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());

    buf.extend_from_slice(&(loc_vars.len() as i32).to_le_bytes());
    for var in loc_vars {
        write_string_53(&mut buf, sizeof_sizet, force_extended, Some(var));
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
    }

    buf.extend_from_slice(&(upval_names.len() as i32).to_le_bytes());
    for u in upval_names {
        write_string_53(&mut buf, sizeof_sizet, force_extended, Some(u));
    }

    buf
}

fn write_string_53(buf: &mut Vec<u8>, sizeof_sizet: u8, force_extended: bool, s: Option<&[u8]>) {
    match s {
        None => buf.push(0),
        Some(bytes) => {
            let size = bytes.len() + 1;
            if force_extended || size >= 0xFF {
                buf.push(0xFF);
                if sizeof_sizet == 4 {
                    buf.extend_from_slice(&(size as u32).to_le_bytes());
                } else {
                    buf.extend_from_slice(&(size as u64).to_le_bytes());
                }
            } else {
                buf.push(size as u8);
            }
            buf.extend_from_slice(bytes);
        }
    }
}

fn build_lua54_chunk(
    source_name: Option<&[u8]>,
    constants: &[&[u8]],
    loc_vars: &[&[u8]],
    upval_names: &[&[u8]],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\x1bLua");
    buf.push(0x54);
    buf.push(0x00);
    buf.extend_from_slice(b"\x19\x93\r\n\x1a\n");
    buf.push(0x04);
    buf.push(0x08);
    buf.push(0x08);
    buf.extend_from_slice(&0x5678i64.to_le_bytes());
    buf.extend_from_slice(&370.5f64.to_le_bytes());

    buf.push(0);

    write_string_54(&mut buf, source_name);

    write_varint_54(&mut buf, 0);
    write_varint_54(&mut buf, 0);
    buf.push(0);
    buf.push(0);
    buf.push(2);

    write_varint_54(&mut buf, 0);

    write_varint_54(&mut buf, constants.len() as u64);
    for s in constants {
        buf.push(4);
        write_string_54(&mut buf, Some(s));
    }

    write_varint_54(&mut buf, upval_names.len() as u64);
    for _ in upval_names {
        buf.push(0);
        buf.push(0);
        buf.push(0);
    }

    write_varint_54(&mut buf, 0);
    write_varint_54(&mut buf, 0);
    write_varint_54(&mut buf, 0);

    write_varint_54(&mut buf, loc_vars.len() as u64);
    for var in loc_vars {
        write_string_54(&mut buf, Some(var));
        write_varint_54(&mut buf, 0);
        write_varint_54(&mut buf, 0);
    }

    write_varint_54(&mut buf, upval_names.len() as u64);
    for u in upval_names {
        write_string_54(&mut buf, Some(u));
    }

    buf
}

fn write_varint_54(buf: &mut Vec<u8>, val: u64) {
    luad_dialect_lua54::chunk::write_varint_lua54(buf, val);
}

fn write_string_54(buf: &mut Vec<u8>, s: Option<&[u8]>) {
    luad_dialect_lua54::chunk::write_string_lua54(buf, s);
}

#[derive(Clone, Copy, Debug)]
enum Lua55StringSpec<'a> {
    Null,
    New(&'a [u8]),
    Reuse(u64),
}

fn build_lua55_chunk(
    source_name: Option<Lua55StringSpec>,
    constants: &[Lua55StringSpec],
    loc_vars: &[Lua55StringSpec],
    upval_names: &[Lua55StringSpec],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"\x1bLua");
    buf.push(0x55);
    buf.push(0x00);
    buf.extend_from_slice(b"\x19\x93\r\n\x1a\n");
    buf.push(0x04);
    buf.extend_from_slice(&0x5678i32.to_le_bytes());
    buf.push(0x04);
    buf.extend_from_slice(&0x5678i32.to_le_bytes());
    buf.push(0x08);
    buf.extend_from_slice(&0x5678i64.to_le_bytes());
    buf.push(0x08);
    buf.extend_from_slice(&370.5f64.to_le_bytes());

    buf.push(0);

    write_varint_55(&mut buf, 0);
    write_varint_55(&mut buf, 0);
    buf.push(0);
    buf.push(0);
    buf.push(2);

    write_varint_55(&mut buf, 0);
    let rem = buf.len() % 4;
    if rem != 0 {
        buf.extend(std::iter::repeat_n(0, 4 - rem));
    }

    write_varint_55(&mut buf, constants.len() as u64);
    for spec in constants {
        buf.push(4);
        write_string_55(&mut buf, spec);
    }

    write_varint_55(&mut buf, upval_names.len() as u64);
    for _ in upval_names {
        buf.push(0);
        buf.push(0);
        buf.push(0);
    }

    write_varint_55(&mut buf, 0);

    write_string_55(&mut buf, &source_name.unwrap_or(Lua55StringSpec::Null));

    write_varint_55(&mut buf, 0);
    write_varint_55(&mut buf, 0);

    write_varint_55(&mut buf, loc_vars.len() as u64);
    for spec in loc_vars {
        write_string_55(&mut buf, spec);
        write_varint_55(&mut buf, 0);
        write_varint_55(&mut buf, 0);
    }

    write_varint_55(&mut buf, upval_names.len() as u64);
    for spec in upval_names {
        write_string_55(&mut buf, spec);
    }

    buf
}

fn write_varint_55(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let mut b = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if val == 0 {
            break;
        }
    }
}

fn write_string_55(buf: &mut Vec<u8>, spec: &Lua55StringSpec) {
    match spec {
        Lua55StringSpec::Null => {
            write_varint_55(buf, 0);
            write_varint_55(buf, 0);
        }
        Lua55StringSpec::Reuse(idx) => {
            write_varint_55(buf, 0);
            write_varint_55(buf, *idx);
        }
        Lua55StringSpec::New(bytes) => {
            write_varint_55(buf, (bytes.len() + 1) as u64);
            buf.extend_from_slice(bytes);
            buf.push(0);
        }
    }
}

// ---------------------------------------------------------------------------
// Matrix validation evaluator
// ---------------------------------------------------------------------------

fn require_limit_rejection(
    target: StockTarget,
    result: Result<(), Diagnostic>,
) -> Result<(), String> {
    let diagnostic = result.map_or_else(Ok, |()| {
        Err(format!(
            "{}: expected the declared string to be rejected",
            target.name()
        ))
    })?;

    if diagnostic.code != target.expected_diagnostic_code() {
        return Err(format!(
            "{}: expected code {}, got {}",
            target.name(),
            target.expected_diagnostic_code(),
            diagnostic.code
        ));
    }
    if diagnostic.severity != Severity::Error {
        return Err(format!(
            "{}: expected Severity::Error, got {:?}",
            target.name(),
            diagnostic.severity
        ));
    }
    if diagnostic.category != DiagnosticCategory::Parse {
        return Err(format!(
            "{}: expected DiagnosticCategory::Parse, got {:?}",
            target.name(),
            diagnostic.category
        ));
    }
    Ok(())
}

fn evaluate_target_string_limits(target: StockTarget) -> Result<(), String> {
    let limit = 16usize;
    let limits = ResourceLimits {
        max_string_bytes: limit,
        ..Default::default()
    };

    // 1. Exactly at limit: success
    let exact_bytes = vec![b'x'; limit];
    let exact_chunk_bytes = target.build_chunk_with_constant_string(&exact_bytes);
    let mut reader =
        SafeReader::with_options(&exact_chunk_bytes, 0, limits.clone(), ParseMode::Strict);
    let chunk = target
        .decode(&mut reader)
        .map_err(|e| format!("{}: exact limit parse failed: {e:?}", target.name()))?;
    assert_eq!(chunk.verdict, Verdict::ValidForParser);
    if let ConstantValue::ShortString(s) = &chunk.main_proto.constants[0].value {
        assert_eq!(s.raw_bytes, exact_bytes);
    } else {
        return Err(format!("{}: expected ShortString constant", target.name()));
    }

    // Zero limit with empty string: success
    let zero_limits = ResourceLimits {
        max_string_bytes: 0,
        ..Default::default()
    };
    let empty_chunk_bytes = target.build_chunk_with_constant_string(b"");
    let mut reader_zero =
        SafeReader::with_options(&empty_chunk_bytes, 0, zero_limits, ParseMode::Strict);
    let chunk_zero = target.decode(&mut reader_zero).map_err(|e| {
        format!(
            "{}: zero-limit empty string parse failed: {e:?}",
            target.name()
        )
    })?;
    assert_eq!(chunk_zero.verdict, Verdict::ValidForParser);

    // 2. One byte over limit: pinned diagnostic error
    let over_bytes = vec![b'y'; limit + 1];
    let over_chunk_bytes = target.build_chunk_with_constant_string(&over_bytes);
    let mut reader_over =
        SafeReader::with_options(&over_chunk_bytes, 0, limits.clone(), ParseMode::Strict);
    require_limit_rejection(target, target.decode(&mut reader_over).map(|_| ()))?;

    // 3. Declared over limit with absent payload: limit diagnostic rather than EOF
    let absent_chunk_bytes = target.build_chunk_declared_over_limit_absent_payload(limit + 10);
    let mut reader_absent =
        SafeReader::with_options(&absent_chunk_bytes, 0, limits, ParseMode::Strict);
    require_limit_rejection(target, target.decode(&mut reader_absent).map(|_| ()))?;

    Ok(())
}

fn evaluate_complete_string_limits_suite(targets: &[StockTarget]) -> Result<(), String> {
    if targets.len() != ALL_TARGETS.len() {
        return Err(format!(
            "Suite requires {} targets, got {}",
            ALL_TARGETS.len(),
            targets.len()
        ));
    }
    for required in &ALL_TARGETS {
        if !targets.contains(required) {
            return Err(format!(
                "Suite missing required target: {}",
                required.name()
            ));
        }
    }
    for target in targets {
        evaluate_target_string_limits(*target)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Table-driven acceptance tests
// ---------------------------------------------------------------------------

#[test]
fn test_string_limits_exact_at_limit_accepted() {
    for target in &ALL_TARGETS {
        let limit = 20usize;
        let limits = ResourceLimits {
            max_string_bytes: limit,
            ..Default::default()
        };

        let content = vec![b'A'; limit];
        let bytes = target.build_chunk_with_constant_string(&content);
        let mut reader = SafeReader::with_options(&bytes, 0, limits, ParseMode::Strict);
        let chunk = target
            .decode(&mut reader)
            .unwrap_or_else(|e| panic!("{}: exactly-at-limit failed: {e:?}", target.name()));
        assert_eq!(chunk.verdict, Verdict::ValidForParser);
        assert!(chunk.diagnostics.is_empty());
    }
}

#[test]
fn test_string_limits_one_byte_over_rejected_with_pinned_diagnostic() {
    for target in &ALL_TARGETS {
        let limit = 8usize;
        let limits = ResourceLimits {
            max_string_bytes: limit,
            ..Default::default()
        };

        let content = vec![b'B'; limit + 1];
        let bytes = target.build_chunk_with_constant_string(&content);
        let mut reader = SafeReader::with_options(&bytes, 0, limits, ParseMode::Strict);
        let err = target
            .decode(&mut reader)
            .expect_err(&format!("{}: one-byte-over must fail", target.name()));
        assert_eq!(
            err.code,
            target.expected_diagnostic_code(),
            "target: {}",
            target.name()
        );
        assert_eq!(err.severity, Severity::Error);
        assert_eq!(err.category, DiagnosticCategory::Parse);
        assert!(err.message.contains(&format!(
            "String length {} exceeds limit of {limit} bytes",
            limit + 1
        )));
    }
}

#[test]
fn test_string_limits_declared_over_limit_absent_payload_returns_limit_diagnostic_not_eof() {
    for target in &ALL_TARGETS {
        let limit = 12usize;
        let limits = ResourceLimits {
            max_string_bytes: limit,
            ..Default::default()
        };

        let bytes = target.build_chunk_declared_over_limit_absent_payload(limit + 5);
        let mut reader = SafeReader::with_options(&bytes, 0, limits, ParseMode::Strict);
        let err = target.decode(&mut reader).expect_err(&format!(
            "{}: declared over-limit absent payload must fail",
            target.name()
        ));
        assert_ne!(
            err.code,
            "CORE-TRUNC-001",
            "{}: must not mask violated limit with unexpected EOF",
            target.name()
        );
        assert_eq!(
            err.code,
            target.expected_diagnostic_code(),
            "{}: must report limit diagnostic",
            target.name()
        );
    }
}

#[test]
fn test_string_limits_all_string_bearing_fields_covered() {
    let limit = 4usize;
    let limits = ResourceLimits {
        max_string_bytes: limit,
        ..Default::default()
    };
    let over = b"toolongstring";

    // 1. Lua 5.1
    // Source name
    let b = build_lua51_chunk(8, Some(over), &[], &[], &[]);
    let err = luad_dialect_lua51::decode_chunk_lua51(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L51-STR-001");

    // Constants
    let b = build_lua51_chunk(8, None, &[over], &[], &[]);
    let err = luad_dialect_lua51::decode_chunk_lua51(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L51-STR-001");

    // Local variable names
    let b = build_lua51_chunk(8, None, &[], &[over], &[]);
    let err = luad_dialect_lua51::decode_chunk_lua51(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L51-STR-001");

    // Upvalue names
    let b = build_lua51_chunk(8, None, &[], &[], &[over]);
    let err = luad_dialect_lua51::decode_chunk_lua51(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L51-STR-001");

    // 2. Lua 5.2
    let b = build_lua52_chunk(8, Some(over), &[], &[], &[]);
    let err = luad_dialect_lua52::decode_chunk_lua52(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L52-STR-001");

    let b = build_lua52_chunk(8, None, &[over], &[], &[]);
    let err = luad_dialect_lua52::decode_chunk_lua52(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L52-STR-001");

    let b = build_lua52_chunk(8, None, &[], &[over], &[]);
    let err = luad_dialect_lua52::decode_chunk_lua52(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L52-STR-001");

    let b = build_lua52_chunk(8, None, &[], &[], &[over]);
    let err = luad_dialect_lua52::decode_chunk_lua52(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L52-STR-001");

    // 3. Lua 5.3
    let b = build_lua53_chunk(8, false, Some(over), &[], &[], &[]);
    let err = luad_dialect_lua53::decode_chunk_lua53(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L53-STR-001");

    let b = build_lua53_chunk(8, false, None, &[over], &[], &[]);
    let err = luad_dialect_lua53::decode_chunk_lua53(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L53-STR-001");

    let b = build_lua53_chunk(8, false, None, &[], &[over], &[]);
    let err = luad_dialect_lua53::decode_chunk_lua53(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L53-STR-001");

    let b = build_lua53_chunk(8, false, None, &[], &[], &[over]);
    let err = luad_dialect_lua53::decode_chunk_lua53(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L53-STR-001");

    // 4. Lua 5.4
    let b = build_lua54_chunk(Some(over), &[], &[], &[]);
    let err = luad_dialect_lua54::decode_chunk_lua54(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L54-STR-001");

    let b = build_lua54_chunk(None, &[over], &[], &[]);
    let err = luad_dialect_lua54::decode_chunk_lua54(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L54-STR-001");

    let b = build_lua54_chunk(None, &[], &[over], &[]);
    let err = luad_dialect_lua54::decode_chunk_lua54(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L54-STR-001");

    let b = build_lua54_chunk(None, &[], &[], &[over]);
    let err = luad_dialect_lua54::decode_chunk_lua54(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L54-STR-001");

    // 5. Lua 5.5
    let b = build_lua55_chunk(Some(Lua55StringSpec::New(over)), &[], &[], &[]);
    let err = luad_dialect_lua55::decode_chunk_lua55(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L55-STR-002");

    let b = build_lua55_chunk(None, &[Lua55StringSpec::New(over)], &[], &[]);
    let err = luad_dialect_lua55::decode_chunk_lua55(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L55-STR-002");

    let b = build_lua55_chunk(None, &[], &[Lua55StringSpec::New(over)], &[]);
    let err = luad_dialect_lua55::decode_chunk_lua55(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L55-STR-002");

    let b = build_lua55_chunk(None, &[], &[], &[Lua55StringSpec::New(over)]);
    let err = luad_dialect_lua55::decode_chunk_lua55(&mut SafeReader::with_options(
        &b,
        0,
        limits.clone(),
        ParseMode::Strict,
    ))
    .unwrap_err();
    assert_eq!(err.code, "L55-STR-002");
}

#[test]
fn test_lua55_string_reuse_table_invariants() {
    let limit = 8usize;
    let limits = ResourceLimits {
        max_string_bytes: limit,
        ..Default::default()
    };

    // Valid string definition followed by reuse
    let valid_spec = [
        Lua55StringSpec::New(b"valid"),
        Lua55StringSpec::Reuse(1), // references "valid"
    ];
    let bytes = build_lua55_chunk(None, &valid_spec, &[], &[]);
    let mut reader = SafeReader::with_options(&bytes, 0, limits.clone(), ParseMode::Strict);
    let chunk = luad_dialect_lua55::decode_chunk_lua55(&mut reader)
        .expect("Valid string followed by reuse must decode cleanly");
    assert_eq!(chunk.main_proto.constants.len(), 2);
    if let ConstantValue::ShortString(s0) = &chunk.main_proto.constants[0].value {
        assert_eq!(s0.raw_bytes, b"valid");
    } else {
        panic!("Expected ShortString");
    }
    if let ConstantValue::ShortString(s1) = &chunk.main_proto.constants[1].value {
        assert_eq!(s1.raw_bytes, b"valid");
    } else {
        panic!("Expected ShortString");
    }

    // Invalid reuse index returns L55-STR-001
    let invalid_reuse = [Lua55StringSpec::Reuse(99)];
    let bytes = build_lua55_chunk(None, &invalid_reuse, &[], &[]);
    let mut reader = SafeReader::with_options(&bytes, 0, limits, ParseMode::Strict);
    let err = luad_dialect_lua55::decode_chunk_lua55(&mut reader)
        .expect_err("Invalid reuse index must fail");
    assert_eq!(err.code, "L55-STR-001");
}

#[test]
fn test_default_limits_stock_lua_fixtures() {
    let dialect_fixtures = [
        (
            "lua51",
            &["hello", "control_flow", "closures", "tables", "numerics"][..],
        ),
        (
            "lua52",
            &["hello", "control_flow", "closures", "tables", "numerics"][..],
        ),
        (
            "lua53",
            &["hello", "control_flow", "closures", "tables", "numerics"][..],
        ),
        (
            "lua54",
            &["hello", "control_flow", "closures", "tables", "numerics"][..],
        ),
        (
            "lua55",
            &["hello", "control_flow", "closures", "tables", "numerics"][..],
        ),
    ];

    for (dialect, fixtures) in dialect_fixtures {
        for &fixture in fixtures {
            for strip in [false, true] {
                let raw = load_precompiled_fixture(dialect, fixture, strip).unwrap_or_else(|e| {
                    panic!("Failed to load precompiled fixture {dialect}/{fixture}: {e}")
                });
                let mut reader = SafeReader::new(&raw);
                let chunk = match dialect {
                    "lua51" => luad_dialect_lua51::decode_chunk_lua51(&mut reader),
                    "lua52" => luad_dialect_lua52::decode_chunk_lua52(&mut reader),
                    "lua53" => luad_dialect_lua53::decode_chunk_lua53(&mut reader),
                    "lua54" => luad_dialect_lua54::decode_chunk_lua54(&mut reader),
                    "lua55" => luad_dialect_lua55::decode_chunk_lua55(&mut reader),
                    _ => unreachable!(),
                }
                .unwrap_or_else(|e| {
                    panic!(
                        "Default-limit parsing failed for fixture {dialect}/{fixture} (strip={strip}): {e:?}"
                    )
                });

                assert_eq!(chunk.verdict, Verdict::ValidForParser);
                assert_eq!(chunk.byte_length, raw.len());
            }
        }
    }
}

#[test]
fn test_killer_mutation_bypassed_dialect_limit_check_rejected() {
    // 1. The complete, unmutated suite must be accepted by the matrix evaluator
    assert!(evaluate_complete_string_limits_suite(&ALL_TARGETS).is_ok());

    // 2. Killer mutation: suite with missing target encoding is rejected
    let partial = &ALL_TARGETS[0..8];
    let res = evaluate_complete_string_limits_suite(partial);
    assert!(
        res.is_err(),
        "Evaluator must reject a matrix that omits required targets"
    );

    let target = StockTarget::Lua51_64Bit;
    let limits = ResourceLimits {
        max_string_bytes: 4,
        ..Default::default()
    };
    let bytes = target.build_chunk_with_constant_string(b"oversized");
    let mut reader = SafeReader::with_options(&bytes, 0, limits, ParseMode::Strict);
    let observed = target.decode(&mut reader).map(|_| ());
    assert!(require_limit_rejection(target, observed.clone()).is_ok());

    // 3. Killer mutation: accepting an over-limit observation is rejected by the same
    // comparator used for the complete matrix.
    let res = require_limit_rejection(target, Ok(()));
    assert!(
        res.is_err(),
        "Evaluator must reject a dialect that accepts over-limit string"
    );

    // 4. Killer mutation: replacing the observed code with EOF is rejected.
    let mut eof = observed
        .clone()
        .expect_err("real over-limit decode must fail");
    eof.code = "CORE-TRUNC-001".to_string();
    let res = require_limit_rejection(target, Err(eof));
    assert!(
        res.is_err(),
        "Evaluator must reject EOF diagnostic on declared-over-limit absent payload"
    );

    // 5. Killer mutation: replacing the observed code with another dialect's code is
    // rejected.
    let mut wrong = observed.expect_err("real over-limit decode must fail");
    wrong.code = "L54-STR-001".to_string();
    let res = require_limit_rejection(target, Err(wrong));
    assert!(
        res.is_err(),
        "Evaluator must reject incorrect diagnostic code for dialect"
    );
}
