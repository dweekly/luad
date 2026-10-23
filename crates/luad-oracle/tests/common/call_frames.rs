//! Source-generated, structurally validated controls. Never execute crafted chunks.
#![allow(dead_code)]

use luad_core::{Chunk, ConstantValue};
use luad_dialect_lua51::{Opcode51 as Op, RawInstruction51 as Raw};

pub const SOURCE: &str = r#"
local saved = luci.sys.exec
local function child() consume(saved); return saved("fixed") end
os.getenv("PATH")
consume("fixed")
return child
"#;

pub fn string_index(chunk: &Chunk, name: &str) -> u32 {
    chunk.main_proto.constants.iter().position(|k| {
        matches!(&k.value, ConstantValue::ShortString(value) | ConstantValue::LongString(value) if value.raw_bytes == name.as_bytes())
    }).expect("constant in source template") as u32
}

pub fn global(chunk: &Chunk, register: u8, name: &str) -> u32 {
    Raw::encode_iabx(Op::GetGlobal, register, string_index(chunk, name))
}
pub fn literal(chunk: &Chunk, register: u8, name: &str) -> u32 {
    Raw::encode_iabx(Op::LoadK, register, string_index(chunk, name))
}
pub fn path(chunk: &Chunk, register: u8) -> Vec<u32> {
    vec![
        global(chunk, register, "luci"),
        Raw::encode_iabc(
            Op::GetTable,
            register,
            register.into(),
            256 + string_index(chunk, "sys") as u16,
        ),
        Raw::encode_iabc(
            Op::GetTable,
            register,
            register.into(),
            256 + string_index(chunk, "exec") as u16,
        ),
    ]
}
pub fn call(register: u8, arguments: u16, results: u16) -> u32 {
    Raw::encode_iabc(Op::Call, register, arguments, results)
}
pub fn mov(to: u8, from: u8) -> u32 {
    Raw::encode_iabc(Op::Move, to, from.into(), 0)
}
pub fn ret() -> u32 {
    Raw::encode_iabc(Op::Return, 0, 1, 0)
}
pub fn getenv(chunk: &Chunk, base: u8, results: u16) -> Vec<u32> {
    vec![
        global(chunk, base, "os"),
        Raw::encode_iabc(
            Op::GetTable,
            base,
            base.into(),
            256 + string_index(chunk, "getenv") as u16,
        ),
        literal(chunk, base + 1, "PATH"),
        call(base, 2, results),
    ]
}

pub fn craft(build: impl FnOnce(&Chunk) -> Vec<u32>) -> (Vec<u8>, Chunk) {
    let mut bytes = luad_oracle::compile_source_lua51(SOURCE, true)
        .expect("required official Lua 5.1.5 template compiler");
    let mut reader = luad_core::reader::SafeReader::new(&bytes);
    let original = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();
    let words = build(&original);
    let code = &original.main_proto.instructions;
    let start = code.first().unwrap().source.byte_offset;
    let end = code.last().unwrap().source.byte_offset + 4;
    assert_eq!(bytes[9], 4, "declared instruction width");
    let int_width = usize::from(bytes[7]);
    assert!(matches!(int_width, 4 | 8), "explicit supported count width");
    let little = match bytes[6] {
        0 => false,
        1 => true,
        _ => panic!("declared byte order"),
    };
    let count = if little {
        (words.len() as u64).to_le_bytes()
    } else {
        (words.len() as u64).to_be_bytes()
    };
    let count = if little {
        &count[..int_width]
    } else {
        &count[8 - int_width..]
    };
    bytes[start - int_width..start].copy_from_slice(count);
    bytes[start - int_width - 1] = 12; // declared test frame; independent of host pointer width
    let encoded: Vec<u8> = words
        .iter()
        .flat_map(|w| {
            if little {
                w.to_le_bytes()
            } else {
                w.to_be_bytes()
            }
        })
        .collect();
    bytes.splice(start..end, encoded);
    let mut reader = luad_core::reader::SafeReader::new(&bytes);
    let chunk = luad_dialect_lua51::decode_chunk_lua51(&mut reader).unwrap();
    assert!(
        luad_analysis::validate_for_analysis(&chunk).is_ok(),
        "crafted control must be structurally valid"
    );
    (bytes, chunk)
}

pub fn captured(
    results: u16,
    overlaps: bool,
    before_creation: bool,
    literal_value: bool,
    tailcall: bool,
) -> Chunk {
    craft(|c| {
        let saved = if overlaps { 5 } else { 0 };
        let mut words = if literal_value {
            vec![literal(c, saved, "fixed")]
        } else {
            path(c, saved)
        };
        let closure = vec![Raw::encode_iabx(Op::Closure, 8, 0), mov(0, saved)];
        if !before_creation {
            words.extend(&closure);
        }
        if tailcall {
            words.push(global(c, 1, "consume"));
            words.push(Raw::encode_iabc(Op::TailCall, 1, 1, 0));
        } else {
            words.extend(getenv(c, 1, results));
        }
        if before_creation {
            words.extend(&closure);
        }
        words.push(ret());
        words
    })
    .1
}

pub fn captured_iterator(saved: u8, literal_value: bool) -> Chunk {
    craft(|c| {
        let mut w = if literal_value {
            vec![literal(c, saved, "fixed")]
        } else {
            path(c, saved)
        };
        w.extend([
            Raw::encode_iabx(Op::Closure, 9, 0),
            mov(0, saved),
            global(c, 0, "consume"),
            Raw::encode_iabc(Op::TForLoop, 0, 0, 1),
            Raw::encode_iasbx(Op::Jmp, 0, 0),
            ret(),
        ]);
        w
    })
    .1
}

pub fn captured_companion(literal_value: bool) -> Chunk {
    craft(|c| {
        let mut w = if literal_value {
            vec![literal(c, 1, "fixed")]
        } else {
            path(c, 1)
        };
        w.extend([
            Raw::encode_iabx(Op::Closure, 8, 0),
            mov(0, 1),
            Raw::encode_iabc(Op::NewTable, 9, 0, 0),
            literal(c, 10, "fixed"),
            Raw::encode_iabc(Op::SetList, 9, 1, 0),
            call(0, 1, 1),
            ret(),
        ]);
        w
    })
    .1
}

pub fn captured_unreachable(literal_value: bool) -> Chunk {
    craft(|c| {
        let mut w = if literal_value {
            vec![literal(c, 5, "fixed")]
        } else {
            path(c, 5)
        };
        w.extend([Raw::encode_iabx(Op::Closure, 8, 0), mov(0, 5), ret()]);
        w.extend(getenv(c, 1, 1));
        w.push(ret());
        w
    })
    .1
}
