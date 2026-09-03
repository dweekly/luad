//! Stock Lua 5.1 integral-number layouts: a header whose integral flag is 1 declares
//! `lua_Number` as an integer type, so every LUA_TNUMBER constant decodes as a
//! two's-complement integer of the declared width, not as an IEEE-754 float.
//!
//! No official compiler in the pinned set emits this layout, so each case is a
//! hand-built chunk that runs through the public CLI.

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

/// Encode one Lua 5.1 instruction in the stock layout from `lopcodes.h` (Lua
/// 5.1.5): opcode in bits 0-5, A in bits 6-13, C in bits 14-22, B in bits 23-31.
fn lua51_abc(op: u32, a: u32, b: u32, c: u32) -> u32 {
    op | (a << 6) | (c << 14) | (b << 23)
}

/// Encode one Lua 5.1 `iABx` instruction: opcode in bits 0-5, A in bits 6-13,
/// Bx in bits 14-31 (`lopcodes.h`, Lua 5.1.5).
fn lua51_abx(op: u32, a: u32, bx: u32) -> u32 {
    op | (a << 6) | (bx << 14)
}

/// A stock little-endian Lua 5.1 chunk holding the single call `f(K1)`, where `K1`
/// is one LUA_TNUMBER constant made of `number_bytes`. The header declares
/// `sizeof(lua_Number) == number_bytes.len()` and the given integral flag.
fn lua51_chunk_with_number(integral_flag: u8, number_bytes: &[u8]) -> Vec<u8> {
    // Opcode numbers from `lopcodes.h`, Lua 5.1.5.
    const OP_LOADK: u32 = 1;
    const OP_GETGLOBAL: u32 = 5;
    const OP_CALL: u32 = 28;
    const OP_RETURN: u32 = 30;
    // Constant tags from `lua.h`, Lua 5.1.5.
    const LUA_TNUMBER: u8 = 3;
    const LUA_TSTRING: u8 = 4;
    // `VARARG_ISVARARG` from `lobject.h`, Lua 5.1.5: every main chunk is vararg.
    const VARARG_ISVARARG: u8 = 2;

    let number_size = u8::try_from(number_bytes.len()).expect("number width fits a byte");
    assert!(
        number_size == 4 || number_size == 8,
        "Lua 5.1 accepts only 4- or 8-byte numbers"
    );

    let mut out = Vec::new();
    out.extend_from_slice(b"\x1bLua");
    // version 5.1, format 0, little-endian, int 4, size_t 8, Instruction 4,
    // lua_Number width, integral flag.
    out.extend_from_slice(&[0x51, 0, 1, 4, 8, 4, number_size, integral_flag]);
    out.extend_from_slice(&0u64.to_le_bytes()); // empty source name
    out.extend_from_slice(&0u32.to_le_bytes()); // linedefined
    out.extend_from_slice(&0u32.to_le_bytes()); // lastlinedefined
    out.extend_from_slice(&[0, 0, VARARG_ISVARARG, 2]); // nups, numparams, is_vararg, maxstacksize
    let code = [
        lua51_abx(OP_GETGLOBAL, 0, 0),
        lua51_abx(OP_LOADK, 1, 1),
        lua51_abc(OP_CALL, 0, 2, 1),
        lua51_abc(OP_RETURN, 0, 1, 0),
    ];
    out.extend_from_slice(&(code.len() as u32).to_le_bytes());
    for word in code {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out.extend_from_slice(&2u32.to_le_bytes());
    out.push(LUA_TSTRING);
    out.extend_from_slice(&2u64.to_le_bytes());
    out.extend_from_slice(b"f\0");
    out.push(LUA_TNUMBER);
    out.extend_from_slice(number_bytes);
    out.extend_from_slice(&0u32.to_le_bytes()); // prototypes
    out.extend_from_slice(&0u32.to_le_bytes()); // lineinfo
    out.extend_from_slice(&0u32.to_le_bytes()); // locvars
    out.extend_from_slice(&0u32.to_le_bytes()); // upvalue names
    out
}

fn write_chunk(dir: &TempDir, name: &str, bytes: &[u8]) -> String {
    let path = dir.path().join(name);
    fs::write(&path, bytes).expect("write synthesized chunk");
    path.to_str().expect("utf8 path").to_string()
}

fn run(luad: &Path, args: &[&str]) -> String {
    let output = Command::new(luad).args(args).output().expect("run luad");
    assert!(
        output.status.success(),
        "luad {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

/// The typed constant object whose `raw_hex` equals `raw_hex`, found anywhere in the
/// `disasm --format json` document.
fn constant_with_raw_hex(document: &serde_json::Value, raw_hex: &str) -> serde_json::Value {
    fn walk(value: &serde_json::Value, raw_hex: &str, found: &mut Vec<serde_json::Value>) {
        match value {
            serde_json::Value::Object(map) => {
                if map.get("raw_hex").and_then(|v| v.as_str()) == Some(raw_hex) {
                    found.push(value.clone());
                }
                for child in map.values() {
                    walk(child, raw_hex, found);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    walk(child, raw_hex, found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(document, raw_hex, &mut found);
    assert!(
        !found.is_empty(),
        "no typed constant with raw_hex {raw_hex} in the disassembly"
    );
    // Every occurrence is the same preserved constant; the first suffices.
    found.remove(0)
}

struct Case {
    name: &'static str,
    integral_flag: u8,
    number_bytes: Vec<u8>,
    /// Expected `val` in the typed constant, and whether it is an integer.
    expected_integer: Option<i64>,
    expected_float: Option<f64>,
    /// Expected spelling in `origins --format text`.
    expected_text: &'static str,
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "int32",
            integral_flag: 1,
            number_bytes: 42i32.to_le_bytes().to_vec(),
            expected_integer: Some(42),
            expected_float: None,
            expected_text: "42",
        },
        Case {
            name: "int64",
            integral_flag: 1,
            number_bytes: (-1i64).to_le_bytes().to_vec(),
            expected_integer: Some(-1),
            expected_float: None,
            expected_text: "-1",
        },
        Case {
            name: "int32-min",
            integral_flag: 1,
            number_bytes: i32::MIN.to_le_bytes().to_vec(),
            expected_integer: Some(i64::from(i32::MIN)),
            expected_float: None,
            expected_text: "-2147483648",
        },
        // Controls: the same byte patterns under integral flag 0 stay IEEE-754.
        Case {
            name: "float32-control",
            integral_flag: 0,
            number_bytes: 42i32.to_le_bytes().to_vec(),
            expected_integer: None,
            expected_float: Some(f64::from(f32::from_bits(42))),
            expected_text: "5.885453550164232e-44",
        },
        Case {
            name: "float64-control",
            integral_flag: 0,
            number_bytes: 1.5f64.to_le_bytes().to_vec(),
            expected_integer: None,
            expected_float: Some(1.5),
            expected_text: "1.5",
        },
    ]
}

#[test]
fn integral_flag_selects_integer_or_float_decoding_for_tag_3_constants() {
    let luad = luad_oracle::luad_binary_path();
    let dir = TempDir::new().expect("temporary directory");

    for case in cases() {
        let chunk = lua51_chunk_with_number(case.integral_flag, &case.number_bytes);
        let path = write_chunk(&dir, &format!("{}.luac", case.name), &chunk);
        let raw_hex = hex::encode(&case.number_bytes);

        let summary = run(&luad, &["inspect", &path, "--summary"]);
        let expected_layout = format!(
            "num={},endian=1,integral_flag={}",
            case.number_bytes.len(),
            case.integral_flag
        );
        assert!(
            summary.contains(&expected_layout),
            "{}: inspect must report the declared layout {expected_layout}:\n{summary}",
            case.name
        );

        let json = run(&luad, &["disasm", &path, "--format", "json"]);
        let document: serde_json::Value = serde_json::from_str(&json).expect("json document");
        let constant = constant_with_raw_hex(&document, &raw_hex);

        match (case.expected_integer, case.expected_float) {
            (Some(expected), None) => {
                assert_eq!(
                    constant.get("val").and_then(|v| v.as_i64()),
                    Some(expected),
                    "{}: integral layout must decode {raw_hex} as the integer {expected}: {constant}",
                    case.name
                );
                assert!(
                    constant.get("is_nan").is_none() && constant.get("is_inf").is_none(),
                    "{}: an integral constant must not carry float classification: {constant}",
                    case.name
                );
            }
            (None, Some(expected)) => {
                let val = constant
                    .get("val")
                    .and_then(|v| v.as_f64())
                    .unwrap_or_else(|| {
                        panic!("{}: float constant lacks val: {constant}", case.name)
                    });
                assert_eq!(
                    val.to_bits(),
                    expected.to_bits(),
                    "{}: floating layout must decode {raw_hex} as {expected}: {constant}",
                    case.name
                );
                assert!(
                    constant.get("is_nan").is_some(),
                    "{}: a float constant carries its classification: {constant}",
                    case.name
                );
            }
            _ => unreachable!("each case expects exactly one representation"),
        }

        let text = run(&luad, &["origins", &path, "--format", "text"]);
        let expected_line = format!("<- {}", case.expected_text);
        assert!(
            text.contains(&expected_line),
            "{}: origins text must render the argument as {expected_line:?}:\n{text}",
            case.name
        );
    }
}

#[test]
fn integral_layout_reaches_the_typed_model_as_an_integer() {
    use luad_core::{ConstantValue, SafeReader};

    let chunk = lua51_chunk_with_number(1, &42i32.to_le_bytes());
    let mut reader = SafeReader::new(&chunk);
    let decoded =
        luad_dialect_lua51::decode_chunk_lua51(&mut reader).expect("decode integral chunk");
    let constant = &decoded.main_proto.constants[1].value;
    assert_eq!(
        constant,
        &ConstantValue::Integer {
            val: 42,
            raw_hex: "2a000000".to_string(),
        },
        "tag 3 under integral flag 1 must be a typed integer, got {constant:?}"
    );
}
