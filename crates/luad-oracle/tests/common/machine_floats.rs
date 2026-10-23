//! Public source-generated float controls. Crafted bytes are parsed/listed, never executed.

use std::path::PathBuf;
use std::process::Command;

use luad_core::envelope::{JsonlDataRecord, MachineDocument};
use luad_core::{Chunk, ConstantValue, SafeReader};
use serde_json::Value;

type Compile = fn(&str, bool) -> Result<Vec<u8>, String>;
type DialectCase = (&'static str, &'static str, Compile, fn() -> PathBuf);
const DIALECTS: [DialectCase; 5] = [
    (
        "lua5.1",
        "Lua 5.1.5",
        luad_oracle::compile_source_lua51,
        luad_oracle::require_luac51,
    ),
    (
        "lua5.2",
        "Lua 5.2.4",
        luad_oracle::compile_source_lua52,
        luad_oracle::require_luac52,
    ),
    (
        "lua5.3",
        "Lua 5.3.6",
        luad_oracle::compile_source_lua53,
        luad_oracle::require_luac53,
    ),
    (
        "lua5.4",
        "Lua 5.4.8",
        luad_oracle::compile_source_lua54,
        luad_oracle::require_luac54,
    ),
    (
        "lua5.5",
        "Lua 5.5.1",
        luad_oracle::compile_source_lua55,
        luad_oracle::require_luac55,
    ),
];
fn decode(dialect: &str, bytes: &[u8]) -> Result<Chunk, Box<luad_core::Diagnostic>> {
    let mut reader = SafeReader::new(bytes);
    let result = match dialect {
        "lua5.1" => luad_dialect_lua51::decode_chunk_lua51(&mut reader),
        "lua5.2" => luad_dialect_lua52::decode_chunk_lua52(&mut reader),
        "lua5.3" => luad_dialect_lua53::decode_chunk_lua53(&mut reader),
        "lua5.4" => luad_dialect_lua54::decode_chunk_lua54(&mut reader),
        "lua5.5" => luad_dialect_lua55::decode_chunk_lua55(&mut reader),
        other => panic!("unknown test dialect {other}"),
    };
    result.map_err(Box::new)
}
fn compiler_banner(compiler: &std::path::Path, expected: &str) {
    let output = Command::new(compiler).arg("-v").output().unwrap();
    assert!(output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        text.starts_with(expected),
        "required {expected}, got {text}"
    );
}
fn same_evidence(value: &ConstantValue, raw: &[u8], expected: f64) -> bool {
    matches!(value, ConstantValue::Float { val, raw_hex, is_nan, is_inf }
        if *raw_hex == hex::encode(raw) && *is_nan == expected.is_nan()
        && *is_inf == expected.is_infinite()
        && if expected.is_nan() { val.is_nan() } else { val.to_bits() == expected.to_bits() })
}
fn schema(luad: &str, name: &str) -> jsonschema::Validator {
    let output = Command::new(luad).args(["schema", name]).output().unwrap();
    assert!(output.status.success());
    jsonschema::validator_for(&serde_json::from_slice::<Value>(&output.stdout).unwrap()).unwrap()
}

pub fn assert_json_float_facts(luad: &str) {
    let inspect_schema = schema(luad, "chunk");
    let disasm_schema = schema(luad, "disasm");
    let export_schema = schema(luad, "export");
    let directory = tempfile::tempdir().unwrap();
    for (dialect, version, compile, require) in DIALECTS {
        compiler_banner(&require(), version);
        let original =
            compile("local t=...; return t[3.25](3.25)", true).expect("required official compiler");
        let base = decode(dialect, &original).unwrap();
        let constant = base
            .main_proto
            .constants
            .iter()
            .find(|c| matches!(c.value, ConstantValue::Float { .. }))
            .unwrap();
        let start = constant.source.byte_offset + constant.source.byte_length - 8;
        assert_eq!(
            &original[start..start + 8],
            &3.25f64.to_le_bytes(),
            "explicit little-endian fixture payload"
        );
        for width in if dialect == "lua5.1" {
            vec![8, 4]
        } else {
            vec![8]
        } {
            let cases: Vec<Vec<u8>> = if width == 8 {
                [
                    0,
                    0x8000_0000_0000_0000,
                    3.25f64.to_bits(),
                    f64::MIN_POSITIVE.to_bits(),
                    1,
                    f64::MAX.to_bits(),
                    f64::MIN.to_bits(),
                    f64::INFINITY.to_bits(),
                    f64::NEG_INFINITY.to_bits(),
                    0x7ff8_0000_0000_0042,
                    0x7ff0_0000_0000_0043,
                    0xfff8_0000_0000_0044,
                ]
                .into_iter()
                .map(|b| b.to_le_bytes().to_vec())
                .collect()
            } else {
                [
                    0u32,
                    0x8000_0000,
                    3.25f32.to_bits(),
                    0x0080_0000,
                    1,
                    0x7f7f_ffff,
                    0xff7f_ffff,
                    0x7f80_0000,
                    0xff80_0000,
                    0x7fc0_0042,
                    0x7f80_0043,
                    0xffc0_0044,
                ]
                .into_iter()
                .map(|b| b.to_le_bytes().to_vec())
                .collect()
            };
            let mut nan_records = Vec::new();
            for raw in cases {
                let expected = if width == 8 {
                    f64::from_le_bytes(raw.clone().try_into().unwrap())
                } else {
                    f64::from(f32::from_le_bytes(raw.clone().try_into().unwrap()))
                };
                let mut bytes = original.clone();
                bytes.splice(start..start + 8, raw.iter().copied());
                if width == 4 {
                    bytes[10] = 4;
                } // declared number width, no host inference
                let parsed = decode(dialect, &bytes).unwrap();
                assert!(
                    luad_analysis::validate_for_analysis(&parsed).is_ok()
                        || !matches!(dialect, "lua5.1" | "lua5.4")
                );
                let path = directory.path().join(format!("{dialect}-{width}.luac"));
                std::fs::write(&path, &bytes).unwrap();
                let output = Command::new(luad)
                    .args(["inspect", path.to_str().unwrap(), "--format", "json"])
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let validation = Command::new(luad)
                    .args(["validate", path.to_str().unwrap(), "--format", "json"])
                    .output()
                    .unwrap();
                assert!(
                    validation.status.success(),
                    "structural float control must remain valid"
                );
                let json: Value = serde_json::from_slice(&output.stdout).unwrap();
                assert!(
                    inspect_schema.is_valid(&json),
                    "schema rejects {dialect}/{width}: {json}"
                );
                let document: MachineDocument<Chunk> =
                    serde_json::from_slice(&output.stdout).unwrap();
                let fact = document
                    .data
                    .main_proto
                    .constants
                    .iter()
                    .find(|c| matches!(c.value, ConstantValue::Float { .. }))
                    .unwrap();
                assert!(
                    same_evidence(&fact.value, &raw, expected),
                    "typed raw/class round trip {dialect}/{width}"
                );
                assert_eq!(
                    fact.source.raw_hex,
                    hex::encode(
                        &bytes[fact.source.byte_offset
                            ..fact.source.byte_offset + fact.source.byte_length]
                    )
                );
                let json_constant = serde_json::to_value(&fact.value).unwrap();
                if expected.is_nan() {
                    assert_eq!(json_constant["value"]["val"], "nan");
                    nan_records.push((fact.value.clone(), raw.clone(), expected));
                } else if expected.is_infinite() {
                    assert_eq!(
                        json_constant["value"]["val"],
                        if expected.is_sign_negative() {
                            "-inf"
                        } else {
                            "inf"
                        }
                    );
                } else {
                    assert!(json_constant["value"]["val"].is_number());
                }
                let disasm = Command::new(luad)
                    .args(["disasm", path.to_str().unwrap(), "--format", "json"])
                    .output()
                    .unwrap();
                if matches!(dialect, "lua5.1" | "lua5.4") {
                    assert!(disasm.status.success());
                    let json: Value = serde_json::from_slice(&disasm.stdout).unwrap();
                    assert!(disasm_schema.is_valid(&json));
                    let _: MachineDocument<luad_core::DisassembledPrototype> =
                        serde_json::from_slice(&disasm.stdout).unwrap();
                } else {
                    assert_eq!(disasm.status.code(), Some(4));
                    assert!(disasm.stdout.is_empty());
                    assert!(String::from_utf8_lossy(&disasm.stderr).contains("ANA-PRECOND-001"));
                }
                let export = Command::new(luad)
                    .args(["export", "--facts", "constant", path.to_str().unwrap()])
                    .output()
                    .unwrap();
                assert!(export.status.success());
                let mut observed = 0;
                for line in String::from_utf8(export.stdout).unwrap().lines() {
                    let json: Value = serde_json::from_str(line).unwrap();
                    assert!(export_schema.is_valid(&json));
                    if json["record_type"] == "constant" {
                        let record: JsonlDataRecord<luad_core::Constant> =
                            serde_json::from_str(line).unwrap();
                        if matches!(record.data.value, ConstantValue::Float { .. }) {
                            assert!(same_evidence(&record.data.value, &raw, expected));
                            observed += 1;
                        }
                    }
                }
                assert_eq!(observed, 1);
                // Corrupt the comparator's actual record, not its expected input.
                let mut corrupt = fact.value.clone();
                if let ConstantValue::Float { raw_hex, .. } = &mut corrupt {
                    raw_hex.push('0');
                }
                assert!(
                    !same_evidence(&corrupt, &raw, expected),
                    "raw corruption must be detected"
                );
                let mut corrupt = fact.value.clone();
                if let ConstantValue::Float { val, .. } = &mut corrupt {
                    *val = if expected.is_nan() { 0.0 } else { f64::NAN };
                }
                assert!(!same_evidence(&corrupt, &raw, expected));
                let mut corrupt = fact.value.clone();
                if let ConstantValue::Float { is_nan, .. } = &mut corrupt {
                    *is_nan = !*is_nan;
                }
                assert!(!same_evidence(&corrupt, &raw, expected));
                let mut corrupt = fact.value.clone();
                if let ConstantValue::Float { is_inf, .. } = &mut corrupt {
                    *is_inf = !*is_inf;
                }
                assert!(!same_evidence(&corrupt, &raw, expected));
            }
            assert_eq!(nan_records.len(), 3);
            assert_ne!(nan_records[0].1, nan_records[1].1);
            assert!(
                !same_evidence(&nan_records[0].0, &nan_records[1].1, nan_records[1].2),
                "class equality cannot erase raw NaN payload differences"
            );
        }
    }
}

pub fn assert_exact_header_sentinels(luad: &str) {
    let directory = tempfile::tempdir().unwrap();
    for (dialect, version, compile, require) in DIALECTS.into_iter().skip(2) {
        let compiler = require();
        compiler_banner(&compiler, version);
        let original = compile("return 3.25", true).unwrap();
        let base = decode(dialect, &original).unwrap();
        let start = base.header.source.byte_offset + base.header.source.byte_length - 8;
        assert_eq!(
            &original[start..start + 8],
            &base.header.luac_num.to_le_bytes()
        );
        for bits in [
            base.header.luac_num.to_bits(),
            0x7ff8_0000_0000_0042,
            0xfff0_0000_0000_0043,
            f64::INFINITY.to_bits(),
            f64::NEG_INFINITY.to_bits(),
            0,
            3.25f64.to_bits(),
        ] {
            let mut bytes = original.clone();
            bytes[start..start + 8].copy_from_slice(&bits.to_le_bytes());
            let path = directory.path().join(format!("{dialect}.luac"));
            std::fs::write(&path, &bytes).unwrap();
            let expected = bits == base.header.luac_num.to_bits();
            let oracle = Command::new(&compiler)
                .current_dir(directory.path())
                .args(["-l", "-p"])
                .arg(&path)
                .output()
                .unwrap();
            assert_eq!(
                oracle.status.success(),
                expected,
                "official loader control {dialect}"
            );
            let output = Command::new(luad)
                .args(["validate", path.to_str().unwrap(), "--format", "json"])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                expected,
                "{dialect}: LUAC_NUM {bits:016x} differs from official loader"
            );
            let decoded = decode(dialect, &bytes);
            assert_eq!(decoded.is_ok(), expected);
            if let Err(diagnostic) = decoded {
                let source = diagnostic
                    .source
                    .expect("header refusal retains byte evidence");
                assert_eq!(source.byte_offset, start);
                assert_eq!(source.raw_hex, hex::encode(bits.to_le_bytes()));
            }
        }
    }
}
