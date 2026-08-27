//! Cross-platform scalar-rendering contract for the exact Lua 5.1.5 and Lua 5.4.8 targets.

use std::fs;
use std::process::Command;

use luad_core::{ConstantValue, DisassembledPrototype, LuaString, ResolvedFact, SafeReader};

#[derive(Clone, Copy)]
enum ExactTarget {
    Lua51,
    Lua54,
}

fn float_value(bits: u64) -> ConstantValue {
    let val = f64::from_bits(bits);
    ConstantValue::Float {
        val,
        raw_hex: hex::encode(bits.to_le_bytes()),
        is_nan: val.is_nan(),
        is_inf: val.is_infinite(),
    }
}

fn scalar_cases() -> Vec<(&'static str, ConstantValue)> {
    vec![
        ("nil", ConstantValue::Nil),
        ("false", ConstantValue::Boolean(false)),
        ("true", ConstantValue::Boolean(true)),
        (
            "integer-min",
            ConstantValue::Integer {
                val: i64::MIN,
                raw_hex: hex::encode(i64::MIN.to_le_bytes()),
            },
        ),
        (
            "integer-max",
            ConstantValue::Integer {
                val: i64::MAX,
                raw_hex: hex::encode(i64::MAX.to_le_bytes()),
            },
        ),
        (
            "escaped-bytes",
            ConstantValue::ShortString(LuaString::from_bytes(&[
                0x00, b'\n', b'\r', b'\t', b' ', b'"', b'\\', b'~', 0x7f, 0x80, 0xff,
            ])),
        ),
        (
            "truncated-bytes",
            ConstantValue::LongString(LuaString::from_bytes(&[b'a'; 65])),
        ),
        ("finite-integral", float_value(1.0_f64.to_bits())),
        (
            "finite-fractional",
            float_value(std::f64::consts::PI.to_bits()),
        ),
        ("positive-zero", float_value(0.0_f64.to_bits())),
        ("negative-zero", float_value((-0.0_f64).to_bits())),
        ("positive-infinity", float_value(f64::INFINITY.to_bits())),
        (
            "negative-infinity",
            float_value(f64::NEG_INFINITY.to_bits()),
        ),
        ("nan", float_value(0x7ff8_0000_0000_0042)),
    ]
}

fn base_proto(target: ExactTarget) -> luad_core::Prototype {
    let root = luad_oracle::find_workspace_root();
    let relative = match target {
        ExactTarget::Lua51 => "tests/fixtures/precompiled/lua51/numerics.luac",
        ExactTarget::Lua54 => "tests/fixtures/precompiled/lua54/numerics.luac",
    };
    let bytes = fs::read(root.join(relative)).expect("read maintained exact-target fixture");
    let mut reader = SafeReader::new(&bytes);
    let chunk =
        match target {
            ExactTarget::Lua51 => luad_dialect_lua51::decode_chunk_lua51(&mut reader)
                .expect("decode Lua 5.1.5 fixture"),
            ExactTarget::Lua54 => luad_dialect_lua54::decode_chunk_lua54(&mut reader)
                .expect("decode Lua 5.4.8 fixture"),
        };
    chunk.main_proto
}

fn disassemble(target: ExactTarget, proto: &luad_core::Prototype) -> DisassembledPrototype {
    match target {
        ExactTarget::Lua51 => luad_dialect_lua51::disassemble_proto_lua51(proto),
        ExactTarget::Lua54 => luad_dialect_lua54::disassemble_proto_lua54(proto),
    }
}

fn constant_zero(disassembly: &DisassembledPrototype) -> (&ConstantValue, &str) {
    disassembly
        .instructions
        .iter()
        .flat_map(|instruction| &instruction.operands)
        .find_map(|operand| match operand.resolved.as_ref() {
            Some(ResolvedFact::Constant {
                index: 0,
                value,
                formatted_preview,
                ..
            }) => Some((value, formatted_preview.as_str())),
            _ => None,
        })
        .expect("maintained numerics fixture must execute a reference to K[0]")
}

fn target_golden(target: ExactTarget) -> String {
    let base = base_proto(target);
    let mut lines = Vec::new();
    for (name, value) in scalar_cases() {
        let mut proto = base.clone();
        proto.constants[0].value = value.clone();
        let disassembly = disassemble(target, &proto);
        let (typed_value, preview) = constant_zero(&disassembly);
        if name == "nan" {
            let ConstantValue::Float {
                val,
                raw_hex,
                is_nan,
                is_inf,
            } = typed_value
            else {
                panic!("NaN case lost its float type");
            };
            assert_eq!(val.to_bits(), 0x7ff8_0000_0000_0042);
            assert_eq!(raw_hex, "420000000000f87f");
            assert!(*is_nan);
            assert!(!*is_inf);
        } else {
            assert_eq!(typed_value, &value, "{name}: raw typed value changed");
        }
        lines.push(format!("{name}={preview}"));
    }
    lines.join("\n") + "\n"
}

#[test]
fn exact_targets_match_the_same_byte_for_byte_scalar_golden() {
    let root = luad_oracle::find_workspace_root();
    let expected = fs::read_to_string(root.join("tests/goldens/scalars/exact-targets.golden"))
        .expect("read scalar golden");
    let lua51 = target_golden(ExactTarget::Lua51);
    let lua54 = target_golden(ExactTarget::Lua54);

    assert_eq!(lua51.as_bytes(), expected.as_bytes());
    assert_eq!(lua54.as_bytes(), expected.as_bytes());
    assert_eq!(lua51.as_bytes(), lua54.as_bytes());
}

#[test]
fn text_and_typed_disassembly_use_the_same_preview() {
    let root = luad_oracle::find_workspace_root();
    let luad = luad_oracle::resolve_test_binary().expect("resolve luad test binary");
    for relative in [
        "tests/fixtures/precompiled/lua51/numerics.luac",
        "tests/fixtures/precompiled/lua54/numerics.luac",
    ] {
        let fixture = root.join(relative);
        let json = Command::new(&luad)
            .args(["disasm", fixture.to_str().unwrap(), "--format", "json"])
            .output()
            .expect("run typed disassembly");
        let text = Command::new(&luad)
            .args(["disasm", fixture.to_str().unwrap(), "--format", "text"])
            .output()
            .expect("run text disassembly");
        assert!(
            json.status.success(),
            "typed disassembly failed for {relative}"
        );
        assert!(
            text.status.success(),
            "text disassembly failed for {relative}"
        );

        let document: luad_core::MachineDocument<DisassembledPrototype> =
            serde_json::from_slice(&json.stdout).expect("typed disassembly document");
        let text = String::from_utf8(text.stdout).expect("ASCII text disassembly");
        let mut previews = 0;
        for instruction in &document.data.instructions {
            for operand in &instruction.operands {
                if let Some(ResolvedFact::Constant {
                    formatted_preview, ..
                }) = &operand.resolved
                {
                    previews += 1;
                    assert!(
                        text.contains(formatted_preview),
                        "{relative}: text omitted typed preview {formatted_preview:?}"
                    );
                }
            }
        }
        assert!(previews > 0, "fixture must exercise resolved constants");
    }
}

fn private_formatter_violation(source: &str) -> bool {
    [
        "fn format_float",
        "fn render_float",
        "fn format_string_preview",
        "fn render_scalar",
    ]
    .iter()
    .any(|forbidden| source.contains(forbidden))
}

#[test]
fn dialect_crates_cannot_regain_private_scalar_formatters() {
    let root = luad_oracle::find_workspace_root();
    for dialect in ["luad-dialect-lua51", "luad-dialect-lua54"] {
        let source_root = root.join("crates").join(dialect).join("src");
        for entry in fs::read_dir(&source_root).expect("read exact dialect source directory") {
            let path = entry.expect("read dialect source entry").path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            let source = fs::read_to_string(&path).expect("read exact dialect source");
            assert!(
                !private_formatter_violation(&source),
                "{} contains a private scalar formatter",
                path.display()
            );
        }
    }
}

#[test]
fn private_scalar_formatter_negative_control_is_detected() {
    assert!(private_formatter_violation(
        "fn format_float(value: f64) -> String { value.to_string() }"
    ));
}

#[test]
fn named_scalar_mutations_are_rejected_by_the_exact_target_golden() {
    let canonical = target_golden(ExactTarget::Lua54);
    let corruptions = [
        canonical.replacen("negative-zero=-0.0", "negative-zero=0.0", 1),
        canonical.replacen("nan=nan", "nan=NaN", 1),
        canonical.replacen("finite-integral=1.0", "finite-integral=1", 1),
        canonical.replacen(r#"escaped-bytes="\x00"#, r#"escaped-bytes="\0"#, 1),
    ];
    for corrupted in corruptions {
        assert_ne!(corrupted.as_bytes(), canonical.as_bytes());
    }
}
