//! Cross-platform scalar-rendering contract for the exact Lua 5.1.5 and Lua 5.4.8 targets.

use std::fs;
use std::process::Command;

use luad_core::scalar::BYTE_STRING_PREVIEW_BYTES;
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

    // Byte equality, but reported as text: a golden diff nobody can read is a
    // golden nobody updates correctly.
    assert!(
        lua51.as_bytes() == expected.as_bytes(),
        "Lua 5.1.5 diverged from the golden\n--- golden ---\n{expected}--- lua5.1 ---\n{lua51}"
    );
    assert!(
        lua54.as_bytes() == expected.as_bytes(),
        "Lua 5.4.8 diverged from the golden\n--- golden ---\n{expected}--- lua5.4 ---\n{lua54}"
    );
    // True by construction while both dialects delegate to the dialect-free
    // `render_constant`; kept as a tripwire for a dialect that stops delegating.
    assert!(
        lua51.as_bytes() == lua54.as_bytes(),
        "exact targets disagree\n--- lua5.1 ---\n{lua51}--- lua5.4 ---\n{lua54}"
    );
}

/// Resolve the `luad` binary and refuse to run against a stale build.
///
/// `cargo test -p luad-oracle` does not rebuild `luad-cli`, so a CLI-driven test
/// can otherwise pass against a binary that predates the change under test. The
/// aggregate `cargo test --workspace` in `scripts/check.sh` always rebuilds, so
/// this only fires on a partial local run.
fn resolve_current_luad() -> std::path::PathBuf {
    let luad = luad_oracle::resolve_test_binary().expect("resolve luad test binary");
    let built_at = fs::metadata(&luad)
        .and_then(|meta| meta.modified())
        .expect("luad binary modification time");

    let mut sources = Vec::new();
    let root = luad_oracle::find_workspace_root();
    for crate_name in ["luad-cli", "luad-core"] {
        rust_sources(
            &root.join("crates").join(crate_name).join("src"),
            &mut sources,
        );
    }
    for source in sources {
        let changed_at = fs::metadata(&source)
            .and_then(|meta| meta.modified())
            .expect("source modification time");
        assert!(
            changed_at <= built_at,
            "{} is newer than {}; rebuild with `cargo build --workspace` \
             before running CLI-driven tests",
            source.display(),
            luad.display()
        );
    }
    luad
}

#[test]
fn text_and_typed_disassembly_use_the_same_preview() {
    let root = luad_oracle::find_workspace_root();
    let luad = resolve_current_luad();
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

/// Crates whose scalar output reaches a user and must therefore defer to
/// `luad_core::scalar`.
///
/// `luad-oracle` is absent on purpose: its listing parser reproduces the *reference*
/// `luac -l` spelling, octal escapes and all, which is a different contract from
/// luad's own rendering.
const RENDERING_CRATES: [&str; 8] = [
    "luad-core",
    "luad-cli",
    "luad-analysis",
    "luad-dialect-lua51",
    "luad-dialect-lua52",
    "luad-dialect-lua53",
    "luad-dialect-lua54",
    "luad-dialect-lua55",
];

/// The one file allowed to define scalar formatters: the authority itself.
const SCALAR_AUTHORITY: &str = "crates/luad-core/src/scalar.rs";

/// Verbs that mean "turn a value into text for a human".
const FORMATTING_VERBS: [&str; 7] = [
    "format",
    "render",
    "escape",
    "display",
    "preview",
    "stringify",
    "print",
];

/// Nouns that name a scalar this crate's authority owns.
const SCALAR_NOUNS: [&str; 12] = [
    "float", "double", "number", "numeric", "integer", "int", "scalar", "string", "str", "bytes",
    "byte", "constant",
];

/// Report every function in `source` whose name reads as a private scalar formatter.
///
/// This matches on name structure rather than a fixed blocklist, so a formatter
/// reintroduced under a new name is still caught. It deliberately ignores
/// extractors such as `string_operand`, which carry no formatting verb.
fn private_formatter_violations(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (offset, _) in source.match_indices("fn ") {
        // Require a token boundary so `r#fn ` or `..fn ` inside an identifier
        // cannot masquerade as a definition.
        if offset > 0 {
            let previous = source[..offset].chars().next_back().unwrap_or(' ');
            if previous.is_alphanumeric() || previous == '_' {
                continue;
            }
        }
        let rest = &source[offset + "fn ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let parts: Vec<&str> = name.split('_').collect();
        let has_verb = parts.iter().any(|part| FORMATTING_VERBS.contains(part));
        let has_noun = parts.iter().any(|part| SCALAR_NOUNS.contains(part));
        if has_verb && has_noun {
            found.push(name);
        }
    }
    found
}

fn rust_sources(root: &std::path::Path, into: &mut Vec<std::path::PathBuf>) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            rust_sources(&path, into);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            into.push(path);
        }
    }
}

#[test]
fn no_crate_outside_the_authority_defines_a_private_scalar_formatter() {
    let root = luad_oracle::find_workspace_root();
    let authority = root.join(SCALAR_AUTHORITY);
    let mut scanned = 0usize;

    for crate_name in RENDERING_CRATES {
        let mut sources = Vec::new();
        rust_sources(
            &root.join("crates").join(crate_name).join("src"),
            &mut sources,
        );
        assert!(
            !sources.is_empty(),
            "{crate_name} has no sources; the guard would pass vacuously"
        );
        for path in sources {
            if path == authority {
                continue;
            }
            scanned += 1;
            let source = fs::read_to_string(&path).expect("read crate source");
            let violations = private_formatter_violations(&source);
            assert!(
                violations.is_empty(),
                "{} defines private scalar formatter(s) {violations:?}; \
                 route them through luad_core::scalar instead",
                path.display()
            );
        }
    }

    assert!(scanned > 20, "guard scanned only {scanned} files");
}

#[test]
fn the_scalar_authority_is_where_the_formatters_actually_live() {
    let root = luad_oracle::find_workspace_root();
    let source = fs::read_to_string(root.join(SCALAR_AUTHORITY)).expect("read scalar authority");
    let defined = private_formatter_violations(&source);
    for expected in [
        "escape_bytes",
        "render_byte_string",
        "render_byte_string_full",
        "render_float",
        "render_integer",
        "render_constant",
        "render_constant_full",
    ] {
        assert!(
            defined.iter().any(|name| name == expected),
            "{expected} is missing from the authority, or the guard stopped recognising it"
        );
    }
}

#[test]
fn private_scalar_formatter_negative_controls_are_detected() {
    // A formatter reintroduced under each of several plausible names, plus the
    // exact shapes this sprint deleted.
    for control in [
        "fn format_float(value: f64) -> String { value.to_string() }",
        "fn render_float(v: f64) -> String { String::new() }",
        "fn format_string_preview(s: &str) -> String { String::new() }",
        "fn escape_bytes(b: &[u8]) -> String { String::new() }",
        "fn display_number(v: f64) -> String { String::new() }",
        "fn stringify_constant(v: &u8) -> String { String::new() }",
        "    pub(crate) fn render_scalar_bytes(b: &[u8]) -> String { String::new() }",
    ] {
        assert!(
            !private_formatter_violations(control).is_empty(),
            "guard missed {control:?}"
        );
    }

    // Extractors and unrelated helpers must not trip the guard.
    for allowed in [
        "fn string_operand(i: &u8) -> Option<String> { None }",
        "fn lua_string_operand(i: &u8) -> Option<&str> { None }",
        "fn string_literal(v: &u8) -> Option<u8> { None }",
        "fn render_callees(a: &u8) {}",
        "fn format_origin_expression(e: &u8) -> String { String::new() }",
        "fn check_string_limit(n: usize) -> bool { true }",
    ] {
        assert!(
            private_formatter_violations(allowed).is_empty(),
            "guard false-positived on {allowed:?}"
        );
    }
}

#[test]
fn the_guard_recurses_into_nested_source_directories() {
    let root = luad_oracle::find_workspace_root();
    let mut sources = Vec::new();
    rust_sources(&root.join("crates/luad-cli/src"), &mut sources);
    assert!(
        sources.iter().any(|path| path.ends_with("render/text.rs")),
        "guard did not reach crates/luad-cli/src/render/text.rs; nested modules are unprotected"
    );
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

/// Compile a Lua source string with one dialect's official compiler.
type CompileWithDialect = fn(&str, bool) -> Result<Vec<u8>, String>;

/// Every dialect luad can disassemble, with the compiler that produces it.
const ALL_DIALECTS: [(&str, CompileWithDialect); 5] = [
    ("lua5.1", luad_oracle::compile_source_lua51),
    ("lua5.2", luad_oracle::compile_source_lua52),
    ("lua5.3", luad_oracle::compile_source_lua53),
    ("lua5.4", luad_oracle::compile_source_lua54),
    ("lua5.5", luad_oracle::compile_source_lua55),
];

fn decode_constants(dialect: &str, bytes: &[u8]) -> Vec<luad_core::Constant> {
    let mut reader = SafeReader::new(bytes);
    let chunk = match dialect {
        "lua5.1" => luad_dialect_lua51::decode_chunk_lua51(&mut reader),
        "lua5.2" => luad_dialect_lua52::decode_chunk_lua52(&mut reader),
        "lua5.3" => luad_dialect_lua53::decode_chunk_lua53(&mut reader),
        "lua5.4" => luad_dialect_lua54::decode_chunk_lua54(&mut reader),
        "lua5.5" => luad_dialect_lua55::decode_chunk_lua55(&mut reader),
        other => panic!("unhandled dialect {other}"),
    }
    .unwrap_or_else(|e| panic!("{dialect}: decode freshly compiled chunk: {e:?}"));
    chunk.main_proto.constants
}

/// The scalar authority owns the text constant listing on *every* dialect, not
/// only on the exact targets.
///
/// The source below carries a string constant past the preview bound, so a
/// dialect that stopped consuming the authority would disagree here rather than
/// coincidentally matching on short values.
#[test]
fn every_dialect_renders_its_constant_listing_through_the_scalar_authority() {
    let luad = resolve_current_luad();
    let long_string = "A".repeat(BYTE_STRING_PREVIEW_BYTES + 20);
    let source =
        format!("local s = \"{long_string}\"\nlocal f = 1.5\nlocal n = 7\nreturn s, f, n\n");

    let scratch = tempfile::tempdir().expect("scratch directory");
    let mut bounded_seen = 0;

    for (dialect, compile) in ALL_DIALECTS {
        let bytes = compile(&source, false)
            .unwrap_or_else(|e| panic!("{dialect}: compile scalar listing source: {e}"));
        let path = scratch.path().join(format!("{dialect}.luac"));
        fs::write(&path, &bytes).expect("write compiled chunk");

        let run = |extra: &[&str]| -> String {
            let mut args = vec!["disasm", path.to_str().unwrap(), "--format", "text"];
            args.extend_from_slice(extra);
            let output = Command::new(&luad)
                .args(&args)
                .output()
                .unwrap_or_else(|e| panic!("{dialect}: run luad: {e}"));
            assert!(output.status.success(), "{dialect}: disasm failed");
            String::from_utf8(output.stdout).expect("ASCII disassembly")
        };
        let bounded = run(&[]);
        let untruncated = run(&["--raw"]);

        let constants = decode_constants(dialect, &bytes);
        assert!(
            !constants.is_empty(),
            "{dialect}: fixture produced no constants"
        );

        for constant in &constants {
            let expected = format!(
                ";   k[{}] = {}",
                constant.index,
                luad_core::scalar::render_constant(&constant.value)
            );
            assert!(
                bounded.contains(&expected),
                "{dialect}: constant listing did not use the scalar authority.\n\
                 expected line: {expected}\n--- output ---\n{bounded}"
            );

            let expected_full = format!(
                ";   k[{}] = {}",
                constant.index,
                luad_core::scalar::render_constant_full(&constant.value)
            );
            assert!(
                untruncated.contains(&expected_full),
                "{dialect}: --raw listing did not emit the untruncated constant.\n\
                 expected line: {expected_full}"
            );

            if let luad_core::ConstantValue::ShortString(s)
            | luad_core::ConstantValue::LongString(s) = &constant.value
            {
                if s.raw_bytes.len() > BYTE_STRING_PREVIEW_BYTES {
                    bounded_seen += 1;
                    assert!(
                        expected.contains(&format!("({} bytes)", s.raw_bytes.len())),
                        "{dialect}: truncated preview must state the full byte count"
                    );
                    assert_ne!(
                        expected, expected_full,
                        "{dialect}: --raw must differ from the bounded listing here"
                    );
                }
            }
        }
    }

    assert_eq!(
        bounded_seen,
        ALL_DIALECTS.len(),
        "every dialect must have exercised the preview bound"
    );
}
