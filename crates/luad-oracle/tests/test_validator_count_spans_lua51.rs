//! Public acceptance for Lua 5.1 count-encoded register windows.

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

const FIXTURE_PATH: &str = "tests/fixtures/precompiled/lua51/control_flow.luac";
const FIXTURE_SHA256: &str = "d7e98a66c1ec34cde480a49c20aa5f070d2113294dd60b81100a1cf6d15ebe40";
const OFFSET: usize = 69;
const TARGET: &str = "proto:0:pc:0";
const MAXSTACK: u32 = 6;
const A: u32 = 1;
const SPAN_CODE: &str = "L51-REG-SPAN-001";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    B,
    C,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Row {
    label: &'static str,
    opcode: u32,
    mnemonic: &'static str,
    field: Field,
    valid_count: u32,
    invalid_count: u32,
    other_b: u32,
    other_c: u32,
    start: u32,
    valid_end: u32,
    invalid_end: u32,
}

const MATRIX: [Row; 6] = [
    Row {
        label: "CALL.B arguments",
        opcode: 28,
        mnemonic: "CALL",
        field: Field::B,
        valid_count: 5,
        invalid_count: 6,
        other_b: 0,
        other_c: 1,
        start: 1,
        valid_end: 5,
        invalid_end: 6,
    },
    Row {
        label: "CALL.C results",
        opcode: 28,
        mnemonic: "CALL",
        field: Field::C,
        valid_count: 6,
        invalid_count: 7,
        other_b: 1,
        other_c: 0,
        start: 1,
        valid_end: 5,
        invalid_end: 6,
    },
    Row {
        label: "TAILCALL.B arguments",
        opcode: 29,
        mnemonic: "TAILCALL",
        field: Field::B,
        valid_count: 5,
        invalid_count: 6,
        other_b: 0,
        other_c: 0,
        start: 1,
        valid_end: 5,
        invalid_end: 6,
    },
    Row {
        label: "RETURN.B values",
        opcode: 30,
        mnemonic: "RETURN",
        field: Field::B,
        valid_count: 6,
        invalid_count: 7,
        other_b: 0,
        other_c: 0,
        start: 1,
        valid_end: 5,
        invalid_end: 6,
    },
    Row {
        label: "SETLIST.B sources",
        opcode: 34,
        mnemonic: "SETLIST",
        field: Field::B,
        valid_count: 4,
        invalid_count: 5,
        other_b: 0,
        other_c: 1,
        start: 2,
        valid_end: 5,
        invalid_end: 6,
    },
    Row {
        label: "VARARG.B results",
        opcode: 37,
        mnemonic: "VARARG",
        field: Field::B,
        valid_count: 6,
        invalid_count: 7,
        other_b: 0,
        other_c: 0,
        start: 1,
        valid_end: 5,
        invalid_end: 6,
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
struct ObservedSpan {
    mnemonic: String,
    start: u32,
    end: u32,
    bound: u32,
    target: String,
    scalar_count_is_register: bool,
    open_ended_emitted: bool,
}

fn iabc(opcode: u32, a: u32, b: u32, c: u32) -> u32 {
    opcode | (a << 6) | (c << 14) | (b << 23)
}

fn row_word(row: Row, count: u32) -> u32 {
    match row.field {
        Field::B => iabc(row.opcode, A, count, row.other_c),
        Field::C => iabc(row.opcode, A, row.other_b, count),
    }
}

fn workspace() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn fixture() -> Vec<u8> {
    std::fs::read(workspace().join(FIXTURE_PATH)).expect("read pinned fixture")
}

fn mutated(word: u32) -> Vec<u8> {
    let mut bytes = fixture();
    bytes[OFFSET..OFFSET + 4].copy_from_slice(&word.to_le_bytes());
    bytes
}

fn luad_bin() -> PathBuf {
    static LUAD: OnceLock<PathBuf> = OnceLock::new();
    LUAD.get_or_init(|| {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
            return path.into();
        }
        let out = Command::new("cargo")
            .args(["build", "-p", "luad-cli", "--bin", "luad"])
            .current_dir(workspace())
            .output()
            .expect("build luad CLI");
        assert!(out.status.success(), "luad build failed");
        workspace().join("target/debug/luad")
    })
    .clone()
}

fn schema_validator(command: &str) -> &'static jsonschema::Validator {
    static INSPECT: OnceLock<jsonschema::Validator> = OnceLock::new();
    static VALIDATE: OnceLock<jsonschema::Validator> = OnceLock::new();
    static DISASM: OnceLock<jsonschema::Validator> = OnceLock::new();
    let slot = match command {
        "inspect" => &INSPECT,
        "validate" => &VALIDATE,
        "disasm" => &DISASM,
        _ => panic!("unsupported schema command"),
    };
    slot.get_or_init(|| {
        let schema_name = if command == "inspect" {
            "chunk"
        } else {
            command
        };
        let output = Command::new(luad_bin())
            .args(["schema", schema_name])
            .output()
            .expect("run schema command");
        assert!(output.status.success(), "schema command failed");
        let schema: Value = serde_json::from_slice(&output.stdout).expect("schema JSON");
        jsonschema::validator_for(&schema).expect("compile schema")
    })
}

fn run_luad(command: &str, extra: &[&str], bytes: &[u8]) -> Value {
    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), bytes).expect("write temporary chunk");
    let mut args = vec![
        command,
        file.path().to_str().unwrap(),
        "--dialect",
        "lua5.1",
    ];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--format", "json"]);
    let output = Command::new(luad_bin())
        .args(args)
        .output()
        .expect("run luad");
    assert!(output.stderr.is_empty(), "machine stderr was not empty");
    let document: Value = serde_json::from_slice(&output.stdout).expect("machine JSON");
    let errors: Vec<_> = schema_validator(command)
        .iter_errors(&document)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "{command} schema errors: {errors:?}");
    document
}

fn instructions(value: &Value) -> Vec<&Value> {
    fn walk<'a>(value: &'a Value, found: &mut Vec<&'a Value>) {
        match value {
            Value::Object(map) => {
                if map.contains_key("mnemonic") && map.contains_key("raw_word") {
                    found.push(value);
                }
                map.values().for_each(|child| walk(child, found));
            }
            Value::Array(items) => items.iter().for_each(|child| walk(child, found)),
            _ => {}
        }
    }
    let mut found = Vec::new();
    walk(value, &mut found);
    found
}

fn instruction(document: &Value) -> &Value {
    instructions(document)
        .into_iter()
        .find(|inst| inst["id"].as_str() == Some(TARGET))
        .expect("mutated instruction")
}

fn span_diagnostics(document: &Value) -> Vec<&Value> {
    document["data"]["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .filter(|diag| diag["code"].as_str() == Some(SPAN_CODE))
        .collect()
}

fn observe(diag: &Value) -> ObservedSpan {
    let message = diag["message"].as_str().expect("diagnostic message");
    let words: Vec<_> = message.split_whitespace().collect();
    let range = words[3].strip_prefix("R(").expect("range start");
    let (start, end) = range.split_once(")..R(").expect("register range");
    let end = end.strip_suffix(')').expect("range end");
    ObservedSpan {
        mnemonic: words[0].to_string(),
        start: start.parse().expect("numeric start"),
        end: end.parse().expect("numeric end"),
        bound: words[6]
            .trim_matches(|ch| ch == '(' || ch == ')')
            .parse()
            .expect("numeric bound"),
        target: diag["target"].as_str().expect("target").to_string(),
        scalar_count_is_register: false,
        open_ended_emitted: false,
    }
}

fn expected(row: Row) -> ObservedSpan {
    ObservedSpan {
        mnemonic: row.mnemonic.to_string(),
        start: row.start,
        end: row.invalid_end,
        bound: MAXSTACK,
        target: TARGET.to_string(),
        scalar_count_is_register: false,
        open_ended_emitted: false,
    }
}

fn assert_scalar_operand(inst: &Value, field: Field, count: u32) {
    let name = match field {
        Field::B => "B",
        Field::C => "C",
    };
    let operand = inst["operands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operand| operand["name"].as_str() == Some(name))
        .expect("count operand");
    assert_eq!(operand["kind"]["kind"].as_str(), Some("immediate-unsigned"));
    assert_eq!(operand["kind"]["value"].as_u64(), Some(count as u64));
}

fn normalize_invocation_path(mut document: Value) -> Value {
    document["input_identity"]["path"] = Value::String("<INPUT>".to_string());
    document
}

#[test]
fn test_fixture_maxstack_and_encoding_are_pinned() {
    let bytes = fixture();
    assert_eq!(hex::encode(Sha256::digest(&bytes)), FIXTURE_SHA256);
    let inspect = run_luad("inspect", &[], &bytes);
    assert_eq!(
        inspect["data"]["main_proto"]["maxstacksize"].as_u64(),
        Some(MAXSTACK as u64)
    );
    assert_eq!(&bytes[OFFSET..OFFSET + 4], &1u32.to_le_bytes());
    assert_eq!(row_word(MATRIX[0], 5), 0x0280_405c);
    assert_eq!(row_word(MATRIX[1], 7), 0x0081_c05c);
    assert_eq!(row_word(MATRIX[4], 5), 0x0280_4062);
}

#[test]
fn test_killer_comparator_mutations_are_rejected() {
    let baseline = expected(MATRIX[0]);
    let mutants = [
        None,
        Some(ObservedSpan {
            end: 5,
            ..baseline.clone()
        }),
        Some(ObservedSpan {
            bound: 7,
            ..baseline.clone()
        }),
        Some(ObservedSpan {
            target: "proto:1:pc:0".into(),
            ..baseline.clone()
        }),
        Some(ObservedSpan {
            scalar_count_is_register: true,
            ..baseline.clone()
        }),
        Some(ObservedSpan {
            open_ended_emitted: true,
            ..baseline.clone()
        }),
    ];
    for mutant in mutants {
        assert_ne!(mutant.as_ref(), Some(&baseline));
    }
    assert_eq!(Some(baseline.clone()).as_ref(), Some(&baseline));
}

#[test]
fn test_call_argument_and_result_windows_are_proved_independently() {
    for row in &MATRIX[..2] {
        let invalid = run_luad("validate", &[], &mutated(row_word(*row, row.invalid_count)));
        let findings = span_diagnostics(&invalid);
        assert_eq!(findings.len(), 1, "{}", row.label);
        assert_eq!(observe(findings[0]), expected(*row), "{}", row.label);
    }
}

#[test]
fn test_count_span_boundary_matrix_is_exact() {
    for row in MATRIX {
        assert_eq!(row.valid_end, MAXSTACK - 1, "{}", row.label);
        assert_eq!(row.invalid_end, MAXSTACK, "{}", row.label);

        let valid_word = row_word(row, row.valid_count);
        let valid = run_luad("validate", &[], &mutated(valid_word));
        assert!(span_diagnostics(&valid).is_empty(), "{}", row.label);

        let invalid_word = row_word(row, row.invalid_count);
        let invalid_bytes = mutated(invalid_word);
        let invalid = run_luad("validate", &[], &invalid_bytes);
        let findings = span_diagnostics(&invalid);
        assert_eq!(findings.len(), 1, "{}", row.label);
        assert_eq!(observe(findings[0]), expected(row), "{}", row.label);
        let diag = findings[0];
        assert_eq!(diag["source"]["byte_offset"].as_u64(), Some(OFFSET as u64));
        assert_eq!(diag["source"]["byte_length"].as_u64(), Some(4));
        assert_eq!(
            diag["source"]["raw_hex"].as_str(),
            Some(hex::encode(invalid_word.to_le_bytes()).as_str())
        );
        assert!(!invalid["data"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diag| matches!(diag["code"].as_str(), Some("L51-REG-002" | "L51-REG-003"))));

        let disasm = run_luad("disasm", &["--proto", "proto:0"], &invalid_bytes);
        let inst = instruction(&disasm);
        assert_eq!(inst["mnemonic"].as_str(), Some(row.mnemonic));
        assert_eq!(inst["raw_word"].as_u64(), Some(invalid_word as u64));
        assert_eq!(inst["source"]["byte_offset"].as_u64(), Some(OFFSET as u64));
        assert_scalar_operand(inst, row.field, row.invalid_count);
    }
}

#[test]
fn test_non_register_count_fields_stay_scalar_in_public_disasm() {
    for row in MATRIX {
        let word = row_word(row, row.invalid_count);
        let disasm = run_luad("disasm", &["--proto", "proto:0"], &mutated(word));
        assert_scalar_operand(instruction(&disasm), row.field, row.invalid_count);
    }
    for (opcode, mnemonic) in [(29, "TAILCALL"), (34, "SETLIST")] {
        let word = iabc(opcode, A, 1, 511);
        let bytes = mutated(word);
        let disasm = run_luad("disasm", &["--proto", "proto:0"], &bytes);
        let inst = instruction(&disasm);
        assert_eq!(inst["mnemonic"].as_str(), Some(mnemonic));
        assert_scalar_operand(inst, Field::C, 511);
        let validation = run_luad("validate", &[], &bytes);
        assert!(!validation["data"]["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|diag| diag["code"].as_str() == Some("L51-REG-003")));
    }
}

#[test]
fn test_open_ended_and_empty_count_windows_receive_no_static_span() {
    let cases = [
        iabc(28, A, 0, 1),
        iabc(28, A, 1, 0),
        iabc(29, A, 0, 0),
        iabc(30, A, 0, 0),
        iabc(34, A, 0, 1),
        iabc(37, A, 0, 0),
        iabc(28, A, 1, 1),
        iabc(30, A, 1, 0),
        iabc(37, A, 1, 0),
    ];
    for word in cases {
        let validation = run_luad("validate", &[], &mutated(word));
        assert!(
            span_diagnostics(&validation).is_empty(),
            "word 0x{word:08x}"
        );
    }
}

#[test]
fn test_public_documents_match_schemas_and_are_deterministic() {
    let bytes = mutated(row_word(MATRIX[5], MATRIX[5].invalid_count));
    for (command, extra) in [
        ("inspect", Vec::<&str>::new()),
        ("validate", Vec::<&str>::new()),
        ("disasm", vec!["--proto", "proto:0"]),
    ] {
        let first = normalize_invocation_path(run_luad(command, &extra, &bytes));
        let second = normalize_invocation_path(run_luad(command, &extra, &bytes));
        assert_eq!(first, second, "{command} output must be deterministic");
    }
}
