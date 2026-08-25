//! Public acceptance for the diagnostic catalog machine contract.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use serde_json::{json, Value};

const PINNED_CODES: [&str; 110] = [
    "CORE-LIMIT-001",
    "CORE-LIMIT-002",
    "CORE-OVERFLOW-001",
    "CORE-SLICE-001",
    "CORE-TRUNC-001",
    "INTERNAL-IDENTITY-001",
    "IO-001",
    "L51-BOOL-001",
    "L51-CHUNK-001",
    "L51-CLOSURE-001",
    "L51-CLOSURE-002",
    "L51-CODE-001",
    "L51-CONST-001",
    "L51-CONST-002",
    "L51-CONST-003",
    "L51-CONST-004",
    "L51-CONST-005",
    "L51-DISASM-001",
    "L51-DISASM-002",
    "L51-HEADER-001",
    "L51-HEADER-002",
    "L51-HEADER-003",
    "L51-JMP-001",
    "L51-OP-001",
    "L51-PROTO-001",
    "L51-PROTO-002",
    "L51-REG-001",
    "L51-REG-002",
    "L51-REG-003",
    "L51-REG-SPAN-001",
    "L51-STACK-001",
    "L51-UPVAL-001",
    "L52-CHUNK-001",
    "L52-CODE-001",
    "L52-CONST-001",
    "L52-HEADER-001",
    "L52-HEADER-002",
    "L52-HEADER-003",
    "L52-JMP-001",
    "L52-OP-001",
    "L52-PROTO-001",
    "L52-STACK-001",
    "L52-UPVAL-001",
    "L53-CHUNK-001",
    "L53-CODE-001",
    "L53-CONST-001",
    "L53-CONST-002",
    "L53-HEADER-001",
    "L53-HEADER-002",
    "L53-HEADER-003",
    "L53-HEADER-004",
    "L53-HEADER-005",
    "L53-HEADER-006",
    "L53-HEADER-007",
    "L53-HEADER-008",
    "L53-HEADER-009",
    "L53-HEADER-010",
    "L53-JMP-001",
    "L53-OP-001",
    "L53-PROTO-001",
    "L53-STACK-001",
    "L53-UPVAL-001",
    "L54-CHUNK-001",
    "L54-CODE-001",
    "L54-CONST-001",
    "L54-CONST-002",
    "L54-HEADER-001",
    "L54-HEADER-002",
    "L54-HEADER-003",
    "L54-HEADER-004",
    "L54-HEADER-005",
    "L54-HEADER-006",
    "L54-HEADER-007",
    "L54-HEADER-008",
    "L54-HEADER-009",
    "L54-INVALID-OPCODE",
    "L54-OOB-CONSTANT",
    "L54-OOB-PROTO",
    "L54-PROTO-001",
    "L54-SIZE-001",
    "L54-STR-001",
    "L54-UPVAL-001",
    "L54-VAL-CONST-001",
    "L54-VAL-HEADER-001",
    "L54-VAL-HEADER-002",
    "L54-VAL-HEADER-003",
    "L54-VAL-JUMP-001",
    "L54-VAL-OPCODE-001",
    "L54-VAL-PROTO-001",
    "L54-VAL-REG-001",
    "L54-VAL-UPVAL-001",
    "L54-VAL-UPVAL-002",
    "L54-VARINT-001",
    "L55-CHUNK-001",
    "L55-CODE-001",
    "L55-CONST-001",
    "L55-HEADER-001",
    "L55-HEADER-002",
    "L55-HEADER-003",
    "L55-HEADER-004",
    "L55-JMP-001",
    "L55-OP-001",
    "L55-PROTO-001",
    "L55-STACK-001",
    "L55-STR-001",
    "L55-UPVAL-001",
    "L55-VARINT-001",
    "PARSE-001",
    "PARSE-SOURCE-001",
    "PARSE-UNKNOWN-001",
];

const CONTRIBUTOR_FILES: [&str; 19] = [
    "crates/luad-cli/src/main.rs",
    "crates/luad-core/src/reader.rs",
    "crates/luad-dialect-lua51/src/chunk.rs",
    "crates/luad-dialect-lua51/src/disasm.rs",
    "crates/luad-dialect-lua51/src/header.rs",
    "crates/luad-dialect-lua51/src/validator.rs",
    "crates/luad-dialect-lua52/src/chunk.rs",
    "crates/luad-dialect-lua52/src/header.rs",
    "crates/luad-dialect-lua52/src/validator.rs",
    "crates/luad-dialect-lua53/src/chunk.rs",
    "crates/luad-dialect-lua53/src/header.rs",
    "crates/luad-dialect-lua53/src/validator.rs",
    "crates/luad-dialect-lua54/src/chunk.rs",
    "crates/luad-dialect-lua54/src/disasm.rs",
    "crates/luad-dialect-lua54/src/header.rs",
    "crates/luad-dialect-lua54/src/validator.rs",
    "crates/luad-dialect-lua55/src/chunk.rs",
    "crates/luad-dialect-lua55/src/header.rs",
    "crates/luad-dialect-lua55/src/validator.rs",
];

const WARNING_CODES: [&str; 14] = [
    "L51-CHUNK-001",
    "L51-STACK-001",
    "L52-CHUNK-001",
    "L52-STACK-001",
    "L53-CHUNK-001",
    "L53-HEADER-003",
    "L53-HEADER-010",
    "L53-STACK-001",
    "L54-CHUNK-001",
    "L54-HEADER-003",
    "L54-VAL-REG-001",
    "L55-CHUNK-001",
    "L55-HEADER-003",
    "L55-STACK-001",
];

const CONTROL_FLOW_CODES: [&str; 5] = [
    "L51-JMP-001",
    "L52-JMP-001",
    "L53-JMP-001",
    "L54-VAL-JUMP-001",
    "L55-JMP-001",
];

const ANALYSIS_CODES: [&str; 1] = ["INTERNAL-IDENTITY-001"];

const STRUCTURE_CODES: [&str; 31] = [
    "IO-001",
    "L51-CHUNK-001",
    "L51-STACK-001",
    "L52-CHUNK-001",
    "L52-HEADER-003",
    "L52-STACK-001",
    "L53-CHUNK-001",
    "L53-HEADER-003",
    "L53-HEADER-004",
    "L53-HEADER-005",
    "L53-HEADER-006",
    "L53-HEADER-007",
    "L53-HEADER-008",
    "L53-HEADER-009",
    "L53-HEADER-010",
    "L53-STACK-001",
    "L54-CHUNK-001",
    "L54-HEADER-003",
    "L54-HEADER-004",
    "L54-HEADER-005",
    "L54-HEADER-006",
    "L54-HEADER-007",
    "L54-HEADER-008",
    "L54-HEADER-009",
    "L54-VAL-HEADER-001",
    "L54-VAL-HEADER-002",
    "L54-VAL-HEADER-003",
    "L55-CHUNK-001",
    "L55-HEADER-003",
    "L55-HEADER-004",
    "L55-STACK-001",
];

const INSTRUCTION_CODES: [&str; 27] = [
    "L51-BOOL-001",
    "L51-CLOSURE-001",
    "L51-CLOSURE-002",
    "L51-CONST-003",
    "L51-CONST-004",
    "L51-CONST-005",
    "L51-DISASM-001",
    "L51-DISASM-002",
    "L51-OP-001",
    "L51-PROTO-002",
    "L51-REG-001",
    "L51-REG-002",
    "L51-REG-003",
    "L51-REG-SPAN-001",
    "L51-UPVAL-001",
    "L52-OP-001",
    "L53-OP-001",
    "L54-INVALID-OPCODE",
    "L54-OOB-CONSTANT",
    "L54-OOB-PROTO",
    "L54-VAL-CONST-001",
    "L54-VAL-OPCODE-001",
    "L54-VAL-PROTO-001",
    "L54-VAL-REG-001",
    "L54-VAL-UPVAL-001",
    "L54-VAL-UPVAL-002",
    "L55-OP-001",
];

const CORE_TRUNC_SEMANTICS: &str = "Input ended before the requested byte range could be read.";
const CORE_TRUNC_ACTION: &str =
    "Verify that the chunk is complete and was extracted without truncation.";
const SPAN_SEMANTICS: &str = "A statically bounded instruction register window reaches beyond the owning prototype's maxstacksize.";
const SPAN_ACTION: &str = "Inspect the instruction counts and owning prototype stack bound.";
const INVALID_OPCODE_SEMANTICS: &str =
    "A Lua 5.4 instruction word contains an opcode not recognized by the dialect table.";
const INVALID_OPCODE_ACTION: &str =
    "Confirm the selected dialect and inspect the raw word for corruption or vendor changes.";
const SOURCE_SEMANTICS: &str =
    "The input is plain Lua source rather than compiled bytecode accepted by this command.";
const SOURCE_ACTION: &str = "Compile trusted source explicitly or provide a compiled Lua chunk.";

fn workspace() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn luad_bin() -> PathBuf {
    static LUAD: OnceLock<PathBuf> = OnceLock::new();
    LUAD.get_or_init(|| {
        if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
            return path.into();
        }
        let output = Command::new("cargo")
            .args(["build", "-p", "luad-cli", "--bin", "luad"])
            .current_dir(workspace())
            .output()
            .expect("build luad CLI");
        assert!(output.status.success(), "luad build failed");
        workspace().join("target/debug/luad")
    })
    .clone()
}

fn run(args: &[&str]) -> Output {
    Command::new(luad_bin())
        .args(args)
        .output()
        .expect("run luad")
}

fn catalog(code: Option<&str>) -> (Output, Value) {
    let mut args = vec!["diagnostics"];
    if let Some(code) = code {
        args.push(code);
    }
    args.extend_from_slice(&["--format", "json"]);
    let output = run(&args);
    let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "diagnostics stdout is not JSON: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, document)
}

fn collect_rs(dir: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            let name = path.file_name().and_then(|name| name.to_str());
            if name != Some("tests") && name != Some("luad-oracle") {
                collect_rs(&path, output);
            }
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs")
            && path.file_name().and_then(|name| name.to_str()) != Some("diagnostic_catalog.rs")
        {
            output.push(path);
        }
    }
}

fn production_sources() -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    collect_rs(&workspace().join("crates"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let mut source =
                strip_comments(&std::fs::read_to_string(&path).expect("read Rust source"));
            if let Some(test_module) = source.find("#[cfg(test)]") {
                let tail = &source[test_module..];
                assert!(
                    !tail.contains("Diagnostic::error(")
                        && !tail.contains("Diagnostic::warning(")
                        && !tail.contains("code: \""),
                    "production emission follows #[cfg(test)] in {}",
                    path.display()
                );
                source.truncate(test_module);
            }
            (path, source)
        })
        .collect()
}

fn strip_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut block_depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let current = bytes[index];
        let next = bytes.get(index + 1).copied();
        if block_depth > 0 {
            if current == b'/' && next == Some(b'*') {
                block_depth += 1;
                output.extend_from_slice(b"  ");
                index += 2;
            } else if current == b'*' && next == Some(b'/') {
                block_depth -= 1;
                output.extend_from_slice(b"  ");
                index += 2;
            } else {
                output.push(if current == b'\n' { b'\n' } else { b' ' });
                index += 1;
            }
            continue;
        }
        if !in_string && current == b'/' && next == Some(b'/') {
            while index < bytes.len() && bytes[index] != b'\n' {
                output.push(b' ');
                index += 1;
            }
            continue;
        }
        if !in_string && current == b'/' && next == Some(b'*') {
            block_depth = 1;
            output.extend_from_slice(b"  ");
            index += 2;
            continue;
        }
        output.push(current);
        if escaped {
            escaped = false;
        } else if in_string && current == b'\\' {
            escaped = true;
        } else if current == b'"' {
            in_string = !in_string;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment-stripped Rust remains UTF-8")
}

fn quoted_after(source: &str, start: usize) -> Option<String> {
    let rest = source.get(start..)?.trim_start();
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_string())
}

fn is_code(value: &str) -> bool {
    [
        "CORE-",
        "INTERNAL-",
        "IO-",
        "L51-",
        "L52-",
        "L53-",
        "L54-",
        "L55-",
        "PARSE-",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn category_in(window: &str) -> Option<String> {
    [
        ("DiagnosticCategory::Parse", "parse"),
        ("DiagnosticCategory::Structure", "structure"),
        ("DiagnosticCategory::Instruction", "instruction"),
        ("DiagnosticCategory::ControlFlow", "control-flow"),
        ("DiagnosticCategory::DebugMetadata", "debug-metadata"),
        ("DiagnosticCategory::Analysis", "analysis"),
    ]
    .into_iter()
    .find(|(token, _)| window.contains(token))
    .map(|(_, serialized)| serialized.to_string())
}

type EmittedMetadata = BTreeMap<String, BTreeSet<(String, String)>>;

fn source_inventory() -> (
    BTreeSet<String>,
    EmittedMetadata,
    BTreeSet<String>,
    Vec<String>,
) {
    let mut codes = BTreeSet::new();
    let mut metadata: EmittedMetadata = BTreeMap::new();
    let mut contributor_files = BTreeSet::new();
    let mut violations = Vec::new();
    for (path, source) in production_sources() {
        let mut contributed = false;
        for (marker, severity) in [
            ("Diagnostic::error(", "error"),
            ("Diagnostic::warning(", "warning"),
        ] {
            for (offset, _) in source.match_indices(marker) {
                let value_start = offset + marker.len();
                match quoted_after(&source, value_start) {
                    Some(code) if is_code(&code) => {
                        let window = &source[offset..source.len().min(offset + 400)];
                        if let Some(category) = category_in(window) {
                            codes.insert(code.clone());
                            contributed = true;
                            metadata
                                .entry(code)
                                .or_default()
                                .insert((severity.to_string(), category));
                        } else {
                            violations.push(format!(
                                "{}:{} has a nonliteral diagnostic category",
                                path.display(),
                                source[..offset].lines().count()
                            ));
                        }
                    }
                    _ => violations.push(format!(
                        "{}:{} has nonliteral diagnostic constructor code",
                        path.display(),
                        source[..offset].lines().count()
                    )),
                }
            }
        }

        for (offset, _) in source.match_indices("code:") {
            if let Some(code) = quoted_after(&source, offset + "code:".len()) {
                if is_code(&code) {
                    let window = &source[offset..source.len().min(offset + 400)];
                    let severity = if window.contains("Severity::Error") {
                        Some("error")
                    } else if window.contains("Severity::Warning") {
                        Some("warning")
                    } else if window.contains("Severity::Info") {
                        Some("info")
                    } else {
                        None
                    };
                    if let (Some(severity), Some(category)) = (severity, category_in(window)) {
                        codes.insert(code.clone());
                        contributed = true;
                        metadata
                            .entry(code)
                            .or_default()
                            .insert((severity.to_string(), category));
                    }
                }
            }
        }

        for marker in ["= Diagnostic {", "(Diagnostic {"] {
            for (offset, _) in source.match_indices(marker) {
                let tail = &source[offset..source.len().min(offset + 600)];
                if !tail.contains("code: \"") {
                    violations.push(format!(
                        "{}:{} has a direct diagnostic without a literal code",
                        path.display(),
                        source[..offset].lines().count()
                    ));
                }
            }
        }
        if contributed {
            contributor_files.insert(
                path.strip_prefix(workspace())
                    .expect("source beneath workspace")
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }
    (codes, metadata, contributor_files, violations)
}

fn expected_metadata(code: &str) -> (&'static str, &'static str) {
    let severity = if WARNING_CODES.contains(&code) {
        "warning"
    } else {
        "error"
    };
    let category = if ANALYSIS_CODES.contains(&code) {
        "analysis"
    } else if CONTROL_FLOW_CODES.contains(&code) {
        "control-flow"
    } else if STRUCTURE_CODES.contains(&code) {
        "structure"
    } else if INSTRUCTION_CODES.contains(&code) {
        "instruction"
    } else {
        "parse"
    };
    (severity, category)
}

fn descriptors(document: &Value) -> &[Value] {
    document["diagnostics"]
        .as_array()
        .expect("diagnostics descriptor array")
}

fn descriptor<'a>(document: &'a Value, code: &str) -> &'a Value {
    descriptors(document)
        .iter()
        .find(|item| item["code"].as_str() == Some(code))
        .unwrap_or_else(|| panic!("missing descriptor {code}"))
}

fn compare_catalog(expected_codes: &[&str], actual: &[Value]) -> Result<(), String> {
    let actual_codes: Vec<_> = actual
        .iter()
        .map(|item| item["code"].as_str().unwrap_or_default())
        .collect();
    if actual_codes != expected_codes {
        return Err("code set or ordering mismatch".to_string());
    }
    for item in actual {
        if !matches!(
            item["severity"].as_str(),
            Some("info" | "warning" | "error")
        ) {
            return Err("invalid severity".to_string());
        }
        if !matches!(
            item["category"].as_str(),
            Some(
                "parse"
                    | "structure"
                    | "instruction"
                    | "control-flow"
                    | "debug-metadata"
                    | "analysis"
            )
        ) {
            return Err("invalid category".to_string());
        }
        if item["semantics"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err("blank semantics".to_string());
        }
        if item["suggested_action"]
            .as_str()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err("blank suggested action".to_string());
        }
    }
    Ok(())
}

fn schema_named<'a>(value: &'a Value, title: &str) -> Option<&'a Value> {
    if value["title"].as_str() == Some(title) {
        return Some(value);
    }
    match value {
        Value::Object(map) => map.values().find_map(|child| schema_named(child, title)),
        Value::Array(items) => items.iter().find_map(|child| schema_named(child, title)),
        _ => None,
    }
}

fn required(schema: &Value) -> BTreeSet<String> {
    schema["required"]
        .as_array()
        .expect("required array")
        .iter()
        .map(|field| field.as_str().expect("required field").to_string())
        .collect()
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.contains_key(key) || map.values().any(|child| contains_key(child, key))
        }
        Value::Array(items) => items.iter().any(|child| contains_key(child, key)),
        _ => false,
    }
}

fn text_blocks(text: &str) -> Vec<String> {
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len() % 3, 0, "catalog text must use three-line rows");
    lines
        .chunks(3)
        .map(|lines| format!("{}\n{}\n{}\n", lines[0], lines[1], lines[2]))
        .collect()
}

#[test]
fn test_catalog_code_set_matches_independent_production_inventory() {
    let pinned: BTreeSet<_> = PINNED_CODES.iter().map(|code| code.to_string()).collect();
    let (source, metadata, contributors, violations) = source_inventory();
    assert!(violations.is_empty(), "source violations: {violations:?}");
    assert_eq!(source, pinned, "pinned inventory and emitters diverged");
    assert_eq!(
        contributors,
        CONTRIBUTOR_FILES
            .iter()
            .map(|path| path.to_string())
            .collect(),
        "diagnostic contributor files diverged"
    );
    assert!(
        workspace()
            .join("crates/luad-core/src/diagnostic_catalog.rs")
            .is_file(),
        "the pinned catalog module is absent"
    );

    let (output, document) = catalog(None);
    assert!(output.status.success(), "diagnostics command failed");
    let public: BTreeSet<_> = descriptors(&document)
        .iter()
        .map(|item| item["code"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(public, pinned, "public catalog and emitters diverged");
    for item in descriptors(&document) {
        let code = item["code"].as_str().unwrap();
        let emitted = metadata
            .get(code)
            .unwrap_or_else(|| panic!("no metadata for {code}"));
        assert_eq!(emitted.len(), 1, "{code} has inconsistent emitted metadata");
        let expected = emitted.iter().next().unwrap();
        assert_eq!(
            expected_metadata(code),
            (expected.0.as_str(), expected.1.as_str())
        );
        assert_eq!(
            item["severity"].as_str(),
            Some(expected.0.as_str()),
            "{code}"
        );
        assert_eq!(
            item["category"].as_str(),
            Some(expected.1.as_str()),
            "{code}"
        );
    }
}

#[test]
fn test_production_emitters_use_literal_diagnostic_codes() {
    let (_, metadata, _, violations) = source_inventory();
    assert!(violations.is_empty(), "source violations: {violations:?}");
    assert_eq!(metadata.len(), PINNED_CODES.len());
    for (code, emitted) in metadata {
        assert_eq!(emitted.len(), 1, "{code} has inconsistent metadata");
        let actual = emitted.iter().next().unwrap();
        assert_eq!(
            expected_metadata(&code),
            (actual.0.as_str(), actual.1.as_str())
        );
    }
}

#[test]
fn test_catalog_descriptors_are_unique_sorted_complete_and_actionable() {
    let (_, document) = catalog(None);
    assert!(PINNED_CODES.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(document["schema_version"].as_u64(), Some(1));
    assert_eq!(
        document["diagnostic_count"].as_u64(),
        Some(PINNED_CODES.len() as u64)
    );
    assert_eq!(descriptors(&document).len(), PINNED_CODES.len());
    assert!(compare_catalog(&PINNED_CODES, descriptors(&document)).is_ok());

    let required_fields: BTreeSet<_> = [
        "code",
        "severity",
        "category",
        "semantics",
        "suggested_action",
    ]
    .into_iter()
    .collect();
    for item in descriptors(&document) {
        assert_eq!(
            item.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            required_fields,
            "descriptor fields changed for {}",
            item["code"]
        );
        for field in ["semantics", "suggested_action"] {
            let value = item[field].as_str().unwrap();
            assert_eq!(
                value,
                value.trim(),
                "{field} is not trimmed for {}",
                item["code"]
            );
            assert!(
                (12..=320).contains(&value.len()),
                "{field} is not bounded for {}",
                item["code"]
            );
            let uppercase = value.to_ascii_uppercase();
            assert!(
                !["TODO", "TBD", "N/A"]
                    .iter()
                    .any(|placeholder| uppercase.contains(placeholder)),
                "placeholder {field} for {}",
                item["code"]
            );
        }
    }

    let exact = [
        (
            "CORE-TRUNC-001",
            "error",
            "parse",
            CORE_TRUNC_SEMANTICS,
            CORE_TRUNC_ACTION,
        ),
        (
            "L51-REG-SPAN-001",
            "error",
            "instruction",
            SPAN_SEMANTICS,
            SPAN_ACTION,
        ),
        (
            "L54-INVALID-OPCODE",
            "error",
            "instruction",
            INVALID_OPCODE_SEMANTICS,
            INVALID_OPCODE_ACTION,
        ),
        (
            "PARSE-SOURCE-001",
            "error",
            "parse",
            SOURCE_SEMANTICS,
            SOURCE_ACTION,
        ),
    ];
    for (code, severity, category, semantics, action) in exact {
        let item = descriptor(&document, code);
        assert_eq!(item["severity"].as_str(), Some(severity));
        assert_eq!(item["category"].as_str(), Some(category));
        assert_eq!(item["semantics"].as_str(), Some(semantics));
        assert_eq!(item["suggested_action"].as_str(), Some(action));
    }
}

#[test]
fn test_public_json_list_and_lookup_are_schema_valid_deterministic() {
    let schema_output = run(&["schema", "diagnostics"]);
    assert!(schema_output.status.success(), "diagnostics schema failed");
    let schema: Value = serde_json::from_slice(&schema_output.stdout).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("compile diagnostics schema");
    assert_eq!(
        required(schema_named(&schema, "DiagnosticCatalogResponse").expect("response schema")),
        [
            "schema_version",
            "tool_version",
            "diagnostic_count",
            "diagnostics"
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    );
    assert_eq!(
        required(schema_named(&schema, "DiagnosticDescriptor").expect("descriptor schema")),
        [
            "code",
            "severity",
            "category",
            "semantics",
            "suggested_action"
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    );

    let first = catalog(None);
    let second = catalog(None);
    assert!(first.0.status.success() && second.0.status.success());
    assert!(first.0.stderr.is_empty() && second.0.stderr.is_empty());
    assert_eq!(first.0.stdout, second.0.stdout);
    let errors: Vec<_> = validator
        .iter_errors(&first.1)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "catalog schema errors: {errors:?}");
    let version = run(&["--version"]);
    let version = String::from_utf8(version.stdout).unwrap();
    assert_eq!(
        first.1["tool_version"].as_str(),
        version.trim().strip_prefix("luad ")
    );
    assert!(!contains_key(&first.1, "input_identity"));
    assert!(!contains_key(&first.1, "interpretation"));

    let (lookup_output, lookup) = catalog(Some("L51-REG-SPAN-001"));
    assert!(lookup_output.status.success());
    assert!(lookup_output.stderr.is_empty());
    let errors: Vec<_> = validator
        .iter_errors(&lookup)
        .map(|error| error.to_string())
        .collect();
    assert!(errors.is_empty(), "lookup schema errors: {errors:?}");
    assert_eq!(lookup["diagnostic_count"].as_u64(), Some(1));
    assert_eq!(descriptors(&lookup)[0]["code"], "L51-REG-SPAN-001");
}

#[test]
fn test_public_text_list_and_lookup_golden() {
    let lookup = run(&["diagnostics", "L51-REG-SPAN-001", "--format", "text"]);
    assert!(lookup.status.success());
    assert!(lookup.stderr.is_empty());
    let expected = format!(
        "L51-REG-SPAN-001 [error/instruction]\n  Semantics: {SPAN_SEMANTICS}\n  Next action: {SPAN_ACTION}\n"
    );
    assert_eq!(String::from_utf8(lookup.stdout).unwrap(), expected);

    let list = run(&["diagnostics", "--format", "text"]);
    assert!(list.status.success());
    assert!(list.stderr.is_empty());
    let text = String::from_utf8(list.stdout).unwrap();
    assert!(text.starts_with("CORE-LIMIT-001 ["));
    assert!(text.contains("\nPARSE-SOURCE-001 ["));
    assert!(text.contains("\nPARSE-UNKNOWN-001 ["));
    assert_eq!(text.matches("\n  Semantics: ").count(), PINNED_CODES.len());
    assert_eq!(
        text.matches("\n  Next action: ").count(),
        PINNED_CODES.len()
    );
    assert!(!text.contains("\u{1b}["));

    let blocks = text_blocks(&text);
    for code in [
        "CORE-TRUNC-001",
        "L51-REG-SPAN-001",
        "L54-INVALID-OPCODE",
        "PARSE-SOURCE-001",
    ] {
        let block = blocks
            .iter()
            .find(|block| block.starts_with(code))
            .unwrap_or_else(|| panic!("missing text block {code}"));
        let lookup = run(&["diagnostics", code, "--format", "text"]);
        assert_eq!(
            lookup.stdout,
            block.as_bytes(),
            "lookup/list renderer diverged for {code}"
        );
    }
    let default = run(&["diagnostics", "L51-REG-SPAN-001"]);
    assert_eq!(default.stdout, expected.as_bytes());
}

#[test]
fn test_unknown_code_fails_closed() {
    for code in ["L51-REG", "l51-reg-span-001", "L51-REG-SPAN-999"] {
        let output = run(&["diagnostics", code, "--format", "json"]);
        assert_eq!(output.status.code(), Some(2), "unknown code status: {code}");
        assert!(
            output.stdout.is_empty(),
            "unknown code produced stdout: {code}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr, format!("error: Unknown diagnostic code '{code}'\n"));
    }
    for args in [
        vec!["diagnostics", "--format", "jsonl"],
        vec!["diagnostics", "--format", "dot"],
        vec!["diagnostics", "CORE-TRUNC-001", "EXTRA"],
    ] {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "invalid args succeeded: {args:?}"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn test_catalog_comparator_rejects_killer_mutations() {
    let baseline = vec![
        json!({"code":"A-001","severity":"error","category":"parse","semantics":"one","suggested_action":"act"}),
        json!({"code":"B-001","severity":"warning","category":"analysis","semantics":"two","suggested_action":"review"}),
    ];
    let expected = ["A-001", "B-001"];
    assert!(compare_catalog(&expected, &baseline).is_ok());

    let mut mutants = Vec::new();
    mutants.push(vec![baseline[0].clone()]);
    mutants.push(vec![baseline[0].clone(), baseline[1].clone(), json!({"code":"C-001","severity":"error","category":"parse","semantics":"extra","suggested_action":"act"})]);
    mutants.push(vec![baseline[0].clone(), baseline[0].clone()]);
    mutants.push(vec![baseline[1].clone(), baseline[0].clone()]);
    for (field, value) in [
        ("severity", json!("fact")),
        ("category", json!("security")),
        ("semantics", json!("")),
        ("suggested_action", json!("")),
    ] {
        let mut changed = baseline.clone();
        changed[0][field] = value;
        mutants.push(changed);
    }
    for mutant in mutants {
        assert!(compare_catalog(&expected, &mutant).is_err());
    }
    assert!(!strip_comments("// Diagnostic::error(\"FAKE-001\")\nlet x = 1;").contains("FAKE-001"));

    let schema = json!({
        "title": "DiagnosticDescriptor",
        "required": ["code", "severity", "category", "semantics", "suggested_action"]
    });
    assert_eq!(required(&schema).len(), 5);
    let mut missing = schema;
    missing["required"] = json!(["code", "severity", "category", "semantics"]);
    assert_ne!(required(&missing).len(), 5);
}

#[test]
fn test_existing_diagnostic_instance_schema_remains_compatible() {
    let output = run(&["schema", "diagnostic"]);
    assert!(output.status.success());
    let live: Value = serde_json::from_slice(&output.stdout).expect("live diagnostic schema");
    let golden: Value = serde_json::from_slice(
        &std::fs::read(workspace().join("tests/schemas/diagnostic.schema.json"))
            .expect("diagnostic schema golden"),
    )
    .expect("golden diagnostic schema");
    assert_eq!(live, golden);
    let catalog = run(&["schema", "diagnostics"]);
    assert!(catalog.status.success());
    assert_ne!(output.stdout, catalog.stdout);
}
