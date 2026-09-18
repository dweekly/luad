//! Public, mutation-sensitive evidence for bounded Lua 5.1 call-argument origins.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::process::Command;

use luad_analysis::{
    analyze_chunk_origins, CallArgumentWindow, CallOriginFact, ChunkOriginAnalysis,
    OriginExpression, OriginExpressionKind, OriginLiteral, OriginUnknownReason,
};
use luad_core::envelope::{JsonlDataRecord, MachineDocument};
use luad_core::model::LuaString;
use luad_core::{ProtoPath, TypedOperand};

fn fixture_source() -> String {
    let root = luad_oracle::find_workspace_root();
    std::fs::read_to_string(root.join("tests/fixtures/origins.lua")).expect("read origins.lua")
}

fn fixture_chunk() -> luad_core::Chunk {
    let _ = luad_oracle::require_luac51();
    luad_oracle::compile_and_parse_lua51(&fixture_source(), false).expect("compile fixture")
}

fn compiled_fixture_file() -> tempfile::NamedTempFile {
    let bytes = luad_oracle::compile_source_lua51(&fixture_source(), false)
        .expect("compile origins fixture");
    let mut file = tempfile::NamedTempFile::new().expect("temp fixture");
    file.write_all(&bytes).expect("write fixture");
    file
}

fn get_luad_bin() -> String {
    luad_oracle::luad_binary_path().display().to_string()
}

fn all_facts(analysis: &ChunkOriginAnalysis) -> Vec<&CallOriginFact> {
    analysis
        .prototypes
        .iter()
        .flat_map(|prototype| &prototype.calls)
        .collect()
}

fn fixed_origins(analysis: &ChunkOriginAnalysis) -> Vec<&OriginExpression> {
    all_facts(analysis)
        .into_iter()
        .flat_map(|fact| match &fact.argument_window {
            CallArgumentWindow::Fixed { arguments } => {
                arguments.iter().map(|argument| &argument.origin).collect()
            }
            CallArgumentWindow::Open { .. } => vec![],
        })
        .collect()
}

fn root_kind(expression: &OriginExpression) -> &'static str {
    match expression.kind {
        OriginExpressionKind::Literal { .. } => "literal",
        OriginExpressionKind::Parameter { .. } => "parameter",
        OriginExpressionKind::Upvalue { .. } => "upvalue",
        OriginExpressionKind::Prototype { .. } => "prototype",
        OriginExpressionKind::Global { .. } => "global",
        OriginExpressionKind::Field { .. } => "field",
        OriginExpressionKind::CallResult { .. } => "call-result",
        OriginExpressionKind::Concat { .. } => "concat",
        OriginExpressionKind::Table { .. } => "table",
        OriginExpressionKind::TableLiteral { .. } => "table-literal",
        OriginExpressionKind::Unary { .. } => "unary",
        OriginExpressionKind::Binary { .. } => "binary",
        OriginExpressionKind::Unknown { .. } => "unknown",
    }
}

fn has_string_literal(expression: &OriginExpression, expected: &str) -> bool {
    matches!(
        &expression.kind,
        OriginExpressionKind::Literal {
            value: OriginLiteral::String { value },
            ..
        } if value.as_str() == expected
    )
}

fn assert_evidence_tree(expression: &OriginExpression) {
    assert!(
        !expression.evidence.is_empty(),
        "every expression node must retain evidence: {expression:?}"
    );
    assert!(
        expression.evidence.windows(2).all(|pair| pair[0] < pair[1]),
        "evidence must be sorted and unique"
    );
    match &expression.kind {
        OriginExpressionKind::Field { base, .. }
        | OriginExpressionKind::Unary { operand: base, .. } => assert_evidence_tree(base),
        OriginExpressionKind::Binary { left, right, .. } => {
            assert_evidence_tree(left);
            assert_evidence_tree(right);
        }
        OriginExpressionKind::Concat { parts } => {
            parts.iter().for_each(assert_evidence_tree);
        }
        OriginExpressionKind::Table { entries } => {
            entries.iter().for_each(assert_evidence_tree);
        }
        OriginExpressionKind::TableLiteral { fields, .. } => {
            for field in fields {
                assert!(
                    !field.evidence.is_empty(),
                    "field write evidence must not be empty"
                );
                assert!(
                    field.evidence.windows(2).all(|pair| pair[0] < pair[1]),
                    "field evidence must be sorted and unique"
                );
                assert_evidence_tree(&field.value);
            }
        }
        _ => {}
    }
}

#[test]
fn test_origin_matrix_histogram_and_cardinality_are_pinned() {
    let analysis = analyze_chunk_origins(&fixture_chunk());
    let facts = all_facts(&analysis);
    assert_eq!(facts.len(), 31);
    assert_eq!(
        facts
            .iter()
            .filter(|fact| matches!(fact.argument_window, CallArgumentWindow::Open { .. }))
            .count(),
        1
    );
    let origins = fixed_origins(&analysis);
    assert_eq!(origins.len(), 48);
    let mut histogram = BTreeMap::new();
    for origin in origins {
        *histogram.entry(root_kind(origin)).or_insert(0usize) += 1;
        assert_evidence_tree(origin);
    }
    assert_eq!(
        histogram,
        BTreeMap::from([
            ("binary", 7),
            ("call-result", 2),
            ("concat", 1),
            ("field", 2),
            ("literal", 13),
            ("parameter", 6),
            ("prototype", 1),
            ("table-literal", 6),
            ("unary", 3),
            ("unknown", 7),
        ])
    );
}

#[test]
fn test_origins_preserve_concat_mod_captures_and_explicit_stops() {
    let analysis = analyze_chunk_origins(&fixture_chunk());
    let origins = fixed_origins(&analysis);

    let concat = origins
        .iter()
        .find(|origin| matches!(origin.kind, OriginExpressionKind::Concat { .. }))
        .expect("concat origin");
    let OriginExpressionKind::Concat { parts } = &concat.kind else {
        unreachable!()
    };
    assert_eq!(parts.len(), 3);
    assert!(has_string_literal(&parts[0], "prefix:"));
    assert!(matches!(
        parts[1].kind,
        OriginExpressionKind::Parameter { index: 0, .. }
    ));
    assert!(has_string_literal(&parts[2], ":suffix"));

    let formatting = origins
        .iter()
        .find(|origin| {
            matches!(
                &origin.kind,
                OriginExpressionKind::Binary { operator, left, .. }
                    if operator == "MOD" && has_string_literal(left, "value=%s")
            )
        })
        .expect("LuCI formatting-shaped MOD");
    let OriginExpressionKind::Binary { right, .. } = &formatting.kind else {
        unreachable!()
    };
    let OriginExpressionKind::Table { entries } = &right.kind else {
        panic!("MOD right operand must retain table construction")
    };
    assert!(matches!(
        entries.as_slice(),
        [OriginExpression {
            kind: OriginExpressionKind::Parameter { index: 0, .. },
            ..
        }]
    ));

    let nested = all_facts(&analysis)
        .into_iter()
        .find(|fact| fact.proto_path == "0/2/0/0".parse::<ProtoPath>().expect("path"))
        .expect("grandchild call");
    let CallArgumentWindow::Fixed { arguments } = &nested.argument_window else {
        panic!("fixed nested arguments")
    };
    let owners: Vec<_> = arguments
        .iter()
        .filter_map(|argument| match &argument.origin.kind {
            OriginExpressionKind::Parameter { owner, .. } => Some(owner.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(owners, ["0/2", "0/2/0", "0/2/0/0"]);

    let proto_origin = origins
        .iter()
        .find(|origin| matches!(origin.kind, OriginExpressionKind::Prototype { .. }))
        .expect("prototype origin");
    assert_eq!(
        proto_origin.kind,
        OriginExpressionKind::Prototype {
            prototype: "0/3/0".parse().expect("child proto path")
        }
    );
    assert!(!proto_origin.evidence.is_empty());

    for reason in [
        OriginUnknownReason::DynamicKey,
        OriginUnknownReason::ControlFlowConflict,
        OriginUnknownReason::VarargValue,
        OriginUnknownReason::UnsupportedValue,
        OriginUnknownReason::ExpressionDepthLimit,
        OriginUnknownReason::Unreachable,
    ] {
        assert!(origins.iter().any(|origin| {
            matches!(origin.kind, OriginExpressionKind::Unknown { reason: actual } if actual == reason)
        }));
    }
    assert!(all_facts(&analysis).iter().any(|fact| matches!(
        fact.argument_window,
        CallArgumentWindow::Open {
            reason: OriginUnknownReason::OpenArgumentWindow
        }
    )));
}

#[test]
fn test_sibling_closure_mutation_prevents_stale_capture_origin() {
    let source = r#"
local sink = function(...) return ... end
local function outer(parameter)
  local shared = parameter
  local function reader() sink(shared) end
  local function writer() shared = "changed" end
  reader()
  writer()
end
outer("value")
"#;
    let chunk = luad_oracle::compile_and_parse_lua51(source, false).expect("compile sibling case");
    let analysis = analyze_chunk_origins(&chunk);
    assert!(fixed_origins(&analysis).iter().any(|origin| matches!(
        origin.kind,
        OriginExpressionKind::Unknown {
            reason: OriginUnknownReason::MutableCapture
        }
    )));
}

#[test]
fn test_every_call_and_fixed_argument_slot_has_exactly_one_fact() {
    fn collect_expected(
        dialect: &str,
        proto: &luad_core::Prototype,
        output: &mut BTreeMap<String, Option<usize>>,
    ) {
        for instruction in luad_analysis::lift_proto_for_dialect(dialect, proto) {
            if !matches!(instruction.mnemonic.as_str(), "CALL" | "TAILCALL") {
                continue;
            }
            let count = instruction
                .operands
                .iter()
                .find_map(|operand| match operand {
                    TypedOperand::Count { value, is_variable } => Some((*value, *is_variable)),
                    _ => None,
                })
                .and_then(|(value, is_variable)| (!is_variable).then_some(value.saturating_sub(1)));
            output.insert(instruction.id.to_string(), count);
        }
        for child in &proto.protos {
            collect_expected(dialect, child, output);
        }
    }

    let chunk = fixture_chunk();
    let analysis = analyze_chunk_origins(&chunk);
    let mut expected = BTreeMap::new();
    collect_expected(&chunk.dialect, &chunk.main_proto, &mut expected);
    let facts = all_facts(&analysis);
    assert_eq!(facts.len(), expected.len());
    assert_eq!(
        facts
            .iter()
            .map(|fact| fact.call_id.to_string())
            .collect::<BTreeSet<_>>()
            .len(),
        facts.len()
    );
    for fact in facts {
        match (expected[&fact.call_id.to_string()], &fact.argument_window) {
            (Some(count), CallArgumentWindow::Fixed { arguments }) => {
                assert_eq!(arguments.len(), count);
                for (index, argument) in arguments.iter().enumerate() {
                    assert_eq!(argument.argument_index, index);
                    assert_eq!(argument.register, fact.callee_register + 1 + index as u8);
                }
            }
            (None, CallArgumentWindow::Open { .. }) => {}
            other => panic!("argument-window mismatch: {other:?}"),
        }
    }
}

#[test]
fn test_origin_killer_mutations_are_rejected() {
    fn reject(expected: &ChunkOriginAnalysis, mutation: ChunkOriginAnalysis) {
        assert_ne!(
            &mutation, expected,
            "mutated origin output must be rejected"
        );
    }

    let expected = analyze_chunk_origins(&fixture_chunk());

    let mut missing_argument = expected.clone();
    let arguments = missing_argument
        .prototypes
        .iter_mut()
        .flat_map(|prototype| &mut prototype.calls)
        .find_map(|fact| match &mut fact.argument_window {
            CallArgumentWindow::Fixed { arguments } if arguments.len() > 1 => Some(arguments),
            _ => None,
        })
        .expect("multi-argument call");
    arguments.pop();
    reject(&expected, missing_argument);

    let mut missing_concat_part = expected.clone();
    let OriginExpressionKind::Concat { parts } =
        &mut fixed_origin_mut(&mut missing_concat_part, |origin| {
            matches!(origin.kind, OriginExpressionKind::Concat { .. })
        })
        .kind
    else {
        unreachable!()
    };
    parts.pop();
    reject(&expected, missing_concat_part);

    let mut relabeled_mod = expected.clone();
    let OriginExpressionKind::Binary { operator, .. } =
        &mut fixed_origin_mut(&mut relabeled_mod, |origin| {
            matches!(&origin.kind, OriginExpressionKind::Binary { operator, left, .. }
                if operator == "MOD" && has_string_literal(left, "value=%s"))
        })
        .kind
    else {
        unreachable!()
    };
    *operator = "FORMAT".to_string();
    reject(&expected, relabeled_mod);

    let mut erased_conflict = expected.clone();
    fixed_origin_mut(&mut erased_conflict, |origin| {
        matches!(
            origin.kind,
            OriginExpressionKind::Unknown {
                reason: OriginUnknownReason::ControlFlowConflict
            }
        )
    })
    .kind = OriginExpressionKind::Parameter {
        owner: ProtoPath::root(),
        index: 0,
    };
    reject(&expected, erased_conflict);

    let mut erased_cutoff = expected.clone();
    fixed_origin_mut(&mut erased_cutoff, |origin| {
        matches!(
            origin.kind,
            OriginExpressionKind::Unknown {
                reason: OriginUnknownReason::ExpressionDepthLimit
            }
        )
    })
    .kind = OriginExpressionKind::Unknown {
        reason: OriginUnknownReason::Overwritten,
    };
    reject(&expected, erased_cutoff);

    let mut mutated_prototype_origin = expected.clone();
    fixed_origin_mut(&mut mutated_prototype_origin, |origin| {
        matches!(origin.kind, OriginExpressionKind::Prototype { .. })
    })
    .kind = OriginExpressionKind::Prototype {
        prototype: "0/999".parse::<ProtoPath>().expect("path"),
    };
    reject(&expected, mutated_prototype_origin);

    let mut mutated_prototype_evidence = expected.clone();
    fixed_origin_mut(&mut mutated_prototype_evidence, |origin| {
        matches!(origin.kind, OriginExpressionKind::Prototype { .. })
    })
    .evidence
    .clear();
    reject(&expected, mutated_prototype_evidence);

    let mut omitted_table_field = expected.clone();
    let OriginExpressionKind::TableLiteral { fields, .. } =
        &mut fixed_origin_mut(&mut omitted_table_field, |origin| {
            matches!(&origin.kind, OriginExpressionKind::TableLiteral { fields, .. } if fields.len() > 1)
        })
        .kind
    else {
        unreachable!()
    };
    fields.pop();
    reject(&expected, omitted_table_field);

    let mut substituted_table_field_key = expected.clone();
    let OriginExpressionKind::TableLiteral { fields, .. } =
        &mut fixed_origin_mut(&mut substituted_table_field_key, |origin| {
            matches!(&origin.kind, OriginExpressionKind::TableLiteral { fields, .. } if !fields.is_empty())
        })
        .kind
    else {
        unreachable!()
    };
    fields[0].key = OriginLiteral::String {
        value: LuaString::from_bytes(b"mutated_key"),
    };
    reject(&expected, substituted_table_field_key);

    let mut substituted_table_field_value = expected.clone();
    let OriginExpressionKind::TableLiteral { fields, .. } =
        &mut fixed_origin_mut(&mut substituted_table_field_value, |origin| {
            matches!(&origin.kind, OriginExpressionKind::TableLiteral { fields, .. } if !fields.is_empty())
        })
        .kind
    else {
        unreachable!()
    };
    fields[0].value.kind = OriginExpressionKind::Unknown {
        reason: OriginUnknownReason::DynamicKey,
    };
    reject(&expected, substituted_table_field_value);

    let mut toggled_table_incomplete = expected.clone();
    let OriginExpressionKind::TableLiteral { incomplete, .. } =
        &mut fixed_origin_mut(&mut toggled_table_incomplete, |origin| {
            matches!(
                &origin.kind,
                OriginExpressionKind::TableLiteral {
                    incomplete: false,
                    ..
                }
            )
        })
        .kind
    else {
        unreachable!()
    };
    *incomplete = true;
    reject(&expected, toggled_table_incomplete);

    let mut mutated_table_evidence = expected.clone();
    fixed_origin_mut(&mut mutated_table_evidence, |origin| {
        matches!(origin.kind, OriginExpressionKind::TableLiteral { .. })
    })
    .evidence
    .clear();
    reject(&expected, mutated_table_evidence);
}

#[test]
fn test_constant_key_table_literal_origins_emit_table_literal_expression() {
    let analysis = analyze_chunk_origins(&fixture_chunk());
    let origins = fixed_origins(&analysis);

    let table_literals: Vec<_> = origins
        .iter()
        .filter(|origin| matches!(origin.kind, OriginExpressionKind::TableLiteral { .. }))
        .collect();
    assert!(!table_literals.is_empty(), "must find table literals");

    // 1. Complete table: fields [a, b], incomplete: false
    let complete = table_literals
        .iter()
        .find(|origin| match &origin.kind {
            OriginExpressionKind::TableLiteral { fields, incomplete } => {
                !incomplete
                    && fields.len() == 2
                    && matches!(&fields[0].key, OriginLiteral::String { value } if value.as_str() == "a")
                    && matches!(&fields[1].key, OriginLiteral::String { value } if value.as_str() == "b")
            }
            _ => false,
        })
        .expect("complete table literal");
    let OriginExpressionKind::TableLiteral { fields, incomplete } = &complete.kind else {
        unreachable!()
    };
    assert!(!incomplete);
    assert_eq!(fields.len(), 2);
    assert_eq!(
        fields[0].key,
        OriginLiteral::String {
            value: LuaString::from_bytes(b"a")
        }
    );
    assert!(matches!(
        &fields[0].value.kind,
        OriginExpressionKind::Literal {
            value: OriginLiteral::String { value },
            ..
        } if value.as_str() == "x"
    ));
    assert!(!fields[0].evidence.is_empty());
    assert_eq!(
        fields[1].key,
        OriginLiteral::String {
            value: LuaString::from_bytes(b"b")
        }
    );
    assert!(matches!(
        &fields[1].value.kind,
        OriginExpressionKind::Parameter { index: 0, .. }
    ));
    assert!(!fields[1].evidence.is_empty());
    assert!(!complete.evidence.is_empty());

    // 2. Dynamic key table: incomplete: true, field "a" retained
    let dynamic = table_literals
        .iter()
        .find(|origin| match &origin.kind {
            OriginExpressionKind::TableLiteral { fields, incomplete } => {
                *incomplete
                    && fields.len() == 1
                    && matches!(&fields[0].key, OriginLiteral::String { value } if value.as_str() == "a")
            }
            _ => false,
        })
        .expect("dynamic key table literal");
    assert!(matches!(
        dynamic.kind,
        OriginExpressionKind::TableLiteral {
            incomplete: true,
            ..
        }
    ));

    // 3. Post-construction escape: incomplete: true, fields [a, b]
    let escaped = table_literals
        .iter()
        .find(|origin| match &origin.kind {
            OriginExpressionKind::TableLiteral { fields, incomplete } => {
                *incomplete && fields.len() == 2
            }
            _ => false,
        })
        .expect("escaped table literal");
    assert!(matches!(
        escaped.kind,
        OriginExpressionKind::TableLiteral {
            incomplete: true,
            ..
        }
    ));

    // 4. Aliased table: fields [a, b], incomplete: false
    let aliased = table_literals
        .iter()
        .filter(|origin| match &origin.kind {
            OriginExpressionKind::TableLiteral { fields, incomplete } => {
                !incomplete
                    && fields.len() == 2
                    && matches!(
                        &fields[1].value.kind,
                        OriginExpressionKind::Literal {
                            value: OriginLiteral::String { value },
                            ..
                        } if value.as_str() == "y"
                    )
            }
            _ => false,
        })
        .count();
    assert!(aliased >= 1, "must find aliased table literal");

    // 5. Overwrite / conflicting writes: incomplete: true, field "a" = "second"
    let overwrite = table_literals
        .iter()
        .find(|origin| match &origin.kind {
            OriginExpressionKind::TableLiteral { fields, incomplete } => {
                *incomplete
                    && fields.len() == 1
                    && matches!(
                        &fields[0].value.kind,
                        OriginExpressionKind::Literal {
                            value: OriginLiteral::String { value },
                            ..
                        } if value.as_str() == "second"
                    )
            }
            _ => false,
        })
        .expect("overwrite table literal");
    assert!(matches!(
        overwrite.kind,
        OriginExpressionKind::TableLiteral {
            incomplete: true,
            ..
        }
    ));
}

fn fixed_origin_mut(
    analysis: &mut ChunkOriginAnalysis,
    predicate: impl Fn(&OriginExpression) -> bool,
) -> &mut OriginExpression {
    analysis
        .prototypes
        .iter_mut()
        .flat_map(|prototype| &mut prototype.calls)
        .find_map(|fact| match &mut fact.argument_window {
            CallArgumentWindow::Fixed { arguments } => arguments
                .iter_mut()
                .map(|argument| &mut argument.origin)
                .find(|origin| predicate(origin)),
            CallArgumentWindow::Open { .. } => None,
        })
        .expect("matching origin")
}

#[test]
fn test_public_origins_json_jsonl_and_text_agree() {
    let luad = get_luad_bin();
    let fixture = compiled_fixture_file();
    let path = fixture.path().to_str().expect("path");
    let json = Command::new(&luad)
        .args(["origins", path, "--format", "json"])
        .output()
        .expect("origins json");
    assert!(json.status.success());
    let document: MachineDocument<ChunkOriginAnalysis> =
        serde_json::from_slice(&json.stdout).expect("typed origins document");
    let expected: Vec<_> = all_facts(&document.data).into_iter().cloned().collect();

    let jsonl = Command::new(&luad)
        .args(["origins", path, "--format", "jsonl"])
        .output()
        .expect("origins jsonl");
    assert!(jsonl.status.success());
    let records: Vec<serde_json::Value> = jsonl
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("jsonl record"))
        .collect();
    let actual: Vec<CallOriginFact> = records
        .iter()
        .filter(|record| record["record_type"] == "origin")
        .map(|record| {
            let typed: JsonlDataRecord<CallOriginFact> =
                serde_json::from_value(record.clone()).expect("typed origin record");
            assert_eq!(
                typed
                    .context
                    .input_identity
                    .as_ref()
                    .expect("successful identity")
                    .sha256,
                document.input_identity.sha256
            );
            typed.data
        })
        .collect();
    assert_eq!(actual, expected);

    let text = Command::new(&luad)
        .args(["origins", path, "--format", "text"])
        .output()
        .expect("origins text");
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).expect("utf8 text");
    assert!(text.contains("CONCAT(\"prefix:\""));
    assert!(text.contains("MOD(\"value=%s\", table(proto:0/3:parameter[0]))"));
    assert!(text.contains("unknown:ExpressionDepthLimit"));
    assert!(text.contains("prototype 0/3/0"));
    assert!(!text.contains("taint"));
    assert!(!text.contains("safe"));
}

#[test]
fn test_export_origin_records_equal_direct_command() {
    let luad = get_luad_bin();
    let fixture = compiled_fixture_file();
    let path = fixture.path().to_str().expect("path");
    let direct = Command::new(&luad)
        .args(["origins", path, "--format", "json"])
        .output()
        .expect("origins");
    let document: MachineDocument<ChunkOriginAnalysis> =
        serde_json::from_slice(&direct.stdout).expect("origin document");
    let expected: Vec<_> = all_facts(&document.data).into_iter().cloned().collect();

    let export = Command::new(&luad)
        .args(["export", path, "--format", "jsonl"])
        .output()
        .expect("export");
    assert!(export.status.success());
    let actual: Vec<CallOriginFact> = export
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).expect("jsonl"))
        .filter(|record| record["record_type"] == "origin")
        .map(|record| serde_json::from_value(record["data"].clone()).expect("origin data"))
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn test_origins_schema_capability_and_lnum_profile_are_public() {
    let luad = get_luad_bin();
    let schema = Command::new(&luad)
        .args(["schema", "origins"])
        .output()
        .expect("schema");
    assert!(schema.status.success());
    let schema: serde_json::Value = serde_json::from_slice(&schema.stdout).expect("schema json");
    assert!(schema["definitions"]["OriginExpression"].is_object());
    assert!(schema["definitions"]["OriginUnknownReason"].is_object());
    let schema_text = serde_json::to_string(&schema).expect("schema text");
    assert!(schema_text.contains("expression-depth-limit"));
    assert!(schema_text.contains("call-result"));

    let capabilities = Command::new(&luad)
        .args(["capabilities", "--format", "json"])
        .output()
        .expect("capabilities");
    let manifest: serde_json::Value =
        serde_json::from_slice(&capabilities.stdout).expect("capabilities json");
    let lua51 = manifest["dialects"]
        .as_array()
        .expect("dialects")
        .iter()
        .find(|dialect| dialect["id"] == "lua5.1")
        .expect("lua5.1");
    assert!(lua51["features"]
        .as_array()
        .expect("features")
        .iter()
        .any(|feature| feature == "call-argument origins (experimental)"));

    let root = luad_oracle::find_workspace_root();
    let lnum = root.join("tests/fixtures/precompiled/lua51_lnum32/hello.luac");
    let output = Command::new(&luad)
        .args(["origins", lnum.to_str().expect("lnum"), "--format", "json"])
        .output()
        .expect("lnum origins");
    assert!(output.status.success());
    let document: MachineDocument<ChunkOriginAnalysis> =
        serde_json::from_slice(&output.stdout).expect("lnum document");
    assert_eq!(document.interpretation.profile, "lua5.1-lnum32");
}

#[test]
fn test_closure_argument_origin_emits_prototype_expression() {
    let source = r#"
local sink = function(...) return ... end
sink(function() end)
"#;
    let chunk = luad_oracle::compile_and_parse_lua51(source, false)
        .expect("compile closure callback fixture");
    let analysis = analyze_chunk_origins(&chunk);
    let facts = all_facts(&analysis);
    assert_eq!(facts.len(), 1);
    let fact = facts[0];
    let CallArgumentWindow::Fixed { arguments } = &fact.argument_window else {
        panic!("expected fixed argument window");
    };
    assert_eq!(arguments.len(), 1);
    let arg = &arguments[0];
    assert_eq!(arg.argument_index, 0);
    assert_eq!(arg.register, 2);
    assert_eq!(
        arg.origin.kind,
        OriginExpressionKind::Prototype {
            prototype: "0/1".parse().expect("child proto path")
        }
    );
    assert_eq!(arg.origin.evidence.len(), 1);
    assert_eq!(
        arg.origin.evidence[0],
        luad_core::StableId::instruction("0".parse().unwrap(), 2)
    );

    let val = serde_json::to_value(&arg.origin).expect("json");
    assert_eq!(val["kind"], "prototype");
    assert_eq!(val["prototype"], "0/1");
    assert_eq!(val["evidence"], serde_json::json!(["proto:0:pc:2"]));
}
