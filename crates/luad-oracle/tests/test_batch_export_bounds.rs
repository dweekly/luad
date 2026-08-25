//! Frozen acceptance boundary for the per-file export fact-bounds claim.
//!
//! Contract: `docs/MACHINE-INTERFACE.md` (`export` fact bounds).
//! Canonical gate: `gate-batch-export-bounds`.
//!
//! Authority rules observed by this module:
//!
//! - Every observation comes from invoking the public `luad` CLI and re-parsing the
//!   serialized public JSONL stream. No production export helper, record struct, or
//!   counting routine is called.
//! - Records are classified with the contract-derived tables `CONTROL_RECORD_TYPES`
//!   and `COUNTED_FACT_RECORD_TYPES`, which are the reviewed record-type goldens.
//! - Framing is checked by `parse_stream`, a state machine written from the contract's
//!   "Public behavior" section.
//! - `verify_bounded_stream` is the single comparator. Positive cases and every killer
//!   mutation are routed through it, so a mutation that the comparator would tolerate
//!   fails the acceptance suite instead of passing quietly.
//! - Nothing here skips. A missing binary, missing fixture, or corrupted fixture is a
//!   hard failure.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Contract-derived goldens
// ---------------------------------------------------------------------------

/// Stream-control records. Never suppressed by the per-file fact bound.
const CONTROL_RECORD_TYPES: [&str; 5] = [
    "export_start",
    "file_start",
    "diagnostic",
    "file_end",
    "export_end",
];

/// Ordinary fact records counted against `--max-facts-per-file`.
const COUNTED_FACT_RECORD_TYPES: [&str; 9] = [
    "prototype",
    "prototype_identity",
    "instruction",
    "constant",
    "upvalue",
    "xref",
    "callee",
    "origin",
    "call_relation",
];

/// Public fixture pinned by the sprint contract: path relative to the workspace root
/// and its required SHA-256.
struct PinnedFixture {
    relative_path: &'static str,
    sha256: &'static str,
}

const FIXTURE_CLOSURES_LUA51: PinnedFixture = PinnedFixture {
    relative_path: "tests/fixtures/precompiled/lua51/closures.luac",
    sha256: "62c4438b660880fa546cbe377d1f40113d2efc25aefc40df227979276efa756e",
};

const FIXTURE_HELLO_LNUM32: PinnedFixture = PinnedFixture {
    relative_path: "tests/fixtures/precompiled/lua51_lnum32/hello.luac",
    sha256: "8376be37ec3042d3b0a87aa39db7d7396fb54ae390abe346d885e1527d23e353",
};

const FIXTURE_HELLO_LUA54: PinnedFixture = PinnedFixture {
    relative_path: "tests/fixtures/precompiled/lua54/hello.luac",
    sha256: "a171c4c88ec40b1c871a57a888f66d7a93144e1d742f4071af286c9dc7b93575",
};

const FIXTURE_HELLO_STRIPPED_LUA54: PinnedFixture = PinnedFixture {
    relative_path: "tests/fixtures/precompiled/lua54/hello_stripped.luac",
    sha256: "9806c9692fd2e55f737c0af5b9cfb96fd543383a2f4decc715c8c30a861ede0f",
};

/// Generated plain-source input. Provenance is the byte literal plus its pinned hash.
const GENERATED_SOURCE_BYTES: &[u8] =
    b"-- luad acceptance fixture: plain Lua source, not bytecode\nprint('export bounds acceptance')\n";
const GENERATED_SOURCE_SHA256: &str =
    "fa574c371227b077cdcef2a5aad7fe1421f363e97e60ae028c916fdef1728b45";

/// Generated malformed-bytecode input: a Lua 5.1 signature and header followed by a
/// truncated body. Provenance is the byte literal plus its pinned hash.
const GENERATED_MALFORMED_BYTES: &[u8] = &[
    0x1b, 0x4c, 0x75, 0x61, 0x51, 0x00, 0x01, 0x04, 0x08, 0x04, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
];
const GENERATED_MALFORMED_SHA256: &str =
    "38d25bfd25e20e13b7236c28d08ea38fc0c07eac75850081b1f2e6a76f0515e9";

/// Diagnostic code the contract requires plain Lua source to retain under any bound.
const SOURCE_DIAGNOSTIC_CODE: &str = "PARSE-SOURCE-001";

/// Default exit code for a mixed batch containing at least one successful input.
const EXIT_MIXED_DEFAULT: i32 = 0;
/// Usage/option error exit code.
const EXIT_USAGE_ERROR: i32 = 2;

// ---------------------------------------------------------------------------
// Environment: binary, fixtures, generated inputs
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

/// Absolute path of the public `luad` binary, built on demand.
///
/// Absence of the binary is a hard failure: the acceptance suite must never report a
/// green or skipped result because the public interface could not be produced.
fn luad_bin() -> PathBuf {
    static BINARY: OnceLock<PathBuf> = OnceLock::new();
    BINARY
        .get_or_init(|| {
            if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
                return PathBuf::from(path);
            }
            let root = workspace_root();
            let binary = root.join("target").join("debug").join("luad");

            let build = Command::new("cargo")
                .args(["build", "-p", "luad-cli", "--bin", "luad"])
                .current_dir(&root)
                .output()
                .unwrap_or_else(|error| {
                    panic!("Failed to spawn `cargo build -p luad-cli`: {error}")
                });

            assert!(
                binary.exists(),
                "Public `luad` binary is required and was not produced at {}. \
                 cargo build status={:?}\nstderr:\n{}",
                binary.display(),
                build.status.code(),
                String::from_utf8_lossy(&build.stderr)
            );
            binary
        })
        .clone()
}

/// Resolve a pinned fixture and enforce its recorded SHA-256.
fn pinned_fixture(fixture: &PinnedFixture) -> String {
    let path = workspace_root().join(fixture.relative_path);
    let bytes = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "Pinned fixture '{}' is required and could not be read: {error}",
            fixture.relative_path
        )
    });
    let actual = format!("{:x}", Sha256::digest(&bytes));
    assert_eq!(
        actual, fixture.sha256,
        "Pinned fixture '{}' has SHA-256 {actual}, contract requires {}",
        fixture.relative_path, fixture.sha256
    );
    path.to_string_lossy().to_string()
}

/// Generated inputs for the failure rows of the contract fixture matrix.
struct GeneratedInputs {
    _dir: tempfile::TempDir,
    source_path: String,
    malformed_path: String,
    missing_path: String,
}

fn generated_inputs() -> GeneratedInputs {
    let dir = tempfile::tempdir().expect("temporary directory for generated acceptance inputs");

    let source_path = dir.path().join("acceptance_source.lua");
    std::fs::write(&source_path, GENERATED_SOURCE_BYTES).expect("write generated source input");
    let source_sha = format!("{:x}", Sha256::digest(GENERATED_SOURCE_BYTES));
    assert_eq!(
        source_sha, GENERATED_SOURCE_SHA256,
        "Generated source input hash drifted from its recorded provenance"
    );

    let malformed_path = dir.path().join("acceptance_malformed.luac");
    std::fs::write(&malformed_path, GENERATED_MALFORMED_BYTES)
        .expect("write generated malformed input");
    let malformed_sha = format!("{:x}", Sha256::digest(GENERATED_MALFORMED_BYTES));
    assert_eq!(
        malformed_sha, GENERATED_MALFORMED_SHA256,
        "Generated malformed input hash drifted from its recorded provenance"
    );

    let missing_path = dir.path().join("acceptance_absent_input.luac");
    assert!(
        !missing_path.exists(),
        "Missing-input row of the fixture matrix requires an absent path"
    );

    GeneratedInputs {
        source_path: source_path.to_string_lossy().to_string(),
        malformed_path: malformed_path.to_string_lossy().to_string(),
        missing_path: missing_path.to_string_lossy().to_string(),
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// Public CLI invocation
// ---------------------------------------------------------------------------

fn export_argv(files: &[String], bound: Option<&str>) -> Vec<String> {
    let mut argv = vec!["export".to_string()];
    argv.extend(files.iter().cloned());
    argv.push("--format".to_string());
    argv.push("jsonl".to_string());
    if let Some(value) = bound {
        argv.push("--max-facts-per-file".to_string());
        argv.push(value.to_string());
    }
    argv
}

fn run_export(files: &[String], bound: Option<&str>) -> std::process::Output {
    let luad = luad_bin();
    let argv = export_argv(files, bound);
    Command::new(&luad)
        .args(&argv)
        .output()
        .unwrap_or_else(|error| panic!("Failed to execute `luad {}`: {error}", argv.join(" ")))
}

/// Run a bounded export that the contract requires to succeed at the option level, and
/// return its stdout. A usage error here means the public option is absent or rejected.
fn bounded_stdout(files: &[String], bound: usize, expected_exit: i32) -> Vec<u8> {
    let bound_text = bound.to_string();
    let output = run_export(files, Some(&bound_text));
    assert_ne!(
        output.status.code(),
        Some(EXIT_USAGE_ERROR),
        "`luad export --max-facts-per-file {bound}` returned a usage error; the public bounded \
         export option is required by docs/NEXT-SPRINT.md.\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(expected_exit),
        "`luad export --max-facts-per-file {bound}` exit code mismatch.\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

// ---------------------------------------------------------------------------
// Contract-derived stream state machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordKind {
    Control,
    CountedFact,
}

fn classify(record_type: &str) -> Option<RecordKind> {
    if CONTROL_RECORD_TYPES.contains(&record_type) {
        Some(RecordKind::Control)
    } else if COUNTED_FACT_RECORD_TYPES.contains(&record_type) {
        Some(RecordKind::CountedFact)
    } else {
        None
    }
}

#[derive(Debug, Clone)]
struct FileBlock {
    start: serde_json::Value,
    end: serde_json::Value,
    facts: Vec<serde_json::Value>,
    diagnostics: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct ParsedStream {
    start: serde_json::Value,
    end: serde_json::Value,
    files: Vec<FileBlock>,
}

fn record_type_of(value: &serde_json::Value) -> Result<String, String> {
    value
        .get("record_type")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("record has no string `record_type` discriminator: {value}"))
}

/// Parse the public JSONL export stream and enforce the framing state machine:
/// `export_start`, then one `file_start` .. `file_end` block per input in argv order,
/// then `export_end`. Only known record types are accepted.
fn parse_stream(stdout: &[u8]) -> Result<ParsedStream, String> {
    let text =
        std::str::from_utf8(stdout).map_err(|error| format!("stdout is not UTF-8: {error}"))?;

    let mut records: Vec<(String, serde_json::Value)> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|error| format!("stdout line {} is not JSON: {error}", index + 1))?;
        let record_type = record_type_of(&value)?;
        if classify(&record_type).is_none() {
            return Err(format!(
                "stdout line {} has unknown record_type '{record_type}'",
                index + 1
            ));
        }
        records.push((record_type, value));
    }

    if records.is_empty() {
        return Err("export stream is empty; framing records are never suppressed".to_string());
    }
    if records[0].0 != "export_start" {
        return Err(format!(
            "first record must be export_start, got '{}'",
            records[0].0
        ));
    }
    let last = records.len() - 1;
    if records[last].0 != "export_end" {
        return Err(format!(
            "last record must be export_end, got '{}'",
            records[last].0
        ));
    }
    for (index, (record_type, _)) in records.iter().enumerate() {
        if record_type == "export_start" && index != 0 {
            return Err(format!("extra export_start record at position {index}"));
        }
        if record_type == "export_end" && index != last {
            return Err(format!("early export_end record at position {index}"));
        }
    }

    let mut files: Vec<FileBlock> = Vec::new();
    let mut open: Option<FileBlock> = None;

    for (index, (record_type, value)) in records.iter().enumerate().take(last).skip(1) {
        match record_type.as_str() {
            "file_start" => {
                if open.is_some() {
                    return Err(format!(
                        "file_start at position {index} while the previous input has no file_end"
                    ));
                }
                open = Some(FileBlock {
                    start: value.clone(),
                    end: serde_json::Value::Null,
                    facts: Vec::new(),
                    diagnostics: Vec::new(),
                });
            }
            "file_end" => {
                let mut block = open.take().ok_or_else(|| {
                    format!("file_end at position {index} without a preceding file_start")
                })?;
                block.end = value.clone();
                files.push(block);
            }
            "diagnostic" => {
                let block = open.as_mut().ok_or_else(|| {
                    format!("diagnostic at position {index} outside a file_start/file_end block")
                })?;
                block.diagnostics.push(value.clone());
            }
            other => {
                // Classification already rejected unknown types, so this is a counted fact.
                let block = open.as_mut().ok_or_else(|| {
                    format!("{other} fact at position {index} outside a file_start/file_end block")
                })?;
                block.facts.push(value.clone());
            }
        }
    }

    if open.is_some() {
        return Err("stream ended with an input that never received its file_end".to_string());
    }

    Ok(ParsedStream {
        start: records[0].1.clone(),
        end: records[last].1.clone(),
        files,
    })
}

// ---------------------------------------------------------------------------
// The comparator
// ---------------------------------------------------------------------------

/// Independently observed truth for one input, derived from the unbounded public stream.
#[derive(Debug, Clone)]
struct FileExpectation {
    path: String,
    status: String,
    available_facts: Vec<serde_json::Value>,
    diagnostic_codes: Vec<String>,
}

fn expect_u64(record: &serde_json::Value, field: &str) -> Result<u64, String> {
    match record.get(field) {
        None => Err(format!("file_end is missing required field `{field}`")),
        Some(value) => value.as_u64().ok_or_else(|| {
            format!("file_end field `{field}` is not a non-negative integer: {value}")
        }),
    }
}

fn expect_bool(record: &serde_json::Value, field: &str) -> Result<bool, String> {
    match record.get(field) {
        None => Err(format!("file_end is missing required field `{field}`")),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| format!("file_end field `{field}` is not a boolean: {value}")),
    }
}

fn expect_str(record: &serde_json::Value, field: &str) -> Result<String, String> {
    record
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("record is missing string field `{field}`"))
}

fn diagnostic_codes(block: &FileBlock) -> Vec<String> {
    block
        .diagnostics
        .iter()
        .map(|diagnostic| {
            diagnostic["data"]["code"]
                .as_str()
                .unwrap_or("<no-code>")
                .to_string()
        })
        .collect()
}

/// The single acceptance comparator.
///
/// `bound` is `None` for an unbounded invocation and `Some(n)` for
/// `--max-facts-per-file n`. `expected` is the independently observed per-input truth,
/// in argv order.
fn verify_bounded_stream(
    stdout: &[u8],
    bound: Option<usize>,
    expected: &[FileExpectation],
) -> Result<(), String> {
    let stream = parse_stream(stdout)?;

    if stream.files.len() != expected.len() {
        return Err(format!(
            "stream framed {} inputs, expected {} (every input keeps its own framing)",
            stream.files.len(),
            expected.len()
        ));
    }

    let mut succeeded = 0u64;
    let mut skipped = 0u64;
    let mut failed = 0u64;

    for (index, (block, want)) in stream.files.iter().zip(expected.iter()).enumerate() {
        let start_path = expect_str(&block.start, "path")?;
        if start_path != want.path {
            return Err(format!(
                "input {index}: file_start path '{start_path}', expected '{}'",
                want.path
            ));
        }
        let end_path = expect_str(&block.end, "path")?;
        if end_path != want.path {
            return Err(format!(
                "input {index}: file_end path '{end_path}', expected '{}'",
                want.path
            ));
        }

        let status = expect_str(&block.end, "status")?;
        if status != want.status {
            return Err(format!(
                "input {index} ('{}'): file_end status '{status}', expected '{}'",
                want.path, want.status
            ));
        }
        match status.as_str() {
            "succeeded" => succeeded += 1,
            "skipped" => skipped += 1,
            "failed" => failed += 1,
            other => return Err(format!("unknown file_end status '{other}'")),
        }

        let available = want.available_facts.len();
        let expected_emitted = match bound {
            Some(limit) => &want.available_facts[..limit.min(available)],
            None => &want.available_facts[..],
        };

        if let Some(limit) = bound {
            if block.facts.len() > limit {
                return Err(format!(
                    "input {index} ('{}'): emitted {} counted facts, bound is {limit}",
                    want.path,
                    block.facts.len()
                ));
            }
        }

        if block.facts.len() != expected_emitted.len() {
            return Err(format!(
                "input {index} ('{}'): emitted {} counted facts, expected {} \
                 (available {available}, bound {:?})",
                want.path,
                block.facts.len(),
                expected_emitted.len(),
                bound
            ));
        }

        for (fact_index, (emitted, wanted)) in
            block.facts.iter().zip(expected_emitted.iter()).enumerate()
        {
            if emitted != wanted {
                return Err(format!(
                    "input {index} ('{}'): counted fact {fact_index} differs from the \
                     independently observed deterministic prefix.\n  emitted:  {emitted}\n  expected: {wanted}",
                    want.path
                ));
            }
        }

        let emitted_fact_count = expect_u64(&block.end, "emitted_fact_count")?;
        if emitted_fact_count != block.facts.len() as u64 {
            return Err(format!(
                "input {index} ('{}'): file_end emitted_fact_count={emitted_fact_count}, \
                 stream carries {} counted facts",
                want.path,
                block.facts.len()
            ));
        }

        let available_fact_count = expect_u64(&block.end, "available_fact_count")?;
        if available_fact_count != available as u64 {
            return Err(format!(
                "input {index} ('{}'): file_end available_fact_count={available_fact_count}, \
                 independently counted full stream has {available}",
                want.path
            ));
        }

        let is_truncated = expect_bool(&block.end, "is_truncated")?;
        let should_be_truncated = expected_emitted.len() < available;
        if is_truncated != should_be_truncated {
            return Err(format!(
                "input {index} ('{}'): file_end is_truncated={is_truncated}, expected \
                 {should_be_truncated} (emitted {}, available {available})",
                want.path,
                expected_emitted.len()
            ));
        }

        let codes = diagnostic_codes(block);
        if codes != want.diagnostic_codes {
            return Err(format!(
                "input {index} ('{}'): diagnostic codes {codes:?}, expected {:?} \
                 (diagnostics are stream-control records and are never suppressed)",
                want.path, want.diagnostic_codes
            ));
        }

        let diagnostic_count = expect_u64(&block.end, "diagnostic_count")?;
        if diagnostic_count != block.diagnostics.len() as u64 {
            return Err(format!(
                "input {index} ('{}'): file_end diagnostic_count={diagnostic_count}, stream \
                 carries {} diagnostic records",
                want.path,
                block.diagnostics.len()
            ));
        }
    }

    if expect_str(&stream.start, "record_type")? != "export_start" {
        return Err("export_start discriminator changed".to_string());
    }

    let files_processed = expect_u64(&stream.end, "files_processed")?;
    if files_processed != expected.len() as u64 {
        return Err(format!(
            "export_end files_processed={files_processed}, expected {}",
            expected.len()
        ));
    }
    let files_succeeded = expect_u64(&stream.end, "files_succeeded")?;
    if files_succeeded != succeeded {
        return Err(format!(
            "export_end files_succeeded={files_succeeded}, stream framed {succeeded} succeeded inputs"
        ));
    }
    let files_skipped = expect_u64(&stream.end, "files_skipped")?;
    if files_skipped != skipped {
        return Err(format!(
            "export_end files_skipped={files_skipped}, stream framed {skipped} skipped inputs"
        ));
    }
    let files_failed = expect_u64(&stream.end, "files_failed")?;
    if files_failed != failed {
        return Err(format!(
            "export_end files_failed={files_failed}, stream framed {failed} failed inputs"
        ));
    }

    Ok(())
}

fn assert_comparator_accepts(
    stdout: &[u8],
    bound: Option<usize>,
    expected: &[FileExpectation],
    context: &str,
) {
    if let Err(reason) = verify_bounded_stream(stdout, bound, expected) {
        panic!("Acceptance comparator rejected {context}: {reason}");
    }
}

/// Assert that the comparator rejects a mutated stream, and record the rejection reason.
fn assert_comparator_rejects(
    stdout: &[u8],
    bound: Option<usize>,
    expected: &[FileExpectation],
    mutation: &str,
) {
    match verify_bounded_stream(stdout, bound, expected) {
        Ok(()) => {
            panic!("Killer mutation '{mutation}' was NOT rejected by the acceptance comparator")
        }
        Err(reason) => println!("killer mutation '{mutation}' rejected: {reason}"),
    }
}

// ---------------------------------------------------------------------------
// Independent baseline observation
// ---------------------------------------------------------------------------

/// Observe each input's full fact stream, status, and diagnostics from the unbounded
/// public invocation. This uses only framing that already exists at the accepted
/// revision, so a red result here means the baseline export itself regressed.
fn observe_baseline(files: &[String]) -> Vec<FileExpectation> {
    let output = run_export(files, None);
    let stream = parse_stream(&output.stdout).unwrap_or_else(|reason| {
        panic!(
            "Unbounded baseline export stream is unusable: {reason}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_eq!(
        stream.files.len(),
        files.len(),
        "Unbounded baseline framed {} inputs for {} arguments",
        stream.files.len(),
        files.len()
    );

    stream
        .files
        .iter()
        .zip(files.iter())
        .map(|(block, path)| FileExpectation {
            path: expect_str(&block.start, "path").unwrap_or_else(|error| {
                panic!("Unbounded baseline file_start for '{path}' is malformed: {error}")
            }),
            status: expect_str(&block.end, "status").unwrap_or_else(|error| {
                panic!("Unbounded baseline file_end for '{path}' is malformed: {error}")
            }),
            available_facts: block.facts.clone(),
            diagnostic_codes: diagnostic_codes(block),
        })
        .collect()
}

fn fact_type_histogram(facts: &[serde_json::Value]) -> BTreeMap<String, usize> {
    let mut histogram = BTreeMap::new();
    for fact in facts {
        let record_type = fact["record_type"].as_str().unwrap_or("<none>").to_string();
        *histogram.entry(record_type).or_insert(0) += 1;
    }
    histogram
}

// ---------------------------------------------------------------------------
// Line-level mutation helpers (applied to real, otherwise-valid CLI output)
// ---------------------------------------------------------------------------

fn stdout_lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8(stdout.to_vec())
        .expect("stdout is UTF-8")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

fn rejoin(lines: &[String]) -> Vec<u8> {
    let mut joined = lines.join("\n");
    joined.push('\n');
    joined.into_bytes()
}

fn line_record(line: &str) -> serde_json::Value {
    serde_json::from_str(line).expect("stream line is JSON")
}

fn line_type(line: &str) -> String {
    line_record(line)["record_type"]
        .as_str()
        .expect("stream line has record_type")
        .to_string()
}

fn index_of_type(lines: &[String], record_type: &str, occurrence: usize) -> usize {
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line_type(line) == record_type)
        .map(|(index, _)| index)
        .nth(occurrence)
        .unwrap_or_else(|| panic!("stream has no {record_type} record at occurrence {occurrence}"))
}

fn index_of_first_fact(lines: &[String]) -> usize {
    lines
        .iter()
        .position(|line| classify(&line_type(line)) == Some(RecordKind::CountedFact))
        .expect("stream has at least one counted fact record")
}

/// Replace one field of one record, leaving every other byte of the stream intact.
fn mutate_record_field(
    lines: &[String],
    index: usize,
    field: &str,
    new_value: serde_json::Value,
) -> Vec<String> {
    let mut mutated = lines.to_vec();
    let mut record = line_record(&mutated[index]);
    record
        .as_object_mut()
        .expect("record is a JSON object")
        .insert(field.to_string(), new_value);
    mutated[index] = serde_json::to_string(&record).expect("re-serialize mutated record");
    mutated
}

fn shift_u64_field(lines: &[String], index: usize, field: &str, delta: i64) -> Vec<String> {
    let current = line_record(&lines[index])[field]
        .as_u64()
        .unwrap_or_else(|| panic!("record field `{field}` is not an integer"));
    let shifted = (current as i64 + delta).max(0) as u64;
    mutate_record_field(lines, index, field, serde_json::json!(shifted))
}

// ---------------------------------------------------------------------------
// Fixture batches used by the tests
// ---------------------------------------------------------------------------

fn pinned_bytecode_batch() -> Vec<String> {
    vec![
        pinned_fixture(&FIXTURE_CLOSURES_LUA51),
        pinned_fixture(&FIXTURE_HELLO_LNUM32),
        pinned_fixture(&FIXTURE_HELLO_LUA54),
        pinned_fixture(&FIXTURE_HELLO_STRIPPED_LUA54),
    ]
}

/// Full contract fixture matrix: pinned bytecode inputs interleaved with the generated
/// source, malformed, and missing inputs so failures sit between successes.
fn full_matrix_batch(generated: &GeneratedInputs) -> Vec<String> {
    vec![
        pinned_fixture(&FIXTURE_CLOSURES_LUA51),
        generated.malformed_path.clone(),
        pinned_fixture(&FIXTURE_HELLO_LNUM32),
        generated.source_path.clone(),
        pinned_fixture(&FIXTURE_HELLO_LUA54),
        generated.missing_path.clone(),
        pinned_fixture(&FIXTURE_HELLO_STRIPPED_LUA54),
    ]
}

// ---------------------------------------------------------------------------
// Positive acceptance assertions
// ---------------------------------------------------------------------------

#[test]
fn test_bounds_matrix_matches_independent_prefix_and_counts_for_pinned_fixtures() {
    for fixture in [
        &FIXTURE_CLOSURES_LUA51,
        &FIXTURE_HELLO_LNUM32,
        &FIXTURE_HELLO_LUA54,
        &FIXTURE_HELLO_STRIPPED_LUA54,
    ] {
        let files = vec![pinned_fixture(fixture)];
        let baseline = observe_baseline(&files);
        let available = baseline[0].available_facts.len();
        assert!(
            available > 3,
            "Pinned fixture '{}' must expose more facts than the smallest tested bound, got {available}",
            fixture.relative_path
        );

        let histogram = fact_type_histogram(&baseline[0].available_facts);
        if fixture.relative_path == FIXTURE_CLOSURES_LUA51.relative_path {
            for counted in COUNTED_FACT_RECORD_TYPES {
                assert!(
                    histogram.get(counted).copied().unwrap_or(0) > 0,
                    "closures.luac must expose at least one '{counted}' fact, histogram={histogram:?}"
                );
            }
            assert!(
                histogram.get("prototype").copied().unwrap_or(0) >= 4,
                "closures.luac must recursively emit its prototype tree, histogram={histogram:?}"
            );
        }

        let mut bounds = vec![0usize, 1, 3, 1000];
        bounds.push(available.saturating_sub(1));
        bounds.push(available);
        bounds.push(available + 1);
        bounds.sort_unstable();
        bounds.dedup();

        for bound in bounds {
            let stdout = bounded_stdout(&files, bound, 0);
            assert_comparator_accepts(
                &stdout,
                Some(bound),
                &baseline,
                &format!("'{}' at bound {bound}", fixture.relative_path),
            );
        }
    }
}

#[test]
fn test_contract_example_closures_bound_three_stream_shape() {
    let files = vec![pinned_fixture(&FIXTURE_CLOSURES_LUA51)];
    let baseline = observe_baseline(&files);
    assert!(
        baseline[0].available_facts.len() > 3,
        "The contract example requires closures.luac to have more than three facts"
    );

    let stdout = bounded_stdout(&files, 3, 0);
    assert_comparator_accepts(&stdout, Some(3), &baseline, "contract example at bound 3");

    let lines = stdout_lines(&stdout);
    let sequence: Vec<String> = lines.iter().map(|line| line_type(line)).collect();
    assert_eq!(
        sequence.len(),
        7,
        "Contract example stream must be export_start, file_start, three facts, file_end, \
         export_end. Got: {sequence:?}"
    );
    assert_eq!(sequence[0], "export_start", "sequence: {sequence:?}");
    assert_eq!(sequence[1], "file_start", "sequence: {sequence:?}");
    for record_type in &sequence[2..5] {
        assert_eq!(
            classify(record_type),
            Some(RecordKind::CountedFact),
            "Records 3..5 must be counted facts. Got: {sequence:?}"
        );
    }
    assert_eq!(sequence[5], "file_end", "sequence: {sequence:?}");
    assert_eq!(sequence[6], "export_end", "sequence: {sequence:?}");

    let file_end = line_record(&lines[5]);
    assert_eq!(
        file_end["is_truncated"],
        serde_json::json!(true),
        "Contract example must report is_truncated: true, got {file_end}"
    );
    assert_eq!(
        file_end["emitted_fact_count"],
        serde_json::json!(3),
        "Contract example must report emitted_fact_count: 3, got {file_end}"
    );
}

#[test]
fn test_zero_bound_preserves_framing_and_failure_diagnostics() {
    let generated = generated_inputs();
    let files = full_matrix_batch(&generated);
    let baseline = observe_baseline(&files);

    let stdout = bounded_stdout(&files, 0, EXIT_MIXED_DEFAULT);
    assert_comparator_accepts(
        &stdout,
        Some(0),
        &baseline,
        "full fixture matrix at bound 0",
    );

    let stream = parse_stream(&stdout).expect("bound-0 stream is framed");
    for (block, want) in stream.files.iter().zip(baseline.iter()) {
        assert!(
            block.facts.is_empty(),
            "Bound 0 must emit no counted facts for '{}', got {:?}",
            want.path,
            fact_type_histogram(&block.facts)
        );
    }

    let source_index = files
        .iter()
        .position(|path| path == &generated.source_path)
        .expect("generated source input is in the batch");
    assert_eq!(
        baseline[source_index].diagnostic_codes,
        vec![SOURCE_DIAGNOSTIC_CODE.to_string()],
        "Plain Lua source must retain its structured unsupported diagnostic"
    );
    assert_eq!(
        stream.files[source_index].diagnostics.len(),
        1,
        "Plain Lua source diagnostic must survive bound 0"
    );

    for skipped in [&generated.malformed_path, &generated.source_path] {
        let index = files
            .iter()
            .position(|path| path == skipped)
            .expect("skipped input is in the batch");
        assert_eq!(
            baseline[index].status, "skipped",
            "'{skipped}' must retain skipped status"
        );
    }
    let missing_index = files
        .iter()
        .position(|path| path == &generated.missing_path)
        .expect("missing input is in the batch");
    assert_eq!(baseline[missing_index].status, "failed");

    for non_success in [
        &generated.malformed_path,
        &generated.source_path,
        &generated.missing_path,
    ] {
        let index = files
            .iter()
            .position(|path| path == non_success)
            .expect("non-success input is in the batch");
        assert!(
            !stream.files[index].diagnostics.is_empty(),
            "'{non_success}' must retain at least one diagnostic record at bound 0"
        );
        for diagnostic in &stream.files[index].diagnostics {
            assert_eq!(
                diagnostic["data"]["severity"], "error",
                "'{non_success}' diagnostic must remain an error: {diagnostic}"
            );
            assert!(
                diagnostic["data"]["code"]
                    .as_str()
                    .is_some_and(|code| !code.is_empty()),
                "'{non_success}' diagnostic must carry a stable code: {diagnostic}"
            );
        }
    }
}

#[test]
fn test_later_inputs_receive_complete_framing_after_truncation_and_failure() {
    let generated = generated_inputs();
    let files = full_matrix_batch(&generated);
    let baseline = observe_baseline(&files);

    let bound = 2usize;
    let stdout = bounded_stdout(&files, bound, EXIT_MIXED_DEFAULT);
    assert_comparator_accepts(
        &stdout,
        Some(bound),
        &baseline,
        "full fixture matrix at bound 2",
    );

    let stream = parse_stream(&stdout).expect("mixed stream is framed");
    assert_eq!(
        stream.files.len(),
        files.len(),
        "Every input keeps its own file_start/file_end block"
    );

    let first_truncated = baseline[0].available_facts.len() > bound;
    assert!(
        first_truncated,
        "The first input must actually truncate for this probe to be meaningful"
    );

    let last = stream.files.last().expect("last input block");
    assert_eq!(
        expect_str(&last.start, "path").unwrap(),
        *files.last().unwrap(),
        "The final input must still be framed after earlier truncation and failures"
    );
    assert_eq!(
        expect_u64(&last.end, "emitted_fact_count").unwrap(),
        bound as u64,
        "The final input must still receive its own bounded fact budget"
    );
}

#[test]
fn test_truncation_alone_does_not_make_aggregate_exit_nonzero() {
    let files = pinned_bytecode_batch();
    let baseline = observe_baseline(&files);
    let bound = 2usize;

    let bound_text = bound.to_string();
    let output = run_export(&files, Some(&bound_text));
    assert_eq!(
        output.status.code(),
        Some(0),
        "Truncation is a successful bounded result.\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_comparator_accepts(
        &output.stdout,
        Some(bound),
        &baseline,
        "all-valid batch at bound 2",
    );

    let stream = parse_stream(&output.stdout).expect("all-valid stream is framed");
    assert!(
        stream
            .files
            .iter()
            .any(|block| expect_bool(&block.end, "is_truncated").unwrap()),
        "At least one input must report is_truncated: true at bound 2"
    );
}

#[test]
fn test_repeated_bounded_invocations_are_byte_identical() {
    let generated = generated_inputs();
    let files = full_matrix_batch(&generated);
    let baseline = observe_baseline(&files);
    let bound = 5usize;

    let first = bounded_stdout(&files, bound, EXIT_MIXED_DEFAULT);
    let second = bounded_stdout(&files, bound, EXIT_MIXED_DEFAULT);

    assert_comparator_accepts(&first, Some(bound), &baseline, "first bounded run");
    assert_comparator_accepts(&second, Some(bound), &baseline, "second bounded run");

    assert_eq!(
        format!("{:x}", Sha256::digest(&first)),
        format!("{:x}", Sha256::digest(&second)),
        "Repeated bounded export over identical inputs must be byte-for-byte deterministic"
    );
    assert_eq!(first, second);
}

#[test]
fn test_vendor_profile_identity_preserved_under_bound() {
    let files = vec![pinned_fixture(&FIXTURE_HELLO_LNUM32)];
    let baseline = observe_baseline(&files);

    let unbounded = run_export(&files, None);
    let unbounded_stream = parse_stream(&unbounded.stdout).expect("unbounded lnum32 stream");
    let unbounded_interpretation = unbounded_stream.files[0].start["interpretation"].clone();
    assert_eq!(
        unbounded_interpretation["profile"],
        serde_json::json!("lua5.1-lnum32"),
        "The vendor-profile fixture must resolve the explicit LNUM32 profile"
    );

    let bound = 2usize;
    let stdout = bounded_stdout(&files, bound, 0);
    assert_comparator_accepts(&stdout, Some(bound), &baseline, "lnum32 fixture at bound 2");

    let bounded_stream = parse_stream(&stdout).expect("bounded lnum32 stream");
    assert_eq!(
        bounded_stream.files[0].start["interpretation"], unbounded_interpretation,
        "Bounding facts must not change resolved profile, layout, or selection evidence"
    );
}

#[test]
fn test_omitted_bound_preserves_unbounded_fact_stream() {
    let generated = generated_inputs();
    let files = full_matrix_batch(&generated);
    let baseline = observe_baseline(&files);

    let output = run_export(&files, None);
    assert_eq!(
        output.status.code(),
        Some(EXIT_MIXED_DEFAULT),
        "Omitting the bound must preserve default mixed-batch success.\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_comparator_accepts(&output.stdout, None, &baseline, "omitted bound");

    let stream = parse_stream(&output.stdout).expect("unbounded stream is framed");
    for (block, want) in stream.files.iter().zip(baseline.iter()) {
        assert_eq!(
            block.facts.len(),
            want.available_facts.len(),
            "Omitting the bound must emit every available fact for '{}'",
            want.path
        );
        assert!(
            !expect_bool(&block.end, "is_truncated").unwrap(),
            "Omitting the bound must report is_truncated: false for '{}'",
            want.path
        );
    }
}

#[test]
fn test_stderr_diagnostics_never_contaminate_jsonl_stdout() {
    let generated = generated_inputs();
    let files = full_matrix_batch(&generated);
    let baseline = observe_baseline(&files);

    let bound = 4usize;
    let bound_text = bound.to_string();
    let output = run_export(&files, Some(&bound_text));
    assert_eq!(
        output.status.code(),
        Some(EXIT_MIXED_DEFAULT),
        "Mixed batch with usable results must retain default success.\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_comparator_accepts(
        &output.stdout,
        Some(bound),
        &baseline,
        "mixed batch at bound 4",
    );

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        !stderr.trim().is_empty(),
        "Failing inputs must still produce human diagnostics on stderr"
    );

    let stdout_text = String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8");
    assert!(
        !stdout_text.contains('\u{1b}'),
        "Machine stdout must not contain ANSI escape sequences"
    );
    for (index, line) in stdout_text.lines().enumerate() {
        assert!(
            !line.trim().is_empty(),
            "Machine stdout must not contain blank commentary lines (line {})",
            index + 1
        );
        let record: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|error| {
            panic!(
                "stdout line {} is not a machine record: {error}: {line}",
                index + 1
            )
        });
        let record_type = record_type_of(&record).expect("record_type present");
        assert!(
            classify(&record_type).is_some(),
            "stdout line {} carries unknown record_type '{record_type}'",
            index + 1
        );
    }
    for stderr_line in stderr.lines().filter(|line| !line.trim().is_empty()) {
        assert!(
            !stdout_text.contains(stderr_line),
            "stderr text leaked into machine stdout: {stderr_line}"
        );
    }
}

#[test]
fn test_invalid_bound_values_are_usage_errors_without_machine_stdout() {
    let files = vec![pinned_fixture(&FIXTURE_HELLO_LUA54)];

    // Non-vacuity guard: a valid bound must be accepted by the same public option.
    let accepted = run_export(&files, Some("3"));
    assert_eq!(
        accepted.status.code(),
        Some(0),
        "A valid --max-facts-per-file value must be accepted.\nstderr:\n{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    assert!(
        String::from_utf8_lossy(&accepted.stdout).contains("export_start"),
        "A valid bounded invocation must emit machine records on stdout"
    );

    for invalid in ["-1", "abc", "3.5", "", " ", "0x3", "18446744073709551616"] {
        let output = run_export(&files, Some(invalid));
        assert_eq!(
            output.status.code(),
            Some(EXIT_USAGE_ERROR),
            "--max-facts-per-file '{invalid}' must be a usage error (exit 2).\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(line) {
                assert!(
                    record.get("record_type").is_none(),
                    "--max-facts-per-file '{invalid}' emitted a machine record on stdout: {line}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Live schema authority
// ---------------------------------------------------------------------------

fn live_export_schema() -> serde_json::Value {
    let luad = luad_bin();
    let output = Command::new(&luad)
        .args(["schema", "export"])
        .output()
        .expect("execute `luad schema export`");
    assert_eq!(
        output.status.code(),
        Some(0),
        "`luad schema export` must succeed.\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("`luad schema export` emits JSON")
}

fn file_end_variant_index(schema: &serde_json::Value) -> usize {
    schema["oneOf"]
        .as_array()
        .expect("export schema is a oneOf union")
        .iter()
        .position(|variant| variant["properties"]["record_type"]["enum"][0] == "file_end")
        .expect("export schema has a file_end variant")
}

#[test]
fn test_live_export_schema_validates_bounded_records_and_truncation_fields() {
    let files = vec![pinned_fixture(&FIXTURE_CLOSURES_LUA51)];
    let baseline = observe_baseline(&files);
    let bound = 3usize;
    let stdout = bounded_stdout(&files, bound, 0);
    assert_comparator_accepts(&stdout, Some(bound), &baseline, "schema subject stream");

    let schema = live_export_schema();
    let validator = jsonschema::validator_for(&schema).expect("compile live export schema");

    let lines = stdout_lines(&stdout);
    for (index, line) in lines.iter().enumerate() {
        let record = line_record(line);
        if let Err(error) = validator.validate(&record) {
            panic!(
                "Live export schema rejected bounded record on line {}: {error}\n{line}",
                index + 1
            );
        }
    }

    let file_end_index = index_of_type(&lines, "file_end", 0);
    let file_end = line_record(&lines[file_end_index]);

    for field in ["is_truncated", "emitted_fact_count", "available_fact_count"] {
        let mut missing = file_end.clone();
        missing
            .as_object_mut()
            .expect("file_end is an object")
            .remove(field);
        assert!(
            !validator.is_valid(&missing),
            "Live export schema must reject a file_end record missing `{field}`"
        );

        let mut mistyped = file_end.clone();
        mistyped
            .as_object_mut()
            .expect("file_end is an object")
            .insert(field.to_string(), serde_json::json!("not-the-right-type"));
        assert!(
            !validator.is_valid(&mistyped),
            "Live export schema must reject a file_end record whose `{field}` is mistyped"
        );
    }

    assert!(
        validator.is_valid(&file_end),
        "Live export schema must accept the unmutated bounded file_end record"
    );
}

// ---------------------------------------------------------------------------
// Killer mutations
//
// Each probe takes real, otherwise-valid CLI output, changes exactly one fact, and
// routes the result through the same comparator (or the same schema validator) used
// by the positive cases.
// ---------------------------------------------------------------------------

/// Build the standard mutation subject: closures.luac truncated at bound 3, followed by
/// a second input that must survive the first input reaching its bound.
fn truncated_pair_subject() -> (Vec<String>, Vec<FileExpectation>, usize, Vec<u8>) {
    let files = vec![
        pinned_fixture(&FIXTURE_CLOSURES_LUA51),
        pinned_fixture(&FIXTURE_HELLO_LUA54),
    ];
    let baseline = observe_baseline(&files);
    let bound = 3usize;
    let stdout = bounded_stdout(&files, bound, 0);
    assert_comparator_accepts(
        &stdout,
        Some(bound),
        &baseline,
        "unmutated truncated-pair subject",
    );
    (files, baseline, bound, stdout)
}

#[test]
fn test_killer_mutation_extra_fact_beyond_bound_rejected() {
    let (_files, baseline, bound, stdout) = truncated_pair_subject();
    let lines = stdout_lines(&stdout);

    let fact_index = index_of_first_fact(&lines);
    let mut mutated = lines.clone();
    mutated.insert(fact_index, lines[fact_index].clone());

    assert_comparator_rejects(
        &rejoin(&mutated),
        Some(bound),
        &baseline,
        "emit N+1 counted facts for the bounded input",
    );
}

#[test]
fn test_killer_mutation_missing_file_end_after_truncation_rejected() {
    let (_files, baseline, bound, stdout) = truncated_pair_subject();
    let lines = stdout_lines(&stdout);

    let file_end_index = index_of_type(&lines, "file_end", 0);
    let mut mutated = lines.clone();
    mutated.remove(file_end_index);

    assert_comparator_rejects(
        &rejoin(&mutated),
        Some(bound),
        &baseline,
        "remove the file_end record of the truncated input",
    );
}

#[test]
fn test_killer_mutation_is_truncated_flipped_false_rejected() {
    let (_files, baseline, bound, stdout) = truncated_pair_subject();
    let lines = stdout_lines(&stdout);

    let file_end_index = index_of_type(&lines, "file_end", 0);
    assert_eq!(
        line_record(&lines[file_end_index])["is_truncated"],
        serde_json::json!(true),
        "Mutation subject must genuinely truncate before is_truncated is flipped"
    );
    let mutated = mutate_record_field(
        &lines,
        file_end_index,
        "is_truncated",
        serde_json::json!(false),
    );

    assert_comparator_rejects(
        &rejoin(&mutated),
        Some(bound),
        &baseline,
        "report is_truncated: false for a truncated input",
    );
}

#[test]
fn test_killer_mutation_emitted_fact_count_off_by_one_rejected() {
    let (_files, baseline, bound, stdout) = truncated_pair_subject();
    let lines = stdout_lines(&stdout);

    let file_end_index = index_of_type(&lines, "file_end", 0);
    let mutated = shift_u64_field(&lines, file_end_index, "emitted_fact_count", 1);

    assert_comparator_rejects(
        &rejoin(&mutated),
        Some(bound),
        &baseline,
        "increase emitted_fact_count by one",
    );
}

#[test]
fn test_killer_mutation_available_fact_count_off_by_one_rejected() {
    let (_files, baseline, bound, stdout) = truncated_pair_subject();
    let lines = stdout_lines(&stdout);

    let file_end_index = index_of_type(&lines, "file_end", 0);
    let mutated = shift_u64_field(&lines, file_end_index, "available_fact_count", -1);

    assert_comparator_rejects(
        &rejoin(&mutated),
        Some(bound),
        &baseline,
        "decrease available_fact_count by one",
    );
}

#[test]
fn test_killer_mutation_diagnostic_suppressed_at_zero_bound_rejected() {
    let generated = generated_inputs();
    let files = full_matrix_batch(&generated);
    let baseline = observe_baseline(&files);
    let stdout = bounded_stdout(&files, 0, EXIT_MIXED_DEFAULT);
    assert_comparator_accepts(
        &stdout,
        Some(0),
        &baseline,
        "unmutated bound-0 diagnostic subject",
    );

    let lines = stdout_lines(&stdout);
    let diagnostic_index = index_of_type(&lines, "diagnostic", 0);
    let mut mutated = lines.clone();
    mutated.remove(diagnostic_index);
    let file_end_index = mutated[diagnostic_index..]
        .iter()
        .position(|line| line_type(line) == "file_end")
        .expect("diagnostic belongs to a framed input")
        + diagnostic_index;
    let mutated = shift_u64_field(&mutated, file_end_index, "diagnostic_count", -1);

    assert_comparator_rejects(
        &rejoin(&mutated),
        Some(0),
        &baseline,
        "suppress a diagnostic record at bound 0",
    );
}

#[test]
fn test_killer_mutation_next_input_dropped_after_bound_rejected() {
    let (_files, baseline, bound, stdout) = truncated_pair_subject();
    let lines = stdout_lines(&stdout);

    let second_start = index_of_type(&lines, "file_start", 1);
    let second_end = index_of_type(&lines, "file_end", 1);
    assert!(
        second_end > second_start,
        "second input block is well formed"
    );

    let mut mutated = lines.clone();
    mutated.drain(second_start..=second_end);

    // Keep the epilogue self-consistent so the probe cannot be caught by a count
    // mismatch alone: the defect under test is the vanished input, not arithmetic.
    let export_end_index = index_of_type(&mutated, "export_end", 0);
    let mutated = shift_u64_field(&mutated, export_end_index, "files_processed", -1);
    let mutated = shift_u64_field(&mutated, export_end_index, "files_succeeded", -1);

    assert_comparator_rejects(
        &rejoin(&mutated),
        Some(bound),
        &baseline,
        "drop the next input after the preceding input reaches its bound",
    );
}

#[test]
fn test_killer_mutation_record_reordering_between_runs_rejected() {
    let (files, baseline, bound, first) = truncated_pair_subject();
    let second = bounded_stdout(&files, bound, 0);

    assert_eq!(
        first, second,
        "Unmutated repeated bounded runs must be byte-identical before the reorder probe"
    );

    let lines = stdout_lines(&second);
    let fact_index = index_of_first_fact(&lines);
    assert_eq!(
        classify(&line_type(&lines[fact_index + 1])),
        Some(RecordKind::CountedFact),
        "Reorder probe needs two adjacent counted facts"
    );
    let mut mutated = lines.clone();
    mutated.swap(fact_index, fact_index + 1);
    let reordered = rejoin(&mutated);

    assert_ne!(
        first, reordered,
        "Byte-identity comparison must detect reordered records between runs"
    );
    assert_comparator_rejects(
        &reordered,
        Some(bound),
        &baseline,
        "change record ordering between repeated runs",
    );
}

#[test]
fn test_killer_mutation_export_schema_without_truncation_field_accepts_defect() {
    let files = vec![pinned_fixture(&FIXTURE_CLOSURES_LUA51)];
    let baseline = observe_baseline(&files);
    let bound = 3usize;
    let stdout = bounded_stdout(&files, bound, 0);
    assert_comparator_accepts(&stdout, Some(bound), &baseline, "schema mutation subject");

    let lines = stdout_lines(&stdout);
    let file_end = line_record(&lines[index_of_type(&lines, "file_end", 0)]);
    let defective = {
        let mut record = file_end.clone();
        record
            .as_object_mut()
            .expect("file_end is an object")
            .remove("is_truncated");
        record
    };

    let live_schema = live_export_schema();
    let live_validator = jsonschema::validator_for(&live_schema).expect("compile live schema");
    assert!(
        live_validator.is_valid(&file_end),
        "Live export schema must accept the unmutated bounded file_end record"
    );
    assert!(
        !live_validator.is_valid(&defective),
        "Live export schema must reject a file_end record with no is_truncated field"
    );

    let mut weakened = live_schema.clone();
    let variant_index = file_end_variant_index(&weakened);
    let required = weakened["oneOf"][variant_index]["required"]
        .as_array()
        .expect("file_end variant declares required fields")
        .iter()
        .filter(|field| *field != &serde_json::json!("is_truncated"))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        required.len() + 1,
        weakened["oneOf"][variant_index]["required"]
            .as_array()
            .unwrap()
            .len(),
        "The live export schema must require `is_truncated` on file_end before it can be removed"
    );
    weakened["oneOf"][variant_index]["required"] = serde_json::Value::Array(required);

    let weakened_validator = jsonschema::validator_for(&weakened).expect("compile weakened schema");
    assert!(
        weakened_validator.is_valid(&defective),
        "Removing the truncation field from the schema must be what admits the defective \
         record; otherwise the schema requirement is not load-bearing"
    );

    println!(
        "killer mutation 'remove is_truncated from the export schema' rejected: the live schema \
         rejects a file_end without is_truncated while the weakened schema accepts it"
    );
}
