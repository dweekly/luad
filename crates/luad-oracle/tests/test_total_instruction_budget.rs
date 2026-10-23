//! Chunk-wide instruction budget (issue #117).
//!
//! Each parsed instruction word costs a few hundred bytes, so the declared code sizes
//! across a chunk are charged to one budget before any instruction vector is allocated.
//! Official compilers produce the inputs; nothing is executed.

use luad_core::diagnostic::Diagnostic;
use luad_core::limits::{ParseMode, ResourceLimits};
use luad_core::model::{Chunk, Prototype};
use luad_core::reader::SafeReader;

const SOURCE: &str =
    "local function a(x) return x + 1 end\nlocal function b(y) return a(y) * 2 end\nreturn b(3)\n";

type Decode = fn(&mut SafeReader) -> Result<Chunk, Diagnostic>;

fn dialects() -> Vec<(&'static str, Vec<u8>, Decode)> {
    vec![
        (
            "lua5.1",
            luad_oracle::compile_source_lua51(SOURCE, true).unwrap(),
            luad_dialect_lua51::decode_chunk_lua51 as Decode,
        ),
        (
            "lua5.2",
            luad_oracle::compile_source_lua52(SOURCE, true).unwrap(),
            luad_dialect_lua52::decode_chunk_lua52 as Decode,
        ),
        (
            "lua5.3",
            luad_oracle::compile_source_lua53(SOURCE, true).unwrap(),
            luad_dialect_lua53::decode_chunk_lua53 as Decode,
        ),
        (
            "lua5.4",
            luad_oracle::compile_source_lua54(SOURCE, true).unwrap(),
            luad_dialect_lua54::decode_chunk_lua54 as Decode,
        ),
        (
            "lua5.5",
            luad_oracle::compile_source_lua55(SOURCE, true).unwrap(),
            luad_dialect_lua55::decode_chunk_lua55 as Decode,
        ),
    ]
}

fn total(proto: &Prototype) -> usize {
    proto.instructions.len() + proto.protos.iter().map(total).sum::<usize>()
}

// Mirrors the dialect decoders' own `Result<Chunk, Diagnostic>` signature.
#[allow(clippy::result_large_err)]
fn decode(bytes: &[u8], decode: Decode, budget: usize) -> Result<Chunk, Diagnostic> {
    let limits = ResourceLimits {
        max_total_instructions: budget,
        ..ResourceLimits::default()
    };
    let mut reader = SafeReader::with_options(bytes, 0, limits, ParseMode::Strict);
    decode(&mut reader)
}

#[test]
fn test_every_dialect_charges_the_whole_chunk_to_one_budget() {
    for (name, bytes, decoder) in dialects() {
        let chunk = decode(&bytes, decoder, usize::MAX).unwrap_or_else(|d| panic!("{name}: {d:?}"));
        let count = total(&chunk.main_proto);
        assert!(
            chunk.main_proto.protos.len() >= 2,
            "{name}: control needs nested prototypes"
        );
        assert!(
            count > chunk.main_proto.instructions.len(),
            "{name}: children carry code"
        );
        assert!(
            decode(&bytes, decoder, count).is_ok(),
            "{name}: exactly at the budget parses"
        );
        let refused = decode(&bytes, decoder, count - 1).expect_err(name);
        assert_eq!(refused.code, "CORE-LIMIT-004", "{name}: {refused:?}");
        assert!(
            refused.source.is_some(),
            "{name}: the size field location is reported"
        );
    }
}

#[test]
fn test_the_budget_refuses_a_declared_size_before_reading_it() {
    // A stripped Lua 5.1 chunk: 12-byte header, then the main prototype's empty source
    // name (8-byte size_t on this host), two line ints, four byte fields, then sizecode.
    let _ = luad_oracle::require_luac51();
    let mut bytes = luad_oracle::compile_source_lua51(SOURCE, true).unwrap();
    assert_eq!(bytes[8], 8, "control assumes an 8-byte size_t header");
    let sizecode = 12 + 8 + 4 + 4 + 4;
    bytes.truncate(sizecode + 4);
    bytes[sizecode..sizecode + 4].copy_from_slice(&900_000u32.to_le_bytes());
    let decoder = luad_dialect_lua51::decode_chunk_lua51 as Decode;
    let refused = decode(&bytes, decoder, 1_000).expect_err("budget");
    assert_eq!(refused.code, "CORE-LIMIT-004", "{refused:?}");
    // Under the default budget the same input fails later, on the missing words.
    let later = decode(
        &bytes,
        decoder,
        ResourceLimits::default().max_total_instructions,
    )
    .expect_err("truncated");
    assert_ne!(later.code, "CORE-LIMIT-004", "{later:?}");
}

#[test]
fn test_the_default_budget_admits_the_vendored_corpus_with_wide_margin() {
    let limit = ResourceLimits::default().max_total_instructions;
    assert_eq!(limit, 2_000_000);
    let root = luad_oracle::find_workspace_root().join("tests/corpus/luci-23.05");
    let mut largest = 0;
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "lua") {
                let source = std::fs::read_to_string(&path).unwrap();
                let bytes = luad_oracle::compile_source_lua51(&source, false).unwrap();
                let chunk = decode(&bytes, luad_dialect_lua51::decode_chunk_lua51, limit)
                    .unwrap_or_else(|d| panic!("{}: {d:?}", path.display()));
                largest = largest.max(total(&chunk.main_proto));
            }
        }
    }
    assert!(largest > 0);
    assert!(
        limit >= 50 * largest,
        "largest LuCI module {largest} instructions"
    );
}
