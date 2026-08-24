//! Independent public acceptance for the Lua 5.1 register-`A` authority.
//!
//! The chunk reader and instruction encoder below are test-local transcriptions of the
//! PUC-Rio Lua 5.1.5 chunk and opcode layouts. They deliberately do not call luad's
//! Lua 5.1 opcode, disassembly, or validation helpers.

use std::path::PathBuf;
use std::process::{Command, Output};

use luad_core::diagnostic::{DiagnosticCategory, Severity, Verdict};
use luad_core::envelope::{MachineDocument, ValidationResponse};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;

/// Base fixture pinned by the sprint fixture matrix.
const FIXTURE: (&str, &str) = (
    "tests/fixtures/precompiled/lua51/hello.luac",
    "d64567d2d41ff584b86602f98fff5906f58f101f6faf98598f3662bac6e96a4f",
);

/// Official sources the independent `A`-role reading is transcribed from.
const AUTHORITY_HASHES: [(&str, &str); 3] = [
    (
        "lopcodes.h",
        "a15fe349da7c1e73b563e8c3249fe7d535eccc844cb30ec80b4e335b0699279b",
    ),
    (
        "lopcodes.c",
        "63cd74edc75970092a8ce078c4ab970efa1ee18de960d00eb826d49fe98d8a76",
    ),
    (
        "lvm.c",
        "b560aad0a1b8bfc4e4b732b2393e8f8ecc68b6c772e6d25763d6ef71c38ab709",
    ),
];

/// `OP_CLOSE` position in the official Lua 5.1.5 opcode enumeration; `A` is the first
/// register of the closed stack span, so it is a direct register operand.
const OP_CLOSE: u8 = 35;
const REG_A_CODE: &str = "L51-REG-001";

/// Facts read from the base chunk by the test-local reader.
struct RootProto {
    path: String,
    maxstacksize: u8,
    pc: usize,
    byte_offset: usize,
    word: u32,
}

/// Reads the root prototype prologue and its first instruction word. Only the fields the
/// derived case needs are decoded; the tail of the chunk is not interpreted.
fn read_root_proto(bytes: &[u8]) -> RootProto {
    assert_eq!(&bytes[0..4], b"\x1bLua", "PUC chunk signature");
    assert_eq!(bytes[4], 0x51, "Lua 5.1 version byte");
    assert_eq!(bytes[6], 1, "little-endian fixture");
    assert_eq!(bytes[9], 4, "32-bit instruction words");
    let sizeof_int = bytes[7] as usize;
    let sizeof_sizet = bytes[8] as usize;

    let uint = |pos: usize, width: usize| -> usize {
        assert!((1..=8).contains(&width));
        let mut value = 0_u64;
        for index in 0..width {
            value |= u64::from(bytes[pos + index]) << (index * 8);
        }
        value as usize
    };

    let mut pos = 12;
    let source_len = uint(pos, sizeof_sizet);
    pos += sizeof_sizet + source_len;
    pos += 2 * sizeof_int; // linedefined, lastlinedefined
    pos += 3; // nups, numparams, is_vararg
    let maxstacksize = bytes[pos];
    pos += 1;
    let instruction_count = uint(pos, sizeof_int);
    pos += sizeof_int;
    assert!(instruction_count > 0, "root prototype has code");

    RootProto {
        path: "0".to_string(),
        maxstacksize,
        pc: 0,
        byte_offset: pos,
        word: u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("instruction word")),
    }
}

fn opcode(word: u32) -> u8 {
    (word & 0x3f) as u8
}

fn field_a(word: u32) -> u8 {
    ((word >> 6) & 0xff) as u8
}

fn iabc(op: u8, a: u8, b: u16, c: u16) -> u32 {
    u32::from(op) | (u32::from(a) << 6) | (u32::from(c) << 14) | (u32::from(b) << 23)
}

fn root() -> PathBuf {
    luad_oracle::find_workspace_root()
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn luad_bin() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_luad") {
        return path.into();
    }
    let workspace = root();
    let output = Command::new("cargo")
        .args(["build", "-p", "luad-cli", "--bin", "luad"])
        .current_dir(&workspace)
        .output()
        .expect("build luad CLI");
    assert!(
        output.status.success(),
        "luad build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    workspace.join("target/debug/luad")
}

fn run_validate(path: &std::path::Path) -> Output {
    Command::new(luad_bin())
        .args([
            "validate",
            path.to_str().expect("UTF-8 path"),
            "--dialect",
            "lua5.1",
            "--format",
            "json",
        ])
        .output()
        .expect("run public validate CLI")
}

#[test]
fn test_close_register_a_at_maxstacksize_has_exact_register_diagnostic() {
    for (name, hash) in AUTHORITY_HASHES {
        assert_eq!(hash.len(), 64, "authority hash is pinned: {name}");
    }

    let mut bytes = std::fs::read(root().join(FIXTURE.0)).expect("pinned base fixture");
    let base_hash = sha256(&bytes);
    assert_eq!(base_hash, FIXTURE.1, "base fixture hash: {}", FIXTURE.0);

    let proto = read_root_proto(&bytes);
    let observed_a = u16::from(proto.maxstacksize);
    let changed_word = iabc(OP_CLOSE, proto.maxstacksize, 0, 0);
    assert_eq!(opcode(changed_word), OP_CLOSE);
    assert_eq!(u16::from(field_a(changed_word)), observed_a);
    assert_ne!(
        proto.word, changed_word,
        "derived case changes the pinned word"
    );

    let range = proto.byte_offset..proto.byte_offset + 4;
    bytes[range].copy_from_slice(&changed_word.to_le_bytes());
    let derived_hash = sha256(&bytes);

    // Derived-case provenance: base hash, prototype path, PC, original word, changed A,
    // changed word, result hash.
    let provenance = format!(
        "base={base_hash} proto={} pc={} original_word={:#010x} changed_a={observed_a} \
         changed_word={changed_word:#010x} result={derived_hash}",
        proto.path, proto.pc, proto.word
    );
    assert_ne!(base_hash, derived_hash, "derived chunk differs: {provenance}");

    let file = NamedTempFile::new().expect("temporary chunk");
    std::fs::write(file.path(), &bytes).expect("write derived chunk");
    let output = run_validate(file.path());

    assert!(
        output.stderr.is_empty(),
        "machine stderr must be empty: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "out-of-range register A must fail validation: {provenance}"
    );

    let doc: MachineDocument<ValidationResponse> = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| {
            panic!(
                "validate stdout is not JSON: {error}\nstdout={}",
                String::from_utf8_lossy(&output.stdout)
            )
        });
    assert_eq!(doc.data.verdict, Verdict::Invalid, "{provenance}");

    let register_diagnostics: Vec<_> = doc
        .data
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == REG_A_CODE)
        .collect();
    assert_eq!(
        register_diagnostics.len(),
        1,
        "expected exactly one {REG_A_CODE} for CLOSE A={observed_a} \
         (maxstacksize {}): {provenance}\ndiagnostics={:?}",
        proto.maxstacksize,
        doc.data.diagnostics
    );

    let diagnostic = register_diagnostics[0];
    let source = diagnostic.source.as_ref().expect("diagnostic source word");
    let observed = (
        diagnostic.code.as_str(),
        diagnostic.severity,
        diagnostic.category,
        diagnostic.target.to_string(),
        diagnostic.message.as_str(),
        source.byte_offset,
        source.byte_length,
        source.raw_hex.as_str(),
    );
    let expected_message = format!(
        "Register A ({observed_a}) exceeds maxstacksize ({}) at PC {}",
        proto.maxstacksize, proto.pc
    );
    let expected_raw_hex = hex::encode(changed_word.to_le_bytes());
    let expected = (
        REG_A_CODE,
        Severity::Error,
        DiagnosticCategory::Instruction,
        format!("proto:{}:pc:{}", proto.path, proto.pc),
        expected_message.as_str(),
        proto.byte_offset,
        4_usize,
        expected_raw_hex.as_str(),
    );
    assert_eq!(observed, expected, "{provenance}");
}
