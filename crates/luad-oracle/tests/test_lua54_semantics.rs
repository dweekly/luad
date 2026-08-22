use std::process::Command;
use tempfile::NamedTempFile;
use std::fs;

use luad_core::ir::EffectTarget;
use luad_dialect_lua54::lift_proto_lua54;
use luad_oracle::{compile_and_parse_lua54, find_luac54};

/// Run `luac -l -l` on a source snippet and return raw output.
fn run_luac_listing(source: &str) -> String {
    let luac_path = find_luac54().expect("luac not found");
    let src_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    fs::write(src_file.path(), source).unwrap();

    // Compile
    let _ = Command::new(&luac_path)
        .arg("-o")
        .arg(out_file.path())
        .arg(src_file.path())
        .output()
        .unwrap();

    // Run luac -l -l
    let output = Command::new(&luac_path)
        .arg("-l")
        .arg("-l")
        .arg(out_file.path())
        .output()
        .unwrap();

    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn test_all_opcode_lifting_and_effects() {
    let source = r#"
        local a = 10
        local b = 20
        local c = a + b
        local d = c * 2
        local str = "hello" .. " world"
        local t = { x = 1, y = 2 }
        t.x = t.y + 5
        local function f(x, ...)
            return x + 1, ...
        end
        local res1, res2 = f(c, 100)
        return res1, res2, str, d, t
    "#;

    let chunk = compile_and_parse_lua54(source, false).expect("parse failed");
    let lifted = lift_proto_lua54(&chunk.main_proto);

    assert!(!lifted.is_empty());
    for inst in &lifted {
        assert_eq!(inst.confidence, luad_core::Confidence::Fact);
        assert!(!inst.mnemonic.is_empty());
        assert!(!inst.explanation.is_empty());
    }

    // Verify luac listing aligns
    let listing = run_luac_listing(source);
    assert!(listing.contains("ADD"));
    assert!(listing.contains("MULK") || listing.contains("MUL"));
    assert!(listing.contains("CONCAT"));
    assert!(listing.contains("CALL"));
    assert!(listing.contains("RETURN"));
}

#[test]
fn test_calls_and_multireturn_effects() {
    let source = "local function foo(a, b) return a, b end; local x, y = foo(1, 2); return x, y";
    let chunk = compile_and_parse_lua54(source, false).expect("parse failed");
    let lifted = lift_proto_lua54(&chunk.main_proto);

    let call_inst = lifted.iter().find(|i| i.mnemonic == "CALL").expect("expected CALL");
    assert!(call_inst.metamethod_fallbacks.contains(&"__call".to_string()));
    assert!(call_inst.reads.iter().any(|r| matches!(r, EffectTarget::Register { .. })));
    assert!(call_inst.writes.iter().any(|w| matches!(w, EffectTarget::RegisterRange { .. })));
}

#[test]
fn test_for_loop_jump_targets() {
    let source = "local sum = 0; for i = 1, 10 do sum = sum + i end; return sum";
    let chunk = compile_and_parse_lua54(source, false).expect("parse failed");
    let lifted = lift_proto_lua54(&chunk.main_proto);

    let forprep = lifted.iter().find(|i| i.mnemonic == "FORPREP").expect("expected FORPREP");
    assert!(forprep.jump_target.is_some());

    let forloop = lifted.iter().find(|i| i.mnemonic == "FORLOOP").expect("expected FORLOOP");
    assert!(forloop.jump_target.is_some());
}
