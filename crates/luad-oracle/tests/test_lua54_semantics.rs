use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

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

    let call_inst = lifted
        .iter()
        .find(|i| i.mnemonic == "CALL")
        .expect("expected CALL");
    assert!(call_inst
        .metamethod_fallbacks
        .contains(&"__call".to_string()));
    assert!(call_inst
        .reads
        .iter()
        .any(|r| matches!(r, EffectTarget::Register { .. })));
    assert!(call_inst
        .writes
        .iter()
        .any(|w| matches!(w, EffectTarget::RegisterRange { .. })));
}

#[test]
fn test_for_loop_jump_targets() {
    let source = "local sum = 0; for i = 1, 10 do sum = sum + i end; return sum";
    let chunk = compile_and_parse_lua54(source, false).expect("parse failed");
    let lifted = lift_proto_lua54(&chunk.main_proto);

    let forprep_inst = lifted
        .iter()
        .find(|i| i.mnemonic == "FORPREP")
        .expect("expected FORPREP");
    assert!(forprep_inst.jump_target.is_some());
}

#[test]
fn test_lua54_golden_word_vectors() {
    use luad_dialect_lua54::{Opcode54, RawInstruction54};

    // 1. MOVE 0 1 (A=0, B=1, C=0, k=0) -> 0x00010000
    let word_move = 0x00010000;
    let raw_move = RawInstruction54::decode(word_move);
    assert_eq!(raw_move.opcode, Some(Opcode54::Move));
    assert_eq!(raw_move.a, 0);
    assert_eq!(raw_move.b, 1);
    assert_eq!(raw_move.c, 0);
    assert_eq!(raw_move.k, 0);
    assert_eq!(raw_move.encode(), Some(word_move));

    // 2. LOADI 0 42 (A=0, sBx=42, Bx = 42 + 65535 = 65577)
    let word_loadi = RawInstruction54::encode_iasbx(Opcode54::Loadi, 0, 42);
    let raw_loadi = RawInstruction54::decode(word_loadi);
    assert_eq!(raw_loadi.opcode, Some(Opcode54::Loadi));
    assert_eq!(raw_loadi.a, 0);
    assert_eq!(raw_loadi.sbx, 42);
    assert_eq!(raw_loadi.encode(), Some(word_loadi));

    // 3. ADDI 0 1 -5 (A=0, B=1, sC=-5 -> C=122, k=0)
    let word_addi = RawInstruction54::encode_iabc(Opcode54::Addi, 0, 1, (-5 + 127) as u8, 0);
    let raw_addi = RawInstruction54::decode(word_addi);
    assert_eq!(raw_addi.opcode, Some(Opcode54::Addi));
    assert_eq!(raw_addi.a, 0);
    assert_eq!(raw_addi.b, 1);
    assert_eq!(raw_addi.sc, -5);
    assert_eq!(raw_addi.encode(), Some(word_addi));

    // 4. EQI 0 -10 1 (A=0, sB=-10 -> B=117, C=0, k=1)
    let word_eqi = RawInstruction54::encode_iabc(Opcode54::Eqi, 0, (-10 + 127) as u8, 0, 1);
    let raw_eqi = RawInstruction54::decode(word_eqi);
    assert_eq!(raw_eqi.opcode, Some(Opcode54::Eqi));
    assert_eq!(raw_eqi.a, 0);
    assert_eq!(raw_eqi.sb, -10);
    assert_eq!(raw_eqi.k, 1);
    assert_eq!(raw_eqi.encode(), Some(word_eqi));

    // 5. JMP -5 (sJ=-5 -> uJ = -5 + 16777215 = 16777210)
    let word_jmp = RawInstruction54::encode_isj(Opcode54::Jmp, -5);
    let raw_jmp = RawInstruction54::decode(word_jmp);
    assert_eq!(raw_jmp.opcode, Some(Opcode54::Jmp));
    assert_eq!(raw_jmp.sj, -5);
    assert_eq!(raw_jmp.encode(), Some(word_jmp));
}

#[test]
fn test_lua54_all_83_opcodes_round_trip() {
    use luad_dialect_lua54::{OpMode54, Opcode54, RawInstruction54};

    for op_idx in 0..=82 {
        let op = Opcode54::from_u8(op_idx).expect("Valid opcode");
        let word = match op.mode() {
            OpMode54::IABC => RawInstruction54::encode_iabc(op, 10, 20, 30, 1),
            OpMode54::IABx => RawInstruction54::encode_iabx(op, 10, 5000),
            OpMode54::IAsBx => RawInstruction54::encode_iasbx(op, 10, -500),
            OpMode54::IAx => RawInstruction54::encode_iax(op, 123456),
            OpMode54::IsJ => RawInstruction54::encode_isj(op, -1000),
        };

        let decoded = RawInstruction54::decode(word);
        assert_eq!(decoded.opcode, Some(op), "Opcode mismatch for #{op_idx}");
        assert_eq!(
            decoded.encode(),
            Some(word),
            "Round-trip encode mismatch for #{op_idx} ({})",
            op.name()
        );
    }
}
