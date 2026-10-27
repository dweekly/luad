//! The opt-in `luci-module-trusted-init` convention: admissions, refusals and labels.
//!
//! Each provider is compiled by the required official Lua 5.1.5 compiler and never
//! executed. The convention states its assumption rather than proving it, so a control
//! passes only when the caller's link is exactly what docs/MACHINE-INTERFACE.md says:
//! resolved or absent with the `trusted-init` label, dynamic for the label a visible root
//! store makes uncertain, or dynamic for the corpus after a visible refusal.

use luad_analysis::{analyze_corpus_links, CrossChunkLinkFact, LinkConvention, LinkStatus};
use luad_core::envelope::InputIdentity;
use luad_core::id::ProtoPath;

const CALLER: &str = "luci.sys.exec('argument')";

fn compiled(name: &str, source: &str) -> (InputIdentity, luad_core::Chunk) {
    let chunk = luad_oracle::compile_and_parse_lua51(source, true)
        .expect("required official Lua 5.1.5 compiler");
    (
        InputIdentity {
            path: name.into(),
            sha256: chunk.sha256.clone(),
            byte_length: chunk.byte_length,
        },
        chunk,
    )
}

fn caller_link(providers: &[&str], convention: LinkConvention) -> CrossChunkLinkFact {
    let mut chunks: Vec<_> = providers
        .iter()
        .enumerate()
        .map(|(i, source)| compiled(&format!("provider{i}.luac"), source))
        .collect();
    chunks.push(compiled("caller.luac", CALLER));
    let links = analyze_corpus_links(&chunks, convention);
    let mut at_caller: Vec<_> = links
        .into_iter()
        .filter(|l| l.caller_path == "caller.luac")
        .collect();
    assert_eq!(at_caller.len(), 1, "{providers:?}: {at_caller:?}");
    at_caller.remove(0)
}

fn trusted(providers: &[&str]) -> CrossChunkLinkFact {
    caller_link(providers, LinkConvention::LuciModuleTrustedInit)
}

#[test]
fn test_trusted_init_admits_initialization_the_strict_rule_refuses() {
    for source in [
        "local util = require 'luci.util'; module('luci.sys', package.seeall); function exec() end",
        "module('luci.sys', package.seeall); local t = {}; t.x = 1; function exec() end",
        "local setfenv = setfenv; local u = require 'luci.util'; module('luci.sys'); function exec() end",
        "module('luci.sys'); local u = require 'luci.util'; u.helper = function() end; function exec() end",
        "module('luci.sys'); local mt = setmetatable({}, {__index = function() end}); function exec() end",
        "module('luci.sys'); getmetatable('').__mod = function() end; function exec() end",
        "module('luci.sys'); net = {}; function net.routes() end; function exec() end",
        "local debug = require 'debug'; module('luci.sys'); file = debug.getinfo(1, 'S').source; function exec() end",
        "module('luci.sys'); if flag then helper = 1 end; function exec() end",
    ] {
        let strict = caller_link(&[source], LinkConvention::LuciModuleSetglobal);
        assert_eq!(strict.status, LinkStatus::Dynamic, "strict refuses {source}");
        assert!(strict.assumptions.is_empty());

        let link = trusted(&[source]);
        assert_eq!(link.status, LinkStatus::Resolved, "{source}: {link:?}");
        assert_eq!(link.target_proto.as_ref(), Some(&exec_proto(source)));
        assert_eq!(link.assumptions, ["trusted-init"], "{source}");
        assert!(!link.evidence.is_empty());
    }
}

/// The prototype `function exec` compiles to: the last root child.
fn exec_proto(source: &str) -> ProtoPath {
    let chunk = luad_oracle::compile_and_parse_lua51(source, true).unwrap();
    ProtoPath::root().child(chunk.main_proto.protos.len() - 1)
}

#[test]
fn test_trusted_init_leaves_strict_answers_unlabeled() {
    // A strictly admissible corpus needs no assumption under either convention.
    let source = "module('luci.sys'); function exec() end";
    for convention in [
        LinkConvention::LuciModuleSetglobal,
        LinkConvention::LuciModuleTrustedInit,
    ] {
        let link = caller_link(&[source], convention);
        assert_eq!(link.status, LinkStatus::Resolved);
        assert!(link.assumptions.is_empty(), "{convention}: {link:?}");
        let json = serde_json::to_string(&link).unwrap();
        assert!(!json.contains("assumptions"), "{json}");
    }
    // Once any provider is trust-admitted, every definite answer carries the label, even
    // one resolved to a strictly admitted provider.
    let link = trusted(&[
        source,
        "local u = require 'luci.util'; module('luci.other'); function f() end",
    ]);
    assert_eq!(link.status, LinkStatus::Resolved);
    assert_eq!(link.assumptions, ["trusted-init"]);
    let absent = caller_link(
        &["local u = require 'luci.util'; module('luci.other'); function f() end"],
        LinkConvention::LuciModuleTrustedInit,
    );
    assert_eq!(absent.status, LinkStatus::Absent);
    assert_eq!(absent.assumptions, ["trusted-init"]);
}

#[test]
fn test_trusted_init_makes_visibly_unsettled_stores_dynamic() {
    let require = "local u = require 'luci.util'; ";
    for source in [
        // The root rebinds, conditionally defines, loops, or defines before declaring.
        format!("{require}module('luci.sys'); function exec() end; exec = u.exec"),
        format!("{require}module('luci.sys'); if flag then function exec() end end"),
        format!("{require}module('luci.sys'); for i = 1, 2 do function exec() end end"),
        format!("{require}function exec() end; module('luci.sys')"),
        format!("{require}module('luci.sys'); local f = function() end; if flag then f = u.g end; exec = f"),
        // Path-insensitive transfer sees the branch's closure last; the store is not proved.
        format!("{require}module('luci.sys'); local f = u.g; if flag then f = function() end end; exec = f"),
        // Options receive the module table and may change its metatable.
        format!("{require}module('luci.sys', function(m) end); function exec() end"),
    ] {
        let link = trusted(&[&source]);
        assert_eq!(link.status, LinkStatus::Dynamic, "{source}: {link:?}");
        assert!(link.target_artifact.is_none() && link.target_proto.is_none());
        assert!(link.assumptions.is_empty());
        assert!(!link.evidence.is_empty());
    }
    // A non-function store replaces the namespace labels below it rely on.
    let link = trusted(&[
        "module('luci.sys'); function exec() end",
        &format!("{require}module('luci'); sys = nil"),
    ]);
    assert_eq!(link.status, LinkStatus::Dynamic, "{link:?}");
    // Only that label: a clean neighbour in the same module still resolves.
    let link = trusted(&[&format!(
        "{require}module('luci.sys'); function exec() end; helper = 1; helper = 2"
    )]);
    assert_eq!(link.status, LinkStatus::Resolved);
    assert_eq!(link.assumptions, ["trusted-init"]);
}

#[test]
fn test_trusted_init_refuses_what_is_visibly_unbounded_for_the_whole_corpus() {
    let exec = "module('luci.sys'); function exec() end";
    let require = "local u = require 'luci.util'; ";
    for refused in [
        format!("{require}module('luci.other'); module('luci.more')"),
        // Two loads of `module`, one declaration: the second could be called anywhere.
        format!("{require}local later = module; module('luci.other'); u.defer(later)"),
        format!("{require}local name = 'luci.' .. 'other'; module(name)"),
        format!("{require}if flag then module('luci.other') end"),
        format!("{require}module('luci.other'); setfenv(1, {{}})"),
        format!("local sf = setfenv; {require}module('luci.other'); sf(1, {{}})"),
        format!("{require}module('luci.other'); getfenv(1).exec = nil"),
    ] {
        // The provider of luci.sys is clean, but the refused module could define anything.
        let link = trusted(&[exec, &refused]);
        assert_eq!(link.status, LinkStatus::Dynamic, "{refused}: {link:?}");
        assert!(link.target_proto.is_none());
        assert!(link.assumptions.is_empty());
    }
}

/// What the assumption covers, pinned: each provider's initialization does remove or
/// redirect `luci.sys.exec` at runtime, through code luad does not follow. The answer is
/// still `resolved`, and says it rests on `trusted-init`. These are the examples the
/// assumption names, including both code-review round-2 findings; they are not defects.
#[test]
fn test_trusted_init_labels_what_the_assumption_covers() {
    let exec = "module('luci.sys'); function exec() end";
    let require = "local u = require 'luci.util'; ";
    for covered in [
        // Code review round 2: a call through a value luad does not identify, and a table
        // returned by a metamethod.
        format!("{require}module('luci.other', package.seeall); rawget(_G, 'setfenv')(1, luci.sys); function exec() return 'evil' end"),
        format!("{require}module('luci.other'); local o = u.wrap() .. ''; o.sys.exec = nil"),
        // Code review round 1, now covered rather than chased.
        format!("{require}module('luci.other'); local t = {{}}; table.insert(t, luci.sys); t[1].exec = nil"),
        format!("{require}module('luci.other', package.seeall); local t = {{}}; local function f() t = luci.sys end; f(); t.exec = nil"),
        format!("{require}module('luci.other', package.seeall); _G.module('luci.sys'); function exec() return 'evil' end"),
        // The root's own writes into another module's table are initialization code too.
        format!("{require}module('luci.other'); luci.sys.exec = function() end"),
        format!("{require}module('luci.other'); package.loaded['luci.sys'].exec = nil"),
        // Same-file code run through a table or a callback.
        format!("{require}module('luci.other'); local t = {{}}; t.g = function() luci.sys.exec = nil end; t.g()"),
        format!("{require}module('luci.other'); u.patch(luci.sys)"),
    ] {
        let link = trusted(&[exec, &covered]);
        assert_eq!(link.status, LinkStatus::Resolved, "{covered}: {link:?}");
        assert_eq!(link.assumptions, ["trusted-init"], "{covered}");
    }
    // Within the module itself, too: `_M.exec = nil` after the definition.
    let link = trusted(&[&format!(
        "{require}module('luci.sys'); function exec() end; _M.exec = nil"
    )]);
    assert_eq!(link.status, LinkStatus::Resolved);
    assert_eq!(link.assumptions, ["trusted-init"]);
}

/// Hostile input: deeply nested closures under initialization code, through the CLI as a
/// user runs it. The admission visits only root instructions, so nesting depth adds no
/// work of its own. Just under the parser's nesting limit the answer is labeled and quick;
/// over it, parsing refuses before any admission runs.
#[test]
fn test_trusted_init_deep_nesting_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, source: &str| {
        let bytes = luad_oracle::compile_source_lua51(source, true).expect("official luac");
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.display().to_string()
    };
    let caller = write("caller.luac", CALLER);
    for (depth, expected_exit) in [(126usize, 0), (140, 5)] {
        let mut body = String::from("return 1");
        for i in 0..depth {
            body = format!("local function f{i}() {body} end; local t{i} = {{f{i}}}; return t{i}");
        }
        let provider = write(
            &format!("deep{depth}.luac"),
            &format!(
                "local u = require 'luci.util'; module('luci.sys'); function exec() end; \
                 local function deep() {body} end; local x = deep()"
            ),
        );
        let started = std::time::Instant::now();
        let output = std::process::Command::new(luad_oracle::luad_binary_path())
            .args(["callers", &provider, "--proto", "0/0", &caller])
            .args([
                "--link-convention",
                "luci-module-trusted-init",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        let elapsed = started.elapsed();
        assert_eq!(output.status.code(), Some(expected_exit), "depth {depth}");
        assert!(elapsed < std::time::Duration::from_secs(20), "{elapsed:?}");
        if expected_exit == 0 {
            let document: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let callers = document["data"]["callers"].as_array().unwrap();
            assert_eq!(callers.len(), 1, "depth {depth}");
            assert_eq!(
                callers[0]["bases"][0]["assumptions"],
                serde_json::json!(["trusted-init"])
            );
        }
    }
}

#[test]
fn test_trusted_init_convention_is_listed_and_parsed() {
    assert_eq!(
        LinkConvention::parse("luci-module-trusted-init"),
        Some(LinkConvention::LuciModuleTrustedInit)
    );
    assert!(LinkConvention::all_names().contains(&"luci-module-trusted-init"));
    let output = std::process::Command::new(luad_oracle::luad_binary_path())
        .args(["capabilities", "-f", "json"])
        .output()
        .unwrap();
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("luci-module-trusted-init"));
}
