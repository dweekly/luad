//! The opt-in `luci-module-trusted-init` convention: admissions, refusals and labels.
//!
//! Each provider is compiled by the required official Lua 5.1.5 compiler and never
//! executed. A control passes only when the caller's link is exactly what the contract in
//! docs/NEXT-SPRINT.md says: resolved with the `trusted-init` label, or not resolved.

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
fn test_trusted_init_never_resolves_what_the_root_visibly_changes() {
    let require = "local u = require 'luci.util'; ";
    for providers in [
        // The root rebinds, conditionally defines, or defines before declaring.
        vec![format!("{require}module('luci.sys'); function exec() end; exec = u.exec")],
        vec![format!("{require}module('luci.sys'); if flag then function exec() end end")],
        vec![format!("{require}module('luci.sys'); for i = 1, 2 do function exec() end end")],
        vec![format!("{require}function exec() end; module('luci.sys')")],
        vec![format!("{require}module('luci.sys'); local f = function() end; if flag then f = u.g end; exec = f")],
        // Path-insensitive transfer sees the branch's closure last; the store is not proved.
        vec![format!("{require}module('luci.sys'); local f = u.g; if flag then f = function() end end; exec = f")],
        // The module table itself escapes or is written.
        vec![format!("{require}module('luci.sys'); function exec() end; setmetatable(_M, {{}})")],
        vec![format!("{require}module('luci.sys'); function exec() end; _M.exec = nil")],
        vec![format!("{require}module('luci.sys', function(m) end); function exec() end")],
        // Another module writes the namespace through a name the analysis follows.
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); luci.sys.exec = function() end"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local s = require 'luci.sys'; s.exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); package.loaded['luci.sys'].exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local l = package.loaded; l['luci.sys'].exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local s = luci.sys; local rs = rawset; rs(s, 'exec', nil)"),
        ],
        // Namespaces kept in tables this root made are followed out of them.
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local t = {{}}; t.s = luci.sys; t.s.exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local t = {{s = require 'luci.sys'}}; local x = t.s; x.exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local t = {{luci.sys}}; t[1].exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local t = {{}}; local k = 'x'; t[k] = luci.sys; t.y.exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local t = {{inner = {{s = luci.sys}}}}; setmetatable(t, {{}})"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); local t = {{s = luci.sys}}; holder = t"),
        ],
        // A namespace stored under another name is followed through that alias.
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); holder = luci.sys; holder.exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); sys = require 'luci.sys'; local x = sys; x.exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); a = luci; b = a; b.sys.exec = nil"),
        ],
        vec![
            "module('luci.sys'); function exec() end".to_string(),
            format!("{require}module('luci.other'); holder = luci.sys; setmetatable(holder, {{}})"),
        ],
    ] {
        let sources: Vec<&str> = providers.iter().map(String::as_str).collect();
        let link = trusted(&sources);
        assert_eq!(link.status, LinkStatus::Dynamic, "{sources:?}: {link:?}");
        assert!(link.target_artifact.is_none() && link.target_proto.is_none());
        assert!(link.assumptions.is_empty());
        assert!(!link.evidence.is_empty());
    }
}

#[test]
fn test_trusted_init_refuses_unbounded_initialization_for_the_whole_corpus() {
    let exec = "module('luci.sys'); function exec() end";
    let require = "local u = require 'luci.util'; ";
    for refused in [
        format!("{require}module('luci.other'); module('luci.more')"),
        format!("{require}local name = 'luci.' .. 'other'; module(name)"),
        format!("{require}module('luci.other'); setfenv(1, {{}})"),
        format!("local sf = setfenv; {require}module('luci.other'); sf(1, {{}})"),
        "local debug = require 'debug'; module('luci.other'); debug.setmetatable(u, {})".to_string(),
        format!("{require}module('luci.other'); local k = 'x'; _G[k] = 1"),
        format!("{require}module('luci.other'); local n = 'luci.' .. 'sys'; local s = require(n); s.exec = nil"),
        format!("{require}module('luci.other'); local ok, s = pcall(require, 'luci.sys'); s.exec = nil"),
        format!("{require}module('luci.other'); getfenv(1).exec = nil"),
        format!("{require}module('luci.other'); local m = module; u.call(m)"),
        format!("{require}if flag then module('luci.other') end"),
    ] {
        // The provider of luci.sys is clean, but the refused module could define anything.
        let link = trusted(&[exec, &refused]);
        assert_eq!(link.status, LinkStatus::Dynamic, "{refused}: {link:?}");
        assert!(link.target_proto.is_none());
        assert!(link.assumptions.is_empty());
    }
}

#[test]
fn test_trusted_init_caps_are_limits_not_partial_admissions() {
    let deep = (0..40)
        .map(|i| format!("f{i}"))
        .collect::<Vec<_>>()
        .join(".");
    let link = trusted(&[
        "module('luci.sys'); function exec() end",
        &format!("local u = require 'luci.util'; module('luci.other'); local x = luci.{deep}"),
    ]);
    assert_eq!(link.status, LinkStatus::LimitExceeded, "{link:?}");
    assert!(link.target_proto.is_none() && link.assumptions.is_empty());
}

/// The contract's stated gap, pinned: same-file functions run by code other than the
/// root's own instructions are inside the assumption, so this answer is labeled, not
/// proved.
#[test]
fn test_trusted_init_labels_same_file_code_it_does_not_follow() {
    let source = "module('luci.sys', package.seeall); function exec() return 1 end; \
                  local t = {}; t.g = function() exec = function() return 2 end end; t.g()";
    let link = trusted(&[source]);
    assert_eq!(link.status, LinkStatus::Resolved);
    assert_eq!(link.assumptions, ["trusted-init"]);
    // So is a namespace handed to a function other than the mutating builtins.
    let link = trusted(&[
        "module('luci.sys'); function exec() end",
        "local u = require 'luci.util'; module('luci.other'); u.patch(luci.sys)",
    ]);
    assert_eq!(link.status, LinkStatus::Resolved);
    assert_eq!(link.assumptions, ["trusted-init"]);
}

#[test]
fn test_trusted_init_aliases_do_not_dirty_their_source() {
    // Re-exporting or keeping a namespace under another name changes neither.
    for other in [
        "local u = require 'luci.util'; module('luci.other'); exec2 = luci.sys.exec",
        "local u = require 'luci.util'; module('luci.other'); sys = require 'luci.sys'",
        "local u = require 'luci.util'; module('luci.other'); local c = sys:cursor()",
        "local u = require 'luci.util'; module('luci.other'); holder = luci.sys; holder.other.x = 1",
    ] {
        let link = trusted(&["module('luci.sys'); function exec() end", other]);
        assert_eq!(link.status, LinkStatus::Resolved, "{other}: {link:?}");
        assert_eq!(link.assumptions, ["trusted-init"]);
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
